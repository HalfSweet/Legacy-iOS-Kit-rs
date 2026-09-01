use plist::{Dictionary, Value};
use thiserror::Error;

use crate::{DataRequest, DataType};

#[derive(Clone, Debug, Default)]
pub struct PreparedRestoreData {
    root_ticket: Option<Vec<u8>>,
    kernel_cache: Option<Vec<u8>>,
    device_tree: Option<Vec<u8>>,
    system_image_root_hash: Option<Vec<u8>>,
    system_image_canonical_metadata: Option<Vec<u8>>,
    nor: Option<Dictionary>,
    nor_version_1: Option<Dictionary>,
    baseband: Option<Dictionary>,
    fud: Option<Dictionary>,
    firmware_updater: Option<Dictionary>,
}

impl PreparedRestoreData {
    pub fn with_root_ticket(mut self, ticket: Vec<u8>) -> Self {
        self.root_ticket = Some(ticket);
        self
    }

    pub fn with_kernel_cache(mut self, kernel_cache: Vec<u8>) -> Self {
        self.kernel_cache = Some(kernel_cache);
        self
    }

    pub fn with_device_tree(mut self, device_tree: Vec<u8>) -> Self {
        self.device_tree = Some(device_tree);
        self
    }

    pub fn with_system_image_root_hash(mut self, data: Vec<u8>) -> Self {
        self.system_image_root_hash = Some(data);
        self
    }

    pub fn with_system_image_canonical_metadata(mut self, data: Vec<u8>) -> Self {
        self.system_image_canonical_metadata = Some(data);
        self
    }

    pub fn with_nor(mut self, response: Dictionary) -> Self {
        self.nor = Some(response);
        self
    }

    /// Alternative NOR response for requests whose `Arguments` carry the
    /// `FlashVersion1` flag (old devices): `NorImageData` is a dictionary
    /// keyed by component name instead of an array.
    pub fn with_nor_version_1(mut self, response: Dictionary) -> Self {
        self.nor_version_1 = Some(response);
        self
    }

    pub fn with_baseband(mut self, response: Dictionary) -> Self {
        self.baseband = Some(response);
        self
    }

    pub fn with_fud(mut self, response: Dictionary) -> Self {
        self.fud = Some(response);
        self
    }

    pub fn with_firmware_updater(mut self, response: Dictionary) -> Self {
        self.firmware_updater = Some(response);
        self
    }

    pub fn dispatch(&self, request: &DataRequest) -> Result<DispatchAction, RestoreDispatchError> {
        match request.data_type() {
            DataType::SystemImage => Ok(DispatchAction::SystemImage),
            DataType::RootTicket => {
                let mut response = Dictionary::new();
                if let Some(ticket) = &self.root_ticket {
                    response.insert("RootTicketData".into(), Value::Data(ticket.clone()));
                }
                Ok(DispatchAction::Send(response))
            }
            DataType::KernelCache => {
                component(&self.kernel_cache, "KernelCacheFile", "KernelCache")
            }
            DataType::DeviceTree => component(&self.device_tree, "DeviceTreeFile", "DeviceTree"),
            DataType::SystemImageRootHash => component(
                &self.system_image_root_hash,
                "SystemImageRootHashFile",
                "SystemImageRootHash",
            ),
            DataType::SystemImageCanonicalMetadata => component(
                &self.system_image_canonical_metadata,
                "SystemImageCanonicalMetadataFile",
                "SystemImageCanonicalMetadata",
            ),
            DataType::Nor => {
                // Old devices request NORData with Arguments.FlashVersion1 and
                // expect the component-keyed dictionary form; fall back to the
                // prepared response when no FlashVersion1 form was prepared.
                let nor = if request.flash_version_1() {
                    self.nor_version_1.as_ref().or(self.nor.as_ref())
                } else {
                    self.nor.as_ref()
                };
                nor.cloned()
                    .map(DispatchAction::Send)
                    .ok_or(RestoreDispatchError::MissingData("NORData"))
            }
            DataType::Baseband => response(&self.baseband, "BasebandData"),
            DataType::FdrTrust => Ok(DispatchAction::Send(Dictionary::new())),
            DataType::Fud => response(&self.fud, "FUDData"),
            DataType::FirmwareUpdater => response(&self.firmware_updater, "FirmwareUpdaterData"),
            DataType::FirmwareUpdaterPreflight | DataType::DeviceRestoreInfoPreflight => {
                Ok(DispatchAction::Send(Dictionary::new()))
            }
            DataType::Unknown(value) => Err(RestoreDispatchError::UnknownDataType(value.clone())),
        }
    }
}

fn component(
    data: &Option<Vec<u8>>,
    key: &'static str,
    name: &'static str,
) -> Result<DispatchAction, RestoreDispatchError> {
    let data = data
        .clone()
        .ok_or(RestoreDispatchError::MissingData(name))?;
    let mut response = Dictionary::new();
    response.insert(key.into(), Value::Data(data));
    Ok(DispatchAction::Send(response))
}

fn response(
    response: &Option<Dictionary>,
    name: &'static str,
) -> Result<DispatchAction, RestoreDispatchError> {
    response
        .clone()
        .map(DispatchAction::Send)
        .ok_or(RestoreDispatchError::MissingData(name))
}

#[derive(Clone, Debug)]
pub enum DispatchAction {
    SystemImage,
    Send(Dictionary),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RestoreDispatchError {
    #[error("prepared restore data does not contain {0}")]
    MissingData(&'static str),
    #[error("restored requested unknown data type {0}")]
    UnknownDataType(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RestoredMessage;

    fn data_request(data_type: &str, flash_version_1: bool) -> DataRequest {
        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), data_type.into());
        if flash_version_1 {
            let mut arguments = Dictionary::new();
            arguments.insert("FlashVersion1".into(), true.into());
            message.insert("Arguments".into(), arguments.into());
        }
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        request
    }

    #[test]
    fn builds_root_ticket_response() {
        let prepared = PreparedRestoreData::default().with_root_ticket(vec![1, 2, 3]);
        let DispatchAction::Send(response) = prepared
            .dispatch(&data_request("RootTicket", false))
            .unwrap()
        else {
            panic!("expected plist response");
        };
        assert_eq!(
            response.get("RootTicketData").and_then(Value::as_data),
            Some([1, 2, 3].as_slice())
        );
    }

    #[test]
    fn nor_response_follows_the_flash_version_1_flag() {
        let mut array_nor = Dictionary::new();
        array_nor.insert("LlbImageData".into(), Value::Data(vec![1]));
        array_nor.insert(
            "NorImageData".into(),
            Value::Array(vec![Value::Data(vec![2])]),
        );
        let mut dict_nor = Dictionary::new();
        dict_nor.insert("LlbImageData".into(), Value::Data(vec![1]));
        let mut images = Dictionary::new();
        images.insert("iBoot".into(), Value::Data(vec![2]));
        dict_nor.insert("NorImageData".into(), images.into());
        let prepared = PreparedRestoreData::default()
            .with_nor(array_nor)
            .with_nor_version_1(dict_nor);

        let DispatchAction::Send(response) =
            prepared.dispatch(&data_request("NORData", true)).unwrap()
        else {
            panic!("expected plist response");
        };
        assert!(
            response
                .get("NorImageData")
                .and_then(Value::as_dictionary)
                .is_some_and(|images| images.contains_key("iBoot")),
            "FlashVersion1 requests expect the component-keyed dictionary"
        );

        let DispatchAction::Send(response) =
            prepared.dispatch(&data_request("NORData", false)).unwrap()
        else {
            panic!("expected plist response");
        };
        assert!(
            response
                .get("NorImageData")
                .and_then(Value::as_array)
                .is_some(),
            "requests without FlashVersion1 keep the array form"
        );
    }

    #[test]
    fn flash_version_1_falls_back_to_the_prepared_nor_response() {
        let mut array_nor = Dictionary::new();
        array_nor.insert("LlbImageData".into(), Value::Data(vec![1]));
        let prepared = PreparedRestoreData::default().with_nor(array_nor);

        let DispatchAction::Send(response) =
            prepared.dispatch(&data_request("NORData", true)).unwrap()
        else {
            panic!("expected plist response");
        };
        assert!(response.contains_key("LlbImageData"));
    }
}
