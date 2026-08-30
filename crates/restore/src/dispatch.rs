use plist::{Dictionary, Value};
use thiserror::Error;

use crate::DataType;

#[derive(Clone, Debug, Default)]
pub struct PreparedRestoreData {
    root_ticket: Option<Vec<u8>>,
    kernel_cache: Option<Vec<u8>>,
    device_tree: Option<Vec<u8>>,
    system_image_root_hash: Option<Vec<u8>>,
    system_image_canonical_metadata: Option<Vec<u8>>,
    nor: Option<Dictionary>,
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

    pub fn dispatch(&self, data_type: &DataType) -> Result<DispatchAction, RestoreDispatchError> {
        match data_type {
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
            DataType::Nor => response(&self.nor, "NORData"),
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

    #[test]
    fn builds_root_ticket_response() {
        let prepared = PreparedRestoreData::default().with_root_ticket(vec![1, 2, 3]);
        let DispatchAction::Send(response) = prepared.dispatch(&DataType::RootTicket).unwrap()
        else {
            panic!("expected plist response");
        };
        assert_eq!(
            response.get("RootTicketData").and_then(Value::as_data),
            Some([1, 2, 3].as_slice())
        );
    }
}
