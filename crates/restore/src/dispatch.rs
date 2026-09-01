use plist::{Dictionary, Value};
use thiserror::Error;

use crate::{DataRequest, DataType};

/// Chunk size of the `FileData` message sequence used to answer boot-object
/// requests (idevicerestore `_restore_send_file_data`, restore.c:4681).
pub const FILE_DATA_CHUNK_SIZE: usize = 8192;

/// Build the `{FileData: <chunk>}` message sequence for `data`, terminated by
/// a `{FileDataDone: true}` message (also the only message for empty data).
pub fn file_data_messages(data: &[u8]) -> Vec<Dictionary> {
    let mut messages = data
        .chunks(FILE_DATA_CHUNK_SIZE)
        .map(|chunk| {
            let mut message = Dictionary::new();
            message.insert("FileData".into(), Value::Data(chunk.to_vec()));
            message
        })
        .collect::<Vec<_>>();
    let mut done = Dictionary::new();
    done.insert("FileDataDone".into(), true.into());
    messages.push(done);
    messages
}

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
    build_identity: Option<Dictionary>,
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

    /// Build identity dictionary answered to `BuildIdentityDict` requests
    /// (already rewritten against the cryptex source when the restore plan
    /// calls for it).
    pub fn with_build_identity(mut self, identity: Dictionary) -> Self {
        self.build_identity = Some(identity);
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
            // Boot objects are streamed by a live resolver (`FileData`
            // sequence); the static prepared data cannot answer them.
            DataType::SourceBootObjectV4 | DataType::PersonalizedBootObjectV3 => {
                Err(RestoreDispatchError::MissingData("boot object"))
            }
            DataType::BuildIdentityDict => {
                let identity = self
                    .build_identity
                    .clone()
                    .ok_or(RestoreDispatchError::MissingData("BuildIdentityDict"))?;
                let variant = request
                    .message()
                    .get("Arguments")
                    .and_then(Value::as_dictionary)
                    .and_then(|arguments| arguments.get("Variant"))
                    .and_then(Value::as_string)
                    .unwrap_or("Erase");
                let mut response = Dictionary::new();
                response.insert("BuildIdentityDict".into(), identity.into());
                response.insert("Variant".into(), variant.into());
                Ok(DispatchAction::Send(response))
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
    /// Stream the payload as a `FileData` chunk sequence terminated by
    /// `FileDataDone` (boot-object requests).
    FileData(Vec<u8>),
}

/// Payload routed to a request's separate data port: either a single
/// response message or a `FileData` chunk sequence.
#[derive(Clone, Debug)]
pub enum DataResponse {
    Message(Dictionary),
    FileData(Vec<u8>),
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

    #[test]
    fn file_data_messages_chunk_at_8192_and_terminate_with_done() {
        // Empty payloads send only the terminator.
        let messages = file_data_messages(&[]);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].get("FileDataDone").and_then(Value::as_boolean),
            Some(true)
        );

        // An exact chunk boundary does not produce a trailing empty chunk.
        let data = vec![7_u8; FILE_DATA_CHUNK_SIZE];
        let messages = file_data_messages(&data);
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].get("FileData").and_then(Value::as_data),
            Some(data.as_slice())
        );
        assert!(messages[1].contains_key("FileDataDone"));

        let data = vec![9_u8; FILE_DATA_CHUNK_SIZE + 1];
        let messages = file_data_messages(&data);
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages[1]
                .get("FileData")
                .and_then(Value::as_data)
                .map(<[u8]>::len),
            Some(1)
        );
        assert!(messages[2].contains_key("FileDataDone"));
    }

    #[test]
    fn build_identity_response_carries_the_request_variant() {
        let mut identity = Dictionary::new();
        identity.insert("ApBoardID".into(), 8_u64.into());
        let prepared = PreparedRestoreData::default().with_build_identity(identity);

        let DispatchAction::Send(response) = prepared
            .dispatch(&data_request("BuildIdentityDict", false))
            .unwrap()
        else {
            panic!("expected plist response");
        };
        assert!(response.contains_key("BuildIdentityDict"));
        // Without Arguments.Variant the response defaults to "Erase"
        // (idevicerestore restore_send_buildidentity, restore.c:5189-5194).
        assert_eq!(
            response.get("Variant").and_then(Value::as_string),
            Some("Erase")
        );

        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), "BuildIdentityDict".into());
        let mut arguments = Dictionary::new();
        arguments.insert("Variant".into(), "Customer Erase Install (IPSW)".into());
        message.insert("Arguments".into(), arguments.into());
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        let DispatchAction::Send(response) = prepared.dispatch(&request).unwrap() else {
            panic!("expected plist response");
        };
        assert_eq!(
            response.get("Variant").and_then(Value::as_string),
            Some("Customer Erase Install (IPSW)")
        );
    }

    #[test]
    fn boot_object_requests_are_not_answered_from_static_data() {
        let prepared = PreparedRestoreData::default();
        assert!(matches!(
            prepared.dispatch(&data_request("SourceBootObjectV4", false)),
            Err(RestoreDispatchError::MissingData("boot object"))
        ));
        assert!(matches!(
            prepared.dispatch(&data_request("PersonalizedBootObjectV3", false)),
            Err(RestoreDispatchError::MissingData("boot object"))
        ));
    }
}
