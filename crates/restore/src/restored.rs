use plist::{Dictionary, Value};
use tracing::debug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataType {
    SystemImage,
    RootTicket,
    KernelCache,
    Nor,
    Baseband,
    FdrTrust,
    Fud,
    FirmwareUpdater,
    Unknown(String),
}

impl DataType {
    fn from_name(value: &str) -> Self {
        match value {
            "SystemImageData" => Self::SystemImage,
            "RootTicket" => Self::RootTicket,
            "KernelCache" => Self::KernelCache,
            "NORData" => Self::Nor,
            "BasebandData" => Self::Baseband,
            "FDRTrustData" => Self::FdrTrust,
            "FUDData" => Self::Fud,
            "FirmwareUpdaterData" => Self::FirmwareUpdater,
            value => Self::Unknown(value.to_owned()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DataRequest {
    data_type: DataType,
    message: Dictionary,
}

impl DataRequest {
    pub fn data_type(&self) -> &DataType {
        &self.data_type
    }

    pub fn message(&self) -> &Dictionary {
        &self.message
    }
}

#[derive(Clone, Debug)]
pub struct ProgressMessage {
    operation: Option<u64>,
    progress: Option<u64>,
    message: Dictionary,
}

impl ProgressMessage {
    pub const fn operation(&self) -> Option<u64> {
        self.operation
    }

    pub const fn progress(&self) -> Option<u64> {
        self.progress
    }

    pub fn message(&self) -> &Dictionary {
        &self.message
    }
}

#[derive(Clone, Debug)]
pub struct StatusMessage {
    status: Option<u64>,
    message: Dictionary,
}

impl StatusMessage {
    pub const fn status(&self) -> Option<u64> {
        self.status
    }

    pub fn message(&self) -> &Dictionary {
        &self.message
    }
}

#[derive(Clone, Debug)]
pub struct BasebandStatus {
    message: Dictionary,
}

impl BasebandStatus {
    pub fn message(&self) -> &Dictionary {
        &self.message
    }
}

#[derive(Clone, Debug)]
pub enum RestoredMessage {
    DataRequest(DataRequest),
    Progress(ProgressMessage),
    Status(StatusMessage),
    BasebandStatus(BasebandStatus),
    PreviousRestoreLog(Dictionary),
    Unknown {
        message_type: Option<String>,
        message: Dictionary,
    },
}

impl RestoredMessage {
    pub fn parse(message: Dictionary) -> Self {
        let message_type = message
            .get("MsgType")
            .and_then(Value::as_string)
            .map(ToOwned::to_owned);
        debug!(
            message_type,
            keys = message.len(),
            "parsed restored message"
        );

        match message_type.as_deref() {
            Some("DataRequestMsg") => {
                let data_type = message
                    .get("DataType")
                    .and_then(Value::as_string)
                    .map(DataType::from_name)
                    .unwrap_or_else(|| DataType::Unknown(String::new()));
                Self::DataRequest(DataRequest { data_type, message })
            }
            Some("ProgressMsg") => Self::Progress(ProgressMessage {
                operation: unsigned(&message, "Operation"),
                progress: unsigned(&message, "Progress"),
                message,
            }),
            Some("StatusMsg") => Self::Status(StatusMessage {
                status: unsigned(&message, "Status"),
                message,
            }),
            Some("BBUpdateStatusMsg") => Self::BasebandStatus(BasebandStatus { message }),
            Some("PreviousRestoreLogMsg") => Self::PreviousRestoreLog(message),
            _ => Self::Unknown {
                message_type,
                message,
            },
        }
    }
}

fn unsigned(dictionary: &Dictionary, key: &str) -> Option<u64> {
    dictionary.get(key).and_then(Value::as_unsigned_integer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_data_request_type() {
        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), "SystemImageData".into());

        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };
        assert_eq!(request.data_type(), &DataType::SystemImage);
    }
}
