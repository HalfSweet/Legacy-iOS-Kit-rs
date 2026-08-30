use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::{PlistFrameError, PlistFramed};

pub struct RestoredClient<S> {
    framed: PlistFramed<S>,
    label: String,
}

impl<S> RestoredClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, label: impl Into<String>) -> Self {
        Self {
            framed: PlistFramed::new(stream),
            label: label.into(),
        }
    }

    pub fn into_inner(self) -> S {
        self.framed.into_inner()
    }

    pub async fn query_type(&mut self) -> Result<RestoredType, RestoredError> {
        let request = self.request("QueryType");
        self.framed.send(&request).await?;
        let response = self.framed.receive().await?;
        let service_type = string(&response, "Type")?.to_owned();
        let protocol_version = unsigned_required(&response, "RestoreProtocolVersion")?;
        Ok(RestoredType {
            service_type,
            protocol_version,
            info: response,
        })
    }

    pub async fn query_value(&mut self, key: &str) -> Result<Value, RestoredError> {
        let mut request = self.request("QueryValue");
        request.insert("QueryKey".into(), key.into());
        self.framed.send(&request).await?;
        let mut response = self.framed.receive().await?;
        response
            .remove(key)
            .ok_or_else(|| RestoredError::MissingValue(key.to_owned()))
    }

    pub async fn start_restore(
        &mut self,
        options: Dictionary,
        protocol_version: u64,
    ) -> Result<(), RestoredError> {
        let mut request = self.request("StartRestore");
        request.insert("RestoreOptions".into(), options.into());
        request.insert("RestoreProtocolVersion".into(), protocol_version.into());
        self.framed.send(&request).await?;
        Ok(())
    }

    pub async fn reboot(&mut self) -> Result<(), RestoredError> {
        let request = self.request("Reboot");
        self.framed.send(&request).await?;
        self.framed.receive().await?;
        Ok(())
    }

    pub async fn goodbye(&mut self) -> Result<(), RestoredError> {
        let request = self.request("Goodbye");
        self.framed.send(&request).await?;
        let response = self.framed.receive().await?;
        if response.get("Result").and_then(Value::as_string) != Some("Success") {
            return Err(RestoredError::RequestFailed("Goodbye"));
        }
        Ok(())
    }

    pub async fn send(&mut self, message: &Dictionary) -> Result<(), RestoredError> {
        self.framed.send(message).await?;
        Ok(())
    }

    pub async fn next_message(&mut self) -> Result<RestoredMessage, RestoredError> {
        Ok(RestoredMessage::parse(self.framed.receive().await?))
    }

    fn request(&self, name: &str) -> Dictionary {
        let mut request = Dictionary::new();
        request.insert("Label".into(), self.label.clone().into());
        request.insert("Request".into(), name.into());
        request
    }
}

#[derive(Clone, Debug)]
pub struct RestoredType {
    service_type: String,
    protocol_version: u64,
    info: Dictionary,
}

impl RestoredType {
    pub fn service_type(&self) -> &str {
        &self.service_type
    }

    pub const fn protocol_version(&self) -> u64 {
        self.protocol_version
    }

    pub fn info(&self) -> &Dictionary {
        &self.info
    }
}

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

    pub fn data_port(&self) -> Option<u16> {
        unsigned(&self.message, "DataPort").and_then(|port| u16::try_from(port).ok())
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

fn string<'a>(dictionary: &'a Dictionary, key: &str) -> Result<&'a str, RestoredError> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .ok_or_else(|| RestoredError::MissingValue(key.to_owned()))
}

fn unsigned_required(dictionary: &Dictionary, key: &str) -> Result<u64, RestoredError> {
    unsigned(dictionary, key).ok_or_else(|| RestoredError::MissingValue(key.to_owned()))
}

#[derive(Debug, Error)]
pub enum RestoredError {
    #[error("restored plist protocol failed: {0}")]
    Frame(#[from] PlistFrameError),
    #[error("restored response is missing {0}")]
    MissingValue(String),
    #[error("restored request {0} failed")]
    RequestFailed(&'static str),
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

    #[tokio::test]
    async fn queries_restored_protocol_type() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = RestoredClient::new(client_stream, "test");
        let server = tokio::spawn(async move {
            let mut framed = PlistFramed::new(server_stream);
            let request = framed.receive().await.unwrap();
            assert_eq!(
                request.get("Request").and_then(Value::as_string),
                Some("QueryType")
            );

            let mut response = Dictionary::new();
            response.insert("Type".into(), "com.apple.mobile.restored".into());
            response.insert("RestoreProtocolVersion".into(), 15_u64.into());
            framed.send(&response).await.unwrap();
        });

        let response = client.query_type().await.unwrap();
        server.await.unwrap();
        assert_eq!(response.service_type(), "com.apple.mobile.restored");
        assert_eq!(response.protocol_version(), 15);
    }
}
