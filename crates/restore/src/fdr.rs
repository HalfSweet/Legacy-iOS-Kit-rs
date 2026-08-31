use std::io::Cursor;

use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

pub const FDR_CONTROL_PORT: u16 = 1082;

const MAX_PLIST_SIZE: usize = 1024 * 1024;
const COMMAND_SYNC: u16 = 0x0001;
const COMMAND_PROXY: u16 = 0x0105;
const COMMAND_PLIST: u16 = 0xbbaa;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdrProtocol {
    V1,
    V2,
}

pub struct FdrControl<S> {
    stream: S,
    protocol: FdrProtocol,
    connection_port: u16,
}

impl<S> FdrControl<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake_v2(mut stream: S) -> Result<Self, FdrError> {
        stream.write_all(b"BeginCtrl\0").await?;
        let mut request = Dictionary::new();
        request.insert("Command".into(), "BeginCtrl".into());
        request.insert("CtrlProtoVersion".into(), 2_u64.into());
        send_plist(&mut stream, &request).await?;
        let response = receive_plist(&mut stream).await?;
        let port = response
            .get("ConnPort")
            .and_then(Value::as_unsigned_integer)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(FdrError::MissingConnectionPort)?;
        debug!(protocol = 2, port, "completed FDR control handshake");
        Ok(Self {
            stream,
            protocol: FdrProtocol::V2,
            connection_port: port,
        })
    }

    pub async fn handshake_v1(mut stream: S) -> Result<Self, FdrError> {
        stream.write_all(b"HelloCtrl\0").await?;
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await?;
        if &reply != b"HelloCtrl\0" {
            return Err(FdrError::InvalidHandshake);
        }
        let port = stream.read_u16_le().await?;
        debug!(protocol = 1, port, "completed FDR control handshake");
        Ok(Self {
            stream,
            protocol: FdrProtocol::V1,
            connection_port: port,
        })
    }

    pub const fn protocol(&self) -> FdrProtocol {
        self.protocol
    }

    pub const fn connection_port(&self) -> u16 {
        self.connection_port
    }

    pub async fn next_command(&mut self) -> Result<FdrControlCommand, FdrError> {
        match self.stream.read_u16_le().await? {
            COMMAND_SYNC => {
                let mut trailer = [0; 2];
                self.stream.read_exact(&mut trailer).await?;
                Ok(FdrControlCommand::OpenConnection)
            }
            command => Ok(FdrControlCommand::Unknown(command)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdrControlCommand {
    OpenConnection,
    Unknown(u16),
}

pub struct FdrConnection<S> {
    stream: S,
}

impl<S> FdrConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(mut stream: S, protocol: FdrProtocol) -> Result<Self, FdrError> {
        stream.write_all(b"HelloConn\0").await?;
        match protocol {
            FdrProtocol::V1 => {
                let mut reply = [0; 10];
                stream.read_exact(&mut reply).await?;
                if &reply != b"HelloConn\0" {
                    return Err(FdrError::InvalidHandshake);
                }
            }
            FdrProtocol::V2 => {
                let response = receive_plist(&mut stream).await?;
                if response.get("Command").and_then(Value::as_string) != Some("HelloConn") {
                    return Err(FdrError::InvalidHandshake);
                }
            }
        }
        Ok(Self { stream })
    }

    pub async fn next_command(&mut self) -> Result<FdrConnectionCommand, FdrError> {
        match self.stream.read_u16_le().await? {
            COMMAND_PLIST => {
                let request = receive_plist(&mut self.stream).await?;
                if request.get("Command").and_then(Value::as_string) == Some("Ping") {
                    let mut response = Dictionary::new();
                    response.insert("Pong".into(), true.into());
                    send_plist(&mut self.stream, &response).await?;
                    Ok(FdrConnectionCommand::Ping)
                } else {
                    Err(FdrError::UnsupportedPlistCommand)
                }
            }
            COMMAND_PROXY => {
                let mut prefix = [0; 3];
                self.stream.read_exact(&mut prefix).await?;
                if prefix[..2] != [0, 3] || prefix[2] == 0 {
                    return Err(FdrError::InvalidProxyRequest);
                }
                let mut host = vec![0; usize::from(prefix[2])];
                self.stream.read_exact(&mut host).await?;
                let port = self.stream.read_u16().await?;
                self.stream.write_u16_le(5).await?;
                self.stream.write_all(&prefix).await?;
                self.stream.write_all(&host).await?;
                self.stream.write_u16(port).await?;
                let host = String::from_utf8(host).map_err(|_| FdrError::InvalidProxyRequest)?;
                Ok(FdrConnectionCommand::Proxy(FdrProxyRequest { host, port }))
            }
            command => Ok(FdrConnectionCommand::Unknown(command)),
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FdrConnectionCommand {
    Ping,
    Proxy(FdrProxyRequest),
    Unknown(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FdrProxyRequest {
    host: String,
    port: u16,
}

impl FdrProxyRequest {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

async fn send_plist<S>(stream: &mut S, dictionary: &Dictionary) -> Result<(), FdrError>
where
    S: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    Value::Dictionary(dictionary.clone()).to_writer_binary(&mut payload)?;
    let length = u32::try_from(payload.len()).map_err(|_| FdrError::PlistTooLarge)?;
    stream.write_u32_le(length).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    trace!(
        bytes = payload.len(),
        keys = dictionary.len(),
        "sent FDR plist"
    );
    Ok(())
}

async fn receive_plist<S>(stream: &mut S) -> Result<Dictionary, FdrError>
where
    S: AsyncRead + Unpin,
{
    let length =
        usize::try_from(stream.read_u32_le().await?).map_err(|_| FdrError::PlistTooLarge)?;
    if length > MAX_PLIST_SIZE {
        return Err(FdrError::PlistTooLarge);
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Value::from_reader(Cursor::new(payload))?
        .into_dictionary()
        .ok_or(FdrError::PlistNotDictionary)
}

#[derive(Debug, Error)]
pub enum FdrError {
    #[error("FDR I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("FDR plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("FDR plist exceeds 1 MiB")]
    PlistTooLarge,
    #[error("FDR plist root is not a dictionary")]
    PlistNotDictionary,
    #[error("FDR control reply has no connection port")]
    MissingConnectionPort,
    #[error("FDR handshake reply is invalid")]
    InvalidHandshake,
    #[error("FDR plist command is unsupported")]
    UnsupportedPlistCommand,
    #[error("FDR proxy request is invalid")]
    InvalidProxyRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn performs_v2_control_handshake() {
        let (client_stream, mut device_stream) = tokio::io::duplex(4096);
        let device = tokio::spawn(async move {
            let mut command = [0; 10];
            device_stream.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"BeginCtrl\0");
            let request = receive_plist(&mut device_stream).await.unwrap();
            assert_eq!(
                request.get("Command").and_then(Value::as_string),
                Some("BeginCtrl")
            );
            let mut response = Dictionary::new();
            response.insert("ConnPort".into(), 2345_u64.into());
            send_plist(&mut device_stream, &response).await.unwrap();
        });

        let control = FdrControl::handshake_v2(client_stream).await.unwrap();
        device.await.unwrap();
        assert_eq!(control.protocol(), FdrProtocol::V2);
        assert_eq!(control.connection_port(), 2345);
    }

    #[tokio::test]
    async fn handles_ping_and_proxy_prelude() {
        let (client_stream, mut device_stream) = tokio::io::duplex(4096);
        let device = tokio::spawn(async move {
            let mut command = [0; 10];
            device_stream.read_exact(&mut command).await.unwrap();
            let mut response = Dictionary::new();
            response.insert("Command".into(), "HelloConn".into());
            send_plist(&mut device_stream, &response).await.unwrap();

            device_stream.write_u16_le(COMMAND_PLIST).await.unwrap();
            let mut ping = Dictionary::new();
            ping.insert("Command".into(), "Ping".into());
            send_plist(&mut device_stream, &ping).await.unwrap();
            let pong = receive_plist(&mut device_stream).await.unwrap();
            assert_eq!(pong.get("Pong").and_then(Value::as_boolean), Some(true));

            device_stream.write_u16_le(COMMAND_PROXY).await.unwrap();
            device_stream.write_all(&[0, 3, 9]).await.unwrap();
            device_stream.write_all(b"localhost").await.unwrap();
            device_stream.write_u16(443).await.unwrap();
            assert_eq!(device_stream.read_u16_le().await.unwrap(), 5);
            let mut echoed = [0; 14];
            device_stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed[..3], &[0, 3, 9]);
        });

        let mut connection = FdrConnection::handshake(client_stream, FdrProtocol::V2)
            .await
            .unwrap();
        assert_eq!(
            connection.next_command().await.unwrap(),
            FdrConnectionCommand::Ping
        );
        let FdrConnectionCommand::Proxy(proxy) = connection.next_command().await.unwrap() else {
            panic!("expected proxy command");
        };
        assert_eq!(proxy.host(), "localhost");
        assert_eq!(proxy.port(), 443);
        device.await.unwrap();
    }
}
