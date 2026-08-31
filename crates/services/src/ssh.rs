use std::{borrow::Cow, fmt, str::FromStr, sync::Arc, time::Duration};

use russh::{
    ChannelMsg, Disconnect, client,
    keys::{Algorithm, EcdsaCurve, HashAlg, PublicKeyOrCertificate},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{ServiceError, SystemMux};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SshTarget {
    OnlyUsbDevice,
    DeviceId(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostKeyPolicy {
    AcceptEphemeral,
    Sha256(String),
}

pub struct SshPassword(Zeroizing<String>);

impl SshPassword {
    pub fn new(password: impl Into<String>) -> Self {
        Self(Zeroizing::new(password.into()))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ScpPath {
    path: String,
    parent: String,
    name: String,
}

impl ScpPath {
    pub fn new(path: impl Into<String>) -> Result<Self, ScpPathError> {
        let path = path.into();
        if path.is_empty() || path.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(ScpPathError);
        }
        let (parent, name) = path
            .rsplit_once('/')
            .map_or((".", path.as_str()), |(parent, name)| {
                (if parent.is_empty() { "/" } else { parent }, name)
            });
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(ScpPathError);
        }
        let parent = parent.to_owned();
        let name = name.to_owned();
        Ok(Self { path, parent, name })
    }

    pub fn as_str(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for ScpPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.fmt(formatter)
    }
}

impl FromStr for ScpPath {
    type Err = ScpPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid SCP remote path")]
pub struct ScpPathError;

impl fmt::Debug for SshPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SshPassword([REDACTED])")
    }
}

pub struct RamdiskSsh {
    session: client::Handle<ClientHandler>,
}

impl RamdiskSsh {
    pub async fn connect(
        mux: &SystemMux,
        target: SshTarget,
        username: &str,
        password: &SshPassword,
        host_key: HostKeyPolicy,
    ) -> Result<Self, SshError> {
        let devices = mux.list_mux_devices().await?;
        let device_id = match target {
            SshTarget::OnlyUsbDevice => match devices.as_slice() {
                [device] => device.id(),
                [] => return Err(SshError::NoDevice),
                devices => return Err(SshError::AmbiguousDevices(devices.len())),
            },
            SshTarget::DeviceId(device_id) => devices
                .iter()
                .find(|device| device.id() == device_id)
                .map(|device| device.id())
                .ok_or(SshError::NoDevice)?,
        };
        let stream = mux.connect_device_port(device_id, 22).await?;
        let config = Arc::new(legacy_config());
        let handler = ClientHandler { host_key };
        let mut session = client::connect_stream(config, stream, handler).await?;
        let authentication = session
            .authenticate_password(username.to_owned(), password.expose().to_owned())
            .await?;
        if !authentication.success() {
            return Err(SshError::AuthenticationRejected);
        }
        Ok(Self { session })
    }

    pub async fn execute(&self, command: &str) -> Result<SshCommandOutput, SshError> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = Some(status),
                _ => {}
            }
        }
        Ok(SshCommandOutput {
            stdout,
            stderr,
            exit_status,
        })
    }

    pub async fn upload(&self, destination: &ScpPath, data: &[u8]) -> Result<(), SshError> {
        let channel = self.session.channel_open_session().await?;
        channel
            .exec(true, format!("scp -t {}", shell_quote(&destination.parent)))
            .await?;
        let mut stream = channel.into_stream();
        read_scp_ack(&mut stream).await?;
        stream
            .write_all(format!("C0644 {} {}\n", data.len(), destination.name).as_bytes())
            .await?;
        stream.flush().await?;
        read_scp_ack(&mut stream).await?;
        stream.write_all(data).await?;
        stream.write_u8(0).await?;
        stream.flush().await?;
        read_scp_ack(&mut stream).await?;
        stream.shutdown().await?;
        Ok(())
    }

    pub async fn download(&self, source: &ScpPath, maximum_size: u64) -> Result<Vec<u8>, SshError> {
        let channel = self.session.channel_open_session().await?;
        channel
            .exec(true, format!("scp -f {}", shell_quote(source.as_str())))
            .await?;
        let mut stream = channel.into_stream();
        stream.write_u8(0).await?;
        stream.flush().await?;
        loop {
            let line = read_scp_line(&mut stream).await?;
            match line.first().copied() {
                Some(b'T') => {
                    stream.write_u8(0).await?;
                    stream.flush().await?;
                }
                Some(b'C') => {
                    let header = std::str::from_utf8(&line[1..])
                        .map_err(|_| SshError::Scp("non-UTF-8 file header".into()))?;
                    let mut fields = header.trim_end().splitn(3, ' ');
                    let _mode = fields.next().ok_or_else(invalid_scp_header)?;
                    let size = fields
                        .next()
                        .ok_or_else(invalid_scp_header)?
                        .parse::<u64>()
                        .map_err(|_| invalid_scp_header())?;
                    let _name = fields.next().ok_or_else(invalid_scp_header)?;
                    if size > maximum_size {
                        return Err(SshError::ScpFileTooLarge {
                            size,
                            maximum: maximum_size,
                        });
                    }
                    stream.write_u8(0).await?;
                    stream.flush().await?;
                    let size = usize::try_from(size).map_err(|_| SshError::ScpFileTooLarge {
                        size,
                        maximum: maximum_size,
                    })?;
                    let mut data = vec![0; size];
                    stream.read_exact(&mut data).await?;
                    if stream.read_u8().await? != 0 {
                        return Err(SshError::Scp("missing file terminator".into()));
                    }
                    stream.write_u8(0).await?;
                    stream.flush().await?;
                    stream.shutdown().await?;
                    return Ok(data);
                }
                Some(1 | 2) => {
                    return Err(SshError::Scp(
                        String::from_utf8_lossy(&line[1..]).trim().to_owned(),
                    ));
                }
                _ => return Err(invalid_scp_header()),
            }
        }
    }

    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

impl fmt::Debug for RamdiskSsh {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RamdiskSsh").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
}

impl SshCommandOutput {
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub const fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    pub fn success(&self) -> bool {
        self.exit_status == Some(0)
    }
}

#[derive(Clone)]
struct ClientHandler {
    host_key: HostKeyPolicy,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match &self.host_key {
            HostKeyPolicy::AcceptEphemeral => true,
            HostKeyPolicy::Sha256(expected) => {
                key.public_key().fingerprint(HashAlg::Sha256).to_string() == *expected
            }
        })
    }
}

fn legacy_config() -> client::Config {
    let preferred = russh::Preferred {
        kex: Cow::Owned(vec![
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
            russh::kex::DH_G14_SHA256,
            russh::kex::DH_G14_SHA1,
            russh::kex::DH_G1_SHA1,
            russh::kex::DH_GEX_SHA1,
            russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
        ]),
        key: Cow::Owned(vec![
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa { hash: None },
            Algorithm::Dsa,
        ]),
        cipher: Cow::Owned(vec![
            russh::cipher::AES_256_CTR,
            russh::cipher::AES_128_CTR,
            russh::cipher::AES_256_CBC,
            russh::cipher::AES_192_CBC,
            russh::cipher::AES_128_CBC,
            russh::cipher::TRIPLE_DES_CBC,
        ]),
        mac: Cow::Owned(vec![russh::mac::HMAC_SHA256, russh::mac::HMAC_SHA1]),
        ..Default::default()
    };
    client::Config {
        preferred,
        inactivity_timeout: Some(Duration::from_secs(30)),
        keepalive_interval: Some(Duration::from_secs(5)),
        ..Default::default()
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

async fn read_scp_ack(stream: &mut (impl AsyncRead + Unpin)) -> Result<(), SshError> {
    match stream.read_u8().await? {
        0 => Ok(()),
        code @ (1 | 2) => {
            let message = read_scp_line(stream).await?;
            Err(SshError::Scp(format!(
                "remote error {code}: {}",
                String::from_utf8_lossy(&message).trim()
            )))
        }
        code => Err(SshError::Scp(format!("unexpected ACK {code}"))),
    }
}

async fn read_scp_line(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, SshError> {
    let mut line = Vec::new();
    loop {
        if line.len() == 4096 {
            return Err(SshError::Scp("protocol line is too long".into()));
        }
        let byte = stream.read_u8().await?;
        line.push(byte);
        if byte == b'\n' {
            return Ok(line);
        }
    }
}

fn invalid_scp_header() -> SshError {
    SshError::Scp("invalid file header".into())
}

#[derive(Debug, Error)]
pub enum SshError {
    #[error("no USB mux device is available for SSH")]
    NoDevice,
    #[error("multiple USB mux devices are available for SSH ({0})")]
    AmbiguousDevices(usize),
    #[error("SSH authentication was rejected")]
    AuthenticationRejected,
    #[error("SCP protocol failed: {0}")]
    Scp(String),
    #[error("SCP file is {size} bytes, exceeding {maximum}")]
    ScpFileTooLarge { size: u64, maximum: u64 },
    #[error("SSH I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("SSH protocol failed: {0}")]
    Protocol(#[from] russh::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enables_dropbear_legacy_algorithms() {
        let config = legacy_config();
        assert!(config.preferred.kex.contains(&russh::kex::DH_G1_SHA1));
        assert!(
            config
                .preferred
                .cipher
                .contains(&russh::cipher::TRIPLE_DES_CBC)
        );
        assert!(config.preferred.key.contains(&Algorithm::Dsa));
    }

    #[test]
    fn quotes_scp_paths_for_remote_shell() {
        assert_eq!(shell_quote("/tmp/it's here"), "'/tmp/it'\\''s here'");
        assert!(ScpPath::new("/tmp/file\nname").is_err());
    }
}
