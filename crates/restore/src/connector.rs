use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use legacy_ios_core::Ecid;
use legacy_ios_services::{RawServiceConnection, ServiceError, SystemMux};
use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};
use tracing::{debug, info, warn};

use crate::{
    FDR_CONTROL_PORT, FdrConnection, FdrConnectionCommand, FdrControl, FdrControlCommand, FdrError,
    FdrProtocol, FdrProxyRequest, PlistFrameError, PlistFramed, RestoredClient, RestoredError,
};

const RESTORED_PORT: u16 = 62078;
const RESTORED_SERVICE: &str = "com.apple.mobile.restored";

#[derive(Clone, Debug, Default)]
pub struct RestoredConnector {
    mux: SystemMux,
}

impl RestoredConnector {
    pub async fn connect_by_ecid(
        &self,
        ecid: Ecid,
        timeout: Duration,
    ) -> Result<RestoredSession, RestoredConnectError> {
        let deadline = Instant::now() + timeout;
        loop {
            for device in self.mux.list_mux_devices().await? {
                let stream = match self
                    .mux
                    .connect_device_port(device.id(), RESTORED_PORT)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        debug!(device_id = device.id(), %error, "mux device is not accepting restored connections");
                        continue;
                    }
                };
                let mut client = RestoredClient::new(stream, "legacy-ios-kit");
                let service = match client.query_type().await {
                    Ok(service) if service.service_type() == RESTORED_SERVICE => service,
                    Ok(service) => {
                        debug!(
                            service = service.service_type(),
                            "mux device is not restored"
                        );
                        continue;
                    }
                    Err(error) => {
                        debug!(device_id = device.id(), %error, "restored handshake failed");
                        continue;
                    }
                };
                match restored_matches_ecid(&mut client, ecid).await {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        debug!(device_id = device.id(), %error, "restored device check failed");
                        continue;
                    }
                }
                info!(
                    protocol = service.protocol_version(),
                    "connected to restored"
                );
                return Ok(RestoredSession {
                    client,
                    protocol_version: service.protocol_version(),
                    data: RestoredDataConnector {
                        mux: self.mux.clone(),
                        device_id: device.id(),
                    },
                });
            }
            if Instant::now() >= deadline {
                return Err(RestoredConnectError::Timeout);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

pub struct RestoredSession {
    client: RestoredClient<RawServiceConnection>,
    protocol_version: u64,
    data: RestoredDataConnector,
}

impl RestoredSession {
    pub fn client_mut(&mut self) -> &mut RestoredClient<RawServiceConnection> {
        &mut self.client
    }

    pub const fn protocol_version(&self) -> u64 {
        self.protocol_version
    }

    pub fn data_connector(&self) -> RestoredDataConnector {
        self.data.clone()
    }

    pub fn into_client(self) -> RestoredClient<RawServiceConnection> {
        self.client
    }
}

impl fmt::Debug for RestoredSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredSession")
            .field("protocol_version", &self.protocol_version)
            .field("data", &self.data)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct RestoredDataConnector {
    mux: SystemMux,
    device_id: u32,
}

impl RestoredDataConnector {
    pub async fn connect(&self, port: u16) -> Result<RawServiceConnection, RestoredConnectError> {
        Ok(self.mux.connect_device_port(self.device_id, port).await?)
    }

    pub async fn send(&self, port: u16, response: &Dictionary) -> Result<(), RestoredConnectError> {
        let stream = self.connect(port).await?;
        let mut framed = PlistFramed::new(stream);
        framed.send(response).await?;
        Ok(())
    }

    pub async fn connect_fdr(
        &self,
        proxy: Arc<dyn FdrProxyConnector>,
    ) -> Result<FdrService, FdrServiceError> {
        let first = self.connect_fdr_control().await?;
        let control = match FdrControl::handshake_v2(first).await {
            Ok(control) => control,
            Err(error) => {
                debug!(%error, "FDR v2 handshake failed; retrying v1");
                let second = self.connect_fdr_control().await?;
                FdrControl::handshake_v1(second).await?
            }
        };
        Ok(FdrService {
            control,
            connector: self.clone(),
            proxy,
        })
    }

    async fn connect_fdr_control(&self) -> Result<RawServiceConnection, RestoredConnectError> {
        let mut last_error = None;
        for attempt in 1..=10 {
            match self.connect(FDR_CONTROL_PORT).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    debug!(attempt, %error, "FDR control port is not ready");
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        Err(last_error.expect("FDR connection attempt records an error"))
    }
}

pub trait FdrProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> FdrProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type FdrProxyFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn FdrProxyStream>, std::io::Error>> + Send>>;

pub trait FdrProxyConnector: Send + Sync + fmt::Debug {
    fn connect(&self, request: FdrProxyRequest) -> FdrProxyFuture;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpFdrProxyConnector;

impl FdrProxyConnector for TcpFdrProxyConnector {
    fn connect(&self, request: FdrProxyRequest) -> FdrProxyFuture {
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect((request.host(), request.port())).await?;
            Ok(Box::new(stream) as Box<dyn FdrProxyStream>)
        })
    }
}

pub struct FdrService {
    control: FdrControl<RawServiceConnection>,
    connector: RestoredDataConnector,
    proxy: Arc<dyn FdrProxyConnector>,
}

impl FdrService {
    pub async fn run(mut self) -> Result<(), FdrServiceError> {
        loop {
            match self.control.next_command().await? {
                FdrControlCommand::OpenConnection => {
                    let connector = self.connector.clone();
                    let proxy = Arc::clone(&self.proxy);
                    let protocol = self.control.protocol();
                    let port = self.control.connection_port();
                    tokio::spawn(async move {
                        if let Err(error) =
                            run_fdr_connection(connector, proxy, protocol, port).await
                        {
                            warn!(%error, "FDR data connection stopped");
                        }
                    });
                }
                FdrControlCommand::Unknown(command) => {
                    warn!(command, "ignoring unknown FDR control command")
                }
            }
        }
    }
}

impl fmt::Debug for FdrService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FdrService")
            .field("connector", &self.connector)
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

async fn run_fdr_connection(
    connector: RestoredDataConnector,
    proxy: Arc<dyn FdrProxyConnector>,
    protocol: FdrProtocol,
    port: u16,
) -> Result<(), FdrServiceError> {
    let stream = connector.connect(port).await?;
    let mut connection = FdrConnection::handshake(stream, protocol).await?;
    loop {
        match connection.next_command().await? {
            FdrConnectionCommand::Ping => {}
            FdrConnectionCommand::Proxy(request) => {
                let mut remote = proxy.connect(request).await?;
                let mut device = connection.into_inner();
                tokio::io::copy_bidirectional(&mut device, &mut remote).await?;
                return Ok(());
            }
            FdrConnectionCommand::Unknown(command) => {
                warn!(command, "ignoring unknown FDR data command")
            }
        }
    }
}

fn hardware_ecid(hardware: &Dictionary) -> Option<Ecid> {
    hardware
        .get("UniqueChipID")
        .and_then(Value::as_unsigned_integer)
        .map(Ecid::new)
}

/// ECID match of a mux device against the selected device. Pre-iOS 3 restored
/// does not implement the HardwareInfo query; when the device reports a
/// pre-iOS 3 ProductVersion, accept it without the ECID check (idevicerestore
/// restore.c:447-459 does the same off the target version, noting that
/// restoring multiple pre-iOS 3 devices at once is unsupported).
async fn restored_matches_ecid<S>(
    client: &mut RestoredClient<S>,
    ecid: Ecid,
) -> Result<bool, RestoredError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Ok(Value::Dictionary(hardware)) = client.query_value("HardwareInfo").await {
        return Ok(hardware_ecid(&hardware) == Some(ecid));
    }
    if let Ok(Value::String(version)) = client.query_value("ProductVersion").await
        && is_pre_ios3(&version)
    {
        debug!(%version, "pre-iOS 3 restored has no HardwareInfo; skipping the ECID check");
        return Ok(true);
    }
    Ok(false)
}

fn is_pre_ios3(version: &str) -> bool {
    matches!(version.split('.').next(), Some("1" | "2"))
}

#[derive(Debug, Error)]
pub enum RestoredConnectError {
    #[error("timed out waiting for the selected device in Restore mode")]
    Timeout,
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Restored(#[from] RestoredError),
    #[error(transparent)]
    Frame(#[from] PlistFrameError),
}

#[derive(Debug, Error)]
pub enum FdrServiceError {
    #[error(transparent)]
    Connect(#[from] RestoredConnectError),
    #[error(transparent)]
    Protocol(#[from] FdrError),
    #[error("FDR proxy connection failed: {0}")]
    Proxy(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlistFramed;

    #[test]
    fn reads_hardware_ecid() {
        let mut hardware = Dictionary::new();
        hardware.insert("UniqueChipID".into(), 42_u64.into());
        assert_eq!(hardware_ecid(&hardware), Some(Ecid::new(42)));
    }

    #[test]
    fn detects_pre_ios3_versions() {
        assert!(is_pre_ios3("2.2.1"));
        assert!(is_pre_ios3("1.1.4"));
        assert!(!is_pre_ios3("3.1.3"));
        assert!(!is_pre_ios3("10.3.3"));
    }

    #[tokio::test]
    async fn pre_ios3_restored_skips_the_hardware_info_check() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = RestoredClient::new(client_stream, "test");
        let server = tokio::spawn(async move {
            let mut framed = PlistFramed::new(server_stream);
            let request = framed.receive().await.unwrap();
            assert_eq!(
                request.get("QueryKey").and_then(Value::as_string),
                Some("HardwareInfo")
            );
            // Pre-iOS 3 restored answers with no value for unknown keys.
            framed.send(&Dictionary::new()).await.unwrap();

            let request = framed.receive().await.unwrap();
            assert_eq!(
                request.get("QueryKey").and_then(Value::as_string),
                Some("ProductVersion")
            );
            let mut response = Dictionary::new();
            response.insert("ProductVersion".into(), "2.2.1".into());
            framed.send(&response).await.unwrap();
        });

        let matches = restored_matches_ecid(&mut client, Ecid::new(42))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(matches);
    }

    #[tokio::test]
    async fn modern_restored_still_requires_a_matching_ecid() {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let mut client = RestoredClient::new(client_stream, "test");
        let server = tokio::spawn(async move {
            let mut framed = PlistFramed::new(server_stream);
            let request = framed.receive().await.unwrap();
            assert_eq!(
                request.get("QueryKey").and_then(Value::as_string),
                Some("HardwareInfo")
            );
            let mut response = Dictionary::new();
            let mut hardware = Dictionary::new();
            hardware.insert("UniqueChipID".into(), 43_u64.into());
            response.insert("HardwareInfo".into(), hardware.into());
            framed.send(&response).await.unwrap();
        });

        let matches = restored_matches_ecid(&mut client, Ecid::new(42))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(!matches);
    }
}
