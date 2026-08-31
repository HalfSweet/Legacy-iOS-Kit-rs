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
                let hardware = match client.query_value("HardwareInfo").await {
                    Ok(Value::Dictionary(hardware)) => hardware,
                    _ => continue,
                };
                if hardware_ecid(&hardware) != Some(ecid) {
                    continue;
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

    #[test]
    fn reads_hardware_ecid() {
        let mut hardware = Dictionary::new();
        hardware.insert("UniqueChipID".into(), 42_u64.into());
        assert_eq!(hardware_ecid(&hardware), Some(Ecid::new(42)));
    }
}
