use std::{fmt, time::Duration};

use legacy_ios_core::Ecid;
use legacy_ios_services::{RawServiceConnection, ServiceError, SystemMux};
use plist::{Dictionary, Value};
use thiserror::Error;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::{PlistFrameError, PlistFramed, RestoredClient, RestoredError};

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
