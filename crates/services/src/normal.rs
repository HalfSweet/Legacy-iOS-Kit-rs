use std::{
    fmt,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use idevice::{
    IdeviceService,
    provider::IdeviceProvider,
    services::{diagnostics_relay::DiagnosticsRelayClient, lockdown::LockdownClient},
    usbmuxd::{Connection, UsbmuxdAddr},
};
use legacy_ios_core::{BoardConfig, Ecid, ProductType, Udid};
use plist::Dictionary;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info};

#[derive(Clone, Debug, Default)]
pub struct SystemMux {
    address: UsbmuxdAddr,
}

impl SystemMux {
    pub async fn list_devices(&self) -> Result<Vec<NormalDevice>, ServiceError> {
        let mut connection = self.address.connect(0).await?;
        let devices = connection
            .get_devices()
            .await?
            .into_iter()
            .filter(|device| device.connection_type == Connection::Usb)
            .map(|device| {
                let udid = Udid::new(device.udid.clone());
                let provider = device.to_provider(self.address.clone(), "legacy-ios-kit");
                NormalDevice {
                    udid,
                    provider: Arc::new(provider),
                    system_mux: Some(self.address.clone()),
                }
            })
            .collect::<Vec<_>>();
        debug!(
            count = devices.len(),
            "listed normal-mode devices through system mux"
        );
        Ok(devices)
    }

    pub async fn find_device(&self, udid: &Udid) -> Result<NormalDevice, ServiceError> {
        let mut connection = self.address.connect(0).await?;
        let device = connection.get_device(udid.as_str()).await?;
        let provider = device.to_provider(self.address.clone(), "legacy-ios-kit");
        Ok(NormalDevice {
            udid: udid.clone(),
            provider: Arc::new(provider),
            system_mux: Some(self.address.clone()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct NormalDevice {
    udid: Udid,
    provider: Arc<dyn IdeviceProvider>,
    system_mux: Option<UsbmuxdAddr>,
}

impl NormalDevice {
    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    pub(crate) fn provider(&self) -> &dyn IdeviceProvider {
        self.provider.as_ref()
    }

    pub(crate) async fn connect_service(
        &self,
        identifier: &str,
    ) -> Result<RawServiceConnection, ServiceError> {
        let mut lockdown = LockdownClient::connect(self.provider()).await?;
        let product_version = lockdown
            .get_value(Some("ProductVersion"), None)
            .await?
            .as_string()
            .map(ToOwned::to_owned)
            .ok_or(ServiceError::UnexpectedValue("ProductVersion"))?;
        let pairing = self.provider.get_pairing_file().await?;
        lockdown.start_session(&pairing).await?;
        let (port, ssl) = lockdown.start_service(identifier).await?;
        let mut connection = self.provider.connect(port).await?;
        if ssl {
            let legacy = product_version
                .split('.')
                .next()
                .and_then(|value| value.parse::<u8>().ok())
                .is_some_and(|major| major < 5);
            connection.start_session(&pairing, legacy).await?;
        }
        let inner = connection.get_socket().ok_or(ServiceError::MissingSocket)?;
        Ok(RawServiceConnection { inner })
    }

    pub async fn query_info(&self) -> Result<NormalDeviceInfo, ServiceError> {
        let mut lockdown = LockdownClient::connect(self.provider.as_ref()).await?;
        let product_type = get_string(&mut lockdown, "ProductType").await?;
        let hardware_model = get_string(&mut lockdown, "HardwareModel").await?;
        let product_version = get_string(&mut lockdown, "ProductVersion").await?;
        let build_version = get_string(&mut lockdown, "BuildVersion").await?;
        let ecid = get_u64(&mut lockdown, "UniqueChipID").await?;
        let device_name = get_string(&mut lockdown, "DeviceName").await?;

        let info = NormalDeviceInfo {
            udid: self.udid.clone(),
            ecid: Ecid::new(ecid),
            product_type: ProductType::new(product_type),
            board_config: BoardConfig::new(normalize_board_config(&hardware_model)),
            product_version,
            build_version,
            device_name,
        };
        info!(
            product_type = %info.product_type,
            version = %info.product_version,
            build = %info.build_version,
            "queried normal-mode device"
        );
        Ok(info)
    }

    pub async fn connect_port(&self, port: u16) -> Result<RawServiceConnection, ServiceError> {
        let connection = self.provider.connect(port).await?;
        let inner = connection.get_socket().ok_or(ServiceError::MissingSocket)?;
        Ok(RawServiceConnection { inner })
    }

    pub async fn pair(&self) -> Result<(), ServiceError> {
        let address = self
            .system_mux
            .as_ref()
            .ok_or(ServiceError::PairStoreUnavailable)?;
        let mut mux = address.connect(0).await?;
        let buid = mux.get_buid().await?;
        let mut lockdown = LockdownClient::connect(self.provider.as_ref()).await?;
        let mut pairing = lockdown
            .pair(uuid::Uuid::new_v4().to_string().to_uppercase(), buid)
            .await?;
        pairing.udid = Some(self.udid.to_string());
        let serialized = pairing.serialize()?;
        mux.save_pair_record(self.udid.as_str(), serialized).await?;
        info!("paired normal-mode device");
        Ok(())
    }

    pub async fn battery_info(&self) -> Result<Dictionary, ServiceError> {
        let mut diagnostics = DiagnosticsRelayClient::connect(self.provider.as_ref()).await?;
        diagnostics
            .gasguage()
            .await?
            .ok_or(ServiceError::MissingDiagnostics)
    }

    pub async fn restart(&self) -> Result<(), ServiceError> {
        let mut diagnostics = DiagnosticsRelayClient::connect(self.provider.as_ref()).await?;
        diagnostics.restart().await?;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), ServiceError> {
        let mut diagnostics = DiagnosticsRelayClient::connect(self.provider.as_ref()).await?;
        diagnostics.shutdown().await?;
        Ok(())
    }
}

pub struct RawServiceConnection {
    inner: Box<dyn idevice::ReadWrite>,
}

impl fmt::Debug for RawServiceConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawServiceConnection")
            .finish_non_exhaustive()
    }
}

impl AsyncRead for RawServiceConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for RawServiceConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut *self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NormalDeviceInfo {
    udid: Udid,
    ecid: Ecid,
    product_type: ProductType,
    board_config: BoardConfig,
    product_version: String,
    build_version: String,
    device_name: String,
}

impl NormalDeviceInfo {
    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    pub const fn ecid(&self) -> Ecid {
        self.ecid
    }

    pub fn product_type(&self) -> &ProductType {
        &self.product_type
    }

    pub fn board_config(&self) -> &BoardConfig {
        &self.board_config
    }

    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    pub fn build_version(&self) -> &str {
        &self.build_version
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }
}

async fn get_string(
    client: &mut LockdownClient,
    key: &'static str,
) -> Result<String, ServiceError> {
    let value = client.get_value(Some(key), None).await?;
    value
        .as_string()
        .map(ToOwned::to_owned)
        .ok_or(ServiceError::UnexpectedValue(key))
}

async fn get_u64(client: &mut LockdownClient, key: &'static str) -> Result<u64, ServiceError> {
    let value = client.get_value(Some(key), None).await?;
    value
        .as_unsigned_integer()
        .ok_or(ServiceError::UnexpectedValue(key))
}

fn normalize_board_config(hardware_model: &str) -> String {
    let normalized = hardware_model.to_ascii_lowercase();
    normalized
        .strip_suffix("ap")
        .unwrap_or(&normalized)
        .to_owned()
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("iOS device service failed: {0}")]
    Idevice(#[from] idevice::IdeviceError),
    #[error("lockdown returned an unexpected value for {0}")]
    UnexpectedValue(&'static str),
    #[error("iOS service connection did not expose a socket")]
    MissingSocket,
    #[error("pairing record storage is unavailable for this transport")]
    PairStoreUnavailable,
    #[error("device returned no diagnostics payload")]
    MissingDiagnostics,
    #[error("invalid IPA path")]
    InvalidIpaPath,
    #[error("device file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("device plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("device plist frame is too large")]
    FrameTooLarge,
    #[error("device plist root is not a dictionary")]
    PlistNotDictionary,
    #[error("app installation failed: {0}")]
    AppInstallation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_lockdown_hardware_model() {
        assert_eq!(normalize_board_config("N90AP"), "n90");
        assert_eq!(normalize_board_config("j71"), "j71");
    }
}
