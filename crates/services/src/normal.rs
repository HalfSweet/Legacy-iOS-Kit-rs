use std::{
    collections::HashMap,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use idevice::{
    Idevice, IdeviceError, IdeviceService,
    pairing_file::PairingFile,
    provider::IdeviceProvider,
    services::{
        diagnostics_relay::DiagnosticsRelayClient, lockdown::LockdownClient,
        syslog_relay::SyslogRelayClient,
    },
    usbmuxd::UsbmuxdAddr,
};
use legacy_ios_core::{BoardConfig, DeviceMode, Ecid, ProductType, Udid};
use legacy_ios_transport::classify_apple_mode;
use plist::{Dictionary, Value};
use rusbmux::{device::Device, provider::RusbmuxProvider, usb_backend::AnyDeviceInfo};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::RwLock,
};
use tracing::{debug, info, warn};

use crate::plist_service::PropertyListService;

#[derive(Clone, Debug, Default)]
pub struct SystemMux {
    address: UsbmuxdAddr,
}

impl SystemMux {
    pub async fn list_mux_devices(&self) -> Result<Vec<MuxDevice>, ServiceError> {
        Ok(crate::system_mux::list()
            .await?
            .into_iter()
            .map(|device| MuxDevice {
                id: device.device_id,
                udid: Udid::new(device.udid),
            })
            .collect())
    }

    pub async fn connect_device_port(
        &self,
        device_id: u32,
        port: u16,
    ) -> Result<RawServiceConnection, ServiceError> {
        let connection = self
            .address
            .connect(0)
            .await?
            .connect_to_device(device_id, port, "legacy-ios-kit")
            .await?;
        let inner = connection.get_socket().ok_or(ServiceError::MissingSocket)?;
        Ok(RawServiceConnection { inner })
    }

    pub async fn list_devices(&self) -> Result<Vec<NormalDevice>, ServiceError> {
        let devices = crate::system_mux::list()
            .await?
            .into_iter()
            .map(|device| {
                let udid = Udid::new(device.udid.clone());
                let provider = device.to_provider(self.address.clone(), "legacy-ios-kit");
                NormalDevice {
                    udid,
                    provider: Arc::new(provider),
                    pairing: PairingBackend::System,
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
        let device = crate::system_mux::list()
            .await?
            .into_iter()
            .find(|device| device.udid == udid.as_str())
            .ok_or(ServiceError::DeviceNotFound)?;
        let provider = device.to_provider(self.address.clone(), "legacy-ios-kit");
        Ok(NormalDevice {
            udid: udid.clone(),
            provider: Arc::new(provider),
            pairing: PairingBackend::System,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NormalBackend {
    #[default]
    Auto,
    System,
    Direct,
}

#[derive(Clone, Debug)]
pub struct NormalMux {
    backend: NormalBackend,
    system: SystemMux,
    direct: DirectMux,
}

impl NormalMux {
    pub fn new(backend: NormalBackend) -> Self {
        Self {
            backend,
            system: SystemMux::default(),
            direct: DirectMux::default(),
        }
    }

    pub const fn backend(&self) -> NormalBackend {
        self.backend
    }

    pub async fn list_devices(&self) -> Result<Vec<NormalDevice>, ServiceError> {
        match self.backend {
            NormalBackend::System => self.system.list_devices().await,
            NormalBackend::Direct => self.direct.list_devices().await,
            NormalBackend::Auto => match self.system.list_devices().await {
                Ok(devices) => Ok(devices),
                Err(error) => {
                    warn!(%error, "system mux unavailable; using direct USB backend");
                    self.direct.list_devices().await
                }
            },
        }
    }

    pub async fn find_device(&self, udid: &Udid) -> Result<NormalDevice, ServiceError> {
        match self.backend {
            NormalBackend::System => self.system.find_device(udid).await,
            NormalBackend::Direct => self.direct.find_device(udid).await,
            NormalBackend::Auto => match self.system.find_device(udid).await {
                Ok(device) => Ok(device),
                Err(error) => {
                    warn!(%error, "device unavailable through system mux; using direct USB backend");
                    self.direct.find_device(udid).await
                }
            },
        }
    }

    pub async fn import_pairing_record(
        &self,
        udid: Udid,
        record: PairingRecord,
    ) -> Option<PairingRecord> {
        self.direct.import_pairing_record(udid, record).await
    }

    pub async fn pairing_record(&self, udid: &Udid) -> Option<PairingRecord> {
        self.direct.pairing_record(udid).await
    }
}

impl Default for NormalMux {
    fn default() -> Self {
        Self::new(NormalBackend::Auto)
    }
}

type PairingRecords = Arc<RwLock<HashMap<Udid, PairingFile>>>;

#[derive(Clone, Default)]
pub struct DirectMux {
    pairing_records: PairingRecords,
}

impl fmt::Debug for DirectMux {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DirectMux").finish_non_exhaustive()
    }
}

impl DirectMux {
    pub async fn list_devices(&self) -> Result<Vec<NormalDevice>, ServiceError> {
        let mut devices = Vec::new();
        for info in direct_device_infos().await? {
            devices.push(self.open_device(info).await?);
        }
        debug!(
            count = devices.len(),
            "listed normal-mode devices through direct USB"
        );
        Ok(devices)
    }

    pub async fn find_device(&self, udid: &Udid) -> Result<NormalDevice, ServiceError> {
        let info = direct_device_infos()
            .await?
            .find(|info| info.serial_number() == Some(udid.as_str()))
            .ok_or(ServiceError::DeviceNotFound)?;
        self.open_device(info).await
    }

    pub async fn import_pairing_record(
        &self,
        udid: Udid,
        record: PairingRecord,
    ) -> Option<PairingRecord> {
        self.pairing_records
            .write()
            .await
            .insert(udid, record.0)
            .map(PairingRecord)
    }

    pub async fn pairing_record(&self, udid: &Udid) -> Option<PairingRecord> {
        self.pairing_records
            .read()
            .await
            .get(udid)
            .cloned()
            .map(PairingRecord)
    }

    async fn open_device(&self, info: nusb::DeviceInfo) -> Result<NormalDevice, ServiceError> {
        let udid = Udid::new(
            info.serial_number()
                .ok_or(ServiceError::MissingUdid)?
                .to_owned(),
        );
        let id = direct_device_id(info.id());
        let device = Device::new_usb(AnyDeviceInfo::Nusb(info), id).await?;
        let device = device
            .as_usb()
            .expect("new USB device must remain USB")
            .clone();
        let provider = DirectProvider {
            inner: RusbmuxProvider::new(device, "legacy-ios-kit".into()),
            pairing_records: Arc::clone(&self.pairing_records),
            udid: udid.clone(),
        };

        Ok(NormalDevice {
            udid,
            provider: Arc::new(provider),
            pairing: PairingBackend::Direct(Arc::clone(&self.pairing_records)),
        })
    }
}

#[derive(Clone)]
pub struct PairingRecord(PairingFile);

impl PairingRecord {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ServiceError> {
        Ok(Self(PairingFile::from_bytes(bytes)?))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ServiceError> {
        Ok(self.0.clone().serialize()?)
    }
}

impl fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .finish_non_exhaustive()
    }
}

struct DirectProvider {
    inner: RusbmuxProvider,
    pairing_records: PairingRecords,
    udid: Udid,
}

impl fmt::Debug for DirectProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectProvider")
            .finish_non_exhaustive()
    }
}

impl IdeviceProvider for DirectProvider {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        self.inner.connect(port)
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        let pairing_records = Arc::clone(&self.pairing_records);
        let udid = self.udid.clone();
        Box::pin(async move {
            pairing_records
                .read()
                .await
                .get(&udid)
                .cloned()
                .ok_or(IdeviceError::NotFound)
        })
    }
}

async fn direct_device_infos() -> Result<impl Iterator<Item = nusb::DeviceInfo>, ServiceError> {
    Ok(nusb::list_devices().await?.filter(|info| {
        classify_apple_mode(info.vendor_id(), info.product_id()) == Some(DeviceMode::Normal)
    }))
}

fn direct_device_id(id: nusb::DeviceId) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxDevice {
    id: u32,
    udid: Udid,
}

impl MuxDevice {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn udid(&self) -> &Udid {
        &self.udid
    }
}

#[derive(Clone, Debug)]
pub struct NormalDevice {
    udid: Udid,
    provider: Arc<dyn IdeviceProvider>,
    pairing: PairingBackend,
}

#[derive(Clone)]
enum PairingBackend {
    System,
    Direct(PairingRecords),
}

impl fmt::Debug for PairingBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => formatter.write_str("System"),
            Self::Direct(_) => formatter.write_str("Direct"),
        }
    }
}

impl NormalDevice {
    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    /// Open an existing authenticated pairing. This never pairs the device.
    pub async fn session(&self) -> Result<crate::DeviceSession, ServiceError> {
        crate::DeviceSession::open(self).await
    }

    pub(crate) async fn pairing_file(&self) -> Result<PairingFile, ServiceError> {
        match &self.pairing {
            PairingBackend::System => crate::system_mux::pairing(self.udid.as_str()).await,
            PairingBackend::Direct(records) => records
                .read()
                .await
                .get(&self.udid)
                .cloned()
                .ok_or(ServiceError::Idevice(IdeviceError::InvalidHostID)),
        }
    }

    pub(crate) async fn connect_service(
        &self,
        identifier: &str,
    ) -> Result<RawServiceConnection, ServiceError> {
        let mut session = self.session().await?;
        let result = session.service(self, identifier).await;
        let _ = session.close().await;
        result
    }

    pub(crate) async fn service_client<T: IdeviceService>(&self) -> Result<T, ServiceError> {
        let connection = self.connect_service(T::service_name().as_ref()).await?;
        Ok(T::from_stream(Idevice::new(Box::new(connection), "legacy-ios-kit")).await?)
    }

    pub async fn query_info(&self) -> Result<NormalDeviceInfo, ServiceError> {
        let keys = [
            "ProductType",
            "HardwareModel",
            "ProductVersion",
            "BuildVersion",
            "UniqueChipID",
            "DeviceName",
        ];
        let values = match crate::session::unpaired_values(self, &keys).await {
            Ok(values) => values,
            Err(ServiceError::LockdownRejected { code, .. }) if code == "GetProhibited" => {
                let mut session = self.session().await?;
                let mut values = Dictionary::new();
                for key in keys {
                    values.insert(key.into(), session.get_value(Some(key), None).await?);
                }
                let _ = session.close().await;
                values
            }
            Err(error) => return Err(error),
        };
        let info = NormalDeviceInfo::from_values(self.udid.clone(), &values)?;
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
        let buid = match &self.pairing {
            PairingBackend::System => crate::system_mux::buid().await?,
            PairingBackend::Direct(_) => uuid::Uuid::new_v4().to_string().to_uppercase(),
        };
        let mut lockdown = LockdownClient::connect(self.provider.as_ref()).await?;
        let mut pairing = lockdown
            .pair(
                uuid::Uuid::new_v4().to_string().to_uppercase(),
                buid,
                Some("legacy-ios-kit"),
            )
            .await?;
        pairing.udid = Some(self.udid.to_string());
        match &self.pairing {
            PairingBackend::System => {
                crate::system_mux::save_pairing(self.udid.as_str(), pairing.serialize()?).await?;
            }
            PairingBackend::Direct(records) => {
                records.write().await.insert(self.udid.clone(), pairing);
            }
        }
        info!("paired normal-mode device");
        Ok(())
    }

    pub async fn battery_info(&self) -> Result<Dictionary, ServiceError> {
        let mut diagnostics = self.service_client::<DiagnosticsRelayClient>().await?;
        diagnostics
            .gasguage()
            .await?
            .ok_or(ServiceError::MissingDiagnostics)
    }

    pub async fn restart(&self) -> Result<(), ServiceError> {
        let mut diagnostics = self.service_client::<DiagnosticsRelayClient>().await?;
        diagnostics.restart().await?;
        Ok(())
    }

    /// Whether the device encrypts its backups (`WillEncrypt` in the
    /// `com.apple.mobile.backup` lockdown domain).
    pub async fn will_encrypt_backup(&self) -> Result<bool, ServiceError> {
        let mut lockdown = self.session().await?;
        let value = lockdown
            .get_value(Some("WillEncrypt"), Some("com.apple.mobile.backup"))
            .await?;
        let _ = lockdown.close().await;
        Ok(value.as_boolean().unwrap_or(false))
    }

    /// Crash iOS 5-era lockdownd with a malformed Pair request (PairRecord
    /// must be a dictionary; a boolean dereferences a null plist node).
    /// lockdownd restarts itself shortly after. Used by the g1lbertJB
    /// jailbreak to race launchd socket creation.
    pub async fn crash_lockdownd(&self) -> Result<(), ServiceError> {
        let stream = self.connect_port(LockdownClient::LOCKDOWND_PORT).await?;
        let mut lockdown = PropertyListService::new(stream);
        let mut request = Dictionary::new();
        request.insert("Label".into(), "legacy-ios-kit".into());
        request.insert("Request".into(), "Pair".into());
        request.insert("PairRecord".into(), Value::Boolean(false));
        lockdown.send(&request).await?;
        // The daemon may crash without replying; either a reply or an I/O
        // error means the packet landed.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), lockdown.receive()).await;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), ServiceError> {
        let mut diagnostics = self.service_client::<DiagnosticsRelayClient>().await?;
        diagnostics.shutdown().await?;
        Ok(())
    }

    pub async fn enter_recovery(&self) -> Result<(), ServiceError> {
        let stream = self.connect_port(LockdownClient::LOCKDOWND_PORT).await?;
        let mut lockdown = PropertyListService::new(stream);
        let mut request = Dictionary::new();
        request.insert("Label".into(), "legacy-ios-kit".into());
        request.insert("Request".into(), "EnterRecovery".into());
        lockdown.send(&request).await?;
        let response = lockdown.receive().await?;
        if response.get("Result").and_then(plist::Value::as_string) == Some("Success") {
            Ok(())
        } else {
            Err(ServiceError::EnterRecoveryRejected)
        }
    }

    pub async fn syslog(&self) -> Result<DeviceSyslog, ServiceError> {
        Ok(DeviceSyslog {
            client: self.service_client::<SyslogRelayClient>().await?,
        })
    }
}

#[derive(Debug)]
pub struct DeviceSyslog {
    client: SyslogRelayClient,
}

impl DeviceSyslog {
    pub async fn next_line(&mut self) -> Result<String, ServiceError> {
        Ok(self.client.next().await?)
    }
}

pub struct RawServiceConnection {
    inner: Box<dyn idevice::ReadWrite>,
}

impl RawServiceConnection {
    pub(crate) fn new(inner: Box<dyn idevice::ReadWrite>) -> Self {
        Self { inner }
    }
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
    pub(crate) fn from_values(udid: Udid, values: &Dictionary) -> Result<Self, ServiceError> {
        let hardware_model = get_string(values, "HardwareModel")?;
        let product_type = if hardware_model.eq_ignore_ascii_case("n81ap") {
            "iPod4,1".into()
        } else {
            get_string(values, "ProductType")?
        };
        let product_version = get_string(values, "ProductVersion")?;
        let build_version = get_string(values, "BuildVersion")?;
        let ecid = values
            .get("UniqueChipID")
            .and_then(Value::as_unsigned_integer)
            .ok_or(ServiceError::UnexpectedValue("UniqueChipID"))?;
        let device_name = get_string(values, "DeviceName")?;

        let info = NormalDeviceInfo {
            udid,
            ecid: Ecid::new(ecid),
            product_type: ProductType::new(product_type),
            board_config: BoardConfig::new(normalize_board_config(&hardware_model)),
            product_version,
            build_version,
            device_name,
        };
        Ok(info)
    }

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

fn get_string(values: &Dictionary, key: &'static str) -> Result<String, ServiceError> {
    values
        .get(key)
        .and_then(Value::as_string)
        .map(str::to_owned)
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
    #[error("legacy iOS TLS requires the legacy-tls Cargo feature")]
    LegacyTlsUnavailable,
    #[cfg(feature = "legacy-tls")]
    #[error(transparent)]
    LegacyTls(#[from] crate::LegacyTlsError),
    #[error("lockdown rejected {request}: {code}")]
    LockdownRejected { request: &'static str, code: String },
    #[error("paired device session timed out")]
    SessionTimeout,
    #[error("usbmux request failed with code {0}")]
    MuxRequestRejected(u64),
    #[error("iOS device service failed: {0}")]
    Idevice(#[from] idevice::IdeviceError),
    #[error("lockdown returned an unexpected value for {0}")]
    UnexpectedValue(&'static str),
    #[error("iOS service connection did not expose a socket")]
    MissingSocket,
    #[error("normal-mode device did not expose a UDID")]
    MissingUdid,
    #[error("normal-mode device was not found")]
    DeviceNotFound,
    #[error("USB access failed: {0}")]
    Usb(#[from] nusb::Error),
    #[error("direct USB multiplexing failed: {0}")]
    DirectMux(#[from] rusbmux::error::RusbmuxError),
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
    #[error("app {operation} failed: {error}")]
    AppOperation {
        operation: &'static str,
        error: String,
    },
    #[error("device rejected EnterRecovery")]
    EnterRecoveryRejected,
    #[error("file relay rejected the source request: {0}")]
    FileRelayRejected(String),
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
