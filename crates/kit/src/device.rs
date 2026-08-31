use futures_util::StreamExt;
use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{
    BoardConfig, CapabilitySet, ConnectionId, DeviceIdentity, DeviceMode, DeviceSnapshot, Ecid,
    ProductType, Soc, Udid,
};
use legacy_ios_services::{
    ActivationState, AppFilter, BackupOptions, BackupOutcome, BackupRestoreOptions, DeviceFiles,
    DeviceSyslog, HostKeyPolicy, InstalledApp, NormalBackend, NormalDevice, NormalMux, RamdiskSsh,
    SshPassword, SshTarget, SystemMux,
};
use legacy_ios_transport::{
    DeviceLocator, NusbDeviceLocator, ObservedUsbDevice, parse_iboot_serial,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{KitError, OperationHandle, PairingStore};

#[derive(Clone, Debug, Default)]
pub struct DeviceManager {
    bootloader: NusbDeviceLocator,
    normal: NormalMux,
    ramdisk: SystemMux,
    pairing_store: Option<PairingStore>,
}

impl DeviceManager {
    pub fn with_normal_backend(backend: NormalBackend) -> Self {
        Self {
            bootloader: NusbDeviceLocator,
            normal: NormalMux::new(backend),
            ramdisk: SystemMux::default(),
            pairing_store: None,
        }
    }

    pub fn with_pairing_store(mut self, store: PairingStore) -> Self {
        self.pairing_store = Some(store);
        self
    }

    pub const fn normal_backend(&self) -> NormalBackend {
        self.normal.backend()
    }

    pub fn set_normal_backend(&mut self, backend: NormalBackend) {
        self.normal = NormalMux::new(backend);
    }

    pub fn watch_bootloader(&self) -> Result<OperationHandle, KitError> {
        let mut watch = self.bootloader.watch()?;
        let (emitter, handle) = OperationHandle::channel(32);
        tokio::spawn(async move {
            while !emitter.is_cancelled() {
                let Some(event) = watch.next().await else {
                    break;
                };
                let event = match event {
                    legacy_ios_transport::UsbDeviceEvent::Connected(device) => {
                        legacy_ios_core::OperationEvent::ModeChanged {
                            mode: device.mode(),
                        }
                    }
                    legacy_ios_transport::UsbDeviceEvent::Disconnected(_) => {
                        legacy_ios_core::OperationEvent::DeviceDisconnected
                    }
                };
                if !emitter.emit(event).await {
                    break;
                }
            }
        });
        Ok(handle)
    }

    pub async fn list(&self) -> Result<DeviceInventory, KitError> {
        let (bootloader, normal) = tokio::join!(self.list_bootloader(), self.list_normal());
        match (bootloader, normal) {
            (Ok(mut bootloader), Ok(normal)) => {
                bootloader.extend(normal);
                Ok(DeviceInventory {
                    devices: bootloader,
                    failures: Vec::new(),
                })
            }
            (Ok(devices), Err(error)) => {
                warn!(%error, "normal-mode discovery unavailable");
                Ok(DeviceInventory {
                    devices,
                    failures: vec![BackendFailure::new("normal", error.to_string())],
                })
            }
            (Err(error), Ok(devices)) => {
                warn!(%error, "bootloader discovery unavailable");
                Ok(DeviceInventory {
                    devices,
                    failures: vec![BackendFailure::new("bootloader", error.to_string())],
                })
            }
            (Err(bootloader), Err(normal)) => Err(KitError::DeviceDiscovery {
                bootloader: bootloader.to_string(),
                normal: normal.to_string(),
            }),
        }
    }

    pub async fn list_bootloader(&self) -> Result<Vec<DeviceSummary>, KitError> {
        Ok(self
            .bootloader
            .list()
            .await?
            .into_iter()
            .map(DeviceSummary::from_bootloader)
            .collect())
    }

    pub async fn list_normal(&self) -> Result<Vec<DeviceSummary>, KitError> {
        let mut summaries = Vec::new();
        for device in self.normal.list_devices().await? {
            let info = device.query_info().await?;
            let profile = DeviceDatabase::bundled().find_product(info.product_type());
            summaries.push(DeviceSummary {
                mode: DeviceMode::Normal,
                connection_id: ConnectionId::new(format!("usbmux:{}", info.udid())),
                ecid: Some(info.ecid()),
                udid: Some(info.udid().clone()),
                product_type: Some(info.product_type().clone()),
                board_config: Some(info.board_config().clone()),
                soc: profile.map(|profile| profile.soc()),
                name: Some(info.device_name().to_owned()),
                product_version: Some(info.product_version().to_owned()),
                build_version: Some(info.build_version().to_owned()),
            });
        }
        Ok(summaries)
    }

    pub async fn pair(&self, udid: &Udid) -> Result<(), KitError> {
        self.normal.find_device(udid).await?.pair().await?;
        if let Some(store) = &self.pairing_store
            && let Some(record) = self.normal.pairing_record(udid).await
        {
            store.save(udid, &record).await?;
        }
        Ok(())
    }

    pub async fn battery_info(&self, udid: &Udid) -> Result<DeviceDiagnostics, KitError> {
        let values = self.find_normal(udid).await?.battery_info().await?;
        Ok(DeviceDiagnostics { values })
    }

    pub async fn restart(&self, udid: &Udid) -> Result<(), KitError> {
        self.find_normal(udid).await?.restart().await?;
        Ok(())
    }

    pub async fn shutdown(&self, udid: &Udid) -> Result<(), KitError> {
        self.find_normal(udid).await?.shutdown().await?;
        Ok(())
    }

    pub async fn list_apps(
        &self,
        udid: &Udid,
        filter: AppFilter,
    ) -> Result<Vec<InstalledApp>, KitError> {
        Ok(self.find_normal(udid).await?.list_apps(filter).await?)
    }

    pub async fn install_ipa(&self, udid: &Udid, ipa: &std::path::Path) -> Result<(), KitError> {
        self.find_normal(udid).await?.install_ipa(ipa).await?;
        Ok(())
    }

    pub async fn uninstall_app(&self, udid: &Udid, bundle_id: &str) -> Result<(), KitError> {
        self.find_normal(udid)
            .await?
            .uninstall_app(bundle_id)
            .await?;
        Ok(())
    }

    pub async fn enter_recovery(&self, udid: &Udid) -> Result<(), KitError> {
        self.find_normal(udid).await?.enter_recovery().await?;
        Ok(())
    }

    pub async fn syslog(&self, udid: &Udid) -> Result<DeviceSyslog, KitError> {
        Ok(self.find_normal(udid).await?.syslog().await?)
    }

    pub async fn files(&self, udid: &Udid) -> Result<DeviceFiles, KitError> {
        Ok(self.find_normal(udid).await?.files().await?)
    }

    pub async fn backup(
        &self,
        udid: &Udid,
        destination: &std::path::Path,
        options: BackupOptions,
    ) -> Result<BackupOutcome, KitError> {
        Ok(self
            .find_normal(udid)
            .await?
            .backup(destination, options)
            .await?)
    }

    pub async fn restore_backup(
        &self,
        udid: &Udid,
        root: &std::path::Path,
        source_identifier: &str,
        options: BackupRestoreOptions,
    ) -> Result<BackupOutcome, KitError> {
        Ok(self
            .find_normal(udid)
            .await?
            .restore_backup(root, source_identifier, options)
            .await?)
    }

    pub async fn ramdisk_ssh(
        &self,
        target: SshTarget,
        username: &str,
        password: &SshPassword,
        host_key: HostKeyPolicy,
    ) -> Result<RamdiskSsh, KitError> {
        Ok(RamdiskSsh::connect(&self.ramdisk, target, username, password, host_key).await?)
    }

    pub async fn activation_state(&self, udid: &Udid) -> Result<ActivationState, KitError> {
        Ok(self.find_normal(udid).await?.activation_state().await?)
    }

    pub async fn deactivate(&self, udid: &Udid) -> Result<(), KitError> {
        self.find_normal(udid).await?.deactivate().await?;
        Ok(())
    }

    async fn find_normal(&self, udid: &Udid) -> Result<NormalDevice, KitError> {
        let device = self.normal.find_device(udid).await?;
        if let Some(store) = &self.pairing_store
            && self.normal.pairing_record(udid).await.is_none()
            && let Some(record) = store.load(udid).await?
        {
            self.normal
                .import_pairing_record(udid.clone(), record)
                .await;
        }
        Ok(device)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct DeviceDiagnostics {
    values: plist::Dictionary,
}

impl DeviceDiagnostics {
    pub fn values(&self) -> &plist::Dictionary {
        &self.values
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceInventory {
    devices: Vec<DeviceSummary>,
    failures: Vec<BackendFailure>,
}

impl DeviceInventory {
    pub fn devices(&self) -> &[DeviceSummary] {
        &self.devices
    }

    pub fn failures(&self) -> &[BackendFailure] {
        &self.failures
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendFailure {
    backend: String,
    message: String,
}

impl BackendFailure {
    fn new(backend: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            message: message.into(),
        }
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceSummary {
    mode: DeviceMode,
    connection_id: ConnectionId,
    ecid: Option<Ecid>,
    udid: Option<Udid>,
    product_type: Option<ProductType>,
    board_config: Option<BoardConfig>,
    soc: Option<Soc>,
    name: Option<String>,
    product_version: Option<String>,
    build_version: Option<String>,
}

impl DeviceSummary {
    fn from_bootloader(device: ObservedUsbDevice) -> Self {
        let info = parse_iboot_serial(device.serial_number().unwrap_or_default());
        Self {
            mode: device.mode(),
            connection_id: device.connection_id().clone(),
            ecid: info.ecid(),
            udid: None,
            product_type: None,
            board_config: None,
            soc: info.cpid().map(soc_from_cpid),
            name: device.product_name().map(ToOwned::to_owned),
            product_version: None,
            build_version: None,
        }
    }

    pub const fn mode(&self) -> DeviceMode {
        self.mode
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub const fn ecid(&self) -> Option<Ecid> {
        self.ecid
    }

    pub fn udid(&self) -> Option<&Udid> {
        self.udid.as_ref()
    }

    pub fn product_type(&self) -> Option<&ProductType> {
        self.product_type.as_ref()
    }

    pub fn board_config(&self) -> Option<&BoardConfig> {
        self.board_config.as_ref()
    }

    pub const fn soc(&self) -> Option<Soc> {
        self.soc
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn product_version(&self) -> Option<&str> {
        self.product_version.as_deref()
    }

    pub fn build_version(&self) -> Option<&str> {
        self.build_version.as_deref()
    }

    pub(crate) fn snapshot(&self) -> Option<DeviceSnapshot> {
        let product_type = self.product_type.clone()?;
        let soc = self.soc?;
        let mut identity = DeviceIdentity::new(product_type.clone(), soc);
        if let Some(board_config) = &self.board_config {
            identity = identity.with_board_config(board_config.clone());
        }
        if let Some(ecid) = self.ecid {
            identity = identity.with_ecid(ecid);
        }
        if let Some(udid) = &self.udid {
            identity = identity.with_udid(udid.clone());
        }
        let capabilities = DeviceDatabase::bundled()
            .find_product(&product_type)
            .map_or_else(CapabilitySet::default, |profile| profile.capabilities());
        Some(DeviceSnapshot::new(
            identity,
            self.mode,
            self.connection_id.clone(),
            capabilities,
        ))
    }
}

fn soc_from_cpid(cpid: u32) -> Soc {
    match cpid {
        0x8900 => Soc::S5l8900,
        0x8720 => Soc::S5l8720,
        0x8920 => Soc::S5l8920,
        0x8922 => Soc::S5l8922,
        0x8930 => Soc::A4,
        0x8940 | 0x8942 => Soc::A5,
        0x8945 => Soc::A5x,
        0x8950 => Soc::A6,
        0x8955 => Soc::A6x,
        0x8960 => Soc::A7,
        0x7000 => Soc::A8,
        0x7001 => Soc::A8x,
        0x8000 | 0x8003 => Soc::A9,
        0x8001 => Soc::A9x,
        0x8010 => Soc::A10,
        0x8011 => Soc::A10x,
        0x8015 => Soc::A11,
        value => Soc::Other(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_chip_ids_to_soc_families() {
        assert_eq!(soc_from_cpid(0x8930), Soc::A4);
        assert_eq!(soc_from_cpid(0x8015), Soc::A11);
        assert_eq!(soc_from_cpid(0xffff), Soc::Other(0xffff));
    }
}
