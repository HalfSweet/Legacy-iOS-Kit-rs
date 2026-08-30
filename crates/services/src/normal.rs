use std::sync::Arc;

use idevice::{
    IdeviceService,
    provider::IdeviceProvider,
    services::lockdown::LockdownClient,
    usbmuxd::{Connection, UsbmuxdAddr},
};
use legacy_ios_core::{BoardConfig, Ecid, ProductType, Udid};
use serde::{Deserialize, Serialize};
use thiserror::Error;
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
                }
            })
            .collect::<Vec<_>>();
        debug!(
            count = devices.len(),
            "listed normal-mode devices through system mux"
        );
        Ok(devices)
    }
}

#[derive(Clone, Debug)]
pub struct NormalDevice {
    udid: Udid,
    provider: Arc<dyn IdeviceProvider>,
}

impl NormalDevice {
    pub fn udid(&self) -> &Udid {
        &self.udid
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
