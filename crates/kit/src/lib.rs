#![forbid(unsafe_code)]

//! Public facade for embedding Legacy iOS Kit workflows.

mod device;
mod error;
mod firmware;

pub use device::{BackendFailure, DeviceInventory, DeviceManager, DeviceSummary};
pub use error::KitError;
pub use firmware::{FirmwareIdentitySummary, FirmwareSummary};
pub use legacy_ios_core::{
    BoardConfig, BuildId, Capability, CapabilitySet, ConnectionId, DeviceIdentity, DeviceMode,
    DeviceSelector, DeviceSnapshot, Ecid, IosVersion, OperationEvent, OperationId, ProductType,
    Soc, Udid,
};

#[derive(Clone, Debug, Default)]
pub struct LegacyIosKit {
    devices: DeviceManager,
}

impl LegacyIosKit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &DeviceManager {
        &self.devices
    }

    pub fn inspect_firmware(
        &self,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<FirmwareSummary, KitError> {
        FirmwareSummary::inspect(path.into())
    }
}
