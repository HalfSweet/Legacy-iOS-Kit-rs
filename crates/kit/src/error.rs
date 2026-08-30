use thiserror::Error;

#[derive(Debug, Error)]
pub enum KitError {
    #[error("bootloader device discovery failed: {0}")]
    Transport(#[from] legacy_ios_transport::TransportError),
    #[error("normal-mode device discovery failed: {0}")]
    Service(#[from] legacy_ios_services::ServiceError),
    #[error("firmware operation failed: {0}")]
    Firmware(#[from] legacy_ios_firmware::FirmwareError),
    #[error("restore planning failed: {0}")]
    RestorePlan(#[from] legacy_ios_workflows::RestorePlanError),
    #[error("Recovery/DFU operation failed: {0}")]
    Recovery(#[from] legacy_ios_transport::RecoveryError),
    #[error("host I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("unknown product type {0}")]
    UnknownProduct(legacy_ios_core::ProductType),
    #[error("board config {board_config} does not belong to {product_type}")]
    UnknownBoardConfig {
        product_type: legacy_ios_core::ProductType,
        board_config: legacy_ios_core::BoardConfig,
    },
    #[error("device identity has no ECID or UDID")]
    MissingDeviceSelector,
    #[error("both device discovery backends failed (bootloader: {bootloader}; normal: {normal})")]
    DeviceDiscovery { bootloader: String, normal: String },
}
