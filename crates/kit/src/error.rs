use thiserror::Error;

use legacy_ios_core::{OperationPhase, Recoverability};

#[derive(Debug, Error)]
pub enum KitError {
    #[error("bootloader device discovery failed: {0}")]
    Transport(#[from] legacy_ios_transport::TransportError),
    #[error("normal-mode device discovery failed: {0}")]
    Service(#[from] legacy_ios_services::ServiceError),
    #[error("device backup failed: {0}")]
    Backup(#[from] legacy_ios_services::BackupError),
    #[error("firmware operation failed: {0}")]
    Firmware(#[from] legacy_ios_firmware::FirmwareError),
    #[error("remote firmware operation failed: {0}")]
    RemoteFirmware(#[from] legacy_ios_firmware::RemoteFirmwareError),
    #[error("signing service operation failed: {0}")]
    Signing(#[from] legacy_ios_firmware::TssError),
    #[error("property list operation failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("restore planning failed: {0}")]
    RestorePlan(#[from] legacy_ios_workflows::RestorePlanError),
    #[error("Recovery/DFU operation failed: {0}")]
    Recovery(#[from] legacy_ios_transport::RecoveryError),
    #[error("bootrom exploit failed: {0}")]
    Limera1n(#[from] legacy_ios_exploits::Limera1nError),
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

impl KitError {
    pub const fn stage(&self) -> OperationPhase {
        match self {
            Self::Firmware(_)
            | Self::RemoteFirmware(_)
            | Self::RestorePlan(_)
            | Self::UnknownProduct(_)
            | Self::UnknownBoardConfig { .. }
            | Self::MissingDeviceSelector => OperationPhase::Planning,
            Self::Signing(_) | Self::Plist(_) => OperationPhase::Personalizing,
            Self::Transport(_) | Self::Service(_) | Self::DeviceDiscovery { .. } | Self::Io(_) => {
                OperationPhase::Preflight
            }
            Self::Backup(_) => OperationPhase::TransferringFilesystem,
            Self::Recovery(_) => OperationPhase::Booting,
            Self::Limera1n(_) => OperationPhase::Exploiting,
        }
    }

    pub const fn recovery(&self) -> Recoverability {
        match self {
            Self::Transport(_) | Self::Service(_) | Self::DeviceDiscovery { .. } => {
                Recoverability::ReconnectDevice
            }
            Self::Signing(_) | Self::Io(_) => Recoverability::RetryImmediately,
            Self::Recovery(_) | Self::Limera1n(_) => Recoverability::ReenterDfu,
            Self::Plist(_) => Recoverability::RestartOperation,
            Self::Backup(_) => Recoverability::RestartOperation,
            Self::Firmware(_)
            | Self::RemoteFirmware(_)
            | Self::RestorePlan(_)
            | Self::UnknownProduct(_)
            | Self::UnknownBoardConfig { .. }
            | Self::MissingDeviceSelector => Recoverability::NotRecoverable,
        }
    }
}
