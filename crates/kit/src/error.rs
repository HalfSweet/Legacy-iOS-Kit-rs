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
    #[error("ramdisk SSH failed: {0}")]
    Ssh(#[from] legacy_ios_services::SshError),
    #[error("firmware operation failed: {0}")]
    Firmware(#[from] legacy_ios_firmware::FirmwareError),
    #[error("remote firmware operation failed: {0}")]
    RemoteFirmware(#[from] legacy_ios_firmware::RemoteFirmwareError),
    #[error("artifact operation failed: {0}")]
    Artifact(#[from] legacy_ios_firmware::ArtifactError),
    #[error("custom IPSW operation failed: {0}")]
    CustomIpsw(#[from] legacy_ios_firmware::CustomIpswError),
    #[error("signing service operation failed: {0}")]
    Signing(#[from] legacy_ios_firmware::TssError),
    #[error("property list operation failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("onboard ticket conversion failed: {0}")]
    OnboardTicket(#[from] legacy_ios_image::OnboardTicketError),
    #[error("disk image operation failed: {0}")]
    Dmg(#[from] legacy_ios_image::DmgError),
    #[error("binary patch operation failed: {0}")]
    Patch(#[from] legacy_ios_image::PatchError),
    #[error("HFS+ operation failed: {0}")]
    Hfs(#[from] legacy_ios_image::HfsError),
    #[error("image payload operation failed: {0}")]
    ImagePayload(#[from] legacy_ios_image::ImagePayloadError),
    #[error("iBoot patch failed: {0}")]
    IbootPatch(#[from] legacy_ios_image::IbootPatchError),
    #[error("signing ticket operation failed: {0}")]
    Ticket(#[from] legacy_ios_firmware::TicketError),
    #[error("restore execution ticket does not match the plan ticket policy")]
    TicketPolicyMismatch,
    #[error("device signing information is missing {0}")]
    MissingSigningDeviceInfo(&'static str),
    #[error("restore planning failed: {0}")]
    RestorePlan(#[from] legacy_ios_workflows::RestorePlanError),
    #[error("ramdisk boot planning failed: {0}")]
    RamdiskBootPlan(#[from] legacy_ios_workflows::RamdiskBootPlanError),
    #[error("ramdisk boot preparation failed: {0}")]
    RamdiskPreparation(#[from] legacy_ios_workflows::RamdiskPreparationError),
    #[error("ramdisk boot failed: {0}")]
    RamdiskBoot(#[from] legacy_ios_workflows::RamdiskBootError),
    #[error("restore preparation failed: {0}")]
    RestorePreparation(#[from] legacy_ios_workflows::RestorePreparationError),
    #[error("restore execution failed: {0}")]
    RestoreExecution(#[from] legacy_ios_workflows::RestoreExecutionError),
    #[error("Recovery/DFU operation failed: {0}")]
    Recovery(#[from] legacy_ios_transport::RecoveryError),
    #[error("bootrom exploit failed: {0}")]
    Limera1n(#[from] legacy_ios_exploits::Limera1nError),
    #[error("checkm8 exploit failed: {0}")]
    Checkm8(#[from] legacy_ios_exploits::Checkm8Error),
    #[error("automatic exploit is not implemented for {0}")]
    AutomaticExploitUnsupported(legacy_ios_core::Soc),
    #[error("automatic limera1n execution requires a payload")]
    MissingLimera1nPayload,
    #[error("the device did not report a pwned state after exploitation")]
    PwnVerificationFailed,
    #[error("timed out waiting for external pwn hardware")]
    ExternalExploitTimeout,
    #[error("host I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("worker task failed: {0}")]
    Task(String),
    #[error("timed out waiting for the device to return to normal mode")]
    VerificationTimeout,
    #[error("WTF image from the Apple IPSW does not match the pinned SHA-1")]
    PwnageWtfDigest,
    #[error("timed out waiting for the device to re-enumerate in Pwnage 2.0 WTF mode")]
    PwnageVerificationTimeout,
    #[error("timed out waiting for the device to enter kDFU mode")]
    KdfuTimeout,
    #[error("restored device version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },
    #[error("unknown product type {0}")]
    UnknownProduct(legacy_ios_core::ProductType),
    #[error("unknown resource {0}")]
    UnknownResource(legacy_ios_assets::ResourceId),
    #[error("root filesystem DMG has no HFS+ partition")]
    MissingHfsPartition,
    #[error("board config {board_config} does not belong to {product_type}")]
    UnknownBoardConfig {
        product_type: legacy_ios_core::ProductType,
        board_config: legacy_ios_core::BoardConfig,
    },
    #[error("device identity has no ECID or UDID")]
    MissingDeviceSelector,
    #[error("erase consent does not belong to the erase plan")]
    EraseConsentMismatch,
    #[error("both device discovery backends failed (bootloader: {bootloader}; normal: {normal})")]
    DeviceDiscovery { bootloader: String, normal: String },
}

impl KitError {
    pub const fn stage(&self) -> OperationPhase {
        match self {
            Self::Firmware(_)
            | Self::RemoteFirmware(_)
            | Self::CustomIpsw(_)
            | Self::RestorePlan(_)
            | Self::RamdiskBootPlan(_)
            | Self::RestorePreparation(_)
            | Self::UnknownProduct(_)
            | Self::UnknownResource(_)
            | Self::MissingHfsPartition
            | Self::UnknownBoardConfig { .. }
            | Self::MissingDeviceSelector => OperationPhase::Planning,
            Self::EraseConsentMismatch => OperationPhase::Preflight,
            Self::RamdiskPreparation(_) => OperationPhase::Preflight,
            Self::RamdiskBoot(_) => OperationPhase::Booting,
            Self::Signing(_)
            | Self::Plist(_)
            | Self::OnboardTicket(_)
            | Self::Dmg(_)
            | Self::Patch(_)
            | Self::Hfs(_)
            | Self::ImagePayload(_)
            | Self::IbootPatch(_)
            | Self::Ticket(_)
            | Self::TicketPolicyMismatch
            | Self::MissingSigningDeviceInfo(_) => OperationPhase::Personalizing,
            Self::Artifact(_) => OperationPhase::Downloading,
            Self::Transport(_)
            | Self::Service(_)
            | Self::Ssh(_)
            | Self::DeviceDiscovery { .. }
            | Self::Io(_) => OperationPhase::Preflight,
            Self::Backup(_) => OperationPhase::TransferringFilesystem,
            Self::RestoreExecution(_) => OperationPhase::Restoring,
            Self::Recovery(_) => OperationPhase::Booting,
            Self::Limera1n(_)
            | Self::Checkm8(_)
            | Self::AutomaticExploitUnsupported(_)
            | Self::PwnageVerificationTimeout
            | Self::KdfuTimeout
            | Self::PwnageWtfDigest
            | Self::MissingLimera1nPayload
            | Self::PwnVerificationFailed
            | Self::ExternalExploitTimeout => OperationPhase::Exploiting,
            Self::Task(_) | Self::VerificationTimeout | Self::VersionMismatch { .. } => {
                OperationPhase::Verifying
            }
        }
    }

    pub const fn recovery(&self) -> Recoverability {
        match self {
            Self::Transport(_) | Self::Service(_) | Self::Ssh(_) | Self::DeviceDiscovery { .. } => {
                Recoverability::ReconnectDevice
            }
            Self::Signing(_) | Self::Artifact(_) | Self::Io(_) => Recoverability::RetryImmediately,
            Self::Recovery(_) | Self::Limera1n(_) | Self::Checkm8(_) | Self::RamdiskBoot(_) => {
                Recoverability::ReenterDfu
            }
            Self::PwnVerificationFailed | Self::ExternalExploitTimeout => {
                Recoverability::ReenterDfu
            }
            Self::Plist(_) | Self::Backup(_) | Self::RestoreExecution(_) | Self::Task(_) => {
                Recoverability::RestartOperation
            }
            Self::VerificationTimeout => Recoverability::ReconnectDevice,
            Self::PwnageVerificationTimeout | Self::KdfuTimeout => Recoverability::ReenterDfu,
            Self::PwnageWtfDigest => Recoverability::NotRecoverable,
            Self::VersionMismatch { .. } => Recoverability::ManualRecoveryRequired,
            Self::Firmware(_)
            | Self::RemoteFirmware(_)
            | Self::CustomIpsw(_)
            | Self::RestorePlan(_)
            | Self::RamdiskBootPlan(_)
            | Self::RestorePreparation(_)
            | Self::RamdiskPreparation(_)
            | Self::AutomaticExploitUnsupported(_)
            | Self::MissingLimera1nPayload
            | Self::OnboardTicket(_)
            | Self::Dmg(_)
            | Self::Patch(_)
            | Self::Hfs(_)
            | Self::ImagePayload(_)
            | Self::IbootPatch(_)
            | Self::Ticket(_)
            | Self::TicketPolicyMismatch
            | Self::MissingSigningDeviceInfo(_)
            | Self::UnknownProduct(_)
            | Self::UnknownResource(_)
            | Self::MissingHfsPartition
            | Self::UnknownBoardConfig { .. }
            | Self::MissingDeviceSelector => Recoverability::NotRecoverable,
            Self::EraseConsentMismatch => Recoverability::NotRecoverable,
        }
    }
}
