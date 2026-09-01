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
    #[error("synthetic backup generation failed: {0}")]
    SparseBackup(#[from] legacy_ios_services::SparseBackupError),
    #[error("anisette data provisioning failed: {0}")]
    Anisette(#[from] legacy_ios_services::signing::AnisetteError),
    #[error("Apple ID authentication failed: {0}")]
    AppleIdAuth(#[from] legacy_ios_services::signing::GsaError),
    #[error("developer services operation failed: {0}")]
    DeveloperApi(#[from] legacy_ios_services::signing::DeveloperApiError),
    #[error("IPA re-signing failed: {0}")]
    Resign(#[from] legacy_ios_services::signing::ResignError),
    #[error("developer team {0} was not found on the Apple ID account")]
    UnknownDeveloperTeam(String),
    #[error("ramdisk SSH failed: {0}")]
    Ssh(#[from] legacy_ios_services::SshError),
    #[error("firmware operation failed: {0}")]
    Firmware(#[from] legacy_ios_firmware::FirmwareError),
    #[error("firmware key operation failed: {0}")]
    FirmwareKey(#[from] legacy_ios_firmware::FirmwareKeyError),
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
    #[error("powdersn0w bundle resolution failed: {0}")]
    PowderBundle(#[from] legacy_ios_firmware::PowderBundleError),
    #[error("powdersn0w single-IPSW builds support A4/A5/A5X/A6/A6X devices, found {0}")]
    PowderUnsupportedDevice(String),
    #[error("the payload plan expects an iBoot.tar sidecar but none was provided")]
    PowderMissingIbootSidecar,
    #[error("powdersn0w -base builds with an APTicket replacement require the -apticket DER")]
    PowderMissingApTicket,
    #[error("the {0} image is too short for the IMG3 TYPE tag rewrite")]
    PowderTruncatedNorImage(&'static str),
    #[error("the partition script resource is not valid UTF-8")]
    PowderInvalidPartitionScript,
    #[error("the restore ramdisk has no options plist at the per-board or default path")]
    PowderMissingRamdiskOptions,
    #[error("the firmware bundle has no {0} entry")]
    PowderMissingComponent(&'static str),
    #[error("the BuildManifest has no BuildIdentities array")]
    PowderInvalidManifest,
    #[error("no latest-baseband manifest rewrite is known for {0}")]
    PowderUnsupportedBasebandReplace(String),
    #[error("powder restores support A4/A5/A5X/A6/A6X devices, found {0}")]
    PowderRestoreUnsupportedDevice(String),
    #[error("powder restore of {0} goes through the two-stage multipart flow (restore multipart)")]
    PowderRestoreRequiresMultipart(String),
    #[error("live latest-version ticket fetches are only valid for A4 powder restores, found {0}")]
    PowderRestoreTicketFetchUnsupported(String),
    #[error("powdersn0w iBoot patch failed: {0}")]
    PowderIbootPatch(#[from] legacy_ios_image::PowderIBootError),
    #[error("powdersn0w ASR patch failed: {0}")]
    PowderAsrPatch(#[from] legacy_ios_image::PowderAsrError),
    #[error("powdersn0w kernel patch failed: {0}")]
    PowderKernelPatch(#[from] legacy_ios_image::Kernel32Error),
    #[error("classic bundle resolution failed: {0}")]
    ClassicBundle(#[from] legacy_ios_firmware::ClassicBundleError),
    #[error(
        "the classic ipsw builder supports S5L8900/S5L8720/S5L8920/S5L8922/A4 devices, found {0}"
    )]
    ClassicUnsupportedDevice(String),
    #[error(
        "{product_type} on iOS {version} cannot be hacktivated with a custom IPSW (requires a jailbroken iPhone/iPad1,1 on iOS 3.1-6.x)"
    )]
    ClassicCannotHacktivate {
        product_type: String,
        version: String,
    },
    #[error("the payload plan expects an iBoot.tar sidecar but none was provided")]
    ClassicMissingIbootSidecar,
    #[error("the classic firmware bundle has no {0} entry")]
    ClassicMissingComponent(&'static str),
    #[error("the restore ramdisk has no options plist at the per-board or default path")]
    ClassicMissingRamdiskOptions,
    #[error(
        "classic restores support iPhone1,1/iPhone1,2/iPod1,1 (S5L8900) and iPod2,1/iPhone2,1 devices, found {0}"
    )]
    ClassicRestoreUnsupportedDevice(String),
    #[error(
        "classic restores support iOS 2.x (foreign custom IPSWs only) and 3.x/4.x targets, found {0}; iPhone2,1 5.x/6.x restores go through `lik restore execute`"
    )]
    ClassicRestoreUnsupportedVersion(String),
    #[error("the device identity has no board config")]
    ClassicRestoreMissingBoardConfig,
    #[error("the custom IPSW is missing the {0} entry")]
    ClassicRestoreMissingComponent(String),
    #[error("this classic restore requires a 3.x/4.x SHSH blob for the device")]
    ClassicRestoreTicketRequired,
    #[error("{0}")]
    ClassicRestoreTicketRejected(&'static str),
    #[error("the SHSH blob does not fit this restore: {0}")]
    ClassicRestoreTicketMismatch(&'static str),
    #[error("destructive consent does not match the classic restore plan")]
    ClassicRestoreConsentMismatch,
    #[error("the device is not in pwned DFU mode: {0}")]
    ClassicRestoreNotPwned(&'static str),
    #[error("timed out waiting for the device to enter {0} mode")]
    ClassicRestoreDeviceTimeout(&'static str),
    #[error("restore mode connection failed: {0}")]
    RestoredConnect(#[from] legacy_ios_restore::RestoredConnectError),
    #[error("restored session failed: {0}")]
    RestoredRun(#[from] legacy_ios_restore::RestoreRunError),
    #[error("layered image patch failed: {0}")]
    Layered(#[from] legacy_ios_image::LayeredError),
    #[error("8900 image operation failed: {0}")]
    Img1(#[from] legacy_ios_image::Img1Error),
    #[error("IMG3 personalization failed: {0}")]
    Img3(#[from] legacy_ios_image::Img3Error),
    #[error("LZSS payload processing failed: {0}")]
    Lzss(#[from] legacy_ios_image::LzssError),
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
    #[error("alloc8 install failed: {0}")]
    Alloc8(#[from] legacy_ios_exploits::Alloc8Error),
    #[error("iBSS from the Apple IPSW does not match the pinned SHA-1")]
    Alloc8IbssDigest,
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
    #[error("bootstrap installation supports 64-bit iOS 7/8/9, found {0}")]
    UnsupportedBootstrapVersion(String),
    #[error("bootstrap package {0} was not provided")]
    MissingBootstrapPackage(&'static str),
    #[error("the device already has /mnt1/bin/bash; it appears to be already jailbroken")]
    AlreadyJailbroken,
    #[error("jailbreak package {0} was not provided")]
    MissingJailbreakPackage(&'static str),
    #[error("the device is already hacktivated")]
    AlreadyHacktivated,
    #[error("no lockdownd patch was provided for the hacktivation method")]
    MissingHacktivationPatch,
    #[error("no original lockdownd on the device; provide one with a file")]
    MissingOriginalLockdownd,
    #[error("FourThree step 1 (restore to iOS 6.1.3) is not complete on the device")]
    FourThreeRestoreIncomplete,
    #[error("FourThree step 2 (partitioning) is not complete on the device")]
    FourThreePartitionIncomplete,
    #[error("FourThree step 3 (kernelcache/LLB install) is not complete on the device")]
    FourThreeInstallIncomplete,
    #[error("FourThree {0} has already been completed")]
    FourThreeStepAlreadyDone(&'static str),
    #[error("invalid FourThree iOS 6.1.3 data partition size {0} GB")]
    InvalidFourThreePartitionSize(u32),
    #[error("no lockdownd patch was provided for the FourThree base system")]
    MissingFourThreeLockdowndPatch,
    #[error("TwistedMind2 did not produce any output files on the device")]
    FourThreePartitionerFailed,
    #[error("FourThree does not support {0}")]
    FourThreeUnsupportedDevice(String),
    #[error("FourThree requires an iOS 6.1.3 target IPSW, found {0}")]
    FourThreeUnsupportedTarget(String),
    #[error("FourThree supports iOS 4.3-4.3.5 base IPSWs, found {0}")]
    FourThreeUnsupportedBase(String),
    #[error("no firmware key material for the FourThree {0} component")]
    FourThreeMissingKey(&'static str),
    #[error("the IPSW does not contain a valid {0}")]
    FourThreeInvalidImage(&'static str),
    #[error("the BuildManifest has no BuildIdentities array")]
    FourThreeInvalidManifest,
    #[error("multipart restore supports iOS 3.x and 4.0-4.2 targets, found {0}")]
    MultipartUnsupportedTarget(String),
    #[error("the custom IPSW restore ramdisk is already multipatched")]
    MultipartAlreadyPatched,
    #[error("the custom IPSW ramdisk options.plist is not a dictionary plist")]
    MultipartInvalidOptionsPlist,
    #[error("the BuildManifest has no BuildIdentities array")]
    MultipartInvalidManifest,
    #[error("no firmware key material for the {0} component")]
    MultipartMissingKey(&'static str),
    #[error("iPad1,1 multipart builds require an output path for the patched target iBoot")]
    MultipartMissingIbootOutput,
    #[error("--skip-first keeps the existing part 2 IPSW, but {0} does not exist")]
    MultipartMissingPart2(std::path::PathBuf),
    #[error("timed out waiting for the device to re-enter DFU/recovery between multipart stages")]
    MultipartStageTimeout,
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
    #[error("TrollRestore consent does not belong to the TrollRestore plan")]
    TrollRestoreConsentMismatch,
    #[error(
        "TrollRestore does not support {product_type} on iOS {version} ({build}); it requires an A9+ device on iOS 15.2-16.6.1, 16.7 RC (20H18), or 17.0"
    )]
    TrollRestoreUnsupported {
        product_type: String,
        version: String,
        build: String,
    },
    #[error(
        "system app {0} was not found on the device; TrollRestore requires a removable Apple app such as Tips"
    )]
    TrollRestoreAppNotFound(String),
    #[error(
        "app {0} is not a removable system app; choose an Apple app that can be deleted and re-downloaded, such as Tips"
    )]
    TrollRestoreAppNotRemovable(String),
    #[error(
        "Find My must be disabled to install TrollStore; disable it in Settings > [Your Name] > Find My and retry"
    )]
    TrollRestoreFindMyEnabled,
    #[error("backup record encoding failed: {0}")]
    Mbdb(#[from] legacy_ios_services::MbdbError),
    #[error("g1lbertJB consent does not belong to the g1lbertJB plan")]
    GilbertJbConsentMismatch,
    #[error(
        "g1lbertJB does not support {product_type} on iOS {version} ({build}); it supports iPhone4,1, iPad2,1-2,4, and iPad3,1-3,3 on iOS 5.0-5.1.1"
    )]
    GilbertJbUnsupported {
        product_type: String,
        version: String,
        build: String,
    },
    #[error("the device is not activated; activate it before jailbreaking with g1lbertJB")]
    GilbertJbUnactivated,
    #[error(
        "the device encrypts its backups; disable the backup password in iTunes/Finder before jailbreaking with g1lbertJB"
    )]
    GilbertJbBackupEncrypted,
    #[error("the device is already jailbroken (a stash or an existing untether was detected)")]
    GilbertJbAlreadyJailbroken,
    #[error(
        "a previous g1lbertJB attempt left /HackStore behind; the media directories were moved back, so re-run the jailbreak"
    )]
    GilbertJbCleanedUp,
    #[error("the g1lbertJB file relay dump is unusable: {0}")]
    GilbertJbInvalidDump(&'static str),
    #[error("the g1lbertJB operation was cancelled")]
    GilbertJbCancelled,
    #[error("both device discovery backends failed (bootloader: {bootloader}; normal: {normal})")]
    DeviceDiscovery { bootloader: String, normal: String },
}

impl KitError {
    pub const fn stage(&self) -> OperationPhase {
        match self {
            Self::Firmware(_)
            | Self::FirmwareKey(_)
            | Self::RemoteFirmware(_)
            | Self::CustomIpsw(_)
            | Self::RestorePlan(_)
            | Self::RamdiskBootPlan(_)
            | Self::RestorePreparation(_)
            | Self::UnknownProduct(_)
            | Self::UnknownResource(_)
            | Self::MissingHfsPartition
            | Self::UnknownBoardConfig { .. }
            | Self::MissingDeviceSelector
            | Self::UnknownDeveloperTeam(_) => OperationPhase::Planning,
            Self::EraseConsentMismatch
            | Self::TrollRestoreConsentMismatch
            | Self::GilbertJbConsentMismatch => OperationPhase::Preflight,
            Self::GilbertJbUnsupported { .. }
            | Self::GilbertJbUnactivated
            | Self::GilbertJbBackupEncrypted
            | Self::GilbertJbAlreadyJailbroken => OperationPhase::Planning,
            Self::GilbertJbCleanedUp | Self::GilbertJbInvalidDump(_) => OperationPhase::Preflight,
            Self::GilbertJbCancelled => OperationPhase::Restoring,
            Self::TrollRestoreUnsupported { .. }
            | Self::TrollRestoreAppNotFound(_)
            | Self::TrollRestoreAppNotRemovable(_) => OperationPhase::Planning,
            Self::TrollRestoreFindMyEnabled => OperationPhase::Restoring,
            Self::UnsupportedBootstrapVersion(_)
            | Self::MissingBootstrapPackage(_)
            | Self::AlreadyJailbroken
            | Self::MissingJailbreakPackage(_)
            | Self::AlreadyHacktivated
            | Self::MissingHacktivationPatch
            | Self::MissingOriginalLockdownd
            | Self::FourThreeRestoreIncomplete
            | Self::FourThreePartitionIncomplete
            | Self::FourThreeInstallIncomplete
            | Self::FourThreeStepAlreadyDone(_)
            | Self::InvalidFourThreePartitionSize(_)
            | Self::MissingFourThreeLockdowndPatch
            | Self::FourThreePartitionerFailed
            | Self::FourThreeUnsupportedDevice(_)
            | Self::FourThreeUnsupportedTarget(_)
            | Self::FourThreeUnsupportedBase(_)
            | Self::FourThreeMissingKey(_)
            | Self::FourThreeInvalidImage(_)
            | Self::FourThreeInvalidManifest => OperationPhase::Planning,
            Self::MultipartUnsupportedTarget(_)
            | Self::MultipartAlreadyPatched
            | Self::MultipartInvalidOptionsPlist
            | Self::MultipartInvalidManifest
            | Self::MultipartMissingKey(_)
            | Self::MultipartMissingIbootOutput
            | Self::MultipartMissingPart2(_) => OperationPhase::Planning,
            Self::PowderBundle(_)
            | Self::PowderUnsupportedDevice(_)
            | Self::PowderMissingIbootSidecar
            | Self::PowderMissingApTicket
            | Self::PowderInvalidPartitionScript
            | Self::PowderMissingRamdiskOptions
            | Self::PowderMissingComponent(_)
            | Self::PowderInvalidManifest
            | Self::PowderUnsupportedBasebandReplace(_) => OperationPhase::Planning,
            Self::ClassicBundle(_)
            | Self::ClassicUnsupportedDevice(_)
            | Self::ClassicCannotHacktivate { .. }
            | Self::ClassicMissingIbootSidecar
            | Self::ClassicMissingComponent(_)
            | Self::ClassicMissingRamdiskOptions => OperationPhase::Planning,
            Self::ClassicRestoreUnsupportedDevice(_)
            | Self::ClassicRestoreUnsupportedVersion(_)
            | Self::ClassicRestoreMissingBoardConfig
            | Self::ClassicRestoreMissingComponent(_)
            | Self::ClassicRestoreTicketRequired
            | Self::ClassicRestoreTicketRejected(_)
            | Self::ClassicRestoreTicketMismatch(_) => OperationPhase::Planning,
            Self::ClassicRestoreConsentMismatch => OperationPhase::Preflight,
            Self::ClassicRestoreNotPwned(_) => OperationPhase::Exploiting,
            Self::ClassicRestoreDeviceTimeout(_) => OperationPhase::WaitingForDevice,
            Self::RestoredConnect(_) | Self::RestoredRun(_) => OperationPhase::Restoring,
            Self::PowderRestoreUnsupportedDevice(_)
            | Self::PowderRestoreRequiresMultipart(_)
            | Self::PowderRestoreTicketFetchUnsupported(_) => OperationPhase::Planning,
            Self::MultipartStageTimeout => OperationPhase::WaitingForDevice,
            Self::RamdiskPreparation(_) => OperationPhase::Preflight,
            Self::RamdiskBoot(_) => OperationPhase::Booting,
            Self::Signing(_)
            | Self::Resign(_)
            | Self::Plist(_)
            | Self::OnboardTicket(_)
            | Self::Dmg(_)
            | Self::Patch(_)
            | Self::Hfs(_)
            | Self::ImagePayload(_)
            | Self::IbootPatch(_)
            | Self::PowderIbootPatch(_)
            | Self::PowderAsrPatch(_)
            | Self::PowderKernelPatch(_)
            | Self::PowderTruncatedNorImage(_)
            | Self::Layered(_)
            | Self::Img1(_)
            | Self::Img3(_)
            | Self::Lzss(_)
            | Self::Ticket(_)
            | Self::TicketPolicyMismatch
            | Self::MissingSigningDeviceInfo(_) => OperationPhase::Personalizing,
            Self::Artifact(_) => OperationPhase::Downloading,
            Self::Transport(_)
            | Self::Service(_)
            | Self::Ssh(_)
            | Self::Anisette(_)
            | Self::AppleIdAuth(_)
            | Self::DeveloperApi(_)
            | Self::DeviceDiscovery { .. }
            | Self::SparseBackup(_)
            | Self::Io(_) => OperationPhase::Preflight,
            Self::Backup(_) | Self::Mbdb(_) => OperationPhase::TransferringFilesystem,
            Self::RestoreExecution(_) => OperationPhase::Restoring,
            Self::Recovery(_) => OperationPhase::Booting,
            Self::Limera1n(_)
            | Self::Checkm8(_)
            | Self::Alloc8(_)
            | Self::AutomaticExploitUnsupported(_)
            | Self::PwnageVerificationTimeout
            | Self::KdfuTimeout
            | Self::PwnageWtfDigest
            | Self::Alloc8IbssDigest
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
            Self::Signing(_)
            | Self::Artifact(_)
            | Self::Anisette(_)
            | Self::Io(_)
            | Self::SparseBackup(_) => Recoverability::RetryImmediately,
            Self::Recovery(_) | Self::Limera1n(_) | Self::Checkm8(_) | Self::RamdiskBoot(_) => {
                Recoverability::ReenterDfu
            }
            Self::Alloc8(_) => Recoverability::ReenterDfu,
            Self::PwnVerificationFailed | Self::ExternalExploitTimeout => {
                Recoverability::ReenterDfu
            }
            Self::Plist(_)
            | Self::Backup(_)
            | Self::Mbdb(_)
            | Self::Resign(_)
            | Self::RestoreExecution(_)
            | Self::Task(_) => Recoverability::RestartOperation,
            Self::GilbertJbCleanedUp | Self::GilbertJbInvalidDump(_) | Self::GilbertJbCancelled => {
                Recoverability::RestartOperation
            }
            Self::VerificationTimeout => Recoverability::ReconnectDevice,
            Self::PwnageVerificationTimeout | Self::KdfuTimeout => Recoverability::ReenterDfu,
            Self::PwnageWtfDigest | Self::Alloc8IbssDigest => Recoverability::NotRecoverable,
            Self::VersionMismatch { .. } | Self::TrollRestoreFindMyEnabled => {
                Recoverability::ManualRecoveryRequired
            }
            Self::Firmware(_)
            | Self::FirmwareKey(_)
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
            | Self::PowderIbootPatch(_)
            | Self::PowderAsrPatch(_)
            | Self::PowderKernelPatch(_)
            | Self::Lzss(_)
            | Self::Ticket(_)
            | Self::TicketPolicyMismatch
            | Self::MissingSigningDeviceInfo(_)
            | Self::UnknownProduct(_)
            | Self::UnknownResource(_)
            | Self::MissingHfsPartition
            | Self::UnknownBoardConfig { .. }
            | Self::AppleIdAuth(_)
            | Self::DeveloperApi(_)
            | Self::UnknownDeveloperTeam(_)
            | Self::MissingDeviceSelector => Recoverability::NotRecoverable,
            Self::EraseConsentMismatch
            | Self::TrollRestoreConsentMismatch
            | Self::TrollRestoreUnsupported { .. }
            | Self::TrollRestoreAppNotFound(_)
            | Self::TrollRestoreAppNotRemovable(_)
            | Self::GilbertJbConsentMismatch
            | Self::GilbertJbUnsupported { .. }
            | Self::GilbertJbUnactivated
            | Self::GilbertJbBackupEncrypted
            | Self::GilbertJbAlreadyJailbroken
            | Self::UnsupportedBootstrapVersion(_)
            | Self::MissingBootstrapPackage(_)
            | Self::AlreadyJailbroken
            | Self::MissingJailbreakPackage(_)
            | Self::AlreadyHacktivated
            | Self::MissingHacktivationPatch
            | Self::MissingOriginalLockdownd
            | Self::FourThreeRestoreIncomplete
            | Self::FourThreePartitionIncomplete
            | Self::FourThreeInstallIncomplete
            | Self::FourThreeStepAlreadyDone(_)
            | Self::InvalidFourThreePartitionSize(_)
            | Self::MissingFourThreeLockdowndPatch
            | Self::FourThreePartitionerFailed
            | Self::FourThreeUnsupportedDevice(_)
            | Self::FourThreeUnsupportedTarget(_)
            | Self::FourThreeUnsupportedBase(_)
            | Self::FourThreeMissingKey(_)
            | Self::FourThreeInvalidImage(_)
            | Self::FourThreeInvalidManifest => Recoverability::NotRecoverable,
            Self::MultipartUnsupportedTarget(_)
            | Self::MultipartAlreadyPatched
            | Self::MultipartInvalidOptionsPlist
            | Self::MultipartInvalidManifest
            | Self::MultipartMissingKey(_)
            | Self::MultipartMissingIbootOutput
            | Self::MultipartMissingPart2(_) => Recoverability::NotRecoverable,
            Self::PowderBundle(_)
            | Self::PowderUnsupportedDevice(_)
            | Self::PowderMissingIbootSidecar
            | Self::PowderMissingApTicket
            | Self::PowderInvalidPartitionScript
            | Self::PowderMissingRamdiskOptions
            | Self::PowderMissingComponent(_)
            | Self::PowderInvalidManifest
            | Self::PowderUnsupportedBasebandReplace(_)
            | Self::PowderTruncatedNorImage(_) => Recoverability::NotRecoverable,
            Self::ClassicBundle(_)
            | Self::ClassicUnsupportedDevice(_)
            | Self::ClassicCannotHacktivate { .. }
            | Self::ClassicMissingIbootSidecar
            | Self::ClassicMissingComponent(_)
            | Self::ClassicMissingRamdiskOptions
            | Self::Layered(_)
            | Self::Img1(_)
            | Self::Img3(_) => Recoverability::NotRecoverable,
            Self::ClassicRestoreUnsupportedDevice(_)
            | Self::ClassicRestoreUnsupportedVersion(_)
            | Self::ClassicRestoreMissingBoardConfig
            | Self::ClassicRestoreMissingComponent(_)
            | Self::ClassicRestoreTicketRequired
            | Self::ClassicRestoreTicketRejected(_)
            | Self::ClassicRestoreTicketMismatch(_)
            | Self::ClassicRestoreConsentMismatch => Recoverability::NotRecoverable,
            Self::ClassicRestoreNotPwned(_) | Self::ClassicRestoreDeviceTimeout(_) => {
                Recoverability::ReenterDfu
            }
            Self::RestoredConnect(_) | Self::RestoredRun(_) => Recoverability::RestartOperation,
            Self::PowderRestoreUnsupportedDevice(_)
            | Self::PowderRestoreRequiresMultipart(_)
            | Self::PowderRestoreTicketFetchUnsupported(_) => Recoverability::NotRecoverable,
            Self::MultipartStageTimeout => Recoverability::ReenterDfu,
        }
    }
}
