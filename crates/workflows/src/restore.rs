use std::path::PathBuf;

use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{CancellationSafety, DeviceIdentity, DeviceSelector, OperationPhase};
use legacy_ios_firmware::{
    FirmwareArchive, FirmwareError, RestoreBehavior, SigningTicket, TicketError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub device: DeviceIdentity,
    pub firmware: PathBuf,
    pub behavior: RestoreBehavior,
    pub ticket: TicketPolicy,
    pub baseband: BasebandPolicy,
    pub sep: SepPolicy,
    pub rsep: RsepPolicy,
    pub exploit: ExploitPolicy,
    pub nonce: NoncePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "policy", content = "value")]
pub enum TicketPolicy {
    Signed,
    Provided(PathBuf),
    Onboard,
    /// Restore without a signing ticket; requires a pwned boot chain.
    Skip,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "policy", content = "value")]
pub enum BasebandPolicy {
    Auto,
    None,
    Provided(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "policy", content = "value")]
pub enum SepPolicy {
    Auto,
    /// Do not send RestoreSEP during boot or SEP data in the NOR response.
    None,
    Provided(PathBuf),
}

/// Whether the recovery-mode boot chain uploads RestoreSEP and issues the
/// `rsepfirmware` command (futurerestore `--no-rsep`; idevicerestore
/// recovery.c:234-243). Independent of [`SepPolicy`], which also controls the
/// NOR response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RsepPolicy {
    /// Send RestoreSEP only for iOS 16+ targets (the iPhone X flow, which
    /// always sends, is not implemented yet).
    #[default]
    Auto,
    Send,
    Skip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExploitPolicy {
    Auto,
    None,
    AlreadyPwned,
}

/// Whether the executor writes the ticket's generator to the device NVRAM
/// before booting the restore chain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoncePolicy {
    /// Do not touch the device boot nonce.
    #[default]
    Manual,
    /// Set `com.apple.System.boot-nonce` to the ticket generator.
    Auto,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlanId(pub(crate) String);

impl PlanId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestorePlan {
    id: PlanId,
    device: DeviceIdentity,
    selector: DeviceSelector,
    firmware: PathBuf,
    behavior: RestoreBehavior,
    product_version: String,
    build_id: String,
    ticket: TicketPolicy,
    baseband: BasebandPolicy,
    sep: SepPolicy,
    rsep: RsepPolicy,
    exploit: ExploitPolicy,
    nonce: NoncePolicy,
    components: Vec<RestoreComponent>,
    steps: Vec<RestoreStep>,
}

impl RestorePlan {
    pub fn resolve(request: RestoreRequest) -> Result<Self, RestorePlanError> {
        let mut request = request;
        let selector = request
            .device
            .selector()
            .ok_or(RestorePlanError::MissingDeviceSelector)?;
        let profile = DeviceDatabase::bundled()
            .find_product(request.device.product_type())
            .ok_or_else(|| {
                RestorePlanError::UnknownDevice(request.device.product_type().clone())
            })?;
        if !profile.has_baseband() && matches!(request.baseband, BasebandPolicy::Auto) {
            request.baseband = BasebandPolicy::None;
        }
        let board_config = request
            .device
            .board_config()
            .ok_or(RestorePlanError::MissingBoardConfig)?;
        if !profile.board_configs().contains(board_config) {
            return Err(RestorePlanError::BoardConfigMismatch);
        }
        if let TicketPolicy::Provided(path) = &request.ticket {
            let ticket =
                SigningTicket::open(path).map_err(|source| RestorePlanError::InvalidTicket {
                    path: path.clone(),
                    source,
                })?;
            if let Some(ecid) = request.device.ecid() {
                ticket
                    .verify_ecid(ecid)
                    .map_err(|source| RestorePlanError::InvalidTicket {
                        path: path.clone(),
                        source,
                    })?;
            }
        }
        if matches!(request.ticket, TicketPolicy::Skip) && request.exploit == ExploitPolicy::None {
            return Err(RestorePlanError::SkipTicketRequiresExploit);
        }
        if let BasebandPolicy::Provided(path) = &request.baseband
            && !path.is_file()
        {
            return Err(RestorePlanError::BasebandNotFound(path.clone()));
        }
        if let SepPolicy::Provided(path) = &request.sep
            && !path.is_file()
        {
            return Err(RestorePlanError::SepNotFound(path.clone()));
        }

        let archive = FirmwareArchive::open(&request.firmware)?;
        let manifest = archive.build_manifest()?;
        if !manifest
            .supported_product_types()
            .contains(request.device.product_type())
        {
            return Err(RestorePlanError::UnsupportedProduct);
        }
        let identity = manifest.select_identity(board_config, request.behavior)?;
        let rsep = match request.rsep {
            RsepPolicy::Auto => match major_version(manifest.product_version().as_str()) {
                Some(major) if major >= 16 => RsepPolicy::Send,
                _ => RsepPolicy::Skip,
            },
            policy => policy,
        };
        let components = identity
            .component_paths()
            .map(|(name, path)| RestoreComponent {
                name: name.to_owned(),
                path: path.to_owned(),
            })
            .collect::<Vec<_>>();
        let steps = restore_steps(request.exploit);
        let id = plan_id(
            &request,
            manifest.product_version().as_str(),
            manifest.build_id().as_str(),
            rsep,
        );

        Ok(Self {
            id,
            device: request.device,
            selector,
            firmware: request.firmware,
            behavior: request.behavior,
            product_version: manifest.product_version().to_string(),
            build_id: manifest.build_id().to_string(),
            ticket: request.ticket,
            baseband: request.baseband,
            sep: request.sep,
            rsep,
            exploit: request.exploit,
            nonce: request.nonce,
            components,
            steps,
        })
    }

    pub fn id(&self) -> &PlanId {
        &self.id
    }

    pub fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    pub fn selector(&self) -> &DeviceSelector {
        &self.selector
    }

    pub fn firmware(&self) -> &std::path::Path {
        &self.firmware
    }

    pub const fn behavior(&self) -> RestoreBehavior {
        self.behavior
    }

    pub fn product_version(&self) -> &str {
        &self.product_version
    }

    pub fn build_id(&self) -> &str {
        &self.build_id
    }

    pub fn components(&self) -> &[RestoreComponent] {
        &self.components
    }

    pub fn ticket_policy(&self) -> &TicketPolicy {
        &self.ticket
    }

    pub fn baseband_policy(&self) -> &BasebandPolicy {
        &self.baseband
    }

    pub fn sep_policy(&self) -> &SepPolicy {
        &self.sep
    }

    /// Resolved RestoreSEP send decision; never [`RsepPolicy::Auto`].
    pub const fn rsep_policy(&self) -> RsepPolicy {
        self.rsep
    }

    pub const fn exploit_policy(&self) -> ExploitPolicy {
        self.exploit
    }

    pub const fn nonce_policy(&self) -> NoncePolicy {
        self.nonce
    }

    pub fn steps(&self) -> &[RestoreStep] {
        &self.steps
    }

    pub fn confirm_destructive(&self) -> DestructiveConsent {
        DestructiveConsent {
            plan_id: self.id.clone(),
        }
    }

    pub fn accepts(&self, consent: &DestructiveConsent) -> bool {
        self.id == consent.plan_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructiveConsent {
    pub(crate) plan_id: PlanId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreComponent {
    pub name: String,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreStep {
    pub kind: RestoreStepKind,
    pub phase: OperationPhase,
    pub cancellation: CancellationSafety,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreStepKind {
    Preflight,
    Personalize,
    AcquireDevice,
    Exploit,
    BootRestore,
    StartRestored,
    TransferFilesystem,
    FlashFirmware,
    Verify,
}

fn restore_steps(exploit: ExploitPolicy) -> Vec<RestoreStep> {
    let mut steps = vec![
        step(
            RestoreStepKind::Preflight,
            OperationPhase::Preflight,
            CancellationSafety::Immediate,
        ),
        step(
            RestoreStepKind::Personalize,
            OperationPhase::Personalizing,
            CancellationSafety::AtCheckpoint,
        ),
        step(
            RestoreStepKind::AcquireDevice,
            OperationPhase::WaitingForDevice,
            CancellationSafety::Immediate,
        ),
    ];
    if exploit != ExploitPolicy::None {
        steps.push(step(
            RestoreStepKind::Exploit,
            OperationPhase::Exploiting,
            CancellationSafety::AtCheckpoint,
        ));
    }
    steps.extend([
        step(
            RestoreStepKind::BootRestore,
            OperationPhase::Booting,
            CancellationSafety::AtCheckpoint,
        ),
        step(
            RestoreStepKind::StartRestored,
            OperationPhase::Restoring,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ),
        step(
            RestoreStepKind::TransferFilesystem,
            OperationPhase::TransferringFilesystem,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ),
        step(
            RestoreStepKind::FlashFirmware,
            OperationPhase::FlashingFirmware,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ),
        step(
            RestoreStepKind::Verify,
            OperationPhase::Verifying,
            CancellationSafety::Immediate,
        ),
    ]);
    steps
}

const fn step(
    kind: RestoreStepKind,
    phase: OperationPhase,
    cancellation: CancellationSafety,
) -> RestoreStep {
    RestoreStep {
        kind,
        phase,
        cancellation,
    }
}

fn plan_id(
    request: &RestoreRequest,
    product_version: &str,
    build_id: &str,
    rsep: RsepPolicy,
) -> PlanId {
    let material = format!(
        "{}|{}|{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        request.device.product_type(),
        request
            .device
            .board_config()
            .expect("resolved requests have a board config"),
        request.firmware.display(),
        product_version,
        build_id,
        request.behavior,
        request.ticket,
        request.baseband,
        request.sep,
        rsep,
        request.exploit,
        request.nonce,
    );
    PlanId(hex::encode(Sha256::digest(material.as_bytes())))
}

/// Numeric major version of a dotted product version ("16.0.1" -> 16).
fn major_version(version: &str) -> Option<u64> {
    version.split('.').next()?.parse().ok()
}

#[derive(Debug, Error)]
pub enum RestorePlanError {
    #[error("device identity has no ECID or UDID")]
    MissingDeviceSelector,
    #[error("device identity has no board config")]
    MissingBoardConfig,
    #[error("unknown device {0}")]
    UnknownDevice(legacy_ios_core::ProductType),
    #[error("board config does not belong to the selected product type")]
    BoardConfigMismatch,
    #[error("firmware does not support the selected product type")]
    UnsupportedProduct,
    #[error("invalid signing ticket {}: {source}", path.display())]
    InvalidTicket {
        path: PathBuf,
        #[source]
        source: TicketError,
    },
    #[error("provided baseband firmware does not exist: {}", .0.display())]
    BasebandNotFound(PathBuf),
    #[error("provided SEP firmware does not exist: {}", .0.display())]
    SepNotFound(PathBuf),
    #[error("skipping the signing ticket requires a pwned boot chain")]
    SkipTicketRequiresExploit,
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::{BoardConfig, Ecid, ProductType, Soc};
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn resolves_plan_and_binds_consent() {
        let file = firmware_fixture();
        let request = RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: file.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
        };

        let plan = RestorePlan::resolve(request).unwrap();
        let consent = plan.confirm_destructive();

        assert!(plan.accepts(&consent));
        assert_eq!(plan.product_version(), "7.1.2");
        assert_eq!(plan.components()[0].name, "RestoreRamDisk");
    }

    #[test]
    fn rsep_auto_follows_the_target_major_version() {
        let legacy = firmware_fixture();
        let modern = firmware_fixture_with_version("16.7.10");
        let request = |firmware: &NamedTempFile, rsep| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
        };

        let plan = RestorePlan::resolve(request(&legacy, RsepPolicy::Auto)).unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Skip);
        let plan = RestorePlan::resolve(request(&modern, RsepPolicy::Auto)).unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Send);
        // Explicit policies are preserved regardless of the target version.
        let plan = RestorePlan::resolve(request(&legacy, RsepPolicy::Send)).unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Send);
        let plan = RestorePlan::resolve(request(&modern, RsepPolicy::Skip)).unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Skip);
    }

    #[test]
    fn skip_ticket_requires_pwned_boot_chain() {
        let file = firmware_fixture();
        let request = |exploit| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: file.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Skip,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            exploit,
            nonce: NoncePolicy::Manual,
        };

        let error = RestorePlan::resolve(request(ExploitPolicy::None)).unwrap_err();
        assert!(matches!(error, RestorePlanError::SkipTicketRequiresExploit));
        RestorePlan::resolve(request(ExploitPolicy::AlreadyPwned)).unwrap();
    }

    fn firmware_fixture() -> NamedTempFile {
        firmware_fixture_with_version("7.1.2")
    }

    fn firmware_fixture_with_version(version: &str) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>{version}</string>
<key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n90ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict></dict>
</dict></array>
</dict></plist>"#
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
        file
    }
}
