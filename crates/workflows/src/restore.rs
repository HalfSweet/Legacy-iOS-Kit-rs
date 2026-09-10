use std::path::PathBuf;

use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{CancellationSafety, DeviceIdentity, DeviceSelector, OperationPhase};
use legacy_ios_firmware::{
    FirmwareArchive, FirmwareError, RestoreBehavior, SigningTicket, TicketError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::auxiliary::{
    AppleDbCatalog, AuxFirmwareCatalog, AuxFirmwareError, AuxFirmwareResolution,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreRequest {
    pub device: DeviceIdentity,
    pub firmware: PathBuf,
    pub behavior: RestoreBehavior,
    pub ticket: TicketPolicy,
    pub baseband: BasebandPolicy,
    pub sep: SepPolicy,
    pub rsep: RsepPolicy,
    pub cryptex: CryptexPolicy,
    pub cryptex_source: CryptexSource,
    pub exploit: ExploitPolicy,
    pub nonce: NoncePolicy,
    /// Patched ramdisk IM4P replacing RestoreRamDisk (futurerestore
    /// `--rdsk`); must be given together with `rkrn`.
    pub rdsk: Option<PathBuf>,
    /// Patched kernelcache IM4P replacing RestoreKernelCache (futurerestore
    /// `--rkrn`); must be given together with `rdsk`.
    pub rkrn: Option<PathBuf>,
}

/// The paired rdsk/rkrn boot component overrides of the iPhone X downgrade
/// flow (futurerestore `--rdsk rdsk.im4p --rkrn kcache.im4p`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BootComponentOverrides {
    pub rdsk: PathBuf,
    pub rkrn: PathBuf,
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
    /// Resolve the baseband from the device tables (upstream
    /// `restore_download_bbsep`): the aux `use`/`latest` build, or the target
    /// IPSW when the builds match.
    Auto,
    None,
    /// A user-provided IPSW whose BasebandFirmware is used instead (upstream
    /// `-b` with a standalone baseband source).
    Provided(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "policy", content = "value")]
pub enum SepPolicy {
    /// Resolve the SEP from the device tables and sign it with an
    /// independent SEP ticket fetched against the aux build identity after
    /// the device boots to recovery (futurerestore.cpp:1613-1621).
    Auto,
    /// Do not send RestoreSEP during boot or SEP data in the NOR response.
    None,
    /// A user-provided IPSW whose RestoreSEP is used instead, still signed
    /// with an independent SEP ticket against its build identity.
    Provided(PathBuf),
}

/// Whether the recovery-mode boot chain uploads RestoreSEP and issues the
/// `rsepfirmware` command (futurerestore `--no-rsep`; idevicerestore
/// recovery.c:234-243). Independent of [`SepPolicy`], which also controls the
/// NOR response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RsepPolicy {
    /// Send RestoreSEP for iOS 16+ targets, or whenever rdsk/rkrn boot
    /// overrides are set (the iPhone X flow always sends; upstream does not
    /// pass `--no-rsep` there).
    #[default]
    Auto,
    Send,
    Skip,
}

/// Whether the restore answers Cryptex1 boot-object and firmware-updater
/// requests (futurerestore dev branch, iOS 16+).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptexPolicy {
    /// Enable Cryptex1 handling for iOS 16+ targets whose build identity
    /// manifest carries `Cryptex1,SystemOS`.
    #[default]
    Auto,
    None,
}

/// Source of the six `Cryptex1,*` payloads and, for a separate source, the
/// build-identity rewrite / TSS retry identity.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "policy", content = "value")]
pub enum CryptexSource {
    /// The target IPSW itself (upstream's `IDR_DISABLE_LATEST_CRYPTEX` path).
    #[default]
    Target,
    /// A user-provided latest-version IPSW (the explicit-file equivalent of
    /// upstream's `downloadLatestCryptex1`).
    Provided(PathBuf),
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestorePlan {
    inputs: Vec<crate::input::PinnedInput>,
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
    /// Resolved Cryptex1 handling: the payload source when enabled.
    cryptex: Option<CryptexSource>,
    exploit: ExploitPolicy,
    nonce: NoncePolicy,
    boot_overrides: Option<BootComponentOverrides>,
    /// Resolved auxiliary (SEP/baseband) firmware source, when the device
    /// tables select one for the auto policies.
    aux: Option<AuxFirmwareResolution>,
    components: Vec<RestoreComponent>,
    steps: Vec<RestoreStep>,
}

impl RestorePlan {
    pub async fn resolve(request: RestoreRequest) -> Result<Self, RestorePlanError> {
        Self::resolve_with_catalog(request, &AppleDbCatalog::new()).await
    }

    /// Resolve with an explicit aux firmware catalog; the catalog is only
    /// consulted when the selection rules pick an aux build different from
    /// the target build.
    pub async fn resolve_with_catalog(
        request: RestoreRequest,
        catalog: &dyn AuxFirmwareCatalog,
    ) -> Result<Self, RestorePlanError> {
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
        if let CryptexSource::Provided(path) = &request.cryptex_source
            && !path.is_file()
        {
            return Err(RestorePlanError::CryptexSourceNotFound(path.clone()));
        }
        let mut boot_overrides = match (request.rdsk.take(), request.rkrn.take()) {
            (Some(rdsk), Some(rkrn)) => {
                if !rdsk.is_file() {
                    return Err(RestorePlanError::BootOverrideNotFound(rdsk));
                }
                if !rkrn.is_file() {
                    return Err(RestorePlanError::BootOverrideNotFound(rkrn));
                }
                Some(BootComponentOverrides { rdsk, rkrn })
            }
            (None, None) => None,
            _ => return Err(RestorePlanError::BootOverridePair),
        };

        let mut inputs = Vec::new();
        pin_path("firmware", &mut request.firmware, &mut inputs)?;
        if let TicketPolicy::Provided(path) = &mut request.ticket {
            pin_path("ticket", path, &mut inputs)?;
        }
        if let BasebandPolicy::Provided(path) = &mut request.baseband {
            pin_path("baseband", path, &mut inputs)?;
        }
        if let SepPolicy::Provided(path) = &mut request.sep {
            pin_path("sep", path, &mut inputs)?;
        }
        if let CryptexSource::Provided(path) = &mut request.cryptex_source {
            pin_path("cryptex", path, &mut inputs)?;
        }
        if let Some(overrides) = &mut boot_overrides {
            pin_path("rdsk", &mut overrides.rdsk, &mut inputs)?;
            pin_path("rkrn", &mut overrides.rkrn, &mut inputs)?;
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
        let archive = FirmwareArchive::open(&request.firmware)?;
        let manifest = archive.build_manifest()?;
        if !manifest
            .supported_product_types()
            .contains(request.device.product_type())
        {
            return Err(RestorePlanError::UnsupportedProduct);
        }
        let identity = manifest.select_identity(board_config, request.behavior)?;
        if let TicketPolicy::Provided(path) = &request.ticket {
            let validate = || -> Result<(), TicketError> {
                let ticket = SigningTicket::open(path)?;
                ticket.claims().verify_signature()?;
                if request.exploit == ExploitPolicy::None {
                    ticket.claims().verify_identity(identity)?;
                }
                Ok(())
            };
            validate().map_err(|source| RestorePlanError::InvalidTicket {
                path: path.clone(),
                source,
            })?;
        }
        // A provided SEP/baseband IPSW must actually carry the component it
        // substitutes for (its content is used as the aux firmware source).
        if let SepPolicy::Provided(path) = &request.sep {
            let sep_archive = FirmwareArchive::open(path)?;
            let sep_manifest = sep_archive.build_manifest()?;
            let sep_identity = sep_manifest.select_identity(board_config, request.behavior)?;
            if !sep_identity.manifest().contains_key("RestoreSEP") {
                return Err(RestorePlanError::MissingProvidedSep);
            }
        }
        let aux = crate::auxiliary::resolve_aux(
            &crate::auxiliary::AuxTarget {
                device: &request.device,
                profile,
                manifest: &manifest,
                identity,
                behavior: request.behavior,
                exploit: request.exploit,
            },
            &request.sep,
            &request.baseband,
            catalog,
        )
        .await?;
        let rsep = match request.rsep {
            // The iPhone X flow (rdsk/rkrn overrides) always sends RestoreSEP:
            // upstream passes --rdsk/--rkrn without --no-rsep.
            RsepPolicy::Auto if boot_overrides.is_some() => RsepPolicy::Send,
            RsepPolicy::Auto => {
                match crate::auxiliary::major_version(manifest.product_version().as_str()) {
                    Some(major) if major >= 16 => RsepPolicy::Send,
                    _ => RsepPolicy::Skip,
                }
            }
            policy => policy,
        };
        let cryptex = match request.cryptex {
            CryptexPolicy::None => None,
            CryptexPolicy::Auto => {
                let gated = crate::auxiliary::major_version(manifest.product_version().as_str())
                    .is_some_and(|major| major >= 16)
                    && identity.manifest().contains_key("Cryptex1,SystemOS");
                gated.then(|| request.cryptex_source.clone())
            }
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
            ResolvedPlanExtras {
                product_version: manifest.product_version().as_str(),
                build_id: manifest.build_id().as_str(),
                rsep,
                cryptex: cryptex.as_ref(),
                boot_overrides: boot_overrides.as_ref(),
                aux: aux.as_ref(),
            },
            &inputs,
        );

        Ok(Self {
            inputs,
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
            cryptex,
            exploit: request.exploit,
            nonce: request.nonce,
            boot_overrides,
            aux,
            components,
            steps,
        })
    }

    pub(crate) fn retained_inputs(&self) -> Vec<crate::input::PinnedInput> {
        self.inputs.clone()
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

    /// Resolved Cryptex1 payload source, or `None` when Cryptex1 handling is
    /// disabled for this target.
    pub fn cryptex_source(&self) -> Option<&CryptexSource> {
        self.cryptex.as_ref()
    }

    pub const fn exploit_policy(&self) -> ExploitPolicy {
        self.exploit
    }

    pub const fn nonce_policy(&self) -> NoncePolicy {
        self.nonce
    }

    /// The rdsk/rkrn boot component overrides of the iPhone X downgrade flow,
    /// when set.
    pub const fn boot_overrides(&self) -> Option<&BootComponentOverrides> {
        self.boot_overrides.as_ref()
    }

    /// The resolved auxiliary (SEP/baseband) firmware source for the auto
    /// policies, when the device tables select one.
    pub const fn aux_firmware(&self) -> Option<&AuxFirmwareResolution> {
        self.aux.as_ref()
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

fn pin_path(
    role: &str,
    path: &mut PathBuf,
    inputs: &mut Vec<crate::input::PinnedInput>,
) -> Result<(), RestorePlanError> {
    let input =
        crate::input::PinnedInput::copy(role, path).map_err(RestorePlanError::InputSnapshot)?;
    *path = input.path().to_owned();
    inputs.push(input);
    Ok(())
}

/// The resolved plan extras participating in the plan identity.
struct ResolvedPlanExtras<'a> {
    product_version: &'a str,
    build_id: &'a str,
    rsep: RsepPolicy,
    cryptex: Option<&'a CryptexSource>,
    boot_overrides: Option<&'a BootComponentOverrides>,
    aux: Option<&'a AuxFirmwareResolution>,
}

fn plan_id(
    request: &RestoreRequest,
    extras: ResolvedPlanExtras<'_>,
    inputs: &[crate::input::PinnedInput],
) -> PlanId {
    // Only content identities are encoded, never temporary snapshot paths.
    let ticket = match request.ticket {
        TicketPolicy::Signed => "signed",
        TicketPolicy::Provided(_) => "provided",
        TicketPolicy::Onboard => "onboard",
        TicketPolicy::Skip => "skip",
    };
    let baseband = match request.baseband {
        BasebandPolicy::Auto => "auto",
        BasebandPolicy::None => "none",
        BasebandPolicy::Provided(_) => "provided",
    };
    let sep = match request.sep {
        SepPolicy::Auto => "auto",
        SepPolicy::None => "none",
        SepPolicy::Provided(_) => "provided",
    };
    let material = serde_json::to_vec(&(
        3_u32,
        "restore",
        &request.device,
        request.behavior,
        extras.product_version,
        extras.build_id,
        ticket,
        baseband,
        sep,
        extras.rsep,
        extras.cryptex.is_some(),
        request.exploit,
        request.nonce,
        extras.boot_overrides.is_some(),
        extras.aux,
        inputs,
    ))
    .expect("plan identity contains only serializable values");
    PlanId(hex::encode(Sha256::digest(&material)))
}

#[derive(Debug, Error)]
pub enum RestorePlanError {
    #[error("could not retain the approved restore input: {0}")]
    InputSnapshot(#[source] std::io::Error),
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
    #[error("provided SEP firmware has no RestoreSEP component")]
    MissingProvidedSep,
    #[error("provided cryptex source IPSW does not exist: {}", .0.display())]
    CryptexSourceNotFound(PathBuf),
    #[error("--rdsk and --rkrn boot overrides must be given together")]
    BootOverridePair,
    #[error("provided boot component override does not exist: {}", .0.display())]
    BootOverrideNotFound(PathBuf),
    #[error("skipping the signing ticket requires a pwned boot chain")]
    SkipTicketRequiresExploit,
    #[error(transparent)]
    AuxFirmware(#[from] AuxFirmwareError),
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
    use crate::auxiliary::{AuxCatalogFuture, AuxFirmwareSource};

    #[tokio::test]
    async fn resolves_plan_and_binds_consent() {
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
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };

        let plan = RestorePlan::resolve(request.clone()).await.unwrap();
        let consent = plan.confirm_destructive();
        let same = RestorePlan::resolve(request.clone()).await.unwrap();
        assert_eq!(plan.id(), same.id());
        let mut other_device = request.clone();
        other_device.device = other_device.device.with_ecid(Ecid::new(43));
        let other = RestorePlan::resolve(other_device).await.unwrap();
        assert!(!other.accepts(&consent));
        let replacement = firmware_fixture_with_components(
            "7.1.2",
            &format!(
                "<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>other.dmg</string></dict></dict>{BASEBAND_MANIFEST}"
            ),
        );
        std::fs::copy(replacement.path(), file.path()).unwrap();
        let changed = RestorePlan::resolve(request).await.unwrap();
        assert!(!changed.accepts(&consent));
        assert_eq!(
            FirmwareArchive::open(plan.firmware())
                .unwrap()
                .build_manifest()
                .unwrap()
                .select_identity(&BoardConfig::from("n90"), RestoreBehavior::Erase)
                .unwrap()
                .component_path("RestoreRamDisk")
                .unwrap(),
            "ramdisk.dmg"
        );

        assert!(plan.accepts(&consent));
        assert_eq!(plan.product_version(), "7.1.2");
        assert_eq!(plan.components()[0].name, "RestoreRamDisk");
    }

    #[tokio::test]
    async fn rsep_auto_follows_the_target_major_version() {
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
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };

        let plan = RestorePlan::resolve(request(&legacy, RsepPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Skip);
        let plan = RestorePlan::resolve(request(&modern, RsepPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Send);
        // Explicit policies are preserved regardless of the target version.
        let plan = RestorePlan::resolve(request(&legacy, RsepPolicy::Send))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Send);
        let plan = RestorePlan::resolve(request(&modern, RsepPolicy::Skip))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Skip);
    }

    #[tokio::test]
    async fn cryptex_auto_gates_on_version_and_manifest() {
        const CRYPTEX_MANIFEST: &str = concat!(
            "<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key>",
            "<string>ramdisk.dmg</string></dict></dict>",
            "<key>Cryptex1,SystemOS</key><dict><key>Info</key><dict><key>Path</key>",
            "<string>cryptex.dmg</string></dict></dict>",
        );
        let modern = firmware_fixture_with_components("16.7.10", CRYPTEX_MANIFEST);
        let modern_without = firmware_fixture_with_version("16.7.10");
        let legacy = firmware_fixture_with_components("15.8.3", CRYPTEX_MANIFEST);
        let request = |firmware: &NamedTempFile, cryptex| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            cryptex,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };

        // iOS 16+ with a Cryptex1,SystemOS manifest entry enables handling.
        let plan = RestorePlan::resolve(request(&modern, CryptexPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.cryptex_source(), Some(&CryptexSource::Target));
        // iOS 15.x and identities without Cryptex1,SystemOS stay disabled.
        let plan = RestorePlan::resolve(request(&modern_without, CryptexPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.cryptex_source(), None);
        let plan = RestorePlan::resolve(request(&legacy, CryptexPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.cryptex_source(), None);
        let plan = RestorePlan::resolve(request(&modern, CryptexPolicy::None))
            .await
            .unwrap();
        assert_eq!(plan.cryptex_source(), None);
    }

    #[tokio::test]
    async fn cryptex_provided_source_must_exist() {
        let firmware = firmware_fixture_with_version("16.7.10");
        let request = RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Provided(PathBuf::from("/nonexistent.ipsw")),
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };

        assert!(matches!(
            RestorePlan::resolve(request).await,
            Err(RestorePlanError::CryptexSourceNotFound(_))
        ));
    }

    #[tokio::test]
    async fn skip_ticket_requires_pwned_boot_chain() {
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
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        };

        let error = RestorePlan::resolve(request(ExploitPolicy::None))
            .await
            .unwrap_err();
        assert!(matches!(error, RestorePlanError::SkipTicketRequiresExploit));
        RestorePlan::resolve(request(ExploitPolicy::AlreadyPwned))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn boot_overrides_must_be_paired_and_exist() {
        let firmware = firmware_fixture();
        let rdsk = NamedTempFile::new().unwrap();
        let base = |rdsk, rkrn| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk,
            rkrn,
        };

        // Only one of the pair is rejected.
        let error = RestorePlan::resolve(base(Some(rdsk.path().to_owned()), None))
            .await
            .unwrap_err();
        assert!(matches!(error, RestorePlanError::BootOverridePair));
        // A missing file is rejected.
        let error = RestorePlan::resolve(base(
            Some(rdsk.path().to_owned()),
            Some(PathBuf::from("/nonexistent-kcache.im4p")),
        ))
        .await
        .unwrap_err();
        assert!(matches!(error, RestorePlanError::BootOverrideNotFound(_)));
    }

    #[tokio::test]
    async fn boot_overrides_force_rsep_send() {
        let firmware = firmware_fixture();
        let rdsk = NamedTempFile::new().unwrap();
        let rkrn = NamedTempFile::new().unwrap();
        let request = |rsep| RestoreRequest {
            device: DeviceIdentity::new(ProductType::from("iPhone3,1"), Soc::A4)
                .with_board_config(BoardConfig::from("n90"))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.path().to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep,
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: Some(rdsk.path().to_owned()),
            rkrn: Some(rkrn.path().to_owned()),
        };

        // The iPhone X flow always sends RestoreSEP, even for a pre-16 target.
        let plan = RestorePlan::resolve(request(RsepPolicy::Auto))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Send);
        assert!(plan.boot_overrides().is_some());
        // Explicit policies still win.
        let plan = RestorePlan::resolve(request(RsepPolicy::Skip))
            .await
            .unwrap();
        assert_eq!(plan.rsep_policy(), RsepPolicy::Skip);
    }

    #[tokio::test]
    async fn bb2_devices_disable_baseband_for_non_latest_targets() {
        // iPhone3,1 restoring 6.1.3: the baseband update is disabled (upstream
        // device_use_bb2), no aux firmware is fetched.
        let firmware =
            firmware_fixture_for("iPhone3,1", "n90ap", "6.1.3", "10B329", RAMDISK_MANIFEST);
        let plan = RestorePlan::resolve_with_catalog(
            base_request("iPhone3,1", "n90", Soc::A4, firmware.path()),
            &PanicCatalog,
        )
        .await
        .unwrap();
        assert_eq!(plan.aux_firmware(), None);

        // Restoring the `use` version keeps the baseband, taken from the
        // target IPSW's own BasebandFirmware entry.
        let firmware = firmware_fixture();
        let plan = RestorePlan::resolve_with_catalog(
            base_request("iPhone3,1", "n90", Soc::A4, firmware.path()),
            &PanicCatalog,
        )
        .await
        .unwrap();
        let aux = plan.aux_firmware().unwrap();
        assert_eq!(aux.version(), "7.1.2");
        assert_eq!(aux.build(), "11D257");
        assert_eq!(aux.source(), &AuxFirmwareSource::Target);
        assert!(!aux.sep(), "32-bit devices have no SEP");
        let baseband = aux.baseband().unwrap();
        assert_eq!(baseband.path(), "Firmware/baseband.bbfw");
        assert_eq!(baseband.sha1(), None);
    }

    #[tokio::test]
    async fn a7_ios10_targets_use_the_target_ipsw_locally() {
        // iPhone6,1 restoring 10.3.3: aux == target, so nothing is fetched;
        // SEP and the table baseband come from the target IPSW.
        let firmware = a7_firmware_fixture("10.3.3", "14G60");
        let plan = RestorePlan::resolve_with_catalog(
            base_request("iPhone6,1", "n51", Soc::A7, firmware.path()),
            &PanicCatalog,
        )
        .await
        .unwrap();

        let aux = plan.aux_firmware().unwrap();
        assert_eq!(aux.version(), "10.3.3");
        assert_eq!(aux.build(), "14G60");
        assert_eq!(aux.source(), &AuxFirmwareSource::Target);
        assert!(aux.sep());
        let baseband = aux.baseband().unwrap();
        assert_eq!(baseband.path(), "Firmware/Mav7Mav8-7.60.00.Release.bbfw");
        assert_eq!(
            baseband.sha1(),
            Some("f397724367f6bed459cf8f3d523553c13e8ae12c")
        );

        // The plan serializes for CLI plan output.
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(json["aux"]["source"]["kind"], "target");
    }

    #[tokio::test]
    async fn a7_other_targets_fetch_the_remote_aux_manifest() {
        // iPhone6,1 restoring 12.0.1: aux is the latest 12.5.8 build, resolved
        // through the catalog and pinned by manifest SHA-256.
        let aux_manifest = aux_manifest_fixture("12.5.8", "16H88");
        let aux_sha256 = hex::encode(Sha256::digest(&aux_manifest));
        let catalog = StubCatalog {
            url: "https://example.com/iPhone_4.0_64bit_12.5.8_16H88_Restore.ipsw".to_owned(),
            manifest: aux_manifest,
        };
        let firmware = a7_firmware_fixture("12.0.1", "16A404");
        let plan = RestorePlan::resolve_with_catalog(
            base_request("iPhone6,1", "n51", Soc::A7, firmware.path()),
            &catalog,
        )
        .await
        .unwrap();

        let aux = plan.aux_firmware().unwrap();
        assert_eq!(aux.version(), "12.5.8");
        assert_eq!(aux.build(), "16H88");
        assert_eq!(
            aux.source(),
            &AuxFirmwareSource::Remote {
                url: catalog.url.clone(),
                manifest_sha256: aux_sha256,
            }
        );
        assert!(aux.sep());
        let baseband = aux.baseband().unwrap();
        assert_eq!(baseband.path(), "Firmware/Mav7Mav8-10.80.02.Release.bbfw");
        assert_eq!(
            baseband.sha1(),
            Some("f5db17f72a78d807a791138cd5ca87d2f5e859f0")
        );
    }

    #[tokio::test]
    async fn a8_baseband_path_comes_from_the_aux_manifest() {
        // iPhone7,2 (A8) restoring 14.8: aux is the latest 12.5.8 build; the
        // device table records no baseband file, so the plan records the
        // BasebandFirmware path of the fetched aux manifest.
        let catalog = StubCatalog {
            url: "https://example.com/iPhone_4.0_64bit_12.5.8_16H88_Restore.ipsw".to_owned(),
            manifest: aux_manifest_fixture("12.5.8", "16H88"),
        };
        let firmware = firmware_fixture_for("iPhone7,2", "n61ap", "14.8", "18H17", MODERN_MANIFEST);
        let plan = RestorePlan::resolve_with_catalog(
            base_request("iPhone7,2", "n61", Soc::A8, firmware.path()),
            &catalog,
        )
        .await
        .unwrap();

        let aux = plan.aux_firmware().unwrap();
        assert_eq!(aux.build(), "16H88");
        assert!(aux.sep());
        let baseband = aux.baseband().unwrap();
        assert_eq!(baseband.path(), "Firmware/Mav7Mav8-10.80.02.Release.bbfw");
        assert_eq!(baseband.sha1(), None);
    }

    #[tokio::test]
    async fn plan_id_reflects_the_aux_resolution() {
        let firmware = a7_firmware_fixture("12.0.1", "16A404");
        let request = |sep: SepPolicy| {
            let mut request = base_request("iPhone6,1", "n51", Soc::A7, firmware.path());
            request.sep = sep;
            // Isolate the SEP variable of the aux resolution.
            request.baseband = BasebandPolicy::None;
            request
        };
        let catalog = StubCatalog {
            url: "https://example.com/iPhone_4.0_64bit_12.5.8_16H88_Restore.ipsw".to_owned(),
            manifest: aux_manifest_fixture("12.5.8", "16H88"),
        };

        let with_aux = RestorePlan::resolve_with_catalog(request(SepPolicy::Auto), &catalog)
            .await
            .unwrap();
        let again = RestorePlan::resolve_with_catalog(request(SepPolicy::Auto), &catalog)
            .await
            .unwrap();
        assert_eq!(with_aux.id(), again.id());
        // A plan without SEP handling and a plan whose remote manifest content
        // differs both produce different plan ids.
        let without_aux =
            RestorePlan::resolve_with_catalog(request(SepPolicy::None), &PanicCatalog)
                .await
                .unwrap();
        assert_ne!(with_aux.id(), without_aux.id());
        let tampered = StubCatalog {
            manifest: aux_manifest_fixture("12.5.8 ", "16H88"),
            ..catalog
        };
        let other = RestorePlan::resolve_with_catalog(request(SepPolicy::Auto), &tampered)
            .await
            .unwrap();
        assert_ne!(with_aux.id(), other.id());
    }

    #[tokio::test]
    async fn aux_resolution_failures_fail_planning() {
        let firmware = a7_firmware_fixture("12.0.1", "16A404");
        let request = || base_request("iPhone6,1", "n51", Soc::A7, firmware.path());

        // The catalog cannot resolve the aux build.
        let error = RestorePlan::resolve_with_catalog(
            request(),
            &StubCatalog {
                url: String::new(),
                manifest: Vec::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RestorePlanError::AuxFirmware(_)));

        // The fetched manifest belongs to another build.
        let error = RestorePlan::resolve_with_catalog(
            request(),
            &StubCatalog {
                url: "https://example.com/16H88_Restore.ipsw".to_owned(),
                manifest: aux_manifest_fixture("12.5.7", "16H81"),
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                RestorePlanError::AuxFirmware(AuxFirmwareError::BuildMismatch { .. })
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn provided_policies_keep_their_local_sources() {
        // Provided SEP/baseband IPSWs never consult the aux catalog.
        let firmware = a7_firmware_fixture("12.0.1", "16A404");
        let sep_ipsw = a7_firmware_fixture("12.5.8", "16H88");
        let mut request = base_request("iPhone6,1", "n51", Soc::A7, firmware.path());
        request.sep = SepPolicy::Provided(sep_ipsw.path().to_owned());
        request.baseband = BasebandPolicy::Provided(sep_ipsw.path().to_owned());

        let plan = RestorePlan::resolve_with_catalog(request, &PanicCatalog)
            .await
            .unwrap();
        assert_eq!(plan.aux_firmware(), None);

        // A provided SEP IPSW without a RestoreSEP component is rejected.
        let bad_sep =
            firmware_fixture_for("iPhone6,1", "n51ap", "12.5.8", "16H88", RAMDISK_MANIFEST);
        let mut request = base_request("iPhone6,1", "n51", Soc::A7, firmware.path());
        request.sep = SepPolicy::Provided(bad_sep.path().to_owned());
        request.baseband = BasebandPolicy::None;
        let error = RestorePlan::resolve_with_catalog(request, &PanicCatalog)
            .await
            .unwrap_err();
        assert!(matches!(error, RestorePlanError::MissingProvidedSep));
    }

    #[derive(Debug)]
    struct PanicCatalog;

    impl AuxFirmwareCatalog for PanicCatalog {
        fn resolve_ipsw_url<'a>(
            &'a self,
            _product_type: &'a ProductType,
            _build: &'a str,
        ) -> AuxCatalogFuture<'a, String> {
            panic!("tests must not resolve aux firmware URLs")
        }

        fn fetch_build_manifest<'a>(&'a self, _url: &'a str) -> AuxCatalogFuture<'a, Vec<u8>> {
            panic!("tests must not fetch aux firmware manifests")
        }
    }

    /// A catalog serving canned data; `url`/`manifest` are empty to simulate
    /// an appledb lookup failure.
    #[derive(Debug)]
    struct StubCatalog {
        url: String,
        manifest: Vec<u8>,
    }

    impl AuxFirmwareCatalog for StubCatalog {
        fn resolve_ipsw_url<'a>(
            &'a self,
            product_type: &'a ProductType,
            build: &'a str,
        ) -> AuxCatalogFuture<'a, String> {
            Box::pin(async move {
                if self.url.is_empty() {
                    return Err(AuxFirmwareError::NoIpswSource {
                        product: product_type.clone(),
                        build: build.to_owned(),
                    });
                }
                Ok(self.url.clone())
            })
        }

        fn fetch_build_manifest<'a>(&'a self, _url: &'a str) -> AuxCatalogFuture<'a, Vec<u8>> {
            Box::pin(async move { Ok(self.manifest.clone()) })
        }
    }

    fn base_request(
        product: &str,
        board: &str,
        soc: Soc,
        firmware: &std::path::Path,
    ) -> RestoreRequest {
        RestoreRequest {
            device: DeviceIdentity::new(ProductType::from(product), soc)
                .with_board_config(BoardConfig::from(board))
                .with_ecid(Ecid::new(42)),
            firmware: firmware.to_owned(),
            behavior: RestoreBehavior::Erase,
            ticket: TicketPolicy::Signed,
            baseband: BasebandPolicy::Auto,
            sep: SepPolicy::Auto,
            rsep: RsepPolicy::Auto,
            cryptex: CryptexPolicy::Auto,
            cryptex_source: CryptexSource::Target,
            exploit: ExploitPolicy::Auto,
            nonce: NoncePolicy::Manual,
            rdsk: None,
            rkrn: None,
        }
    }

    const RAMDISK_MANIFEST: &str = "<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict>";
    const BASEBAND_MANIFEST: &str = "<key>BasebandFirmware</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/baseband.bbfw</string></dict></dict>";
    /// The SEP and baseband entries of a 64-bit firmware fixture.
    const MODERN_MANIFEST: &str = concat!(
        "<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict>",
        "<key>RestoreSEP</key><dict><key>Info</key><dict><key>Path</key>",
        "<string>Firmware/all_flash/sep-firmware.n51ap.RELEASE.im4p</string></dict></dict>",
        "<key>BasebandFirmware</key><dict><key>Info</key><dict><key>Path</key>",
        "<string>Firmware/Mav7Mav8-10.80.02.Release.bbfw</string></dict></dict>",
    );

    fn firmware_fixture() -> NamedTempFile {
        firmware_fixture_with_version("7.1.2")
    }

    fn firmware_fixture_with_version(version: &str) -> NamedTempFile {
        firmware_fixture_with_components(version, &format!("{RAMDISK_MANIFEST}{BASEBAND_MANIFEST}"))
    }

    fn firmware_fixture_with_components(version: &str, manifest: &str) -> NamedTempFile {
        firmware_fixture_for("iPhone3,1", "n90ap", version, "11D257", manifest)
    }

    fn a7_firmware_fixture(version: &str, build: &str) -> NamedTempFile {
        firmware_fixture_for("iPhone6,1", "n51ap", version, build, MODERN_MANIFEST)
    }

    /// A synthetic aux (latest-build) BuildManifest for the stub catalog.
    fn aux_manifest_fixture(version: &str, build: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>{version}</string>
<key>ProductBuildVersion</key><string>{build}</string>
<key>SupportedProductTypes</key><array><string>iPhone6,1</string><string>iPhone7,2</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n51ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>{MODERN_MANIFEST}</dict>
</dict><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n61ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>{MODERN_MANIFEST}</dict>
</dict></array>
</dict></plist>"#
        )
        .into_bytes()
    }

    fn firmware_fixture_for(
        product: &str,
        device_class: &str,
        version: &str,
        build: &str,
        manifest: &str,
    ) -> NamedTempFile {
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
<key>ProductBuildVersion</key><string>{build}</string>
<key>SupportedProductTypes</key><array><string>{product}</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>{device_class}</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>{manifest}</dict>
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
