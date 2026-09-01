//! Restore-side execution for classic custom IPSWs, porting the
//! `device_proc 1`/`4`-old branches of upstream's `restore_deviceprepare`
//! (6500-6563) and `restore_prepare` (6574-6652) plus the S5L8900/old-device
//! parts of `restore_latest custom` (6336-6363) and idevicerestore's
//! `recovery_enter_restore` boot chain (LukeZGD/idevicerestore
//! `src/recovery.c`).
//!
//! Coverage:
//! - proc 1 (S5L8900: iPhone1,1/iPhone1,2/iPod1,1) iOS 3.x/4.x custom
//!   restores: pwn the device into Pwnage 2.0 WTF mode
//!   ([`crate::pwnage`]); on 4.x targets send the custom IPSW's patched WTF 2
//!   to reach DFU-real, then the custom iBSS; on 3.1.3 reach DFU-real with
//!   the pwnage WTF and send the custom iBSS.
//! - proc 4 old (S5L8720 iPod2,1, S5L8920 iPhone2,1) iOS 3.x/4.2.x custom
//!   restores with a per-component SHSH blob (`restore_idevicerestore -ew`):
//!   pwned DFU (24kpwn marker, or limera1n on the S5L8920), personalized iBSS,
//!   then the old-style boot chain (auto-boot off, ramdisk + `ramdisk`,
//!   device tree + `devicetree`, kernelcache, `setenv boot-args
//!   rd=md0 nand-enable-reformat=1 -progress` on build major >= 8, `bootx`).
//! - Foreign custom IPSWs (`restore_customipsw`: whited00r/GeekGrade) restore
//!   ticket-free on both device classes (`idevicerestore -e -c`, no `-w`).
//!
//! Engine compatibility: the restore engine's restored session (mux port
//! 62078, QueryType/QueryValue handshake, StartRestore, DataRequest/StatusMsg
//! loop with protocol < 14 progress adaptation) speaks the protocol old
//! ramdisks implement, so the session-level pieces ([`RestoredConnector`],
//! [`run_restored_session_with_dispatcher`], [`AsrClient`]) are reused
//! directly. The workflow-level `run_restore`/`boot_restore`/`RestorePlan`
//! are deliberately not reused: 3.1.3 IPSWs have no BuildManifest, old 4.x
//! blobs are per-component `Blob` dicts without a root APTicket, and the
//! patched old iBSS does not set the PWND marker `boot_restore` requires.
//! Old devices have no FDR, SEP, or boot nonce; baseband data requests error
//! out like the workflow runner with baseband disabled. The
//! RestoreLogo/`setpicture` step and idevicerestore's pre-bootx USB control
//! transfer are skipped (cosmetic / not exposed by the transport); the
//! restored QueryValue/HardwareInfo handshake on old ramdisks is
//! hardware-unverified.

use std::{
    fmt,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use legacy_ios_core::{
    ActionId, ActionKind, BoardConfig, BuildId, CancellationSafety, DeviceIdentity, DeviceMode,
    Ecid, IosVersion, OperationEvent, OperationKind, OperationOutcome, OperationPhase, Progress,
    ProgressUnit, Soc,
};
use legacy_ios_firmware::{BuildIdentity, FirmwareArchive, RestoreBehavior};
use legacy_ios_image::Img3;
use legacy_ios_restore::{
    ASR_PORT, AsrClient, DataRequest, PreparedRestoreData, RestoreOptions, RestoredConnector,
    run_restored_session_with_dispatcher,
};
use legacy_ios_transport::{IbootClient, RecoveryError, UploadResult};
use plist::{Dictionary, Value};
use tracing::{debug, info};

use crate::{
    DeviceManager, KitError, OperationHandle, lease::DeviceLeaseRegistry,
    operation::OperationEmitter, pwnage,
};

/// `setenv auto-boot false` + ramdisk/devicetree/kernelcache/bootx timeouts.
const REENUMERATION_TIMEOUT: Duration = Duration::from_secs(60);
/// idevicerestore's pause after the `ramdisk` command.
const RAMDISK_DELAY: Duration = Duration::from_secs(2);
const DEVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(600);
const RESTORED_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(120);
const RESTORE_BOOT_ARGS: &str = "rd=md0 nand-enable-reformat=1 -progress";

/// Pwned-chain entry and boot sequence of a classic restore, per the upstream
/// dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicBootSequence {
    /// S5L8900 4.x targets: pwned Pwnage 2.0 WTF mode, custom WTF 2 to
    /// DFU-real, custom iBSS to recovery (`restore_latest custom`'s
    /// iPhone1,2 4.x branch).
    WtfRealThenIbss,
    /// S5L8900 3.x targets: pwned DFU-real via the pwnage WTF, then the
    /// custom iBSS to recovery (`restore_latest custom`'s 3.1.3 branch).
    DfuThenIbss,
    /// iPod2,1/iPhone2,1: pwned DFU (24kpwn/limera1n), personalized iBSS to
    /// recovery (`restore_idevicerestore -ew`).
    PwnedDfu,
}

impl ClassicBootSequence {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WtfRealThenIbss => "wtf-real-ibss",
            Self::DfuThenIbss => "dfu-ibss",
            Self::PwnedDfu => "pwned-dfu",
        }
    }
}

/// Request for a classic custom IPSW restore.
pub struct ClassicRestoreRequest {
    device: DeviceIdentity,
    firmware: PathBuf,
    cache_root: PathBuf,
    foreign: bool,
    ticket: Option<PathBuf>,
    limera1n_payload: Option<Vec<u8>>,
    final_verification: bool,
}

impl ClassicRestoreRequest {
    /// `device` must carry a board config and an ECID. `firmware` is the
    /// classic custom IPSW; `cache_root` backs the pwnage payload fetch of
    /// the S5L8900 sequences.
    pub fn new(
        device: DeviceIdentity,
        firmware: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            device,
            firmware: firmware.into(),
            cache_root: cache_root.into(),
            foreign: false,
            ticket: None,
            limera1n_payload: None,
            final_verification: true,
        }
    }

    /// Foreign custom IPSW (`restore_customipsw`): restores ticket-free on
    /// every supported device.
    pub fn with_foreign(mut self, enabled: bool) -> Self {
        self.foreign = enabled;
        self
    }

    /// Per-component 3.x/4.x SHSH blob of the device; required for
    /// self-built iPod2,1/iPhone2,1 restores, rejected elsewhere.
    pub fn with_ticket(mut self, ticket: Option<PathBuf>) -> Self {
        self.ticket = ticket;
        self
    }

    /// limera1n payload for pwning an S5L8920 (iPhone2,1) in DFU mode.
    pub fn with_limera1n_payload(mut self, payload: Vec<u8>) -> Self {
        self.limera1n_payload = Some(payload);
        self
    }

    /// Skip the final wait for a normal-mode device and version check.
    pub fn with_final_verification(mut self, enabled: bool) -> Self {
        self.final_verification = enabled;
        self
    }
}

impl fmt::Debug for ClassicRestoreRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicRestoreRequest")
            .field("device", &self.device)
            .field("firmware", &self.firmware)
            .field("foreign", &self.foreign)
            .field("ticket", &self.ticket)
            .field("final_verification", &self.final_verification)
            .finish_non_exhaustive()
    }
}

/// Resolved custom-IPSW entry paths of a classic restore.
#[derive(Clone, Debug)]
struct ClassicPaths {
    ibss: String,
    /// Custom WTF 2 (S5L8900 4.x only).
    wtf2: Option<String>,
    llb: String,
    device_tree: String,
    kernel_cache: String,
    ramdisk: String,
    rootfs: String,
}

/// A resolved classic restore plan, ready to execute after destructive
/// consent.
#[derive(Clone)]
pub struct ClassicRestorePlan {
    id: String,
    device: DeviceIdentity,
    firmware: PathBuf,
    cache_root: PathBuf,
    version: IosVersion,
    build: BuildId,
    build_major: u32,
    board: BoardConfig,
    sequence: ClassicBootSequence,
    foreign: bool,
    blob: Option<Dictionary>,
    paths: ClassicPaths,
    /// NOR components (name, entry path), excluding the LLB.
    nor: Vec<(String, String)>,
    /// `IsLoadedByiBoot` components (name, entry path), sent with the
    /// `firmware` command before the ramdisk.
    loaded_by_iboot: Vec<(String, String)>,
    limera1n_payload: Option<Vec<u8>>,
    final_verification: bool,
}

impl ClassicRestorePlan {
    /// Plan id binding the destructive consent.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    pub const fn version(&self) -> &IosVersion {
        &self.version
    }

    pub const fn build_id(&self) -> &BuildId {
        &self.build
    }

    pub const fn board_config(&self) -> &BoardConfig {
        &self.board
    }

    pub const fn sequence(&self) -> ClassicBootSequence {
        self.sequence
    }

    /// Whether this is a foreign (ticket-free) custom IPSW restore.
    pub const fn foreign(&self) -> bool {
        self.foreign
    }

    pub fn confirm_destructive(&self) -> ClassicRestoreConsent {
        ClassicRestoreConsent {
            plan_id: self.id.clone(),
        }
    }

    pub fn accepts(&self, consent: &ClassicRestoreConsent) -> bool {
        consent.plan_id == self.id
    }
}

impl fmt::Debug for ClassicRestorePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicRestorePlan")
            .field("id", &self.id)
            .field("device", &self.device)
            .field("firmware", &self.firmware)
            .field("version", &self.version)
            .field("build", &self.build)
            .field("sequence", &self.sequence)
            .field("foreign", &self.foreign)
            .finish_non_exhaustive()
    }
}

/// Destructive consent bound to a [`ClassicRestorePlan`] id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicRestoreConsent {
    plan_id: String,
}

impl ClassicRestoreConsent {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
}

/// Resolve a classic restore plan: gate the device and target version, read
/// the component paths from the BuildManifest (or, for 3.x S5L8900 IPSWs,
/// `Restore.plist`), and validate the ticket per upstream's rules.
pub(crate) fn plan(request: ClassicRestoreRequest) -> Result<ClassicRestorePlan, KitError> {
    let device = request.device;
    let soc = device.soc();
    match soc {
        Soc::S5l8900 | Soc::S5l8720 | Soc::S5l8920 => {}
        _ => {
            return Err(KitError::ClassicRestoreUnsupportedDevice(format!(
                "{} ({soc})",
                device.product_type()
            )));
        }
    }
    let ecid = device.ecid().ok_or(KitError::MissingDeviceSelector)?;
    let board = device
        .board_config()
        .cloned()
        .ok_or(KitError::ClassicRestoreMissingBoardConfig)?;

    let archive = FirmwareArchive::open(&request.firmware)?;
    let manifest = archive.build_manifest().ok();
    let (version, build, identity, paths) = match &manifest {
        Some(manifest) => {
            let identity = manifest
                .select_identity(&board, RestoreBehavior::Erase)?
                .clone();
            let paths = ClassicPaths {
                ibss: component_path(&identity, "iBSS")?,
                wtf2: None,
                llb: component_path(&identity, "LLB")?,
                device_tree: component_path(&identity, "RestoreDeviceTree")?,
                kernel_cache: component_path(&identity, "RestoreKernelCache")?,
                ramdisk: component_path(&identity, "RestoreRamDisk")?,
                rootfs: component_path(&identity, "OS")?,
            };
            (
                manifest.product_version().clone(),
                manifest.build_id().clone(),
                Some(identity),
                paths,
            )
        }
        None if soc == Soc::S5l8900 => {
            let (version, build, paths) = restore_plist_paths(&archive, &board)?;
            (version, build, None, paths)
        }
        None => {
            return Err(KitError::ClassicRestoreMissingComponent(
                "BuildManifest.plist".to_owned(),
            ));
        }
    };

    let major = version
        .as_str()
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok());
    if !matches!(major, Some(3 | 4)) {
        return Err(KitError::ClassicRestoreUnsupportedVersion(format!(
            "{} {}",
            device.product_type(),
            version
        )));
    }
    let build_major = build
        .as_str()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .map_err(|_| {
            KitError::ClassicRestoreUnsupportedVersion(format!(
                "{} {} ({})",
                device.product_type(),
                version,
                build
            ))
        })?;

    let sequence = match soc {
        Soc::S5l8900 if major == Some(4) => ClassicBootSequence::WtfRealThenIbss,
        Soc::S5l8900 => ClassicBootSequence::DfuThenIbss,
        _ => ClassicBootSequence::PwnedDfu,
    };
    let mut paths = paths;
    if sequence == ClassicBootSequence::WtfRealThenIbss {
        paths.wtf2 = Some("Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu".to_owned());
    }

    // Ticket rules: S5L8900 restores are unsigned; foreign custom IPSWs
    // restore ticket-free on every device; self-built iPod2,1/iPhone2,1
    // restores require a per-component blob (upstream's `-w`).
    let blob = match (soc, request.foreign, request.ticket) {
        (Soc::S5l8900, _, Some(_)) => {
            return Err(KitError::ClassicRestoreTicketRejected(
                "S5L8900 restores do not use a signing ticket",
            ));
        }
        (_, true, Some(_)) => {
            return Err(KitError::ClassicRestoreTicketRejected(
                "foreign custom IPSW restores do not use a signing ticket",
            ));
        }
        (Soc::S5l8720 | Soc::S5l8920, false, None) => {
            return Err(KitError::ClassicRestoreTicketRequired);
        }
        (_, _, None) => None,
        (_, _, Some(path)) => Some(parse_blob(&path, ecid)?),
    };

    // idevicerestore fails the restore when a component has no blob entry;
    // check the always-sent components at plan time instead.
    if let Some(blob) = &blob {
        for component in [
            "iBSS",
            "LLB",
            "RestoreRamDisk",
            "RestoreDeviceTree",
            "RestoreKernelCache",
        ] {
            if blob_entry(blob, component).is_none() {
                return Err(KitError::ClassicRestoreTicketMismatch(
                    "a required component has no blob entry",
                ));
            }
        }
    }

    let nor = nor_components(&archive, identity.as_ref(), &paths.llb)?;
    let loaded_by_iboot = identity
        .as_ref()
        .map(loaded_by_iboot_components)
        .unwrap_or_default();

    let mut required = vec![
        paths.ibss.clone(),
        paths.llb.clone(),
        paths.device_tree.clone(),
        paths.kernel_cache.clone(),
        paths.ramdisk.clone(),
        paths.rootfs.clone(),
    ];
    required.extend(paths.wtf2.iter().cloned());
    required.extend(nor.iter().map(|(_, path)| path.clone()));
    required.extend(loaded_by_iboot.iter().map(|(_, path)| path.clone()));
    let entries = archive.entry_names()?;
    for path in required {
        if !entries.contains(&path) {
            return Err(KitError::ClassicRestoreMissingComponent(path));
        }
    }

    let id = plan_id(&[
        "classic-restore",
        device.product_type().as_str(),
        board.as_str(),
        version.as_str(),
        build.as_str(),
        sequence.name(),
        if request.foreign { "foreign" } else { "self" },
        &request.firmware.to_string_lossy(),
    ]);

    info!(
        product = %device.product_type(),
        version = %version,
        build = %build,
        sequence = sequence.name(),
        foreign = request.foreign,
        "resolved classic restore plan"
    );
    Ok(ClassicRestorePlan {
        id,
        device,
        firmware: request.firmware,
        cache_root: request.cache_root,
        version,
        build,
        build_major,
        board,
        sequence,
        foreign: request.foreign,
        blob,
        paths,
        nor,
        loaded_by_iboot,
        limera1n_payload: request.limera1n_payload,
        final_verification: request.final_verification,
    })
}

fn component_path(identity: &BuildIdentity, component: &'static str) -> Result<String, KitError> {
    identity
        .component_path(component)
        .map(str::to_owned)
        .map_err(|_| KitError::ClassicRestoreMissingComponent(component.to_owned()))
}

/// Version/build and fixed component paths of a 3.x S5L8900 IPSW, which
/// carries `Restore.plist` instead of a BuildManifest.
fn restore_plist_paths(
    archive: &FirmwareArchive,
    board: &BoardConfig,
) -> Result<(IosVersion, BuildId, ClassicPaths), KitError> {
    let bytes = archive.read_entry("Restore.plist")?;
    let value = plist::Value::from_reader(Cursor::new(bytes))?;
    if value.as_dictionary().is_none() {
        return Err(KitError::ClassicRestoreMissingComponent(
            "Restore.plist".to_owned(),
        ));
    }
    let get = |path: &[&str]| {
        let missing = || {
            KitError::ClassicRestoreMissingComponent(format!("Restore.plist {}", path.join(".")))
        };
        let mut value = value.clone();
        for key in path {
            value = value
                .as_dictionary()
                .and_then(|dictionary| dictionary.get(key).cloned())
                .ok_or_else(missing)?;
        }
        value.as_string().map(str::to_owned).ok_or_else(missing)
    };
    let board = board.as_str();
    let all_flash = format!("Firmware/all_flash/all_flash.{board}ap");
    let paths = ClassicPaths {
        ibss: format!("Firmware/dfu/iBSS.{board}ap.RELEASE.dfu"),
        wtf2: None,
        llb: format!("{all_flash}/LLB.{board}ap.RELEASE.img3"),
        device_tree: format!("{all_flash}/DeviceTree.{board}ap.img3"),
        kernel_cache: get(&["RestoreKernelCaches", "Release"])?,
        ramdisk: get(&["RestoreRamDisks", "User"])?,
        rootfs: get(&["SystemRestoreImages", "User"])?,
    };
    Ok((
        IosVersion::from(get(&["ProductVersion"])?),
        BuildId::from(get(&["ProductBuildVersion"])?),
        paths,
    ))
}

/// The NOR component list: the all_flash manifest file when present, else
/// the build identity's firmware payloads (mirroring the workflow
/// personalizer's fallback).
fn nor_components(
    archive: &FirmwareArchive,
    identity: Option<&BuildIdentity>,
    llb_path: &str,
) -> Result<Vec<(String, String)>, KitError> {
    let directory = llb_path
        .rsplit_once('/')
        .map(|(directory, _)| directory)
        .ok_or(KitError::ClassicRestoreMissingComponent(
            "all_flash manifest".to_owned(),
        ))?;
    let manifest_path = format!("{directory}/manifest");
    if let Ok(data) = archive.read_entry(&manifest_path) {
        let manifest = String::from_utf8(data)
            .map_err(|_| KitError::ClassicRestoreMissingComponent(manifest_path.clone()))?;
        return Ok(manifest
            .lines()
            .filter_map(|line| {
                let filename = line.trim_end_matches('\r');
                component_name(filename)
                    .filter(|component| *component != "LLB")
                    .map(|component| (component.to_owned(), format!("{directory}/{filename}")))
            })
            .collect());
    }
    identity
        .map(|identity| {
            identity
                .manifest()
                .iter()
                .filter_map(|(component, value)| {
                    let info = value.as_dictionary()?.get("Info")?.as_dictionary()?;
                    let firmware = info
                        .get("IsFirmwarePayload")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    let secondary = info
                        .get("IsSecondaryFirmwarePayload")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    let loaded_by_iboot = info
                        .get("IsLoadedByiBoot")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    (firmware || secondary && loaded_by_iboot).then(|| {
                        let path = info.get("Path")?.as_string()?;
                        (component != "LLB").then(|| (component.clone(), path.to_owned()))
                    })?
                })
                .collect()
        })
        .ok_or(KitError::ClassicRestoreMissingComponent(manifest_path))
}

/// The build identity's `IsLoadedByiBoot` components (excluding stage-1),
/// sent with the `firmware` command ahead of the ramdisk
/// (`recovery_send_loaded_by_iboot`).
fn loaded_by_iboot_components(identity: &BuildIdentity) -> Vec<(String, String)> {
    identity
        .manifest()
        .iter()
        .filter_map(|(component, value)| {
            let info = value.as_dictionary()?.get("Info")?.as_dictionary()?;
            let stage1 = info
                .get("IsLoadedByiBootStage1")
                .and_then(Value::as_boolean)
                .unwrap_or(false);
            let loaded = info
                .get("IsLoadedByiBoot")
                .and_then(Value::as_boolean)
                .unwrap_or(false);
            (loaded && !stage1).then(|| {
                let path = info.get("Path")?.as_string()?;
                Some((component.clone(), path.to_owned()))
            })?
        })
        .collect()
}

/// NOR manifest filename prefix to component name (mirrors the workflow
/// personalizer's table).
fn component_name(filename: &str) -> Option<&'static str> {
    [
        ("LLB", "LLB"),
        ("iBoot", "iBoot"),
        ("DeviceTree", "DeviceTree"),
        ("applelogo", "AppleLogo"),
        ("liquiddetect", "Liquid"),
        ("recoverymode", "RecoveryMode"),
        ("batterylow0", "BatteryLow0"),
        ("batterylow1", "BatteryLow1"),
        ("glyphcharging", "BatteryCharging"),
        ("glyphplugin", "BatteryPlugin"),
        ("batterycharging0", "BatteryCharging0"),
        ("batterycharging1", "BatteryCharging1"),
        ("batteryfull", "BatteryFull"),
        ("needservice", "NeedService"),
    ]
    .into_iter()
    .find_map(|(prefix, component)| filename.starts_with(prefix).then_some(component))
}

fn parse_blob(path: &Path, ecid: Ecid) -> Result<Dictionary, KitError> {
    let value = plist::Value::from_reader(Cursor::new(std::fs::read(path)?))?;
    let dictionary = value
        .into_dictionary()
        .ok_or(KitError::ClassicRestoreTicketMismatch(
            "the blob is not a plist dictionary",
        ))?;
    if let Some(blob_ecid) = dictionary
        .get("ApECID")
        .and_then(Value::as_unsigned_integer)
        && blob_ecid != ecid.get()
    {
        return Err(KitError::ClassicRestoreTicketMismatch(
            "ApECID does not match the device",
        ));
    }
    Ok(dictionary)
}

/// The per-component IMG3 blob of an old SHSH dictionary
/// (`RestoreRamDisk` entries are commonly named `RestoreRamdisk`).
fn blob_entry<'a>(blob: &'a Dictionary, component: &str) -> Option<&'a [u8]> {
    let entry = blob.get(component).or_else(|| {
        (component == "RestoreRamDisk")
            .then(|| blob.get("RestoreRamdisk"))
            .flatten()
    });
    entry
        .and_then(Value::as_dictionary)
        .and_then(|entry| entry.get("Blob"))
        .and_then(Value::as_data)
}

/// Personalize one IMG3 component with its blob entry; without a blob the
/// component ships raw (S5L8900 and foreign restores).
fn personalize(
    component: &str,
    data: Vec<u8>,
    blob: Option<&Dictionary>,
) -> Result<Vec<u8>, KitError> {
    let Some(blob) = blob else { return Ok(data) };
    let Some(entry) = blob_entry(blob, component) else {
        debug!(component, "no blob entry; sending the component raw");
        return Ok(data);
    };
    Ok(Img3::parse(&data)?.personalize(entry)?.to_bytes())
}

fn plan_id(parts: &[&str]) -> String {
    use sha1::Digest as _;
    let mut hasher = sha1::Sha1::new();
    for part in parts {
        hasher.update(part);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(40);
    for byte in digest {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    plan: ClassicRestorePlan,
    consent: ClassicRestoreConsent,
    work_directory: PathBuf,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(128);
    tokio::spawn(async move {
        match execute(&devices, &leases, &emitter, plan, consent, work_directory).await {
            Ok(Some(outcome)) => {
                emitter.emit(OperationEvent::Completed { outcome }).await;
            }
            Ok(None) => {}
            Err(error) => emitter.fail(error).await,
        }
    });
    handle
}

async fn execute(
    devices: &DeviceManager,
    leases: &DeviceLeaseRegistry,
    emitter: &OperationEmitter,
    plan: ClassicRestorePlan,
    consent: ClassicRestoreConsent,
    work_directory: PathBuf,
) -> Result<Option<OperationOutcome>, KitError> {
    if !plan.accepts(&consent) {
        return Err(KitError::ClassicRestoreConsentMismatch);
    }
    let ecid = plan.device.ecid().ok_or(KitError::MissingDeviceSelector)?;
    let selector = plan
        .device
        .selector()
        .ok_or(KitError::MissingDeviceSelector)?;

    emitter
        .emit(phase(
            OperationPhase::WaitingForDevice,
            CancellationSafety::Immediate,
        ))
        .await;
    let lease = leases.acquire(selector).await;
    if emitter.is_cancelled() {
        return Ok(None);
    }

    emitter
        .emit(phase(
            OperationPhase::Personalizing,
            CancellationSafety::AtCheckpoint,
        ))
        .await;
    let boot_plan = plan.clone();
    let boot = tokio::task::spawn_blocking(move || prepare_boot_data(&boot_plan))
        .await
        .map_err(|error| KitError::Task(error.to_string()))??;
    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }
    tokio::fs::create_dir_all(&work_directory).await?;
    let filesystem = work_directory.join(format!("filesystem-{}.dmg", plan.id()));
    FirmwareArchive::open(&plan.firmware)?
        .extract_entry_to(&plan.paths.rootfs, &filesystem)
        .await?;

    // The device must reach DFU (S5L8900 also accepts pwned WTF) before the
    // pwn stage; upstream pauses with DFU instructions here.
    emitter
        .emit(OperationEvent::ActionRequired {
            id: ActionId::new(1),
            action: ActionKind::FollowDfuInstructions {
                steps: dfu_steps(&plan),
            },
        })
        .await;
    let initial_modes: &[DeviceMode] = match plan.sequence {
        ClassicBootSequence::WtfRealThenIbss | ClassicBootSequence::DfuThenIbss => {
            &[DeviceMode::Dfu, DeviceMode::Wtf]
        }
        ClassicBootSequence::PwnedDfu => &[DeviceMode::Dfu],
    };
    let Some(client) =
        await_iboot(ecid, initial_modes, DEVICE_WAIT_TIMEOUT, "DFU", emitter).await?
    else {
        drop(lease);
        return Ok(None);
    };

    // The pwn and iBSS chains end with the device in recovery mode; each
    // chain emits its Exploiting/Booting phases.
    let Some(mut client) = (match plan.sequence {
        ClassicBootSequence::WtfRealThenIbss => wtf_real_chain(client, &plan, &boot, emitter).await,
        ClassicBootSequence::DfuThenIbss => dfu_real_chain(client, &plan, &boot, emitter).await,
        ClassicBootSequence::PwnedDfu => pwned_dfu_chain(client, &plan, &boot, emitter).await,
    })?
    else {
        drop(lease);
        return Ok(None);
    };

    // Old-style restore boot chain (idevicerestore recovery_enter_restore).
    client.send_command("setenv auto-boot false").await?;
    client.send_command("saveenv").await?;
    for data in &boot.loaded_by_iboot {
        client.upload_payload(data).await?;
        client.send_command("firmware").await?;
    }
    client.upload_payload(&boot.ramdisk).await?;
    client.send_command("ramdisk").await?;
    tokio::time::sleep(RAMDISK_DELAY).await;
    client.upload_payload(&boot.device_tree).await?;
    client.send_command("devicetree").await?;
    client.upload_payload(&boot.kernel_cache).await?;
    if plan.build_major >= 8 {
        client
            .send_command(&format!("setenv boot-args {RESTORE_BOOT_ARGS}"))
            .await?;
    }
    client.send_command("bootx").await?;
    drop(client);
    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }

    // Restored session: connect, then drive the DataRequest/StatusMsg loop
    // with the prepared data and the ASR system image transfer.
    let mut restored = RestoredConnector::default()
        .connect_by_ecid(ecid, RESTORED_CONNECT_TIMEOUT)
        .await?;
    let data_connector = restored.data_connector();
    let asr_started = Arc::new(AtomicBool::new(false));
    let restored_started = Arc::new(AtomicBool::new(false));
    let cancellation_deferred = Arc::new(AtomicBool::new(false));
    let options = RestoreOptions::erase().without_baseband();
    let prepared = boot.restored_data;
    let asr_emitter = emitter.clone();
    let restored_emitter = emitter.clone();
    let asr_deferred = cancellation_deferred.clone();
    run_restored_session_with_dispatcher(
        &mut restored,
        &options,
        move |request: DataRequest| {
            let prepared = prepared.clone();
            async move { Ok(prepared.dispatch(&request)?) }
        },
        move |port| {
            let data_connector = data_connector.clone();
            let filesystem = filesystem.clone();
            let emitter = asr_emitter.clone();
            let started = asr_started.clone();
            let deferred = asr_deferred.clone();
            async move {
                let stream = data_connector.connect(port.unwrap_or(ASR_PORT)).await?;
                let mut asr = AsrClient::initiate(stream).await?;
                asr.validate(&filesystem).await?;
                asr.send_payload(&filesystem, |value| {
                    note_cancellation(&emitter, &deferred);
                    if !started.swap(true, Ordering::Relaxed) {
                        emitter.try_emit(phase(
                            OperationPhase::TransferringFilesystem,
                            CancellationSafety::UnsafeUntilPhaseEnds,
                        ));
                    }
                    emitter.try_emit(OperationEvent::Progress(Progress {
                        phase: OperationPhase::TransferringFilesystem,
                        completed: value.transferred,
                        total: Some(value.total),
                        unit: ProgressUnit::Bytes,
                    }));
                })
                .await?;
                Ok(())
            }
        },
        {
            let cancellation_deferred = cancellation_deferred.clone();
            move |value: legacy_ios_restore::RestoreProgress| {
                note_cancellation(&restored_emitter, &cancellation_deferred);
                if !restored_started.swap(true, Ordering::Relaxed) {
                    restored_emitter.try_emit(phase(
                        OperationPhase::Restoring,
                        CancellationSafety::UnsafeUntilPhaseEnds,
                    ));
                }
                restored_emitter.try_emit(OperationEvent::Progress(Progress {
                    phase: OperationPhase::Restoring,
                    completed: value.completed,
                    total: Some(100),
                    unit: ProgressUnit::Percent,
                }));
            }
        },
    )
    .await?;

    if emitter.is_cancelled() {
        drop(lease);
        return Ok(None);
    }
    if !plan.final_verification {
        drop(lease);
        return Ok(Some(OperationOutcome {
            operation: OperationKind::Restore,
            summary: format!(
                "restored {} ({}) without final verification",
                plan.version, plan.build
            ),
        }));
    }
    emitter
        .emit(phase(
            OperationPhase::Verifying,
            CancellationSafety::Immediate,
        ))
        .await;
    let expected = format!("{} ({})", plan.version, plan.build);
    let actual = wait_for_normal_device(devices, ecid, emitter).await?;
    if actual != expected {
        return Err(KitError::VersionMismatch { expected, actual });
    }
    drop(lease);
    Ok(Some(OperationOutcome {
        operation: OperationKind::Restore,
        summary: format!("restored {actual}"),
    }))
}

fn note_cancellation(emitter: &OperationEmitter, deferred: &AtomicBool) {
    if emitter.is_cancelled() && !deferred.swap(true, Ordering::Relaxed) {
        emitter.try_emit(OperationEvent::CancellationDeferred {
            phase: OperationPhase::Restoring,
        });
    }
}

/// Personalized boot/restore components and the restored-session data of a
/// classic restore.
struct ClassicBootData {
    wtf2: Option<Vec<u8>>,
    ibss: Vec<u8>,
    ramdisk: Vec<u8>,
    device_tree: Vec<u8>,
    kernel_cache: Vec<u8>,
    loaded_by_iboot: Vec<Vec<u8>>,
    restored_data: PreparedRestoreData,
}

fn prepare_boot_data(plan: &ClassicRestorePlan) -> Result<ClassicBootData, KitError> {
    let archive = FirmwareArchive::open(&plan.firmware)?;
    let blob = plan.blob.as_ref();
    let wtf2 = plan
        .paths
        .wtf2
        .as_deref()
        .map(|path| archive.read_entry(path).map_err(KitError::from))
        .transpose()?;
    let ibss = personalize("iBSS", archive.read_entry(&plan.paths.ibss)?, blob)?;
    let ramdisk = personalize(
        "RestoreRamDisk",
        archive.read_entry(&plan.paths.ramdisk)?,
        blob,
    )?;
    let device_tree = personalize(
        "RestoreDeviceTree",
        archive.read_entry(&plan.paths.device_tree)?,
        blob,
    )?;
    let kernel_cache = personalize(
        "RestoreKernelCache",
        archive.read_entry(&plan.paths.kernel_cache)?,
        blob,
    )?;
    let loaded_by_iboot = plan
        .loaded_by_iboot
        .iter()
        .map(|(component, path)| personalize(component, archive.read_entry(path)?, blob))
        .collect::<Result<Vec<_>, KitError>>()?;

    let llb = personalize("LLB", archive.read_entry(&plan.paths.llb)?, blob)?;
    let mut images = plan
        .nor
        .iter()
        .map(|(component, path)| {
            personalize(component, archive.read_entry(path)?, blob)
                .map(|data| (component.clone(), data))
        })
        .collect::<Result<Vec<_>, KitError>>()?;
    if images.is_empty() {
        return Err(KitError::ClassicRestoreMissingComponent(
            "all_flash NOR images".to_owned(),
        ));
    }
    // NOR data sends iBoot first, like the workflow personalizer.
    images.sort_by_key(|(component, _)| !component.starts_with("iBoot"));
    let mut nor = Dictionary::new();
    nor.insert("LlbImageData".into(), Value::Data(llb));
    nor.insert(
        "NorImageData".into(),
        Value::Array(
            images
                .into_iter()
                .map(|(_, data)| Value::Data(data))
                .collect(),
        ),
    );
    let restored_data = PreparedRestoreData::default()
        .with_kernel_cache(kernel_cache.clone())
        .with_device_tree(device_tree.clone())
        .with_nor(nor);

    Ok(ClassicBootData {
        wtf2,
        ibss,
        ramdisk,
        device_tree,
        kernel_cache,
        loaded_by_iboot,
        restored_data,
    })
}

/// iPhone1,2 4.x chain: pwned Pwnage 2.0 WTF, custom WTF 2 to DFU-real,
/// custom iBSS to recovery. Returns the recovery-mode client, `None` when
/// cancelled.
async fn wtf_real_chain(
    client: IbootClient,
    plan: &ClassicRestorePlan,
    boot: &ClassicBootData,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    let ecid = plan.device.ecid().ok_or(KitError::MissingDeviceSelector)?;
    let client = match client.mode() {
        DeviceMode::Wtf if pwnage::is_pwned_wtf_srtg(client.device_info().srtg()) => client,
        DeviceMode::Dfu => {
            emitter
                .emit(phase(
                    OperationPhase::Exploiting,
                    CancellationSafety::AtCheckpoint,
                ))
                .await;
            pwnage::pwn_wtf(Some(ecid), plan.cache_root.clone()).await?;
            // The pwned device lands in WTF (or, on a re-send, DFU-real);
            // both accept the WTF 2 upload.
            let Some(client) = await_iboot(
                ecid,
                &[DeviceMode::Dfu, DeviceMode::Wtf],
                REENUMERATION_TIMEOUT,
                "DFU",
                emitter,
            )
            .await?
            else {
                return Ok(None);
            };
            client
        }
        _ => {
            return Err(KitError::ClassicRestoreNotPwned(
                "device is in WTF mode without the Pwnage 2.0 patch; force restart and re-enter DFU mode",
            ));
        }
    };

    // Custom WTF 2 (pwnage-patched in the build) boots the device to
    // DFU-real.
    emitter
        .emit(phase(
            OperationPhase::Booting,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ))
        .await;
    info!("sending the custom WTF image");
    let Some(client) = upload_and_await(
        client,
        boot.wtf2.as_deref().expect("WTF 2 path resolved at plan"),
        ecid,
        &[DeviceMode::Dfu],
        "DFU",
        emitter,
    )
    .await?
    else {
        return Ok(None);
    };
    send_ibss(client, boot, ecid, emitter).await
}

/// S5L8900 3.1.3 chain: reach pwned DFU-real via the pwnage WTF, then the
/// custom iBSS to recovery.
async fn dfu_real_chain(
    client: IbootClient,
    plan: &ClassicRestorePlan,
    boot: &ClassicBootData,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    let ecid = plan.device.ecid().ok_or(KitError::MissingDeviceSelector)?;
    let mut client = client;
    let already_pwned_dfu =
        client.mode() == DeviceMode::Dfu && pwnage::is_pwned_wtf_srtg(client.device_info().srtg());
    if !already_pwned_dfu {
        emitter
            .emit(phase(
                OperationPhase::Exploiting,
                CancellationSafety::AtCheckpoint,
            ))
            .await;
        if client.mode() == DeviceMode::Dfu {
            pwnage::pwn_wtf(Some(ecid), plan.cache_root.clone()).await?;
            let Some(reconnected) = await_iboot(
                ecid,
                &[DeviceMode::Dfu, DeviceMode::Wtf],
                REENUMERATION_TIMEOUT,
                "DFU",
                emitter,
            )
            .await?
            else {
                return Ok(None);
            };
            client = reconnected;
        }
        if client.mode() == DeviceMode::Wtf {
            if !pwnage::is_pwned_wtf_srtg(client.device_info().srtg()) {
                return Err(KitError::ClassicRestoreNotPwned(
                    "device is in WTF mode without the Pwnage 2.0 patch; force restart and re-enter DFU mode",
                ));
            }
            // device_s5l8900xall: re-send the pwned WTF to reach DFU-real.
            info!("sending the pwned WTF image to reach DFU-real");
            let payload = pwnage::pwnage_payload(plan.cache_root.clone()).await?;
            let Some(reconnected) =
                upload_and_await(client, &payload, ecid, &[DeviceMode::Dfu], "DFU", emitter)
                    .await?
            else {
                return Ok(None);
            };
            client = reconnected;
        }
        // A DFU-mode client here was verified pwned by pwn_wtf.
    }
    emitter
        .emit(phase(
            OperationPhase::Booting,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ))
        .await;
    send_ibss(client, boot, ecid, emitter).await
}

/// iPod2,1/iPhone2,1 chain: require a pwned DFU (24kpwn marker, else
/// limera1n on the S5L8920), then the personalized iBSS to recovery.
async fn pwned_dfu_chain(
    client: IbootClient,
    plan: &ClassicRestorePlan,
    boot: &ClassicBootData,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    let ecid = plan.device.ecid().ok_or(KitError::MissingDeviceSelector)?;
    let mut client = client;
    if client.device_info().pwned().is_none() {
        emitter
            .emit(phase(
                OperationPhase::Exploiting,
                CancellationSafety::AtCheckpoint,
            ))
            .await;
        match plan.device.soc() {
            Soc::S5l8920 => {
                let payload = plan
                    .limera1n_payload
                    .clone()
                    .ok_or(KitError::MissingLimera1nPayload)?;
                client = legacy_ios_exploits::Limera1n::new(payload)?
                    .exploit(client)
                    .await?;
                if client.device_info().pwned().is_none() {
                    return Err(KitError::PwnVerificationFailed);
                }
            }
            _ => {
                return Err(KitError::ClassicRestoreNotPwned(
                    "iPod2,1 restores require a 24kpwn-pwned DFU (old bootrom); new-bootrom devices cannot be pwned",
                ));
            }
        }
    }
    emitter
        .emit(phase(
            OperationPhase::Booting,
            CancellationSafety::UnsafeUntilPhaseEnds,
        ))
        .await;
    send_ibss(client, boot, ecid, emitter).await
}

/// Send the (personalized) iBSS and wait for recovery mode.
async fn send_ibss(
    client: IbootClient,
    boot: &ClassicBootData,
    ecid: Ecid,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    info!("sending iBSS");
    upload_and_await(
        client,
        &boot.ibss,
        ecid,
        &[DeviceMode::Recovery],
        "recovery",
        emitter,
    )
    .await
}

/// Upload a boot-chain image (re-enumerating in DFU/WTF modes) and wait for
/// the device in one of `modes`. Returns `None` on cancellation.
async fn upload_and_await(
    client: IbootClient,
    data: &[u8],
    ecid: Ecid,
    modes: &[DeviceMode],
    timeout_mode: &'static str,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    match client.upload_image(data).await? {
        UploadResult::Connected(client) => {
            debug!("image upload completed without re-enumeration");
            if modes.contains(&client.mode()) {
                return Ok(Some(*client));
            }
        }
        UploadResult::Reenumerating => debug!("image uploaded, waiting for re-enumeration"),
    }
    await_iboot(ecid, modes, REENUMERATION_TIMEOUT, timeout_mode, emitter).await
}

/// Poll for the device in one of `modes`, returning `None` on cancellation.
async fn await_iboot(
    ecid: Ecid,
    modes: &[DeviceMode],
    timeout: Duration,
    timeout_mode: &'static str,
    emitter: &OperationEmitter,
) -> Result<Option<IbootClient>, KitError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if emitter.is_cancelled() {
            return Ok(None);
        }
        match IbootClient::open(Some(ecid)).await {
            Ok(client) if modes.contains(&client.mode()) => return Ok(Some(client)),
            Ok(_) | Err(RecoveryError::NoDevice) => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(KitError::ClassicRestoreDeviceTimeout(timeout_mode));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_normal_device(
    devices: &DeviceManager,
    ecid: Ecid,
    emitter: &OperationEmitter,
) -> Result<String, KitError> {
    let deadline = tokio::time::Instant::now() + VERIFY_TIMEOUT;
    loop {
        if emitter.is_cancelled() {
            return Err(KitError::VerificationTimeout);
        }
        match devices.list_normal().await {
            Ok(summaries) => {
                if let Some(device) = summaries
                    .into_iter()
                    .find(|device| device.ecid() == Some(ecid))
                {
                    if let Some(snapshot) = device.snapshot() {
                        emitter
                            .emit(OperationEvent::DeviceReconnected { device: snapshot })
                            .await;
                    }
                    return Ok(format!(
                        "{} ({})",
                        device.product_version().unwrap_or("unknown"),
                        device.build_version().unwrap_or("unknown")
                    ));
                }
            }
            Err(error) => debug!(%error, "normal device not ready for verification"),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(KitError::VerificationTimeout);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn dfu_steps(plan: &ClassicRestorePlan) -> Vec<String> {
    match plan.sequence {
        ClassicBootSequence::WtfRealThenIbss => vec![
            "Put the device into DFU mode (or Pwnage 2.0 WTF mode) to continue.".to_owned(),
            "The restore pwns the device with Pwnage 2.0, then boots the custom WTF and iBSS."
                .to_owned(),
        ],
        ClassicBootSequence::DfuThenIbss => vec![
            "Put the device into DFU mode to continue.".to_owned(),
            "The restore pwns the device with Pwnage 2.0 (WTF), then boots the custom iBSS."
                .to_owned(),
        ],
        ClassicBootSequence::PwnedDfu => vec![
            "Put the device into DFU mode to continue.".to_owned(),
            "The device must be in pwned DFU mode: iPhone2,1 is pwned with limera1n, iPod2,1 needs a 24kpwn-pwned DFU (old bootrom)."
                .to_owned(),
        ],
    }
}

const fn phase(phase: OperationPhase, cancellation: CancellationSafety) -> OperationEvent {
    OperationEvent::PhaseStarted {
        phase,
        cancellation,
    }
}
#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::ProductType;
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn iphone3g_421_uses_the_wtf_real_chain() {
        let ipsw = manifest_ipsw("iPhone1,2", "n82ap", "4.2.1", "8C148");
        let request = ClassicRestoreRequest::new(
            device("iPhone1,2", Soc::S5l8900, "n82"),
            ipsw.path().to_owned(),
            "cache",
        );
        let plan = plan(request).unwrap();
        assert_eq!(plan.sequence(), ClassicBootSequence::WtfRealThenIbss);
        assert_eq!(plan.build_major, 8);
        assert!(!plan.foreign());
        assert!(plan.accepts(&plan.confirm_destructive()));
    }

    #[test]
    fn s5l8900_rejects_a_ticket() {
        let ipsw = manifest_ipsw("iPhone1,2", "n82ap", "4.2.1", "8C148");
        let directory = tempfile::tempdir().unwrap();
        let ticket = blob(directory.path(), 42, true);
        let request = ClassicRestoreRequest::new(
            device("iPhone1,2", Soc::S5l8900, "n82"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_ticket(Some(ticket));
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreTicketRejected(_))
        ));
    }

    #[test]
    fn iphone2g_313_uses_the_dfu_chain() {
        let ipsw = restore_plist_ipsw("m68ap");
        let request = ClassicRestoreRequest::new(
            device("iPhone1,1", Soc::S5l8900, "m68"),
            ipsw.path().to_owned(),
            "cache",
        );
        let plan = plan(request).unwrap();
        assert_eq!(plan.sequence(), ClassicBootSequence::DfuThenIbss);
        assert_eq!(plan.version().as_str(), "3.1.3");
        assert_eq!(plan.build_id().as_str(), "7E18");
        assert_eq!(plan.build_major, 7);
    }

    #[test]
    fn ipod2_requires_a_ticket_unless_foreign() {
        let ipsw = manifest_ipsw("iPod2,1", "n72ap", "3.1.3", "7E18");
        let without = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        );
        assert!(matches!(
            plan(without),
            Err(KitError::ClassicRestoreTicketRequired)
        ));

        let foreign = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_foreign(true);
        let plan = plan(foreign).unwrap();
        assert_eq!(plan.sequence(), ClassicBootSequence::PwnedDfu);
        assert!(plan.foreign());
    }

    #[test]
    fn foreign_rejects_a_ticket() {
        let ipsw = manifest_ipsw("iPod2,1", "n72ap", "3.1.3", "7E18");
        let directory = tempfile::tempdir().unwrap();
        let ticket = blob(directory.path(), 42, true);
        let request = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_foreign(true)
        .with_ticket(Some(ticket));
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreTicketRejected(_))
        ));
    }

    #[test]
    fn ipod2_with_a_matching_ticket_plans() {
        let ipsw = manifest_ipsw("iPod2,1", "n72ap", "3.1.3", "7E18");
        let directory = tempfile::tempdir().unwrap();
        let ticket = blob(directory.path(), 42, true);
        let request = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_ticket(Some(ticket));
        let plan = plan(request).unwrap();
        assert_eq!(plan.sequence(), ClassicBootSequence::PwnedDfu);
    }

    #[test]
    fn blob_ecid_mismatch_is_rejected() {
        let ipsw = manifest_ipsw("iPod2,1", "n72ap", "3.1.3", "7E18");
        let directory = tempfile::tempdir().unwrap();
        let ticket = blob(directory.path(), 43, true);
        let request = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_ticket(Some(ticket));
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreTicketMismatch(_))
        ));
    }

    #[test]
    fn blob_missing_a_required_component_is_rejected() {
        let ipsw = manifest_ipsw("iPod2,1", "n72ap", "3.1.3", "7E18");
        let directory = tempfile::tempdir().unwrap();
        let ticket = blob(directory.path(), 42, false);
        let request = ClassicRestoreRequest::new(
            device("iPod2,1", Soc::S5l8720, "n72"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_ticket(Some(ticket));
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreTicketMismatch(_))
        ));
    }

    #[test]
    fn iphone3gs_5x_and_later_is_redirected() {
        let ipsw = manifest_ipsw("iPhone2,1", "n88ap", "6.1.6", "10B500");
        let request = ClassicRestoreRequest::new(
            device("iPhone2,1", Soc::S5l8920, "n88"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_foreign(true);
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreUnsupportedVersion(_))
        ));
    }

    #[test]
    fn a4_devices_are_rejected() {
        let ipsw = manifest_ipsw("iPhone3,1", "n90ap", "4.2.1", "8C148");
        let request = ClassicRestoreRequest::new(
            device("iPhone3,1", Soc::A4, "n90"),
            ipsw.path().to_owned(),
            "cache",
        )
        .with_foreign(true);
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreUnsupportedDevice(_))
        ));
    }

    #[test]
    fn missing_ipsw_entries_are_rejected() {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Restore.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(RESTORE_PLIST.as_bytes()).unwrap();
        writer.finish().unwrap();
        let request = ClassicRestoreRequest::new(
            device("iPhone1,1", Soc::S5l8900, "m68"),
            file.path().to_owned(),
            "cache",
        );
        assert!(matches!(
            plan(request),
            Err(KitError::ClassicRestoreMissingComponent(_))
        ));
    }

    #[test]
    fn consent_binds_to_the_plan_id() {
        let ipsw = manifest_ipsw("iPhone1,2", "n82ap", "4.2.1", "8C148");
        let request = ClassicRestoreRequest::new(
            device("iPhone1,2", Soc::S5l8900, "n82"),
            ipsw.path().to_owned(),
            "cache",
        );
        let plan = plan(request).unwrap();
        let consent = plan.confirm_destructive();
        assert_eq!(consent.plan_id(), plan.id());
        assert!(plan.accepts(&consent));
        let other = ClassicRestoreConsent {
            plan_id: "other".to_owned(),
        };
        assert!(!plan.accepts(&other));
    }

    #[test]
    fn blob_entry_aliases_restore_ramdisk() {
        let mut entry = Dictionary::new();
        entry.insert("Blob".into(), Value::Data(vec![1, 2, 3]));
        let mut dictionary = Dictionary::new();
        dictionary.insert("RestoreRamdisk".into(), entry.into());
        assert_eq!(
            blob_entry(&dictionary, "RestoreRamDisk"),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(blob_entry(&dictionary, "iBSS"), None);
    }

    fn device(product: &str, soc: Soc, board: &str) -> DeviceIdentity {
        DeviceIdentity::new(ProductType::from(product), soc)
            .with_board_config(BoardConfig::from(board))
            .with_ecid(Ecid::new(42))
    }

    fn blob(directory: &Path, ecid: u64, complete: bool) -> PathBuf {
        let path = directory.join("blob.shsh");
        let mut dictionary = Dictionary::new();
        dictionary.insert("ApECID".to_owned(), plist::Value::Integer(ecid.into()));
        let components: &[&str] = if complete {
            &[
                "iBSS",
                "LLB",
                "RestoreRamDisk",
                "RestoreDeviceTree",
                "RestoreKernelCache",
            ]
        } else {
            &["iBSS", "LLB"]
        };
        for component in components {
            let mut entry = Dictionary::new();
            entry.insert("Blob".into(), Value::Data(vec![0x30, 0x82]));
            dictionary.insert((*component).to_owned(), entry.into());
        }
        plist::to_file_xml(&path, &plist::Value::Dictionary(dictionary)).unwrap();
        path
    }

    /// A 4.x-style IPSW with a BuildManifest whose erase identity carries the
    /// classic component paths.
    fn manifest_ipsw(
        product: &str,
        device_class: &str,
        version: &str,
        build: &str,
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
<key>Manifest</key><dict>
<key>iBSS</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/dfu/iBSS.RELEASE.dfu</string></dict></dict>
<key>LLB</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/manifest.dir/LLB.img3</string></dict></dict>
<key>iBoot</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/manifest.dir/iBoot.img3</string><key>IsFirmwarePayload</key><true/></dict></dict>
<key>DeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/manifest.dir/DeviceTree.img3</string><key>IsFirmwarePayload</key><true/></dict></dict>
<key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Downgrade/RestoreDeviceTree</string></dict></dict>
<key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>Downgrade/RestoreKernelCache</string></dict></dict>
<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>rootfs.dmg</string></dict></dict>
</dict>
</dict></array>
</dict></plist>"#
                )
                .as_bytes(),
            )
            .unwrap();
        for name in [
            "Firmware/dfu/iBSS.RELEASE.dfu",
            "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu",
            "Firmware/all_flash/manifest.dir/LLB.img3",
            "Firmware/all_flash/manifest.dir/iBoot.img3",
            "Firmware/all_flash/manifest.dir/DeviceTree.img3",
            "Downgrade/RestoreDeviceTree",
            "Downgrade/RestoreKernelCache",
            "ramdisk.dmg",
            "rootfs.dmg",
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"data").unwrap();
        }
        writer.finish().unwrap();
        file
    }

    const RESTORE_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>3.1.3</string>
<key>ProductBuildVersion</key><string>7E18</string>
<key>RestoreRamDisks</key><dict><key>User</key><string>018-6494-014.dmg</string></dict>
<key>SystemRestoreImages</key><dict><key>User</key><string>018-6488-015.dmg</string></dict>
<key>RestoreKernelCaches</key><dict><key>Release</key><string>kernelcache.release.s5l8900x</string></dict>
</dict></plist>"#;

    /// A 3.1.3-style IPSW with Restore.plist and the fixed S5L8900 paths.
    fn restore_plist_ipsw(board_class: &str) -> NamedTempFile {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Restore.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(RESTORE_PLIST.as_bytes()).unwrap();
        let all_flash = format!("Firmware/all_flash/all_flash.{board_class}");
        for name in [
            format!("Firmware/dfu/iBSS.{board_class}.RELEASE.dfu"),
            format!("{all_flash}/LLB.{board_class}.RELEASE.img3"),
            format!("{all_flash}/DeviceTree.{board_class}.img3"),
            format!("{all_flash}/iBoot.{board_class}.RELEASE.img3"),
            "018-6494-014.dmg".to_owned(),
            "018-6488-015.dmg".to_owned(),
            "kernelcache.release.s5l8900x".to_owned(),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"data").unwrap();
        }
        writer
            .start_file(
                format!("{all_flash}/manifest"),
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer
            .write_all(
                format!(
                    "LLB.{board_class}.RELEASE.img3\niBoot.{board_class}.RELEASE.img3\nDeviceTree.{board_class}.img3\n"
                )
                .as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
        file
    }
}
