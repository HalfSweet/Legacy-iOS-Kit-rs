//! powdersn0w custom IPSW builder for single-IPSW restores, mirroring the
//! `ipsw_prepare_32bit` driver of restore.sh and the xpwn-based `powdersn0w`
//! tool it invokes (`xpwn/ipsw-patch/main.c` of LukeZGD/powdersn0w_pub at
//! `300c54a161925afdb77723616025bd60047db7fd`).
//!
//! Planning mirrors `ipsw_prepare_bundle`/`ipsw_prepare_config`: validate the
//! device (powdersn0w covers A4/A5/A5X/A6/A6X), fetch the firmware keys,
//! resolve the payload tar matrix, derive the bundle from the IPSW's restore
//! ramdisk options plist (`SystemPartitionSize` plus 30), and fetch the
//! jailbreak payload resources.
//!
//! Building mirrors main.c's stage order. The Firmware loop patches
//! iBSS/iBEC with the powdersn0w iBoot patcher (always `PATCH_DEBUG`, boot-args
//! always starting with `CSBYPASS_BOOTARGS`), writes decrypted
//! RestoreDeviceTree/RestoreKernelCache copies under `Downgrade/` with the
//! matching BuildManifest path rewrite, and decrypts the restore ramdisk in
//! place. The root filesystem is decrypted, grown to the estimated size
//! (upstream's "poor estimate" of one MB per tar MB), punchd-renamed, and
//! merged with the payload tars, with the daibutsu LaunchDaemon shuffles
//! around the untether untar and the `needPref` SpringBoard blob at the end.
//! The restore ramdisk is grown by `-ramdiskgrow` blocks plus the daibutsu
//! payload allowance, its ASR binary is patched, its options plist is
//! rewritten with the computed system partition size, and the daibutsu
//! `/sbin/reboot` hook is installed. The output stays a deflated IPSW written
//! through [`CustomIpswBuilder`].
//!
//! Deliberately out of scope (two-bundle `-base` mode): the
//! FirmwarePath/FirmwareReplace NOR copies with their TYPE tag rewrites, the
//! APTicket scab reseal, the NewiBoot patch, the RamdiskExploit/partition
//! script hook, and the ios4powder `-apticket` mode. main.c's `Update
//! Ramdisk` removal is not modeled because the bundle format never emits an
//! `Update Ramdisk` entry.

use std::{fmt, io::Cursor, path::PathBuf};

use legacy_ios_assets::{DeviceDatabase, ResourceId};
use legacy_ios_core::{
    BoardConfig, BuildId, CancellationSafety, IosVersion, OperationEvent, OperationKind,
    OperationOutcome, OperationPhase, ProductType, Progress, ProgressUnit, Soc,
};
use legacy_ios_firmware::{
    BundleRole, CustomIpswBuilder, FirmwareArchive, FirmwareComponentKind, FirmwareEntry,
    FirmwareKeyProvider, PowderBundle, PowderBundleRequest, PowderConfig, PowderMode,
    PowderPayloadPlan, PowderPayloadRequest, PowderTar, RestoreBehavior, iboot_tar, reboot_script,
    system_partition_size, system_version_tar,
};
use legacy_ios_image::{
    DmgFirmwareKey, DmgImage, DmgPartitionInput, HfsError, HfsImage, PowderIBootPatchOptions,
    compress_lzss, decompress_lzss, decrypt_firmware_image, extract_image_payload,
    is_lzss_compressed, patch_asr, patch_kernel32, patch_powder_iboot, replace_image_payload,
};
use tracing::{debug, info};

use crate::{FirmwareSummary, KitError, OperationHandle, operation::OperationEmitter};

/// `-ramdiskgrow` default passed by `ipsw_prepare_32bit`, in ramdisk
/// allocation blocks (upstream quirk: the value counts blocks, not bytes).
pub const DEFAULT_RAMDISK_GROW_BLOCKS: u64 = 10;

/// `CSBYPASS_BOOTARGS` from xpwn's `include/iboot.h`. main.c writes it into
/// every patched iBSS/iBEC unconditionally (unlike the base-FW iBoot block).
const CSBYPASS_BOOTARGS: &str = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1 amfi=0xff";

/// `FSTAB_PATH` and `fstabData` from xpwn's `include/fstab.h`: the rw fstab
/// written under the `FilesystemJailbreak` config (never set by single-IPSW
/// builds; the jailbreak fstab arrives via payload tars there).
const FSTAB_PATH: &str = "/private/etc/fstab";
const FSTAB_DATA: &[u8] = b"/dev/disk0s1 / hfs rw 0 1\n/dev/disk0s2 /private/var hfs rw 0 2\n";

/// `PREF_PATH` and `prefData` from xpwn's `include/pref.h`: the
/// SBShowNonDefaultSystemApps SpringBoard preference written when the config
/// carries `needPref` (jailbroken single-IPSW builds).
const PREF_PATH: &str = "/private/var/mobile/Library/Preferences/com.apple.springboard.plist";
const PREF_DATA: [u8; 76] = [
    0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0xd1, 0x01, 0x02, 0x5f, 0x10, 0x1a, 0x53, 0x42,
    0x53, 0x68, 0x6f, 0x77, 0x4e, 0x6f, 0x6e, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x53, 0x79,
    0x73, 0x74, 0x65, 0x6d, 0x41, 0x70, 0x70, 0x73, 0x09, 0x08, 0x0b, 0x28, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29,
];

const MIB: u64 = 1024 * 1024;

/// Request for a powdersn0w single-IPSW custom build, mirroring the option
/// surface of upstream's `ipsw_prepare_32bit`.
pub struct PowderPrepareRequest {
    product_type: ProductType,
    board_config: BoardConfig,
    source: PathBuf,
    destination: PathBuf,
    cache_root: PathBuf,
    jailbreak: bool,
    openssh: bool,
    beta: bool,
    update_baseband: bool,
    verbose_boot_args: bool,
    boot_args: Option<String>,
    ramdisk_grow_blocks: u64,
    iboot_sidecar: Option<(String, Vec<u8>)>,
    extra_tars: Vec<(String, Vec<u8>)>,
}

impl PowderPrepareRequest {
    pub fn new(
        product_type: ProductType,
        board_config: BoardConfig,
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            product_type,
            board_config,
            source: source.into(),
            destination: destination.into(),
            cache_root: cache_root.into(),
            jailbreak: false,
            openssh: false,
            beta: false,
            update_baseband: false,
            verbose_boot_args: false,
            boot_args: None,
            ramdisk_grow_blocks: DEFAULT_RAMDISK_GROW_BLOCKS,
            iboot_sidecar: None,
            extra_tars: Vec::new(),
        }
    }

    /// Mirror of upstream's `ipsw_jailbreak`: resolve the jailbreak payload
    /// matrix and set `needPref` in the build config.
    pub fn with_jailbreak(mut self, enabled: bool) -> Self {
        self.jailbreak = enabled;
        self
    }

    /// Mirror of `ipsw_openssh`: append the sshdeb/openssh/openssl payload
    /// tars (and the sshd launch daemon drop of the aquila reboot script).
    pub fn with_openssh(mut self, enabled: bool) -> Self {
        self.openssh = enabled;
        self
    }

    /// Beta target: prepend the generated `systemversion.tar`.
    pub fn with_beta(mut self, enabled: bool) -> Self {
        self.beta = enabled;
        self
    }

    /// Mirror of `-bbupdate`: keep `UpdateBaseband` enabled in the restore
    /// ramdisk options plist.
    pub fn with_update_baseband(mut self, enabled: bool) -> Self {
        self.update_baseband = enabled;
        self
    }

    /// Verbose boot-args variant (`pio-error=0 -v`), mirroring
    /// `--ipsw-verbose`.
    pub fn with_verbose_boot_args(mut self, enabled: bool) -> Self {
        self.verbose_boot_args = enabled;
        self
    }

    /// Extra boot-args appended to the boot-args string, mirroring
    /// `--bootargs`.
    pub fn with_boot_args(mut self, args: impl Into<String>) -> Self {
        self.boot_args = Some(args.into());
        self
    }

    /// Mirror of `-ramdiskgrow`: ramdisk growth in allocation blocks.
    /// Defaults to [`DEFAULT_RAMDISK_GROW_BLOCKS`].
    pub fn with_ramdisk_grow_blocks(mut self, blocks: u64) -> Self {
        self.ramdisk_grow_blocks = blocks;
        self
    }

    /// Externally patched iBoot merged as `iBoot.tar` between the generated
    /// extras and the jailbreak payloads. `name` is the tar entry name
    /// (`iBEC` for iPad1,1, `iBoot` for ramdiskH builds).
    pub fn with_iboot_sidecar(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.iboot_sidecar = Some((name.into(), data));
        self
    }

    /// Extra payload tars merged into the root filesystem between the
    /// generated extras and the jailbreak payloads, like upstream's
    /// per-device `baseband-<ecid>.tar`/`activation-<ecid>.tar`.
    pub fn with_extra_tars(mut self, tars: Vec<(String, Vec<u8>)>) -> Self {
        self.extra_tars = tars;
        self
    }
}

impl fmt::Debug for PowderPrepareRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowderPrepareRequest")
            .field("product_type", &self.product_type)
            .field("board_config", &self.board_config)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("jailbreak", &self.jailbreak)
            .field("openssh", &self.openssh)
            .field("beta", &self.beta)
            .field("update_baseband", &self.update_baseband)
            .field("verbose_boot_args", &self.verbose_boot_args)
            .field("boot_args", &self.boot_args)
            .field("ramdisk_grow_blocks", &self.ramdisk_grow_blocks)
            .finish_non_exhaustive()
    }
}

/// daibutsu payload of a single-IPSW 7.x/8.x jailbreak build: the bin.tar
/// merged into the ramdisk, the untether tar merged into the root filesystem,
/// and the generated reboot.sh installed as the ramdisk reboot hook.
struct DaibutsuStage {
    bin_tar: Vec<u8>,
    untether: Vec<u8>,
    reboot: Vec<u8>,
    hwmodel: String,
}

/// A resolved powder build: validated device/version, firmware bundle,
/// config, ordered payload tars, and sizing, ready to execute.
pub struct PowderPreparePlan {
    source: PathBuf,
    destination: PathBuf,
    product_type: ProductType,
    board_config: BoardConfig,
    version: IosVersion,
    build: BuildId,
    bundle: PowderBundle,
    config: PowderConfig,
    tars: Vec<(String, Vec<u8>)>,
    punchd: bool,
    daibutsu: Option<DaibutsuStage>,
    root_size_mb: u64,
    update_baseband: bool,
    ramdisk_grow_blocks: u64,
}

impl PowderPreparePlan {
    pub fn source(&self) -> &std::path::Path {
        &self.source
    }

    pub fn destination(&self) -> &std::path::Path {
        &self.destination
    }

    pub const fn product_type(&self) -> &ProductType {
        &self.product_type
    }

    pub const fn board_config(&self) -> &BoardConfig {
        &self.board_config
    }

    pub const fn version(&self) -> &IosVersion {
        &self.version
    }

    pub const fn build_id(&self) -> &BuildId {
        &self.build
    }

    /// The resolved firmware bundle, mirroring upstream's generated
    /// `Info.plist`.
    pub const fn bundle(&self) -> &PowderBundle {
        &self.bundle
    }

    /// The resolved build config, mirroring upstream's `config.plist`.
    pub const fn config(&self) -> &PowderConfig {
        &self.config
    }

    /// Estimated root filesystem size in MB (upstream's `defaultRootSize`):
    /// the bundle's `RootFilesystemSize` plus one MB per tar MB.
    pub const fn root_size_mb(&self) -> u64 {
        self.root_size_mb
    }
}

impl fmt::Debug for PowderPreparePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowderPreparePlan")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("product_type", &self.product_type)
            .field("board_config", &self.board_config)
            .field("version", &self.version)
            .field("build", &self.build)
            .field("root_size_mb", &self.root_size_mb)
            .field("update_baseband", &self.update_baseband)
            .finish_non_exhaustive()
    }
}

/// Resolve a powder build plan, mirroring `ipsw_prepare_bundle` (including
/// the ramdisk options plist extraction for `SystemPartitionSize`) and
/// `ipsw_prepare_config` for a single-IPSW build.
pub(crate) async fn plan(request: PowderPrepareRequest) -> Result<PowderPreparePlan, KitError> {
    let profile = DeviceDatabase::bundled()
        .find_product(&request.product_type)
        .ok_or_else(|| KitError::UnknownProduct(request.product_type.clone()))?;
    if !profile.board_configs().contains(&request.board_config) {
        return Err(KitError::UnknownBoardConfig {
            product_type: request.product_type,
            board_config: request.board_config,
        });
    }
    match profile.soc() {
        Soc::A4 | Soc::A5 | Soc::A5x | Soc::A6 | Soc::A6x => {}
        soc => {
            return Err(KitError::PowderUnsupportedDevice(format!(
                "{} ({soc})",
                request.product_type
            )));
        }
    }

    let archive = FirmwareArchive::open(&request.source)?;
    let manifest = archive.build_manifest()?;
    let version = manifest.product_version().clone();
    let build = manifest.build_id().clone();

    let payload = PowderPayloadPlan::resolve(
        &PowderPayloadRequest::new(
            PowderMode::Single,
            request.product_type.clone(),
            version.clone(),
            build.clone(),
        )
        .with_jailbreak(request.jailbreak)
        .with_openssh(request.openssh)
        .with_beta(request.beta)
        .with_iboot_sidecar(request.iboot_sidecar.is_some()),
    )?;

    info!(
        product = %request.product_type,
        version = %version,
        build = %build,
        "fetching powder component keys"
    );
    let keys = FirmwareKeyProvider::with_cache(&request.cache_root)
        .fetch(&request.product_type, &build)
        .await?;

    let identity = manifest.select_identity(&request.board_config, RestoreBehavior::Erase)?;

    // `ipsw_prepare_bundle` derives RootFilesystemSize from the restore
    // ramdisk's options plist: decrypt the ramdisk and read the per-board
    // plist first, falling back to the plain one, like the shell flow.
    let ramdisk_path = identity.component_path("RestoreRamDisk")?.to_owned();
    let ramdisk_container = archive.read_entry(&ramdisk_path)?;
    let ramdisk_key = keys
        .key("RestoreRamdisk")
        .and_then(|key| key.key().map(<[u8]>::to_vec));
    let ramdisk_iv = keys.key("RestoreRamdisk").and_then(|key| key.iv().copied());
    let board = request.board_config.clone();
    let options_plist = tokio::task::spawn_blocking(move || {
        let encryption = ramdisk_key
            .as_deref()
            .zip(ramdisk_iv.as_ref().map(|iv| iv.as_slice()));
        let payload = extract_image_payload(&ramdisk_container, encryption)?;
        let hfs = HfsImage::parse(payload)?;
        let per_board = format!("/usr/local/share/restore/options.{}.plist", board.as_str());
        match hfs.read(&per_board) {
            Ok(bytes) if !bytes.is_empty() => Ok(bytes),
            _ => hfs
                .read("/usr/local/share/restore/options.plist")
                .map_err(|_| KitError::PowderMissingRamdiskOptions),
        }
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    let system_partition = system_partition_size(&options_plist)?;

    let filename = request
        .source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "custom.ipsw".to_owned());
    let bundle = PowderBundle::resolve(
        &PowderBundleRequest::new(
            BundleRole::Single,
            request.product_type.clone(),
            request.board_config.clone(),
            filename,
            version.clone(),
            version.clone(),
            // The latest version only feeds target-bundle manifest additions.
            version.clone(),
            system_partition,
        )
        .with_jailbreak(request.jailbreak)
        .with_daibutsu(payload.daibutsu().is_some()),
        &keys,
        Some(identity),
    )?;
    let Some(config) = PowderConfig::resolve(
        BundleRole::Single,
        request.jailbreak,
        &version,
        request.verbose_boot_args,
        request.boot_args.as_deref(),
    )?
    else {
        unreachable!("single-IPSW builds always carry a config");
    };

    // Payload tars in upstream argv order: generated extras
    // (systemversion.tar, iBoot.tar), caller extras (baseband/activation),
    // then the jailbreak payload tars.
    let mut generated = Vec::new();
    let mut jailbreak_tars = Vec::new();
    for tar in payload.tars() {
        match tar {
            PowderTar::SystemVersion => {
                generated.push((
                    "systemversion.tar".to_owned(),
                    system_version_tar(&version, &build),
                ));
            }
            PowderTar::IBoot => {
                let (name, bytes) = request
                    .iboot_sidecar
                    .as_ref()
                    .ok_or(KitError::PowderMissingIbootSidecar)?;
                generated.push(("iBoot.tar".to_owned(), iboot_tar(name, bytes)));
            }
            PowderTar::Resource(id) => {
                debug!(resource = id.as_str(), "fetching jailbreak payload");
                jailbreak_tars.push((
                    id.as_str().to_owned(),
                    read_tar_resource(id, &request.cache_root).await?,
                ));
            }
        }
    }
    let mut tars = generated;
    tars.extend(request.extra_tars);
    tars.extend(jailbreak_tars);

    let daibutsu = match payload.daibutsu() {
        Some(payload) => {
            let bin_tar = read_tar_resource(payload.bin_tar(), &request.cache_root).await?;
            let untether = read_tar_resource(payload.untether(), &request.cache_root).await?;
            let reboot = reboot_script(
                payload.reboot_script(),
                &request.product_type,
                &build,
                request.openssh,
            )
            .into_bytes();
            let hwmodel = bundle
                .daibutsu()
                .expect("a daibutsu payload implies a daibutsu bundle")
                .hwmodel()
                .to_owned();
            Some(DaibutsuStage {
                bin_tar,
                untether,
                reboot,
                hwmodel,
            })
        }
        None => None,
    };

    // Two-bundle builds additionally count the bundle-declared
    // FilesystemPackage tars here: the bootstrap only under a
    // FilesystemJailbreak config, the package unconditionally. Single-IPSW
    // bundles declare neither.
    let tar_sizes: Vec<u64> = tars.iter().map(|(_, bytes)| bytes.len() as u64).collect();
    let root_size_mb = root_size_estimate_mb(
        bundle.root_filesystem_size_mb(),
        &tar_sizes,
        daibutsu.as_ref().map(|stage| stage.untether.len() as u64),
        None,
        None,
    );

    info!(
        product = %request.product_type,
        version = %version,
        jailbreak = request.jailbreak,
        daibutsu = daibutsu.is_some(),
        root_size_mb,
        "resolved powder build plan"
    );
    Ok(PowderPreparePlan {
        source: request.source,
        destination: request.destination,
        product_type: request.product_type,
        board_config: request.board_config,
        version,
        build,
        bundle,
        config,
        tars,
        punchd: payload.punchd(),
        daibutsu,
        root_size_mb,
        update_baseband: request.update_baseband,
        ramdisk_grow_blocks: request.ramdisk_grow_blocks,
    })
}

/// Fetch a catalog resource and gunzip it when it is gzip-compressed, like
/// the `gzip -d` calls of `ipsw_prepare_32bit` for the .tar.gz payloads.
async fn read_tar_resource(
    id: &ResourceId,
    cache_root: &std::path::Path,
) -> Result<Vec<u8>, KitError> {
    let path = crate::firmware::fetch_resource(id, cache_root.to_owned()).await?;
    let bytes = tokio::fs::read(path).await?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        crate::bootstrap::gunzip(&bytes)
    } else {
        Ok(bytes)
    }
}

pub(crate) fn spawn(plan: PowderPreparePlan) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(32);
    tokio::spawn(async move {
        if let Err(error) = execute(plan, &emitter).await {
            emitter.fail(error).await;
        }
    });
    handle
}

async fn execute(plan: PowderPreparePlan, emitter: &OperationEmitter) -> Result<(), KitError> {
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Personalizing,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    let stages = (plan.bundle.firmware().len() + 2) as u64;
    let source = plan.source.clone();
    let destination = plan.destination.clone();
    let summary_text = format!(
        "built powder custom IPSW for {} {} ({}) at {}",
        plan.product_type,
        plan.version,
        plan.build,
        destination.display()
    );
    let build_emitter = emitter.clone();
    let replacements = tokio::task::spawn_blocking(move || assemble(&plan, &build_emitter, stages))
        .await
        .map_err(|error| KitError::Task(error.to_string()))??;
    if emitter.is_cancelled() {
        return Ok(());
    }

    let mut builder = CustomIpswBuilder::new(FirmwareArchive::open(source)?);
    for (name, data) in replacements {
        builder = builder.replace(name, data)?;
    }
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    builder.build(&destination).await?;

    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Verifying,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    FirmwareSummary::inspect(destination)?;
    emitter
        .emit(OperationEvent::Completed {
            outcome: OperationOutcome {
                operation: OperationKind::Restore,
                summary: summary_text,
            },
        })
        .await;
    Ok(())
}

/// main.c's component and filesystem stages, returning the replacement
/// entries of the custom IPSW.
fn assemble(
    plan: &PowderPreparePlan,
    emitter: &OperationEmitter,
    stages: u64,
) -> Result<Vec<(String, Vec<u8>)>, KitError> {
    let archive = FirmwareArchive::open(&plan.source)?;
    let mut replacements: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest_rewrites: Vec<(String, String)> = Vec::new();
    let mut ramdisk = None;
    let boot_args = iboot_boot_args(&plan.config);
    let mut completed = 0_u64;
    let progress = |emitter: &OperationEmitter, completed: u64| {
        emitter.try_emit(OperationEvent::Progress(Progress {
            phase: OperationPhase::Personalizing,
            completed,
            total: Some(stages),
            unit: ProgressUnit::Steps,
        }));
    };

    for entry in plan.bundle.firmware() {
        debug!(
            component = entry.kind().plist_name(),
            file = entry.file(),
            "processing firmware entry"
        );
        let data = archive.read_entry(entry.file())?;
        let encryption = entry_encryption(entry);
        let mut current = data;

        // iBSS/iBEC patch: doiBootPatch fully unwraps (decrypt + LZSS
        // decompress), patches, and re-encrypts/re-compresses; PATCH_DEBUG is
        // unconditional for the restore boot chain.
        if matches!(
            entry.kind(),
            FirmwareComponentKind::Ibss | FirmwareComponentKind::Ibec
        ) && entry.patch()
        {
            current = transform_payload(&current, encryption, |raw| {
                Ok(patch_powder_iboot(
                    raw,
                    &PowderIBootPatchOptions {
                        boot_args: Some(boot_args.clone()),
                        debug: true,
                    },
                )?)
            })?;
        }

        if entry.kind() == FirmwareComponentKind::KernelCache {
            // main.c's dedicated "KernelCache" branch; only two-bundle 6/8/9
            // target bundles emit this kind, single-IPSW bundles never do.
            if let Some(path) = entry.decrypt_path() {
                let mut copy = decrypt_rewrap(&current, encryption)?;
                if entry.patch() {
                    copy = transform_payload(&copy, None, |raw| Ok(patch_kernel32(raw)?))?;
                }
                replacements.push((path.to_owned(), copy));
                // main.c rewrites the hardcoded "RestoreKernelCache" component.
                manifest_rewrites.push(("RestoreKernelCache".to_owned(), path.to_owned()));
            }
            if plan.config.filesystem_jailbreak() {
                current = transform_payload(&current, encryption, |raw| Ok(patch_kernel32(raw)?))?;
            }
            if entry.decrypt() {
                current = decrypt_rewrap(&current, encryption)?;
            }
            replacements.push((entry.file().to_owned(), current));
        } else if entry.decrypt() || entry.decrypt_path().is_some() {
            // doDecrypt: peel the IMG3 encryption and rewrap unencrypted; a
            // DecryptPath redirects the output and rewrites the manifest.
            let decrypted = decrypt_rewrap(&current, encryption)?;
            match entry.decrypt_path() {
                Some(path) => {
                    replacements.push((path.to_owned(), decrypted));
                    manifest_rewrites.push((entry.kind().plist_name().to_owned(), path.to_owned()));
                }
                None => {
                    if entry.kind() == FirmwareComponentKind::RestoreRamdisk {
                        // The ramdisk is decrypted in place first and mutated
                        // later; defer the replacement until the ramdisk stage.
                        ramdisk = Some((entry.file().to_owned(), decrypted));
                    } else {
                        replacements.push((entry.file().to_owned(), decrypted));
                    }
                }
            }
        }
        completed += 1;
        progress(emitter, completed);
    }

    // Bundle without an in-place ramdisk decrypt: decrypt at open time, like
    // main.c's pRamdiskKey path.
    let (ramdisk_path, ramdisk_container) = match ramdisk {
        Some(pair) => pair,
        None => {
            let entry = plan
                .bundle
                .firmware()
                .iter()
                .find(|entry| entry.kind() == FirmwareComponentKind::RestoreRamdisk)
                .ok_or(KitError::PowderMissingComponent("Restore Ramdisk"))?;
            let data = archive.read_entry(entry.file())?;
            (
                entry.file().to_owned(),
                decrypt_rewrap(&data, entry_encryption(entry))?,
            )
        }
    };

    if !manifest_rewrites.is_empty() {
        let manifest = archive.read_entry("BuildManifest.plist")?;
        let rewrites: Vec<(&str, &str)> = manifest_rewrites
            .iter()
            .map(|(component, path)| (component.as_str(), path.as_str()))
            .collect();
        replacements.push((
            "BuildManifest.plist".to_owned(),
            rewrite_manifest_paths(&manifest, &rewrites)?,
        ));
    }

    info!("personalizing root filesystem");
    replacements.push(personalize_rootfs(plan, &archive)?);
    completed += 1;
    progress(emitter, completed);

    info!("personalizing restore ramdisk");
    replacements.push((ramdisk_path, personalize_ramdisk(plan, &ramdisk_container)?));
    progress(emitter, completed + 1);

    Ok(replacements)
}

/// Root filesystem stage of main.c: decrypt and extract the DMG, grow to the
/// estimated size, punchd rename, payload tar merges, the daibutsu
/// LaunchDaemon shuffles around the untether untar, the FilesystemJailbreak
/// fstab block, and the needPref blob; then rebuild the UDIF.
fn personalize_rootfs(
    plan: &PowderPreparePlan,
    archive: &FirmwareArchive,
) -> Result<(String, Vec<u8>), KitError> {
    let dmg = archive.read_entry(plan.bundle.root_filesystem())?;
    let key = DmgFirmwareKey::from_bytes(plan.bundle.root_filesystem_key())?;
    let decrypted = decrypt_firmware_image(&dmg, &key)?;
    let image = DmgImage::parse(decrypted)?;
    let hfs_index = image
        .partitions()
        .iter()
        .position(|partition| partition.name().contains("Apple_HFS"))
        .ok_or(KitError::MissingHfsPartition)?;
    let mut hfs = HfsImage::parse(image.extract(hfs_index)?)?;

    // minimumRootSize == rootSize here (no `-s`/`-S` overrides), rounded down
    // to 512 like main.c; grow_hfs no-ops when the volume already exceeds the
    // target.
    let root_bytes = (plan.root_size_mb * MIB) & !(512 - 1);
    let current = u64::from(hfs.total_blocks()?) * u64::from(hfs.block_size()?);
    if root_bytes > current {
        debug!(root_size_mb = plan.root_size_mb, "growing root filesystem");
        hfs.grow(usize::try_from(root_bytes).map_err(|_| HfsError::VolumeTooLarge)?)?;
    }

    if plan.punchd {
        hfs.move_entry("/sbin/launchd", "/sbin/punchd")?;
    }

    for (name, tar) in &plan.tars {
        debug!(tar = name, "merging payload tar");
        if !tar.is_empty() {
            hfs.untar(tar)?;
        }
    }

    if let Some(daibutsu) = &plan.daibutsu {
        for (source, destination) in daibutsu_pre_moves() {
            move_if_present(&mut hfs, source, destination)?;
        }
        if !daibutsu.untether.is_empty() {
            hfs.untar(&daibutsu.untether)?;
        }
        for (source, destination) in daibutsu_post_dir_moves() {
            move_if_present(&mut hfs, source, destination)?;
        }
        hfs.mkdir("/System/Library/LaunchDaemons")?;
        hfs.chmod("/System/Library/LaunchDaemons", 0o755)?;
        for (source, destination) in daibutsu_post_file_moves(&daibutsu.hwmodel) {
            move_if_present(&mut hfs, &source, &destination)?;
        }
        // Gated on hasUntether upstream; the daibutsu stage always carries one.
        if hfs.stat("/usr/libexec/CrashHousekeeping").is_ok() {
            hfs.chmod("/usr/libexec/CrashHousekeeping", 0o755)?;
        }
    }

    if plan.config.filesystem_jailbreak() {
        // Never set by single-IPSW configs; two-bundle jailbroken 6/8/9
        // targets land here and also untar the bundle-declared
        // FilesystemPackage bootstrap/package bytes after the fstab write.
        if hfs.stat(FSTAB_PATH).is_ok() {
            hfs.remove_file(FSTAB_PATH)?;
        }
        hfs.add_file(FSTAB_PATH, FSTAB_DATA)?;
        hfs.chmod(FSTAB_PATH, 0o644)?;
        hfs.chown(FSTAB_PATH, 0, 0)?;
    }

    if plan.config.need_pref() {
        // add_hfs semantics: overwrite in place when the plist exists.
        upsert_file(&mut hfs, PREF_PATH, &PREF_DATA)?;
        hfs.chmod(PREF_PATH, 0o600)?;
        hfs.chown(PREF_PATH, 501, 501)?;
    }

    let rebuilt = DmgImage::build(vec![DmgPartitionInput::new("Apple_HFS", hfs.into_bytes())])?;
    Ok((
        plan.bundle.root_filesystem().to_owned(),
        rebuilt.into_bytes(),
    ))
}

/// Restore ramdisk stage of main.c: grow by the block-count arithmetic,
/// patch ASR, untar the RamdiskPackage (target bundles only), write the dummy
/// ios marker, rewrite the options plist, and install the daibutsu reboot
/// hook; the container is rewrapped unencrypted.
fn personalize_ramdisk(plan: &PowderPreparePlan, container: &[u8]) -> Result<Vec<u8>, KitError> {
    let mut hfs = HfsImage::parse(extract_image_payload(container, None)?)?;

    let block_size = u64::from(hfs.block_size()?);
    // The RamdiskPackage size feeds the growth only when nonzero (main.c's
    // `if(rdsize)`); single-IPSW bundles declare no RamdiskPackage, and
    // two-bundle mode passes the fetched package bytes here.
    let package_size: Option<u64> = None;
    let daibutsu_sizes = plan
        .daibutsu
        .as_ref()
        .map(|stage| (stage.bin_tar.len() as u64, stage.reboot.len() as u64));
    let grow = ramdisk_grow_blocks(
        plan.ramdisk_grow_blocks,
        block_size,
        package_size,
        daibutsu_sizes,
    );
    let new_size = (u64::from(hfs.total_blocks()?) + grow) * block_size;
    debug!(grow_blocks = grow, "growing restore ramdisk");
    hfs.grow(usize::try_from(new_size).map_err(|_| HfsError::VolumeTooLarge)?)?;

    let asr = patch_asr(&hfs.read("/usr/sbin/asr")?)?;
    upsert_file(&mut hfs, "/usr/sbin/asr", &asr)?;

    // Two-bundle mode: untar the bundle-declared RamdiskPackage bytes here
    // (before the marker), followed by the base bundle's RamdiskExploit
    // reboot hook and /exploit payload.
    if let Some(marker) = plan
        .bundle
        .ramdisk_package()
        .and_then(|package| package.ios_marker())
    {
        hfs.add_file(&format!("/ios{marker}"), b"A")?;
    }

    let options_path = plan.bundle.ramdisk_options_path().to_owned();
    let original = hfs.read(&options_path).ok();
    let options =
        restore_options_plist(original.as_deref(), plan.root_size_mb, plan.update_baseband)?;
    upsert_file(&mut hfs, &options_path, &options)?;

    if let Some(daibutsu) = &plan.daibutsu {
        hfs.move_entry("/sbin/reboot", "/sbin/reboot_")?;
        hfs.add_file("/sbin/reboot", &daibutsu.reboot)?;
        if !daibutsu.bin_tar.is_empty() {
            hfs.untar(&daibutsu.bin_tar)?;
        }
        hfs.chmod("/sbin/reboot", 0o755)?;
        hfs.chown("/sbin/reboot", 0, 0)?;
    }

    Ok(replace_image_payload(container, &hfs.into_bytes(), None)?)
}

/// main.c's `defaultRootSize`: the bundle's RootFilesystemSize plus a
/// one-MB-per-MB-or-part "poor estimate" of every merged tar, the untether,
/// the bootstrap (counted by upstream only when the FilesystemJailbreak config
/// gates its untar in), and the filesystem package (counted unconditionally —
/// an upstream quirk).
fn root_size_estimate_mb(
    base_mb: u64,
    tar_sizes: &[u64],
    untether_size: Option<u64>,
    bootstrap_size: Option<u64>,
    package_size: Option<u64>,
) -> u64 {
    let mut size = base_mb;
    let extras = tar_sizes
        .iter()
        .copied()
        .chain(untether_size)
        .chain(bootstrap_size)
        .chain(package_size);
    for extra in extras {
        size += extra.div_ceil(MIB);
    }
    size
}

/// Ramdisk growth in allocation blocks, mirroring main.c: the `-ramdiskgrow`
/// base (a block count), plus `(size + 1MB) / blockSize + 64` for the
/// RamdiskPackage (only when its size is nonzero), plus
/// `(1MB + bin.tar + reboot.sh) / blockSize + 64` for daibutsu.
fn ramdisk_grow_blocks(
    base: u64,
    block_size: u64,
    package_size: Option<u64>,
    daibutsu_sizes: Option<(u64, u64)>,
) -> u64 {
    let mut grow = base;
    if let Some(size) = package_size.filter(|size| *size > 0) {
        grow += (size + MIB) / block_size + 64;
    }
    if let Some((tar, reboot)) = daibutsu_sizes {
        grow += (MIB + tar + reboot) / block_size + 64;
    }
    grow
}

/// Boot-args written into patched iBSS/iBEC images. main.c rebuilds them in
/// the Firmware loop: always CSBYPASS_BOOTARGS, with the config's
/// bootArgsString appended when bootArgsInjection is set.
fn iboot_boot_args(config: &PowderConfig) -> String {
    let mut args = CSBYPASS_BOOTARGS.to_owned();
    if config.boot_args_injection() {
        args.push(' ');
        args.push_str(config.boot_args());
    }
    args
}

/// `createRestoreOptions`: rewrite the ramdisk options plist with the
/// computed system partition size. An existing parseable plist keeps its
/// other keys and gains `MinimumSystemPartition`; a missing or unparseable
/// plist is replaced with a fresh three-key dictionary (the
/// MinimumSystemPartition add happens only on the parse path upstream).
fn restore_options_plist(
    original: Option<&[u8]>,
    size_mb: u64,
    update_baseband: bool,
) -> Result<Vec<u8>, KitError> {
    let mut dictionary = original
        .and_then(|bytes| plist::from_bytes::<plist::Value>(bytes).ok())
        .and_then(plist::Value::into_dictionary)
        .map(|mut dictionary| {
            for key in [
                "CreateFilesystemPartitions",
                "SystemPartitionSize",
                "UpdateBaseband",
                "MinimumSystemPartition",
            ] {
                dictionary.remove(key);
            }
            dictionary.insert(
                "MinimumSystemPartition".to_owned(),
                plist::Value::from(size_mb),
            );
            dictionary
        })
        .unwrap_or_default();
    dictionary.insert(
        "CreateFilesystemPartitions".to_owned(),
        plist::Value::Boolean(true),
    );
    dictionary.insert(
        "SystemPartitionSize".to_owned(),
        plist::Value::from(size_mb),
    );
    dictionary.insert(
        "UpdateBaseband".to_owned(),
        plist::Value::Boolean(update_baseband),
    );
    let mut output = Vec::new();
    plist::Value::Dictionary(dictionary).to_writer_xml(&mut output)?;
    Ok(output)
}

/// Rewrite `Manifest/<component>/Info/Path` of every build identity, like
/// main.c's manifestDirty pass. Missing keys are skipped, and manifests
/// without a BuildIdentities array are returned unchanged, as upstream.
fn rewrite_manifest_paths(manifest: &[u8], rewrites: &[(&str, &str)]) -> Result<Vec<u8>, KitError> {
    let mut value = plist::Value::from_reader(Cursor::new(manifest))?;
    let Some(identities) = value
        .as_dictionary_mut()
        .and_then(|root| root.get_mut("BuildIdentities"))
        .and_then(plist::Value::as_array_mut)
    else {
        return Ok(manifest.to_vec());
    };
    for identity in identities {
        let Some(map) = identity
            .as_dictionary_mut()
            .and_then(|identity| identity.get_mut("Manifest"))
            .and_then(plist::Value::as_dictionary_mut)
        else {
            continue;
        };
        for &(component, path) in rewrites {
            if let Some(info) = map
                .get_mut(component)
                .and_then(plist::Value::as_dictionary_mut)
                .and_then(|component| component.get_mut("Info"))
                .and_then(plist::Value::as_dictionary_mut)
            {
                info.insert("Path".to_owned(), plist::Value::String(path.to_owned()));
            }
        }
    }
    let mut output = Vec::new();
    value.to_writer_xml(&mut output)?;
    Ok(output)
}

/// doDecrypt: peel one layer (IMG3 decryption only, the payload stays
/// LZSS-compressed) and rewrap into an unencrypted container.
fn decrypt_rewrap(
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, KitError> {
    let payload = extract_image_payload(container, encryption)?;
    Ok(replace_image_payload(container, &payload, None)?)
}

/// doiBootPatch/doKernelPatch payload flow: decrypt, LZSS-decompress when
/// compressed, transform the raw image, re-compress when it was compressed,
/// and rewrap with the same encryption.
fn transform_payload(
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
    transform: impl FnOnce(&[u8]) -> Result<Vec<u8>, KitError>,
) -> Result<Vec<u8>, KitError> {
    let payload = extract_image_payload(container, encryption)?;
    let compressed = is_lzss_compressed(&payload);
    let raw = if compressed {
        decompress_lzss(&payload)?
    } else {
        payload
    };
    let transformed = transform(&raw)?;
    let wrapped = if compressed {
        compress_lzss(&transformed)?
    } else {
        transformed
    };
    Ok(replace_image_payload(container, &wrapped, encryption)?)
}

/// add_hfs semantics: overwrite the file in place when it exists, create it
/// otherwise.
fn upsert_file(image: &mut HfsImage, path: &str, data: &[u8]) -> Result<(), HfsError> {
    if image.stat(path).is_ok() {
        image.write_file(path, data)
    } else {
        image.add_file(path, data)
    }
}

/// xpwn's `move`: the return value is ignored upstream, so a missing source
/// (e.g. `/System/Library/NanoLaunchDaemons` before iOS 8.2) is skipped.
fn move_if_present(image: &mut HfsImage, source: &str, destination: &str) -> Result<(), HfsError> {
    if image.stat(source).is_ok() {
        image.move_entry(source, destination)?;
    }
    Ok(())
}

fn entry_encryption(entry: &FirmwareEntry) -> Option<(&[u8], &[u8])> {
    match (entry.key(), entry.iv()) {
        (Some(key), Some(iv)) => Some((key, iv.as_slice())),
        _ => None,
    }
}

/// Pre-untether rootfs moves of main.c's daibutsu block, in order.
fn daibutsu_pre_moves() -> [(&'static str, &'static str); 3] {
    [
        (
            "/usr/libexec/CrashHousekeeping",
            "/usr/libexec/CrashHousekeeping_o",
        ),
        (
            "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        ),
        ("/Library/LaunchDaemons", "/tmp/.LaunchDaemons"),
    ]
}

/// Post-untether directory swaps of the daibutsu block, in order. The caller
/// recreates `/System/Library/LaunchDaemons` (mkdir + chmod 0755) between
/// these and [`daibutsu_post_file_moves`], like main.c.
fn daibutsu_post_dir_moves() -> [(&'static str, &'static str); 2] {
    [
        ("/System/Library/LaunchDaemons", "/Library/LaunchDaemons"),
        (
            "/System/Library/NanoLaunchDaemons",
            "/Library/NanoLaunchDaemons",
        ),
    ]
}

/// Post-untether file moves of the daibutsu block, in order: the three
/// plists moved back under their own name, the three renamed to `.plist_`,
/// then the per-hwmodel jetsam plist.
fn daibutsu_post_file_moves(hwmodel: &str) -> Vec<(String, String)> {
    let mut moves = Vec::new();
    for name in [
        "bootps.plist",
        "com.apple.CrashHousekeeping.plist",
        "com.apple.MobileFileIntegrity.plist",
    ] {
        moves.push((
            format!("/Library/LaunchDaemons/{name}"),
            format!("/System/Library/LaunchDaemons/{name}"),
        ));
    }
    for name in [
        "com.apple.mDNSResponder.plist",
        "com.apple.mobile.softwareupdated.plist",
        "com.apple.softwareupdateservicesd.plist",
    ] {
        moves.push((
            format!("/Library/LaunchDaemons/{name}"),
            format!("/System/Library/LaunchDaemons/{name}_"),
        ));
    }
    moves.push((
        format!("/Library/LaunchDaemons/com.apple.jetsamproperties.{hwmodel}.plist"),
        format!("/System/Library/LaunchDaemons/com.apple.jetsamproperties.{hwmodel}.plist"),
    ));
    moves
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ramdisk_grow_matches_main_c_arithmetic() {
        // Plain build: the -ramdiskgrow base only.
        assert_eq!(ramdisk_grow_blocks(10, 4096, None, None), 10);
        // daibutsu bin.tar (2273280 bytes) + reboot.sh (500 bytes):
        // (1048576 + 2273280 + 500) / 4096 = 811 blocks.
        assert_eq!(
            ramdisk_grow_blocks(10, 4096, None, Some((2_273_280, 500))),
            10 + 811 + 64
        );
        // RamdiskPackage of 3358720 bytes: (3358720 + 1048576) / 4096 = 1076.
        assert_eq!(
            ramdisk_grow_blocks(10, 4096, Some(3_358_720), None),
            10 + 1076 + 64
        );
        // A zero-length package contributes nothing (main.c's `if(rdsize)`).
        assert_eq!(ramdisk_grow_blocks(10, 4096, Some(0), None), 10);
    }

    #[test]
    fn root_size_estimate_rounds_each_tar_up() {
        assert_eq!(root_size_estimate_mb(1030, &[], None, None, None), 1030);
        assert_eq!(root_size_estimate_mb(1030, &[MIB], None, None, None), 1031);
        assert_eq!(
            root_size_estimate_mb(1030, &[MIB + 1], None, None, None),
            1032
        );
        // Zero-length tars still count as zero, like upstream's ceil.
        assert_eq!(root_size_estimate_mb(1030, &[0], None, None, None), 1030);
        // Untether and package sizes are estimated the same way.
        assert_eq!(
            root_size_estimate_mb(1030, &[], Some(500), None, None),
            1031
        );
        assert_eq!(
            root_size_estimate_mb(1030, &[], None, None, Some(399_360)),
            1031
        );
        assert_eq!(
            root_size_estimate_mb(1030, &[100], Some(100), Some(100), Some(100)),
            1034
        );
    }

    fn options_dictionary(bytes: &[u8]) -> plist::Dictionary {
        plist::from_bytes::<plist::Value>(bytes)
            .unwrap()
            .into_dictionary()
            .unwrap()
    }

    #[test]
    fn restore_options_fresh_when_missing() {
        let output = restore_options_plist(None, 1280, true).unwrap();
        let dictionary = options_dictionary(&output);
        assert_eq!(dictionary.len(), 3);
        assert_eq!(
            dictionary.get("CreateFilesystemPartitions"),
            Some(&plist::Value::Boolean(true))
        );
        assert_eq!(
            dictionary.get("SystemPartitionSize"),
            Some(&plist::Value::from(1280_u64))
        );
        assert_eq!(
            dictionary.get("UpdateBaseband"),
            Some(&plist::Value::Boolean(true))
        );
        // Upstream adds MinimumSystemPartition only on the existing-plist path.
        assert!(!dictionary.contains_key("MinimumSystemPartition"));
    }

    #[test]
    fn restore_options_rewrites_existing_plist() {
        let original = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>CreateFilesystemPartitions</key><false/>
    <key>SystemPartitionSize</key><integer>1000</integer>
    <key>UpdateBaseband</key><true/>
    <key>MinimumSystemPartition</key><integer>900</integer>
    <key>SystemImage</key><true/>
</dict></plist>"#;
        let output = restore_options_plist(Some(original), 1280, false).unwrap();
        let dictionary = options_dictionary(&output);
        assert_eq!(dictionary.len(), 5);
        assert_eq!(
            dictionary.get("SystemImage"),
            Some(&plist::Value::Boolean(true))
        );
        assert_eq!(
            dictionary.get("CreateFilesystemPartitions"),
            Some(&plist::Value::Boolean(true))
        );
        assert_eq!(
            dictionary.get("SystemPartitionSize"),
            Some(&plist::Value::from(1280_u64))
        );
        assert_eq!(
            dictionary.get("MinimumSystemPartition"),
            Some(&plist::Value::from(1280_u64))
        );
        assert_eq!(
            dictionary.get("UpdateBaseband"),
            Some(&plist::Value::Boolean(false))
        );
    }

    #[test]
    fn restore_options_tolerates_unparseable_plist() {
        let output = restore_options_plist(Some(b"not a plist"), 1280, false).unwrap();
        let dictionary = options_dictionary(&output);
        assert_eq!(dictionary.len(), 3);
        assert!(!dictionary.contains_key("MinimumSystemPartition"));
    }

    #[test]
    fn fstab_and_pref_blobs_match_upstream() {
        assert_eq!(FSTAB_DATA.len(), 63);
        assert_eq!(
            FSTAB_DATA,
            b"/dev/disk0s1 / hfs rw 0 1\n/dev/disk0s2 /private/var hfs rw 0 2\n"
        );
        assert_eq!(PREF_DATA.len(), 76);
        let pref = plist::from_bytes::<plist::Value>(&PREF_DATA)
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            pref.get("SBShowNonDefaultSystemApps"),
            Some(&plist::Value::Boolean(true))
        );
    }

    #[test]
    fn restore_iboot_args_always_carry_csbypass() {
        let version = IosVersion::from("8.4.1");
        let config = PowderConfig::resolve(BundleRole::Single, true, &version, false, None)
            .unwrap()
            .unwrap();
        assert_eq!(iboot_boot_args(&config), CSBYPASS_BOOTARGS);
        let verbose = PowderConfig::resolve(BundleRole::Single, true, &version, true, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            iboot_boot_args(&verbose),
            format!("{CSBYPASS_BOOTARGS} pio-error=0 -v")
        );
        let custom =
            PowderConfig::resolve(BundleRole::Single, false, &version, false, Some("serial=1"))
                .unwrap()
                .unwrap();
        assert_eq!(
            iboot_boot_args(&custom),
            format!("{CSBYPASS_BOOTARGS} pio-error=0 debug=0x2014e serial=3 serial=1")
        );
    }

    #[test]
    fn daibutsu_move_lists_match_main_c_order() {
        assert_eq!(
            daibutsu_pre_moves(),
            [
                (
                    "/usr/libexec/CrashHousekeeping",
                    "/usr/libexec/CrashHousekeeping_o"
                ),
                (
                    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
                ),
                ("/Library/LaunchDaemons", "/tmp/.LaunchDaemons"),
            ]
        );
        assert_eq!(
            daibutsu_post_dir_moves(),
            [
                ("/System/Library/LaunchDaemons", "/Library/LaunchDaemons"),
                (
                    "/System/Library/NanoLaunchDaemons",
                    "/Library/NanoLaunchDaemons"
                ),
            ]
        );
        let moves = daibutsu_post_file_moves("N90");
        let expected: Vec<(String, String)> = [
            ("bootps.plist", "bootps.plist"),
            (
                "com.apple.CrashHousekeeping.plist",
                "com.apple.CrashHousekeeping.plist",
            ),
            (
                "com.apple.MobileFileIntegrity.plist",
                "com.apple.MobileFileIntegrity.plist",
            ),
            (
                "com.apple.mDNSResponder.plist",
                "com.apple.mDNSResponder.plist_",
            ),
            (
                "com.apple.mobile.softwareupdated.plist",
                "com.apple.mobile.softwareupdated.plist_",
            ),
            (
                "com.apple.softwareupdateservicesd.plist",
                "com.apple.softwareupdateservicesd.plist_",
            ),
            (
                "com.apple.jetsamproperties.N90.plist",
                "com.apple.jetsamproperties.N90.plist",
            ),
        ]
        .iter()
        .map(|(source, destination)| {
            (
                format!("/Library/LaunchDaemons/{source}"),
                format!("/System/Library/LaunchDaemons/{destination}"),
            )
        })
        .collect();
        assert_eq!(moves, expected);
    }

    #[test]
    fn manifest_rewrite_updates_every_identity_and_skips_missing() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildIdentities</key><array>
<dict><key>Manifest</key><dict>
    <key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3</string></dict></dict>
    <key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.n90</string></dict></dict>
</dict></dict>
<dict><key>Manifest</key><dict>
    <key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/all_flash.n90bap.production/DeviceTree.n90bap.img3</string></dict></dict>
</dict></dict>
</array>
</dict></plist>"#;
        let output = rewrite_manifest_paths(
            manifest,
            &[
                ("RestoreDeviceTree", "Downgrade/RestoreDeviceTree"),
                ("RestoreKernelCache", "Downgrade/RestoreKernelCache"),
            ],
        )
        .unwrap();
        let value = plist::Value::from_reader(Cursor::new(&output)).unwrap();
        let identities = value
            .as_dictionary()
            .unwrap()
            .get("BuildIdentities")
            .unwrap()
            .as_array()
            .unwrap();
        let path_of = |identity: &plist::Value, component: &str| {
            identity
                .as_dictionary()
                .unwrap()
                .get("Manifest")?
                .as_dictionary()?
                .get(component)?
                .as_dictionary()?
                .get("Info")?
                .as_dictionary()?
                .get("Path")?
                .as_string()
                .map(str::to_owned)
        };
        assert_eq!(
            path_of(&identities[0], "RestoreDeviceTree").as_deref(),
            Some("Downgrade/RestoreDeviceTree")
        );
        assert_eq!(
            path_of(&identities[0], "RestoreKernelCache").as_deref(),
            Some("Downgrade/RestoreKernelCache")
        );
        // The second identity lacks RestoreKernelCache; only its DeviceTree moves.
        assert_eq!(
            path_of(&identities[1], "RestoreDeviceTree").as_deref(),
            Some("Downgrade/RestoreDeviceTree")
        );
    }

    #[test]
    fn manifest_rewrite_passes_through_without_identities() {
        let manifest = br#"<?xml version="1.0"?><plist version="1.0"><dict></dict></plist>"#;
        let output =
            rewrite_manifest_paths(manifest, &[("RestoreDeviceTree", "Downgrade/X")]).unwrap();
        assert_eq!(output, manifest);
    }
}
