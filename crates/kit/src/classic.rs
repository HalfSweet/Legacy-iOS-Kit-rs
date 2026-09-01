//! Classic xpwn `ipsw` custom IPSW builder for old devices, porting
//! daibutsuCFW's `xpwn/ipsw-patch/main.c` (commit
//! `de7956d9722ed83f27caec8c0b29e3d8361691fc`, the tool LukeZGD's
//! Legacy-iOS-Kit ships as `bin/ipsw`) and the payload/hacktivation wiring of
//! restore.sh's `ipsw_prepare_jailbreak` for the S5L8900 and
//! S5L8720/8920/8922/A4 targets the classic tool serves.
//!
//! Planning mirrors `ipsw_prepare_jailbreak` plus the classic branches of
//! `ipsw_prepare_bundle`: validate the device, read the target version/build
//! from the BuildManifest (or, for 3.x S5L8900 IPSWs, `Restore.plist`), gate
//! hacktivation, fetch the firmware keys, derive old mode from the upstream
//! dispatch, resolve the payload tar matrix, and resolve the firmware bundle
//! (patch availability checked against the resource catalog).
//!
//! Building mirrors main.c's stage order. The `FirmwarePatches` loop patches
//! each entry with `doPatch` ([`patch_layered`]: peel the 8900/IMG2/IMG3/
//! complzss stack, bsdiff the raw image, re-stack with the same key material;
//! `exploit8900` for `WTF.s5l8900xall.RELEASE`), then decrypts it with
//! `doDecrypt` (peel one layer, rewrap plaintext) when `Decrypt`/
//! `DecryptPath` is set, rewriting `Manifest/<component>/Info/Path` of every
//! build identity for `DecryptPath` outputs (skipped when the IPSW has no
//! BuildManifest, like upstream's NULL-manifest guard). The "Restore Ramdisk"
//! entry's key material is retained for the ramdisk stage unless the entry
//! was decrypted in place (old mode). The root filesystem is decrypted with
//! the bundle's `RootFilesystemKey`, grown to `defaultRootSize` plus the
//! `-S 30` jailbreak allowance, patched in place (`FilesystemPatches`, only
//! the "Patch" action is emitted — the lockdownd hacktivation patch),
//! punchd-renamed, and merged with the payload tars in argv order. The
//! restore ramdisk is grown by `-ramdiskgrow` blocks, patched in place
//! (`RamdiskPatches`), stripped of `PASS.png` when the bundle carries a
//! "WTF 2" entry, and gets the rewritten options plist
//! (`createRestoreOptions`); old mode re-encrypts it with the same keys.
//!
//! After the builder's own stages, the patchcomp post-steps of
//! `ipsw_prepare_s5l8900`/`ipsw_prepare_custom` and the iPhone2,1 >=5.x
//! `ipsw_prepare_ios4patches` tail replace whole custom-IPSW entries with
//! precomputed bundle diffs over the stock components
//! ([`crate::classic_post`]). `ipsw_bbreplace` never applies to a classic
//! flow (restore.sh:4350-4351 returns early for `device_proc < 5`).
//!
//! Not modeled (never reachable from the classic call sites upstream):
//! main.c's `-s`/`-e`/`-ota`/`-daibutsu`/`-memory` flags (memory output is
//! inherent), the `Update Ramdisk` and `DeleteBaseband` bundle keys (no
//! classic bundle emits them), the `IsPlain` entry flag, the ibootim layer of
//! the container stack (iOS 1.x era), `needPref` (no classic bundle sets it;
//! the write step is ported but inert), and the Cydia package untar of the
//! post-`ipsw` steps. The output stays a deflated IPSW written through
//! [`CustomIpswBuilder`] (upstream stores entries; same as the powder
//! builder).

use std::{fmt, io::Cursor, path::PathBuf};

use legacy_ios_assets::DeviceDatabase;
use legacy_ios_core::{
    BoardConfig, BuildId, CancellationSafety, IosVersion, OperationEvent, OperationKind,
    OperationOutcome, OperationPhase, ProductType, Progress, ProgressUnit, Soc,
};
use legacy_ios_firmware::{
    ClassicBundle, ClassicBundleRequest, ClassicComponent, ClassicFirmwareEntry,
    ClassicPayloadPlan, ClassicPayloadRequest, ClassicProcessor, ClassicTar, CustomIpswBuilder,
    FirmwareArchive, FirmwareKeyProvider, FirmwareKeySet, RestoreBehavior, iboot_tar,
    system_partition_size, system_version_tar,
};
use legacy_ios_image::{
    DmgFirmwareKey, DmgImage, DmgPartitionInput, HfsError, HfsImage, apply_wtf_exploit,
    decrypt_firmware_image, extract_image_payload, patch_layered, replace_image_payload,
};
use tracing::{debug, info};

use crate::powder::{
    PREF_DATA, PREF_PATH, decrypt_rewrap, read_resource, read_tar_resource, restore_options_plist,
    rewrite_manifest_paths, upsert_file,
};
use crate::{FirmwareSummary, KitError, OperationHandle, operation::OperationEmitter};

/// `-ramdiskgrow` default passed by `ipsw_prepare_jailbreak`, in ramdisk
/// allocation blocks (upstream quirk: the value counts blocks, not bytes).
pub const DEFAULT_CLASSIC_RAMDISK_GROW_BLOCKS: u64 = 10;

const MIB: u64 = 1024 * 1024;

/// Request for a classic custom build, mirroring the option surface of
/// upstream's `ipsw_prepare_jailbreak` for the classic `ipsw` tool path
/// (jailbreak, OpenSSH, hacktivate, beta, baseband update, ramdisk growth,
/// and the merge tars).
pub struct ClassicPrepareRequest {
    product_type: ProductType,
    board_config: BoardConfig,
    source: PathBuf,
    destination: PathBuf,
    cache_root: PathBuf,
    jailbreak: bool,
    openssh: bool,
    hacktivate: bool,
    beta: bool,
    old_bootrom_24kpwn: bool,
    disable_baseband_update: bool,
    ramdisk_grow_blocks: u64,
    iboot_sidecar: Option<(String, Vec<u8>)>,
    extra_tars: Vec<(String, Vec<u8>)>,
    latest_version: Option<IosVersion>,
    ios41_ipsw: Option<PathBuf>,
}

impl ClassicPrepareRequest {
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
            hacktivate: false,
            beta: false,
            old_bootrom_24kpwn: false,
            disable_baseband_update: false,
            ramdisk_grow_blocks: DEFAULT_CLASSIC_RAMDISK_GROW_BLOCKS,
            iboot_sidecar: None,
            extra_tars: Vec::new(),
            latest_version: None,
            ios41_ipsw: None,
        }
    }

    /// Mirror of upstream's `ipsw_jailbreak`: resolve the jailbreak payload
    /// matrix and add the `-S 30` system partition allowance.
    pub fn with_jailbreak(mut self, enabled: bool) -> Self {
        self.jailbreak = enabled;
        self
    }

    /// Mirror of `ipsw_openssh`: append the sshdeb/openssh/openssl payload
    /// tars.
    pub fn with_openssh(mut self, enabled: bool) -> Self {
        self.openssh = enabled;
        self
    }

    /// Mirror of `ipsw_hacktivate`: patch lockdownd in the root filesystem.
    /// Gated at plan time: requires the jailbreak option and a hacktivatable
    /// device/version (iPhone/iPad1,1 on iOS 3.1-6.x).
    pub fn with_hacktivate(mut self, enabled: bool) -> Self {
        self.hacktivate = enabled;
        self
    }

    /// Beta target: merge the generated `systemversion.tar` and emit the
    /// reduced beta bundle.
    pub fn with_beta(mut self, enabled: bool) -> Self {
        self.beta = enabled;
        self
    }

    /// The device is an old-bootrom iPod2,1 on a 3.1/4.0 target (upstream's
    /// `$ipsw_24o`): suppresses the 3.1.x greenpois0n package and enables the
    /// 24kpwn old-mode bundle entries.
    pub fn with_24kpwn_old_bootrom(mut self, enabled: bool) -> Self {
        self.old_bootrom_24kpwn = enabled;
        self
    }

    /// Mirror of `--disable-bbupdate`/`--dead-bb`: keep `UpdateBaseband`
    /// disabled in the restore ramdisk options plist.
    pub fn with_disable_baseband_update(mut self, enabled: bool) -> Self {
        self.disable_baseband_update = enabled;
        self
    }

    /// Mirror of `-ramdiskgrow`: ramdisk growth in allocation blocks.
    /// Defaults to [`DEFAULT_CLASSIC_RAMDISK_GROW_BLOCKS`].
    pub fn with_ramdisk_grow_blocks(mut self, blocks: u64) -> Self {
        self.ramdisk_grow_blocks = blocks;
        self
    }

    /// Externally patched iBoot merged as `iBoot.tar` ahead of the jailbreak
    /// payloads (upstream's `ipsw_prepare_jailbreak iboot`). `name` is the tar
    /// entry name (`iBEC` for iPad1,1, `iBoot` otherwise).
    pub fn with_iboot_sidecar(mut self, name: impl Into<String>, data: Vec<u8>) -> Self {
        self.iboot_sidecar = Some((name.into(), data));
        self
    }

    /// Extra payload tars merged into the root filesystem ahead of the
    /// generated and jailbreak payloads, like upstream's per-device
    /// `baseband-<ecid>.tar`/`activation-<ecid>.tar` (pass them in that
    /// order).
    pub fn with_extra_tars(mut self, tars: Vec<(String, Vec<u8>)>) -> Self {
        self.extra_tars = tars;
        self
    }

    /// The device's latest iOS version (`device_latest_vers`), driving the
    /// old-mode derivation. Defaults to the target version; pass the target
    /// version explicitly to force the non-old iPhone2,1 blob-restore path.
    pub fn with_latest_version(mut self, version: IosVersion) -> Self {
        self.latest_version = Some(version);
        self
    }

    /// Local iPhone1,2 4.1 (8B117) IPSW override for the 4.2.1 patchcomp
    /// components (upstream downloads it into `saved/iPhone1,2/8B117` when
    /// absent). Defaults to fetching from the pinned Apple URL.
    pub fn with_ios41_ipsw(mut self, path: Option<PathBuf>) -> Self {
        self.ios41_ipsw = path;
        self
    }
}

impl fmt::Debug for ClassicPrepareRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicPrepareRequest")
            .field("product_type", &self.product_type)
            .field("board_config", &self.board_config)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("jailbreak", &self.jailbreak)
            .field("openssh", &self.openssh)
            .field("hacktivate", &self.hacktivate)
            .field("beta", &self.beta)
            .field("old_bootrom_24kpwn", &self.old_bootrom_24kpwn)
            .field("disable_baseband_update", &self.disable_baseband_update)
            .field("ramdisk_grow_blocks", &self.ramdisk_grow_blocks)
            .field("latest_version", &self.latest_version)
            .finish_non_exhaustive()
    }
}

/// A `FirmwarePatches` entry with its bsdiff patch payload fetched.
struct ClassicStage {
    entry: ClassicFirmwareEntry,
    patch: Option<Vec<u8>>,
}

/// A resolved classic build: validated device/version, firmware bundle with
/// fetched patch payloads, ordered payload tars, and sizing, ready to
/// execute.
pub struct ClassicPreparePlan {
    source: PathBuf,
    destination: PathBuf,
    product_type: ProductType,
    board_config: BoardConfig,
    version: IosVersion,
    build: BuildId,
    bundle: ClassicBundle,
    old: bool,
    stages: Vec<ClassicStage>,
    ramdisk_patches: Vec<(String, Vec<u8>)>,
    filesystem_patches: Vec<(String, Vec<u8>)>,
    tars: Vec<(String, Vec<u8>)>,
    punchd: bool,
    pass_delete: bool,
    root_size_mb: u64,
    update_baseband: bool,
    ramdisk_grow_blocks: u64,
    /// main.c's `needPref`: never set by classic bundles upstream, so the
    /// write step in the root filesystem stage is inert. Kept for parity.
    need_pref: bool,
    /// The post-build patchcomp / `ipsw_prepare_ios4patches` steps, applied
    /// after the builder's own stages ([`crate::classic_post`]).
    post_steps: crate::classic_post::ClassicPostSteps,
}

impl ClassicPreparePlan {
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
    pub const fn bundle(&self) -> &ClassicBundle {
        &self.bundle
    }

    /// Old mode (`ipsw_prepare_jailbreak old`): the ramdisk stays encrypted
    /// and the old-mode entry matrix (iBoot/KernelCache/WTF 2) applies.
    pub const fn old(&self) -> bool {
        self.old
    }

    /// Preferred root filesystem size in MB (main.c's `preferredRootSize`):
    /// the bundle's `RootFilesystemSize` plus one MB per tar MB, plus the
    /// `-S 30` jailbreak allowance.
    pub const fn root_size_mb(&self) -> u64 {
        self.root_size_mb
    }
}

impl fmt::Debug for ClassicPreparePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClassicPreparePlan")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("product_type", &self.product_type)
            .field("board_config", &self.board_config)
            .field("version", &self.version)
            .field("build", &self.build)
            .field("old", &self.old)
            .field("root_size_mb", &self.root_size_mb)
            .field("update_baseband", &self.update_baseband)
            .finish_non_exhaustive()
    }
}

/// Resolve a classic build plan, mirroring `ipsw_prepare_jailbreak` and the
/// classic branches of `ipsw_prepare_bundle` (including the ramdisk options
/// plist extraction for `SystemPartitionSize` on non-3.x targets).
pub(crate) async fn plan(request: ClassicPrepareRequest) -> Result<ClassicPreparePlan, KitError> {
    let profile = DeviceDatabase::bundled()
        .find_product(&request.product_type)
        .ok_or_else(|| KitError::UnknownProduct(request.product_type.clone()))?;
    if !profile.board_configs().contains(&request.board_config) {
        return Err(KitError::UnknownBoardConfig {
            product_type: request.product_type,
            board_config: request.board_config,
        });
    }
    let processor = match profile.soc() {
        Soc::S5l8900 => ClassicProcessor::S5l8900,
        Soc::S5l8720 | Soc::S5l8920 | Soc::S5l8922 | Soc::A4 => ClassicProcessor::Other,
        soc => {
            return Err(KitError::ClassicUnsupportedDevice(format!(
                "{} ({soc})",
                request.product_type
            )));
        }
    };

    let archive = FirmwareArchive::open(&request.source)?;
    // Upstream extracts BuildManifest.plist only for non-S5L8900 devices;
    // 3.x S5L8900 IPSWs carry Restore.plist instead.
    let manifest = match (archive.build_manifest(), processor) {
        (Ok(manifest), _) => Some(manifest),
        (Err(_), ClassicProcessor::S5l8900) => None,
        (Err(error), ClassicProcessor::Other) => return Err(error.into()),
    };
    let (version, build) = match &manifest {
        Some(manifest) => (
            manifest.product_version().clone(),
            manifest.build_id().clone(),
        ),
        None => restore_plist_version(&archive)?,
    };

    if request.hacktivate
        && !(request.jailbreak && can_hacktivate(&request.product_type, version.as_str()))
    {
        return Err(KitError::ClassicCannotHacktivate {
            product_type: request.product_type.to_string(),
            version: version.to_string(),
        });
    }

    info!(
        product = %request.product_type,
        version = %version,
        build = %build,
        "fetching classic component keys"
    );
    let keys = FirmwareKeyProvider::with_cache(&request.cache_root)
        .fetch(&request.product_type, &build)
        .await?;

    let identity = match (processor, &manifest) {
        (ClassicProcessor::Other, Some(manifest)) => {
            Some(manifest.select_identity(&request.board_config, RestoreBehavior::Erase)?)
        }
        _ => None,
    };
    let major = version_major(version.as_str());
    let system_partition = if major == Some(3) {
        None
    } else {
        Some(ramdisk_system_partition(&archive, identity, &keys, &request.board_config).await?)
    };

    let filename = request
        .source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "custom.ipsw".to_owned());
    let sha1 = whole_ipsw_sha1(&request.source).await?;
    let latest_version = request
        .latest_version
        .clone()
        .unwrap_or_else(|| version.clone());
    let old = old_mode(
        processor,
        &request.product_type,
        &version,
        &latest_version,
        request.jailbreak,
    );

    let payload = ClassicPayloadPlan::resolve(
        &ClassicPayloadRequest::new(request.product_type.clone(), version.clone(), build.clone())
            .with_jailbreak(request.jailbreak)
            .with_openssh(request.openssh)
            .with_beta(request.beta)
            .with_24kpwn_old_bootrom(request.old_bootrom_24kpwn)
            .with_iboot_sidecar(request.iboot_sidecar.is_some()),
    )?;

    let mut bundle_request = ClassicBundleRequest::new(
        request.product_type.clone(),
        request.board_config.clone(),
        processor,
        filename,
        version.clone(),
        build.clone(),
        latest_version,
        sha1,
    )
    .with_old(old)
    .with_hacktivate(request.hacktivate)
    .with_beta(request.beta)
    .with_24kpwn_old_bootrom(request.old_bootrom_24kpwn);
    if let Some(system_partition) = system_partition {
        bundle_request = bundle_request.with_system_partition_size(system_partition);
    }
    let bundle = ClassicBundle::resolve(&bundle_request, &keys, identity)?;

    let mut stages = Vec::new();
    for entry in bundle.firmware() {
        let patch = match entry.patch() {
            Some(patch) => {
                debug!(
                    resource = patch.resource().as_str(),
                    "fetching bundle patch"
                );
                Some(read_resource(patch.resource(), &request.cache_root).await?)
            }
            None => None,
        };
        stages.push(ClassicStage {
            entry: entry.clone(),
            patch,
        });
    }
    let ramdisk_patches = match bundle.ramdisk_patches() {
        Some(patches) => {
            let mut fetched = Vec::with_capacity(patches.len());
            for patch in patches {
                fetched.push((
                    patch.file().to_owned(),
                    read_resource(patch.patch().resource(), &request.cache_root).await?,
                ));
            }
            fetched
        }
        None => Vec::new(),
    };
    let filesystem_patches = match bundle.filesystem_patches() {
        Some(patches) => {
            let mut fetched = Vec::with_capacity(patches.len());
            for patch in patches {
                fetched.push((
                    patch.file().to_owned(),
                    read_resource(patch.patch().resource(), &request.cache_root).await?,
                ));
            }
            fetched
        }
        None => Vec::new(),
    };

    // Payload tars in upstream argv order: the caller extras
    // (baseband/activation) come first (ExtraArgs), then iBoot.tar and
    // systemversion.tar, then the jailbreak payload tars (JBFiles).
    let mut tars = request.extra_tars.clone();
    for tar in payload.tars() {
        match tar {
            ClassicTar::IBoot => {
                let (name, bytes) = request
                    .iboot_sidecar
                    .as_ref()
                    .ok_or(KitError::ClassicMissingIbootSidecar)?;
                tars.push(("iBoot.tar".to_owned(), iboot_tar(name, bytes)));
            }
            ClassicTar::SystemVersion => {
                tars.push((
                    "systemversion.tar".to_owned(),
                    system_version_tar(&version, &build),
                ));
            }
            ClassicTar::Resource(id) => {
                debug!(resource = id.as_str(), "fetching jailbreak payload");
                tars.push((
                    id.as_str().to_owned(),
                    read_tar_resource(id, &request.cache_root).await?,
                ));
            }
        }
    }

    // main.c's defaultRootSize (bundle RootFilesystemSize plus a one-MB-per-
    // MB-or-part estimate of every merge tar) plus the -S 30 jailbreak
    // allowance.
    let tar_mb: u64 = tars
        .iter()
        .map(|(_, bytes)| (bytes.len() as u64).div_ceil(MIB))
        .sum();
    let root_size_mb =
        bundle.root_filesystem_size_mb() + tar_mb + if request.jailbreak { 30 } else { 0 };
    // main.c's passDelete: set when the FirmwarePatches dict carries a
    // "WTF 2" entry.
    let pass_delete = bundle
        .firmware()
        .iter()
        .any(|entry| entry.component() == ClassicComponent::Wtf2);
    let update_baseband = profile.has_baseband() && !request.disable_baseband_update;
    let jailbreak = request.jailbreak;

    // Post-`ipsw` steps of ipsw_prepare_s5l8900 / ipsw_prepare_custom /
    // ipsw_prepare_ios4patches (classic_post). Empty for the devices and
    // versions that reach none of them.
    let post_steps = crate::classic_post::ClassicPostSteps {
        patchcomp: crate::classic_post::resolve_patchcomp(
            &request.product_type,
            &request.board_config,
            version.as_str(),
            &build,
            request.jailbreak,
            request.old_bootrom_24kpwn,
            request.ios41_ipsw.as_deref(),
            &request.cache_root,
        )
        .await?,
        ios4_boot: crate::classic_post::resolve_ios4patches(
            &request.product_type,
            &request.board_config,
            version.as_str(),
            &keys,
        )?,
    };

    let plan = ClassicPreparePlan {
        source: request.source,
        destination: request.destination,
        product_type: request.product_type,
        board_config: request.board_config,
        version,
        build,
        bundle,
        old,
        stages,
        ramdisk_patches,
        filesystem_patches,
        tars,
        punchd: payload.punchd(),
        pass_delete,
        root_size_mb,
        update_baseband,
        ramdisk_grow_blocks: request.ramdisk_grow_blocks,
        need_pref: false,
        post_steps,
    };
    info!(
        product = %plan.product_type,
        version = %plan.version,
        old = plan.old,
        jailbreak,
        root_size_mb = plan.root_size_mb,
        "resolved classic build plan"
    );
    Ok(plan)
}

pub(crate) fn spawn(plan: ClassicPreparePlan) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(32);
    tokio::spawn(async move {
        if let Err(error) = execute(plan, &emitter).await {
            emitter.fail(error).await;
        }
    });
    handle
}

async fn execute(plan: ClassicPreparePlan, emitter: &OperationEmitter) -> Result<(), KitError> {
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Personalizing,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    let stages = (plan.stages.len() + 2 + usize::from(plan.post_steps.len() > 0)) as u64;
    let source = plan.source.clone();
    let destination = plan.destination.clone();
    let summary_text = format!(
        "built classic custom IPSW for {} {} ({}) at {}",
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

/// The deferred restore ramdisk of the Firmware loop: its IPSW path, the
/// patched/decrypted bytes when the loop produced them, and the key material
/// the ramdisk stage opens it with (main.c's pRamdiskKey, cleared by an
/// in-place doDecrypt).
struct RamdiskDeferral {
    path: String,
    container: Option<Vec<u8>>,
    encryption: Option<(Vec<u8>, Vec<u8>)>,
}

/// main.c's component and filesystem stages, returning the replacement
/// entries of the custom IPSW.
fn assemble(
    plan: &ClassicPreparePlan,
    emitter: &OperationEmitter,
    stages: u64,
) -> Result<Vec<(String, Vec<u8>)>, KitError> {
    let archive = FirmwareArchive::open(&plan.source)?;
    let mut replacements: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest_rewrites: Vec<(String, String)> = Vec::new();
    let mut ramdisk: Option<RamdiskDeferral> = None;
    let mut completed = 0_u64;
    let progress = |emitter: &OperationEmitter, completed: u64| {
        emitter.try_emit(OperationEvent::Progress(Progress {
            phase: OperationPhase::Personalizing,
            completed,
            total: Some(stages),
            unit: ProgressUnit::Steps,
        }));
    };

    for stage in &plan.stages {
        let entry = &stage.entry;
        debug!(
            component = entry.component().plist_name(),
            file = entry.file(),
            "processing firmware entry"
        );
        let is_ramdisk = entry.component() == ClassicComponent::RestoreRamdisk;
        if is_ramdisk {
            ramdisk = Some(RamdiskDeferral {
                path: entry.file().to_owned(),
                container: None,
                encryption: entry_encryption(entry).map(|(key, iv)| (key.to_vec(), iv.to_vec())),
            });
        }
        if stage.patch.is_none() && !entry.decrypt() && entry.decrypt_path().is_none() {
            // The entry only contributed its key/iv (Restore Ramdisk) or is
            // passed through untouched.
            completed += 1;
            progress(emitter, completed);
            continue;
        }
        let mut current = archive.read_entry(entry.file())?;
        let encryption = entry_encryption(entry);

        // doPatch: peel every layer, bsdiff the raw image, re-stack with the
        // same key material; exploit8900 for the WTF 2 image.
        if let Some(patch) = &stage.patch {
            current = patch_layered(&current, patch, encryption)?;
            if entry.file().contains("WTF.s5l8900xall.RELEASE") {
                current = apply_wtf_exploit(&current)?;
            }
        }

        // doDecrypt: peel one layer and rewrap plaintext; a DecryptPath
        // redirects the output and rewrites the manifest.
        if entry.decrypt() || entry.decrypt_path().is_some() {
            let decrypted = decrypt_rewrap(&current, encryption)?;
            match entry.decrypt_path() {
                Some(path) => {
                    if stage.patch.is_some() {
                        // The original path keeps the patched bytes.
                        replacements.push((entry.file().to_owned(), current));
                    }
                    replacements.push((path.to_owned(), decrypted));
                    manifest_rewrites
                        .push((entry.component().plist_name().to_owned(), path.to_owned()));
                }
                None if is_ramdisk => {
                    // Decrypted in place: the ramdisk stage opens it plain
                    // (main.c clears pRamdiskKey here).
                    ramdisk = Some(RamdiskDeferral {
                        path: entry.file().to_owned(),
                        container: Some(decrypted),
                        encryption: None,
                    });
                }
                None => replacements.push((entry.file().to_owned(), decrypted)),
            }
        } else if stage.patch.is_some() {
            if is_ramdisk {
                // Patched but still encrypted: the ramdisk stage opens it
                // with the retained keys.
                let mut deferral = ramdisk.take().expect("ramdisk captured above");
                deferral.container = Some(current);
                ramdisk = Some(deferral);
            } else {
                replacements.push((entry.file().to_owned(), current));
            }
        }
        completed += 1;
        progress(emitter, completed);
    }

    if !manifest_rewrites.is_empty() {
        // Skipped when the IPSW has no BuildManifest.plist (3.x S5L8900),
        // like main.c's NULL-manifest guard.
        if let Ok(manifest) = archive.read_entry("BuildManifest.plist") {
            let rewrites: Vec<(&str, &str)> = manifest_rewrites
                .iter()
                .map(|(component, path)| (component.as_str(), path.as_str()))
                .collect();
            replacements.push((
                "BuildManifest.plist".to_owned(),
                rewrite_manifest_paths(&manifest, &rewrites)?,
            ));
        }
    }

    let Some(deferral) = ramdisk else {
        return Err(KitError::ClassicMissingComponent("Restore Ramdisk"));
    };
    let ramdisk_container = match deferral.container {
        Some(container) => container,
        None => archive.read_entry(&deferral.path)?,
    };

    info!("personalizing root filesystem");
    replacements.push(personalize_rootfs(plan, &archive)?);
    completed += 1;
    progress(emitter, completed);

    info!("personalizing restore ramdisk");
    let encryption = deferral
        .encryption
        .as_ref()
        .map(|(key, iv)| (key.as_slice(), iv.as_slice()));
    replacements.push((
        deferral.path,
        personalize_ramdisk(plan, &ramdisk_container, encryption)?,
    ));
    progress(emitter, completed + 1);
    completed += 1;

    if plan.post_steps.len() > 0 {
        // The patchcomp / ios4patches replacements overwrite same-name
        // entries written by the stages above (CustomIpswBuilder::replace
        // semantics), like upstream's `zip -r0` updates.
        info!("applying post-build component patches");
        replacements.extend(crate::classic_post::apply_post_steps(
            &plan.post_steps,
            &archive,
        )?);
        completed += 1;
        progress(emitter, completed);
    }

    Ok(replacements)
}

/// Root filesystem stage of main.c: decrypt and extract the DMG, grow to the
/// preferred size, patch the FilesystemPatches files in place (the lockdownd
/// hacktivation patch), punchd rename, and merge the payload tars in argv
/// order; then rebuild the UDIF.
fn personalize_rootfs(
    plan: &ClassicPreparePlan,
    archive: &FirmwareArchive,
) -> Result<(String, Vec<u8>), KitError> {
    let dmg = archive.read_entry(plan.bundle.root_filesystem())?;
    let key = DmgFirmwareKey::from_bytes(plan.bundle.root_filesystem_key())?;
    let decrypted = decrypt_firmware_image(&dmg, &key)?;
    let image = DmgImage::parse(decrypted)?;
    // Old rootfs UDIFs do not reliably name their HFS partition; fall back to
    // a single-partition image.
    let hfs_index = image
        .partitions()
        .iter()
        .position(|partition| partition.name().contains("Apple_HFS"))
        .or_else(|| (image.partitions().len() == 1).then_some(0))
        .ok_or(KitError::MissingHfsPartition)?;
    let mut hfs = HfsImage::parse(image.extract(hfs_index)?)?;

    // minimumRootSize == rootSize here (no `-s`; `-S` is already folded into
    // root_size_mb), rounded down to 512 like main.c; grow_hfs no-ops when the
    // volume already exceeds the target.
    let root_bytes = (plan.root_size_mb * MIB) & !(512 - 1);
    let current = u64::from(hfs.total_blocks()?) * u64::from(hfs.block_size()?);
    if root_bytes > current {
        debug!(root_size_mb = plan.root_size_mb, "growing root filesystem");
        hfs.grow(usize::try_from(root_bytes).map_err(|_| HfsError::VolumeTooLarge)?)?;
    }

    // FilesystemPatches: doPatchInPlace (only the "Patch" action is emitted;
    // "ReplaceKernel" never is). The bundle paths have no leading slash.
    for (file, patch) in &plan.filesystem_patches {
        let path = format!("/{file}");
        let patched = patch_layered(&hfs.read(&path)?, patch, None)?;
        upsert_file(&mut hfs, &path, &patched)?;
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

    if plan.need_pref {
        // add_hfs semantics: overwrite in place when the plist exists. No
        // classic bundle sets needPref upstream, so this never runs.
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

/// Restore ramdisk stage of main.c: grow by `-ramdiskgrow` blocks, patch the
/// RamdiskPatches files in place, delete `PASS.png` when the bundle carries a
/// "WTF 2" entry, and write the rewritten options plist
/// (`createRestoreOptions`). Old mode re-encrypts the container with the same
/// keys (xpwn's closeImg3).
fn personalize_ramdisk(
    plan: &ClassicPreparePlan,
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, KitError> {
    let mut hfs = HfsImage::parse(extract_image_payload(container, encryption)?)?;

    let block_size = u64::from(hfs.block_size()?);
    let new_size = (u64::from(hfs.total_blocks()?) + plan.ramdisk_grow_blocks) * block_size;
    debug!(
        grow_blocks = plan.ramdisk_grow_blocks,
        "growing restore ramdisk"
    );
    hfs.grow(usize::try_from(new_size).map_err(|_| HfsError::VolumeTooLarge)?)?;

    // RamdiskPatches: doPatchInPlace; the bundle paths have no leading slash.
    for (file, patch) in &plan.ramdisk_patches {
        let path = format!("/{file}");
        let patched = patch_layered(&hfs.read(&path)?, patch, None)?;
        upsert_file(&mut hfs, &path, &patched)?;
    }

    // main.c ignores removeFile's return, so a missing PASS.png is skipped.
    const PASS_PATH: &str = "/usr/local/share/restore/PASS.png";
    if plan.pass_delete && hfs.stat(PASS_PATH).is_ok() {
        hfs.remove_file(PASS_PATH)?;
    }

    let options_path = plan.bundle.ramdisk_options_path().to_owned();
    let original = hfs.read(&options_path).ok();
    let options =
        restore_options_plist(original.as_deref(), plan.root_size_mb, plan.update_baseband)?;
    upsert_file(&mut hfs, &options_path, &options)?;

    Ok(replace_image_payload(
        container,
        &hfs.into_bytes(),
        encryption,
    )?)
}

/// Version/build of a 3.x S5L8900 IPSW, which carries `Restore.plist` instead
/// of a BuildManifest.
fn restore_plist_version(archive: &FirmwareArchive) -> Result<(IosVersion, BuildId), KitError> {
    let bytes = archive.read_entry("Restore.plist")?;
    let value = plist::Value::from_reader(Cursor::new(bytes))?;
    let dictionary = value
        .as_dictionary()
        .ok_or(KitError::ClassicMissingComponent("Restore.plist"))?;
    let get = |key: &str| {
        dictionary
            .get(key)
            .and_then(plist::Value::as_string)
            .map(str::to_owned)
            .ok_or(KitError::ClassicMissingComponent("Restore.plist version"))
    };
    Ok((
        IosVersion::from(get("ProductVersion")?),
        BuildId::from(get("ProductBuildVersion")?),
    ))
}

/// `ipsw_prepare_bundle` derives RootFilesystemSize from the restore
/// ramdisk's options plist: decrypt the ramdisk and read the per-board plist
/// first, falling back to the plain one, like the shell flow. The ramdisk
/// path comes from the build identity when one was extracted (non-S5L8900)
/// and from the firmware key set otherwise.
async fn ramdisk_system_partition(
    archive: &FirmwareArchive,
    identity: Option<&legacy_ios_firmware::BuildIdentity>,
    keys: &FirmwareKeySet,
    board: &BoardConfig,
) -> Result<u64, KitError> {
    let ramdisk_path = identity
        .and_then(|identity| identity.component_path("RestoreRamDisk").ok())
        .map(str::to_owned)
        .or_else(|| {
            keys.key("RestoreRamdisk")
                .map(|key| key.filename().to_owned())
        })
        .ok_or(KitError::ClassicBundle(
            legacy_ios_firmware::ClassicBundleError::MissingKeyMaterial(
                "RestoreRamdisk".to_owned(),
            ),
        ))?;
    let ramdisk_container = archive.read_entry(&ramdisk_path)?;
    let ramdisk_key = keys
        .key("RestoreRamdisk")
        .and_then(|key| key.key().map(<[u8]>::to_vec));
    let ramdisk_iv = keys.key("RestoreRamdisk").and_then(|key| key.iv().copied());
    let board = board.clone();
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
                .map_err(|_| KitError::ClassicMissingRamdiskOptions),
        }
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    Ok(system_partition_size(&options_plist)?)
}

/// Whole-IPSW SHA-1 of the source archive (`device_target_sha1`), computed as
/// a stream.
async fn whole_ipsw_sha1(path: &std::path::Path) -> Result<String, KitError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use sha1::Digest;
        let mut file = std::fs::File::open(path)?;
        let mut hasher = sha1::Sha1::new();
        let mut buffer = vec![0_u8; MIB as usize];
        loop {
            let read = std::io::Read::read(&mut file, &mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(40);
        for byte in digest {
            use std::fmt::Write;
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(hex)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))?
}

/// Upstream's hacktivation gate (restore.sh `ipsw_canhacktivate`): iPhone and
/// iPad1,1 devices on iOS 3.1-6.x (3.0 excluded).
fn can_hacktivate(product_type: &ProductType, version: &str) -> bool {
    let product = product_type.as_str();
    (product.starts_with("iPhone") || product == "iPad1,1")
        && matches!(version_major(version), Some(3..=6))
        && !version.starts_with("3.0")
}

/// Old-mode derivation, mirroring the upstream dispatch: S5L8900 always goes
/// through `ipsw_prepare_s5l8900` (old); iPod2,1 always through
/// `ipsw_prepare_custom` (old); iPhone2,1 reaches the plain
/// `ipsw_prepare_jailbreak` on the latest version with jailbreak (blob
/// restores too — the caller models those by passing the target as
/// `latest_version`); other proc4 devices reach the classic tool only through
/// `ipsw_prepare_32bit`'s 3.x/4.0/4.1 redirect, which passes no `old`.
fn old_mode(
    processor: ClassicProcessor,
    product_type: &ProductType,
    version: &IosVersion,
    latest: &IosVersion,
    jailbreak: bool,
) -> bool {
    if processor == ClassicProcessor::S5l8900 {
        return true;
    }
    match product_type.as_str() {
        "iPod2,1" => true,
        "iPhone2,1" => !(version == latest && jailbreak),
        _ => !is_pre_42(version.as_str()),
    }
}

/// The `[23]* | 4.[01]*` redirect versions of `ipsw_prepare_32bit`.
fn is_pre_42(version: &str) -> bool {
    version.starts_with('2')
        || version.starts_with('3')
        || version.starts_with("4.0")
        || version.starts_with("4.1")
}

fn version_major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

fn entry_encryption(entry: &ClassicFirmwareEntry) -> Option<(&[u8], &[u8])> {
    match (entry.key(), entry.iv()) {
        (Some(key), Some(iv)) => Some((key, iv.as_slice())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use hfsplus::testutil::HfsPlusImageBuilder;

    use super::*;

    /// The image crate's bsdiff fixture: "abc" to "axc!".
    const ABC_PATCH: &str = concat!(
        "42534449464634302a0000000000000027000000000000000400000000000000",
        "425a6839314159265359d0149a29000004c0006808200030cd34193f5209593c5d",
        "c914e14243405268a4425a6839314159265359bd1ca64a000000e0004000010020",
        "002100828c5dc914e14242f4729928425a68393141592653592d15eb1c00000010",
        "002000200021184682ee48a70a1205a2bd6380"
    );

    fn hex(bytes: &str) -> Vec<u8> {
        (0..bytes.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&bytes[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hacktivation_gate_matches_upstream() {
        let iphone = ProductType::from("iPhone2,1");
        let ipad = ProductType::from("iPad1,1");
        let ipod = ProductType::from("iPod3,1");
        assert!(can_hacktivate(&iphone, "6.1.6"));
        assert!(can_hacktivate(&iphone, "3.1.3"));
        assert!(!can_hacktivate(&iphone, "3.0.1"));
        assert!(!can_hacktivate(&iphone, "7.1.2"));
        assert!(can_hacktivate(&ipad, "4.3.3"));
        assert!(!can_hacktivate(&ipod, "4.1"));
    }

    #[test]
    fn old_mode_matches_upstream_dispatch() {
        let version = |version: &str| IosVersion::from(version);
        // S5L8900 is always old.
        assert!(old_mode(
            ClassicProcessor::S5l8900,
            &ProductType::from("iPhone1,2"),
            &version("4.2.1"),
            &version("4.2.1"),
            true,
        ));
        // iPod2,1 always goes through ipsw_prepare_custom (old).
        assert!(old_mode(
            ClassicProcessor::Other,
            &ProductType::from("iPod2,1"),
            &version("4.2.1"),
            &version("4.2.1"),
            true,
        ));
        // iPhone2,1 on the latest version with jailbreak is non-old.
        assert!(!old_mode(
            ClassicProcessor::Other,
            &ProductType::from("iPhone2,1"),
            &version("6.1.6"),
            &version("6.1.6"),
            true,
        ));
        // ...but old for a non-latest menu version (4.1 jailbreak).
        assert!(old_mode(
            ClassicProcessor::Other,
            &ProductType::from("iPhone2,1"),
            &version("4.1"),
            &version("6.1.6"),
            true,
        ));
        // ...and non-old without jailbreak on the latest version.
        assert!(old_mode(
            ClassicProcessor::Other,
            &ProductType::from("iPhone2,1"),
            &version("6.1.6"),
            &version("6.1.6"),
            false,
        ));
        // Other proc4 devices only reach the classic tool via the pre-4.2
        // redirect (non-old).
        assert!(!old_mode(
            ClassicProcessor::Other,
            &ProductType::from("iPhone3,1"),
            &version("4.1"),
            &version("7.1.2"),
            true,
        ));
    }

    #[test]
    fn patch_in_place_over_hfs_file() {
        // doPatchInPlace: read the file, bsdiff the raw bytes, add_hfs back.
        let mut builder = HfsPlusImageBuilder::new();
        builder.add_file("lockdownd", b"abc", 0o755);
        let mut hfs = HfsImage::parse(builder.build()).unwrap();

        let patched =
            patch_layered(&hfs.read("/lockdownd").unwrap(), &hex(ABC_PATCH), None).unwrap();
        upsert_file(&mut hfs, "/lockdownd", &patched).unwrap();
        assert_eq!(hfs.read("/lockdownd").unwrap(), b"axc!");
    }
}
