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
//! Two-bundle `-base` builds (upstream's `ipsw_prepare_powder` and the
//! 4.3.x-only `ipsw_prepare_ios4powder`, main.c's `useBaseFW` block)
//! additionally: reseal the `-apticket` DER into the scab template (the same
//! `replace_image_payload` reseal `crate::multipart` uses — xpwn's own path
//! is marked "buggy" upstream), append the bundle manifest additions to the
//! target's all_flash manifest, copy the base IPSW's NOR images over the
//! target paths with the IMG3 TYPE byte rewrites (`logo`→`logb`,
//! `recm`→`recb`, `ibot`→`ibob`), patch the target iBoot into the decrypted
//! `NewiBoot` with the config-gated boot-args (no unconditional CSBYPASS
//! here), untar the bundle-declared `FilesystemPackage` (bootstrap gated on
//! the FilesystemJailbreak config, package untarred under the same block) and
//! `RamdiskPackage` (`bin4.tar` with the patched iBoot appended for
//! ios4powder), and install the base bundle's RamdiskExploit hook: the
//! (templated) partition script as `/sbin/reboot` — the reboot4 binary for
//! ios4powder — and the per-hw/per-build exploit as `/exploit`. main.c's
//! `Update Ramdisk` removal is not modeled because the bundle format never
//! emits an `Update Ramdisk` entry.
//!
//! The build-side finishing steps upstream applies around the powdersn0w
//! invocation are part of the same build: `ipsw_prepare_battery_images`
//! copies the base IPSW's battery images into the custom IPSW (appending
//! names missing from the target BuildManifest to the all_flash manifest);
//! the non-ramdiskH two-bundle 5.x/6.x builds re-patch the powdersn0w iBoot2
//! with iBoot32Patcher's `--logo` only; `ipsw_bbreplace` swaps in the latest
//! baseband with the matching BuildManifest rewrite; and the ios4powder tail
//! re-patches the dfu iBSS/iBEC with iBoot32Patcher (`ipsw_prepare_ios4patches`,
//! superseding the powder patcher's iBSS pass), applies the AppleLogo `4g`
//! tag bytes, and installs the externally patched target iBoot as the
//! all_flash iBoot2.

use std::{fmt, io::Cursor, path::PathBuf};

use legacy_ios_assets::{DeviceDatabase, ResourceId};
use legacy_ios_core::{
    BoardConfig, BuildId, CancellationSafety, IosVersion, OperationEvent, OperationKind,
    OperationOutcome, OperationPhase, ProductType, Progress, ProgressUnit, Soc,
};
use legacy_ios_firmware::{
    BuildIdentity, BundleRole, CustomIpswBuilder, FirmwareArchive, FirmwareComponentKind,
    FirmwareEntry, FirmwareKeyProvider, FirmwareKeySet, PowderBundle, PowderBundleRequest,
    PowderConfig, PowderMode, PowderPayloadPlan, PowderPayloadRequest, PowderTar, RestoreBehavior,
    UstarBuilder, iboot_tar, partition_script_resource, reboot_script, render_partition_script,
    system_partition_size, system_version_tar, uses_ramdisk_h,
};
use legacy_ios_image::{
    DmgFirmwareKey, DmgImage, DmgPartitionInput, HfsError, HfsImage, Iboot32PatchOptions,
    PowderIBootPatchOptions, compress_lzss, decompress_lzss, decrypt_firmware_image,
    extract_image_payload, is_lzss_compressed, patch_asr, patch_iboot32_with_options,
    patch_kernel32, patch_powder_iboot, replace_image_payload,
};
use tracing::{debug, info, warn};

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

/// Request for a powdersn0w custom build, mirroring the option surface of
/// upstream's `ipsw_prepare_32bit` (single IPSW), `ipsw_prepare_powder`
/// (two-bundle `-base`), and `ipsw_prepare_ios4powder` (4.3.x `-base` with
/// `-apticket`).
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
    base: Option<PathBuf>,
    apticket: Option<Vec<u8>>,
    drav6: bool,
    latest_version: Option<IosVersion>,
    disable_baseband_update: bool,
    baseband_replacement: Option<(String, Vec<u8>)>,
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
            base: None,
            apticket: None,
            drav6: false,
            latest_version: None,
            disable_baseband_update: false,
            baseband_replacement: None,
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

    /// Base IPSW of a two-bundle build (`-base`), mirroring
    /// `ipsw_prepare_powder`; combined with a 4.3.x target this selects the
    /// `ipsw_prepare_ios4powder` variant. The base build/version are read
    /// from the base IPSW's BuildManifest at plan time.
    pub fn with_base(mut self, base: impl Into<PathBuf>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// APTicket DER resealed into the scab template (`-apticket`), required
    /// when the target bundle declares an APTicket replacement (the 4.3.x
    /// ios4powder flow). Extract it from a saved signing ticket with
    /// [`extract_apticket_der`][crate::extract_apticket_der]. Ignored without
    /// `with_base`, like upstream's `-apticket` outside `-base` mode.
    pub fn with_apticket(mut self, der: Vec<u8>) -> Self {
        self.apticket = Some(der);
        self
    }

    /// DRA v6 target (`device_target_drav6`): keeps the board name in the
    /// RamdiskExploit hardware mapping and drops the `nvram boot-ramdisk`
    /// write from the partition script of iPhone4,1 builds.
    pub fn with_drav6(mut self, enabled: bool) -> Self {
        self.drav6 = enabled;
        self
    }

    /// The device's latest iOS version (`device_latest_vers`), driving the
    /// target bundle's manifest additions. Defaults to the target version,
    /// which is correct whenever the manifest additions go unused.
    pub fn with_latest_version(mut self, version: IosVersion) -> Self {
        self.latest_version = Some(version);
        self
    }

    /// Mirror of `--disable-bbupdate`/`--dead-bb` (`device_disable_bbupdate`):
    /// skips the `ipsw_bbreplace` latest-baseband swap.
    pub fn with_disable_baseband_update(mut self, enabled: bool) -> Self {
        self.disable_baseband_update = enabled;
        self
    }

    /// The latest baseband firmware swapped in by `ipsw_bbreplace` for
    /// two-bundle builds targeting a non-latest version: `file_name` is the
    /// baseband file name the BuildManifest is pointed at (upstream's
    /// `device_use_bb`, e.g. `Mav5-11.80.00.Release.bbfw`), `data` the .bbfw
    /// bytes. Only planned for baseband devices on A5+ with a known manifest
    /// rewrite; otherwise the target baseband is kept, like upstream's early
    /// return.
    pub fn with_baseband_replacement(
        mut self,
        file_name: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        self.baseband_replacement = Some((file_name.into(), data));
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
            .field("base", &self.base)
            .field("drav6", &self.drav6)
            .field("latest_version", &self.latest_version)
            .field("disable_baseband_update", &self.disable_baseband_update)
            .field("baseband_replacement", &self.baseband_replacement.is_some())
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

/// The `ipsw_bbreplace` latest-baseband swap of a two-bundle plan: the .bbfw
/// file installed at `file` and the BuildManifest rewrite matching it.
struct BasebandReplace {
    file: String,
    data: Vec<u8>,
    rewrite: crate::baseband::BasebandRewrite,
}

/// A dfu image (iBSS/iBEC) of the ios4powder tail, resolved at plan time from
/// the target (or, for cross-device special flows, the base) firmware keys.
struct Ios4DfuImage {
    /// `Firmware/dfu/<name>` path inside the IPSW.
    file: String,
    iv: [u8; 16],
    key: Vec<u8>,
}

/// The ios4powder tail of `ipsw_prepare_ios4powder` (restore.sh:5680-5696):
/// the `ipsw_prepare_ios4patches` iBSS/iBEC re-patch and the externally
/// patched target iBoot added as the all_flash iBoot2 (absent on iPad1,1).
struct Ios4Tail {
    /// IPSW the pristine dfu images are read from: the target IPSW, or the
    /// base IPSW for cross-device special flows (`device_type_special`).
    dfu_source: PathBuf,
    dfu_images: [Ios4DfuImage; 2],
    iboot2: Option<Vec<u8>>,
}

/// Resolved base side of a two-bundle build: the base bundle (FirmwarePath
/// NOR sources, RamdiskExploit) plus the fetched exploit payload and the
/// rendered partition script (the reboot4 binary for ios4powder).
pub struct PowderBasePlan {
    source: PathBuf,
    version: IosVersion,
    build: BuildId,
    bundle: PowderBundle,
    partition: Vec<u8>,
    exploit: Vec<u8>,
}

impl PowderBasePlan {
    /// Path of the base IPSW.
    pub fn source(&self) -> &std::path::Path {
        &self.source
    }

    /// Base iOS version, read from the base IPSW's BuildManifest. The restore
    /// side takes the signing ticket from blobs saved for this version.
    pub const fn version(&self) -> &IosVersion {
        &self.version
    }

    /// Base build id.
    pub const fn build_id(&self) -> &BuildId {
        &self.build
    }

    /// The resolved base bundle, mirroring upstream's generated
    /// `BASE_*` `Info.plist`.
    pub const fn bundle(&self) -> &PowderBundle {
        &self.bundle
    }
}

impl fmt::Debug for PowderBasePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowderBasePlan")
            .field("source", &self.source)
            .field("version", &self.version)
            .field("build", &self.build)
            .finish_non_exhaustive()
    }
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
    mode: PowderMode,
    bundle: PowderBundle,
    config: PowderConfig,
    tars: Vec<(String, Vec<u8>)>,
    punchd: bool,
    daibutsu: Option<DaibutsuStage>,
    base: Option<PowderBasePlan>,
    apticket: Option<Vec<u8>>,
    scab_template: Option<Vec<u8>>,
    bootstrap: Option<Vec<u8>>,
    filesystem_package: Option<Vec<u8>>,
    ramdisk_package: Option<Vec<u8>>,
    root_size_mb: u64,
    update_baseband: bool,
    ramdisk_grow_blocks: u64,
    iboot2_logo_pass: bool,
    baseband: Option<BasebandReplace>,
    ios4_tail: Option<Ios4Tail>,
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

    /// The powdersn0w call path, derived from the base/target combination at
    /// plan time.
    pub const fn mode(&self) -> PowderMode {
        self.mode
    }

    /// The base side of a two-bundle build; `None` for single-IPSW builds.
    pub const fn base(&self) -> Option<&PowderBasePlan> {
        self.base.as_ref()
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
            .field("mode", &self.mode)
            .field("base", &self.base)
            .field("root_size_mb", &self.root_size_mb)
            .field("update_baseband", &self.update_baseband)
            .field("iboot2_logo_pass", &self.iboot2_logo_pass)
            .field("baseband", &self.baseband.is_some())
            .field("ios4_tail", &self.ios4_tail.is_some())
            .finish_non_exhaustive()
    }
}

/// Resolve a powder build plan, mirroring `ipsw_prepare_bundle` (including
/// the ramdisk options plist extraction for `SystemPartitionSize`) and
/// `ipsw_prepare_config`. With a base IPSW this mirrors the two-bundle
/// `ipsw_prepare_powder` flow (or the 4.3.x `ipsw_prepare_ios4powder`
/// variant): the base bundle/keys/options are resolved the same way and the
/// RamdiskExploit payloads are fetched.
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

    // Upstream dispatch (restore.sh `ipsw_prepare`): a 4.3.x target with a
    // base goes to `ipsw_prepare_ios4powder` (the payload plan rejects 4.x
    // other than 4.3), any other base build to `ipsw_prepare_powder`.
    let mode = match &request.base {
        None => PowderMode::Single,
        Some(_) if version.as_str().starts_with("4.") => PowderMode::Ios4,
        Some(_) => PowderMode::TwoBundle,
    };

    let base_archive = request
        .base
        .as_ref()
        .map(FirmwareArchive::open)
        .transpose()?;
    let base_manifest = base_archive
        .as_ref()
        .map(FirmwareArchive::build_manifest)
        .transpose()?;
    let base_version = base_manifest
        .as_ref()
        .map(|manifest| manifest.product_version().clone());
    let base_build = base_manifest
        .as_ref()
        .map(|manifest| manifest.build_id().clone());

    let mut payload_request = PowderPayloadRequest::new(
        mode,
        request.product_type.clone(),
        version.clone(),
        build.clone(),
    )
    .with_jailbreak(request.jailbreak)
    .with_openssh(request.openssh)
    .with_beta(request.beta)
    .with_iboot_sidecar(request.iboot_sidecar.is_some());
    if let Some(base_version) = &base_version {
        payload_request = payload_request.with_base_version(base_version.clone());
    }
    let payload = PowderPayloadPlan::resolve(&payload_request)?;

    info!(
        product = %request.product_type,
        version = %version,
        build = %build,
        "fetching powder component keys"
    );
    let key_provider = FirmwareKeyProvider::with_cache(&request.cache_root);
    let keys = key_provider.fetch(&request.product_type, &build).await?;

    let identity = manifest.select_identity(&request.board_config, RestoreBehavior::Erase)?;
    let system_partition =
        ramdisk_system_partition(&archive, identity, &keys, &request.board_config).await?;

    let filename = request
        .source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "custom.ipsw".to_owned());
    let latest_version = request
        .latest_version
        .clone()
        .unwrap_or_else(|| version.clone());
    let role = match mode {
        PowderMode::Single => BundleRole::Single,
        PowderMode::TwoBundle | PowderMode::Ios4 => BundleRole::Target,
    };
    let bundle = PowderBundle::resolve(
        &PowderBundleRequest::new(
            role,
            request.product_type.clone(),
            request.board_config.clone(),
            filename,
            version.clone(),
            version.clone(),
            latest_version.clone(),
            system_partition,
        )
        .with_jailbreak(request.jailbreak)
        .with_daibutsu(payload.daibutsu().is_some()),
        &keys,
        Some(identity),
    )?;
    let Some(config) = PowderConfig::resolve(
        role,
        request.jailbreak,
        &version,
        request.verbose_boot_args,
        request.boot_args.as_deref(),
    )?
    else {
        unreachable!("single-IPSW and target bundles always carry a config");
    };

    // The `ipsw_bbreplace` early-return conditions (restore.sh:4350-4353),
    // computed before `latest_version` moves into the base bundle request.
    let baseband_applies = baseband_replace_applies(
        profile.has_baseband(),
        profile.soc(),
        &version,
        &latest_version,
        request.disable_baseband_update,
    );

    let mut base_keys = None;
    let base = match (
        &request.base,
        base_archive,
        base_manifest,
        base_version,
        base_build,
    ) {
        (
            Some(base_path),
            Some(base_archive),
            Some(base_manifest),
            Some(base_version),
            Some(base_build),
        ) => {
            info!(
                version = %base_version,
                build = %base_build,
                "fetching base powder component keys"
            );
            let fetched_base_keys = key_provider
                .fetch(&request.product_type, &base_build)
                .await?;
            let base_identity =
                base_manifest.select_identity(&request.board_config, RestoreBehavior::Erase)?;
            let base_system_partition = ramdisk_system_partition(
                &base_archive,
                base_identity,
                &fetched_base_keys,
                &request.board_config,
            )
            .await?;
            let base_filename = base_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "base.ipsw".to_owned());
            let base_bundle = PowderBundle::resolve(
                &PowderBundleRequest::new(
                    BundleRole::Base,
                    request.product_type.clone(),
                    request.board_config.clone(),
                    base_filename,
                    base_version.clone(),
                    version.clone(),
                    latest_version,
                    base_system_partition,
                )
                .with_drav6(request.drav6)
                .with_base_build(base_build.clone()),
                &fetched_base_keys,
                Some(base_identity),
            )?;

            let exploit = base_bundle
                .ramdisk_exploit()
                .expect("base bundles always carry a RamdiskExploit");
            let exploit_id = exploit.resource_id();
            debug!(resource = exploit_id.as_str(), "fetching ramdisk exploit");
            let exploit = read_resource(&exploit_id, &request.cache_root).await?;
            let partition = match mode {
                // ios4powder installs the reboot4 binary as `partition`
                // (`ipsw_prepare_reboot4`); it is not a shell script.
                PowderMode::Ios4 => {
                    read_resource(
                        &crate::multipart::reboot4_resource(&request.product_type),
                        &request.cache_root,
                    )
                    .await?
                }
                _ => {
                    let ramdisk_h = uses_ramdisk_h(&request.product_type, base_version.as_str());
                    let id = partition_script_resource(ramdisk_h);
                    debug!(resource = id.as_str(), "fetching partition script");
                    let template = read_resource(&id, &request.cache_root).await?;
                    if ramdisk_h {
                        // The ramdiskH (iPhone5) script is used verbatim.
                        template
                    } else {
                        let template = String::from_utf8(template)
                            .map_err(|_| KitError::PowderInvalidPartitionScript)?;
                        render_partition_script(
                            &template,
                            base_version.as_str(),
                            &request.product_type,
                            request.drav6,
                        )
                        .into_bytes()
                    }
                }
            };
            base_keys = Some(fetched_base_keys);
            Some(PowderBasePlan {
                source: base_path.clone(),
                version: base_version,
                build: base_build,
                bundle: base_bundle,
                partition,
                exploit,
            })
        }
        _ => None,
    };

    // ios4powder appends the externally patched iBoot to the bin4 ramdisk
    // package for every device, so the sidecar is mandatory there even though
    // the payload plan only lists iBoot.tar for iPad1,1.
    if mode == PowderMode::Ios4 && request.iboot_sidecar.is_none() {
        return Err(KitError::PowderMissingIbootSidecar);
    }

    // Post-build steps upstream applies around the powdersn0w invocation: the
    // non-ramdiskH `patch_iboot --logo` re-patch of iBoot2
    // (restore.sh:5807-5817), the ios4powder tail (restore.sh:5680-5696), and
    // the `ipsw_bbreplace` latest-baseband swap (restore.sh:5820).
    let iboot2_logo_pass = match &base {
        Some(base) if mode == PowderMode::TwoBundle => {
            let target_major = version
                .as_str()
                .split('.')
                .next()
                .and_then(|major| major.parse::<u32>().ok())
                .unwrap_or(0);
            needs_iboot2_logo_pass(&request.product_type, base.version.as_str(), target_major)
        }
        _ => false,
    };
    let ios4_tail = match (mode, &base, &base_keys) {
        (PowderMode::Ios4, Some(base), Some(base_keys)) => Some(resolve_ios4_tail(
            &request, &manifest, &keys, base, base_keys,
        )?),
        _ => None,
    };
    let baseband = match &request.baseband_replacement {
        Some((name, bytes)) if mode == PowderMode::TwoBundle && baseband_applies => {
            let rewrite =
                crate::baseband::baseband_rewrite(&request.product_type).ok_or_else(|| {
                    KitError::PowderUnsupportedBasebandReplace(request.product_type.to_string())
                })?;
            info!(baseband = name, "planning latest-baseband swap");
            Some(BasebandReplace {
                file: format!("Firmware/{name}"),
                data: bytes.clone(),
                rewrite,
            })
        }
        Some(_) => {
            debug!("latest-baseband swap not applicable; keeping the target baseband");
            None
        }
        None => None,
    };
    // The scab reseal runs when the target bundle declares an APTicket
    // replacement (4.x targets); upstream requires `-apticket` there.
    let needs_apticket = bundle
        .firmware_replacements()
        .iter()
        .any(|entry| entry.component() == "APTicket");
    let apticket = if needs_apticket {
        let der = request.apticket.ok_or(KitError::PowderMissingApTicket)?;
        Some(der)
    } else {
        None
    };
    let scab_template = if needs_apticket {
        Some(read_resource(&ResourceId::new("ios4-scab-template"), &request.cache_root).await?)
    } else {
        None
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

    // Two-bundle target bundles declare package payloads (main.c's
    // FilesystemPackage/RamdiskPackage). The bootstrap (freeze.tar) is
    // fetched only under a FilesystemJailbreak config, like main.c's
    // `bootstrap && jailbreak` gate; the filesystem package (ios9.tar) is
    // fetched whenever declared; the ramdisk package is bin.tar, replaced by
    // bin4.tar with the patched iBoot appended for ios4powder
    // (`rm src/bin.tar; mv src/bin4.tar src/bin.tar; tar -rvf src/bin.tar iBoot`).
    let bootstrap = match bundle.filesystem_package() {
        Some(_) if config.filesystem_jailbreak() => Some(
            read_tar_resource(
                &ResourceId::new("jailbreak-bootstrap-freeze"),
                &request.cache_root,
            )
            .await?,
        ),
        _ => None,
    };
    let filesystem_package = match bundle.filesystem_package().and_then(|p| p.package()) {
        Some(_) => Some(
            read_tar_resource(&ResourceId::new("powder-ios9-package"), &request.cache_root).await?,
        ),
        None => None,
    };
    let ramdisk_package = match bundle.ramdisk_package() {
        Some(_) => {
            let package = match mode {
                PowderMode::Ios4 => {
                    let bin4 = read_tar_resource(
                        &ResourceId::new("ios4-restore-bin-tar"),
                        &request.cache_root,
                    )
                    .await?;
                    let (_, iboot) = request
                        .iboot_sidecar
                        .as_ref()
                        .expect("ios4powder requires the iBoot sidecar");
                    let mut tar = UstarBuilder::appending(&bin4);
                    tar.add_file("iBoot", iboot)
                        .expect("constant ustar entry name");
                    tar.finish()
                }
                _ => {
                    read_tar_resource(
                        &ResourceId::new("legacy-restore-bin-tar"),
                        &request.cache_root,
                    )
                    .await?
                }
            };
            Some(package)
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
        bootstrap.as_ref().map(|bytes| bytes.len() as u64),
        filesystem_package.as_ref().map(|bytes| bytes.len() as u64),
    );

    info!(
        product = %request.product_type,
        version = %version,
        mode = ?mode,
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
        mode,
        bundle,
        config,
        tars,
        punchd: payload.punchd(),
        daibutsu,
        base,
        apticket,
        scab_template,
        bootstrap,
        filesystem_package,
        ramdisk_package,
        root_size_mb,
        update_baseband: request.update_baseband,
        ramdisk_grow_blocks: request.ramdisk_grow_blocks,
        iboot2_logo_pass,
        baseband,
        ios4_tail,
    })
}

/// The `ipsw_bbreplace` early-return conditions (restore.sh:4350-4353):
/// devices without a baseband, targets at the latest version, disabled
/// baseband updates, and A4-and-older devices keep the target baseband.
fn baseband_replace_applies(
    has_baseband: bool,
    soc: Soc,
    target: &IosVersion,
    latest: &IosVersion,
    disabled: bool,
) -> bool {
    has_baseband && !matches!(soc, Soc::A4) && target != latest && !disabled
}

/// Gate of the post-build `patch_iboot --logo` re-patch of iBoot2
/// (restore.sh:5807-5817): two-bundle builds for non-ramdiskH devices — not
/// iPhone5,* except the iPhone5,3/5,4 7.0-base case (`ipsw_powder_5c70`), and
/// never iPad1,1 — targeting iOS 5.x/6.x.
fn needs_iboot2_logo_pass(
    product_type: &ProductType,
    base_version: &str,
    target_major: u32,
) -> bool {
    !uses_ramdisk_h(product_type, base_version)
        && product_type.as_str() != "iPad1,1"
        && !matches!(target_major, 7..=9)
}

/// Resolve the ios4powder tail (restore.sh:5680-5696). Cross-device special
/// flows (`device_type_special`, e.g. iPad1,1 building from an iPad2,1 target
/// IPSW) take the pristine dfu images from the base IPSW with the base build
/// keys, like `ipsw_prepare_ios4patches` (restore.sh:5536-5539).
fn resolve_ios4_tail(
    request: &PowderPrepareRequest,
    manifest: &legacy_ios_firmware::BuildManifest,
    keys: &FirmwareKeySet,
    base: &PowderBasePlan,
    base_keys: &FirmwareKeySet,
) -> Result<Ios4Tail, KitError> {
    let special = !manifest
        .supported_product_types()
        .contains(&request.product_type);
    let (dfu_source, dfu_keys) = if special {
        (base.source.clone(), base_keys)
    } else {
        (request.source.clone(), keys)
    };
    Ok(Ios4Tail {
        dfu_source,
        dfu_images: [dfu_image(dfu_keys, "iBSS")?, dfu_image(dfu_keys, "iBEC")?],
        iboot2: if request.product_type.as_str() == "iPad1,1" {
            None
        } else {
            let (_, bytes) = request
                .iboot_sidecar
                .as_ref()
                .expect("ios4powder requires the iBoot sidecar");
            Some(bytes.clone())
        },
    })
}

/// Resolve one dfu image of `ipsw_prepare_ios4patches`: path, IV, and key.
fn dfu_image(keys: &FirmwareKeySet, image: &'static str) -> Result<Ios4DfuImage, KitError> {
    let key = keys
        .key(image)
        .ok_or(KitError::PowderMissingComponent(image))?;
    let missing = || {
        KitError::PowderBundle(legacy_ios_firmware::PowderBundleError::MissingKeyMaterial(
            image.to_owned(),
        ))
    };
    Ok(Ios4DfuImage {
        file: format!("Firmware/dfu/{}", key.filename()),
        iv: key.iv().copied().ok_or_else(missing)?,
        key: key.key().map(<[u8]>::to_vec).ok_or_else(missing)?,
    })
}

/// Fetch a catalog resource and gunzip it when it is gzip-compressed, like
/// the `gzip -d` calls of `ipsw_prepare_32bit` for the .tar.gz payloads.
async fn read_tar_resource(
    id: &ResourceId,
    cache_root: &std::path::Path,
) -> Result<Vec<u8>, KitError> {
    let bytes = read_resource(id, cache_root).await?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        crate::bootstrap::gunzip(&bytes)
    } else {
        Ok(bytes)
    }
}

/// Fetch a catalog resource verbatim.
async fn read_resource(id: &ResourceId, cache_root: &std::path::Path) -> Result<Vec<u8>, KitError> {
    let path = crate::firmware::fetch_resource(id, cache_root.to_owned()).await?;
    Ok(tokio::fs::read(path).await?)
}

/// `ipsw_prepare_bundle` derives RootFilesystemSize from the restore
/// ramdisk's options plist: decrypt the ramdisk and read the per-board plist
/// first, falling back to the plain one, like the shell flow.
async fn ramdisk_system_partition(
    archive: &FirmwareArchive,
    identity: &BuildIdentity,
    keys: &FirmwareKeySet,
    board: &BoardConfig,
) -> Result<u64, KitError> {
    let ramdisk_path = identity.component_path("RestoreRamDisk")?.to_owned();
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
                .map_err(|_| KitError::PowderMissingRamdiskOptions),
        }
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    Ok(system_partition_size(&options_plist)?)
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
    let stages = (plan.bundle.firmware().len()
        + 2
        + plan
            .base
            .as_ref()
            .map_or(0, |base| base.bundle.firmware_paths().len())) as u64;
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

    // main.c's useBaseFW block runs before the Firmware dict loop: APTicket
    // scab reseal, the all_flash manifest rewrite, and the FirmwarePath →
    // FirmwareReplace NOR copies with their TYPE rewrites and the NewiBoot
    // patch.
    if let Some(base) = &plan.base {
        completed = apply_base_stage(plan, base, &archive, &mut replacements, completed)?;
        progress(emitter, completed);
        // `ipsw_prepare_battery_images` runs on the built IPSW after the
        // powdersn0w invocation; its manifest appends land on the all_flash
        // manifest the base stage just produced.
        apply_battery_images(plan, base, &archive, &mut replacements)?;
    }

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

    // The ios4powder tail (restore.sh:5680-5696) overrides the Firmware-loop
    // dfu iBSS with iBoot32Patcher builds of the pristine images and rewrites
    // the base stage's NewAppleLogo/NewiBoot, so it runs after both.
    if let Some(tail) = &plan.ios4_tail {
        apply_ios4_tail(plan, tail, &mut replacements)?;
    }

    // `ipsw_bbreplace` rewrites the BuildManifest of the built IPSW, after
    // the manifest path rewrites above.
    if let Some(baseband) = &plan.baseband {
        let manifest = match replacements
            .iter()
            .find(|(name, _)| name == "BuildManifest.plist")
        {
            Some((_, data)) => data.clone(),
            None => archive.read_entry("BuildManifest.plist")?,
        };
        info!(baseband = %baseband.file, "swapping in the latest baseband");
        replacements.push((
            "BuildManifest.plist".to_owned(),
            crate::baseband::rewrite_baseband_manifest(
                &manifest,
                &baseband.rewrite,
                &baseband.file,
            )?,
        ));
        replacements.push((baseband.file.clone(), baseband.data.clone()));
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

/// The useBaseFW block of main.c: reseal the APTicket into the scab
/// template, write the all_flash manifest with the bundle's additions
/// appended, and copy the base IPSW's NOR images over the target bundle's
/// FirmwareReplace paths — with the IMG3 TYPE byte rewrites for the target's
/// own logo/recovery/iBoot and the NewiBoot patch (patched target iBoot,
/// stored decrypted under the `ibob` tag). Returns the updated stage count.
fn apply_base_stage(
    plan: &PowderPreparePlan,
    base: &PowderBasePlan,
    archive: &FirmwareArchive,
    replacements: &mut Vec<(String, Vec<u8>)>,
    mut completed: u64,
) -> Result<u64, KitError> {
    let base_archive = FirmwareArchive::open(&base.source)?;
    let replacement = |component: &'static str| {
        plan.bundle
            .firmware_replacements()
            .iter()
            .find(|entry| entry.component() == component)
            .ok_or(KitError::PowderMissingComponent(component))
    };

    // APTicket: reseal the `-apticket` DER into the scab template IMG3, like
    // main.c's duplicateAbstractFile2 payload swap (and multipart's reseal,
    // which uses the same primitive successfully; xpwn's own ticket path is
    // marked "buggy" upstream).
    if let Ok(entry) = replacement("APTicket") {
        let template = plan
            .scab_template
            .as_deref()
            .expect("an APTicket replacement implies a fetched scab template");
        let der = plan
            .apticket
            .as_deref()
            .expect("an APTicket replacement implies a validated ticket");
        replacements.push((
            entry.file().to_owned(),
            replace_image_payload(template, der, None)?,
        ));
    }

    // manifest: the bundle manifest is the target IPSW's own all_flash
    // manifest with the renamed images appended by `ipsw_prepare_paths`.
    let manifest_entry = replacement("manifest")?;
    let original = archive.read_entry(manifest_entry.file())?;
    replacements.push((
        manifest_entry.file().to_owned(),
        all_flash_manifest(&original, plan.bundle.manifest_additions()),
    ));

    // FirmwarePath loop: base NOR images over the target paths.
    for base_path in base.bundle.firmware_paths() {
        let data = base_archive.read_entry(base_path.file())?;
        match base_path.component() {
            "AppleLogo" => {
                replacements.push((replacement("AppleLogo")?.file().to_owned(), data));
                // NewAppleLogo: the target's own logo with TYPE logo→logb.
                let new_logo = replacement("NewAppleLogo")?;
                let mut logo = archive.read_entry(new_logo.file())?;
                rewrite_img3_type_base(&mut logo, "NewAppleLogo")?;
                replacements.push((new_logo.file().to_owned(), logo));
            }
            "RecoveryMode" => {
                replacements.push((replacement("RecoveryMode")?.file().to_owned(), data));
                // NewRecoveryMode: the target's own recoverym with TYPE
                // recm→recb.
                let new_recovery = replacement("NewRecoveryMode")?;
                let mut recovery = archive.read_entry(new_recovery.file())?;
                rewrite_img3_type_base(&mut recovery, "NewRecoveryMode")?;
                replacements.push((new_recovery.file().to_owned(), recovery));
            }
            "iBoot" => {
                let ibot = replacement("iBoot")?;
                if let Ok(new_iboot) = replacement("NewiBoot") {
                    // NewiBoot (absent on iPad1,1): the target's own iBoot
                    // with TYPE ibot→ibob, patched with the config-gated
                    // boot-args and stored decrypted (main.c's doiBootPatch
                    // followed by doDecrypt).
                    let mut container = archive.read_entry(ibot.file())?;
                    rewrite_img3_type_base(&mut container, "NewiBoot")?;
                    let encryption = match (new_iboot.key(), new_iboot.iv()) {
                        (Some(key), Some(iv)) => Some((key, iv.as_slice())),
                        _ => None,
                    };
                    let patched = transform_payload(&container, encryption, |raw| {
                        Ok(patch_powder_iboot(
                            raw,
                            &PowderIBootPatchOptions {
                                boot_args: base_iboot_boot_args(&plan.config),
                                debug: plan.config.filesystem_jailbreak(),
                            },
                        )?)
                    })?;
                    let mut container = decrypt_rewrap(&patched, encryption)?;
                    if plan.iboot2_logo_pass {
                        container = patch_iboot2_logo(&container, encryption)?;
                    }
                    replacements.push((new_iboot.file().to_owned(), container));
                }
                // The base IPSW's original iBoot takes the target iBoot path.
                replacements.push((ibot.file().to_owned(), data));
            }
            // Batteries, BatteryPlugin, LLB: plain copies.
            component => {
                let entry = plan
                    .bundle
                    .firmware_replacements()
                    .iter()
                    .find(|entry| entry.component() == component)
                    .ok_or(KitError::PowderMissingComponent("NOR image"))?;
                replacements.push((entry.file().to_owned(), data));
            }
        }
        completed += 1;
    }
    Ok(completed)
}

/// main.c's TYPE tag rewrite for base-mode NOR images: the IMG3 identify
/// field and the TYPE tag value are stored byte-reversed, so flipping the
/// first stored byte of each to `b` turns `logo`/`recm`/`ibot` into
/// `logb`/`recb`/`ibob`.
fn rewrite_img3_type_base(data: &mut [u8], component: &'static str) -> Result<(), KitError> {
    if data.len() <= 0x20 {
        return Err(KitError::PowderTruncatedNorImage(component));
    }
    data[0x10] = b'b';
    data[0x20] = b'b';
    Ok(())
}

/// The non-ramdiskH `patch_iboot --logo` re-patch of the powdersn0w-produced
/// iBoot2 (restore.sh:5807-5817): the decrypted payload is patched with
/// iBoot32Patcher's `--logo` only — no `--rsa`, the powdersn0w iBoot patcher
/// already removed the RSA check — and re-encrypted with the iBoot keys.
/// Like the xpwntool rewrap, the payload is not LZSS-recompressed.
fn patch_iboot2_logo(
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, KitError> {
    let payload = extract_image_payload(container, None)?;
    let raw = if is_lzss_compressed(&payload) {
        decompress_lzss(&payload)?
    } else {
        payload
    };
    let patched = patch_iboot32_with_options(
        &raw,
        &Iboot32PatchOptions {
            logo: true,
            skip_rsa: true,
            ..Iboot32PatchOptions::default()
        },
    )?;
    Ok(replace_image_payload(container, &patched, encryption)?)
}

/// Battery components of `ipsw_prepare_battery_images`, in upstream order.
/// These are BuildManifest component names (`BatteryCharging` is the
/// GlyphCharging image, absent on iOS 7+ bases).
const BATTERY_COMPONENTS: [&str; 7] = [
    "BatteryCharging0",
    "BatteryCharging1",
    "BatteryFull",
    "BatteryLow0",
    "BatteryLow1",
    "BatteryCharging",
    "BatteryPlugin",
];

/// Per-component decision of `ipsw_prepare_battery_images`
/// (restore.sh:5573-5599).
enum BatteryImageAction {
    /// The base manifest lacks the component (e.g. BatteryCharging on iOS
    /// 7+): leave the existing image unchanged.
    Skip,
    /// Copy the base image onto the target-named path.
    Copy { base: String, target: String },
    /// Copy the base image onto the base-named path and append that name to
    /// the all_flash manifest (the target manifest lacks the component).
    CopyAndAppend { base: String },
}

fn battery_image_action(
    base_name: Option<String>,
    target_name: Option<String>,
) -> BatteryImageAction {
    let Some(base) = base_name else {
        return BatteryImageAction::Skip;
    };
    match target_name {
        Some(target) => BatteryImageAction::Copy { base, target },
        None => BatteryImageAction::CopyAndAppend { base },
    }
}

/// Basename of a BuildManifest component path, mirroring the PlistBuddy +
/// basename lookup of `ipsw_prepare_battery_images`; absent or empty paths
/// behave like upstream's empty lookup result.
fn manifest_component_name(identity: Option<&BuildIdentity>, component: &str) -> Option<String> {
    identity?
        .component_path(component)
        .ok()?
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// `ipsw_prepare_battery_images` (restore.sh:5560-5602), applied to every
/// `-base` build: copy the base IPSW's battery images over the target paths
/// of the built IPSW, appending the base file name to the all_flash manifest
/// for components the target BuildManifest lacks. Upstream reads
/// BuildIdentities:0 of both manifests via PlistBuddy; do the same (the
/// battery image file names are SoC-named and shared across boards).
fn apply_battery_images(
    plan: &PowderPreparePlan,
    base: &PowderBasePlan,
    archive: &FirmwareArchive,
    replacements: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), KitError> {
    let manifest_entry = plan
        .bundle
        .firmware_replacements()
        .iter()
        .find(|entry| entry.component() == "manifest")
        .ok_or(KitError::PowderMissingComponent("manifest"))?;
    let all_flash = manifest_entry
        .file()
        .strip_suffix("/manifest")
        .ok_or(KitError::PowderMissingComponent("all_flash manifest"))?
        .to_owned();
    let base_archive = FirmwareArchive::open(base.source())?;
    let base_identity = base_archive.build_manifest()?.identities().first().cloned();
    let target_identity = archive.build_manifest()?.identities().first().cloned();

    let mut appended: Vec<String> = Vec::new();
    for component in BATTERY_COMPONENTS {
        let action = battery_image_action(
            manifest_component_name(base_identity.as_ref(), component),
            manifest_component_name(target_identity.as_ref(), component),
        );
        let (base_name, target_name) = match action {
            BatteryImageAction::Skip => {
                debug!(
                    component,
                    "no base battery image; leaving the existing image unchanged"
                );
                continue;
            }
            BatteryImageAction::Copy { base, target } => (base, target),
            BatteryImageAction::CopyAndAppend { base } => {
                debug!(
                    component,
                    "no target battery image; adding it to the manifest"
                );
                // Upstream appends to the manifest before the extraction
                // check, so a failed extraction still leaves the entry.
                appended.push(base.clone());
                (base.clone(), base)
            }
        };
        match base_archive.read_entry(&format!("{all_flash}/{base_name}")) {
            Ok(data) if !data.is_empty() => {
                replacements.push((format!("{all_flash}/{target_name}"), data));
            }
            _ => {
                warn!(
                    component,
                    "failed to extract the base battery image; leaving the existing image unchanged"
                );
            }
        }
    }
    if !appended.is_empty() {
        let (_, manifest) = replacements
            .iter_mut()
            .find(|(name, _)| name == manifest_entry.file())
            .ok_or(KitError::PowderMissingComponent("all_flash manifest"))?;
        *manifest = all_flash_manifest(manifest, &appended);
    }
    Ok(())
}

/// Boot-args of the `ipsw_prepare_ios4patches` iBSS/iBEC patch
/// (restore.sh:5555); `--ticket` never applies because ios4powder targets
/// are 4.3.x (`target_vers_maj >= 5` is never true there).
const IOS4_DFU_BOOT_ARGS: &str = "rd=md0 -v amfi=0xff cs_enforcement_disable=1 pio-error=0";

/// The ios4powder tail of `ipsw_prepare_ios4powder` (restore.sh:5680-5696):
/// `ipsw_prepare_ios4patches` replaces the dfu iBSS/iBEC with iBoot32Patcher
/// builds of the pristine images (superseding the powder patcher's iBSS patch
/// of the Firmware loop, which ios4patches overwrites upstream too), the
/// target-name AppleLogo gets its iOS 4 `4g` tag bytes, and the externally
/// patched target iBoot replaces the NewiBoot as the all_flash iBoot2.
fn apply_ios4_tail(
    plan: &PowderPreparePlan,
    tail: &Ios4Tail,
    replacements: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), KitError> {
    let archive = FirmwareArchive::open(&tail.dfu_source)?;
    for image in &tail.dfu_images {
        let container = archive.read_entry(&image.file)?;
        let payload = extract_image_payload(&container, Some((&image.key, &image.iv)))?;
        let patched = legacy_ios_image::patch_iboot32(&payload, Some(IOS4_DFU_BOOT_ARGS), None)?;
        // xpwntool rewraps against the original container without keys.
        replacements.push((
            image.file.clone(),
            replace_image_payload(&container, &patched, None)?,
        ));
    }

    let replacement = |component: &'static str| {
        plan.bundle
            .firmware_replacements()
            .iter()
            .find(|entry| entry.component() == component)
            .ok_or(KitError::PowderMissingComponent(component))
    };

    // Patch AppleLogo (restore.sh:5684-5690): the same two-byte `4g` mangle
    // at 0x10/0x20 that `crate::multipart` applies to the part 1 logo.
    let new_logo = replacement("NewAppleLogo")?;
    let (_, logo) = replacements
        .iter_mut()
        .find(|(name, _)| name == new_logo.file())
        .ok_or(KitError::PowderMissingComponent("NewAppleLogo"))?;
    if logo.len() <= 0x20 {
        return Err(KitError::PowderTruncatedNorImage("NewAppleLogo"));
    }
    logo[0x10..0x12].copy_from_slice(b"4g");
    logo[0x20..0x22].copy_from_slice(b"4g");

    // Add the iboot32-patched target iBoot as iBoot2 (restore.sh:5692-5696);
    // the bundle manifest already lists the iBoot2 name.
    if let Some(iboot2) = &tail.iboot2 {
        let new_iboot = replacement("NewiBoot")?;
        let (_, entry) = replacements
            .iter_mut()
            .find(|(name, _)| name == new_iboot.file())
            .ok_or(KitError::PowderMissingComponent("NewiBoot"))?;
        *entry = iboot2.clone();
    }
    Ok(())
}

/// Boot-args of the NewiBoot patch, mirroring main.c's bootargs assembly:
/// CSBYPASS_BOOTARGS only under the FilesystemJailbreak config, with the
/// config's bootArgsString appended (or used alone) when bootArgsInjection
/// is set; no boot-args otherwise. Unlike the Firmware-loop iBSS/iBEC patch,
/// CSBYPASS is not unconditional here.
fn base_iboot_boot_args(config: &PowderConfig) -> Option<String> {
    let mut args = config
        .filesystem_jailbreak()
        .then(|| CSBYPASS_BOOTARGS.to_owned());
    if config.boot_args_injection() {
        match &mut args {
            Some(args) => {
                args.push(' ');
                args.push_str(config.boot_args());
            }
            None => args = Some(config.boot_args().to_owned()),
        }
    }
    args
}

/// The bundle manifest main.c writes over all_flash/manifest: the target
/// IPSW's own manifest text with the bundle's additions appended one per
/// line, mirroring the `echo >> $FirmwareBundle/manifest` calls of
/// `ipsw_prepare_paths`.
fn all_flash_manifest(original: &[u8], additions: &[String]) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(original).into_owned();
    for addition in additions {
        text.push_str(addition);
        text.push('\n');
    }
    text.into_bytes()
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
        // Two-bundle jailbroken 6/8/9 targets land here: the rw fstab wins
        // over the payload tar merge, then the bundle-declared
        // FilesystemPackage bootstrap and package bytes are untarred (main.c
        // untars both inside the jailbreak block, bootstrap first).
        if hfs.stat(FSTAB_PATH).is_ok() {
            hfs.remove_file(FSTAB_PATH)?;
        }
        hfs.add_file(FSTAB_PATH, FSTAB_DATA)?;
        hfs.chmod(FSTAB_PATH, 0o644)?;
        hfs.chown(FSTAB_PATH, 0, 0)?;
        if let Some(bootstrap) = &plan.bootstrap {
            debug!(bytes = bootstrap.len(), "installing bootstrap package");
            if !bootstrap.is_empty() {
                hfs.untar(bootstrap)?;
            }
        }
        if let Some(package) = &plan.filesystem_package {
            debug!(bytes = package.len(), "installing filesystem package");
            if !package.is_empty() {
                hfs.untar(package)?;
            }
        }
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
    // `if(rdsize)`); single-IPSW bundles declare no RamdiskPackage.
    let package_size = plan
        .ramdisk_package
        .as_ref()
        .map(|bytes| bytes.len() as u64);
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

    // Two-bundle mode: untar the bundle-declared RamdiskPackage bytes
    // (bin.tar, or bin4.tar with the patched iBoot appended for ios4powder),
    // then install the base bundle's RamdiskExploit hook: move /sbin/reboot
    // aside, install the partition script (reboot4 binary for ios4powder) as
    // /sbin/reboot, and the per-hw/per-build exploit as /exploit, in main.c's
    // order.
    if let Some(package) = &plan.ramdisk_package {
        debug!(bytes = package.len(), "installing ramdisk package");
        if !package.is_empty() {
            hfs.untar(package)?;
        }
    }
    if let Some(base) = &plan.base {
        hfs.move_entry("/sbin/reboot", "/sbin/reboot_")?;
        hfs.add_file("/sbin/reboot", &base.partition)?;
        hfs.add_file("/exploit", &base.exploit)?;
        hfs.chmod("/sbin/reboot", 0o755)?;
        hfs.chown("/sbin/reboot", 0, 0)?;
    }
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

    #[test]
    fn img3_type_rewrite_flips_byte_reversed_fourcc() {
        // IMG3 stores the identify field and TYPE tag value byte-reversed:
        // "logo" appears as "ogol" at 0x10 and 0x20; flipping the first stored
        // byte to 'b' yields "logb".
        let mut image = vec![0u8; 0x30];
        image[0x10..0x14].copy_from_slice(b"ogol");
        image[0x20..0x24].copy_from_slice(b"ogol");
        rewrite_img3_type_base(&mut image, "NewAppleLogo").unwrap();
        assert_eq!(&image[0x10..0x14], b"bgol");
        assert_eq!(&image[0x20..0x24], b"bgol");
        assert!(rewrite_img3_type_base(&mut [0u8; 0x20], "NewAppleLogo").is_err());
    }

    #[test]
    fn scab_reseal_swaps_payload_like_multipart() {
        // The same replace_image_payload primitive multipart uses for its
        // working ticket reseal: the scab template keeps its header/TYPE tag,
        // the DATA payload becomes the APTicket DER.
        use legacy_ios_image::{Img3, Img3Element, Img3Tag};
        let template = Img3::new(
            0x7363_6162,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"scab".to_vec()),
                Img3Element::new(Img3Tag::DATA, b"placeholder".to_vec()),
            ],
        )
        .to_bytes();
        let der = [0x30, 0x82, 0x01, 0x00, 0xaa];
        let resealed = replace_image_payload(&template, &der, None).unwrap();
        assert_eq!(extract_image_payload(&resealed, None).unwrap(), der);
        // Magic and the identify field are untouched (the size fields scale
        // with the payload).
        assert_eq!(&resealed[..4], &template[..4]);
        assert_eq!(&resealed[0x10..0x14], &template[0x10..0x14]);
        assert_eq!(
            Img3::parse(&resealed).unwrap().elements()[0].data(),
            b"scab"
        );
    }

    #[test]
    fn battery_image_action_matches_upstream_branches() {
        // Base lacks the component (BatteryCharging on iOS 7+): unchanged.
        assert!(matches!(
            battery_image_action(None, Some("batterycharging.s5l8930x.img3".to_owned())),
            BatteryImageAction::Skip
        ));
        assert!(matches!(
            battery_image_action(None, None),
            BatteryImageAction::Skip
        ));
        // Both manifests carry the component: copy base onto the target name.
        match battery_image_action(
            Some("batteryfull.s5l8940x.img3".to_owned()),
            Some("batteryfull.s5l8930x.img3".to_owned()),
        ) {
            BatteryImageAction::Copy { base, target } => {
                assert_eq!(base, "batteryfull.s5l8940x.img3");
                assert_eq!(target, "batteryfull.s5l8930x.img3");
            }
            _ => panic!("expected a plain copy"),
        }
        // Target manifest lacks the component: copy under the base name and
        // append that name to the manifest.
        match battery_image_action(Some("batterycharging.s5l8940x.img3".to_owned()), None) {
            BatteryImageAction::CopyAndAppend { base } => {
                assert_eq!(base, "batterycharging.s5l8940x.img3");
            }
            _ => panic!("expected a copy with manifest append"),
        }
    }

    #[test]
    fn manifest_component_name_takes_the_basename() {
        // A manifest path resolves to its basename; missing components and
        // empty paths behave like upstream's empty PlistBuddy output.
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>7.1.2</string>
<key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n90ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>
    <key>BatteryFull</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/all_flash.n90ap.production/batteryfull.s5l8930x.img3</string></dict></dict>
</dict>
</dict></array></dict></plist>"#;
        let manifest =
            legacy_ios_firmware::BuildManifest::from_reader(Cursor::new(manifest)).unwrap();
        let identity = manifest.identities().first();
        assert_eq!(
            manifest_component_name(identity, "BatteryFull").as_deref(),
            Some("batteryfull.s5l8930x.img3")
        );
        assert_eq!(manifest_component_name(identity, "BatteryCharging"), None);
        assert_eq!(manifest_component_name(None, "BatteryFull"), None);
    }

    #[test]
    fn iboot2_logo_pass_gate_matches_upstream() {
        // ramdiskH devices (iPhone5,* on a non-7.0 base) skip the pass.
        assert!(!needs_iboot2_logo_pass(
            &ProductType::from("iPhone5,1"),
            "8.4.1",
            6
        ));
        // The iPhone5,3/5,4 7.0-base exception (`ipsw_powder_5c70`) runs it.
        assert!(needs_iboot2_logo_pass(
            &ProductType::from("iPhone5,3"),
            "7.0.4",
            6
        ));
        // iPad1,1 never runs it.
        assert!(!needs_iboot2_logo_pass(
            &ProductType::from("iPad1,1"),
            "5.1.1",
            5
        ));
        // Non-ramdiskH devices on 5.x/6.x targets run it.
        assert!(needs_iboot2_logo_pass(
            &ProductType::from("iPhone4,1"),
            "8.4.1",
            5
        ));
        assert!(needs_iboot2_logo_pass(
            &ProductType::from("iPad3,1"),
            "9.3.5",
            6
        ));
        // 7.x/8.x/9.x targets skip it (upstream's `[789]* ) :;;`).
        for major in [7, 8, 9] {
            assert!(!needs_iboot2_logo_pass(
                &ProductType::from("iPhone4,1"),
                "8.4.1",
                major
            ));
        }
    }

    #[test]
    fn baseband_replace_gate_matches_upstream_early_return() {
        let target = IosVersion::from("6.1.3");
        let latest = IosVersion::from("8.4.1");
        assert!(baseband_replace_applies(
            true,
            Soc::A5,
            &target,
            &latest,
            false
        ));
        // No baseband, A4, target == latest, or disabled bbupdate: keep the
        // target baseband.
        assert!(!baseband_replace_applies(
            false,
            Soc::A5,
            &target,
            &latest,
            false
        ));
        assert!(!baseband_replace_applies(
            true,
            Soc::A4,
            &target,
            &latest,
            false
        ));
        assert!(!baseband_replace_applies(
            true,
            Soc::A5,
            &latest,
            &latest,
            false
        ));
        assert!(!baseband_replace_applies(
            true,
            Soc::A5,
            &target,
            &latest,
            true
        ));
        assert!(baseband_replace_applies(
            true,
            Soc::A6x,
            &target,
            &latest,
            false
        ));
    }

    #[test]
    fn all_flash_manifest_appends_additions_in_order() {
        let output = all_flash_manifest(
            b"applelogo.s5l8930x.img3\nLLB.n90ap.RELEASE.img3\n",
            &[
                "applelogo7.s5l8930x.img3".to_owned(),
                "recoverymode7.s5l8930x.img3".to_owned(),
                "iBoot2.n90ap.RELEASE.img3".to_owned(),
            ],
        );
        assert_eq!(
            output,
            b"applelogo.s5l8930x.img3\nLLB.n90ap.RELEASE.img3\napplelogo7.s5l8930x.img3\nrecoverymode7.s5l8930x.img3\niBoot2.n90ap.RELEASE.img3\n"
        );
    }

    #[test]
    fn base_iboot_args_follow_the_config_gates() {
        let version = IosVersion::from("8.4.1");
        // FilesystemJailbreak (jailbroken 6/8/9 target): CSBYPASS leads.
        let jailbroken = PowderConfig::resolve(BundleRole::Target, true, &version, false, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            base_iboot_boot_args(&jailbroken),
            Some(CSBYPASS_BOOTARGS.to_owned())
        );
        let verbose = PowderConfig::resolve(BundleRole::Target, true, &version, true, None)
            .unwrap()
            .unwrap();
        assert_eq!(
            base_iboot_boot_args(&verbose),
            Some(format!("{CSBYPASS_BOOTARGS} pio-error=0 -v"))
        );
        // No jailbreak, bootArgsInjection set: the config string alone.
        let custom =
            PowderConfig::resolve(BundleRole::Target, false, &version, false, Some("serial=1"))
                .unwrap()
                .unwrap();
        assert_eq!(
            base_iboot_boot_args(&custom),
            Some("pio-error=0 debug=0x2014e serial=3 serial=1".to_owned())
        );
        // Plain config (the ios4powder forced `false true`): no boot-args.
        let plain = PowderConfig::resolve(
            BundleRole::Target,
            true,
            &IosVersion::from("4.3.3"),
            false,
            None,
        )
        .unwrap()
        .unwrap();
        assert!(!plain.filesystem_jailbreak());
        assert_eq!(base_iboot_boot_args(&plain), None);
    }
}
