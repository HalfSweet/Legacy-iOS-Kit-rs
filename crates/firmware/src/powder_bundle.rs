//! Typed model of the powdersn0w runtime firmware bundle and config,
//! replacing the `Info.plist`/`config.plist` documents that upstream's
//! `ipsw_prepare_bundle`/`ipsw_prepare_config` (restore.sh) generate for the
//! xpwn-based `powdersn0w` tool. Also ports the payload-tar selection matrix
//! of `ipsw_prepare_32bit`/`ipsw_prepare_powder`/`ipsw_prepare_ios4powder`
//! and the small payload generators (`ipsw_prepare_systemversion`,
//! `ipsw_prepare_rebootsh`, `ipsw_prepare_partition_script`,
//! `ipsw_prepare_powder_exploit`).
//!
//! Whole-IPSW SHA-1 matching is intentionally not modeled: the bundle is
//! constructed directly for a known IPSW instead of being discovered by
//! hashing, so the `SHA1` key of the plist format has no equivalent here.

use legacy_ios_assets::ResourceId;
use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use thiserror::Error;
use tracing::debug;

use crate::manifest::BuildIdentity;
use crate::ustar::UstarBuilder;
use crate::{FirmwareKey, FirmwareKeySet};

/// Upstream's `device_bootargs_default`.
pub const DEFAULT_BOOT_ARGS: &str = "pio-error=0 debug=0x2014e serial=3";
/// Boot-args injected for verbose boots, mirroring `--ipsw-verbose`.
pub const VERBOSE_BOOT_ARGS: &str = "pio-error=0 -v";

const ALL_FLASH_PREFIX: &str = "Firmware/all_flash";

/// Which bundle of a powdersn0w build this is, mirroring the argument of
/// upstream's `ipsw_prepare_bundle`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleRole {
    /// Single-IPSW builds driven by `ipsw_prepare_32bit` (upstream passes no
    /// argument, or the `daibutsu` marker).
    Single,
    /// The target bundle of a two-bundle build (`ipsw_prepare_bundle target`).
    Target,
    /// The base bundle of a two-bundle build (`ipsw_prepare_bundle base`).
    Base,
}

/// Component names used as keys of the bundle's `Firmware` dict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareComponentKind {
    Ibss,
    Ibec,
    RestoreDeviceTree,
    RestoreKernelCache,
    KernelCache,
    RestoreRamdisk,
}

impl FirmwareComponentKind {
    /// Key name in the bundle's `Firmware` dict (upstream plist spelling).
    pub const fn plist_name(self) -> &'static str {
        match self {
            Self::Ibss => "iBSS",
            Self::Ibec => "iBEC",
            Self::RestoreDeviceTree => "RestoreDeviceTree",
            Self::RestoreKernelCache => "RestoreKernelCache",
            Self::KernelCache => "KernelCache",
            Self::RestoreRamdisk => "Restore Ramdisk",
        }
    }

    /// Image name in a [`FirmwareKeySet`], mirroring upstream's `getcomp`.
    const fn key_image(self) -> &'static str {
        match self {
            Self::Ibss => "iBSS",
            Self::Ibec => "iBEC",
            Self::RestoreDeviceTree => "DeviceTree",
            Self::RestoreKernelCache | Self::KernelCache => "Kernelcache",
            Self::RestoreRamdisk => "RestoreRamdisk",
        }
    }

    /// BuildManifest component name, mirroring upstream's `getcomp_bm`.
    const fn manifest_component(self) -> &'static str {
        match self {
            Self::RestoreRamdisk => "RestoreRamDisk",
            other => other.plist_name(),
        }
    }

    /// Whether the file lives under the given all_flash directory.
    const fn in_all_flash(self) -> bool {
        matches!(self, Self::RestoreDeviceTree)
    }

    /// Whether the file lives under `Firmware/dfu`.
    const fn in_dfu(self) -> bool {
        matches!(self, Self::Ibss | Self::Ibec)
    }
}

/// One entry of the bundle's `Firmware` dict.
#[derive(Clone)]
pub struct FirmwareEntry {
    kind: FirmwareComponentKind,
    file: String,
    iv: Option<[u8; 16]>,
    key: Option<Vec<u8>>,
    patch: bool,
    decrypt: bool,
    decrypt_path: Option<String>,
}

impl FirmwareEntry {
    pub const fn kind(&self) -> FirmwareComponentKind {
        self.kind
    }

    /// Path of the component inside the source IPSW.
    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn iv(&self) -> Option<&[u8; 16]> {
        self.iv.as_ref()
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    /// `Patch=true`: patched in place by the builder (iBSS/iBEC, and
    /// KernelCache of jailbroken 6/8/9 targets).
    pub const fn patch(&self) -> bool {
        self.patch
    }

    /// `Decrypt=true`.
    pub const fn decrypt(&self) -> bool {
        self.decrypt
    }

    /// `DecryptPath`: decrypted copy destination (e.g.
    /// `Downgrade/RestoreKernelCache`).
    pub fn decrypt_path(&self) -> Option<&str> {
        self.decrypt_path.as_deref()
    }
}

impl std::fmt::Debug for FirmwareEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirmwareEntry")
            .field("kind", &self.kind)
            .field("file", &self.file)
            .field("patch", &self.patch)
            .field("decrypt", &self.decrypt)
            .field("decrypt_path", &self.decrypt_path)
            .finish_non_exhaustive()
    }
}

/// One `FirmwarePath` (base bundle) or `FirmwareReplace` (target bundle)
/// entry: an all_flash NOR image path, with key material attached only for
/// `NewiBoot`.
#[derive(Clone)]
pub struct NorImagePath {
    component: String,
    file: String,
    iv: Option<[u8; 16]>,
    key: Option<Vec<u8>>,
}

impl NorImagePath {
    /// Plist key of the entry (e.g. `AppleLogo`, `NewiBoot`, `manifest`).
    pub fn component(&self) -> &str {
        &self.component
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn iv(&self) -> Option<&[u8; 16]> {
        self.iv.as_ref()
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }
}

impl std::fmt::Debug for NorImagePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NorImagePath")
            .field("component", &self.component)
            .field("file", &self.file)
            .finish_non_exhaustive()
    }
}

/// `FilesystemPackage`: payloads untarred into the grown root filesystem of a
/// target bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemPackage {
    bootstrap: String,
    package: Option<String>,
}

impl FilesystemPackage {
    /// Jailbreak bootstrap tar (`freeze.tar`).
    pub fn bootstrap(&self) -> &str {
        &self.bootstrap
    }

    /// Extra package tar: `src/ios9.tar` for iOS 8/9 targets, absent
    /// otherwise.
    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }
}

/// `RamdiskPackage`: payload untarred into the restore ramdisk of a target
/// bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamdiskPackage {
    package: String,
    ios_marker: Option<u32>,
}

impl RamdiskPackage {
    /// Ramdisk binary package (`src/bin.tar`).
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Major version of the dummy `ios<N>` marker file written into the
    /// ramdisk; only present for jailbroken targets.
    pub const fn ios_marker(&self) -> Option<u32> {
        self.ios_marker
    }
}

/// `RamdiskExploit` of a base bundle: the per-board/per-base-build exploit
/// payload installed as `/exploit` in the base ramdisk, plus the `partition`
/// inject script path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamdiskExploit {
    exploit: String,
    inject: String,
}

impl RamdiskExploit {
    /// Exploit payload path, e.g. `src/target/iphone5/11D257/exploit`.
    pub fn exploit(&self) -> &str {
        &self.exploit
    }

    /// Inject script name (`partition`).
    pub fn inject(&self) -> &str {
        &self.inject
    }

    /// Catalog resource id of the exploit payload.
    pub fn resource_id(&self) -> ResourceId {
        let parts: Vec<&str> = self.exploit.split('/').collect();
        // "src/target/<hw>/<build>/exploit"
        ResourceId::new(format!("powder-exploit-{}-{}", parts[2], parts[3]))
    }
}

/// daibutsu additions of a single-IPSW bundle (`ipsw_prepare_bundle
/// daibutsu`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaibutsuPackage {
    ramdisk_package2: String,
    ramdisk_reboot: String,
    untether: String,
    hwmodel: String,
}

impl DaibutsuPackage {
    /// `RamdiskPackage2` (`./bin.tar`).
    pub fn ramdisk_package2(&self) -> &str {
        &self.ramdisk_package2
    }

    /// `RamdiskReboot` (`./reboot.sh`).
    pub fn ramdisk_reboot(&self) -> &str {
        &self.ramdisk_reboot
    }

    /// `UntetherPath` (`./untether.tar`).
    pub fn untether(&self) -> &str {
        &self.untether
    }

    /// `hwmodel` (board with an uppercased first letter, e.g. `N90`).
    pub fn hwmodel(&self) -> &str {
        &self.hwmodel
    }
}

/// A resolved powdersn0w firmware bundle.
#[derive(Clone, Debug)]
pub struct PowderBundle {
    role: BundleRole,
    filename: String,
    root_filesystem: String,
    root_filesystem_key: Vec<u8>,
    root_filesystem_size_mb: u64,
    ramdisk_options_path: String,
    firmware: Vec<FirmwareEntry>,
    firmware_paths: Vec<NorImagePath>,
    firmware_replacements: Vec<NorImagePath>,
    manifest_additions: Vec<String>,
    filesystem_package: Option<FilesystemPackage>,
    ramdisk_package: Option<RamdiskPackage>,
    ramdisk_exploit: Option<RamdiskExploit>,
    daibutsu: Option<DaibutsuPackage>,
}

impl PowderBundle {
    pub const fn role(&self) -> BundleRole {
        self.role
    }

    /// `Filename`: the source IPSW file name.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// `RootFilesystem`: root filesystem DMG name.
    pub fn root_filesystem(&self) -> &str {
        &self.root_filesystem
    }

    /// `RootFilesystemKey`: vfdecrypt key of the root filesystem.
    pub fn root_filesystem_key(&self) -> &[u8] {
        &self.root_filesystem_key
    }

    /// `RootFilesystemSize` in MB: the ramdisk options plist's
    /// `SystemPartitionSize` plus 30.
    pub const fn root_filesystem_size_mb(&self) -> u64 {
        self.root_filesystem_size_mb
    }

    /// `RamdiskOptionsPath`: path of the options plist inside the restore
    /// ramdisk.
    pub fn ramdisk_options_path(&self) -> &str {
        &self.ramdisk_options_path
    }

    /// `Firmware` dict entries, in upstream emission order. Empty for base
    /// bundles.
    pub fn firmware(&self) -> &[FirmwareEntry] {
        &self.firmware
    }

    /// `FirmwarePath` entries (base bundles only).
    pub fn firmware_paths(&self) -> &[NorImagePath] {
        &self.firmware_paths
    }

    /// `FirmwareReplace` entries (target bundles only).
    pub fn firmware_replacements(&self) -> &[NorImagePath] {
        &self.firmware_replacements
    }

    /// File names appended to the bundle `manifest` (target bundles only),
    /// mirroring the `echo >> $FirmwareBundle/manifest` calls of
    /// `ipsw_prepare_paths`.
    pub fn manifest_additions(&self) -> &[String] {
        &self.manifest_additions
    }

    pub const fn filesystem_package(&self) -> Option<&FilesystemPackage> {
        self.filesystem_package.as_ref()
    }

    pub const fn ramdisk_package(&self) -> Option<&RamdiskPackage> {
        self.ramdisk_package.as_ref()
    }

    pub const fn ramdisk_exploit(&self) -> Option<&RamdiskExploit> {
        self.ramdisk_exploit.as_ref()
    }

    pub const fn daibutsu(&self) -> Option<&DaibutsuPackage> {
        self.daibutsu.as_ref()
    }
}

/// Inputs for [`PowderBundle::resolve`], mirroring the device/target state
/// `ipsw_prepare_bundle` reads. All versions refer to the target unless
/// noted.
#[derive(Clone, Debug)]
pub struct PowderBundleRequest {
    role: BundleRole,
    product_type: ProductType,
    board_config: BoardConfig,
    filename: String,
    version: IosVersion,
    target_version: IosVersion,
    latest_version: IosVersion,
    system_partition_size_mb: u64,
    jailbreak: bool,
    daibutsu: bool,
    drav6: bool,
    base_build: Option<BuildId>,
}

impl PowderBundleRequest {
    /// `version` describes the IPSW the bundle is generated for (the
    /// base IPSW for [`BundleRole::Base`]). `system_partition_size_mb` is the
    /// `SystemPartitionSize` of that IPSW's restore ramdisk options plist;
    /// the bundle records it plus 30, like upstream.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: BundleRole,
        product_type: ProductType,
        board_config: BoardConfig,
        filename: impl Into<String>,
        version: IosVersion,
        target_version: IosVersion,
        latest_version: IosVersion,
        system_partition_size_mb: u64,
    ) -> Self {
        Self {
            role,
            product_type,
            board_config,
            filename: filename.into(),
            version,
            target_version,
            latest_version,
            system_partition_size_mb,
            jailbreak: false,
            daibutsu: false,
            drav6: false,
            base_build: None,
        }
    }

    /// Mirror of upstream's `ipsw_jailbreak`.
    pub fn with_jailbreak(mut self, enabled: bool) -> Self {
        self.jailbreak = enabled;
        self
    }

    /// daibutsu marker of single-IPSW builds (`-daibutsu`).
    pub fn with_daibutsu(mut self, enabled: bool) -> Self {
        self.daibutsu = enabled;
        self
    }

    /// Whether the target is a DRA v6 restore, mirroring
    /// `device_target_drav6`; affects the exploit hardware mapping.
    pub fn with_drav6(mut self, enabled: bool) -> Self {
        self.drav6 = enabled;
        self
    }

    /// Base build id, required for [`BundleRole::Base`] (exploit mapping).
    pub fn with_base_build(mut self, build: BuildId) -> Self {
        self.base_build = Some(build);
        self
    }
}

impl PowderBundle {
    /// Resolve a bundle, mirroring `ipsw_prepare_bundle` for powder builds
    /// (`ipsw_prepare_usepowder=1`). `keys` and `identity` describe the IPSW
    /// the bundle is generated for; `identity` may be absent, in which case
    /// component file names fall back to the firmware key set, like upstream.
    pub fn resolve(
        request: &PowderBundleRequest,
        keys: &FirmwareKeySet,
        identity: Option<&BuildIdentity>,
    ) -> Result<Self, PowderBundleError> {
        validate_version(&request.version)?;
        if request.daibutsu && request.role != BundleRole::Single {
            return Err(PowderBundleError::MisplacedDaibutsu);
        }
        let all_flash = all_flash_dir(&request.board_config);

        let rootfs = required_key(keys, "RootFS")?;
        let root_filesystem = component_name(identity, "OS", rootfs);
        let root_filesystem_key = rootfs
            .key()
            .ok_or_else(|| PowderBundleError::MissingKeyMaterial("RootFS".to_owned()))?
            .to_vec();

        let ramdisk_options_path = ramdisk_options_path(
            &request.product_type,
            &request.board_config,
            request.target_version.as_str(),
        );

        let mut bundle = Self {
            role: request.role,
            filename: request.filename.clone(),
            root_filesystem,
            root_filesystem_key,
            root_filesystem_size_mb: request.system_partition_size_mb + 30,
            ramdisk_options_path,
            firmware: Vec::new(),
            firmware_paths: Vec::new(),
            firmware_replacements: Vec::new(),
            manifest_additions: Vec::new(),
            filesystem_package: None,
            ramdisk_package: None,
            ramdisk_exploit: None,
            daibutsu: None,
        };

        match request.role {
            BundleRole::Base => {
                bundle.ramdisk_exploit = Some(RamdiskExploit {
                    exploit: exploit_path(
                        &request.product_type,
                        &request.board_config,
                        request.drav6,
                        request
                            .base_build
                            .as_ref()
                            .ok_or(PowderBundleError::MissingBaseBuild)?,
                    ),
                    inject: "partition".to_owned(),
                });
                bundle.firmware_paths = base_firmware_paths(keys, identity, &all_flash)?;
            }
            BundleRole::Target => {
                let (major, _, _) = version_parts(request.version.as_str())?;
                bundle.filesystem_package = Some(FilesystemPackage {
                    bootstrap: "freeze.tar".to_owned(),
                    package: (major == 8 || major == 9).then(|| "src/ios9.tar".to_owned()),
                });
                bundle.ramdisk_package = Some(RamdiskPackage {
                    package: "src/bin.tar".to_owned(),
                    ios_marker: request.jailbreak.then_some(major),
                });
                bundle.firmware = target_firmware(request, keys, identity, &all_flash)?;
                bundle.firmware_replacements =
                    target_firmware_replacements(request, keys, identity, &all_flash)?;
                bundle.manifest_additions = manifest_additions(request, keys, identity)?;
            }
            BundleRole::Single => {
                bundle.firmware = single_firmware(request, keys, identity, &all_flash)?;
                if request.daibutsu {
                    bundle.daibutsu = Some(DaibutsuPackage {
                        ramdisk_package2: "./bin.tar".to_owned(),
                        ramdisk_reboot: "./reboot.sh".to_owned(),
                        untether: "./untether.tar".to_owned(),
                        hwmodel: hwmodel(&request.board_config),
                    });
                }
            }
        }

        debug!(
            role = ?request.role,
            version = %request.version,
            "resolved powder firmware bundle"
        );
        Ok(bundle)
    }
}

/// The config accompanying a powdersn0w build, replacing the
/// `config.plist` generated by `ipsw_prepare_config`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowderConfig {
    filesystem_jailbreak: bool,
    need_pref: bool,
    boot_args_injection: bool,
    boot_args: String,
}

impl PowderConfig {
    /// Mirror of `ipsw_prepare_config` as invoked from `ipsw_prepare_bundle`:
    /// base bundles carry no config (`None`); single-IPSW builds never set
    /// `FilesystemJailbreak`; target bundles set it only for jailbroken
    /// 6.x/8.x/9.x targets. `needPref` is set for target bundles and for
    /// jailbroken single-IPSW builds.
    pub fn resolve(
        role: BundleRole,
        jailbreak: bool,
        target_version: &IosVersion,
        verbose: bool,
        custom_boot_args: Option<&str>,
    ) -> Result<Option<Self>, PowderBundleError> {
        let (filesystem_jailbreak, need_pref) = match role {
            BundleRole::Base => return Ok(None),
            BundleRole::Target => {
                let (major, _, _) = version_parts(target_version.as_str())?;
                (jailbreak && matches!(major, 6 | 8 | 9), true)
            }
            BundleRole::Single => (false, jailbreak),
        };
        let custom_boot_args = custom_boot_args.filter(|args| !args.is_empty());
        let mut boot_args = if verbose {
            VERBOSE_BOOT_ARGS.to_owned()
        } else {
            DEFAULT_BOOT_ARGS.to_owned()
        };
        if let Some(custom) = custom_boot_args {
            boot_args.push(' ');
            boot_args.push_str(custom);
        }
        Ok(Some(Self {
            filesystem_jailbreak,
            need_pref,
            boot_args_injection: verbose || custom_boot_args.is_some(),
            boot_args,
        }))
    }

    /// `FilesystemJailbreak`: gates the kernel patch, rw fstab, and the
    /// bootstrap/package untars in the builder.
    pub const fn filesystem_jailbreak(&self) -> bool {
        self.filesystem_jailbreak
    }

    /// `needPref`: write the SpringBoard preference blob into the root
    /// filesystem.
    pub const fn need_pref(&self) -> bool {
        self.need_pref
    }

    /// `iBootPatches.bootArgsInjection`.
    pub const fn boot_args_injection(&self) -> bool {
        self.boot_args_injection
    }

    /// `iBootPatches.bootArgsString`.
    pub fn boot_args(&self) -> &str {
        &self.boot_args
    }
}

/// The powdersn0w call path, mirroring upstream's `ipsw_prepare_*` drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowderMode {
    /// `ipsw_prepare_32bit`: single IPSW, no `-base`.
    Single,
    /// `ipsw_prepare_powder`: two-bundle mode with `-base`.
    TwoBundle,
    /// `ipsw_prepare_ios4powder`: 4.3.x single IPSW with `-base` and
    /// `-apticket`.
    Ios4,
}

/// A payload tar of a powder build, in argument order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PowderTar {
    /// A cataloged jailbreak resource.
    Resource(ResourceId),
    /// The generated beta `systemversion.tar` ([`system_version_tar`]).
    SystemVersion,
    /// The generated `iBoot.tar` holding the externally patched iBoot
    /// ([`iboot_tar`]); `iBoot` for iPhone5,\* ramdiskH builds, `iBEC` for
    /// iPad1,1.
    IBoot,
}

/// daibutsu ramdisk payload of a single-IPSW 7.x/8.x jailbreak build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaibutsuPayload {
    bin_tar: ResourceId,
    untether: ResourceId,
    reboot_script: RebootScriptVariant,
}

impl DaibutsuPayload {
    /// `RamdiskPackage2` resource (`jailbreak-daibutsu-bin-tar`).
    pub fn bin_tar(&self) -> &ResourceId {
        &self.bin_tar
    }

    /// Resource installed as `./untether.tar`: `jailbreak-aquila-7` for 7.x
    /// targets, `jailbreak-daibutsu-untether` for 8.x.
    pub fn untether(&self) -> &ResourceId {
        &self.untether
    }

    /// `reboot.sh` variant installed as the ramdisk reboot hook.
    pub const fn reboot_script(&self) -> RebootScriptVariant {
        self.reboot_script
    }
}

/// `reboot.sh` variants of `ipsw_prepare_rebootsh`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebootScriptVariant {
    /// iOS 7.x: aquila CrashHousekeeping relink, then `reboot_`.
    Aquila,
    /// iOS 8.x: `haxx_overwrite --<device>_<build>`.
    Daibutsu,
}

/// The ordered payload selection for one powder build: the contract consumed
/// by the custom-IPSW builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PowderPayloadPlan {
    tars: Vec<PowderTar>,
    punchd: bool,
    daibutsu: Option<DaibutsuPayload>,
}

impl PowderPayloadPlan {
    /// Ordered payload tars: generated extras first (`systemversion.tar`,
    /// `iBoot.tar`), then the jailbreak payload tars, mirroring upstream's
    /// argument order. Per-device baseband/activation tars are not cataloged
    /// and are appended by the caller.
    pub fn tars(&self) -> &[PowderTar] {
        &self.tars
    }

    /// `-punchd`: move `/sbin/launchd` to `/sbin/punchd` in the root
    /// filesystem (4.2.x greenpois0n targets).
    pub const fn punchd(&self) -> bool {
        self.punchd
    }

    /// daibutsu ramdisk payload of single-IPSW 7.x/8.x jailbreak builds.
    pub const fn daibutsu(&self) -> Option<&DaibutsuPayload> {
        self.daibutsu.as_ref()
    }

    /// Mirror of the jailbreak payload matrix of `ipsw_prepare_32bit`
    /// ([`PowderMode::Single`]), `ipsw_prepare_powder`
    /// ([`PowderMode::TwoBundle`]), and `ipsw_prepare_ios4powder`
    /// ([`PowderMode::Ios4`]).
    pub fn resolve(request: &PowderPayloadRequest) -> Result<Self, PowderBundleError> {
        let version = request.target_version.as_str();
        let (major, minor, patch) = version_parts(version)?;
        match request.mode {
            PowderMode::Single => {
                // 4.1 and lower redirect to the classic path, 10+ needs no
                // custom IPSW.
                if !(4..=9).contains(&major) || (major == 4 && minor < 2) {
                    return Err(PowderBundleError::UnsupportedTarget(
                        request.product_type.as_str().to_owned(),
                        version.to_owned(),
                    ));
                }
            }
            PowderMode::TwoBundle => {
                if !(4..=9).contains(&major) {
                    return Err(PowderBundleError::UnsupportedTarget(
                        request.product_type.as_str().to_owned(),
                        version.to_owned(),
                    ));
                }
            }
            PowderMode::Ios4 => {
                if !(major == 4 && minor == 3) {
                    return Err(PowderBundleError::UnsupportedTarget(
                        request.product_type.as_str().to_owned(),
                        version.to_owned(),
                    ));
                }
            }
        }

        let mut plan = Self {
            tars: Vec::new(),
            punchd: false,
            daibutsu: None,
        };

        if request.beta {
            plan.tars.push(PowderTar::SystemVersion);
        }
        if request.includes_iboot_tar() {
            plan.tars.push(PowderTar::IBoot);
        }

        if !request.jailbreak {
            return Ok(plan);
        }

        match request.mode {
            PowderMode::Single => {
                // A5/A5X 8.0-8.2 use everuntether instead of daibutsu.
                let everuntether =
                    is_a5(&request.product_type) && major == 8 && matches!(minor, 0..=2);
                let mut first = None;
                if everuntether {
                    first = Some(ResourceId::new("jailbreak-everuntether"));
                } else {
                    match major {
                        8 => {
                            plan.daibutsu = Some(DaibutsuPayload {
                                bin_tar: ResourceId::new("jailbreak-daibutsu-bin-tar"),
                                untether: ResourceId::new("jailbreak-daibutsu-untether"),
                                reboot_script: RebootScriptVariant::Daibutsu,
                            });
                        }
                        7 => {
                            plan.daibutsu = Some(DaibutsuPayload {
                                bin_tar: ResourceId::new("jailbreak-daibutsu-bin-tar"),
                                untether: ResourceId::new("jailbreak-aquila-7"),
                                reboot_script: RebootScriptVariant::Aquila,
                            });
                        }
                        _ => {}
                    }
                }
                match (major, minor, patch) {
                    (9, 3, Some(5..=6)) => {}
                    (9, _, _) => first = Some(ResourceId::new("jailbreak-everuntether")),
                    (6, _, _) => first = Some(ResourceId::new("jailbreak-aquila-6")),
                    (5, _, _) => first = Some(ResourceId::new("jailbreak-aquila-5")),
                    (4, 3, _) => first = Some(ResourceId::new("jailbreak-aquila-4")),
                    (4, 2, Some(1 | 6 | 7 | 8)) => {
                        plan.punchd = true;
                        first = Some(greenpois0n_resource(
                            &request.product_type,
                            &request.target_build,
                        )?);
                    }
                    _ => {}
                }
                if let Some(first) = first {
                    plan.tars.push(PowderTar::Resource(first));
                }
                plan.tars
                    .push(PowderTar::Resource(ResourceId::new(match major {
                        8 | 9 => "jailbreak-fstab-8",
                        7 => "jailbreak-fstab-7",
                        4 => "jailbreak-fstab-old",
                        _ => "jailbreak-fstab-rw",
                    })));
                plan.tars.push(PowderTar::Resource(ResourceId::new(
                    "jailbreak-bootstrap-freeze",
                )));
                match major {
                    9 => {
                        plan.tars
                            .push(PowderTar::Resource(ResourceId::new("jailbreak-launchctl")));
                        plan.tars
                            .push(PowderTar::Resource(ResourceId::new("jailbreak-zebra")));
                    }
                    5 => plan.tars.push(PowderTar::Resource(ResourceId::new(
                        "jailbreak-cydiasubstrate",
                    ))),
                    _ => {}
                }
                push_openssh(&mut plan.tars, request.openssh);
                if major != 4 {
                    plan.tars
                        .push(PowderTar::Resource(ResourceId::new("jailbreak-lukezgd")));
                }
            }
            PowderMode::TwoBundle => {
                match major {
                    7 => plan
                        .tars
                        .push(PowderTar::Resource(ResourceId::new("jailbreak-aquila-7"))),
                    5 => plan
                        .tars
                        .push(PowderTar::Resource(ResourceId::new("jailbreak-aquila-5"))),
                    _ => {}
                }
                match major {
                    9 => plan
                        .tars
                        .push(PowderTar::Resource(ResourceId::new("jailbreak-zebra"))),
                    5 => plan.tars.push(PowderTar::Resource(ResourceId::new(
                        "jailbreak-cydiasubstrate",
                    ))),
                    _ => {}
                }
                // freeze comes from the target bundle's FilesystemPackage for
                // 6/8/9 targets.
                if !matches!(major, 6 | 8 | 9) {
                    plan.tars.push(PowderTar::Resource(ResourceId::new(
                        "jailbreak-bootstrap-freeze",
                    )));
                }
                push_openssh(&mut plan.tars, request.openssh);
                plan.tars
                    .push(PowderTar::Resource(ResourceId::new("jailbreak-lukezgd")));
            }
            PowderMode::Ios4 => {
                for id in [
                    "jailbreak-aquila-4",
                    "jailbreak-fstab-old",
                    "jailbreak-cydiasubstrate",
                    "jailbreak-bootstrap-freeze",
                ] {
                    plan.tars.push(PowderTar::Resource(ResourceId::new(id)));
                }
                push_openssh(&mut plan.tars, request.openssh);
            }
        }
        Ok(plan)
    }
}

/// Inputs for [`PowderPayloadPlan::resolve`].
#[derive(Clone, Debug)]
pub struct PowderPayloadRequest {
    mode: PowderMode,
    product_type: ProductType,
    target_version: IosVersion,
    target_build: BuildId,
    base_version: Option<IosVersion>,
    jailbreak: bool,
    openssh: bool,
    beta: bool,
    iboot_sidecar: bool,
}

impl PowderPayloadRequest {
    pub fn new(
        mode: PowderMode,
        product_type: ProductType,
        target_version: IosVersion,
        target_build: BuildId,
    ) -> Self {
        Self {
            mode,
            product_type,
            target_version,
            target_build,
            base_version: None,
            jailbreak: false,
            openssh: false,
            beta: false,
            iboot_sidecar: false,
        }
    }

    /// Base iOS version of a two-bundle build; drives the ramdiskH/iBoot.tar
    /// gates.
    pub fn with_base_version(mut self, version: IosVersion) -> Self {
        self.base_version = Some(version);
        self
    }

    /// Mirror of upstream's `ipsw_jailbreak`.
    pub fn with_jailbreak(mut self, enabled: bool) -> Self {
        self.jailbreak = enabled;
        self
    }

    /// Mirror of upstream's `ipsw_openssh`.
    pub fn with_openssh(mut self, enabled: bool) -> Self {
        self.openssh = enabled;
        self
    }

    /// Beta target: include the generated `systemversion.tar`.
    pub fn with_beta(mut self, enabled: bool) -> Self {
        self.beta = enabled;
        self
    }

    /// Pass an `iBoot.tar` sidecar to the build, mirroring the `iboot`
    /// argument of the multipart part 2 call for iPad1,1.
    pub fn with_iboot_sidecar(mut self, enabled: bool) -> Self {
        self.iboot_sidecar = enabled;
        self
    }

    fn includes_iboot_tar(&self) -> bool {
        match self.mode {
            PowderMode::Single => self.iboot_sidecar,
            PowderMode::Ios4 => self.product_type.as_str() == "iPad1,1",
            PowderMode::TwoBundle => {
                self.product_type.as_str() == "iPad1,1"
                    || uses_ramdisk_h(
                        &self.product_type,
                        self.base_version.as_ref().map_or("", IosVersion::as_str),
                    )
            }
        }
    }
}

/// Whether a two-bundle build uses the ramdiskH boot chain (patched iBoot
/// passed as `iBoot.tar` and the iPhone5 partition script), mirroring
/// upstream's `ipsw_powder_ramdiskH`: iPhone5,\* except iPhone5,3/5,4 with an
/// iOS 7.0 base.
pub fn uses_ramdisk_h(product_type: &ProductType, base_version: &str) -> bool {
    if !product_type.as_str().starts_with("iPhone5,") {
        return false;
    }
    let five_c_7_0 = matches!(product_type.as_str(), "iPhone5,3" | "iPhone5,4")
        && base_version.starts_with("7.0");
    !five_c_7_0
}

/// Exploit payload path of a base bundle, mirroring
/// `ipsw_prepare_powder_exploit`: `src/target/<hw>/<build>/exploit`, where
/// `hw` is the board unless the device is remapped to a shared exploit, and
/// `build` is normalized per base version family.
pub fn exploit_path(
    product_type: &ProductType,
    board_config: &BoardConfig,
    drav6: bool,
    base_build: &BuildId,
) -> String {
    let mut hw = board_config.as_str().to_owned();
    if !drav6 {
        match product_type.as_str() {
            "iPhone5,1" | "iPhone5,2" => hw = "iphone5".to_owned(),
            "iPhone5,3" | "iPhone5,4" => hw = "iphone5b".to_owned(),
            "iPad2,1" | "iPad2,2" | "iPad2,3" => hw = "ipad2".to_owned(),
            "iPad2,5" | "iPad2,6" | "iPad2,7" => hw = "ipad2b".to_owned(),
            "iPad3,1" | "iPad3,2" | "iPad3,3" => hw = "ipad3".to_owned(),
            "iPad3,4" | "iPad3,5" | "iPad3,6" => hw = "ipad3b".to_owned(),
            _ => {}
        }
    }
    let build = base_build.as_str();
    let build_dir = if build.starts_with("11A") || build.starts_with("11B") {
        "11B554a"
    } else if build.starts_with("10") {
        build
    } else if build.starts_with("9B") {
        "9B206"
    } else if build.starts_with("9A") {
        "9A405"
    } else {
        "11D257"
    };
    format!("src/target/{hw}/{build_dir}/exploit")
}

/// Partition script resource of a two-bundle build, mirroring the template
/// selection of `ipsw_prepare_partition_script`.
pub fn partition_script_resource(ramdisk_h: bool) -> ResourceId {
    if ramdisk_h {
        ResourceId::new("powder-partition-script-iphone5")
    } else {
        ResourceId::new("powder-partition-script")
    }
}

/// Apply the upstream `sed` edits of `ipsw_prepare_partition_script` to the
/// generic partition script: shrink the exploit block to 64k for iOS 5
/// bases, and drop the `nvram boot-ramdisk` write for iOS 5 bases, iPhone3,1,
/// and DRA v6 iPhone4,1 targets. The ramdiskH (iPhone5) script is used
/// verbatim.
pub fn render_partition_script(
    template: &str,
    base_version: &str,
    product_type: &ProductType,
    drav6: bool,
) -> String {
    let ios5_base = base_version.starts_with("5.");
    let drop_nvram = ios5_base
        || product_type.as_str() == "iPhone3,1"
        || (drav6 && product_type.as_str() == "iPhone4,1");
    let mut output = String::with_capacity(template.len());
    for line in template.split_inclusive('\n') {
        let content = line.trim_end_matches('\n');
        if drop_nvram && content.starts_with("nvram boot-ramdisk") {
            continue;
        }
        if ios5_base && content.starts_with("Exploit_LastSector=") {
            output.push_str("Exploit_LastSector=\"$((65536/$LogicalSector))\"\n");
            continue;
        }
        if ios5_base
            && content.starts_with("dd of=$exploitDisk if=/exploit bs=")
            && content.ends_with(" count=1")
        {
            output.push_str("dd of=$exploitDisk if=/exploit bs=64k count=1\n");
            continue;
        }
        output.push_str(line);
    }
    output
}

/// Generate `reboot.sh`, mirroring `ipsw_prepare_rebootsh`. The aquila
/// variant additionally writes the openssh launch daemon plist when `openssh`
/// is set.
pub fn reboot_script(
    variant: RebootScriptVariant,
    product_type: &ProductType,
    target_build: &BuildId,
    openssh: bool,
) -> String {
    let mut script = String::from(
        "#!/bin/bash\n\
         mount_hfs /dev/disk0s1s1 /mnt1; mount_hfs /dev/disk0s1s2 /mnt2; nvram -c\n",
    );
    match variant {
        RebootScriptVariant::Aquila => {
            script.push_str(
                "mv /mnt1/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist_ /mnt1/Library/LaunchDaemons/com.apple.mDNSResponder.plist\n\
                 mv /mnt1/Library/LaunchDaemons/com.apple.sandboxd.plist /mnt1/System/Library/LaunchDaemons/\n\
                 mv /mnt1/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist /mnt1/System/Library/LaunchDaemons/\n\
                 mv /mnt1/usr/libexec/CrashHousekeeping_o /mnt1/usr/libexec/CrashHousekeeping.backup\n\
                 ln -sf /aquila /mnt1/usr/libexec/CrashHousekeeping\n",
            );
            if openssh {
                script.push_str(OPENSSH_PLIST_DROP);
            }
            script.push_str("/sbin/reboot_\n");
        }
        RebootScriptVariant::Daibutsu => {
            script.push_str(&format!(
                "/usr/bin/haxx_overwrite --{}_{}\n",
                product_type.as_str(),
                target_build.as_str()
            ));
        }
    }
    script
}

/// The openssh launch daemon drop of `ipsw_prepare_openssh_plist`: a single
/// shell line writing the plist to the mounted root filesystem.
const OPENSSH_PLIST_DROP: &str = r#"echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">

<dict>
    <key>Label</key>
    <string>com.openssh.sshd</string>

    <key>Program</key>
    <string>/usr/libexec/sshd-keygen-wrapper</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/sbin/sshd</string>
        <string>-i</string>
    </array>

    <key>SessionCreate</key>
    <true/>

    <key>Sockets</key>
    <dict>
        <key>Listeners</key>
        <dict>
            <key>SockServiceName</key>
            <string>ssh</string>
        </dict>
    </dict>

    <key>StandardErrorPath</key>
    <string>/dev/null</string>

    <key>inetdCompatibility</key>
    <dict>
        <key>Wait</key>
        <false/>
    </dict>
</dict>

</plist>' > /mnt1/Library/LaunchDaemons/com.openssh.sshd.plist
"#;

/// Generate the beta `systemversion.tar`, mirroring
/// `ipsw_prepare_systemversion`: a tar holding a modified
/// `System/Library/CoreServices/SystemVersion.plist`.
pub fn system_version_tar(target_version: &IosVersion, target_build: &BuildId) -> Vec<u8> {
    let copyright_suffix = match target_version.as_str().split('.').next() {
        Some("3") => "0",
        Some("4") => "1",
        Some("5") => "2",
        Some("6") => "3",
        Some("7") => "4",
        Some("8") => "5",
        _ => "6",
    };
    let plist = format!(
        "<plist><dict>\n\
         <key>ProductBuildVersion</key><string>{}</string>\n\
         <key>ProductCopyright</key><string>1983-201{copyright_suffix} Apple Inc.</string>\n\
         <key>ProductName</key><string>iPhone OS</string>\n\
         <key>ProductVersion</key><string>{}</string>\n\
         </dict></plist>\n",
        target_build.as_str(),
        target_version.as_str(),
    );
    let mut tar = UstarBuilder::new();
    // Constant entry names; only a pathological version string could exceed
    // the ustar name limit.
    tar.add_directory("System")
        .expect("constant ustar entry name");
    tar.add_directory("System/Library")
        .expect("constant ustar entry name");
    tar.add_directory("System/Library/CoreServices")
        .expect("constant ustar entry name");
    tar.add_file(
        "System/Library/CoreServices/SystemVersion.plist",
        plist.as_bytes(),
    )
    .expect("constant ustar entry name");
    tar.finish()
}

/// Generate the `iBoot.tar` sidecar holding an externally patched iBoot:
/// `tar -cvf iBoot.tar iBoot` for iPhone5,\* ramdiskH builds, or with the
/// iBoot renamed to `iBEC` for iPad1,1.
pub fn iboot_tar(name: &str, iboot: &[u8]) -> Vec<u8> {
    let mut tar = UstarBuilder::new();
    tar.add_file(name, iboot)
        .expect("constant ustar entry name");
    tar.finish()
}

/// Extract `SystemPartitionSize` (in MB) from a restore ramdisk options
/// plist, mirroring the `plutil`/grep extraction of `ipsw_prepare_bundle`.
pub fn system_partition_size(options_plist: &[u8]) -> Result<u64, PowderBundleError> {
    let value: plist::Value = plist::from_bytes(options_plist)?;
    value
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("SystemPartitionSize"))
        .and_then(plist::Value::as_unsigned_integer)
        .ok_or(PowderBundleError::MissingSystemPartitionSize)
}

fn push_openssh(tars: &mut Vec<PowderTar>, openssh: bool) {
    if !openssh {
        return;
    }
    for id in ["jailbreak-sshdeb", "jailbreak-openssh", "jailbreak-openssl"] {
        tars.push(PowderTar::Resource(ResourceId::new(id)));
    }
}

fn greenpois0n_resource(
    product_type: &ProductType,
    build: &BuildId,
) -> Result<ResourceId, PowderBundleError> {
    let id = format!(
        "greenpois0n-{}-{}",
        product_type.as_str().replace(',', "-"),
        build.as_str()
    );
    let id = ResourceId::new(id);
    if legacy_ios_assets::ResourceCatalog::bundled()
        .get(&id)
        .is_none()
    {
        return Err(PowderBundleError::MissingUntether {
            device: product_type.as_str().to_owned(),
            build: build.as_str().to_owned(),
        });
    }
    Ok(id)
}

fn is_a5(product_type: &ProductType) -> bool {
    matches!(
        product_type.as_str(),
        "iPhone4,1" | "iPad2,1" | "iPad2,2" | "iPad2,3" | "iPad2,4" | "iPod5,1"
    )
}

pub(crate) fn all_flash_dir(board_config: &BoardConfig) -> String {
    format!(
        "{ALL_FLASH_PREFIX}/all_flash.{}ap.production",
        board_config.as_str()
    )
}

fn hwmodel(board_config: &BoardConfig) -> String {
    let board = board_config.as_str();
    let mut chars = board.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

/// `RamdiskOptionsPath` rule of `ipsw_prepare_bundle`: per-board options
/// plist unless the target is iOS 3.x/4.x (iPad1,1 4.x excepted). Upstream
/// keys this on the target version even for base bundles.
pub(crate) fn ramdisk_options_path(
    product_type: &ProductType,
    board_config: &BoardConfig,
    target_version: &str,
) -> String {
    let per_board = (!target_version.starts_with('3') && !target_version.starts_with('4'))
        || (product_type.as_str() == "iPad1,1" && target_version.starts_with('4'));
    let mut path = "/usr/local/share/restore/options".to_owned();
    if per_board {
        path.push('.');
        path.push_str(board_config.as_str());
    }
    path.push_str(".plist");
    path
}

fn validate_version(version: &IosVersion) -> Result<(u32, u32, Option<u32>), PowderBundleError> {
    version_parts(version.as_str())
}

fn version_parts(version: &str) -> Result<(u32, u32, Option<u32>), PowderBundleError> {
    let mut parts = version.split('.');
    let parse = |part: Option<&str>| {
        part.and_then(|part| part.parse::<u32>().ok())
            .ok_or_else(|| PowderBundleError::InvalidVersion(version.to_owned()))
    };
    let major = parse(parts.next())?;
    let minor = parse(parts.next())?;
    let patch = parts
        .next()
        .map(|part| {
            part.parse::<u32>()
                .map_err(|_| PowderBundleError::InvalidVersion(version.to_owned()))
        })
        .transpose()?;
    Ok((major, minor, patch))
}

fn required_key<'a>(
    keys: &'a FirmwareKeySet,
    image: &str,
) -> Result<&'a FirmwareKey, PowderBundleError> {
    keys.key(image)
        .ok_or_else(|| PowderBundleError::MissingKeyMaterial(image.to_owned()))
}

/// Component file name: the BuildManifest path basename when available,
/// otherwise the firmware key set's filename, with anything after the first
/// `.dmg` stripped, mirroring `ipsw_prepare_keys`/`ipsw_prepare_paths`.
pub(crate) fn component_name(
    identity: Option<&BuildIdentity>,
    manifest_component: &str,
    key: &FirmwareKey,
) -> String {
    let name = identity
        .and_then(|identity| identity.component_path(manifest_component).ok())
        .map(|path| path.rsplit('/').next().unwrap_or(path))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| key.filename());
    truncate_dmg(name)
}

fn truncate_dmg(name: &str) -> String {
    match name.find(".dmg") {
        Some(index) => name[..index + 4].to_owned(),
        None => name.to_owned(),
    }
}

fn firmware_entry(
    kind: FirmwareComponentKind,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
    patch: bool,
    decrypt_path: Option<String>,
) -> Result<FirmwareEntry, PowderBundleError> {
    let key = required_key(keys, kind.key_image())?;
    let name = component_name(identity, kind.manifest_component(), key);
    let file = if kind.in_dfu() {
        format!("Firmware/dfu/{name}")
    } else if kind.in_all_flash() {
        format!("{all_flash}/{name}")
    } else {
        name
    };
    Ok(FirmwareEntry {
        kind,
        file,
        iv: key.iv().copied(),
        key: key.key().map(<[u8]>::to_vec),
        patch,
        decrypt: true,
        decrypt_path,
    })
}

/// `Firmware` dict of a single-IPSW bundle, mirroring the final `else`
/// branch of `ipsw_prepare_bundle` with `ipsw_prepare_usepowder=1`.
fn single_firmware(
    request: &PowderBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<FirmwareEntry>, PowderBundleError> {
    let version = request.version.as_str();
    let mut entries = Vec::new();
    entries.push(firmware_entry(
        FirmwareComponentKind::Ibss,
        keys,
        identity,
        all_flash,
        true,
        None,
    )?);
    // iOS 4 and lower need no iBEC patch, except on the iPad lineup.
    let needs_ibec = (!version.starts_with('3') && !version.starts_with('4'))
        || request.product_type.as_str() == "iPad1,1"
        || request.product_type.as_str().starts_with("iPad2");
    if needs_ibec {
        entries.push(firmware_entry(
            FirmwareComponentKind::Ibec,
            keys,
            identity,
            all_flash,
            true,
            None,
        )?);
    }
    entries.push(firmware_entry(
        FirmwareComponentKind::RestoreDeviceTree,
        keys,
        identity,
        all_flash,
        false,
        Some("Downgrade/RestoreDeviceTree".to_owned()),
    )?);
    entries.push(firmware_entry(
        FirmwareComponentKind::RestoreKernelCache,
        keys,
        identity,
        all_flash,
        false,
        Some("Downgrade/RestoreKernelCache".to_owned()),
    )?);
    entries.push(firmware_entry(
        FirmwareComponentKind::RestoreRamdisk,
        keys,
        identity,
        all_flash,
        false,
        None,
    )?);
    Ok(entries)
}

/// `Firmware` dict of a target bundle. 4.x targets (the iOS 4.3 powder
/// path) get iBSS plus the Downgrade decrypt set; newer targets add iBEC and
/// select RestoreKernelCache (5/7) or a patched KernelCache (6/8/9).
fn target_firmware(
    request: &PowderBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<FirmwareEntry>, PowderBundleError> {
    let (major, _, _) = version_parts(request.version.as_str())?;
    let mut entries = Vec::new();
    entries.push(firmware_entry(
        FirmwareComponentKind::Ibss,
        keys,
        identity,
        all_flash,
        true,
        None,
    )?);
    if major != 4 {
        entries.push(firmware_entry(
            FirmwareComponentKind::Ibec,
            keys,
            identity,
            all_flash,
            true,
            None,
        )?);
    }
    entries.push(firmware_entry(
        FirmwareComponentKind::RestoreDeviceTree,
        keys,
        identity,
        all_flash,
        false,
        Some("Downgrade/RestoreDeviceTree".to_owned()),
    )?);
    if major == 4 || major == 5 || major == 7 {
        entries.push(firmware_entry(
            FirmwareComponentKind::RestoreKernelCache,
            keys,
            identity,
            all_flash,
            false,
            Some("Downgrade/RestoreKernelCache".to_owned()),
        )?);
    } else {
        entries.push(firmware_entry(
            FirmwareComponentKind::KernelCache,
            keys,
            identity,
            all_flash,
            true,
            None,
        )?);
    }
    entries.push(firmware_entry(
        FirmwareComponentKind::RestoreRamdisk,
        keys,
        identity,
        all_flash,
        false,
        None,
    )?);
    Ok(entries)
}

/// NOR component keys of `ipsw_prepare_paths`, in upstream order.
const BASE_NOR_COMPONENTS: [(&str, &str, &str); 10] = [
    ("AppleLogo", "AppleLogo", "AppleLogo"),
    ("BatteryCharging0", "BatteryCharging0", "BatteryCharging0"),
    ("BatteryCharging1", "BatteryCharging1", "BatteryCharging1"),
    ("BatteryFull", "BatteryFull", "BatteryFull"),
    ("BatteryLow0", "BatteryLow0", "BatteryLow0"),
    ("BatteryLow1", "BatteryLow1", "BatteryLow1"),
    ("BatteryPlugin", "GlyphPlugin", "BatteryPlugin"),
    ("RecoveryMode", "RecoveryMode", "RecoveryMode"),
    ("LLB", "LLB", "LLB"),
    ("iBoot", "iBoot", "iBoot"),
];

/// `FirmwarePath` of a base bundle: plain all_flash paths of the base IPSW's
/// NOR images.
fn base_firmware_paths(
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<NorImagePath>, PowderBundleError> {
    BASE_NOR_COMPONENTS
        .iter()
        .map(|&(component, key_image, manifest_component)| {
            let key = required_key(keys, key_image)?;
            let name = component_name(identity, manifest_component, key);
            Ok(NorImagePath {
                component: component.to_owned(),
                file: format!("{all_flash}/{name}"),
                iv: None,
                key: None,
            })
        })
        .collect()
}

/// `FirmwareReplace` of a target bundle, mirroring `ipsw_prepare_paths
/// <comp> target`: renamed destination paths for AppleLogo/RecoveryMode/
/// iBoot, key material on NewiBoot, and the manifest entry. NewiBoot is
/// skipped on iPad1,1, whose ramdiskH chain boots the iBoot tar's iBEC.
fn target_firmware_replacements(
    request: &PowderBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<NorImagePath>, PowderBundleError> {
    let (major, _, _) = version_parts(request.version.as_str())?;
    let mut entries = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn replacement(
        entries: &mut Vec<NorImagePath>,
        keys: &FirmwareKeySet,
        identity: Option<&BuildIdentity>,
        all_flash: &str,
        component: &str,
        key_image: &str,
        manifest_component: &str,
        rename: impl FnOnce(&str) -> String,
        with_keys: bool,
    ) -> Result<(), PowderBundleError> {
        let key = required_key(keys, key_image)?;
        let name = component_name(identity, manifest_component, key);
        entries.push(NorImagePath {
            component: component.to_owned(),
            file: format!("{all_flash}/{}", rename(&name)),
            iv: if with_keys { key.iv().copied() } else { None },
            key: if with_keys {
                key.key().map(<[u8]>::to_vec)
            } else {
                None
            },
        });
        Ok(())
    }

    if major == 4 {
        replacement(
            &mut entries,
            keys,
            identity,
            all_flash,
            "APTicket",
            "AppleLogo",
            "AppleLogo",
            |name| name.replacen("applelogo", "applelogoT", 1),
            false,
        )?;
    }
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "AppleLogo",
        "AppleLogo",
        "AppleLogo",
        |name| name.replacen("applelogo", "applelogo7", 1),
        false,
    )?;
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "NewAppleLogo",
        "AppleLogo",
        "AppleLogo",
        str::to_owned,
        false,
    )?;
    for &(component, key_image, manifest_component) in &BASE_NOR_COMPONENTS[1..7] {
        replacement(
            &mut entries,
            keys,
            identity,
            all_flash,
            component,
            key_image,
            manifest_component,
            str::to_owned,
            false,
        )?;
    }
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "RecoveryMode",
        "RecoveryMode",
        "RecoveryMode",
        |name| name.replacen("recoverymode", "recoverymode7", 1),
        false,
    )?;
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "NewRecoveryMode",
        "RecoveryMode",
        "RecoveryMode",
        str::to_owned,
        false,
    )?;
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "LLB",
        "LLB",
        "LLB",
        str::to_owned,
        false,
    )?;
    replacement(
        &mut entries,
        keys,
        identity,
        all_flash,
        "iBoot",
        "iBoot",
        "iBoot",
        str::to_owned,
        false,
    )?;
    if request.product_type.as_str() != "iPad1,1" {
        replacement(
            &mut entries,
            keys,
            identity,
            all_flash,
            "NewiBoot",
            "iBoot",
            "iBoot",
            |name| name.replacen("iBoot", "iBoot2", 1),
            true,
        )?;
    }
    entries.push(NorImagePath {
        component: "manifest".to_owned(),
        file: format!("{all_flash}/manifest"),
        iv: None,
        key: None,
    });
    Ok(entries)
}

/// File names appended to the target bundle's manifest by
/// `ipsw_prepare_paths`: the renamed AppleLogo (for iOS 7+ targets or
/// devices whose latest version is iOS 5), APTicket and RecoveryMode
/// renames, and NewiBoot except on iPad1,1.
fn manifest_additions(
    request: &PowderBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
) -> Result<Vec<String>, PowderBundleError> {
    let (target_major, _, _) = version_parts(request.version.as_str())?;
    let (latest_major, _, _) = version_parts(request.latest_version.as_str())?;
    let logo_stuff = latest_major == 5 || matches!(target_major, 7..=9);
    let mut additions = Vec::new();
    let logo_name = component_name(identity, "AppleLogo", required_key(keys, "AppleLogo")?);
    if target_major == 4 {
        additions.push(logo_name.replacen("applelogo", "applelogoT", 1));
    }
    if logo_stuff {
        additions.push(logo_name.replacen("applelogo", "applelogo7", 1));
    }
    let recovery_name = component_name(
        identity,
        "RecoveryMode",
        required_key(keys, "RecoveryMode")?,
    );
    additions.push(recovery_name.replacen("recoverymode", "recoverymode7", 1));
    if request.product_type.as_str() != "iPad1,1" {
        let iboot_name = component_name(identity, "iBoot", required_key(keys, "iBoot")?);
        additions.push(iboot_name.replacen("iBoot", "iBoot2", 1));
    }
    Ok(additions)
}

#[derive(Debug, Error)]
pub enum PowderBundleError {
    #[error("unsupported powdersn0w target {0} {1}")]
    UnsupportedTarget(String, String),
    #[error("invalid iOS version {0}")]
    InvalidVersion(String),
    #[error("missing firmware key material for {0}")]
    MissingKeyMaterial(String),
    #[error("base bundles require the base build id for the exploit mapping")]
    MissingBaseBuild,
    #[error("daibutsu packages only apply to single-IPSW bundles")]
    MisplacedDaibutsu,
    #[error("no greenpois0n untether cataloged for {device} {build}")]
    MissingUntether { device: String, build: String },
    #[error("failed to parse the ramdisk options plist: {0}")]
    OptionsPlist(#[from] plist::Error),
    #[error("ramdisk options plist lacks SystemPartitionSize")]
    MissingSystemPartitionSize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BuildManifest, RestoreBehavior};
    use std::io::Cursor;

    fn key_json(image: &str, filename: &str) -> String {
        format!(
            r#"{{"image":"{image}","filename":"{filename}","iv":"{iv}","key":"{key}","kbag":null}}"#,
            iv = "00".repeat(16),
            key = "11".repeat(32),
        )
    }

    fn test_keys() -> FirmwareKeySet {
        let entries = [
            ("iBSS", "iBSS.n90ap.RELEASE.dfu"),
            ("iBEC", "iBEC.n90ap.RELEASE.dfu"),
            ("DeviceTree", "DeviceTree.n90ap.img3"),
            ("Kernelcache", "kernelcache.release.n90"),
            ("RestoreRamdisk", "048-0000-001.dmg"),
            ("AppleLogo", "applelogo.s5l8930x.img3"),
            ("BatteryCharging0", "batterycharging0.s5l8930x.img3"),
            ("BatteryCharging1", "batterycharging1.s5l8930x.img3"),
            ("BatteryFull", "batteryfull.s5l8930x.img3"),
            ("BatteryLow0", "batterylow0.s5l8930x.img3"),
            ("BatteryLow1", "batterylow1.s5l8930x.img3"),
            ("GlyphPlugin", "glyphplugin.s5l8930x.img3"),
            ("RecoveryMode", "recoverymode.s5l8930x.img3"),
            ("LLB", "LLB.n90ap.RELEASE.img3"),
            ("iBoot", "iBoot.n90ap.RELEASE.img3"),
        ]
        .iter()
        .map(|(image, filename)| key_json(image, filename))
        .collect::<Vec<_>>()
        .join(",");
        let rootfs = format!(
            r#"{{"image":"RootFS","filename":"048-9999-001.dmg","iv":null,"key":"{}","kbag":null}}"#,
            "22".repeat(36)
        );
        FirmwareKeySet::parse(format!(r#"{{"keys":[{entries},{rootfs}]}}"#).as_bytes()).unwrap()
    }

    fn request(role: BundleRole, version: &str, target_version: &str) -> PowderBundleRequest {
        PowderBundleRequest::new(
            role,
            ProductType::from("iPhone3,1"),
            BoardConfig::from("n90"),
            "iPhone3,1_Restore.ipsw",
            IosVersion::from(version),
            IosVersion::from(target_version),
            IosVersion::from("7.1.2"),
            1000,
        )
    }

    fn kinds(bundle: &PowderBundle) -> Vec<FirmwareComponentKind> {
        bundle.firmware().iter().map(FirmwareEntry::kind).collect()
    }

    fn tar_ids(plan: &PowderPayloadPlan) -> Vec<String> {
        plan.tars()
            .iter()
            .map(|tar| match tar {
                PowderTar::Resource(id) => id.as_str().to_owned(),
                PowderTar::SystemVersion => "<systemversion>".to_owned(),
                PowderTar::IBoot => "<iboot>".to_owned(),
            })
            .collect()
    }

    fn payload_request(mode: PowderMode, version: &str, build: &str) -> PowderPayloadRequest {
        PowderPayloadRequest::new(
            mode,
            ProductType::from("iPhone3,1"),
            IosVersion::from(version),
            BuildId::from(build),
        )
    }

    #[test]
    fn single_bundle_firmware_entries() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Single, "7.1.2", "7.1.2"),
            &test_keys(),
            None,
        )
        .unwrap();
        assert_eq!(
            kinds(&bundle),
            [
                FirmwareComponentKind::Ibss,
                FirmwareComponentKind::Ibec,
                FirmwareComponentKind::RestoreDeviceTree,
                FirmwareComponentKind::RestoreKernelCache,
                FirmwareComponentKind::RestoreRamdisk,
            ]
        );
        let ibss = &bundle.firmware()[0];
        assert!(ibss.patch() && ibss.decrypt());
        assert_eq!(ibss.file(), "Firmware/dfu/iBSS.n90ap.RELEASE.dfu");
        let kernel = &bundle.firmware()[3];
        assert!(!kernel.patch());
        assert_eq!(kernel.decrypt_path(), Some("Downgrade/RestoreKernelCache"));
        let devicetree = &bundle.firmware()[2];
        assert_eq!(
            devicetree.file(),
            "Firmware/all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3"
        );
        // Root filesystem: key set filename, key material, size + 30.
        assert_eq!(bundle.root_filesystem(), "048-9999-001.dmg");
        assert_eq!(bundle.root_filesystem_key().len(), 36);
        assert_eq!(bundle.root_filesystem_size_mb(), 1030);
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.n90.plist"
        );
        // Single bundles carry empty packages upstream.
        assert!(bundle.filesystem_package().is_none());
        assert!(bundle.ramdisk_package().is_none());
        assert!(bundle.daibutsu().is_none());
    }

    #[test]
    fn single_bundle_42_has_no_ibec_and_plain_options_plist() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Single, "4.2.1", "4.2.1"),
            &test_keys(),
            None,
        )
        .unwrap();
        assert!(!kinds(&bundle).contains(&FirmwareComponentKind::Ibec));
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.plist"
        );
    }

    #[test]
    fn single_bundle_ipad1_42_keeps_ibec() {
        let req = PowderBundleRequest::new(
            BundleRole::Single,
            ProductType::from("iPad1,1"),
            BoardConfig::from("k48"),
            "iPad1,1_Restore.ipsw",
            IosVersion::from("4.2.1"),
            IosVersion::from("4.2.1"),
            IosVersion::from("5.1.1"),
            1000,
        );
        let bundle = PowderBundle::resolve(&req, &test_keys(), None).unwrap();
        assert!(kinds(&bundle).contains(&FirmwareComponentKind::Ibec));
        // iPad1,1 4.x still uses the per-board options plist.
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.k48.plist"
        );
    }

    #[test]
    fn single_bundle_daibutsu_package() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Single, "8.4.1", "8.4.1")
                .with_jailbreak(true)
                .with_daibutsu(true),
            &test_keys(),
            None,
        )
        .unwrap();
        let daibutsu = bundle.daibutsu().unwrap();
        assert_eq!(daibutsu.ramdisk_package2(), "./bin.tar");
        assert_eq!(daibutsu.ramdisk_reboot(), "./reboot.sh");
        assert_eq!(daibutsu.untether(), "./untether.tar");
        assert_eq!(daibutsu.hwmodel(), "N90");
    }

    #[test]
    fn daibutsu_rejected_for_two_bundle_roles() {
        let req = request(BundleRole::Target, "8.4.1", "8.4.1").with_daibutsu(true);
        assert!(matches!(
            PowderBundle::resolve(&req, &test_keys(), None),
            Err(PowderBundleError::MisplacedDaibutsu)
        ));
    }

    #[test]
    fn target_bundle_8_patches_kernelcache() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Target, "8.4.1", "8.4.1").with_jailbreak(true),
            &test_keys(),
            None,
        )
        .unwrap();
        assert_eq!(
            kinds(&bundle),
            [
                FirmwareComponentKind::Ibss,
                FirmwareComponentKind::Ibec,
                FirmwareComponentKind::RestoreDeviceTree,
                FirmwareComponentKind::KernelCache,
                FirmwareComponentKind::RestoreRamdisk,
            ]
        );
        assert!(bundle.firmware()[3].patch());
        let filesystem = bundle.filesystem_package().unwrap();
        assert_eq!(filesystem.bootstrap(), "freeze.tar");
        assert_eq!(filesystem.package(), Some("src/ios9.tar"));
        let ramdisk = bundle.ramdisk_package().unwrap();
        assert_eq!(ramdisk.package(), "src/bin.tar");
        assert_eq!(ramdisk.ios_marker(), Some(8));
    }

    #[test]
    fn target_bundle_5_decrypts_kernelcache_copy() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Target, "5.1.1", "5.1.1"),
            &test_keys(),
            None,
        )
        .unwrap();
        assert!(kinds(&bundle).contains(&FirmwareComponentKind::RestoreKernelCache));
        assert!(!kinds(&bundle).contains(&FirmwareComponentKind::KernelCache));
        let filesystem = bundle.filesystem_package().unwrap();
        assert_eq!(filesystem.package(), None);
        // No ios marker without jailbreak.
        assert_eq!(bundle.ramdisk_package().unwrap().ios_marker(), None);
    }

    #[test]
    fn target_bundle_ios43_has_no_ibec_and_apticket() {
        let req = PowderBundleRequest::new(
            BundleRole::Target,
            ProductType::from("iPad1,1"),
            BoardConfig::from("k48"),
            "iPad1,1_Restore.ipsw",
            IosVersion::from("4.3.3"),
            IosVersion::from("4.3.3"),
            IosVersion::from("5.1.1"),
            1000,
        );
        let bundle = PowderBundle::resolve(&req, &test_keys(), None).unwrap();
        assert_eq!(
            kinds(&bundle),
            [
                FirmwareComponentKind::Ibss,
                FirmwareComponentKind::RestoreDeviceTree,
                FirmwareComponentKind::RestoreKernelCache,
                FirmwareComponentKind::RestoreRamdisk,
            ]
        );
        let components: Vec<&str> = bundle
            .firmware_replacements()
            .iter()
            .map(NorImagePath::component)
            .collect();
        assert!(components.first() == Some(&"APTicket"));
        // iPad1,1 has no NewiBoot replacement.
        assert!(!components.contains(&"NewiBoot"));
        assert!(components.last() == Some(&"manifest"));
        // Latest is 5.1.1, so the applelogo7 rename is manifest-listed, and
        // APTicket adds applelogoT; NewiBoot is skipped on iPad1,1.
        assert_eq!(
            bundle.manifest_additions(),
            [
                "applelogoT.s5l8930x.img3",
                "applelogo7.s5l8930x.img3",
                "recoverymode7.s5l8930x.img3",
            ]
        );
    }

    #[test]
    fn target_bundle_replacements_rename_nor_images() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Target, "7.1.2", "7.1.2"),
            &test_keys(),
            None,
        )
        .unwrap();
        let find = |component: &str| {
            bundle
                .firmware_replacements()
                .iter()
                .find(|entry| entry.component() == component)
                .unwrap()
        };
        let all_flash = "Firmware/all_flash/all_flash.n90ap.production";
        // 4.x-only APTicket is absent here.
        assert!(
            !bundle
                .firmware_replacements()
                .iter()
                .any(|entry| entry.component() == "APTicket")
        );
        assert_eq!(
            find("AppleLogo").file(),
            format!("{all_flash}/applelogo7.s5l8930x.img3")
        );
        assert_eq!(
            find("NewAppleLogo").file(),
            format!("{all_flash}/applelogo.s5l8930x.img3")
        );
        assert_eq!(
            find("BatteryPlugin").file(),
            format!("{all_flash}/glyphplugin.s5l8930x.img3")
        );
        assert_eq!(
            find("RecoveryMode").file(),
            format!("{all_flash}/recoverymode7.s5l8930x.img3")
        );
        let new_iboot = find("NewiBoot");
        assert_eq!(
            new_iboot.file(),
            format!("{all_flash}/iBoot2.n90ap.RELEASE.img3")
        );
        assert!(new_iboot.iv().is_some() && new_iboot.key().is_some());
        assert_eq!(find("manifest").file(), format!("{all_flash}/manifest"));
        assert_eq!(
            bundle.manifest_additions(),
            [
                "applelogo7.s5l8930x.img3",
                "recoverymode7.s5l8930x.img3",
                "iBoot2.n90ap.RELEASE.img3",
            ]
        );
    }

    #[test]
    fn base_bundle_has_exploit_and_nor_paths() {
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Base, "7.1.2", "8.4.1").with_base_build(BuildId::from("11D257")),
            &test_keys(),
            None,
        )
        .unwrap();
        assert!(bundle.firmware().is_empty());
        assert_eq!(bundle.firmware_paths().len(), 10);
        assert_eq!(
            bundle.firmware_paths()[0].file(),
            "Firmware/all_flash/all_flash.n90ap.production/applelogo.s5l8930x.img3"
        );
        let exploit = bundle.ramdisk_exploit().unwrap();
        assert_eq!(exploit.exploit(), "src/target/n90/11D257/exploit");
        assert_eq!(exploit.inject(), "partition");
        assert_eq!(exploit.resource_id().as_str(), "powder-exploit-n90-11D257");
        // The options path rule keys on the target version even for bases.
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.n90.plist"
        );
        // Root filesystem metadata describes the base IPSW.
        assert_eq!(bundle.root_filesystem(), "048-9999-001.dmg");
    }

    #[test]
    fn base_bundle_requires_base_build() {
        let req = request(BundleRole::Base, "7.1.2", "8.4.1");
        assert!(matches!(
            PowderBundle::resolve(&req, &test_keys(), None),
            Err(PowderBundleError::MissingBaseBuild)
        ));
    }

    #[test]
    fn bundle_names_come_from_build_manifest_when_present() {
        let manifest = BuildManifest::from_reader(Cursor::new(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>ProductVersion</key><string>7.1.2</string>
  <key>ProductBuildVersion</key><string>11D257</string>
  <key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
  <key>BuildIdentities</key><array><dict>
    <key>Info</key><dict>
      <key>DeviceClass</key><string>n90ap</string>
      <key>RestoreBehavior</key><string>Erase</string>
    </dict>
    <key>Manifest</key><dict>
      <key>OS</key><dict><key>Info</key><dict>
        <key>Path</key><string>058-0000-002.dmg</string>
      </dict></dict>
      <key>RestoreRamDisk</key><dict><key>Info</key><dict>
        <key>Path</key><string>058-0000-001.dmg</string>
      </dict></dict>
    </dict>
  </dict></array>
</dict></plist>"#,
        ))
        .unwrap();
        let identity = manifest
            .select_identity(&BoardConfig::from("n90"), RestoreBehavior::Erase)
            .unwrap();
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Single, "7.1.2", "7.1.2"),
            &test_keys(),
            Some(identity),
        )
        .unwrap();
        assert_eq!(bundle.root_filesystem(), "058-0000-002.dmg");
        let ramdisk = &bundle.firmware()[4];
        assert_eq!(ramdisk.file(), "058-0000-001.dmg");
        // Components absent from the manifest fall back to key filenames.
        assert_eq!(
            bundle.firmware()[0].file(),
            "Firmware/dfu/iBSS.n90ap.RELEASE.dfu"
        );
    }

    #[test]
    fn config_gates() {
        let version = |v: &str| IosVersion::from(v);
        // Target bundles: FilesystemJailbreak only for jailbroken 6/8/9.
        let config =
            PowderConfig::resolve(BundleRole::Target, true, &version("8.4.1"), false, None)
                .unwrap()
                .unwrap();
        assert!(config.filesystem_jailbreak() && config.need_pref());
        let config =
            PowderConfig::resolve(BundleRole::Target, true, &version("7.1.2"), false, None)
                .unwrap()
                .unwrap();
        assert!(!config.filesystem_jailbreak() && config.need_pref());
        let config =
            PowderConfig::resolve(BundleRole::Target, false, &version("6.1.3"), false, None)
                .unwrap()
                .unwrap();
        assert!(!config.filesystem_jailbreak() && config.need_pref());
        // Single-IPSW builds never set FilesystemJailbreak; needPref follows
        // the jailbreak flag.
        let config =
            PowderConfig::resolve(BundleRole::Single, true, &version("8.4.1"), false, None)
                .unwrap()
                .unwrap();
        assert!(!config.filesystem_jailbreak() && config.need_pref());
        let config =
            PowderConfig::resolve(BundleRole::Single, false, &version("6.1.3"), false, None)
                .unwrap()
                .unwrap();
        assert!(!config.filesystem_jailbreak() && !config.need_pref());
        // Base bundles carry no config.
        assert!(
            PowderConfig::resolve(BundleRole::Base, true, &version("7.1.2"), false, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn config_boot_args_variants() {
        let version = IosVersion::from("8.4.1");
        let config = PowderConfig::resolve(BundleRole::Target, true, &version, false, None)
            .unwrap()
            .unwrap();
        assert!(!config.boot_args_injection());
        assert_eq!(config.boot_args(), DEFAULT_BOOT_ARGS);
        let config = PowderConfig::resolve(BundleRole::Target, true, &version, true, None)
            .unwrap()
            .unwrap();
        assert!(config.boot_args_injection());
        assert_eq!(config.boot_args(), VERBOSE_BOOT_ARGS);
        let config =
            PowderConfig::resolve(BundleRole::Target, true, &version, false, Some("serial=1"))
                .unwrap()
                .unwrap();
        assert!(config.boot_args_injection());
        assert_eq!(config.boot_args(), format!("{DEFAULT_BOOT_ARGS} serial=1"));
        let config =
            PowderConfig::resolve(BundleRole::Target, true, &version, true, Some("serial=1"))
                .unwrap()
                .unwrap();
        assert_eq!(config.boot_args(), format!("{VERBOSE_BOOT_ARGS} serial=1"));
        // Empty custom args are treated as absent, like upstream's -n test.
        let config = PowderConfig::resolve(BundleRole::Target, true, &version, false, Some(""))
            .unwrap()
            .unwrap();
        assert!(!config.boot_args_injection());
    }

    #[test]
    fn matrix_single_42_punchd() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "4.2.1", "8C148").with_jailbreak(true),
        )
        .unwrap();
        assert!(plan.punchd());
        assert_eq!(
            tar_ids(&plan),
            [
                "greenpois0n-iPhone3-1-8C148",
                "jailbreak-fstab-old",
                "jailbreak-bootstrap-freeze",
            ]
        );
    }

    #[test]
    fn matrix_single_43() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "4.3.5", "8L1").with_jailbreak(true),
        )
        .unwrap();
        assert!(!plan.punchd());
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-aquila-4",
                "jailbreak-fstab-old",
                "jailbreak-bootstrap-freeze",
            ]
        );
    }

    #[test]
    fn matrix_single_5() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "5.1.1", "9B206")
                .with_jailbreak(true)
                .with_openssh(true),
        )
        .unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-aquila-5",
                "jailbreak-fstab-rw",
                "jailbreak-bootstrap-freeze",
                "jailbreak-cydiasubstrate",
                "jailbreak-sshdeb",
                "jailbreak-openssh",
                "jailbreak-openssl",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_6() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "6.1.3", "10B329").with_jailbreak(true),
        )
        .unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-aquila-6",
                "jailbreak-fstab-rw",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_7_daibutsu() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "7.1.2", "11D257").with_jailbreak(true),
        )
        .unwrap();
        let daibutsu = plan.daibutsu().unwrap();
        assert_eq!(daibutsu.bin_tar().as_str(), "jailbreak-daibutsu-bin-tar");
        assert_eq!(daibutsu.untether().as_str(), "jailbreak-aquila-7");
        assert_eq!(daibutsu.reboot_script(), RebootScriptVariant::Aquila);
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-fstab-7",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_8_daibutsu() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "8.4.1", "12H321").with_jailbreak(true),
        )
        .unwrap();
        let daibutsu = plan.daibutsu().unwrap();
        assert_eq!(daibutsu.untether().as_str(), "jailbreak-daibutsu-untether");
        assert_eq!(daibutsu.reboot_script(), RebootScriptVariant::Daibutsu);
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-fstab-8",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_8_a5_uses_everuntether() {
        let req = PowderPayloadRequest::new(
            PowderMode::Single,
            ProductType::from("iPhone4,1"),
            IosVersion::from("8.1"),
            BuildId::from("12B411"),
        )
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert!(plan.daibutsu().is_none());
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-everuntether",
                "jailbreak-fstab-8",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_9() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "9.3.2", "13F69").with_jailbreak(true),
        )
        .unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-everuntether",
                "jailbreak-fstab-8",
                "jailbreak-bootstrap-freeze",
                "jailbreak-launchctl",
                "jailbreak-zebra",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_935_has_no_untether() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "9.3.5", "13G36").with_jailbreak(true),
        )
        .unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-fstab-8",
                "jailbreak-bootstrap-freeze",
                "jailbreak-launchctl",
                "jailbreak-zebra",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_single_non_jailbreak_has_no_tars() {
        let plan =
            PowderPayloadPlan::resolve(&payload_request(PowderMode::Single, "7.1.2", "11D257"))
                .unwrap();
        assert!(plan.tars().is_empty());
        assert!(plan.daibutsu().is_none());
    }

    #[test]
    fn matrix_beta_includes_systemversion_first() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "8.0", "12A4297a")
                .with_jailbreak(true)
                .with_beta(true),
        )
        .unwrap();
        assert_eq!(tar_ids(&plan)[0], "<systemversion>");
    }

    #[test]
    fn matrix_single_iboot_sidecar() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Single, "4.2.1", "8C148")
                .with_jailbreak(true)
                .with_iboot_sidecar(true),
        )
        .unwrap();
        assert_eq!(tar_ids(&plan)[0], "<iboot>");
    }

    #[test]
    fn matrix_two_bundle() {
        // iPhone5,1 8.4.1 on a 7.1.2 base: ramdiskH iBoot.tar, no freeze
        // (bundle FilesystemPackage supplies it), LukeZGD always.
        let req = PowderPayloadRequest::new(
            PowderMode::TwoBundle,
            ProductType::from("iPhone5,1"),
            IosVersion::from("8.4.1"),
            BuildId::from("12H321"),
        )
        .with_base_version(IosVersion::from("7.1.2"))
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert_eq!(tar_ids(&plan), ["<iboot>", "jailbreak-lukezgd"]);

        // iPad2,4 7.1.2 target: aquila_7 plus freeze, no iBoot.tar.
        let req = PowderPayloadRequest::new(
            PowderMode::TwoBundle,
            ProductType::from("iPad2,4"),
            IosVersion::from("7.1.2"),
            BuildId::from("11D257"),
        )
        .with_base_version(IosVersion::from("7.1.2"))
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-aquila-7",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );

        // iPhone5,3 with a 7.0 base is the 5c70 exception: no iBoot.tar.
        let req = PowderPayloadRequest::new(
            PowderMode::TwoBundle,
            ProductType::from("iPhone5,3"),
            IosVersion::from("9.3.2"),
            BuildId::from("13F69"),
        )
        .with_base_version(IosVersion::from("7.0.4"))
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert_eq!(tar_ids(&plan), ["jailbreak-zebra", "jailbreak-lukezgd"]);

        // iPad1,1 5.1.1: iBEC iBoot.tar, aquila_5, cydiasubstrate, freeze.
        let req = PowderPayloadRequest::new(
            PowderMode::TwoBundle,
            ProductType::from("iPad1,1"),
            IosVersion::from("5.1.1"),
            BuildId::from("9B206"),
        )
        .with_base_version(IosVersion::from("5.1.1"))
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "<iboot>",
                "jailbreak-aquila-5",
                "jailbreak-cydiasubstrate",
                "jailbreak-bootstrap-freeze",
                "jailbreak-lukezgd",
            ]
        );
    }

    #[test]
    fn matrix_ios4_powder() {
        let plan = PowderPayloadPlan::resolve(
            &payload_request(PowderMode::Ios4, "4.3.3", "8J2").with_jailbreak(true),
        )
        .unwrap();
        assert_eq!(
            tar_ids(&plan),
            [
                "jailbreak-aquila-4",
                "jailbreak-fstab-old",
                "jailbreak-cydiasubstrate",
                "jailbreak-bootstrap-freeze",
            ]
        );
        // iPad1,1 gets the iBEC iBoot.tar.
        let req = PowderPayloadRequest::new(
            PowderMode::Ios4,
            ProductType::from("iPad1,1"),
            IosVersion::from("4.3.3"),
            BuildId::from("8J2"),
        )
        .with_jailbreak(true);
        let plan = PowderPayloadPlan::resolve(&req).unwrap();
        assert_eq!(tar_ids(&plan)[0], "<iboot>");
    }

    #[test]
    fn matrix_rejects_unsupported_targets() {
        // 4.1 and lower redirect to the classic path.
        assert!(matches!(
            PowderPayloadPlan::resolve(&payload_request(PowderMode::Single, "4.1", "8B117")),
            Err(PowderBundleError::UnsupportedTarget(..))
        ));
        // 10.x needs no custom IPSW.
        assert!(matches!(
            PowderPayloadPlan::resolve(&payload_request(PowderMode::Single, "10.3.3", "14G60")),
            Err(PowderBundleError::UnsupportedTarget(..))
        ));
        // iOS 4 powder is 4.3.x only.
        assert!(matches!(
            PowderPayloadPlan::resolve(&payload_request(PowderMode::Ios4, "5.1.1", "9B206")),
            Err(PowderBundleError::UnsupportedTarget(..))
        ));
        // 4.2.x punchd requires a cataloged greenpois0n tar for the device.
        assert!(
            PowderPayloadPlan::resolve(
                &payload_request(PowderMode::Single, "4.2.1", "8C148").with_jailbreak(true)
            )
            .is_ok()
        );
        let req = PowderPayloadRequest::new(
            PowderMode::Single,
            ProductType::from("iPhone1,2"),
            IosVersion::from("4.2.1"),
            BuildId::from("8C148"),
        )
        .with_jailbreak(true);
        assert!(matches!(
            PowderPayloadPlan::resolve(&req),
            Err(PowderBundleError::MissingUntether { .. })
        ));
    }

    #[test]
    fn exploit_path_mapping() {
        // A5/A5X/A6 devices remap to shared exploit hardware names.
        let path = exploit_path(
            &ProductType::from("iPhone5,1"),
            &BoardConfig::from("n41"),
            false,
            &BuildId::from("11D257"),
        );
        assert_eq!(path, "src/target/iphone5/11D257/exploit");
        let path = exploit_path(
            &ProductType::from("iPhone5,4"),
            &BoardConfig::from("n48"),
            false,
            &BuildId::from("11B554a"),
        );
        assert_eq!(path, "src/target/iphone5b/11B554a/exploit");
        let path = exploit_path(
            &ProductType::from("iPad2,5"),
            &BoardConfig::from("p105"),
            false,
            &BuildId::from("11A465"),
        );
        assert_eq!(path, "src/target/ipad2b/11B554a/exploit");
        // DRA v6 keeps the board name; 6.1.3 builds stay as-is.
        let path = exploit_path(
            &ProductType::from("iPhone4,1"),
            &BoardConfig::from("n94"),
            true,
            &BuildId::from("10B329"),
        );
        assert_eq!(path, "src/target/n94/10B329/exploit");
        // iOS 5 base families collapse to 9A405/9B206.
        let path = exploit_path(
            &ProductType::from("iPad1,1"),
            &BoardConfig::from("k48"),
            false,
            &BuildId::from("9B176"),
        );
        assert_eq!(path, "src/target/k48/9B206/exploit");
        let path = exploit_path(
            &ProductType::from("iPad1,1"),
            &BoardConfig::from("k48"),
            false,
            &BuildId::from("9A334"),
        );
        assert_eq!(path, "src/target/k48/9A405/exploit");
        // Unknown build families (e.g. 8.4.1 bases) fall back to 11D257.
        let path = exploit_path(
            &ProductType::from("iPad3,2"),
            &BoardConfig::from("j2"),
            false,
            &BuildId::from("12H321"),
        );
        assert_eq!(path, "src/target/ipad3/11D257/exploit");
    }

    #[test]
    fn ramdisk_h_gate() {
        assert!(uses_ramdisk_h(&ProductType::from("iPhone5,1"), "7.1.2"));
        assert!(uses_ramdisk_h(&ProductType::from("iPhone5,3"), "7.1.2"));
        assert!(!uses_ramdisk_h(&ProductType::from("iPhone5,3"), "7.0.4"));
        assert!(!uses_ramdisk_h(&ProductType::from("iPad1,1"), "5.1.1"));
    }

    #[test]
    fn partition_script_templating() {
        let template = "#!/bin/sh\n\
                        Exploit_LastSector=\"$((524288/$LogicalSector))\"\n\
                        keep_this_line\n\
                        dd of=$exploitDisk if=/exploit bs=512k count=1\n\
                        nvram boot-ramdisk=\"/a/b/c/disk.dmg\"\n";
        // iOS 5 base: exploit shrinks to 64k and nvram write is dropped.
        let rendered =
            render_partition_script(template, "5.1.1", &ProductType::from("iPhone3,3"), false);
        assert!(rendered.contains("Exploit_LastSector=\"$((65536/$LogicalSector))\""));
        assert!(rendered.contains("dd of=$exploitDisk if=/exploit bs=64k count=1"));
        assert!(!rendered.contains("nvram boot-ramdisk"));
        assert!(rendered.contains("keep_this_line"));
        // iPhone3,1 drops the nvram write on any base.
        let rendered =
            render_partition_script(template, "7.1.2", &ProductType::from("iPhone3,1"), false);
        assert!(!rendered.contains("nvram boot-ramdisk"));
        assert!(rendered.contains("bs=512k"));
        // DRA v6 iPhone4,1 drops the nvram write.
        let rendered =
            render_partition_script(template, "6.1.3", &ProductType::from("iPhone4,1"), true);
        assert!(!rendered.contains("nvram boot-ramdisk"));
        // Otherwise the script is verbatim.
        let rendered =
            render_partition_script(template, "7.1.2", &ProductType::from("iPad2,4"), false);
        assert_eq!(rendered, template);
    }

    #[test]
    fn partition_script_resources() {
        assert_eq!(
            partition_script_resource(true).as_str(),
            "powder-partition-script-iphone5"
        );
        assert_eq!(
            partition_script_resource(false).as_str(),
            "powder-partition-script"
        );
    }

    #[test]
    fn reboot_scripts() {
        let script = reboot_script(
            RebootScriptVariant::Aquila,
            &ProductType::from("iPhone3,1"),
            &BuildId::from("11D257"),
            false,
        );
        assert!(script.starts_with("#!/bin/bash\n"));
        assert!(script.contains(
            "mount_hfs /dev/disk0s1s1 /mnt1; mount_hfs /dev/disk0s1s2 /mnt2; nvram -c\n"
        ));
        assert!(script.contains("ln -sf /aquila /mnt1/usr/libexec/CrashHousekeeping\n"));
        assert!(script.ends_with("/sbin/reboot_\n"));
        assert!(!script.contains("com.openssh.sshd"));

        let script = reboot_script(
            RebootScriptVariant::Aquila,
            &ProductType::from("iPhone3,1"),
            &BuildId::from("11D257"),
            true,
        );
        assert!(script.contains("com.openssh.sshd.plist"));

        let script = reboot_script(
            RebootScriptVariant::Daibutsu,
            &ProductType::from("iPhone3,1"),
            &BuildId::from("12H321"),
            false,
        );
        assert!(script.ends_with("/usr/bin/haxx_overwrite --iPhone3,1_12H321\n"));
    }

    #[test]
    fn systemversion_tar_contains_beta_plist() {
        let archive = system_version_tar(&IosVersion::from("8.0"), &BuildId::from("12A4297a"));
        assert_eq!(&archive[..7], b"System/");
        let text = String::from_utf8_lossy(&archive);
        assert!(text.contains("<key>ProductBuildVersion</key><string>12A4297a</string>"));
        assert!(text.contains("<key>ProductCopyright</key><string>1983-2015 Apple Inc.</string>"));
        assert!(text.contains("<key>ProductVersion</key><string>8.0</string>"));
    }

    #[test]
    fn iboot_tar_names_entry() {
        let archive = iboot_tar("iBEC", b"iboot");
        assert_eq!(&archive[..4], b"iBEC");
        let archive = iboot_tar("iBoot", b"iboot");
        assert_eq!(&archive[..5], b"iBoot");
    }

    #[test]
    fn system_partition_size_parsing() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>SystemPartitionSize</key><integer>1295</integer>
</dict></plist>"#;
        assert_eq!(system_partition_size(plist).unwrap(), 1295);
        let bundle = PowderBundle::resolve(
            &request(BundleRole::Single, "7.1.2", "7.1.2"),
            &test_keys(),
            None,
        );
        // request() uses 1000; the bundle records +30.
        assert_eq!(bundle.unwrap().root_filesystem_size_mb(), 1030);
        assert!(matches!(
            system_partition_size(b"<plist version=\"1.0\"><dict/></plist>"),
            Err(PowderBundleError::MissingSystemPartitionSize)
        ));
    }
}
