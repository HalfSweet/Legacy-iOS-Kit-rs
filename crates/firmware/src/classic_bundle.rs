//! Typed model of the classic xpwn `ipsw` firmware bundle, replacing the
//! `Info.plist` that upstream's `ipsw_prepare_bundle`/`ipsw_prepare_keys`
//! (restore.sh) generate at runtime for old-device (S5L8900 and
//! S5L8720/8920/8922/A4) custom IPSW builds. This is the non-powdersn0w
//! variant; the powder variant lives in [`crate::powder_bundle`].
//!
//! The bundle references bsdiff patches of the upstream
//! `Down_<device>_<version>_<build>.bundle` directories, cataloged as
//! `classic-patch-<device>-<build>-<name>` resources (and
//! `lockdownd-patch-*` for the hacktivation patch). Unlike upstream, which
//! discovers patch files on disk, patch availability is resolved against the
//! resource catalog at planning time: references upstream emits
//! unconditionally (iBoot in old mode, WTF 2) become resolve-time errors when
//! the catalog lacks them, instead of failing inside the `ipsw` tool.
//!
//! The `device_target_build == "14"*`) branch of upstream's emission chain is
//! an A5 (device_proc 5) path and is intentionally not modeled here.

use legacy_ios_assets::{ResourceCatalog, ResourceId};
use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use thiserror::Error;
use tracing::debug;

use crate::manifest::BuildIdentity;
use crate::powder_bundle::{all_flash_dir, component_name, ramdisk_options_path};
use crate::{FirmwareKey, FirmwareKeySet};

/// Processor family of the classic custom IPSW target, mirroring upstream's
/// `device_proc` for the devices the classic `ipsw` tool serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicProcessor {
    /// S5L8900 (iPhone1,1/iPhone1,2/iPod1,1): upstream `device_proc == 1`.
    S5l8900,
    /// S5L8720/8920/8922 and A4: upstream `device_proc == 4`.
    Other,
}

/// Plist keys of the bundle's `FirmwarePatches` dict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicComponent {
    Ibss,
    Ibec,
    IBoot,
    RestoreDeviceTree,
    RestoreKernelCache,
    KernelCache,
    RestoreRamdisk,
    Wtf2,
}

impl ClassicComponent {
    /// Key name in the bundle's `FirmwarePatches` dict (upstream plist
    /// spelling).
    pub const fn plist_name(self) -> &'static str {
        match self {
            Self::Ibss => "iBSS",
            Self::Ibec => "iBEC",
            Self::IBoot => "iBoot",
            Self::RestoreDeviceTree => "RestoreDeviceTree",
            Self::RestoreKernelCache => "RestoreKernelCache",
            Self::KernelCache => "KernelCache",
            Self::RestoreRamdisk => "Restore Ramdisk",
            Self::Wtf2 => "WTF 2",
        }
    }

    /// Image name in a [`FirmwareKeySet`], mirroring upstream's `getcomp`.
    const fn key_image(self) -> &'static str {
        match self {
            Self::Ibss => "iBSS",
            Self::Ibec => "iBEC",
            Self::IBoot => "iBoot",
            Self::RestoreDeviceTree => "DeviceTree",
            Self::RestoreKernelCache | Self::KernelCache => "Kernelcache",
            Self::RestoreRamdisk => "RestoreRamdisk",
            Self::Wtf2 => "",
        }
    }

    /// BuildManifest component name, mirroring upstream's `getcomp_bm`.
    const fn manifest_component(self) -> &'static str {
        match self {
            Self::RestoreRamdisk => "RestoreRamDisk",
            other => other.plist_name(),
        }
    }
}

/// A bsdiff patch of the bundle directory: the patch file name plus its
/// catalog resource id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicPatch {
    file: String,
    resource: ResourceId,
}

impl ClassicPatch {
    /// Patch file name inside the bundle directory (e.g. `asr.patch`).
    pub fn file(&self) -> &str {
        &self.file
    }

    /// Catalog resource id of the patch payload.
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }
}

/// One entry of the bundle's `FirmwarePatches` dict.
#[derive(Clone)]
pub struct ClassicFirmwareEntry {
    component: ClassicComponent,
    file: String,
    iv: Option<[u8; 16]>,
    key: Option<Vec<u8>>,
    patch: Option<ClassicPatch>,
    decrypt: bool,
    decrypt_path: Option<String>,
}

impl ClassicFirmwareEntry {
    pub const fn component(&self) -> ClassicComponent {
        self.component
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

    /// `Patch`: the bundle bsdiff patch, when the component has one.
    pub const fn patch(&self) -> Option<&ClassicPatch> {
        self.patch.as_ref()
    }

    /// `Decrypt=true`: present on every entry except in old mode (upstream
    /// `ipsw_prepare_keys` line 3718).
    pub const fn decrypt(&self) -> bool {
        self.decrypt
    }

    /// `DecryptPath`: decrypted copy destination (e.g.
    /// `Downgrade/RestoreKernelCache`).
    pub fn decrypt_path(&self) -> Option<&str> {
        self.decrypt_path.as_deref()
    }
}

impl std::fmt::Debug for ClassicFirmwareEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClassicFirmwareEntry")
            .field("component", &self.component)
            .field("file", &self.file)
            .field("patch", &self.patch)
            .field("decrypt", &self.decrypt)
            .field("decrypt_path", &self.decrypt_path)
            .finish_non_exhaustive()
    }
}

/// One entry of the bundle's `RamdiskPatches` dict (`asr`,
/// `restoredexternal`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicRamdiskPatch {
    name: String,
    file: String,
    patch: ClassicPatch,
}

impl ClassicRamdiskPatch {
    /// Dict key of the entry (`asr` or `restoredexternal`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Path of the binary inside the restore ramdisk.
    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn patch(&self) -> &ClassicPatch {
        &self.patch
    }
}

/// One `Hacktivation` action of the bundle's `FilesystemPatches` dict.
/// Upstream only ever emits the lockdownd patch action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicFilesystemPatch {
    file: String,
    patch: ClassicPatch,
}

impl ClassicFilesystemPatch {
    /// `Action` of the dict; upstream only emits `Patch`.
    pub const ACTION: &str = "Patch";

    /// Path of the binary inside the root filesystem (`usr/libexec/lockdownd`).
    pub fn file(&self) -> &str {
        &self.file
    }

    pub const fn patch(&self) -> &ClassicPatch {
        &self.patch
    }
}

/// A resolved classic `ipsw` firmware bundle.
#[derive(Clone)]
pub struct ClassicBundle {
    filename: String,
    sha1: String,
    root_filesystem: String,
    root_filesystem_key: Vec<u8>,
    root_filesystem_size_mb: u64,
    ramdisk_options_path: String,
    manifest_path: String,
    bundle_directory: String,
    firmware: Vec<ClassicFirmwareEntry>,
    ramdisk_patches: Option<Vec<ClassicRamdiskPatch>>,
    filesystem_patches: Option<Vec<ClassicFilesystemPatch>>,
}

impl ClassicBundle {
    /// `Filename`: the source IPSW file name.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// `SHA1`: whole-IPSW SHA-1 (lowercase hex), used by the `ipsw` tool to
    /// locate the matching bundle.
    pub fn sha1(&self) -> &str {
        &self.sha1
    }

    /// `RootFilesystem`: root filesystem DMG name.
    pub fn root_filesystem(&self) -> &str {
        &self.root_filesystem
    }

    /// `RootFilesystemKey`: vfdecrypt key of the root filesystem.
    pub fn root_filesystem_key(&self) -> &[u8] {
        &self.root_filesystem_key
    }

    /// `RootFilesystemSize` in MB, per the version/device rules of
    /// `ipsw_prepare_bundle`: 3.2 targets get 1030, other 3.x targets get
    /// 450 (iPhone1,\*/iPod1,1), 480 (iPod2,1), or 780, and newer targets get
    /// the ramdisk options plist's `SystemPartitionSize` — each plus 30.
    pub const fn root_filesystem_size_mb(&self) -> u64 {
        self.root_filesystem_size_mb
    }

    /// `RamdiskOptionsPath`: path of the options plist inside the restore
    /// ramdisk.
    pub fn ramdisk_options_path(&self) -> &str {
        &self.ramdisk_options_path
    }

    /// Path of the all_flash NOR manifest inside the source IPSW; the bundle
    /// ships a copy of this file.
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    /// Name of the upstream bundle directory this bundle mirrors
    /// (`Down_<device>_<version>_<build>.bundle`).
    pub fn bundle_directory(&self) -> &str {
        &self.bundle_directory
    }

    /// `FirmwarePatches` dict entries, in upstream emission order.
    pub fn firmware(&self) -> &[ClassicFirmwareEntry] {
        &self.firmware
    }

    /// `RamdiskPatches` dict entries. `None` when upstream emits the key not
    /// at all (no `Down_*` bundle for the target); `Some` entries are `asr`
    /// plus `restoredexternal` when its patch exists. Empty for betas.
    pub fn ramdisk_patches(&self) -> Option<&[ClassicRamdiskPatch]> {
        self.ramdisk_patches.as_deref()
    }

    /// `Hacktivation` array of the `FilesystemPatches` dict. `None` when
    /// upstream emits no `FilesystemPatches` key; `Some` (possibly empty)
    /// otherwise. The empty case matters: upstream documents that the `ipsw`
    /// tool segfaults when the key is missing from a bundle that carries
    /// `RamdiskPatches`.
    pub fn filesystem_patches(&self) -> Option<&[ClassicFilesystemPatch]> {
        self.filesystem_patches.as_deref()
    }
}

impl std::fmt::Debug for ClassicBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClassicBundle")
            .field("filename", &self.filename)
            .field("root_filesystem", &self.root_filesystem)
            .field("root_filesystem_size_mb", &self.root_filesystem_size_mb)
            .field("ramdisk_options_path", &self.ramdisk_options_path)
            .field("manifest_path", &self.manifest_path)
            .field("bundle_directory", &self.bundle_directory)
            .field("firmware", &self.firmware)
            .field("ramdisk_patches", &self.ramdisk_patches)
            .field("filesystem_patches", &self.filesystem_patches)
            .finish_non_exhaustive()
    }
}

/// Inputs for [`ClassicBundle::resolve`], mirroring the device/target state
/// `ipsw_prepare_bundle` reads for classic (non-powdersn0w) builds.
#[derive(Clone, Debug)]
pub struct ClassicBundleRequest {
    product_type: ProductType,
    board_config: BoardConfig,
    processor: ClassicProcessor,
    filename: String,
    version: IosVersion,
    build: BuildId,
    latest_version: IosVersion,
    sha1: String,
    system_partition_size_mb: Option<u64>,
    old: bool,
    hacktivate: bool,
    beta: bool,
    pwn24kpwn_old_bootrom: bool,
}

impl ClassicBundleRequest {
    /// `version`/`build` describe the target IPSW (`device_target_vers`/
    /// `device_target_build`); `sha1` is its whole-IPSW SHA-1.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product_type: ProductType,
        board_config: BoardConfig,
        processor: ClassicProcessor,
        filename: impl Into<String>,
        version: IosVersion,
        build: BuildId,
        latest_version: IosVersion,
        sha1: impl Into<String>,
    ) -> Self {
        Self {
            product_type,
            board_config,
            processor,
            filename: filename.into(),
            version,
            build,
            latest_version,
            sha1: sha1.into(),
            system_partition_size_mb: None,
            old: false,
            hacktivate: false,
            beta: false,
            pwn24kpwn_old_bootrom: false,
        }
    }

    /// Old mode: `ipsw_prepare_jailbreak old`. Omits `Decrypt` on every
    /// `FirmwarePatches` entry and enables the old-mode entry matrix
    /// (iBoot/KernelCache/WTF 2 additions).
    pub fn with_old(mut self, enabled: bool) -> Self {
        self.old = enabled;
        self
    }

    /// Latest iOS version of the device (`device_latest_vers`); the old-mode
    /// matrix skips iBoot/KernelCache when the target equals it.
    pub fn with_latest(mut self, version: IosVersion) -> Self {
        self.latest_version = version;
        self
    }

    /// Mirror of upstream's `ipsw_hacktivate`: patch lockdownd in the root
    /// filesystem.
    pub fn with_hacktivate(mut self, enabled: bool) -> Self {
        self.hacktivate = enabled;
        self
    }

    /// Beta target (`ipsw_isbeta`): empty `RamdiskPatches`/
    /// `FilesystemPatches` and a reduced `FirmwarePatches` set.
    pub fn with_beta(mut self, enabled: bool) -> Self {
        self.beta = enabled;
        self
    }

    /// Mirror of upstream's `ipsw_24o`: the 24kpwn old-bootrom iPod2,1 path,
    /// adding iBoot/KernelCache entries in old mode.
    pub fn with_24kpwn_old_bootrom(mut self, enabled: bool) -> Self {
        self.pwn24kpwn_old_bootrom = enabled;
        self
    }

    /// `SystemPartitionSize` of the target's restore ramdisk options plist,
    /// required for non-3.x targets. Extract it with
    /// [`crate::system_partition_size`].
    pub fn with_system_partition_size(mut self, size_mb: u64) -> Self {
        self.system_partition_size_mb = Some(size_mb);
        self
    }
}

impl ClassicBundle {
    /// Resolve a bundle, mirroring the non-powder branches of
    /// `ipsw_prepare_bundle`. `keys` and `identity` describe the target IPSW;
    /// `identity` may be absent (upstream never extracts BuildManifest for
    /// S5L8900 targets), in which case component file names fall back to the
    /// firmware key set.
    pub fn resolve(
        request: &ClassicBundleRequest,
        keys: &FirmwareKeySet,
        identity: Option<&BuildIdentity>,
    ) -> Result<Self, ClassicBundleError> {
        let version = request.version.as_str();
        let (major, _, _) = version_parts(version)?;
        validate_sha1(&request.sha1)?;
        let all_flash = all_flash_dir(&request.board_config);

        let rootfs = required_key(keys, "RootFS")?;
        let root_filesystem = component_name(identity, "OS", rootfs);
        let root_filesystem_key = rootfs
            .key()
            .ok_or_else(|| ClassicBundleError::MissingKeyMaterial("RootFS".to_owned()))?
            .to_vec();

        let root_base_mb = if version.starts_with("3.2") {
            1000
        } else if major == 3 {
            match request.product_type.as_str() {
                "iPhone1,1" | "iPhone1,2" | "iPod1,1" => 420,
                "iPod2,1" => 450,
                _ => 750,
            }
        } else {
            request
                .system_partition_size_mb
                .ok_or(ClassicBundleError::MissingSystemPartitionSize)?
        };

        let bundle_directory = format!(
            "Down_{}_{}_{}.bundle",
            request.product_type.as_str(),
            version,
            request.build.as_str()
        );

        let firmware = if request.beta {
            beta_firmware(request, keys, identity, &all_flash)?
        } else {
            classic_firmware(request, keys, identity, &all_flash)?
        };

        let (ramdisk_patches, filesystem_patches) = if request.beta {
            (Some(Vec::new()), Some(Vec::new()))
        } else if let Some(asr) = catalog_patch(request, "asr.patch") {
            let mut ramdisk = vec![ClassicRamdiskPatch {
                name: "asr".to_owned(),
                file: "usr/sbin/asr".to_owned(),
                patch: asr,
            }];
            if let Some(restoredexternal) = catalog_patch(request, "restoredexternal.patch") {
                ramdisk.push(ClassicRamdiskPatch {
                    name: "restoredexternal".to_owned(),
                    file: "usr/local/bin/restored_external".to_owned(),
                    patch: restoredexternal,
                });
            }
            let filesystem = if request.hacktivate {
                vec![ClassicFilesystemPatch {
                    file: "usr/libexec/lockdownd".to_owned(),
                    patch: require_lockdownd_patch(request)?,
                }]
            } else {
                // Emitted as an empty dict upstream; the `ipsw` tool
                // segfaults when the key is missing entirely.
                Vec::new()
            };
            (Some(ramdisk), Some(filesystem))
        } else {
            (None, None)
        };

        let bundle = Self {
            filename: request.filename.clone(),
            sha1: request.sha1.clone(),
            root_filesystem,
            root_filesystem_key,
            root_filesystem_size_mb: root_base_mb + 30,
            ramdisk_options_path: ramdisk_options_path(
                &request.product_type,
                &request.board_config,
                version,
            ),
            manifest_path: format!("{all_flash}/manifest"),
            bundle_directory,
            firmware,
            ramdisk_patches,
            filesystem_patches,
        };
        debug!(
            version,
            old = request.old,
            beta = request.beta,
            "resolved classic firmware bundle"
        );
        Ok(bundle)
    }
}

/// The reduced `FirmwarePatches` set of a beta bundle (`ipsw_isbeta`), with
/// empty ramdisk/filesystem patch dicts: RestoreDeviceTree,
/// RestoreKernelCache, and the restore ramdisk.
fn beta_firmware(
    request: &ClassicBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<ClassicFirmwareEntry>, ClassicBundleError> {
    let decrypt = !request.old;
    Ok(vec![
        firmware_entry(
            ClassicComponent::RestoreDeviceTree,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            Some("Downgrade/RestoreDeviceTree".to_owned()),
        )?,
        firmware_entry(
            ClassicComponent::RestoreKernelCache,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            Some("Downgrade/RestoreKernelCache".to_owned()),
        )?,
        firmware_entry(
            ClassicComponent::RestoreRamdisk,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            None,
        )?,
    ])
}

/// The full classic `FirmwarePatches` matrix: iBSS always; iBEC except on
/// 3.x/4.x non-iPad targets; RestoreDeviceTree except on S5L8900 targets
/// other than 4.2.1; RestoreKernelCache except on S5L8900 non-4.2.1 and
/// 3.0.x targets; Restore Ramdisk (whose key material decrypts the ramdisk
/// for the ramdisk patches); then the old-mode additions.
fn classic_firmware(
    request: &ClassicBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
) -> Result<Vec<ClassicFirmwareEntry>, ClassicBundleError> {
    let version = request.version.as_str();
    let decrypt = !request.old;
    let mut entries = Vec::new();
    entries.push(firmware_entry(
        ClassicComponent::Ibss,
        request,
        keys,
        identity,
        all_flash,
        decrypt,
        None,
    )?);
    // iOS 4 and lower do not need iBEC patches; the iPad lineup is excepted.
    let needs_ibec = (!version.starts_with('3') && !version.starts_with('4'))
        || request.product_type.as_str() == "iPad1,1"
        || request.product_type.as_str().starts_with("iPad2");
    if needs_ibec {
        entries.push(firmware_entry(
            ClassicComponent::Ibec,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            None,
        )?);
    }
    let s5l8900 = request.processor == ClassicProcessor::S5l8900;
    if !(s5l8900 && version != "4.2.1") {
        entries.push(firmware_entry(
            ClassicComponent::RestoreDeviceTree,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            Some("Downgrade/RestoreDeviceTree".to_owned()),
        )?);
    }
    if (s5l8900 && version == "4.2.1") || (!s5l8900 && !version.starts_with("3.0")) {
        entries.push(firmware_entry(
            ClassicComponent::RestoreKernelCache,
            request,
            keys,
            identity,
            all_flash,
            decrypt,
            Some("Downgrade/RestoreKernelCache".to_owned()),
        )?);
    }
    entries.push(firmware_entry(
        ClassicComponent::RestoreRamdisk,
        request,
        keys,
        identity,
        all_flash,
        decrypt,
        None,
    )?);

    if request.old {
        if request.pwn24kpwn_old_bootrom {
            // Old-bootrom iPod2,1: patch iBoot and the kernelcache.
            entries.push(firmware_entry(
                ClassicComponent::IBoot,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
            entries.push(firmware_entry(
                ClassicComponent::KernelCache,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
        } else if request.product_type.as_str() == "iPod2,1" && version == "3.1.3" {
            // New-bootrom iPod2,1 3.1.3: do not patch iBoot/kernelcache.
        } else if s5l8900 {
            entries.push(firmware_entry(
                ClassicComponent::KernelCache,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
            entries.push(firmware_entry(
                ClassicComponent::Wtf2,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
        } else if version == request.latest_version.as_str() || version == "4.1" {
            // Latest and 4.1 targets need no iBoot/kernelcache patches.
        } else if version.starts_with("3.0") {
            entries.push(firmware_entry(
                ClassicComponent::IBoot,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
        } else {
            entries.push(firmware_entry(
                ClassicComponent::IBoot,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
            entries.push(firmware_entry(
                ClassicComponent::KernelCache,
                request,
                keys,
                identity,
                all_flash,
                decrypt,
                None,
            )?);
        }
    }
    Ok(entries)
}

fn firmware_entry(
    component: ClassicComponent,
    request: &ClassicBundleRequest,
    keys: &FirmwareKeySet,
    identity: Option<&BuildIdentity>,
    all_flash: &str,
    decrypt: bool,
    decrypt_path: Option<String>,
) -> Result<ClassicFirmwareEntry, ClassicBundleError> {
    if component == ClassicComponent::Wtf2 {
        // The S5L8900 WTF image has a fixed name, no key material, and is
        // always patched into the Pwnage 2.0 exploit image.
        return Ok(ClassicFirmwareEntry {
            component,
            file: "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu".to_owned(),
            iv: None,
            key: None,
            patch: Some(require_patch(request, "WTF.s5l8900xall.RELEASE.patch")?),
            decrypt,
            decrypt_path,
        });
    }

    let key = keys.key(component.key_image());
    let name = match key {
        Some(key) => component_name(identity, component.manifest_component(), key),
        None if request.processor == ClassicProcessor::S5l8900
            && matches!(component, ClassicComponent::Ibss | ClassicComponent::Ibec) =>
        {
            // Upstream falls back to the deterministic DFU file name for
            // S5L8900 devices instead of erroring.
            format!(
                "{}.{}ap.RELEASE.dfu",
                component.key_image(),
                request.board_config.as_str()
            )
        }
        None => {
            return Err(ClassicBundleError::MissingKeyMaterial(
                component.key_image().to_owned(),
            ));
        }
    };

    let file = match component {
        ClassicComponent::Ibss | ClassicComponent::Ibec => format!("Firmware/dfu/{name}"),
        ClassicComponent::IBoot | ClassicComponent::RestoreDeviceTree => {
            format!("{all_flash}/{name}")
        }
        _ => name,
    };

    // iBSS/iBEC carry key material only when both IV and key are known
    // (upstream's `-n $iv && -n $key` guard); the other components attach
    // whatever is present.
    let (iv, key_material) = match (component, key) {
        (ClassicComponent::Ibss | ClassicComponent::Ibec, Some(key)) => {
            match (key.iv(), key.key()) {
                (Some(iv), Some(key_material)) => (Some(*iv), Some(key_material.to_vec())),
                _ => (None, None),
            }
        }
        (_, Some(key)) => (key.iv().copied(), key.key().map(<[u8]>::to_vec)),
        (_, None) => (None, None),
    };

    let patch = match component {
        ClassicComponent::Ibss | ClassicComponent::Ibec | ClassicComponent::IBoot => {
            let patch_file = format!(
                "{}.{}ap.RELEASE.patch",
                component.key_image(),
                request.board_config.as_str()
            );
            // Upstream emits the iBoot patch reference unconditionally; check
            // iBSS/iBEC patch availability like upstream's `-s` test and fail
            // early when a referenced patch is not cataloged.
            if component == ClassicComponent::IBoot {
                Some(require_patch(request, &patch_file)?)
            } else {
                catalog_patch(request, &patch_file)
            }
        }
        ClassicComponent::KernelCache => catalog_patch(request, "kernelcache.release.patch"),
        _ => None,
    };

    Ok(ClassicFirmwareEntry {
        component,
        file,
        iv,
        key: key_material,
        patch,
        decrypt,
        decrypt_path,
    })
}

/// Catalog resource id of a bundle patch file:
/// `classic-patch-<device>-<build>-<name>`.
fn patch_id(request: &ClassicBundleRequest, patch_file: &str) -> ResourceId {
    ResourceId::new(format!(
        "classic-patch-{}-{}-{}",
        request.product_type.as_str().replace(',', "-"),
        request.build.as_str(),
        patch_file.strip_suffix(".patch").unwrap_or(patch_file)
    ))
}

/// The patch reference when the catalog carries the patch, mirroring
/// upstream's `[[ -s $FirmwareBundle/<patch> ]]` tests.
fn catalog_patch(request: &ClassicBundleRequest, patch_file: &str) -> Option<ClassicPatch> {
    let id = patch_id(request, patch_file);
    ResourceCatalog::bundled().get(&id)?;
    Some(ClassicPatch {
        file: patch_file.to_owned(),
        resource: id,
    })
}

/// The patch reference, failing when the catalog lacks it. Used where
/// upstream references the patch unconditionally and the `ipsw` tool would
/// fail at runtime instead.
fn require_patch(
    request: &ClassicBundleRequest,
    patch_file: &str,
) -> Result<ClassicPatch, ClassicBundleError> {
    catalog_patch(request, patch_file).ok_or_else(|| ClassicBundleError::MissingPatch {
        device: request.product_type.as_str().to_owned(),
        build: request.build.as_str().to_owned(),
        patch: patch_file.to_owned(),
    })
}

/// The hacktivation patch reference, using the `lockdownd-patch-*` id scheme
/// (which, unlike the other classic patches, includes the version).
fn require_lockdownd_patch(
    request: &ClassicBundleRequest,
) -> Result<ClassicPatch, ClassicBundleError> {
    let id = ResourceId::new(format!(
        "lockdownd-patch-{}-{}-{}",
        request.product_type.as_str().replace(',', "-"),
        request.version.as_str(),
        request.build.as_str()
    ));
    if ResourceCatalog::bundled().get(&id).is_none() {
        return Err(ClassicBundleError::MissingPatch {
            device: request.product_type.as_str().to_owned(),
            build: request.build.as_str().to_owned(),
            patch: "lockdownd.patch".to_owned(),
        });
    }
    Ok(ClassicPatch {
        file: "lockdownd.patch".to_owned(),
        resource: id,
    })
}

fn required_key<'a>(
    keys: &'a FirmwareKeySet,
    image: &str,
) -> Result<&'a FirmwareKey, ClassicBundleError> {
    keys.key(image)
        .ok_or_else(|| ClassicBundleError::MissingKeyMaterial(image.to_owned()))
}

fn version_parts(version: &str) -> Result<(u32, u32, Option<u32>), ClassicBundleError> {
    let mut parts = version.split('.');
    let parse = |part: Option<&str>| {
        part.and_then(|part| part.parse::<u32>().ok())
            .ok_or_else(|| ClassicBundleError::InvalidVersion(version.to_owned()))
    };
    let major = parse(parts.next())?;
    let minor = parse(parts.next())?;
    let patch = parts
        .next()
        .map(|part| {
            part.parse::<u32>()
                .map_err(|_| ClassicBundleError::InvalidVersion(version.to_owned()))
        })
        .transpose()?;
    Ok((major, minor, patch))
}

fn validate_sha1(sha1: &str) -> Result<(), ClassicBundleError> {
    if sha1.len() == 40 && sha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ClassicBundleError::InvalidSha1(sha1.to_owned()))
    }
}

#[derive(Debug, Error)]
pub enum ClassicBundleError {
    #[error("invalid iOS version {0}")]
    InvalidVersion(String),
    #[error("invalid whole-IPSW SHA-1 {0}")]
    InvalidSha1(String),
    #[error("missing firmware key material for {0}")]
    MissingKeyMaterial(String),
    #[error("non-3.x targets require the ramdisk SystemPartitionSize")]
    MissingSystemPartitionSize,
    #[error("no classic bundle patch cataloged for {device} {build}: {patch}")]
    MissingPatch {
        device: String,
        build: String,
        patch: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn key_json(image: &str, filename: &str) -> String {
        format!(
            r#"{{"image":"{image}","filename":"{filename}","iv":"{iv}","key":"{key}","kbag":null}}"#,
            iv = "00".repeat(16),
            key = "11".repeat(32),
        )
    }

    fn test_keys(board: &str) -> FirmwareKeySet {
        let entries = [
            ("iBSS", format!("iBSS.{board}ap.RELEASE.dfu")),
            ("iBEC", format!("iBEC.{board}ap.RELEASE.dfu")),
            ("DeviceTree", format!("DeviceTree.{board}ap.img3")),
            ("Kernelcache", format!("kernelcache.release.{board}")),
            ("RestoreRamdisk", "018-6494-014.dmg".to_owned()),
            ("iBoot", format!("iBoot.{board}ap.RELEASE.img3")),
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

    fn request(device: &str, board: &str, version: &str, build: &str) -> ClassicBundleRequest {
        ClassicBundleRequest::new(
            ProductType::from(device),
            BoardConfig::from(board),
            ClassicProcessor::Other,
            format!("{device}_{version}_{build}_Restore.ipsw"),
            IosVersion::from(version),
            BuildId::from(build),
            IosVersion::from("6.1.6"),
            SHA1,
        )
    }

    fn s5l8900_request(
        device: &str,
        board: &str,
        version: &str,
        build: &str,
    ) -> ClassicBundleRequest {
        let mut request = request(device, board, version, build);
        request.processor = ClassicProcessor::S5l8900;
        request
    }

    fn components(bundle: &ClassicBundle) -> Vec<ClassicComponent> {
        bundle
            .firmware()
            .iter()
            .map(|entry| entry.component())
            .collect()
    }

    use ClassicComponent::*;

    #[test]
    fn old_mode_iphone2_1_313_full_matrix() {
        let bundle = ClassicBundle::resolve(
            &request("iPhone2,1", "n88", "3.1.3", "7E18").with_old(true),
            &test_keys("n88"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [
                Ibss,
                RestoreDeviceTree,
                RestoreKernelCache,
                RestoreRamdisk,
                IBoot,
                KernelCache
            ]
        );
        // Old mode: no Decrypt on any entry.
        assert!(bundle.firmware().iter().all(|entry| !entry.decrypt()));
        let ibss = &bundle.firmware()[0];
        assert_eq!(ibss.file(), "Firmware/dfu/iBSS.n88ap.RELEASE.dfu");
        assert_eq!(
            ibss.patch().unwrap().resource().as_str(),
            "classic-patch-iPhone2-1-7E18-iBSS.n88ap.RELEASE"
        );
        let devicetree = &bundle.firmware()[1];
        assert_eq!(
            devicetree.file(),
            "Firmware/all_flash/all_flash.n88ap.production/DeviceTree.n88ap.img3"
        );
        assert_eq!(
            devicetree.decrypt_path(),
            Some("Downgrade/RestoreDeviceTree")
        );
        assert!(devicetree.patch().is_none());
        let iboot = &bundle.firmware()[4];
        assert_eq!(
            iboot.patch().unwrap().resource().as_str(),
            "classic-patch-iPhone2-1-7E18-iBoot.n88ap.RELEASE"
        );
        let kernelcache = &bundle.firmware()[5];
        assert_eq!(kernelcache.file(), "kernelcache.release.n88");
        assert_eq!(
            kernelcache.patch().unwrap().resource().as_str(),
            "classic-patch-iPhone2-1-7E18-kernelcache.release"
        );
        // 3.x root size rule: iPhone2,1 -> 750 + 30.
        assert_eq!(bundle.root_filesystem_size_mb(), 780);
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.plist"
        );
        assert_eq!(
            bundle.bundle_directory(),
            "Down_iPhone2,1_3.1.3_7E18.bundle"
        );
        assert_eq!(
            bundle.manifest_path(),
            "Firmware/all_flash/all_flash.n88ap.production/manifest"
        );
        // The 7E18 bundle has no restoredexternal patch.
        let ramdisk = bundle.ramdisk_patches().unwrap();
        assert_eq!(ramdisk.len(), 1);
        assert_eq!(ramdisk[0].name(), "asr");
        assert_eq!(ramdisk[0].file(), "usr/sbin/asr");
        assert_eq!(
            ramdisk[0].patch().resource().as_str(),
            "classic-patch-iPhone2-1-7E18-asr"
        );
        assert_eq!(bundle.filesystem_patches(), Some([].as_slice()));
    }

    #[test]
    fn old_mode_ipod2_1_313_new_bootrom_skips_iboot_and_kernelcache() {
        let bundle = ClassicBundle::resolve(
            &request("iPod2,1", "n72", "3.1.3", "7E18")
                .with_old(true)
                .with_latest(IosVersion::from("4.2.1")),
            &test_keys("n72"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [Ibss, RestoreDeviceTree, RestoreKernelCache, RestoreRamdisk]
        );
        // 3.x root size rule: iPod2,1 -> 450 + 30.
        assert_eq!(bundle.root_filesystem_size_mb(), 480);
    }

    #[test]
    fn old_mode_ipod2_1_313_old_bootrom_24kpwn_adds_iboot_and_kernelcache() {
        let bundle = ClassicBundle::resolve(
            &request("iPod2,1", "n72", "3.1.3", "7E18")
                .with_old(true)
                .with_latest(IosVersion::from("4.2.1"))
                .with_24kpwn_old_bootrom(true),
            &test_keys("n72"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [
                Ibss,
                RestoreDeviceTree,
                RestoreKernelCache,
                RestoreRamdisk,
                IBoot,
                KernelCache
            ]
        );
    }

    #[test]
    fn old_mode_iphone2_1_30_patches_iboot_only() {
        let bundle = ClassicBundle::resolve(
            &request("iPhone2,1", "n88", "3.0", "7A341").with_old(true),
            &test_keys("n88"),
            None,
        )
        .unwrap();
        // 3.0.x targets skip RestoreKernelCache and patch only iBoot.
        assert_eq!(
            components(&bundle),
            [Ibss, RestoreDeviceTree, RestoreRamdisk, IBoot]
        );
    }

    #[test]
    fn old_mode_iphone2_1_41_has_no_extras() {
        let bundle = ClassicBundle::resolve(
            &request("iPhone2,1", "n88", "4.1", "8B117")
                .with_old(true)
                .with_system_partition_size(700),
            &test_keys("n88"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [Ibss, RestoreDeviceTree, RestoreKernelCache, RestoreRamdisk]
        );
    }

    #[test]
    fn old_mode_s5l8900_313_adds_kernelcache_and_wtf2() {
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,2", "n82", "3.1.3", "7E18").with_old(true),
            &test_keys("n82"),
            None,
        )
        .unwrap();
        // S5L8900 non-4.2.1: no RestoreDeviceTree/RestoreKernelCache.
        assert_eq!(
            components(&bundle),
            [Ibss, RestoreRamdisk, KernelCache, Wtf2]
        );
        let wtf = &bundle.firmware()[3];
        assert_eq!(wtf.file(), "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu");
        assert!(wtf.iv().is_none() && wtf.key().is_none());
        assert!(!wtf.decrypt());
        assert_eq!(
            wtf.patch().unwrap().resource().as_str(),
            "classic-patch-iPhone1-2-7E18-WTF.s5l8900xall.RELEASE"
        );
    }

    #[test]
    fn old_mode_s5l8900_421_keeps_restore_devicetree() {
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,2", "n82", "4.2.1", "8C148")
                .with_old(true)
                .with_system_partition_size(700),
            &test_keys("n82"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [
                Ibss,
                RestoreDeviceTree,
                RestoreKernelCache,
                RestoreRamdisk,
                KernelCache,
                Wtf2
            ]
        );
        assert_eq!(bundle.root_filesystem_size_mb(), 730);
    }

    #[test]
    fn s5l8900_ibss_falls_back_to_deterministic_name() {
        // Without iBSS key material, S5L8900 targets fall back to the
        // deterministic DFU file name instead of erroring.
        let rootfs = format!(
            r#"{{"image":"RootFS","filename":"048-9999-001.dmg","iv":null,"key":"{}","kbag":null}}"#,
            "22".repeat(36)
        );
        let keys = FirmwareKeySet::parse(
            format!(
                r#"{{"keys":[{},{},{}]}}"#,
                key_json("Kernelcache", "kernelcache.release.n82"),
                key_json("RestoreRamdisk", "018-6494-014.dmg"),
                rootfs
            )
            .as_bytes(),
        )
        .unwrap();
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,2", "n82", "3.1.3", "7E18").with_old(true),
            &keys,
            None,
        )
        .unwrap();
        let ibss = &bundle.firmware()[0];
        assert_eq!(ibss.file(), "Firmware/dfu/iBSS.n82ap.RELEASE.dfu");
        assert!(ibss.iv().is_none() && ibss.key().is_none());
    }

    #[test]
    fn non_old_ipad1_1_32_keeps_ibec_and_decrypts() {
        let bundle = ClassicBundle::resolve(
            &request("iPad1,1", "k48", "3.2", "7B367"),
            &test_keys("k48"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [
                Ibss,
                Ibec,
                RestoreDeviceTree,
                RestoreKernelCache,
                RestoreRamdisk
            ]
        );
        assert!(bundle.firmware().iter().all(|entry| entry.decrypt()));
        // 3.2 targets: root size 1000 + 30, no SystemPartitionSize needed.
        assert_eq!(bundle.root_filesystem_size_mb(), 1030);
        // 3.x targets use the shared options plist even on iPad1,1.
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.plist"
        );
        let ramdisk = bundle.ramdisk_patches().unwrap();
        assert_eq!(ramdisk.len(), 2);
        assert_eq!(ramdisk[1].name(), "restoredexternal");
        assert_eq!(ramdisk[1].file(), "usr/local/bin/restored_external");
    }

    #[test]
    fn non_old_iphone2_1_616_latest() {
        let bundle = ClassicBundle::resolve(
            &request("iPhone2,1", "n88", "6.1.6", "10B500").with_system_partition_size(1000),
            &test_keys("n88"),
            None,
        )
        .unwrap();
        // 6.x targets include iBEC; non-old mode decrypts everything.
        assert_eq!(
            components(&bundle),
            [
                Ibss,
                Ibec,
                RestoreDeviceTree,
                RestoreKernelCache,
                RestoreRamdisk
            ]
        );
        assert!(bundle.firmware().iter().all(|entry| entry.decrypt()));
        assert_eq!(bundle.root_filesystem_size_mb(), 1030);
        assert_eq!(
            bundle.ramdisk_options_path(),
            "/usr/local/share/restore/options.n88.plist"
        );
        // The 10B500 bundle has no restoredexternal patch.
        assert_eq!(bundle.ramdisk_patches().unwrap().len(), 1);
    }

    #[test]
    fn beta_bundle_reduces_firmware_patches() {
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,2", "n82", "4.0", "8A230m")
                .with_beta(true)
                .with_system_partition_size(500),
            &test_keys("n82"),
            None,
        )
        .unwrap();
        assert_eq!(
            components(&bundle),
            [RestoreDeviceTree, RestoreKernelCache, RestoreRamdisk]
        );
        assert!(bundle.firmware().iter().all(|entry| entry.decrypt()));
        assert_eq!(bundle.ramdisk_patches(), Some([].as_slice()));
        assert_eq!(bundle.filesystem_patches(), Some([].as_slice()));
    }

    #[test]
    fn beta_old_mode_omits_decrypt() {
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,2", "n82", "4.0", "8A230m")
                .with_beta(true)
                .with_old(true)
                .with_system_partition_size(500),
            &test_keys("n82"),
            None,
        )
        .unwrap();
        assert!(bundle.firmware().iter().all(|entry| !entry.decrypt()));
    }

    #[test]
    fn hacktivate_adds_lockdownd_patch() {
        let bundle = ClassicBundle::resolve(
            &request("iPhone1,2", "n82", "4.1", "8B117")
                .with_old(true)
                .with_hacktivate(true)
                .with_system_partition_size(700),
            &test_keys("n82"),
            None,
        )
        .unwrap();
        let filesystem = bundle.filesystem_patches().unwrap();
        assert_eq!(filesystem.len(), 1);
        assert_eq!(filesystem[0].file(), "usr/libexec/lockdownd");
        assert_eq!(filesystem[0].patch().file(), "lockdownd.patch");
        assert_eq!(
            filesystem[0].patch().resource().as_str(),
            "lockdownd-patch-iPhone1-2-4.1-8B117"
        );
        // The 8B117 bundle also carries restoredexternal.
        assert_eq!(bundle.ramdisk_patches().unwrap().len(), 2);
    }

    #[test]
    fn hacktivate_without_lockdownd_patch_fails() {
        // The iPhone2,1 3.0 bundle exists but has no lockdownd patch.
        assert!(matches!(
            ClassicBundle::resolve(
                &request("iPhone2,1", "n88", "3.0", "7A341")
                    .with_old(true)
                    .with_hacktivate(true),
                &test_keys("n88"),
                None,
            ),
            Err(ClassicBundleError::MissingPatch { .. })
        ));
    }

    #[test]
    fn missing_bundle_omits_patch_dicts() {
        let bundle = ClassicBundle::resolve(
            &request("iPod2,1", "n72", "4.3.1", "8G4").with_system_partition_size(700),
            &test_keys("n72"),
            None,
        )
        .unwrap();
        assert!(bundle.ramdisk_patches().is_none());
        assert!(bundle.filesystem_patches().is_none());
        // No cataloged bundle also means no iBSS patch reference.
        assert!(bundle.firmware()[0].patch().is_none());
    }

    #[test]
    fn old_mode_missing_iboot_patch_fails() {
        // iPod2,1 4.3.1 old mode references iBoot.n72ap.RELEASE.patch, which
        // no cataloged bundle carries.
        assert!(matches!(
            ClassicBundle::resolve(
                &request("iPod2,1", "n72", "4.3.1", "8G4")
                    .with_old(true)
                    .with_system_partition_size(700),
                &test_keys("n72"),
                None,
            ),
            Err(ClassicBundleError::MissingPatch { .. })
        ));
    }

    #[test]
    fn non_3x_requires_system_partition_size() {
        assert!(matches!(
            ClassicBundle::resolve(
                &request("iPhone2,1", "n88", "4.2.1", "8C148a"),
                &test_keys("n88"),
                None,
            ),
            Err(ClassicBundleError::MissingSystemPartitionSize)
        ));
    }

    #[test]
    fn iphone1_1_313_root_size() {
        let bundle = ClassicBundle::resolve(
            &s5l8900_request("iPhone1,1", "m68", "3.1.3", "7E18").with_old(true),
            &test_keys("m68"),
            None,
        )
        .unwrap();
        // 3.x root size rule: iPhone1,* -> 420 + 30.
        assert_eq!(bundle.root_filesystem_size_mb(), 450);
    }

    #[test]
    fn invalid_sha1_and_version_rejected() {
        let bad_sha1 = ClassicBundleRequest::new(
            ProductType::from("iPhone2,1"),
            BoardConfig::from("n88"),
            ClassicProcessor::Other,
            "iPhone2,1_Restore.ipsw",
            IosVersion::from("3.1.3"),
            BuildId::from("7E18"),
            IosVersion::from("6.1.6"),
            "not-a-sha1",
        );
        assert!(matches!(
            ClassicBundle::resolve(&bad_sha1, &test_keys("n88"), None),
            Err(ClassicBundleError::InvalidSha1(_))
        ));
        let bad_version = ClassicBundleRequest::new(
            ProductType::from("iPhone2,1"),
            BoardConfig::from("n88"),
            ClassicProcessor::Other,
            "iPhone2,1_Restore.ipsw",
            IosVersion::from("three"),
            BuildId::from("7E18"),
            IosVersion::from("6.1.6"),
            SHA1,
        );
        assert!(matches!(
            ClassicBundle::resolve(&bad_version, &test_keys("n88"), None),
            Err(ClassicBundleError::InvalidVersion(_))
        ));
    }
}
