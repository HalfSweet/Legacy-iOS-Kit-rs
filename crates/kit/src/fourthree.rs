//! FourThree dualboot (iOS 6.1.3 + 4.3.x) for the iPad 2, mirroring upstream's
//! `ipsw_prepare_fourthree*` and `device_fourthree_*` flows.
//!
//! Step 1 builds the custom 6.1.3 IPSW (part 1) and the patched 4.3.x
//! kernelcache, LLB, and RootFS (part 2) from the stock IPSWs, mirroring
//! upstream `ipsw_prepare_fourthree` and `ipsw_prepare_fourthree_part2`.
//! Steps 2 and 3 run over SSH against a jailbroken normal-mode device.

use std::io::Cursor;
use std::path::PathBuf;

use legacy_ios_assets::ResourceId;
use legacy_ios_core::{BuildId, ProductType};
use legacy_ios_firmware::{
    CustomIpswBuilder, FirmwareArchive, FirmwareKey, FirmwareKeyProvider, FirmwareKeySet,
    RemoteFirmwareArchive,
};
use legacy_ios_image::{
    DmgFirmwareKey, DmgImage, DmgPartitionInput, Img3Tag, apply_bsdiff, decrypt_firmware_image,
    decrypt_img3_payload, extract_image_payload, repair_truncated_img3, replace_image_payload,
};
use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};
use plist::Value;
use tracing::info;

use crate::{FirmwareSummary, KitError};

/// Base (dualbooted) iOS versions supported by FourThree.
pub const FOURTHREE_BASE_VERSIONS: [&str; 6] = ["4.3", "4.3.1", "4.3.2", "4.3.3", "4.3.4", "4.3.5"];
/// iOS version of the target (primary) system the base system boots from.
pub const FOURTHREE_TARGET_VERSION: &str = "6.1.3";
/// iOS version and build supplying the dualboot bootchain components
/// (AppleLogo/DeviceTree/iBoot/RecoveryMode), hardcoded like upstream's
/// `saved/$device_type/8L1` path and `device_fw_key_check temp 8L1`.
pub const FOURTHREE_BOOTCHAIN_VERSION: &str = "4.3.5";
pub const FOURTHREE_BOOTCHAIN_BUILD: &str = "8L1";
/// Fixed size in bytes of the 4.3.x system partition created by TwistedMind2.
const TWISTED_MIND2_SYSTEM_SIZE: u64 = 879_124_480;
/// Partition name used by upstream's `dmg build` for the rebuilt RootFS.
const ROOTFS_PARTITION_NAME: &str = "Mac_OS_X (Apple_HFSX : 1)";
const KERNELCACHEB: &str = "/System/Library/Caches/com.apple.kernelcaches/kernelcachb";
const LOCKDOWND: &str = "/mnt1/usr/libexec/lockdownd";

/// Highest FourThree step completed on the device, mirroring upstream
/// `device_fourthree_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourThreeStep {
    /// Step 1: the device is restored to iOS 6.1.3 (/dev/disk0s2s1 exists).
    Restore,
    /// Step 2: TwistedMind2 created the 4.3.x partitions (/dev/disk0s3).
    Partition,
    /// Step 3: kernelcache and LLB are in place; dualboot is ready.
    DualBoot,
}

impl FourThreeStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Partition => "partition",
            Self::DualBoot => "dualboot",
        }
    }
}

/// FourThree bsdiff patch components registered in the resource catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourThreePatch {
    Llb,
    Kernelcache,
    RestoreDeviceTree,
    IBoot,
}

impl FourThreePatch {
    fn file_stem(self, board: &str) -> String {
        match self {
            Self::Llb => format!("LLB.{board}.RELEASE"),
            Self::Kernelcache => "kernelcache.release".to_owned(),
            Self::RestoreDeviceTree => "RestoreDeviceTree".to_owned(),
            Self::IBoot => format!("iBoot.{board}.RELEASE"),
        }
    }
}

/// Map a FourThree-capable product type to its board config (k93ap/k94ap/k95ap).
pub fn fourthree_board_config(product_type: &str) -> Option<&'static str> {
    match product_type {
        "iPad2,1" => Some("k93ap"),
        "iPad2,2" => Some("k94ap"),
        "iPad2,3" => Some("k95ap"),
        _ => None,
    }
}

/// Resource id of a FourThree bsdiff patch for a device/version/component,
/// mirroring the upstream `resources/patch/fourthree` layout. Returns `None`
/// for unsupported devices or a version that does not carry the component.
pub fn fourthree_patch_id(
    product_type: &str,
    version: &str,
    component: FourThreePatch,
) -> Option<ResourceId> {
    let board = fourthree_board_config(product_type)?;
    let valid = match component {
        FourThreePatch::Llb | FourThreePatch::Kernelcache => {
            FOURTHREE_BASE_VERSIONS.contains(&version)
        }
        FourThreePatch::RestoreDeviceTree | FourThreePatch::IBoot => {
            version == FOURTHREE_TARGET_VERSION
        }
    };
    if !valid {
        return None;
    }
    Some(ResourceId::new(format!(
        "fourthree-patch-{}-{version}-{}",
        product_type.replace(',', "-"),
        component.file_stem(board)
    )))
}

/// Resource id of the lockdownd patch FourThree step 3 applies on cellular
/// iPad 2 models, reusing the iPhone2,1 hacktivation bundles like upstream.
pub fn fourthree_lockdownd_patch_id(base_version: &str, base_build: &str) -> ResourceId {
    ResourceId::new(format!(
        "lockdownd-patch-iPhone2-1-{base_version}-{base_build}"
    ))
}

/// Bytes to leave for the iOS 6.1.3 data partition, given the user's GB
/// choice. Sizes outside 1..=64 GB are rejected.
pub fn fourthree_data_partition_bytes(size_gb: u32) -> Option<u64> {
    if (1..=64).contains(&size_gb) {
        Some(u64::from(size_gb) * 1024 * 1024 * 1024)
    } else {
        None
    }
}

/// Where the iOS 4.3.5 (8L1) bootchain components are read from.
#[derive(Clone, Debug)]
pub enum FourThreeComponentSource {
    /// A local iOS 4.3.5 IPSW.
    Local(PathBuf),
    /// An iOS 4.3.5 IPSW URL read through HTTP range requests.
    Remote(String),
}

enum ComponentSource {
    Local(FirmwareArchive),
    Remote(RemoteFirmwareArchive),
}

impl ComponentSource {
    async fn open(source: &FourThreeComponentSource) -> Result<Self, KitError> {
        match source {
            FourThreeComponentSource::Local(path) => Ok(Self::Local(FirmwareArchive::open(path)?)),
            FourThreeComponentSource::Remote(url) => {
                Ok(Self::Remote(RemoteFirmwareArchive::open(url).await?))
            }
        }
    }

    async fn read(&self, name: &str) -> Result<Vec<u8>, KitError> {
        match self {
            Self::Local(archive) => Ok(archive.read_entry(name)?),
            Self::Remote(archive) => Ok(archive.read_entry(name).await?),
        }
    }

    fn entry_names(&self) -> Result<Vec<String>, KitError> {
        match self {
            Self::Local(archive) => Ok(archive.entry_names()?),
            Self::Remote(archive) => Ok(archive.entry_names().map(str::to_owned).collect()),
        }
    }
}

/// Request for building the FourThree custom IPSW and dualboot components.
#[derive(Clone, Debug)]
pub struct FourThreePrepareRequest {
    product_type: ProductType,
    target_ipsw: PathBuf,
    base_ipsw: PathBuf,
    bootchain_source: FourThreeComponentSource,
    ipsw_output: PathBuf,
    component_output: PathBuf,
    cache_root: PathBuf,
}

impl FourThreePrepareRequest {
    /// `target_ipsw` is a stock iOS 6.1.3 IPSW, `base_ipsw` a stock IPSW of
    /// the dualbooted 4.3.x version, and `component_output` the directory the
    /// patched `Kernelcache`, `LLB`, and `RootFS.dmg` are written to.
    pub fn new(
        product_type: ProductType,
        target_ipsw: impl Into<PathBuf>,
        base_ipsw: impl Into<PathBuf>,
        bootchain_source: FourThreeComponentSource,
        ipsw_output: impl Into<PathBuf>,
        component_output: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            product_type,
            target_ipsw: target_ipsw.into(),
            base_ipsw: base_ipsw.into(),
            bootchain_source,
            ipsw_output: ipsw_output.into(),
            component_output: component_output.into(),
            cache_root: cache_root.into(),
        }
    }
}

/// Artifacts produced by FourThree step 1.
pub struct FourThreePrepareOutcome {
    ipsw: FirmwareSummary,
    kernelcache: PathBuf,
    llb: PathBuf,
    rootfs_dmg: PathBuf,
}

impl FourThreePrepareOutcome {
    /// The custom 6.1.3 IPSW restored in step 1.
    pub const fn ipsw(&self) -> &FirmwareSummary {
        &self.ipsw
    }

    /// Patched decrypted 4.3.x kernelcache, installed as kernelcachb.
    pub fn kernelcache(&self) -> &std::path::Path {
        &self.kernelcache
    }

    /// Patched 4.3.x LLB payload, installed at /LLB.
    pub fn llb(&self) -> &std::path::Path {
        &self.llb
    }

    /// Rebuilt 4.3.x RootFS.dmg restored onto /dev/disk0s3.
    pub fn rootfs_dmg(&self) -> &std::path::Path {
        &self.rootfs_dmg
    }
}

/// Build the FourThree custom 6.1.3 IPSW and the patched 4.3.x dualboot
/// components, mirroring upstream `ipsw_prepare_fourthree` and
/// `ipsw_prepare_fourthree_part2`.
pub(crate) async fn prepare(
    request: FourThreePrepareRequest,
) -> Result<FourThreePrepareOutcome, KitError> {
    let board = fourthree_board_config(request.product_type.as_str())
        .ok_or_else(|| KitError::FourThreeUnsupportedDevice(request.product_type.to_string()))?;

    let target = FirmwareArchive::open(&request.target_ipsw)?;
    let target_manifest = target.build_manifest()?;
    let target_version = target_manifest.product_version().to_string();
    let target_build = target_manifest.build_id().clone();
    if target_version != FOURTHREE_TARGET_VERSION {
        return Err(KitError::FourThreeUnsupportedTarget(format!(
            "{} {target_version}",
            request.product_type
        )));
    }
    let base = FirmwareArchive::open(&request.base_ipsw)?;
    let base_manifest = base.build_manifest()?;
    let base_version = base_manifest.product_version().to_string();
    let base_build = base_manifest.build_id().clone();
    if !FOURTHREE_BASE_VERSIONS.contains(&base_version.as_str()) {
        return Err(KitError::FourThreeUnsupportedBase(format!(
            "{} {base_version}",
            request.product_type
        )));
    }

    let keys = FirmwareKeyProvider::with_cache(&request.cache_root);
    info!(
        version = FOURTHREE_TARGET_VERSION,
        "fetching target component keys"
    );
    let target_keys = keys.fetch(&request.product_type, &target_build).await?;
    info!(
        version = FOURTHREE_BOOTCHAIN_VERSION,
        "fetching bootchain component keys"
    );
    let bootchain_keys = keys
        .fetch(
            &request.product_type,
            &BuildId::new(FOURTHREE_BOOTCHAIN_BUILD),
        )
        .await?;
    info!(version = %base_version, "fetching base component keys");
    let base_keys = keys.fetch(&request.product_type, &base_build).await?;

    // The device and both versions are validated against the catalog above,
    // so every patch id resolves.
    let patch_id = |version: &str, component: FourThreePatch| {
        fourthree_patch_id(request.product_type.as_str(), version, component)
            .expect("device and version are validated against the catalog")
    };
    let rdt_patch = read_resource(
        &patch_id(FOURTHREE_TARGET_VERSION, FourThreePatch::RestoreDeviceTree),
        &request.cache_root,
    )
    .await?;
    let iboot_patch = read_resource(
        &patch_id(FOURTHREE_TARGET_VERSION, FourThreePatch::IBoot),
        &request.cache_root,
    )
    .await?;
    let llb_patch = read_resource(
        &patch_id(&base_version, FourThreePatch::Llb),
        &request.cache_root,
    )
    .await?;
    let kernelcache_patch = read_resource(
        &patch_id(&base_version, FourThreePatch::Kernelcache),
        &request.cache_root,
    )
    .await?;

    let target_entries = target.entry_names()?;
    let target_flash = all_flash_dir(&target_entries, board)?;
    let device_tree = key_for(&target_keys, "DeviceTree")?.filename().to_owned();
    let restore_device_tree = target.read_entry(&format!("{target_flash}/{device_tree}"))?;
    let flash_manifest = target.read_entry(&format!("{target_flash}/manifest"))?;
    let build_manifest = target.read_entry("BuildManifest.plist")?;

    let bootchain = ComponentSource::open(&request.bootchain_source).await?;
    let bootchain_entries = bootchain.entry_names()?;
    let bootchain_flash = all_flash_dir(&bootchain_entries, board)?;
    let mut boot_images = Vec::new();
    for image in ["AppleLogo", "DeviceTree", "RecoveryMode", "iBoot"] {
        let key = key_for(&bootchain_keys, image)?;
        let data = bootchain
            .read(&format!("{bootchain_flash}/{}", key.filename()))
            .await?;
        boot_images.push((image, data));
    }

    let base_entries = base.entry_names()?;
    let base_flash = all_flash_dir(&base_entries, board)?;
    let llb_container = base.read_entry(&format!(
        "{base_flash}/{}",
        key_for(&base_keys, "LLB")?.filename()
    ))?;
    let kernelcache_container = base.read_entry(key_for(&base_keys, "Kernelcache")?.filename())?;
    let rootfs_dmg = base.read_entry(key_for(&base_keys, "RootFS")?.filename())?;

    info!("building the FourThree custom IPSW and dualboot components");
    let built = tokio::task::spawn_blocking(move || {
        // Part 1: the patched RestoreDeviceTree under Downgrade/ and the
        // mangled/patched 4.3.5 bootchain components as *B.img3, mirroring
        // ipsw_prepare_fourthree.
        let mut replacements: Vec<(String, Vec<u8>)> = Vec::new();
        let (key, iv) = key_material(key_for(&target_keys, "DeviceTree")?, "DeviceTree")?;
        let decrypted = decrypt_img3_payload(&restore_device_tree, &key, &iv)?;
        let patched = apply_bsdiff(&decrypted, &rdt_patch)?;
        replacements.push((
            "Downgrade/RestoreDeviceTree".to_owned(),
            repair_truncated_img3(&patched)?,
        ));

        let mut names = Vec::new();
        for (image, container) in boot_images {
            let (key, iv) = key_material(key_for(&bootchain_keys, image)?, image)?;
            let decrypted = decrypt_img3_payload(&container, &key, &iv)?;
            let (name, data) = match image {
                "AppleLogo" => (
                    "applelogoB.img3",
                    mangle_bootchain_image(&decrypted, *b"bg", image)?,
                ),
                "DeviceTree" => (
                    "DeviceTreeB.img3",
                    mangle_bootchain_image(&decrypted, *b"br", image)?,
                ),
                "RecoveryMode" => (
                    "recoverymodeB.img3",
                    mangle_bootchain_image(&decrypted, *b"bc", image)?,
                ),
                "iBoot" => (
                    "iBootB.img3",
                    repair_truncated_img3(&apply_bsdiff(&decrypted, &iboot_patch)?)?,
                ),
                _ => unreachable!("fixed component list"),
            };
            replacements.push((format!("{target_flash}/{name}"), data));
            names.push(name);
        }
        replacements.push((
            format!("{target_flash}/manifest"),
            append_to_flash_manifest(&flash_manifest, &names),
        ));
        // Upstream gets the Downgrade/RestoreDeviceTree manifest path from the
        // powdersn0w IPSW builder; this flow starts from a stock IPSW, so the
        // BuildManifest edit happens here.
        replacements.push((
            "BuildManifest.plist".to_owned(),
            point_restore_device_tree_at_downgrade(&build_manifest)?,
        ));

        // Part 2: the patched 4.3.x kernelcache, LLB, and RootFS, mirroring
        // ipsw_prepare_fourthree_part2.
        let (key, iv) = key_material(key_for(&base_keys, "Kernelcache")?, "Kernelcache")?;
        let raw = extract_image_payload(&kernelcache_container, Some((&key, &iv)))?;
        let patched = apply_bsdiff(&raw, &kernelcache_patch)?;
        // Upstream re-wraps the patched payload using the original container
        // as the template, encrypting and then decrypting with the same key:
        // the identity. Wrap the patched payload directly instead.
        let kernelcache = replace_image_payload(&kernelcache_container, &patched, None)?;

        let (key, iv) = key_material(key_for(&base_keys, "LLB")?, "LLB")?;
        let raw = extract_image_payload(&llb_container, Some((&key, &iv)))?;
        let llb = apply_bsdiff(&raw, &llb_patch)?;

        let rootfs_key = key_for(&base_keys, "RootFS")?
            .key()
            .ok_or(KitError::FourThreeMissingKey("RootFS"))?;
        let rootfs = DmgImage::build(vec![DmgPartitionInput::new(
            ROOTFS_PARTITION_NAME,
            decrypt_firmware_image(&rootfs_dmg, &DmgFirmwareKey::from_bytes(rootfs_key)?)?,
        )])?
        .into_bytes();
        Ok::<_, KitError>((replacements, kernelcache, llb, rootfs))
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    let (replacements, kernelcache, llb, rootfs) = built;

    let mut builder = CustomIpswBuilder::new(FirmwareArchive::open(&request.target_ipsw)?);
    for (name, data) in replacements {
        builder = builder.replace(name, data)?;
    }
    builder.build(&request.ipsw_output).await?;

    tokio::fs::create_dir_all(&request.component_output).await?;
    let kernelcache_path = request.component_output.join("Kernelcache");
    tokio::fs::write(&kernelcache_path, &kernelcache).await?;
    let llb_path = request.component_output.join("LLB");
    tokio::fs::write(&llb_path, &llb).await?;
    let rootfs_path = request.component_output.join("RootFS.dmg");
    tokio::fs::write(&rootfs_path, &rootfs).await?;
    info!(
        ipsw = %request.ipsw_output.display(),
        components = %request.component_output.display(),
        "FourThree step 1 artifacts built"
    );

    let ipsw = FirmwareSummary::inspect(request.ipsw_output)?;
    Ok(FourThreePrepareOutcome {
        ipsw,
        kernelcache: kernelcache_path,
        llb: llb_path,
        rootfs_dmg: rootfs_path,
    })
}

async fn read_resource(id: &ResourceId, cache_root: &std::path::Path) -> Result<Vec<u8>, KitError> {
    let path = crate::firmware::fetch_resource(id, cache_root.to_owned()).await?;
    Ok(tokio::fs::read(path).await?)
}

/// `Firmware/all_flash/all_flash.<board>ap[.production]` directory inside an
/// IPSW, located via its `manifest` entry. Falls back to the only all_flash
/// manifest when the directory name does not carry the board config.
fn all_flash_dir(entries: &[String], board: &str) -> Result<String, KitError> {
    let marker = format!("all_flash.{board}ap");
    let mut fallback = None;
    for name in entries {
        let Some(dir) = name.strip_suffix("/manifest") else {
            continue;
        };
        if !dir.starts_with("Firmware/all_flash/") {
            continue;
        }
        if dir.contains(&marker) {
            return Ok(dir.to_owned());
        }
        fallback.get_or_insert_with(|| dir.to_owned());
    }
    fallback.ok_or(KitError::FourThreeInvalidImage("all_flash manifest"))
}

fn key_for<'a>(keys: &'a FirmwareKeySet, image: &'static str) -> Result<&'a FirmwareKey, KitError> {
    keys.key(image).ok_or(KitError::FourThreeMissingKey(image))
}

fn key_material(key: &FirmwareKey, image: &'static str) -> Result<(Vec<u8>, [u8; 16]), KitError> {
    match (key.key(), key.iv()) {
        (Some(key), Some(iv)) => Ok((key.to_vec(), *iv)),
        _ => Err(KitError::FourThreeMissingKey(image)),
    }
}

/// Apply the FourThree `*B.img3` type mangle to a decrypted IMG3 container,
/// mirroring upstream's `echo "0000010: 62xx" | xxd -r` edits: the last
/// character of the image type fourcc (image header and TYPE element) becomes
/// 'b' so the dualboot components do not collide with the 6.1.3 copies in
/// NOR.
fn mangle_bootchain_image(
    container: &[u8],
    marker: [u8; 2],
    image: &'static str,
) -> Result<Vec<u8>, KitError> {
    // A decrypted IMG3 with a leading TYPE element: image type at 0x10, TYPE
    // element header at 0x14, TYPE data at 0x20.
    if container.len() < 0x24
        || !container.starts_with(b"3gmI")
        || container[0x14..0x18] != Img3Tag::TYPE.get().to_le_bytes()
    {
        return Err(KitError::FourThreeInvalidImage(image));
    }
    let mut mangled = container.to_vec();
    mangled[0x10..0x12].copy_from_slice(&marker);
    mangled[0x20..0x22].copy_from_slice(&marker);
    Ok(mangled)
}

/// Append the `*B.img3` names to the all_flash manifest, mirroring upstream's
/// `echo "${getcomp}B.img3" >> $all_flash/manifest`.
fn append_to_flash_manifest(manifest: &[u8], names: &[&str]) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(manifest).into_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    for name in names {
        text.push_str(name);
        text.push('\n');
    }
    text.into_bytes()
}

/// Point every build identity's RestoreDeviceTree component at the patched
/// copy under `Downgrade/`, mirroring the BuildManifest edit the upstream
/// flow gets from the powdersn0w IPSW builder. Manifests already referencing
/// `Downgrade/` are returned unchanged, like upstream's idempotence check.
pub fn point_restore_device_tree_at_downgrade(manifest: &[u8]) -> Result<Vec<u8>, KitError> {
    if manifest
        .windows(b"Downgrade/".len())
        .any(|window| window == b"Downgrade/")
    {
        return Ok(manifest.to_vec());
    }
    let mut value = Value::from_reader(Cursor::new(manifest))?;
    let root = value
        .as_dictionary_mut()
        .ok_or(KitError::FourThreeInvalidManifest)?;
    let identities = root
        .get_mut("BuildIdentities")
        .and_then(Value::as_array_mut)
        .ok_or(KitError::FourThreeInvalidManifest)?;
    for identity in identities {
        let Some(manifest) = identity
            .as_dictionary_mut()
            .and_then(|identity| identity.get_mut("Manifest"))
            .and_then(Value::as_dictionary_mut)
        else {
            continue;
        };
        if let Some(info) = manifest
            .get_mut("RestoreDeviceTree")
            .and_then(Value::as_dictionary_mut)
            .and_then(|component| component.get_mut("Info"))
            .and_then(Value::as_dictionary_mut)
        {
            info.insert(
                "Path".to_owned(),
                Value::String("Downgrade/RestoreDeviceTree".to_owned()),
            );
        }
    }
    let mut output = Vec::new();
    value.to_writer_xml(&mut output)?;
    Ok(output)
}

/// A file produced by the on-device TwistedMind2 partitioner, pulled back to
/// the host to boot the step 3 ramdisk.
pub struct TwistedMind2Output {
    name: String,
    data: Vec<u8>,
}

impl TwistedMind2Output {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Optional OpenSSH payload for the 4.3.x system, mirroring upstream's
/// `ipsw_openssh` branch (decompressed tars).
pub struct FourThreeOpenSsh {
    pub sshdeb: Vec<u8>,
    pub openssh: Vec<u8>,
    pub openssl: Vec<u8>,
}

/// Resolved package bytes for FourThree step 3.
pub struct FourThreeStep3Packages {
    /// Rebuilt 4.3.x RootFS.dmg restored onto /dev/disk0s3.
    pub rootfs_dmg: Vec<u8>,
    /// Patched decrypted 4.3.x kernelcache, installed as kernelcachb.
    pub kernelcache: Vec<u8>,
    /// Patched 4.3.x LLB payload, installed at /LLB.
    pub llb: Vec<u8>,
    /// Decompressed freeze.tar Cydia bootstrap.
    pub freeze: Vec<u8>,
    /// fourthree.tar companion app.
    pub app: Vec<u8>,
    /// lockdownd bsdiff patch; required on every model except iPad2,1.
    pub lockdownd_patch: Option<Vec<u8>>,
    pub openssh: Option<FourThreeOpenSsh>,
}

/// Query the highest completed FourThree step on the device, mirroring
/// upstream `device_fourthree_check`. Errors when step 1 is missing.
pub(crate) async fn check(ssh: &RamdiskSsh) -> Result<FourThreeStep, KitError> {
    if !path_exists(ssh, "/dev/disk0s2s1").await? {
        return Err(KitError::FourThreeRestoreIncomplete);
    }
    if !path_exists(ssh, "/dev/disk0s3").await? {
        return Ok(FourThreeStep::Restore);
    }
    let kernelcache = path_exists(ssh, KERNELCACHEB).await?;
    let llb = path_exists(ssh, "/LLB").await?;
    if !(kernelcache && llb) {
        return Ok(FourThreeStep::Partition);
    }
    Ok(FourThreeStep::DualBoot)
}

/// Step 2: install the dualboot packages and partition the device with
/// TwistedMind2, mirroring upstream `device_fourthree_step2`. Returns the
/// generated /TwistedMind2* files needed to boot the step 3 ramdisk.
pub(crate) async fn step2(
    ssh: &RamdiskSsh,
    dualbootstuff: &[u8],
    size_gb: u32,
) -> Result<Vec<TwistedMind2Output>, KitError> {
    let size = fourthree_data_partition_bytes(size_gb)
        .ok_or(KitError::InvalidFourThreePartitionSize(size_gb))?;
    ensure_step2_allowed(check(ssh).await?)?;

    info!("sending FourThree partition packages");
    ssh.upload(&scp_path("/tmp/dualbootstuff.tar")?, dualbootstuff)
        .await?;
    run(
        ssh,
        "tar -xf /tmp/dualbootstuff.tar -C /; dpkg -i /tmp/dualbootstuff/*.deb",
    )
    .await?;

    info!(size_gb, "running TwistedMind2 partitioner");
    run(
        ssh,
        &format!(
            "rm -f /TwistedMind2*; TwistedMind2 -d1 {size} -s2 {TWISTED_MIND2_SYSTEM_SIZE} -d2 max"
        ),
    )
    .await?;

    let listing = ssh.execute("ls /TwistedMind2* 2>/dev/null").await?;
    let mut outputs = Vec::new();
    for line in listing.stdout().split(|byte| *byte == b'\n') {
        let path = std::str::from_utf8(line).map(str::trim).unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        let data = ssh.download(&scp_path(path)?, 64 * 1024 * 1024).await?;
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        outputs.push(TwistedMind2Output { name, data });
    }
    if outputs.is_empty() {
        return Err(KitError::FourThreePartitionerFailed);
    }
    info!(files = outputs.len(), "TwistedMind2 partitioning complete");
    Ok(outputs)
}

/// Step 3: create the 4.3.x filesystems, restore the rootfs, jailbreak it,
/// and install the dualboot components, mirroring upstream
/// `device_fourthree_step3`.
pub(crate) async fn step3(
    ssh: &RamdiskSsh,
    product_type: &str,
    packages: &FourThreeStep3Packages,
) -> Result<(), KitError> {
    if fourthree_board_config(product_type).is_none() {
        return Err(KitError::FourThreeUnsupportedDevice(
            product_type.to_owned(),
        ));
    }
    ensure_step3_allowed(check(ssh).await?)?;

    info!("creating 4.3.x filesystems");
    run(ssh, "mkdir -p /mnt1 /mnt2").await?;
    run(
        ssh,
        "/sbin/newfs_hfs -s -v System -J -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s3",
    )
    .await?;
    run(
        ssh,
        "/sbin/newfs_hfs -s -v Data -J -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s4",
    )
    .await?;

    info!("sending root filesystem");
    ssh.upload(&scp_path("/var/RootFS.dmg")?, &packages.rootfs_dmg)
        .await?;
    info!("restoring root filesystem");
    run(
        ssh,
        "echo 'y' | asr restore --source /var/RootFS.dmg --target /dev/disk0s3 --erase",
    )
    .await?;
    // fsck_hfs reports repaired inconsistencies through its exit status.
    let _ = ssh
        .execute("rm /var/RootFS.dmg; fsck_hfs -f /dev/disk0s3")
        .await?;

    info!("restoring data partition");
    run(
        ssh,
        "mount_hfs /dev/disk0s3 /mnt1; mount_hfs /dev/disk0s4 /mnt2; mv /mnt1/private/var/* /mnt2",
    )
    .await?;

    info!("fixing fstab");
    let fstab = b"/dev/disk0s3 / hfs rw 0 1\n/dev/disk0s4 /private/var hfs rw 0 2\n";
    ssh.upload(&scp_path("/mnt1/private/etc/fstab")?, fstab)
        .await?;

    if product_type != "iPad2,1" {
        let patch = packages
            .lockdownd_patch
            .as_deref()
            .ok_or(KitError::MissingFourThreeLockdowndPatch)?;
        info!("patching lockdownd");
        let lockdownd = ssh
            .download(&scp_path(LOCKDOWND)?, 16 * 1024 * 1024)
            .await?;
        let patched = apply_bsdiff(&lockdownd, patch)?;
        run(ssh, &format!("mv {LOCKDOWND} {LOCKDOWND}.orig")).await?;
        ssh.upload(&scp_path(LOCKDOWND)?, &patched).await?;
        run(ssh, &format!("chmod +x {LOCKDOWND}")).await?;
    }

    info!("fixing system keybag");
    run(
        ssh,
        "mkdir -p /mnt2/keybags; ttbthingy; fixkeybag -v2; cp /tmp/systembag.kb /mnt2/keybags",
    )
    .await?;

    info!("remounting data partition");
    run(
        ssh,
        "umount /mnt2; mount_hfs /dev/disk0s4 /mnt1/private/var",
    )
    .await?;

    // Copying activation records is best-effort upstream as well.
    let dump = "private/var/root/Library/Lockdown";
    let _ = ssh
        .execute(&format!(
            "mkdir -p /mnt1/{dump}; cp -Rv /{dump}/* /mnt1/{dump}"
        ))
        .await?;

    info!("installing jailbreak bootstrap");
    install_mnt1_tar(ssh, "freeze.tar", &packages.freeze).await?;
    if let Some(openssh) = &packages.openssh {
        info!("installing OpenSSH");
        install_mnt1_tar(ssh, "sshdeb.tar", &openssh.sshdeb).await?;
        install_mnt1_tar(ssh, "openssh.tar", &openssh.openssh).await?;
        install_mnt1_tar(ssh, "openssl.tar", &openssh.openssl).await?;
    }

    run(ssh, "umount /mnt1/private/var; umount /mnt1").await?;

    info!("sending kernelcache and LLB");
    ssh.upload(&scp_path(KERNELCACHEB)?, &packages.kernelcache)
        .await?;
    ssh.upload(&scp_path("/LLB")?, &packages.llb).await?;

    install_app(ssh, &packages.app).await?;
    info!("FourThree step 3 complete");
    Ok(())
}

/// Install the FourThree companion app, mirroring upstream
/// `device_fourthree_app`.
pub(crate) async fn install_app(ssh: &RamdiskSsh, app: &[u8]) -> Result<(), KitError> {
    check(ssh).await?;
    info!("installing FourThree app");
    ssh.upload(&scp_path("/tmp/fourthree.tar")?, app).await?;
    run(
        ssh,
        "tar -h -xf /tmp/fourthree.tar -C /; rm /tmp/fourthree.tar; \
         cd /Applications/FourThree.app; \
         chmod 6755 boot.sh FourThree kloader_ios5 /usr/bin/runasroot",
    )
    .await?;
    // Upstream runs uicache as mobile over a second SSH session; running it
    // as root rebuilds the same cache.
    run(ssh, "uicache").await?;
    Ok(())
}

/// Boot the 4.3.x system through the FourThree app, mirroring upstream
/// `device_fourthree_boot`. The kloader drops the SSH session.
pub(crate) async fn boot(ssh: &RamdiskSsh) -> Result<(), KitError> {
    if check(ssh).await? != FourThreeStep::DualBoot {
        return Err(KitError::FourThreeInstallIncomplete);
    }
    info!("booting the 4.3.x system");
    let _ = ssh.execute("/Applications/FourThree.app/FourThree").await;
    Ok(())
}

fn ensure_step2_allowed(step: FourThreeStep) -> Result<(), KitError> {
    match step {
        FourThreeStep::Restore => Ok(()),
        FourThreeStep::Partition | FourThreeStep::DualBoot => {
            Err(KitError::FourThreeStepAlreadyDone("step 2"))
        }
    }
}

fn ensure_step3_allowed(step: FourThreeStep) -> Result<(), KitError> {
    match step {
        FourThreeStep::Restore => Err(KitError::FourThreePartitionIncomplete),
        FourThreeStep::Partition => Ok(()),
        FourThreeStep::DualBoot => Err(KitError::FourThreeStepAlreadyDone("step 3")),
    }
}

async fn path_exists(ssh: &RamdiskSsh, path: &str) -> Result<bool, KitError> {
    let output = ssh.execute(&format!("ls {path} 2>/dev/null")).await?;
    Ok(output.stdout().trim_ascii() == path.as_bytes())
}

async fn install_mnt1_tar(ssh: &RamdiskSsh, name: &str, data: &[u8]) -> Result<(), KitError> {
    ssh.upload(&scp_path(&format!("/tmp/{name}"))?, data)
        .await?;
    run(
        ssh,
        &format!("tar -xf /tmp/{name} -C /mnt1; rm /tmp/{name}"),
    )
    .await
}

async fn run(ssh: &RamdiskSsh, command: &str) -> Result<(), KitError> {
    let result = ssh.execute(command).await?;
    if !result.success() {
        return Err(KitError::Ssh(SshError::RemoteCommand(result.exit_status())));
    }
    Ok(())
}

fn scp_path(path: &str) -> Result<ScpPath, KitError> {
    ScpPath::new(path).map_err(|error| KitError::Ssh(SshError::Scp(error.to_string())))
}

#[cfg(test)]
mod tests {
    use legacy_ios_image::{Img3, Img3Element};

    use super::*;

    fn sample_img3(image_type: u32) -> Vec<u8> {
        Img3::new(
            image_type,
            vec![
                Img3Element::new(Img3Tag::TYPE, image_type.to_le_bytes().to_vec()),
                Img3Element::new(Img3Tag::DATA, b"payload".to_vec()),
            ],
        )
        .to_bytes()
    }

    #[test]
    fn maps_ipad2_boards() {
        assert_eq!(fourthree_board_config("iPad2,1"), Some("k93ap"));
        assert_eq!(fourthree_board_config("iPad2,2"), Some("k94ap"));
        assert_eq!(fourthree_board_config("iPad2,3"), Some("k95ap"));
        assert_eq!(fourthree_board_config("iPad2,4"), None);
        assert_eq!(fourthree_board_config("iPhone4,1"), None);
    }

    #[test]
    fn maps_base_version_patches() {
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for device in ["iPad2,1", "iPad2,2", "iPad2,3"] {
            for version in FOURTHREE_BASE_VERSIONS {
                for component in [FourThreePatch::Llb, FourThreePatch::Kernelcache] {
                    let id = fourthree_patch_id(device, version, component).unwrap();
                    assert!(catalog.get(&id).is_some(), "missing resource {id}");
                }
            }
        }
        assert_eq!(
            fourthree_patch_id("iPad2,1", "4.3.3", FourThreePatch::Llb)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-1-4.3.3-LLB.k93ap.RELEASE"
        );
        assert_eq!(
            fourthree_patch_id("iPad2,3", "4.3.5", FourThreePatch::Kernelcache)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-3-4.3.5-kernelcache.release"
        );
    }

    #[test]
    fn maps_target_version_patches() {
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for device in ["iPad2,1", "iPad2,2", "iPad2,3"] {
            for component in [FourThreePatch::RestoreDeviceTree, FourThreePatch::IBoot] {
                let id = fourthree_patch_id(device, "6.1.3", component).unwrap();
                assert!(catalog.get(&id).is_some(), "missing resource {id}");
            }
        }
        assert_eq!(
            fourthree_patch_id("iPad2,2", "6.1.3", FourThreePatch::IBoot)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-2-6.1.3-iBoot.k94ap.RELEASE"
        );
    }

    #[test]
    fn rejects_mismatched_versions_and_devices() {
        // RestoreDeviceTree/iBoot patches only exist for 6.1.3.
        assert!(fourthree_patch_id("iPad2,1", "4.3.3", FourThreePatch::IBoot).is_none());
        // LLB/kernelcache patches only exist for the 4.3.x base versions.
        assert!(fourthree_patch_id("iPad2,1", "6.1.3", FourThreePatch::Llb).is_none());
        assert!(fourthree_patch_id("iPad2,1", "4.3.6", FourThreePatch::Llb).is_none());
        assert!(fourthree_patch_id("iPad2,4", "4.3.3", FourThreePatch::Llb).is_none());
    }

    #[test]
    fn maps_lockdownd_patch_to_iphone21_bundles() {
        let id = fourthree_lockdownd_patch_id("4.3.3", "8J2");
        assert_eq!(id.as_str(), "lockdownd-patch-iPhone2-1-4.3.3-8J2");
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for (version, build) in [
            ("4.3", "8F190"),
            ("4.3.1", "8G4"),
            ("4.3.2", "8H7"),
            ("4.3.3", "8J2"),
            ("4.3.4", "8K2"),
            ("4.3.5", "8L1"),
        ] {
            let id = fourthree_lockdownd_patch_id(version, build);
            assert!(catalog.get(&id).is_some(), "missing resource {id}");
        }
    }

    #[test]
    fn converts_partition_size() {
        assert_eq!(
            fourthree_data_partition_bytes(3),
            Some(3 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            fourthree_data_partition_bytes(64),
            Some(64 * 1024 * 1024 * 1024)
        );
        assert_eq!(fourthree_data_partition_bytes(0), None);
        assert_eq!(fourthree_data_partition_bytes(65), None);
    }

    #[test]
    fn gates_steps_on_progress() {
        assert!(ensure_step2_allowed(FourThreeStep::Restore).is_ok());
        assert!(matches!(
            ensure_step2_allowed(FourThreeStep::Partition),
            Err(KitError::FourThreeStepAlreadyDone("step 2"))
        ));
        assert!(matches!(
            ensure_step3_allowed(FourThreeStep::Restore),
            Err(KitError::FourThreePartitionIncomplete)
        ));
        assert!(ensure_step3_allowed(FourThreeStep::Partition).is_ok());
        assert!(matches!(
            ensure_step3_allowed(FourThreeStep::DualBoot),
            Err(KitError::FourThreeStepAlreadyDone("step 3"))
        ));
    }

    #[test]
    fn mangles_bootchain_image_types() {
        let container = sample_img3(u32::from_be_bytes(*b"logo"));
        let mangled = mangle_bootchain_image(&container, *b"bg", "AppleLogo").unwrap();
        let parsed = Img3::parse(&mangled).unwrap();
        let logb = u32::from_be_bytes(*b"logb");
        assert_eq!(parsed.image_type(), logb);
        let type_element = parsed
            .elements()
            .iter()
            .find(|element| element.tag() == Img3Tag::TYPE)
            .unwrap();
        assert_eq!(type_element.data(), logb.to_le_bytes());
        // The payload and the rest of the container are untouched.
        assert_eq!(parsed.payload().unwrap(), b"payload");
        assert_eq!(mangled.len(), container.len());
    }

    #[test]
    fn mangle_requires_a_leading_type_element() {
        let mut container = sample_img3(u32::from_be_bytes(*b"logo"));
        container[0x14..0x18].copy_from_slice(b"ATAD");
        assert!(matches!(
            mangle_bootchain_image(&container, *b"bg", "AppleLogo"),
            Err(KitError::FourThreeInvalidImage("AppleLogo"))
        ));
        assert!(matches!(
            mangle_bootchain_image(b"not an image", *b"br", "DeviceTree"),
            Err(KitError::FourThreeInvalidImage("DeviceTree"))
        ));
    }

    #[test]
    fn finds_all_flash_dir() {
        let entries = vec![
            "Firmware/all_flash/all_flash.k93ap.production/LLB.k93ap.RELEASE.img3".to_owned(),
            "Firmware/all_flash/all_flash.k93ap.production/manifest".to_owned(),
            "kernelcache.release.k93".to_owned(),
        ];
        assert_eq!(
            all_flash_dir(&entries, "k93ap").unwrap(),
            "Firmware/all_flash/all_flash.k93ap.production"
        );
        // Falls back to the only all_flash manifest for other boards.
        assert!(all_flash_dir(&entries, "k94ap").is_ok());
        assert!(matches!(
            all_flash_dir(&[], "k93ap"),
            Err(KitError::FourThreeInvalidImage("all_flash manifest"))
        ));
    }

    #[test]
    fn appends_bootchain_names_to_flash_manifest() {
        let manifest = b"LLB.k93ap.RELEASE.img3\napplelogo.s5l8940x.img3";
        let updated = append_to_flash_manifest(manifest, &["applelogoB.img3", "DeviceTreeB.img3"]);
        assert_eq!(
            updated,
            b"LLB.k93ap.RELEASE.img3\napplelogo.s5l8940x.img3\napplelogoB.img3\nDeviceTreeB.img3\n"
        );
    }

    #[test]
    fn points_restore_device_tree_at_downgrade() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildIdentities</key><array><dict>
<key>Manifest</key><dict>
<key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/all_flash.k93ap.production/DeviceTree.k93ap.img3</string></dict></dict>
<key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.k93</string></dict></dict>
</dict>
</dict></array></dict></plist>"#;
        let rewritten = point_restore_device_tree_at_downgrade(manifest).unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("Downgrade/RestoreDeviceTree"));
        // RestoreKernelCache is left untouched.
        assert!(text.contains("kernelcache.release.k93"));

        // Idempotent, like upstream's Downgrade grep check.
        let again = point_restore_device_tree_at_downgrade(text.as_bytes()).unwrap();
        assert_eq!(again, text.as_bytes());
    }

    #[test]
    fn rejects_manifest_without_identities() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict></dict></plist>"#;
        assert!(matches!(
            point_restore_device_tree_at_downgrade(manifest),
            Err(KitError::FourThreeInvalidManifest)
        ));
    }
}
