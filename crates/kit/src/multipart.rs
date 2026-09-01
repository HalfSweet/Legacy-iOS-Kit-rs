//! iOS 3.x/4.x multipart (two-stage) custom IPSW preparation and restore
//! orchestration, mirroring upstream `ipsw_prepare_ios4multipart`,
//! `ipsw_prepare_multipatch`, and the powdersn0w two-stage restore flow in
//! `restore_prepare`.
//!
//! Stage 1 (part 1) is a NOR flash IPSW built from iOS 5.1.1 (9B206) restore
//! components: RSA-patched iBSS/iBEC (the iBEC boots the restore ramdisk with
//! `nand-enable-reformat=1`), decrypted DeviceTree/Kernelcache under
//! `Downgrade/`, a ramdisk whose options.plist disables filesystem creation,
//! baseband update, and system image restore, plus the device APTicket
//! resealed into the scab IMG3 template as `applelogoT.img3`.
//!
//! Stage 2 (part 2) is the target version's custom IPSW (built externally,
//! e.g. by powdersn0w, like FourThree's externally-produced components) with
//! the multipatch transform applied: target iBSS/iBEC patched with the
//! multistage boot-args, `FlashNOR` disabled in the ramdisk options.plist,
//! and — for 4.x targets — the multistage payload (bin4.tar contents plus the
//! reboot4 binary installed as `/sbin/reboot`) baked into the ramdisk.
//!
//! Restore orchestration runs part 1 through the normal restore engine with
//! final verification disabled (the device does not boot a normal system
//! after the NOR flash), waits for the device to re-enter DFU/recovery, then
//! runs part 2 through the restore engine on the pwned boot chain. The
//! device-side multistage work (reboot4, bin4.tar tools) runs inside the
//! part 2 ramdisk itself, so no host-side SSH session is involved.

use std::{io::Cursor, path::PathBuf, time::Duration};

use legacy_ios_assets::ResourceId;
use legacy_ios_core::{ActionId, ActionKind, BoardConfig, BuildId, Ecid, ProductType};
use legacy_ios_firmware::{
    BuildManifest, CustomIpswBuilder, FirmwareArchive, FirmwareKey, FirmwareKeyProvider,
    FirmwareKeySet, RemoteFirmwareArchive, SigningTicket, TssClient,
};
use legacy_ios_image::{HfsImage, apply_bsdiff, extract_image_payload, replace_image_payload};
use legacy_ios_transport::IbootClient;
use plist::Value;
use tracing::{info, warn};

use crate::{
    DeviceManager, FirmwareSummary, HfsMutation, KitError, OperationHandle, hfs::apply_mutations,
    lease::DeviceLeaseRegistry, operation::OperationEmitter,
    restore_execution::RestoreExecutionRequest,
};

/// iOS version and build of the NOR flash (part 1) restore components.
pub const MULTIPART_NOR_VERSION: &str = "5.1.1";
pub const MULTIPART_NOR_BUILD: &str = "9B206";

/// Boot-args for the part 1 iBEC, mirroring upstream
/// `ipsw_prepare_ios4multipart`.
pub const MULTIPART_IBEC_BOOT_ARGS: &str =
    "rd=md0 -v nand-enable-reformat=1 amfi=0xff cs_enforcement_disable=1";

/// Boot-args for the multipatch iBSS/iBEC, mirroring upstream
/// `ipsw_prepare_multipatch`.
pub const MULTIPATCH_BOOT_ARGS: &str = "rd=md0 -v nand-enable-reformat=1 amfi=0xff amfi_get_out_of_my_way=1 cs_enforcement_disable=1 pio-error=0";

const PART1_RAMDISK_SIZE: usize = 18_000_000;
const PART2_RAMDISK_SIZE: usize = 30_000_000;

/// End-of-central-directory record of an empty ZIP archive; used as the
/// source of [`CustomIpswBuilder`] when assembling the part 1 IPSW from
/// scratch.
const EMPTY_ZIP: [u8; 22] = [
    0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Whether the device/version combination is served by the multipart flow:
/// powdersn0w-capable A4 devices targeting iOS 3.x or 4.0-4.2.x. iOS 4.3.x
/// uses the single-IPSW powdersn0w variant instead, which is not implemented.
pub fn multipart_support(product_type: &ProductType, target_version: &str) -> bool {
    if multipart_base_version(product_type).is_none() {
        return false;
    }
    let mut components = target_version.split('.');
    match components.next() {
        Some("3") => true,
        Some("4") => matches!(components.next(), Some(minor) if minor.parse::<u32>() == Ok(0)
            || minor.parse::<u32>() == Ok(1)
            || minor.parse::<u32>() == Ok(2)),
        _ => false,
    }
}

/// Latest (base) iOS version for a multipart-capable device, mirroring
/// upstream's `device_base_vers` for powdersn0w targets on A4. The base IPSW
/// of this version supplies the all_flash contents of the part 1 IPSW.
pub fn multipart_base_version(product_type: &ProductType) -> Option<&'static str> {
    match product_type.as_str() {
        "iPhone3,1" | "iPhone3,2" => Some("7.1.2"),
        "iPhone3,3" | "iPad1,1" | "iPod3,1" => Some("5.1.1"),
        "iPod4,1" => Some("6.1.3"),
        _ => None,
    }
}

/// reboot4 variant for the device, mirroring upstream `ipsw_prepare_reboot4`:
/// devices whose restore chain keeps `boot-ramdisk` use the full binary, the
/// others the no-boot-ramdisk variant.
pub fn reboot4_resource(product_type: &ProductType) -> ResourceId {
    match product_type.as_str() {
        "iPad2,1" | "iPad2,2" | "iPad2,3" | "iPod4,1" => ResourceId::new("ios4-reboot"),
        _ => ResourceId::new("ios4-reboot-nor"),
    }
}

/// Multistage ramdisk payload resources for a target version. iOS 4.x targets
/// get bin4.tar plus the reboot4 binary; iOS 3.x targets need no payload
/// (upstream patches nothing extra into the 3.x ramdisk).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamdiskPayload {
    pub bin_tar: ResourceId,
    pub reboot: ResourceId,
}

pub fn ramdisk_payload(product_type: &ProductType, target_version: &str) -> Option<RamdiskPayload> {
    if !target_version.starts_with("4.") {
        return None;
    }
    Some(RamdiskPayload {
        bin_tar: ResourceId::new("ios4-restore-bin-tar"),
        reboot: reboot4_resource(product_type),
    })
}

/// options.plist file name inside the restore ramdisk, mirroring upstream:
/// iOS 3.x/4.x ramdisks carry a single `options.plist`, newer ones a
/// per-board `options.<board>ap.plist`.
pub fn options_plist_name(target_version: &str, board_config: &BoardConfig) -> String {
    if target_version.starts_with("3.") || target_version.starts_with("4.") {
        "options.plist".to_owned()
    } else {
        format!("options.{}ap.plist", board_config.as_str())
    }
}

/// The fixed options.plist written into the part 1 ramdisk, mirroring
/// upstream `ipsw_prepare_ios4multipart`.
pub fn nor_options_plist() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CreateFilesystemPartitions</key>
    <false/>
    <key>UpdateBaseband</key>
    <false/>
    <key>SystemImage</key>
    <false/>
</dict>
</plist>
"#
    .to_vec()
}

/// Add `FlashNOR=false` (and optionally `UpdateBaseband=false`, unless
/// already present) to a ramdisk options.plist, mirroring the multipatch
/// options.plist edit.
pub fn edit_options_plist(
    original: &[u8],
    disable_baseband_update: bool,
) -> Result<Vec<u8>, KitError> {
    let mut value = Value::from_reader(Cursor::new(original))?;
    let dictionary = value
        .as_dictionary_mut()
        .ok_or(KitError::MultipartInvalidOptionsPlist)?;
    dictionary.insert("FlashNOR".to_owned(), Value::Boolean(false));
    if disable_baseband_update && !dictionary.contains_key("UpdateBaseband") {
        dictionary.insert("UpdateBaseband".to_owned(), Value::Boolean(false));
    }
    let mut output = Vec::new();
    value.to_writer_xml(&mut output)?;
    Ok(output)
}

/// Point the RestoreDeviceTree/RestoreKernelCache component paths of every
/// build identity at the `Downgrade/` directory, mirroring the BuildManifest
/// edits of both multipart stages. Manifests that already reference
/// `Downgrade/` are returned unchanged, like upstream's idempotence check.
pub fn rewrite_downgrade_paths(manifest: &[u8]) -> Result<Vec<u8>, KitError> {
    if manifest
        .windows(b"Downgrade/".len())
        .any(|w| w == b"Downgrade/")
    {
        return Ok(manifest.to_vec());
    }
    let mut value = Value::from_reader(Cursor::new(manifest))?;
    let root = value
        .as_dictionary_mut()
        .ok_or(KitError::MultipartInvalidManifest)?;
    let identities = root
        .get_mut("BuildIdentities")
        .and_then(Value::as_array_mut)
        .ok_or(KitError::MultipartInvalidManifest)?;
    for identity in identities {
        let Some(manifest) = identity
            .as_dictionary_mut()
            .and_then(|identity| identity.get_mut("Manifest"))
            .and_then(Value::as_dictionary_mut)
        else {
            continue;
        };
        for (component, path) in [
            ("RestoreDeviceTree", "Downgrade/RestoreDeviceTree"),
            ("RestoreKernelCache", "Downgrade/RestoreKernelCache"),
        ] {
            if let Some(info) = manifest
                .get_mut(component)
                .and_then(Value::as_dictionary_mut)
                .and_then(|component| component.get_mut("Info"))
                .and_then(Value::as_dictionary_mut)
            {
                info.insert("Path".to_owned(), Value::String(path.to_owned()));
            }
        }
    }
    let mut output = Vec::new();
    value.to_writer_xml(&mut output)?;
    Ok(output)
}

/// Extract the APTicket DER from a saved signing ticket, mirroring upstream's
/// extraction of the first data block from the SHSH blob. [`SigningTicket`]
/// already guarantees a root ticket is present.
pub fn extract_apticket_der(ticket: &SigningTicket) -> Vec<u8> {
    ticket.root_ticket().to_vec()
}

/// `Firmware/all_flash/all_flash.<board>ap` directory inside the IPSW.
fn all_flash_dir(board_config: &BoardConfig) -> String {
    format!("Firmware/all_flash/all_flash.{}ap", board_config.as_str())
}

fn decrypt_component(data: &[u8], key: &FirmwareKey) -> Result<Vec<u8>, KitError> {
    let encryption = match (key.key(), key.iv()) {
        (Some(key), Some(iv)) => Some((key, iv.as_slice())),
        _ => None,
    };
    Ok(extract_image_payload(data, encryption)?)
}

fn key_for<'a>(keys: &'a FirmwareKeySet, image: &'static str) -> Result<&'a FirmwareKey, KitError> {
    keys.key(image).ok_or(KitError::MultipartMissingKey(image))
}

fn iboot_dfu_path(filename: &str) -> String {
    format!("Firmware/dfu/{filename}")
}

fn payload_bytes(container: &[u8]) -> Result<Vec<u8>, KitError> {
    if container.starts_with(b"3gmI") {
        Ok(extract_image_payload(container, None)?)
    } else {
        Ok(container.to_vec())
    }
}

/// Where the iOS 5.1.1 (9B206) NOR components are read from.
#[derive(Clone, Debug)]
pub enum NorSource {
    /// A local iOS 5.1.1 IPSW.
    Local(PathBuf),
    /// An iOS 5.1.1 IPSW URL read through HTTP range requests.
    Remote(String),
}

enum ComponentSource {
    Local(FirmwareArchive),
    Remote(RemoteFirmwareArchive),
}

impl ComponentSource {
    async fn open(source: &NorSource) -> Result<Self, KitError> {
        match source {
            NorSource::Local(path) => Ok(Self::Local(FirmwareArchive::open(path)?)),
            NorSource::Remote(url) => Ok(Self::Remote(RemoteFirmwareArchive::open(url).await?)),
        }
    }

    async fn read(&self, name: &str) -> Result<Vec<u8>, KitError> {
        match self {
            Self::Local(archive) => Ok(archive.read_entry(name)?),
            Self::Remote(archive) => Ok(archive.read_entry(name).await?),
        }
    }
}

/// Request for building the two multipart custom IPSWs.
#[derive(Clone, Debug)]
pub struct MultipartPrepareRequest {
    product_type: ProductType,
    board_config: BoardConfig,
    target_ipsw: PathBuf,
    custom_ipsw: PathBuf,
    base_ipsw: PathBuf,
    nor_source: NorSource,
    ticket: PathBuf,
    part1_output: PathBuf,
    part2_output: PathBuf,
    cache_root: PathBuf,
    asr_patch: Option<PathBuf>,
    exploit: Option<PathBuf>,
    disable_baseband_update: bool,
}

impl MultipartPrepareRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        product_type: ProductType,
        board_config: BoardConfig,
        target_ipsw: impl Into<PathBuf>,
        custom_ipsw: impl Into<PathBuf>,
        base_ipsw: impl Into<PathBuf>,
        nor_source: NorSource,
        ticket: impl Into<PathBuf>,
        part1_output: impl Into<PathBuf>,
        part2_output: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            product_type,
            board_config,
            target_ipsw: target_ipsw.into(),
            custom_ipsw: custom_ipsw.into(),
            base_ipsw: base_ipsw.into(),
            nor_source,
            ticket: ticket.into(),
            part1_output: part1_output.into(),
            part2_output: part2_output.into(),
            cache_root: cache_root.into(),
            asr_patch: None,
            exploit: None,
            disable_baseband_update: false,
        }
    }

    /// bsdiff patch applied to `usr/sbin/asr` of both restore ramdisks,
    /// replacing the ASR binary copies used when no patch is given.
    pub fn with_asr_patch(mut self, path: impl Into<PathBuf>) -> Self {
        self.asr_patch = Some(path.into());
        self
    }

    /// powdersn0w exploit payload installed as `/exploit` in the part 2
    /// ramdisk of iOS 4.x targets. Not part of the resource catalog, so it
    /// is supplied externally like FourThree's patched components.
    pub fn with_exploit(mut self, path: impl Into<PathBuf>) -> Self {
        self.exploit = Some(path.into());
        self
    }

    /// Mirror of upstream's `--disable-bbupdate` for the part 2 ramdisk
    /// options.plist.
    pub fn with_disable_baseband_update(mut self, enabled: bool) -> Self {
        self.disable_baseband_update = enabled;
        self
    }
}

/// The two built IPSWs of a multipart restore.
pub struct MultipartIpswSummary {
    part1: FirmwareSummary,
    part2: FirmwareSummary,
}

impl MultipartIpswSummary {
    /// NOR flash IPSW restored first.
    pub const fn part1(&self) -> &FirmwareSummary {
        &self.part1
    }

    /// Multipatched target IPSW restored second.
    pub const fn part2(&self) -> &FirmwareSummary {
        &self.part2
    }
}

pub(crate) async fn prepare(
    request: MultipartPrepareRequest,
) -> Result<MultipartIpswSummary, KitError> {
    let target = FirmwareArchive::open(&request.target_ipsw)?;
    let target_manifest = target.build_manifest()?;
    let target_version = target_manifest.product_version().to_string();
    let target_build = target_manifest.build_id().clone();
    if !multipart_support(&request.product_type, &target_version) {
        return Err(KitError::MultipartUnsupportedTarget(format!(
            "{} {target_version}",
            request.product_type
        )));
    }

    let keys = FirmwareKeyProvider::with_cache(&request.cache_root);
    info!(
        version = MULTIPART_NOR_VERSION,
        "fetching NOR component keys"
    );
    let nor_keys = keys
        .fetch(&request.product_type, &BuildId::new(MULTIPART_NOR_BUILD))
        .await?;
    info!(version = %target_version, "fetching target component keys");
    let target_keys = keys.fetch(&request.product_type, &target_build).await?;

    let ticket = SigningTicket::open(&request.ticket)?;
    let apticket = extract_apticket_der(&ticket);
    let scab_template =
        read_resource(&ResourceId::new("ios4-scab-template"), &request.cache_root).await?;
    let asr_patch = match &request.asr_patch {
        Some(path) => Some(tokio::fs::read(path).await?),
        None => None,
    };
    let exploit = match &request.exploit {
        Some(path) => Some(tokio::fs::read(path).await?),
        None => None,
    };

    info!("building part 1 (NOR flash) IPSW");
    let part1 = build_part1(
        &request,
        nor_keys,
        apticket,
        scab_template,
        asr_patch.clone(),
    )
    .await?;
    info!("building part 2 (multipatch) IPSW");
    let part2 = build_part2(
        &request,
        &target,
        &target_version,
        target_keys,
        asr_patch,
        exploit,
    )
    .await?;
    Ok(MultipartIpswSummary { part1, part2 })
}

async fn read_resource(id: &ResourceId, cache_root: &std::path::Path) -> Result<Vec<u8>, KitError> {
    let path = crate::firmware::fetch_resource(id, cache_root.to_owned()).await?;
    Ok(tokio::fs::read(path).await?)
}

async fn build_part1(
    request: &MultipartPrepareRequest,
    keys: FirmwareKeySet,
    apticket: Vec<u8>,
    scab_template: Vec<u8>,
    asr_patch: Option<Vec<u8>>,
) -> Result<FirmwareSummary, KitError> {
    let nor = ComponentSource::open(&request.nor_source).await?;
    let all_flash = all_flash_dir(&request.board_config);

    let mut raw = Vec::new();
    for image in [
        "iBSS",
        "iBEC",
        "DeviceTree",
        "Kernelcache",
        "RestoreRamdisk",
    ] {
        let key = key_for(&keys, image)?;
        let path = match image {
            "iBSS" | "iBEC" => iboot_dfu_path(key.filename()),
            "DeviceTree" => format!("{all_flash}/{}", key.filename()),
            _ => key.filename().to_owned(),
        };
        let data = nor.read(&path).await?;
        raw.push((image, path, data));
    }
    let manifest = nor.read("BuildManifest.plist").await?;

    let base = FirmwareArchive::open(&request.base_ipsw)?;
    let mut flash_entries = Vec::new();
    let devicetree_name = format!("DeviceTree.{}ap.img3", request.board_config.as_str());
    for name in base.entry_names()? {
        if name.starts_with(&format!("{all_flash}/"))
            && !name.ends_with('/')
            && name != format!("{all_flash}/{devicetree_name}")
        {
            flash_entries.push((name.clone(), base.read_entry(&name)?));
        }
    }
    // The part 1 NOR contents carry the target version's DeviceTree.
    let target = FirmwareArchive::open(&request.target_ipsw)?;
    flash_entries.push((
        format!("{all_flash}/{devicetree_name}"),
        target.read_entry(&format!("{all_flash}/{devicetree_name}"))?,
    ));

    let output = request.part1_output.clone();
    let board = request.board_config.clone();
    let entries = tokio::task::spawn_blocking(move || {
        let mut entries = Vec::new();
        for (image, _, data) in raw {
            let key = key_for(&keys, image)?;
            let decrypted = decrypt_component(&data, key)?;
            match image {
                "iBSS" => {
                    let patched = legacy_ios_image::patch_iboot32(&decrypted, None, None)?;
                    entries.push((
                        iboot_dfu_path(key.filename()),
                        replace_image_payload(&data, &patched, None)?,
                    ));
                }
                "iBEC" => {
                    let patched = legacy_ios_image::patch_iboot32(
                        &decrypted,
                        Some(MULTIPART_IBEC_BOOT_ARGS),
                        None,
                    )?;
                    entries.push((
                        iboot_dfu_path(key.filename()),
                        replace_image_payload(&data, &patched, None)?,
                    ));
                }
                "DeviceTree" => entries.push(("Downgrade/RestoreDeviceTree".to_owned(), decrypted)),
                "Kernelcache" => {
                    entries.push(("Downgrade/RestoreKernelCache".to_owned(), decrypted))
                }
                "RestoreRamdisk" => {
                    let mut ramdisk = HfsImage::parse(decrypted)?;
                    let options_path = format!(
                        "/usr/local/share/restore/options.{}ap.plist",
                        board.as_str()
                    );
                    let mut mutations = vec![
                        HfsMutation::Grow {
                            size: PART1_RAMDISK_SIZE,
                        },
                        HfsMutation::Remove {
                            path: options_path.clone(),
                            recursive: false,
                        },
                        HfsMutation::AddFile {
                            path: options_path,
                            data: nor_options_plist(),
                        },
                    ];
                    if let Some(patch) = &asr_patch {
                        let asr = ramdisk.read("/usr/sbin/asr")?;
                        let patched = apply_bsdiff(&asr, patch)?;
                        mutations.extend([
                            HfsMutation::Remove {
                                path: "/usr/sbin/asr".to_owned(),
                                recursive: false,
                            },
                            HfsMutation::AddFile {
                                path: "/usr/sbin/asr".to_owned(),
                                data: patched,
                            },
                            HfsMutation::Chmod {
                                path: "/usr/sbin/asr".to_owned(),
                                mode: 0o755,
                            },
                        ]);
                    }
                    apply_mutations(&mut ramdisk, mutations)?;
                    entries.push((
                        key.filename().to_owned(),
                        replace_image_payload(&data, &ramdisk.into_bytes(), None)?,
                    ));
                }
                _ => unreachable!("fixed component list"),
            }
        }
        // Empty placeholder rootfs; the part 1 options.plist disables the
        // system image restore.
        let rootfs = key_for(&keys, "RootFS")?.filename().to_owned();
        entries.push((rootfs, Vec::new()));
        entries.push((
            "BuildManifest.plist".to_owned(),
            rewrite_downgrade_paths(&manifest)?,
        ));
        // The APTicket resealed into the scab template boots the restored
        // chain from NOR.
        let applelogo = replace_image_payload(&scab_template, &apticket, None)?;
        let mut flash_entries = flash_entries;
        for (name, data) in &mut flash_entries {
            if name.ends_with("/manifest") {
                let mut text = String::from_utf8_lossy(data).into_owned();
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str("applelogoT.img3\n");
                *data = text.into_bytes();
            }
        }
        flash_entries.push((format!("{all_flash}/applelogoT.img3"), applelogo));
        entries.extend(flash_entries);
        Ok::<_, KitError>(entries)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;

    write_ipsw_from_scratch(entries, &output).await?;
    FirmwareSummary::inspect(output)
}

async fn write_ipsw_from_scratch(
    entries: Vec<(String, Vec<u8>)>,
    destination: &std::path::Path,
) -> Result<(), KitError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    tokio::fs::create_dir_all(parent).await?;
    let skeleton = parent.join(".multipart-empty.zip");
    tokio::fs::write(&skeleton, EMPTY_ZIP).await?;
    let mut builder = CustomIpswBuilder::new(FirmwareArchive::open(&skeleton)?);
    for (name, data) in entries {
        builder = builder.replace(name, data)?;
    }
    builder.build(destination).await?;
    tokio::fs::remove_file(&skeleton).await?;
    Ok(())
}

async fn build_part2(
    request: &MultipartPrepareRequest,
    target: &FirmwareArchive,
    target_version: &str,
    keys: FirmwareKeySet,
    asr_patch: Option<Vec<u8>>,
    exploit: Option<Vec<u8>>,
) -> Result<FirmwareSummary, KitError> {
    let custom = FirmwareArchive::open(&request.custom_ipsw)?;
    let manifest_bytes = custom.read_entry("BuildManifest.plist")?;
    let manifest = BuildManifest::from_reader(Cursor::new(&manifest_bytes))?;
    let identity = manifest.select_identity(
        &request.board_config,
        legacy_ios_firmware::RestoreBehavior::Erase,
    )?;
    let ramdisk_path = identity.component_path("RestoreRamDisk")?.to_owned();
    let custom_ramdisk_container = custom.read_entry(&ramdisk_path)?;

    let all_flash = all_flash_dir(&request.board_config);
    let mut raw = Vec::new();
    for image in [
        "iBSS",
        "iBEC",
        "DeviceTree",
        "Kernelcache",
        "RestoreRamdisk",
    ] {
        let key = key_for(&keys, image)?;
        let path = match image {
            "iBSS" | "iBEC" => iboot_dfu_path(key.filename()),
            "DeviceTree" => format!("{all_flash}/{}", key.filename()),
            _ => key.filename().to_owned(),
        };
        let data = target.read_entry(&path)?;
        raw.push((image, path, data));
    }

    let payload = ramdisk_payload(&request.product_type, target_version);
    let bin_tar = match &payload {
        Some(payload) => Some(read_resource(&payload.bin_tar, &request.cache_root).await?),
        None => None,
    };
    let reboot = match &payload {
        Some(payload) => Some(read_resource(&payload.reboot, &request.cache_root).await?),
        None => None,
    };
    if payload.is_some() && exploit.is_none() {
        warn!("no powdersn0w exploit payload provided; the multistage reboot will lack /exploit");
    }

    let custom_source = request.custom_ipsw.clone();
    let output = request.part2_output.clone();
    let options_name = options_plist_name(target_version, &request.board_config);
    let disable_baseband_update = request.disable_baseband_update;
    let replacements = tokio::task::spawn_blocking(move || {
        let custom_ramdisk = HfsImage::parse(payload_bytes(&custom_ramdisk_container)?)?;
        if custom_ramdisk.read("/multipatched").is_ok() {
            return Err(KitError::MultipartAlreadyPatched);
        }

        let mut replacements: Vec<(String, Vec<u8>)> = vec![(
            "BuildManifest.plist".to_owned(),
            rewrite_downgrade_paths(&manifest_bytes)?,
        )];
        for (image, path, data) in raw {
            let key = key_for(&keys, image)?;
            let decrypted = decrypt_component(&data, key)?;
            match image {
                "iBSS" | "iBEC" => {
                    let patched = legacy_ios_image::patch_iboot32(
                        &decrypted,
                        Some(MULTIPATCH_BOOT_ARGS),
                        None,
                    )?;
                    replacements.push((path, replace_image_payload(&data, &patched, None)?));
                }
                "DeviceTree" => {
                    replacements.push(("Downgrade/RestoreDeviceTree".to_owned(), decrypted));
                }
                "Kernelcache" => {
                    replacements.push(("Downgrade/RestoreKernelCache".to_owned(), decrypted));
                }
                "RestoreRamdisk" => {
                    let options_path = format!("/usr/local/share/restore/{options_name}");
                    let options = custom_ramdisk.read(&options_path)?;
                    let options = edit_options_plist(&options, disable_baseband_update)?;

                    let mut ramdisk = HfsImage::parse(decrypted)?;
                    let mut mutations = vec![
                        HfsMutation::Grow {
                            size: PART2_RAMDISK_SIZE,
                        },
                        HfsMutation::Remove {
                            path: options_path.clone(),
                            recursive: false,
                        },
                        HfsMutation::AddFile {
                            path: options_path,
                            data: options,
                        },
                    ];
                    // Without a bundle ASR patch the target ramdisk keeps the
                    // ASR binary of the custom IPSW ramdisk, like upstream's
                    // fallback branch.
                    let asr = match &asr_patch {
                        Some(patch) => apply_bsdiff(&ramdisk.read("/usr/sbin/asr")?, patch)?,
                        None => custom_ramdisk.read("/usr/sbin/asr")?,
                    };
                    mutations.extend([
                        HfsMutation::Remove {
                            path: "/usr/sbin/asr".to_owned(),
                            recursive: false,
                        },
                        HfsMutation::AddFile {
                            path: "/usr/sbin/asr".to_owned(),
                            data: asr,
                        },
                        HfsMutation::Chmod {
                            path: "/usr/sbin/asr".to_owned(),
                            mode: 0o755,
                        },
                    ]);
                    if let (Some(bin_tar), Some(reboot)) = (&bin_tar, &reboot) {
                        mutations.extend([
                            HfsMutation::Untar {
                                archive: bin_tar.clone(),
                            },
                            HfsMutation::Move {
                                source: "/sbin/reboot".to_owned(),
                                destination: "/sbin/reboot_".to_owned(),
                            },
                            HfsMutation::AddFile {
                                path: "/sbin/reboot".to_owned(),
                                data: reboot.clone(),
                            },
                            HfsMutation::Chmod {
                                path: "/sbin/reboot".to_owned(),
                                mode: 0o755,
                            },
                            HfsMutation::Chown {
                                path: "/sbin/reboot".to_owned(),
                                owner: 0,
                                group: 0,
                            },
                        ]);
                        if let Some(exploit) = &exploit {
                            mutations.push(HfsMutation::AddFile {
                                path: "/exploit".to_owned(),
                                data: exploit.clone(),
                            });
                        }
                    }
                    mutations.push(HfsMutation::AddFile {
                        path: "/multipatched".to_owned(),
                        data: b"multipatched\n".to_vec(),
                    });
                    apply_mutations(&mut ramdisk, mutations)?;
                    replacements.push((
                        ramdisk_path.clone(),
                        replace_image_payload(&data, &ramdisk.into_bytes(), None)?,
                    ));
                }
                _ => unreachable!("fixed component list"),
            }
        }
        Ok::<_, KitError>(replacements)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;

    let mut builder = CustomIpswBuilder::new(FirmwareArchive::open(&custom_source)?);
    for (name, data) in replacements {
        builder = builder.replace(name, data)?;
    }
    builder.build(&output).await?;
    FirmwareSummary::inspect(output)
}

/// Two-stage multipart restore execution: part 1 (NOR flash) through the
/// restore engine without final verification, an inter-stage wait for the
/// device to re-enter DFU/recovery, then part 2 on the pwned boot chain.
pub struct MultipartRestoreRequest {
    part1: RestoreExecutionRequest,
    part2: RestoreExecutionRequest,
}

impl MultipartRestoreRequest {
    pub fn new(part1: RestoreExecutionRequest, part2: RestoreExecutionRequest) -> Self {
        Self {
            // The NOR flash stage does not boot a normal system.
            part1: part1.with_final_verification(false),
            part2,
        }
    }
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    tss: TssClient,
    request: MultipartRestoreRequest,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(128);
    tokio::spawn(async move {
        match execute(&devices, &leases, &tss, &emitter, request).await {
            Ok(Some(outcome)) => {
                emitter
                    .emit(legacy_ios_core::OperationEvent::Completed { outcome })
                    .await;
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
    tss: &TssClient,
    emitter: &OperationEmitter,
    request: MultipartRestoreRequest,
) -> Result<Option<legacy_ios_core::OperationOutcome>, KitError> {
    let ecid = request.part2.device().ecid();

    info!("multipart stage 1: NOR flash restore");
    if crate::restore_execution::execute(devices, leases, tss, emitter, request.part1)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    if emitter.is_cancelled() {
        return Ok(None);
    }

    info!("multipart stage 2: waiting for the device to re-enter DFU/recovery");
    emitter
        .emit(legacy_ios_core::OperationEvent::PhaseStarted {
            phase: legacy_ios_core::OperationPhase::WaitingForDevice,
            cancellation: legacy_ios_core::CancellationSafety::Immediate,
        })
        .await;
    emitter
        .emit(legacy_ios_core::OperationEvent::ActionRequired {
            id: ActionId::new(1),
            action: ActionKind::FollowDfuInstructions {
                steps: vec![
                    "The NOR flash stage is complete; do not disconnect the device.".to_owned(),
                    "Put the device into DFU mode to continue with the target restore.".to_owned(),
                ],
            },
        })
        .await;
    if !await_bootloader_device(ecid, emitter).await? {
        return Ok(None);
    }

    info!("multipart stage 2: target restore");
    crate::restore_execution::execute(devices, leases, tss, emitter, request.part2).await
}

async fn await_bootloader_device(
    ecid: Option<Ecid>,
    emitter: &OperationEmitter,
) -> Result<bool, KitError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        if emitter.is_cancelled() {
            return Ok(false);
        }
        match IbootClient::open(ecid).await {
            Ok(_) => return Ok(true),
            Err(error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(KitError::MultipartStageTimeout);
                }
                tracing::debug!(%error, "waiting for the device between multipart stages");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_devices_and_versions() {
        for device in [
            "iPhone3,1",
            "iPhone3,2",
            "iPhone3,3",
            "iPad1,1",
            "iPod3,1",
            "iPod4,1",
        ] {
            let product = ProductType::from(device);
            assert!(multipart_support(&product, "3.1.3"), "{device} 3.x");
            assert!(multipart_support(&product, "4.0"), "{device} 4.0");
            assert!(multipart_support(&product, "4.2.1"), "{device} 4.2.1");
            assert!(!multipart_support(&product, "4.3.5"), "{device} 4.3.x");
            assert!(!multipart_support(&product, "5.1.1"), "{device} 5.x");
        }
        assert!(!multipart_support(&ProductType::from("iPhone4,1"), "4.2.1"));
        assert!(!multipart_support(&ProductType::from("iPhone2,1"), "3.1.3"));
    }

    #[test]
    fn maps_base_versions() {
        assert_eq!(
            multipart_base_version(&ProductType::from("iPhone3,1")),
            Some("7.1.2")
        );
        assert_eq!(
            multipart_base_version(&ProductType::from("iPhone3,3")),
            Some("5.1.1")
        );
        assert_eq!(
            multipart_base_version(&ProductType::from("iPod4,1")),
            Some("6.1.3")
        );
        assert_eq!(
            multipart_base_version(&ProductType::from("iPhone4,1")),
            None
        );
    }

    #[test]
    fn maps_reboot4_variants() {
        assert_eq!(
            reboot4_resource(&ProductType::from("iPod4,1")).as_str(),
            "ios4-reboot"
        );
        assert_eq!(
            reboot4_resource(&ProductType::from("iPhone3,1")).as_str(),
            "ios4-reboot-nor"
        );
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for device in ["iPod4,1", "iPhone3,1", "iPad1,1"] {
            let id = reboot4_resource(&ProductType::from(device));
            assert!(catalog.get(&id).is_some(), "missing resource {id}");
        }
    }

    #[test]
    fn maps_ramdisk_payload_by_version() {
        let payload =
            ramdisk_payload(&ProductType::from("iPhone3,1"), "4.2.1").expect("4.x has a payload");
        assert_eq!(payload.bin_tar.as_str(), "ios4-restore-bin-tar");
        assert_eq!(payload.reboot.as_str(), "ios4-reboot-nor");
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        assert!(catalog.get(&payload.bin_tar).is_some());
        assert!(catalog.get(&payload.reboot).is_some());
        assert!(ramdisk_payload(&ProductType::from("iPhone3,1"), "3.1.3").is_none());
    }

    #[test]
    fn names_options_plist() {
        assert_eq!(
            options_plist_name("4.2.1", &BoardConfig::from("n90")),
            "options.plist"
        );
        assert_eq!(
            options_plist_name("3.1.3", &BoardConfig::from("n90")),
            "options.plist"
        );
        assert_eq!(
            options_plist_name("5.1.1", &BoardConfig::from("n90")),
            "options.n90ap.plist"
        );
    }

    #[test]
    fn nor_options_plist_disables_restore_phases() {
        let value = Value::from_reader(Cursor::new(nor_options_plist())).unwrap();
        let dictionary = value.as_dictionary().unwrap();
        for key in [
            "CreateFilesystemPartitions",
            "UpdateBaseband",
            "SystemImage",
        ] {
            assert_eq!(dictionary.get(key).and_then(Value::as_boolean), Some(false));
        }
    }

    #[test]
    fn edits_options_plist() {
        let original = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>UpdateBaseband</key><true/>
</dict></plist>"#;
        let edited = edit_options_plist(original, true).unwrap();
        let value = Value::from_reader(Cursor::new(edited)).unwrap();
        let dictionary = value.as_dictionary().unwrap();
        assert_eq!(
            dictionary.get("FlashNOR").and_then(Value::as_boolean),
            Some(false)
        );
        // An existing UpdateBaseband entry is left untouched.
        assert_eq!(
            dictionary.get("UpdateBaseband").and_then(Value::as_boolean),
            Some(true)
        );

        let without_baseband = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
</dict></plist>"#;
        let edited = edit_options_plist(without_baseband, true).unwrap();
        let value = Value::from_reader(Cursor::new(edited)).unwrap();
        let dictionary = value.as_dictionary().unwrap();
        assert_eq!(
            dictionary.get("UpdateBaseband").and_then(Value::as_boolean),
            Some(false)
        );
        let edited = edit_options_plist(without_baseband, false).unwrap();
        let value = Value::from_reader(Cursor::new(edited)).unwrap();
        assert!(
            !value
                .as_dictionary()
                .unwrap()
                .contains_key("UpdateBaseband")
        );
    }

    #[test]
    fn rewrites_downgrade_paths() {
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>BuildIdentities</key><array><dict>
<key>Manifest</key><dict>
<key>RestoreDeviceTree</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/all_flash.n90ap/DeviceTree.n90ap.img3</string></dict></dict>
<key>RestoreKernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release.n90</string></dict></dict>
<key>OS</key><dict><key>Info</key><dict><key>Path</key><string>rootfs.dmg</string></dict></dict>
</dict>
</dict></array></dict></plist>"#;
        let rewritten = rewrite_downgrade_paths(manifest).unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("Downgrade/RestoreDeviceTree"));
        assert!(text.contains("Downgrade/RestoreKernelCache"));
        assert!(text.contains("rootfs.dmg"));
        assert!(!text.contains("kernelcache.release.n90"));

        // Idempotent, like upstream's Downgrade grep check.
        let again = rewrite_downgrade_paths(text.as_bytes()).unwrap();
        assert_eq!(again, text.as_bytes());
    }

    #[test]
    fn extracts_apticket_der() {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("APTicket".to_owned(), Value::Data(vec![0x30, 0x82, 0x01]));
        let ticket = SigningTicket::from_dictionary(dictionary).unwrap();
        assert_eq!(extract_apticket_der(&ticket), vec![0x30, 0x82, 0x01]);
    }

    #[tokio::test]
    async fn writes_ipsw_from_scratch() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("part1.ipsw");
        write_ipsw_from_scratch(
            vec![
                ("BuildManifest.plist".to_owned(), b"manifest".to_vec()),
                (
                    "Firmware/all_flash/all_flash.n90ap/manifest".to_owned(),
                    b"applelogoT.img3\n".to_vec(),
                ),
            ],
            &destination,
        )
        .await
        .unwrap();
        let archive = FirmwareArchive::open(&destination).unwrap();
        assert_eq!(
            archive.read_entry("BuildManifest.plist").unwrap(),
            b"manifest"
        );
        assert_eq!(
            archive
                .read_entry("Firmware/all_flash/all_flash.n90ap/manifest")
                .unwrap(),
            b"applelogoT.img3\n"
        );
    }
}
