//! iOS 3.x/4.x multipart (two-stage) custom IPSW preparation and restore
//! orchestration, mirroring upstream `ipsw_prepare_ios4multipart`,
//! `ipsw_prepare_multipatch`, and the powdersn0w two-stage restore flow in
//! `restore_prepare`.
//!
//! Stage 1 (part 1) is a NOR flash IPSW built from iOS 5.1.1 (9B206) restore
//! components: RSA-patched iBSS/iBEC (the iBEC skips the APTicket check and
//! boots the restore ramdisk with `nand-enable-reformat=1`), decrypted
//! DeviceTree/Kernelcache under `Downgrade/`, a ramdisk grown to 18 MB whose
//! options.plist disables filesystem creation, baseband update, and system
//! image restore and whose ASR binary is patched with the bundled bsdiff
//! patch, an empty dummy RootFS, the base all_flash contents with the target
//! version's DeviceTree swapped in, the target version's iBoot patched with
//! the boot-partition/boot-ramdisk/logo4 patch set, the target AppleLogo
//! mangled to its iOS 4 form, and the device APTicket resealed into the scab
//! IMG3 template as `applelogoT.img3`.
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
    FirmwareKeySet, RemoteFirmwareArchive, SigningTicket, TssClient, UstarBuilder,
};
use legacy_ios_image::{
    BootPartition, HfsImage, Iboot32PatchOptions, apply_bsdiff, extract_image_payload,
    patch_iboot32_with_options, replace_image_payload,
};
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

/// Default boot-args of the target iBoot patched into the part 1 IPSW,
/// mirroring upstream `device_bootargs_default`.
pub const MULTIPART_IBOOT_BOOT_ARGS: &str = "pio-error=0 debug=0x2014e serial=3";

/// Verbose boot-args variant of the target iBoot, selected by upstream
/// `--ipsw-verbose`.
pub const MULTIPART_IBOOT_BOOT_ARGS_VERBOSE: &str = "pio-error=0 -v";

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

/// Where the patched target iBoot of a part 1 build goes, mirroring the
/// device branches of upstream `ipsw_prepare_ios4multipart`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetIbootDisposition {
    /// Added to all_flash as `iBoot2.img3` with a manifest entry.
    AllFlash,
    /// Written raw to the sidecar output; iPad1,1 iOS 3 targets keep it as
    /// `iBoot3_<ecid>` for the restore-time SSH upload.
    SidecarRaw,
    /// Written to the sidecar output as a tar archive holding the iBoot under
    /// the name `iBEC`; iPad1,1 iOS 4 targets feed it to the externally run
    /// powdersn0w base preparation.
    SidecarTar,
}

pub fn target_iboot_disposition(
    product_type: &ProductType,
    target_version: &str,
) -> TargetIbootDisposition {
    if product_type.as_str() == "iPad1,1" {
        if target_version.starts_with("3.") {
            TargetIbootDisposition::SidecarRaw
        } else {
            TargetIbootDisposition::SidecarTar
        }
    } else {
        TargetIbootDisposition::AllFlash
    }
}

/// iBoot32Patcher option set for the target iBoot of the part 1 IPSW,
/// mirroring the `ExtraArr` of upstream `ipsw_prepare_ios4multipart`:
/// `--boot-partition --boot-ramdisk --logo4`, `--433` unless the target is
/// 4.2.9/4.2.10, and `-b` with the default boot-args (verbose variant under
/// `--ipsw-verbose`) plus any user-supplied extras.
pub fn target_iboot_patch_options(
    target_version: &str,
    verbose: bool,
    extra_boot_args: Option<&str>,
) -> Iboot32PatchOptions {
    let mut boot_args = if verbose {
        MULTIPART_IBOOT_BOOT_ARGS_VERBOSE
    } else {
        MULTIPART_IBOOT_BOOT_ARGS
    }
    .to_owned();
    if let Some(extra) = extra_boot_args.filter(|extra| !extra.is_empty()) {
        boot_args.push(' ');
        boot_args.push_str(extra);
    }
    Iboot32PatchOptions {
        boot_args: Some(boot_args),
        boot_partition: Some(BootPartition::Standard),
        boot_ramdisk: true,
        logo4: true,
        jump_iboot_433: !matches!(target_version, "4.2.9" | "4.2.10"),
        ..Iboot32PatchOptions::default()
    }
}

/// Two-byte image-tag mangle applied at offsets 0x10 and 0x20 of the target
/// iBoot container, mirroring upstream `patch_iboot`: iPad1,1 turns the iBoot
/// into an iBEC, every other multipart device into an iB0B.
fn iboot_tag_mangle(product_type: &ProductType) -> [u8; 2] {
    if product_type.as_str() == "iPad1,1" {
        *b"ce"
    } else {
        *b"bo"
    }
}

/// Whether the target AppleLogo is added as a separate `applelogo4.img3`
/// (devices whose latest version is 5.x) rather than replacing the base
/// all_flash applelogo manifest entry, mirroring upstream's
/// `device_latest_vers == "5"*` branch.
fn applelogo_separate_entry(product_type: &ProductType) -> bool {
    multipart_base_version(product_type) == Some("5.1.1")
}

/// How the target AppleLogo appears in the part 1 all_flash manifest.
enum AppleLogoEntry<'a> {
    /// Appended as `applelogo4.img3` after `applelogoT.img3`.
    Separate,
    /// All `applelogo` lines of the base manifest (including the just-added
    /// `applelogoT.img3`, like upstream's `sed '/applelogo/d'`) are dropped
    /// and the target logo is appended under its original file name.
    Replace(&'a str),
}

/// Rewrite the base all_flash `manifest` file of the part 1 IPSW, applying
/// the iBoot2/AppleLogo edits of upstream `ipsw_prepare_ios4multipart` in
/// upstream's order.
fn edit_all_flash_manifest(text: &str, add_iboot2: bool, applelogo: &AppleLogoEntry) -> String {
    let mut output = String::new();
    let mut push_line = |line: &str| {
        output.push_str(line);
        output.push('\n');
    };
    let base_lines: Vec<&str> = match applelogo {
        AppleLogoEntry::Replace(_) => text
            .lines()
            .filter(|line| !line.contains("applelogo"))
            .collect(),
        AppleLogoEntry::Separate => text.lines().collect(),
    };
    for line in base_lines {
        push_line(line);
    }
    if add_iboot2 {
        push_line("iBoot2.img3");
    }
    match applelogo {
        AppleLogoEntry::Separate => {
            push_line("applelogoT.img3");
            push_line("applelogo4.img3");
        }
        AppleLogoEntry::Replace(name) => push_line(name),
    }
    output
}

/// Build a ustar archive holding a single file, mirroring upstream's
/// `tar -cvf iBoot.tar iBEC` for iPad1,1 iOS 4 targets.
fn tar_single_file(name: &str, data: &[u8]) -> Vec<u8> {
    let mut tar = UstarBuilder::new();
    tar.add_file(name, data).expect("constant ustar entry name");
    tar.finish()
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

fn encryption_of(key: &FirmwareKey) -> Option<(&[u8], &[u8])> {
    match (key.key(), key.iv()) {
        (Some(key), Some(iv)) => Some((key, iv.as_slice())),
        _ => None,
    }
}

fn decrypt_component(data: &[u8], key: &FirmwareKey) -> Result<Vec<u8>, KitError> {
    Ok(extract_image_payload(data, encryption_of(key))?)
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
    verbose_boot_args: bool,
    boot_args: Option<String>,
    iboot_output: Option<PathBuf>,
    skip_first: bool,
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
            verbose_boot_args: false,
            boot_args: None,
            iboot_output: None,
            skip_first: false,
        }
    }

    /// bsdiff patch applied to `usr/sbin/asr` of the part 2 ramdisk,
    /// replacing the ASR binary copy used when no patch is given. The part 1
    /// ramdisk always uses the bundled iOS 5.1.1 ASR patch, like upstream.
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

    /// Verbose boot-args variant of the target iBoot patched into the part 1
    /// IPSW, mirroring upstream's `--ipsw-verbose`.
    pub fn with_verbose_boot_args(mut self, enabled: bool) -> Self {
        self.verbose_boot_args = enabled;
        self
    }

    /// Extra boot-args appended to the target iBoot boot-args, mirroring
    /// upstream's `--bootargs`.
    pub fn with_boot_args(mut self, args: impl Into<String>) -> Self {
        self.boot_args = Some(args.into());
        self
    }

    /// Output path of the patched target iBoot sidecar required on iPad1,1:
    /// the raw iBoot for iOS 3 targets (upstream's `iBoot3_<ecid>`), or a tar
    /// holding it as `iBEC` for iOS 4 targets (upstream's `iBoot.tar`).
    pub fn with_iboot_output(mut self, path: impl Into<PathBuf>) -> Self {
        self.iboot_output = Some(path.into());
        self
    }

    /// Mirror of upstream's `--skip-first`: keep the existing part 2 IPSW and
    /// build only the part 1 NOR flash IPSW, for continuing a powdersn0w
    /// 4.2.x or lower restore after the multipatched target already exists.
    pub fn with_skip_first(mut self, enabled: bool) -> Self {
        self.skip_first = enabled;
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
    if request.skip_first && !tokio::fs::try_exists(&request.part2_output).await? {
        return Err(KitError::MultipartMissingPart2(
            request.part2_output.clone(),
        ));
    }

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
    // The part 1 ramdisk always takes the bundled iOS 5.1.1 ASR patch
    // (upstream resources/patch/old); the request-level patch only feeds the
    // part 2 ramdisk, like upstream's FirmwareBundle asr.patch.
    let part1_asr_patch =
        read_resource(&ResourceId::new("ios4-asr-patch"), &request.cache_root).await?;
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
        &target,
        &target_version,
        nor_keys,
        target_keys.clone(),
        apticket,
        scab_template,
        part1_asr_patch,
    )
    .await?;
    let part2 = if request.skip_first {
        info!("skip-first: keeping the existing part 2 IPSW");
        FirmwareSummary::inspect(request.part2_output.clone())?
    } else {
        info!("building part 2 (multipatch) IPSW");
        build_part2(
            &request,
            &target,
            &target_version,
            target_keys,
            asr_patch,
            exploit,
        )
        .await?
    };
    Ok(MultipartIpswSummary { part1, part2 })
}

async fn read_resource(id: &ResourceId, cache_root: &std::path::Path) -> Result<Vec<u8>, KitError> {
    let path = crate::firmware::fetch_resource(id, cache_root.to_owned()).await?;
    Ok(tokio::fs::read(path).await?)
}

#[allow(clippy::too_many_arguments)]
async fn build_part1(
    request: &MultipartPrepareRequest,
    target: &FirmwareArchive,
    target_version: &str,
    keys: FirmwareKeySet,
    target_keys: FirmwareKeySet,
    apticket: Vec<u8>,
    scab_template: Vec<u8>,
    asr_patch: Vec<u8>,
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
    flash_entries.push((
        format!("{all_flash}/{devicetree_name}"),
        target.read_entry(&format!("{all_flash}/{devicetree_name}"))?,
    ));

    // Target version's iBoot and AppleLogo, patched/mangled into the all_flash
    // contents like upstream's patch_iboot and AppleLogo branches.
    let iboot_key = key_for(&target_keys, "iBoot")?;
    let iboot_container = target.read_entry(&format!("{all_flash}/{}", iboot_key.filename()))?;
    let logo_key = key_for(&target_keys, "AppleLogo")?;
    let logo_name = logo_key.filename().to_owned();
    let logo_container = target.read_entry(&format!("{all_flash}/{logo_name}"))?;

    let disposition = target_iboot_disposition(&request.product_type, target_version);
    if disposition != TargetIbootDisposition::AllFlash && request.iboot_output.is_none() {
        return Err(KitError::MultipartMissingIbootOutput);
    }
    let iboot_options = target_iboot_patch_options(
        target_version,
        request.verbose_boot_args,
        request.boot_args.as_deref(),
    );
    let mangle = iboot_tag_mangle(&request.product_type);
    let applelogo_separate = applelogo_separate_entry(&request.product_type);

    let output = request.part1_output.clone();
    let board = request.board_config.clone();
    let (entries, iboot_sidecar) = tokio::task::spawn_blocking(move || {
        let mut entries = Vec::new();
        for (image, _, data) in raw {
            let key = key_for(&keys, image)?;
            let decrypted = decrypt_component(&data, key)?;
            match image {
                "iBSS" => {
                    let patched =
                        patch_iboot32_with_options(&decrypted, &Iboot32PatchOptions::default())?;
                    entries.push((
                        iboot_dfu_path(key.filename()),
                        replace_image_payload(&data, &patched, None)?,
                    ));
                }
                "iBEC" => {
                    let patched = patch_iboot32_with_options(
                        &decrypted,
                        &Iboot32PatchOptions {
                            boot_args: Some(MULTIPART_IBEC_BOOT_ARGS.to_owned()),
                            ticket: true,
                            ..Iboot32PatchOptions::default()
                        },
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
                    let asr = apply_bsdiff(&ramdisk.read("/usr/sbin/asr")?, &asr_patch)?;
                    let mutations = vec![
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
                    ];
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

        // Target iBoot: decrypt, patch, mangle the image tag, and re-encrypt
        // into the mangled container with the target keys.
        let iboot_key = key_for(&target_keys, "iBoot")?;
        let decrypted = decrypt_component(&iboot_container, iboot_key)?;
        let patched = patch_iboot32_with_options(&decrypted, &iboot_options)?;
        let mut template = iboot_container;
        template[0x10..0x12].copy_from_slice(&mangle);
        template[0x20..0x22].copy_from_slice(&mangle);
        let iboot = replace_image_payload(&template, &patched, encryption_of(iboot_key))?;

        // Target AppleLogo mangled to its iOS 4 form.
        let mut logo = logo_container;
        logo[0x10..0x12].copy_from_slice(b"4g");
        logo[0x20..0x22].copy_from_slice(b"4g");
        let applelogo = if applelogo_separate {
            AppleLogoEntry::Separate
        } else {
            AppleLogoEntry::Replace(logo_name.as_str())
        };

        // The APTicket resealed into the scab template boots the restored
        // chain from NOR.
        let apticket_img3 = replace_image_payload(&scab_template, &apticket, None)?;

        let iboot_sidecar = match disposition {
            TargetIbootDisposition::AllFlash => {
                flash_entries.push((format!("{all_flash}/iBoot2.img3"), iboot));
                None
            }
            TargetIbootDisposition::SidecarRaw | TargetIbootDisposition::SidecarTar => Some(iboot),
        };
        flash_entries.push((format!("{all_flash}/applelogoT.img3"), apticket_img3));
        match &applelogo {
            AppleLogoEntry::Separate => {
                flash_entries.push((format!("{all_flash}/applelogo4.img3"), logo));
            }
            AppleLogoEntry::Replace(name) => {
                let path = format!("{all_flash}/{name}");
                match flash_entries.iter_mut().find(|entry| entry.0 == path) {
                    Some(entry) => entry.1 = logo,
                    None => flash_entries.push((path, logo)),
                }
            }
        }
        for (name, data) in &mut flash_entries {
            if name.ends_with("/manifest") {
                let text = String::from_utf8_lossy(data).into_owned();
                *data = edit_all_flash_manifest(
                    &text,
                    disposition == TargetIbootDisposition::AllFlash,
                    &applelogo,
                )
                .into_bytes();
            }
        }
        entries.extend(flash_entries);
        Ok::<_, KitError>((entries, iboot_sidecar))
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;

    if let Some(iboot) = iboot_sidecar {
        let output = request
            .iboot_output
            .as_ref()
            .ok_or(KitError::MultipartMissingIbootOutput)?;
        let data = match disposition {
            TargetIbootDisposition::SidecarRaw => iboot,
            TargetIbootDisposition::SidecarTar => tar_single_file("iBEC", &iboot),
            TargetIbootDisposition::AllFlash => unreachable!("no sidecar for all_flash iBoot"),
        };
        if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(output, data).await?;
    }

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

    // iPod3,1 iOS 3.1 targets take the options.plist template bundled
    // upstream instead of the custom ramdisk's own options.plist.
    let options_override =
        if request.product_type.as_str() == "iPod3,1" && target_version.starts_with("3.1") {
            Some(
                read_resource(
                    &ResourceId::new("ios4-options-n18-plist"),
                    &request.cache_root,
                )
                .await?,
            )
        } else {
            None
        };

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
                    let options = match &options_override {
                        Some(override_plist) => override_plist.clone(),
                        None => custom_ramdisk.read(&options_path)?,
                    };
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
    skip_first: bool,
}

impl MultipartRestoreRequest {
    pub fn new(part1: RestoreExecutionRequest, part2: RestoreExecutionRequest) -> Self {
        Self {
            // The NOR flash stage does not boot a normal system.
            part1: part1.with_final_verification(false),
            part2,
            skip_first: false,
        }
    }

    /// Mirror of upstream's `--skip-first`: skip the part 1 NOR flash restore
    /// and proceed straight to the pwned part 2 restore, for powdersn0w 4.2.x
    /// and lower devices whose NOR is already flashed.
    pub fn with_skip_first(mut self, enabled: bool) -> Self {
        self.skip_first = enabled;
        self
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

    if request.skip_first {
        info!(
            "skip-first: skipping the part 1 NOR flash restore; proceeding to the pwned part 2 restore"
        );
    } else {
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
                        "Put the device into DFU mode to continue with the target restore."
                            .to_owned(),
                        "If pwning fails after this point, re-enter DFU and run again with --skip-first to continue."
                            .to_owned(),
                    ],
                },
            })
            .await;
        if !await_bootloader_device(ecid, emitter).await? {
            return Ok(None);
        }
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
    fn target_iboot_options_match_upstream_extra_arr() {
        for version in ["3.1.3", "4.0", "4.2.1", "4.3.3"] {
            let options = target_iboot_patch_options(version, false, None);
            assert_eq!(
                options.boot_partition,
                Some(BootPartition::Standard),
                "{version}"
            );
            assert!(options.boot_ramdisk, "{version}");
            assert!(options.logo4, "{version}");
            assert!(options.jump_iboot_433, "{version}");
            assert_eq!(
                options.boot_args.as_deref(),
                Some(MULTIPART_IBOOT_BOOT_ARGS),
                "{version}"
            );
        }
        // 4.2.9/4.2.10 ship an iBoot new enough to skip the --433 jump.
        for version in ["4.2.9", "4.2.10"] {
            assert!(
                !target_iboot_patch_options(version, false, None).jump_iboot_433,
                "{version}"
            );
        }
    }

    #[test]
    fn target_iboot_options_boot_args_variants() {
        let verbose = target_iboot_patch_options("4.2.1", true, None);
        assert_eq!(
            verbose.boot_args.as_deref(),
            Some(MULTIPART_IBOOT_BOOT_ARGS_VERBOSE)
        );
        let extra = target_iboot_patch_options("4.2.1", false, Some("serial=1"));
        assert_eq!(
            extra.boot_args.as_deref(),
            Some("pio-error=0 debug=0x2014e serial=3 serial=1")
        );
        // Empty extras are ignored, like upstream's `-n` check.
        let empty = target_iboot_patch_options("4.2.1", false, Some(""));
        assert_eq!(empty.boot_args.as_deref(), Some(MULTIPART_IBOOT_BOOT_ARGS));
    }

    #[test]
    fn maps_target_iboot_disposition() {
        assert_eq!(
            target_iboot_disposition(&ProductType::from("iPad1,1"), "3.1.3"),
            TargetIbootDisposition::SidecarRaw
        );
        assert_eq!(
            target_iboot_disposition(&ProductType::from("iPad1,1"), "4.2.1"),
            TargetIbootDisposition::SidecarTar
        );
        for device in ["iPhone3,1", "iPhone3,3", "iPod3,1", "iPod4,1"] {
            assert_eq!(
                target_iboot_disposition(&ProductType::from(device), "4.2.1"),
                TargetIbootDisposition::AllFlash,
                "{device}"
            );
        }
    }

    #[test]
    fn maps_iboot_tag_mangle() {
        assert_eq!(iboot_tag_mangle(&ProductType::from("iPad1,1")), *b"ce");
        assert_eq!(iboot_tag_mangle(&ProductType::from("iPhone3,1")), *b"bo");
        assert_eq!(iboot_tag_mangle(&ProductType::from("iPod4,1")), *b"bo");
    }

    #[test]
    fn maps_applelogo_branch() {
        for device in ["iPhone3,3", "iPad1,1", "iPod3,1"] {
            assert!(
                applelogo_separate_entry(&ProductType::from(device)),
                "{device}"
            );
        }
        for device in ["iPhone3,1", "iPhone3,2", "iPod4,1"] {
            assert!(
                !applelogo_separate_entry(&ProductType::from(device)),
                "{device}"
            );
        }
    }

    #[test]
    fn edits_all_flash_manifest_separate_branch() {
        let base = "applelogo.img3\niBoot.img3\nmanifest\n";
        let edited = edit_all_flash_manifest(base, true, &AppleLogoEntry::Separate);
        assert_eq!(
            edited,
            "applelogo.img3\niBoot.img3\nmanifest\niBoot2.img3\napplelogoT.img3\napplelogo4.img3\n"
        );
        // iPad1,1 adds no iBoot2 entry.
        let edited = edit_all_flash_manifest(base, false, &AppleLogoEntry::Separate);
        assert_eq!(
            edited,
            "applelogo.img3\niBoot.img3\nmanifest\napplelogoT.img3\napplelogo4.img3\n"
        );
    }

    #[test]
    fn edits_all_flash_manifest_replace_branch() {
        // Upstream's sed drops every line containing "applelogo", including
        // the applelogoT.img3 line added moments earlier.
        let base = "applelogo@2x.img3\niBoot.img3\nbatterylow0.img3\n";
        let edited = edit_all_flash_manifest(
            base,
            true,
            &AppleLogoEntry::Replace("applelogo.s5l8930x.img3"),
        );
        assert_eq!(
            edited,
            "iBoot.img3\nbatterylow0.img3\niBoot2.img3\napplelogo.s5l8930x.img3\n"
        );
    }

    #[test]
    fn builds_single_file_tar() {
        let data = b"iboot-bytes";
        let archive = tar_single_file("iBEC", data);
        assert_eq!(&archive[0..4], b"iBEC");
        assert_eq!(&archive[257..263], b"ustar\0");
        // Size field holds the payload length in octal.
        let size =
            u64::from_str_radix(std::str::from_utf8(&archive[124..135]).unwrap(), 8).unwrap();
        assert_eq!(size, data.len() as u64);
        // Checksum covers the header with the checksum field blanked.
        let mut header = archive[0..512].to_vec();
        header[148..156].copy_from_slice(b"        ");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let stored =
            u64::from_str_radix(std::str::from_utf8(&archive[148..154]).unwrap(), 8).unwrap();
        assert_eq!(stored, checksum);
        assert_eq!(&archive[512..512 + data.len()], data);
        assert!(archive.len().is_multiple_of(512));
        assert!(archive.len() >= 512 + 512 + 1024);
    }

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
    async fn skip_first_requires_an_existing_part2() {
        let root = tempfile::tempdir().unwrap();
        let request = MultipartPrepareRequest::new(
            ProductType::from("iPhone3,1"),
            BoardConfig::from("n90ap"),
            root.path().join("target.ipsw"),
            root.path().join("custom.ipsw"),
            root.path().join("base.ipsw"),
            NorSource::Local(root.path().join("nor.ipsw")),
            root.path().join("ticket.shsh2"),
            root.path().join("part1.ipsw"),
            root.path().join("part2.ipsw"),
            root.path().join("cache"),
        )
        .with_skip_first(true);
        let error = prepare(request).await.err().unwrap();
        assert!(
            matches!(error, KitError::MultipartMissingPart2(_)),
            "{error}"
        );
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
