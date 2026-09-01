//! Post-build component patches of the classic custom IPSW flows, porting
//! restore.sh's `ipsw_prepare_patchcomp` (5825-5921) and its call sites
//! `ipsw_prepare_s5l8900` (5923-6007, iPhone1,2 3.1.3/4.x) and
//! `ipsw_prepare_custom` (6011-6026, old-bootrom 24kpwn iPod2,1), plus the
//! iPhone2,1 >=5.x `ipsw_prepare_ios4patches` tail of
//! `ipsw_prepare_jailbreak` (3513-3517).
//!
//! Unlike the builder's `FirmwarePatches` loop (which patches the peeled
//! plaintext and re-stacks the container), patchcomp replaces whole files of
//! the custom IPSW with precomputed bundle diffs applied to the *stock*
//! components of the source IPSW: LLB/iBoot/iBSS/iBEC/WTF 2 take a raw
//! bsdiff, while the RestoreRamdisk is decrypted with the hardcoded
//! per-version iv/key, bsdiffed, and re-encrypted into the original IMG3
//! template (re-encrypted with the keys on 4.x targets only, matching
//! upstream's `ivkey` guard). On 4.2.1 the RestoreRamdisk, RestoreDeviceTree,
//! and RestoreKernelCache are sourced from the iPhone1,2 4.1 (8B117) IPSW —
//! the ramdisk is re-targeted to `038-0029-002.dmg`, the device tree is
//! copied unpatched, and the kernelcache takes the *8B117 bundle's*
//! kernelcache patch with the hardcoded 8B117 keys — all landing under
//! `Downgrade/`.
//!
//! The iPhone2,1 >=5.x step decrypts the stock iBSS/iBEC, applies
//! iBoot32Patcher (`--rsa --debug`, `--ticket` on the iBEC, upstream's
//! boot-args), and re-wraps the plaintext payload in the original IMG3
//! template; upstream then re-zips `Firmware/dfu/*`, which is equivalent to
//! replacing those two entries here.
//!
//! `ipsw_bbreplace` is intentionally absent: it returns early for
//! `device_proc < 5` (restore.sh:4350-4351), so no classic flow ever applies
//! it. iPhone1,1/iPod1,1 reach no patchcomp step either — upstream downloads
//! prebuilt custom IPSWs for them instead of building
//! (`ipsw_prepare_s5l8900`'s early return).

use std::path::Path;

use legacy_ios_core::{BuildId, ProductType};
use legacy_ios_firmware::{FirmwareArchive, RemoteFirmwareArchive};
use legacy_ios_image::{
    Iboot32PatchOptions, apply_bsdiff, extract_image_payload, patch_iboot32_with_options,
    replace_image_payload,
};
use tracing::debug;

use crate::{KitError, powder::read_resource};

/// Pinned iPhone1,2 4.1 (8B117) IPSW URL, the source of the 4.2.1
/// RestoreRamdisk/RestoreDeviceTree/RestoreKernelCache patchcomp components
/// (upstream's `ipsw_get_url 8B117` + partial-zip download, cached under
/// `saved/iPhone1,2/8B117`).
pub const IOS41_IPSW_URL: &str = "https://secure-appldnld.apple.com/iPhone4/061-7932.20100908.3fgt5/iPhone1,2_4.1_8B117_Restore.ipsw";

/// iOS version/build of [`IOS41_IPSW_URL`].
pub const IOS41_VERSION: &str = "4.1";
pub const IOS41_BUILD: &str = "8B117";

/// Boot-args of the iPhone2,1 >=5.x iBSS/iBEC patches
/// (`ipsw_prepare_ios4patches`).
pub const IOS4P_BOOT_ARGS: &str = "rd=md0 -v amfi=0xff cs_enforcement_disable=1 pio-error=0";

// Hardcoded patchcomp key material (restore.sh `ipsw_prepare_patchcomp`).
const RAMDISK_313_NAME: &str = "018-6494-014.dmg";
const RAMDISK_313_IV: &str = "25e713dd5663badebe046d0ffa164fee";
const RAMDISK_313_KEY: &str = "7029389c2dadaaa1d1e51bf579493824";
const RAMDISK_4X_NAME: &str = "018-7079-079.dmg";
const RAMDISK_4X_IV: &str = "a0fc6ca4ef7ef305d975e7f881ddcc7f";
const RAMDISK_4X_KEY: &str = "18eab1ba646ae018b013bc959001fbde";
const RAMDISK_421_NAME: &str = "038-0029-002.dmg";
const KERNELCACHE_41_IV: &str = "7238dcea75bf213eff209825a03add51";
const KERNELCACHE_41_KEY: &str = "0295d4ef87b9db687b44f54c8585d2b6";

/// One `ipsw_prepare_patchcomp` invocation, by component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchcompComponent {
    Llb,
    IBoot,
    RestoreRamdisk,
    Wtf2,
    Ibec,
    Ibss,
    RestoreDeviceTree,
    RestoreKernelCache,
}

impl PatchcompComponent {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Llb => "LLB",
            Self::IBoot => "iBoot",
            Self::RestoreRamdisk => "RestoreRamdisk",
            Self::Wtf2 => "WTF2",
            Self::Ibec => "iBEC",
            Self::Ibss => "iBSS",
            Self::RestoreDeviceTree => "RestoreDeviceTree",
            Self::RestoreKernelCache => "RestoreKernelCache",
        }
    }
}

/// The patchcomp component list of a classic build, per the upstream call
/// sites: iPhone1,2 jailbreak builds (`ipsw_prepare_s5l8900`) patch LLB,
/// iBoot, and the RestoreRamdisk, add WTF 2 and iBEC on 4.x targets, and add
/// iBSS plus the 8B117-sourced RestoreDeviceTree/RestoreKernelCache on
/// 4.2.1; old-bootrom 24kpwn iPod2,1 builds (`ipsw_prepare_custom`) patch
/// LLB only. Every other device/version reaches no patchcomp step.
pub fn patchcomp_components(
    product_type: &ProductType,
    version: &str,
    jailbreak: bool,
    old_bootrom_24kpwn: bool,
) -> Vec<PatchcompComponent> {
    if product_type.as_str() == "iPod2,1" {
        return if old_bootrom_24kpwn {
            vec![PatchcompComponent::Llb]
        } else {
            Vec::new()
        };
    }
    if product_type.as_str() != "iPhone1,2" || !jailbreak {
        return Vec::new();
    }
    let mut components = vec![
        PatchcompComponent::Llb,
        PatchcompComponent::IBoot,
        PatchcompComponent::RestoreRamdisk,
    ];
    if version.starts_with('4') {
        components.push(PatchcompComponent::Wtf2);
        components.push(PatchcompComponent::Ibec);
        if version == "4.2.1" {
            components.push(PatchcompComponent::Ibss);
            components.push(PatchcompComponent::RestoreDeviceTree);
            components.push(PatchcompComponent::RestoreKernelCache);
        }
    }
    components
}

/// Whether the iPhone2,1 >=5.x `ipsw_prepare_ios4patches` step applies.
pub fn ios4patches_apply(product_type: &ProductType, version: &str) -> bool {
    product_type.as_str() == "iPhone2,1"
        && version
            .split('.')
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .is_some_and(|major| major >= 5)
}

/// Where a patchcomp component's input bytes come from.
#[derive(Clone, Debug)]
enum PatchcompSource {
    /// An entry of the source (target) IPSW.
    Target(String),
    /// An entry of the iPhone1,2 4.1 (8B117) IPSW, fetched at plan time.
    Ios41(Vec<u8>),
}

/// How the patched output is produced.
#[derive(Clone, Debug)]
enum PatchcompTransform {
    /// `$bspatch` on the raw file bytes.
    Raw,
    /// Copied unpatched (4.2.1 RestoreDeviceTree).
    Copy,
    /// xpwntool decrypt with the hardcoded iv/key, bsdiff, then
    /// `xpwntool -t` template re-encrypt — re-encrypted with the keys only
    /// when `reencrypt` (upstream's `ivkey` guard: 4.x ramdisks and the
    /// 4.2.1 kernelcache).
    Encrypted {
        iv: [u8; 16],
        key: [u8; 16],
        reencrypt: bool,
    },
}

/// A resolved patchcomp step: input source, patch payload, transform, and
/// the custom IPSW entry it replaces.
pub(crate) struct PatchcompStep {
    component: PatchcompComponent,
    source: PatchcompSource,
    patch: Option<Vec<u8>>,
    transform: PatchcompTransform,
    output: String,
}

impl std::fmt::Debug for PatchcompStep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PatchcompStep")
            .field("component", &self.component)
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}

/// A resolved iPhone2,1 >=5.x iBSS/iBEC patch step.
pub(crate) struct Ios4BootPatchStep {
    source_path: String,
    key: Vec<u8>,
    iv: [u8; 16],
    ticket: bool,
}

impl std::fmt::Debug for Ios4BootPatchStep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ios4BootPatchStep")
            .field("source_path", &self.source_path)
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

/// The resolved post-build steps of a classic plan.
#[derive(Debug, Default)]
pub(crate) struct ClassicPostSteps {
    pub(crate) patchcomp: Vec<PatchcompStep>,
    pub(crate) ios4_boot: Vec<Ios4BootPatchStep>,
}

impl ClassicPostSteps {
    pub(crate) fn len(&self) -> usize {
        self.patchcomp.len() + self.ios4_boot.len()
    }
}

/// Catalog resource id of a bundle patch file, mirroring
/// `classic_bundle`'s `classic-patch-<device>-<build>-<name>` scheme.
fn patch_id(product_type: &ProductType, build: &BuildId, patch_file: &str) -> String {
    format!(
        "classic-patch-{}-{}-{}",
        product_type.as_str().replace(',', "-"),
        build.as_str(),
        patch_file.strip_suffix(".patch").unwrap_or(patch_file)
    )
}

async fn fetch_patch(
    product_type: &ProductType,
    build: &BuildId,
    patch_file: &str,
    cache_root: &Path,
) -> Result<Vec<u8>, KitError> {
    let id = legacy_ios_assets::ResourceId::new(patch_id(product_type, build, patch_file));
    if legacy_ios_assets::ResourceCatalog::bundled()
        .get(&id)
        .is_none()
    {
        return Err(KitError::ClassicBundle(
            legacy_ios_firmware::ClassicBundleError::MissingPatch {
                device: product_type.as_str().to_owned(),
                build: build.as_str().to_owned(),
                patch: patch_file.to_owned(),
            },
        ));
    }
    read_resource(&id, cache_root).await
}

/// Read an entry of the iPhone1,2 4.1 (8B117) IPSW, from the request's local
/// override when given and from the pinned Apple URL otherwise (upstream
/// downloads it with a partial-zip read into `saved/iPhone1,2/8B117`).
async fn read_ios41_entry(local: Option<&Path>, entry: &str) -> Result<Vec<u8>, KitError> {
    match local {
        Some(path) => Ok(FirmwareArchive::open(path)?.read_entry(entry)?),
        None => Ok(RemoteFirmwareArchive::open(IOS41_IPSW_URL)
            .await?
            .read_entry(entry)
            .await?),
    }
}

fn hex16(value: &str) -> [u8; 16] {
    let bytes: Vec<u8> = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
        .collect::<Result<_, _>>()
        .expect("patchcomp key material is compile-time hex");
    bytes
        .try_into()
        .expect("patchcomp key material is 16 bytes")
}

/// Resolve the patchcomp steps of a classic build. `ios41_ipsw` overrides
/// the 8B117 component source of 4.2.1 builds with a local IPSW.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_patchcomp(
    product_type: &ProductType,
    board_config: &legacy_ios_core::BoardConfig,
    version: &str,
    build: &BuildId,
    jailbreak: bool,
    old_bootrom_24kpwn: bool,
    ios41_ipsw: Option<&Path>,
    cache_root: &Path,
) -> Result<Vec<PatchcompStep>, KitError> {
    let board = board_config.as_str();
    let all_flash = format!("Firmware/all_flash/all_flash.{board}ap");
    let mut steps = Vec::new();
    for component in patchcomp_components(product_type, version, jailbreak, old_bootrom_24kpwn) {
        let step = match component {
            PatchcompComponent::Llb => PatchcompStep {
                component,
                source: PatchcompSource::Target(format!("{all_flash}/LLB.{board}ap.RELEASE.img3")),
                patch: Some(
                    fetch_patch(
                        product_type,
                        build,
                        &format!("LLB.{board}ap.RELEASE.patch"),
                        cache_root,
                    )
                    .await?,
                ),
                transform: PatchcompTransform::Raw,
                output: format!("{all_flash}/LLB.{board}ap.RELEASE.img3"),
            },
            PatchcompComponent::IBoot => PatchcompStep {
                component,
                source: PatchcompSource::Target(format!(
                    "{all_flash}/iBoot.{board}ap.RELEASE.img3"
                )),
                patch: Some(
                    fetch_patch(
                        product_type,
                        build,
                        &format!("iBoot.{board}ap.RELEASE.patch"),
                        cache_root,
                    )
                    .await?,
                ),
                transform: PatchcompTransform::Raw,
                output: format!("{all_flash}/iBoot.{board}ap.RELEASE.img3"),
            },
            PatchcompComponent::Wtf2 => PatchcompStep {
                component,
                source: PatchcompSource::Target(
                    "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu".to_owned(),
                ),
                patch: Some(
                    fetch_patch(
                        product_type,
                        build,
                        "WTF.s5l8900xall.RELEASE.patch",
                        cache_root,
                    )
                    .await?,
                ),
                transform: PatchcompTransform::Raw,
                output: "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu".to_owned(),
            },
            PatchcompComponent::Ibec | PatchcompComponent::Ibss => {
                let name = format!("{}.{board}ap.RELEASE", component.name());
                PatchcompStep {
                    component,
                    source: PatchcompSource::Target(format!("Firmware/dfu/{name}.dfu")),
                    patch: Some(
                        fetch_patch(product_type, build, &format!("{name}.patch"), cache_root)
                            .await?,
                    ),
                    transform: PatchcompTransform::Raw,
                    output: format!("Firmware/dfu/{name}.dfu"),
                }
            }
            PatchcompComponent::RestoreRamdisk => {
                let (source, patch_file, output, iv, key) = match version {
                    "4.2.1" => (
                        PatchcompSource::Ios41(
                            read_ios41_entry(ios41_ipsw, RAMDISK_4X_NAME).await?,
                        ),
                        format!(
                            "{}.patch",
                            RAMDISK_421_NAME.strip_suffix(".dmg").expect("dmg")
                        ),
                        RAMDISK_421_NAME,
                        RAMDISK_4X_IV,
                        RAMDISK_4X_KEY,
                    ),
                    v if v.starts_with('4') => (
                        PatchcompSource::Target(RAMDISK_4X_NAME.to_owned()),
                        format!(
                            "{}.patch",
                            RAMDISK_4X_NAME.strip_suffix(".dmg").expect("dmg")
                        ),
                        RAMDISK_4X_NAME,
                        RAMDISK_4X_IV,
                        RAMDISK_4X_KEY,
                    ),
                    _ => (
                        PatchcompSource::Target(RAMDISK_313_NAME.to_owned()),
                        format!(
                            "{}.patch",
                            RAMDISK_313_NAME.strip_suffix(".dmg").expect("dmg")
                        ),
                        RAMDISK_313_NAME,
                        RAMDISK_313_IV,
                        RAMDISK_313_KEY,
                    ),
                };
                PatchcompStep {
                    component,
                    source,
                    patch: Some(fetch_patch(product_type, build, &patch_file, cache_root).await?),
                    transform: PatchcompTransform::Encrypted {
                        iv: hex16(iv),
                        key: hex16(key),
                        // Upstream's ivkey guard: `4*` targets and iPhone1,1/
                        // iPod1,1 re-encrypt; only iPhone1,2 reaches this step
                        // and its 3.1.3 target re-wraps plaintext.
                        reencrypt: version.starts_with('4')
                            || product_type.as_str().ends_with("1,1"),
                    },
                    output: output.to_owned(),
                }
            }
            PatchcompComponent::RestoreDeviceTree => PatchcompStep {
                component,
                source: PatchcompSource::Ios41(
                    read_ios41_entry(
                        ios41_ipsw,
                        &format!("{all_flash}/DeviceTree.{board}ap.img3"),
                    )
                    .await?,
                ),
                patch: None,
                transform: PatchcompTransform::Copy,
                output: "Downgrade/RestoreDeviceTree".to_owned(),
            },
            PatchcompComponent::RestoreKernelCache => PatchcompStep {
                component,
                source: PatchcompSource::Ios41(
                    read_ios41_entry(ios41_ipsw, &format!("kernelcache.release.{board}")).await?,
                ),
                // The 4.2.1 kernelcache takes the *8B117 bundle's* patch.
                patch: Some(
                    fetch_patch(
                        product_type,
                        &BuildId::new(IOS41_BUILD),
                        "kernelcache.release.patch",
                        cache_root,
                    )
                    .await?,
                ),
                transform: PatchcompTransform::Encrypted {
                    iv: hex16(KERNELCACHE_41_IV),
                    key: hex16(KERNELCACHE_41_KEY),
                    reencrypt: true,
                },
                output: "Downgrade/RestoreKernelCache".to_owned(),
            },
        };
        debug!(component = component.name(), "resolved patchcomp step");
        steps.push(step);
    }
    Ok(steps)
}

/// Resolve the iPhone2,1 >=5.x iBSS/iBEC steps of a classic build, pulling
/// the key material of the target build from the firmware key set like
/// upstream's `device_fw_key_check temp`.
pub(crate) fn resolve_ios4patches(
    product_type: &ProductType,
    board_config: &legacy_ios_core::BoardConfig,
    version: &str,
    keys: &legacy_ios_firmware::FirmwareKeySet,
) -> Result<Vec<Ios4BootPatchStep>, KitError> {
    if !ios4patches_apply(product_type, version) {
        return Ok(Vec::new());
    }
    let board = board_config.as_str();
    let mut steps = Vec::new();
    for (image, ticket) in [("iBSS", false), ("iBEC", true)] {
        let key = keys
            .key(image)
            .ok_or(KitError::ClassicMissingComponent("iBSS/iBEC key"))?;
        let (Some(key_material), Some(iv)) = (key.key(), key.iv()) else {
            return Err(KitError::ClassicMissingComponent("iBSS/iBEC key material"));
        };
        steps.push(Ios4BootPatchStep {
            source_path: format!("Firmware/dfu/{image}.{board}ap.RELEASE.dfu"),
            key: key_material.to_vec(),
            iv: *iv,
            ticket,
        });
    }
    Ok(steps)
}

/// Execute the resolved post steps, returning the replacement entries they
/// produce for the custom IPSW (applied after the builder's own stages, so
/// they overwrite them, like upstream's `zip -r0` updates).
pub(crate) fn apply_post_steps(
    steps: &ClassicPostSteps,
    archive: &FirmwareArchive,
) -> Result<Vec<(String, Vec<u8>)>, KitError> {
    let mut replacements = Vec::new();
    for step in &steps.patchcomp {
        debug!(component = step.component.name(), "applying patchcomp step");
        let source = match &step.source {
            PatchcompSource::Target(path) => archive.read_entry(path)?,
            PatchcompSource::Ios41(bytes) => bytes.clone(),
        };
        let patched = match (&step.transform, &step.patch) {
            (PatchcompTransform::Copy, None) => source,
            (PatchcompTransform::Raw, Some(patch)) => apply_bsdiff(&source, patch)?,
            (PatchcompTransform::Encrypted { iv, key, reencrypt }, Some(patch)) => {
                let decrypted =
                    extract_image_payload(&source, Some((key.as_slice(), iv.as_slice())))?;
                let mut patched = apply_bsdiff(&decrypted, patch)?;
                if *reencrypt {
                    // xpwntool's `-t` re-encrypt zero-pads to the cipher
                    // block size.
                    patched.resize(patched.len().next_multiple_of(16), 0);
                }
                let encryption = reencrypt.then_some((key.as_slice(), iv.as_slice()));
                replace_image_payload(&source, &patched, encryption)?
            }
            _ => return Err(KitError::ClassicMissingComponent("patchcomp patch payload")),
        };
        replacements.push((step.output.clone(), patched));
    }
    for step in &steps.ios4_boot {
        let source = archive.read_entry(&step.source_path)?;
        let decrypted =
            extract_image_payload(&source, Some((step.key.as_slice(), step.iv.as_slice())))?;
        let patched = patch_iboot32_with_options(
            &decrypted,
            &Iboot32PatchOptions {
                boot_args: Some(IOS4P_BOOT_ARGS.to_owned()),
                debug: true,
                ticket: step.ticket,
                ..Iboot32PatchOptions::default()
            },
        )?;
        replacements.push((
            step.source_path.clone(),
            replace_image_payload(&source, &patched, None)?,
        ));
    }
    Ok(replacements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patchcomp_selection_matches_upstream_call_sites() {
        let iphone3g = ProductType::from("iPhone1,2");
        // iPhone1,2 3.1.3: LLB/iBoot/RestoreRamdisk only.
        assert_eq!(
            patchcomp_components(&iphone3g, "3.1.3", true, false),
            vec![
                PatchcompComponent::Llb,
                PatchcompComponent::IBoot,
                PatchcompComponent::RestoreRamdisk,
            ]
        );
        // iPhone1,2 4.1: + WTF2/iBEC.
        assert_eq!(
            patchcomp_components(&iphone3g, "4.1", true, false),
            vec![
                PatchcompComponent::Llb,
                PatchcompComponent::IBoot,
                PatchcompComponent::RestoreRamdisk,
                PatchcompComponent::Wtf2,
                PatchcompComponent::Ibec,
            ]
        );
        // iPhone1,2 4.2.1: + iBSS/RestoreDeviceTree/RestoreKernelCache.
        assert_eq!(
            patchcomp_components(&iphone3g, "4.2.1", true, false),
            vec![
                PatchcompComponent::Llb,
                PatchcompComponent::IBoot,
                PatchcompComponent::RestoreRamdisk,
                PatchcompComponent::Wtf2,
                PatchcompComponent::Ibec,
                PatchcompComponent::Ibss,
                PatchcompComponent::RestoreDeviceTree,
                PatchcompComponent::RestoreKernelCache,
            ]
        );
        // Non-jailbreak iPhone1,2 builds no custom IPSW upstream.
        assert!(patchcomp_components(&iphone3g, "4.2.1", false, false).is_empty());
        // Old-bootrom 24kpwn iPod2,1: LLB only; new bootrom: nothing.
        let ipod2 = ProductType::from("iPod2,1");
        assert_eq!(
            patchcomp_components(&ipod2, "3.1.3", true, true),
            vec![PatchcompComponent::Llb]
        );
        assert!(patchcomp_components(&ipod2, "3.1.3", true, false).is_empty());
        assert!(patchcomp_components(&ipod2, "4.2.1", true, false).is_empty());
        // iPhone1,1/iPod1,1 download prebuilt custom IPSWs upstream.
        assert!(
            patchcomp_components(&ProductType::from("iPhone1,1"), "3.1.3", true, false).is_empty()
        );
        assert!(
            patchcomp_components(&ProductType::from("iPod1,1"), "3.1.3", true, false).is_empty()
        );
        // iPhone2,1 reaches no patchcomp step.
        assert!(
            patchcomp_components(&ProductType::from("iPhone2,1"), "6.1.6", true, false).is_empty()
        );
    }

    #[test]
    fn ios4patches_gate_matches_upstream() {
        let iphone3gs = ProductType::from("iPhone2,1");
        assert!(ios4patches_apply(&iphone3gs, "5.0"));
        assert!(ios4patches_apply(&iphone3gs, "6.1.6"));
        assert!(!ios4patches_apply(&iphone3gs, "4.2.1"));
        assert!(!ios4patches_apply(&ProductType::from("iPod3,1"), "5.1.1"));
    }

    #[test]
    fn patch_resource_ids_match_the_catalog() {
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        let iphone3g = ProductType::from("iPhone1,2");
        for (build, patch) in [
            ("7E18", "LLB.n82ap.RELEASE.patch"),
            ("7E18", "iBoot.n82ap.RELEASE.patch"),
            ("7E18", "018-6494-014.patch"),
            ("8B117", "LLB.n82ap.RELEASE.patch"),
            ("8B117", "WTF.s5l8900xall.RELEASE.patch"),
            ("8B117", "iBEC.n82ap.RELEASE.patch"),
            ("8B117", "018-7079-079.patch"),
            ("8B117", "kernelcache.release.patch"),
            ("8C148", "LLB.n82ap.RELEASE.patch"),
            ("8C148", "iBSS.n82ap.RELEASE.patch"),
            ("8C148", "038-0029-002.patch"),
        ] {
            let id = legacy_ios_assets::ResourceId::new(patch_id(
                &iphone3g,
                &BuildId::new(build),
                patch,
            ));
            assert!(catalog.get(&id).is_some(), "missing catalog entry {id}");
        }
        // The 24kpwn iPod2,1 LLB patches exist for 3.1.x/4.0 targets.
        let ipod2 = ProductType::from("iPod2,1");
        for build in ["7C145", "7D11", "7E18", "8A293", "8A400"] {
            let id = legacy_ios_assets::ResourceId::new(patch_id(
                &ipod2,
                &BuildId::new(build),
                "LLB.n72ap.RELEASE.patch",
            ));
            assert!(catalog.get(&id).is_some(), "missing catalog entry {id}");
        }
    }

    #[test]
    fn encrypted_transform_decrypt_patch_reencrypt() {
        use legacy_ios_image::{Img3, Img3Element, Img3Tag, encrypt_cbc};

        // The image crate's bsdiff fixture: "abc" to "axc!".
        const ABC_PATCH: &str = concat!(
            "42534449464634302a0000000000000027000000000000000400000000000000",
            "425a6839314159265359d0149a29000004c0006808200030cd34193f5209593c5d",
            "c914e14243405268a4425a6839314159265359bd1ca64a000000e0004000010020",
            "002100828c5dc914e14242f4729928425a68393141592653592d15eb1c00000010",
            "002000200021184682ee48a70a1205a2bd6380"
        );
        let patch: Vec<u8> = (0..ABC_PATCH.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&ABC_PATCH[index..index + 2], 16).unwrap())
            .collect();

        let iv = hex16(RAMDISK_4X_IV);
        let key = hex16(RAMDISK_4X_KEY);
        let mut padded = b"abc".to_vec();
        padded.resize(16, 0);
        let body = encrypt_cbc(&padded, &key, &iv).unwrap();
        let container = Img3::new(
            0x746f_6f62,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"rdsk".to_vec()),
                Img3Element::new(Img3Tag::DATA, body),
            ],
        )
        .to_bytes();

        // reencrypt: output decrypts to the (zero-padded) patched payload.
        let decrypted = extract_image_payload(&container, Some((&key, &iv))).unwrap();
        let mut patched = apply_bsdiff(&decrypted[..3], &patch).unwrap();
        patched.resize(16, 0);
        let output = replace_image_payload(&container, &patched, Some((&key, &iv))).unwrap();
        assert_eq!(
            &extract_image_payload(&output, Some((&key, &iv))).unwrap()[..4],
            b"axc!"
        );
        // Without re-encryption the payload stays plaintext in the template
        // (xpwntool -t without -iv/-k, the iPhone1,2 3.1.3 ramdisk case).
        let output = replace_image_payload(&container, &patched, None).unwrap();
        assert_eq!(&extract_image_payload(&output, None).unwrap()[..4], b"axc!");
    }
}
