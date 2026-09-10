//! Auxiliary firmware (SEP/baseband) source selection and resolution,
//! mirroring upstream `restore_download_bbsep` (restore.sh:6074-6150) on top
//! of the `device_use_*`/`device_latest_*` device tables
//! (restore.sh:1597-1705) and the appledb URL resolution of
//! `ipsw_get_url`/`download_appledb` (restore.sh:2696-2780).

use std::{future::Future, io::Cursor, path::Path, pin::Pin};

use legacy_ios_assets::{AuxBaseband, AuxFirmwareInfo, DeviceProfile};
use legacy_ios_core::{BoardConfig, DeviceIdentity, ProductType, Soc};
use legacy_ios_firmware::{
    BuildIdentity, BuildManifest, FirmwareArchive, FirmwareError, RemoteFirmwareArchive,
    RemoteFirmwareError, RestoreBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tracing::{debug, info};

use crate::{BasebandPolicy, ExploitPolicy, SepPolicy};

/// The aux firmware source recorded by a restore plan: the build the
/// SEP/baseband are taken from, where to get it, and what is taken from it.
/// Plain data so the plan stays serializable for CLI output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuxFirmwareResolution {
    version: String,
    build: String,
    source: AuxFirmwareSource,
    baseband: Option<AuxBasebandResolution>,
    /// Whether the RestoreSEP/NOR SEP images are taken from this source.
    sep: bool,
}

impl AuxFirmwareResolution {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }

    pub const fn source(&self) -> &AuxFirmwareSource {
        &self.source
    }

    pub fn baseband(&self) -> Option<&AuxBasebandResolution> {
        self.baseband.as_ref()
    }

    /// Whether the SEP firmware comes from this source (64-bit devices).
    pub const fn sep(&self) -> bool {
        self.sep
    }
}

/// Where the auxiliary firmware is read from. Remote sources are pinned by
/// the SHA-256 of the BuildManifest fetched at plan time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum AuxFirmwareSource {
    /// The aux build equals the target build; the target IPSW is used locally.
    Target,
    /// A remote IPSW read over HTTP range requests (upstream `download_with_pzb`).
    Remote {
        url: String,
        manifest_sha256: String,
    },
}

/// The baseband firmware resolved from the aux source: the in-IPSW path and,
/// when the upstream device table records one, the expected SHA-1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuxBasebandResolution {
    path: String,
    sha1: Option<String>,
}

impl AuxBasebandResolution {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sha1(&self) -> Option<&str> {
        self.sha1.as_deref()
    }
}

/// The processor class of a device SoC (upstream `device_proc`,
/// restore.sh:1539-1558).
pub(crate) fn processor_class(soc: Soc) -> u32 {
    match soc {
        Soc::S5l8900 => 1,
        Soc::S5l8720 | Soc::S5l8920 | Soc::S5l8922 | Soc::A4 => 4,
        Soc::A5 | Soc::A5x => 5,
        Soc::A6 | Soc::A6x => 6,
        Soc::A7 => 7,
        Soc::A8 | Soc::A8x => 8,
        Soc::A9 | Soc::A9x => 9,
        Soc::A10 | Soc::A10x | Soc::A11 => 10,
        Soc::Other(_) => 11,
    }
}

/// Numeric major version of a dotted product version ("16.0.1" -> 16).
pub(crate) fn major_version(version: &str) -> Option<u64> {
    version.split('.').next()?.parse().ok()
}

/// The aux build selected for a target version (the build/baseband branch of
/// `restore_download_bbsep`). Baseband is the device-table entry of the
/// selected build, when upstream records one.
#[derive(Debug)]
pub(crate) struct AuxBuildSelection {
    pub(crate) version: String,
    pub(crate) build: String,
    pub(crate) baseband: Option<AuxBaseband>,
}

pub(crate) fn select_aux_build(
    product: &ProductType,
    soc: Soc,
    aux: Option<&AuxFirmwareInfo>,
    target_version: &str,
) -> Result<AuxBuildSelection, AuxFirmwareError> {
    let aux = aux.ok_or_else(|| AuxFirmwareError::MissingDeviceData(product.clone()))?;
    let class = processor_class(soc);
    let unavailable = || AuxFirmwareError::BuildUnavailable {
        product: product.clone(),
        target: target_version.to_owned(),
    };
    // restore_download_bbsep: A8, 15.x/16.x-latest and checkm8 iPad devices
    // return early and use the latest firmware (futurerestore --latest-sep);
    // A7 uses the `use` build only for iOS 10 targets; 32-bit devices always
    // use the `use` build (their latest version falls back to it upstream).
    let (selected, baseband) =
        if class < 7 || (class == 7 && major_version(target_version) == Some(10)) {
            (aux.use_build().ok_or_else(unavailable)?, aux.use_baseband())
        } else {
            (
                aux.latest_build().ok_or_else(unavailable)?,
                aux.latest_baseband(),
            )
        };
    Ok(AuxBuildSelection {
        version: selected.version().to_owned(),
        build: selected.build().to_owned(),
        baseband: baseband.cloned(),
    })
}

/// The remote reads needed to resolve an aux firmware build at plan time.
/// The live implementation is [`AppleDbCatalog`]; tests substitute synthetic
/// catalogs so planning never requires the network.
pub trait AuxFirmwareCatalog: Send + Sync + std::fmt::Debug {
    /// Resolve the IPSW download URL of a device build (upstream
    /// `ipsw_get_url` via appledb).
    fn resolve_ipsw_url<'a>(
        &'a self,
        product_type: &'a ProductType,
        build: &'a str,
    ) -> AuxCatalogFuture<'a, String>;

    /// Fetch the BuildManifest bytes of a remote IPSW through HTTP range
    /// reads (upstream `download_with_pzb ... BuildManifest.plist`).
    fn fetch_build_manifest<'a>(&'a self, url: &'a str) -> AuxCatalogFuture<'a, Vec<u8>>;
}

pub type AuxCatalogFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuxFirmwareError>> + Send + 'a>>;

/// The live aux catalog: appledb for the IPSW URL, [`RemoteFirmwareArchive`]
/// for the manifest.
#[derive(Clone, Debug, Default)]
pub struct AppleDbCatalog {
    client: reqwest::Client,
}

impl AppleDbCatalog {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuxFirmwareCatalog for AppleDbCatalog {
    fn resolve_ipsw_url<'a>(
        &'a self,
        product_type: &'a ProductType,
        build: &'a str,
    ) -> AuxCatalogFuture<'a, String> {
        Box::pin(async move {
            let bucket = appledb_bucket(product_type.as_str(), build);
            let url = format!(
                "https://api.appledb.dev/ios/{};{build}.json",
                bucket.replace(' ', "%20")
            );
            debug!(%url, "resolving auxiliary IPSW URL via appledb");
            let response = self
                .client
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json::<AppleDbResponse>()
                .await?;
            parse_appledb_response(&response, product_type.as_str(), build)
        })
    }

    fn fetch_build_manifest<'a>(&'a self, url: &'a str) -> AuxCatalogFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let archive = RemoteFirmwareArchive::open(url).await?;
            Ok(archive.read_entry("BuildManifest.plist").await?)
        })
    }
}

/// The appledb bucket of a build (the `case $build_id in ...` rules of
/// `download_appledb`, restore.sh:2749-2762).
fn appledb_bucket(product_type: &str, build: &str) -> &'static str {
    let bytes = build.as_bytes();
    let first = bytes.first();
    let second = bytes.get(1);
    let mut bucket = "iOS";
    let modern_major = matches!(first, Some(b'2' | b'3')) && second.is_some_and(u8::is_ascii_digit);
    if !(modern_major || build == "7B405" || build == "7B500") {
        if matches!((first, second), (Some(b'1'), Some(b'A' | b'C')))
            || matches!(first, Some(b'2'..=b'5'))
        {
            bucket = "iPhone Software";
        } else if first == Some(&b'7') {
            bucket = "iPhone OS";
        }
    }
    if product_type.starts_with("iPad")
        && (matches!((first, second), (Some(b'1'), Some(b'7' | b'8' | b'9')))
            || matches!(first, Some(b'2' | b'3')))
    {
        bucket = "iPadOS";
    }
    bucket
}

#[derive(Debug, Deserialize)]
struct AppleDbResponse {
    #[serde(default)]
    sources: Vec<AppleDbSource>,
}

#[derive(Debug, Deserialize)]
struct AppleDbSource {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, rename = "deviceMap")]
    device_map: Vec<String>,
    #[serde(default)]
    links: Vec<AppleDbLink>,
}

#[derive(Debug, Deserialize)]
struct AppleDbLink {
    url: String,
}

/// Pick the first `ipsw` source covering the device and sanity-check that its
/// URL carries the build id (restore.sh:2722-2740).
fn parse_appledb_response(
    response: &AppleDbResponse,
    product_type: &str,
    build: &str,
) -> Result<String, AuxFirmwareError> {
    let url = response
        .sources
        .iter()
        .filter(|source| {
            source.kind == "ipsw"
                && source
                    .device_map
                    .iter()
                    .any(|device| device == product_type)
        })
        .filter_map(|source| source.links.first())
        .map(|link| link.url.clone())
        .next()
        .ok_or_else(|| AuxFirmwareError::NoIpswSource {
            product: ProductType::new(product_type),
            build: build.to_owned(),
        })?;
    if url.contains('<') || !url.to_lowercase().contains(&build.to_lowercase()) {
        return Err(AuxFirmwareError::IpswUrlMismatch {
            url,
            build: build.to_owned(),
        });
    }
    Ok(url)
}

/// Select the aux build identity of a manifest, falling back to the other
/// restore behavior on a pwned boot chain like futurerestore does for the SEP
/// identity (futurerestore.cpp:1186-1198).
pub(crate) fn select_aux_identity(
    manifest: &BuildManifest,
    board: &BoardConfig,
    behavior: RestoreBehavior,
    allow_behavior_fallback: bool,
) -> Result<BuildIdentity, FirmwareError> {
    match manifest.select_identity(board, behavior) {
        Ok(identity) => Ok(identity.clone()),
        Err(FirmwareError::IdentityNotFound { .. }) if allow_behavior_fallback => {
            let other = match behavior {
                RestoreBehavior::Erase => RestoreBehavior::Update,
                RestoreBehavior::Update => RestoreBehavior::Erase,
            };
            Ok(manifest.select_identity(board, other)?.clone())
        }
        Err(error) => Err(error),
    }
}

/// The restore target inputs of the aux resolution: the device, its profile,
/// and the target manifest and selected identity.
pub(crate) struct AuxTarget<'a> {
    pub(crate) device: &'a DeviceIdentity,
    pub(crate) profile: &'a DeviceProfile,
    pub(crate) manifest: &'a BuildManifest,
    pub(crate) identity: &'a BuildIdentity,
    pub(crate) behavior: RestoreBehavior,
    pub(crate) exploit: ExploitPolicy,
}

/// Resolve the aux firmware source of a restore plan: the build the
/// selection rules pick, and — when it differs from the target build — the
/// appledb URL and BuildManifest of that build (pinned by SHA-256). Planning
/// fails on any lookup or parse problem; it never silently falls back to the
/// target IPSW.
pub(crate) async fn resolve_aux(
    target: &AuxTarget<'_>,
    sep: &SepPolicy,
    baseband: &BasebandPolicy,
    catalog: &dyn AuxFirmwareCatalog,
) -> Result<Option<AuxFirmwareResolution>, AuxFirmwareError> {
    let device = target.device;
    let profile = target.profile;
    let manifest = target.manifest;
    let identity = target.identity;
    let behavior = target.behavior;
    let exploit = target.exploit;
    let class = processor_class(profile.soc());
    let sep_from_aux = matches!(sep, SepPolicy::Auto) && class >= 7;
    let mut baseband_from_aux = matches!(baseband, BasebandPolicy::Auto) && profile.has_baseband();
    let aux = profile.aux_firmware();
    if baseband_from_aux
        && let Some(aux) = aux
        && aux.disable_baseband_for_non_latest()
    {
        // device_use_bb2: only a target matching the `use` version keeps the
        // baseband update (restore.sh:9799-9815).
        let use_version = aux.use_build().map(|build| build.version());
        if Some(manifest.product_version().as_str()) != use_version {
            debug!(
                target = manifest.product_version().as_str(),
                "baseband update disabled for this non-latest target"
            );
            baseband_from_aux = false;
        }
    }
    if !sep_from_aux && !baseband_from_aux {
        return Ok(None);
    }
    let selection = select_aux_build(
        device.product_type(),
        profile.soc(),
        aux,
        manifest.product_version().as_str(),
    )?;

    let board = device
        .board_config()
        .ok_or(AuxFirmwareError::MissingBoardConfig)?;
    let behavior_fallback = exploit != ExploitPolicy::None;
    let (source, aux_identity) = if selection.build == manifest.build_id().as_str() {
        // The aux build equals the target build: use the target IPSW locally,
        // no download.
        (AuxFirmwareSource::Target, identity.clone())
    } else {
        let url = catalog
            .resolve_ipsw_url(device.product_type(), &selection.build)
            .await?;
        let manifest_bytes = catalog.fetch_build_manifest(&url).await?;
        let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
        let aux_manifest = BuildManifest::from_reader(Cursor::new(&manifest_bytes))?;
        if aux_manifest.build_id().as_str() != selection.build {
            return Err(AuxFirmwareError::BuildMismatch {
                expected: selection.build,
                actual: aux_manifest.build_id().as_str().to_owned(),
            });
        }
        let aux_identity = select_aux_identity(&aux_manifest, board, behavior, behavior_fallback)
            .map_err(|error| AuxFirmwareError::Identity {
            build: selection.build.clone(),
            source: Box::new(error),
        })?;
        (
            AuxFirmwareSource::Remote {
                url,
                manifest_sha256,
            },
            aux_identity,
        )
    };

    let baseband = if baseband_from_aux {
        let (path, sha1) = match &selection.baseband {
            Some(entry) => (
                format!("Firmware/{}", entry.file()),
                Some(entry.sha1().to_owned()),
            ),
            None => (
                aux_identity.component_path("BasebandFirmware")?.to_owned(),
                None,
            ),
        };
        Some(AuxBasebandResolution { path, sha1 })
    } else {
        None
    };
    if sep_from_aux && !aux_identity.manifest().contains_key("RestoreSEP") {
        return Err(AuxFirmwareError::MissingComponent("RestoreSEP"));
    }
    if sep_from_aux {
        info!(
            version = selection.version.as_str(),
            build = selection.build.as_str(),
            "auxiliary SEP firmware source resolved"
        );
    }
    Ok(Some(AuxFirmwareResolution {
        version: selection.version,
        build: selection.build,
        source,
        baseband,
        sep: sep_from_aux,
    }))
}

/// The opened aux firmware source at execution time: the target archive when
/// the aux build equals the target build, otherwise a range-reading remote
/// archive over the plan-recorded URL.
#[derive(Clone, Debug)]
pub(crate) enum AuxArchive {
    Local(FirmwareArchive),
    Remote(RemoteFirmwareArchive),
}

/// The aux archive plus its selected build identity; private fields so the
/// manifest digest pinning holds at every use site.
#[derive(Clone, Debug)]
pub(crate) struct AuxContext {
    archive: AuxArchive,
    identity: BuildIdentity,
}

impl AuxContext {
    /// Open a plan-resolved aux source, verifying the BuildManifest SHA-256
    /// recorded at plan time for remote sources.
    pub(crate) async fn open(
        plan: &crate::RestorePlan,
        aux: &AuxFirmwareResolution,
    ) -> Result<Self, AuxFirmwareError> {
        let board = plan
            .device()
            .board_config()
            .ok_or(AuxFirmwareError::MissingBoardConfig)?;
        let (archive, manifest) = match aux.source() {
            AuxFirmwareSource::Target => {
                let archive = FirmwareArchive::open(plan.firmware())?;
                let manifest = archive.build_manifest()?;
                (AuxArchive::Local(archive), manifest)
            }
            AuxFirmwareSource::Remote {
                url,
                manifest_sha256,
            } => {
                let archive = RemoteFirmwareArchive::open(url).await?;
                let bytes = archive.read_entry("BuildManifest.plist").await?;
                let actual = hex::encode(Sha256::digest(&bytes));
                if actual != *manifest_sha256 {
                    return Err(AuxFirmwareError::ManifestDigestMismatch {
                        expected: manifest_sha256.clone(),
                        actual,
                    });
                }
                let manifest = BuildManifest::from_reader(Cursor::new(bytes))?;
                (AuxArchive::Remote(archive), manifest)
            }
        };
        let identity = select_aux_identity(
            &manifest,
            board,
            plan.behavior(),
            plan.exploit_policy() != ExploitPolicy::None,
        )?;
        Ok(Self { archive, identity })
    }

    /// Open a local user-provided IPSW as the aux source (the
    /// `SepPolicy::Provided`/`BasebandPolicy::Provided` pins).
    pub(crate) fn from_local(
        path: &Path,
        board: &BoardConfig,
        behavior: RestoreBehavior,
    ) -> Result<Self, AuxFirmwareError> {
        let archive = FirmwareArchive::open(path)?;
        let manifest = archive.build_manifest()?;
        let identity = select_aux_identity(&manifest, board, behavior, false)?;
        Ok(Self {
            archive: AuxArchive::Local(archive),
            identity,
        })
    }

    pub(crate) fn identity(&self) -> &BuildIdentity {
        &self.identity
    }

    pub(crate) fn archive(&self) -> &AuxArchive {
        &self.archive
    }

    pub(crate) async fn read_entry(&self, path: &str) -> Result<Vec<u8>, AuxFirmwareError> {
        match &self.archive {
            AuxArchive::Local(archive) => Ok(archive.read_entry(path)?),
            AuxArchive::Remote(archive) => Ok(archive.read_entry(path).await?),
        }
    }
}

/// The aux firmware selection for a restore plan failed.
#[derive(Debug, Error)]
pub enum AuxFirmwareError {
    #[error("device {0} has no auxiliary firmware table entry")]
    MissingDeviceData(ProductType),
    #[error("device {product} has no auxiliary firmware build for target {target}")]
    BuildUnavailable {
        product: ProductType,
        target: String,
    },
    #[error("restore plan device has no board config")]
    MissingBoardConfig,
    #[error("appledb request failed: {0}")]
    AppleDb(#[from] reqwest::Error),
    #[error("appledb found no IPSW source for {product} {build}")]
    NoIpswSource { product: ProductType, build: String },
    #[error("appledb IPSW URL for {build} does not contain the build id: {url}")]
    IpswUrlMismatch { url: String, build: String },
    #[error("auxiliary build identity of {build} could not be selected: {source}")]
    Identity {
        build: String,
        #[source]
        source: Box<FirmwareError>,
    },
    #[error("remote auxiliary firmware read failed: {0}")]
    Remote(#[from] RemoteFirmwareError),
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error("auxiliary firmware build {actual} does not match the selected {expected}")]
    BuildMismatch { expected: String, actual: String },
    #[error("auxiliary BuildManifest SHA-256 mismatch: expected {expected}, got {actual}")]
    ManifestDigestMismatch { expected: String, actual: String },
    #[error("auxiliary build identity has no {0} component")]
    MissingComponent(&'static str),
    #[error("auxiliary SEP firmware has no Digest in the build manifest")]
    MissingSepDigest,
    #[error("auxiliary SEP firmware does not match the build manifest Digest")]
    SepDigestMismatch,
    #[error("firmware I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use legacy_ios_assets::DeviceDatabase;

    use super::*;

    fn profile(product: &str) -> &'static DeviceProfile {
        DeviceDatabase::bundled()
            .find_product(&ProductType::from(product))
            .unwrap()
    }

    fn select(product: &str, target: &str) -> AuxBuildSelection {
        let profile = profile(product);
        select_aux_build(
            profile.product_type(),
            profile.soc(),
            profile.aux_firmware(),
            target,
        )
        .unwrap()
    }

    #[test]
    fn processor_classes_follow_the_upstream_table() {
        assert_eq!(processor_class(Soc::S5l8900), 1);
        assert_eq!(processor_class(Soc::A4), 4);
        assert_eq!(processor_class(Soc::A5x), 5);
        assert_eq!(processor_class(Soc::A6x), 6);
        assert_eq!(processor_class(Soc::A7), 7);
        assert_eq!(processor_class(Soc::A8x), 8);
        assert_eq!(processor_class(Soc::A9x), 9);
        assert_eq!(processor_class(Soc::A10x), 10);
        assert_eq!(processor_class(Soc::A11), 10);
    }

    #[test]
    fn selects_the_use_build_for_32_bit_devices() {
        let selection = select("iPhone4,1", "6.1.3");
        assert_eq!(selection.version, "9.3.6");
        assert_eq!(selection.build, "13G37");
        assert_eq!(
            selection.baseband.unwrap().file(),
            "Trek-6.7.00.Release.bbfw"
        );

        // WiFi-only devices have no table baseband.
        let selection = select("iPad2,1", "6.1.3");
        assert_eq!(selection.build, "13G36");
        assert!(selection.baseband.is_none());
    }

    #[test]
    fn a7_uses_the_use_build_only_for_ios10_targets() {
        let selection = select("iPhone6,1", "10.3.3");
        assert_eq!(selection.build, "14G60");
        assert_eq!(
            selection.baseband.unwrap().file(),
            "Mav7Mav8-7.60.00.Release.bbfw"
        );

        let selection = select("iPhone6,1", "12.0.1");
        assert_eq!(selection.version, "12.5.8");
        assert_eq!(selection.build, "16H88");
        assert_eq!(
            selection.baseband.unwrap().file(),
            "Mav7Mav8-10.80.02.Release.bbfw"
        );

        // iPad4,8 has no `use` build upstream, so iOS 10 targets cannot be
        // planned for it instead of silently using the wrong firmware.
        let error = {
            let profile = profile("iPad4,8");
            select_aux_build(
                profile.product_type(),
                profile.soc(),
                profile.aux_firmware(),
                "10.3.3",
            )
            .unwrap_err()
        };
        assert!(matches!(error, AuxFirmwareError::BuildUnavailable { .. }));
    }

    #[test]
    fn a8_and_later_always_use_the_latest_build() {
        for (product, version, build) in [
            ("iPhone7,2", "12.5.8", "16H88"),
            ("iPod7,1", "12.5.8", "16H88"),
            ("iPhone8,1", "15.8.8", "19H422"),
            ("iPhone9,3", "15.8.8", "19H422"),
            ("iPhone10,3", "16.7.16", "20H392"),
            ("iPad6,11", "16.7.16", "20H392"),
            ("iPad7,5", "17.7.11", "21H461"),
            ("iPad7,11", "18.7.10", "22H374"),
        ] {
            let selection = select(product, "10.0");
            assert_eq!(
                (selection.version.as_str(), selection.build.as_str()),
                (version, build),
                "{product}"
            );
            // A8+ devices have no table baseband; it comes from the fetched
            // aux manifest instead.
            assert!(selection.baseband.is_none(), "{product}");
        }
    }

    #[test]
    fn appledb_bucket_follows_the_upstream_case_rules() {
        assert_eq!(appledb_bucket("iPhone6,1", "14G60"), "iOS");
        assert_eq!(appledb_bucket("iPhone6,1", "19H422"), "iOS");
        assert_eq!(appledb_bucket("iPhone6,1", "20H392"), "iOS");
        assert_eq!(appledb_bucket("iPhone3,1", "5H11"), "iPhone Software");
        assert_eq!(appledb_bucket("iPhone3,1", "1C25"), "iPhone Software");
        assert_eq!(appledb_bucket("iPhone3,1", "7E18"), "iPhone OS");
        assert_eq!(appledb_bucket("iPhone3,1", "7B405"), "iOS");
        // iPad builds 17.x+ move to the iPadOS bucket.
        assert_eq!(appledb_bucket("iPad7,5", "21H461"), "iPadOS");
        assert_eq!(appledb_bucket("iPad7,11", "22H374"), "iPadOS");
        assert_eq!(appledb_bucket("iPad5,1", "19H422"), "iPadOS");
        assert_eq!(appledb_bucket("iPad2,1", "13G36"), "iOS");
    }

    #[test]
    fn picks_the_ipsw_source_covering_the_device() {
        let response: AppleDbResponse = serde_json::from_str(
            r#"{
                "version": "12.5.8",
                "sources": [
                    {"type": "ota", "deviceMap": ["iPhone6,1"], "links": [{"url": "https://example.com/ota.zip"}]},
                    {"type": "ipsw", "deviceMap": ["iPhone6,2"], "links": [{"url": "https://example.com/other_16H88_Restore.ipsw"}]},
                    {"type": "ipsw", "deviceMap": ["iPhone6,1", "iPhone6,2"], "links": [{"url": "https://example.com/iPhone_4.0_64bit_12.5.8_16H88_Restore.ipsw"}]}
                ]
            }"#,
        )
        .unwrap();
        let url = parse_appledb_response(&response, "iPhone6,1", "16H88").unwrap();
        assert_eq!(
            url,
            "https://example.com/iPhone_4.0_64bit_12.5.8_16H88_Restore.ipsw"
        );
    }

    #[test]
    fn rejects_sources_without_the_device_or_build_id() {
        let response: AppleDbResponse = serde_json::from_str(
            r#"{"sources": [{"type": "ipsw", "deviceMap": ["iPhone6,2"], "links": [{"url": "https://example.com/16H88.ipsw"}]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            parse_appledb_response(&response, "iPhone6,1", "16H88"),
            Err(AuxFirmwareError::NoIpswSource { .. })
        ));

        // A URL not carrying the build id is rejected like upstream's check.
        let response: AppleDbResponse = serde_json::from_str(
            r#"{"sources": [{"type": "ipsw", "deviceMap": ["iPhone6,1"], "links": [{"url": "https://example.com/restore.ipsw"}]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            parse_appledb_response(&response, "iPhone6,1", "16H88"),
            Err(AuxFirmwareError::IpswUrlMismatch { .. })
        ));
    }
}
