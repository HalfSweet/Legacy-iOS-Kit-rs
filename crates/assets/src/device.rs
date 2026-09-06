use std::{collections::BTreeMap, sync::OnceLock};

use legacy_ios_core::{BoardConfig, Capability, CapabilitySet, ProductType, Soc};
use serde::Deserialize;
use thiserror::Error;

const BUNDLED_DEVICES: &str = include_str!("../data/devices.toml");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceProfile {
    product_type: ProductType,
    name: String,
    board_configs: Vec<BoardConfig>,
    soc: Soc,
    has_baseband: bool,
    aux: Option<AuxFirmwareInfo>,
}

/// An auxiliary iOS release a device's SEP/baseband firmware is sourced from,
/// mirroring upstream's `device_use_vers`/`device_use_build` and
/// `device_latest_vers`/`device_latest_build` pairs (restore.sh:1597-1656).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxBuild {
    version: String,
    build: String,
}

impl AuxBuild {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }
}

/// A baseband firmware file inside the auxiliary IPSW, with the SHA-1 digest
/// upstream verifies after download (`device_use_bb_sha1`/`device_latest_bb_sha1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxBaseband {
    file: String,
    sha1: String,
}

impl AuxBaseband {
    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn sha1(&self) -> &str {
        &self.sha1
    }
}

/// Auxiliary firmware table of a device: where the SEP and baseband used
/// during a restore come from when they differ from the target IPSW
/// (upstream `restore_download_bbsep`, restore.sh:6074-6150).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuxFirmwareInfo {
    use_build: Option<AuxBuild>,
    latest_build: Option<AuxBuild>,
    use_baseband: Option<AuxBaseband>,
    latest_baseband: Option<AuxBaseband>,
    disable_baseband_for_non_latest: bool,
}

impl AuxFirmwareInfo {
    /// The device's `use` build (upstream `device_use_vers`/`device_use_build`).
    pub fn use_build(&self) -> Option<&AuxBuild> {
        self.use_build.as_ref()
    }

    /// The device's `latest` build; falls back to the `use` build like
    /// upstream does when the latest version is not set (restore.sh:1657-1661).
    pub fn latest_build(&self) -> Option<&AuxBuild> {
        self.latest_build.as_ref().or(self.use_build.as_ref())
    }

    /// The baseband firmware of the `use` build; falls back to the latest
    /// baseband like upstream does when only the latter is set
    /// (restore.sh:1697-1701).
    pub fn use_baseband(&self) -> Option<&AuxBaseband> {
        self.use_baseband.as_ref().or(self.latest_baseband.as_ref())
    }

    /// The baseband firmware of the `latest` build.
    pub fn latest_baseband(&self) -> Option<&AuxBaseband> {
        self.latest_baseband.as_ref()
    }

    /// Whether baseband updates are disabled for targets other than the
    /// `use` version (upstream `device_use_bb2`, restore.sh:1692-1693).
    pub const fn disable_baseband_for_non_latest(&self) -> bool {
        self.disable_baseband_for_non_latest
    }
}

impl DeviceProfile {
    pub fn product_type(&self) -> &ProductType {
        &self.product_type
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn board_configs(&self) -> &[BoardConfig] {
        &self.board_configs
    }

    pub const fn soc(&self) -> Soc {
        self.soc
    }

    pub const fn has_baseband(&self) -> bool {
        self.has_baseband
    }

    /// Auxiliary firmware table of the device (upstream `device_use_*` /
    /// `device_latest_*`), when the upstream tables cover the product.
    pub fn aux_firmware(&self) -> Option<&AuxFirmwareInfo> {
        self.aux.as_ref()
    }

    /// Capabilities the current entry points can execute for this device:
    /// [`DeviceProfile::hardware_capabilities`] minus
    /// [`DeviceProfile::capability_gaps`]. Per-version, per-board, and
    /// per-state constraints remain the restore planner's job; this set only
    /// declares hardware-level applicability and entry-level executability.
    /// Verification status (offline vs. on-device) is tracked per feature in
    /// `docs/COMPATIBILITY.md`, not encoded here.
    pub fn capabilities(&self) -> CapabilitySet {
        let gaps = self.capability_gaps();
        CapabilitySet::from_capabilities(
            self.hardware_capabilities()
                .iter()
                .filter(|capability| !gaps.contains(*capability)),
        )
    }

    /// Capabilities the device's hardware supports in principle per the
    /// upstream baseline, including ones with no executable entry point yet.
    pub fn hardware_capabilities(&self) -> CapabilitySet {
        let mut capabilities = vec![
            Capability::Recovery,
            Capability::Dfu,
            Capability::PwnDfu,
            Capability::Restore,
            Capability::AppManagement,
            Capability::DataManagement,
        ];
        if supports_blob_restore(self.soc, self.product_type.as_str()) {
            capabilities.push(Capability::BlobRestore);
        }
        if supports_onboard_shsh(self.product_type.as_str()) {
            capabilities.push(Capability::OnboardShsh);
        }
        if supports_ssh_ramdisk(self.product_type.as_str()) {
            capabilities.push(Capability::SshRamdisk);
        }
        if supports_tethered_restore(self.soc, self.product_type.as_str()) {
            capabilities.push(Capability::TetheredRestore);
        }
        if is_32_bit(self.soc) {
            capabilities.push(Capability::Jailbreak);
        }
        if matches!(self.soc, Soc::A4 | Soc::A5 | Soc::A5x | Soc::A6 | Soc::A6x) {
            capabilities.push(Capability::KDfu);
        }
        if supports_ota(self.product_type.as_str()) {
            capabilities.push(Capability::OtaDowngrade);
        }
        if matches!(
            self.product_type.as_str(),
            "iPhone1,1" | "iPhone1,2" | "iPhone2,1" | "iPhone3,1" | "iPhone3,2" | "iPhone3,3"
        ) {
            capabilities.push(Capability::Hacktivation);
        }
        CapabilitySet::from_capabilities(capabilities)
    }

    /// Hardware-applicable capabilities the shipped entry points cannot
    /// execute yet (upstream parity gaps).
    pub fn capability_gaps(&self) -> CapabilitySet {
        let mut gaps = Vec::new();
        // The 32-bit tethered boot builder (upstream "Other (Tethered)",
        // restore.sh:9197-9199) is not implemented.
        if self
            .hardware_capabilities()
            .contains(Capability::TetheredRestore)
        {
            gaps.push(Capability::TetheredRestore);
        }
        CapabilitySet::from_capabilities(gaps)
    }
}

const fn is_32_bit(soc: Soc) -> bool {
    matches!(
        soc,
        Soc::S5l8900
            | Soc::S5l8720
            | Soc::S5l8920
            | Soc::S5l8922
            | Soc::A4
            | Soc::A5
            | Soc::A5x
            | Soc::A6
            | Soc::A6x
    )
}

/// Upstream gates blob restores ("Other (Use SHSH Blobs)") to devices past
/// the S5L8900, excluding iPod2,1 (restore.sh:9196).
fn supports_blob_restore(soc: Soc, product_type: &str) -> bool {
    soc != Soc::S5l8900 && product_type != "iPod2,1"
}

/// Upstream excludes iPhone2,1, iPod3,1, and iPad1,1 from onboard SHSH dumps
/// (restore.sh:8983).
fn supports_onboard_shsh(product_type: &str) -> bool {
    !matches!(product_type, "iPhone2,1" | "iPod3,1" | "iPad1,1")
}

/// Upstream excludes devices whose latest release is iOS 16 (iPhone10,*,
/// iPad6,*) and the checkm8 iPads (iPad[67],*) from the SSH ramdisk path
/// (restore.sh:10667, with `device_checkm8ipad` set at restore.sh:1560).
fn supports_ssh_ramdisk(product_type: &str) -> bool {
    !(product_type.starts_with("iPhone10,")
        || product_type.starts_with("iPad6,")
        || product_type.starts_with("iPad7,"))
}

/// Upstream gates tethered restores ("Other (Tethered)") to 32-bit devices
/// past the S5L8900, excluding iPod2,1 (restore.sh:9196-9199).
fn supports_tethered_restore(soc: Soc, product_type: &str) -> bool {
    is_32_bit(soc) && soc != Soc::S5l8900 && product_type != "iPod2,1"
}

fn supports_ota(product_type: &str) -> bool {
    matches!(
        product_type,
        "iPhone4,1"
            | "iPhone5,1"
            | "iPhone5,2"
            | "iPhone6,1"
            | "iPhone6,2"
            | "iPad2,1"
            | "iPad2,2"
            | "iPad2,3"
            | "iPad2,4"
            | "iPad2,5"
            | "iPad2,6"
            | "iPad2,7"
            | "iPad3,1"
            | "iPad3,2"
            | "iPad3,3"
            | "iPad3,4"
            | "iPad3,5"
            | "iPad3,6"
            | "iPad4,1"
            | "iPad4,2"
            | "iPad4,3"
            | "iPad4,4"
            | "iPad4,5"
            | "iPod5,1"
    )
}

#[derive(Clone, Debug)]
pub struct DeviceDatabase {
    schema_version: u32,
    baseline_commit: String,
    by_product: BTreeMap<ProductType, DeviceProfile>,
    product_by_board: BTreeMap<BoardConfig, ProductType>,
}

impl DeviceDatabase {
    pub fn bundled() -> &'static Self {
        static DATABASE: OnceLock<DeviceDatabase> = OnceLock::new();
        DATABASE.get_or_init(|| {
            Self::parse(BUNDLED_DEVICES).expect("bundled device database must be valid")
        })
    }

    pub fn parse(source: &str) -> Result<Self, AssetError> {
        let raw: RawDatabase = toml::from_str(source)?;
        if raw.schema_version != 1 {
            return Err(AssetError::UnsupportedSchema(raw.schema_version));
        }
        let mut by_product = BTreeMap::new();
        let mut product_by_board = BTreeMap::new();

        for raw_profile in raw.devices {
            let product_type = ProductType::new(raw_profile.product_type);
            let board_configs = raw_profile
                .board_configs
                .into_iter()
                .map(BoardConfig::new)
                .collect::<Vec<_>>();
            let profile = DeviceProfile {
                product_type: product_type.clone(),
                name: raw_profile.name,
                board_configs: board_configs.clone(),
                soc: raw_profile.soc,
                has_baseband: raw_profile.has_baseband,
                aux: raw_profile.aux.map(AuxFirmwareInfo::try_from).transpose()?,
            };

            if by_product.insert(product_type.clone(), profile).is_some() {
                return Err(AssetError::DuplicateProduct(product_type));
            }
            for board_config in board_configs {
                if product_by_board
                    .insert(board_config.clone(), product_type.clone())
                    .is_some()
                {
                    return Err(AssetError::DuplicateBoardConfig(board_config));
                }
            }
        }

        Ok(Self {
            schema_version: raw.schema_version,
            baseline_commit: raw.baseline_commit,
            by_product,
            product_by_board,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn baseline_commit(&self) -> &str {
        &self.baseline_commit
    }

    pub fn find_product(&self, product_type: &ProductType) -> Option<&DeviceProfile> {
        self.by_product.get(product_type)
    }

    pub fn find_board_config(&self, board_config: &BoardConfig) -> Option<&DeviceProfile> {
        let product_type = self.product_by_board.get(board_config)?;
        self.by_product.get(product_type)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DeviceProfile> {
        self.by_product.values()
    }
}

#[derive(Debug, Error)]
pub enum AssetError {
    #[error("invalid asset TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),
    #[error("unsupported device database schema {0}")]
    UnsupportedSchema(u32),
    #[error("duplicate product type {0}")]
    DuplicateProduct(ProductType),
    #[error("duplicate board config {0}")]
    DuplicateBoardConfig(BoardConfig),
    #[error("duplicate resource {0}")]
    DuplicateResource(crate::ResourceId),
    #[error("resource {0} has an invalid SHA-256 digest")]
    InvalidDigest(String),
    #[error("auxiliary baseband {0} has an invalid SHA-1 digest")]
    InvalidAuxBasebandDigest(String),
}

#[derive(Deserialize)]
struct RawDatabase {
    schema_version: u32,
    baseline_commit: String,
    devices: Vec<RawDeviceProfile>,
}

#[derive(Deserialize)]
struct RawDeviceProfile {
    product_type: String,
    name: String,
    board_configs: Vec<String>,
    soc: Soc,
    has_baseband: bool,
    aux: Option<RawAuxFirmware>,
}

#[derive(Deserialize)]
struct RawAuxFirmware {
    #[serde(rename = "use")]
    use_build: Option<RawAuxBuild>,
    latest: Option<RawAuxBuild>,
    use_baseband: Option<RawAuxBaseband>,
    latest_baseband: Option<RawAuxBaseband>,
    #[serde(default)]
    disable_baseband_for_non_latest: bool,
}

#[derive(Deserialize)]
struct RawAuxBuild {
    version: String,
    build: String,
}

#[derive(Deserialize)]
struct RawAuxBaseband {
    file: String,
    sha1: String,
}

impl TryFrom<RawAuxFirmware> for AuxFirmwareInfo {
    type Error = AssetError;

    fn try_from(raw: RawAuxFirmware) -> Result<Self, Self::Error> {
        let baseband = |raw: Option<RawAuxBaseband>| -> Result<Option<AuxBaseband>, AssetError> {
            raw.map(|raw| {
                if raw.sha1.len() != 40 || !raw.sha1.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(AssetError::InvalidAuxBasebandDigest(raw.file));
                }
                Ok(AuxBaseband {
                    file: raw.file,
                    sha1: raw.sha1,
                })
            })
            .transpose()
        };
        Ok(Self {
            use_build: raw.use_build.map(|raw| AuxBuild {
                version: raw.version,
                build: raw.build,
            }),
            latest_build: raw.latest.map(|raw| AuxBuild {
                version: raw.version,
                build: raw.build,
            }),
            use_baseband: baseband(raw.use_baseband)?,
            latest_baseband: baseband(raw.latest_baseband)?,
            disable_baseband_for_non_latest: raw.disable_baseband_for_non_latest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_database_resolves_product_and_board_aliases() {
        let database = DeviceDatabase::bundled();

        let a4 = database
            .find_product(&ProductType::from("iPhone3,1"))
            .unwrap();
        assert_eq!(a4.soc(), Soc::A4);

        let a9 = database
            .find_board_config(&BoardConfig::from("n71m"))
            .unwrap();
        assert_eq!(a9.product_type(), &ProductType::from("iPhone8,1"));
    }

    #[test]
    fn derives_capabilities_from_device_family() {
        let database = DeviceDatabase::bundled();
        let a5 = database
            .find_product(&ProductType::from("iPhone4,1"))
            .unwrap();
        assert!(a5.capabilities().contains(Capability::OtaDowngrade));
        assert!(a5.capabilities().contains(Capability::KDfu));

        let a11 = database
            .find_product(&ProductType::from("iPhone10,6"))
            .unwrap();
        assert!(!a11.capabilities().contains(Capability::Jailbreak));
    }

    #[test]
    fn ssh_ramdisk_excludes_the_ios16_class_and_checkm8_ipads() {
        // restore.sh:10667 excludes devices whose latest release is iOS 16
        // (iPhone10,*, iPad6,*) and the checkm8 iPads (restore.sh:1560).
        let database = DeviceDatabase::bundled();
        for excluded in ["iPhone10,6", "iPad6,11", "iPad7,5"] {
            let profile = database.find_product(&ProductType::from(excluded)).unwrap();
            assert!(
                !profile
                    .hardware_capabilities()
                    .contains(Capability::SshRamdisk),
                "{excluded} must not declare SshRamdisk"
            );
        }
        let a10 = database
            .find_product(&ProductType::from("iPhone9,1"))
            .unwrap();
        assert!(a10.capabilities().contains(Capability::SshRamdisk));
    }

    #[test]
    fn tethered_restore_is_a_hardware_capability_without_an_entry_point() {
        // Hardware-applicable per restore.sh:9196-9199, but the 32-bit
        // tethered boot builder is not implemented.
        let database = DeviceDatabase::bundled();
        let a5 = database
            .find_product(&ProductType::from("iPhone4,1"))
            .unwrap();
        assert!(
            a5.hardware_capabilities()
                .contains(Capability::TetheredRestore)
        );
        assert!(a5.capability_gaps().contains(Capability::TetheredRestore));
        assert!(!a5.capabilities().contains(Capability::TetheredRestore));

        // S5L8900 and iPod2,1 are not hardware-applicable (restore.sh:9196).
        for excluded in ["iPhone1,1", "iPod2,1"] {
            let profile = database.find_product(&ProductType::from(excluded)).unwrap();
            assert!(
                !profile
                    .hardware_capabilities()
                    .contains(Capability::TetheredRestore),
                "{excluded} must not declare TetheredRestore"
            );
        }
    }

    #[test]
    fn blob_restore_and_onboard_shsh_follow_the_upstream_device_gates() {
        // restore.sh:9196 (blob restores) and restore.sh:8983 (onboard blobs).
        let database = DeviceDatabase::bundled();
        let profile = |product: &str| {
            database
                .find_product(&ProductType::from(product))
                .unwrap()
                .hardware_capabilities()
        };

        assert!(!profile("iPhone1,1").contains(Capability::BlobRestore));
        assert!(!profile("iPod2,1").contains(Capability::BlobRestore));
        assert!(profile("iPhone2,1").contains(Capability::BlobRestore));
        assert!(profile("iPhone8,1").contains(Capability::BlobRestore));

        assert!(!profile("iPhone2,1").contains(Capability::OnboardShsh));
        assert!(!profile("iPod3,1").contains(Capability::OnboardShsh));
        assert!(!profile("iPad1,1").contains(Capability::OnboardShsh));
        assert!(profile("iPhone1,1").contains(Capability::OnboardShsh));
        assert!(profile("iPhone8,1").contains(Capability::OnboardShsh));
    }

    #[test]
    fn aux_firmware_matches_the_upstream_device_tables() {
        let database = DeviceDatabase::bundled();

        // iPhone6,1 (restore.sh:1628-1630, 1646-1649, 1683-1685, 1694-1696).
        let iphone5s = database
            .find_product(&ProductType::from("iPhone6,1"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        let use_build = iphone5s.use_build().unwrap();
        assert_eq!(use_build.version(), "10.3.3");
        assert_eq!(use_build.build(), "14G60");
        let latest_build = iphone5s.latest_build().unwrap();
        assert_eq!(latest_build.version(), "12.5.8");
        assert_eq!(latest_build.build(), "16H88");
        assert_eq!(
            iphone5s.use_baseband().unwrap().file(),
            "Mav7Mav8-7.60.00.Release.bbfw"
        );
        assert_eq!(
            iphone5s.use_baseband().unwrap().sha1(),
            "f397724367f6bed459cf8f3d523553c13e8ae12c"
        );
        assert_eq!(
            iphone5s.latest_baseband().unwrap().file(),
            "Mav7Mav8-10.80.02.Release.bbfw"
        );
        assert_eq!(
            iphone5s.latest_baseband().unwrap().sha1(),
            "f5db17f72a78d807a791138cd5ca87d2f5e859f0"
        );

        // iPhone8,1 has only a latest build upstream (restore.sh:1646-1652).
        let iphone6s = database
            .find_product(&ProductType::from("iPhone8,1"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        assert!(iphone6s.use_build().is_none());
        let latest_build = iphone6s.latest_build().unwrap();
        assert_eq!(latest_build.version(), "15.8.8");
        assert_eq!(latest_build.build(), "19H422");
        assert!(iphone6s.use_baseband().is_none());

        // iPhone4,1: `use` only, and the latest build falls back to it.
        let iphone4s = database
            .find_product(&ProductType::from("iPhone4,1"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        assert_eq!(iphone4s.use_build().unwrap().build(), "13G37");
        assert_eq!(iphone4s.latest_build().unwrap().version(), "9.3.6");
        assert_eq!(
            iphone4s.use_baseband().unwrap().file(),
            "Trek-6.7.00.Release.bbfw"
        );

        // iPad4,8 has no `use` build upstream; the use baseband falls back to
        // the latest one (restore.sh:1697-1701).
        let ipadmini3 = database
            .find_product(&ProductType::from("iPad4,8"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        assert!(ipadmini3.use_build().is_none());
        assert_eq!(
            ipadmini3.use_baseband().unwrap().file(),
            "Mav7Mav8-10.80.02.Release.bbfw"
        );

        // iPhone3,1 disables baseband updates for non-latest targets
        // (device_use_bb2, restore.sh:1692).
        let iphone4 = database
            .find_product(&ProductType::from("iPhone3,1"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        assert!(iphone4.disable_baseband_for_non_latest());
        assert!(iphone4.use_baseband().is_none());
        let iphone5 = database
            .find_product(&ProductType::from("iPhone5,1"))
            .unwrap()
            .aux_firmware()
            .unwrap();
        assert!(!iphone5.disable_baseband_for_non_latest());
    }
}
