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

    pub fn capabilities(&self) -> CapabilitySet {
        let mut capabilities = vec![
            Capability::Recovery,
            Capability::Dfu,
            Capability::PwnDfu,
            Capability::Restore,
            Capability::BlobRestore,
            Capability::OnboardShsh,
            Capability::SshRamdisk,
            Capability::AppManagement,
            Capability::DataManagement,
        ];
        if is_32_bit(self.soc) {
            capabilities.extend([Capability::TetheredRestore, Capability::Jailbreak]);
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
}
