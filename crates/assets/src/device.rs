use std::{collections::BTreeMap, sync::OnceLock};

use legacy_ios_core::{BoardConfig, ProductType, Soc};
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
    #[error("invalid device database: {0}")]
    InvalidToml(#[from] toml::de::Error),
    #[error("unsupported device database schema {0}")]
    UnsupportedSchema(u32),
    #[error("duplicate product type {0}")]
    DuplicateProduct(ProductType),
    #[error("duplicate board config {0}")]
    DuplicateBoardConfig(BoardConfig),
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
}
