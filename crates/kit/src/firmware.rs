use std::path::PathBuf;

use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use legacy_ios_firmware::{FirmwareArchive, RestoreBehavior};
use serde::{Deserialize, Serialize};

use crate::KitError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirmwareSummary {
    path: PathBuf,
    product_version: IosVersion,
    build_id: BuildId,
    supported_product_types: Vec<ProductType>,
    identities: Vec<FirmwareIdentitySummary>,
}

impl FirmwareSummary {
    pub(crate) fn inspect(path: PathBuf) -> Result<Self, KitError> {
        let archive = FirmwareArchive::open(&path)?;
        let manifest = archive.build_manifest()?;
        let identities = manifest
            .identities()
            .iter()
            .map(|identity| FirmwareIdentitySummary {
                board_config: identity.board_config().clone(),
                restore_behavior: identity.restore_behavior(),
                component_count: identity.manifest().len(),
            })
            .collect();
        Ok(Self {
            path,
            product_version: manifest.product_version().clone(),
            build_id: manifest.build_id().clone(),
            supported_product_types: manifest.supported_product_types().to_vec(),
            identities,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn product_version(&self) -> &IosVersion {
        &self.product_version
    }

    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    pub fn supported_product_types(&self) -> &[ProductType] {
        &self.supported_product_types
    }

    pub fn identities(&self) -> &[FirmwareIdentitySummary] {
        &self.identities
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FirmwareIdentitySummary {
    board_config: BoardConfig,
    restore_behavior: RestoreBehavior,
    component_count: usize,
}

impl FirmwareIdentitySummary {
    pub fn board_config(&self) -> &BoardConfig {
        &self.board_config
    }

    pub const fn restore_behavior(&self) -> RestoreBehavior {
        self.restore_behavior
    }

    pub const fn component_count(&self) -> usize {
        self.component_count
    }
}
