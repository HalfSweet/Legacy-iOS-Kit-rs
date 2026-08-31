use std::{
    io::Write,
    path::{Path, PathBuf},
};

use legacy_ios_assets::{ResourceCatalog, ResourceId};
use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use legacy_ios_firmware::{
    ArtifactSpec, ArtifactStore, BuildManifest, FirmwareArchive, RemoteFirmwareArchive,
    RestoreBehavior,
};
use legacy_ios_image::{DmgFirmwareKey, decrypt_firmware_image};
use serde::{Deserialize, Serialize};

use crate::KitError;

pub(crate) async fn decrypt_dmg(
    source: PathBuf,
    destination: PathBuf,
    key: DmgFirmwareKey,
) -> Result<(), KitError> {
    let encrypted = tokio::fs::read(source).await?;
    let decrypted = tokio::task::spawn_blocking(move || decrypt_firmware_image(&encrypted, &key))
        .await
        .map_err(|error| KitError::Task(error.to_string()))??;
    tokio::task::spawn_blocking(move || {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&decrypted)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(destination)
            .map_err(|error| error.error)?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    Ok(())
}

pub(crate) async fn fetch_resource(
    id: &ResourceId,
    cache_root: PathBuf,
) -> Result<PathBuf, KitError> {
    let record = ResourceCatalog::bundled()
        .get(id)
        .ok_or_else(|| KitError::UnknownResource(id.clone()))?;
    let digest = format!("sha256:{}", record.sha256());
    let spec = ArtifactSpec::parse(record.source_url(), &digest)?.with_size(record.size());
    Ok(ArtifactStore::new(cache_root).fetch(&spec).await?)
}

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
pub struct RemoteFirmwareSummary {
    url: String,
    length: u64,
    product_version: IosVersion,
    build_id: BuildId,
    supported_product_types: Vec<ProductType>,
    identities: Vec<FirmwareIdentitySummary>,
}

impl RemoteFirmwareSummary {
    pub(crate) async fn inspect(url: String) -> Result<Self, KitError> {
        let archive = RemoteFirmwareArchive::open(&url).await?;
        let length = archive.length();
        let manifest = archive.build_manifest().await?;
        Ok(Self {
            url,
            length,
            product_version: manifest.product_version().clone(),
            build_id: manifest.build_id().clone(),
            supported_product_types: manifest.supported_product_types().to_vec(),
            identities: identities(&manifest),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub const fn length(&self) -> u64 {
        self.length
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

fn identities(manifest: &BuildManifest) -> Vec<FirmwareIdentitySummary> {
    manifest
        .identities()
        .iter()
        .map(|identity| FirmwareIdentitySummary {
            board_config: identity.board_config().clone(),
            restore_behavior: identity.restore_behavior(),
            component_count: identity.manifest().len(),
        })
        .collect()
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
