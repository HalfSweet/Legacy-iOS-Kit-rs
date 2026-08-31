use std::{
    io::Write,
    path::{Path, PathBuf},
};

use legacy_ios_assets::{ResourceCatalog, ResourceId};
use legacy_ios_core::{BoardConfig, BuildId, IosVersion, ProductType};
use legacy_ios_firmware::{
    ArtifactSpec, ArtifactStore, BuildManifest, CustomIpswBuilder, FirmwareArchive,
    RemoteFirmwareArchive, RestoreBehavior,
};
use legacy_ios_image::{
    DmgFirmwareKey, DmgImage, DmgPartitionInput, HfsImage, decrypt_firmware_image,
};
use serde::{Deserialize, Serialize};

use crate::{HfsMutation, KitError, hfs::apply_mutations};

#[derive(Clone, Debug)]
pub struct CustomRootfsRequest {
    source: PathBuf,
    destination: PathBuf,
    board_config: BoardConfig,
    behavior: RestoreBehavior,
    key: Option<DmgFirmwareKey>,
    mutations: Vec<HfsMutation>,
}

impl CustomRootfsRequest {
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        board_config: BoardConfig,
        behavior: RestoreBehavior,
        mutations: Vec<HfsMutation>,
    ) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            board_config,
            behavior,
            key: None,
            mutations,
        }
    }

    pub fn with_firmware_key(mut self, key: DmgFirmwareKey) -> Self {
        self.key = Some(key);
        self
    }
}

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

pub(crate) async fn build_custom_rootfs(
    request: CustomRootfsRequest,
) -> Result<FirmwareSummary, KitError> {
    let source_path = request.source.clone();
    let destination = request.destination.clone();
    let (entry, replacement) = tokio::task::spawn_blocking(move || {
        let archive = FirmwareArchive::open(&request.source)?;
        let manifest = archive.build_manifest()?;
        let identity = manifest.select_identity(&request.board_config, request.behavior)?;
        let entry = identity.component_path("OS")?.to_owned();
        let source = archive.read_entry(&entry)?;
        let source = match request.key {
            Some(key) => decrypt_firmware_image(&source, &key)?,
            None => source,
        };
        let dmg = DmgImage::parse(source)?;
        let hfs_index = dmg
            .partitions()
            .iter()
            .position(|partition| partition.name().contains("Apple_HFS"))
            .ok_or(KitError::MissingHfsPartition)?;
        let mut mutations = Some(request.mutations);
        let mut partitions = Vec::with_capacity(dmg.partitions().len());
        for (index, partition) in dmg.partitions().iter().enumerate() {
            let mut data = dmg.extract(index)?;
            if index == hfs_index {
                let mut hfs = HfsImage::parse(data)?;
                apply_mutations(
                    &mut hfs,
                    mutations
                        .take()
                        .expect("selected HFS partition is processed once"),
                )?;
                data = hfs.into_bytes();
            }
            partitions.push(DmgPartitionInput::new(partition.name(), data));
        }
        Ok::<_, KitError>((entry, DmgImage::build(partitions)?.into_bytes()))
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    CustomIpswBuilder::new(FirmwareArchive::open(source_path)?)
        .replace(entry, replacement)?
        .build(&destination)
        .await?;
    FirmwareSummary::inspect(destination)
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use hfsplus::testutil::HfsPlusImageBuilder;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>7.1.2</string>
<key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n90ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>OS</key><dict><key>Info</key><dict><key>Path</key><string>rootfs.dmg</string></dict></dict></dict>
</dict></array></dict></plist>"#;

    #[tokio::test]
    async fn rebuilds_ipsw_with_edited_root_filesystem() {
        let mut hfs = HfsPlusImageBuilder::new();
        hfs.add_file("tool", b"payload", 0o644);
        let dmg = DmgImage::build(vec![DmgPartitionInput::new("Apple_HFS", hfs.build())])
            .unwrap()
            .into_bytes();
        let source = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(source.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(MANIFEST.as_bytes()).unwrap();
        writer
            .start_file("rootfs.dmg", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&dmg).unwrap();
        writer.finish().unwrap();
        let output_root = tempfile::tempdir().unwrap();
        let output = output_root.path().join("custom.ipsw");

        build_custom_rootfs(CustomRootfsRequest::new(
            source.path(),
            &output,
            BoardConfig::from("n90"),
            RestoreBehavior::Erase,
            vec![HfsMutation::Chmod {
                path: "/tool".into(),
                mode: 0o755,
            }],
        ))
        .await
        .unwrap();

        let rootfs = FirmwareArchive::open(&output)
            .unwrap()
            .read_entry("rootfs.dmg")
            .unwrap();
        let dmg = DmgImage::parse(rootfs).unwrap();
        let hfs = HfsImage::parse(dmg.extract(0).unwrap()).unwrap();
        assert_eq!(hfs.stat("/tool").unwrap().mode(), 0o100755);
    }
}
