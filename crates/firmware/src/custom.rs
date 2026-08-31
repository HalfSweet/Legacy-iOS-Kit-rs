use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    path::{Component, Path, PathBuf},
};

use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::FirmwareArchive;

#[derive(Clone, Debug)]
pub struct CustomIpswBuilder {
    source: FirmwareArchive,
    replacements: BTreeMap<String, Vec<u8>>,
    removals: BTreeSet<String>,
}

impl CustomIpswBuilder {
    pub fn new(source: FirmwareArchive) -> Self {
        Self {
            source,
            replacements: BTreeMap::new(),
            removals: BTreeSet::new(),
        }
    }

    pub fn replace(
        mut self,
        name: impl Into<String>,
        data: Vec<u8>,
    ) -> Result<Self, CustomIpswError> {
        let name = name.into();
        validate_name(&name)?;
        self.removals.remove(&name);
        self.replacements.insert(name, data);
        Ok(self)
    }

    pub fn remove(mut self, name: impl Into<String>) -> Result<Self, CustomIpswError> {
        let name = name.into();
        validate_name(&name)?;
        self.replacements.remove(&name);
        self.removals.insert(name);
        Ok(self)
    }

    pub async fn build(
        self,
        destination: impl Into<PathBuf>,
    ) -> Result<FirmwareArchive, CustomIpswError> {
        let destination = destination.into();
        let built_destination = destination.clone();
        tokio::task::spawn_blocking(move || self.build_sync(&built_destination))
            .await
            .map_err(|error| CustomIpswError::Task(error.to_string()))??;
        Ok(FirmwareArchive::open(destination)?)
    }

    fn build_sync(self, destination: &Path) -> Result<(), CustomIpswError> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temporary = tempfile::Builder::new()
            .prefix("custom-ipsw-")
            .tempfile_in(parent)?;
        let mut source = ZipArchive::new(File::open(self.source.path())?)?;
        let mut writer = ZipWriter::new(temporary.reopen()?);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        let mut replacements = self.replacements;

        for index in 0..source.len() {
            let entry = source.by_index(index)?;
            let name = entry.name().to_owned();
            if self.removals.contains(&name) {
                continue;
            }
            if let Some(data) = replacements.remove(&name) {
                writer.start_file(name, options)?;
                writer.write_all(&data)?;
            } else {
                writer.raw_copy_file(entry)?;
            }
        }
        for (name, data) in replacements {
            writer.start_file(name, options)?;
            writer.write_all(&data)?;
        }
        writer.finish()?.sync_all()?;
        temporary
            .into_temp_path()
            .persist(destination)
            .map_err(|error| error.error)?;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), CustomIpswError> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CustomIpswError::UnsafeName(name.to_owned()));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum CustomIpswError {
    #[error("unsafe custom IPSW entry name: {0}")]
    UnsafeName(String),
    #[error("custom IPSW I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("custom IPSW ZIP failed: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("custom IPSW worker task failed: {0}")]
    Task(String),
    #[error(transparent)]
    Firmware(#[from] crate::FirmwareError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replaces_and_removes_entries() {
        let source_file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(source_file.reopen().unwrap());
        writer
            .start_file("keep.bin", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"old").unwrap();
        writer
            .start_file("remove.bin", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"remove").unwrap();
        writer.finish().unwrap();
        let destination_root = tempfile::tempdir().unwrap();
        let destination = destination_root.path().join("custom.ipsw");

        let archive = CustomIpswBuilder::new(FirmwareArchive::open(source_file.path()).unwrap())
            .replace("keep.bin", b"new".to_vec())
            .unwrap()
            .remove("remove.bin")
            .unwrap()
            .build(&destination)
            .await
            .unwrap();

        assert_eq!(archive.read_entry("keep.bin").unwrap(), b"new");
        assert!(archive.read_entry("remove.bin").is_err());
    }
}
