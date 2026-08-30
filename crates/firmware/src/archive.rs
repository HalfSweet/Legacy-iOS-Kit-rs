use std::{
    collections::HashSet,
    fs::File,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use zip::ZipArchive;

use crate::{BuildManifest, FirmwareError};

const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXPANDED_SIZE: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirmwareArchive {
    path: PathBuf,
}

impl FirmwareArchive {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, FirmwareError> {
        let path = path.into();
        let mut archive = ZipArchive::new(File::open(&path)?)?;
        validate_archive(&mut archive)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn build_manifest(&self) -> Result<BuildManifest, FirmwareError> {
        let data = self.read_entry_with_limit("BuildManifest.plist", MAX_MANIFEST_SIZE)?;
        BuildManifest::from_reader(Cursor::new(data))
    }

    pub fn read_entry(&self, name: &str) -> Result<Vec<u8>, FirmwareError> {
        self.read_entry_with_limit(name, u64::MAX)
    }

    pub fn read_entry_with_limit(
        &self,
        name: &str,
        maximum_size: u64,
    ) -> Result<Vec<u8>, FirmwareError> {
        let mut archive = ZipArchive::new(File::open(&self.path)?)?;
        let mut entry = archive.by_name(name).map_err(|error| match error {
            zip::result::ZipError::FileNotFound => {
                FirmwareError::ArchiveEntryNotFound(name.to_owned())
            }
            error => FirmwareError::Zip(error),
        })?;
        if entry.size() > maximum_size {
            return Err(FirmwareError::ArchiveEntryTooLarge {
                name: name.to_owned(),
                size: entry.size(),
                maximum: maximum_size,
            });
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;
        Ok(data)
    }
}

fn validate_archive(archive: &mut ZipArchive<File>) -> Result<(), FirmwareError> {
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(FirmwareError::TooManyArchiveEntries(archive.len()));
    }
    let mut names = HashSet::with_capacity(archive.len());
    let mut expanded_size = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.enclosed_name().is_none() {
            return Err(FirmwareError::UnsafeArchivePath(entry.name().to_owned()));
        }
        if !names.insert(entry.name().to_owned()) {
            return Err(FirmwareError::DuplicateArchiveEntry(
                entry.name().to_owned(),
            ));
        }
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or(FirmwareError::ArchiveExpandedTooLarge)?;
        if expanded_size > MAX_EXPANDED_SIZE {
            return Err(FirmwareError::ArchiveExpandedTooLarge);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn reads_named_archive_entries() {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Firmware/test.bin", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"firmware").unwrap();
        writer.finish().unwrap();

        let archive = FirmwareArchive::open(file.path()).unwrap();
        assert_eq!(
            archive.read_entry("Firmware/test.bin").unwrap(),
            b"firmware"
        );
    }

    #[test]
    fn rejects_parent_directory_entries() {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("../BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"malicious").unwrap();
        writer.finish().unwrap();

        assert!(matches!(
            FirmwareArchive::open(file.path()),
            Err(FirmwareError::UnsafeArchivePath(path)) if path == "../BuildManifest.plist"
        ));
    }
}
