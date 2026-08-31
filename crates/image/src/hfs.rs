use std::io::Cursor;

use hfsplus::{EntryKind, HfsPlusError, HfsVolume};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HfsImage {
    data: Vec<u8>,
}

impl HfsImage {
    pub fn parse(data: Vec<u8>) -> Result<Self, HfsError> {
        HfsVolume::open(Cursor::new(&data))?;
        Ok(Self { data })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn list(&self, path: &str) -> Result<Vec<HfsEntry>, HfsError> {
        Ok(self
            .volume()?
            .list_directory(path)?
            .into_iter()
            .map(|entry| HfsEntry {
                name: entry.name,
                kind: entry.kind.into(),
                size: entry.size,
            })
            .collect())
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>, HfsError> {
        Ok(self.volume()?.read_file(path)?)
    }

    pub fn stat(&self, path: &str) -> Result<HfsStat, HfsError> {
        let stat = self.volume()?.stat(path)?;
        Ok(HfsStat {
            kind: stat.kind.into(),
            size: stat.size,
            owner: stat.permissions.owner_id,
            group: stat.permissions.group_id,
            mode: stat.permissions.mode,
        })
    }

    pub fn walk(&self) -> Result<Vec<HfsEntry>, HfsError> {
        Ok(self
            .volume()?
            .walk()?
            .into_iter()
            .map(|entry| HfsEntry {
                name: entry.path,
                kind: entry.entry.kind.into(),
                size: entry.entry.size,
            })
            .collect())
    }

    fn volume(&self) -> Result<HfsVolume<Cursor<&[u8]>>, HfsError> {
        Ok(HfsVolume::open(Cursor::new(self.data.as_slice()))?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HfsEntry {
    name: String,
    kind: HfsEntryKind,
    size: u64,
}

impl HfsEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> HfsEntryKind {
        self.kind
    }

    pub const fn size(&self) -> u64 {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HfsEntryKind {
    File,
    Directory,
    Symlink,
}

impl From<EntryKind> for HfsEntryKind {
    fn from(value: EntryKind) -> Self {
        match value {
            EntryKind::File => Self::File,
            EntryKind::Directory => Self::Directory,
            EntryKind::Symlink => Self::Symlink,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfsStat {
    kind: HfsEntryKind,
    size: u64,
    owner: u32,
    group: u32,
    mode: u16,
}

impl HfsStat {
    pub const fn kind(&self) -> HfsEntryKind {
        self.kind
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn owner(&self) -> u32 {
        self.owner
    }

    pub const fn group(&self) -> u32 {
        self.group
    }

    pub const fn mode(&self) -> u16 {
        self.mode
    }
}

#[derive(Debug, Error)]
pub enum HfsError {
    #[error("HFS+ operation failed: {0}")]
    Hfs(#[from] HfsPlusError),
}
