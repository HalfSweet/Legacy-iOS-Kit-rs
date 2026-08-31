use std::io::Cursor;

use hfsplus::{EntryKind, HfsPlusError, HfsVolume, btree, volume::VolumeHeader};
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
            cnid: stat.cnid,
            kind: stat.kind.into(),
            size: stat.size,
            owner: stat.permissions.owner_id,
            group: stat.permissions.group_id,
            mode: stat.permissions.mode,
        })
    }

    pub fn chmod(&mut self, path: &str, mode: u16) -> Result<(), HfsError> {
        let permissions = self.catalog_permissions_offset(path)?;
        let mode_offset = permissions + 10;
        let current = read_u16(&self.data, mode_offset)?;
        write_u16(
            &mut self.data,
            mode_offset,
            (current & 0o170000) | (mode & 0o7777),
        )
    }

    pub fn chown(&mut self, path: &str, owner: u32, group: u32) -> Result<(), HfsError> {
        let permissions = self.catalog_permissions_offset(path)?;
        write_u32(&mut self.data, permissions, owner)?;
        write_u32(&mut self.data, permissions + 4, group)
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

    fn catalog_permissions_offset(&self, path: &str) -> Result<usize, HfsError> {
        let mut volume = self.volume()?;
        let cnid = volume.stat(path)?.cnid;
        let mut reader = Cursor::new(self.data.as_slice());
        let header = VolumeHeader::parse(&mut reader)?;
        let tree = btree::read_btree_header(&mut reader, &header.catalog_file, header.block_size)?;
        let mut node_number = tree.first_leaf_node;
        while node_number != 0 {
            let node = btree::read_node(&mut reader, &tree, node_number)?;
            for index in 0..usize::from(node.descriptor.num_records) {
                let record = node.record_data(index)?;
                let body = catalog_body_offset(record)?;
                let record_type = read_u16(record, body)?;
                if matches!(record_type, 1 | 2) && read_u32(record, body + 8)? == cnid {
                    let node_offset = btree::compute_fork_offset(
                        &tree.fork,
                        tree.block_size,
                        u64::from(node_number) * u64::from(tree.node_size),
                    )?;
                    let node_offset = usize::try_from(node_offset)
                        .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
                    return node_offset
                        .checked_add(usize::from(node.record_offsets[index]))
                        .and_then(|offset| offset.checked_add(body + 32))
                        .ok_or(HfsError::CatalogOffsetTooLarge);
                }
            }
            node_number = node.descriptor.forward_link;
        }
        Err(HfsError::CatalogRecordNotFound)
    }
}

fn catalog_body_offset(record: &[u8]) -> Result<usize, HfsError> {
    let length = usize::from(read_u16(record, 0)?)
        .checked_add(2)
        .ok_or(HfsError::InvalidCatalogRecord)?;
    let aligned = length + (length & 1);
    if aligned >= record.len() {
        return Err(HfsError::InvalidCatalogRecord);
    }
    Ok(aligned)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, HfsError> {
    data.get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(HfsError::InvalidCatalogRecord)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, HfsError> {
    data.get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(HfsError::InvalidCatalogRecord)
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), HfsError> {
    data.get_mut(offset..offset + 2)
        .ok_or(HfsError::InvalidCatalogRecord)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), HfsError> {
    data.get_mut(offset..offset + 4)
        .ok_or(HfsError::InvalidCatalogRecord)?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
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
    cnid: u32,
    kind: HfsEntryKind,
    size: u64,
    owner: u32,
    group: u32,
    mode: u16,
}

impl HfsStat {
    pub const fn cnid(&self) -> u32 {
        self.cnid
    }

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
    #[error("HFS+ catalog record is invalid")]
    InvalidCatalogRecord,
    #[error("HFS+ catalog record was not found")]
    CatalogRecordNotFound,
    #[error("HFS+ catalog offset is too large for this host")]
    CatalogOffsetTooLarge,
}

#[cfg(test)]
mod tests {
    use hfsplus::testutil::HfsPlusImageBuilder;

    use super::*;

    #[test]
    fn updates_catalog_permissions_in_place() {
        let mut builder = HfsPlusImageBuilder::new();
        builder.add_file("tool", b"payload", 0o644);
        let mut image = HfsImage::parse(builder.build()).unwrap();

        image.chmod("/tool", 0o755).unwrap();
        image.chown("/tool", 501, 20).unwrap();

        let stat = image.stat("/tool").unwrap();
        assert_eq!(stat.mode(), 0o100755);
        assert_eq!(stat.owner(), 501);
        assert_eq!(stat.group(), 20);
    }
}
