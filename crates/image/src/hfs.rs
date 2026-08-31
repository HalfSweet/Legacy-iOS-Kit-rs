use std::io::Cursor;

use hfsplus::{
    EntryKind, HfsPlusError, HfsVolume, btree,
    volume::{ForkData, VOLUME_HEADER_OFFSET, VolumeHeader},
};
use thiserror::Error;

use crate::hfs_btree::{CatalogTree, record_body_offset};

const VOLUME_HEADER_SIZE: usize = 512;
const TOTAL_BLOCKS_OFFSET: usize = 44;
const FREE_BLOCKS_OFFSET: usize = 48;
const NEXT_ALLOCATION_OFFSET: usize = 52;
const ALLOCATION_FILE_OFFSET: usize = 112;
const NEXT_CATALOG_ID_OFFSET: usize = 64;

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
        let permissions = self.catalog_record_offset(path)? + 32;
        let mode_offset = permissions + 10;
        let current = read_u16(&self.data, mode_offset)?;
        write_u16(
            &mut self.data,
            mode_offset,
            (current & 0o170000) | (mode & 0o7777),
        )
    }

    pub fn chown(&mut self, path: &str, owner: u32, group: u32) -> Result<(), HfsError> {
        let permissions = self.catalog_record_offset(path)? + 32;
        write_u32(&mut self.data, permissions, owner)?;
        write_u32(&mut self.data, permissions + 4, group)
    }

    pub fn write_file(&mut self, path: &str, contents: &[u8]) -> Result<(), HfsError> {
        let record = self.catalog_record_offset(path)?;
        if read_u16(&self.data, record)? != 2 {
            return Err(HfsError::NotAFile);
        }
        let fork = record + 88;
        let header = self.volume()?.volume_header().clone();
        let block_size =
            usize::try_from(header.block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let total_blocks = usize::try_from(read_u32(&self.data, fork + 12)?)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let capacity = total_blocks
            .checked_mul(block_size)
            .ok_or(HfsError::CatalogOffsetTooLarge)?;
        if contents.len() > capacity {
            self.expand_file(fork, contents.len().div_ceil(block_size), &header)?;
            return self.write_file(path, contents);
        }

        let mut extents = Vec::new();
        for (start_block, block_count) in inline_extents(&self.data, fork, total_blocks)? {
            let extent_size = block_count
                .checked_mul(block_size)
                .ok_or(HfsError::CatalogOffsetTooLarge)?;
            let offset = start_block
                .checked_mul(block_size)
                .ok_or(HfsError::CatalogOffsetTooLarge)?;
            let end = offset
                .checked_add(extent_size)
                .ok_or(HfsError::CatalogOffsetTooLarge)?;
            if end > self.data.len() {
                return Err(HfsError::InvalidCatalogRecord);
            }
            extents.push((offset, end));
        }

        let mut source = contents;
        for (offset, end) in extents {
            let destination = &mut self.data[offset..end];
            let length = source.len().min(destination.len());
            destination[..length].copy_from_slice(&source[..length]);
            destination[length..].fill(0);
            source = &source[length..];
        }
        write_u64(&mut self.data, fork, contents.len() as u64)
    }

    pub fn grow(&mut self, new_size: usize) -> Result<(), HfsError> {
        let mut reader = Cursor::new(self.data.as_slice());
        let header = VolumeHeader::parse(&mut reader)?;
        let block_size =
            usize::try_from(header.block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let new_blocks = new_size / block_size;
        let old_blocks =
            usize::try_from(header.total_blocks).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        if new_blocks <= old_blocks {
            return Err(HfsError::CannotShrink);
        }
        let new_blocks_u32 = u32::try_from(new_blocks).map_err(|_| HfsError::VolumeTooLarge)?;
        let map_size = new_blocks.div_ceil(8);
        let old_map_size = usize::try_from(header.allocation_file.logical_size)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let map_logical_size = old_map_size.max(map_size);
        let map_capacity = usize::try_from(header.allocation_file.total_blocks)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?
            .checked_mul(block_size)
            .ok_or(HfsError::CatalogOffsetTooLarge)?;
        if map_logical_size > map_capacity {
            return Err(HfsError::AllocationMapCapacityExceeded {
                capacity: map_capacity,
                requested: map_logical_size,
            });
        }
        let alternate = new_blocks
            .checked_mul(block_size)
            .and_then(|offset| offset.checked_sub(VOLUME_HEADER_OFFSET as usize))
            .ok_or(HfsError::VolumeTooLarge)?;
        let alternate_end = alternate
            .checked_add(VOLUME_HEADER_SIZE)
            .ok_or(HfsError::VolumeTooLarge)?;
        if alternate_end > new_size {
            return Err(HfsError::VolumeTooLarge);
        }

        self.data.resize(new_size, 0);
        for index in old_map_size..map_size {
            let offset = fork_byte_offset(&header.allocation_file, block_size, index)?;
            self.data[offset] = 0;
        }
        set_allocation_block(
            &mut self.data,
            &header.allocation_file,
            block_size,
            old_blocks - 1,
            false,
        )?;
        set_allocation_block(
            &mut self.data,
            &header.allocation_file,
            block_size,
            new_blocks - 1,
            true,
        )?;

        let blocks_added =
            u32::try_from(new_blocks - old_blocks).map_err(|_| HfsError::VolumeTooLarge)?;
        let free_blocks = header
            .free_blocks
            .checked_add(blocks_added)
            .ok_or(HfsError::VolumeTooLarge)?;
        let primary = VOLUME_HEADER_OFFSET as usize;
        write_u32(
            &mut self.data,
            primary + TOTAL_BLOCKS_OFFSET,
            new_blocks_u32,
        )?;
        write_u32(&mut self.data, primary + FREE_BLOCKS_OFFSET, free_blocks)?;
        write_u64(
            &mut self.data,
            primary + ALLOCATION_FILE_OFFSET,
            map_logical_size as u64,
        )?;
        let volume_header = self.data[primary..primary + VOLUME_HEADER_SIZE].to_vec();
        self.data[alternate..alternate_end].copy_from_slice(&volume_header);
        Ok(())
    }

    pub fn remove_file(&mut self, path: &str) -> Result<(), HfsError> {
        let mut volume = self.volume()?;
        let stat = volume.stat(path)?;
        if stat.kind != EntryKind::File && stat.kind != EntryKind::Symlink {
            return Err(HfsError::NotAFile);
        }
        let header = volume.volume_header().clone();
        let mut tree = CatalogTree::read(&self.data)?;
        let mut file_index = None;
        let mut thread_index = None;
        let mut parent_id = None;
        let mut blocks = Vec::new();
        for (index, record) in tree.records().iter().enumerate() {
            let body = record_body_offset(record)?;
            let record_type = read_u16(record, body)?;
            let key_parent = read_u32(record, 2)?;
            if record_type == 2 && read_u32(record, body + 8)? == stat.cnid {
                file_index = Some(index);
                parent_id = Some(key_parent);
                blocks.extend(record_fork_blocks(record, body + 88)?);
                blocks.extend(record_fork_blocks(record, body + 168)?);
            } else if record_type == 4 && key_parent == stat.cnid {
                thread_index = Some(index);
            }
        }
        let file_index = file_index.ok_or(HfsError::CatalogRecordNotFound)?;
        let thread_index = thread_index.ok_or(HfsError::CatalogRecordNotFound)?;
        let parent_id = parent_id.ok_or(HfsError::CatalogRecordNotFound)?;
        let parent_index = tree
            .records()
            .iter()
            .position(|record| {
                let Ok(body) = record_body_offset(record) else {
                    return false;
                };
                matches!(read_u16(record, body), Ok(1))
                    && matches!(read_u32(record, body + 8), Ok(value) if value == parent_id)
            })
            .ok_or(HfsError::CatalogRecordNotFound)?;
        let block_size =
            usize::try_from(header.block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        for block in &blocks {
            if !allocation_block_used(&self.data, &header.allocation_file, block_size, *block)? {
                return Err(HfsError::InvalidCatalogRecord);
            }
        }

        let parent_body = record_body_offset(&tree.records()[parent_index])?;
        let valence = read_u32(&tree.records()[parent_index], parent_body + 4)?
            .checked_sub(1)
            .ok_or(HfsError::InvalidCatalogRecord)?;
        write_u32(
            &mut tree.records_mut()[parent_index],
            parent_body + 4,
            valence,
        )?;
        let mut removals = [file_index, thread_index];
        removals.sort_unstable_by(|left, right| right.cmp(left));
        for index in removals {
            tree.records_mut().remove(index);
        }

        let mut updated = self.data.clone();
        for block in &blocks {
            set_allocation_block(
                &mut updated,
                &header.allocation_file,
                block_size,
                *block,
                false,
            )?;
        }
        tree.write(&mut updated)?;
        let primary = VOLUME_HEADER_OFFSET as usize;
        write_u32(
            &mut updated,
            primary + 32,
            header
                .file_count
                .checked_sub(1)
                .ok_or(HfsError::InvalidCatalogRecord)?,
        )?;
        write_u32(
            &mut updated,
            primary + FREE_BLOCKS_OFFSET,
            header
                .free_blocks
                .checked_add(u32::try_from(blocks.len()).map_err(|_| HfsError::VolumeTooLarge)?)
                .ok_or(HfsError::VolumeTooLarge)?,
        )?;
        sync_alternate_header(
            &mut updated,
            usize::try_from(header.total_blocks).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
            block_size,
        )?;
        self.data = updated;
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), HfsError> {
        let (parent_path, name) = split_parent(path)?;
        let mut volume = self.volume()?;
        if volume.exists(path)? {
            return Err(HfsError::EntryExists);
        }
        let parent = volume.stat(&parent_path)?;
        if parent.kind != EntryKind::Directory {
            return Err(HfsError::NotADirectory);
        }
        let header = volume.volume_header().clone();
        let folder_id = header.next_catalog_id;
        let mut tree = CatalogTree::read(&self.data)?;
        let parent_index = tree
            .records()
            .iter()
            .position(|record| {
                let Ok(body) = record_body_offset(record) else {
                    return false;
                };
                matches!(read_u16(record, body), Ok(1))
                    && matches!(read_u32(record, body + 8), Ok(value) if value == parent.cnid)
            })
            .ok_or(HfsError::CatalogRecordNotFound)?;
        let parent_body = record_body_offset(&tree.records()[parent_index])?;
        let valence = read_u32(&tree.records()[parent_index], parent_body + 4)?
            .checked_add(1)
            .ok_or(HfsError::VolumeTooLarge)?;
        write_u32(
            &mut tree.records_mut()[parent_index],
            parent_body + 4,
            valence,
        )?;
        tree.insert(build_catalog_entry(
            parent.cnid,
            &name,
            &build_folder_record(folder_id, header.modify_date),
        ))?;
        tree.insert(build_catalog_entry(
            folder_id,
            "",
            &build_thread_record(3, parent.cnid, &name),
        ))?;

        let mut updated = self.data.clone();
        tree.write(&mut updated)?;
        let primary = VOLUME_HEADER_OFFSET as usize;
        write_u32(
            &mut updated,
            primary + 36,
            header
                .folder_count
                .checked_add(1)
                .ok_or(HfsError::VolumeTooLarge)?,
        )?;
        write_u32(
            &mut updated,
            primary + NEXT_CATALOG_ID_OFFSET,
            folder_id.checked_add(1).ok_or(HfsError::VolumeTooLarge)?,
        )?;
        sync_alternate_header(
            &mut updated,
            usize::try_from(header.total_blocks).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
            usize::try_from(header.block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
        )?;
        self.data = updated;
        Ok(())
    }

    fn expand_file(
        &mut self,
        fork: usize,
        required_blocks: usize,
        header: &VolumeHeader,
    ) -> Result<(), HfsError> {
        let current_blocks = usize::try_from(read_u32(&self.data, fork + 12)?)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let blocks_needed = required_blocks - current_blocks;
        if usize::try_from(header.free_blocks).map_err(|_| HfsError::CatalogOffsetTooLarge)?
            < blocks_needed
        {
            return Err(HfsError::VolumeFull);
        }
        let block_size =
            usize::try_from(header.block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let volume_blocks =
            usize::try_from(header.total_blocks).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let volume_size = volume_blocks
            .checked_mul(block_size)
            .ok_or(HfsError::VolumeTooLarge)?;
        if volume_size > self.data.len() {
            return Err(HfsError::InvalidCatalogRecord);
        }
        let mut blocks = Vec::with_capacity(blocks_needed);
        let mut candidate =
            usize::try_from(header.next_allocation).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        for _ in 0..volume_blocks {
            if candidate != volume_blocks - 1
                && !allocation_block_used(
                    &self.data,
                    &header.allocation_file,
                    block_size,
                    candidate,
                )?
            {
                blocks.push(candidate);
                if blocks.len() == blocks_needed {
                    break;
                }
            }
            candidate = (candidate + 1) % volume_blocks;
        }
        if blocks.len() != blocks_needed {
            return Err(HfsError::VolumeFull);
        }

        let mut extents = inline_extents(&self.data, fork, current_blocks)?;
        for block in &blocks {
            if let Some((start, count)) = extents.last_mut()
                && *start + *count == *block
            {
                *count += 1;
            } else {
                extents.push((*block, 1));
            }
        }
        if extents.len() > 8 {
            return Err(HfsError::ExtentsOverflowUnsupported);
        }

        for block in &blocks {
            set_allocation_block(
                &mut self.data,
                &header.allocation_file,
                block_size,
                *block,
                true,
            )?;
            let offset = block
                .checked_mul(block_size)
                .ok_or(HfsError::CatalogOffsetTooLarge)?;
            self.data[offset..offset + block_size].fill(0);
        }
        write_u32(
            &mut self.data,
            fork + 12,
            u32::try_from(required_blocks).map_err(|_| HfsError::VolumeTooLarge)?,
        )?;
        for index in 0..8 {
            let offset = fork + 16 + index * 8;
            let (start, count) = extents.get(index).copied().unwrap_or((0, 0));
            write_u32(
                &mut self.data,
                offset,
                u32::try_from(start).map_err(|_| HfsError::VolumeTooLarge)?,
            )?;
            write_u32(
                &mut self.data,
                offset + 4,
                u32::try_from(count).map_err(|_| HfsError::VolumeTooLarge)?,
            )?;
        }

        let primary = VOLUME_HEADER_OFFSET as usize;
        write_u32(
            &mut self.data,
            primary + FREE_BLOCKS_OFFSET,
            header.free_blocks
                - u32::try_from(blocks_needed).map_err(|_| HfsError::VolumeTooLarge)?,
        )?;
        write_u32(
            &mut self.data,
            primary + NEXT_ALLOCATION_OFFSET,
            u32::try_from((blocks[blocks.len() - 1] + 1) % volume_blocks)
                .map_err(|_| HfsError::VolumeTooLarge)?,
        )?;
        let alternate = volume_blocks
            .checked_mul(block_size)
            .and_then(|offset| offset.checked_sub(VOLUME_HEADER_OFFSET as usize))
            .ok_or(HfsError::VolumeTooLarge)?;
        let volume_header = self.data[primary..primary + VOLUME_HEADER_SIZE].to_vec();
        self.data[alternate..alternate + VOLUME_HEADER_SIZE].copy_from_slice(&volume_header);
        Ok(())
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

    fn catalog_record_offset(&self, path: &str) -> Result<usize, HfsError> {
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
                        .and_then(|offset| offset.checked_add(body))
                        .ok_or(HfsError::CatalogOffsetTooLarge);
                }
            }
            node_number = node.descriptor.forward_link;
        }
        Err(HfsError::CatalogRecordNotFound)
    }
}

fn record_fork_blocks(record: &[u8], fork: usize) -> Result<Vec<usize>, HfsError> {
    let total_blocks = usize::try_from(read_u32(record, fork + 12)?)
        .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
    let mut blocks = Vec::with_capacity(total_blocks);
    for (start, count) in inline_extents(record, fork, total_blocks)? {
        blocks.extend(start..start + count);
    }
    Ok(blocks)
}

fn split_parent(path: &str) -> Result<(String, String), HfsError> {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return Err(HfsError::InvalidPath);
    }
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() {
        return Err(HfsError::InvalidPath);
    }
    let parent = if parent.is_empty() {
        "/".to_owned()
    } else {
        format!("/{parent}")
    };
    Ok((parent, name.to_owned()))
}

fn build_catalog_entry(parent_id: u32, name: &str, body: &[u8]) -> Vec<u8> {
    let name = name.encode_utf16().collect::<Vec<_>>();
    let key_length = 6 + name.len() * 2;
    let mut record = Vec::with_capacity(2 + key_length + body.len());
    record.extend_from_slice(&(key_length as u16).to_be_bytes());
    record.extend_from_slice(&parent_id.to_be_bytes());
    record.extend_from_slice(&(name.len() as u16).to_be_bytes());
    for unit in name {
        record.extend_from_slice(&unit.to_be_bytes());
    }
    if !record.len().is_multiple_of(2) {
        record.push(0);
    }
    record.extend_from_slice(body);
    record
}

fn build_folder_record(folder_id: u32, timestamp: u32) -> Vec<u8> {
    let mut record = Vec::with_capacity(84);
    record.extend_from_slice(&1_u16.to_be_bytes());
    record.extend_from_slice(&0_u16.to_be_bytes());
    record.extend_from_slice(&0_u32.to_be_bytes());
    record.extend_from_slice(&folder_id.to_be_bytes());
    for _ in 0..5 {
        record.extend_from_slice(&timestamp.to_be_bytes());
    }
    record.extend_from_slice(&0_u32.to_be_bytes());
    record.extend_from_slice(&0_u32.to_be_bytes());
    record.extend_from_slice(&[0, 0]);
    record.extend_from_slice(&0o040755_u16.to_be_bytes());
    record.extend_from_slice(&0_u32.to_be_bytes());
    record.extend_from_slice(&[0; 32]);
    record.extend_from_slice(&0_u32.to_be_bytes());
    record
}

fn build_thread_record(record_type: u16, parent_id: u32, name: &str) -> Vec<u8> {
    let name = name.encode_utf16().collect::<Vec<_>>();
    let mut record = Vec::with_capacity(10 + name.len() * 2);
    record.extend_from_slice(&record_type.to_be_bytes());
    record.extend_from_slice(&0_u16.to_be_bytes());
    record.extend_from_slice(&parent_id.to_be_bytes());
    record.extend_from_slice(&(name.len() as u16).to_be_bytes());
    for unit in name {
        record.extend_from_slice(&unit.to_be_bytes());
    }
    record
}

fn sync_alternate_header(
    data: &mut [u8],
    total_blocks: usize,
    block_size: usize,
) -> Result<(), HfsError> {
    let primary = VOLUME_HEADER_OFFSET as usize;
    let alternate = total_blocks
        .checked_mul(block_size)
        .and_then(|offset| offset.checked_sub(VOLUME_HEADER_OFFSET as usize))
        .ok_or(HfsError::VolumeTooLarge)?;
    let alternate_end = alternate
        .checked_add(VOLUME_HEADER_SIZE)
        .ok_or(HfsError::VolumeTooLarge)?;
    if alternate_end > data.len() {
        return Err(HfsError::InvalidCatalogRecord);
    }
    let header = data[primary..primary + VOLUME_HEADER_SIZE].to_vec();
    data[alternate..alternate_end].copy_from_slice(&header);
    Ok(())
}

fn inline_extents(
    data: &[u8],
    fork: usize,
    total_blocks: usize,
) -> Result<Vec<(usize, usize)>, HfsError> {
    let mut extents = Vec::new();
    let mut described_blocks = 0_usize;
    for index in 0..8 {
        let offset = fork + 16 + index * 8;
        let start = usize::try_from(read_u32(data, offset)?)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        let count = usize::try_from(read_u32(data, offset + 4)?)
            .map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        if count == 0 {
            break;
        }
        described_blocks = described_blocks
            .checked_add(count)
            .ok_or(HfsError::InvalidCatalogRecord)?;
        if described_blocks > total_blocks {
            return Err(HfsError::InvalidCatalogRecord);
        }
        extents.push((start, count));
    }
    if described_blocks != total_blocks {
        return Err(HfsError::ExtentsOverflowUnsupported);
    }
    Ok(extents)
}

fn fork_byte_offset(
    fork: &ForkData,
    block_size: usize,
    logical_offset: usize,
) -> Result<usize, HfsError> {
    let offset = btree::compute_fork_offset(
        fork,
        u32::try_from(block_size).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
        u64::try_from(logical_offset).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
    )?;
    usize::try_from(offset).map_err(|_| HfsError::CatalogOffsetTooLarge)
}

fn set_allocation_block(
    data: &mut [u8],
    fork: &ForkData,
    block_size: usize,
    block: usize,
    used: bool,
) -> Result<(), HfsError> {
    let offset = fork_byte_offset(fork, block_size, block / 8)?;
    let byte = data.get_mut(offset).ok_or(HfsError::InvalidCatalogRecord)?;
    let mask = 1 << (7 - block % 8);
    if used {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
    Ok(())
}

fn allocation_block_used(
    data: &[u8],
    fork: &ForkData,
    block_size: usize,
    block: usize,
) -> Result<bool, HfsError> {
    let offset = fork_byte_offset(fork, block_size, block / 8)?;
    let byte = *data.get(offset).ok_or(HfsError::InvalidCatalogRecord)?;
    Ok(byte & (1 << (7 - block % 8)) != 0)
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

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), HfsError> {
    data.get_mut(offset..offset + 8)
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
    #[error("HFS+ entry is not a file")]
    NotAFile,
    #[error("HFS+ extents overflow updates are not implemented")]
    ExtentsOverflowUnsupported,
    #[error("HFS+ volume has insufficient free blocks")]
    VolumeFull,
    #[error("HFS+ volumes cannot be shrunk")]
    CannotShrink,
    #[error("HFS+ volume is too large")]
    VolumeTooLarge,
    #[error("HFS+ allocation map requires {requested} bytes but holds {capacity} bytes")]
    AllocationMapCapacityExceeded { capacity: usize, requested: usize },
    #[error("HFS+ catalog B-tree requires {requested} nodes but holds {capacity}")]
    CatalogTreeCapacityExceeded { capacity: u32, requested: u32 },
    #[error("HFS+ catalog map is too small")]
    CatalogMapCapacityExceeded,
    #[error("HFS+ catalog record of {0} bytes does not fit in a node")]
    CatalogRecordTooLarge(usize),
    #[error("HFS+ entry already exists")]
    EntryExists,
    #[error("HFS+ path is invalid")]
    InvalidPath,
    #[error("HFS+ parent is not a directory")]
    NotADirectory,
}

#[cfg(test)]
mod tests {
    use hfsplus::testutil::HfsPlusImageBuilder;

    use super::*;

    fn growable_image() -> HfsImage {
        const BLOCK_SIZE: usize = 4096;
        let mut builder = HfsPlusImageBuilder::new();
        builder.add_file("payload", b"data", 0o644);
        let mut data = builder.build();
        data.resize(8 * BLOCK_SIZE, 0);
        let primary = VOLUME_HEADER_OFFSET as usize;
        write_u32(&mut data, primary + TOTAL_BLOCKS_OFFSET, 8).unwrap();
        write_u32(&mut data, primary + FREE_BLOCKS_OFFSET, 1).unwrap();
        write_u64(&mut data, primary + ALLOCATION_FILE_OFFSET, 1).unwrap();
        write_u32(&mut data, primary + ALLOCATION_FILE_OFFSET + 12, 1).unwrap();
        write_u32(&mut data, primary + ALLOCATION_FILE_OFFSET + 16, 6).unwrap();
        write_u32(&mut data, primary + ALLOCATION_FILE_OFFSET + 20, 1).unwrap();
        data[6 * BLOCK_SIZE] = 0xfb;
        let alternate = 8 * BLOCK_SIZE - VOLUME_HEADER_OFFSET as usize;
        let volume_header = data[primary..primary + VOLUME_HEADER_SIZE].to_vec();
        data[alternate..alternate + VOLUME_HEADER_SIZE].copy_from_slice(&volume_header);
        HfsImage::parse(data).unwrap()
    }

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

    #[test]
    fn replaces_file_within_existing_extents() {
        let mut builder = HfsPlusImageBuilder::new();
        builder.add_file("payload", b"old", 0o644);
        let mut image = HfsImage::parse(builder.build()).unwrap();
        let replacement = vec![0xa5; 3000];

        image.write_file("/payload", &replacement).unwrap();

        assert_eq!(image.stat("/payload").unwrap().size(), 3000);
        assert_eq!(image.read("/payload").unwrap(), replacement);
    }

    #[test]
    fn grows_volume_headers_and_allocation_map() {
        const BLOCK_SIZE: usize = 4096;
        let mut image = growable_image();
        let primary = VOLUME_HEADER_OFFSET as usize;

        image.grow(12 * BLOCK_SIZE).unwrap();

        let header = image.volume().unwrap().volume_header().clone();
        assert_eq!(header.total_blocks, 12);
        assert_eq!(header.free_blocks, 5);
        assert_eq!(header.allocation_file.logical_size, 2);
        assert_eq!(image.data()[6 * BLOCK_SIZE], 0xfa);
        assert_eq!(image.data()[6 * BLOCK_SIZE + 1], 0x10);
        assert_eq!(image.read("/payload").unwrap(), b"data");
        assert_eq!(
            &image.data()[12 * BLOCK_SIZE - VOLUME_HEADER_OFFSET as usize
                ..12 * BLOCK_SIZE - VOLUME_HEADER_OFFSET as usize + VOLUME_HEADER_SIZE],
            &image.data()[primary..primary + VOLUME_HEADER_SIZE]
        );
    }

    #[test]
    fn expands_file_into_free_allocation_blocks() {
        const BLOCK_SIZE: usize = 4096;
        let mut image = growable_image();
        let replacement = vec![0x6d; 5000];

        image.write_file("/payload", &replacement).unwrap();

        assert_eq!(image.read("/payload").unwrap(), replacement);
        assert_eq!(image.volume().unwrap().volume_header().free_blocks, 0);
        assert_eq!(image.data()[6 * BLOCK_SIZE], 0xff);
    }

    #[test]
    fn removes_file_and_releases_its_blocks() {
        const BLOCK_SIZE: usize = 4096;
        let mut image = growable_image();

        image.remove_file("/payload").unwrap();

        assert!(
            image
                .volume()
                .unwrap()
                .list_directory("/")
                .unwrap()
                .is_empty()
        );
        let header = image.volume().unwrap().volume_header().clone();
        assert_eq!(header.file_count, 0);
        assert_eq!(header.free_blocks, 2);
        assert_eq!(image.data()[6 * BLOCK_SIZE], 0xf3);
    }

    #[test]
    fn creates_directory_catalog_records() {
        let mut image = growable_image();

        image.mkdir("/newdir").unwrap();

        let mut volume = image.volume().unwrap();
        let entry = volume
            .list_directory("/")
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "newdir")
            .unwrap();
        assert_eq!(entry.kind, EntryKind::Directory);
        assert_eq!(volume.stat("/newdir").unwrap().permissions.mode, 0o040755);
        assert_eq!(volume.volume_header().folder_count, 2);
        assert_eq!(volume.volume_header().next_catalog_id, 18);
    }
}
