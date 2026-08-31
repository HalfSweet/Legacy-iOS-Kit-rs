use std::io::Cursor;

use hfsplus::{btree, volume::VolumeHeader};

use crate::HfsError;

pub(crate) struct CatalogTree {
    volume: VolumeHeader,
    header: btree::BTreeHeaderRecord,
    header_node: btree::BTreeNode,
    records: Vec<Vec<u8>>,
}

impl CatalogTree {
    pub(crate) fn read(data: &[u8]) -> Result<Self, HfsError> {
        let mut reader = Cursor::new(data);
        let volume = VolumeHeader::parse(&mut reader)?;
        let header =
            btree::read_btree_header(&mut reader, &volume.catalog_file, volume.block_size)?;
        let header_node = btree::read_node(&mut reader, &header, 0)?;
        let mut records = Vec::with_capacity(header.leaf_records as usize);
        let mut node_number = header.first_leaf_node;
        let mut visited = 0_u32;
        while node_number != 0 {
            if visited >= header.total_nodes {
                return Err(HfsError::InvalidCatalogRecord);
            }
            let node = btree::read_node(&mut reader, &header, node_number)?;
            if node.descriptor.kind != btree::NODE_KIND_LEAF {
                return Err(HfsError::InvalidCatalogRecord);
            }
            for index in 0..usize::from(node.descriptor.num_records) {
                records.push(node.record_data(index)?.to_vec());
            }
            node_number = node.descriptor.forward_link;
            visited += 1;
        }
        if records.len() != header.leaf_records as usize {
            return Err(HfsError::InvalidCatalogRecord);
        }
        Ok(Self {
            volume,
            header,
            header_node,
            records,
        })
    }

    pub(crate) fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    pub(crate) fn records_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.records
    }

    pub(crate) fn write(self, data: &mut [u8]) -> Result<(), HfsError> {
        let node_size = usize::from(self.header.node_size);
        let leaf_groups = pack_records(&self.records, node_size)?;
        let mut next_number = 1_u32;
        let mut nodes = Vec::new();
        let mut level = Vec::new();
        for records in leaf_groups {
            let number = next_number;
            next_number += 1;
            let first_key = record_key(records[0])?.to_vec();
            level.push(NodeReference {
                number,
                first_key,
                height: 1,
            });
            nodes.push(NodeContents {
                number,
                kind: btree::NODE_KIND_LEAF,
                height: 1,
                records: records.iter().map(|record| (*record).clone()).collect(),
                forward: 0,
                backward: 0,
            });
        }
        let first_leaf = level[0].number;
        let last_leaf = level[level.len() - 1].number;

        while level.len() > 1 {
            let index_records = level
                .iter()
                .map(index_record)
                .collect::<Result<Vec<_>, _>>()?;
            let groups = pack_records(&index_records, node_size)?;
            let mut parent_level = Vec::new();
            for records in groups {
                let number = next_number;
                next_number += 1;
                let first_key = record_key(records[0])?.to_vec();
                let height = level[0].height + 1;
                parent_level.push(NodeReference {
                    number,
                    first_key,
                    height,
                });
                nodes.push(NodeContents {
                    number,
                    kind: btree::NODE_KIND_INDEX,
                    height,
                    records: records.iter().map(|record| (*record).clone()).collect(),
                    forward: 0,
                    backward: 0,
                });
            }
            level = parent_level;
        }

        if next_number > self.header.total_nodes {
            return Err(HfsError::CatalogTreeCapacityExceeded {
                capacity: self.header.total_nodes,
                requested: next_number,
            });
        }
        for same_level in 1..=level[0].height {
            let positions = nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.height == same_level)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            for (position, index) in positions.iter().enumerate() {
                nodes[*index].backward = position
                    .checked_sub(1)
                    .map(|previous| nodes[positions[previous]].number)
                    .unwrap_or(0);
                nodes[*index].forward = positions
                    .get(position + 1)
                    .map(|next| nodes[*next].number)
                    .unwrap_or(0);
            }
        }

        let mut header_node = self.header_node.data;
        write_u16(&mut header_node, 14, u16::from(level[0].height))?;
        write_u32(&mut header_node, 16, level[0].number)?;
        write_u32(
            &mut header_node,
            20,
            u32::try_from(self.records.len()).map_err(|_| HfsError::CatalogOffsetTooLarge)?,
        )?;
        write_u32(&mut header_node, 24, first_leaf)?;
        write_u32(&mut header_node, 28, last_leaf)?;
        write_u32(&mut header_node, 40, self.header.total_nodes - next_number)?;
        update_map(
            &mut header_node,
            &self.header_node.record_offsets,
            next_number,
        )?;

        for number in 1..self.header.total_nodes {
            let offset = node_offset(&self.volume, &self.header, number)?;
            data.get_mut(offset..offset + node_size)
                .ok_or(HfsError::InvalidCatalogRecord)?
                .fill(0);
        }
        let header_offset = node_offset(&self.volume, &self.header, 0)?;
        data.get_mut(header_offset..header_offset + node_size)
            .ok_or(HfsError::InvalidCatalogRecord)?
            .copy_from_slice(&header_node);
        for node in nodes {
            let offset = node_offset(&self.volume, &self.header, node.number)?;
            let encoded = node.encode(node_size)?;
            data.get_mut(offset..offset + node_size)
                .ok_or(HfsError::InvalidCatalogRecord)?
                .copy_from_slice(&encoded);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct NodeReference {
    number: u32,
    first_key: Vec<u8>,
    height: u8,
}

struct NodeContents {
    number: u32,
    kind: u8,
    height: u8,
    records: Vec<Vec<u8>>,
    forward: u32,
    backward: u32,
}

impl NodeContents {
    fn encode(self, node_size: usize) -> Result<Vec<u8>, HfsError> {
        let mut node = vec![0; node_size];
        write_u32(&mut node, 0, self.forward)?;
        write_u32(&mut node, 4, self.backward)?;
        node[8] = self.kind;
        node[9] = self.height;
        write_u16(
            &mut node,
            10,
            u16::try_from(self.records.len()).map_err(|_| HfsError::InvalidCatalogRecord)?,
        )?;
        let mut offsets = Vec::with_capacity(self.records.len() + 1);
        let mut cursor = 14;
        for record in self.records {
            offsets.push(cursor);
            let end = cursor + record.len();
            node[cursor..end].copy_from_slice(&record);
            cursor = end;
        }
        offsets.push(cursor);
        for (index, offset) in offsets.into_iter().enumerate() {
            write_u16(
                &mut node,
                node_size - (index + 1) * 2,
                u16::try_from(offset).map_err(|_| HfsError::InvalidCatalogRecord)?,
            )?;
        }
        Ok(node)
    }
}

fn pack_records(records: &[Vec<u8>], node_size: usize) -> Result<Vec<Vec<&Vec<u8>>>, HfsError> {
    if records.is_empty() {
        return Err(HfsError::InvalidCatalogRecord);
    }
    let mut groups = vec![Vec::new()];
    let mut used = 16_usize;
    for record in records {
        let needed = record.len() + 2;
        if used + needed > node_size {
            if groups.last().is_some_and(Vec::is_empty) {
                return Err(HfsError::CatalogRecordTooLarge(record.len()));
            }
            groups.push(Vec::new());
            used = 16;
            if used + needed > node_size {
                return Err(HfsError::CatalogRecordTooLarge(record.len()));
            }
        }
        groups.last_mut().expect("record group exists").push(record);
        used += needed;
    }
    Ok(groups)
}

fn index_record(child: &NodeReference) -> Result<Vec<u8>, HfsError> {
    let mut record = child.first_key.clone();
    record.extend_from_slice(&child.number.to_be_bytes());
    Ok(record)
}

pub(crate) fn record_key(record: &[u8]) -> Result<&[u8], HfsError> {
    let length = usize::from(read_u16(record, 0)?) + 2;
    record.get(..length).ok_or(HfsError::InvalidCatalogRecord)
}

pub(crate) fn record_body_offset(record: &[u8]) -> Result<usize, HfsError> {
    let length = record_key(record)?.len();
    Ok(length + (length & 1))
}

fn node_offset(
    volume: &VolumeHeader,
    header: &btree::BTreeHeaderRecord,
    number: u32,
) -> Result<usize, HfsError> {
    let offset = btree::compute_fork_offset(
        &volume.catalog_file,
        volume.block_size,
        u64::from(number) * u64::from(header.node_size),
    )?;
    usize::try_from(offset).map_err(|_| HfsError::CatalogOffsetTooLarge)
}

fn update_map(header: &mut [u8], offsets: &[u16], used_nodes: u32) -> Result<(), HfsError> {
    if offsets.len() < 4 {
        return Ok(());
    }
    let start = usize::from(offsets[2]);
    let end = usize::from(offsets[3]);
    let map = header
        .get_mut(start..end)
        .ok_or(HfsError::InvalidCatalogRecord)?;
    if usize::try_from(used_nodes).map_err(|_| HfsError::CatalogOffsetTooLarge)? > map.len() * 8 {
        return Err(HfsError::CatalogMapCapacityExceeded);
    }
    map.fill(0);
    for node in 0..used_nodes {
        let node = usize::try_from(node).map_err(|_| HfsError::CatalogOffsetTooLarge)?;
        map[node / 8] |= 1 << (7 - node % 8);
    }
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, HfsError> {
    data.get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
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

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use hfsplus::{HfsVolume, testutil::HfsPlusImageBuilder};

    use super::*;

    #[test]
    fn rebuilds_multilevel_catalog_tree() {
        const BLOCK_SIZE: usize = 4096;
        const CATALOG_FORK_OFFSET: usize = 272;
        let mut builder = HfsPlusImageBuilder::new();
        builder.add_file("payload", b"data", 0o644);
        let mut image = builder.build();
        image.resize(40 * BLOCK_SIZE, 0);
        let primary = 1024;
        write_u32(&mut image, primary + 44, 40).unwrap();
        image[primary + CATALOG_FORK_OFFSET..primary + CATALOG_FORK_OFFSET + 8]
            .copy_from_slice(&(32_u64 * BLOCK_SIZE as u64).to_be_bytes());
        write_u32(&mut image, primary + CATALOG_FORK_OFFSET + 12, 32).unwrap();
        write_u32(&mut image, primary + CATALOG_FORK_OFFSET + 16, 2).unwrap();
        write_u32(&mut image, primary + CATALOG_FORK_OFFSET + 20, 32).unwrap();
        write_u32(&mut image, 2 * BLOCK_SIZE + 36, 32).unwrap();
        write_u32(&mut image, 2 * BLOCK_SIZE + 40, 30).unwrap();

        let mut tree = CatalogTree::read(&image).unwrap();
        let template = tree
            .records()
            .iter()
            .find(|record| {
                let body = record_body_offset(record).unwrap();
                read_u16(record, body).unwrap() == 2
            })
            .unwrap()
            .clone();
        for index in 0..200 {
            let mut record = template.clone();
            let name = format!("f{index:06}");
            for (offset, codepoint) in name.encode_utf16().enumerate() {
                record[8 + offset * 2..10 + offset * 2].copy_from_slice(&codepoint.to_be_bytes());
            }
            tree.records_mut().push(record);
        }
        tree.records_mut().sort_by(|left, right| {
            let left_parent = u32::from_be_bytes(left[2..6].try_into().unwrap());
            let right_parent = u32::from_be_bytes(right[2..6].try_into().unwrap());
            match left_parent.cmp(&right_parent) {
                Ordering::Equal => left[8..record_body_offset(left).unwrap()]
                    .cmp(&right[8..record_body_offset(right).unwrap()]),
                ordering => ordering,
            }
        });
        tree.write(&mut image).unwrap();

        let mut volume = HfsVolume::open(Cursor::new(image)).unwrap();
        assert_eq!(volume.list_directory("/").unwrap().len(), 201);
    }
}
