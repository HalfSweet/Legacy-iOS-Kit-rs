use std::io::{Cursor, Read, Write};

use bzip2_rs::DecoderReader;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use plist::{Dictionary, Value};
use thiserror::Error;

const SECTOR_SIZE: usize = 512;
const KOLY_SIZE: usize = 512;
const BLKX_HEADER_SIZE: usize = 204;
const BLKX_CHUNK_SIZE: usize = 40;
const CHUNK_SIZE: usize = 1024 * 1024;

const CHUNK_ZERO: u32 = 0;
const CHUNK_RAW: u32 = 1;
const CHUNK_IGNORE: u32 = 2;
const CHUNK_COMMENT: u32 = 0x7fff_fffe;
const CHUNK_ADC: u32 = 0x8000_0004;
const CHUNK_ZLIB: u32 = 0x8000_0005;
const CHUNK_BZLIB: u32 = 0x8000_0006;
const CHUNK_LZFSE: u32 = 0x8000_0007;
const CHUNK_TERM: u32 = 0xffff_ffff;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmgImage {
    data: Vec<u8>,
    partitions: Vec<DmgPartition>,
    tables: Vec<BlkxTable>,
}

impl DmgImage {
    pub fn parse(data: Vec<u8>) -> Result<Self, DmgError> {
        let (plist_offset, plist_length) = parse_koly(&data)?;
        let plist_end = plist_offset
            .checked_add(plist_length)
            .ok_or(DmgError::InvalidPlistRange)?;
        let plist_data = data
            .get(plist_offset..plist_end)
            .ok_or(DmgError::InvalidPlistRange)?;
        let root = Value::from_reader(Cursor::new(plist_data))?;
        let entries = root
            .as_dictionary()
            .and_then(|root| root.get("resource-fork"))
            .and_then(Value::as_dictionary)
            .and_then(|resources| resources.get("blkx"))
            .and_then(Value::as_array)
            .ok_or(DmgError::MissingBlockMap)?;

        let mut partitions = Vec::with_capacity(entries.len());
        let mut tables = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.as_dictionary().ok_or(DmgError::InvalidBlockMap)?;
            let name = entry
                .get("Name")
                .and_then(Value::as_string)
                .ok_or(DmgError::InvalidBlockMap)?;
            let encoded = entry
                .get("Data")
                .and_then(Value::as_data)
                .ok_or(DmgError::InvalidBlockMap)?;
            let table = BlkxTable::parse(encoded)?;
            partitions.push(DmgPartition {
                name: name.to_owned(),
                sectors: table.sector_count,
            });
            tables.push(table);
        }
        Ok(Self {
            data,
            partitions,
            tables,
        })
    }

    pub fn build(partitions: Vec<DmgPartitionInput>) -> Result<Self, DmgError> {
        let mut data_fork = Vec::new();
        let mut entries = Vec::with_capacity(partitions.len());
        let mut first_sector = 0_u64;
        let mut main_checksum = crc32fast::Hasher::new();

        for (index, partition) in partitions.into_iter().enumerate() {
            if !partition.data.len().is_multiple_of(SECTOR_SIZE) {
                return Err(DmgError::UnalignedPartition(partition.name));
            }
            let checksum = crc32fast::hash(&partition.data);
            main_checksum.update(&checksum.to_be_bytes());
            let mut chunks = Vec::new();
            let mut partition_sector = 0_u64;
            for raw in partition.data.chunks(CHUNK_SIZE) {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(raw)?;
                let compressed = encoder.finish()?;
                let compressed_offset = data_fork.len() as u64;
                let compressed_length = compressed.len() as u64;
                data_fork.extend_from_slice(&compressed);
                chunks.push(BlkxChunk {
                    chunk_type: CHUNK_ZLIB,
                    sector_number: partition_sector,
                    sector_count: (raw.len() / SECTOR_SIZE) as u64,
                    compressed_offset,
                    compressed_length,
                });
                partition_sector += (raw.len() / SECTOR_SIZE) as u64;
            }
            chunks.push(BlkxChunk {
                chunk_type: CHUNK_TERM,
                sector_number: partition_sector,
                sector_count: 0,
                compressed_offset: data_fork.len() as u64,
                compressed_length: 0,
            });
            let table = BlkxTable {
                sector_number: first_sector,
                sector_count: partition_sector,
                checksum,
                chunks,
            };
            first_sector += partition_sector;
            entries.push(partition_entry(index, &partition.name, table.encode()));
        }

        let mut resources = Dictionary::new();
        resources.insert("blkx".into(), Value::Array(entries));
        resources.insert("plst".into(), Value::Array(Vec::new()));
        let mut root = Dictionary::new();
        root.insert("resource-fork".into(), resources.into());
        let mut xml = Vec::new();
        Value::Dictionary(root).to_writer_xml(&mut xml)?;

        let data_checksum = crc32fast::hash(&data_fork);
        let main_checksum = main_checksum.finalize();
        let plist_offset = data_fork.len() as u64;
        let mut data = data_fork;
        data.extend_from_slice(&xml);
        data.extend_from_slice(&encode_koly(
            plist_offset,
            xml.len() as u64,
            first_sector,
            data_checksum,
            main_checksum,
        ));
        Self::parse(data)
    }

    pub fn partitions(&self) -> &[DmgPartition] {
        &self.partitions
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn extract(&self, index: usize) -> Result<Vec<u8>, DmgError> {
        let table = self
            .tables
            .get(index)
            .ok_or(DmgError::PartitionNotFound(index))?;
        let expected_size = table
            .sector_count
            .checked_mul(SECTOR_SIZE as u64)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(DmgError::PartitionTooLarge)?;
        let mut output = Vec::with_capacity(expected_size);
        for chunk in &table.chunks {
            let expanded_size = chunk
                .sector_count
                .checked_mul(SECTOR_SIZE as u64)
                .and_then(|size| usize::try_from(size).ok())
                .ok_or(DmgError::PartitionTooLarge)?;
            match chunk.chunk_type {
                CHUNK_ZERO | CHUNK_IGNORE => output.resize(output.len() + expanded_size, 0),
                CHUNK_RAW => {
                    let compressed = chunk.data(&self.data)?;
                    if compressed.len() != expanded_size {
                        return Err(DmgError::ChunkSizeMismatch);
                    }
                    output.extend_from_slice(compressed);
                }
                CHUNK_ZLIB => {
                    let compressed = chunk.data(&self.data)?;
                    let start = output.len();
                    ZlibDecoder::new(compressed).read_to_end(&mut output)?;
                    if output.len() - start != expanded_size {
                        return Err(DmgError::ChunkSizeMismatch);
                    }
                }
                CHUNK_BZLIB => {
                    let compressed = chunk.data(&self.data)?;
                    let start = output.len();
                    DecoderReader::new(compressed).read_to_end(&mut output)?;
                    if output.len() - start != expanded_size {
                        return Err(DmgError::ChunkSizeMismatch);
                    }
                }
                CHUNK_LZFSE => {
                    let compressed = chunk.data(&self.data)?;
                    let start = output.len();
                    lzfse_rust::decode_bytes(compressed, &mut output)
                        .map_err(std::io::Error::from)?;
                    if output.len() - start != expanded_size {
                        return Err(DmgError::ChunkSizeMismatch);
                    }
                }
                CHUNK_ADC => {
                    let compressed = chunk.data(&self.data)?;
                    output.extend_from_slice(&decode_adc(compressed, expanded_size)?);
                }
                CHUNK_COMMENT | CHUNK_TERM => {}
                value => return Err(DmgError::UnknownChunkType(value)),
            }
        }
        if output.len() != expected_size {
            return Err(DmgError::PartitionSizeMismatch);
        }
        let actual = crc32fast::hash(&output);
        if table.checksum != actual {
            return Err(DmgError::ChecksumMismatch {
                expected: table.checksum,
                actual,
            });
        }
        Ok(output)
    }
}

fn decode_adc(input: &[u8], expected_size: usize) -> Result<Vec<u8>, DmgError> {
    let mut output = Vec::with_capacity(expected_size);
    let mut cursor = 0;
    while cursor < input.len() {
        let tag = input[cursor];
        cursor += 1;
        if tag & 0x80 != 0 {
            let length = usize::from(tag & 0x7f) + 1;
            let end = cursor
                .checked_add(length)
                .ok_or(DmgError::InvalidAdcStream)?;
            let literal = input.get(cursor..end).ok_or(DmgError::InvalidAdcStream)?;
            if output.len() + length > expected_size {
                return Err(DmgError::ChunkSizeMismatch);
            }
            output.extend_from_slice(literal);
            cursor = end;
            continue;
        }

        let (length, offset) = if tag & 0x40 != 0 {
            let encoded = input
                .get(cursor..cursor + 2)
                .ok_or(DmgError::InvalidAdcStream)?;
            cursor += 2;
            (
                usize::from(tag & 0x3f) + 4,
                usize::from(u16::from_be_bytes([encoded[0], encoded[1]])),
            )
        } else {
            let low = *input.get(cursor).ok_or(DmgError::InvalidAdcStream)?;
            cursor += 1;
            (
                usize::from((tag & 0x3c) >> 2) + 3,
                (usize::from(tag & 0x03) << 8) | usize::from(low),
            )
        };
        let distance = offset + 1;
        if distance > output.len() {
            return Err(DmgError::InvalidAdcStream);
        }
        if output.len() + length > expected_size {
            return Err(DmgError::ChunkSizeMismatch);
        }
        for _ in 0..length {
            output.push(output[output.len() - distance]);
        }
    }
    if output.len() != expected_size {
        return Err(DmgError::ChunkSizeMismatch);
    }
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmgPartition {
    name: String,
    sectors: u64,
}

impl DmgPartition {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn sectors(&self) -> u64 {
        self.sectors
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DmgPartitionInput {
    name: String,
    data: Vec<u8>,
}

impl DmgPartitionInput {
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlkxTable {
    sector_number: u64,
    sector_count: u64,
    checksum: u32,
    chunks: Vec<BlkxChunk>,
}

impl BlkxTable {
    fn parse(data: &[u8]) -> Result<Self, DmgError> {
        if data.len() < BLKX_HEADER_SIZE || &data[..4] != b"mish" {
            return Err(DmgError::InvalidBlockMap);
        }
        let chunk_count = read_u32(data, 200)? as usize;
        let expected_size = BLKX_HEADER_SIZE
            .checked_add(
                chunk_count
                    .checked_mul(BLKX_CHUNK_SIZE)
                    .ok_or(DmgError::InvalidBlockMap)?,
            )
            .ok_or(DmgError::InvalidBlockMap)?;
        if data.len() < expected_size {
            return Err(DmgError::InvalidBlockMap);
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for index in 0..chunk_count {
            let offset = BLKX_HEADER_SIZE + index * BLKX_CHUNK_SIZE;
            chunks.push(BlkxChunk {
                chunk_type: read_u32(data, offset)?,
                sector_number: read_u64(data, offset + 8)?,
                sector_count: read_u64(data, offset + 16)?,
                compressed_offset: read_u64(data, offset + 24)?,
                compressed_length: read_u64(data, offset + 32)?,
            });
        }
        Ok(Self {
            sector_number: read_u64(data, 8)?,
            sector_count: read_u64(data, 16)?,
            checksum: read_u32(data, 72)?,
            chunks,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(BLKX_HEADER_SIZE + self.chunks.len() * BLKX_CHUNK_SIZE);
        output.extend_from_slice(b"mish");
        push_u32(&mut output, 1);
        push_u64(&mut output, self.sector_number);
        push_u64(&mut output, self.sector_count);
        push_u64(&mut output, 0);
        push_u32(&mut output, 2056);
        push_u32(&mut output, 0);
        output.extend_from_slice(&[0; 24]);
        push_checksum(&mut output, self.checksum);
        push_u32(&mut output, self.chunks.len() as u32);
        for chunk in &self.chunks {
            push_u32(&mut output, chunk.chunk_type);
            push_u32(&mut output, 0);
            push_u64(&mut output, chunk.sector_number);
            push_u64(&mut output, chunk.sector_count);
            push_u64(&mut output, chunk.compressed_offset);
            push_u64(&mut output, chunk.compressed_length);
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlkxChunk {
    chunk_type: u32,
    sector_number: u64,
    sector_count: u64,
    compressed_offset: u64,
    compressed_length: u64,
}

impl BlkxChunk {
    fn data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], DmgError> {
        let start =
            usize::try_from(self.compressed_offset).map_err(|_| DmgError::InvalidChunkRange)?;
        let length =
            usize::try_from(self.compressed_length).map_err(|_| DmgError::InvalidChunkRange)?;
        let end = start
            .checked_add(length)
            .ok_or(DmgError::InvalidChunkRange)?;
        data.get(start..end).ok_or(DmgError::InvalidChunkRange)
    }
}

fn parse_koly(data: &[u8]) -> Result<(usize, usize), DmgError> {
    let start = data
        .len()
        .checked_sub(KOLY_SIZE)
        .ok_or(DmgError::MissingKoly)?;
    let trailer = &data[start..];
    if &trailer[..4] != b"koly" || read_u32(trailer, 8)? != KOLY_SIZE as u32 {
        return Err(DmgError::MissingKoly);
    }
    let offset =
        usize::try_from(read_u64(trailer, 216)?).map_err(|_| DmgError::InvalidPlistRange)?;
    let length =
        usize::try_from(read_u64(trailer, 224)?).map_err(|_| DmgError::InvalidPlistRange)?;
    Ok((offset, length))
}

fn encode_koly(
    plist_offset: u64,
    plist_length: u64,
    sector_count: u64,
    data_checksum: u32,
    main_checksum: u32,
) -> [u8; KOLY_SIZE] {
    let mut output = Vec::with_capacity(KOLY_SIZE);
    output.extend_from_slice(b"koly");
    push_u32(&mut output, 4);
    push_u32(&mut output, KOLY_SIZE as u32);
    push_u32(&mut output, 1);
    push_u64(&mut output, 0);
    push_u64(&mut output, 0);
    push_u64(&mut output, plist_offset);
    push_u64(&mut output, 0);
    push_u64(&mut output, 0);
    push_u32(&mut output, 1);
    push_u32(&mut output, 1);
    output.extend_from_slice(&[0; 16]);
    push_checksum(&mut output, data_checksum);
    push_u64(&mut output, plist_offset);
    push_u64(&mut output, plist_length);
    output.extend_from_slice(&[0; 64]);
    push_u64(&mut output, 0);
    push_u64(&mut output, 0);
    output.extend_from_slice(&[0; 40]);
    push_checksum(&mut output, main_checksum);
    push_u32(&mut output, 1);
    push_u64(&mut output, sector_count);
    output.extend_from_slice(&[0; 12]);
    output
        .try_into()
        .expect("koly trailer is exactly 512 bytes")
}

fn partition_entry(index: usize, name: &str, table: Vec<u8>) -> Value {
    let mut entry = Dictionary::new();
    entry.insert("Attributes".into(), "0x0050".into());
    entry.insert("CFName".into(), name.into());
    entry.insert("Data".into(), Value::Data(table));
    entry.insert("ID".into(), (index as i64 - 1).to_string().into());
    entry.insert("Name".into(), name.into());
    entry.into()
}

fn push_checksum(output: &mut Vec<u8>, checksum: u32) {
    push_u32(output, 2);
    push_u32(output, 32);
    output.extend_from_slice(&checksum.to_be_bytes());
    output.extend_from_slice(&[0; 124]);
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DmgError> {
    data.get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(DmgError::Truncated)
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, DmgError> {
    data.get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(DmgError::Truncated)
}

#[derive(Debug, Error)]
pub enum DmgError {
    #[error("DMG has no valid koly trailer")]
    MissingKoly,
    #[error("DMG plist points outside the image")]
    InvalidPlistRange,
    #[error("DMG plist has no blkx resource map")]
    MissingBlockMap,
    #[error("DMG blkx resource map is invalid")]
    InvalidBlockMap,
    #[error("DMG structure is truncated")]
    Truncated,
    #[error("DMG partition {0} does not exist")]
    PartitionNotFound(usize),
    #[error("DMG partition {0} is not aligned to 512-byte sectors")]
    UnalignedPartition(String),
    #[error("DMG partition is too large for this host")]
    PartitionTooLarge,
    #[error("DMG uses unsupported compression type {0:#010x}")]
    UnsupportedCompression(u32),
    #[error("DMG uses unknown chunk type {0:#010x}")]
    UnknownChunkType(u32),
    #[error("DMG chunk points outside the image")]
    InvalidChunkRange,
    #[error("DMG chunk expanded to an unexpected size")]
    ChunkSizeMismatch,
    #[error("DMG ADC chunk is invalid")]
    InvalidAdcStream,
    #[error("DMG partition expanded to an unexpected size")]
    PartitionSizeMismatch,
    #[error("DMG checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    ChecksumMismatch { expected: u32, actual: u32 },
    #[error("DMG I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("DMG plist failed: {0}")]
    Plist(#[from] plist::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_extracts_zlib_dmg() {
        let data = vec![0x5a; 4096];
        let image =
            DmgImage::build(vec![DmgPartitionInput::new("Apple_HFS", data.clone())]).unwrap();

        assert_eq!(image.partitions()[0].name(), "Apple_HFS");
        assert_eq!(image.extract(0).unwrap(), data);
    }

    #[test]
    fn extracts_bzip2_blkx_chunk() {
        let compressed = vec![
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x6f, 0xa6, 0xeb, 0x63,
            0x00, 0x00, 0x01, 0x82, 0x00, 0x80, 0x10, 0x00, 0x08, 0x20, 0x00, 0x30, 0x80, 0x49,
            0xea, 0x06, 0xae, 0x2e, 0xe4, 0x8a, 0x70, 0xa1, 0x20, 0xdf, 0x4d, 0xd6, 0xc6,
        ];
        let expected = vec![0x5a; SECTOR_SIZE];
        let image = DmgImage {
            data: compressed.clone(),
            partitions: vec![DmgPartition {
                name: "Apple_HFS".into(),
                sectors: 1,
            }],
            tables: vec![BlkxTable {
                sector_number: 0,
                sector_count: 1,
                checksum: crc32fast::hash(&expected),
                chunks: vec![
                    BlkxChunk {
                        chunk_type: CHUNK_BZLIB,
                        sector_number: 0,
                        sector_count: 1,
                        compressed_offset: 0,
                        compressed_length: compressed.len() as u64,
                    },
                    BlkxChunk {
                        chunk_type: CHUNK_TERM,
                        sector_number: 1,
                        sector_count: 0,
                        compressed_offset: compressed.len() as u64,
                        compressed_length: 0,
                    },
                ],
            }],
        };

        assert_eq!(image.extract(0).unwrap(), expected);
    }

    #[test]
    fn extracts_lzfse_blkx_chunk() {
        let expected = vec![0x3c; SECTOR_SIZE];
        let mut compressed = Vec::new();
        lzfse_rust::encode_bytes(&expected, &mut compressed).unwrap();
        let image = DmgImage {
            data: compressed.clone(),
            partitions: vec![DmgPartition {
                name: "Apple_HFS".into(),
                sectors: 1,
            }],
            tables: vec![BlkxTable {
                sector_number: 0,
                sector_count: 1,
                checksum: crc32fast::hash(&expected),
                chunks: vec![
                    BlkxChunk {
                        chunk_type: CHUNK_LZFSE,
                        sector_number: 0,
                        sector_count: 1,
                        compressed_offset: 0,
                        compressed_length: compressed.len() as u64,
                    },
                    BlkxChunk {
                        chunk_type: CHUNK_TERM,
                        sector_number: 1,
                        sector_count: 0,
                        compressed_offset: compressed.len() as u64,
                        compressed_length: 0,
                    },
                ],
            }],
        };

        assert_eq!(image.extract(0).unwrap(), expected);
    }

    #[test]
    fn extracts_adc_blkx_chunk() {
        let expected = b"ABCD".repeat(SECTOR_SIZE / 4);
        let mut compressed = vec![0x83, b'A', b'B', b'C', b'D', 0x34, 0x03];
        for _ in 0..7 {
            compressed.extend_from_slice(&[0x7f, 0x00, 0x03]);
        }
        compressed.extend_from_slice(&[0x53, 0x00, 0x03]);
        let image = DmgImage {
            data: compressed.clone(),
            partitions: vec![DmgPartition {
                name: "Apple_HFS".into(),
                sectors: 1,
            }],
            tables: vec![BlkxTable {
                sector_number: 0,
                sector_count: 1,
                checksum: crc32fast::hash(&expected),
                chunks: vec![
                    BlkxChunk {
                        chunk_type: CHUNK_ADC,
                        sector_number: 0,
                        sector_count: 1,
                        compressed_offset: 0,
                        compressed_length: compressed.len() as u64,
                    },
                    BlkxChunk {
                        chunk_type: CHUNK_TERM,
                        sector_number: 1,
                        sector_count: 0,
                        compressed_offset: compressed.len() as u64,
                        compressed_length: 0,
                    },
                ],
            }],
        };

        assert_eq!(image.extract(0).unwrap(), expected);
    }
}
