use std::{
    collections::HashMap,
    io::{Cursor, Read},
};

use flate2::read::DeflateDecoder;
use reqwest::{StatusCode, Url, header};
use thiserror::Error;
use tracing::{debug, trace};

use crate::{BuildManifest, FirmwareError};

const EOCD_SEARCH_SIZE: u64 = 65_557;
const MAX_DIRECTORY_SIZE: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: u64 = 100_000;
const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RemoteFirmwareArchive {
    url: Url,
    length: u64,
    entries: HashMap<String, RemoteZipEntry>,
    client: reqwest::Client,
}

impl RemoteFirmwareArchive {
    pub async fn open(url: &str) -> Result<Self, RemoteFirmwareError> {
        let url = Url::parse(url).map_err(|_| RemoteFirmwareError::InvalidUrl(url.to_owned()))?;
        let client = reqwest::Client::new();
        let length = discover_length(&client, &url).await?;
        let tail_length = length.min(EOCD_SEARCH_SIZE);
        let tail = fetch_range(&client, &url, length - tail_length, tail_length).await?;
        let eocd = parse_eocd(&tail)?;
        let directory = if eocd.zip64 {
            let locator_position = eocd
                .position
                .checked_sub(20)
                .ok_or(RemoteFirmwareError::InvalidZip)?;
            if read_u32(&tail, locator_position)? != 0x0706_4b50 {
                return Err(RemoteFirmwareError::InvalidZip);
            }
            let zip64_offset = read_u64(&tail, locator_position + 8)?;
            let zip64 = fetch_range(&client, &url, zip64_offset, 56).await?;
            parse_zip64_eocd(&zip64)?
        } else {
            CentralDirectory {
                offset: eocd.offset,
                size: eocd.size,
                entries: eocd.entries,
            }
        };
        if directory.size > MAX_DIRECTORY_SIZE || directory.entries > MAX_ENTRIES {
            return Err(RemoteFirmwareError::DirectoryTooLarge);
        }
        let end = directory
            .offset
            .checked_add(directory.size)
            .ok_or(RemoteFirmwareError::InvalidZip)?;
        if end > length {
            return Err(RemoteFirmwareError::InvalidZip);
        }
        let encoded = fetch_range(&client, &url, directory.offset, directory.size).await?;
        let entries = parse_directory(&encoded, directory.entries)?;
        debug!(
            entries = entries.len(),
            length, "opened remote IPSW central directory"
        );
        Ok(Self {
            url,
            length,
            entries,
            client,
        })
    }

    pub const fn length(&self) -> u64 {
        self.length
    }

    pub fn entry_names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub async fn build_manifest(&self) -> Result<BuildManifest, RemoteFirmwareError> {
        let data = self
            .read_entry_with_limit("BuildManifest.plist", MAX_MANIFEST_SIZE)
            .await?;
        Ok(BuildManifest::from_reader(Cursor::new(data))?)
    }

    pub async fn read_entry(&self, name: &str) -> Result<Vec<u8>, RemoteFirmwareError> {
        self.read_entry_with_limit(name, u64::MAX).await
    }

    pub async fn read_entry_with_limit(
        &self,
        name: &str,
        maximum_size: u64,
    ) -> Result<Vec<u8>, RemoteFirmwareError> {
        let entry = self
            .entries
            .get(name)
            .cloned()
            .ok_or_else(|| RemoteFirmwareError::EntryNotFound(name.to_owned()))?;
        if entry.uncompressed_size > maximum_size {
            return Err(RemoteFirmwareError::EntryTooLarge {
                name: name.to_owned(),
                size: entry.uncompressed_size,
                maximum: maximum_size,
            });
        }
        if entry.flags & 1 != 0 {
            return Err(RemoteFirmwareError::EncryptedEntry(name.to_owned()));
        }

        let local = fetch_range(&self.client, &self.url, entry.local_header_offset, 30).await?;
        if read_u32(&local, 0)? != 0x0403_4b50 {
            return Err(RemoteFirmwareError::InvalidZip);
        }
        let name_length = u64::from(read_u16(&local, 26)?);
        let extra_length = u64::from(read_u16(&local, 28)?);
        let data_offset = entry
            .local_header_offset
            .checked_add(30 + name_length + extra_length)
            .ok_or(RemoteFirmwareError::InvalidZip)?;
        let compressed =
            fetch_range(&self.client, &self.url, data_offset, entry.compressed_size).await?;
        let maximum = usize::try_from(entry.uncompressed_size)
            .map_err(|_| RemoteFirmwareError::EntryTooLargeForHost)?;
        let data = match entry.compression {
            0 => compressed,
            8 => {
                let decoder = DeflateDecoder::new(compressed.as_slice());
                let mut data = Vec::with_capacity(maximum);
                std::io::Read::take(decoder, entry.uncompressed_size + 1).read_to_end(&mut data)?;
                data
            }
            method => return Err(RemoteFirmwareError::UnsupportedCompression(method)),
        };
        if data.len() != maximum {
            return Err(RemoteFirmwareError::SizeMismatch(name.to_owned()));
        }
        let actual = crc32fast::hash(&data);
        if actual != entry.crc32 {
            return Err(RemoteFirmwareError::ChecksumMismatch {
                expected: entry.crc32,
                actual,
            });
        }
        trace!(name, bytes = data.len(), "read remote IPSW entry");
        Ok(data)
    }
}

#[derive(Clone, Debug)]
struct RemoteZipEntry {
    flags: u16,
    compression: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
}

async fn discover_length(client: &reqwest::Client, url: &Url) -> Result<u64, RemoteFirmwareError> {
    if let Ok(response) = client.head(url.clone()).send().await {
        if response.status().is_success() {
            if let Some(length) = response.content_length() {
                return Ok(length);
            }
        }
    }
    let response = client
        .get(url.clone())
        .header(header::RANGE, "bytes=0-0")
        .send()
        .await?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(RemoteFirmwareError::RangeUnsupported);
    }
    response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit_once('/'))
        .and_then(|(_, length)| length.parse().ok())
        .ok_or(RemoteFirmwareError::MissingLength)
}

async fn fetch_range(
    client: &reqwest::Client,
    url: &Url,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, RemoteFirmwareError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let end = offset
        .checked_add(length - 1)
        .ok_or(RemoteFirmwareError::InvalidZip)?;
    let response = client
        .get(url.clone())
        .header(header::RANGE, format!("bytes={offset}-{end}"))
        .send()
        .await?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(RemoteFirmwareError::RangeUnsupported);
    }
    let data = response.bytes().await?.to_vec();
    if data.len() as u64 != length {
        return Err(RemoteFirmwareError::ShortRangeResponse);
    }
    Ok(data)
}

#[derive(Clone, Copy, Debug)]
struct Eocd {
    position: usize,
    offset: u64,
    size: u64,
    entries: u64,
    zip64: bool,
}

fn parse_eocd(data: &[u8]) -> Result<Eocd, RemoteFirmwareError> {
    let position = data
        .windows(4)
        .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
        .ok_or(RemoteFirmwareError::InvalidZip)?;
    if position + 22 > data.len()
        || read_u16(data, position + 4)? != 0
        || read_u16(data, position + 6)? != 0
    {
        return Err(RemoteFirmwareError::MultiDiskZip);
    }
    let entries = u64::from(read_u16(data, position + 10)?);
    let size = u64::from(read_u32(data, position + 12)?);
    let offset = u64::from(read_u32(data, position + 16)?);
    Ok(Eocd {
        position,
        offset,
        size,
        entries,
        zip64: entries == u16::MAX as u64 || size == u32::MAX as u64 || offset == u32::MAX as u64,
    })
}

#[derive(Clone, Copy, Debug)]
struct CentralDirectory {
    offset: u64,
    size: u64,
    entries: u64,
}

fn parse_zip64_eocd(data: &[u8]) -> Result<CentralDirectory, RemoteFirmwareError> {
    if data.len() < 56
        || read_u32(data, 0)? != 0x0606_4b50
        || read_u32(data, 16)? != 0
        || read_u32(data, 20)? != 0
    {
        return Err(RemoteFirmwareError::MultiDiskZip);
    }
    Ok(CentralDirectory {
        entries: read_u64(data, 32)?,
        size: read_u64(data, 40)?,
        offset: read_u64(data, 48)?,
    })
}

fn parse_directory(
    data: &[u8],
    expected_entries: u64,
) -> Result<HashMap<String, RemoteZipEntry>, RemoteFirmwareError> {
    let mut entries = HashMap::new();
    let mut position = 0;
    while position < data.len() {
        if position + 46 > data.len() || read_u32(data, position)? != 0x0201_4b50 {
            return Err(RemoteFirmwareError::InvalidZip);
        }
        let name_length = usize::from(read_u16(data, position + 28)?);
        let extra_length = usize::from(read_u16(data, position + 30)?);
        let comment_length = usize::from(read_u16(data, position + 32)?);
        if read_u16(data, position + 34)? != 0 {
            return Err(RemoteFirmwareError::MultiDiskZip);
        }
        let end = position
            .checked_add(46 + name_length + extra_length + comment_length)
            .ok_or(RemoteFirmwareError::InvalidZip)?;
        if end > data.len() {
            return Err(RemoteFirmwareError::InvalidZip);
        }
        let name = std::str::from_utf8(&data[position + 46..position + 46 + name_length])
            .map_err(|_| RemoteFirmwareError::InvalidEntryName)?
            .to_owned();
        validate_name(&name)?;
        let extra_start = position + 46 + name_length;
        let extra = &data[extra_start..extra_start + extra_length];
        let mut compressed_size = u64::from(read_u32(data, position + 20)?);
        let mut uncompressed_size = u64::from(read_u32(data, position + 24)?);
        let mut local_header_offset = u64::from(read_u32(data, position + 42)?);
        apply_zip64_extra(
            extra,
            &mut uncompressed_size,
            &mut compressed_size,
            &mut local_header_offset,
        )?;
        let entry = RemoteZipEntry {
            flags: read_u16(data, position + 8)?,
            compression: read_u16(data, position + 10)?,
            crc32: read_u32(data, position + 16)?,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        };
        if entries.insert(name.clone(), entry).is_some() {
            return Err(RemoteFirmwareError::DuplicateEntry(name));
        }
        position = end;
    }
    if entries.len() as u64 != expected_entries {
        return Err(RemoteFirmwareError::InvalidZip);
    }
    Ok(entries)
}

fn apply_zip64_extra(
    data: &[u8],
    uncompressed: &mut u64,
    compressed: &mut u64,
    offset: &mut u64,
) -> Result<(), RemoteFirmwareError> {
    let needs_zip64 = *uncompressed == u32::MAX as u64
        || *compressed == u32::MAX as u64
        || *offset == u32::MAX as u64;
    if !needs_zip64 {
        return Ok(());
    }
    let mut position = 0;
    while position + 4 <= data.len() {
        let id = read_u16(data, position)?;
        let length = usize::from(read_u16(data, position + 2)?);
        let end = position + 4 + length;
        if end > data.len() {
            return Err(RemoteFirmwareError::InvalidZip);
        }
        if id == 1 {
            let mut field = position + 4;
            for value in [uncompressed, compressed, offset] {
                if *value == u32::MAX as u64 {
                    *value = read_u64(data, field)?;
                    field += 8;
                }
            }
            return Ok(());
        }
        position = end;
    }
    Err(RemoteFirmwareError::InvalidZip)
}

fn validate_name(name: &str) -> Result<(), RemoteFirmwareError> {
    if name.starts_with('/')
        || name.starts_with('\\')
        || name.split(['/', '\\']).any(|component| component == "..")
    {
        return Err(RemoteFirmwareError::UnsafeEntryName(name.to_owned()));
    }
    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, RemoteFirmwareError> {
    data.get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(RemoteFirmwareError::InvalidZip)
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, RemoteFirmwareError> {
    data.get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(RemoteFirmwareError::InvalidZip)
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, RemoteFirmwareError> {
    data.get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(RemoteFirmwareError::InvalidZip)
}

#[derive(Debug, Error)]
pub enum RemoteFirmwareError {
    #[error("invalid firmware URL: {0}")]
    InvalidUrl(String),
    #[error("remote server did not provide firmware length")]
    MissingLength,
    #[error("remote server does not support HTTP Range requests")]
    RangeUnsupported,
    #[error("remote server returned a short byte range")]
    ShortRangeResponse,
    #[error("invalid remote ZIP archive")]
    InvalidZip,
    #[error("multi-disk ZIP archives are unsupported")]
    MultiDiskZip,
    #[error("remote ZIP central directory exceeds supported limits")]
    DirectoryTooLarge,
    #[error("remote ZIP entry name is not UTF-8")]
    InvalidEntryName,
    #[error("unsafe remote ZIP entry name: {0}")]
    UnsafeEntryName(String),
    #[error("remote ZIP contains duplicate entry {0}")]
    DuplicateEntry(String),
    #[error("remote firmware does not contain {0}")]
    EntryNotFound(String),
    #[error("remote firmware entry {name} is {size} bytes, exceeding {maximum}")]
    EntryTooLarge {
        name: String,
        size: u64,
        maximum: u64,
    },
    #[error("remote firmware entry is too large for this host")]
    EntryTooLargeForHost,
    #[error("remote firmware entry {0} is encrypted")]
    EncryptedEntry(String),
    #[error("ZIP compression method {0} is unsupported")]
    UnsupportedCompression(u16),
    #[error("remote firmware entry {0} expanded to an unexpected size")]
    SizeMismatch(String),
    #[error("remote firmware checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    ChecksumMismatch { expected: u32, actual: u32 },
    #[error("remote firmware HTTP failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("remote firmware decompression failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Manifest(#[from] FirmwareError),
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn parses_central_directory() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"manifest").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let eocd = parse_eocd(&archive).unwrap();
        let start = eocd.offset as usize;
        let end = start + eocd.size as usize;
        let entries = parse_directory(&archive[start..end], eocd.entries).unwrap();

        assert!(entries.contains_key("BuildManifest.plist"));
    }
}
