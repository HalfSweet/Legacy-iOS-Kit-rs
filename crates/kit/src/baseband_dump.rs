use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read, Write},
};

use legacy_ios_firmware::UstarBuilder;
use legacy_ios_services::{RamdiskSsh, ScpPath};
use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::KitError;

const MAX_BYTES: usize = 256 * 1024 * 1024;
const FIRMWARE_ROOT: &str = "usr/local/standalone/firmware";

#[derive(Clone, Debug)]
pub struct BasebandDumpRequest {
    family: &'static str,
    major: u32,
    iphone4s: bool,
}

impl BasebandDumpRequest {
    pub fn new(product: &str, version: &str) -> Result<Self, BasebandDumpError> {
        let family = match product {
            "iPhone4,1" => "Trek",
            "iPhone5,3" | "iPhone5,4" => "Mav7Mav8",
            "iPhone5,1" | "iPhone5,2" | "iPad2,6" | "iPad2,7" | "iPad3,5" | "iPad3,6" => "Mav5",
            _ => return Err(BasebandDumpError::UnsupportedDevice),
        };
        let major = version
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|major| (5..=10).contains(major))
            .ok_or(BasebandDumpError::UnsupportedVersion)?;
        Ok(Self {
            family,
            major,
            iphone4s: product == "iPhone4,1",
        })
    }

    fn zip_source(&self) -> Option<String> {
        match self.major {
            5 => Some(format!(
                "/mnt1/usr/standalone/firmware/{}-personalized.zip",
                self.family
            )),
            6 => Some(format!(
                "/mnt1/{FIRMWARE_ROOT}/Baseband/{0}/{0}-personalized.zip",
                self.family
            )),
            _ => None,
        }
    }
}

pub(crate) async fn dump(
    ssh: &RamdiskSsh,
    request: &BasebandDumpRequest,
) -> Result<Vec<u8>, KitError> {
    let input = if let Some(source) = request.zip_source() {
        ssh.download(
            &ScpPath::new(source).map_err(|_| BasebandDumpError::InvalidPath)?,
            MAX_BYTES as u64,
        )
        .await?
    } else {
        let temporary = format!("/mnt2/tmp/lik-baseband-{}.tar", uuid::Uuid::new_v4());
        let command = format!("mkdir -p /mnt2/tmp && tar -C /mnt1 -cf {temporary} {FIRMWARE_ROOT}");
        let result = ssh.execute(&command).await?;
        if !result.success() {
            return Err(BasebandDumpError::ExportFailed.into());
        }
        let downloaded = ssh
            .download(
                &ScpPath::new(&temporary).map_err(|_| BasebandDumpError::InvalidPath)?,
                MAX_BYTES as u64,
            )
            .await;
        let _ = ssh.execute(&format!("rm -f {temporary}")).await;
        downloaded?
    };
    let request = request.clone();
    tokio::task::spawn_blocking(move || normalize(&request, &input))
        .await
        .map_err(|error| KitError::Task(error.to_string()))?
        .map_err(Into::into)
}

fn normalize(request: &BasebandDumpRequest, input: &[u8]) -> Result<Vec<u8>, BasebandDumpError> {
    let prefix = format!("{FIRMWARE_ROOT}/Baseband/{}/", request.family);
    let zip_name = format!("{}-personalized.zip", request.family);
    let mut files = if request.major <= 6 {
        read_zip(input)?
            .into_iter()
            .map(|(name, bytes)| (format!("{prefix}{name}"), bytes))
            .collect()
    } else {
        read_tar(input)?
    };
    let ticket = files.get(&format!("{prefix}bbticket.der"));
    if ticket.is_none_or(Vec::is_empty) {
        return Err(BasebandDumpError::MissingTicket);
    }
    let zip = if request.major <= 6 {
        input.to_vec()
    } else {
        let entries = files
            .iter()
            .filter_map(|(name, bytes)| {
                let name = name.strip_prefix(&prefix)?;
                (name != zip_name).then_some((name, bytes.as_slice()))
            })
            .collect::<Vec<_>>();
        write_zip(&entries)?
    };
    files.insert(format!("{prefix}{zip_name}"), zip.clone());
    if request.iphone4s {
        files.insert(format!("usr/standalone/firmware/{zip_name}"), zip);
    }
    let mut directories = BTreeSet::new();
    for name in files.keys() {
        let mut parent = name.as_str();
        while let Some((directory, _)) = parent.rsplit_once('/') {
            directories.insert(directory.to_owned());
            parent = directory;
        }
    }
    let mut output = UstarBuilder::new();
    for directory in directories {
        output.add_directory(&directory)?;
    }
    for (name, bytes) in files {
        output.add_file(&name, &bytes)?;
    }
    let output = output.finish();
    if output.len() > MAX_BYTES {
        return Err(BasebandDumpError::TooLarge);
    }
    Ok(output)
}

fn relative_path(name: &str) -> Result<&str, BasebandDumpError> {
    let name = name
        .strip_prefix("./")
        .unwrap_or(name)
        .trim_end_matches('/');
    if name.is_empty()
        || name.contains(['\\', ':', '\0'])
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(BasebandDumpError::InvalidPath);
    }
    Ok(name)
}

fn read_zip(input: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, BasebandDumpError> {
    let mut archive = ZipArchive::new(Cursor::new(input))?;
    if archive.len() > 4096 {
        return Err(BasebandDumpError::TooLarge);
    }
    let mut files = BTreeMap::new();
    let mut total = 0;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = relative_path(entry.name())?.to_owned();
        if entry.is_dir() {
            continue;
        }
        if entry.is_symlink() {
            return Err(BasebandDumpError::InvalidPath);
        }
        let mut bytes = Vec::new();
        entry
            .take((MAX_BYTES - total + 1) as u64)
            .read_to_end(&mut bytes)?;
        total += bytes.len();
        if total > MAX_BYTES {
            return Err(BasebandDumpError::TooLarge);
        }
        if files.insert(name, bytes).is_some() {
            return Err(BasebandDumpError::InvalidArchive);
        }
    }
    Ok(files)
}

fn write_zip(files: &[(&str, &[u8])]) -> Result<Vec<u8>, BasebandDumpError> {
    let mut archive = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        archive.start_file(
            *name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )?;
        archive.write_all(bytes)?;
    }
    Ok(archive.finish()?.into_inner())
}

fn octal(bytes: &[u8]) -> Result<usize, BasebandDumpError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| BasebandDumpError::InvalidArchive)?
        .trim_matches(['\0', ' ']);
    usize::from_str_radix(value, 8).map_err(|_| BasebandDumpError::InvalidArchive)
}

fn tar_string(bytes: &[u8]) -> Result<&str, BasebandDumpError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).map_err(|_| BasebandDumpError::InvalidArchive)
}

fn read_tar(input: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, BasebandDumpError> {
    if input.len() > MAX_BYTES {
        return Err(BasebandDumpError::TooLarge);
    }
    let mut files = BTreeMap::new();
    let mut offset = 0;
    while let Some(header) = input.get(offset..offset + 512) {
        if header.iter().all(|byte| *byte == 0) {
            return Ok(files);
        }
        let checksum = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    32
                } else {
                    usize::from(*byte)
                }
            })
            .sum::<usize>();
        if octal(&header[148..156])? != checksum {
            return Err(BasebandDumpError::InvalidArchive);
        }
        let prefix = tar_string(&header[345..500])?;
        let name = tar_string(&header[..100])?;
        let name = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let name = relative_path(&name)?.to_owned();
        if name != FIRMWARE_ROOT && !name.starts_with(&format!("{FIRMWARE_ROOT}/")) {
            return Err(BasebandDumpError::InvalidPath);
        }
        let size = octal(&header[124..136])?;
        let end = (offset + 512)
            .checked_add(size)
            .filter(|end| *end <= input.len())
            .ok_or(BasebandDumpError::InvalidArchive)?;
        match header[156] {
            0 | b'0' => {
                if files
                    .insert(name, input[offset + 512..end].to_vec())
                    .is_some()
                {
                    return Err(BasebandDumpError::InvalidArchive);
                }
            }
            b'5' if size == 0 => {}
            _ => return Err(BasebandDumpError::InvalidArchive),
        }
        offset = end.next_multiple_of(512);
    }
    Err(BasebandDumpError::InvalidArchive)
}

#[derive(Debug, Error)]
pub enum BasebandDumpError {
    #[error("baseband export is not supported for this device")]
    UnsupportedDevice,
    #[error("baseband export requires a supported iOS 5-10 version")]
    UnsupportedVersion,
    #[error("device failed to export the baseband files")]
    ExportFailed,
    #[error("baseband export contains no nonempty bbticket.der")]
    MissingTicket,
    #[error("baseband archive contains an invalid path or link")]
    InvalidPath,
    #[error("baseband archive is malformed or has duplicate entries")]
    InvalidArchive,
    #[error("baseband archive exceeds the supported size")]
    TooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    Tar(#[from] legacy_ios_firmware::UstarError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ios5_and_ios6_personalized_archives() {
        let input = write_zip(&[("bbticket.der", b"ticket"), ("dbl.mbn", b"firmware")]).unwrap();
        for version in ["5.1.1", "6.1.3"] {
            let request = BasebandDumpRequest::new("iPhone4,1", version).unwrap();
            let output = normalize(&request, &input).unwrap();
            assert!(legacy_ios_services::tar_contains_entry(
                &output,
                "Trek/bbticket.der"
            ));
            assert_eq!(
                legacy_ios_services::tar_extract_entry(
                    &output,
                    "usr/standalone/firmware/Trek-personalized.zip"
                )
                .unwrap(),
                input
            );
        }
        assert_eq!(
            BasebandDumpRequest::new("iPhone4,1", "5.1.1")
                .unwrap()
                .zip_source()
                .unwrap(),
            "/mnt1/usr/standalone/firmware/Trek-personalized.zip"
        );
        assert_eq!(
            BasebandDumpRequest::new("iPhone5,1", "6.1.3")
                .unwrap()
                .zip_source()
                .unwrap(),
            "/mnt1/usr/local/standalone/firmware/Baseband/Mav5/Mav5-personalized.zip"
        );
    }

    #[test]
    fn rebuilds_modern_personalized_zip_without_nesting_old_zip() {
        let mut tar = UstarBuilder::new();
        let prefix = format!("{FIRMWARE_ROOT}/Baseband/Mav7Mav8");
        tar.add_file(&format!("{prefix}/bbticket.der"), b"ticket")
            .unwrap();
        tar.add_file(&format!("{prefix}/dbl.mbn"), b"firmware")
            .unwrap();
        tar.add_file(&format!("{prefix}/Mav7Mav8-personalized.zip"), b"old")
            .unwrap();
        let output = normalize(
            &BasebandDumpRequest::new("iPhone5,3", "9.3.5").unwrap(),
            &tar.finish(),
        )
        .unwrap();
        let zip = legacy_ios_services::tar_extract_entry(
            &output,
            &format!("{prefix}/Mav7Mav8-personalized.zip"),
        )
        .unwrap();
        let files = read_zip(&zip).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files["bbticket.der"], b"ticket");
    }

    #[test]
    fn rejects_missing_ticket_traversal_and_truncated_archives() {
        let request = BasebandDumpRequest::new("iPhone4,1", "5.1.1").unwrap();
        assert!(matches!(
            normalize(&request, &write_zip(&[("dbl.mbn", b"x")]).unwrap()),
            Err(BasebandDumpError::MissingTicket)
        ));
        assert!(matches!(
            normalize(&request, &write_zip(&[("../bbticket.der", b"x")]).unwrap()),
            Err(BasebandDumpError::InvalidPath)
        ));
        assert!(read_tar(&[1; 511]).is_err());
        let mut tar = UstarBuilder::new();
        tar.add_file(&format!("{FIRMWARE_ROOT}/x"), b"data")
            .unwrap();
        let mut input = tar.finish();
        input[1] ^= 1;
        assert!(read_tar(&input).is_err());
    }
}
