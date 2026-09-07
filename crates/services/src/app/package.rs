use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use plist::Value;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use super::{AppFailure, AppIdentifier};
use crate::ServiceError;

/// Metadata read from the actual IPA, independent of any catalog description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpaMetadata {
    bundle_id: AppIdentifier,
    bundle_name: String,
    executable: String,
    product_version: Option<String>,
    build_version: Option<String>,
    minimum_os_version: Option<String>,
}
impl IpaMetadata {
    pub fn bundle_id(&self) -> &AppIdentifier {
        &self.bundle_id
    }
    pub fn bundle_name(&self) -> &str {
        &self.bundle_name
    }
    pub fn executable(&self) -> &str {
        &self.executable
    }
    pub fn product_version(&self) -> Option<&str> {
        self.product_version.as_deref()
    }
    pub fn build_version(&self) -> Option<&str> {
        self.build_version.as_deref()
    }
    pub fn minimum_os_version(&self) -> Option<&str> {
        self.minimum_os_version.as_deref()
    }
}

/// Owns the inspected file handle. The uploader reads this same file and checks
/// its digest again before committing a device installation.
pub struct IpaPackage {
    file: File,
    metadata: IpaMetadata,
    digest: [u8; 32],
    size: u64,
}
impl IpaPackage {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let path = path.as_ref().to_owned();
        tokio::task::spawn_blocking(move || inspect(File::open(path)?))
            .await
            .map_err(|_| AppFailure::InspectionTask)?
    }
    pub fn metadata(&self) -> &IpaMetadata {
        &self.metadata
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn size_bytes(&self) -> u64 {
        self.size
    }
    pub(super) fn into_parts(self) -> (File, IpaMetadata, [u8; 32], u64) {
        (self.file, self.metadata, self.digest, self.size)
    }
}
fn inspect(mut file: File) -> Result<IpaPackage, ServiceError> {
    let info = file.metadata()?;
    if !info.is_file() || info.len() == 0 || info.len() > 512 * 1024 * 1024 {
        return Err(AppFailure::InvalidPackage.into());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size += count as u64;
        if size > info.len() {
            return Err(AppFailure::DigestMismatch.into());
        }
    }
    if size != info.len() {
        return Err(AppFailure::DigestMismatch.into());
    }
    file.rewind()?;
    let mut archive = ZipArchive::new(file).map_err(|_| AppFailure::InvalidPackage)?;
    if archive.len() > 50_000 {
        return Err(AppFailure::InvalidPackage.into());
    }
    let infos: Vec<_> = archive
        .file_names()
        .filter(|name| {
            let parts: Vec<_> = name.split('/').collect();
            parts.len() == 3
                && parts[0] == "Payload"
                && parts[1].ends_with(".app")
                && parts[2] == "Info.plist"
        })
        .map(str::to_owned)
        .collect();
    if infos.len() != 1 {
        return Err(AppFailure::InvalidPackage.into());
    }
    let path = &infos[0];
    let mut entry = archive
        .by_name(path)
        .map_err(|_| AppFailure::InvalidPackage)?;
    if entry.size() > 1024 * 1024 {
        return Err(AppFailure::InvalidPackage.into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut entry)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(AppFailure::InvalidPackage.into());
    }
    let dictionary = Value::from_reader(std::io::Cursor::new(bytes))
        .map_err(|_| AppFailure::InvalidPackage)?
        .into_dictionary()
        .ok_or(AppFailure::InvalidPackage)?;
    let value = |key: &str| {
        dictionary
            .get(key)
            .and_then(Value::as_string)
            .map(str::to_owned)
    };
    let bundle_id =
        AppIdentifier::parse(value("CFBundleIdentifier").ok_or(AppFailure::InvalidPackage)?)?;
    let executable = value("CFBundleExecutable").ok_or(AppFailure::InvalidPackage)?;
    if executable.is_empty()
        || executable.contains(['/', '\\', '\0'])
        || matches!(executable.as_str(), "." | "..")
    {
        return Err(AppFailure::InvalidPackage.into());
    }
    let bundle_name = path
        .split('/')
        .nth(1)
        .ok_or(AppFailure::InvalidPackage)?
        .to_owned();
    let metadata = IpaMetadata {
        bundle_id,
        bundle_name,
        executable,
        product_version: value("CFBundleShortVersionString"),
        build_version: value("CFBundleVersion"),
        minimum_os_version: value("MinimumOSVersion"),
    };
    drop(entry);
    archive
        .by_name(&format!(
            "Payload/{}/{}",
            metadata.bundle_name, metadata.executable
        ))
        .map_err(|_| AppFailure::InvalidPackage)?;
    let mut file = archive.into_inner();
    file.rewind()?;
    Ok(IpaPackage {
        file,
        metadata,
        digest: hasher.finalize().into(),
        size,
    })
}
