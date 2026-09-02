use std::{fmt, io::SeekFrom, str::FromStr};

use idevice::{
    IdeviceService,
    services::afc::{AfcClient, opcode::AfcFopenMode},
};
use serde::Serialize;
use thiserror::Error;
use tokio::io::AsyncSeekExt;

use crate::{NormalDevice, ServiceError};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AfcPath(String);

impl AfcPath {
    pub fn new(path: impl Into<String>) -> Result<Self, AfcPathError> {
        let path = path.into();
        if path.as_bytes().contains(&0) {
            return Err(AfcPathError);
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AfcPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for AfcPath {
    type Err = AfcPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("AFC path contains NUL")]
pub struct AfcPathError;

#[derive(Debug)]
pub struct DeviceFiles {
    client: AfcClient,
}

impl DeviceFiles {
    pub(crate) fn new(client: AfcClient) -> Self {
        Self { client }
    }

    pub async fn list(&mut self, path: &AfcPath) -> Result<Vec<String>, ServiceError> {
        Ok(self
            .client
            .list_dir(path.as_str())
            .await?
            .into_iter()
            .filter(|entry| entry != "." && entry != "..")
            .collect())
    }

    pub async fn info(&mut self, path: &AfcPath) -> Result<DeviceFileInfo, ServiceError> {
        let info = self.client.get_file_info(path.as_str()).await?;
        Ok(DeviceFileInfo {
            size: info.size as u64,
            kind: DeviceFileKind::from_afc(info.st_ifmt),
            link_target: info.st_link_target,
            modified_unix: info.modified.and_utc().timestamp(),
        })
    }

    pub async fn storage_info(&mut self) -> Result<DeviceStorageInfo, ServiceError> {
        let info = self.client.get_device_info().await?;
        Ok(DeviceStorageInfo {
            model: info.model,
            total_bytes: info.total_bytes as u64,
            free_bytes: info.free_bytes as u64,
            block_size: info.block_size as u64,
        })
    }

    pub async fn read(&mut self, path: &AfcPath) -> Result<Vec<u8>, ServiceError> {
        let mut file = self
            .client
            .open(path.as_str(), AfcFopenMode::RdOnly)
            .await?;
        let data = file.read_entire().await?;
        file.close().await?;
        Ok(data)
    }

    /// Read up to `len` bytes starting at `offset`, opening and closing the
    /// device file around the transfer. Returns fewer bytes at end of file.
    pub async fn read_at(
        &mut self,
        path: &AfcPath,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ServiceError> {
        let mut file = self
            .client
            .open(path.as_str(), AfcFopenMode::RdOnly)
            .await?;
        let result = async {
            file.seek(SeekFrom::Start(offset)).await?;
            Ok::<Vec<u8>, ServiceError>(file.read_n(len).await?)
        }
        .await;
        let close = file.close().await;
        let data = result?;
        close?;
        Ok(data)
    }

    /// Write `data` starting at `offset` in an existing device file.
    pub async fn write_at(
        &mut self,
        path: &AfcPath,
        offset: u64,
        data: &[u8],
    ) -> Result<(), ServiceError> {
        let mut file = self.client.open(path.as_str(), AfcFopenMode::Rw).await?;
        let result = async {
            file.seek(SeekFrom::Start(offset)).await?;
            file.write_entire(data).await?;
            Ok::<(), ServiceError>(())
        }
        .await;
        let close = file.close().await;
        result?;
        close?;
        Ok(())
    }

    /// Create an empty device file, truncating it when it already exists.
    pub async fn create_file(&mut self, path: &AfcPath) -> Result<(), ServiceError> {
        let file = self
            .client
            .open(path.as_str(), AfcFopenMode::WrOnly)
            .await?;
        file.close().await?;
        Ok(())
    }

    pub async fn write(&mut self, path: &AfcPath, data: &[u8]) -> Result<(), ServiceError> {
        let mut file = self
            .client
            .open(path.as_str(), AfcFopenMode::WrOnly)
            .await?;
        file.write_entire(data).await?;
        file.close().await?;
        Ok(())
    }

    pub async fn create_dir(&mut self, path: &AfcPath) -> Result<(), ServiceError> {
        self.client.mk_dir(path.as_str()).await?;
        Ok(())
    }

    pub async fn remove(&mut self, path: &AfcPath, recursive: bool) -> Result<(), ServiceError> {
        if recursive {
            self.client.remove_all(path.as_str()).await?;
        } else {
            self.client.remove(path.as_str()).await?;
        }
        Ok(())
    }

    pub async fn rename(
        &mut self,
        source: &AfcPath,
        destination: &AfcPath,
    ) -> Result<(), ServiceError> {
        self.client
            .rename(source.as_str(), destination.as_str())
            .await?;
        Ok(())
    }
}

impl NormalDevice {
    pub async fn files(&self) -> Result<DeviceFiles, ServiceError> {
        Ok(DeviceFiles::new(AfcClient::connect(self.provider()).await?))
    }

    /// AFC over the jailbroken-device root service (`com.apple.afc2`). The
    /// connection fails on a stock device, so a successful connect already
    /// indicates an existing jailbreak.
    pub async fn root_files(&self) -> Result<DeviceFiles, ServiceError> {
        Ok(DeviceFiles::new(
            AfcClient::new_afc2(self.provider()).await?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceFileInfo {
    size: u64,
    kind: DeviceFileKind,
    link_target: Option<String>,
    modified_unix: i64,
}

impl DeviceFileInfo {
    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn kind(&self) -> &DeviceFileKind {
        &self.kind
    }

    pub fn link_target(&self) -> Option<&str> {
        self.link_target.as_deref()
    }

    /// Last modification time as seconds since the Unix epoch.
    pub const fn modified_unix(&self) -> i64 {
        self.modified_unix
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum DeviceFileKind {
    File,
    Directory,
    Symlink,
    Other(String),
}

impl DeviceFileKind {
    fn from_afc(value: String) -> Self {
        match value.as_str() {
            "S_IFREG" => Self::File,
            "S_IFDIR" => Self::Directory,
            "S_IFLNK" => Self::Symlink,
            _ => Self::Other(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceStorageInfo {
    model: String,
    total_bytes: u64,
    free_bytes: u64,
    block_size: u64,
}

impl DeviceStorageInfo {
    pub fn model(&self) -> &str {
        &self.model
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub const fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    pub const fn block_size(&self) -> u64 {
        self.block_size
    }
}
