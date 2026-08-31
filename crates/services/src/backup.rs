use std::path::{Component, Path, PathBuf};

use plist::{Dictionary, Value};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, info, trace};

use crate::{NormalDevice, RawServiceConnection, ServiceError};

const MOBILEBACKUP2: &str = "com.apple.mobilebackup2";
const MAX_PLIST_SIZE: usize = 64 * 1024 * 1024;
const FILE_CHUNK_SIZE: usize = 32 * 1024;
const CODE_SUCCESS: u8 = 0x00;
const CODE_ERROR_LOCAL: u8 = 0x06;
const CODE_FILE_DATA: u8 = 0x0c;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackupOptions {
    force_full: bool,
}

impl BackupOptions {
    pub fn force_full(mut self, enabled: bool) -> Self {
        self.force_full = enabled;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BackupOutcome {
    files: u64,
    bytes: u64,
}

impl BackupOutcome {
    pub const fn files(&self) -> u64 {
        self.files
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl NormalDevice {
    pub async fn backup(
        &self,
        destination: &Path,
        options: BackupOptions,
    ) -> Result<BackupOutcome, BackupError> {
        fs::create_dir_all(destination).await?;
        let stream = self.connect_service(MOBILEBACKUP2).await?;
        let mut protocol = MobileBackup2::connect(stream).await?;
        protocol
            .start_backup(destination, self.udid().as_str(), options)
            .await
    }
}

struct MobileBackup2 {
    link: DeviceLink,
}

impl MobileBackup2 {
    async fn connect(stream: RawServiceConnection) -> Result<Self, BackupError> {
        let mut link = DeviceLink { stream };
        let (tag, _) = link.receive_message().await?;
        if tag != "DLMessageVersionExchange" {
            return Err(BackupError::UnexpectedMessage(tag));
        }
        link.send_value(Value::Array(vec![
            "DLMessageVersionExchange".into(),
            "DLVersionsOk".into(),
            400_u64.into(),
        ]))
        .await?;
        let (tag, _) = link.receive_message().await?;
        if tag != "DLMessageDeviceReady" {
            return Err(BackupError::UnexpectedMessage(tag));
        }

        let mut hello = Dictionary::new();
        hello.insert(
            "SupportedProtocolVersions".into(),
            Value::Array(vec![2.0_f64.into(), 2.1_f64.into()]),
        );
        link.send_process_message("Hello", hello).await?;
        let response = link.receive_process_message().await?;
        if response.get("ErrorCode").and_then(unsigned) != Some(0)
            && response.contains_key("ErrorCode")
        {
            return Err(remote_error(&response));
        }
        let version = response
            .get("ProtocolVersion")
            .and_then(Value::as_real)
            .ok_or(BackupError::MissingProtocolVersion)?;
        debug!(version, "negotiated mobilebackup2 protocol");
        Ok(Self { link })
    }

    async fn start_backup(
        &mut self,
        destination: &Path,
        udid: &str,
        options: BackupOptions,
    ) -> Result<BackupOutcome, BackupError> {
        let mut request = Dictionary::new();
        request.insert("TargetIdentifier".into(), udid.into());
        request.insert("SourceIdentifier".into(), udid.into());
        let mut request_options = Dictionary::new();
        if options.force_full {
            request_options.insert("ForceFullBackup".into(), true.into());
        }
        request.insert("Options".into(), request_options.into());
        self.link.send_process_message("Backup", request).await?;
        let response = self.link.receive_process_message().await?;
        if response.contains_key("ErrorCode")
            && response.get("ErrorCode").and_then(unsigned) != Some(0)
        {
            return Err(remote_error(&response));
        }

        let mut outcome = BackupOutcome { files: 0, bytes: 0 };
        loop {
            let (tag, value) = self.link.receive_message().await?;
            trace!(tag, "received mobilebackup2 message");
            match tag.as_str() {
                "DLMessageUploadFiles" => {
                    let transferred = self.receive_files(destination).await?;
                    outcome.files += transferred.files;
                    outcome.bytes += transferred.bytes;
                    self.link.send_status(0, None, empty_dictionary()).await?;
                }
                "DLMessageDownloadFiles" => {
                    self.send_files(destination, &value).await?;
                }
                "DLMessageCreateDirectory" => {
                    let result = create_directory(destination, &value).await;
                    self.link.send_result(result).await?;
                }
                "DLMessageMoveFiles" | "DLMessageMoveItems" => {
                    let result = move_files(destination, &value).await;
                    self.link.send_result(result).await?;
                }
                "DLMessageRemoveFiles" | "DLMessageRemoveItems" => {
                    let result = remove_files(destination, &value).await;
                    self.link.send_result(result).await?;
                }
                "DLMessageCopyItem" => {
                    let result = copy_item(destination, &value).await;
                    self.link.send_result(result).await?;
                }
                "DLMessageGetFreeDiskSpace" => {
                    self.link.send_status(0, None, 0_u64.into()).await?;
                }
                "DLContentsOfDirectory" => {
                    self.link.send_status(0, None, empty_dictionary()).await?;
                }
                "DLMessageProcessMessage" => {
                    let response = process_dictionary(&value)?;
                    if response.contains_key("ErrorCode")
                        && response.get("ErrorCode").and_then(unsigned) != Some(0)
                    {
                        return Err(remote_error(response));
                    }
                    info!(
                        files = outcome.files,
                        bytes = outcome.bytes,
                        "backup completed"
                    );
                    return Ok(outcome);
                }
                "DLMessageDisconnect" => return Ok(outcome),
                _ => {
                    self.link
                        .send_status(
                            -1,
                            Some("Operation not supported"),
                            Value::String(String::new()),
                        )
                        .await?;
                }
            }
        }
    }

    async fn receive_files(&mut self, root: &Path) -> Result<BackupOutcome, BackupError> {
        let mut outcome = BackupOutcome { files: 0, bytes: 0 };
        loop {
            let domain_length = self.link.read_u32().await?;
            if domain_length == 0 {
                break;
            }
            let _domain = self.link.read_string(domain_length as usize).await?;
            let name_length = self.link.read_u32().await?;
            if name_length == 0 {
                break;
            }
            let name = self.link.read_string(name_length as usize).await?;
            let path = safe_join(root, &name)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await?;
            }
            let mut file = fs::File::create(path).await?;
            loop {
                let frame_length = self.link.read_u32().await?;
                if frame_length == 0 {
                    break;
                }
                let code = self.link.read_u8().await?;
                let payload_length = frame_length
                    .checked_sub(1)
                    .ok_or(BackupError::InvalidFileFrame)?
                    as usize;
                let payload = self.link.read_exact(payload_length).await?;
                if code == CODE_FILE_DATA {
                    file.write_all(&payload).await?;
                    outcome.bytes += payload.len() as u64;
                } else if code != CODE_SUCCESS {
                    return Err(BackupError::FileTransfer(
                        String::from_utf8_lossy(&payload).into(),
                    ));
                }
            }
            file.flush().await?;
            outcome.files += 1;
        }
        Ok(outcome)
    }

    async fn send_files(&mut self, root: &Path, message: &Value) -> Result<(), BackupError> {
        let files = message_array(message, 1)?;
        let mut failed = false;
        for file in files {
            let name = file.as_string().ok_or(BackupError::InvalidFileFrame)?;
            self.link.write_u32(name.len() as u32).await?;
            self.link.stream.write_all(name.as_bytes()).await?;
            let path = safe_join(root, name)?;
            match fs::File::open(path).await {
                Ok(mut file) => {
                    let mut buffer = vec![0; FILE_CHUNK_SIZE];
                    loop {
                        let read = file.read(&mut buffer).await?;
                        if read == 0 {
                            break;
                        }
                        self.link.write_u32(read as u32 + 1).await?;
                        self.link.stream.write_u8(CODE_FILE_DATA).await?;
                        self.link.stream.write_all(&buffer[..read]).await?;
                    }
                    self.link.write_u32(1).await?;
                    self.link.stream.write_u8(CODE_SUCCESS).await?;
                }
                Err(error) => {
                    failed = true;
                    let message = error.to_string();
                    self.link.write_u32(message.len() as u32 + 1).await?;
                    self.link.stream.write_u8(CODE_ERROR_LOCAL).await?;
                    self.link.stream.write_all(message.as_bytes()).await?;
                }
            }
        }
        self.link.write_u32(0).await?;
        let status = if failed { -13 } else { 0 };
        self.link
            .send_status(status, None, empty_dictionary())
            .await
    }
}

struct DeviceLink {
    stream: RawServiceConnection,
}

impl DeviceLink {
    async fn send_value(&mut self, value: Value) -> Result<(), BackupError> {
        let mut data = Vec::new();
        value.to_writer_binary(&mut data)?;
        let length = u32::try_from(data.len()).map_err(|_| BackupError::PlistTooLarge)?;
        self.stream.write_u32(length).await?;
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn receive_value(&mut self) -> Result<Value, BackupError> {
        let length = self.stream.read_u32().await? as usize;
        if length > MAX_PLIST_SIZE {
            return Err(BackupError::PlistTooLarge);
        }
        let mut data = vec![0; length];
        self.stream.read_exact(&mut data).await?;
        Ok(Value::from_reader(std::io::Cursor::new(data))?)
    }

    async fn receive_message(&mut self) -> Result<(String, Value), BackupError> {
        let value = self.receive_value().await?;
        let tag = value
            .as_array()
            .and_then(|array| array.first())
            .and_then(Value::as_string)
            .ok_or(BackupError::InvalidMessage)?
            .to_owned();
        Ok((tag, value))
    }

    async fn send_process_message(
        &mut self,
        name: &str,
        mut dictionary: Dictionary,
    ) -> Result<(), BackupError> {
        dictionary.insert("MessageName".into(), name.into());
        self.send_value(Value::Array(vec![
            "DLMessageProcessMessage".into(),
            dictionary.into(),
        ]))
        .await
    }

    async fn receive_process_message(&mut self) -> Result<Dictionary, BackupError> {
        let (tag, value) = self.receive_message().await?;
        if tag != "DLMessageProcessMessage" {
            return Err(BackupError::UnexpectedMessage(tag));
        }
        Ok(process_dictionary(&value)?.clone())
    }

    async fn send_status(
        &mut self,
        code: i64,
        message: Option<&str>,
        details: Value,
    ) -> Result<(), BackupError> {
        self.send_value(Value::Array(vec![
            "DLMessageStatusResponse".into(),
            code.into(),
            message.unwrap_or("___EmptyParameterString___").into(),
            details,
        ]))
        .await
    }

    async fn send_result(&mut self, result: Result<(), BackupError>) -> Result<(), BackupError> {
        match result {
            Ok(()) => self.send_status(0, None, empty_dictionary()).await,
            Err(error) => {
                self.send_status(-1, Some(&error.to_string()), empty_dictionary())
                    .await
            }
        }
    }

    async fn read_u32(&mut self) -> Result<u32, BackupError> {
        Ok(self.stream.read_u32().await?)
    }

    async fn write_u32(&mut self, value: u32) -> Result<(), BackupError> {
        self.stream.write_u32(value).await?;
        Ok(())
    }

    async fn read_u8(&mut self) -> Result<u8, BackupError> {
        Ok(self.stream.read_u8().await?)
    }

    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, BackupError> {
        let mut data = vec![0; length];
        self.stream.read_exact(&mut data).await?;
        Ok(data)
    }

    async fn read_string(&mut self, length: usize) -> Result<String, BackupError> {
        String::from_utf8(self.read_exact(length).await?).map_err(|_| BackupError::InvalidFileName)
    }
}

async fn create_directory(root: &Path, message: &Value) -> Result<(), BackupError> {
    let path = message_string(message, 1)?;
    fs::create_dir_all(safe_join(root, path)?).await?;
    Ok(())
}

async fn move_files(root: &Path, message: &Value) -> Result<(), BackupError> {
    let map = message
        .as_array()
        .and_then(|array| array.get(1))
        .and_then(Value::as_dictionary)
        .ok_or(BackupError::InvalidMessage)?;
    for (source, destination) in map {
        let destination = destination.as_string().ok_or(BackupError::InvalidMessage)?;
        let destination = safe_join(root, destination)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::rename(safe_join(root, source)?, destination).await?;
    }
    Ok(())
}

async fn remove_files(root: &Path, message: &Value) -> Result<(), BackupError> {
    for value in message_array(message, 1)? {
        let path = safe_join(root, value.as_string().ok_or(BackupError::InvalidMessage)?)?;
        match fs::metadata(&path).await {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path).await?,
            Ok(_) => fs::remove_file(path).await?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn copy_item(root: &Path, message: &Value) -> Result<(), BackupError> {
    let source = safe_join(root, message_string(message, 1)?)?;
    let destination = safe_join(root, message_string(message, 2)?)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).await?;
    }
    if fs::metadata(&source).await?.is_dir() {
        fs::create_dir_all(destination).await?;
    } else {
        fs::copy(source, destination).await?;
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, BackupError> {
    if relative.contains('\\') {
        return Err(BackupError::UnsafePath(relative.to_owned()));
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BackupError::UnsafePath(relative.to_owned()));
    }
    Ok(root.join(path))
}

fn process_dictionary(value: &Value) -> Result<&Dictionary, BackupError> {
    value
        .as_array()
        .and_then(|array| array.get(1))
        .and_then(Value::as_dictionary)
        .ok_or(BackupError::InvalidMessage)
}

fn message_array(value: &Value, index: usize) -> Result<&[Value], BackupError> {
    value
        .as_array()
        .and_then(|array| array.get(index))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(BackupError::InvalidMessage)
}

fn message_string(value: &Value, index: usize) -> Result<&str, BackupError> {
    value
        .as_array()
        .and_then(|array| array.get(index))
        .and_then(Value::as_string)
        .ok_or(BackupError::InvalidMessage)
}

fn empty_dictionary() -> Value {
    Value::Dictionary(Dictionary::new())
}

fn unsigned(value: &Value) -> Option<u64> {
    value.as_unsigned_integer().or_else(|| {
        value
            .as_signed_integer()
            .and_then(|value| value.try_into().ok())
    })
}

fn remote_error(dictionary: &Dictionary) -> BackupError {
    let code = dictionary
        .get("ErrorCode")
        .and_then(unsigned)
        .unwrap_or_default();
    let description = dictionary
        .get("ErrorDescription")
        .and_then(Value::as_string)
        .unwrap_or("mobilebackup2 rejected the request")
        .to_owned();
    BackupError::Remote { code, description }
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("mobilebackup2 I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("mobilebackup2 plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("mobilebackup2 plist frame is too large")]
    PlistTooLarge,
    #[error("invalid mobilebackup2 message")]
    InvalidMessage,
    #[error("expected another mobilebackup2 message, got {0}")]
    UnexpectedMessage(String),
    #[error("mobilebackup2 response has no protocol version")]
    MissingProtocolVersion,
    #[error("mobilebackup2 file frame is invalid")]
    InvalidFileFrame,
    #[error("mobilebackup2 file name is not UTF-8")]
    InvalidFileName,
    #[error("mobilebackup2 file transfer failed: {0}")]
    FileTransfer(String),
    #[error("mobilebackup2 path is unsafe: {0}")]
    UnsafePath(String),
    #[error("mobilebackup2 rejected the request ({code}): {description}")]
    Remote { code: u64, description: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_backup_path_traversal() {
        let root = Path::new("backup");
        assert!(safe_join(root, "device/file").is_ok());
        assert!(matches!(
            safe_join(root, "device/../../outside"),
            Err(BackupError::UnsafePath(_))
        ));
    }
}
