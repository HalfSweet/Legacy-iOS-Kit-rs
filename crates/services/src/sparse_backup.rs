//! Synthetic mobilebackup2 backup directory generation.
//!
//! Ports JJTech0130's TrollRestore `sparserestore/backup.py`: a backup is a
//! flat directory holding one blob per concrete file (named
//! `sha1(domain + "-" + path)`), a `Manifest.mbdb` describing every entry,
//! and the `Status`/`Manifest`/`Info` property lists that mobilebackup2
//! requires before it accepts the restore.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use plist::{Dictionary, Value};
use sha1::Digest as _;
use thiserror::Error;
use tokio::fs;

use crate::mbdb::{Mbdb, MbdbError, MbdbRecord, mode};

/// Backup key bag blob hardcoded by the reference tool; mobilebackup2 only
/// checks that it parses, not that it matches the device.
const BACKUP_KEY_BAG_BASE64: &str = "VkVSUwAAAAQAAAAFVFlQRQAAAAQAAAABVVVJRAAAABDud41d1b9NBICR1BH9JfVtSE1DSwAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAV1JBUAAAAAQAAAAAU0FMVAAAABRY5Ne2bthGQ5rf4O3gikep1e6tZUlURVIAAAAEAAAnEFVVSUQAAAAQB7R8awiGR9aba1UuVahGPENMQVMAAAAEAAAAAVdSQVAAAAAEAAAAAktUWVAAAAAEAAAAAFdQS1kAAAAoN3kQAJloFg+ukEUY+v5P+dhc/Welw/oucsyS40UBh67ZHef5ZMk9UVVVSUQAAAAQgd0cg0hSTgaxR3PVUbcEkUNMQVMAAAAEAAAAAldSQVAAAAAEAAAAAktUWVAAAAAEAAAAAFdQS1kAAAAoMiQTXx0SJlyrGJzdKZQ+SfL124w+2Tf/3d1R2i9yNj9zZCHNJhnorVVVSUQAAAAQf7JFQiBOS12JDD7qwKNTSkNMQVMAAAAEAAAAA1dSQVAAAAAEAAAAAktUWVAAAAAEAAAAAFdQS1kAAAAoSEelorROJA46ZUdwDHhMKiRguQyqHukotrxhjIfqiZ5ESBXX9txi51VVSUQAAAAQfF0G/837QLq01xH9+66vx0NMQVMAAAAEAAAABFdSQVAAAAAEAAAAAktUWVAAAAAEAAAAAFdQS1kAAAAol0BvFhd5bu4Hr75XqzNf4g0fMqZAie6OxI+x/pgm6Y95XW17N+ZIDVVVSUQAAAAQimkT2dp1QeadMu1KhJKNTUNMQVMAAAAEAAAABVdSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo2N2DZarQ6GPoWRgTiy/tdjKArOqTaH0tPSG9KLbIjGTOcLodhx23xFVVSUQAAAAQQV37JVZHQFiKpoNiGmT6+ENMQVMAAAAEAAAABldSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAofe2QSvDC2cV7Etk4fSBbgqDx5ne/z1VHwmJ6NdVrTyWi80Sy869DM1VVSUQAAAAQFzkdH+VgSOmTj3yEcfWmMUNMQVMAAAAEAAAAB1dSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo7kLYPQ/DnHBERGpaz37eyntIX/XzovsS0mpHW3SoHvrb9RBgOB+WblVVSUQAAAAQEBpgKOz9Tni8F9kmSXd0sENMQVMAAAAEAAAACFdSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo5mxVoyNFgPMzphYhm1VG8Fhsin/xX+r6mCd9gByF5SxeolAIT/ICF1VVSUQAAAAQrfKB2uPSQtWh82yx6w4BoUNMQVMAAAAEAAAACVdSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAo5iayZBwcRa1c1MMx7vh6lOYux3oDI/bdxFCW1WHCQR/Ub1MOv+QaYFVVSUQAAAAQiLXvK3qvQza/mea5inss/0NMQVMAAAAEAAAACldSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAoD2wHX7KriEe1E31z7SQ7/+AVymcpARMYnQgegtZD0Mq2U55uxwNr2FVVSUQAAAAQ/Q9feZxLS++qSe/a4emRRENMQVMAAAAEAAAAC1dSQVAAAAAEAAAAA0tUWVAAAAAEAAAAAFdQS1kAAAAocYda2jyYzzSKggRPw/qgh6QPESlkZedgDUKpTr4ZZ8FDgd7YoALY1g==";

/// A directory entry in a synthetic backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    path: String,
    domain: String,
    owner: u32,
    group: u32,
    mode: u16,
}

impl DirectoryEntry {
    pub fn new(path: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            domain: domain.into(),
            owner: 0,
            group: 0,
            mode: mode::DEFAULT,
        }
    }

    pub fn with_owner(mut self, owner: u32, group: u32) -> Self {
        self.owner = owner;
        self.group = group;
        self
    }

    pub fn with_mode(mut self, mode: u16) -> Self {
        self.mode = mode;
        self
    }
}

/// A concrete file whose contents are stored in a backup blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEntry {
    path: String,
    domain: String,
    contents: Vec<u8>,
    owner: u32,
    group: u32,
    mode: u16,
    inode: Option<u64>,
}

impl FileEntry {
    pub fn new(path: impl Into<String>, domain: impl Into<String>, contents: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            domain: domain.into(),
            contents,
            owner: 0,
            group: 0,
            mode: mode::DEFAULT,
            inode: None,
        }
    }

    pub fn with_owner(mut self, owner: u32, group: u32) -> Self {
        self.owner = owner;
        self.group = group;
        self
    }

    pub fn with_mode(mut self, mode: u16) -> Self {
        self.mode = mode;
        self
    }

    /// Pin the inode number; a random one is generated when omitted.
    pub fn with_inode(mut self, inode: u64) -> Self {
        self.inode = Some(inode);
        self
    }
}

/// A symbolic link entry in a synthetic backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkEntry {
    path: String,
    domain: String,
    target: String,
    owner: u32,
    group: u32,
    mode: u16,
    inode: Option<u64>,
}

impl SymlinkEntry {
    pub fn new(
        path: impl Into<String>,
        domain: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            domain: domain.into(),
            target: target.into(),
            owner: 0,
            group: 0,
            mode: mode::DEFAULT,
            inode: None,
        }
    }

    pub fn with_owner(mut self, owner: u32, group: u32) -> Self {
        self.owner = owner;
        self.group = group;
        self
    }

    pub fn with_mode(mut self, mode: u16) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_inode(mut self, inode: u64) -> Self {
        self.inode = Some(inode);
        self
    }
}

/// One entry of a synthetic backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupEntry {
    Directory(DirectoryEntry),
    File(FileEntry),
    SymbolicLink(SymlinkEntry),
}

impl BackupEntry {
    pub fn domain(&self) -> &str {
        match self {
            Self::Directory(entry) => &entry.domain,
            Self::File(entry) => &entry.domain,
            Self::SymbolicLink(entry) => &entry.domain,
        }
    }

    pub fn path(&self) -> &str {
        match self {
            Self::Directory(entry) => &entry.path,
            Self::File(entry) => &entry.path,
            Self::SymbolicLink(entry) => &entry.path,
        }
    }

    fn to_record(&self, now: u32) -> MbdbRecord {
        match self {
            Self::Directory(entry) => MbdbRecord::new(
                entry.domain.clone(),
                entry.path.clone(),
                entry.mode | mode::S_IFDIR,
            )
            .with_owner(entry.owner, entry.group)
            .with_timestamps(now, now, now),
            Self::File(entry) => MbdbRecord::new(
                entry.domain.clone(),
                entry.path.clone(),
                entry.mode | mode::S_IFREG,
            )
            .with_hash(sha1::Sha1::digest(&entry.contents).to_vec())
            .with_inode(entry.inode.unwrap_or_else(rand::random))
            .with_owner(entry.owner, entry.group)
            .with_timestamps(now, now, now)
            .with_size(entry.contents.len() as u64),
            Self::SymbolicLink(entry) => MbdbRecord::new(
                entry.domain.clone(),
                entry.path.clone(),
                entry.mode | mode::S_IFLNK,
            )
            .with_link(entry.target.clone())
            .with_inode(entry.inode.unwrap_or_else(rand::random))
            .with_owner(entry.owner, entry.group)
            .with_timestamps(now, now, now),
        }
    }
}

/// The blob file name mobilebackup2 expects for a domain/path pair.
pub fn blob_name(domain: &str, path: &str) -> String {
    hex(&sha1::Sha1::digest(format!("{domain}-{path}").as_bytes()))
}

/// A synthetic backup that can be written to a host directory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SparseBackup {
    entries: Vec<BackupEntry>,
}

impl SparseBackup {
    pub fn new(entries: Vec<BackupEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[BackupEntry] {
        &self.entries
    }

    /// Write the blob files, `Manifest.mbdb`, `Status.plist`,
    /// `Manifest.plist`, and `Info.plist` into `directory`.
    pub async fn write_to_directory(
        &self,
        directory: impl AsRef<Path>,
    ) -> Result<(), SparseBackupError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory).await?;
        for entry in &self.entries {
            if let BackupEntry::File(file) = entry {
                fs::write(
                    directory.join(blob_name(&file.domain, &file.path)),
                    &file.contents,
                )
                .await?;
            }
        }
        fs::write(
            directory.join("Manifest.mbdb"),
            self.manifest_db()?.to_bytes()?,
        )
        .await?;
        fs::write(directory.join("Status.plist"), status_plist()?).await?;
        fs::write(directory.join("Manifest.plist"), manifest_plist()?).await?;
        fs::write(
            directory.join("Info.plist"),
            xml(&Value::Dictionary(Dictionary::new()))?,
        )
        .await?;
        Ok(())
    }

    fn manifest_db(&self) -> Result<Mbdb, SparseBackupError> {
        Ok(Mbdb::new(self.records(now())))
    }

    fn records(&self, now: u32) -> Vec<MbdbRecord> {
        self.entries
            .iter()
            .map(|entry| entry.to_record(now))
            .collect()
    }
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u32::try_from(elapsed.as_secs()).ok())
        .unwrap_or(u32::MAX)
}

fn status_plist() -> Result<Vec<u8>, SparseBackupError> {
    let mut status = Dictionary::new();
    status.insert("BackupState".into(), "new".into());
    status.insert("Date".into(), Value::Date(UNIX_EPOCH.into()));
    status.insert("IsFullBackup".into(), false.into());
    status.insert("SnapshotState".into(), "finished".into());
    status.insert("UUID".into(), "00000000-0000-0000-0000-000000000000".into());
    status.insert("Version".into(), "2.4".into());
    xml(&Value::Dictionary(status))
}

fn manifest_plist() -> Result<Vec<u8>, SparseBackupError> {
    let key_bag = base64::engine::general_purpose::STANDARD
        .decode(BACKUP_KEY_BAG_BASE64)
        .map_err(|_| SparseBackupError::InvalidKeyBag)?;
    let mut manifest = Dictionary::new();
    manifest.insert("BackupKeyBag".into(), Value::Data(key_bag));
    manifest.insert("Lockdown".into(), Value::Dictionary(Dictionary::new()));
    manifest.insert("SystemDomainsVersion".into(), "20.0".into());
    manifest.insert("Version".into(), "9.1".into());
    xml(&Value::Dictionary(manifest))
}

fn xml(value: &Value) -> Result<Vec<u8>, SparseBackupError> {
    let mut output = Vec::new();
    plist::to_writer_xml(&mut output, value)?;
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum SparseBackupError {
    #[error("mbdb encoding failed: {0}")]
    Mbdb(#[from] MbdbError),
    #[error("backup directory I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup property list failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("the embedded backup key bag failed to decode")]
    InvalidKeyBag,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_blobs_like_the_reference_tool() {
        // sha1("RootDomain-Library/Preferences/temp")
        assert_eq!(
            blob_name("RootDomain", "Library/Preferences/temp"),
            "87674218a791b623d9f39c8d97768c06332c88a4"
        );
    }

    #[test]
    fn file_record_carries_contents_digest_and_owner() {
        let entry = BackupEntry::File(
            FileEntry::new(
                "Library/Preferences/temp",
                "RootDomain",
                b"payload".to_vec(),
            )
            .with_owner(33, 33)
            .with_inode(42),
        );
        let record = entry.to_record(1_700_000_000);
        assert_eq!(record.domain(), "RootDomain");
        assert_eq!(record.filename(), "Library/Preferences/temp");
        assert_eq!(record.mode(), mode::S_IFREG | mode::DEFAULT);
        assert_eq!(record.hash(), sha1::Sha1::digest(b"payload").as_slice());
        assert_eq!(record.inode(), 42);
        assert_eq!(record.user_id(), 33);
        assert_eq!(record.group_id(), 33);
        assert_eq!(record.size(), 7);
    }

    #[test]
    fn directory_and_symlink_records_match_reference_modes() {
        let directory = BackupEntry::Directory(DirectoryEntry::new("Library", "RootDomain"));
        assert_eq!(directory.to_record(0).mode(), mode::S_IFDIR | mode::DEFAULT);
        let symlink = BackupEntry::SymbolicLink(
            SymlinkEntry::new("link", "RootDomain", "/target").with_inode(7),
        );
        let record = symlink.to_record(0);
        assert_eq!(record.mode(), mode::S_IFLNK | mode::DEFAULT);
        assert_eq!(record.link(), "/target");
        assert_eq!(record.size(), 0);
    }

    #[test]
    fn embeds_the_reference_backup_key_bag() {
        let manifest = manifest_plist().unwrap();
        let value = Value::from_reader(std::io::Cursor::new(manifest)).unwrap();
        let dictionary = value.as_dictionary().unwrap();
        let key_bag = dictionary
            .get("BackupKeyBag")
            .and_then(Value::as_data)
            .unwrap();
        assert_eq!(key_bag.len(), 1336);
        assert_eq!(&key_bag[..4], b"VERS");
        assert_eq!(
            hex(&sha1::Sha1::digest(key_bag)),
            "05f048630af23e9a508de230977c3ec5e05c017f"
        );
        assert_eq!(
            dictionary
                .get("SystemDomainsVersion")
                .and_then(Value::as_string),
            Some("20.0")
        );
        assert_eq!(
            dictionary.get("Version").and_then(Value::as_string),
            Some("9.1")
        );
    }

    #[test]
    fn status_plist_matches_reference_shape() {
        let value = Value::from_reader(std::io::Cursor::new(status_plist().unwrap())).unwrap();
        let status = value.as_dictionary().unwrap();
        assert_eq!(
            status.get("BackupState").and_then(Value::as_string),
            Some("new")
        );
        assert_eq!(
            status.get("SnapshotState").and_then(Value::as_string),
            Some("finished")
        );
        assert_eq!(
            status.get("IsFullBackup").and_then(Value::as_boolean),
            Some(false)
        );
        assert_eq!(
            status.get("UUID").and_then(Value::as_string),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(
            status.get("Version").and_then(Value::as_string),
            Some("2.4")
        );
        assert!(status.contains_key("Date"));
    }

    #[tokio::test]
    async fn writes_a_complete_backup_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("backup");
        let backup = SparseBackup::new(vec![
            BackupEntry::Directory(DirectoryEntry::new("", "RootDomain")),
            BackupEntry::File(
                FileEntry::new("Library/Preferences/temp", "RootDomain", b"helper".to_vec())
                    .with_owner(33, 33),
            ),
        ]);
        backup.write_to_directory(&root).await.unwrap();

        let blob = std::fs::read(root.join("87674218a791b623d9f39c8d97768c06332c88a4")).unwrap();
        assert_eq!(blob, b"helper");
        let mbdb = Mbdb::from_bytes(&std::fs::read(root.join("Manifest.mbdb")).unwrap()).unwrap();
        assert_eq!(mbdb.records().len(), 2);
        for name in ["Status.plist", "Manifest.plist", "Info.plist"] {
            Value::from_reader(std::io::Cursor::new(
                std::fs::read(root.join(name)).unwrap(),
            ))
            .unwrap();
        }
    }
}
