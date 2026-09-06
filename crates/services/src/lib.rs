#![forbid(unsafe_code)]

//! Normal-mode iOS services and host integrations.

mod activation;
mod app;
mod backup;
mod file_relay;
mod files;
mod inspection;
mod mbdb;
mod normal;
mod plist_service;
mod session;
pub mod signing;
mod sparse_backup;
mod ssh;
mod system_mux;

pub use activation::ActivationState;
pub use app::{AppFilter, InstalledApp};
pub use backup::{BackupError, BackupOptions, BackupOutcome, BackupPassword, BackupRestoreOptions};
pub use files::{
    AfcPath, AfcPathError, DeviceFileInfo, DeviceFileKind, DeviceFiles, DeviceStorageInfo,
};
pub use inspection::{DeviceInspection, InspectionIssue, JailbreakEvidence, JailbreakStatus};
pub use mbdb::{Mbdb, MbdbError, MbdbRecord, mode};
pub use normal::{
    DeviceSyslog, DirectMux, MuxDevice, NormalBackend, NormalDevice, NormalDeviceInfo, NormalMux,
    PairingRecord, RawServiceConnection, ServiceError, SystemMux,
};
pub use session::DeviceSession;
#[cfg(feature = "legacy-tls")]
pub use session::LegacyTlsError;
pub use sparse_backup::{
    BackupEntry, DirectoryEntry, FileEntry, SparseBackup, SparseBackupError, SymlinkEntry,
    blob_name,
};
pub use ssh::{
    HostKeyPolicy, RamdiskSsh, ScpPath, ScpPathError, SshCommandOutput, SshError, SshPassword,
    SshTarget, tar_contains_entry, tar_extract_entry,
};
