#![forbid(unsafe_code)]

//! Normal-mode iOS services and host integrations.

mod activation;
mod app;
mod backup;
mod files;
mod mount;
mod normal;
mod plist_service;
mod ssh;

pub use activation::ActivationState;
pub use app::{AppFilter, InstalledApp};
pub use backup::{BackupError, BackupOptions, BackupOutcome, BackupPassword, BackupRestoreOptions};
pub use files::{
    AfcPath, AfcPathError, DeviceFileInfo, DeviceFileKind, DeviceFiles, DeviceStorageInfo,
};
pub use mount::{MountError, MountGuard, MountOptions};
pub use normal::{
    DeviceSyslog, DirectMux, MuxDevice, NormalBackend, NormalDevice, NormalDeviceInfo, NormalMux,
    PairingRecord, RawServiceConnection, ServiceError, SystemMux,
};
pub use ssh::{
    HostKeyPolicy, RamdiskSsh, ScpPath, ScpPathError, SshCommandOutput, SshError, SshPassword,
    SshTarget, tar_contains_entry, tar_extract_entry,
};
