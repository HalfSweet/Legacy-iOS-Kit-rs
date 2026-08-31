#![forbid(unsafe_code)]

//! Normal-mode iOS services and host integrations.

mod app;
mod files;
mod normal;
mod plist_service;

pub use app::{AppFilter, InstalledApp};
pub use files::{
    AfcPath, AfcPathError, DeviceFileInfo, DeviceFileKind, DeviceFiles, DeviceStorageInfo,
};
pub use normal::{
    DeviceSyslog, MuxDevice, NormalDevice, NormalDeviceInfo, RawServiceConnection, ServiceError,
    SystemMux,
};
