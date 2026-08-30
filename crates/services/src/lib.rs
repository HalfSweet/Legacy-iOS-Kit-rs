#![forbid(unsafe_code)]

//! Normal-mode iOS services and host integrations.

mod app;
mod normal;
mod plist_service;

pub use app::{AppFilter, InstalledApp};
pub use normal::{
    DeviceSyslog, MuxDevice, NormalDevice, NormalDeviceInfo, RawServiceConnection, ServiceError,
    SystemMux,
};
