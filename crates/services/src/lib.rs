#![forbid(unsafe_code)]

//! Normal-mode iOS services and host integrations.

mod normal;

pub use normal::{NormalDevice, NormalDeviceInfo, RawServiceConnection, ServiceError, SystemMux};
