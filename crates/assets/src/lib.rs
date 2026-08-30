#![forbid(unsafe_code)]

//! Versioned device facts, workflow recipes, and asset provenance.

mod device;

pub use device::{AssetError, DeviceDatabase, DeviceProfile};
