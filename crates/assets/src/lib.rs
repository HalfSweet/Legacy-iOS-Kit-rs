#![forbid(unsafe_code)]

//! Versioned device facts, workflow recipes, and asset provenance.

mod device;
mod resource;

pub use device::{AssetError, DeviceDatabase, DeviceProfile};
pub use resource::{Redistribution, ResourceCatalog, ResourceId, ResourceRecord};
