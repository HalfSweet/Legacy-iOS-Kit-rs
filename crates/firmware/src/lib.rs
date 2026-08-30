#![forbid(unsafe_code)]

//! Firmware archives, manifests, signing tickets, and artifact storage.

mod archive;
mod manifest;

pub use archive::FirmwareArchive;
pub use manifest::{BuildIdentity, BuildManifest, FirmwareError, RestoreBehavior};
