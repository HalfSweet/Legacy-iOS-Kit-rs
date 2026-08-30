#![forbid(unsafe_code)]

//! Firmware archives, manifests, signing tickets, and artifact storage.

mod manifest;

pub use manifest::{BuildIdentity, BuildManifest, FirmwareError, RestoreBehavior};
