#![forbid(unsafe_code)]

//! Firmware archives, manifests, signing tickets, and artifact storage.

mod archive;
mod artifact;
mod manifest;

pub use archive::FirmwareArchive;
pub use artifact::{ArtifactError, ArtifactSpec, ArtifactStore, Digest};
pub use manifest::{BuildIdentity, BuildManifest, FirmwareError, RestoreBehavior};
