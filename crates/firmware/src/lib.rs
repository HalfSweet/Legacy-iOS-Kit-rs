#![forbid(unsafe_code)]

//! Firmware archives, manifests, signing tickets, and artifact storage.

mod archive;
mod artifact;
mod custom;
mod manifest;
mod remote_zip;
mod ticket;
mod tss;

pub use archive::FirmwareArchive;
pub use artifact::{ArtifactError, ArtifactSpec, ArtifactStore, Digest};
pub use custom::{CustomIpswBuilder, CustomIpswError};
pub use manifest::{BuildIdentity, BuildManifest, FirmwareError, RestoreBehavior};
pub use remote_zip::{RemoteFirmwareArchive, RemoteFirmwareError};
pub use ticket::{SigningTicket, TicketError, derive_ap_nonce};
pub use tss::{
    ApParameters, BasebandParameters, TssClient, TssError, TssRequest, TssResponse,
    apply_restore_request_rules,
};
