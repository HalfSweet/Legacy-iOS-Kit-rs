#![forbid(unsafe_code)]

//! Firmware archives, manifests, signing tickets, and artifact storage.

mod archive;
mod artifact;
mod custom;
mod keys;
mod manifest;
mod powder_bundle;
mod remote_zip;
mod ticket;
mod tss;
mod ustar;

pub use archive::FirmwareArchive;
pub use artifact::{ArtifactError, ArtifactSpec, ArtifactStore, Digest};
pub use custom::{CustomIpswBuilder, CustomIpswError};
pub use keys::{FirmwareKey, FirmwareKeyError, FirmwareKeyProvider, FirmwareKeySet};
pub use manifest::{BuildIdentity, BuildManifest, FirmwareError, RestoreBehavior};
pub use powder_bundle::{
    BundleRole, DEFAULT_BOOT_ARGS, DaibutsuPackage, DaibutsuPayload, FilesystemPackage,
    FirmwareComponentKind, FirmwareEntry, NorImagePath, PowderBundle, PowderBundleError,
    PowderBundleRequest, PowderConfig, PowderMode, PowderPayloadPlan, PowderPayloadRequest,
    PowderTar, RamdiskExploit, RamdiskPackage, RebootScriptVariant, VERBOSE_BOOT_ARGS,
    exploit_path, iboot_tar, partition_script_resource, reboot_script, render_partition_script,
    system_partition_size, system_version_tar, uses_ramdisk_h,
};
pub use remote_zip::{RemoteFirmwareArchive, RemoteFirmwareError};
pub use ticket::{SigningTicket, TicketError, derive_ap_nonce};
pub use tss::{
    ApParameters, BasebandParameters, TssClient, TssError, TssRequest, TssResponse,
    apply_restore_request_rules,
};
pub use ustar::{UstarBuilder, UstarError};
