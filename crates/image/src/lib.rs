#![forbid(unsafe_code)]

//! Apple image formats, filesystem images, and personalization.

mod crypto;
mod dmg;
mod fls;
mod hfs;
mod img3;
mod img4;
mod mbn;
mod onboard;
mod patch;

pub use crypto::{CryptoError, decrypt_cbc, encrypt_cbc};
pub use dmg::{
    DmgError, DmgFirmwareKey, DmgImage, DmgPartition, DmgPartitionInput, decrypt_firmware_image,
};
pub use fls::{FlsError, FlsFile};
pub use hfs::{HfsEntry, HfsEntryKind, HfsError, HfsImage, HfsStat};
pub use img3::{Img3, Img3Element, Img3Error, Img3Tag};
pub use img4::{Img4Error, personalize_img4};
pub use mbn::{MbnError, MbnFile, MbnFormat};
pub use onboard::{OnboardTicket, OnboardTicketError};
pub use patch::{PatchError, apply_bsdiff};
