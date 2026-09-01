#![forbid(unsafe_code)]

//! Apple image formats, filesystem images, and personalization.

mod crypto;
mod dmg;
mod fls;
mod hfs;
mod hfs_btree;
mod iboot32;
mod img3;
mod img4;
mod mbn;
mod onboard;
mod patch;
mod payload;

pub use crypto::{CryptoError, decrypt_cbc, encrypt_cbc};
pub use dmg::{
    DmgError, DmgFirmwareKey, DmgImage, DmgPartition, DmgPartitionInput, decrypt_firmware_image,
};
pub use fls::{FlsError, FlsFile};
pub use hfs::{HfsEntry, HfsEntryKind, HfsError, HfsImage, HfsStat};
pub use iboot32::{
    BootMode, BootPartition, IBoot32, Iboot32PatchOptions, IbootPatchError, patch_iboot32,
    patch_iboot32_with_options,
};
pub use img3::{Img3, Img3Element, Img3Error, Img3Tag};
pub use img4::{Img4Error, extract_im4p_payload, personalize_img4, replace_im4p_payload};
pub use mbn::{MbnError, MbnFile, MbnFormat};
pub use onboard::{OnboardTicket, OnboardTicketError};
pub use patch::{PatchError, apply_bsdiff};
pub use payload::{
    ImagePayloadError, decrypt_img3_payload, extract_image_payload, repair_truncated_img3,
    replace_image_payload,
};
