#![forbid(unsafe_code)]

//! Apple image formats, filesystem images, and personalization.

mod img3;
mod img4;

pub use img3::{Img3, Img3Element, Img3Error, Img3Tag};
pub use img4::{Img4Error, personalize_img4};
