#![forbid(unsafe_code)]

//! Apple image formats, filesystem images, and personalization.

mod img3;

pub use img3::{Img3, Img3Element, Img3Error, Img3Tag};
