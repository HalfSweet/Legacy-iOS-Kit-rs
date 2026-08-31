//! Platform mount backends.
//!
//! The FUSE backend builds on targets where `fuser` works against a pure-Rust
//! mount implementation (Linux and the BSDs): no system library is needed at
//! build time, and a missing kernel driver is reported at mount time. On
//! macOS, `fuser` links against macFUSE at build time, so hosts without
//! macFUSE cannot compile that path at all; the stub reports the requirement
//! instead of failing the build.

#[cfg(all(unix, not(target_os = "macos")))]
mod fuse;
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) use fuse::{Guard, mount};

#[cfg(not(all(unix, not(target_os = "macos"))))]
mod unsupported;
#[cfg(not(all(unix, not(target_os = "macos"))))]
pub(crate) use unsupported::{Guard, mount};
