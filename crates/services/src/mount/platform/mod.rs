//! Platform mount backends.
//!
//! The FUSE backend builds on targets where `fuser` works against a pure-Rust
//! mount implementation (Linux and the BSDs): no system library is needed at
//! build time, and a missing kernel driver is reported at mount time. On
//! macOS, `fuser` links against macFUSE at build time, so the backend is only
//! compiled with the opt-in `macfuse` feature; builds without it use the stub,
//! which reports the requirement instead of failing the build.

/// The real FUSE backend is available on every unix target except macOS
/// builds without the `macfuse` feature.
#[cfg(all(unix, any(not(target_os = "macos"), feature = "macfuse")))]
mod fuse;
#[cfg(all(unix, any(not(target_os = "macos"), feature = "macfuse")))]
pub(crate) use fuse::{Guard, mount};

#[cfg(not(all(unix, any(not(target_os = "macos"), feature = "macfuse"))))]
mod unsupported;
#[cfg(not(all(unix, any(not(target_os = "macos"), feature = "macfuse"))))]
pub(crate) use unsupported::{Guard, mount};
