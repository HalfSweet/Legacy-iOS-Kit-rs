//! Mount an AFC device file tree on the host (the `ifuse` equivalent).
//!
//! [`DeviceFiles::mount`] exposes the device media directory (or an
//! application container) through the system FUSE driver and returns a
//! [`MountGuard`]; dropping the guard unmounts. The session runs in the
//! background and is read-write by default, limited to what AFC permits;
//! pass [`MountOptions::read_only`] for a read-only mount.
//!
//! Requires a system FUSE driver: FUSE on Linux/BSD, macFUSE on macOS (a
//! build-time link dependency, so macOS builds currently report
//! [`MountError::Unsupported`]/[`MountError::DriverMissing`] instead), and
//! WinFsp on Windows (not yet implemented). Real mounts need hardware and a
//! system driver, so they are not exercised in CI; the AFC-to-FUSE
//! conversions are tested as pure logic.

#[cfg(any(test, all(unix, not(target_os = "macos"))))]
mod attr;
#[cfg(all(unix, not(target_os = "macos")))]
mod bridge;
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
mod inode;
mod platform;

use std::path::{Path, PathBuf};

use legacy_ios_transport::HostRequirement;
use thiserror::Error;
use tracing::debug;

use crate::DeviceFiles;

/// Options controlling how the device file tree is mounted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MountOptions {
    read_only: bool,
}

impl MountOptions {
    /// Mount read-only; write, create, remove, and rename operations fail
    /// with `EROFS`.
    pub const fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }
}

#[derive(Debug, Error)]
pub enum MountError {
    /// The system FUSE driver is not installed or not usable.
    #[error("system FUSE driver is unavailable: {}", .0.message())]
    DriverMissing(HostRequirement),
    #[error("mount point {path} is not usable: {reason}")]
    InvalidMountPoint { path: PathBuf, reason: String },
    /// The current build has no mount backend for this platform.
    #[error("mounting is unavailable: {0}")]
    Unsupported(&'static str),
    #[error("mount permission denied (check fuse group membership and /etc/fuse.conf): {0}")]
    PermissionDenied(#[source] std::io::Error),
    #[error("mount session failed: {0}")]
    Session(#[source] std::io::Error),
}

/// An active device mount. Dropping the guard unmounts the filesystem.
#[derive(Debug)]
pub struct MountGuard {
    mountpoint: PathBuf,
    guard: platform::Guard,
}

impl MountGuard {
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Unmount immediately; equivalent to dropping the guard, but reports
    /// unmount failures.
    pub fn unmount(self) -> Result<(), MountError> {
        self.guard.unmount()
    }
}

impl DeviceFiles {
    /// Mount this AFC file tree at `mountpoint`, which must be an existing
    /// empty directory. The mount runs in the background until the returned
    /// guard is dropped. When the device disconnects, further file operations
    /// fail with `EIO` until the guard is dropped.
    ///
    /// This is a synchronous call: it only sets up the background session.
    pub fn mount(
        self,
        mountpoint: impl AsRef<Path>,
        options: MountOptions,
    ) -> Result<MountGuard, MountError> {
        let mountpoint = mountpoint.as_ref();
        debug!(mountpoint = %mountpoint.display(), "mounting device files");
        let guard = platform::mount(self, mountpoint, &options)?;
        Ok(MountGuard {
            mountpoint: mountpoint.to_path_buf(),
            guard,
        })
    }
}
