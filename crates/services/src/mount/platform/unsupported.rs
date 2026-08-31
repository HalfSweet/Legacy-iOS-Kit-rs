//! Stub backend for platforms without a compiled FUSE backend (macOS,
//! Windows). Mounting reports an actionable host requirement instead of
//! failing to build on hosts without the system FUSE driver installed.

use std::path::Path;

use legacy_ios_transport::{HostRequirement, HostRequirementCode};

use super::super::{MountError, MountOptions};
use crate::DeviceFiles;

/// Never constructed: mounting always fails on this backend.
#[derive(Debug)]
pub(crate) struct Guard;

impl Guard {
    pub(crate) fn unmount(self) -> Result<(), MountError> {
        Ok(())
    }
}

pub(crate) fn mount(
    _files: DeviceFiles,
    _mountpoint: &Path,
    _options: &MountOptions,
) -> Result<Guard, MountError> {
    #[cfg(target_os = "macos")]
    {
        if Path::new("/Library/Filesystems/macfuse.fs").exists() {
            Err(MountError::Unsupported(
                "macFUSE is installed, but this build has no macFUSE backend; \
                 rebuild on a host with macFUSE available to enable mounting",
            ))
        } else {
            Err(MountError::DriverMissing(HostRequirement::new(
                HostRequirementCode::FuseDriver,
                "Install macFUSE (https://macfuse.io), then build lik on a host \
                 with macFUSE available to enable device mounts",
            )))
        }
    }
    #[cfg(target_os = "windows")]
    {
        Err(MountError::Unsupported(
            "mounting via WinFsp is not implemented in this build",
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(MountError::Unsupported(
            "mounting is not supported on this platform",
        ))
    }
}
