//! Stub backend for platforms without a compiled FUSE backend (macOS builds
//! without the `macfuse` feature, Windows). Mounting reports an actionable
//! host requirement instead of failing to build on hosts without the system
//! FUSE driver installed.

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

#[cfg(target_os = "macos")]
fn macos_error() -> MountError {
    macos_error_for(Path::new("/Library/Filesystems/macfuse.fs").exists())
}

#[cfg(target_os = "macos")]
fn macos_error_for(macfuse_installed: bool) -> MountError {
    if macfuse_installed {
        MountError::Unsupported(
            "macFUSE is installed, but this build has no macFUSE backend; \
             rebuild with the `macfuse` feature (`cargo build --features \
             legacy-ios-kit-cli/macfuse`) to enable mounting",
        )
    } else {
        MountError::DriverMissing(HostRequirement::new(
            HostRequirementCode::FuseDriver,
            "Install macFUSE (https://macfuse.io), then rebuild with the \
             `macfuse` feature to enable device mounts",
        ))
    }
}

pub(crate) fn mount(
    _files: DeviceFiles,
    _mountpoint: &Path,
    _options: &MountOptions,
) -> Result<Guard, MountError> {
    #[cfg(target_os = "macos")]
    {
        Err(macos_error())
    }
    #[cfg(target_os = "windows")]
    {
        Err(MountError::Unsupported(
            "mounting via WinFsp is not supported: fuser 0.18 has no Windows \
             backend",
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(MountError::Unsupported(
            "mounting is not supported on this platform",
        ))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn macos_error_with_macfuse_installed_points_at_feature() {
        let MountError::Unsupported(message) = macos_error_for(true) else {
            panic!("expected Unsupported");
        };
        assert!(message.contains("macfuse"));
    }

    #[test]
    fn macos_error_without_macfuse_reports_host_requirement() {
        let MountError::DriverMissing(requirement) = macos_error_for(false) else {
            panic!("expected DriverMissing");
        };
        assert_eq!(requirement.code(), HostRequirementCode::FuseDriver);
        assert!(requirement.message().contains("macfuse"));
    }
}
