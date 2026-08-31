//! Pure conversions between AFC metadata and filesystem-level attributes.
//!
//! These mappings are platform-neutral so they can be tested without a FUSE
//! driver; the platform backend turns them into concrete kernel types.

use crate::{DeviceFileInfo, DeviceFileKind, ServiceError};

/// Filesystem entry kind as understood by the mount layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryKind {
    File,
    Directory,
    Symlink,
    /// AFC reported a type we do not model; exposed as a read-only file.
    Other,
}

/// Platform-neutral attributes for one device entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryAttr {
    pub(crate) ino: u64,
    pub(crate) kind: EntryKind,
    pub(crate) size: u64,
    pub(crate) perm: u16,
    pub(crate) modified_unix: i64,
}

pub(crate) const ROOT_INO: u64 = 1;
pub(crate) const DIR_PERM: u16 = 0o755;
pub(crate) const FILE_PERM: u16 = 0o644;
pub(crate) const OTHER_PERM: u16 = 0o600;

pub(crate) fn root_attr() -> EntryAttr {
    EntryAttr {
        ino: ROOT_INO,
        kind: EntryKind::Directory,
        size: 0,
        perm: DIR_PERM,
        modified_unix: 0,
    }
}

pub(crate) fn entry_attr(ino: u64, info: &DeviceFileInfo) -> EntryAttr {
    let (kind, perm) = match info.kind() {
        DeviceFileKind::File => (EntryKind::File, FILE_PERM),
        DeviceFileKind::Directory => (EntryKind::Directory, DIR_PERM),
        DeviceFileKind::Symlink => (EntryKind::Symlink, 0o777),
        DeviceFileKind::Other(_) => (EntryKind::Other, OTHER_PERM),
    };
    EntryAttr {
        ino,
        kind,
        size: info.size(),
        perm,
        modified_unix: info.modified_unix(),
    }
}

/// Portable classification of AFC failures for the FUSE backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotEmpty,
    NoSpace,
    IsDirectory,
    Invalid,
    Io,
}

pub(crate) fn fs_error_kind(error: &ServiceError) -> FsErrorKind {
    use idevice::services::afc::errors::AfcError;
    let ServiceError::Idevice(idevice::IdeviceError::Afc(afc)) = error else {
        return FsErrorKind::Io;
    };
    match afc {
        AfcError::ObjectNotFound => FsErrorKind::NotFound,
        AfcError::PermDenied => FsErrorKind::PermissionDenied,
        AfcError::ObjectExists => FsErrorKind::AlreadyExists,
        AfcError::DirNotEmpty => FsErrorKind::NotEmpty,
        AfcError::NoSpaceLeft => FsErrorKind::NoSpace,
        AfcError::ObjectIsDir => FsErrorKind::IsDirectory,
        AfcError::InvalidArg => FsErrorKind::Invalid,
        _ => FsErrorKind::Io,
    }
}

#[cfg(test)]
mod tests {
    use idevice::services::afc::errors::AfcError;

    use super::*;

    fn info(kind: DeviceFileKind, size: u64) -> DeviceFileInfo {
        DeviceFileInfo::new_for_test(size, kind, None, 1_700_000_000)
    }

    #[test]
    fn root_is_a_directory_with_fixed_inode() {
        let attr = root_attr();
        assert_eq!(attr.ino, ROOT_INO);
        assert_eq!(attr.kind, EntryKind::Directory);
        assert_eq!(attr.perm, DIR_PERM);
    }

    #[test]
    fn maps_afc_kinds_to_entry_attributes() {
        let attr = entry_attr(42, &info(DeviceFileKind::File, 128));
        assert_eq!(attr.kind, EntryKind::File);
        assert_eq!(attr.perm, FILE_PERM);
        assert_eq!(attr.size, 128);
        assert_eq!(attr.ino, 42);
        assert_eq!(attr.modified_unix, 1_700_000_000);

        let attr = entry_attr(7, &info(DeviceFileKind::Directory, 0));
        assert_eq!(attr.kind, EntryKind::Directory);
        assert_eq!(attr.perm, DIR_PERM);

        let attr = entry_attr(8, &info(DeviceFileKind::Symlink, 5));
        assert_eq!(attr.kind, EntryKind::Symlink);

        let attr = entry_attr(9, &info(DeviceFileKind::Other("S_IFSOCK".into()), 0));
        assert_eq!(attr.kind, EntryKind::Other);
        assert_eq!(attr.perm, OTHER_PERM);
    }

    #[test]
    fn maps_afc_errors_to_fs_error_kinds() {
        let cases = [
            (AfcError::ObjectNotFound, FsErrorKind::NotFound),
            (AfcError::PermDenied, FsErrorKind::PermissionDenied),
            (AfcError::ObjectExists, FsErrorKind::AlreadyExists),
            (AfcError::DirNotEmpty, FsErrorKind::NotEmpty),
            (AfcError::NoSpaceLeft, FsErrorKind::NoSpace),
            (AfcError::ObjectIsDir, FsErrorKind::IsDirectory),
            (AfcError::InvalidArg, FsErrorKind::Invalid),
            (AfcError::ReadError, FsErrorKind::Io),
        ];
        for (afc, expected) in cases {
            let error = ServiceError::from(idevice::IdeviceError::from(afc));
            assert_eq!(fs_error_kind(&error), expected);
        }
    }

    #[test]
    fn non_afc_failures_are_io_errors() {
        assert_eq!(
            fs_error_kind(&ServiceError::DeviceNotFound),
            FsErrorKind::Io
        );
    }
}
