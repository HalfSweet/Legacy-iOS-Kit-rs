//! FUSE backend: exposes an AFC file tree through the kernel filesystem
//! interface using `fuser` against the system FUSE driver.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BackgroundSession, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType,
    Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenAccMode, OpenFlags,
    RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyStatfs, ReplyWrite, Request, SessionACL, TimeOrNow, WriteFlags,
};
use legacy_ios_transport::{HostRequirement, HostRequirementCode};
use tracing::{debug, info, trace, warn};

use super::super::attr::{EntryAttr, EntryKind, FsErrorKind, entry_attr, root_attr};
use super::super::bridge::AfcBridge;
use super::super::inode::InodeTable;
use super::super::{MountError, MountOptions};
use crate::{AfcPath, DeviceFiles};

const ATTR_TTL: Duration = Duration::from_secs(1);

fn errno(kind: FsErrorKind) -> Errno {
    match kind {
        FsErrorKind::NotFound => Errno::ENOENT,
        FsErrorKind::PermissionDenied => Errno::EACCES,
        FsErrorKind::AlreadyExists => Errno::EEXIST,
        FsErrorKind::NotEmpty => Errno::ENOTEMPTY,
        FsErrorKind::NoSpace => Errno::ENOSPC,
        FsErrorKind::IsDirectory => Errno::EISDIR,
        FsErrorKind::Invalid => Errno::EINVAL,
        FsErrorKind::Io => Errno::EIO,
    }
}

fn file_type(kind: EntryKind) -> FileType {
    match kind {
        EntryKind::File | EntryKind::Other => FileType::RegularFile,
        EntryKind::Directory => FileType::Directory,
        EntryKind::Symlink => FileType::Symlink,
    }
}

fn file_attr(attr: EntryAttr) -> FileAttr {
    let modified = if attr.modified_unix > 0 {
        UNIX_EPOCH + Duration::from_secs(attr.modified_unix as u64)
    } else {
        UNIX_EPOCH
    };
    FileAttr {
        ino: INodeNo(attr.ino),
        size: attr.size,
        blocks: attr.size.div_ceil(512),
        atime: modified,
        mtime: modified,
        ctime: modified,
        crtime: modified,
        kind: file_type(attr.kind),
        perm: attr.perm,
        nlink: u32::from(attr.kind == EntryKind::Directory) + 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

struct AfcFs {
    bridge: AfcBridge,
    inodes: Mutex<InodeTable>,
    read_only: bool,
}

impl AfcFs {
    fn inodes(&self) -> MutexGuard<'_, InodeTable> {
        self.inodes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Resolve an inode to a validated AFC path.
    fn resolve(&self, ino: INodeNo) -> Result<AfcPath, Errno> {
        let table = self.inodes();
        let path = table.path(ino.0).ok_or(Errno::ENOENT)?;
        // Table entries are built from kernel-supplied path components and can
        // never contain NUL, so validation is infallible here.
        AfcPath::new(path).map_err(|_| Errno::EINVAL)
    }

    fn child_path(&self, parent: INodeNo, name: &OsStr) -> Result<String, Errno> {
        let name = name.to_str().ok_or(Errno::EINVAL)?;
        if name.contains('/') {
            return Err(Errno::EINVAL);
        }
        self.inodes()
            .child_path(parent.0, name)
            .ok_or(Errno::ENOENT)
    }

    fn child_afc_path(&self, parent: INodeNo, name: &OsStr) -> Result<(String, AfcPath), Errno> {
        let path = self.child_path(parent, name)?;
        let afc = AfcPath::new(path.clone()).map_err(|_| Errno::EINVAL)?;
        Ok((path, afc))
    }

    fn attr_reply(&self, ino: INodeNo) -> Result<FileAttr, Errno> {
        if ino.0 == super::super::attr::ROOT_INO {
            return Ok(file_attr(root_attr()));
        }
        let path = self.resolve(ino)?;
        let info = self.bridge.info(path).map_err(errno)?;
        Ok(file_attr(entry_attr(ino.0, &info)))
    }

    fn deny_write(&self) -> Option<Errno> {
        self.read_only.then_some(Errno::EROFS)
    }
}

impl Filesystem for AfcFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let (path, afc) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        match self.bridge.info(afc) {
            Ok(info) => {
                let ino = self.inodes().intern(&path);
                trace!(ino, path, "lookup");
                reply.entry(&ATTR_TTL, &file_attr(entry_attr(ino, &info)), Generation(0));
            }
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr_reply(ino) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(err) => reply.error(err),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(size) = size {
            if let Some(err) = self.deny_write() {
                return reply.error(err);
            }
            if size != 0 {
                // AFC has no truncate-to-length operation; only full truncate
                // via reopen is available.
                return reply.error(Errno::ENOSYS);
            }
            let path = match self.resolve(ino) {
                Ok(path) => path,
                Err(err) => return reply.error(err),
            };
            if let Err(kind) = self.bridge.create_file(path) {
                return reply.error(errno(kind));
            }
        }
        // Other attribute changes (mode, owner, timestamps) cannot be applied
        // over AFC; report the current attributes instead of failing tools
        // that set them optimistically.
        match self.attr_reply(ino) {
            Ok(attr) => reply.attr(&ATTR_TTL, &attr),
            Err(err) => reply.error(err),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let path = match self.resolve(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        match self.bridge.info(path) {
            Ok(info) => match info.link_target() {
                Some(target) => reply.data(target.as_bytes()),
                None => reply.error(Errno::EINVAL),
            },
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        let (path, afc) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        if let Err(kind) = self.bridge.create_dir(afc) {
            return reply.error(errno(kind));
        }
        let dir = match AfcPath::new(path.clone()) {
            Ok(dir) => dir,
            Err(_) => return reply.error(Errno::EINVAL),
        };
        match self.bridge.info(dir) {
            Ok(info) => {
                let ino = self.inodes().intern(&path);
                reply.entry(&ATTR_TTL, &file_attr(entry_attr(ino, &info)), Generation(0));
            }
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        let (_, afc) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        match self.bridge.remove(afc) {
            Ok(()) => reply.ok(),
            Err(FsErrorKind::IsDirectory) => reply.error(Errno::EISDIR),
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        let (_, afc) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        match self.bridge.remove(afc) {
            Ok(()) => reply.ok(),
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        if !flags.is_empty() {
            return reply.error(Errno::EINVAL);
        }
        let (from_path, from) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        let (to_path, to) = match self.child_afc_path(newparent, newname) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        match self.bridge.rename(from, to) {
            Ok(()) => {
                debug!(from = from_path, to = to_path, "renamed device path");
                reply.ok();
            }
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if self.read_only && flags.acc_mode() != OpenAccMode::O_RDONLY {
            return reply.error(Errno::EROFS);
        }
        match self.attr_reply(ino) {
            Ok(attr) if attr.kind == FileType::Directory => reply.error(Errno::EISDIR),
            Ok(_) => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Err(err) => reply.error(err),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let path = match self.resolve(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        match self.bridge.read(path, offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        let path = match self.resolve(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        match self.bridge.write(path, offset, data.to_vec()) {
            Ok(()) => reply.written(data.len() as u32),
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.attr_reply(ino) {
            Ok(attr) if attr.kind != FileType::Directory => reply.error(Errno::ENOTDIR),
            Ok(_) => reply.opened(FileHandle(ino.0), FopenFlags::empty()),
            Err(err) => reply.error(err),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        let path = match self.resolve(ino) {
            Ok(path) => path,
            Err(err) => return reply.error(err),
        };
        let parent_ino = self
            .inodes()
            .parent_ino(ino.0)
            .map(INodeNo)
            .unwrap_or(INodeNo::ROOT);
        let names = match self.bridge.list(path) {
            Ok(names) => names,
            Err(kind) => return reply.error(errno(kind)),
        };
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_owned()),
            (parent_ino, FileType::Directory, "..".to_owned()),
        ];
        for name in names {
            let child = match self.inodes().child_path(ino.0, &name) {
                Some(child) => child,
                None => continue,
            };
            let child_afc = match AfcPath::new(child.clone()) {
                Ok(path) => path,
                Err(_) => continue,
            };
            // A vanished or unreadable child is skipped rather than failing
            // the whole listing.
            let Ok(info) = self.bridge.info(child_afc) else {
                continue;
            };
            let child_ino = INodeNo(self.inodes().intern(&child));
            entries.push((
                child_ino,
                file_type(entry_attr(child_ino.0, &info).kind),
                name,
            ));
        }
        let mut reply = reply;
        for (index, (child_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*child_ino, (index + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match self.bridge.storage() {
            Ok(info) => {
                let block_size = u32::try_from(info.block_size()).unwrap_or(4096).max(512);
                let bsize = u64::from(block_size);
                reply.statfs(
                    info.total_bytes() / bsize,
                    info.free_bytes() / bsize,
                    info.free_bytes() / bsize,
                    0,
                    0,
                    block_size,
                    255,
                    block_size,
                );
            }
            Err(kind) => reply.error(errno(kind)),
        }
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if let Some(err) = self.deny_write() {
            return reply.error(err);
        }
        let (path, afc) = match self.child_afc_path(parent, name) {
            Ok(value) => value,
            Err(err) => return reply.error(err),
        };
        if let Err(kind) = self.bridge.create_file(afc) {
            return reply.error(errno(kind));
        }
        let file = match AfcPath::new(path.clone()) {
            Ok(file) => file,
            Err(_) => return reply.error(Errno::EINVAL),
        };
        match self.bridge.info(file) {
            Ok(info) => {
                let ino = self.inodes().intern(&path);
                reply.created(
                    &ATTR_TTL,
                    &file_attr(entry_attr(ino, &info)),
                    Generation(0),
                    FileHandle(ino),
                    FopenFlags::empty(),
                );
            }
            Err(kind) => reply.error(errno(kind)),
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_fuse_driver() -> Result<(), MountError> {
    if Path::new("/dev/fuse").exists() {
        return Ok(());
    }
    Err(MountError::DriverMissing(HostRequirement::new(
        HostRequirementCode::FuseDriver,
        "Load the fuse kernel module and install the FUSE userspace package \
         (e.g. fuse3), then retry the mount",
    )))
}

#[cfg(target_os = "macos")]
fn ensure_fuse_driver() -> Result<(), MountError> {
    if Path::new("/Library/Filesystems/macfuse.fs").exists() {
        return Ok(());
    }
    Err(MountError::DriverMissing(HostRequirement::new(
        HostRequirementCode::FuseDriver,
        "Install macFUSE (https://macfuse.io), then retry the mount",
    )))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_fuse_driver() -> Result<(), MountError> {
    Ok(())
}

fn validate_mountpoint(mountpoint: &Path) -> Result<(), MountError> {
    let invalid = |reason: &str| MountError::InvalidMountPoint {
        path: mountpoint.to_path_buf(),
        reason: reason.to_owned(),
    };
    let metadata = std::fs::metadata(mountpoint)
        .map_err(|_| invalid("directory does not exist or is not accessible"))?;
    if !metadata.is_dir() {
        return Err(invalid("not a directory"));
    }
    if std::fs::read_dir(mountpoint)
        .map_err(|_| invalid("directory is not readable"))?
        .next()
        .is_some()
    {
        return Err(invalid("directory is not empty"));
    }
    Ok(())
}

fn spawn_error(error: std::io::Error) -> MountError {
    match error.kind() {
        std::io::ErrorKind::NotFound => MountError::DriverMissing(HostRequirement::new(
            HostRequirementCode::FuseDriver,
            "The system FUSE device is unavailable; install the FUSE driver \
             package for this platform, then retry the mount",
        )),
        std::io::ErrorKind::PermissionDenied => MountError::PermissionDenied(error),
        _ => MountError::Session(error),
    }
}

/// Active mount session; unmounts on drop.
#[derive(Debug)]
pub(crate) struct Guard {
    session: Option<BackgroundSession>,
}

impl Guard {
    pub(crate) fn unmount(mut self) -> Result<(), MountError> {
        match self.session.take() {
            Some(session) => session.join().map_err(MountError::Session),
            None => Ok(()),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take()
            && let Err(error) = session.join()
        {
            warn!(%error, "failed to unmount FUSE session cleanly");
        }
    }
}

pub(crate) fn mount(
    files: DeviceFiles,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<Guard, MountError> {
    ensure_fuse_driver()?;
    validate_mountpoint(mountpoint)?;
    let bridge = AfcBridge::spawn(files).map_err(MountError::Session)?;
    let filesystem = AfcFs {
        bridge,
        inodes: Mutex::new(InodeTable::new()),
        read_only: options.is_read_only(),
    };
    let mut mount_options = vec![
        MountOption::FSName("lik-afc".to_owned()),
        MountOption::Subtype("likafc".to_owned()),
    ];
    if options.is_read_only() {
        mount_options.push(MountOption::RO);
    }
    // Config is non-exhaustive, so it is built by field assignment.
    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = SessionACL::Owner;
    let session = fuser::spawn_mount(filesystem, mountpoint, &config).map_err(spawn_error)?;
    info!(mountpoint = %mountpoint.display(), read_only = options.is_read_only(), "mounted device files");
    Ok(Guard {
        session: Some(session),
    })
}
