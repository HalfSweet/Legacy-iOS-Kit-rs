//! g1lbertJB: untethered jailbreak for A5/A5X devices on iOS 5.0-5.1.1.
//!
//! Ports the g1lbertJB C tool (unthreadedjb/unthredera1n descendant,
//! evasi0n/absinthe2-style userland chain over usbmuxd, no bootrom exploit):
//!
//! - Stage 1: move the user's media directories aside over AFC, pull the
//!   mobile.installation cache through file_relay, plant a fake system app
//!   (com.apple.DemoApp at /var/mobile/DemoApp.app) and trashed LaunchServices
//!   caches through an edited backup restored with a reboot, then wait for
//!   the device and SpringBoard to come back.
//! - Stage 2: two backup/restore rounds move a `Media/Recordings/.haxx`
//!   symlink to /var/db and swing /var/db/timezone onto /var/tmp/launchd and
//!   then /var/tmp/launchd/sock, crashing lockdownd after each restore so the
//!   launchd socket ends up world-writable.
//! - Interactive: the user runs the g1lbertJB home-screen icon, which runs
//!   the DemoApp launchd-submit script as root through that socket and
//!   remounts the root filesystem read/write; the host polls AFC for the
//!   resulting /mount.stderr marker.
//! - Stage 3: a final edited backup (`.haxx` -> / on the now-writable rootfs)
//!   plants /var/unthreadedjb (boot payload, launchd.conf, Cydia bootstrap,
//!   amfi bypass, patched dirhelper), the AutoInstall debs, and the
//!   /private/etc/launchd.conf + /usr/libexec/dirhelper symlinks; then the
//!   media directories are moved back and the device restarts.
//!
//! The per-build `jb` kernel payloads are downloaded data assets; they run on
//! the device at boot and are never regenerated here.

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use legacy_ios_assets::ResourceId;
use legacy_ios_core::{
    ActionId, ActionKind, CancellationSafety, OperationEvent, OperationId, OperationKind,
    OperationOutcome, OperationPhase, ProductType, Udid,
};
use legacy_ios_services::{
    ActivationState, AfcPath, BackupOptions, BackupRestoreOptions, DeviceFileKind, Mbdb,
    MbdbRecord, blob_name, mode,
};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{debug, info, warn};

use crate::{
    DeviceManager, KitError, OperationHandle, bootstrap::gunzip, lease::DeviceLeaseRegistry,
    operation::OperationEmitter,
};

const BACKUP_DOMAIN: &str = "MediaDomain";
const HACK_STORE: &str = "/HackStore";
/// Media directories moved aside so the backup restore can recreate
/// /Recordings with the `.haxx` symlink inside.
const MOVED_DIRECTORIES: [&str; 5] = ["/Books", "/DCIM", "/PhotoData", "/Photos", "/Recordings"];
const MOUNT_STDERR: &str = "/mount.stderr";
const MOUNT_STDOUT: &str = "/mount.stdout";
const CSSTORE_TRASH: &[u8] = b"LOLWUT";
/// The inode counter start used by the reference tool's backup.c.
const FIRST_INODE: u64 = 54327;
const LOCKDOWND_RESTART: Duration = Duration::from_secs(5);
const SPRINGBOARD_RETRIES: u32 = 20;
const SPRINGBOARD_INTERVAL: Duration = Duration::from_secs(3);
const REMOUNT_TIMEOUT: Duration = Duration::from_secs(600);
const REMOUNT_INTERVAL: Duration = Duration::from_secs(2);
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(300);
const RECONNECT_INTERVAL: Duration = Duration::from_secs(2);

/// (product type, hardware model, builds with an on-device payload), covering
/// exactly the A5/A5X iOS 5 payload set shipped by g1lbertJB. iPod5,1 never
/// shipped iOS 5 and is not supported.
const SUPPORT: &[(&str, &str, &[&str])] = &[
    (
        "iPhone4,1",
        "N94AP",
        &["9A334", "9A405", "9A406", "9B179", "9B206"],
    ),
    ("iPad2,1", "K93AP", &["9A334", "9A405", "9B176", "9B206"]),
    ("iPad2,2", "K94AP", &["9A334", "9A405", "9B176", "9B206"]),
    ("iPad2,3", "K95AP", &["9A334", "9A405", "9B176", "9B206"]),
    ("iPad2,4", "K93aAP", &["9B176", "9B206"]),
    ("iPad3,1", "J1AP", &["9B176", "9B206"]),
    ("iPad3,2", "J2AP", &["9B176", "9B206"]),
    ("iPad3,3", "J2aAP", &["9B176", "9B206"]),
];

fn hardware_model(product_type: &str) -> Option<&'static str> {
    SUPPORT
        .iter()
        .find(|(product, _, _)| *product == product_type)
        .map(|(_, model, _)| *model)
}

fn jb_resource(build: &str, hardware_model: &str) -> ResourceId {
    ResourceId::new(format!("gilbertjb-jb-{build}-{hardware_model}"))
}

/// Whether g1lbertJB supports this device, mirroring the payload set of the
/// reference tool: A5/A5X devices on iOS 5.0-5.1.1 builds only.
pub fn gilbertjb_support(
    product_type: &ProductType,
    version: &str,
    build: &str,
) -> Result<(), KitError> {
    let supported = hardware_model(product_type.as_str())
        .zip(Some(build))
        .filter(|_| version.starts_with("5."))
        .is_some_and(|(model, build)| {
            SUPPORT
                .iter()
                .any(|(_, m, builds)| *m == model && builds.contains(&build))
        });
    if supported {
        Ok(())
    } else {
        Err(KitError::GilbertJbUnsupported {
            product_type: product_type.to_string(),
            version: version.to_owned(),
            build: build.to_owned(),
        })
    }
}

/// A resolved, consent-ready g1lbertJB operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GilbertJbPlan {
    id: OperationId,
    udid: Udid,
    product_type: String,
    hardware_model: String,
    version: String,
    build: String,
}

impl GilbertJbPlan {
    pub const fn id(&self) -> OperationId {
        self.id
    }

    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    pub fn product_type(&self) -> &str {
        &self.product_type
    }

    pub fn hardware_model(&self) -> &str {
        &self.hardware_model
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }

    pub fn confirm_destructive(&self) -> GilbertJbConsent {
        GilbertJbConsent { plan: self.id }
    }
}

pub struct GilbertJbConsent {
    plan: OperationId,
}

pub(crate) async fn plan(devices: &DeviceManager, udid: Udid) -> Result<GilbertJbPlan, KitError> {
    let device = devices.find_normal(&udid).await?;
    let info = device.query_info().await?;
    gilbertjb_support(
        info.product_type(),
        info.product_version(),
        info.build_version(),
    )?;
    if device.activation_state().await? == ActivationState::Unactivated {
        return Err(KitError::GilbertJbUnactivated);
    }
    if device.will_encrypt_backup().await? {
        return Err(KitError::GilbertJbBackupEncrypted);
    }
    // com.apple.afc2 only answers on a jailbroken device; when it does,
    // refuse devices with a stashed /Applications or an existing untether.
    if let Ok(mut root) = device.root_files().await {
        let stashed = root
            .info(&afc_path("/Applications"))
            .await
            .is_ok_and(|info| matches!(info.kind(), DeviceFileKind::Symlink));
        let untethered = root
            .info(&afc_path("/private/etc/launchd.conf"))
            .await
            .is_ok();
        if stashed || untethered {
            return Err(KitError::GilbertJbAlreadyJailbroken);
        }
    }
    let hardware_model = hardware_model(info.product_type().as_str())
        .expect("support gate passed")
        .to_owned();
    info!(
        product_type = %info.product_type(),
        version = info.product_version(),
        build = info.build_version(),
        "planned g1lbertJB jailbreak"
    );
    Ok(GilbertJbPlan {
        id: OperationId::new(uuid::Uuid::new_v4().as_u128()),
        udid,
        product_type: info.product_type().to_string(),
        hardware_model,
        version: info.product_version().to_owned(),
        build: info.build_version().to_owned(),
    })
}

/// The downloaded payload set for one device.
struct Payloads {
    jb: Vec<u8>,
    launchd_conf: Vec<u8>,
    amfi: Vec<u8>,
    dirhelper: Vec<u8>,
    cydia_tar: Vec<u8>,
    demo_app: Vec<(String, Vec<u8>, u16)>,
    debs: Vec<(String, Vec<u8>)>,
}

async fn fetch_payloads(
    cache_root: PathBuf,
    build: &str,
    hardware_model: &str,
) -> Result<Payloads, KitError> {
    let fetch = |id: ResourceId| {
        let cache_root = cache_root.clone();
        async move {
            let path = crate::firmware::fetch_resource(&id, cache_root).await?;
            Ok::<Vec<u8>, KitError>(fs::read(path).await?)
        }
    };
    let demo_app = [
        ("gilbertjb-app-info-plist", "Info.plist", 0o644),
        ("gilbertjb-app-demoapp", "DemoApp", 0o755),
        ("gilbertjb-app-icon-72", "Icon-72.png", 0o644),
        ("gilbertjb-app-icon-72-2x", "Icon-72@2x.png", 0o644),
        ("gilbertjb-app-icon", "Icon.png", 0o644),
        ("gilbertjb-app-icon-2x", "Icon@2x.png", 0o644),
    ];
    let mut app_files = Vec::with_capacity(demo_app.len());
    for (resource, name, perm) in demo_app {
        app_files.push((
            name.to_owned(),
            fetch(ResourceId::new(resource)).await?,
            perm,
        ));
    }
    let debs = [
        ("gilbertjb-deb-openssl", "1-openssl.deb"),
        ("gilbertjb-deb-openssh", "2-openssh.deb"),
        ("gilbertjb-deb-substrate", "substrate4g1lbert.deb"),
        ("gilbertjb-deb-safemode", "safemode4g1lbert.deb"),
    ];
    let mut deb_files = Vec::with_capacity(debs.len());
    for (resource, name) in debs {
        deb_files.push((name.to_owned(), fetch(ResourceId::new(resource)).await?));
    }
    // Upstream copies the already-cataloged freeze.tar into the payload as
    // Cydia.tar; the catalog stores it gzipped.
    let freeze = fetch(ResourceId::new("jailbreak-bootstrap-freeze")).await?;
    Ok(Payloads {
        jb: fetch(jb_resource(build, hardware_model)).await?,
        launchd_conf: fetch(ResourceId::new("gilbertjb-launchd-conf")).await?,
        amfi: fetch(ResourceId::new("gilbertjb-amfi-dylib")).await?,
        dirhelper: fetch(ResourceId::new("gilbertjb-dirhelper")).await?,
        cydia_tar: gunzip(&freeze)?,
        demo_app: app_files,
        debs: deb_files,
    })
}

/// In-place edits of a device backup directory in the style of g1lbertJB's
/// backup.c: records are replaced by domain/path or appended, file contents
/// land in sha1-named blobs, and the stale Manifest.mbdx index is deleted on
/// write.
struct BackupEdit {
    records: Vec<MbdbRecord>,
    blobs: Vec<(String, Vec<u8>)>,
    next_inode: u64,
}

impl BackupEdit {
    async fn open(directory: &Path) -> Result<Self, KitError> {
        let mbdb = Mbdb::from_bytes(&fs::read(directory.join("Manifest.mbdb")).await?)?;
        Ok(Self {
            records: mbdb.records().to_vec(),
            blobs: Vec::new(),
            next_inode: FIRST_INODE,
        })
    }

    fn upsert(&mut self, record: MbdbRecord) {
        if let Some(existing) = self.records.iter_mut().find(|existing| {
            existing.domain() == record.domain() && existing.filename() == record.filename()
        }) {
            *existing = record;
        } else {
            self.records.push(record);
        }
    }

    fn base_record(&mut self, path: &str, mode: u16) -> MbdbRecord {
        self.next_inode += 1;
        MbdbRecord::new(BACKUP_DOMAIN, path, mode)
            .with_absent_markers()
            .with_inode(self.next_inode)
            .with_timestamps(now_unix(), now_unix(), now_unix())
    }

    /// Mirror of backup_mkdir: a directory record with the given permission
    /// bits, owner, and flag 4.
    fn mkdir(&mut self, path: &str, perm: u16, uid: u32, gid: u32) {
        let record = self
            .base_record(path, perm | mode::S_IFDIR)
            .with_owner(uid, gid);
        self.upsert(record);
    }

    /// Mirror of backup_symlink: a link record with mode 0120644 and flag 4.
    fn symlink(&mut self, path: &str, target: &str, uid: u32, gid: u32) {
        let record = self
            .base_record(path, mode::S_IFLNK | 0o644)
            .with_link(target)
            .with_owner(uid, gid);
        self.upsert(record);
    }

    /// Mirror of backup_add_file_from_data: a regular file record with no
    /// data hash, flag 4, and the contents stored in a blob file.
    fn add_file(&mut self, path: &str, contents: Vec<u8>, perm: u16, uid: u32, gid: u32) {
        let record = self
            .base_record(path, perm | mode::S_IFREG)
            .with_owner(uid, gid)
            .with_size(contents.len() as u64);
        self.blobs.push((blob_name(BACKUP_DOMAIN, path), contents));
        self.upsert(record);
    }

    /// Mirror of stage 2 (2/2): swing the `/var/db/timezone` symlink onto the
    /// launchd socket path, with uid/gid 0 and flag 0, keeping its inode.
    fn retarget_symlink(&mut self, path: &str, target: &str) -> Result<(), KitError> {
        let inode = self
            .records
            .iter()
            .find(|record| record.domain() == BACKUP_DOMAIN && record.filename() == path)
            .ok_or(KitError::GilbertJbInvalidDump(
                "the stage 2 symlink record is missing",
            ))?
            .inode();
        let record = MbdbRecord::new(BACKUP_DOMAIN, path, mode::S_IFLNK | 0o644)
            .with_absent_markers()
            .with_link(target)
            .with_inode(inode)
            .with_owner(0, 0)
            .with_flags(0)
            .with_timestamps(now_unix(), now_unix(), now_unix());
        self.upsert(record);
        Ok(())
    }

    async fn write_to(&self, directory: &Path) -> Result<(), KitError> {
        fs::write(
            directory.join("Manifest.mbdb"),
            Mbdb::new(self.records.clone()).to_bytes()?,
        )
        .await?;
        for (name, contents) in &self.blobs {
            fs::write(directory.join(name), contents).await?;
        }
        match fs::remove_file(directory.join("Manifest.mbdx")).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

/// Stage 1 records: the DemoApp bundle under `.haxx` (-> /var/mobile), the
/// patched installation plist, and the trashed LaunchServices caches.
fn stage1_edit(
    edit: &mut BackupEdit,
    payloads: &Payloads,
    installation: Vec<u8>,
    csstores: &[u32],
) {
    edit.mkdir("Media", 0o755, 501, 501);
    edit.mkdir("Media/Recordings", 0o755, 501, 501);
    edit.symlink("Media/Recordings/.haxx", "/var/mobile", 501, 501);
    edit.mkdir("Media/Recordings/.haxx/DemoApp.app", 0o755, 501, 501);
    for (name, contents, perm) in &payloads.demo_app {
        edit.add_file(
            &format!("Media/Recordings/.haxx/DemoApp.app/{name}"),
            contents.clone(),
            *perm,
            501,
            501,
        );
    }
    edit.add_file(
        "Media/Recordings/.haxx/Library/Caches/com.apple.mobile.installation.plist",
        installation,
        0o644,
        501,
        501,
    );
    for number in csstores {
        edit.add_file(
            &format!(
                "Media/Recordings/.haxx/Library/Caches/com.apple.LaunchServices-{number:03}.csstore"
            ),
            CSSTORE_TRASH.to_vec(),
            0o644,
            501,
            501,
        );
    }
}

/// Stage 2 (1/2) records: `/var/db/timezone` redirected at /var/tmp/launchd.
fn stage2_edit(edit: &mut BackupEdit) {
    edit.mkdir("Media", 0o755, 501, 501);
    edit.mkdir("Media/Recordings", 0o755, 501, 501);
    edit.symlink("Media/Recordings/.haxx", "/var/db/", 501, 501);
    edit.symlink(
        "Media/Recordings/.haxx/timezone",
        "/var/tmp/launchd",
        501,
        501,
    );
}

/// Stage 3 records: with the root filesystem writable, `.haxx` -> / plants
/// the unthreadedjb payload tree, the Cydia bootstrap and AutoInstall debs,
/// and the boot-time symlinks.
fn stage3_edit(edit: &mut BackupEdit, payloads: &Payloads) {
    edit.mkdir("Media", 0o755, 501, 501);
    edit.mkdir("Media/Recordings", 0o755, 501, 501);
    edit.symlink("Media/Recordings/.haxx", "/", 501, 501);
    edit.mkdir("Media/Recordings/.haxx/var/db/timezone", 0o777, 0, 0);
    edit.mkdir("Media/Recordings/.haxx/var/root", 0o755, 0, 0);
    edit.mkdir("Media/Recordings/.haxx/var/root/Media", 0o755, 0, 0);
    edit.mkdir("Media/Recordings/.haxx/var/root/Media/Cydia", 0o755, 0, 0);
    edit.mkdir(
        "Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall",
        0o755,
        0,
        0,
    );
    for (name, contents) in payloads.debs.iter().take(2) {
        edit.add_file(
            &format!("Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall/{name}"),
            contents.clone(),
            0o644,
            0,
            0,
        );
    }
    edit.mkdir("Media/Recordings/.haxx/var/unthreadedjb", 0o755, 0, 0);
    edit.add_file(
        "Media/Recordings/.haxx/var/unthreadedjb/jb",
        payloads.jb.clone(),
        0o755,
        0,
        0,
    );
    edit.add_file(
        "Media/Recordings/.haxx/var/unthreadedjb/launchd.conf",
        payloads.launchd_conf.clone(),
        0o644,
        0,
        0,
    );
    edit.symlink(
        "Media/Recordings/.haxx/private/etc/launchd.conf",
        "/private/var/unthreadedjb/launchd.conf",
        501,
        501,
    );
    edit.add_file(
        "Media/Recordings/.haxx/var/unthreadedjb/Cydia.tar",
        payloads.cydia_tar.clone(),
        0o644,
        501,
        501,
    );
    edit.add_file(
        "Media/Recordings/.haxx/var/unthreadedjb/amfi.dylib",
        payloads.amfi.clone(),
        0o755,
        0,
        0,
    );
    edit.add_file(
        "Media/Recordings/.haxx/var/unthreadedjb/dirhelper",
        payloads.dirhelper.clone(),
        0o755,
        0,
        0,
    );
    edit.symlink(
        "Media/Recordings/.haxx/usr/libexec/dirhelper",
        "/private/var/unthreadedjb/dirhelper",
        501,
        501,
    );
    edit.symlink(
        "Media/Recordings/.haxx/.g1lbert_installed",
        "/private/var/unthreadedjb/install",
        501,
        501,
    );
    // iOS 5 only: Cydia Substrate and Safe Mode.
    for (name, contents) in payloads.debs.iter().skip(2) {
        edit.add_file(
            &format!("Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall/{name}"),
            contents.clone(),
            0o644,
            0,
            0,
        );
    }
}

/// One entry of a cpio "newc" archive.
struct CpioEntry<'a> {
    name: &'a str,
    data: &'a [u8],
}

fn parse_cpio_newc(data: &[u8]) -> Result<Vec<CpioEntry<'_>>, KitError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    loop {
        let header = data
            .get(offset..offset + 110)
            .ok_or(KitError::GilbertJbInvalidDump(
                "the file relay cpio is truncated",
            ))?;
        if &header[..6] != b"070701" {
            return Err(KitError::GilbertJbInvalidDump(
                "the file relay cpio has a bad entry magic",
            ));
        }
        let field = |index: usize| -> Result<usize, KitError> {
            let start = 6 + index * 8;
            let hex = std::str::from_utf8(&header[start..start + 8])
                .map_err(|_| KitError::GilbertJbInvalidDump("the file relay cpio is not hex"))?;
            usize::from_str_radix(hex, 16)
                .map_err(|_| KitError::GilbertJbInvalidDump("the file relay cpio is not hex"))
        };
        let file_size = field(6)?;
        let name_size = field(11)?;
        let name_start = offset + 110;
        let name_bytes =
            data.get(name_start..name_start + name_size)
                .ok_or(KitError::GilbertJbInvalidDump(
                    "the file relay cpio is truncated",
                ))?;
        let name = std::str::from_utf8(&name_bytes[..name_bytes.len().saturating_sub(1)])
            .map_err(|_| KitError::GilbertJbInvalidDump("a cpio entry name is not UTF-8"))?;
        // Header+name and file data are padded to 4-byte boundaries.
        let data_start = (name_start + name_size).next_multiple_of(4);
        let data_end = data_start + file_size;
        let entry_data = data
            .get(data_start..data_end)
            .ok_or(KitError::GilbertJbInvalidDump(
                "the file relay cpio is truncated",
            ))?;
        offset = data_end.next_multiple_of(4);
        if name == "TRAILER!!!" {
            return Ok(entries);
        }
        entries.push(CpioEntry {
            name,
            data: entry_data,
        });
    }
}

/// Pull the mobile.installation cache plist and the LaunchServices csstore
/// numbers out of the gzipped cpio the file_relay "Caches" source returns.
/// Mirrors the reference tool, which looks under both var/mobile and
/// private/var/mobile and defaults to csstore 045 when none is found.
fn extract_caches(dump: &[u8]) -> Result<(Vec<u8>, Vec<u32>), KitError> {
    let cpio = gunzip(dump)?;
    let entries = parse_cpio_newc(&cpio)?;
    let installation = entries
        .iter()
        .find(|entry| {
            let name = entry.name.trim_start_matches("./");
            (name.starts_with("var/mobile/") || name.starts_with("private/var/mobile/"))
                && name.ends_with("Library/Caches/com.apple.mobile.installation.plist")
        })
        .ok_or(KitError::GilbertJbInvalidDump(
            "the file relay dump has no com.apple.mobile.installation.plist",
        ))?;
    let mut csstores: Vec<u32> = entries
        .iter()
        .filter_map(|entry| {
            let name = entry.name.rsplit('/').next()?;
            let digits = name
                .strip_prefix("com.apple.LaunchServices-")?
                .strip_suffix(".csstore")?;
            digits.parse().ok()
        })
        .collect();
    if csstores.is_empty() {
        csstores.push(45);
    }
    debug!(?csstores, "parsed file relay Caches dump");
    Ok((installation.data.to_vec(), csstores))
}

/// Point the fake system app com.apple.DemoApp at /var/mobile/DemoApp.app
/// with the launchd socket environment, mirroring plist edits in the
/// reference tool.
fn patch_installation_plist(installation: &[u8]) -> Result<Vec<u8>, KitError> {
    let mut value = Value::from_reader(Cursor::new(installation))?;
    let demo_app = value
        .as_dictionary_mut()
        .and_then(|root| root.get_mut("System"))
        .and_then(Value::as_dictionary_mut)
        .and_then(|system| system.get_mut("com.apple.DemoApp"))
        .and_then(Value::as_dictionary_mut)
        .ok_or(KitError::GilbertJbInvalidDump(
            "the installation plist has no System/com.apple.DemoApp entry",
        ))?;
    demo_app.remove("ApplicationType");
    demo_app.remove("SBAppTags");
    demo_app.insert("Path".into(), "/var/mobile/DemoApp.app".into());
    let mut environment = Dictionary::new();
    environment.insert(
        "LAUNCHD_SOCKET".into(),
        "/private/var/tmp/launchd/sock".into(),
    );
    demo_app.insert("EnvironmentVariables".into(), environment.into());
    let mut output = Vec::new();
    value.to_writer_binary(&mut output)?;
    Ok(output)
}

fn afc_path(path: &str) -> AfcPath {
    AfcPath::new(path).expect("static g1lbertJB AFC paths contain no NUL")
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u32::try_from(elapsed.as_secs()).ok())
        .unwrap_or(u32::MAX)
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    plan: GilbertJbPlan,
    consent: GilbertJbConsent,
    cache_root: PathBuf,
    work_directory: PathBuf,
) -> OperationHandle {
    let (emitter, handle) = OperationHandle::channel(32);
    tokio::spawn(async move {
        if let Err(error) = execute(
            &devices,
            &leases,
            &emitter,
            plan,
            consent,
            cache_root,
            work_directory,
        )
        .await
        {
            emitter.fail(error).await;
        }
    });
    handle
}

async fn execute(
    devices: &DeviceManager,
    leases: &DeviceLeaseRegistry,
    emitter: &OperationEmitter,
    plan: GilbertJbPlan,
    consent: GilbertJbConsent,
    cache_root: PathBuf,
    work_directory: PathBuf,
) -> Result<(), KitError> {
    if consent.plan != plan.id {
        return Err(KitError::GilbertJbConsentMismatch);
    }
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Preflight,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    let _lease = leases
        .acquire(legacy_ios_core::DeviceSelector::Udid(plan.udid.clone()))
        .await;
    if emitter.is_cancelled() {
        return Ok(());
    }

    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Downloading,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    let payloads = fetch_payloads(cache_root, &plan.build, &plan.hardware_model).await?;

    let backup_root = work_directory.join("g1lbertJB");
    let backup_dir = backup_root.join(plan.udid.as_str());
    let device = devices.find_normal(&plan.udid).await?;

    // Stage 1: move media dirs aside, dump the caches, plant DemoApp.
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::TransferringFilesystem,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    let mut files = device.files().await?;
    if files.list(&afc_path(HACK_STORE)).await.is_ok() {
        // A previous attempt left the store behind; move everything back and
        // ask for a re-run, like the reference tool's fix path (which also
        // restarts the device).
        move_back_media(&mut files).await?;
        drop(files);
        let _ = device.restart().await;
        return Err(KitError::GilbertJbCleanedUp);
    }
    files.create_dir(&afc_path(HACK_STORE)).await?;
    for directory in MOVED_DIRECTORIES {
        let source = afc_path(directory);
        if files.info(&source).await.is_ok() {
            files
                .rename(&source, &afc_path(&format!("{HACK_STORE}{directory}")))
                .await?;
        }
    }
    drop(files);

    let dump = device.file_relay_dump(&["Caches"]).await?;
    let (installation, csstores) = extract_caches(&dump)?;
    let installation = patch_installation_plist(&installation)?;

    fresh_backup(&device, &backup_root).await?;
    let mut edit = BackupEdit::open(&backup_dir).await?;
    stage1_edit(&mut edit, &payloads, installation, &csstores);
    edit.write_to(&backup_dir).await?;
    restore(&device, &backup_root, plan.udid.as_str(), true).await;
    deferred_cancellation(emitter).await;

    // Wait for the reboot and for SpringBoard to come up.
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::WaitingForDevice,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    let device = await_reconnect(devices, &plan.udid, emitter).await?;
    await_springboard(&device, emitter).await?;

    // Stage 2: swing /var/db/timezone onto the launchd socket in two
    // restore/crash rounds so it becomes world-writable.
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Restoring,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    device
        .files()
        .await?
        .remove(&afc_path("/Recordings"), true)
        .await?;
    fresh_backup(&device, &backup_root).await?;
    let mut edit = BackupEdit::open(&backup_dir).await?;
    stage2_edit(&mut edit);
    edit.write_to(&backup_dir).await?;
    restore(&device, &backup_root, plan.udid.as_str(), false).await;
    crash_lockdownd(&device).await;
    deferred_cancellation(emitter).await;

    let mut edit = BackupEdit::open(&backup_dir).await?;
    edit.retarget_symlink("Media/Recordings/.haxx/timezone", "/var/tmp/launchd/sock")?;
    edit.write_to(&backup_dir).await?;
    restore(&device, &backup_root, plan.udid.as_str(), false).await;
    crash_lockdownd(&device).await;
    deferred_cancellation(emitter).await;

    // Interactive: the user runs the g1lbertJB icon to remount the root
    // filesystem; poll for the remount marker instead of blocking on input.
    let mut files = device.files().await?;
    let _ = files.remove(&afc_path(MOUNT_STDERR), false).await;
    let _ = files.remove(&afc_path(MOUNT_STDOUT), false).await;
    emitter
        .emit(OperationEvent::ActionRequired {
            id: ActionId::new(1),
            action: ActionKind::RunJailbreakApp {
                name: "g1lbertJB".to_owned(),
            },
        })
        .await;
    if !await_remount(&mut files, emitter).await? {
        emitter
            .emit(OperationEvent::Warning {
                message:
                    "no /mount.stderr marker appeared; continuing anyway like the reference tool"
                        .to_owned(),
            })
            .await;
    }

    // Stage 3: plant the untether payload tree on the writable rootfs.
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Restoring,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    files.remove(&afc_path("/Recordings"), true).await?;
    drop(files);
    fresh_backup(&device, &backup_root).await?;
    let mut edit = BackupEdit::open(&backup_dir).await?;
    stage3_edit(&mut edit, &payloads);
    edit.write_to(&backup_dir).await?;
    restore(&device, &backup_root, plan.udid.as_str(), false).await;
    deferred_cancellation(emitter).await;

    // Move the user's media directories back and restart.
    let mut files = device.files().await?;
    move_back_media(&mut files).await?;
    drop(files);
    match fs::remove_dir_all(&backup_root).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Booting,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    devices.find_normal(&plan.udid).await?.restart().await?;
    emitter
        .emit(OperationEvent::Completed {
            outcome: OperationOutcome {
                operation: OperationKind::Jailbreak,
                summary: format!(
                    "jailbroke {} on iOS {} ({}) with g1lbertJB and restarted the device",
                    plan.product_type, plan.version, plan.build
                ),
            },
        })
        .await;
    Ok(())
}

/// Fresh full backup of the device into `backup_root/<udid>`, replacing any
/// previous attempt.
async fn fresh_backup(
    device: &legacy_ios_services::NormalDevice,
    backup_root: &Path,
) -> Result<(), KitError> {
    match fs::remove_dir_all(backup_root).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    device.backup(backup_root, BackupOptions::default()).await?;
    Ok(())
}

/// Restore the edited backup. The reference tool ignores the benign
/// mobilebackup2 error codes 1 and 102 that end these restores, so remote
/// errors are logged and tolerated while transport failures still abort.
async fn restore(
    device: &legacy_ios_services::NormalDevice,
    backup_root: &Path,
    udid: &str,
    reboot: bool,
) {
    let options = BackupRestoreOptions::default()
        .reboot(reboot)
        .copy_backup(false)
        .preserve_settings(false)
        .system_files(true);
    match device.restore_backup(backup_root, udid, options).await {
        Ok(outcome) => info!(
            files = outcome.files(),
            reboot, "restored the edited g1lbertJB backup"
        ),
        Err(error @ legacy_ios_services::BackupError::Remote { .. }) => {
            warn!(%error, reboot, "the device reported a benign restore error");
        }
        Err(error) => {
            warn!(%error, reboot, "the restore connection dropped");
        }
    }
}

/// Move every directory stored in /HackStore back to the media partition root
/// and remove the store, mirroring the reference tool's fix path.
async fn move_back_media(files: &mut legacy_ios_services::DeviceFiles) -> Result<(), KitError> {
    let store = afc_path(HACK_STORE);
    let entries = files.list(&store).await.unwrap_or_default();
    for entry in entries {
        let destination = afc_path(&format!("/{entry}"));
        let _ = files.remove(&destination, true).await;
        files
            .rename(&afc_path(&format!("{HACK_STORE}/{entry}")), &destination)
            .await?;
    }
    files.remove(&store, false).await?;
    info!("moved the media directories back from {HACK_STORE}");
    Ok(())
}

async fn crash_lockdownd(device: &legacy_ios_services::NormalDevice) {
    if let Err(error) = device.crash_lockdownd().await {
        warn!(%error, "failed to send the lockdownd crash packet");
    }
    debug!("waiting for lockdownd to restart");
    tokio::time::sleep(LOCKDOWND_RESTART).await;
}

async fn await_reconnect(
    devices: &DeviceManager,
    udid: &Udid,
    emitter: &OperationEmitter,
) -> Result<legacy_ios_services::NormalDevice, KitError> {
    let deadline = tokio::time::Instant::now() + RECONNECT_TIMEOUT;
    loop {
        if emitter.is_cancelled() {
            return Err(KitError::GilbertJbCancelled);
        }
        match devices.find_normal(udid).await {
            Ok(device) => {
                info!("device reconnected after the stage 1 reboot");
                return Ok(device);
            }
            Err(error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(KitError::VerificationTimeout);
                }
                debug!(%error, "waiting for the device to reconnect");
                tokio::time::sleep(RECONNECT_INTERVAL).await;
            }
        }
    }
}

/// Poll SpringBoard services until the icon state answers, like the
/// reference tool's 20-try sbservices loop.
async fn await_springboard(
    device: &legacy_ios_services::NormalDevice,
    emitter: &OperationEmitter,
) -> Result<(), KitError> {
    for _ in 0..SPRINGBOARD_RETRIES {
        if emitter.is_cancelled() {
            return Err(KitError::GilbertJbCancelled);
        }
        if device.icon_state().await.is_ok() {
            info!("SpringBoard is up after the stage 1 reboot");
            return Ok(());
        }
        tokio::time::sleep(SPRINGBOARD_INTERVAL).await;
    }
    Err(KitError::VerificationTimeout)
}

/// Poll AFC for the /mount.stderr marker the DemoApp remount script leaves
/// behind. Returns false when the marker never appeared.
async fn await_remount(
    files: &mut legacy_ios_services::DeviceFiles,
    emitter: &OperationEmitter,
) -> Result<bool, KitError> {
    let deadline = tokio::time::Instant::now() + REMOUNT_TIMEOUT;
    loop {
        if emitter.is_cancelled() {
            return Err(KitError::GilbertJbCancelled);
        }
        if files.info(&afc_path(MOUNT_STDERR)).await.is_ok() {
            info!("the device remounted the root filesystem read/write");
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(REMOUNT_INTERVAL).await;
    }
}

async fn deferred_cancellation(emitter: &OperationEmitter) {
    if emitter.is_cancelled() {
        emitter
            .emit(OperationEvent::CancellationDeferred {
                phase: OperationPhase::Restoring,
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_support(product: &str, version: &str, build: &str, ok: bool) {
        let result = gilbertjb_support(&ProductType::from(product), version, build);
        assert_eq!(result.is_ok(), ok, "{product} {version} ({build})");
    }

    #[test]
    fn gates_the_a5_ios5_matrix() {
        // Every payload directory of the reference tool is accepted.
        for (product, _, builds) in SUPPORT {
            for build in *builds {
                let version = if build.starts_with("9A") {
                    "5.0"
                } else {
                    "5.1.1"
                };
                assert_support(product, version, build, true);
            }
        }
        assert_support("iPhone4,1", "5.0", "9A334", true);
        assert_support("iPhone4,1", "5.1", "9B179", true);
        assert_support("iPad2,4", "5.1.1", "9B206", true);
        assert_support("iPad3,3", "5.1", "9B176", true);
    }

    #[test]
    fn rejects_unsupported_devices_and_builds() {
        // iPod5,1 never shipped iOS 5.
        assert_support("iPod5,1", "5.1.1", "9B206", false);
        // iPhone4,1 has no 9B176 payload (its 5.1 build is 9B179).
        assert_support("iPhone4,1", "5.1", "9B176", false);
        // iPad2,4 only shipped 5.1+.
        assert_support("iPad2,4", "5.0", "9A405", false);
        // iOS 6 builds are for the evasi0n/aquila paths, not this port.
        assert_support("iPhone4,1", "6.1.2", "10B146", false);
        // A4 and earlier are covered by other jailbreak paths.
        assert_support("iPhone3,1", "5.1.1", "9B206", false);
        // Non-iOS-5 version strings are rejected even for known builds.
        assert_support("iPhone4,1", "6.0", "9A334", false);
    }

    #[test]
    fn jb_resource_matches_the_payload_layout() {
        assert_eq!(
            jb_resource("9B206", "K93aAP").as_str(),
            "gilbertjb-jb-9B206-K93aAP"
        );
    }

    fn cpio_newc(entries: &[(&str, &[u8])]) -> Vec<u8> {
        fn push(archive: &mut Vec<u8>, name: &str, data: &[u8]) {
            let name = format!("{name}\0");
            let fields = [
                1u32,
                0o100644,
                0,
                0,
                1,
                0,
                data.len() as u32,
                0,
                0,
                0,
                0,
                name.len() as u32,
                0,
            ];
            let mut header = String::from("070701");
            for field in fields {
                header += &format!("{field:08X}");
            }
            archive.extend_from_slice(header.as_bytes());
            archive.extend_from_slice(name.as_bytes());
            while archive.len() % 4 != 0 {
                archive.push(0);
            }
            archive.extend_from_slice(data);
            while archive.len() % 4 != 0 {
                archive.push(0);
            }
        }
        let mut archive = Vec::new();
        for (name, data) in entries {
            push(&mut archive, name, data);
        }
        push(&mut archive, "TRAILER!!!", &[]);
        archive
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn parses_installation_plist_and_csstores_from_the_dump() {
        let cpio = cpio_newc(&[
            (
                "var/mobile/Library/Caches/com.apple.mobile.installation.plist",
                b"plist-bytes",
            ),
            (
                "var/mobile/Library/Caches/com.apple.LaunchServices-045.csstore",
                b"store",
            ),
            (
                "var/mobile/Library/Caches/com.apple.LaunchServices-072.csstore",
                b"store",
            ),
        ]);
        let (installation, csstores) = extract_caches(&gzip(&cpio)).unwrap();
        assert_eq!(installation, b"plist-bytes");
        assert_eq!(csstores, [45, 72]);
    }

    #[test]
    fn accepts_private_var_prefix_and_defaults_csstore() {
        let cpio = cpio_newc(&[(
            "private/var/mobile/Library/Caches/com.apple.mobile.installation.plist",
            b"plist-bytes",
        )]);
        let (installation, csstores) = extract_caches(&gzip(&cpio)).unwrap();
        assert_eq!(installation, b"plist-bytes");
        assert_eq!(csstores, [45]);
    }

    #[test]
    fn rejects_a_dump_without_the_installation_plist() {
        let cpio = cpio_newc(&[("var/mobile/Library/Caches/other", b"x")]);
        assert!(matches!(
            extract_caches(&gzip(&cpio)),
            Err(KitError::GilbertJbInvalidDump(_))
        ));
        assert!(parse_cpio_newc(b"not cpio").is_err());
    }

    #[test]
    fn rewrites_the_demo_app_entry() {
        let mut demo = Dictionary::new();
        demo.insert("ApplicationType".into(), "System".into());
        demo.insert("SBAppTags".into(), Value::Array(vec!["hidden".into()]));
        demo.insert("Path".into(), "/Applications/DemoApp.app".into());
        let mut system = Dictionary::new();
        system.insert("com.apple.DemoApp".into(), demo.into());
        let mut root = Dictionary::new();
        root.insert("System".into(), system.into());
        let mut source = Vec::new();
        Value::Dictionary(root)
            .to_writer_binary(&mut source)
            .unwrap();

        let patched = patch_installation_plist(&source).unwrap();
        let value = Value::from_reader(Cursor::new(patched)).unwrap();
        let demo = value
            .as_dictionary()
            .and_then(|root| root.get("System"))
            .and_then(Value::as_dictionary)
            .and_then(|system| system.get("com.apple.DemoApp"))
            .and_then(Value::as_dictionary)
            .unwrap();
        assert!(!demo.contains_key("ApplicationType"));
        assert!(!demo.contains_key("SBAppTags"));
        assert_eq!(
            demo.get("Path").and_then(Value::as_string),
            Some("/var/mobile/DemoApp.app")
        );
        assert_eq!(
            demo.get("EnvironmentVariables")
                .and_then(Value::as_dictionary)
                .and_then(|environment| environment.get("LAUNCHD_SOCKET"))
                .and_then(Value::as_string),
            Some("/private/var/tmp/launchd/sock")
        );
    }

    #[test]
    fn rejects_a_plist_without_demo_app() {
        let mut source = Vec::new();
        Value::Dictionary(Dictionary::new())
            .to_writer_binary(&mut source)
            .unwrap();
        assert!(matches!(
            patch_installation_plist(&source),
            Err(KitError::GilbertJbInvalidDump(_))
        ));
    }

    #[tokio::test]
    async fn stage_edits_build_the_reference_records() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("backup");
        fs::create_dir_all(&directory).await.unwrap();
        fs::write(directory.join("Manifest.mbdb"), b"mbdb\x05\x00")
            .await
            .unwrap();
        fs::write(directory.join("Manifest.mbdx"), b"mbdx\x05\x00")
            .await
            .unwrap();

        let payloads = Payloads {
            jb: b"jb".to_vec(),
            launchd_conf: b"launchd".to_vec(),
            amfi: b"amfi".to_vec(),
            dirhelper: b"dirhelper".to_vec(),
            cydia_tar: b"cydia".to_vec(),
            demo_app: vec![("DemoApp".to_owned(), b"script".to_vec(), 0o755)],
            debs: vec![
                ("1-openssl.deb".to_owned(), b"ssl".to_vec()),
                ("2-openssh.deb".to_owned(), b"ssh".to_vec()),
                ("substrate4g1lbert.deb".to_owned(), b"sub".to_vec()),
                ("safemode4g1lbert.deb".to_owned(), b"safe".to_vec()),
            ],
        };

        let mut edit = BackupEdit::open(&directory).await.unwrap();
        stage1_edit(&mut edit, &payloads, b"patched".to_vec(), &[45]);
        edit.write_to(&directory).await.unwrap();
        assert!(!directory.join("Manifest.mbdx").exists());
        let mbdb =
            Mbdb::from_bytes(&fs::read(directory.join("Manifest.mbdb")).await.unwrap()).unwrap();
        let record = |path: &str| {
            mbdb.records()
                .iter()
                .find(|record| record.filename() == path)
                .unwrap_or_else(|| panic!("missing record {path}"))
        };
        // The magic symlink: mode 0120644, flag 4, owned by mobile.
        let haxx = record("Media/Recordings/.haxx");
        assert_eq!(haxx.mode(), mode::S_IFLNK | 0o644);
        assert_eq!(haxx.link(), "/var/mobile");
        assert_eq!(haxx.flags(), 4);
        assert_eq!((haxx.user_id(), haxx.group_id()), (501, 501));
        // DemoApp payload files land in sha1-named blobs with flag 4.
        let demo = record("Media/Recordings/.haxx/DemoApp.app/DemoApp");
        assert_eq!(demo.mode(), mode::S_IFREG | 0o755);
        assert_eq!(demo.size(), 6);
        assert_eq!(demo.inode(), FIRST_INODE + 5);
        let blob = blob_name(BACKUP_DOMAIN, "Media/Recordings/.haxx/DemoApp.app/DemoApp");
        assert_eq!(fs::read(directory.join(blob)).await.unwrap(), b"script");
        assert!(
            record("Media/Recordings/.haxx/Library/Caches/com.apple.LaunchServices-045.csstore")
                .size()
                == 6
        );

        // Stage 2 (2/2): the retargeted symlink keeps its inode, drops the
        // flag, and switches to root ownership.
        let mut edit = BackupEdit::open(&directory).await.unwrap();
        stage2_edit(&mut edit);
        edit.write_to(&directory).await.unwrap();
        let mut edit = BackupEdit::open(&directory).await.unwrap();
        edit.retarget_symlink("Media/Recordings/.haxx/timezone", "/var/tmp/launchd/sock")
            .unwrap();
        edit.write_to(&directory).await.unwrap();
        let mbdb =
            Mbdb::from_bytes(&fs::read(directory.join("Manifest.mbdb")).await.unwrap()).unwrap();
        let timezone = mbdb
            .records()
            .iter()
            .find(|record| record.filename() == "Media/Recordings/.haxx/timezone")
            .unwrap();
        assert_eq!(timezone.mode(), mode::S_IFLNK | 0o644);
        assert_eq!(timezone.link(), "/var/tmp/launchd/sock");
        assert_eq!(timezone.flags(), 0);
        assert_eq!((timezone.user_id(), timezone.group_id()), (0, 0));
        assert_eq!(timezone.inode(), FIRST_INODE + 4);
        assert!(
            mbdb.records()
                .iter()
                .filter(|record| record.filename() == "Media/Recordings/.haxx/timezone")
                .count()
                == 1
        );

        // Stage 3: the payload tree and boot symlinks.
        let mut edit = BackupEdit::open(&directory).await.unwrap();
        stage3_edit(&mut edit, &payloads);
        edit.write_to(&directory).await.unwrap();
        let mbdb =
            Mbdb::from_bytes(&fs::read(directory.join("Manifest.mbdb")).await.unwrap()).unwrap();
        let record = |path: &str| {
            mbdb.records()
                .iter()
                .find(|record| record.filename() == path)
                .unwrap_or_else(|| panic!("missing record {path}"))
        };
        assert_eq!(record("Media/Recordings/.haxx").link(), "/");
        assert_eq!(
            record("Media/Recordings/.haxx/var/db/timezone").mode(),
            mode::S_IFDIR | 0o777
        );
        let jb = record("Media/Recordings/.haxx/var/unthreadedjb/jb");
        assert_eq!(jb.mode(), mode::S_IFREG | 0o755);
        assert_eq!((jb.user_id(), jb.group_id()), (0, 0));
        assert_eq!(
            record("Media/Recordings/.haxx/private/etc/launchd.conf").link(),
            "/private/var/unthreadedjb/launchd.conf"
        );
        assert_eq!(
            record("Media/Recordings/.haxx/usr/libexec/dirhelper").link(),
            "/private/var/unthreadedjb/dirhelper"
        );
        assert_eq!(
            record("Media/Recordings/.haxx/.g1lbert_installed").link(),
            "/private/var/unthreadedjb/install"
        );
        for deb in [
            "1-openssl.deb",
            "2-openssh.deb",
            "substrate4g1lbert.deb",
            "safemode4g1lbert.deb",
        ] {
            record(&format!(
                "Media/Recordings/.haxx/var/root/Media/Cydia/AutoInstall/{deb}"
            ));
        }
    }
}
