use legacy_ios_assets::ResourceId;
use legacy_ios_image::apply_bsdiff;
use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};

use crate::KitError;

const DATA_ARK_PLIST: &[u8] = b"<plist><dict><key>com.apple.mobile.lockdown_cache-ActivationState</key><string>FactoryActivated</string></dict></plist>";
const LOCKDOWND: &str = "/usr/libexec/lockdownd";

/// How a device is hacktivated, mirroring upstream `device_hacktivate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HacktivateMethod {
    /// Drop a FactoryActivated data_ark.plist into Lockdown and reboot.
    DataArk,
    /// Patch lockdownd with the given bsdiff patch resource.
    LockdowndPatch(ResourceId),
}

/// Select the hacktivation method for a device, mirroring upstream's rules.
pub fn hacktivate_method(
    product_type: &str,
    version: &str,
    build: &str,
) -> Option<HacktivateMethod> {
    let major: u32 = version.split('.').next()?.parse().ok()?;
    let s5l8900 = matches!(product_type, "iPhone1,1" | "iPhone1,2" | "iPod1,1");
    if (product_type == "iPhone3,3" && version.starts_with("4.2"))
        || (product_type == "iPhone2,1" && version.starts_with("3.0"))
        || (s5l8900 && version.starts_with("3.") && version != "3.1.3")
        || major == 7
    {
        return Some(HacktivateMethod::DataArk);
    }
    // Non-A4+ 32-bit devices reuse the iPhone2,1 bundles with remapped builds.
    let proc4 = !s5l8900;
    let (bundle_type, bundle_build) =
        if proc4 && product_type != "iPhone2,1" && !version.starts_with("3.2") {
            let remapped = match version {
                "4.2.1" => "8C148a",
                "5.1.1" => "9B206",
                "6.1" => "10B141",
                other => return lockdownd_patch("iPhone2,1", other, build),
            };
            ("iPhone2,1", remapped)
        } else {
            (product_type, build)
        };
    lockdownd_patch(bundle_type, version, bundle_build)
}

fn lockdownd_patch(product_type: &str, version: &str, build: &str) -> Option<HacktivateMethod> {
    let id = format!(
        "lockdownd-patch-{}-{}-{}",
        product_type.replace(',', "-"),
        version,
        build
    );
    if legacy_ios_assets::ResourceCatalog::bundled()
        .get(&ResourceId::new(&id))
        .is_some()
    {
        Some(HacktivateMethod::LockdowndPatch(ResourceId::new(id)))
    } else {
        None
    }
}

/// Hacktivate a jailbroken device over SSH.
pub(crate) async fn hacktivate(
    ssh: &RamdiskSsh,
    method: &HacktivateMethod,
    patch: Option<&[u8]>,
) -> Result<(), KitError> {
    match method {
        HacktivateMethod::DataArk => {
            ssh.upload(
                &scp_path("/var/root/Library/Lockdown/data_ark.plist")?,
                DATA_ARK_PLIST,
            )
            .await?;
        }
        HacktivateMethod::LockdowndPatch(_) => {
            let patch = patch.ok_or(KitError::MissingHacktivationPatch)?;
            let existing = ssh
                .execute(&format!("ls {LOCKDOWND}.orig 2>/dev/null"))
                .await?;
            if !existing.stdout().is_empty() {
                return Err(KitError::AlreadyHacktivated);
            }
            let lockdownd = ssh
                .download(&scp_path(LOCKDOWND)?, 16 * 1024 * 1024)
                .await?;
            let patched = apply_bsdiff(&lockdownd, patch)?;
            run(
                ssh,
                &format!("[[ ! -e {LOCKDOWND}.orig ]] && mv {LOCKDOWND} {LOCKDOWND}.orig"),
            )
            .await?;
            ssh.upload(&scp_path(LOCKDOWND)?, &patched).await?;
            run(ssh, &format!("chmod +x {LOCKDOWND}")).await?;
        }
    }
    // The reboot drops the SSH session; a lost reply is expected.
    let _ = ssh.execute("reboot").await;
    Ok(())
}

/// Restore the original lockdownd, reverting hacktivation.
pub(crate) async fn revert_hacktivate(
    ssh: &RamdiskSsh,
    method: &HacktivateMethod,
    original: Option<&[u8]>,
) -> Result<(), KitError> {
    revert_device(ssh, method, original).await
}

trait RevertDevice {
    fn read_original(&self) -> impl std::future::Future<Output = Result<Vec<u8>, KitError>> + Send;
    fn replace(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), KitError>> + Send;
    fn cleanup(&self) -> impl std::future::Future<Output = Result<(), KitError>> + Send;
    fn reboot(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl RevertDevice for RamdiskSsh {
    async fn read_original(&self) -> Result<Vec<u8>, KitError> {
        self.download(&scp_path(&format!("{LOCKDOWND}.orig"))?, 16 * 1024 * 1024)
            .await
            .map_err(|_| KitError::MissingOriginalLockdownd)
    }
    async fn replace(&self, data: &[u8]) -> Result<(), KitError> {
        // Stage a complete executable before replacing the active daemon.
        self.upload(&scp_path("/usr/libexec/lockdownd.lik-restore")?, data)
            .await?;
        run(self, "chmod 755 /usr/libexec/lockdownd.lik-restore && mv /usr/libexec/lockdownd.lik-restore /usr/libexec/lockdownd").await
    }
    async fn cleanup(&self) -> Result<(), KitError> {
        run(
            self,
            "rm -f /usr/libexec/lockdownd.orig /var/root/Library/Lockdown/data_ark.plist",
        )
        .await
    }
    async fn reboot(&self) {
        let _ = self.execute("reboot").await;
    }
}

async fn revert_device(
    device: &impl RevertDevice,
    method: &HacktivateMethod,
    original: Option<&[u8]>,
) -> Result<(), KitError> {
    if matches!(method, HacktivateMethod::LockdowndPatch(_)) {
        let data = match original {
            Some(bytes) => bytes.to_vec(),
            None => device.read_original().await?,
        };
        validate_lockdownd(&data)?;
        device.replace(&data).await?;
    }
    device.cleanup().await?;
    device.reboot().await;
    Ok(())
}

fn validate_lockdownd(data: &[u8]) -> Result<(), KitError> {
    // The supported iOS 3-6 daemon is a 32-bit ARM Mach-O executable.
    if data.len() < 28
        || data[..4] != [0xce, 0xfa, 0xed, 0xfe]
        || data[4..8] != 12_u32.to_le_bytes()
        || data[12..16] != 2_u32.to_le_bytes()
    {
        return Err(KitError::InvalidOriginalLockdownd);
    }
    Ok(())
}

/// Extract a stock daemon from the exact device/version/build IPSW. All input
/// validation and decryption happens before the caller starts device writes.
pub async fn extract_original_lockdownd(
    firmware: std::path::PathBuf,
    product: legacy_ios_core::ProductType,
    board: legacy_ios_core::BoardConfig,
    version: legacy_ios_core::IosVersion,
    build: legacy_ios_core::BuildId,
    key: legacy_ios_image::DmgFirmwareKey,
) -> Result<Vec<u8>, KitError> {
    tokio::task::spawn_blocking(move || {
        let archive = legacy_ios_firmware::FirmwareArchive::open(firmware)?;
        let manifest = archive.build_manifest()?;
        if !manifest.supported_product_types().contains(&product)
            || manifest.product_version() != &version
            || manifest.build_id() != &build
        {
            return Err(KitError::OriginalFirmwareMismatch);
        }
        let identity =
            manifest.select_identity(&board, legacy_ios_firmware::RestoreBehavior::Erase)?;
        let root = identity.component_path("OS")?;
        let encrypted = archive.read_entry(root)?;
        let decrypted = legacy_ios_image::decrypt_firmware_image(&encrypted, &key)?;
        let image = legacy_ios_image::DmgImage::parse(decrypted)?;
        let index = image
            .partitions()
            .iter()
            .position(|part| part.name().contains("Apple_HFS"))
            .or_else(|| (image.partitions().len() == 1).then_some(0))
            .ok_or(KitError::MissingHfsPartition)?;
        let hfs = legacy_ios_image::HfsImage::parse(image.extract(index)?)?;
        let data = hfs.read("/usr/libexec/lockdownd")?;
        validate_lockdownd(&data)?;
        Ok(data)
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))?
}

async fn run(ssh: &RamdiskSsh, command: &str) -> Result<(), KitError> {
    let result = ssh.execute(command).await?;
    if !result.success() {
        return Err(KitError::Ssh(SshError::RemoteCommand(result.exit_status())));
    }
    Ok(())
}

fn scp_path(path: &str) -> Result<ScpPath, KitError> {
    ScpPath::new(path).map_err(|error| KitError::Ssh(SshError::Scp(error.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Device {
        calls: std::sync::Mutex<Vec<&'static str>>,
        backup: Option<Vec<u8>>,
        fail_replace: bool,
    }
    impl RevertDevice for Device {
        async fn read_original(&self) -> Result<Vec<u8>, KitError> {
            self.calls.lock().unwrap().push("read");
            self.backup
                .clone()
                .ok_or(KitError::MissingOriginalLockdownd)
        }
        async fn replace(&self, _: &[u8]) -> Result<(), KitError> {
            self.calls.lock().unwrap().push("replace");
            if self.fail_replace {
                return Err(KitError::InvalidOriginalLockdownd);
            }
            Ok(())
        }
        async fn cleanup(&self) -> Result<(), KitError> {
            self.calls.lock().unwrap().push("cleanup");
            Ok(())
        }
        async fn reboot(&self) {
            self.calls.lock().unwrap().push("reboot");
        }
    }
    fn device(backup: Option<Vec<u8>>) -> Device {
        Device {
            calls: Default::default(),
            backup,
            fail_replace: false,
        }
    }
    fn executable() -> Vec<u8> {
        let mut data = vec![0; 28];
        data[..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        data[4..8].copy_from_slice(&12_u32.to_le_bytes());
        data[12..16].copy_from_slice(&2_u32.to_le_bytes());
        data
    }

    #[tokio::test]
    async fn data_ark_revert_never_requires_or_replaces_lockdownd() {
        let device = device(None);
        revert_device(&device, &HacktivateMethod::DataArk, None)
            .await
            .unwrap();
        assert_eq!(*device.calls.lock().unwrap(), ["cleanup", "reboot"]);
    }

    #[tokio::test]
    async fn patch_revert_cleans_backup_only_after_replacement() {
        let method = HacktivateMethod::LockdowndPatch(ResourceId::new("test"));
        let device = device(Some(executable()));
        revert_device(&device, &method, None).await.unwrap();
        assert_eq!(
            *device.calls.lock().unwrap(),
            ["read", "replace", "cleanup", "reboot"]
        );
    }

    #[tokio::test]
    async fn missing_or_invalid_original_never_changes_device() {
        let method = HacktivateMethod::LockdowndPatch(ResourceId::new("test"));
        let missing = device(None);
        assert!(revert_device(&missing, &method, None).await.is_err());
        assert_eq!(*missing.calls.lock().unwrap(), ["read"]);
        let invalid = device(None);
        assert!(
            revert_device(&invalid, &method, Some(b"invalid"))
                .await
                .is_err()
        );
        assert!(invalid.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn caller_original_bypasses_missing_backup_and_write_failure_preserves_state() {
        let method = HacktivateMethod::LockdowndPatch(ResourceId::new("test"));
        let original = executable();
        let success = device(None);
        revert_device(&success, &method, Some(&original))
            .await
            .unwrap();
        assert_eq!(
            *success.calls.lock().unwrap(),
            ["replace", "cleanup", "reboot"]
        );
        let mut failed = device(None);
        failed.fail_replace = true;
        assert!(
            revert_device(&failed, &method, Some(&original))
                .await
                .is_err()
        );
        assert_eq!(*failed.calls.lock().unwrap(), ["replace"]);
    }

    #[test]
    fn selects_data_ark_fast_path() {
        assert_eq!(
            hacktivate_method("iPhone3,3", "4.2.10", "8E600"),
            Some(HacktivateMethod::DataArk)
        );
        assert_eq!(
            hacktivate_method("iPhone1,2", "3.0", "7A341"),
            Some(HacktivateMethod::DataArk)
        );
        assert_eq!(
            hacktivate_method("iPhone3,1", "7.1.2", "11D257"),
            Some(HacktivateMethod::DataArk)
        );
    }

    #[test]
    fn maps_proc4_devices_to_iphone21_bundles() {
        assert_eq!(
            hacktivate_method("iPod4,1", "6.1.3", "10B329"),
            Some(HacktivateMethod::LockdowndPatch(ResourceId::new(
                "lockdownd-patch-iPhone2-1-6.1.3-10B329"
            )))
        );
        assert_eq!(
            hacktivate_method("iPhone2,1", "6.1.3", "10B329"),
            Some(HacktivateMethod::LockdowndPatch(ResourceId::new(
                "lockdownd-patch-iPhone2-1-6.1.3-10B329"
            )))
        );
    }

    #[test]
    fn rejects_unsupported_combinations() {
        assert_eq!(hacktivate_method("iPhone4,1", "9.3.6", "13G37"), None);
        assert!(hacktivate_method("iPhone1,1", "3.1.3", "7E18").is_some());
    }
}
