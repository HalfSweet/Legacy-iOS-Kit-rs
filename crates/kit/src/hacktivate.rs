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
    original: Option<&[u8]>,
) -> Result<(), KitError> {
    let lockdownd = match original {
        Some(bytes) => bytes.to_vec(),
        None => ssh
            .download(&scp_path(&format!("{LOCKDOWND}.orig"))?, 16 * 1024 * 1024)
            .await
            .map_err(|_| KitError::MissingOriginalLockdownd)?,
    };
    ssh.upload(&scp_path(LOCKDOWND)?, &lockdownd).await?;
    run(ssh, &format!("chmod +x {LOCKDOWND}")).await?;
    let _ = ssh.execute("reboot").await;
    Ok(())
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
