//! FourThree dualboot (iOS 8.4.1 + 4.3.x) for the iPad 2, mirroring upstream's
//! `device_fourthree_*` flows.
//!
//! Step 1 (building the custom 8.4.1 IPSW and the patched 4.3.x kernelcache,
//! LLB, and RootFS, upstream `ipsw_prepare_fourthree*`) is not implemented
//! yet; the patched components are produced externally and passed to step 3.
//! Steps 2 and 3 run over SSH against a jailbroken normal-mode device.

use legacy_ios_assets::ResourceId;
use legacy_ios_image::apply_bsdiff;
use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};
use tracing::info;

use crate::KitError;

/// Base (dualbooted) iOS versions supported by FourThree.
pub const FOURTHREE_BASE_VERSIONS: [&str; 6] = ["4.3", "4.3.1", "4.3.2", "4.3.3", "4.3.4", "4.3.5"];
/// iOS version of the target (primary) system the base system boots from.
pub const FOURTHREE_TARGET_VERSION: &str = "6.1.3";
/// Fixed size in bytes of the 4.3.x system partition created by TwistedMind2.
const TWISTED_MIND2_SYSTEM_SIZE: u64 = 879_124_480;
const KERNELCACHEB: &str = "/System/Library/Caches/com.apple.kernelcaches/kernelcachb";
const LOCKDOWND: &str = "/mnt1/usr/libexec/lockdownd";

/// Highest FourThree step completed on the device, mirroring upstream
/// `device_fourthree_check`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourThreeStep {
    /// Step 1: the device is restored to iOS 8.4.1 (/dev/disk0s2s1 exists).
    Restore,
    /// Step 2: TwistedMind2 created the 4.3.x partitions (/dev/disk0s3).
    Partition,
    /// Step 3: kernelcache and LLB are in place; dualboot is ready.
    DualBoot,
}

impl FourThreeStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Partition => "partition",
            Self::DualBoot => "dualboot",
        }
    }
}

/// FourThree bsdiff patch components registered in the resource catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FourThreePatch {
    Llb,
    Kernelcache,
    RestoreDeviceTree,
    IBoot,
}

impl FourThreePatch {
    fn file_stem(self, board: &str) -> String {
        match self {
            Self::Llb => format!("LLB.{board}.RELEASE"),
            Self::Kernelcache => "kernelcache.release".to_owned(),
            Self::RestoreDeviceTree => "RestoreDeviceTree".to_owned(),
            Self::IBoot => format!("iBoot.{board}.RELEASE"),
        }
    }
}

/// Map a FourThree-capable product type to its board config (k93ap/k94ap/k95ap).
pub fn fourthree_board_config(product_type: &str) -> Option<&'static str> {
    match product_type {
        "iPad2,1" => Some("k93ap"),
        "iPad2,2" => Some("k94ap"),
        "iPad2,3" => Some("k95ap"),
        _ => None,
    }
}

/// Resource id of a FourThree bsdiff patch for a device/version/component,
/// mirroring the upstream `resources/patch/fourthree` layout. Returns `None`
/// for unsupported devices or a version that does not carry the component.
pub fn fourthree_patch_id(
    product_type: &str,
    version: &str,
    component: FourThreePatch,
) -> Option<ResourceId> {
    let board = fourthree_board_config(product_type)?;
    let valid = match component {
        FourThreePatch::Llb | FourThreePatch::Kernelcache => {
            FOURTHREE_BASE_VERSIONS.contains(&version)
        }
        FourThreePatch::RestoreDeviceTree | FourThreePatch::IBoot => {
            version == FOURTHREE_TARGET_VERSION
        }
    };
    if !valid {
        return None;
    }
    Some(ResourceId::new(format!(
        "fourthree-patch-{}-{version}-{}",
        product_type.replace(',', "-"),
        component.file_stem(board)
    )))
}

/// Resource id of the lockdownd patch FourThree step 3 applies on cellular
/// iPad 2 models, reusing the iPhone2,1 hacktivation bundles like upstream.
pub fn fourthree_lockdownd_patch_id(base_version: &str, base_build: &str) -> ResourceId {
    ResourceId::new(format!(
        "lockdownd-patch-iPhone2-1-{base_version}-{base_build}"
    ))
}

/// Bytes to leave for the iOS 6.1.3 data partition, given the user's GB
/// choice. Sizes outside 1..=64 GB are rejected.
pub fn fourthree_data_partition_bytes(size_gb: u32) -> Option<u64> {
    if (1..=64).contains(&size_gb) {
        Some(u64::from(size_gb) * 1024 * 1024 * 1024)
    } else {
        None
    }
}

/// A file produced by the on-device TwistedMind2 partitioner, pulled back to
/// the host to boot the step 3 ramdisk.
pub struct TwistedMind2Output {
    name: String,
    data: Vec<u8>,
}

impl TwistedMind2Output {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Optional OpenSSH payload for the 4.3.x system, mirroring upstream's
/// `ipsw_openssh` branch (decompressed tars).
pub struct FourThreeOpenSsh {
    pub sshdeb: Vec<u8>,
    pub openssh: Vec<u8>,
    pub openssl: Vec<u8>,
}

/// Resolved package bytes for FourThree step 3.
pub struct FourThreeStep3Packages {
    /// Rebuilt 4.3.x RootFS.dmg restored onto /dev/disk0s3.
    pub rootfs_dmg: Vec<u8>,
    /// Patched decrypted 4.3.x kernelcache, installed as kernelcachb.
    pub kernelcache: Vec<u8>,
    /// Patched 4.3.x LLB payload, installed at /LLB.
    pub llb: Vec<u8>,
    /// Decompressed freeze.tar Cydia bootstrap.
    pub freeze: Vec<u8>,
    /// fourthree.tar companion app.
    pub app: Vec<u8>,
    /// lockdownd bsdiff patch; required on every model except iPad2,1.
    pub lockdownd_patch: Option<Vec<u8>>,
    pub openssh: Option<FourThreeOpenSsh>,
}

/// Query the highest completed FourThree step on the device, mirroring
/// upstream `device_fourthree_check`. Errors when step 1 is missing.
pub(crate) async fn check(ssh: &RamdiskSsh) -> Result<FourThreeStep, KitError> {
    if !path_exists(ssh, "/dev/disk0s2s1").await? {
        return Err(KitError::FourThreeRestoreIncomplete);
    }
    if !path_exists(ssh, "/dev/disk0s3").await? {
        return Ok(FourThreeStep::Restore);
    }
    let kernelcache = path_exists(ssh, KERNELCACHEB).await?;
    let llb = path_exists(ssh, "/LLB").await?;
    if !(kernelcache && llb) {
        return Ok(FourThreeStep::Partition);
    }
    Ok(FourThreeStep::DualBoot)
}

/// Step 2: install the dualboot packages and partition the device with
/// TwistedMind2, mirroring upstream `device_fourthree_step2`. Returns the
/// generated /TwistedMind2* files needed to boot the step 3 ramdisk.
pub(crate) async fn step2(
    ssh: &RamdiskSsh,
    dualbootstuff: &[u8],
    size_gb: u32,
) -> Result<Vec<TwistedMind2Output>, KitError> {
    let size = fourthree_data_partition_bytes(size_gb)
        .ok_or(KitError::InvalidFourThreePartitionSize(size_gb))?;
    ensure_step2_allowed(check(ssh).await?)?;

    info!("sending FourThree partition packages");
    ssh.upload(&scp_path("/tmp/dualbootstuff.tar")?, dualbootstuff)
        .await?;
    run(
        ssh,
        "tar -xf /tmp/dualbootstuff.tar -C /; dpkg -i /tmp/dualbootstuff/*.deb",
    )
    .await?;

    info!(size_gb, "running TwistedMind2 partitioner");
    run(
        ssh,
        &format!(
            "rm -f /TwistedMind2*; TwistedMind2 -d1 {size} -s2 {TWISTED_MIND2_SYSTEM_SIZE} -d2 max"
        ),
    )
    .await?;

    let listing = ssh.execute("ls /TwistedMind2* 2>/dev/null").await?;
    let mut outputs = Vec::new();
    for line in listing.stdout().split(|byte| *byte == b'\n') {
        let path = std::str::from_utf8(line).map(str::trim).unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        let data = ssh.download(&scp_path(path)?, 64 * 1024 * 1024).await?;
        let name = path.rsplit('/').next().unwrap_or(path).to_owned();
        outputs.push(TwistedMind2Output { name, data });
    }
    if outputs.is_empty() {
        return Err(KitError::FourThreePartitionerFailed);
    }
    info!(files = outputs.len(), "TwistedMind2 partitioning complete");
    Ok(outputs)
}

/// Step 3: create the 4.3.x filesystems, restore the rootfs, jailbreak it,
/// and install the dualboot components, mirroring upstream
/// `device_fourthree_step3`.
pub(crate) async fn step3(
    ssh: &RamdiskSsh,
    product_type: &str,
    packages: &FourThreeStep3Packages,
) -> Result<(), KitError> {
    if fourthree_board_config(product_type).is_none() {
        return Err(KitError::FourThreeUnsupportedDevice(
            product_type.to_owned(),
        ));
    }
    ensure_step3_allowed(check(ssh).await?)?;

    info!("creating 4.3.x filesystems");
    run(ssh, "mkdir -p /mnt1 /mnt2").await?;
    run(
        ssh,
        "/sbin/newfs_hfs -s -v System -J -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s3",
    )
    .await?;
    run(
        ssh,
        "/sbin/newfs_hfs -s -v Data -J -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s4",
    )
    .await?;

    info!("sending root filesystem");
    ssh.upload(&scp_path("/var/RootFS.dmg")?, &packages.rootfs_dmg)
        .await?;
    info!("restoring root filesystem");
    run(
        ssh,
        "echo 'y' | asr restore --source /var/RootFS.dmg --target /dev/disk0s3 --erase",
    )
    .await?;
    // fsck_hfs reports repaired inconsistencies through its exit status.
    let _ = ssh
        .execute("rm /var/RootFS.dmg; fsck_hfs -f /dev/disk0s3")
        .await?;

    info!("restoring data partition");
    run(
        ssh,
        "mount_hfs /dev/disk0s3 /mnt1; mount_hfs /dev/disk0s4 /mnt2; mv /mnt1/private/var/* /mnt2",
    )
    .await?;

    info!("fixing fstab");
    let fstab = b"/dev/disk0s3 / hfs rw 0 1\n/dev/disk0s4 /private/var hfs rw 0 2\n";
    ssh.upload(&scp_path("/mnt1/private/etc/fstab")?, fstab)
        .await?;

    if product_type != "iPad2,1" {
        let patch = packages
            .lockdownd_patch
            .as_deref()
            .ok_or(KitError::MissingFourThreeLockdowndPatch)?;
        info!("patching lockdownd");
        let lockdownd = ssh
            .download(&scp_path(LOCKDOWND)?, 16 * 1024 * 1024)
            .await?;
        let patched = apply_bsdiff(&lockdownd, patch)?;
        run(ssh, &format!("mv {LOCKDOWND} {LOCKDOWND}.orig")).await?;
        ssh.upload(&scp_path(LOCKDOWND)?, &patched).await?;
        run(ssh, &format!("chmod +x {LOCKDOWND}")).await?;
    }

    info!("fixing system keybag");
    run(
        ssh,
        "mkdir -p /mnt2/keybags; ttbthingy; fixkeybag -v2; cp /tmp/systembag.kb /mnt2/keybags",
    )
    .await?;

    info!("remounting data partition");
    run(
        ssh,
        "umount /mnt2; mount_hfs /dev/disk0s4 /mnt1/private/var",
    )
    .await?;

    // Copying activation records is best-effort upstream as well.
    let dump = "private/var/root/Library/Lockdown";
    let _ = ssh
        .execute(&format!(
            "mkdir -p /mnt1/{dump}; cp -Rv /{dump}/* /mnt1/{dump}"
        ))
        .await?;

    info!("installing jailbreak bootstrap");
    install_mnt1_tar(ssh, "freeze.tar", &packages.freeze).await?;
    if let Some(openssh) = &packages.openssh {
        info!("installing OpenSSH");
        install_mnt1_tar(ssh, "sshdeb.tar", &openssh.sshdeb).await?;
        install_mnt1_tar(ssh, "openssh.tar", &openssh.openssh).await?;
        install_mnt1_tar(ssh, "openssl.tar", &openssh.openssl).await?;
    }

    run(ssh, "umount /mnt1/private/var; umount /mnt1").await?;

    info!("sending kernelcache and LLB");
    ssh.upload(&scp_path(KERNELCACHEB)?, &packages.kernelcache)
        .await?;
    ssh.upload(&scp_path("/LLB")?, &packages.llb).await?;

    install_app(ssh, &packages.app).await?;
    info!("FourThree step 3 complete");
    Ok(())
}

/// Install the FourThree companion app, mirroring upstream
/// `device_fourthree_app`.
pub(crate) async fn install_app(ssh: &RamdiskSsh, app: &[u8]) -> Result<(), KitError> {
    check(ssh).await?;
    info!("installing FourThree app");
    ssh.upload(&scp_path("/tmp/fourthree.tar")?, app).await?;
    run(
        ssh,
        "tar -h -xf /tmp/fourthree.tar -C /; rm /tmp/fourthree.tar; \
         cd /Applications/FourThree.app; \
         chmod 6755 boot.sh FourThree kloader_ios5 /usr/bin/runasroot",
    )
    .await?;
    // Upstream runs uicache as mobile over a second SSH session; running it
    // as root rebuilds the same cache.
    run(ssh, "uicache").await?;
    Ok(())
}

/// Boot the 4.3.x system through the FourThree app, mirroring upstream
/// `device_fourthree_boot`. The kloader drops the SSH session.
pub(crate) async fn boot(ssh: &RamdiskSsh) -> Result<(), KitError> {
    if check(ssh).await? != FourThreeStep::DualBoot {
        return Err(KitError::FourThreeInstallIncomplete);
    }
    info!("booting the 4.3.x system");
    let _ = ssh.execute("/Applications/FourThree.app/FourThree").await;
    Ok(())
}

fn ensure_step2_allowed(step: FourThreeStep) -> Result<(), KitError> {
    match step {
        FourThreeStep::Restore => Ok(()),
        FourThreeStep::Partition | FourThreeStep::DualBoot => {
            Err(KitError::FourThreeStepAlreadyDone("step 2"))
        }
    }
}

fn ensure_step3_allowed(step: FourThreeStep) -> Result<(), KitError> {
    match step {
        FourThreeStep::Restore => Err(KitError::FourThreePartitionIncomplete),
        FourThreeStep::Partition => Ok(()),
        FourThreeStep::DualBoot => Err(KitError::FourThreeStepAlreadyDone("step 3")),
    }
}

async fn path_exists(ssh: &RamdiskSsh, path: &str) -> Result<bool, KitError> {
    let output = ssh.execute(&format!("ls {path} 2>/dev/null")).await?;
    Ok(output.stdout().trim_ascii() == path.as_bytes())
}

async fn install_mnt1_tar(ssh: &RamdiskSsh, name: &str, data: &[u8]) -> Result<(), KitError> {
    ssh.upload(&scp_path(&format!("/tmp/{name}"))?, data)
        .await?;
    run(
        ssh,
        &format!("tar -xf /tmp/{name} -C /mnt1; rm /tmp/{name}"),
    )
    .await
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
    fn maps_ipad2_boards() {
        assert_eq!(fourthree_board_config("iPad2,1"), Some("k93ap"));
        assert_eq!(fourthree_board_config("iPad2,2"), Some("k94ap"));
        assert_eq!(fourthree_board_config("iPad2,3"), Some("k95ap"));
        assert_eq!(fourthree_board_config("iPad2,4"), None);
        assert_eq!(fourthree_board_config("iPhone4,1"), None);
    }

    #[test]
    fn maps_base_version_patches() {
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for device in ["iPad2,1", "iPad2,2", "iPad2,3"] {
            for version in FOURTHREE_BASE_VERSIONS {
                for component in [FourThreePatch::Llb, FourThreePatch::Kernelcache] {
                    let id = fourthree_patch_id(device, version, component).unwrap();
                    assert!(catalog.get(&id).is_some(), "missing resource {id}");
                }
            }
        }
        assert_eq!(
            fourthree_patch_id("iPad2,1", "4.3.3", FourThreePatch::Llb)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-1-4.3.3-LLB.k93ap.RELEASE"
        );
        assert_eq!(
            fourthree_patch_id("iPad2,3", "4.3.5", FourThreePatch::Kernelcache)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-3-4.3.5-kernelcache.release"
        );
    }

    #[test]
    fn maps_target_version_patches() {
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for device in ["iPad2,1", "iPad2,2", "iPad2,3"] {
            for component in [FourThreePatch::RestoreDeviceTree, FourThreePatch::IBoot] {
                let id = fourthree_patch_id(device, "6.1.3", component).unwrap();
                assert!(catalog.get(&id).is_some(), "missing resource {id}");
            }
        }
        assert_eq!(
            fourthree_patch_id("iPad2,2", "6.1.3", FourThreePatch::IBoot)
                .unwrap()
                .as_str(),
            "fourthree-patch-iPad2-2-6.1.3-iBoot.k94ap.RELEASE"
        );
    }

    #[test]
    fn rejects_mismatched_versions_and_devices() {
        // RestoreDeviceTree/iBoot patches only exist for 6.1.3.
        assert!(fourthree_patch_id("iPad2,1", "4.3.3", FourThreePatch::IBoot).is_none());
        // LLB/kernelcache patches only exist for the 4.3.x base versions.
        assert!(fourthree_patch_id("iPad2,1", "6.1.3", FourThreePatch::Llb).is_none());
        assert!(fourthree_patch_id("iPad2,1", "4.3.6", FourThreePatch::Llb).is_none());
        assert!(fourthree_patch_id("iPad2,4", "4.3.3", FourThreePatch::Llb).is_none());
    }

    #[test]
    fn maps_lockdownd_patch_to_iphone21_bundles() {
        let id = fourthree_lockdownd_patch_id("4.3.3", "8J2");
        assert_eq!(id.as_str(), "lockdownd-patch-iPhone2-1-4.3.3-8J2");
        let catalog = legacy_ios_assets::ResourceCatalog::bundled();
        for (version, build) in [
            ("4.3", "8F190"),
            ("4.3.1", "8G4"),
            ("4.3.2", "8H7"),
            ("4.3.3", "8J2"),
            ("4.3.4", "8K2"),
            ("4.3.5", "8L1"),
        ] {
            let id = fourthree_lockdownd_patch_id(version, build);
            assert!(catalog.get(&id).is_some(), "missing resource {id}");
        }
    }

    #[test]
    fn converts_partition_size() {
        assert_eq!(
            fourthree_data_partition_bytes(3),
            Some(3 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            fourthree_data_partition_bytes(64),
            Some(64 * 1024 * 1024 * 1024)
        );
        assert_eq!(fourthree_data_partition_bytes(0), None);
        assert_eq!(fourthree_data_partition_bytes(65), None);
    }

    #[test]
    fn gates_steps_on_progress() {
        assert!(ensure_step2_allowed(FourThreeStep::Restore).is_ok());
        assert!(matches!(
            ensure_step2_allowed(FourThreeStep::Partition),
            Err(KitError::FourThreeStepAlreadyDone("step 2"))
        ));
        assert!(matches!(
            ensure_step3_allowed(FourThreeStep::Restore),
            Err(KitError::FourThreePartitionIncomplete)
        ));
        assert!(ensure_step3_allowed(FourThreeStep::Partition).is_ok());
        assert!(matches!(
            ensure_step3_allowed(FourThreeStep::DualBoot),
            Err(KitError::FourThreeStepAlreadyDone("step 3"))
        ));
    }
}
