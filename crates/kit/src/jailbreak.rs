use legacy_ios_assets::ResourceId;
use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};
use tracing::info;

use crate::KitError;

/// Untether payload selected for a 32-bit jailbreak target, mirroring
/// upstream's `device_ramdisk jailbreak` matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UntetherPackage {
    Aquila(u32),
    Everuntether,
    Daibutsu,
    GreenPois0n(ResourceId),
}

impl UntetherPackage {
    pub fn resource_id(&self) -> ResourceId {
        match self {
            Self::Aquila(major) => ResourceId::new(format!("jailbreak-aquila-{major}")),
            Self::Everuntether => ResourceId::new("jailbreak-everuntether"),
            Self::Daibutsu => ResourceId::new("jailbreak-daibutsu-untether"),
            Self::GreenPois0n(id) => id.clone(),
        }
    }
}

/// fstab replacement strategy, mirroring upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FstabReplacement {
    /// fstab7.tar / fstab8.tar / fstab_rw.tar, extracted into /mnt1.
    Tar(&'static str),
    /// fstab_new / fstab_old, copied over /mnt1/private/etc/fstab.
    File(&'static str),
}

impl FstabReplacement {
    pub fn resource_id(&self) -> ResourceId {
        let name = match self {
            Self::Tar(name) | Self::File(name) => name,
        };
        ResourceId::new(format!("jailbreak-fstab-{name}"))
    }
}

/// Resolved plan for the 32-bit SSH ramdisk jailbreak, mirroring the
/// "jailbreak" branch of upstream `device_ramdisk`.
#[derive(Clone, Debug)]
pub struct JailbreakPlan {
    product_type: String,
    version: String,
    build: String,
    untether: Option<UntetherPackage>,
    /// Extract the untether before mounting the data partition (3.1.3/3.2/4.0/4.1).
    extract_untether_early: bool,
    fstab: FstabReplacement,
    /// iPhone2,1 on 4.3.x uses the smaller freeze5 bootstrap.
    freeze5: bool,
    punchd: bool,
    cydia_substrate: bool,
    launchctl_zebra: bool,
    cydia_http_patch: bool,
    lukezgd: bool,
    remove_patcyh: bool,
    daibutsu_move: bool,
    daibutsu_haxx: bool,
}

impl JailbreakPlan {
    /// Resolve the jailbreak plan for a device and iOS version, mirroring
    /// upstream's untether/extras selection. `None` means the combination is
    /// not supported by the SSH ramdisk jailbreak.
    pub fn for_device(product_type: &str, version: &str, build: &str) -> Option<Self> {
        let (major, minor, patch) = version_triplet(version);
        let a5 = is_a5(product_type);

        let greenpois0n = || {
            let id = ResourceId::new(format!(
                "greenpois0n-{}-{build}",
                product_type.replace(',', "-")
            ));
            legacy_ios_assets::ResourceCatalog::bundled()
                .get(&id)
                .is_some()
                .then_some(UntetherPackage::GreenPois0n(id))
        };
        let is_42x_greenpois0n = matches!((major, minor, patch), (4, 2, Some(1 | 6 | 7 | 8)));
        let early_greenpois0n = matches!(version, "3.1.3")
            || (major == 3 && minor == 2)
            || (major == 4 && matches!(minor, 0 | 1));

        let untether = match (major, minor) {
            (9, 3) if matches!(patch, Some(5 | 6)) => return None,
            (9, _) => Some(UntetherPackage::Everuntether),
            (8, _) => Some(UntetherPackage::Daibutsu),
            (7, _) => Some(UntetherPackage::Aquila(7)),
            (6, _) => Some(UntetherPackage::Aquila(6)),
            (5, _) => Some(UntetherPackage::Aquila(5)),
            (4, 3) => Some(UntetherPackage::Aquila(4)),
            (4, 0 | 1) | (3, 2) => Some(greenpois0n()?),
            (3, 1) if version == "3.1.3" => Some(greenpois0n()?),
            (4, 2) if is_42x_greenpois0n => Some(greenpois0n()?),
            // No untether package: the iPhone3,3 4.2 ramdisk boot already
            // patches what is needed, as does the iPhone2,1 3.x kernel.
            (4, 2) if product_type == "iPhone3,3" => None,
            (3, _) if product_type == "iPhone2,1" => None,
            _ => return None,
        };
        // Use everuntether + jsc_untether instead of daibutsu + dsc haxx on
        // A5/A5X running iOS 8.0-8.2.
        let everuntether = a5 && matches!((major, minor), (8, 0..=2));
        let untether = if everuntether {
            Some(UntetherPackage::Everuntether)
        } else {
            untether
        };

        let fstab = match major {
            8 | 9 => FstabReplacement::Tar("8"),
            7 => FstabReplacement::Tar("7"),
            6 => FstabReplacement::Tar("rw"),
            _ if is_s5l8900(product_type) || product_type == "iPod2,1" => {
                FstabReplacement::File("old")
            }
            _ => FstabReplacement::File("new"),
        };

        Some(Self {
            product_type: product_type.to_owned(),
            version: version.to_owned(),
            build: build.to_owned(),
            extract_untether_early: early_greenpois0n,
            untether,
            fstab,
            freeze5: product_type == "iPhone2,1" && matches!((major, minor), (4, 3)),
            punchd: is_42x_greenpois0n,
            cydia_substrate: matches!(major, 3..=5),
            launchctl_zebra: major == 9,
            cydia_http_patch: major == 3,
            lukezgd: !matches!(major, 3 | 4),
            remove_patcyh: !(major == 9 || matches!((major, minor), (8, 3..=4))),
            daibutsu_move: major == 7 || (major == 8 && !everuntether),
            daibutsu_haxx: major == 8 && !everuntether,
        })
    }

    pub fn product_type(&self) -> &str {
        &self.product_type
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }

    pub fn untether(&self) -> Option<&UntetherPackage> {
        self.untether.as_ref()
    }

    pub const fn fstab(&self) -> FstabReplacement {
        self.fstab
    }

    /// Resource id of the bootstrap payload (freeze5 for iPhone2,1 4.3.x).
    pub fn freeze_resource(&self) -> ResourceId {
        if self.freeze5 {
            ResourceId::new("jailbreak-bootstrap-freeze5")
        } else {
            ResourceId::new("jailbreak-bootstrap-freeze")
        }
    }

    pub const fn needs_daibutsu_move(&self) -> bool {
        self.daibutsu_move
    }

    pub const fn needs_cydia_substrate(&self) -> bool {
        self.cydia_substrate
    }

    pub const fn needs_launchctl_zebra(&self) -> bool {
        self.launchctl_zebra
    }

    pub const fn needs_cydia_http_patch(&self) -> bool {
        self.cydia_http_patch
    }

    pub const fn needs_lukezgd(&self) -> bool {
        self.lukezgd
    }

    pub const fn removes_patcyh(&self) -> bool {
        self.remove_patcyh
    }
}

/// Resolved package bytes for [`JailbreakPlan`]; optional payloads are only
/// required when the plan enables them.
pub struct JailbreakPackages {
    /// Decompressed freeze bootstrap tar (or freeze5 on iPhone2,1 4.3.x).
    pub freeze: Vec<u8>,
    pub untether: Option<Vec<u8>>,
    pub daibutsu_move: Option<Vec<u8>>,
    pub fstab: Vec<u8>,
    pub cydia_substrate: Option<Vec<u8>>,
    pub launchctl: Option<Vec<u8>>,
    pub zebra: Option<Vec<u8>>,
    pub cydia_http_patch: Option<Vec<u8>>,
    pub lukezgd: Option<Vec<u8>>,
    pub nopatcyh: Option<Vec<u8>>,
}

/// Install the 32-bit jailbreak from an SSH ramdisk session, mirroring
/// upstream's `device_ramdisk jailbreak` flow. The device is expected to have
/// the root filesystem mounted at /mnt1 (see `mount_filesystems`).
pub(crate) async fn install_jailbreak(
    ssh: &RamdiskSsh,
    plan: &JailbreakPlan,
    packages: &JailbreakPackages,
) -> Result<(), KitError> {
    info!(
        product_type = %plan.product_type,
        version = %plan.version,
        build = %plan.build,
        "installing 32-bit jailbreak from SSH ramdisk"
    );
    let bash = ssh.execute("ls /mnt1/bin/bash 2>/dev/null").await?;
    if !bash.stdout().is_empty() {
        return Err(KitError::AlreadyJailbroken);
    }

    let untether = match plan.untether() {
        Some(_) => Some(
            packages
                .untether
                .as_deref()
                .ok_or(KitError::MissingJailbreakPackage("untether"))?,
        ),
        None => None,
    };
    if let Some(untether) = untether {
        info!("sending untether package");
        upload_root(ssh, "untether.tar", untether).await?;
        if plan.extract_untether_early {
            extract_root_tar(ssh, "untether.tar").await?;
        }
    }

    ssh.mount_data_partition().await?;

    match plan.fstab {
        FstabReplacement::Tar(_) => {
            install_root_tar(ssh, "fstab.tar", &packages.fstab).await?;
        }
        FstabReplacement::File(_) => {
            ssh.upload(&scp_path("/mnt1/private/etc/fstab")?, &packages.fstab)
                .await?;
        }
    }
    if plan.punchd {
        // Exits non-zero when punchd already exists; that is fine.
        let _ = ssh
            .execute("[[ ! -e /mnt1/sbin/punchd ]] && mv /mnt1/sbin/launchd /mnt1/sbin/punchd")
            .await;
    }

    // Extract the untether now unless it was extracted early or must wait for
    // daibutsu's move.sh (iOS 8 daibutsu + dsc haxx).
    if untether.is_some() && !plan.extract_untether_early && !plan.daibutsu_haxx {
        extract_root_tar(ssh, "untether.tar").await?;
    }

    info!("installing Cydia bootstrap");
    install_root_tar(ssh, "freeze.tar", &packages.freeze).await?;

    if plan.cydia_substrate {
        let tar = packages
            .cydia_substrate
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("cydiasubstrate"))?;
        install_root_tar(ssh, "cydiasubstrate.tar", tar).await?;
    }
    if plan.launchctl_zebra {
        let launchctl = packages
            .launchctl
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("launchctl"))?;
        install_root_tar(ssh, "launchctl.tar", launchctl).await?;
        let zebra = packages
            .zebra
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("zebra"))?;
        install_root_tar(ssh, "zebra.tar", zebra).await?;
    }
    if plan.cydia_http_patch {
        let tar = packages
            .cydia_http_patch
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("cydiahttpatch"))?;
        install_root_tar(ssh, "cydiahttpatch.tar", tar).await?;
    }
    if plan.lukezgd {
        let tar = packages
            .lukezgd
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("LukeZGD"))?;
        install_root_tar(ssh, "LukeZGD.tar", tar).await?;
    }

    if plan.remove_patcyh {
        run(
            ssh,
            "cd /mnt1; rm Library/MobileSubstrate/DynamicLibraries/patcyh* \
             private/lib/dpkg/info/com.saurik.patcyh* usr/lib/libpatcyh.dylib",
        )
        .await?;
        let nopatcyh = packages
            .nopatcyh
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("nopatcyh"))?;
        install_root_tar(ssh, "nopatcyh.tar", nopatcyh).await?;
    }

    if plan.daibutsu_move {
        let script = packages
            .daibutsu_move
            .as_deref()
            .ok_or(KitError::MissingJailbreakPackage("daibutsu move.sh"))?;
        upload_root(ssh, "move.sh", script).await?;
        run(
            ssh,
            &format!("bash /mnt1/move.sh {}; rm /mnt1/move.sh", plan.version),
        )
        .await?;
        if plan.daibutsu_haxx {
            extract_root_tar(ssh, "untether.tar").await?;
            info!("running haxx_overwrite");
            run(
                ssh,
                &format!(
                    "/usr/bin/haxx_overwrite --{}_{}",
                    plan.product_type, plan.build
                ),
            )
            .await?;
        } else {
            reboot(ssh).await;
        }
    } else {
        reboot(ssh).await;
    }
    info!("jailbreak installed");
    Ok(())
}

/// Upload a tar into the ramdisk root and extract it into /mnt1.
async fn install_root_tar(ssh: &RamdiskSsh, name: &str, data: &[u8]) -> Result<(), KitError> {
    upload_root(ssh, name, data).await?;
    extract_root_tar(ssh, name).await
}

async fn upload_root(ssh: &RamdiskSsh, name: &str, data: &[u8]) -> Result<(), KitError> {
    ssh.upload(&scp_path(&format!("/mnt1/{name}"))?, data)
        .await?;
    Ok(())
}

async fn extract_root_tar(ssh: &RamdiskSsh, name: &str) -> Result<(), KitError> {
    run(
        ssh,
        &format!("tar -xf /mnt1/{name} -C /mnt1; rm /mnt1/{name}"),
    )
    .await
}

/// `reboot_bak` drops the SSH session; a lost reply is expected.
async fn reboot(ssh: &RamdiskSsh) {
    let _ = ssh.execute("reboot_bak").await;
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

fn version_triplet(version: &str) -> (u32, u32, Option<u32>) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|part| part.parse().ok());
    (major, minor, patch)
}

/// A5/A5X devices (upstream `device_proc == 5`).
fn is_a5(product_type: &str) -> bool {
    matches!(
        product_type,
        "iPhone4,1"
            | "iPad2,1"
            | "iPad2,2"
            | "iPad2,3"
            | "iPad2,4"
            | "iPad3,1"
            | "iPad3,2"
            | "iPad3,3"
            | "iPod5,1"
            | "AppleTV2,1"
    )
}

/// S5L8900 devices (upstream `device_proc == 1`).
fn is_s5l8900(product_type: &str) -> bool {
    matches!(product_type, "iPhone1,1" | "iPhone1,2" | "iPod1,1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_for(product_type: &str, version: &str, build: &str) -> JailbreakPlan {
        JailbreakPlan::for_device(product_type, version, build).unwrap()
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert!(JailbreakPlan::for_device("iPhone4,1", "9.3.5", "13G36").is_none());
        assert!(JailbreakPlan::for_device("iPad2,1", "9.3.6", "13G37").is_none());
        assert!(JailbreakPlan::for_device("iPhone4,1", "10.3.3", "14G60").is_none());
        assert!(JailbreakPlan::for_device("iPhone3,1", "4.2.10", "8E600").is_none());
        assert!(JailbreakPlan::for_device("iPhone3,1", "", "").is_none());
    }

    #[test]
    fn selects_aquila_by_major_version() {
        for (version, major) in [("7.1.2", 7), ("6.1.3", 6), ("5.1.1", 5)] {
            let plan = plan_for("iPhone3,1", version, "9B206");
            assert_eq!(plan.untether(), Some(&UntetherPackage::Aquila(major)));
            assert!(plan.needs_daibutsu_move() == (major == 7));
        }
        let plan = plan_for("iPhone3,1", "4.3.3", "8J2");
        assert_eq!(plan.untether(), Some(&UntetherPackage::Aquila(4)));
    }

    #[test]
    fn selects_everuntether_for_ios9_and_a5_ios8_low() {
        let plan = plan_for("iPhone4,1", "9.3.3", "13G34");
        assert_eq!(plan.untether(), Some(&UntetherPackage::Everuntether));
        let plan = plan_for("iPhone4,1", "8.1.2", "12B440");
        assert_eq!(plan.untether(), Some(&UntetherPackage::Everuntether));
        // everuntether on 8.x still extracts after the data partition mount.
        assert!(!plan.extract_untether_early);
        assert!(!plan.needs_daibutsu_move());
        // A4 on the same version still uses daibutsu.
        let plan = plan_for("iPhone3,1", "8.1.2", "12B440");
        assert_eq!(plan.untether(), Some(&UntetherPackage::Daibutsu));
        assert!(plan.needs_daibutsu_move());
        assert!(!plan.extract_untether_early);
        // A5 on 8.3+ stays on daibutsu.
        let plan = plan_for("iPad2,1", "8.4.1", "12H321");
        assert_eq!(plan.untether(), Some(&UntetherPackage::Daibutsu));
    }

    #[test]
    fn selects_greenpois0n_by_device_and_build() {
        let plan = plan_for("iPhone3,1", "4.2.1", "8C148");
        assert_eq!(
            plan.untether(),
            Some(&UntetherPackage::GreenPois0n(ResourceId::new(
                "greenpois0n-iPhone3-1-8C148"
            )))
        );
        // 4.2.x greenpois0n extracts after the data partition mount.
        assert!(!plan.extract_untether_early);
        assert!(plan.punchd);
        let plan = plan_for("iPhone2,1", "4.1", "8B117");
        assert!(plan.extract_untether_early);
        let plan = plan_for("iPad1,1", "3.2.2", "7B500");
        assert_eq!(
            plan.untether(),
            Some(&UntetherPackage::GreenPois0n(ResourceId::new(
                "greenpois0n-iPad1-1-7B500"
            )))
        );
        // No greenpois0n package exists for this build.
        assert!(JailbreakPlan::for_device("iPhone3,1", "4.1", "8B999").is_none());
    }

    #[test]
    fn handles_packageless_targets() {
        // iPhone3,3 on other 4.2.x: continue without an untether package.
        let plan = plan_for("iPhone3,3", "4.2.10", "8E600");
        assert_eq!(plan.untether(), None);
        // iPhone2,1 on 3.x: kernel already patched, no untether package.
        let plan = plan_for("iPhone2,1", "3.1.2", "7D11");
        assert_eq!(plan.untether(), None);
        assert!(plan.needs_cydia_substrate() && plan.needs_cydia_http_patch());
    }

    #[test]
    fn selects_fstab_and_extras() {
        let plan = plan_for("iPhone4,1", "9.2", "13C75");
        assert_eq!(plan.fstab(), FstabReplacement::Tar("8"));
        assert!(plan.needs_launchctl_zebra() && !plan.removes_patcyh());
        let plan = plan_for("iPhone3,1", "6.1.3", "10B329");
        assert_eq!(plan.fstab(), FstabReplacement::Tar("rw"));
        let plan = plan_for("iPhone3,1", "7.1.2", "11D257");
        assert_eq!(plan.fstab(), FstabReplacement::Tar("7"));
        let plan = plan_for("iPhone1,2", "3.1.3", "7E18");
        assert_eq!(plan.fstab(), FstabReplacement::File("old"));
        let plan = plan_for("iPhone3,1", "4.3.3", "8J2");
        assert_eq!(plan.fstab(), FstabReplacement::File("new"));
        assert!(plan.needs_cydia_substrate() && !plan.needs_lukezgd());
        // patcyh stays on 8.3+ and 9.x, removed elsewhere.
        assert!(!plan_for("iPhone3,1", "8.3", "12F70").removes_patcyh());
        assert!(plan_for("iPhone3,1", "8.2", "12D508").removes_patcyh());
    }

    #[test]
    fn selects_freeze5_for_iphone21_43() {
        let plan = plan_for("iPhone2,1", "4.3.5", "8L1");
        assert_eq!(
            plan.freeze_resource().as_str(),
            "jailbreak-bootstrap-freeze5"
        );
        let plan = plan_for("iPhone3,1", "4.3.5", "8L1");
        assert_eq!(
            plan.freeze_resource().as_str(),
            "jailbreak-bootstrap-freeze"
        );
    }
}
