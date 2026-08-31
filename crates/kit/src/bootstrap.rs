use std::io::Read as _;

use legacy_ios_assets::ResourceId;
use legacy_ios_services::{RamdiskSsh, ScpPath, SshError};

use crate::KitError;

/// Decompressed bootstrap payload set for 64-bit iOS 7/8/9.
pub struct BootstrapPackages {
    pub freeze: Vec<u8>,
    pub openssh: Vec<u8>,
    pub openssl: Vec<u8>,
    pub launchctl: Option<Vec<u8>>,
    pub pangu_loader: Option<Vec<u8>>,
    pub nopatcyh: Option<Vec<u8>>,
}

/// Which optional bootstrap packages a given iOS version needs.
pub struct BootstrapSelection {
    pub needs_launchctl: bool,
    pub needs_pangu_loader: bool,
    pub needs_nopatcyh: bool,
}

/// Mirror upstream: bootstrap supports 64-bit iOS 7, 8, and 9.
pub fn bootstrap_selection(version: &str) -> Option<BootstrapSelection> {
    let (major, minor) = version_major_minor(version)?;
    if !(7..=9).contains(&major) {
        return None;
    }
    Some(BootstrapSelection {
        needs_launchctl: major == 9,
        needs_pangu_loader: major == 9
            && (minor == 2 || (minor == 3 && !matches!(version, "9.3.4" | "9.3.5"))),
        needs_nopatcyh: major == 7 || (major == 8 && minor <= 2),
    })
}

/// Select the iOS 7 untether package for a version, mirroring upstream.
pub fn select_untether7(version: &str) -> Option<ResourceId> {
    if version.starts_with("7.1") {
        Some(ResourceId::new("jailbreak-untether-panguaxe"))
    } else if version == "7.0" {
        Some(ResourceId::new("jailbreak-untether-evasi0n7-70"))
    } else if version.starts_with("7.0") {
        Some(ResourceId::new("jailbreak-untether-evasi0n7"))
    } else {
        None
    }
}

pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, KitError> {
    let mut output = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut output)
        .map_err(KitError::Io)?;
    Ok(output)
}

/// Install the Cydia bootstrap on 64-bit iOS 7/8/9 from an SSH ramdisk,
/// mirroring upstream's bootstrap flow.
pub(crate) async fn install_bootstrap(
    ssh: &RamdiskSsh,
    version: &str,
    packages: &BootstrapPackages,
) -> Result<(), KitError> {
    let selection = bootstrap_selection(version)
        .ok_or_else(|| KitError::UnsupportedBootstrapVersion(version.to_owned()))?;
    // Mounting may already have happened; a failure here is not fatal.
    let _ = ssh
        .execute("/sbin/mount_hfs /dev/disk0s1s1 /mnt1; /sbin/mount_hfs /dev/disk0s1s2 /mnt2")
        .await;

    upload_tar(ssh, "freeze.tar", &packages.freeze).await?;
    run(
        ssh,
        "cd /mnt1; tar -xf /mnt2/tmp/freeze.tar -C .; mv private/var/lib private",
    )
    .await?;
    if selection.needs_launchctl {
        let launchctl = packages
            .launchctl
            .as_deref()
            .ok_or(KitError::MissingBootstrapPackage("launchctl"))?;
        upload_tar(ssh, "launchctl.tar", launchctl).await?;
        run(ssh, "tar -xf /mnt2/tmp/launchctl.tar -C /mnt1").await?;
    }
    upload_tar(ssh, "openssh.tar", &packages.openssh).await?;
    run(ssh, "tar -xf /mnt2/tmp/openssh.tar -C /mnt1").await?;
    upload_tar(ssh, "openssl.tar", &packages.openssl).await?;
    run(ssh, "tar -xf /mnt2/tmp/openssl.tar -C /mnt1").await?;

    if selection.needs_pangu_loader {
        let plist = packages
            .pangu_loader
            .as_deref()
            .ok_or(KitError::MissingBootstrapPackage("pangu-loader"))?;
        ssh.upload(
            &scp_path("/mnt1/Library/LaunchDaemons/io.pangu93.loader.plist")?,
            plist,
        )
        .await?;
    }
    if selection.needs_nopatcyh {
        let nopatcyh = packages
            .nopatcyh
            .as_deref()
            .ok_or(KitError::MissingBootstrapPackage("nopatcyh"))?;
        run(
            ssh,
            "cd /mnt1; rm Library/MobileSubstrate/DynamicLibraries/patcyh* \
             private/lib/dpkg/info/com.saurik.patcyh* usr/lib/libpatcyh.dylib",
        )
        .await?;
        upload_tar(ssh, "nopatcyh.tar", nopatcyh).await?;
        run(
            ssh,
            "cd /mnt1; tar -xf /mnt2/tmp/nopatcyh.tar -C .; mv private/var/lib/dpkg/* private/lib/dpkg",
        )
        .await?;
    }

    run(
        ssh,
        "cd /mnt1; mv private/var/mobile/Library/Preferences/com.apple.springboard.plist private; \
         rm -r private/var/*; touch .cydia_no_stash",
    )
    .await?;
    run(
        ssh,
        "cd /mnt2; ln -s /private/lib; cd mobile/Library/Preferences; \
         rm -f com.apple.springboard.plist; ln -s /private/com.apple.springboard.plist; \
         /usr/sbin/chown 501:501 com.apple.springboard.plist",
    )
    .await?;
    Ok(())
}

/// Install the iOS 7 untether package from an SSH ramdisk.
pub(crate) async fn install_untether7(
    ssh: &RamdiskSsh,
    untether: &[u8],
    stash: bool,
) -> Result<(), KitError> {
    let _ = ssh.execute("/sbin/mount_hfs /dev/disk0s1s1 /mnt1").await;
    upload_tar(ssh, "untether.tar", untether).await?;
    run(ssh, "tar -xf /mnt2/tmp/untether.tar -C /mnt1").await?;
    if stash {
        run(ssh, "cd /mnt1; rm .cydia_no_stash").await?;
    }
    Ok(())
}

async fn upload_tar(ssh: &RamdiskSsh, name: &str, data: &[u8]) -> Result<(), KitError> {
    ssh.upload(&scp_path(&format!("/mnt2/tmp/{name}"))?, data)
        .await?;
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

fn version_major_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_bootstrap_packages_by_version() {
        let ios7 = bootstrap_selection("7.1.2").unwrap();
        assert!(ios7.needs_nopatcyh && !ios7.needs_launchctl);
        let ios8 = bootstrap_selection("8.4.1").unwrap();
        assert!(!ios8.needs_nopatcyh && !ios8.needs_launchctl);
        let ios92 = bootstrap_selection("9.2").unwrap();
        assert!(ios92.needs_pangu_loader && ios92.needs_launchctl);
        let ios935 = bootstrap_selection("9.3.5").unwrap();
        assert!(!ios935.needs_pangu_loader && ios935.needs_launchctl);
        assert!(bootstrap_selection("10.3.3").is_none());
    }

    #[test]
    fn selects_untether_by_version() {
        assert_eq!(
            select_untether7("7.1.2").unwrap().as_str(),
            "jailbreak-untether-panguaxe"
        );
        assert_eq!(
            select_untether7("7.0").unwrap().as_str(),
            "jailbreak-untether-evasi0n7-70"
        );
        assert_eq!(
            select_untether7("7.0.6").unwrap().as_str(),
            "jailbreak-untether-evasi0n7"
        );
        assert!(select_untether7("8.4.1").is_none());
    }
}
