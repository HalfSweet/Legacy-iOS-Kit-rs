use std::path::Path;
use std::time::Duration;

use legacy_ios_assets::ResourceId;
use legacy_ios_core::{BoardConfig, DeviceMode, Ecid, ProductType};
use legacy_ios_firmware::FirmwareArchive;
use legacy_ios_image::{Img3, Img3Element, Img3Tag, extract_image_payload, patch_iboot32};
use legacy_ios_services::RamdiskSsh;
use legacy_ios_transport::{IbootClient, RecoveryError};
use tokio::time::Instant;
use tracing::info;

use crate::{ImageCipher, KitError};

const KDFU_TIMEOUT: Duration = Duration::from_secs(30);

/// Select the kloader payload resource, mirroring upstream's device rules.
pub fn select_kloader(product_type: &ProductType, ios_major: u32) -> ResourceId {
    if ios_major <= 5 {
        ResourceId::new("kloader-axi0mx")
    } else if product_type.as_str().starts_with("iPad3,") {
        ResourceId::new("kloader5")
    } else {
        ResourceId::new("kloader")
    }
}

/// Build a pwned iBSS: extract the iBSS from an IPSW, decrypt it with the
/// firmware key, remove the RSA signature check, and repack it as IMG3.
pub fn prepare_pwned_ibss(
    firmware: &Path,
    board: &BoardConfig,
    cipher: Option<&ImageCipher>,
) -> Result<Vec<u8>, KitError> {
    let archive = FirmwareArchive::open(firmware)?;
    let entry = format!("Firmware/dfu/iBSS.{}ap.RELEASE.dfu", board.as_str());
    let container = archive.read_entry(&entry)?;
    let decrypted =
        extract_image_payload(&container, cipher.map(|cipher| (cipher.key(), cipher.iv())))?;
    let patched = patch_iboot32(&decrypted, None, None)?;
    Ok(Img3::new(
        u32::from_le_bytes(*b"ibss"),
        vec![
            Img3Element::new(Img3Tag::TYPE, b"ibss".to_vec()),
            Img3Element::new(Img3Tag::DATA, patched),
        ],
    )
    .to_bytes())
}

/// Upload kloader and a pwned iBSS to a jailbroken device and run kloader,
/// which drops the device into kDFU mode.
pub async fn enter_kdfu(
    ssh: &RamdiskSsh,
    kloader: &[u8],
    pwned_ibss: &[u8],
) -> Result<(), KitError> {
    ssh.upload(
        &legacy_ios_services::ScpPath::new("/tmp/pwnediBSS.lik").map_err(|error| {
            KitError::Ssh(legacy_ios_services::SshError::Scp(error.to_string()))
        })?,
        pwned_ibss,
    )
    .await?;
    ssh.upload(
        &legacy_ios_services::ScpPath::new("/tmp/lik-kloader").map_err(|error| {
            KitError::Ssh(legacy_ios_services::SshError::Scp(error.to_string()))
        })?,
        kloader,
    )
    .await?;
    // kloader remaps memory and the SSH session dies with the device; the
    // command result is expected to be lost.
    let _ = ssh
        .execute("chmod +x /tmp/lik-kloader && /tmp/lik-kloader /tmp/pwnediBSS.lik")
        .await;
    Ok(())
}

/// Wait for the device to re-enumerate in DFU mode after kloader ran.
pub async fn await_kdfu(ecid: Option<Ecid>) -> Result<(), KitError> {
    let deadline = Instant::now() + KDFU_TIMEOUT;
    loop {
        match IbootClient::open(ecid).await {
            Ok(client) if client.mode() == DeviceMode::Dfu => {
                info!("device entered kDFU mode");
                return Ok(());
            }
            Ok(_) | Err(RecoveryError::NoDevice) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(KitError::KdfuTimeout);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_kloader_by_device_and_version() {
        assert_eq!(
            select_kloader(&ProductType::from("iPhone4,1"), 9).as_str(),
            "kloader"
        );
        assert_eq!(
            select_kloader(&ProductType::from("iPad3,1"), 9).as_str(),
            "kloader5"
        );
        assert_eq!(
            select_kloader(&ProductType::from("iPhone4,1"), 5).as_str(),
            "kloader-axi0mx"
        );
    }
}
