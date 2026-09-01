use std::path::PathBuf;
use std::time::Duration;

use legacy_ios_assets::{ResourceCatalog, ResourceId};
use legacy_ios_core::{DeviceMode, Ecid};
use legacy_ios_firmware::{ArtifactSpec, ArtifactStore, RemoteFirmwareArchive};
use legacy_ios_transport::{IbootClient, RecoveryError, UploadResult};
use sha1::Digest as _;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::KitError;

// The Pwnage 2.0 WTF image is built from Apple's own iPhone1,1 3.1.3 (7E18)
// restore IPSW, exactly as upstream Legacy-iOS-Kit does. The WTF entry digest
// is pinned by upstream and re-verified here after extraction.
const WTF_IPSW_URL: &str = "https://secure-appldnld.apple.com/iPhone/061-8368.20100611.Up843/iPhone1,1_3.1.3_7E18_Restore.ipsw";
const WTF_ENTRY: &str = "Firmware/dfu/WTF.s5l8900xall.RELEASE.dfu";
const WTF_SHA1: [u8; 20] = [
    0xcb, 0x96, 0x95, 0x41, 0x85, 0xa9, 0x17, 0x12, 0xc4, 0x7f, 0x20, 0xad, 0xb5, 0x19, 0xdb, 0x45,
    0xa3, 0x18, 0xc3, 0x0f,
];
const PWNAGE_PATCH_RESOURCE: &str = "s5l8900-wtf-pwnage-patch";
pub(crate) const PWNED_SRTG: &str = "iBoot-636.66.3x";
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn pwn_wtf(ecid: Option<Ecid>, cache_root: PathBuf) -> Result<(), KitError> {
    let payload = pwnage_payload(cache_root).await?;

    let client = IbootClient::open(ecid).await?;
    if client.mode() != DeviceMode::Dfu {
        return Err(KitError::Recovery(RecoveryError::ExploitRequiresDfu(
            client.mode(),
        )));
    }
    match client.upload_image(&payload).await? {
        UploadResult::Connected(_) => debug!("WTF upload completed without re-enumeration"),
        UploadResult::Reenumerating => debug!("WTF uploaded, waiting for re-enumeration"),
    }

    let deadline = Instant::now() + RECONNECT_TIMEOUT;
    loop {
        match IbootClient::open(ecid).await {
            Ok(client)
                if matches!(client.mode(), DeviceMode::Dfu | DeviceMode::Wtf)
                    && is_pwned_wtf_srtg(client.device_info().srtg()) =>
            {
                info!("device is in Pwnage 2.0 WTF mode");
                return Ok(());
            }
            Ok(_) | Err(RecoveryError::NoDevice) => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(KitError::PwnageVerificationTimeout);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub(crate) async fn pwnage_payload(cache_root: PathBuf) -> Result<Vec<u8>, KitError> {
    let record = ResourceCatalog::bundled()
        .get(&ResourceId::new(PWNAGE_PATCH_RESOURCE))
        .ok_or_else(|| KitError::UnknownResource(ResourceId::new(PWNAGE_PATCH_RESOURCE)))?;
    let digest = format!("sha256:{}", record.sha256());
    let spec = ArtifactSpec::parse(record.source_url(), &digest)?.with_size(record.size());
    let patch_path = ArtifactStore::new(cache_root).fetch(&spec).await?;
    let patch = tokio::fs::read(&patch_path).await?;

    let archive = RemoteFirmwareArchive::open(WTF_IPSW_URL).await?;
    let wtf = archive.read_entry(WTF_ENTRY).await?;
    let digest = sha1::Sha1::digest(&wtf);
    if digest[..] != WTF_SHA1 {
        return Err(KitError::PwnageWtfDigest);
    }

    Ok(legacy_ios_image::apply_bsdiff(&wtf, &patch)?)
}

pub(crate) fn is_pwned_wtf_srtg(srtg: Option<&str>) -> bool {
    srtg == Some(PWNED_SRTG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pwned_wtf_srtg() {
        assert!(is_pwned_wtf_srtg(Some("iBoot-636.66.3x")));
        assert!(!is_pwned_wtf_srtg(Some("iBoot-636.66.33")));
        assert!(!is_pwned_wtf_srtg(None));
    }
}
