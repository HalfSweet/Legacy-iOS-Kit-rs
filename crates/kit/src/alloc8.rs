use std::path::PathBuf;

use legacy_ios_assets::{ResourceCatalog, ResourceId};
use legacy_ios_core::Ecid;
use legacy_ios_exploits::{Alloc8, Limera1n};
use legacy_ios_firmware::{ArtifactSpec, ArtifactStore, RemoteFirmwareArchive};
use legacy_ios_transport::IbootClient;
use sha1::Digest as _;
use tracing::{debug, info};

use crate::KitError;

// The iBSS comes from Apple's own iPhone2,1 4.3.5 (8L1) restore IPSW,
// exactly as upstream Legacy-iOS-Kit does. The entry digest is pinned by
// upstream and re-verified here after extraction.
const IBSS_IPSW_URL: &str =
    "http://appldnld.apple.com/iPhone4/041-1965.20110721.gxUB5/iPhone2,1_4.3.5_8L1_Restore.ipsw";
const IBSS_ENTRY: &str = "Firmware/dfu/iBSS.n88ap.RELEASE.dfu";
const IBSS_SHA1: [u8; 20] = [
    0xeb, 0x90, 0xaf, 0x53, 0x10, 0xa9, 0x58, 0xe6, 0x18, 0x6f, 0x32, 0xc1, 0x44, 0x00, 0x02, 0x96,
    0x2d, 0x1f, 0x97, 0x5d,
];
const ALLOC8_SHELLCODE_RESOURCE: &str = "alloc8-shellcode";
const FLASH_NOR_SHELLCODE_RESOURCE: &str = "alloc8-ibss-flash-nor-shellcode";

/// Install the alloc8 exploit on a new-bootrom iPhone 3GS, mirroring
/// upstream's `device_alloc8`: enter pwned DFU with limera1n when the
/// device is not pwned yet, download the 4.3.5 iBSS and the shellcode
/// assets, then run the NOR installer.
pub(crate) async fn install_alloc8(
    ecid: Option<Ecid>,
    limera1n_payload: Option<Vec<u8>>,
    cache_root: PathBuf,
) -> Result<(), KitError> {
    let ibss = ibss_4_3_5().await?;
    let shellcode = fetch_resource(ALLOC8_SHELLCODE_RESOURCE, &cache_root).await?;
    let flash_shellcode = fetch_resource(FLASH_NOR_SHELLCODE_RESOURCE, &cache_root).await?;

    let client = IbootClient::open(ecid).await?;
    let client = if client.device_info().pwned().is_some() {
        debug!("device is already in pwned DFU mode");
        client
    } else {
        let payload = limera1n_payload.ok_or(KitError::MissingLimera1nPayload)?;
        let client = Limera1n::new(payload)?.exploit(client).await?;
        if client.device_info().pwned().is_none() {
            return Err(KitError::PwnVerificationFailed);
        }
        client
    };

    Alloc8::new(&client)?
        .install(&ibss, &shellcode, &flash_shellcode)
        .await?;
    info!("alloc8 exploit installed");
    Ok(())
}

async fn ibss_4_3_5() -> Result<Vec<u8>, KitError> {
    let archive = RemoteFirmwareArchive::open(IBSS_IPSW_URL).await?;
    let ibss = archive.read_entry(IBSS_ENTRY).await?;
    let digest = sha1::Sha1::digest(&ibss);
    if digest[..] != IBSS_SHA1 {
        return Err(KitError::Alloc8IbssDigest);
    }
    Ok(ibss)
}

async fn fetch_resource(id: &str, cache_root: &std::path::Path) -> Result<Vec<u8>, KitError> {
    let record = ResourceCatalog::bundled()
        .get(&ResourceId::new(id))
        .ok_or_else(|| KitError::UnknownResource(ResourceId::new(id)))?;
    let digest = format!("sha256:{}", record.sha256());
    let spec = ArtifactSpec::parse(record.source_url(), &digest)?.with_size(record.size());
    let path = ArtifactStore::new(cache_root).fetch(&spec).await?;
    Ok(tokio::fs::read(&path).await?)
}
