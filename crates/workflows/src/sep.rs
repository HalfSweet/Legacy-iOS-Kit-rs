//! Independent SEP signing (futurerestore.cpp:1613-1621): once the device
//! reaches recovery mode post-iBEC, the SEP ticket is fetched against the
//! aux build identity with the device's fresh ApNonce/SepNonce, and
//! RestoreSEP plus the NOR SEP components are personalized with that ticket
//! instead of the target ticket (restore.c:1758-1813).

use std::fmt;

use legacy_ios_firmware::{ApParameters, TssClient, TssError, TssRequest};
use legacy_ios_transport::IbootClient;
use plist::{Dictionary, Value};
use sha1::Sha1;
use sha2::{Digest as _, Sha384};
use thiserror::Error;
use tracing::info;

use crate::{
    PersonalizationError, RestorePlan, SepPolicy,
    aux::{AuxContext, AuxFirmwareError},
    personalization::personalize_data,
};

/// The independently signed RestoreSEP of a restore boot: the
/// `rsepfirmware` payload plus the personalized SEP entries of the NOR
/// response.
pub struct SepPayload {
    restore_sep: Vec<u8>,
    nor_images: Vec<(String, Vec<u8>)>,
}

impl SepPayload {
    /// The personalized RestoreSEP sent with `rsepfirmware`.
    pub fn restore_sep(&self) -> &[u8] {
        &self.restore_sep
    }

    /// The NOR response entries: RestoreSEPImageData, SEPImageData, and
    /// SEPPatchImageData, as far as the aux identity carries them.
    pub(crate) fn nor_images(&self) -> &[(String, Vec<u8>)] {
        &self.nor_images
    }
}

impl fmt::Debug for SepPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SepPayload")
            .field("restore_sep_bytes", &self.restore_sep.len())
            .field(
                "nor_images",
                &self
                    .nor_images
                    .iter()
                    .map(|(key, data)| (key, data.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Sign the restore SEP when SEP is in play (a 64-bit target whose plan
/// resolved an aux SEP source, or `SepPolicy::Provided`). Reads the fresh
/// nonces from the recovery-mode `client`, fetches the SEP ticket against
/// the aux build identity, and personalizes the SEP components with it.
/// Returns `None` for `SepPolicy::None` and for 32-bit targets.
pub async fn sign_sep_payload(
    plan: &RestorePlan,
    client: &IbootClient,
    tss: &TssClient,
) -> Result<Option<SepPayload>, SepError> {
    let board = plan
        .device()
        .board_config()
        .ok_or(SepError::MissingBoardConfig)?;
    let context = match plan.sep_policy() {
        SepPolicy::None => return Ok(None),
        SepPolicy::Provided(path) => AuxContext::from_local(path, board, plan.behavior())?,
        SepPolicy::Auto => {
            let Some(aux) = plan.aux_firmware() else {
                return Ok(None);
            };
            if !aux.sep() {
                return Ok(None);
            }
            AuxContext::open(plan, aux).await?
        }
    };
    let identity = context.identity();
    let sep_path = identity.component_path("RestoreSEP")?;
    let sep_data = context.read_entry(sep_path).await?;
    verify_sep_digest(identity, &sep_data)?;

    // The fresh nonces of the recovery-mode device (futurerestore
    // get_sep_nonce/get_ap_nonce, futurerestore.cpp:1613-1614). Never log
    // them.
    let info = client.device_info();
    let sep_nonce = info.sep_nonce().ok_or(SepError::MissingSepNonce)?.to_vec();
    let ap_nonce = info.ap_nonce().ok_or(SepError::MissingApNonce)?.to_vec();
    let chip_id = u64::from(info.cpid().ok_or(SepError::MissingDeviceInfo("CPID"))?);
    let board_id = u64::from(info.bdid().ok_or(SepError::MissingDeviceInfo("BDID"))?);
    let ecid = plan.device().ecid().ok_or(SepError::MissingEcid)?;

    let mut parameters = ApParameters::new(board_id, chip_id, ecid);
    parameters.ap_nonce = Some(ap_nonce);
    parameters.sep_nonce = Some(sep_nonce);
    parameters.supports_img4 = true;

    let request = TssRequest::for_build_identity(identity, &parameters);
    let ticket = tss.send(&request).await?.into_dictionary();
    info!("fetched the independent SEP signing ticket");

    let payload = build_sep_payload(&context, sep_data, &ticket).await?;
    Ok(Some(payload))
}

/// Personalize RestoreSEP and the NOR SEP components with the SEP ticket.
/// The same personalized RestoreSEP serves the `rsepfirmware` upload and the
/// RestoreSEPImageData NOR entry (restore.c:1758-1784).
async fn build_sep_payload(
    context: &AuxContext,
    restore_sep_data: Vec<u8>,
    ticket: &Dictionary,
) -> Result<SepPayload, SepError> {
    let identity = context.identity();
    let restore_sep = personalize_data("RestoreSEP", restore_sep_data, ticket)?;
    let mut nor_images = Vec::new();
    for (component, key) in [
        ("RestoreSEP", "RestoreSEPImageData"),
        ("SEP", "SEPImageData"),
        ("SepStage1", "SEPPatchImageData"),
    ] {
        if !identity.manifest().contains_key(component) {
            continue;
        }
        let data = if component == "RestoreSEP" {
            restore_sep.clone()
        } else {
            let path = identity.component_path(component)?;
            personalize_data(component, context.read_entry(path).await?, ticket)?
        };
        nor_images.push((key.to_owned(), data));
    }
    Ok(SepPayload {
        restore_sep,
        nor_images,
    })
}

/// Verify the SEP firmware bytes against the aux manifest Digest: SHA-1 for
/// 20-byte digests, SHA-384 otherwise (futurerestore.cpp:1347-1357).
fn verify_sep_digest(
    identity: &legacy_ios_firmware::BuildIdentity,
    data: &[u8],
) -> Result<(), AuxFirmwareError> {
    let digest = identity
        .manifest()
        .get("RestoreSEP")
        .and_then(Value::as_dictionary)
        .and_then(|entry| entry.get("Digest"))
        .and_then(Value::as_data)
        .ok_or(AuxFirmwareError::MissingSepDigest)?;
    let actual = if digest.len() == 20 {
        Sha1::digest(data).to_vec()
    } else {
        Sha384::digest(data).to_vec()
    };
    if actual.as_slice() != digest {
        return Err(AuxFirmwareError::SepDigestMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SepError {
    #[error("restore plan device has no board config")]
    MissingBoardConfig,
    #[error("restore plan device has no ECID")]
    MissingEcid,
    #[error("device did not report a SEP nonce")]
    MissingSepNonce,
    #[error("device did not report an AP nonce")]
    MissingApNonce,
    #[error("device info is missing {0}")]
    MissingDeviceInfo(&'static str),
    #[error(transparent)]
    Aux(#[from] AuxFirmwareError),
    #[error(transparent)]
    Firmware(#[from] legacy_ios_firmware::FirmwareError),
    #[error(transparent)]
    Tss(#[from] TssError),
    #[error(transparent)]
    Personalization(#[from] PersonalizationError),
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use legacy_ios_core::BoardConfig;
    use legacy_ios_firmware::{BuildManifest, RestoreBehavior};
    use legacy_ios_image::{Img3, Img3Element, Img3Tag};
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    fn digest_entry(digest: Option<Vec<u8>>) -> String {
        let Some(digest) = digest else {
            return String::new();
        };
        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &plist::Value::Data(digest)).unwrap();
        let xml = String::from_utf8(buffer).unwrap();
        let inner = xml
            .split("<data>")
            .nth(1)
            .unwrap()
            .split("</data>")
            .next()
            .unwrap();
        format!("<key>Digest</key><data>{inner}</data>")
    }

    fn identity_with_sep(digest: Option<Vec<u8>>) -> legacy_ios_firmware::BuildIdentity {
        let digest_entry = digest_entry(digest);
        let manifest = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>10.3.3</string>
<key>ProductBuildVersion</key><string>14G60</string>
<key>SupportedProductTypes</key><array><string>iPhone6,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n51ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>
<key>RestoreSEP</key><dict>{digest_entry}<key>Info</key><dict><key>Path</key><string>Firmware/all_flash/sep-firmware.n51ap.RELEASE.im4p</string></dict></dict>
</dict>
</dict></array>
</dict></plist>"#
        );
        BuildManifest::from_reader(Cursor::new(manifest))
            .unwrap()
            .select_identity(&BoardConfig::from("n51"), RestoreBehavior::Erase)
            .unwrap()
            .clone()
    }

    #[test]
    fn sep_digest_verification_follows_the_digest_length() {
        let data = b"sep firmware bytes";
        let sha1 = Sha1::digest(data).to_vec();
        let identity = identity_with_sep(Some(sha1));
        verify_sep_digest(&identity, data).unwrap();

        let sha384 = Sha384::digest(data).to_vec();
        let identity = identity_with_sep(Some(sha384));
        verify_sep_digest(&identity, data).unwrap();

        let identity = identity_with_sep(Some(Sha1::digest(b"other").to_vec()));
        assert!(matches!(
            verify_sep_digest(&identity, data),
            Err(AuxFirmwareError::SepDigestMismatch)
        ));

        let identity = identity_with_sep(None);
        assert!(matches!(
            verify_sep_digest(&identity, data),
            Err(AuxFirmwareError::MissingSepDigest)
        ));
    }

    fn img3_blob() -> Vec<u8> {
        [
            Img3Element::new(Img3Tag::ECID, vec![1]),
            Img3Element::new(Img3Tag::SHSH, vec![2]),
            Img3Element::new(Img3Tag::CERT, vec![3]),
        ]
        .into_iter()
        .flat_map(|element| {
            let image = Img3::new(0, vec![element]);
            image.to_bytes()[20..].to_vec()
        })
        .collect()
    }

    #[tokio::test]
    async fn sep_payload_personalizes_all_nor_components_with_the_sep_ticket() {
        let restore_sep = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, b"rsep".to_vec())]);
        let sep = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, b"sep".to_vec())]);
        let stage1 = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, b"stage1".to_vec())]);

        let manifest = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>10.3.3</string>
<key>ProductBuildVersion</key><string>14G60</string>
<key>SupportedProductTypes</key><array><string>iPhone6,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n51ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>
<key>RestoreSEP</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/sep-firmware.n51ap.RELEASE.im4p</string></dict></dict>
<key>SEP</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/sep.n51ap.im4p</string></dict></dict>
<key>SepStage1</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/sep-stage1.n51ap.im4p</string></dict></dict>
</dict>
</dict></array>
</dict></plist>"#;

        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(manifest.as_bytes()).unwrap();
        for (path, image) in [
            (
                "Firmware/all_flash/sep-firmware.n51ap.RELEASE.im4p",
                &restore_sep,
            ),
            ("Firmware/all_flash/sep.n51ap.im4p", &sep),
            ("Firmware/all_flash/sep-stage1.n51ap.im4p", &stage1),
        ] {
            writer
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&image.to_bytes()).unwrap();
        }
        writer.finish().unwrap();

        let context = AuxContext::from_local(
            file.path(),
            &BoardConfig::from("n51"),
            RestoreBehavior::Erase,
        )
        .unwrap();

        // A synthetic img3 SEP ticket: per-component blobs.
        let mut ticket = Dictionary::new();
        for component in ["RestoreSEP", "SEP", "SepStage1"] {
            let mut entry = Dictionary::new();
            entry.insert("Blob".into(), Value::Data(img3_blob()));
            ticket.insert(component.into(), entry.into());
        }

        let payload = build_sep_payload(&context, restore_sep.to_bytes(), &ticket)
            .await
            .unwrap();

        // Every payload is the img3 resealed with its ticket blob.
        assert!(
            Img3::parse(payload.restore_sep())
                .unwrap()
                .is_personalized()
        );
        assert_eq!(payload.nor_images().len(), 3);
        for (key, data) in payload.nor_images() {
            assert!(Img3::parse(data).unwrap().is_personalized(), "{key}");
        }
        assert_eq!(payload.nor_images()[0].0, "RestoreSEPImageData");
        assert_eq!(payload.nor_images()[1].0, "SEPImageData");
        assert_eq!(payload.nor_images()[2].0, "SEPPatchImageData");
    }
}
