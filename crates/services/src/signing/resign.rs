//! IPA re-signing with an Apple-issued development certificate.
//!
//! Unpacks the IPA, embeds the team provisioning profile, and re-signs the
//! app bundle (including nested frameworks) with the development certificate
//! using the pure-Rust `apple-codesign` crate, then repacks the IPA.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use apple_codesign::{
    BundleSigner, SettingsScope, SigningSettings, cryptography::InMemoryPrivateKey,
};
use plist::Value;
use thiserror::Error;
use tracing::{debug, info};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use super::developer_api::{DevelopmentCertificate, ProvisioningProfile};

#[derive(Debug, Error)]
pub enum ResignError {
    #[error("IPA file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to process the IPA archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("failed to parse a property list: {0}")]
    Plist(#[from] plist::Error),
    #[error("the IPA contains no Payload/*.app bundle")]
    MissingAppBundle,
    #[error("the app bundle Info.plist is missing {0}")]
    MissingInfoValue(&'static str),
    #[error("the provisioning profile does not contain a usable embedded property list")]
    InvalidProfile,
    #[error("the development certificate or private key is not usable: {0}")]
    InvalidIdentity(String),
    #[error("code signing failed: {0}")]
    Codesign(Box<apple_codesign::AppleCodesignError>),
}

impl From<apple_codesign::AppleCodesignError> for ResignError {
    fn from(error: apple_codesign::AppleCodesignError) -> Self {
        Self::Codesign(Box::new(error))
    }
}

/// Read the bundle identifier of the `Payload/*.app` inside an IPA.
pub fn read_ipa_bundle_id(ipa: &Path) -> Result<String, ResignError> {
    let file = File::open(ipa)?;
    let mut archive = ZipArchive::new(file)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let mut components = name.components();
        if components.next().and_then(|c| c.as_os_str().to_str()) != Some("Payload") {
            continue;
        }
        let Some(app) = components.next().and_then(|c| c.as_os_str().to_str()) else {
            continue;
        };
        if !app.ends_with(".app") || name.file_name().and_then(|n| n.to_str()) != Some("Info.plist")
        {
            continue;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        let info: plist::Dictionary = plist::from_bytes(&data)?;
        return info
            .get("CFBundleIdentifier")
            .and_then(Value::as_string)
            .map(ToOwned::to_owned)
            .ok_or(ResignError::MissingInfoValue("CFBundleIdentifier"));
    }
    Err(ResignError::MissingAppBundle)
}

/// Re-sign `ipa` with the development identity and team provisioning profile,
/// writing the signed IPA to `destination`. Returns the app bundle identifier.
pub fn resign_ipa(
    ipa: &Path,
    destination: &Path,
    team_id: &str,
    certificate: &DevelopmentCertificate,
    profile: &ProvisioningProfile,
) -> Result<String, ResignError> {
    let work = tempfile::tempdir()?;
    let extracted = work.path().join("extracted");
    extract_ipa(ipa, &extracted)?;
    let app = find_app_bundle(&extracted)?;
    let bundle_id = bundle_identifier(&app)?;
    debug!(bundle_id, "re-signing app bundle");

    // iOS looks for the provisioning profile at this fixed bundle location.
    std::fs::write(app.join("embedded.mobileprovision"), profile.data())?;
    let entitlements = profile_entitlements(profile.data())?;
    let mut entitlements_xml = Vec::new();
    entitlements.to_writer_xml(&mut entitlements_xml)?;

    let private = InMemoryPrivateKey::from_pkcs8_der(certificate.private_key_der())
        .map_err(|error| ResignError::InvalidIdentity(error.to_string()))?;
    let key_pair = InMemorySigningKeyPair::try_from(private)
        .map_err(|error| ResignError::InvalidIdentity(error.to_string()))?;
    let public = CapturedX509Certificate::from_pem(certificate.certificate_pem())
        .map_err(|error| ResignError::InvalidIdentity(error.to_string()))?;

    let mut settings = SigningSettings::default();
    settings.set_signing_key(&key_pair, public);
    settings.chain_apple_certificates();
    settings.set_team_id(team_id);
    settings.set_entitlements_xml(
        SettingsScope::Main,
        String::from_utf8(entitlements_xml)
            .map_err(|_| ResignError::MissingInfoValue("Entitlements"))?,
    )?;

    let mut signer = BundleSigner::new_from_path(&app)?;
    signer.collect_nested_bundles()?;
    let signed_root = work.path().join("signed");
    signer.write_signed_bundle(&signed_root, &settings)?;
    info!(bundle_id, "re-signed app bundle");

    pack_ipa(&signed_root, destination)?;
    Ok(bundle_id)
}

fn extract_ipa(ipa: &Path, destination: &Path) -> Result<(), ResignError> {
    let file = File::open(ipa)?;
    let mut archive = ZipArchive::new(file)?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let path = destination.join(name);
        if entry.is_dir() {
            std::fs::create_dir_all(&path)?;
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut output = File::create(&path)?;
        std::io::copy(&mut entry, &mut output)?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn find_app_bundle(root: &Path) -> Result<PathBuf, ResignError> {
    let payload = root.join("Payload");
    let entries = std::fs::read_dir(&payload).map_err(|_| ResignError::MissingAppBundle)?;
    let mut apps = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("app"));
    match (apps.next(), apps.next()) {
        (Some(app), None) => Ok(app),
        _ => Err(ResignError::MissingAppBundle),
    }
}

fn bundle_identifier(app: &Path) -> Result<String, ResignError> {
    let info: plist::Dictionary = plist::from_file(app.join("Info.plist"))?;
    info.get("CFBundleIdentifier")
        .and_then(Value::as_string)
        .map(ToOwned::to_owned)
        .ok_or(ResignError::MissingInfoValue("CFBundleIdentifier"))
}

/// Extract the `Entitlements` dictionary from a CMS-signed provisioning
/// profile. The signed plist is embedded verbatim in the PKCS#7 blob, so it
/// is sliced out between the `<?xml` prologue and the closing `</plist>` tag
/// (the same approach `isign` uses).
fn profile_entitlements(profile: &[u8]) -> Result<Value, ResignError> {
    let start = profile
        .windows(5)
        .position(|window| window == b"<?xml")
        .ok_or(ResignError::InvalidProfile)?;
    let end = profile
        .windows(8)
        .rposition(|window| window == b"</plist>")
        .map(|position| position + 8)
        .ok_or(ResignError::InvalidProfile)?;
    let document: plist::Dictionary = plist::from_bytes(&profile[start..end])?;
    document
        .get("Entitlements")
        .cloned()
        .ok_or(ResignError::InvalidProfile)
}

fn pack_ipa(source_root: &Path, destination: &Path) -> Result<(), ResignError> {
    let output = File::create(destination)?;
    let mut writer = ZipWriter::new(output);
    let mut pending = vec![source_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(source_root)
                .map_err(|_| ResignError::MissingAppBundle)?;
            let name = relative
                .to_str()
                .ok_or(ResignError::MissingAppBundle)?
                .replace('\\', "/");
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            #[cfg(unix)]
            let options = {
                use std::os::unix::fs::PermissionsExt;
                let mode = entry.metadata()?.permissions().mode();
                options.unix_permissions(if mode & 0o111 != 0 { 0o755 } else { 0o644 })
            };
            writer.start_file(name, options)?;
            let mut file = File::open(&path)?;
            std::io::copy(&mut file, &mut writer)?;
        }
    }
    writer.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// The embedded-plist slicer must recover the entitlements from a
    /// CMS-style blob that wraps the XML document in binary data.
    #[test]
    fn extracts_entitlements_from_signed_profile() {
        let mut document = Vec::new();
        plist::Value::Dictionary(plist::Dictionary::from_iter([(
            "Entitlements".to_owned(),
            Value::Dictionary(plist::Dictionary::from_iter([(
                "get-task-allow".to_owned(),
                Value::Boolean(true),
            )])),
        )]))
        .to_writer_xml(&mut document)
        .unwrap();
        let mut blob = vec![0x30, 0x82, 0x01, 0x00];
        blob.extend_from_slice(&document);
        blob.extend_from_slice(&[0xa0, 0x82, 0x02]);
        let entitlements = profile_entitlements(&blob).expect("entitlements");
        let dictionary = entitlements.as_dictionary().expect("dictionary");
        assert_eq!(
            dictionary.get("get-task-allow").and_then(Value::as_boolean),
            Some(true)
        );
    }

    #[test]
    fn rejects_profile_without_plist() {
        assert!(matches!(
            profile_entitlements(&[0x30, 0x82, 0x00]),
            Err(ResignError::InvalidProfile)
        ));
    }

    #[test]
    fn reads_bundle_id_from_ipa() {
        let directory = tempfile::tempdir().unwrap();
        let ipa = directory.path().join("test.ipa");
        {
            let file = File::create(&ipa).unwrap();
            let mut writer = ZipWriter::new(file);
            let options = SimpleFileOptions::default();
            let mut info = Vec::new();
            plist::Value::Dictionary(plist::Dictionary::from_iter([(
                "CFBundleIdentifier".to_owned(),
                Value::String("com.example.app".to_owned()),
            )]))
            .to_writer_xml(&mut info)
            .unwrap();
            writer
                .start_file("Payload/Test.app/Info.plist", options)
                .unwrap();
            writer.write_all(&info).unwrap();
            writer.finish().unwrap();
        }
        assert_eq!(read_ipa_bundle_id(&ipa).unwrap(), "com.example.app");
    }

    #[test]
    fn rejects_ipa_without_app_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let ipa = directory.path().join("empty.ipa");
        {
            let file = File::create(&ipa).unwrap();
            let mut writer = ZipWriter::new(file);
            writer
                .start_file("README.txt", SimpleFileOptions::default())
                .unwrap();
            writer.finish().unwrap();
        }
        assert!(matches!(
            read_ipa_bundle_id(&ipa),
            Err(ResignError::MissingAppBundle)
        ));
    }
}
