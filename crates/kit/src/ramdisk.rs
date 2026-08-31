use std::path::PathBuf;

use legacy_ios_core::BoardConfig;
use legacy_ios_firmware::{FirmwareArchive, RestoreBehavior};
use legacy_ios_image::{HfsImage, extract_image_payload, replace_image_payload};
use serde::Serialize;

use crate::{
    HfsMutation, ImageCipher, KitError,
    hfs::{apply_mutations, write_atomic},
};

#[derive(Clone, Debug)]
pub struct RamdiskBuildRequest {
    firmware: PathBuf,
    destination: PathBuf,
    board_config: BoardConfig,
    behavior: RestoreBehavior,
    cipher: Option<ImageCipher>,
    mutations: Vec<HfsMutation>,
}

impl RamdiskBuildRequest {
    pub fn new(
        firmware: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        board_config: BoardConfig,
        behavior: RestoreBehavior,
        mutations: Vec<HfsMutation>,
    ) -> Self {
        Self {
            firmware: firmware.into(),
            destination: destination.into(),
            board_config,
            behavior,
            cipher: None,
            mutations,
        }
    }

    pub fn with_cipher(mut self, cipher: ImageCipher) -> Self {
        self.cipher = Some(cipher);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RamdiskBuildSummary {
    component_path: String,
    destination: PathBuf,
    size: u64,
}

impl RamdiskBuildSummary {
    pub fn component_path(&self) -> &str {
        &self.component_path
    }

    pub fn destination(&self) -> &std::path::Path {
        &self.destination
    }

    pub const fn size(&self) -> u64 {
        self.size
    }
}

pub(crate) async fn build(request: RamdiskBuildRequest) -> Result<RamdiskBuildSummary, KitError> {
    let destination = request.destination.clone();
    let (component_path, output) = tokio::task::spawn_blocking(move || {
        let archive = FirmwareArchive::open(request.firmware)?;
        let manifest = archive.build_manifest()?;
        let identity = manifest.select_identity(&request.board_config, request.behavior)?;
        let component_path = identity.component_path("RestoreRamDisk")?.to_owned();
        let container = archive.read_entry(&component_path)?;
        let encryption = request
            .cipher
            .as_ref()
            .map(|cipher| (cipher.key(), cipher.iv()));
        let payload = extract_image_payload(&container, encryption)?;
        let mut hfs = HfsImage::parse(payload)?;
        apply_mutations(&mut hfs, request.mutations)?;
        let output = replace_image_payload(&container, &hfs.into_bytes(), encryption)?;
        Ok::<_, KitError>((component_path, output))
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    let size = output.len() as u64;
    write_atomic(destination.clone(), output).await?;
    Ok(RamdiskBuildSummary {
        component_path,
        destination,
        size,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use hfsplus::testutil::HfsPlusImageBuilder;
    use legacy_ios_image::{Img3, Img3Element, Img3Tag};
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>6.1.3</string>
<key>ProductBuildVersion</key><string>10B329</string>
<key>SupportedProductTypes</key><array><string>iPhone4,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n94ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.img3</string></dict></dict></dict>
</dict></array></dict></plist>"#;

    #[tokio::test]
    async fn builds_edited_img3_restore_ramdisk() {
        let mut hfs = HfsPlusImageBuilder::new();
        hfs.add_file("tool", b"payload", 0o644);
        let ramdisk = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, hfs.build())]).to_bytes();
        let firmware = tempfile::NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(firmware.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(MANIFEST.as_bytes()).unwrap();
        writer
            .start_file("ramdisk.img3", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&ramdisk).unwrap();
        writer.finish().unwrap();
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("patched.img3");

        build(RamdiskBuildRequest::new(
            firmware.path(),
            &destination,
            BoardConfig::from("n94"),
            RestoreBehavior::Erase,
            vec![HfsMutation::Chmod {
                path: "/tool".into(),
                mode: 0o755,
            }],
        ))
        .await
        .unwrap();

        let output = tokio::fs::read(destination).await.unwrap();
        let payload = Img3::parse(&output).unwrap().payload().unwrap().to_vec();
        assert_eq!(
            HfsImage::parse(payload)
                .unwrap()
                .stat("/tool")
                .unwrap()
                .mode(),
            0o100755
        );
    }
}
