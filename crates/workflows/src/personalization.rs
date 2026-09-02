use legacy_ios_firmware::{BuildIdentity, FirmwareArchive, FirmwareError};
use legacy_ios_image::{Img3, Img3Error, Img4Error, personalize_img4};
use legacy_ios_restore::PreparedRestoreData;
use plist::{Dictionary, Value};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ComponentPersonalizer {
    archive: FirmwareArchive,
    identity: BuildIdentity,
    tss: Dictionary,
}

impl ComponentPersonalizer {
    pub fn new(archive: FirmwareArchive, identity: BuildIdentity, tss: Dictionary) -> Self {
        Self {
            archive,
            identity,
            tss,
        }
    }

    pub fn root_ticket(&self) -> Option<&[u8]> {
        self.tss
            .get("ApImg4Ticket")
            .or_else(|| self.tss.get("APTicket"))
            .and_then(Value::as_data)
    }

    pub fn personalize(&self, component: &str) -> Result<Vec<u8>, PersonalizationError> {
        let path = self.component_path(component)?;
        self.personalize_path(component, &path)
    }

    /// Personalize component bytes that did not come from the archive (the
    /// rdsk/rkrn boot overrides), applying the same ticket rules as
    /// [`Self::personalize`].
    pub fn personalize_data(
        &self,
        component: &str,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, PersonalizationError> {
        personalize_data(component, data, &self.tss)
    }

    pub fn nor_response(
        &self,
        flash_version_1: bool,
        include_sep: bool,
    ) -> Result<Dictionary, PersonalizationError> {
        let llb = self.personalize("LLB")?;
        let firmware = self.firmware_components()?;
        let mut images = firmware
            .into_iter()
            .filter(|(component, _)| component != "LLB" && component != "RestoreSEP")
            .map(|(component, path)| {
                let data = self.personalize_path(&component, &path)?;
                Ok((component, data))
            })
            .collect::<Result<Vec<_>, PersonalizationError>>()?;
        if images.is_empty() {
            return Err(PersonalizationError::MissingFirmwarePayloads);
        }
        if !flash_version_1 {
            images.sort_by_key(|(component, _)| !component.starts_with("iBoot"));
        }

        let mut response = Dictionary::new();
        response.insert("LlbImageData".into(), Value::Data(llb));
        if flash_version_1 {
            let images = images
                .into_iter()
                .map(|(component, data)| (component, Value::Data(data)))
                .collect::<Dictionary>();
            response.insert("NorImageData".into(), images.into());
        } else {
            response.insert(
                "NorImageData".into(),
                Value::Array(
                    images
                        .into_iter()
                        .map(|(_, data)| Value::Data(data))
                        .collect(),
                ),
            );
        }
        if include_sep {
            for (component, key) in [
                ("RestoreSEP", "RestoreSEPImageData"),
                ("SEP", "SEPImageData"),
                ("SepStage1", "SEPPatchImageData"),
            ] {
                if self.identity.manifest().contains_key(component) {
                    response.insert(key.into(), Value::Data(self.personalize(component)?));
                }
            }
        }
        Ok(response)
    }

    pub fn prepare_restore_data(
        &self,
        flash_version_1: bool,
        include_sep: bool,
    ) -> Result<PreparedRestoreData, PersonalizationError> {
        let mut prepared = PreparedRestoreData::default();
        if let Some(ticket) = self.root_ticket() {
            prepared = prepared.with_root_ticket(ticket.to_vec());
        }
        if self.identity.manifest().contains_key("KernelCache") {
            prepared = prepared.with_kernel_cache(self.personalize("KernelCache")?);
        }
        if self.identity.manifest().contains_key("DeviceTree") {
            prepared = prepared.with_device_tree(self.personalize("DeviceTree")?);
        }
        if self.identity.manifest().contains_key("SystemVolume") {
            prepared = prepared.with_system_image_root_hash(self.personalize("SystemVolume")?);
        }
        if self
            .identity
            .manifest()
            .contains_key("Ap,SystemVolumeCanonicalMetadata")
        {
            prepared = prepared.with_system_image_canonical_metadata(
                self.personalize("Ap,SystemVolumeCanonicalMetadata")?,
            );
        }
        if self.identity.manifest().contains_key("LLB") {
            prepared = prepared.with_nor(self.nor_response(flash_version_1, include_sep)?);
        }
        Ok(prepared)
    }

    fn component_path(&self, component: &str) -> Result<String, PersonalizationError> {
        self.tss
            .get(component)
            .and_then(Value::as_dictionary)
            .and_then(|entry| entry.get("Path"))
            .and_then(Value::as_string)
            .map(ToOwned::to_owned)
            .map_or_else(
                || {
                    self.identity
                        .component_path(component)
                        .map(ToOwned::to_owned)
                },
                Ok,
            )
            .map_err(Into::into)
    }

    fn personalize_path(
        &self,
        component: &str,
        path: &str,
    ) -> Result<Vec<u8>, PersonalizationError> {
        let data = self.archive.read_entry(path)?;
        personalize_data(component, data, &self.tss)
    }

    fn firmware_components(&self) -> Result<Vec<(String, String)>, PersonalizationError> {
        let llb_path = self.component_path("LLB")?;
        let directory = llb_path
            .rsplit_once('/')
            .map(|(directory, _)| directory)
            .ok_or(PersonalizationError::MissingFirmwareDirectory)?;
        let manifest_path = format!("{directory}/manifest");
        match self.archive.read_entry(&manifest_path) {
            Ok(data) => {
                let manifest = String::from_utf8(data)?;
                Ok(manifest
                    .lines()
                    .filter_map(|line| {
                        let filename = line.trim_end_matches('\r');
                        component_name(filename).map(|component| {
                            (component.to_owned(), format!("{directory}/{filename}"))
                        })
                    })
                    .collect())
            }
            Err(FirmwareError::ArchiveEntryNotFound(_)) => Ok(self
                .identity
                .manifest()
                .iter()
                .filter_map(|(component, value)| {
                    let info = value.as_dictionary()?.get("Info")?.as_dictionary()?;
                    let firmware = info
                        .get("IsFirmwarePayload")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    let secondary = info
                        .get("IsSecondaryFirmwarePayload")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    let loaded_by_iboot = info
                        .get("IsLoadedByiBoot")
                        .and_then(Value::as_boolean)
                        .unwrap_or(false);
                    (firmware || secondary && loaded_by_iboot).then(|| {
                        let path = info.get("Path")?.as_string()?;
                        Some((component.clone(), path.to_owned()))
                    })?
                })
                .collect()),
            Err(error) => Err(error.into()),
        }
    }
}

fn component_name(filename: &str) -> Option<&'static str> {
    [
        ("LLB", "LLB"),
        ("iBoot", "iBoot"),
        ("DeviceTree", "DeviceTree"),
        ("applelogo", "AppleLogo"),
        ("liquiddetect", "Liquid"),
        ("lowpowermode", "LowPowerWallet0"),
        ("recoverymode", "RecoveryMode"),
        ("batterylow0", "BatteryLow0"),
        ("batterylow1", "BatteryLow1"),
        ("glyphcharging", "BatteryCharging"),
        ("glyphplugin", "BatteryPlugin"),
        ("batterycharging0", "BatteryCharging0"),
        ("batterycharging1", "BatteryCharging1"),
        ("batteryfull", "BatteryFull"),
        ("needservice", "NeedService"),
        ("SCAB", "SCAB"),
        ("sep-firmware", "RestoreSEP"),
    ]
    .into_iter()
    .find_map(|(prefix, component)| filename.starts_with(prefix).then_some(component))
}

fn personalize_data(
    component: &str,
    data: Vec<u8>,
    tss: &Dictionary,
) -> Result<Vec<u8>, PersonalizationError> {
    if let Some(ticket) = tss.get("ApImg4Ticket").and_then(Value::as_data) {
        return Ok(personalize_img4(component, &data, ticket)?);
    }
    let blob = tss
        .get(component)
        .and_then(Value::as_dictionary)
        .and_then(|entry| entry.get("Blob"))
        .and_then(Value::as_data);
    if let Some(blob) = blob {
        return Ok(Img3::parse(&data)?.personalize(blob)?.to_bytes());
    }
    Ok(data)
}

#[derive(Debug, Error)]
pub enum PersonalizationError {
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Img3(#[from] Img3Error),
    #[error(transparent)]
    Img4(#[from] Img4Error),
    #[error("LLB path has no firmware directory")]
    MissingFirmwareDirectory,
    #[error("firmware manifest contains no NOR payloads")]
    MissingFirmwarePayloads,
    #[error("firmware manifest is not UTF-8")]
    ManifestEncoding(#[from] std::string::FromUtf8Error),
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_core::BoardConfig;
    use legacy_ios_firmware::{BuildManifest, RestoreBehavior};
    use legacy_ios_image::{Img3Element, Img3Tag};
    use tempfile::NamedTempFile;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    #[test]
    fn applies_component_img3_blob() {
        let image = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, vec![1, 2, 3])]);
        let blob = [
            Img3Element::new(Img3Tag::ECID, vec![1]),
            Img3Element::new(Img3Tag::SHSH, vec![2]),
            Img3Element::new(Img3Tag::CERT, vec![3]),
        ]
        .into_iter()
        .flat_map(|element| {
            let image = Img3::new(0, vec![element]);
            image.to_bytes()[20..].to_vec()
        })
        .collect::<Vec<_>>();
        let mut entry = Dictionary::new();
        entry.insert("Blob".into(), Value::Data(blob));
        let mut tss = Dictionary::new();
        tss.insert("iBSS".into(), entry.into());

        let result = personalize_data("iBSS", image.to_bytes(), &tss).unwrap();
        assert!(Img3::parse(&result).unwrap().is_personalized());
    }

    #[test]
    fn builds_nor_response_from_all_flash_manifest() {
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(MANIFEST.as_bytes()).unwrap();
        for (name, data) in [
            (
                "Firmware/all_flash/manifest",
                b"iBoot.n90\nLLB.n90\n".as_slice(),
            ),
            ("Firmware/all_flash/LLB.n90", b"llb".as_slice()),
            ("Firmware/all_flash/iBoot.n90", b"iboot".as_slice()),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();

        let archive = FirmwareArchive::open(file.path()).unwrap();
        let manifest = BuildManifest::from_reader(std::io::Cursor::new(MANIFEST)).unwrap();
        let identity = manifest
            .select_identity(&BoardConfig::from("n90"), RestoreBehavior::Erase)
            .unwrap()
            .clone();
        let response = ComponentPersonalizer::new(archive, identity, Dictionary::new())
            .nor_response(false, true)
            .unwrap();

        assert_eq!(
            response.get("LlbImageData").and_then(Value::as_data),
            Some(b"llb".as_slice())
        );
        let images = response
            .get("NorImageData")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(images[0].as_data(), Some(b"iboot".as_slice()));
    }

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>7.1.2</string>
<key>ProductBuildVersion</key><string>11D257</string>
<key>SupportedProductTypes</key><array><string>iPhone3,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n90ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict><key>LLB</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/all_flash/LLB.n90</string></dict></dict></dict>
</dict></array>
</dict></plist>"#;
}
