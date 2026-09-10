use std::io::{Cursor, Read, Write};

use legacy_ios_firmware::{
    BasebandParameters, BuildIdentity, FirmwareArchive, FirmwareError, TssClient, TssError,
    TssRequest,
};
use legacy_ios_image::{FlsError, FlsFile, MbnError, MbnFile};
use legacy_ios_restore::DataRequest;
use plist::{Dictionary, Value};
use sha1::{Digest as _, Sha1};
use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{RestorePlan, auxiliary::AuxContext};

const MAX_ENTRY_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct BasebandFirmware {
    archive: Vec<u8>,
}

impl BasebandFirmware {
    pub fn sign(
        archive: &[u8],
        tss: &Dictionary,
        nonce: Option<&[u8]>,
        chip_id: u32,
    ) -> Result<Self, BasebandError> {
        let ticket = tss
            .get("BBTicket")
            .and_then(Value::as_data)
            .ok_or(BasebandError::MissingTicket)?;
        let signatures = tss
            .get("BasebandFirmware")
            .and_then(Value::as_dictionary)
            .ok_or(BasebandError::MissingSignatures)?;

        let mut entries = read_entries(archive)?;
        let mut uses_fls = false;
        for (key, value) in signatures {
            let Some(element) = key.strip_suffix("-Blob") else {
                continue;
            };
            let signature = value
                .as_data()
                .ok_or_else(|| BasebandError::InvalidSignature(key.clone()))?;
            let name = firmware_name(element, chip_id)
                .ok_or_else(|| BasebandError::UnknownElement(element.to_owned()))?;
            let entry = entries
                .iter_mut()
                .find(|entry| entry.name == name)
                .ok_or_else(|| BasebandError::MissingEntry(name.to_owned()))?;
            if name.ends_with(".fls") {
                uses_fls = true;
                let mut file = FlsFile::parse(&entry.data)?;
                file.replace_signature(signature)?;
                entry.data = file.to_bytes();
                entry.keep = nonce.is_some() || element == "RamPSI";
            } else {
                let mut file = MbnFile::parse(entry.data.clone())?;
                file.replace_signature(signature)?;
                entry.data = file.into_bytes();
                entry.keep = true;
            }
        }

        entries.retain(|entry| entry.keep || is_firmware_file(&entry.name));
        if uses_fls {
            let entry = entries
                .iter_mut()
                .find(|entry| entry.name == "ebl.fls")
                .ok_or(BasebandError::MissingEntry("ebl.fls".into()))?;
            let mut file = FlsFile::parse(&entry.data)?;
            file.insert_ticket(ticket)?;
            entry.data = file.to_bytes();
        } else {
            entries.retain(|entry| entry.name != "bbticket.der");
            entries.push(ArchiveEntry {
                name: "bbticket.der".into(),
                data: ticket.to_vec(),
                keep: true,
            });
        }

        Ok(Self {
            archive: write_entries(entries)?,
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.archive
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.archive
    }

    pub fn into_restore_response(self) -> Dictionary {
        let mut response = Dictionary::new();
        response.insert("BasebandData".into(), Value::Data(self.archive));
        response
    }
}

#[derive(Clone, Debug)]
pub struct BasebandResolver {
    _inputs: Vec<crate::input::PinnedInput>,
    archive: crate::auxiliary::AuxArchive,
    identity: BuildIdentity,
    firmware_path: String,
    firmware_sha1: Option<String>,
    tss: TssClient,
    ecid: legacy_ios_core::Ecid,
}

impl BasebandResolver {
    /// Resolve against the plan's aux firmware source: the target archive
    /// when the aux build equals the target build, otherwise a remote archive
    /// over the plan-recorded URL (upstream `restore_download_bbsep`). No
    /// resolver is built when the plan disabled the baseband update (bb2
    /// rules) or the device has none.
    pub async fn from_plan(
        plan: &RestorePlan,
        tss: TssClient,
    ) -> Result<Option<Self>, BasebandRequestError> {
        let Some(aux) = plan.aux_firmware() else {
            return Ok(None);
        };
        let Some(baseband) = aux.baseband() else {
            return Ok(None);
        };
        let context = AuxContext::open(plan, aux).await?;
        let ecid = plan
            .device()
            .ecid()
            .ok_or(BasebandRequestError::MissingEcid)?;
        Ok(Some(Self {
            _inputs: plan.retained_inputs(),
            archive: context.archive().clone(),
            identity: context.identity().clone(),
            firmware_path: baseband.path().to_owned(),
            firmware_sha1: baseband.sha1().map(str::to_owned),
            tss,
            ecid,
        }))
    }

    /// Resolve against an already-opened archive and build identity (used by
    /// callers without a [`RestorePlan`], e.g. classic foreign restores).
    pub fn from_identity(
        archive: FirmwareArchive,
        identity: BuildIdentity,
        tss: TssClient,
        ecid: legacy_ios_core::Ecid,
    ) -> Result<Self, BasebandRequestError> {
        let firmware_path = identity.component_path("BasebandFirmware")?.to_owned();
        Ok(Self {
            _inputs: Vec::new(),
            archive: crate::auxiliary::AuxArchive::Local(archive),
            identity,
            firmware_path,
            firmware_sha1: None,
            tss,
            ecid,
        })
    }

    pub fn from_firmware(
        plan: &RestorePlan,
        firmware: &std::path::Path,
        tss: TssClient,
    ) -> Result<Self, BasebandRequestError> {
        let archive = FirmwareArchive::open(firmware)?;
        let manifest = archive.build_manifest()?;
        let board = plan
            .device()
            .board_config()
            .ok_or(BasebandRequestError::MissingBoardConfig)?;
        let identity = manifest.select_identity(board, plan.behavior())?.clone();
        let ecid = plan
            .device()
            .ecid()
            .ok_or(BasebandRequestError::MissingEcid)?;
        let mut resolver = Self::from_identity(archive, identity, tss, ecid)?;
        resolver._inputs = plan.retained_inputs();
        Ok(resolver)
    }

    pub async fn resolve(&self, request: &DataRequest) -> Result<Dictionary, BasebandRequestError> {
        let arguments = request
            .message()
            .get("Arguments")
            .and_then(Value::as_dictionary)
            .ok_or(BasebandRequestError::MissingArgument("Arguments"))?;
        let (parameters, nonce, chip_id) = baseband_parameters(arguments, self.ecid)?;
        let data = match &self.archive {
            crate::auxiliary::AuxArchive::Local(archive) => {
                let archive = archive.clone();
                let path = self.firmware_path.clone();
                tokio::task::spawn_blocking(move || archive.read_entry(&path))
                    .await
                    .map_err(|error| BasebandRequestError::Task(error.to_string()))??
            }
            crate::auxiliary::AuxArchive::Remote(archive) => archive
                .read_entry(&self.firmware_path)
                .await
                .map_err(crate::auxiliary::AuxFirmwareError::from)?,
        };
        // The plan-recorded table SHA-1 pins the aux baseband content
        // (upstream verifies the download the same way, restore.sh:6116-6126).
        if let Some(expected) = &self.firmware_sha1 {
            let actual = hex::encode(Sha1::digest(&data));
            if actual != *expected {
                return Err(BasebandRequestError::FirmwareDigestMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        let request = TssRequest::for_baseband(&self.identity, &parameters)?;
        let response = self.tss.send(&request).await?.into_dictionary();
        let signed = tokio::task::spawn_blocking(move || {
            Ok::<_, BasebandRequestError>(BasebandFirmware::sign(
                &data,
                &response,
                nonce.as_deref(),
                chip_id,
            )?)
        })
        .await
        .map_err(|error| BasebandRequestError::Task(error.to_string()))??;
        Ok(signed.into_restore_response())
    }
}

/// Live baseband TSS parameters of a restored BasebandData request
/// (idevicerestore `restore_send_baseband_data`, restore.c:2314-2346).
fn baseband_parameters(
    arguments: &Dictionary,
    ecid: legacy_ios_core::Ecid,
) -> Result<(BasebandParameters, Option<Vec<u8>>, u32), BasebandRequestError> {
    let chip_id = required_unsigned(arguments, "ChipID")?;
    let chip_id =
        u32::try_from(chip_id).map_err(|_| BasebandRequestError::MissingArgument("ChipID"))?;
    let certificate_id = required_unsigned(arguments, "CertID")?;
    let serial_number = arguments
        .get("ChipSerialNo")
        .and_then(Value::as_data)
        .ok_or(BasebandRequestError::MissingArgument("ChipSerialNo"))?
        .to_vec();
    let nonce = arguments
        .get("Nonce")
        .and_then(Value::as_data)
        .map(ToOwned::to_owned);
    let mut parameters =
        BasebandParameters::new(ecid, u64::from(chip_id), certificate_id, serial_number);
    if let Some(nonce) = &nonce {
        parameters = parameters.with_nonce(nonce.clone());
    }
    Ok((parameters, nonce, chip_id))
}

fn required_unsigned(
    dictionary: &Dictionary,
    key: &'static str,
) -> Result<u64, BasebandRequestError> {
    dictionary
        .get(key)
        .and_then(Value::as_unsigned_integer)
        .ok_or(BasebandRequestError::MissingArgument(key))
}

#[derive(Debug, Error)]
pub enum BasebandRequestError {
    #[error("baseband updates are disabled for this restore")]
    Disabled,
    #[error("restore plan has no board config")]
    MissingBoardConfig,
    #[error("restore plan has no ECID")]
    MissingEcid,
    #[error("baseband request is missing {0}")]
    MissingArgument(&'static str),
    #[error("baseband firmware SHA-1 mismatch: expected {expected}, got {actual}")]
    FirmwareDigestMismatch { expected: String, actual: String },
    #[error("baseband worker task failed: {0}")]
    Task(String),
    #[error(transparent)]
    Aux(#[from] crate::auxiliary::AuxFirmwareError),
    #[error(transparent)]
    Firmware(#[from] FirmwareError),
    #[error(transparent)]
    Tss(#[from] TssError),
    #[error(transparent)]
    Signing(#[from] BasebandError),
}

#[derive(Debug)]
struct ArchiveEntry {
    name: String,
    data: Vec<u8>,
    keep: bool,
}

fn read_entries(data: &[u8]) -> Result<Vec<ArchiveEntry>, BasebandError> {
    let mut archive = ZipArchive::new(Cursor::new(data))?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        if entry.size() > MAX_ENTRY_SIZE {
            return Err(BasebandError::EntryTooLarge(entry.name().to_owned()));
        }
        let mut contents = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut contents)?;
        entries.push(ArchiveEntry {
            name: entry.name().to_owned(),
            data: contents,
            keep: false,
        });
    }
    Ok(entries)
}

fn write_entries(entries: Vec<ArchiveEntry>) -> Result<Vec<u8>, BasebandError> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for entry in entries {
        writer.start_file(entry.name, options)?;
        writer.write_all(&entry.data)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn is_firmware_file(name: &str) -> bool {
    [".fls", ".mbn", ".elf", ".bin"]
        .iter()
        .any(|extension| name.ends_with(extension))
}

fn firmware_name(element: &str, chip_id: u32) -> Option<&'static str> {
    if chip_id == 0x1f30e1 {
        return match element {
            "Misc" => Some("multi_image.mbn"),
            "RestoreSBL1" => Some("restorexbl_sc.elf"),
            "SBL1" => Some("xbl_sc.elf"),
            "TME" => Some("signed_firmware_soc_view.elf"),
            _ => None,
        };
    }
    match element {
        "RamPSI" => Some("psi_ram.fls"),
        "FlashPSI" => Some("psi_flash.fls"),
        "eDBL" | "DBL" => Some("dbl.mbn"),
        "RestoreDBL" => Some("restoredbl.mbn"),
        "ENANDPRG" => Some("ENPRG.mbn"),
        "RestoreSBL1" => Some("restoresbl1.mbn"),
        "SBL1" => Some("sbl1.mbn"),
        "RestorePSI" => Some("restorepsi.bin"),
        "PSI" => Some("psi_ram.bin"),
        "RestorePSI2" => Some("restorepsi2.bin"),
        "PSI2" => Some("psi_ram2.bin"),
        "Misc" => Some("multi_image.mbn"),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum BasebandError {
    #[error("baseband TSS response has no BBTicket")]
    MissingTicket,
    #[error("baseband TSS response has no BasebandFirmware signatures")]
    MissingSignatures,
    #[error("baseband signature {0} is not data")]
    InvalidSignature(String),
    #[error("unknown baseband firmware element {0}")]
    UnknownElement(String),
    #[error("baseband archive has no {0}")]
    MissingEntry(String),
    #[error("baseband archive entry {0} is too large")]
    EntryTooLarge(String),
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Fls(#[from] FlsError),
    #[error(transparent)]
    Mbn(#[from] MbnError),
}

#[cfg(test)]
mod tests {
    use legacy_ios_core::Ecid;
    use legacy_ios_restore::RestoredMessage;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn parses_baseband_tss_parameters_from_request_arguments() {
        let mut arguments = Dictionary::new();
        arguments.insert("ChipID".into(), 0x5a00e1_u64.into());
        arguments.insert("CertID".into(), 257_u64.into());
        arguments.insert("ChipSerialNo".into(), Value::Data(vec![1, 2, 3, 4]));
        arguments.insert("Nonce".into(), Value::Data(vec![5, 6]));

        let (parameters, nonce, chip_id) = baseband_parameters(&arguments, Ecid::new(42)).unwrap();
        assert_eq!(parameters.ecid, Ecid::new(42));
        assert_eq!(parameters.chip_id, 0x5a00e1);
        assert_eq!(parameters.gold_cert_id, 257);
        assert_eq!(parameters.serial_number, [1, 2, 3, 4]);
        assert_eq!(nonce.as_deref(), Some([5, 6].as_slice()));
        assert_eq!(parameters.nonce.as_deref(), Some([5, 6].as_slice()));
        assert_eq!(chip_id, 0x5a00e1);
    }

    #[test]
    fn baseband_parameters_require_chip_serial_number() {
        let mut arguments = Dictionary::new();
        arguments.insert("ChipID".into(), 1_u64.into());
        arguments.insert("CertID".into(), 2_u64.into());

        assert!(matches!(
            baseband_parameters(&arguments, Ecid::new(42)),
            Err(BasebandRequestError::MissingArgument("ChipSerialNo"))
        ));
    }

    #[test]
    fn signs_mbn_and_embeds_ticket() {
        let mut source = ZipWriter::new(Cursor::new(Vec::new()));
        source
            .start_file("sbl1.mbn", SimpleFileOptions::default())
            .unwrap();
        let mut mbn = b"\x0a\0\0\0".to_vec();
        mbn.extend_from_slice(&[0; 12]);
        source.write_all(&mbn).unwrap();
        source
            .start_file("metadata.plist", SimpleFileOptions::default())
            .unwrap();
        source.write_all(b"discarded").unwrap();
        let source = source.finish().unwrap().into_inner();

        let mut signatures = Dictionary::new();
        signatures.insert("SBL1-Blob".into(), Value::Data(vec![1, 2, 3, 4]));
        let mut tss = Dictionary::new();
        tss.insert("BBTicket".into(), Value::Data(vec![5, 6]));
        tss.insert("BasebandFirmware".into(), signatures.into());

        let signed = BasebandFirmware::sign(&source, &tss, None, 0).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(signed.data())).unwrap();
        let mut signed_mbn = Vec::new();
        archive
            .by_name("sbl1.mbn")
            .unwrap()
            .read_to_end(&mut signed_mbn)
            .unwrap();
        assert_eq!(&signed_mbn[12..], &[1, 2, 3, 4]);
        let mut ticket = Vec::new();
        archive
            .by_name("bbticket.der")
            .unwrap()
            .read_to_end(&mut ticket)
            .unwrap();
        assert_eq!(ticket, [5, 6]);
        assert!(archive.by_name("metadata.plist").is_err());
    }

    #[tokio::test]
    async fn aux_baseband_sha1_mismatch_fails_before_the_tss_request() {
        // A resolver over a local archive whose recorded SHA-1 does not match
        // the entry content fails loudly without contacting TSS.
        let file = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Firmware/baseband.bbfw", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"baseband bytes").unwrap();
        writer.finish().unwrap();

        let archive = FirmwareArchive::open(file.path()).unwrap();
        let manifest = legacy_ios_firmware::BuildManifest::from_reader(Cursor::new(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>9.3.6</string><key>ProductBuildVersion</key><string>13G37</string>
<key>SupportedProductTypes</key><array><string>iPhone4,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n94ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>
<key>BasebandFirmware</key><dict><key>Info</key><dict><key>Path</key><string>Firmware/baseband.bbfw</string></dict></dict>
</dict>
</dict></array>
</dict></plist>"#,
        ))
        .unwrap();
        let identity = manifest
            .select_identity(
                &legacy_ios_core::BoardConfig::from("n94"),
                legacy_ios_firmware::RestoreBehavior::Erase,
            )
            .unwrap()
            .clone();
        let resolver = BasebandResolver {
            _inputs: Vec::new(),
            archive: crate::auxiliary::AuxArchive::Local(archive),
            identity,
            firmware_path: "Firmware/baseband.bbfw".to_owned(),
            firmware_sha1: Some(hex::encode(Sha1::digest(b"different bytes"))),
            tss: TssClient::new(),
            ecid: Ecid::new(42),
        };

        let mut arguments = Dictionary::new();
        arguments.insert("ChipID".into(), 0x5a00e1_u64.into());
        arguments.insert("CertID".into(), 257_u64.into());
        arguments.insert("ChipSerialNo".into(), Value::Data(vec![1, 2, 3, 4]));
        let mut message = Dictionary::new();
        message.insert("MsgType".into(), "DataRequestMsg".into());
        message.insert("DataType".into(), "BasebandData".into());
        message.insert("Arguments".into(), arguments.into());
        let RestoredMessage::DataRequest(request) = RestoredMessage::parse(message) else {
            panic!("expected data request");
        };

        let error = resolver.resolve(&request).await.unwrap_err();
        assert!(
            matches!(error, BasebandRequestError::FirmwareDigestMismatch { .. }),
            "{error}"
        );
    }
}
