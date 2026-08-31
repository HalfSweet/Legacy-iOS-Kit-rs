use std::io::{Cursor, Read, Write};

use legacy_ios_firmware::{
    BasebandParameters, BuildIdentity, FirmwareArchive, FirmwareError, TssClient, TssError,
    TssRequest,
};
use legacy_ios_image::{FlsError, FlsFile, MbnError, MbnFile};
use legacy_ios_restore::DataRequest;
use plist::{Dictionary, Value};
use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::RestorePlan;

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
    archive: FirmwareArchive,
    identity: BuildIdentity,
    firmware_path: String,
    tss: TssClient,
    ecid: legacy_ios_core::Ecid,
}

impl BasebandResolver {
    pub fn new(plan: &RestorePlan, tss: TssClient) -> Result<Self, BasebandRequestError> {
        Self::from_firmware(plan, plan.firmware(), tss)
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
        let firmware_path = identity.component_path("BasebandFirmware")?.to_owned();
        let ecid = plan
            .device()
            .ecid()
            .ok_or(BasebandRequestError::MissingEcid)?;
        Ok(Self {
            archive,
            identity,
            firmware_path,
            tss,
            ecid,
        })
    }

    pub async fn resolve(&self, request: &DataRequest) -> Result<Dictionary, BasebandRequestError> {
        let arguments = request
            .message()
            .get("Arguments")
            .and_then(Value::as_dictionary)
            .ok_or(BasebandRequestError::MissingArgument("Arguments"))?;
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
            BasebandParameters::new(self.ecid, u64::from(chip_id), certificate_id, serial_number);
        if let Some(nonce) = &nonce {
            parameters = parameters.with_nonce(nonce.clone());
        }
        let request = TssRequest::for_baseband(&self.identity, &parameters)?;
        let response = self.tss.send(&request).await?;
        let archive = self.archive.clone();
        let path = self.firmware_path.clone();
        let response = response.into_dictionary();
        let signed = tokio::task::spawn_blocking(move || {
            let data = archive.read_entry(&path)?;
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
    #[error("baseband worker task failed: {0}")]
    Task(String),
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
    use super::*;

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
}
