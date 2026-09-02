//! Mach-O entitlements extraction and ad-hoc re-signing, the pure-Rust
//! equivalent of the `ldid -e` / `ldid -Sent.xml` pair restore.sh's
//! `ipsw_prepare_ipx` runs on the patched `restored_external` binary.

use apple_codesign::{MachFile, MachOSigner, SettingsScope, SigningSettings};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MachoSignError {
    #[error("code signing failed: {0}")]
    Codesign(Box<apple_codesign::AppleCodesignError>),
}

impl From<apple_codesign::AppleCodesignError> for MachoSignError {
    fn from(error: apple_codesign::AppleCodesignError) -> Self {
        Self::Codesign(Box::new(error))
    }
}

/// Extract the entitlements XML plist embedded in a signed Mach-O, like
/// `ldid -e`. Returns `None` for an unsigned binary or one signed without
/// entitlements (upstream produces an empty entitlements file there).
pub fn extract_entitlements(macho: &[u8]) -> Result<Option<String>, MachoSignError> {
    let file = MachFile::parse(macho)?;
    for binary in file.iter_macho() {
        if let Some(signature) = binary.code_signature()?
            && let Some(entitlements) = signature.entitlements()?
        {
            return Ok(Some(entitlements.as_str().to_owned()));
        }
    }
    Ok(None)
}

/// Ad-hoc re-sign a Mach-O (single-arch or fat), embedding the given
/// entitlements XML plist, like `ldid -Sent.xml`. With `None` the binary is
/// signed without entitlements. `identifier` becomes the Code Directory
/// identifier (ldid derives it from the file name; callers pass the binary's
/// install name, e.g. `restored_external`).
pub fn adhoc_sign(
    macho: &[u8],
    identifier: &str,
    entitlements_xml: Option<&str>,
) -> Result<Vec<u8>, MachoSignError> {
    let signer = MachOSigner::new(macho)?;
    let mut settings = SigningSettings::default();
    settings.set_binary_identifier(SettingsScope::Main, identifier);
    if let Some(xml) = entitlements_xml {
        settings.set_entitlements_xml(SettingsScope::Main, xml.to_owned())?;
    }
    let mut signed = Vec::new();
    signer.write_signed_binary(&settings, &mut signed)?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const CPU_TYPE_ARM64: u32 = 0x0100_000C;
    const MH_EXECUTE: u32 = 2;
    const LC_SEGMENT_64: u32 = 0x19;

    const TEXT_SECTION_OFFSET: usize = 0x400;

    /// Minimal signable arm64 executable: a `__TEXT` segment with one section
    /// (leaving room for the extra LC_CODE_SIGNATURE load command) and a
    /// trailing `__LINKEDIT` segment.
    fn minimal_macho() -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        let w32 = |data: &mut [u8], offset: usize, value: u32| {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        let w64 = |data: &mut [u8], offset: usize, value: u64| {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };
        let header = 32;
        let text_cmd = header;
        let linkedit_cmd = text_cmd + 72 + 80;
        let file_size = data.len() as u64;
        w32(&mut data, 0, MH_MAGIC_64);
        w32(&mut data, 4, CPU_TYPE_ARM64);
        w32(&mut data, 12, MH_EXECUTE);
        w32(&mut data, 16, 2); // ncmds
        w32(&mut data, 20, (72 + 80 + 72) as u32); // sizeofcmds
        // __TEXT with one __text section.
        w32(&mut data, text_cmd, LC_SEGMENT_64);
        w32(&mut data, text_cmd + 4, (72 + 80) as u32);
        data[text_cmd + 8..text_cmd + 14].copy_from_slice(b"__TEXT");
        w64(&mut data, text_cmd + 32, file_size); // vmsize
        w64(&mut data, text_cmd + 48, file_size); // filesize
        w64(&mut data, text_cmd + 56, 5); // maxprot r-x
        w64(&mut data, text_cmd + 64, 5); // initprot r-x
        w32(&mut data, text_cmd + 72 - 8, 1); // nsects
        let section = text_cmd + 72;
        data[section..section + 6].copy_from_slice(b"__text");
        data[section + 16..section + 22].copy_from_slice(b"__TEXT");
        w64(&mut data, section + 32, TEXT_SECTION_OFFSET as u64); // addr
        w64(&mut data, section + 40, 16); // size
        w32(&mut data, section + 48, TEXT_SECTION_OFFSET as u32); // offset
        w32(&mut data, section + 52, 2); // align
        // __LINKEDIT, last segment.
        w32(&mut data, linkedit_cmd, LC_SEGMENT_64);
        w32(&mut data, linkedit_cmd + 4, 72);
        data[linkedit_cmd + 8..linkedit_cmd + 18].copy_from_slice(b"__LINKEDIT");
        w64(&mut data, linkedit_cmd + 24, file_size); // vmaddr
        w64(&mut data, linkedit_cmd + 40, file_size); // fileoff
        let _ = linkedit_cmd;
        data
    }

    #[test]
    fn adhoc_sign_embeds_and_extracts_entitlements() {
        let entitlements = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>platform-application</key><true/></dict></plist>"#;
        let signed = adhoc_sign(&minimal_macho(), "restored_external", Some(entitlements)).unwrap();
        assert_ne!(signed, minimal_macho());
        let extracted = extract_entitlements(&signed)
            .unwrap()
            .expect("entitlements");
        assert!(extracted.contains("platform-application"));
    }

    #[test]
    fn adhoc_sign_without_entitlements_extracts_none() {
        let signed = adhoc_sign(&minimal_macho(), "restored_external", None).unwrap();
        assert_eq!(extract_entitlements(&signed).unwrap(), None);
    }

    #[test]
    fn unsigned_binary_has_no_entitlements() {
        assert_eq!(extract_entitlements(&minimal_macho()).unwrap(), None);
    }
}
