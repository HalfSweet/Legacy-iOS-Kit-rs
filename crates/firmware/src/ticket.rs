use std::{fs::File, io::Read, path::Path};

use crate::{TicketClaims, TicketFormat};
use legacy_ios_core::{BootNonce, Ecid};
use plist::{Dictionary, Value};
use thiserror::Error;

const MAX_TICKET_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct SigningTicket {
    dictionary: Dictionary,
    root_ticket: Vec<u8>,
    claims: Box<TicketClaims>,
    generator: Option<String>,
}

impl SigningTicket {
    pub fn from_img4_ticket(
        root_ticket: Vec<u8>,
        generator: Option<String>,
    ) -> Result<Self, TicketError> {
        if root_ticket.is_empty() {
            return Err(TicketError::MissingRootTicket);
        }
        let mut dictionary = Dictionary::new();
        dictionary.insert("ApImg4Ticket".into(), Value::Data(root_ticket.clone()));
        if let Some(generator) = &generator {
            dictionary.insert("generator".into(), generator.clone().into());
        }
        Self::from_dictionary(dictionary)
    }

    pub fn open(path: &Path) -> Result<Self, TicketError> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_TICKET_SIZE {
            return Err(TicketError::TooLarge);
        }
        Self::from_reader(file)
    }

    pub fn from_reader(reader: impl Read) -> Result<Self, TicketError> {
        let mut data = Vec::new();
        reader.take(MAX_TICKET_SIZE + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_TICKET_SIZE {
            return Err(TicketError::TooLarge);
        }
        let dictionary = Value::from_reader(std::io::Cursor::new(data))?
            .into_dictionary()
            .ok_or(TicketError::RootNotDictionary)?;
        Self::from_dictionary(dictionary)
    }

    pub fn from_dictionary(dictionary: Dictionary) -> Result<Self, TicketError> {
        let root_ticket = ["ApImg4Ticket", "APTicket", "ApTicket"]
            .into_iter()
            .find_map(|key| dictionary.get(key).and_then(Value::as_data))
            .map(ToOwned::to_owned)
            .ok_or(TicketError::MissingRootTicket)?;
        let format = if dictionary.contains_key("ApImg4Ticket") {
            TicketFormat::Im4m
        } else {
            TicketFormat::Scab
        };
        let claims = TicketClaims::parse(&root_ticket, format)?;
        if let Some(outer) = dictionary.get("ApECID").or_else(|| dictionary.get("ECID")) {
            let outer = parse_ecid(outer).ok_or(TicketError::InvalidEnvelope)?;
            if outer != claims.ecid() {
                return Err(TicketError::EnvelopeIdentityMismatch);
            }
        }
        if let Some(outer) = dictionary.get("ApNonce") {
            let outer = outer.as_data().ok_or(TicketError::InvalidEnvelope)?;
            if claims.ap_nonce() != Some(outer) {
                return Err(TicketError::EnvelopeIdentityMismatch);
            }
        }
        let generator = dictionary
            .get("generator")
            .or_else(|| dictionary.get("Generator"))
            .and_then(Value::as_string)
            .map(ToOwned::to_owned);
        Ok(Self {
            dictionary,
            root_ticket,
            claims: Box::new(claims),
            generator,
        })
    }

    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    pub fn root_ticket(&self) -> &[u8] {
        &self.root_ticket
    }

    pub const fn ecid(&self) -> Option<Ecid> {
        Some(self.claims.ecid())
    }

    pub fn ap_nonce(&self) -> Option<&[u8]> {
        self.claims.ap_nonce()
    }

    pub fn generator(&self) -> Option<&str> {
        self.generator.as_deref()
    }

    pub fn verify_ecid(&self, ecid: Ecid) -> Result<(), TicketError> {
        if self.claims.ecid() != ecid {
            return Err(TicketError::EcidMismatch);
        }
        Ok(())
    }

    pub fn claims(&self) -> &TicketClaims {
        &self.claims
    }

    pub fn verify_nonce(&self, nonce: &[u8]) -> Result<(), TicketError> {
        match self.claims.ap_nonce() {
            Some(expected) if expected != nonce => Err(TicketError::NonceMismatch),
            None if self.claims.format() == TicketFormat::Im4m => Err(TicketError::MissingNonce),
            _ => Ok(()),
        }
    }

    pub async fn save(&self, path: impl Into<std::path::PathBuf>) -> Result<(), TicketError> {
        let dictionary = self.dictionary.clone();
        let path = path.into();
        tokio::task::spawn_blocking(move || save_dictionary(&dictionary, &path))
            .await
            .map_err(|error| TicketError::Task(error.to_string()))?
    }
}

impl std::fmt::Debug for SigningTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningTicket")
            .field("claims", &self.claims)
            .field("has_generator", &self.generator.is_some())
            .finish_non_exhaustive()
    }
}

/// Derive the ApNonce a device generates for a boot nonce generator, matching
/// futurerestore: SHA-1 for 20-byte nonces and truncated SHA-384 for 32-byte
/// nonces, both over the little-endian generator value.
pub fn derive_ap_nonce(generator: BootNonce, size: usize) -> Option<Vec<u8>> {
    use sha1::Digest as _;

    let seed = generator.get().to_le_bytes();
    match size {
        20 => Some(sha1::Sha1::digest(seed).to_vec()),
        32 => Some(sha2::Sha384::digest(seed)[..32].to_vec()),
        _ => None,
    }
}

fn save_dictionary(dictionary: &Dictionary, path: &Path) -> Result<(), TicketError> {
    use std::io::Write as _;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix("shsh-")
        .tempfile_in(parent)?;
    plist::to_writer_xml(&mut temporary, dictionary)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .into_temp_path()
        .persist(path)
        .map_err(|error| error.error)?;
    Ok(())
}

fn parse_ecid(value: &Value) -> Option<Ecid> {
    value
        .as_unsigned_integer()
        .map(Ecid::new)
        .or_else(|| value.as_string()?.parse().ok())
}

#[derive(Debug, Error)]
pub enum TicketError {
    #[error("signed ticket DER payload is invalid")]
    InvalidSignedPayload,
    #[error("signed ticket contains no internal device identity")]
    MissingInternalEcid,
    #[error("ticket envelope metadata is invalid")]
    InvalidEnvelope,
    #[error("ticket envelope conflicts with the signed payload")]
    EnvelopeIdentityMismatch,
    #[error("ticket signature is invalid")]
    InvalidSignature,
    #[error("ticket does not match the selected build identity")]
    BuildIdentityMismatch,
    #[error("device APNonce does not match the ticket")]
    NonceMismatch,
    #[error("ticket contains no APNonce")]
    MissingNonce,
    #[error("signing ticket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("signing ticket plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("signing ticket exceeds the supported size")]
    TooLarge,
    #[error("signing ticket root is not a dictionary")]
    RootNotDictionary,
    #[error("signing ticket has no AP ticket")]
    MissingRootTicket,
    #[error("signing ticket belongs to another ECID")]
    EcidMismatch,
    #[error("signing ticket worker task failed: {0}")]
    Task(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_internal_identity_and_rejects_conflicting_envelopes() {
        let payload = legacy_ios_test_support::tickets::im4m(42, &[7; 20], &[]);
        let ticket = SigningTicket::from_img4_ticket(payload.clone(), None).unwrap();
        assert!(ticket.verify_ecid(Ecid::new(42)).is_ok());
        assert!(matches!(
            ticket.verify_ecid(Ecid::new(43)),
            Err(TicketError::EcidMismatch)
        ));
        assert!(ticket.verify_nonce(&[7; 20]).is_ok());
        assert!(matches!(
            ticket.verify_nonce(&[8; 20]),
            Err(TicketError::NonceMismatch)
        ));
        let mut dictionary = ticket.dictionary().clone();
        dictionary.insert("ApECID".into(), 43_u64.into());
        assert!(matches!(
            SigningTicket::from_dictionary(dictionary),
            Err(TicketError::EnvelopeIdentityMismatch)
        ));
        let mut dictionary = ticket.dictionary().clone();
        dictionary.insert("ApNonce".into(), Value::Data(vec![8; 20]));
        assert!(matches!(
            SigningTicket::from_dictionary(dictionary),
            Err(TicketError::EnvelopeIdentityMismatch)
        ));
        // A syntactically complete unsigned fixture must not pass signature validation.
        assert!(matches!(
            ticket.claims().verify_signature(),
            Err(TicketError::InvalidSignature)
        ));
        assert!(!format!("{ticket:?}").contains("ApImg4Ticket"));
    }

    #[test]
    fn rejects_truncated_or_trailing_der() {
        let payload = legacy_ios_test_support::tickets::im4m(42, &[7; 20], &[]);
        for end in 0..payload.len() {
            assert!(SigningTicket::from_img4_ticket(payload[..end].to_vec(), None).is_err());
        }
        let mut trailing = payload;
        trailing.push(0);
        assert!(SigningTicket::from_img4_ticket(trailing, None).is_err());
    }

    #[test]
    fn parses_scab_little_endian_identity_and_ramdisk_hash() {
        let payload = legacy_ios_test_support::tickets::scab(
            0x123456789abcdef0,
            Some(&[7; 20]),
            Some(&[9; 20]),
        );
        let claims = TicketClaims::parse(&payload, TicketFormat::Scab).unwrap();
        assert_eq!(claims.ecid().get(), 0x123456789abcdef0);
        assert_eq!(claims.ap_nonce(), Some([7; 20].as_slice()));
        assert_eq!(claims.component_digests()["RestoreRamDisk"], [9; 20]);
    }

    #[test]
    fn parses_img4_ticket_metadata() {
        let payload = legacy_ios_test_support::tickets::im4m(42, &[7; 20], &[]);
        let ticket =
            SigningTicket::from_img4_ticket(payload.clone(), Some("0x1111111111111111".into()))
                .unwrap();
        assert_eq!(ticket.root_ticket(), payload);
        assert_eq!(ticket.ecid(), Some(Ecid::new(42)));
        assert_eq!(ticket.generator(), Some("0x1111111111111111"));
    }

    #[test]
    fn derives_ap_nonce_from_generator() {
        let generator = BootNonce::new(0x1111_1111_1111_1111);

        assert_eq!(
            derive_ap_nonce(generator, 20).unwrap(),
            hex::decode("3a88b7c3802f2f0510abc432104a15ebd8bd7154").unwrap()
        );
        assert_eq!(
            derive_ap_nonce(generator, 32).unwrap(),
            hex::decode("27325c8258be46e69d9ee57fa9a8fbc28b873df434e5e702a8b27999551138ae")
                .unwrap()
        );
        assert!(derive_ap_nonce(generator, 24).is_none());
    }
}
