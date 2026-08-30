use std::{fs::File, io::Read, path::Path};

use legacy_ios_core::Ecid;
use plist::{Dictionary, Value};
use thiserror::Error;

const MAX_TICKET_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SigningTicket {
    dictionary: Dictionary,
    root_ticket: Vec<u8>,
    ecid: Option<Ecid>,
    ap_nonce: Option<Vec<u8>>,
    generator: Option<String>,
}

impl SigningTicket {
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
        let root_ticket = ["ApImg4Ticket", "APTicket", "ApTicket"]
            .into_iter()
            .find_map(|key| dictionary.get(key).and_then(Value::as_data))
            .map(ToOwned::to_owned)
            .ok_or(TicketError::MissingRootTicket)?;
        let ecid = dictionary
            .get("ApECID")
            .or_else(|| dictionary.get("ECID"))
            .and_then(parse_ecid);
        let ap_nonce = dictionary
            .get("ApNonce")
            .and_then(Value::as_data)
            .map(ToOwned::to_owned);
        let generator = dictionary
            .get("generator")
            .or_else(|| dictionary.get("Generator"))
            .and_then(Value::as_string)
            .map(ToOwned::to_owned);
        Ok(Self {
            dictionary,
            root_ticket,
            ecid,
            ap_nonce,
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
        self.ecid
    }

    pub fn ap_nonce(&self) -> Option<&[u8]> {
        self.ap_nonce.as_deref()
    }

    pub fn generator(&self) -> Option<&str> {
        self.generator.as_deref()
    }

    pub fn verify_ecid(&self, ecid: Ecid) -> Result<(), TicketError> {
        if self.ecid.is_some_and(|ticket_ecid| ticket_ecid != ecid) {
            return Err(TicketError::EcidMismatch);
        }
        Ok(())
    }
}

fn parse_ecid(value: &Value) -> Option<Ecid> {
    value
        .as_unsigned_integer()
        .map(Ecid::new)
        .or_else(|| value.as_string()?.parse().ok())
}

#[derive(Debug, Error)]
pub enum TicketError {
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
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_img4_ticket_metadata() {
        let ticket = SigningTicket::from_reader(Cursor::new(
            br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ApImg4Ticket</key><data>AQID</data><key>ApECID</key><integer>42</integer>
<key>generator</key><string>0x1111111111111111</string>
</dict></plist>"#,
        ))
        .unwrap();

        assert_eq!(ticket.root_ticket(), [1, 2, 3]);
        assert_eq!(ticket.ecid(), Some(Ecid::new(42)));
        assert_eq!(ticket.generator(), Some("0x1111111111111111"));
    }
}
