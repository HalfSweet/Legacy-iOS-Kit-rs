//! Signed ticket fields, read from the DER payload rather than the plist
//! envelope. IM4M follows MANB/MANP private tags; SCAB follows futurerestore
//! c473a17's context tags 1 (little-endian ECID), 18 (nonce), 26 (ramdisk).

use std::collections::BTreeMap;

use legacy_ios_core::Ecid;
use plist::Value;
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
use sha1::Digest as _;
use x509_cert::der::{Decode, Encode};

use crate::{BuildIdentity, TicketError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketFormat {
    Im4m,
    Scab,
}

#[derive(Clone)]
pub struct TicketClaims {
    format: TicketFormat,
    ecid: Ecid,
    nonce: Option<Vec<u8>>,
    board: Option<u64>,
    chip: Option<u64>,
    domain: Option<u64>,
    digests: BTreeMap<String, Vec<u8>>,
    signed_data: Vec<u8>,
    signature: Vec<u8>,
    certificates: Vec<Vec<u8>>,
}

impl std::fmt::Debug for TicketClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketClaims")
            .field("format", &self.format)
            .field("has_nonce", &self.nonce.is_some())
            .field("component_count", &self.digests.len())
            .finish_non_exhaustive()
    }
}

impl TicketClaims {
    pub fn parse(data: &[u8], format: TicketFormat) -> Result<Self, TicketError> {
        let root = Element::exact(data)?;
        root.require(0, 16, true)?;
        let fields = root.children()?;
        match format {
            TicketFormat::Im4m => {
                if fields.len() != 5 || fields[0].text()? != "IM4M" || fields[1].integer()? != 0 {
                    return Err(TicketError::InvalidSignedPayload);
                }
                fields[2].require(0, 17, true)?;
                let body = named_set(&fields[2])?;
                let manb = required(&body, "MANB")?;
                let entries = named_set(manb)?;
                let properties = named_set(required(&entries, "MANP")?)?;
                let ecid = Ecid::new(required(&properties, "ECID")?.integer()?);
                let nonce = properties
                    .get("BNCH")
                    .map(Element::octets)
                    .transpose()?
                    .map(ToOwned::to_owned);
                let mut digests = BTreeMap::new();
                for (name, value) in &entries {
                    if name == "MANP" {
                        continue;
                    }
                    let properties = named_set(value)?;
                    if let Some(digest) = properties.get("DGST") {
                        digests.insert(name.clone(), digest.octets()?.to_vec());
                    }
                }
                fields[4].require(0, 16, true)?;
                let certificates = fields[4]
                    .children()?
                    .iter()
                    .map(|cert| cert.raw.to_vec())
                    .collect();
                Ok(Self {
                    format,
                    ecid,
                    nonce,
                    board: Some(required(&properties, "BORD")?.integer()?),
                    chip: Some(required(&properties, "CHIP")?.integer()?),
                    domain: Some(required(&properties, "SDOM")?.integer()?),
                    digests,
                    signed_data: fields[2].raw.to_vec(),
                    signature: fields[3].octets()?.to_vec(),
                    certificates,
                })
            }
            TicketFormat::Scab => {
                if fields.len() != 4 {
                    return Err(TicketError::InvalidSignedPayload);
                }
                fields[1].require(0, 17, true)?;
                let mut properties = BTreeMap::new();
                for field in fields[1].children()? {
                    if field.class != 2
                        || field.constructed
                        || properties.insert(field.tag, field).is_some()
                    {
                        return Err(TicketError::InvalidSignedPayload);
                    }
                }
                let ecid = properties.get(&1).ok_or(TicketError::MissingInternalEcid)?;
                let bytes: [u8; 8] = ecid
                    .content
                    .try_into()
                    .map_err(|_| TicketError::InvalidSignedPayload)?;
                let mut digests = BTreeMap::new();
                if let Some(digest) = properties.get(&26) {
                    digests.insert("RestoreRamDisk".into(), digest.content.to_vec());
                }
                Ok(Self {
                    format,
                    ecid: Ecid::new(u64::from_le_bytes(bytes)),
                    nonce: properties.get(&18).map(|field| field.content.to_vec()),
                    board: None,
                    chip: None,
                    domain: None,
                    digests,
                    signed_data: fields[1].raw.to_vec(),
                    signature: fields[2].octets()?.to_vec(),
                    certificates: Vec::new(),
                })
            }
        }
    }

    pub const fn format(&self) -> TicketFormat {
        self.format
    }
    pub const fn ecid(&self) -> Ecid {
        self.ecid
    }
    pub fn ap_nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }
    pub fn component_digests(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.digests
    }

    /// Verify the embedded authority's signature using the same certificate
    /// selection as img4tool. This checks integrity, not an Apple CA trust chain.
    /// SCAB follows the upstream legacy identity/digest checks, not this IMG4 check.
    pub fn verify_signature(&self) -> Result<(), TicketError> {
        if self.format == TicketFormat::Scab {
            return Ok(());
        }
        let index = usize::from(self.certificates.len() > 1);
        let cert = self
            .certificates
            .get(index)
            .ok_or(TicketError::InvalidSignature)?;
        let cert =
            x509_cert::Certificate::from_der(cert).map_err(|_| TicketError::InvalidSignature)?;
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| TicketError::InvalidSignature)?;
        let key =
            RsaPublicKey::from_public_key_der(&spki).map_err(|_| TicketError::InvalidSignature)?;
        let result = if index == 0 {
            key.verify(
                Pkcs1v15Sign::new::<sha2::Sha384>(),
                &sha2::Sha384::digest(&self.signed_data),
                &self.signature,
            )
        } else {
            key.verify(
                Pkcs1v15Sign::new::<sha1::Sha1>(),
                &sha1::Sha1::digest(&self.signed_data),
                &self.signature,
            )
        };
        result.map_err(|_| TicketError::InvalidSignature)
    }

    pub fn verify_identity(&self, identity: &BuildIdentity) -> Result<(), TicketError> {
        for (name, claim) in [
            ("ApBoardID", self.board),
            ("ApChipID", self.chip),
            ("ApSecurityDomain", self.domain),
        ] {
            if let Some(claim) = claim {
                let expected = identity
                    .raw()
                    .get(name)
                    .and_then(integer_value)
                    .ok_or(TicketError::BuildIdentityMismatch)?;
                if expected != claim {
                    return Err(TicketError::BuildIdentityMismatch);
                }
            }
        }
        if self.format == TicketFormat::Scab {
            if let Some(digest) = self.digests.get("RestoreRamDisk") {
                if identity
                    .manifest()
                    .get("RestoreRamDisk")
                    .and_then(Value::as_dictionary)
                    .and_then(|component| component.get("Digest"))
                    .and_then(Value::as_data)
                    != Some(digest.as_slice())
                {
                    return Err(TicketError::BuildIdentityMismatch);
                }
            }
            return Ok(());
        }
        for (name, component) in identity.manifest() {
            let Some(component) = component.as_dictionary() else {
                continue;
            };
            if component.get("Trusted").and_then(Value::as_boolean) != Some(true) {
                continue;
            }
            // futurerestore permits these two mismatches in the fallback identity check.
            if matches!(name.as_str(), "RestoreRamDisk" | "RestoreTrustCache") {
                continue;
            }
            if let Some(digest) = component.get("Digest").and_then(Value::as_data)
                && !self.digests.values().any(|value| value == digest)
            {
                return Err(TicketError::BuildIdentityMismatch);
            }
        }
        Ok(())
    }
}

fn integer_value(value: &Value) -> Option<u64> {
    value.as_unsigned_integer().or_else(|| {
        let value = value.as_string()?;
        value.strip_prefix("0x").map_or_else(
            || value.parse().ok(),
            |value| u64::from_str_radix(value, 16).ok(),
        )
    })
}

fn required<'a, 'b>(
    fields: &'a BTreeMap<String, Element<'b>>,
    name: &str,
) -> Result<&'a Element<'b>, TicketError> {
    fields.get(name).ok_or(TicketError::InvalidSignedPayload)
}

fn named_set<'a>(set: &Element<'a>) -> Result<BTreeMap<String, Element<'a>>, TicketError> {
    set.require(0, 17, true)?;
    let mut fields = BTreeMap::new();
    for wrapper in set.children()? {
        if wrapper.class != 3 || !wrapper.constructed {
            return Err(TicketError::InvalidSignedPayload);
        }
        let sequence = Element::exact(wrapper.content)?;
        sequence.require(0, 16, true)?;
        let mut entries = sequence.children()?.into_iter();
        let name = entries.next().ok_or(TicketError::InvalidSignedPayload)?;
        let name = name.text()?;
        let number = name
            .as_bytes()
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| TicketError::InvalidSignedPayload)?;
        let value = entries.next().ok_or(TicketError::InvalidSignedPayload)?;
        if entries.next().is_some()
            || wrapper.tag != u64::from(number)
            || fields.insert(name.to_owned(), value).is_some()
        {
            return Err(TicketError::InvalidSignedPayload);
        }
    }
    Ok(fields)
}

struct Element<'a> {
    raw: &'a [u8],
    content: &'a [u8],
    class: u8,
    tag: u64,
    constructed: bool,
}

impl<'a> Element<'a> {
    fn exact(data: &'a [u8]) -> Result<Self, TicketError> {
        let (element, rest) = Self::read(data)?;
        if !rest.is_empty() {
            return Err(TicketError::InvalidSignedPayload);
        }
        Ok(element)
    }

    fn read(data: &'a [u8]) -> Result<(Self, &'a [u8]), TicketError> {
        let invalid = || TicketError::InvalidSignedPayload;
        let first = *data.first().ok_or_else(invalid)?;
        let mut offset = 1;
        let mut tag = u64::from(first & 31);
        if tag == 31 {
            tag = 0;
            loop {
                let byte = *data.get(offset).ok_or_else(invalid)?;
                if offset == 1 && byte & 127 == 0 {
                    return Err(invalid());
                }
                offset += 1;
                tag = tag
                    .checked_mul(128)
                    .and_then(|tag| tag.checked_add(u64::from(byte & 127)))
                    .ok_or_else(invalid)?;
                if byte & 128 == 0 {
                    break;
                }
            }
            if tag < 31 {
                return Err(invalid());
            }
        }
        let first_length = *data.get(offset).ok_or_else(invalid)?;
        offset += 1;
        let length = if first_length < 128 {
            usize::from(first_length)
        } else {
            let count = usize::from(first_length & 127);
            if count == 0 || count > 4 {
                return Err(invalid());
            }
            let bytes = data.get(offset..offset + count).ok_or_else(invalid)?;
            if bytes[0] == 0 {
                return Err(invalid());
            }
            offset += count;
            let length = bytes
                .iter()
                .fold(0_usize, |value, byte| value * 256 + usize::from(*byte));
            if length < 128 {
                return Err(invalid());
            }
            length
        };
        let end = offset.checked_add(length).ok_or_else(invalid)?;
        let raw = data.get(..end).ok_or_else(invalid)?;
        Ok((
            Self {
                raw,
                content: &raw[offset..],
                class: first >> 6,
                tag,
                constructed: first & 32 != 0,
            },
            &data[end..],
        ))
    }

    fn require(&self, class: u8, tag: u64, constructed: bool) -> Result<(), TicketError> {
        if (self.class, self.tag, self.constructed) != (class, tag, constructed) {
            return Err(TicketError::InvalidSignedPayload);
        }
        Ok(())
    }

    fn children(&self) -> Result<Vec<Self>, TicketError> {
        if !self.constructed {
            return Err(TicketError::InvalidSignedPayload);
        }
        let mut rest = self.content;
        let mut children = Vec::new();
        while !rest.is_empty() {
            if children.len() == 4096 {
                return Err(TicketError::InvalidSignedPayload);
            }
            let (element, next) = Self::read(rest)?;
            children.push(element);
            rest = next;
        }
        Ok(children)
    }

    fn text(&self) -> Result<&'a str, TicketError> {
        self.require(0, 22, false)?;
        std::str::from_utf8(self.content).map_err(|_| TicketError::InvalidSignedPayload)
    }
    fn octets(&self) -> Result<&'a [u8], TicketError> {
        self.require(0, 4, false)?;
        Ok(self.content)
    }
    fn integer(&self) -> Result<u64, TicketError> {
        self.require(0, 2, false)?;
        if self.content.is_empty()
            || self.content[0] & 128 != 0
            || self.content.len() > 1 && self.content[0] == 0 && self.content[1] & 128 == 0
        {
            return Err(TicketError::InvalidSignedPayload);
        }
        self.content
            .iter()
            .try_fold(0_u64, |value, byte| {
                value
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(u64::from(*byte)))
            })
            .ok_or(TicketError::InvalidSignedPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey};

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if body.len() < 128 {
            output.push(body.len() as u8);
        } else {
            let bytes = body.len().to_be_bytes();
            let start = bytes.iter().position(|byte| *byte != 0).unwrap();
            output.push(128 | (bytes.len() - start) as u8);
            output.extend_from_slice(&bytes[start..]);
        }
        output.extend_from_slice(body);
        output
    }

    #[test]
    fn verifies_embedded_authority_and_rejects_modified_manifest() {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let algorithm = hex::decode("300d06092a864886f70d01010b0500").unwrap();
        let validity = der(
            0x30,
            &[der(0x17, b"260101000000Z"), der(0x17, b"270101000000Z")].concat(),
        );
        let tbs = der(
            0x30,
            &[
                der(2, &[1]),
                algorithm.clone(),
                der(0x30, &[]),
                validity,
                der(0x30, &[]),
                spki.as_bytes().to_vec(),
            ]
            .concat(),
        );
        // The upstream check uses the embedded authority key, not its CA chain.
        let certificate = der(0x30, &[tbs, algorithm, der(3, &[0, 0])].concat());
        let mut claims = TicketClaims::parse(
            &legacy_ios_test_support::tickets::im4m(42, &[7; 20], &[]),
            TicketFormat::Im4m,
        )
        .unwrap();
        claims.certificates = vec![certificate];
        claims.signature = private
            .sign(
                Pkcs1v15Sign::new::<sha2::Sha384>(),
                &sha2::Sha384::digest(&claims.signed_data),
            )
            .unwrap();
        claims.verify_signature().unwrap();
        let last = claims.signed_data.len() - 1;
        claims.signed_data[last] ^= 1;
        assert!(matches!(
            claims.verify_signature(),
            Err(TicketError::InvalidSignature)
        ));
    }

    #[test]
    fn matches_trusted_component_digest_and_board() {
        let manifest = br#"<plist><dict><key>ProductVersion</key><string>10.3.3</string><key>ProductBuildVersion</key><string>14G60</string><key>SupportedProductTypes</key><array><string>iPhone6,1</string></array><key>BuildIdentities</key><array><dict><key>ApBoardID</key><string>0x0</string><key>ApChipID</key><integer>0</integer><key>ApSecurityDomain</key><integer>1</integer><key>Info</key><dict><key>DeviceClass</key><string>n51ap</string><key>RestoreBehavior</key><string>Erase</string></dict><key>Manifest</key><dict><key>KernelCache</key><dict><key>Trusted</key><true/><key>Digest</key><data>AQID</data><key>Info</key><dict><key>Path</key><string>kernel</string></dict></dict></dict></dict></array></dict></plist>"#;
        let manifest = crate::BuildManifest::from_reader(std::io::Cursor::new(manifest)).unwrap();
        let identity = &manifest.identities()[0];
        let mut claims = TicketClaims::parse(
            &legacy_ios_test_support::tickets::im4m(42, &[7; 20], &[("krnl", &[1, 2, 3])]),
            TicketFormat::Im4m,
        )
        .unwrap();
        claims.verify_identity(identity).unwrap();
        claims.board = Some(1);
        assert!(matches!(
            claims.verify_identity(identity),
            Err(TicketError::BuildIdentityMismatch)
        ));
        claims.board = Some(0);
        claims.digests.insert("krnl".into(), vec![4]);
        assert!(matches!(
            claims.verify_identity(identity),
            Err(TicketError::BuildIdentityMismatch)
        ));
    }
}
