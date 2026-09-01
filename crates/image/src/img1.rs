//! S5L8900 IMG1/"8900" containers and the Pwnage 2.0 WTF exploit, ported
//! from daibutsuCFW `src/xpwn/ipsw-patch/8900.c` (commit de7956d).
//!
//! An 8900 file is a 0x800-byte header, a payload (AES-128-CBC encrypted
//! with the 0x837 key when the format byte is 3), a 0x80-byte footer
//! signature, and a footer certificate. `exploit8900` turns the stock
//! `WTF.s5l8900xall.RELEASE.dfu` image into the Pwnage 2.0 exploit image by
//! flipping two certificate bytes, extending the certificate with a 0x54-byte
//! exploit trailer, and re-signing the header.
//!
//! `close8900` additionally fixes up the `dataLenPadded`/header checksum of
//! IMG2 payloads before re-encrypting ([`crate::img2::fixup_nested_payload`]);
//! the WTF payload is a raw ARM image, so the branch only fires for the
//! IMG2-wrapped iBSS/iBEC images patched through an 8900 container.

use sha1::{Digest, Sha1};
use thiserror::Error;

use crate::crypto::{CryptoError, decrypt_cbc, encrypt_cbc};

/// Size of the 8900 header.
pub const HEADER_SIZE: usize = 0x800;
/// Size of the footer signature following the payload.
pub const FOOTER_SIGNATURE_SIZE: usize = 0x80;
/// `format` value of encrypted containers.
pub const FORMAT_ENCRYPTED: u8 = 0x3;

/// The 0x837 key encrypting format-3 payloads and signing headers.
const KEY_0X837: [u8; 16] = [
    0x18, 0x84, 0x58, 0xa6, 0xd1, 0x50, 0x34, 0xdf, 0xe3, 0x86, 0xf2, 0x3b, 0x61, 0xd4, 0x37, 0x74,
];

/// `footerCertLen` after applying the exploit (0xc0a certificate + trailer).
const EXPLOIT_CERT_LEN: u32 = 0xc5e;
/// Size of the exploit trailer appended after the certificate.
const EXPLOIT_TRAILER_SIZE: usize = 0x54;

const MAGIC: &[u8; 4] = b"8900";
const OFFSET_FORMAT: usize = 0x07;
const OFFSET_SIZE_OF_DATA: usize = 0x0c;
const OFFSET_FOOTER_SIGNATURE: usize = 0x10;
const OFFSET_FOOTER_CERT: usize = 0x14;
const OFFSET_FOOTER_CERT_LEN: usize = 0x18;
const OFFSET_EPOCH: usize = 0x3e;
const OFFSET_HEADER_SIGNATURE: usize = 0x40;

/// A parsed 8900 container. The payload is held decrypted; the original
/// header bytes are retained so fields the port does not model (version,
/// salt, unknowns) survive a rebuild byte-identically.
#[derive(Clone, Debug)]
pub struct Img1 {
    header: [u8; HEADER_SIZE],
    payload: Vec<u8>,
    footer_signature: [u8; FOOTER_SIGNATURE_SIZE],
    footer_certificate: Vec<u8>,
}

impl Img1 {
    /// Parse an 8900 container, decrypting the payload of format-3 files.
    pub fn parse(image: &[u8]) -> Result<Self, Img1Error> {
        if image.len() < HEADER_SIZE {
            return Err(Img1Error::Truncated);
        }
        let header: [u8; HEADER_SIZE] = image[..HEADER_SIZE]
            .try_into()
            .map_err(|_| Img1Error::Truncated)?;
        if &header[..4] != MAGIC {
            return Err(Img1Error::BadMagic);
        }
        let size_of_data = read_u32(&header, OFFSET_SIZE_OF_DATA) as usize;
        let footer_signature_offset = read_u32(&header, OFFSET_FOOTER_SIGNATURE) as usize;
        let footer_cert_offset = read_u32(&header, OFFSET_FOOTER_CERT) as usize;
        let footer_cert_len = read_u32(&header, OFFSET_FOOTER_CERT_LEN) as usize;

        let data_end = HEADER_SIZE
            .checked_add(size_of_data)
            .ok_or(Img1Error::Truncated)?;
        let signature_end = HEADER_SIZE
            .checked_add(footer_signature_offset)
            .and_then(|start| start.checked_add(FOOTER_SIGNATURE_SIZE))
            .ok_or(Img1Error::Truncated)?;
        let cert_end = HEADER_SIZE
            .checked_add(footer_cert_offset)
            .and_then(|start| start.checked_add(footer_cert_len))
            .ok_or(Img1Error::Truncated)?;
        if data_end > image.len() || signature_end > image.len() || cert_end > image.len() {
            return Err(Img1Error::Truncated);
        }

        let mut payload = image[HEADER_SIZE..data_end].to_vec();
        if header[OFFSET_FORMAT] == FORMAT_ENCRYPTED {
            if !payload.len().is_multiple_of(16) {
                return Err(Img1Error::UnalignedData);
            }
            payload = decrypt_cbc(&payload, &KEY_0X837, &[0u8; 16])?;
        }

        let footer_signature: [u8; FOOTER_SIGNATURE_SIZE] = image
            [HEADER_SIZE + footer_signature_offset..signature_end]
            .try_into()
            .map_err(|_| Img1Error::Truncated)?;
        let footer_certificate = image[HEADER_SIZE + footer_cert_offset..cert_end].to_vec();

        Ok(Self {
            header,
            payload,
            footer_signature,
            footer_certificate,
        })
    }

    /// Whether the container encrypts its payload (format 3).
    pub const fn is_encrypted(&self) -> bool {
        self.header[OFFSET_FORMAT] == FORMAT_ENCRYPTED
    }

    /// The security epoch field of the header.
    pub fn epoch(&self) -> u16 {
        u16::from_le_bytes([self.header[OFFSET_EPOCH], self.header[OFFSET_EPOCH + 1]])
    }

    /// The decrypted payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The footer certificate.
    pub fn footer_certificate(&self) -> &[u8] {
        &self.footer_certificate
    }

    /// Rebuild the container around a (possibly patched) payload,
    /// re-encrypting format-3 files and re-signing the header. Mirrors
    /// `close8900` without the exploit flag.
    pub fn reseal(&self, payload: &[u8]) -> Result<Vec<u8>, Img1Error> {
        self.build(payload, false)
    }

    /// Rebuild like [`Img1::reseal`], applying the Pwnage 2.0 WTF exploit:
    /// certificate bytes 0x8be/0xb08 are flipped, a 0x54-byte exploit trailer
    /// is appended after the certificate, and `footerCertLen` becomes 0xc5e.
    pub fn reseal_with_exploit(&self, payload: &[u8]) -> Result<Vec<u8>, Img1Error> {
        self.build(payload, true)
    }

    fn build(&self, payload: &[u8], exploit: bool) -> Result<Vec<u8>, Img1Error> {
        let mut data = payload.to_vec();
        if self.is_encrypted() {
            if data.starts_with(crate::img2::IMG2_MAGIC) {
                // close8900's IMG2-payload fixup: realign the inner
                // dataLenPadded and refresh the IMG2 checksum before the
                // whole payload is block-aligned and re-encrypted.
                crate::img2::fixup_nested_payload(&mut data)?;
            }
            // Block-align with zero padding or AES-CBC cannot re-encrypt.
            data.resize(data.len().next_multiple_of(16), 0);
            data = encrypt_cbc(&data, &KEY_0X837, &[0u8; 16])?;
        }

        let mut certificate = self.footer_certificate.clone();
        let footer_cert_len = if exploit {
            if certificate.len() <= 0xb08 {
                return Err(Img1Error::CertificateTooSmall);
            }
            certificate[0x8be] = 0x9f;
            certificate[0xb08] = 0x55;
            EXPLOIT_CERT_LEN
        } else {
            certificate.len() as u32
        };

        let mut header = self.header;
        let size_of_data = data.len() as u32;
        write_u32(&mut header, OFFSET_SIZE_OF_DATA, size_of_data);
        write_u32(&mut header, OFFSET_FOOTER_SIGNATURE, size_of_data);
        write_u32(
            &mut header,
            OFFSET_FOOTER_CERT,
            size_of_data + FOOTER_SIGNATURE_SIZE as u32,
        );
        write_u32(&mut header, OFFSET_FOOTER_CERT_LEN, footer_cert_len);
        // headerSignature = AES-128-CBC(sha1(header[0..0x40])[0..16],
        // key_0x837, zero IV).
        let digest = Sha1::digest(&header[..OFFSET_HEADER_SIGNATURE]);
        let signature = encrypt_cbc(&digest[..16], &KEY_0X837, &[0u8; 16])?;
        header[OFFSET_HEADER_SIGNATURE..OFFSET_HEADER_SIGNATURE + 16].copy_from_slice(&signature);

        let mut output = Vec::with_capacity(
            HEADER_SIZE + data.len() + FOOTER_SIGNATURE_SIZE + certificate.len(),
        );
        output.extend_from_slice(&header);
        output.extend_from_slice(&data);
        output.extend_from_slice(&self.footer_signature);
        output.append(&mut certificate);
        if exploit {
            let mut trailer = [0u8; EXPLOIT_TRAILER_SIZE];
            trailer[0x30] = 0x01;
            trailer[0x50] = 0xec;
            trailer[0x51] = 0x57;
            trailer[0x53] = 0x20;
            output.extend_from_slice(&trailer);
        }
        Ok(output)
    }
}

/// Port of `exploit8900` as applied to `WTF.s5l8900xall.RELEASE` files by
/// `doPatch`: parse the container and rebuild it with the exploit footer,
/// payload unchanged.
pub fn apply_wtf_exploit(image: &[u8]) -> Result<Vec<u8>, Img1Error> {
    let container = Img1::parse(image)?;
    container.reseal_with_exploit(container.payload())
}

fn read_u32(header: &[u8; HEADER_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().expect("u32 field"))
}

fn write_u32(header: &mut [u8; HEADER_SIZE], offset: usize, value: u32) {
    header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Error)]
pub enum Img1Error {
    #[error("8900 image is truncated or has out-of-bounds regions")]
    Truncated,
    #[error("not an 8900 image (bad magic)")]
    BadMagic,
    #[error("encrypted 8900 payload is not block aligned")]
    UnalignedData,
    #[error("footer certificate too small for the WTF exploit")]
    CertificateTooSmall,
    #[error("nested IMG2 payload is malformed: {0}")]
    NestedImg2(#[from] crate::img2::Img2Error),
    #[error("8900 payload crypto failed: {0}")]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD_LEN: usize = 0x60;
    const CERT_LEN: usize = 0xc0a;

    fn synthetic_image(format: u8) -> Vec<u8> {
        let mut header = [0u8; HEADER_SIZE];
        header[..4].copy_from_slice(MAGIC);
        header[4..7].copy_from_slice(b"1.0");
        header[OFFSET_FORMAT] = format;
        write_u32(&mut header, OFFSET_SIZE_OF_DATA, PAYLOAD_LEN as u32);
        write_u32(&mut header, OFFSET_FOOTER_SIGNATURE, PAYLOAD_LEN as u32);
        write_u32(
            &mut header,
            OFFSET_FOOTER_CERT,
            (PAYLOAD_LEN + FOOTER_SIGNATURE_SIZE) as u32,
        );
        write_u32(&mut header, OFFSET_FOOTER_CERT_LEN, CERT_LEN as u32);
        write_u32(&mut header, 0x08, 0x1122_3344);
        header[0x1c..0x1c + 0x20].copy_from_slice(&[0x5a; 0x20]);
        header[OFFSET_EPOCH] = 1;
        // Sign like the C close8900 does.
        let digest = Sha1::digest(&header[..OFFSET_HEADER_SIGNATURE]);
        let signature = encrypt_cbc(&digest[..16], &KEY_0X837, &[0u8; 16]).unwrap();
        header[OFFSET_HEADER_SIGNATURE..OFFSET_HEADER_SIGNATURE + 16].copy_from_slice(&signature);

        let mut payload: Vec<u8> = (0..PAYLOAD_LEN as u8).map(|byte| byte ^ 0xa5).collect();
        if format == FORMAT_ENCRYPTED {
            payload = encrypt_cbc(&payload, &KEY_0X837, &[0u8; 16]).unwrap();
        }

        let mut image = Vec::new();
        image.extend_from_slice(&header);
        image.extend_from_slice(&payload);
        image.extend_from_slice(&[0x77; FOOTER_SIGNATURE_SIZE]);
        image.extend(std::iter::repeat_n(0x11, CERT_LEN));
        image
    }

    fn plaintext_payload() -> Vec<u8> {
        (0..PAYLOAD_LEN as u8).map(|byte| byte ^ 0xa5).collect()
    }

    #[test]
    fn parses_and_reseals_byte_identically() {
        let image = synthetic_image(FORMAT_ENCRYPTED);
        let container = Img1::parse(&image).unwrap();
        assert!(container.is_encrypted());
        assert_eq!(container.epoch(), 1);
        assert_eq!(container.payload(), plaintext_payload());
        assert_eq!(container.footer_certificate().len(), CERT_LEN);
        assert_eq!(container.reseal(container.payload()).unwrap(), image);
    }

    #[test]
    fn plaintext_format_round_trips_without_crypto() {
        let image = synthetic_image(0x4);
        let container = Img1::parse(&image).unwrap();
        assert!(!container.is_encrypted());
        assert_eq!(container.payload(), plaintext_payload());
        assert_eq!(container.reseal(container.payload()).unwrap(), image);
    }

    #[test]
    fn exploit_writes_footer_cert_trailer_and_signature() {
        let image = synthetic_image(FORMAT_ENCRYPTED);
        let exploited = apply_wtf_exploit(&image).unwrap();

        // Layout: header + payload + signature + cert + 0x54 trailer.
        let cert_start = HEADER_SIZE + PAYLOAD_LEN + FOOTER_SIGNATURE_SIZE;
        assert_eq!(
            exploited.len(),
            cert_start + CERT_LEN + EXPLOIT_TRAILER_SIZE
        );
        assert_eq!(exploited[cert_start + 0x8be], 0x9f);
        assert_eq!(exploited[cert_start + 0xb08], 0x55);
        let trailer = &exploited[cert_start + CERT_LEN..];
        assert_eq!(trailer.len(), EXPLOIT_TRAILER_SIZE);
        assert_eq!(trailer[0x30], 0x01);
        assert_eq!(trailer[0x50], 0xec);
        assert_eq!(trailer[0x51], 0x57);
        assert_eq!(trailer[0x53], 0x20);
        assert!(trailer.iter().filter(|&&byte| byte != 0).count() == 4);

        // Header fields: cert length becomes 0xc5e, data region unchanged.
        let header: &[u8] = &exploited[..HEADER_SIZE];
        assert_eq!(
            u32::from_le_bytes(
                header[OFFSET_FOOTER_CERT_LEN..OFFSET_FOOTER_CERT_LEN + 4]
                    .try_into()
                    .unwrap()
            ),
            EXPLOIT_CERT_LEN
        );
        assert_eq!(
            u32::from_le_bytes(
                header[OFFSET_SIZE_OF_DATA..OFFSET_SIZE_OF_DATA + 4]
                    .try_into()
                    .unwrap()
            ),
            PAYLOAD_LEN as u32
        );
        // Header re-signed over the updated fields.
        let digest = Sha1::digest(&header[..OFFSET_HEADER_SIGNATURE]);
        let expected = encrypt_cbc(&digest[..16], &KEY_0X837, &[0u8; 16]).unwrap();
        assert_eq!(
            &header[OFFSET_HEADER_SIGNATURE..OFFSET_HEADER_SIGNATURE + 16],
            expected.as_slice()
        );

        // The payload survives the decrypt/re-encrypt round trip.
        let reparsed = Img1::parse(&exploited).unwrap();
        assert_eq!(reparsed.payload(), plaintext_payload());
    }

    /// Build an encrypted 8900 container around an arbitrary (padded,
    /// encrypted) payload, signed like the C close8900.
    fn synthetic_wrapping(payload: &[u8]) -> Vec<u8> {
        let mut padded = payload.to_vec();
        padded.resize(padded.len().next_multiple_of(16), 0);
        let size_of_data = padded.len();
        let mut header = [0u8; HEADER_SIZE];
        header[..4].copy_from_slice(MAGIC);
        header[OFFSET_FORMAT] = FORMAT_ENCRYPTED;
        write_u32(&mut header, OFFSET_SIZE_OF_DATA, size_of_data as u32);
        write_u32(&mut header, OFFSET_FOOTER_SIGNATURE, size_of_data as u32);
        write_u32(
            &mut header,
            OFFSET_FOOTER_CERT,
            (size_of_data + FOOTER_SIGNATURE_SIZE) as u32,
        );
        write_u32(&mut header, OFFSET_FOOTER_CERT_LEN, CERT_LEN as u32);
        let digest = Sha1::digest(&header[..OFFSET_HEADER_SIGNATURE]);
        let signature = encrypt_cbc(&digest[..16], &KEY_0X837, &[0u8; 16]).unwrap();
        header[OFFSET_HEADER_SIGNATURE..OFFSET_HEADER_SIGNATURE + 16].copy_from_slice(&signature);

        let encrypted = encrypt_cbc(&padded, &KEY_0X837, &[0u8; 16]).unwrap();
        let mut image = Vec::new();
        image.extend_from_slice(&header);
        image.extend_from_slice(&encrypted);
        image.extend_from_slice(&[0x77; FOOTER_SIGNATURE_SIZE]);
        image.extend(std::iter::repeat_n(0x11, CERT_LEN));
        image
    }

    #[test]
    fn reseal_fixes_up_nested_img2_payload() {
        // IMG2 payload with an unaligned dataLenPadded, as written by the
        // inner IMG2 layer of a doPatch re-stack before close8900 runs.
        let mut img2 = vec![0u8; crate::img2::IMG2_HEADER_SIZE + 3];
        img2[..4].copy_from_slice(crate::img2::IMG2_MAGIC);
        img2[0x10..0x14].copy_from_slice(&3u32.to_le_bytes()); // dataLenPadded
        img2[0x14..0x18].copy_from_slice(&3u32.to_le_bytes()); // dataLen
        img2[crate::img2::IMG2_HEADER_SIZE..].copy_from_slice(b"abc");

        let image = synthetic_wrapping(&img2);
        let container = Img1::parse(&image).unwrap();
        let output = container.reseal(container.payload()).unwrap();
        let reparsed = Img1::parse(&output).unwrap();
        let payload = reparsed.payload();

        assert!(payload.starts_with(crate::img2::IMG2_MAGIC));
        // dataLenPadded is block-aligned and the gap zero-filled.
        assert_eq!(
            u32::from_le_bytes(payload[0x10..0x14].try_into().unwrap()),
            16
        );
        assert_eq!(
            u32::from_le_bytes(payload[0x14..0x18].try_into().unwrap()),
            3
        );
        assert_eq!(
            &payload[crate::img2::IMG2_HEADER_SIZE..crate::img2::IMG2_HEADER_SIZE + 3],
            b"abc"
        );
        assert!(
            payload[crate::img2::IMG2_HEADER_SIZE + 3..crate::img2::IMG2_HEADER_SIZE + 16]
                .iter()
                .all(|&byte| byte == 0)
        );
        // The IMG2 header checksum covers the aligned dataLenPadded.
        let checksum = crc32fast::hash(&payload[..0x64]);
        assert_eq!(
            u32::from_le_bytes(payload[0x64..0x68].try_into().unwrap()),
            checksum
        );
    }

    #[test]
    fn reseal_leaves_non_img2_payloads_alone() {
        let image = synthetic_image(FORMAT_ENCRYPTED);
        let container = Img1::parse(&image).unwrap();
        assert_eq!(container.reseal(container.payload()).unwrap(), image);
    }

    #[test]
    fn exploit_rejects_small_certificates() {
        let mut image = synthetic_image(0x4);
        // Shrink the certificate below the patched offsets.
        let cert_len = 0x100usize;
        image.truncate(HEADER_SIZE + PAYLOAD_LEN + FOOTER_SIGNATURE_SIZE + cert_len);
        write_u32_at(&mut image, OFFSET_FOOTER_CERT_LEN, cert_len as u32);
        assert!(matches!(
            apply_wtf_exploit(&image),
            Err(Img1Error::CertificateTooSmall)
        ));
    }

    fn write_u32_at(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(matches!(Img1::parse(&[]), Err(Img1Error::Truncated)));
        assert!(matches!(
            Img1::parse(&[0u8; HEADER_SIZE]),
            Err(Img1Error::BadMagic)
        ));

        // Footer certificate out of bounds.
        let mut image = synthetic_image(FORMAT_ENCRYPTED);
        image.truncate(HEADER_SIZE + PAYLOAD_LEN + FOOTER_SIGNATURE_SIZE);
        assert!(matches!(Img1::parse(&image), Err(Img1Error::Truncated)));

        // Encrypted payload not block aligned.
        let mut image = synthetic_image(FORMAT_ENCRYPTED);
        write_u32_at(&mut image, OFFSET_SIZE_OF_DATA, (PAYLOAD_LEN - 1) as u32);
        assert!(matches!(Img1::parse(&image), Err(Img1Error::UnalignedData)));
    }
}
