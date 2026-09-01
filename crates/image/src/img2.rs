//! IMG2 containers, ported from daibutsuCFW `src/xpwn/ipsw-patch/img2.c`
//! (commit de7956d9722ed83f27caec8c0b29e3d8361691fc).
//!
//! An IMG2 file is a 0x408-byte header (little-endian fields, a crc32 of the
//! first 0x64 bytes at 0x64) followed by the payload. On S5L8900 restores the
//! iBSS/iBEC images are IMG2 payloads nested inside an encrypted 8900
//! container; only that nesting needs the `close8900` fixup that re-aligns
//! `dataLenPadded` and refreshes the checksum ([`fixup_nested_payload`]).

use thiserror::Error;

/// Size of the IMG2 header.
pub const IMG2_HEADER_SIZE: usize = 0x408;
/// On-disk signature bytes (`IMG2_SIGNATURE` 0x496D6732 read little-endian).
pub const IMG2_MAGIC: &[u8; 4] = b"2gmI";

const OFFSET_DATA_LEN_PADDED: usize = 0x10;
const OFFSET_DATA_LEN: usize = 0x14;
const OFFSET_HEADER_CHECKSUM: usize = 0x64;
/// Number of header bytes covered by the crc32 checksum.
const HEADER_CHECKSUM_LEN: usize = 0x64;

/// A parsed IMG2 container. The original header bytes are retained so fields
/// the port does not model survive a re-wrap byte-identically.
#[derive(Clone, Debug)]
pub struct Img2 {
    header: [u8; IMG2_HEADER_SIZE],
    payload: Vec<u8>,
}

impl Img2 {
    /// Parse an IMG2 container, peeling the `dataLen`-byte payload.
    pub fn parse(image: &[u8]) -> Result<Self, Img2Error> {
        if image.len() < IMG2_HEADER_SIZE {
            return Err(Img2Error::Truncated);
        }
        let header: [u8; IMG2_HEADER_SIZE] = image[..IMG2_HEADER_SIZE]
            .try_into()
            .map_err(|_| Img2Error::Truncated)?;
        if &header[..4] != IMG2_MAGIC {
            return Err(Img2Error::BadMagic);
        }
        let data_len = read_u32(&header, OFFSET_DATA_LEN) as usize;
        let end = IMG2_HEADER_SIZE
            .checked_add(data_len)
            .ok_or(Img2Error::Truncated)?;
        if end > image.len() {
            return Err(Img2Error::Truncated);
        }
        Ok(Self {
            header,
            payload: image[IMG2_HEADER_SIZE..end].to_vec(),
        })
    }

    /// The payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Re-wrap a (possibly patched) payload, mirroring `closeImg2` of a
    /// duplicate file: `dataLen` and `dataLenPadded` both become the payload
    /// length and the header checksum is refreshed.
    pub fn rewrap(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = self.header;
        let len = payload.len() as u32;
        write_u32(&mut header, OFFSET_DATA_LEN, len);
        write_u32(&mut header, OFFSET_DATA_LEN_PADDED, len);
        refresh_checksum(&mut header);
        let mut output = Vec::with_capacity(IMG2_HEADER_SIZE + payload.len());
        output.extend_from_slice(&header);
        output.extend_from_slice(payload);
        output
    }
}

/// `close8900`'s IMG2-payload fixup: when an encrypted 8900 payload starts
/// with the IMG2 magic, align the inner `dataLenPadded` up to the AES block
/// size, zero-fill the gap, and refresh the IMG2 header checksum before the
/// 8900 layer pads and re-encrypts the payload as a whole.
pub(crate) fn fixup_nested_payload(data: &mut Vec<u8>) -> Result<(), Img2Error> {
    if data.len() < IMG2_HEADER_SIZE {
        return Err(Img2Error::Truncated);
    }
    let padded = read_u32_slice(data, OFFSET_DATA_LEN_PADDED) as usize;
    let padded = padded.next_multiple_of(16);
    write_u32_slice(data, OFFSET_DATA_LEN_PADDED, padded as u32);
    let new_len = IMG2_HEADER_SIZE
        .checked_add(padded)
        .ok_or(Img2Error::Truncated)?;
    if data.len() < new_len {
        data.resize(new_len, 0);
    }
    refresh_checksum_slice(data);
    Ok(())
}

fn refresh_checksum(header: &mut [u8; IMG2_HEADER_SIZE]) {
    let checksum = crc32fast::hash(&header[..HEADER_CHECKSUM_LEN]);
    header[OFFSET_HEADER_CHECKSUM..OFFSET_HEADER_CHECKSUM + 4]
        .copy_from_slice(&checksum.to_le_bytes());
}

fn refresh_checksum_slice(header: &mut [u8]) {
    let checksum = crc32fast::hash(&header[..HEADER_CHECKSUM_LEN]);
    header[OFFSET_HEADER_CHECKSUM..OFFSET_HEADER_CHECKSUM + 4]
        .copy_from_slice(&checksum.to_le_bytes());
}

fn read_u32(header: &[u8; IMG2_HEADER_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().expect("u32 field"))
}

fn write_u32(header: &mut [u8; IMG2_HEADER_SIZE], offset: usize, value: u32) {
    header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32_slice(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().expect("u32 field"))
}

fn write_u32_slice(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Error)]
pub enum Img2Error {
    #[error("IMG2 image is truncated or has an out-of-bounds payload")]
    Truncated,
    #[error("not an IMG2 image (bad magic)")]
    BadMagic,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_image(payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; IMG2_HEADER_SIZE];
        header[..4].copy_from_slice(IMG2_MAGIC);
        header[4..8].copy_from_slice(b"oGOL");
        write_u32(&mut header, OFFSET_DATA_LEN_PADDED, payload.len() as u32);
        write_u32(&mut header, OFFSET_DATA_LEN, payload.len() as u32);
        write_u32(&mut header, 0x0a, 2);
        refresh_checksum(&mut header);
        let mut image = header.to_vec();
        image.extend_from_slice(payload);
        image
    }

    #[test]
    fn parses_and_rewraps_byte_identically() {
        let payload = b"img2 payload bytes";
        let image = synthetic_image(payload);
        let container = Img2::parse(&image).unwrap();
        assert_eq!(container.payload(), payload);
        assert_eq!(container.rewrap(payload), image);
    }

    #[test]
    fn rewrap_updates_lengths_and_checksum() {
        let container = Img2::parse(&synthetic_image(b"old")).unwrap();
        let payload = b"a longer patched payload";
        let output = container.rewrap(payload);
        assert_eq!(output.len(), IMG2_HEADER_SIZE + payload.len());
        assert_eq!(
            read_u32_slice(&output, OFFSET_DATA_LEN),
            payload.len() as u32
        );
        assert_eq!(
            read_u32_slice(&output, OFFSET_DATA_LEN_PADDED),
            payload.len() as u32
        );
        let checksum = crc32fast::hash(&output[..HEADER_CHECKSUM_LEN]);
        assert_eq!(read_u32_slice(&output, OFFSET_HEADER_CHECKSUM), checksum);
        assert_eq!(&output[IMG2_HEADER_SIZE..], payload);
    }

    #[test]
    fn fixup_aligns_data_len_padded_and_zero_fills() {
        let payload = b"abc";
        let mut data = synthetic_image(payload);
        fixup_nested_payload(&mut data).unwrap();
        assert_eq!(data.len(), IMG2_HEADER_SIZE + 16);
        assert_eq!(read_u32_slice(&data, OFFSET_DATA_LEN), 3);
        assert_eq!(read_u32_slice(&data, OFFSET_DATA_LEN_PADDED), 16);
        assert_eq!(&data[IMG2_HEADER_SIZE..IMG2_HEADER_SIZE + 3], b"abc");
        assert!(data[IMG2_HEADER_SIZE + 3..].iter().all(|&b| b == 0));
        let checksum = crc32fast::hash(&data[..HEADER_CHECKSUM_LEN]);
        assert_eq!(read_u32_slice(&data, OFFSET_HEADER_CHECKSUM), checksum);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(matches!(Img2::parse(&[]), Err(Img2Error::Truncated)));
        assert!(matches!(
            Img2::parse(&[0u8; IMG2_HEADER_SIZE]),
            Err(Img2Error::BadMagic)
        ));
        let mut image = synthetic_image(b"payload");
        image.truncate(IMG2_HEADER_SIZE + 2);
        assert!(matches!(Img2::parse(&image), Err(Img2Error::Truncated)));
        assert!(matches!(
            fixup_nested_payload(&mut vec![0u8; 4]),
            Err(Img2Error::Truncated)
        ));
    }
}
