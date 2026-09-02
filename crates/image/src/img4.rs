use std::ops::Range;

use thiserror::Error;

const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_IA5_STRING: u8 = 0x16;
const ASN1_CONTEXT_ZERO: u8 = 0xa0;
const ASN1_OCTET_STRING: u8 = 0x04;

pub fn personalize_img4(
    component_name: &str,
    component: &[u8],
    ticket: &[u8],
) -> Result<Vec<u8>, Img4Error> {
    if component.is_empty() || ticket.is_empty() {
        return Err(Img4Error::EmptyInput);
    }

    let mut component = component.to_vec();
    if let Some(tag) = restore_component_tag(component_name) {
        replace_im4p_tag(&mut component, tag)?;
    } else {
        validate_im4p(&component)?;
    }

    let mut content = der_element(ASN1_IA5_STRING, b"IMG4");
    content.extend_from_slice(&component);
    content.extend_from_slice(&der_element(ASN1_CONTEXT_ZERO, ticket));
    Ok(der_element(ASN1_SEQUENCE, &content))
}

pub fn extract_im4p_payload(component: &[u8]) -> Result<&[u8], Img4Error> {
    let payload = im4p_payload_element(component)?;
    Ok(&component[payload.content])
}

pub fn replace_im4p_payload(component: &[u8], payload: &[u8]) -> Result<Vec<u8>, Img4Error> {
    let sequence = read_element(component, 0)?;
    let old_payload = im4p_payload_element(component)?;
    let mut content = component[sequence.content.start..old_payload.total_start].to_vec();
    content.extend_from_slice(&der_element(ASN1_OCTET_STRING, payload));
    content.extend_from_slice(&component[old_payload.total_end..sequence.content.end]);
    Ok(der_element(ASN1_SEQUENCE, &content))
}

/// Decode an IM4P payload to plaintext, the dispatch of the img4 tool's vfs
/// layer (`-i` without `-D`): a `bvx2`-prefixed payload is LZFSE-compressed,
/// a `complzss` blob is LZSS-compressed, anything else is raw.
pub fn decode_im4p_payload(component: &[u8]) -> Result<Vec<u8>, Img4Error> {
    let payload = extract_im4p_payload(component)?;
    if payload.starts_with(b"bvx2") {
        let mut output = Vec::new();
        lzfse_rust::decode_bytes(payload, &mut output)
            .map_err(|error| Img4Error::PayloadDecode(error.to_string()))?;
        return Ok(output);
    }
    if crate::lzss::is_lzss_compressed(payload) {
        return Ok(crate::lzss::decompress_lzss(payload)?);
    }
    Ok(payload.to_vec())
}

/// Rebuild an IM4P from scratch with an explicit image type and payload,
/// keeping the source component's description string and dropping every
/// trailing element (the compression descriptor and key bags). This is the
/// img4 tool's `-T <tag>` repack: `-J` (LZSS) callers pass a `complzss` blob,
/// `-A` (uncompressed) callers pass the raw payload.
pub fn rebuild_im4p(
    component: &[u8],
    image_type: &[u8; 4],
    payload: &[u8],
) -> Result<Vec<u8>, Img4Error> {
    let sequence = read_element(component, 0)?;
    if sequence.tag != ASN1_SEQUENCE || sequence.total_end != component.len() {
        return Err(Img4Error::InvalidIm4p);
    }
    let magic = read_element(component, sequence.content.start)?;
    if magic.tag != ASN1_IA5_STRING || &component[magic.content.clone()] != b"IM4P" {
        return Err(Img4Error::InvalidIm4p);
    }
    let old_type = read_element(component, magic.total_end)?;
    let description = read_element(component, old_type.total_end)?;
    if old_type.tag != ASN1_IA5_STRING || description.tag != ASN1_IA5_STRING {
        return Err(Img4Error::InvalidIm4p);
    }
    let mut content = der_element(ASN1_IA5_STRING, b"IM4P");
    content.extend_from_slice(&der_element(ASN1_IA5_STRING, image_type));
    content.extend_from_slice(&der_element(
        ASN1_IA5_STRING,
        &component[description.content],
    ));
    content.extend_from_slice(&der_element(ASN1_OCTET_STRING, payload));
    Ok(der_element(ASN1_SEQUENCE, &content))
}

fn restore_component_tag(component_name: &str) -> Option<&'static [u8; 4]> {
    match component_name {
        "RestoreKernelCache" => Some(b"rkrn"),
        "RestoreDeviceTree" => Some(b"rdtr"),
        "RestoreSEP" => Some(b"rsep"),
        _ => None,
    }
}

fn validate_im4p(component: &[u8]) -> Result<(), Img4Error> {
    im4p_tag_range(component).map(|_| ())
}

fn replace_im4p_tag(component: &mut [u8], tag: &[u8; 4]) -> Result<(), Img4Error> {
    let range = im4p_tag_range(component)?;
    component[range].copy_from_slice(tag);
    Ok(())
}

fn im4p_tag_range(component: &[u8]) -> Result<Range<usize>, Img4Error> {
    let sequence = read_element(component, 0)?;
    if sequence.tag != ASN1_SEQUENCE || sequence.total_end != component.len() {
        return Err(Img4Error::InvalidIm4p);
    }
    let magic = read_element(component, sequence.content.start)?;
    if magic.tag != ASN1_IA5_STRING || &component[magic.content.clone()] != b"IM4P" {
        return Err(Img4Error::InvalidIm4p);
    }
    let image_type = read_element(component, magic.total_end)?;
    if image_type.tag != ASN1_IA5_STRING || image_type.content.len() != 4 {
        return Err(Img4Error::InvalidIm4p);
    }
    Ok(image_type.content)
}

fn im4p_payload_element(component: &[u8]) -> Result<DerElement, Img4Error> {
    let sequence = read_element(component, 0)?;
    if sequence.tag != ASN1_SEQUENCE || sequence.total_end != component.len() {
        return Err(Img4Error::InvalidIm4p);
    }
    let magic = read_element(component, sequence.content.start)?;
    if magic.tag != ASN1_IA5_STRING || &component[magic.content.clone()] != b"IM4P" {
        return Err(Img4Error::InvalidIm4p);
    }
    let image_type = read_element(component, magic.total_end)?;
    let description = read_element(component, image_type.total_end)?;
    let payload = read_element(component, description.total_end)?;
    if image_type.tag != ASN1_IA5_STRING
        || description.tag != ASN1_IA5_STRING
        || payload.tag != ASN1_OCTET_STRING
    {
        return Err(Img4Error::InvalidIm4p);
    }
    Ok(payload)
}

fn der_element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + 5 + content.len());
    output.push(tag);
    write_length(content.len(), &mut output);
    output.extend_from_slice(content);
    output
}

fn write_length(length: usize, output: &mut Vec<u8>) {
    if length < 0x80 {
        output.push(length as u8);
        return;
    }

    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero DER length");
    let encoded = &bytes[first..];
    output.push(0x80 | encoded.len() as u8);
    output.extend_from_slice(encoded);
}

struct DerElement {
    tag: u8,
    total_start: usize,
    content: Range<usize>,
    total_end: usize,
}

fn read_element(data: &[u8], offset: usize) -> Result<DerElement, Img4Error> {
    let tag = *data.get(offset).ok_or(Img4Error::TruncatedDer)?;
    let first_length = *data.get(offset + 1).ok_or(Img4Error::TruncatedDer)?;
    let (length, header_size) = if first_length & 0x80 == 0 {
        (usize::from(first_length), 2)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 4 {
            return Err(Img4Error::InvalidDerLength);
        }
        let encoded = data
            .get(offset + 2..offset + 2 + length_bytes)
            .ok_or(Img4Error::TruncatedDer)?;
        let length = encoded
            .iter()
            .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, 2 + length_bytes)
    };
    let content_start = offset + header_size;
    let total_end = content_start
        .checked_add(length)
        .ok_or(Img4Error::InvalidDerLength)?;
    if total_end > data.len() {
        return Err(Img4Error::TruncatedDer);
    }
    Ok(DerElement {
        tag,
        total_start: offset,
        content: content_start..total_end,
        total_end,
    })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Img4Error {
    #[error("IMG4 component and ticket must not be empty")]
    EmptyInput,
    #[error("component is not a valid IM4P container")]
    InvalidIm4p,
    #[error("DER element is truncated")]
    TruncatedDer,
    #[error("invalid DER length")]
    InvalidDerLength,
    #[error("IM4P payload decompression failed: {0}")]
    PayloadDecode(String),
    #[error(transparent)]
    Lzss(#[from] crate::lzss::LzssError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(tag: &[u8; 4]) -> Vec<u8> {
        let mut content = der_element(ASN1_IA5_STRING, b"IM4P");
        content.extend_from_slice(&der_element(ASN1_IA5_STRING, tag));
        content.extend_from_slice(&der_element(ASN1_IA5_STRING, b"test"));
        content.extend_from_slice(&der_element(ASN1_OCTET_STRING, b"payload"));
        der_element(ASN1_SEQUENCE, &content)
    }

    #[test]
    fn wraps_component_and_ticket() {
        let result = personalize_img4("iBSS", &component(b"ibss"), b"ticket").unwrap();
        let outer = read_element(&result, 0).unwrap();
        assert_eq!(outer.tag, ASN1_SEQUENCE);
        let magic = read_element(&result, outer.content.start).unwrap();
        assert_eq!(&result[magic.content], b"IMG4");
    }

    #[test]
    fn retags_restore_components() {
        let result =
            personalize_img4("RestoreKernelCache", &component(b"krnl"), b"ticket").unwrap();
        assert!(result.windows(4).any(|window| window == b"rkrn"));
    }

    #[test]
    fn extracts_and_replaces_payload() {
        let component = component(b"rdsk");
        assert_eq!(extract_im4p_payload(&component).unwrap(), b"payload");
        let replaced = replace_im4p_payload(&component, b"new payload").unwrap();
        assert_eq!(extract_im4p_payload(&replaced).unwrap(), b"new payload");
    }

    #[test]
    fn decodes_raw_and_lzss_payloads() {
        let raw = component(b"krnl");
        assert_eq!(decode_im4p_payload(&raw).unwrap(), b"payload");

        let blob = crate::lzss::compress_lzss(b"kernel bytes").unwrap();
        let compressed = component_with_payload(b"krnl", &blob);
        assert_eq!(decode_im4p_payload(&compressed).unwrap(), b"kernel bytes");
    }

    #[test]
    fn decodes_lzfse_payload() {
        // Above the encoder's 0x1000-byte LZVN cutoff it emits a compressed
        // (bvx2) block rather than a bvx1/bvxn one.
        let payload = b"ramdisk bytes ramdisk bytes ".repeat(256);
        let mut blob = Vec::new();
        lzfse_rust::encode_bytes(&payload, &mut blob).unwrap();
        assert!(blob.starts_with(b"bvx2"));
        let component = component_with_payload(b"rdsk", &blob);
        assert_eq!(decode_im4p_payload(&component).unwrap(), payload);
    }

    #[test]
    fn rebuilds_im4p_with_new_type_and_without_trailing_elements() {
        let mut with_compression = component_with_payload(b"krnl", b"payload");
        // Append a compression descriptor after the payload element.
        let inner_length = with_compression.len() - 2;
        with_compression[1] = inner_length as u8 + 7;
        with_compression.extend_from_slice(&der_element(ASN1_CONTEXT_ZERO, b"lzss\0"));

        let rebuilt = rebuild_im4p(&with_compression, b"rkrn", b"new payload").unwrap();
        assert_eq!(extract_im4p_payload(&rebuilt).unwrap(), b"new payload");
        assert!(rebuilt.windows(4).any(|window| window == b"rkrn"));
        assert!(!rebuilt.windows(4).any(|window| window == b"lzss"));
        // The description survives the rebuild.
        assert!(rebuilt.windows(4).any(|window| window == b"test"));
    }

    fn component_with_payload(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut content = der_element(ASN1_IA5_STRING, b"IM4P");
        content.extend_from_slice(&der_element(ASN1_IA5_STRING, tag));
        content.extend_from_slice(&der_element(ASN1_IA5_STRING, b"test"));
        content.extend_from_slice(&der_element(ASN1_OCTET_STRING, payload));
        der_element(ASN1_SEQUENCE, &content)
    }
}
