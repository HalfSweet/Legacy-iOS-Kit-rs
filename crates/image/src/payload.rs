use thiserror::Error;

use crate::{
    CryptoError, Img3, Img3Error, Img3Tag, Img4Error, decrypt_cbc, encrypt_cbc,
    extract_im4p_payload, replace_im4p_payload,
};

const IMG3_MAGIC: &[u8; 4] = b"3gmI";
const IMG3_HEADER_SIZE: usize = 20;
const IMG3_ELEMENT_HEADER_SIZE: usize = 12;

pub fn extract_image_payload(
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, ImagePayloadError> {
    let payload = if container.starts_with(IMG3_MAGIC) {
        let image = Img3::parse(container)?;
        let element = image
            .elements()
            .iter()
            .find(|element| element.tag() == Img3Tag::DATA)
            .ok_or(Img3Error::MissingPayload)?;
        match encryption {
            // Encrypted payloads occupy the whole DATA body: the ciphertext is
            // block-aligned, so the padding bytes past the data size are part
            // of the last cipher block (xpwntool's raw decryption behavior).
            Some((key, iv)) => {
                let mut body = element.data().to_vec();
                body.extend_from_slice(element.padding());
                let mut decrypted = decrypt_cbc(&body, key, iv)?;
                decrypted.truncate(element.data().len());
                decrypted
            }
            None => element.data().to_vec(),
        }
    } else {
        let payload = extract_im4p_payload(container)?;
        match encryption {
            Some((key, iv)) => decrypt_cbc(payload, key, iv)?,
            None => payload.to_vec(),
        }
    };
    Ok(payload)
}

/// Decrypt the DATA payload of an IMG3 container in place, preserving the
/// container layout byte-for-byte: every header, tag, and padding byte stays
/// where it is and only the cipher blocks of the DATA body are decrypted.
/// This mirrors xpwntool's `-decrypt` output, which is the format the
/// upstream bsdiff patches are authored against.
pub fn decrypt_img3_payload(
    container: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, ImagePayloadError> {
    if !container.starts_with(IMG3_MAGIC) {
        return Err(Img3Error::InvalidSignature.into());
    }
    let mut output = container.to_vec();
    let body = img3_data_body_range(&output)?;
    let decrypted = decrypt_cbc(&output[body.clone()], key, iv)?;
    output[body].copy_from_slice(&decrypted);
    Ok(output)
}

/// Byte range of the DATA element body (including padding) in a serialized
/// IMG3 container, walking the same layout as `Img3::parse`.
fn img3_data_body_range(container: &[u8]) -> Result<std::ops::Range<usize>, ImagePayloadError> {
    if container.len() < IMG3_HEADER_SIZE {
        return Err(Img3Error::TruncatedHeader.into());
    }
    let full_size = u32::from_le_bytes(container[4..8].try_into().expect("four-byte field"));
    let full_size = full_size as usize;
    if full_size < IMG3_HEADER_SIZE || full_size > container.len() {
        return Err(Img3Error::InvalidContainerSize(full_size).into());
    }
    let mut offset = IMG3_HEADER_SIZE;
    while offset < full_size {
        let header = container
            .get(offset..offset + IMG3_ELEMENT_HEADER_SIZE)
            .ok_or(Img3Error::TruncatedElement)?;
        let tag = u32::from_le_bytes(header[0..4].try_into().expect("four-byte field"));
        let element_size =
            u32::from_le_bytes(header[4..8].try_into().expect("four-byte field")) as usize;
        if element_size < IMG3_ELEMENT_HEADER_SIZE || offset + element_size > full_size {
            return Err(Img3Error::InvalidElementSize {
                tag: Img3Tag::new(tag),
                size: element_size,
            }
            .into());
        }
        if tag == Img3Tag::DATA.get() {
            return Ok(offset + IMG3_ELEMENT_HEADER_SIZE..offset + element_size);
        }
        offset += element_size;
    }
    Err(Img3Error::MissingPayload.into())
}

/// Repair an IMG3 container truncated past its last complete element: drop
/// the incomplete tail and fix the header sizes. Some upstream bsdiff patches
/// (e.g. the FourThree RestoreDeviceTree patch) produce output cut off inside
/// the trailing CERT element, which personalization re-adds anyway. Valid
/// containers are returned unchanged.
pub fn repair_truncated_img3(container: &[u8]) -> Result<Vec<u8>, ImagePayloadError> {
    if Img3::parse(container).is_ok() {
        return Ok(container.to_vec());
    }
    if container.len() < IMG3_HEADER_SIZE {
        return Err(Img3Error::TruncatedHeader.into());
    }
    if !container.starts_with(IMG3_MAGIC) {
        return Err(Img3Error::InvalidSignature.into());
    }
    let mut output = container[..IMG3_HEADER_SIZE].to_vec();
    let mut shsh_offset = None;
    let mut offset = IMG3_HEADER_SIZE;
    while offset + IMG3_ELEMENT_HEADER_SIZE <= container.len() {
        let header = &container[offset..offset + IMG3_ELEMENT_HEADER_SIZE];
        let tag = u32::from_le_bytes(header[0..4].try_into().expect("four-byte field"));
        let element_size =
            u32::from_le_bytes(header[4..8].try_into().expect("four-byte field")) as usize;
        if element_size < IMG3_ELEMENT_HEADER_SIZE || offset + element_size > container.len() {
            break;
        }
        if tag == Img3Tag::SHSH.get() {
            shsh_offset = Some(output.len() - IMG3_HEADER_SIZE);
        }
        output.extend_from_slice(&container[offset..offset + element_size]);
        offset += element_size;
    }
    if offset == IMG3_HEADER_SIZE {
        return Err(Img3Error::TruncatedElement.into());
    }
    let full_size = output.len() as u32;
    output[4..8].copy_from_slice(&full_size.to_le_bytes());
    output[8..12].copy_from_slice(&(full_size - IMG3_HEADER_SIZE as u32).to_le_bytes());
    output[12..16].copy_from_slice(&(shsh_offset.unwrap_or(0) as u32).to_le_bytes());
    Img3::parse(&output)?;
    Ok(output)
}

pub fn replace_image_payload(
    container: &[u8],
    payload: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, ImagePayloadError> {
    let payload = match encryption {
        Some((key, iv)) => encrypt_cbc(payload, key, iv)?,
        None => payload.to_vec(),
    };
    if container.starts_with(IMG3_MAGIC) {
        Ok(Img3::parse(container)?.with_payload(payload)?.to_bytes())
    } else {
        Ok(replace_im4p_payload(container, &payload)?)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ImagePayloadError {
    #[error(transparent)]
    Img3(#[from] Img3Error),
    #[error(transparent)]
    Img4(#[from] Img4Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Img3Element;

    const KEY: [u8; 16] = [0x2b; 16];
    const IV: [u8; 16] = [0x01; 16];

    /// IMG3 with a DATA payload whose data size is not block-aligned; the
    /// ciphertext covers the padded body, like real Apple images.
    fn padded_container(payload: &[u8]) -> Vec<u8> {
        let padded_len = payload.len().next_multiple_of(16);
        let mut padded = payload.to_vec();
        padded.resize(padded_len, 0);
        let ciphertext = encrypt_cbc(&padded, &KEY, &IV).unwrap();
        let image = Img3::new(
            0x6c6f_676f,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"logo".to_vec()),
                Img3Element::new(Img3Tag::DATA, ciphertext),
            ],
        );
        // Trim the DATA element's data size to the real payload length,
        // leaving the encrypted padding in place.
        let mut bytes = image.to_bytes();
        let body = img3_data_body_range(&bytes).unwrap();
        let data_size = (payload.len() as u32).to_le_bytes();
        bytes[body.start - 4..body.start].copy_from_slice(&data_size);
        bytes
    }

    #[test]
    fn extracts_unaligned_encrypted_payload() {
        let payload = b"twenty byte payload!"; // 20 bytes, not block-aligned
        let container = padded_container(payload);
        let decrypted = extract_image_payload(&container, Some((&KEY, &IV))).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn decrypts_img3_payload_preserving_layout() {
        let payload = b"twenty byte payload!";
        let container = padded_container(payload);
        let decrypted = decrypt_img3_payload(&container, &KEY, &IV).unwrap();
        // Byte-for-byte identical outside the DATA body.
        assert_eq!(decrypted.len(), container.len());
        let body = img3_data_body_range(&container).unwrap();
        assert_eq!(decrypted[..body.start], container[..body.start]);
        assert_eq!(decrypted[body.end..], container[body.end..]);
        // The data size region holds the plaintext again.
        assert_eq!(&decrypted[body.start..body.start + payload.len()], payload);
        assert_eq!(Img3::parse(&decrypted).unwrap().payload().unwrap(), payload);
    }

    #[test]
    fn rejects_decrypting_non_img3() {
        assert!(matches!(
            decrypt_img3_payload(b"not an image", &KEY, &IV),
            Err(ImagePayloadError::Img3(Img3Error::InvalidSignature))
        ));
    }

    #[test]
    fn repairs_container_truncated_mid_element() {
        let bytes = Img3::new(
            0x6c6f_676f,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"ogol".to_vec()),
                Img3Element::new(Img3Tag::DATA, b"payload-data".to_vec()),
                Img3Element::new(Img3Tag::SHSH, vec![0xaa; 32]),
                Img3Element::new(Img3Tag::CERT, vec![0xbb; 128]),
            ],
        )
        .to_bytes();
        // Cut off inside the CERT body, like the FourThree bsdiff outputs.
        let truncated = &bytes[..bytes.len() - 100];
        assert!(Img3::parse(truncated).is_err());
        let repaired = repair_truncated_img3(truncated).unwrap();
        let parsed = Img3::parse(&repaired).unwrap();
        assert_eq!(parsed.elements().len(), 3);
        assert_eq!(parsed.payload().unwrap(), b"payload-data");
        assert_eq!(
            u32::from_le_bytes(repaired[4..8].try_into().unwrap()) as usize,
            repaired.len()
        );
        // The SHSH offset header field still points at the SHSH element.
        let shsh_offset = u32::from_le_bytes(repaired[12..16].try_into().unwrap()) as usize;
        assert_eq!(&repaired[20 + shsh_offset..24 + shsh_offset], b"HSHS");
    }

    #[test]
    fn repair_keeps_valid_containers() {
        let container = padded_container(b"some payload");
        assert_eq!(repair_truncated_img3(&container).unwrap(), container);
    }

    #[test]
    fn repair_rejects_elementless_containers() {
        let mut container = padded_container(b"some payload");
        container.truncate(IMG3_HEADER_SIZE + 4);
        assert!(matches!(
            repair_truncated_img3(&container),
            Err(ImagePayloadError::Img3(Img3Error::TruncatedElement))
        ));
        assert!(matches!(
            repair_truncated_img3(b"not an image, but long enough"),
            Err(ImagePayloadError::Img3(Img3Error::InvalidSignature))
        ));
    }
}
