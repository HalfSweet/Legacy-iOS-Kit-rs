use thiserror::Error;

use crate::{
    CryptoError, Img3, Img3Error, Img4Error, decrypt_cbc, encrypt_cbc, extract_im4p_payload,
    replace_im4p_payload,
};

const IMG3_MAGIC: &[u8; 4] = b"3gmI";

pub fn extract_image_payload(
    container: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, ImagePayloadError> {
    let payload = if container.starts_with(IMG3_MAGIC) {
        Img3::parse(container)?.payload()?.to_vec()
    } else {
        extract_im4p_payload(container)?.to_vec()
    };
    match encryption {
        Some((key, iv)) => Ok(decrypt_cbc(&payload, key, iv)?),
        None => Ok(payload),
    }
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
