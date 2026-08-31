use std::{fmt, path::PathBuf};

use thiserror::Error;

use crate::{KitError, hfs::write_atomic};

#[derive(Clone)]
pub struct ImageCipher {
    key: Vec<u8>,
    iv: [u8; 16],
}

impl ImageCipher {
    pub fn from_hex(key: &str, iv: &str) -> Result<Self, ImageCipherError> {
        let key = decode_hex(key)?;
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(ImageCipherError::InvalidKeyLength);
        }
        let iv: [u8; 16] = decode_hex(iv)?
            .try_into()
            .map_err(|_| ImageCipherError::InvalidIvLength)?;
        Ok(Self { key, iv })
    }

    fn key(&self) -> &[u8] {
        &self.key
    }

    fn iv(&self) -> &[u8] {
        &self.iv
    }
}

impl fmt::Debug for ImageCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageCipher")
            .finish_non_exhaustive()
    }
}

impl Drop for ImageCipher {
    fn drop(&mut self) {
        self.key.fill(0);
        self.iv.fill(0);
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ImageCipherError> {
    if !value.len().is_multiple_of(2) {
        return Err(ImageCipherError::InvalidHex);
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|_| ImageCipherError::InvalidHex)
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ImageCipherError {
    #[error("image cipher value is not hexadecimal")]
    InvalidHex,
    #[error("image cipher key must contain 16, 24, or 32 bytes")]
    InvalidKeyLength,
    #[error("image cipher IV must contain 16 bytes")]
    InvalidIvLength,
}

pub(crate) async fn extract(
    source: PathBuf,
    destination: PathBuf,
    cipher: Option<ImageCipher>,
) -> Result<(), KitError> {
    let container = tokio::fs::read(source).await?;
    let payload = tokio::task::spawn_blocking(move || {
        legacy_ios_image::extract_image_payload(
            &container,
            cipher.as_ref().map(|cipher| (cipher.key(), cipher.iv())),
        )
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    write_atomic(destination, payload).await
}

pub(crate) async fn replace(
    source: PathBuf,
    payload: PathBuf,
    destination: PathBuf,
    cipher: Option<ImageCipher>,
) -> Result<(), KitError> {
    let container = tokio::fs::read(source).await?;
    let payload = tokio::fs::read(payload).await?;
    let container = tokio::task::spawn_blocking(move || {
        legacy_ios_image::replace_image_payload(
            &container,
            &payload,
            cipher.as_ref().map(|cipher| (cipher.key(), cipher.iv())),
        )
    })
    .await
    .map_err(|error| KitError::Task(error.to_string()))??;
    write_atomic(destination, container).await
}

#[cfg(test)]
mod tests {
    use legacy_ios_image::{Img3, Img3Element, Img3Tag};

    use super::*;

    #[test]
    fn parses_cipher_material() {
        assert!(ImageCipher::from_hex(&"00".repeat(16), &"11".repeat(16)).is_ok());
        assert_eq!(
            ImageCipher::from_hex("00", "11").unwrap_err(),
            ImageCipherError::InvalidKeyLength
        );
    }

    #[tokio::test]
    async fn extracts_and_replaces_container_payload() {
        let image = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, b"old".to_vec())]);
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.img3");
        let extracted = root.path().join("payload.bin");
        let replacement = root.path().join("replacement.bin");
        let output = root.path().join("output.img3");
        tokio::fs::write(&source, image.to_bytes()).await.unwrap();

        extract(source.clone(), extracted.clone(), None)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(extracted).await.unwrap(), b"old");
        tokio::fs::write(&replacement, b"new").await.unwrap();
        replace(source, replacement, output.clone(), None)
            .await
            .unwrap();
        assert_eq!(
            Img3::parse(&tokio::fs::read(output).await.unwrap())
                .unwrap()
                .payload()
                .unwrap(),
            b"new"
        );
    }
}
