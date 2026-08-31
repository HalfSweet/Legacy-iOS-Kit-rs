use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::NoPadding};
use thiserror::Error;

pub fn decrypt_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crypt(data, key, iv, Direction::Decrypt)
}

pub fn encrypt_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crypt(data, key, iv, Direction::Encrypt)
}

fn crypt(data: &[u8], key: &[u8], iv: &[u8], direction: Direction) -> Result<Vec<u8>, CryptoError> {
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::UnalignedData);
    }
    if iv.len() != 16 {
        return Err(CryptoError::InvalidIv);
    }

    let mut output = data.to_vec();
    match (key.len(), direction) {
        (16, Direction::Decrypt) => decrypt::<Aes128>(&mut output, key, iv)?,
        (24, Direction::Decrypt) => decrypt::<Aes192>(&mut output, key, iv)?,
        (32, Direction::Decrypt) => decrypt::<Aes256>(&mut output, key, iv)?,
        (16, Direction::Encrypt) => encrypt::<Aes128>(&mut output, key, iv)?,
        (24, Direction::Encrypt) => encrypt::<Aes192>(&mut output, key, iv)?,
        (32, Direction::Encrypt) => encrypt::<Aes256>(&mut output, key, iv)?,
        _ => return Err(CryptoError::InvalidKey),
    }
    Ok(output)
}

fn decrypt<C>(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), CryptoError>
where
    C: cbc::cipher::BlockCipher + cbc::cipher::BlockDecrypt + KeyInit,
{
    cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|_| CryptoError::UnalignedData)?;
    Ok(())
}

fn encrypt<C>(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), CryptoError>
where
    C: cbc::cipher::BlockCipher + cbc::cipher::BlockEncrypt + KeyInit,
{
    let length = data.len();
    cbc::Encryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidKey)?
        .encrypt_padded_mut::<NoPadding>(data, length)
        .map_err(|_| CryptoError::UnalignedData)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("AES key must contain 16, 24, or 32 bytes")]
    InvalidKey,
    #[error("AES-CBC IV must contain 16 bytes")]
    InvalidIv,
    #[error("AES-CBC data must be block aligned")]
    UnalignedData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_nist_aes128_cbc_vector() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();

        assert_eq!(encrypt_cbc(&plaintext, &key, &iv).unwrap(), ciphertext);
        assert_eq!(decrypt_cbc(&ciphertext, &key, &iv).unwrap(), plaintext);
    }
}
