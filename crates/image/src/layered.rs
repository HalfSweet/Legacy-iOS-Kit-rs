//! The `doPatch`/`doPatchInPlace` container stack of xpwn's `ipsw` tool,
//! ported from daibutsuCFW `src/xpwn/ipsw-patch/nor_files.c` and
//! `pwnutil.c` (commit de7956d9722ed83f27caec8c0b29e3d8361691fc).
//!
//! `openAbstractFile2` peels every known layer — 8900 (`8900`), IMG2
//! (`2gmI`), IMG3 (`3gmI`, the key/iv applied to the first one), `complzss`
//! — until the raw image remains, and `duplicateAbstractFile2` re-stacks the
//! same layers around the patched payload: the IMG3 layer re-encrypts with
//! the same key material, `complzss` re-compresses, IMG2 refreshes its
//! header, and 8900 re-encrypts with the 0x837 key (fixing up a nested IMG2
//! payload first). The ibootim layer (iOS 1.x era) is not modeled: classic
//! targets never ship it in a patched component, so an ibootim payload is
//! treated as raw.

use thiserror::Error;

use crate::{
    ImagePayloadError, Img1, Img1Error, Img2, Img2Error, Img3, LzssError, PatchError, apply_bsdiff,
    compress_lzss, decompress_lzss, encrypt_cbc, extract_image_payload, is_lzss_compressed,
    replace_image_payload,
};

const IMG1_MAGIC: &[u8; 4] = b"8900";
const IMG3_MAGIC: &[u8; 4] = b"3gmI";

/// One peeled container layer, re-stacked inside-out after the patch.
#[derive(Debug)]
enum Layer {
    Img1(Box<Img1>),
    Img2(Box<Img2>),
    /// The original IMG3 container bytes plus the key material it was
    /// decrypted with (`None` when the layer was plaintext).
    Img3 {
        container: Vec<u8>,
        encryption: Option<(Vec<u8>, Vec<u8>)>,
    },
    CompLzss,
}

/// Port of `doPatch`: peel all container layers of `container` (decrypting
/// the first IMG3 layer with `encryption` when given), apply the bsdiff
/// patch to the raw image, and re-stack the layers around the patched image
/// (`duplicateAbstractFile2` semantics: the IMG3 layer is re-encrypted with
/// the same key material).
///
/// With a raw (uncontainerized) input and no layers this degenerates to
/// `doPatchInPlace`'s plain bsdiff of the file bytes.
pub fn patch_layered(
    container: &[u8],
    patch: &[u8],
    encryption: Option<(&[u8], &[u8])>,
) -> Result<Vec<u8>, LayeredError> {
    let (raw, layers) = peel(container, encryption)?;
    let patched = apply_bsdiff(&raw, patch)?;
    restack(patched, layers)
}

fn peel(
    container: &[u8],
    mut encryption: Option<(&[u8], &[u8])>,
) -> Result<(Vec<u8>, Vec<Layer>), LayeredError> {
    let mut current = container.to_vec();
    let mut layers = Vec::new();
    loop {
        if current.starts_with(IMG1_MAGIC) {
            let image = Img1::parse(&current)?;
            current = image.payload().to_vec();
            layers.push(Layer::Img1(Box::new(image)));
        } else if current.starts_with(crate::img2::IMG2_MAGIC) {
            let image = Img2::parse(&current)?;
            current = image.payload().to_vec();
            layers.push(Layer::Img2(Box::new(image)));
        } else if current.starts_with(IMG3_MAGIC) {
            // The key/iv apply to the first IMG3 layer only (openAbstractFile3
            // clears them afterwards).
            let keys = encryption
                .take()
                .map(|(key, iv)| (key.to_vec(), iv.to_vec()));
            let payload = extract_image_payload(
                &current,
                keys.as_ref()
                    .map(|(key, iv)| (key.as_slice(), iv.as_slice())),
            )?;
            layers.push(Layer::Img3 {
                container: std::mem::take(&mut current),
                encryption: keys,
            });
            current = payload;
        } else if is_lzss_compressed(&current) {
            current = decompress_lzss(&current)?;
            layers.push(Layer::CompLzss);
        } else {
            break;
        }
    }
    Ok((current, layers))
}

fn restack(patched: Vec<u8>, layers: Vec<Layer>) -> Result<Vec<u8>, LayeredError> {
    let mut current = patched;
    for layer in layers.into_iter().rev() {
        current = match layer {
            Layer::CompLzss => compress_lzss(&current)?,
            Layer::Img2(image) => image.rewrap(&current),
            Layer::Img3 {
                container,
                encryption,
            } => match encryption {
                // closeImg3: re-encrypt with the same key material, padding
                // the DATA body to the AES block size while the declared data
                // size stays the real payload length (Apple's layout).
                Some((key, iv)) => {
                    let mut padded = current.clone();
                    padded.resize(current.len().next_multiple_of(16), 0);
                    let body =
                        encrypt_cbc(&padded, &key, &iv).map_err(ImagePayloadError::Crypto)?;
                    Img3::parse(&container)
                        .and_then(|image| image.with_padded_payload(body, current.len()))
                        .map_err(ImagePayloadError::Img3)?
                        .to_bytes()
                }
                None => replace_image_payload(&container, &current, None)?,
            },
            Layer::Img1(image) => image.reseal(&current)?,
        };
    }
    Ok(current)
}

#[derive(Debug, Error)]
pub enum LayeredError {
    #[error("8900 layer failed: {0}")]
    Img1(#[from] Img1Error),
    #[error("IMG2 layer failed: {0}")]
    Img2(#[from] Img2Error),
    #[error("IMG3 layer failed: {0}")]
    Img3(#[from] ImagePayloadError),
    #[error("complzss layer failed: {0}")]
    Lzss(#[from] LzssError),
    #[error("bsdiff patch failed: {0}")]
    Patch(#[from] PatchError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Img3, Img3Element, Img3Tag, encrypt_cbc};

    const KEY: [u8; 16] = [0x2b; 16];
    const IV: [u8; 16] = [0x01; 16];

    /// The patch.rs fixture patch: bsdiff of "abc" to "axc!".
    const ABC_PATCH: &str = concat!(
        "42534449464634302a0000000000000027000000000000000400000000000000",
        "425a6839314159265359d0149a29000004c0006808200030cd34193f5209593c5d",
        "c914e14243405268a4425a6839314159265359bd1ca64a000000e0004000010020",
        "002100828c5dc914e14242f4729928425a68393141592653592d15eb1c00000010",
        "002000200021184682ee48a70a1205a2bd6380"
    );

    fn abc_patch() -> Vec<u8> {
        hex::decode(ABC_PATCH).unwrap()
    }

    /// Encrypted IMG3 around a payload, with the DATA body padded like real
    /// Apple images (the payload.rs test construction).
    fn encrypted_img3(payload: &[u8]) -> Vec<u8> {
        let mut padded = payload.to_vec();
        padded.resize(padded.len().next_multiple_of(16), 0);
        let ciphertext = encrypt_cbc(&padded, &KEY, &IV).unwrap();
        let image = Img3::new(
            0x7373_6269,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"ibss".to_vec()),
                Img3Element::new(Img3Tag::DATA, ciphertext),
            ],
        );
        let mut bytes = image.to_bytes();
        // Trim the DATA element's data size to the real payload length,
        // leaving the encrypted padding in place. Layout: 20-byte IMG3
        // header, 16-byte TYPE element (12-byte header + 4-byte "ibss"),
        // then the DATA element header whose size field sits at +8.
        let body_size_offset = 20 + (12 + 4) + 8;
        let data_size = (payload.len() as u32).to_le_bytes();
        bytes[body_size_offset..body_size_offset + 4].copy_from_slice(&data_size);
        bytes
    }

    fn img2_wrapping(payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; crate::img2::IMG2_HEADER_SIZE];
        header[..4].copy_from_slice(crate::img2::IMG2_MAGIC);
        header[0x10..0x14].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[0x14..0x18].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let checksum = crc32fast::hash(&header[..0x64]);
        header[0x64..0x68].copy_from_slice(&checksum.to_le_bytes());
        let mut image = header.to_vec();
        image.extend_from_slice(payload);
        image
    }

    /// Encrypted (format-3) 8900 around a payload, signed like close8900.
    fn img1_wrapping(payload: &[u8]) -> Vec<u8> {
        use sha1::{Digest, Sha1};
        let mut padded = payload.to_vec();
        padded.resize(padded.len().next_multiple_of(16), 0);
        let size_of_data = padded.len();
        let mut header = [0u8; crate::HEADER_SIZE];
        header[..4].copy_from_slice(IMG1_MAGIC);
        header[0x07] = crate::img1::FORMAT_ENCRYPTED;
        header[0x0c..0x10].copy_from_slice(&(size_of_data as u32).to_le_bytes());
        header[0x10..0x14].copy_from_slice(&(size_of_data as u32).to_le_bytes());
        header[0x14..0x18]
            .copy_from_slice(&((size_of_data + crate::FOOTER_SIGNATURE_SIZE) as u32).to_le_bytes());
        header[0x18..0x1c].copy_from_slice(&0xc0au32.to_le_bytes());
        let digest = Sha1::digest(&header[..0x40]);
        let signature = encrypt_cbc(&digest[..16], &IMG1_PAYLOAD_KEY, &[0u8; 16]).unwrap();
        header[0x40..0x50].copy_from_slice(&signature);
        let encrypted = encrypt_cbc(&padded, &IMG1_PAYLOAD_KEY, &[0u8; 16]).unwrap();
        let mut image = Vec::new();
        image.extend_from_slice(&header);
        image.extend_from_slice(&encrypted);
        image.extend_from_slice(&[0x77; crate::FOOTER_SIGNATURE_SIZE]);
        image.extend(std::iter::repeat_n(0x11, 0xc0a));
        image
    }

    // The 0x837 key is private to img1.rs; the test duplicates it to build
    // the encrypted container by hand.
    const IMG1_PAYLOAD_KEY: [u8; 16] = [
        0x18, 0x84, 0x58, 0xa6, 0xd1, 0x50, 0x34, 0xdf, 0xe3, 0x86, 0xf2, 0x3b, 0x61, 0xd4, 0x37,
        0x74,
    ];

    #[test]
    fn patches_raw_input_like_do_patch_in_place() {
        assert_eq!(patch_layered(b"abc", &abc_patch(), None).unwrap(), b"axc!");
    }

    #[test]
    fn patches_through_encrypted_img3_and_complzss() {
        let container = encrypted_img3(&compress_lzss(b"abc").unwrap());
        let output = patch_layered(&container, &abc_patch(), Some((&KEY, &IV))).unwrap();

        // The output re-stacks both layers and re-encrypts the IMG3 payload.
        let payload = extract_image_payload(&output, Some((&KEY, &IV))).unwrap();
        assert!(is_lzss_compressed(&payload));
        assert_eq!(decompress_lzss(&payload).unwrap(), b"axc!");
        // The DATA body really is re-encrypted (decrypting without keys must
        // not yield the compressed payload).
        let raw = extract_image_payload(&output, None).unwrap();
        assert!(!is_lzss_compressed(&raw));
    }

    #[test]
    fn patches_plaintext_img3_without_key_material() {
        let container = Img3::new(
            0x7373_6269,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"ibss".to_vec()),
                Img3Element::new(Img3Tag::DATA, b"abc".to_vec()),
            ],
        )
        .to_bytes();
        let output = patch_layered(&container, &abc_patch(), None).unwrap();
        assert_eq!(extract_image_payload(&output, None).unwrap(), b"axc!");
    }

    #[test]
    fn patches_through_8900_img2_stack() {
        let container = img1_wrapping(&img2_wrapping(b"abc"));
        let output = patch_layered(&container, &abc_patch(), None).unwrap();

        let img1 = Img1::parse(&output).unwrap();
        assert!(img1.is_encrypted());
        let img2_bytes = img1.payload();
        assert!(img2_bytes.starts_with(crate::img2::IMG2_MAGIC));
        // close8900 aligned the inner dataLenPadded to the AES block size and
        // refreshed the checksum over it.
        assert_eq!(
            u32::from_le_bytes(img2_bytes[0x10..0x14].try_into().unwrap()),
            16
        );
        let checksum = crc32fast::hash(&img2_bytes[..0x64]);
        assert_eq!(
            u32::from_le_bytes(img2_bytes[0x64..0x68].try_into().unwrap()),
            checksum
        );
        let img2 = Img2::parse(img2_bytes).unwrap();
        assert_eq!(img2.payload(), b"axc!");
    }

    #[test]
    fn rejects_garbage_patch() {
        assert!(matches!(
            patch_layered(b"abc", b"not a patch", None),
            Err(LayeredError::Patch(PatchError::InvalidHeader))
        ));
    }
}
