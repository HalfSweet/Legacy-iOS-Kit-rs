use std::path::PathBuf;

use legacy_ios_core::{BuildId, ProductType};
use serde::Deserialize;
use thiserror::Error;

/// Pinned snapshot of the Legacy-iOS-Kit-Keys repository, matching upstream's
/// firmware key source.
const KEYS_COMMIT: &str = "af6bf5934dc61ed557a967a3f42ab7fb8ed8c45e";
const KEYS_BASE_URL: &str = "https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys";

/// A single image's firmware key material. Values are deliberately not
/// logged or debug-printed.
#[derive(Clone)]
pub struct FirmwareKey {
    image: String,
    filename: String,
    iv: Option<[u8; 16]>,
    key: Option<Vec<u8>>,
    kbag: Option<Vec<u8>>,
}

impl FirmwareKey {
    pub fn image(&self) -> &str {
        &self.image
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub const fn iv(&self) -> Option<&[u8; 16]> {
        self.iv.as_ref()
    }

    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    pub fn kbag(&self) -> Option<&[u8]> {
        self.kbag.as_deref()
    }
}

impl std::fmt::Debug for FirmwareKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FirmwareKey")
            .field("image", &self.image)
            .field("filename", &self.filename)
            .finish_non_exhaustive()
    }
}

/// Firmware keys for one product/build pair.
#[derive(Clone, Debug)]
pub struct FirmwareKeySet {
    keys: Vec<FirmwareKey>,
}

impl FirmwareKeySet {
    pub fn parse(source: &[u8]) -> Result<Self, FirmwareKeyError> {
        let raw: RawKeySet = serde_json::from_slice(source)?;
        let mut keys = Vec::with_capacity(raw.keys.len());
        for entry in raw.keys {
            keys.push(FirmwareKey {
                image: entry.image,
                filename: entry.filename,
                iv: entry.iv.as_deref().map(decode_iv).transpose()?,
                key: entry.key.as_deref().map(decode_key).transpose()?,
                kbag: entry.kbag.as_deref().map(hex::decode).transpose()?,
            });
        }
        Ok(Self { keys })
    }

    /// Look up key material by image name (e.g. `iBSS`, `RootFS`).
    pub fn key(&self, image: &str) -> Option<&FirmwareKey> {
        self.keys.iter().find(|key| key.image == image)
    }

    pub fn iter(&self) -> impl Iterator<Item = &FirmwareKey> {
        self.keys.iter()
    }
}

/// Fetches and caches firmware keys from the pinned keys snapshot.
pub struct FirmwareKeyProvider {
    cache_root: Option<PathBuf>,
}

impl FirmwareKeyProvider {
    pub fn uncached() -> Self {
        Self { cache_root: None }
    }

    pub fn with_cache(cache_root: impl Into<PathBuf>) -> Self {
        Self {
            cache_root: Some(cache_root.into()),
        }
    }

    pub async fn fetch(
        &self,
        product_type: &ProductType,
        build: &BuildId,
    ) -> Result<FirmwareKeySet, FirmwareKeyError> {
        let cache = self.cache_path(product_type, build);
        if let Some(path) = &cache
            && let Ok(data) = tokio::fs::read(path).await
        {
            return FirmwareKeySet::parse(&data);
        }
        let url = format!(
            "{KEYS_BASE_URL}/{KEYS_COMMIT}/{}/{}/index.html",
            product_type.as_str(),
            build.as_str()
        );
        let response = reqwest::get(&url).await?;
        if !response.status().is_success() {
            return Err(FirmwareKeyError::NotFound {
                product: product_type.as_str().to_owned(),
                build: build.as_str().to_owned(),
            });
        }
        let data = response.bytes().await?;
        let keys = FirmwareKeySet::parse(&data)?;
        if let Some(path) = &cache {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let temporary = path.with_extension("tmp");
            tokio::fs::write(&temporary, &data).await?;
            tokio::fs::rename(&temporary, path).await?;
        }
        Ok(keys)
    }

    fn cache_path(&self, product_type: &ProductType, build: &BuildId) -> Option<PathBuf> {
        self.cache_root.as_ref().map(|root| {
            root.join("keys")
                .join(product_type.as_str())
                .join(format!("{}.json", build.as_str()))
        })
    }
}

fn decode_iv(value: &str) -> Result<[u8; 16], FirmwareKeyError> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| FirmwareKeyError::InvalidKeyMaterial)
}

fn decode_key(value: &str) -> Result<Vec<u8>, FirmwareKeyError> {
    let key = hex::decode(value)?;
    // 16/24/32 bytes are AES keys; 36 bytes is a rootfs vfdecrypt key
    // (16-byte AES key followed by a 20-byte HMAC key).
    if !matches!(key.len(), 16 | 24 | 32 | 36) {
        return Err(FirmwareKeyError::InvalidKeyMaterial);
    }
    Ok(key)
}

#[derive(Deserialize)]
struct RawKeySet {
    keys: Vec<RawKey>,
}

#[derive(Deserialize)]
struct RawKey {
    image: String,
    filename: String,
    iv: Option<String>,
    key: Option<String>,
    kbag: Option<String>,
}

#[derive(Debug, Error)]
pub enum FirmwareKeyError {
    #[error("no firmware keys for {product} {build}")]
    NotFound { product: String, build: String },
    #[error("invalid firmware key material")]
    InvalidKeyMaterial,
    #[error("firmware key fetch failed: {0}")]
    Fetch(#[from] reqwest::Error),
    #[error("firmware key cache I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("firmware key document is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{"identifier":"iPhone3,1","buildid":"11D257","keys":[
        {"image":"iBSS","filename":"iBSS.n90ap.RELEASE.dfu","iv":"4bd50f8abb89925f20793baac84ad76b","key":"23582ce84d0149c1819b72948c6a55a155c1fa4366678a9e51a6f66f5a77de10","kbag":"4bd50f8a"},
        {"image":"GlyphPlugin","filename":"glyphplugin.img3","iv":null,"key":null,"kbag":null}
    ]}"#;

    #[test]
    fn parses_key_set() {
        let set = FirmwareKeySet::parse(SAMPLE).unwrap();
        let ibss = set.key("iBSS").unwrap();
        assert_eq!(ibss.filename(), "iBSS.n90ap.RELEASE.dfu");
        assert!(ibss.iv().is_some());
        assert_eq!(ibss.key().map(<[u8]>::len), Some(32));
        assert!(set.key("GlyphPlugin").unwrap().key().is_none());
        assert!(set.key("RootFS").is_none());
    }

    #[test]
    fn accepts_rootfs_vfdecrypt_key() {
        let rootfs_key = "00".repeat(36);
        let set = FirmwareKeySet::parse(
            format!(r#"{{"keys":[{{"image":"RootFS","filename":"rootfs.dmg","iv":null,"key":"{rootfs_key}","kbag":null}}]}}"#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(set.key("RootFS").unwrap().key().map(<[u8]>::len), Some(36));
    }

    #[test]
    fn rejects_bad_hex() {
        let bad = br#"{"keys":[{"image":"iBSS","filename":"x","iv":"zz","key":null,"kbag":null}]}"#;
        assert!(FirmwareKeySet::parse(bad).is_err());
    }
}
