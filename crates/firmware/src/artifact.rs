use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use reqwest::Url;
use sha2::Digest as _;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, trace};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Digest {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl Digest {
    fn algorithm(self) -> &'static str {
        match self {
            Self::Sha1(_) => "sha1",
            Self::Sha256(_) => "sha256",
        }
    }

    fn bytes(self) -> Vec<u8> {
        match self {
            Self::Sha1(value) => value.to_vec(),
            Self::Sha256(value) => value.to_vec(),
        }
    }

    fn verifier(self) -> DigestVerifier {
        match self {
            Self::Sha1(_) => DigestVerifier::Sha1(sha1::Sha1::new()),
            Self::Sha256(_) => DigestVerifier::Sha256(sha2::Sha256::new()),
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}",
            self.algorithm(),
            hex::encode(self.bytes())
        )
    }
}

impl FromStr for Digest {
    type Err = ArtifactError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (algorithm, encoded) = value.split_once(':').ok_or(ArtifactError::InvalidDigest)?;
        let decoded = hex::decode(encoded).map_err(|_| ArtifactError::InvalidDigest)?;
        match algorithm {
            "sha1" => decoded
                .try_into()
                .map(Self::Sha1)
                .map_err(|_| ArtifactError::InvalidDigest),
            "sha256" => decoded
                .try_into()
                .map(Self::Sha256)
                .map_err(|_| ArtifactError::InvalidDigest),
            _ => Err(ArtifactError::InvalidDigest),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactSpec {
    url: Url,
    digest: Digest,
    size: Option<u64>,
}

impl ArtifactSpec {
    pub fn new(url: Url, digest: Digest) -> Self {
        Self {
            url,
            digest,
            size: None,
        }
    }

    pub fn parse(url: &str, digest: &str) -> Result<Self, ArtifactError> {
        let url = Url::parse(url).map_err(|_| ArtifactError::InvalidUrl)?;
        Ok(Self::new(url, digest.parse()?))
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }

    pub const fn size(&self) -> Option<u64> {
        self.size
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactStore {
    root: PathBuf,
    client: reqwest::Client,
}

impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn find(&self, digest: Digest) -> Result<Option<PathBuf>, ArtifactError> {
        let path = self.path_for(digest);
        if !path.try_exists()? {
            return Ok(None);
        }
        let actual = hash_file(&path, digest).await?;
        if actual != digest {
            return Err(ArtifactError::DigestMismatch {
                expected: digest,
                actual,
            });
        }
        Ok(Some(path))
    }

    pub async fn fetch(&self, spec: &ArtifactSpec) -> Result<PathBuf, ArtifactError> {
        if let Some(path) = self.find(spec.digest).await? {
            debug!(digest = %spec.digest, "using cached artifact");
            return Ok(path);
        }

        let destination = self.path_for(spec.digest);
        let parent = destination
            .parent()
            .expect("artifact path always has a parent");
        tokio::fs::create_dir_all(parent).await?;
        let temporary = tempfile::Builder::new()
            .prefix("download-")
            .tempfile_in(parent)?;
        let temporary = temporary.into_temp_path();
        let mut output = tokio::fs::File::create(&temporary).await?;
        let mut response = self
            .client
            .get(spec.url.clone())
            .send()
            .await?
            .error_for_status()?;
        let mut verifier = spec.digest.verifier();
        let mut downloaded = 0_u64;

        info!(url = %spec.url, digest = %spec.digest, "downloading artifact");
        while let Some(chunk) = response.chunk().await? {
            verifier.update(&chunk);
            output.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            trace!(downloaded, "downloaded artifact bytes");
        }
        output.flush().await?;
        drop(output);

        let actual = verifier.finalize();
        if actual != spec.digest {
            return Err(ArtifactError::DigestMismatch {
                expected: spec.digest,
                actual,
            });
        }
        if let Some(expected) = spec.size
            && expected != downloaded
        {
            return Err(ArtifactError::SizeMismatch {
                expected,
                actual: downloaded,
            });
        }
        tokio::fs::rename(&temporary, &destination).await?;
        info!(bytes = downloaded, path = %destination.display(), "cached artifact");
        Ok(destination)
    }

    fn path_for(&self, digest: Digest) -> PathBuf {
        self.root
            .join(digest.algorithm())
            .join(hex::encode(digest.bytes()))
    }
}

enum DigestVerifier {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl DigestVerifier {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(data),
            Self::Sha256(hasher) => hasher.update(data),
        }
    }

    fn finalize(self) -> Digest {
        match self {
            Self::Sha1(hasher) => Digest::Sha1(hasher.finalize().into()),
            Self::Sha256(hasher) => Digest::Sha256(hasher.finalize().into()),
        }
    }
}

async fn hash_file(path: &Path, expected: Digest) -> Result<Digest, ArtifactError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0; 128 * 1024];
    let mut verifier = expected.verifier();
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        verifier.update(&buffer[..read]);
    }
    Ok(verifier.finalize())
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("invalid artifact digest")]
    InvalidDigest,
    #[error("invalid artifact URL")]
    InvalidUrl,
    #[error("artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("artifact HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("artifact digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: Digest, actual: Digest },
    #[error("artifact size mismatch: expected {expected} bytes, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_digests() {
        let value = "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(value.parse::<Digest>().unwrap().to_string(), value);
        let spec = ArtifactSpec::parse("https://example.com/resource", value)
            .unwrap()
            .with_size(42);
        assert_eq!(spec.size(), Some(42));
    }

    #[tokio::test]
    async fn finds_verified_cached_artifact() {
        let root = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(root.path());
        let digest = Digest::Sha256(sha2::Sha256::digest(b"artifact").into());
        let path = store.path_for(digest);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"artifact").unwrap();

        assert_eq!(store.find(digest).await.unwrap(), Some(path));
    }
}
