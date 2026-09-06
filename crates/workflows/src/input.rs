use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// A private copy, retained for the lifetime of every plan clone. Executing a
/// plan never reopens the caller's mutable source file.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PinnedInput {
    role: String,
    size: u64,
    sha256: String,
    #[serde(skip)]
    file: Arc<tempfile::TempPath>,
}

impl PinnedInput {
    pub(crate) fn copy(role: &str, source: &Path) -> Result<Self, std::io::Error> {
        let mut source = File::open(source)?;
        let mut copy = tempfile::Builder::new().prefix("lik-input-").tempfile()?;
        let mut digest = Sha256::new();
        let mut size = 0;
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copy.write_all(&buffer[..count])?;
            digest.update(&buffer[..count]);
            size += count as u64;
        }
        copy.flush()?;
        copy.as_file().sync_all()?;
        Ok(Self {
            role: role.to_owned(),
            size,
            sha256: hex::encode(digest.finalize()),
            file: Arc::new(copy.into_temp_path()),
        })
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn path(&self) -> &Path {
        self.file.as_ref().as_ref()
    }
}

impl PartialEq for PinnedInput {
    fn eq(&self, other: &Self) -> bool {
        self.role == other.role && self.size == other.size && self.sha256 == other.sha256
    }
}

impl Eq for PinnedInput {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_replacement_does_not_change_retained_input() {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"approved input").unwrap();
        let first = PinnedInput::copy("firmware", source.path()).unwrap();
        std::fs::write(source.path(), b"replacement").unwrap();
        let second = PinnedInput::copy("firmware", source.path()).unwrap();
        assert_ne!(first, second);
        let clone = first.clone();
        let fixed_path = clone.path().to_owned();
        drop(first);
        assert_eq!(std::fs::read(&fixed_path).unwrap(), b"approved input");
        drop(clone);
        assert!(!fixed_path.exists());
    }
}
