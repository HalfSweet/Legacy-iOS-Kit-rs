use std::{io, path::PathBuf};

use legacy_ios_core::Udid;
use legacy_ios_services::PairingRecord;

use crate::KitError;

#[derive(Clone, Debug)]
pub struct PairingStore {
    root: PathBuf,
}

impl PairingStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub async fn load(&self, udid: &Udid) -> Result<Option<PairingRecord>, KitError> {
        let path = self.record_path(udid);
        match tokio::fs::read(path).await {
            Ok(bytes) => Ok(Some(PairingRecord::from_bytes(&bytes)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn save(&self, udid: &Udid, record: &PairingRecord) -> Result<(), KitError> {
        tokio::fs::create_dir_all(&self.root).await?;
        let root = self.root.clone();
        let destination = self.record_path(udid);
        let bytes = record.to_bytes()?;
        tokio::task::spawn_blocking(move || {
            use std::io::Write;

            let mut temporary = tempfile::NamedTempFile::new_in(root)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist(destination)
                .map_err(|error| error.error)?;
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|error| KitError::Task(error.to_string()))??;
        Ok(())
    }

    fn record_path(&self, udid: &Udid) -> PathBuf {
        self.root.join(record_file_name(udid))
    }
}

fn record_file_name(udid: &Udid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(udid.as_str().len() * 2 + 6);
    for byte in udid.as_str().bytes() {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".plist");
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_record_names_cannot_escape_the_store() {
        assert_eq!(record_file_name(&Udid::from("../")), "2e2e2f.plist");
    }
}
