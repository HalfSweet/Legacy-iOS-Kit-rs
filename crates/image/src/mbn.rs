use thiserror::Error;

const V1_MAGIC: &[u8] = b"\x0a\x00\x00\x00";
const V2_MAGIC: &[u8] = b"\xd1\xdc\x4b\x84\x34\x10\xd7\x73";
const BIN_MAGIC: &[u8] = b"\x7d\x04\x00\xea\x6c\x69\x48\x55";
const ELF_MAGIC: &[u8] = b"\x7fELF\x01\x01\x01\x00";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MbnFormat {
    V1,
    V2,
    Bin,
    Elf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MbnFile {
    format: MbnFormat,
    data: Vec<u8>,
}

impl MbnFile {
    pub fn parse(data: Vec<u8>) -> Result<Self, MbnError> {
        let format = if data.starts_with(V2_MAGIC) {
            MbnFormat::V2
        } else if data.starts_with(V1_MAGIC) {
            MbnFormat::V1
        } else if data.starts_with(BIN_MAGIC) {
            MbnFormat::Bin
        } else if data.starts_with(ELF_MAGIC) {
            MbnFormat::Elf
        } else {
            return Err(MbnError::UnknownFormat);
        };
        Ok(Self { format, data })
    }

    pub const fn format(&self) -> MbnFormat {
        self.format
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn replace_signature(&mut self, signature: &[u8]) -> Result<(), MbnError> {
        let offset = self
            .data
            .len()
            .checked_sub(signature.len())
            .ok_or(MbnError::SignatureTooLarge)?;
        self.data[offset..].copy_from_slice(signature);
        Ok(())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MbnError {
    #[error("unknown MBN format")]
    UnknownFormat,
    #[error("signature is larger than the MBN image")]
    SignatureTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_trailing_signature() {
        let mut data = V1_MAGIC.to_vec();
        data.extend_from_slice(&[0; 12]);
        let mut mbn = MbnFile::parse(data).unwrap();
        mbn.replace_signature(&[1, 2, 3, 4]).unwrap();

        assert_eq!(&mbn.data()[12..], &[1, 2, 3, 4]);
    }
}
