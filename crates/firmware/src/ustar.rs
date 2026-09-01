//! Minimal ustar archive writer shared by the powdersn0w bundle generators
//! and the kit-level IPSW builders. Produces the same header layout as
//! upstream's `tar -cvf` usage: root-owned 0644 files and 0755 directories.

use thiserror::Error;

const BLOCK: usize = 512;
const MAX_NAME: usize = 100;

/// Incremental ustar archive builder.
#[derive(Default)]
pub struct UstarBuilder {
    data: Vec<u8>,
}

impl UstarBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file entry with mode 0644, mirroring upstream's
    /// `tar -cvf <archive> <file>`.
    pub fn add_file(&mut self, path: &str, contents: &[u8]) -> Result<(), UstarError> {
        self.push_entry(path, b"0000644\0", b'0', contents)
    }

    /// Add a directory entry with mode 0755. A trailing slash is appended to
    /// the entry name when missing, matching GNU/BSD tar output.
    pub fn add_directory(&mut self, path: &str) -> Result<(), UstarError> {
        let path = path.strip_suffix('/').unwrap_or(path);
        self.push_entry(&format!("{path}/"), b"0000755\0", b'5', &[])
    }

    /// Finish the archive, appending the two zero end blocks.
    pub fn finish(mut self) -> Vec<u8> {
        self.data.resize(self.data.len() + 2 * BLOCK, 0);
        self.data
    }

    fn push_entry(
        &mut self,
        name: &str,
        mode: &'static [u8; 8],
        typeflag: u8,
        contents: &[u8],
    ) -> Result<(), UstarError> {
        if name.len() > MAX_NAME {
            return Err(UstarError::NameTooLong(name.to_owned()));
        }
        let mut header = [0u8; BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(mode);
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", contents.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        self.data.extend_from_slice(&header);
        self.data.extend_from_slice(contents);
        self.data.resize(self.data.len().next_multiple_of(BLOCK), 0);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum UstarError {
    #[error("ustar entry name exceeds 100 bytes: {0}")]
    NameTooLong(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_single_file_archive() {
        let data = b"hello ustar";
        let mut builder = UstarBuilder::new();
        builder.add_file("iBEC", data).unwrap();
        let archive = builder.finish();
        assert_eq!(&archive[..4], b"iBEC");
        assert_eq!(&archive[257..263], b"ustar\0");
        assert_eq!(archive.len() % 512, 0);
        let checksum_field = &archive[148..154];
        let checksum = u32::from_str_radix(
            std::str::from_utf8(checksum_field)
                .unwrap()
                .trim_end_matches('\0'),
            8,
        )
        .unwrap();
        let mut header = archive[..512].to_vec();
        header[148..156].fill(b' ');
        assert_eq!(checksum, header.iter().map(|b| u32::from(*b)).sum::<u32>());
        assert_eq!(&archive[512..512 + data.len()], data);
    }

    #[test]
    fn builds_nested_directories() {
        let mut builder = UstarBuilder::new();
        builder.add_directory("System").unwrap();
        builder.add_directory("System/Library/").unwrap();
        builder.add_file("System/Library/file", b"x").unwrap();
        let archive = builder.finish();
        assert_eq!(&archive[..7], b"System/");
        assert_eq!(archive[156], b'5');
        assert_eq!(&archive[512..512 + 15], b"System/Library/");
        assert_eq!(&archive[1024..1024 + 19], b"System/Library/file");
        assert_eq!(archive[1024 + 156], b'0');
    }

    #[test]
    fn rejects_long_names() {
        let mut builder = UstarBuilder::new();
        assert!(builder.add_file(&"x".repeat(101), b"").is_err());
    }
}
