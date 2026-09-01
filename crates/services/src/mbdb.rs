//! Classic `Manifest.mbdb` backup record encoding.
//!
//! Ported from JJTech0130's TrollRestore `sparserestore/mbdb.py`, which
//! defines the exact field layout: every record is a sequence of
//! big-endian, length-prefixed fields with no alignment or padding.

use thiserror::Error;

const MAGIC: &[u8; 4] = b"mbdb";
const VERSION: [u8; 2] = [0x05, 0x00];
/// Length marker that decodes as an empty string or blob.
const ABSENT: u16 = 0xffff;

/// File type bits recorded in [`MbdbRecord::mode`].
pub mod mode {
    pub const S_IFDIR: u16 = 0o040000;
    pub const S_IFREG: u16 = 0o100000;
    pub const S_IFLNK: u16 = 0o120000;
    /// RWX:RX:RX, the default permission bits used by the reference tool.
    pub const DEFAULT: u16 = 0o755;
}

/// One file entry in a `Manifest.mbdb`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MbdbRecord {
    domain: String,
    filename: String,
    link: String,
    hash: Vec<u8>,
    key: Vec<u8>,
    /// Whether the link/hash/key fields are encoded as absent (`0xffff`)
    /// rather than empty (`0x0000`). Device backups and the C backup tools
    /// use the absent marker; the marker state is preserved when a parsed
    /// record is re-encoded.
    link_absent: bool,
    hash_absent: bool,
    key_absent: bool,
    mode: u16,
    inode: u64,
    user_id: u32,
    group_id: u32,
    mtime: u32,
    atime: u32,
    ctime: u32,
    size: u64,
    flags: u8,
    properties: Vec<(String, String)>,
}

impl MbdbRecord {
    pub fn new(domain: impl Into<String>, filename: impl Into<String>, mode: u16) -> Self {
        Self {
            domain: domain.into(),
            filename: filename.into(),
            link: String::new(),
            hash: Vec::new(),
            key: Vec::new(),
            link_absent: false,
            hash_absent: false,
            key_absent: false,
            mode,
            inode: 0,
            user_id: 0,
            group_id: 0,
            mtime: 0,
            atime: 0,
            ctime: 0,
            size: 0,
            flags: 4,
            properties: Vec::new(),
        }
    }

    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.link = link.into();
        self.link_absent = false;
        self
    }

    /// Mark the link, hash, and key fields absent (`0xffff` length markers),
    /// matching the records written by the C backup tools; a later
    /// `with_link`/`with_hash` makes its field concrete again.
    pub fn with_absent_markers(mut self) -> Self {
        self.link_absent = true;
        self.hash_absent = true;
        self.key_absent = true;
        self
    }

    pub fn with_hash(mut self, hash: Vec<u8>) -> Self {
        self.hash = hash;
        self.hash_absent = false;
        self
    }

    pub fn with_inode(mut self, inode: u64) -> Self {
        self.inode = inode;
        self
    }

    pub fn with_owner(mut self, user_id: u32, group_id: u32) -> Self {
        self.user_id = user_id;
        self.group_id = group_id;
        self
    }

    pub fn with_timestamps(mut self, mtime: u32, atime: u32, ctime: u32) -> Self {
        self.mtime = mtime;
        self.atime = atime;
        self.ctime = ctime;
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_properties(mut self, properties: Vec<(String, String)>) -> Self {
        self.properties = properties;
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn link(&self) -> &str {
        &self.link
    }

    pub const fn mode(&self) -> u16 {
        self.mode
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    pub const fn group_id(&self) -> u32 {
        self.group_id
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn flags(&self) -> u8 {
        self.flags
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), MbdbError> {
        write_string(output, &self.domain)?;
        write_string(output, &self.filename)?;
        write_optional_bytes(output, self.link.as_bytes(), self.link_absent)?;
        write_optional_bytes(output, &self.hash, self.hash_absent)?;
        write_optional_bytes(output, &self.key, self.key_absent)?;
        output.extend_from_slice(&self.mode.to_be_bytes());
        output.extend_from_slice(&self.inode.to_be_bytes());
        output.extend_from_slice(&self.user_id.to_be_bytes());
        output.extend_from_slice(&self.group_id.to_be_bytes());
        output.extend_from_slice(&self.mtime.to_be_bytes());
        output.extend_from_slice(&self.atime.to_be_bytes());
        output.extend_from_slice(&self.ctime.to_be_bytes());
        output.extend_from_slice(&self.size.to_be_bytes());
        output.push(self.flags);
        let properties = u8::try_from(self.properties.len()).map_err(|_| MbdbError::TooLong)?;
        output.push(properties);
        for (name, value) in &self.properties {
            write_string(output, name)?;
            write_string(output, value)?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MbdbError> {
        let mut output = Vec::new();
        self.encode(&mut output)?;
        Ok(output)
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self, MbdbError> {
        let domain = cursor.string()?;
        let filename = cursor.string()?;
        let (link, link_absent) = cursor.string_with_absence()?;
        let (hash, hash_absent) = cursor.bytes_with_absence()?;
        let (key, key_absent) = cursor.bytes_with_absence()?;
        let mode = cursor.u16()?;
        let inode = cursor.u64()?;
        let user_id = cursor.u32()?;
        let group_id = cursor.u32()?;
        let mtime = cursor.u32()?;
        let atime = cursor.u32()?;
        let ctime = cursor.u32()?;
        let size = cursor.u64()?;
        let flags = cursor.u8()?;
        let properties = cursor.u8()?;
        let mut pairs = Vec::with_capacity(properties as usize);
        for _ in 0..properties {
            let name = cursor.string_or_absent()?;
            let value = cursor.string_or_absent()?;
            pairs.push((name, value));
        }
        Ok(Self {
            domain,
            filename,
            link,
            hash,
            key,
            link_absent,
            hash_absent,
            key_absent,
            mode,
            inode,
            user_id,
            group_id,
            mtime,
            atime,
            ctime,
            size,
            flags,
            properties: pairs,
        })
    }
}

/// A complete `Manifest.mbdb` file: the `mbdb\x05\x00` header followed by
/// every record.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Mbdb {
    records: Vec<MbdbRecord>,
}

impl Mbdb {
    pub fn new(records: Vec<MbdbRecord>) -> Self {
        Self { records }
    }

    pub fn records(&self) -> &[MbdbRecord] {
        &self.records
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MbdbError> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&VERSION);
        for record in &self.records {
            record.encode(&mut output)?;
        }
        Ok(output)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, MbdbError> {
        let mut cursor = Cursor { data, offset: 0 };
        if cursor.take(MAGIC.len())? != MAGIC {
            return Err(MbdbError::InvalidMagic);
        }
        if cursor.take(VERSION.len())? != VERSION {
            return Err(MbdbError::UnsupportedVersion);
        }
        let mut records = Vec::new();
        while cursor.offset < data.len() {
            records.push(MbdbRecord::decode(&mut cursor)?);
        }
        Ok(Self { records })
    }
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<(), MbdbError> {
    write_bytes(output, value.as_bytes())
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), MbdbError> {
    let length = u16::try_from(value.len()).map_err(|_| MbdbError::TooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Write a field, using the absent marker (`0xffff`) instead of an empty
/// length when the record carries no value for it.
fn write_optional_bytes(output: &mut Vec<u8>, value: &[u8], absent: bool) -> Result<(), MbdbError> {
    if absent {
        output.extend_from_slice(&ABSENT.to_be_bytes());
        Ok(())
    } else {
        write_bytes(output, value)
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], MbdbError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or(MbdbError::Truncated)?;
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, MbdbError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MbdbError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, MbdbError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, MbdbError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn string(&mut self) -> Result<String, MbdbError> {
        let length = self.u16()? as usize;
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| MbdbError::InvalidUtf8)
    }

    fn string_or_absent(&mut self) -> Result<String, MbdbError> {
        Ok(self.string_with_absence()?.0)
    }

    fn string_with_absence(&mut self) -> Result<(String, bool), MbdbError> {
        let (bytes, absent) = self.bytes_with_absence()?;
        let string = String::from_utf8(bytes).map_err(|_| MbdbError::InvalidUtf8)?;
        Ok((string, absent))
    }

    fn bytes_with_absence(&mut self) -> Result<(Vec<u8>, bool), MbdbError> {
        let length = self.u16()?;
        if length == ABSENT {
            return Ok((Vec::new(), true));
        }
        Ok((self.take(length as usize)?.to_vec(), false))
    }
}

#[derive(Debug, Error)]
pub enum MbdbError {
    #[error("mbdb field does not fit its length prefix")]
    TooLong,
    #[error("mbdb data is truncated")]
    Truncated,
    #[error("mbdb data does not start with the mbdb magic")]
    InvalidMagic,
    #[error("mbdb version is not supported")]
    UnsupportedVersion,
    #[error("mbdb string is not UTF-8")]
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors produced by JJTech0130's TrollRestore mbdb.py.
    const DIR_RECORD_HEX: &str = "000a526f6f74446f6d61696e00074c69627261727900000000000041ed0000000000000000000000000000000000000000000000000000000000000000000000000400";
    const FILE_RECORD_HEX: &str = "000a526f6f74446f6d61696e00184c6962726172792f507265666572656e6365732f74656d7000000014000102030405060708090a0b0c0d0e0f10111213000081ed010203040506070800000021000000216553f1006553f1016553f102000000000000000b040100046e616d65000576616c7565";

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn directory_record() -> MbdbRecord {
        MbdbRecord::new("RootDomain", "Library", mode::S_IFDIR | mode::DEFAULT)
    }

    fn file_record() -> MbdbRecord {
        MbdbRecord::new(
            "RootDomain",
            "Library/Preferences/temp",
            mode::S_IFREG | mode::DEFAULT,
        )
        .with_hash((0u8..20).collect())
        .with_inode(0x0102_0304_0506_0708)
        .with_owner(33, 33)
        .with_timestamps(1_700_000_000, 1_700_000_001, 1_700_000_002)
        .with_size(11)
        .with_properties(vec![("name".to_owned(), "value".to_owned())])
    }

    #[test]
    fn encodes_directory_record_golden_bytes() {
        assert_eq!(
            directory_record().to_bytes().unwrap(),
            unhex(DIR_RECORD_HEX)
        );
    }

    #[test]
    fn encodes_file_record_golden_bytes() {
        assert_eq!(file_record().to_bytes().unwrap(), unhex(FILE_RECORD_HEX));
    }

    #[test]
    fn writes_magic_and_version_header() {
        let mbdb = Mbdb::new(vec![directory_record()]).to_bytes().unwrap();
        let mut expected = b"mbdb\x05\x00".to_vec();
        expected.extend_from_slice(&unhex(DIR_RECORD_HEX));
        assert_eq!(mbdb, expected);
    }

    #[test]
    fn roundtrips_records() {
        let mbdb = Mbdb::new(vec![directory_record(), file_record()]);
        let parsed = Mbdb::from_bytes(&mbdb.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, mbdb);
    }

    #[test]
    fn decodes_absent_fields_as_empty() {
        let mut record = directory_record().to_bytes().unwrap();
        // Link, hash, and key length prefixes start after the two strings.
        let link_length = 2 + 10 + 2 + 7;
        for offset in [link_length, link_length + 2, link_length + 4] {
            record[offset] = 0xff;
            record[offset + 1] = 0xff;
        }
        let parsed = Mbdb::from_bytes(&[b"mbdb\x05\x00".to_vec(), record].concat()).unwrap();
        assert_eq!(parsed.records()[0].link(), "");
        assert_eq!(parsed.records()[0].hash(), b"");
    }

    #[test]
    fn preserves_absent_markers_on_reencode() {
        let mut record = directory_record().to_bytes().unwrap();
        let link_length = 2 + 10 + 2 + 7;
        for offset in [link_length, link_length + 2, link_length + 4] {
            record[offset] = 0xff;
            record[offset + 1] = 0xff;
        }
        let data = [b"mbdb\x05\x00".to_vec(), record].concat();
        let parsed = Mbdb::from_bytes(&data).unwrap();
        assert_eq!(parsed.to_bytes().unwrap(), data);
    }

    #[test]
    fn absent_markers_encode_like_the_c_backup_tools() {
        let record = directory_record().with_absent_markers().to_bytes().unwrap();
        let link_length = 2 + 10 + 2 + 7;
        assert_eq!(
            &record[link_length..link_length + 6],
            b"\xff\xff\xff\xff\xff\xff"
        );

        // A concrete link makes only that field present again.
        let record = directory_record()
            .with_absent_markers()
            .with_link("/target")
            .to_bytes()
            .unwrap();
        assert_eq!(&record[link_length..link_length + 9], b"\x00\x07/target");
        assert_eq!(
            &record[link_length + 9..link_length + 13],
            b"\xff\xff\xff\xff"
        );
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert!(matches!(
            Mbdb::from_bytes(b"nope\x05\x00"),
            Err(MbdbError::InvalidMagic)
        ));
        assert!(matches!(
            Mbdb::from_bytes(b"mbdb\x05\x00\x00"),
            Err(MbdbError::Truncated)
        ));
    }
}
