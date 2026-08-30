use thiserror::Error;

const COMMON_HEADER: usize = 12;
const TYPE_0C_HEADER: usize = 40;
const TYPE_10_14_HEADER: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlsFile {
    elements: Vec<FlsElement>,
}

impl FlsFile {
    pub fn parse(data: &[u8]) -> Result<Self, FlsError> {
        let mut elements = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            if data.len() - offset < COMMON_HEADER {
                return Err(FlsError::TruncatedElement);
            }
            let element_type = read_u32(data, offset);
            let size = read_u32(data, offset + 4) as usize;
            if size < header_size(element_type) || offset + size > data.len() {
                return Err(FlsError::InvalidElementSize);
            }
            elements.push(FlsElement {
                element_type,
                raw: data[offset..offset + size].to_vec(),
            });
            offset += size;
        }
        if !elements.iter().any(|element| element.element_type == 0x0c) {
            return Err(FlsError::MissingSignatureElement);
        }
        Ok(Self { elements })
    }

    pub fn replace_signature(&mut self, signature: &[u8]) -> Result<(), FlsError> {
        let element = self.signature_element_mut()?;
        let data_size = read_u32(&element.raw, 28) as usize;
        let encoded_size = read_u32(&element.raw, TYPE_0C_HEADER + 0x10) as usize;
        if encoded_size != data_size {
            return Err(FlsError::DataSizeMismatch);
        }
        let signature_offset = read_u32(&element.raw, TYPE_0C_HEADER + 0x14) as usize;
        if signature_offset > data_size {
            return Err(FlsError::InvalidSignatureOffset);
        }
        let old_signature_size = data_size - signature_offset;
        let signature_start = element
            .raw
            .len()
            .checked_sub(old_signature_size)
            .ok_or(FlsError::InvalidSignatureOffset)?;
        element.raw.truncate(signature_start);
        element.raw.extend_from_slice(signature);
        update_type_0c_sizes(element)?;
        self.recalculate_offsets();
        Ok(())
    }

    pub fn insert_ticket(&mut self, ticket: &[u8]) -> Result<(), FlsError> {
        let element = self.signature_element_mut()?;
        let padding = (4 - ticket.len() % 4) % 4;
        let mut raw = Vec::with_capacity(element.raw.len() + ticket.len() + padding);
        raw.extend_from_slice(&element.raw[..TYPE_0C_HEADER]);
        raw.extend_from_slice(ticket);
        raw.extend(std::iter::repeat_n(0xff, padding));
        raw.extend_from_slice(&element.raw[TYPE_0C_HEADER..]);
        element.raw = raw;
        update_type_0c_sizes(element)?;
        self.recalculate_offsets();
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.elements
            .iter()
            .flat_map(|element| element.raw.iter().copied())
            .collect()
    }

    fn signature_element_mut(&mut self) -> Result<&mut FlsElement, FlsError> {
        self.elements
            .iter_mut()
            .find(|element| element.element_type == 0x0c)
            .ok_or(FlsError::MissingSignatureElement)
    }

    fn recalculate_offsets(&mut self) {
        let mut offset = 0_usize;
        for element in &mut self.elements {
            let header = header_size(element.element_type);
            match element.element_type {
                0x0c => write_u32(&mut element.raw, 36, (offset + header) as u32),
                0x10 | 0x14 => write_u32(&mut element.raw, 20, (offset + header) as u32),
                _ => {}
            }
            offset += element.raw.len();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FlsElement {
    element_type: u32,
    raw: Vec<u8>,
}

fn update_type_0c_sizes(element: &mut FlsElement) -> Result<(), FlsError> {
    let data_size = element
        .raw
        .len()
        .checked_sub(TYPE_0C_HEADER)
        .ok_or(FlsError::InvalidElementSize)?;
    let element_size = element.raw.len() as u32;
    write_u32(&mut element.raw, 4, element_size);
    write_u32(&mut element.raw, 28, data_size as u32);
    write_u32(&mut element.raw, TYPE_0C_HEADER + 0x10, data_size as u32);
    Ok(())
}

const fn header_size(element_type: u32) -> usize {
    match element_type {
        0x0c => TYPE_0C_HEADER,
        0x10 | 0x14 => TYPE_10_14_HEADER,
        _ => COMMON_HEADER,
    }
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("four-byte field"),
    )
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FlsError {
    #[error("FLS element is truncated")]
    TruncatedElement,
    #[error("invalid FLS element size")]
    InvalidElementSize,
    #[error("FLS has no type 0x0c signature element")]
    MissingSignatureElement,
    #[error("FLS data size fields do not match")]
    DataSizeMismatch,
    #[error("invalid FLS signature offset")]
    InvalidSignatureOffset,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_signature_in_type_0c_element() {
        let mut raw = vec![0; TYPE_0C_HEADER + 32];
        write_u32(&mut raw, 0, 0x0c);
        let raw_len = raw.len() as u32;
        write_u32(&mut raw, 4, raw_len);
        write_u32(&mut raw, 28, 32);
        write_u32(&mut raw, TYPE_0C_HEADER + 0x10, 32);
        write_u32(&mut raw, TYPE_0C_HEADER + 0x14, 28);
        raw[raw_len as usize - 4..].copy_from_slice(&[1, 2, 3, 4]);

        let mut fls = FlsFile::parse(&raw).unwrap();
        fls.replace_signature(&[9, 8]).unwrap();
        let result = fls.to_bytes();

        assert_eq!(&result[result.len() - 2..], &[9, 8]);
        assert_eq!(read_u32(&result, 28), 30);
    }
}
