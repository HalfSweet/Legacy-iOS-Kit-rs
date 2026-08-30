use std::fmt;

use thiserror::Error;

const IMG3_HEADER_SIZE: usize = 20;
const ELEMENT_HEADER_SIZE: usize = 12;
const IMG3_SIGNATURE: u32 = 0x496d_6733;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Img3Tag(u32);

impl Img3Tag {
    pub const TYPE: Self = Self(0x5459_5045);
    pub const DATA: Self = Self(0x4441_5441);
    pub const KBAG: Self = Self(0x4b42_4147);
    pub const SHSH: Self = Self(0x5348_5348);
    pub const CERT: Self = Self(0x4345_5254);
    pub const CHIP: Self = Self(0x4348_4950);
    pub const PROD: Self = Self(0x5052_4f44);
    pub const SDOM: Self = Self(0x5344_4f4d);
    pub const VERS: Self = Self(0x5645_5253);
    pub const BORD: Self = Self(0x424f_5244);
    pub const SEPO: Self = Self(0x5345_504f);
    pub const ECID: Self = Self(0x4543_4944);
    pub const SALT: Self = Self(0x5341_4c54);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Img3Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0.to_be_bytes();
        write!(formatter, "{}", String::from_utf8_lossy(&bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Img3Element {
    tag: Img3Tag,
    data_size: u32,
    body: Vec<u8>,
}

impl Img3Element {
    pub fn new(tag: Img3Tag, data: Vec<u8>) -> Self {
        Self {
            tag,
            data_size: data.len() as u32,
            body: data,
        }
    }

    pub const fn tag(&self) -> Img3Tag {
        self.tag
    }

    pub fn data(&self) -> &[u8] {
        &self.body[..self.data_size as usize]
    }

    pub fn padding(&self) -> &[u8] {
        &self.body[self.data_size as usize..]
    }

    fn full_size(&self) -> usize {
        ELEMENT_HEADER_SIZE + self.body.len()
    }

    fn write_to(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.tag.0.to_le_bytes());
        output.extend_from_slice(&(self.full_size() as u32).to_le_bytes());
        output.extend_from_slice(&self.data_size.to_le_bytes());
        output.extend_from_slice(&self.body);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Img3 {
    image_type: u32,
    elements: Vec<Img3Element>,
}

impl Img3 {
    pub fn new(image_type: u32, elements: Vec<Img3Element>) -> Self {
        Self {
            image_type,
            elements,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, Img3Error> {
        if data.len() < IMG3_HEADER_SIZE {
            return Err(Img3Error::TruncatedHeader);
        }
        if read_u32(data, 0) != IMG3_SIGNATURE {
            return Err(Img3Error::InvalidSignature);
        }
        let full_size = read_u32(data, 4) as usize;
        if full_size < IMG3_HEADER_SIZE || full_size > data.len() {
            return Err(Img3Error::InvalidContainerSize(full_size));
        }
        let image_type = read_u32(data, 16);
        let mut elements = Vec::new();
        let mut offset = IMG3_HEADER_SIZE;
        while offset < full_size {
            let (element, size) = parse_element(&data[offset..full_size])?;
            elements.push(element);
            offset += size;
        }
        Ok(Self {
            image_type,
            elements,
        })
    }

    pub const fn image_type(&self) -> u32 {
        self.image_type
    }

    pub fn elements(&self) -> &[Img3Element] {
        &self.elements
    }

    pub fn is_personalized(&self) -> bool {
        self.elements
            .iter()
            .any(|element| element.tag == Img3Tag::ECID)
    }

    pub fn personalize(&self, signature: &[u8]) -> Result<Self, Img3Error> {
        if self.is_personalized() {
            return Ok(self.clone());
        }

        let signature = parse_signature(signature)?;
        let mut personalized = self.clone();
        personalized.replace_signature(signature);
        Ok(personalized)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let full_size = IMG3_HEADER_SIZE
            + self
                .elements
                .iter()
                .map(Img3Element::full_size)
                .sum::<usize>();
        let mut output = Vec::with_capacity(full_size);
        output.extend_from_slice(&IMG3_SIGNATURE.to_le_bytes());
        output.extend_from_slice(&(full_size as u32).to_le_bytes());
        output.extend_from_slice(&((full_size - IMG3_HEADER_SIZE) as u32).to_le_bytes());
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&self.image_type.to_le_bytes());

        let mut shsh_offset = None;
        for element in &self.elements {
            if element.tag == Img3Tag::SHSH {
                shsh_offset = Some(output.len() - IMG3_HEADER_SIZE);
            }
            element.write_to(&mut output);
        }
        if let Some(offset) = shsh_offset {
            output[12..16].copy_from_slice(&(offset as u32).to_le_bytes());
        }
        output
    }

    fn replace_signature(&mut self, signature: [Img3Element; 3]) {
        let insertion = self
            .elements
            .iter()
            .position(|element| is_signature_tag(element.tag))
            .unwrap_or(self.elements.len());
        self.elements
            .retain(|element| !is_signature_tag(element.tag));
        self.elements.splice(insertion..insertion, signature);
    }
}

fn parse_signature(data: &[u8]) -> Result<[Img3Element; 3], Img3Error> {
    let mut offset = 0;
    let mut elements = Vec::with_capacity(3);
    while offset < data.len() {
        let (element, size) = parse_element(&data[offset..])?;
        elements.push(element);
        offset += size;
    }
    let elements: [Img3Element; 3] = elements
        .try_into()
        .map_err(|_| Img3Error::InvalidSignatureElements)?;
    if elements[0].tag != Img3Tag::ECID
        || elements[1].tag != Img3Tag::SHSH
        || elements[2].tag != Img3Tag::CERT
    {
        return Err(Img3Error::InvalidSignatureElements);
    }
    Ok(elements)
}

fn parse_element(data: &[u8]) -> Result<(Img3Element, usize), Img3Error> {
    if data.len() < ELEMENT_HEADER_SIZE {
        return Err(Img3Error::TruncatedElement);
    }
    let tag = Img3Tag(read_u32(data, 0));
    let full_size = read_u32(data, 4) as usize;
    let data_size = read_u32(data, 8) as usize;
    if full_size < ELEMENT_HEADER_SIZE || full_size > data.len() {
        return Err(Img3Error::InvalidElementSize {
            tag,
            size: full_size,
        });
    }
    if data_size > full_size - ELEMENT_HEADER_SIZE {
        return Err(Img3Error::InvalidElementDataSize {
            tag,
            size: data_size,
        });
    }
    let body = data[ELEMENT_HEADER_SIZE..full_size].to_vec();
    Ok((
        Img3Element {
            tag,
            data_size: data_size as u32,
            body,
        },
        full_size,
    ))
}

fn is_signature_tag(tag: Img3Tag) -> bool {
    matches!(tag, Img3Tag::ECID | Img3Tag::SHSH | Img3Tag::CERT)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("four-byte field"),
    )
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Img3Error {
    #[error("IMG3 header is truncated")]
    TruncatedHeader,
    #[error("invalid IMG3 signature")]
    InvalidSignature,
    #[error("invalid IMG3 container size {0}")]
    InvalidContainerSize(usize),
    #[error("IMG3 element header is truncated")]
    TruncatedElement,
    #[error("invalid {tag} element size {size}")]
    InvalidElementSize { tag: Img3Tag, size: usize },
    #[error("invalid {tag} data size {size}")]
    InvalidElementDataSize { tag: Img3Tag, size: usize },
    #[error("IMG3 signature must contain ECID, SHSH, and CERT elements")]
    InvalidSignatureElements,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_round_trips() {
        let image = Img3::new(
            0x6962_7373,
            vec![
                Img3Element::new(Img3Tag::TYPE, b"ibss".to_vec()),
                Img3Element::new(Img3Tag::DATA, b"payload".to_vec()),
            ],
        );

        assert_eq!(Img3::parse(&image.to_bytes()).unwrap(), image);
    }

    #[test]
    fn personalizes_with_ticket_elements() {
        let image = Img3::new(1, vec![Img3Element::new(Img3Tag::DATA, vec![1, 2, 3])]);
        let signature = [
            Img3Element::new(Img3Tag::ECID, vec![1]),
            Img3Element::new(Img3Tag::SHSH, vec![2]),
            Img3Element::new(Img3Tag::CERT, vec![3]),
        ]
        .into_iter()
        .flat_map(|element| {
            let mut bytes = Vec::new();
            element.write_to(&mut bytes);
            bytes
        })
        .collect::<Vec<_>>();

        let personalized = image.personalize(&signature).unwrap();
        let tags = personalized
            .elements()
            .iter()
            .map(Img3Element::tag)
            .collect::<Vec<_>>();
        assert_eq!(
            tags,
            vec![Img3Tag::DATA, Img3Tag::ECID, Img3Tag::SHSH, Img3Tag::CERT]
        );
        assert!(personalized.is_personalized());
    }
}
