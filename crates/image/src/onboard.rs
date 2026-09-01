use std::ops::Range;

use thiserror::Error;

const SEQUENCE: u64 = 16;
const OCTET_STRING: u64 = 4;
const IA5_STRING: u64 = 22;

/// Rewrite the first `bobi` magic of a raw onboard dump to `blli`, returning
/// the fixed dump, or `None` when the marker is absent.
///
/// Mirrors restore.sh `shsh_convert_onboard` (upstream commit 1ff4be0): raw
/// dumps dumped on powdersn0w/DRA downgraded devices carry the mangled `ibob`
/// LLB tag, which later tools reject with "unknown magic 69626f62". Upstream
/// gates the fix on pre-A7 devices; the byte-level rewrite is a no-op for
/// dumps without the marker, so it is applied unconditionally here.
pub fn rewrite_ibob_magic(dump: &[u8]) -> Option<Vec<u8>> {
    let position = dump.windows(4).position(|window| window == b"bobi")?;
    let mut fixed = dump.to_vec();
    fixed[position..position + 4].copy_from_slice(b"blli");
    Some(fixed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnboardTicket {
    im4m: Vec<u8>,
    generator: Option<String>,
}

impl OnboardTicket {
    pub fn parse(dump: &[u8]) -> Result<Self, OnboardTicketError> {
        for offset in 0..dump.len() {
            if dump[offset] != 0x30 {
                continue;
            }
            let Ok(root) = DerElement::parse(dump, offset) else {
                continue;
            };
            if root.class != 0 || root.tag != SEQUENCE {
                continue;
            }
            let Ok(magic) = root.first_child(dump) else {
                continue;
            };
            match magic.payload(dump) {
                b"IM4M" => {
                    return Ok(Self {
                        im4m: dump[root.full].to_vec(),
                        generator: None,
                    });
                }
                b"IMG4" => return Self::from_img4(dump, &root),
                _ => {}
            }
        }
        Err(OnboardTicketError::TicketNotFound)
    }

    pub fn im4m(&self) -> &[u8] {
        &self.im4m
    }

    pub fn generator(&self) -> Option<&str> {
        self.generator.as_deref()
    }

    fn from_img4(data: &[u8], root: &DerElement) -> Result<Self, OnboardTicketError> {
        let children = root.children(data)?;
        let ticket_container = children
            .iter()
            .find(|element| element.class == 2 && element.tag == 0)
            .ok_or(OnboardTicketError::TicketNotFound)?;
        let im4m = ticket_container.first_child(data)?;
        if im4m.first_child(data)?.payload(data) != b"IM4M" {
            return Err(OnboardTicketError::InvalidIm4m);
        }
        let generator = children
            .iter()
            .find(|element| element.class == 2 && element.tag == 1)
            .and_then(|container| container.first_child(data).ok())
            .and_then(|im4r| find_bncn(data, &im4r))
            .map(|nonce| {
                let mut generator = String::from("0x");
                for byte in nonce.iter().rev() {
                    use std::fmt::Write as _;
                    write!(generator, "{byte:02x}").expect("writing to String cannot fail");
                }
                generator
            });
        Ok(Self {
            im4m: data[im4m.full].to_vec(),
            generator,
        })
    }
}

fn find_bncn<'a>(data: &'a [u8], element: &DerElement) -> Option<&'a [u8]> {
    let children = element.children(data).ok()?;
    if children.len() >= 2
        && children[0].class == 0
        && children[0].tag == IA5_STRING
        && children[0].payload(data) == b"BNCN"
        && children[1].class == 0
        && children[1].tag == OCTET_STRING
    {
        return Some(children[1].payload(data));
    }
    children
        .iter()
        .find_map(|child| child.constructed.then(|| find_bncn(data, child)).flatten())
}

#[derive(Clone, Debug)]
struct DerElement {
    class: u8,
    constructed: bool,
    tag: u64,
    content: Range<usize>,
    full: Range<usize>,
}

impl DerElement {
    fn parse(data: &[u8], offset: usize) -> Result<Self, OnboardTicketError> {
        let first = *data.get(offset).ok_or(OnboardTicketError::TruncatedDer)?;
        let class = first >> 6;
        let constructed = first & 0x20 != 0;
        let mut position = offset + 1;
        let mut tag = u64::from(first & 0x1f);
        if tag == 0x1f {
            tag = 0;
            loop {
                let byte = *data.get(position).ok_or(OnboardTicketError::TruncatedDer)?;
                position += 1;
                tag = tag
                    .checked_mul(128)
                    .and_then(|tag| tag.checked_add(u64::from(byte & 0x7f)))
                    .ok_or(OnboardTicketError::InvalidDer)?;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        let first_length = *data.get(position).ok_or(OnboardTicketError::TruncatedDer)?;
        position += 1;
        let length = if first_length & 0x80 == 0 {
            usize::from(first_length)
        } else {
            let bytes = usize::from(first_length & 0x7f);
            if bytes == 0 || bytes > std::mem::size_of::<usize>() {
                return Err(OnboardTicketError::InvalidDer);
            }
            let encoded = data
                .get(position..position + bytes)
                .ok_or(OnboardTicketError::TruncatedDer)?;
            position += bytes;
            encoded
                .iter()
                .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte))
        };
        let end = position
            .checked_add(length)
            .ok_or(OnboardTicketError::InvalidDer)?;
        if end > data.len() {
            return Err(OnboardTicketError::TruncatedDer);
        }
        Ok(Self {
            class,
            constructed,
            tag,
            content: position..end,
            full: offset..end,
        })
    }

    fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.content.clone()]
    }

    fn first_child(&self, data: &[u8]) -> Result<Self, OnboardTicketError> {
        if !self.constructed || self.content.is_empty() {
            return Err(OnboardTicketError::InvalidDer);
        }
        Self::parse(data, self.content.start)
    }

    fn children(&self, data: &[u8]) -> Result<Vec<Self>, OnboardTicketError> {
        if !self.constructed {
            return Err(OnboardTicketError::InvalidDer);
        }
        let mut children = Vec::new();
        let mut position = self.content.start;
        while position < self.content.end {
            let child = Self::parse(data, position)?;
            if child.full.end > self.content.end {
                return Err(OnboardTicketError::InvalidDer);
            }
            position = child.full.end;
            children.push(child);
        }
        Ok(children)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OnboardTicketError {
    #[error("onboard dump contains no IMG4 or IM4M ticket")]
    TicketNotFound,
    #[error("onboard dump contains an invalid IM4M")]
    InvalidIm4m,
    #[error("DER data is truncated")]
    TruncatedDer,
    #[error("DER data is invalid")]
    InvalidDer,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut data = vec![tag, content.len() as u8];
        data.extend_from_slice(content);
        data
    }

    #[test]
    fn rewrites_the_first_ibob_magic() {
        let dump = b"....bobi....bobi..";
        let fixed = rewrite_ibob_magic(dump).unwrap();
        assert_eq!(fixed, b"....blli....bobi..");
        assert_eq!(rewrite_ibob_magic(b"....blli...."), None);
    }

    #[test]
    fn extracts_im4m_and_generator_from_img4() {
        let mut im4m_content = der(0x16, b"IM4M");
        im4m_content.extend_from_slice(&der(0x02, &[0]));
        let im4m = der(0x30, &im4m_content);
        let im4m_container = der(0xa0, &im4m);

        let mut bncn_content = der(0x16, b"BNCN");
        bncn_content.extend_from_slice(&der(0x04, &[0x11, 0x22]));
        let bncn = der(0x30, &bncn_content);
        let mut im4r_content = der(0x16, b"IM4R");
        im4r_content.extend_from_slice(&der(0x31, &bncn));
        let im4r = der(0x30, &im4r_content);
        let im4r_container = der(0xa1, &im4r);

        let mut img4_content = der(0x16, b"IMG4");
        img4_content.extend_from_slice(&im4m_container);
        img4_content.extend_from_slice(&im4r_container);
        let img4 = der(0x30, &img4_content);

        let ticket = OnboardTicket::parse(&img4).unwrap();
        assert_eq!(ticket.im4m(), im4m);
        assert_eq!(ticket.generator(), Some("0x2211"));
    }
}
