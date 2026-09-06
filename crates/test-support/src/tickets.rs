//! Synthetic, unsigned DER tickets for parser and protocol tests. These are
//! deliberately not device tickets and must fail cryptographic verification.

pub fn scab(ecid: u64, nonce: Option<&[u8]>, ramdisk_digest: Option<&[u8]>) -> Vec<u8> {
    let mut claims = der(&[0x81], &ecid.to_le_bytes());
    if let Some(nonce) = nonce {
        claims.extend(der(&[0x92], nonce));
    }
    if let Some(digest) = ramdisk_digest {
        claims.extend(der(&[0x9a], digest));
    }
    let mut body = der(&[2], &[0]);
    body.extend(der(&[0x31], &claims));
    body.extend(der(&[4], &[]));
    body.extend(der(&[0x30], &[]));
    der(&[0x30], &body)
}

pub fn im4m(ecid: u64, nonce: &[u8], digests: &[(&str, &[u8])]) -> Vec<u8> {
    let mut props = property("ECID", &integer(ecid));
    props.extend(property("BNCH", &der(&[4], nonce)));
    props.extend(property("BORD", &integer(0)));
    props.extend(property("CHIP", &integer(0)));
    props.extend(property("SDOM", &integer(1)));
    let mut body = property("MANP", &der(&[0x31], &props));
    for (name, digest) in digests {
        body.extend(property(
            name,
            &der(&[0x31], &property("DGST", &der(&[4], digest))),
        ));
    }
    let body = der(&[0x31], &property("MANB", &der(&[0x31], &body)));
    let mut ticket = der(&[0x16], b"IM4M");
    ticket.extend(integer(0));
    ticket.extend(body);
    ticket.extend(der(&[4], &[]));
    ticket.extend(der(&[0x30], &[]));
    der(&[0x30], &ticket)
}

fn integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    let mut body = Vec::new();
    if bytes[start] & 128 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&bytes[start..]);
    der(&[2], &body)
}

fn property(name: &str, value: &[u8]) -> Vec<u8> {
    let mut number = u32::from_be_bytes(name.as_bytes().try_into().unwrap());
    let mut tag = vec![(number & 127) as u8];
    number >>= 7;
    while number != 0 {
        tag.push(((number & 127) | 128) as u8);
        number >>= 7;
    }
    tag.reverse();
    tag.insert(0, 0xff);
    let mut sequence = der(&[0x16], name.as_bytes());
    sequence.extend(value);
    der(&tag, &der(&[0x30], &sequence))
}

fn der(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap();
        out.push(128 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend(body);
    out
}
