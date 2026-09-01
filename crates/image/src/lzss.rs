//! LZSS codec for `complzss`-wrapped kernelcache IMG3 payloads.
//!
//! Port of xpwn's `ipsw-patch/lzss.c` and `ipsw-patch/lzssfile.c`
//! (LukeZGD/powdersn0w_pub `main`, `xpwn/include/xpwn/lzss.h` /
//! `xpwn/include/xpwn/lzssfile.h`). The variant is Okumura's LZSS with
//! N = 4096, F = 18, THRESHOLD = 2; the container is a 0x180-byte
//! big-endian header (`comp` signature, `lzss` compression type, Adler-32
//! of the uncompressed data, both lengths) followed by the LZSS stream.

use thiserror::Error;

/// Ring buffer size; must be a power of two.
const N: usize = 4096;
/// Upper limit for match length.
const F: usize = 18;
/// Encode a position/length pair only when the match is longer than this.
const THRESHOLD: usize = 2;
/// Tree index for the root of the binary search trees ("not used").
const NIL: i32 = N as i32;

const COMP_SIGNATURE: u32 = 0x636F_6D70; // "comp"
const LZSS_SIGNATURE: u32 = 0x6C7A_7373; // "lzss"

/// Size of the `complzss` header: five big-endian u32 fields plus padding.
pub const COMPLZSS_HEADER_SIZE: usize = 0x180;

/// Adler-32 checksum, as xpwn's `lzadler32` (initial s1 = 1, NMAX = 5000).
pub fn adler32(data: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    const NMAX: usize = 5000;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            s1 += u32::from(byte);
            s2 += s1;
        }
        s1 %= BASE;
        s2 %= BASE;
    }
    (s2 << 16) | s1
}

/// Returns true when a decrypted payload starts with the `complzss` magic,
/// i.e. xpwn's img3 layer would route it through the LZSS codec.
pub fn is_lzss_compressed(payload: &[u8]) -> bool {
    payload.len() >= 8
        && read_be_u32(payload, 0) == COMP_SIGNATURE
        && read_be_u32(payload, 4) == LZSS_SIGNATURE
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompLzssHeader {
    checksum: u32,
    length_uncompressed: u32,
    length_compressed: u32,
}

impl CompLzssHeader {
    pub fn parse(data: &[u8]) -> Result<Self, LzssError> {
        if data.len() < COMPLZSS_HEADER_SIZE {
            return Err(LzssError::TruncatedHeader);
        }
        if read_be_u32(data, 0) != COMP_SIGNATURE {
            return Err(LzssError::InvalidSignature);
        }
        let compression = read_be_u32(data, 4);
        if compression != LZSS_SIGNATURE {
            return Err(LzssError::UnsupportedCompression(compression));
        }
        Ok(Self {
            checksum: read_be_u32(data, 8),
            length_uncompressed: read_be_u32(data, 12),
            length_compressed: read_be_u32(data, 16),
        })
    }

    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    pub const fn length_uncompressed(&self) -> u32 {
        self.length_uncompressed
    }

    pub const fn length_compressed(&self) -> u32 {
        self.length_compressed
    }

    /// Serialize the header. xpwn rewrites the padding bytes it read from the
    /// source file; new payloads always get zero padding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(COMPLZSS_HEADER_SIZE);
        output.extend_from_slice(&COMP_SIGNATURE.to_be_bytes());
        output.extend_from_slice(&LZSS_SIGNATURE.to_be_bytes());
        output.extend_from_slice(&self.checksum.to_be_bytes());
        output.extend_from_slice(&self.length_uncompressed.to_be_bytes());
        output.extend_from_slice(&self.length_compressed.to_be_bytes());
        output.resize(COMPLZSS_HEADER_SIZE, 0);
        output
    }
}

/// Decompress a full `complzss` blob (header + stream) into the raw payload.
///
/// Like xpwn's `createAbstractFileFromComp`, integrity is checked by comparing
/// the decoded length against the header — the Adler-32 checksum is written
/// on compression but never verified on decompression (an upstream quirk,
/// replicated here). Callers wanting a checksum check can compare
/// `CompLzssHeader::checksum` against [`adler32`] of the output.
pub fn decompress_lzss(payload: &[u8]) -> Result<Vec<u8>, LzssError> {
    let header = CompLzssHeader::parse(payload)?;
    let stream = &payload[COMPLZSS_HEADER_SIZE..];
    let compressed = header.length_compressed as usize;
    if stream.len() < compressed {
        return Err(LzssError::TruncatedData {
            expected: compressed,
            actual: stream.len(),
        });
    }
    let data = decompress_raw(&stream[..compressed]);
    if data.len() != header.length_uncompressed as usize {
        return Err(LzssError::SizeMismatch {
            expected: header.length_uncompressed as usize,
            actual: data.len(),
        });
    }
    Ok(data)
}

/// Compress a raw payload into a full `complzss` blob, computing the header
/// checksum and lengths the way xpwn's `closeComp` does.
pub fn compress_lzss(data: &[u8]) -> Result<Vec<u8>, LzssError> {
    let stream = compress_raw(data)?;
    let header = CompLzssHeader {
        checksum: adler32(data),
        length_uncompressed: data.len() as u32,
        length_compressed: stream.len() as u32,
    };
    let mut output = header.to_bytes();
    output.extend_from_slice(&stream);
    Ok(output)
}

/// Port of xpwn's `decompress_lzss`: decode until the source is exhausted.
/// A stream ending mid-token is silently cut short, as in C.
fn decompress_raw(src: &[u8]) -> Vec<u8> {
    // C leaves text_buf[N - F..N) uninitialized; valid streams never read
    // slots before writing them, so ' ' is a deterministic stand-in.
    let mut text_buf = [b' '; N];
    let mut output = Vec::new();
    let mut pos = 0;
    let mut r = N - F;
    let mut flags: u32 = 0;
    loop {
        flags >>= 1;
        if flags & 0x100 == 0 {
            if pos >= src.len() {
                break;
            }
            flags = u32::from(src[pos]) | 0xFF00;
            pos += 1;
        }
        if flags & 1 != 0 {
            if pos >= src.len() {
                break;
            }
            let byte = src[pos];
            pos += 1;
            output.push(byte);
            text_buf[r] = byte;
            r = (r + 1) & (N - 1);
        } else {
            if pos >= src.len() {
                break;
            }
            let mut i = usize::from(src[pos]);
            pos += 1;
            if pos >= src.len() {
                break;
            }
            let j = src[pos];
            pos += 1;
            i |= usize::from(j & 0xF0) << 4;
            let length = usize::from(j & 0x0F) + THRESHOLD;
            for k in 0..=length {
                let byte = text_buf[(i + k) & (N - 1)];
                output.push(byte);
                text_buf[r] = byte;
                r = (r + 1) & (N - 1);
            }
        }
    }
    output
}

/// Binary-search-tree encoding state of xpwn's `compress_lzss`.
struct EncodeState {
    lchild: [i32; N + 1],
    rchild: [i32; N + 257],
    parent: [i32; N + 1],
    /// Ring buffer of size N, with F - 1 extra bytes to aid comparison.
    text_buf: [u8; N + F - 1],
    match_position: i32,
    match_length: i32,
}

impl EncodeState {
    fn new() -> Self {
        let mut state = Self {
            lchild: [0; N + 1],
            rchild: [0; N + 257],
            parent: [0; N + 1],
            text_buf: [0; N + F - 1],
            match_position: 0,
            match_length: 0,
        };
        state.text_buf[..N - F].fill(b' ');
        state.rchild[N + 1..=N + 256].fill(NIL);
        state.parent[..N].fill(NIL);
        state
    }
}

/// Inserts the string of length F at `text_buf[r..r + F]` into its tree,
/// recording the longest-match position and length. Faithful port of xpwn's
/// `insert_node`, including the node replacement when the match reaches F.
fn insert_node(state: &mut EncodeState, r: i32) {
    let mut cmp: i32 = 1;
    let key = r as usize;
    let mut p = (N + 1) as i32 + i32::from(state.text_buf[key]);
    state.rchild[r as usize] = NIL;
    state.lchild[r as usize] = NIL;
    state.match_length = 0;
    loop {
        if cmp >= 0 {
            if state.rchild[p as usize] != NIL {
                p = state.rchild[p as usize];
            } else {
                state.rchild[p as usize] = r;
                state.parent[r as usize] = p;
                return;
            }
        } else if state.lchild[p as usize] != NIL {
            p = state.lchild[p as usize];
        } else {
            state.lchild[p as usize] = r;
            state.parent[r as usize] = p;
            return;
        }
        let mut i = 1;
        while i < F {
            cmp = i32::from(state.text_buf[key + i]) - i32::from(state.text_buf[p as usize + i]);
            if cmp != 0 {
                break;
            }
            i += 1;
        }
        if i as i32 > state.match_length {
            state.match_position = p;
            state.match_length = i as i32;
            if state.match_length >= F as i32 {
                break;
            }
        }
    }
    let (r, p) = (r as usize, p as usize);
    state.parent[r] = state.parent[p];
    state.lchild[r] = state.lchild[p];
    state.rchild[r] = state.rchild[p];
    state.parent[state.lchild[p] as usize] = r as i32;
    state.parent[state.rchild[p] as usize] = r as i32;
    if state.rchild[state.parent[p] as usize] == p as i32 {
        state.rchild[state.parent[p] as usize] = r as i32;
    } else {
        state.lchild[state.parent[p] as usize] = r as i32;
    }
    state.parent[p] = NIL; // remove p
}

/// Deletes node `p` from its tree; a no-op when `p` is not in a tree.
fn delete_node(state: &mut EncodeState, p: i32) {
    let p = p as usize;
    if state.parent[p] == NIL {
        return;
    }
    let q;
    if state.rchild[p] == NIL {
        q = state.lchild[p];
    } else if state.lchild[p] == NIL {
        q = state.rchild[p];
    } else {
        let mut successor = state.lchild[p];
        if state.rchild[successor as usize] != NIL {
            while state.rchild[successor as usize] != NIL {
                successor = state.rchild[successor as usize];
            }
            let s = successor as usize;
            state.rchild[state.parent[s] as usize] = state.lchild[s];
            state.parent[state.lchild[s] as usize] = state.parent[s];
            state.lchild[s] = state.lchild[p];
            state.parent[state.lchild[p] as usize] = successor;
        }
        let s = successor as usize;
        state.rchild[s] = state.rchild[p];
        state.parent[state.rchild[p] as usize] = successor;
        q = successor;
    }
    state.parent[q as usize] = state.parent[p];
    if state.rchild[state.parent[p] as usize] == p as i32 {
        state.rchild[state.parent[p] as usize] = q;
    } else {
        state.lchild[state.parent[p] as usize] = q;
    }
    state.parent[p] = NIL;
}

/// Port of xpwn's `compress_lzss`. Unlike C the output buffer grows as needed
/// (xpwn's callers always pass twice the input length, which cannot overflow);
/// zero-length input is rejected, mirroring C's NULL return.
fn compress_raw(src: &[u8]) -> Result<Vec<u8>, LzssError> {
    let mut state = EncodeState::new();
    let mut output = Vec::new();

    // code_buf[1..=16] saves eight units of code; code_buf[0] works as eight
    // flags, "1" representing that the unit is an unencoded letter.
    let mut code_buf = [0u8; 17];
    let mut code_buf_ptr = 1;
    let mut mask: u8 = 1;

    let mut s = 0usize;
    let mut r = N - F;

    // Read F bytes into the last F bytes of the buffer.
    let mut len = 0i32;
    let mut pos = 0usize;
    while len < F as i32 && pos < src.len() {
        state.text_buf[r + len as usize] = src[pos];
        pos += 1;
        len += 1;
    }
    if len == 0 {
        return Err(LzssError::EmptyInput);
    }

    // Insert the F strings, each of which begins with one or more 'space'
    // characters, then the whole string just read.
    for i in 1..=F as i32 {
        insert_node(&mut state, r as i32 - i);
    }
    insert_node(&mut state, r as i32);

    loop {
        // match_length may be spuriously long near the end of the text.
        if state.match_length > len {
            state.match_length = len;
        }
        if state.match_length <= THRESHOLD as i32 {
            // Not a long enough match; send one byte.
            state.match_length = 1;
            code_buf[0] |= mask;
            code_buf[code_buf_ptr] = state.text_buf[r];
            code_buf_ptr += 1;
        } else {
            // Send position and length pair.
            code_buf[code_buf_ptr] = state.match_position as u8;
            code_buf[code_buf_ptr + 1] = (((state.match_position >> 4) & 0xF0)
                | (state.match_length - (THRESHOLD as i32 + 1)))
                as u8;
            code_buf_ptr += 2;
        }
        mask <<= 1;
        if mask == 0 {
            // Send at most 8 units of code together.
            output.extend_from_slice(&code_buf[..code_buf_ptr]);
            code_buf[0] = 0;
            code_buf_ptr = 1;
            mask = 1;
        }
        let last_match_length = state.match_length;
        let mut i = 0i32;
        while i < last_match_length && pos < src.len() {
            delete_node(&mut state, s as i32);
            let byte = src[pos];
            pos += 1;
            state.text_buf[s] = byte;
            // If the position is near the end of the buffer, extend it to
            // make string comparison easier.
            if s < F - 1 {
                state.text_buf[s + N] = byte;
            }
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            insert_node(&mut state, r as i32);
            i += 1;
        }
        while i < last_match_length {
            delete_node(&mut state, s as i32);
            // After the end of the text, no need to read,
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            // but the buffer may not be empty.
            len -= 1;
            if len != 0 {
                insert_node(&mut state, r as i32);
            }
            i += 1;
        }
        if len <= 0 {
            break;
        }
    }

    if code_buf_ptr > 1 {
        // Send remaining code.
        output.extend_from_slice(&code_buf[..code_buf_ptr]);
    }
    Ok(output)
}

fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("four-byte field"),
    )
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LzssError {
    #[error("complzss header is truncated")]
    TruncatedHeader,
    #[error("invalid complzss signature")]
    InvalidSignature,
    #[error("unsupported complzss compression type {0:#010x}")]
    UnsupportedCompression(u32),
    #[error("complzss stream is truncated: expected {expected} compressed bytes, got {actual}")]
    TruncatedData { expected: usize, actual: usize },
    #[error("decompressed size mismatch: header says {expected}, stream produced {actual}")]
    SizeMismatch { expected: usize, actual: usize },
    #[error("cannot compress an empty payload")]
    EmptyInput,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors produced by the authoritative C implementation
    // (xpwn ipsw-patch/lzss.c from LukeZGD/powdersn0w_pub, compiled and run
    // locally): the compressed streams for `input_a`/`input_b` below, and
    // the 0x180-byte complzss header lzssfile would write for `input_a`.
    const INPUT_A_COMPRESSED: &str = "7f00010203040506eefffef9f4e0ff1e3d5c7b9affb9d8f71635547392ffb1d0ef0e2d4c6b8affa9c8e70625446382f9a1f6ff390ba0bfdefd1cff3b5a7998b7d6f514ff33527190afceed0cff2b4a6988a7c6e50407234261360f7201020f140f260ffc70033b0b203f5e7d9cbbffdaf91837567594b3ffd2f1102f4e6d8cabffcae90827466584a303c2e1700ff90b9009";
    const INPUT_B_COMPRESSED: &str = concat!(
        "ff0001020304050607ff08090a0b0c0d0e0fff1011121314151617ff18191a1b1c1d1e1fff2021222324252627ff28292a2b2c2d2e2fff3031323334353637ff38393a3b3c3d3e3f00eeff000f120f240f360f480f5a0f6c0f007e0f900fa20fb40fc60fd80fea0ffc0f000e1f201f321f441f561f681f7a1f8c1ffe9e1d07060504030201ff000f0e0d0c0b0a09ff0817161514131211ff101f1e1d1c1b1a19ff1827262524232221ff202f2e2d2c2b2a29ff2837363534333231ff303f3e3d3c3b3a390138ee1f002f122f242f362f482f5a2f006c2f7e2f902fa22fb42fc62fd82fea2f00fc2f0e3f203f323f443f563f683f7a3ffc8c3f9e3d0e0f0c0d0a0bff0809060704050203ff00011e1f1c1d1a1bff1819161714151213ff10112e2f2c2d2a2bff2829262724252223ff20213e3f3c3d3a3bff3839363734353233033031ee3f004f124f244f364f484f005a4f6c4f7e4f904fa24fb44fc64fd84f00ea4ffc4f0e5f205f325f445f565f685ff87a5f8c5f9e5d1514171611ff1013121d1c1f1e19ff181b1a0504070601ff0003020d0c0f0e09ff080b0a3534373631ff3033323d3c3f3e39ff383b3a2524272621ff2023222d2c2f2e2907282b2aee5f006f126f246f366f00486f5a6f6c6f7e6f906fa26fb46fc66f00d86fea6ffc6f0e7f207f327f447f567f00687f7a7f8c7f9e7dca11c611c211be1100ba11b611b211ae11aa11a611a2119e1100da11d611d211ce11ee7f008f128f248f00368f488f5a8f6c8f7e8f908fa28fb48f00c68fd88fea8ffc8f0e9f209f329f449f00569f689f7a9f8c9f9e9dd231ce31da3100d631a2319e",
        "31aa31a631b231ae31ba3100b631c231be31ca31c631ee9f00af12af0024af36af48af5aaf6caf7eaf90afa2af00b4afc6afd8afeaaffcaf0ebf20bf32bf0044bf56bf68bf7abf8cbf9ebdd251ce5100da51d651a2519e51aa51a651b251ae5100ba51b651c251be51ca51c651eebf00cf0012cf24cf36cf48cf5acf6ccf7ecf90cf00a2cfb4cfc6cfd8cfeacffccf0edf20df0032df44df56df68df7adf8cdf9eddd27100ce71da71d671a2719e71aa71a671b27100ae71ba71b671c271be71ca71c671eedf0000ef12ef24ef36ef48ef5aef6cef7eef0090efa2efb4efc6efd8efeaeffcef0eff0020ff32ff44ff56ff68ff7aff8cff9efd00a6159e15d615ce15c615be15b615ae1500eeff000f120f240f360f480f5a0f6c0f007e0f900fa20fb40fc60fd80fea0ffc0f000e1f201f321f441f561f681f7a1f8c1f009e1da6359e35d635ce35c635be35b63500ae35ee1f002f122f242f362f482f5a2f006c2f7e2f902fa22fb42fc62fd82fea2f00fc2f0e3f203f323f443f563f683f7a3ffc8c3f9e3d464744454243ff40414e4f4c4d4a4bff4849565754555253ff50515e5f5c5d5a5bff5859666764656263ff60616e6f6c6d6a6bff6869767774757273ff70717e7f7c7d7a7b037879ee3f004f124f244f364f484f005a4f6c4f7e4f904fa24fb44fc64fd84f00ea4ffc4f0e5f205f325f445f565f685ff87a5f8c5f9e5d4d4c4f4e49ff484b4a4544474641ff4043425d5c5f5e59ff585b5a5554575651ff5053526d6c6f6e69ff686b6a6564676661ff6063627d7c7f7e79ff787b7a757477767107707372ee5f006f126f246f366f00486f5a6f6c6f7e6f906fa26fb46fc66f00d86fea6ffc6f0e7d",
    );
    /// 0x180-byte complzss header for `input_a` as xpwn's lzssfile writes
    /// it: five big-endian fields, then zero padding.
    fn input_a_header() -> Vec<u8> {
        let mut header = hex::decode("636f6d706c7a7373989048930000012c00000092").unwrap();
        header.resize(COMPLZSS_HEADER_SIZE, 0);
        header
    }

    fn input_a() -> Vec<u8> {
        let mut data: Vec<u8> = (0..300_u32)
            .map(|i| {
                if i % 64 < 32 {
                    (i % 7) as u8
                } else {
                    (i * 31) as u8
                }
            })
            .collect();
        let repeats = data[20..80].to_vec();
        data[150..210].copy_from_slice(&repeats);
        data
    }

    fn input_b() -> Vec<u8> {
        (0..6000_u32)
            .map(|i| ((i % 64) ^ ((i / 512) * 7)) as u8)
            .collect()
    }

    #[test]
    fn adler32_matches_reference() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398); // zlib's example value
        assert_eq!(adler32(&input_a()), 0x9890_4893);
        assert_eq!(adler32(&input_b()), 0x93CB_BCF6);
    }

    #[test]
    fn compress_matches_c_reference() {
        assert_eq!(
            hex::encode(compress_raw(&input_a()).unwrap()),
            INPUT_A_COMPRESSED
        );
        assert_eq!(
            hex::encode(compress_raw(&input_b()).unwrap()),
            INPUT_B_COMPRESSED
        );
    }

    #[test]
    fn decompress_matches_c_reference() {
        assert_eq!(
            decompress_raw(&hex::decode(INPUT_A_COMPRESSED).unwrap()),
            input_a()
        );
        // Crosses the 4096-byte ring boundary during both encode and decode.
        assert_eq!(
            decompress_raw(&hex::decode(INPUT_B_COMPRESSED).unwrap()),
            input_b()
        );
    }

    #[test]
    fn round_trip_is_byte_identical() {
        // Incompressible xorshift noise, a single repeated byte, sizes around
        // F, and a payload wrapping the ring buffer multiple times.
        let mut noise = Vec::with_capacity(10_000);
        let mut state = 0x1234_5678_u32;
        for _ in 0..10_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise.push(state as u8);
        }
        let inputs: Vec<Vec<u8>> = vec![
            vec![1],
            vec![0; 17],
            b"exactly eighteen!!".to_vec(),
            vec![0x41; 100_000],
            noise,
            input_a(),
            input_b(),
        ];
        for input in inputs {
            let blob = compress_lzss(&input).unwrap();
            assert!(is_lzss_compressed(&blob));
            assert_eq!(decompress_lzss(&blob).unwrap(), input);
        }
    }

    #[test]
    fn compress_writes_consistent_header() {
        let input = input_a();
        let blob = compress_lzss(&input).unwrap();
        let header = CompLzssHeader::parse(&blob).unwrap();
        assert_eq!(header.checksum(), adler32(&input));
        assert_eq!(header.length_uncompressed(), input.len() as u32);
        assert_eq!(
            header.length_compressed() as usize,
            blob.len() - COMPLZSS_HEADER_SIZE
        );
    }

    #[test]
    fn parses_c_reference_header() {
        let header = CompLzssHeader::parse(&input_a_header()).unwrap();
        assert_eq!(header.checksum(), 0x9890_4893);
        assert_eq!(header.length_uncompressed(), 300);
        assert_eq!(header.length_compressed(), 146);
    }

    #[test]
    fn decompresses_c_reference_blob() {
        let mut blob = input_a_header();
        blob.extend_from_slice(&hex::decode(INPUT_A_COMPRESSED).unwrap());
        assert!(is_lzss_compressed(&blob));
        assert_eq!(decompress_lzss(&blob).unwrap(), input_a());
    }

    #[test]
    fn rejects_malformed_headers() {
        assert!(matches!(
            CompLzssHeader::parse(&[0; 100]),
            Err(LzssError::TruncatedHeader)
        ));
        let mut header = CompLzssHeader::parse(&input_a_header()).unwrap().to_bytes();
        header[3] = b'q'; // "comq"
        assert!(matches!(
            CompLzssHeader::parse(&header),
            Err(LzssError::InvalidSignature)
        ));
        let mut header = CompLzssHeader::parse(&input_a_header()).unwrap().to_bytes();
        header[7] = b't'; // "lzst"
        assert!(matches!(
            CompLzssHeader::parse(&header),
            Err(LzssError::UnsupportedCompression(0x6C7A_7374))
        ));
    }

    #[test]
    fn rejects_truncated_stream() {
        let mut blob = input_a_header();
        blob.extend_from_slice(&hex::decode(INPUT_A_COMPRESSED).unwrap()[..100]);
        assert!(matches!(
            decompress_lzss(&blob),
            Err(LzssError::TruncatedData {
                expected: 146,
                actual: 100
            })
        ));

        // Truncate the stream *and* the header length: the decoder then runs
        // out of input mid-stream and produces too few bytes.
        let compressed = hex::decode(INPUT_A_COMPRESSED).unwrap();
        let mut header = input_a_header();
        header[16..20].copy_from_slice(&136_u32.to_be_bytes());
        let mut blob = header;
        blob.extend_from_slice(&compressed[..136]);
        assert!(matches!(
            decompress_lzss(&blob),
            Err(LzssError::SizeMismatch {
                expected: 300,
                actual: _
            })
        ));
    }

    #[test]
    fn rejects_empty_compress() {
        assert!(matches!(compress_lzss(b""), Err(LzssError::EmptyInput)));
    }

    #[test]
    fn detects_lzss_payloads() {
        let blob = compress_lzss(&input_a()).unwrap();
        assert!(is_lzss_compressed(&blob));
        assert!(!is_lzss_compressed(b"complzs"));
        assert!(!is_lzss_compressed(b"not a kernelcache payload at all"));
        assert!(!is_lzss_compressed(b""));
    }
}
