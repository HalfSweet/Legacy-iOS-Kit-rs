//! `restored_external` FaceID patcher for iPhone X downgrades, a Rust port of
//! mineek's ipx_restored_patcher (gist 16c2607c928477dcd273e680e40a1c90,
//! `main.c` @13ab7a9). Legacy iOS Kit's `ipsw_prepare_ipx` runs it on the
//! `usr/local/bin/restored_external` extracted from the restore ramdisk
//! before re-signing and repacking (iOS 14.3-15.x targets).
//!
//! # Integration contract
//!
//! The input is the raw `restored_external` Mach-O. The patcher assumes the
//! binary is linked at base 0 so that vaddrs equal file offsets (upstream
//! never parses the Mach-O; it scans the whole file). The output has the same
//! length as the input.
//!
//! The patch point is the return-value override in
//! `decompressReferenceFrames`: the algorithm finds the "refFrame" string,
//! an instruction referencing it (`xref64`, from patchfinder64), the RET
//! ending the containing function, and the `mov xN, xM` (ORR alias, top byte
//! 0xAA) producing the return value, which is overwritten with `mov x0, #0`.
//!
//! Upstream's `main` ignores the `-1` returns from each lookup step and
//! writes the unpatched buffer; here every step's failure is an explicit
//! error. All reads are bounds-checked (upstream scans past the buffer tail
//! on malformed input; that is not ported).

use thiserror::Error;
use tracing::{debug, info};

use crate::patchfinder::find_bytes;

const RET: u32 = 0xD65F_03C0;

#[derive(Debug, Error)]
pub enum IpxRestoredError {
    #[error("cannot locate the refFrame string")]
    StringNotFound,
    #[error("cannot locate an xref to the refFrame string")]
    XrefNotFound,
    #[error("cannot locate the RET after the refFrame xref")]
    RetNotFound,
    #[error("cannot locate the return-value MOV before the RET")]
    MovNotFound,
}

type Result<T> = std::result::Result<T, IpxRestoredError>;

fn r32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("length")))
}

/// patchfinder64's `xref64`: walk the whole file in 4-byte steps, tracking a
/// value per register through ADRP/ADD/LDR (unsigned immediate)/ADR/LDR
/// (literal), and return the offset of the first instruction whose computed
/// register value equals `what`. ADRP itself never counts as a match, and
/// ADD with shift > 1 / LDR with imm 0 are skipped without a match check, as
/// upstream.
fn xref64(buf: &[u8], what: u64) -> Option<usize> {
    let mut value = [0u64; 32];
    let end = buf.len() & !3;
    let mut i = 0;
    while i < end {
        let op = r32(buf, i)?;
        let reg = (op & 0x1f) as usize;
        if op & 0x9f00_0000 == 0x9000_0000 {
            // ADRP: value[reg] = page(pc) + imm << 12.
            let adr = ((op & 0x6000_0000) >> 18) | ((op & 0x00ff_ffe0) << 8);
            value[reg] = ((i64::from(adr as i32)) << 1).wrapping_add((i & !0xfff) as i64) as u64;
            i += 4;
            continue;
        } else if op & 0xff00_0000 == 0x9100_0000 {
            // ADD (immediate).
            let rn = ((op >> 5) & 0x1f) as usize;
            let shift = (op >> 22) & 3;
            let mut imm = u64::from((op >> 10) & 0xfff);
            if shift == 1 {
                imm <<= 12;
            } else if shift > 1 {
                i += 4;
                continue;
            }
            value[reg] = value[rn].wrapping_add(imm);
        } else if op & 0xf9c0_0000 == 0xf940_0000 {
            // LDR (unsigned immediate): the address, not the loaded value.
            let rn = ((op >> 5) & 0x1f) as usize;
            let imm = u64::from((op >> 10) & 0xfff) << 3;
            if imm == 0 {
                i += 4;
                continue;
            }
            value[reg] = value[rn].wrapping_add(imm);
        } else if op & 0x9f00_0000 == 0x1000_0000 {
            // ADR: value[reg] = pc + imm.
            let adr = ((op & 0x6000_0000) >> 18) | ((op & 0x00ff_ffe0) << 8);
            value[reg] = ((i64::from(adr as i32)) >> 11).wrapping_add(i as i64) as u64;
        } else if op & 0xff00_0000 == 0x5800_0000 {
            // LDR (literal): the literal's address, zero-extended as
            // upstream (the sign bit is not honored).
            let adr = u64::from((op & 0x00ff_ffe0) >> 3);
            value[reg] = adr.wrapping_add(i as u64);
        }
        if value[reg] == what {
            return Some(i);
        }
        i += 4;
    }
    None
}

/// `find_next_insn`: the first word in `from..from + count` (word indices,
/// bounded by the buffer) matching `value & mask`.
fn find_next_insn(buf: &[u8], from: usize, count: usize, value: u32, mask: u32) -> Option<usize> {
    let words = buf.len() / 4;
    for k in 0..count {
        let index = from.checked_add(k)?;
        if index >= words {
            return None;
        }
        if r32(buf, 4 * index)? & mask == value & mask {
            return Some(index);
        }
    }
    None
}

/// `find_prev_insn`: `from`, `from - 1`, ..., `from - (count - 1)`, bounded
/// below by word 0.
fn find_prev_insn(buf: &[u8], from: usize, count: usize, value: u32, mask: u32) -> Option<usize> {
    for k in 0..count {
        let index = from.checked_sub(k)?;
        if r32(buf, 4 * index)? & mask == value & mask {
            return Some(index);
        }
    }
    None
}

/// Apply the iPhone X restored_external FaceID patch, returning the patched
/// binary. See the module docs for the integration contract.
pub fn patch_restored_external(restored_external: &[u8]) -> Result<Vec<u8>> {
    let mut buf = restored_external.to_vec();

    let string = find_bytes(&buf, b"refFrame").ok_or(IpxRestoredError::StringNotFound)?;
    let xref = xref64(&buf, string as u64).ok_or(IpxRestoredError::XrefNotFound)?;
    debug!(xref = format_args!("{xref:#x}"), "refFrame xref");

    let ret = find_next_insn(&buf, xref / 4, 0x300, RET, 0xffff_ffff)
        .ok_or(IpxRestoredError::RetNotFound)?;
    let mov = find_prev_insn(&buf, ret, 0x100, 0xaa00_0000, 0xff00_0000)
        .ok_or(IpxRestoredError::MovNotFound)?;

    buf[4 * mov..4 * mov + 4].copy_from_slice(&0xD280_0000u32.to_le_bytes()); // mov x0, #0
    info!(
        offset = format_args!("{:#x}", 4 * mov),
        "patched decompressReferenceFrames"
    );
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: usize = 0x2000;
    /// "refFrame" string offset.
    const STR: usize = 0x800;
    /// adrp x8, ... at XREF - 4, add x8, x8, #lo at XREF.
    const XREF: usize = 0x100;
    const NOP: u32 = 0xd503_201f;

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn r32at(buf: &[u8], offset: usize) -> u32 {
        r32(buf, offset).unwrap()
    }

    /// nop-filled buffer with the refFrame string and an adrp/add xref to it.
    fn restored() -> Vec<u8> {
        let mut buf = vec![0u8; LEN];
        for i in 0..LEN / 4 {
            w32(&mut buf, 4 * i, NOP);
        }
        buf[STR..STR + 8].copy_from_slice(b"refFrame");
        // adrp x8, page(STR); add x8, x8, #(STR & 0xfff). STR is below the
        // xref's page, so the adrp immediate is negative.
        let imm = ((STR & !0xfff) as i64 - ((XREF - 4) & !0xfff) as i64) >> 12;
        let imm = imm as u64;
        let adrp = 0x9000_0008 | (((imm >> 2) & 0x7ffff) << 5) as u32 | (((imm & 3) << 29) as u32);
        w32(&mut buf, XREF - 4, adrp);
        w32(
            &mut buf,
            XREF,
            0x9100_0008 | (((STR & 0xfff) as u32) << 10) | (8 << 5),
        );
        buf
    }

    #[test]
    fn patches_return_value() {
        let mut buf = restored();
        w32(&mut buf, 0x1f0, 0xaa01_03e0); // mov x0, x1
        w32(&mut buf, 0x200, RET);

        let out = patch_restored_external(&buf).unwrap();
        assert_eq!(out.len(), LEN);
        assert_eq!(r32at(&out, 0x1f0), 0xd280_0000); // mov x0, #0
        assert_eq!(r32at(&out, 0x200), RET);
        assert_eq!(&out[STR..STR + 8], b"refFrame");
    }

    #[test]
    fn xref_follows_adrp_add() {
        // The xref is the ADD (ADRP alone never matches).
        assert_eq!(xref64(&restored(), STR as u64), Some(XREF));
    }

    #[test]
    fn rejects_missing_string() {
        let buf = vec![0u8; LEN];
        let err = patch_restored_external(&buf).unwrap_err();
        assert!(matches!(err, IpxRestoredError::StringNotFound));
    }

    #[test]
    fn rejects_missing_xref() {
        let mut buf = vec![0u8; LEN];
        for i in 0..LEN / 4 {
            w32(&mut buf, 4 * i, NOP);
        }
        buf[STR..STR + 8].copy_from_slice(b"refFrame");
        let err = patch_restored_external(&buf).unwrap_err();
        assert!(matches!(err, IpxRestoredError::XrefNotFound));
    }

    #[test]
    fn rejects_missing_ret() {
        let buf = restored();
        let err = patch_restored_external(&buf).unwrap_err();
        assert!(matches!(err, IpxRestoredError::RetNotFound));
    }

    #[test]
    fn rejects_missing_mov() {
        let mut buf = restored();
        w32(&mut buf, 0x200, RET);
        let err = patch_restored_external(&buf).unwrap_err();
        assert!(matches!(err, IpxRestoredError::MovNotFound));
    }
}
