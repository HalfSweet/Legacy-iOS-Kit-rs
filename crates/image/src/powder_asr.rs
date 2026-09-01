//! powdersn0w ASR patcher, a Rust port of xpwn's `asr/asr.c` (`patchASR`)
//! from LukeZGD/powdersn0w_pub.
//!
//! The stock `asr` binary refuses images whose signature verification fails;
//! the patch branches `image_failed_signature` to `image_passed_signature`
//! and then recomputes the SHA-1 code-directory slots so the modified pages
//! pass the binary's own code signature.
//!
//! Unlike the C original, which reads and writes past buffer ends on
//! malformed input, every access here is bounds-checked.

use sha1::{Digest, Sha1};
use thiserror::Error;
use tracing::{debug, info};

use crate::patchfinder as pf;

const MH_MAGIC: u32 = 0xFEED_FACE;
const LC_SEGMENT: u32 = 0x1;

/// SHA-1 code-directory slot size; the C code hardcodes SHA_DIGEST_LENGTH.
const SLOT_SIZE: usize = 20;

#[derive(Debug, Error)]
pub enum PowderAsrError {
    #[error("not a 32-bit Mach-O (bad magic)")]
    NotMachO,
    #[error("malformed Mach-O load commands")]
    BadLoadCommands,
    #[error("cannot locate {0}")]
    AnchorNotFound(&'static str),
    #[error("image_passed_signature and image_failed_signature coincide")]
    IdenticalAnchors,
    #[error("signature branch target is out of Thumb-2 B.W range")]
    BranchOutOfRange,
    #[error("code-directory page size shift {0} is too large")]
    PageSizeTooLarge(u8),
    #[error("image is too small for the required access")]
    OutOfBounds,
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PowderAsrError> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("length")))
        .ok_or(PowderAsrError::OutOfBounds)
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32, PowderAsrError> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_be_bytes(b.try_into().expect("length")))
        .ok_or(PowderAsrError::OutOfBounds)
}

/// __TEXT segment vmaddr from the Mach-O load commands (0 when absent, as in
/// the C original, where it only feeds logging and the anchor sanity checks).
fn text_base(binary: &[u8]) -> Result<u32, PowderAsrError> {
    let ncmds = read_u32(binary, 16)?;
    let mut offset = 28usize; // sizeof(struct mach_header)
    let mut text_vmaddr = 0;
    for _ in 0..ncmds {
        let cmd = read_u32(binary, offset)?;
        let cmdsize = read_u32(binary, offset + 4)? as usize;
        if cmdsize < 8 {
            return Err(PowderAsrError::BadLoadCommands);
        }
        if cmd == LC_SEGMENT {
            let segname = binary
                .get(offset + 8..offset + 8 + 6)
                .ok_or(PowderAsrError::OutOfBounds)?;
            if segname == b"__TEXT" {
                text_vmaddr = read_u32(binary, offset + 24)?;
            }
        }
        offset = offset
            .checked_add(cmdsize)
            .ok_or(PowderAsrError::OutOfBounds)?;
    }
    Ok(text_vmaddr)
}

/// Apply the powdersn0w ASR patch, returning the patched binary.
pub fn patch_asr(binary: &[u8]) -> Result<Vec<u8>, PowderAsrError> {
    if binary.len() < 4 || read_u32(binary, 0)? != MH_MAGIC {
        return Err(PowderAsrError::NotMachO);
    }
    let mut buf = binary.to_vec();

    let text_base = text_base(&buf)?;
    debug!(text_base = format_args!("{text_base:08x}"), "patching asr");

    let passed = pf::find_image_passed_signature(&buf)
        .ok_or(PowderAsrError::AnchorNotFound("image_passed_signature"))?;
    let failed = pf::find_image_failed_signature(&buf)
        .ok_or(PowderAsrError::AnchorNotFound("image_failed_signature"))?;
    // Upstream sanity check on the device-view addresses; file offsets differ
    // by the same base on both sides, so the comparison carries over.
    if text_base.wrapping_add(passed as u32) == text_base.wrapping_add(failed as u32) {
        return Err(PowderAsrError::IdenticalAnchors);
    }

    let branch = pf::make_b_w(failed, passed).ok_or(PowderAsrError::BranchOutOfRange)?;
    debug!(
        failed = format_args!("{failed:08x}"),
        passed = format_args!("{passed:08x}"),
        "signature bypass"
    );
    buf.get_mut(failed..failed + 4)
        .ok_or(PowderAsrError::OutOfBounds)?
        .copy_from_slice(&branch.to_le_bytes());

    // Recompute the SHA-1 code-directory slots covering the patched pages.
    let csdir =
        pf::find_csdir_magic(&buf).ok_or(PowderAsrError::AnchorNotFound("code directory magic"))?;
    let hash_offset = read_u32_be(&buf, csdir + 16)? as usize;
    let code_limit = read_u32_be(&buf, csdir + 32)? as usize;
    let page_shift = *buf.get(csdir + 39).ok_or(PowderAsrError::OutOfBounds)?;
    if page_shift > 16 {
        return Err(PowderAsrError::PageSizeTooLarge(page_shift));
    }
    let page_size = 1usize << page_shift;
    if code_limit > buf.len() {
        return Err(PowderAsrError::OutOfBounds);
    }
    debug!(
        csdir = format_args!("{csdir:08x}"),
        code_limit, page_size, "code directory"
    );

    let mut slot_start = csdir
        .checked_add(hash_offset)
        .ok_or(PowderAsrError::OutOfBounds)?;
    let mut page = 0;
    while page < code_limit {
        let end = (page + page_size).min(code_limit);
        let digest = Sha1::digest(&buf[page..end]);
        let slot = buf
            .get_mut(slot_start..slot_start + SLOT_SIZE)
            .ok_or(PowderAsrError::OutOfBounds)?;
        if slot != digest.as_slice() {
            slot.copy_from_slice(&digest);
        }
        slot_start += SLOT_SIZE;
        page += page_size;
    }

    info!("asr patched");
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn w32_be(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn movw(rd: u8, imm16: u16) -> u32 {
        let imm4 = u32::from(imm16 >> 12);
        let i = u32::from((imm16 >> 11) & 1);
        let imm3 = u32::from((imm16 >> 8) & 7);
        let imm8 = u32::from(imm16 & 0xFF);
        (0xF240 | imm4 | (i << 10)) | (((imm3 << 12) | (u32::from(rd) << 8) | imm8) << 16)
    }

    fn movt(rd: u8, imm16: u16) -> u32 {
        movw(rd, imm16) - 0xF240 + 0xF2C0
    }

    /// Synthetic asr: Mach-O header + __TEXT segment command, movw/movt
    /// references to both signature strings, and a one-slot code directory.
    fn asr_fixture() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        w32(&mut buf, 0, MH_MAGIC);
        w32(&mut buf, 16, 1); // ncmds
        w32(&mut buf, 28, LC_SEGMENT);
        w32(&mut buf, 32, 56); // cmdsize
        buf[36..42].copy_from_slice(b"__TEXT");
        w32(&mut buf, 28 + 24, 0x1000); // vmaddr

        // image_passed_signature: movw/movt r3 referencing the string at 0x100.
        w32(&mut buf, 0x60, movw(3, 0x100));
        w32(&mut buf, 0x64, movt(3, 0));
        // image_failed_signature: same for the string at 0x140.
        w32(&mut buf, 0x80, movw(3, 0x140));
        w32(&mut buf, 0x84, movt(3, 0));

        buf[0x100..0x100 + 35].copy_from_slice(b"Image passed signature verification");
        buf[0x140..0x140 + 35].copy_from_slice(b"Image failed signature verification");

        // Code directory at 0x200 (magic searched as raw bytes, upstream's
        // "buggy" finder).
        buf[0x200..0x204].copy_from_slice(&[0xfa, 0xde, 0x0c, 0x02]);
        w32_be(&mut buf, 0x204, 0x54); // length (unused)
        w32_be(&mut buf, 0x210, 0x40); // hashOffset -> slots at 0x240
        w32_be(&mut buf, 0x21C, 1); // nCodeSlots (unused)
        w32_be(&mut buf, 0x220, 0x180); // codeLimit: one partial page
        buf[0x224] = 20; // hashSize
        buf[0x225] = 1; // hashType: SHA-1
        buf[0x227] = 12; // pageSize shift: 0x1000
        for b in &mut buf[0x240..0x240 + SLOT_SIZE] {
            *b = 0xAA; // stale slot
        }
        buf
    }

    #[test]
    fn branches_failed_to_passed_and_fixes_code_directory() {
        let buf = asr_fixture();
        let patched = patch_asr(&buf).unwrap();

        let branch = pf::make_b_w(0x80, 0x60).unwrap();
        assert_eq!(&patched[0x80..0x84], &branch.to_le_bytes());

        let expected = Sha1::digest(&patched[..0x180]);
        assert_eq!(&patched[0x240..0x240 + SLOT_SIZE], expected.as_slice());
        // Only the branch site and the slot changed.
        assert_eq!(&patched[0x84..0x200], &buf[0x84..0x200]);
    }

    #[test]
    fn rejects_non_macho() {
        let mut buf = asr_fixture();
        buf[0] = 0;
        assert!(matches!(patch_asr(&buf), Err(PowderAsrError::NotMachO)));
    }

    #[test]
    fn missing_anchor_is_an_error() {
        let mut buf = vec![0u8; 0x100];
        w32(&mut buf, 0, MH_MAGIC);
        assert!(matches!(
            patch_asr(&buf),
            Err(PowderAsrError::AnchorNotFound("image_passed_signature"))
        ));
    }
}
