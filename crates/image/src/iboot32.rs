//! 32-bit iBoot patcher, a Rust port of iH8sn0w's iBoot32Patcher (GPL-3.0).
//!
//! Operates on decrypted, headerless iBoot/IBSS/IBEC binaries. All addressing
//! is done in file offsets; `base_address` converts to the device's view.

use thiserror::Error;
use tracing::debug;

const RESET_VECTOR: u32 = 0xea00_000e;
const VERS_OFFSET: usize = 0x286;
const KERNELCACHE_PREP_STRING: &[u8] = b"__PAGEZERO";
const RECOVERY_CONSOLE_STRING: &[u8] = b"Entering recovery mode, starting command prompt";
const DEBUG_ENABLED_DTRE_VAR: &[u8] = b"debug-enabled";
const DEFAULT_BOOT_ARGS: &[u8] = b"rd=md0 nand-enable-reformat=1 -progress";
const RELIANCE_CERT_STRING: &[u8] = b"Reliance on this certificate";

/// BL verify_shsh → MOVS R0, #0; STR R0, [R3] (stored big-endian pair).
const RSA_PATCH: [u8; 4] = [0x00, 0x20, 0x18, 0x60];
/// BL get_dtre_value → MOVS R0, #1; MOVS R0, #1.
const DEBUG_PATCH: [u8; 4] = [0x20, 0x01, 0x20, 0x01];

/// iBoot version number → iOS version mapping used by the RSA finder.
const OS_INTERVALS: &[(u32, u32, u32)] = &[
    (320, 590, 2),
    (594, 817, 3),
    (889, 1072, 4),
    (1218, 1220, 5),
    (1537, 1537, 6),
    (1940, 1940, 7),
    (2261, 2261, 8),
    (2817, 2817, 9),
    (3393, 3393, 10),
];

pub struct IBoot32<'a> {
    buf: &'a mut [u8],
    version: u32,
    base_address: u32,
}

impl<'a> IBoot32<'a> {
    pub fn new(buf: &'a mut [u8]) -> Result<Self, IbootPatchError> {
        if buf.len() < 4 || &buf[..4] == b"Img3" {
            return Err(IbootPatchError::Img3Container);
        }
        if buf.len() < 4 || u32::from_le_bytes(buf[..4].try_into().expect("length")) != RESET_VECTOR
        {
            return Err(IbootPatchError::NotIBoot32);
        }
        let base_address = read_u32(buf, 0x20)? & !0xf_ffff;
        let version = parse_vers(buf)?;
        Ok(Self {
            buf,
            version,
            base_address,
        })
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub fn has_kernel_load(&self) -> bool {
        find_bytes(self.buf, KERNELCACHE_PREP_STRING).is_some()
    }

    pub fn has_recovery_console(&self) -> bool {
        find_bytes(self.buf, RECOVERY_CONSOLE_STRING).is_some()
    }

    /// BL verify_shsh → `MOVS R0, #0; STR R0, [R3]`.
    pub fn patch_rsa_check(&mut self) -> Result<(), IbootPatchError> {
        let os_version = self.os_version();
        let anchor = if (5..=7).contains(&os_version) {
            // Multi-character constant 'RT' as emitted by the compiler.
            find_next_movw(self.buf, 0, self.buf.len(), 0x5254)
        } else {
            // Literal pool constant for the 'CERT' image tag (0x43455254).
            self.find_next_ldr(0x4345_5254)
        }
        .ok_or(IbootPatchError::VerifyShshAnchorNotFound)?;
        let top = search_up_u16(self.buf, anchor, 0x500, 0xb5f0, 0xffff)
            .ok_or(IbootPatchError::VerifyShshTopNotFound)?
            + 1; // Thumb bit
        let call =
            find_next_bl_to(self.buf, top as u32).ok_or(IbootPatchError::VerifyShshCallNotFound)?;
        debug!(offset = call, "patching BL verify_shsh");
        self.buf[call..call + 4].copy_from_slice(&RSA_PATCH);
        Ok(())
    }

    /// BL get_value_for_dtre_var("debug-enabled") → `MOVS R0, #1; MOVS R0, #1`.
    pub fn patch_debug_enabled(&mut self) -> Result<(), IbootPatchError> {
        let call = self
            .find_dtre_get_value_bl(DEBUG_ENABLED_DTRE_VAR)
            .ok_or(IbootPatchError::DtreBlNotFound)?;
        debug!(offset = call, "patching debug-enabled check");
        self.buf[call..call + 4].copy_from_slice(&DEBUG_PATCH);
        Ok(())
    }

    pub fn patch_boot_args(&mut self, boot_args: &str) -> Result<(), IbootPatchError> {
        let mut args_string =
            find_bytes(self.buf, DEFAULT_BOOT_ARGS).ok_or(IbootPatchError::BootArgsNotFound)?;
        let xref = self
            .iboot_memmem(args_string)
            .ok_or(IbootPatchError::BootArgsXrefNotFound)?;

        if boot_args.len() > DEFAULT_BOOT_ARGS.len() {
            let relocated = find_bytes(self.buf, RELIANCE_CERT_STRING)
                .ok_or(IbootPatchError::RelianceCertNotFound)?;
            let target = (relocated as u32).wrapping_add(self.base_address);
            write_u32(self.buf, xref, target)?;
            args_string = relocated;
        }
        let end = args_string + boot_args.len();
        if end >= self.buf.len() {
            return Err(IbootPatchError::BootArgsNotFound);
        }
        self.buf[args_string..end].copy_from_slice(boot_args.as_bytes());
        self.buf[end] = 0;

        let ldr = ldr_to(self.buf, xref)
            .or_else(|| self.find_next_ldr((args_string as u32).wrapping_add(self.base_address)))
            .ok_or(IbootPatchError::BootArgsLdrNotFound)?;
        let ldr_rd = (read_u16(self.buf, ldr)? >> 8) as u8 & 0x7;

        let cmp =
            find_next_cmp(self.buf, ldr, 0x100, 0).ok_or(IbootPatchError::BootArgsCmpNotFound)?;
        let mut it = cmp;
        loop {
            let value = read_u16(self.buf, it)?;
            if value == 0xbf08 || value == 0xbf18 {
                break;
            }
            it += 1;
        }
        let mov = it + 2;
        let mov_insn = read_u16(self.buf, mov)?;
        let (mov_rd, mov_rs) = ((mov_insn & 0x7) as u8, ((mov_insn >> 3) & 0x7) as u8);
        let null_str_reg = if ldr_rd == mov_rs { mov_rd } else { mov_rs };

        let null_ldr = find_last_ldr_rd(self.buf, cmp + 0x20, 0x200, null_str_reg)
            .ok_or(IbootPatchError::BootArgsNullLdrNotFound)?;
        let diff = xref - null_ldr;
        let imm8 = (diff / 4) as u8;
        self.buf[null_ldr] = imm8;
        Ok(())
    }

    /// Point a recovery console command handler at a different address.
    pub fn patch_cmd_handler(
        &mut self,
        command: &str,
        pointer: u32,
    ) -> Result<(), IbootPatchError> {
        let mut needle = Vec::with_capacity(command.len() + 2);
        needle.push(0);
        needle.extend_from_slice(command.as_bytes());
        needle.push(0);
        let string = find_bytes(self.buf, &needle).ok_or(IbootPatchError::CommandNotFound)? + 1;
        let reference = self
            .iboot_memmem(string)
            .ok_or(IbootPatchError::CommandTableNotFound)?;
        write_u32(self.buf, reference + 4, pointer)?;
        Ok(())
    }

    fn os_version(&self) -> u32 {
        OS_INTERVALS
            .iter()
            .find(|(low, high, _)| (low..=high).contains(&&self.version))
            .map(|(_, _, os)| *os)
            .unwrap_or(0)
    }

    /// Search for the 4-byte little-endian device-address reference to the
    /// given file offset.
    fn iboot_memmem(&self, offset: usize) -> Option<usize> {
        let address = (offset as u32)
            .wrapping_add(self.base_address)
            .to_le_bytes();
        find_bytes(self.buf, &address)
    }

    /// find_next_LDR_insn_with_value: locate the literal pool entry holding
    /// `value` and resolve it back to the LDR instruction.
    fn find_next_ldr(&self, value: u32) -> Option<usize> {
        let xref = find_bytes(self.buf, &value.to_le_bytes())?;
        ldr_to(self.buf, xref)
    }

    fn find_dtre_get_value_bl(&self, variable: &[u8]) -> Option<usize> {
        let string = find_bytes(self.buf, variable)?;
        let xref = self.iboot_memmem(string)?;
        let ldr = ldr_to(self.buf, xref)?;
        let first = bl_search_down(self.buf, ldr, 0x100)?;
        bl_search_down(self.buf, first + 1, 0x100)
    }
}

/// Apply the iBoot32Patcher default patch set: boot-args (optional),
/// debug-enabled, command handler (optional), and the RSA check.
pub fn patch_iboot32(
    image: &[u8],
    boot_args: Option<&str>,
    command_handler: Option<(&str, u32)>,
) -> Result<Vec<u8>, IbootPatchError> {
    let mut buf = image.to_vec();
    let mut iboot = IBoot32::new(&mut buf)?;
    if iboot.has_kernel_load() {
        if let Some(args) = boot_args {
            iboot.patch_boot_args(args)?;
        }
        iboot.patch_debug_enabled()?;
    }
    if iboot.has_recovery_console()
        && let Some((command, pointer)) = command_handler
    {
        iboot.patch_cmd_handler(command, pointer)?;
    }
    iboot.patch_rsa_check()?;
    Ok(buf)
}

fn parse_vers(buf: &[u8]) -> Result<u32, IbootPatchError> {
    let tail = buf
        .get(VERS_OFFSET..)
        .ok_or(IbootPatchError::VersionNotFound)?;
    let digits: usize = tail.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 {
        return Err(IbootPatchError::VersionNotFound);
    }
    std::str::from_utf8(&tail[..digits])
        .ok()
        .and_then(|digits| digits.parse().ok())
        .ok_or(IbootPatchError::VersionNotFound)
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16, IbootPatchError> {
    buf.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("length")))
        .ok_or(IbootPatchError::OutOfBounds)
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32, IbootPatchError> {
    buf.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("length")))
        .ok_or(IbootPatchError::OutOfBounds)
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<(), IbootPatchError> {
    buf.get_mut(offset..offset + 4)
        .ok_or(IbootPatchError::OutOfBounds)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// pattern_search with a positive step: match `(u32 & mask) == pattern`
/// walking forward from `from` for `len` bytes.
fn search_down(
    buf: &[u8],
    from: usize,
    len: usize,
    pattern: u32,
    mask: u32,
    step: usize,
) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 4 <= buf.len() {
        let value = u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("length"));
        if value & mask == pattern {
            return Some(offset);
        }
        offset += step;
    }
    None
}

/// pattern_search with a negative step: walk backward from `from`.
fn search_up(
    buf: &[u8],
    from: usize,
    len: usize,
    pattern: u32,
    mask: u32,
    step: usize,
) -> Option<usize> {
    let mut offset = from;
    let end = from.saturating_sub(len);
    while offset > end {
        if offset + 4 <= buf.len() {
            let value = u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("length"));
            if value & mask == pattern {
                return Some(offset);
            }
        }
        offset = offset.checked_sub(step)?;
    }
    None
}

fn search_up_u16(buf: &[u8], from: usize, len: usize, pattern: u16, mask: u16) -> Option<usize> {
    let mut offset = from;
    let end = from.saturating_sub(len);
    while offset > end {
        if offset + 2 <= buf.len() {
            let value = u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("length"));
            if value & mask == pattern {
                return Some(offset);
            }
        }
        offset = offset.checked_sub(2)?;
    }
    None
}

fn bl_search_down(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_down(buf, from, len, 0xd000_f000, 0xd000_f800, 1)
}

/// Decode a Thumb-2 BL instruction at `offset` and return its target offset.
fn resolve_bl32(buf: &[u8], offset: usize) -> Option<usize> {
    let first = read_u16(buf, offset).ok()?;
    let second = read_u16(buf, offset + 2).ok()?;
    let s = u32::from((first >> 10) & 1);
    let imm10 = u32::from(first & 0x3ff);
    let imm11 = u32::from(second & 0x7ff);
    let j1 = u32::from((second >> 13) & 1);
    let j2 = u32::from((second >> 11) & 1);
    let x = u32::from((second >> 12) & 1);
    let jump = (s << 24)
        | ((!(s ^ j1) & 1) << 23)
        | ((!(s ^ j2) & 1) << 22)
        | (imm10 << 12)
        | (imm11 << 1)
        | x;
    // Sign-extend 25 bits.
    let jump = ((jump << 7) as i32) >> 7;
    Some((offset as i64 + 4 + i64::from(jump)) as usize)
}

fn find_next_bl_to(buf: &[u8], target: u32) -> Option<usize> {
    let mut offset = 0;
    while offset + 4 <= buf.len() {
        if let Some(resolved) = resolve_bl32(buf, offset)
            && resolved == target as usize
        {
            return Some(offset);
        }
        offset += 1;
    }
    None
}

fn is_movw(buf: &[u8], offset: usize) -> bool {
    read_u32(buf, offset).is_ok_and(|value| {
        (value >> 4) & 0x3f == 0x24 && (value >> 11) & 0x1f == 0x1e && value >> 31 == 0
    })
}

fn movw_value(buf: &[u8], offset: usize) -> u32 {
    let value = read_u32(buf, offset).unwrap_or(0);
    let imm4 = value & 0xf;
    let i = (value >> 10) & 1;
    let imm8 = (value >> 16) & 0xff;
    let imm3 = (value >> 28) & 0x7;
    (((imm4 << 4) + (i << 3) + imm3) << 8) + imm8
}

fn find_next_movw(buf: &[u8], from: usize, len: usize, value: u32) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 4 <= buf.len() {
        if is_movw(buf, offset) && movw_value(buf, offset) == value {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

/// Resolve a literal-pool entry back to the LDR instruction loading it.
fn ldr_to(buf: &[u8], xref: usize) -> Option<usize> {
    let min_addr = xref.saturating_sub(0x420);
    let mut cursor = xref;
    while cursor > min_addr {
        let Some(ldr) = search_up(buf, cursor, cursor - min_addr, 0x4800, 0xf800, 1) else {
            break;
        };
        let raw = read_u32(buf, ldr).ok()?;
        let target = ((ldr + 4) & !3) + (((raw & 0xff) << 2) as usize);
        if target == xref {
            return Some(ldr);
        }
        cursor = ldr.checked_sub(2)?;
    }
    let min_addr = xref.saturating_sub(0x1000);
    let mut cursor = xref;
    while cursor > min_addr {
        let Some(ldr) = search_up(buf, cursor, cursor - min_addr, 0xf8df, 0xffff, 1) else {
            break;
        };
        let raw = read_u32(buf, ldr).ok()?;
        let target = ((ldr + 4) & !3) + (((raw >> 16) & 0xfff) as usize);
        if target == xref {
            return Some(ldr);
        }
        cursor = ldr.checked_sub(4)?;
    }
    None
}

fn find_next_cmp(buf: &[u8], from: usize, len: usize, value: u8) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 2 <= buf.len() {
        let insn = u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("length"));
        if (insn >> 11) & 0x3 == 1 && (insn & 0xff) == u16::from(value) {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

fn find_last_ldr_rd(buf: &[u8], from: usize, len: usize, rd: u8) -> Option<usize> {
    let mut cursor = from;
    while cursor > 0 {
        let ldr = search_up(buf, cursor, len, 0x4800, 0xf800, 2)?;
        let found_rd = (read_u16(buf, ldr).ok()? >> 8) as u8 & 0x7;
        if found_rd == rd {
            return Some(ldr);
        }
        cursor = ldr.checked_sub(2)?;
    }
    None
}

#[derive(Debug, Error)]
pub enum IbootPatchError {
    #[error("the image is an IMG3 container; strip the header and decrypt first")]
    Img3Container,
    #[error("the image is not a 32-bit iBoot (bad reset vector)")]
    NotIBoot32,
    #[error("no iBoot version string found")]
    VersionNotFound,
    #[error("cannot find the verify_shsh anchor instruction")]
    VerifyShshAnchorNotFound,
    #[error("cannot find the top of verify_shsh")]
    VerifyShshTopNotFound,
    #[error("cannot find the BL verify_shsh call (image may already be patched)")]
    VerifyShshCallNotFound,
    #[error("cannot find the debug-enabled DeviceTree lookup")]
    DtreBlNotFound,
    #[error("cannot find the default boot-args string")]
    BootArgsNotFound,
    #[error("cannot find the boot-args string xref")]
    BootArgsXrefNotFound,
    #[error("cannot find the \"Reliance on this certificate\" string for relocation")]
    RelianceCertNotFound,
    #[error("cannot find the boot-args LDR instruction")]
    BootArgsLdrNotFound,
    #[error("cannot find the CMP following the boot-args load")]
    BootArgsCmpNotFound,
    #[error("cannot find the null-string LDR")]
    BootArgsNullLdrNotFound,
    #[error("cannot find the recovery console command")]
    CommandNotFound,
    #[error("cannot find the command table entry")]
    CommandTableNotFound,
    #[error("image is too small for the required access")]
    OutOfBounds,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x4ff0_0000;
    const CERT_LITERAL: usize = 0x3000;
    const LDR_CERT: usize = 0x2fc0;
    const PUSH_TOP: usize = 0x2b00;
    const BL_VERIFY_SHSH: usize = 0x1000;

    fn write16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> Vec<u8> {
        let mut buf = vec![0u8; 0x8000];
        write32(&mut buf, 0, RESET_VECTOR);
        write32(&mut buf, 0x20, BASE);
        buf[VERS_OFFSET..VERS_OFFSET + 5].copy_from_slice(b"2261.");
        // Literal pool entry holding the 'CERT' tag constant (0x43455254).
        write32(&mut buf, CERT_LITERAL, 0x4345_5254);
        // LDR R2, [PC, #60] at LDR_CERT resolves to CERT_LITERAL.
        write16(&mut buf, LDR_CERT, 0x4a0f);
        // verify_shsh function prologue.
        write16(&mut buf, PUSH_TOP, 0xb5f0);
        // BL verify_shsh at BL_VERIFY_SHSH targeting PUSH_TOP | thumb.
        write16(&mut buf, BL_VERIFY_SHSH, 0xf001);
        write16(&mut buf, BL_VERIFY_SHSH + 2, 0xfd7e);
        buf
    }

    #[test]
    fn rejects_img3_containers_and_bad_vectors() {
        let mut img3 = fixture();
        img3[..4].copy_from_slice(b"Img3");
        assert!(matches!(
            IBoot32::new(&mut img3),
            Err(IbootPatchError::Img3Container)
        ));
        let mut junk = vec![0u8; 0x400];
        assert!(matches!(
            IBoot32::new(&mut junk),
            Err(IbootPatchError::NotIBoot32)
        ));
    }

    #[test]
    fn parses_version_and_base_address() {
        let mut buf = fixture();
        let iboot = IBoot32::new(&mut buf).unwrap();
        assert_eq!(iboot.version(), 2261);
    }

    #[test]
    fn patches_rsa_check() {
        let mut buf = fixture();
        let mut iboot = IBoot32::new(&mut buf).unwrap();

        iboot.patch_rsa_check().unwrap();

        assert_eq!(&iboot.buf[BL_VERIFY_SHSH..BL_VERIFY_SHSH + 4], &RSA_PATCH);
    }

    #[test]
    fn rsa_patch_fails_on_patched_image() {
        let mut buf = fixture();
        let mut iboot = IBoot32::new(&mut buf).unwrap();
        iboot.patch_rsa_check().unwrap();

        assert!(matches!(
            iboot.patch_rsa_check(),
            Err(IbootPatchError::VerifyShshCallNotFound)
        ));
    }

    #[test]
    fn resolves_bl32_targets() {
        let buf = fixture();
        assert_eq!(resolve_bl32(&buf, BL_VERIFY_SHSH), Some(PUSH_TOP + 1));
    }
}
