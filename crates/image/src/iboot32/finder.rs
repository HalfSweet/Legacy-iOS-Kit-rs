//! Search and decode primitives for the 32-bit iBoot patcher.
//!
//! Everything works in file offsets; callers add the image base address when
//! they need the device's view. These mirror `functions.c` from the
//! Merculous iBoot32Patcher fork.

use super::IbootPatchError;

pub(super) fn read_u16(buf: &[u8], offset: usize) -> Result<u16, IbootPatchError> {
    buf.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("length")))
        .ok_or(IbootPatchError::OutOfBounds)
}

pub(super) fn read_u32(buf: &[u8], offset: usize) -> Result<u32, IbootPatchError> {
    buf.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("length")))
        .ok_or(IbootPatchError::OutOfBounds)
}

pub(super) fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<(), IbootPatchError> {
    buf.get_mut(offset..offset + 2)
        .ok_or(IbootPatchError::OutOfBounds)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<(), IbootPatchError> {
    buf.get_mut(offset..offset + 4)
        .ok_or(IbootPatchError::OutOfBounds)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub(super) fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// pattern_search with a positive step: match `(u32 & mask) == pattern`
/// walking forward from `from` for `len` bytes.
pub(super) fn search_down(
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
pub(super) fn search_up(
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

/// 16-bit pattern_search walking backward from `from` in halfword steps.
pub(super) fn search_up_u16(
    buf: &[u8],
    from: usize,
    len: usize,
    pattern: u16,
    mask: u16,
) -> Option<usize> {
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

pub(super) fn bl_search_down(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_down(buf, from, len, 0xd000_f000, 0xd000_f800, 1)
}

/// LDR (literal, T1) search walking backward byte by byte.
pub(super) fn ldr_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_up(buf, from, len, 0x4800, 0xf800, 1)
}

/// Locate an LDR instruction whose PC-relative literal is `from` itself by
/// matching the imm8 against the distance walked, as in the C
/// ldr_pcrel_search_up.
pub(super) fn ldr_pcrel_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    let mut cursor = from;
    let mut remaining = len;
    for i in 0..0xffu32 {
        remaining = remaining.checked_sub(4)?;
        cursor = cursor.checked_sub(4)?;
        let value = read_u32(buf, cursor).ok()?;
        if value & 0xf8ff_0000 == (0x4800_0000 | (i << 16)) {
            return Some(cursor + 2);
        }
        if value & 0x0000_f8ff == (0x0000_4800 | i) {
            return Some(cursor);
        }
    }
    None
}

pub(super) fn push_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_up(buf, from, len, 0xb400, 0xfe00, 2)
}

pub(super) fn push_r4_r7_lr_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_up_u16(buf, from, len, 0xb590, 0xffff)
}

pub(super) fn push_r4_to_r7_lr_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_up_u16(buf, from, len, 0xb5f0, 0xffff)
}

pub(super) fn pop_search(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_down(buf, from, len, 0xbc00, 0xfe00, 2)
}

pub(super) fn branch_thumb_conditional_search(
    buf: &[u8],
    from: usize,
    len: usize,
) -> Option<usize> {
    search_down(buf, from, len, 0xd000, 0xf000, 2)
}

/// branch_search walking backward: unconditional B first, then conditional.
pub(super) fn branch_search_up(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    search_up(buf, from, len, 0xe000, 0xf800, 2)
        .or_else(|| search_up(buf, from, len, 0xd000, 0xf000, 2))
}

/// Decode a Thumb-2 BL instruction at `offset` and return its target offset.
pub(super) fn resolve_bl32(buf: &[u8], offset: usize) -> Option<usize> {
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

/// Find the next BL resolving to `target`, starting the scan at `from`.
pub(super) fn find_next_bl_to_from(buf: &[u8], from: usize, target: u32) -> Option<usize> {
    let mut offset = from;
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

pub(super) fn find_next_bl_to(buf: &[u8], target: u32) -> Option<usize> {
    find_next_bl_to_from(buf, 0, target)
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

pub(super) fn find_next_movw(buf: &[u8], from: usize, len: usize, value: u32) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 4 <= buf.len() {
        if is_movw(buf, offset) && movw_value(buf, offset) == value {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

fn is_movt(buf: &[u8], offset: usize) -> bool {
    read_u32(buf, offset).is_ok_and(|value| {
        (value >> 4) & 0x3f == 0x2c && (value >> 11) & 0x1f == 0x1e && value >> 31 == 0
    })
}

/// find_next_MOVT_insn: MOVT is a 32-bit instruction, so the scan steps by 4.
pub(super) fn find_next_movt(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 4 <= buf.len() {
        if is_movt(buf, offset) {
            return Some(offset);
        }
        offset += 4;
    }
    None
}

/// MOV Rd, Rs (T1): pad 0b010001, op 0b10 in the top byte.
pub(super) fn is_mov(buf: &[u8], offset: usize) -> bool {
    read_u16(buf, offset).is_ok_and(|value| value & 0xff00 == 0x4600)
}

pub(super) fn find_next_mov(buf: &[u8], from: usize, len: usize) -> Option<usize> {
    let mut offset = from;
    while offset < from + len && offset + 2 <= buf.len() {
        if is_mov(buf, offset) {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

/// find_Boot_Args_MOV: the boot-args select MOV directly follows another MOV.
pub(super) fn find_boot_args_mov(buf: &[u8], from: usize) -> Option<usize> {
    let potential = find_next_mov(buf, from, 0x10)?;
    if is_mov(buf, potential + 2) {
        Some(potential + 2)
    } else {
        Some(potential)
    }
}

/// Resolve a literal-pool entry back to the LDR instruction loading it.
pub(super) fn ldr_to(buf: &[u8], xref: usize) -> Option<usize> {
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

pub(super) fn find_next_cmp(buf: &[u8], from: usize, len: usize, value: u8) -> Option<usize> {
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

pub(super) fn find_last_ldr_rd(buf: &[u8], from: usize, len: usize, rd: u8) -> Option<usize> {
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

/// xerub's iloader Thumb-2 B.W builder. Decodes back to `target | 1`
/// (Thumb bit) through [`resolve_bl32`].
pub(super) fn make_b_w(position: usize, target: usize) -> u32 {
    let delta = target as i64 - position as i64 - 4; // range: 0x400000
    let prefix = 0xf000 | ((delta >> 12) as u32 & 0x7ff);
    let suffix = 0xb800 | ((delta >> 1) as u32 & 0x7ff);
    prefix | (suffix << 16)
}

/// MOV Rd, Rs (T1).
pub(super) fn build_mov(rd: u8, rs: u8) -> u16 {
    0x4600 | (u16::from(rs) << 3) | u16::from(rd)
}

fn sign_extend_11_32(value: u32) -> u32 {
    (value ^ 0x400).wrapping_sub(0x400)
}

/// Resolve_BL_Long: decode the BL at `offset`, where `device_address` is the
/// BL's own address in the device's view.
pub(super) fn resolve_bl_long(buf: &[u8], offset: usize, device_address: u32) -> Option<u32> {
    let first = read_u16(buf, offset).ok()?;
    let second = read_u16(buf, offset + 2).ok()?;
    let high = sign_extend_11_32(u32::from(first & 0x7ff)) << 12;
    let low = u32::from(second & 0x7ff) << 1;
    Some(
        device_address
            .wrapping_add(4)
            .wrapping_add(high)
            .wrapping_add(low),
    )
}

/// Build_BL_Long: encode a BL from `device_address` to `target`.
pub(super) fn build_bl_long(target: u32, device_address: u32) -> u32 {
    let offset = target.wrapping_sub(device_address.wrapping_add(4));
    let high = sign_extend_11_32(offset >> 12).wrapping_sub(0x000f_f000) & 0x7ff;
    let low = (offset & 0xfff) >> 1;
    (high | 0xf000) | ((low | 0xf800) << 16)
}
