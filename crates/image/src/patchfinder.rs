//! ARM/Thumb-2 instruction search and decode primitives ported from
//! powdersn0w's xpwn `common/patchfinder.c` (LukeZGD/powdersn0w_pub).
//!
//! Everything operates on file offsets into a byte slice; `region` is the
//! image's load address, used only when a finder must match the device's view
//! of a pointer. Unaligned halfword/word reads mirror the C code's casts;
//! out-of-bounds reads yield zero (which matches no instruction pattern)
//! instead of C's undefined behavior, and backward walks stop at the start of
//! the buffer instead of running wild.
//!
//! Ported: the instruction decoders and helpers needed by the powder iBoot
//! and ASR patchers, plus the machinery and kernel finders needed by the
//! powder kernel patcher (`find_with_search_mask`, `find_pc_rel_value`,
//! `find_last_insn_matching`, the ldr-imm/ldrb/ldr-reg/cmp/and/str decoder
//! families, `insn_bl_imm32`, the `find_vm_*`/`find_mount*`/`find_csops*`/
//! `find_tfp0*`/`find_amfi_*`/LwVM/sandbox finders with their `_ios6`/`_84`
//! variants, and the xnu version finders). The ldr-imm/ldrb/ldr-reg/and/str
//! decoders and `insn_cmp_imm_rn` are defined but never used upstream; they
//! are kept here for decoder-set parity and are exercised only by tests.
//! `find_mapForIO` (non-`_84`) is unused by kernel.c and is not ported.
//! `find_release_env_set_whitelist`, `find_whitelist`, and
//! `find_go_cmd_handler` are dead upstream (their patch flag is never set)
//! and are deliberately not ported.
//!
//! Tests here use synthetic Thumb buffers. Per-(device, build) fixture tests
//! against real decrypted iBoot/iBSS/iBEC and ASR binaries are still needed
//! (opt-in, not CI-gated); the finders are per-build sensitive.

/// memmem: first occurrence of `needle` in `haystack`.
pub(crate) fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Halfword at `offset`, zero when out of bounds (matches no pattern).
fn halfword(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("length")))
        .unwrap_or(0)
}

/// Second halfword of the (possibly 32-bit) instruction at `offset`.
fn halfword_hi(data: &[u8], offset: usize) -> u16 {
    halfword(data, offset + 2)
}

fn word(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("length")))
}

fn bit_range(x: u32, start: u32, end: u32) -> u32 {
    (x << (31 - start)) >> (31 - start) >> end
}

fn thumb_expand_imm_c(imm12: u16) -> u32 {
    let imm12 = u32::from(imm12);
    if bit_range(imm12, 11, 10) == 0 {
        let low = bit_range(imm12, 7, 0);
        match bit_range(imm12, 9, 8) {
            0 => low,
            1 => (low << 16) | low,
            2 => (low << 24) | (low << 8),
            3 => (low << 24) | (low << 16) | (low << 8) | low,
            _ => 0,
        }
    } else {
        let unrotated = 0x80 | bit_range(imm12, 6, 0);
        unrotated.rotate_right(bit_range(imm12, 11, 7))
    }
}

pub(crate) fn insn_is_32bit(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xe000) == 0xe000 && (i & 0x1800) != 0
}

fn insn_is_bl(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    let hi = halfword_hi(data, offset);
    (i & 0xf800) == 0xf000 && ((hi & 0xd000) == 0xd000 || (hi & 0xd001) == 0xc000)
}

fn insn_is_b_conditional(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    // Upstream quirk: the last comparison is against 0xE instead of 0xE00,
    // which is always true for a 0x0F00-masked value.
    #[allow(clippy::bad_bit_mask)]
    {
        (i & 0xF000) == 0xD000 && (i & 0x0F00) != 0x0F00 && (i & 0x0F00) != 0xE
    }
}

fn insn_is_b_unconditional(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0xE000 {
        return true;
    }
    // Upstream quirk: `(i1 & 0xD000) == 9` can never hold, so the 32-bit
    // B.W encoding is never matched here.
    #[allow(clippy::bad_bit_mask)]
    {
        (i & 0xF800) == 0xF000 && (halfword_hi(data, offset) & 0xD000) == 9
    }
}

fn insn_is_ldr_literal(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xF800) == 0x4800 || (i & 0xFF7F) == 0xF85F
}

fn insn_ldr_literal_rt(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x4800 {
        ((i >> 8) & 7) as u8
    } else {
        ((halfword_hi(data, offset) >> 12) & 0xF) as u8
    }
}

/// Signed immediate: the 32-bit encoding may address backwards.
fn insn_ldr_literal_imm(data: &[u8], offset: usize) -> i32 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x4800 {
        i32::from(i & 0xFF) << 2
    } else if (i & 0xFF7F) == 0xF85F {
        let imm = i32::from(halfword_hi(data, offset) & 0xFFF);
        if (i & 0x0800) == 0x0800 { imm } else { -imm }
    } else {
        0
    }
}

fn insn_is_add_reg(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xFE00) == 0x1800 || (i & 0xFF00) == 0x4400 || (i & 0xFFE0) == 0xEB00
}

fn insn_add_reg_rd(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x1800 {
        (i & 7) as u8
    } else if (i & 0xFF00) == 0x4400 {
        ((i & 7) | ((i & 0x80) >> 4)) as u8
    } else if (i & 0xFFE0) == 0xEB00 {
        ((halfword_hi(data, offset) >> 8) & 0xF) as u8
    } else {
        0
    }
}

fn insn_add_reg_rn(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x1800 {
        ((i >> 3) & 7) as u8
    } else if (i & 0xFF00) == 0x4400 {
        ((i & 7) | ((i & 0x80) >> 4)) as u8
    } else if (i & 0xFFE0) == 0xEB00 {
        (i & 0xF) as u8
    } else {
        0
    }
}

fn insn_add_reg_rm(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x1800 || (i & 0xFF00) == 0x4400 {
        ((i >> 6) & 7) as u8
    } else if (i & 0xFFE0) == 0xEB00 {
        (halfword_hi(data, offset) & 0xF) as u8
    } else {
        0
    }
}

fn insn_is_movt(data: &[u8], offset: usize) -> bool {
    (halfword(data, offset) & 0xFBF0) == 0xF2C0 && (halfword_hi(data, offset) & 0x8000) == 0
}

fn insn_movt_rd(data: &[u8], offset: usize) -> u8 {
    ((halfword_hi(data, offset) >> 8) & 0xF) as u8
}

fn insn_movt_imm(data: &[u8], offset: usize) -> u32 {
    let i = u32::from(halfword(data, offset));
    let hi = u32::from(halfword_hi(data, offset));
    ((i & 0xF) << 12) | ((i & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF)
}

fn insn_is_mov_imm(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xF800) == 0x2000
        || ((i & 0xFBEF) == 0xF04F && (halfword_hi(data, offset) & 0x8000) == 0)
        || ((i & 0xFBF0) == 0xF240 && (halfword_hi(data, offset) & 0x8000) == 0)
}

fn insn_mov_imm_rd(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x2000 {
        ((i >> 8) & 7) as u8
    } else {
        ((halfword_hi(data, offset) >> 8) & 0xF) as u8
    }
}

fn insn_mov_imm_imm(data: &[u8], offset: usize) -> u32 {
    let i = halfword(data, offset);
    let hi = halfword_hi(data, offset);
    let wide_imm = || thumb_expand_imm_c(((i & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF));
    if (i & 0xF800) == 0x2000 {
        // Upstream quirk: masks with 0xF instead of 0xFF for the 16-bit form.
        u32::from(i & 0xF)
    } else if (i & 0xFBEF) == 0xF04F && (hi & 0x8000) == 0 {
        wide_imm()
    } else if (i & 0xFBF0) == 0xF240 && (hi & 0x8000) == 0 {
        let i = u32::from(i);
        let hi = u32::from(hi);
        ((i & 0xF) << 12) | ((i & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF)
    } else {
        0
    }
}

fn insn_is_push(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xFE00) == 0xB400
        || i == 0xE92D
        || (i == 0xF84D && (halfword_hi(data, offset) & 0x0FFF) == 0x0D04)
}

fn insn_push_registers(data: &[u8], offset: usize) -> u16 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0xB400 {
        (i & 0x00FF) | ((i & 0x0100) << 6)
    } else if i == 0xE92D {
        halfword_hi(data, offset)
    } else if i == 0xF84D && (halfword_hi(data, offset) & 0x0FFF) == 0x0D04 {
        1 << ((halfword_hi(data, offset) >> 12) & 0xF)
    } else {
        0
    }
}

/// Step one instruction back from `offset`, the way the C code does: if the
/// halfword four bytes back starts a 32-bit instruction, step back four.
fn step_back(data: &[u8], offset: usize) -> Option<usize> {
    let mut pref = offset.checked_sub(4)?;
    if !insn_is_32bit(data, pref) {
        pref += 2;
    }
    Some(pref)
}

/// PC-relative address computed into any register by the time the scan
/// reaches `address`, walking forward from `from`. This is a tiny virtual
/// machine over the instructions used for PC-relative addressing; only the
/// movt and add-to-pc forms report a match, as upstream.
fn find_literal_ref(data: &[u8], from: usize, address: u32) -> Option<usize> {
    let mut value = [0u32; 16];
    let mut cur = from;
    while cur + 2 <= data.len() {
        if insn_is_mov_imm(data, cur) {
            value[usize::from(insn_mov_imm_rd(data, cur))] = insn_mov_imm_imm(data, cur);
        } else if insn_is_ldr_literal(data, cur) {
            let literal =
                ((cur + 4) & !3).checked_add_signed(insn_ldr_literal_imm(data, cur) as isize);
            if let Some(literal) = literal
                && let Some(v) = word(data, literal)
            {
                value[usize::from(insn_ldr_literal_rt(data, cur))] = v;
            }
        } else if insn_is_movt(data, cur) {
            let reg = usize::from(insn_movt_rd(data, cur));
            value[reg] |= insn_movt_imm(data, cur) << 16;
            if value[reg] == address {
                return Some(cur);
            }
        } else if insn_is_add_reg(data, cur) {
            let reg = usize::from(insn_add_reg_rd(data, cur));
            if insn_add_reg_rm(data, cur) == 15 && insn_add_reg_rn(data, cur) == reg as u8 {
                value[reg] = value[reg].wrapping_add(cur as u32 + 4);
                if value[reg] == address {
                    return Some(cur);
                }
            }
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    None
}

/// xerub's iloader Thumb-2 B.W builder with its four range bands; `None`
/// mirrors the C `-1` return for out-of-range targets.
pub(crate) fn make_b_w(pos: usize, tgt: usize) -> Option<u32> {
    const RANGE: i64 = 0x400000;
    let delta = tgt as i64 - pos as i64 - 4;
    let distance = if tgt > pos {
        tgt as i64 - pos as i64 - 4
    } else if tgt < pos {
        pos as i64 - tgt as i64 - 4
    } else {
        0
    };
    let (delta, omask) = if distance < RANGE {
        (delta, 0xB800u16)
    } else if RANGE < distance && distance < RANGE * 2 {
        (delta - RANGE, 0xB000)
    } else if RANGE * 2 < distance && distance < RANGE * 3 {
        (delta - RANGE * 2, 0x9800)
    } else if RANGE * 3 < distance && distance < RANGE * 4 {
        (delta - RANGE * 3, 0x9000)
    } else {
        return None;
    };
    let prefix = 0xF000 | ((delta >> 12) as u16 & 0x7FF);
    let suffix = omask | ((delta >> 1) as u16 & 0x7FF);
    Some(u32::from(prefix) | (u32::from(suffix) << 16))
}

/// Encode a Thumb-2 BL from `pos` to `tgt`.
pub(crate) fn make_bl(pos: usize, tgt: usize) -> u32 {
    let delta = tgt as i64 - pos as i64 - 4;
    let prefix = 0xF000 | ((delta >> 12) as u16 & 0x7FF);
    let suffix = 0xF800 | ((delta >> 1) as u16 & 0x7FF);
    u32::from(prefix) | (u32::from(suffix) << 16)
}

/// Find the code referencing `needle`: a literal-pool LDR loading the string,
/// or the mov_imm feeding a movw/movt (or add-to-pc) address computation.
fn find_xref_begin(data: &[u8], needle: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, needle)?;
    let reference = find_literal_ref(data, 0, str_offset as u32)?;
    let pref = step_back(data, reference)?;
    if insn_is_ldr_literal(data, pref) {
        return Some(pref);
    }
    let mut cur = reference;
    loop {
        if insn_is_mov_imm(data, cur) {
            return Some(cur);
        }
        cur = step_back(data, cur)?;
    }
}

pub(crate) fn find_image_passed_signature(data: &[u8]) -> Option<usize> {
    find_xref_begin(data, b"Image passed signature verification")
}

pub(crate) fn find_image_failed_signature(data: &[u8]) -> Option<usize> {
    find_xref_begin(data, b"Image failed signature verification")
}

/// Upstream names this "buggy": the big-endian CS magic is searched as raw
/// little-endian bytes. Kept as-is.
pub(crate) fn find_csdir_magic(data: &[u8]) -> Option<usize> {
    find_bytes(data, &[0xfa, 0xde, 0x0c, 0x02])
}

/// Version number from the "iBoot-<digits>" string, parsed like the C
/// `strtol` over bytes collected with the `(b & ~0x0F) == 0x30` test.
pub(crate) fn find_iboot_version(data: &[u8]) -> Option<u32> {
    let start = find_bytes(data, b"iBoot-")? + 6;
    let mut end = start;
    while data.get(end).is_some_and(|b| (b & 0xF0) == 0x30) {
        end += 1;
    }
    let mut value = 0u32;
    for &b in &data[start..end] {
        if !b.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(value)
}

/// Image type string at offset 0x200, up to the first space (64 bytes max).
pub(crate) fn find_iboot_type(data: &[u8]) -> Option<String> {
    let rest = data.get(0x200..)?;
    let end = rest
        .iter()
        .position(|&b| b == 0x20)
        .unwrap_or(rest.len())
        .min(64);
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// Image base address, pulled from the literal of the first ARM
/// `LDR Rd, [PC, #imm]` (0xE59F high halfword) at or after offset 0x40.
/// Upstream quirk: the scan steps with the Thumb 32-bit instruction test
/// over ARM code, and the literal address is offset + 12 + imm12 rather than
/// the architected PC-relative offset.
pub(crate) fn find_iboot_base(data: &[u8]) -> Option<u32> {
    let mut offset = 0x40usize;
    let insn = loop {
        if offset + 4 > data.len() {
            return None;
        }
        if halfword(data, offset + 2) == 0xE59F {
            break offset;
        }
        offset += if insn_is_32bit(data, offset) { 4 } else { 2 };
    };
    let imm12 = usize::from(halfword(data, insn) & 0x0FFF);
    word(data, insn + 12 + imm12)
}

/// First MOVT whose 16-bit immediate is `val`.
fn find_insn_movt_rx_val(data: &[u8], val: u16) -> Option<usize> {
    let mut offset = 0;
    while offset + 2 <= data.len() {
        if insn_is_movt(data, offset) && insn_movt_imm(data, offset) == u32::from(val) {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

/// Walk back from `from` to the start of the containing function (push with
/// LR in the register list).
fn find_verify_shsh_func(data: &[u8], from: usize) -> Option<usize> {
    let mut cur = from;
    while cur < data.len() {
        if insn_is_push(data, cur) && (insn_push_registers(data, cur) & (1 << 14)) != 0 {
            return Some(cur);
        }
        cur = step_back(data, cur)?;
    }
    None
}

/// Post-iOS 8 variant: an LDR literal loading the 'CERT' tag (0x43455254).
fn find_verify_shsh_ldr_post_8(data: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset + 2 <= data.len() {
        if insn_is_ldr_literal(data, offset)
            && let Some(literal) = (offset & !3)
                .checked_add_signed(insn_ldr_literal_imm(data, offset) as isize)
                .and_then(|p| p.checked_add(4))
            && word(data, literal) == Some(0x4345_5254)
        {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

/// First BL instruction anywhere in the image that targets `func`.
fn find_bl_insn_to(data: &[u8], func: usize) -> Option<usize> {
    let mut offset = 0;
    while offset + 2 <= data.len() {
        if insn_is_bl(data, offset) && word(data, offset) == Some(make_bl(offset, func)) {
            return Some(offset);
        }
        offset += 2;
    }
    None
}

/// The BL that calls the SHSH verification function: anchored on a MOVT of
/// the 'CERT' high half (0x4345) or, post-iOS 8, an LDR of the tag itself.
pub(crate) fn find_verify_shsh(data: &[u8]) -> Option<usize> {
    let insn = find_insn_movt_rx_val(data, 0x4345).or_else(|| find_verify_shsh_ldr_post_8(data))?;
    let func = find_verify_shsh_func(data, insn)?;
    find_bl_insn_to(data, func)
}

/// Walk back from a pointer's address to the LDR (literal) loading it,
/// within 0x1000 bytes.
fn find_ldr_xref(data: &[u8], reference: usize) -> Option<usize> {
    let mut cur = reference;
    for _ in 0..0x800 {
        // Upstream precedence quirk: `a && b ? c : d` groups as `(a && b)`.
        let candidate = if insn_is_ldr_literal(data, cur) && insn_is_32bit(data, cur) {
            halfword(data, cur) & 0x000F == 0xF
        } else {
            halfword(data, cur) & 0x4800 == 0x4800
        };
        if candidate {
            let addr = (cur & !3) + 4;
            let imm = i64::from(insn_ldr_literal_imm(data, cur));
            if imm != 0 && imm == reference as i64 - addr as i64 {
                return Some(cur);
            }
        }
        cur = cur.checked_sub(2)?;
    }
    None
}

/// Find `needle`, then the pointer-sized reference to it (`region + offset`),
/// then the LDR loading that pointer.
fn find_ldr_xref_with_str(region: u32, data: &[u8], needle: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, needle)?;
    let search = region.wrapping_add(str_offset as u32).to_le_bytes();
    let reference = find_bytes(data, &search)?;
    find_ldr_xref(data, reference)
}

/// Second BL after the LDR referencing "debug-enabled".
pub(crate) fn find_debug_enabled(region: u32, data: &[u8]) -> Option<usize> {
    let mut cur = find_ldr_xref_with_str(region, data, b"debug-enabled")?;
    let mut found = 0;
    let mut walked = 0;
    while cur < data.len() && walked < 0x100 {
        if word(data, cur) == Some(0xbf00_2001) {
            // Already patched.
            return None;
        }
        if insn_is_bl(data, cur) {
            found += 1;
            if found == 2 {
                return Some(cur);
            }
        }
        let step = if insn_is_32bit(data, cur) { 4 } else { 2 };
        walked += step;
        cur += step;
    }
    None
}

/// The BL reached through the ticket pointer chain: pointer to
/// `region + 0x280`, then the third pointer to that pointer, then the LDR
/// loading it, then the next BL.
fn find_ticket(region: u32, data: &[u8]) -> Option<usize> {
    let search1 = region.wrapping_add(0x280).to_le_bytes();
    let ref1 = find_bytes(data, &search1)?;
    let search2 = region.wrapping_add(ref1 as u32).to_le_bytes();
    let mut current = 0usize;
    let mut ref2 = None;
    for _ in 0..3 {
        let found = find_bytes(data.get(current..)?, &search2)? + current;
        current = found + 4;
        ref2 = Some(found);
    }
    let mut cur = find_ldr_xref(data, ref2?)?;
    while cur < data.len() {
        if insn_is_bl(data, cur) {
            return Some(cur);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    None
}

/// Instruction right after the ticket BL.
pub(crate) fn find_ticket1(region: u32, data: &[u8]) -> Option<usize> {
    let bl = find_ticket(region, data)?;
    Some(bl + if insn_is_32bit(data, bl) { 4 } else { 2 })
}

/// End of the ticket code range: after the branch (or at the
/// `mov.w r0, #0x30`) that precedes the function's `pop {r4-r7, pc}`.
pub(crate) fn find_ticket2(region: u32, data: &[u8]) -> Option<usize> {
    let bl = find_ticket(region, data)?;
    let mut cur = bl;
    let pop = loop {
        if cur >= data.len() {
            return None;
        }
        if halfword(data, cur) == 0xBDF0 && !insn_is_32bit(data, cur) {
            break cur;
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    };
    let mut cur = pop;
    loop {
        if cur >= data.len() {
            return None;
        }
        if insn_is_b_conditional(data, cur) || insn_is_b_unconditional(data, cur) {
            return Some(cur + if insn_is_32bit(data, cur) { 4 } else { 2 });
        }
        if insn_is_32bit(data, cur) && word(data, cur) == Some(0x30ff_f04f) {
            return Some(cur);
        }
        cur = step_back(data, cur)?;
    }
}

/// First BL after the LDR referencing "boot-partition".
pub(crate) fn find_boot_partition(region: u32, data: &[u8]) -> Option<usize> {
    let mut cur = find_ldr_xref_with_str(region, data, b"boot-partition")?;
    let mut walked = 0;
    while cur < data.len() && walked < 0x100 {
        if word(data, cur) == Some(0xbf00_2000) {
            // Already patched.
            return None;
        }
        if insn_is_bl(data, cur) {
            return Some(cur);
        }
        let step = if insn_is_32bit(data, cur) { 4 } else { 2 };
        walked += step;
        cur += step;
    }
    None
}

/// BL right after the LDR referencing "boot-ramdisk".
pub(crate) fn find_boot_ramdisk(region: u32, data: &[u8]) -> Option<usize> {
    let reference = find_ldr_xref_with_str(region, data, b"boot-ramdisk")?;
    let cur = reference + if insn_is_32bit(data, reference) { 4 } else { 2 };
    insn_is_bl(data, cur).then_some(cur)
}

/// First BL before the LDR referencing the kernelcache path, i.e. the
/// `sys_setup_default_environment` call site.
pub(crate) fn find_sys_setup_default_environment(region: u32, data: &[u8]) -> Option<usize> {
    let mut cur = find_ldr_xref_with_str(
        region,
        data,
        b"/System/Library/Caches/com.apple.kernelcaches/kernelcache",
    )?;
    let mut walked = 0;
    while cur < data.len() && walked < 0x100 {
        if word(data, cur) == Some(0xbf00_bf00) {
            // Already patched.
            return None;
        }
        if insn_is_bl(data, cur) {
            return Some(cur);
        }
        let mut pref = cur.checked_sub(4)?;
        walked += 4;
        if !insn_is_32bit(data, pref) {
            pref += 2;
            walked -= 2;
        }
        cur = pref;
    }
    None
}

/// Address of the pointer to the stock boot-args string. Upstream quirk:
/// the string search includes the trailing NUL (`sizeof` instead of
/// `strlen`).
pub(crate) fn find_boot_args_xref(region: u32, data: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, b"rd=md0 nand-enable-reformat=1 -progress\0")?;
    let search = region.wrapping_add(str_offset as u32).to_le_bytes();
    find_bytes(data, &search)
}

/// Address of the literal-pool entry pointing at an empty (NUL) string,
/// found shortly after the LDR referencing the stock boot-args string.
/// Unlike upstream, which returns a stale `point` when the scan fails, this
/// returns `None` unless the anchor was actually found.
pub(crate) fn find_boot_args_null_xref(region: u32, data: &[u8]) -> Option<usize> {
    let md0 = find_ldr_xref_with_str(region, data, b"rd=md0 nand-enable-reformat=1 -progress")?;
    let mut cur = md0 + if insn_is_32bit(data, md0) { 4 } else { 2 };
    let mut walked = 0;
    while cur < data.len() && walked < 0x80 {
        if insn_is_ldr_literal(data, cur) {
            let imm = insn_ldr_literal_imm(data, cur);
            if imm != 0
                && let Some(point) = (cur & !3)
                    .checked_add_signed(imm as isize)
                    .and_then(|p| p.checked_add(4))
                && point < data.len()
            {
                let reference = word(data, point).unwrap_or(0);
                if (reference & region) == region {
                    let relative = reference.wrapping_sub(region) as usize;
                    if relative < data.len() && data[relative] == 0 {
                        return Some(point);
                    }
                }
            }
        }
        let step = if insn_is_32bit(data, cur) { 4 } else { 2 };
        walked += step;
        cur += step;
    }
    None
}

/// The "Reliance on this certificate " string, whose storage the boot-args
/// patch overwrites.
pub(crate) fn find_reliance_str(data: &[u8]) -> Option<usize> {
    find_bytes(data, b"Reliance on this certificate ")
}

// ---------------------------------------------------------------------------
// Kernel-patcher top-up: decoder families, search machinery, kernel finders.
// ---------------------------------------------------------------------------

/// BL immediate (signed, scaled by 2): the architected decode.
fn insn_bl_imm32(data: &[u8], offset: usize) -> u32 {
    let insn0 = u32::from(halfword(data, offset));
    let insn1 = u32::from(halfword_hi(data, offset));
    let s = (insn0 >> 10) & 1;
    let j1 = (insn1 >> 13) & 1;
    let j2 = (insn1 >> 11) & 1;
    let i1 = !(j1 ^ s) & 1;
    let i2 = !(j2 ^ s) & 1;
    ((insn1 & 0x7FF) << 1)
        | ((insn0 & 0x3FF) << 12)
        | (i2 << 22)
        | (i1 << 23)
        | if s == 1 { 0xFF00_0000 } else { 0 }
}

// The ldr-imm/ldrb/ldr-reg/and/str decoder families and insn_cmp_imm_rn are
// defined upstream but never used by any finder kernel.c reaches; they are
// ported for parity and exercised only by the decoder tests.
#[allow(dead_code)]
fn insn_is_ldr_imm(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    let op_a = bit_range(u32::from(i), 15, 12);
    let op_b = bit_range(u32::from(i), 11, 9);
    op_a == 6 && (op_b & 4) == 4
}

#[allow(dead_code)]
fn insn_ldr_imm_rt(data: &[u8], offset: usize) -> u8 {
    (halfword(data, offset) & 7) as u8
}

#[allow(dead_code)]
fn insn_ldr_imm_rn(data: &[u8], offset: usize) -> u8 {
    ((halfword(data, offset) >> 3) & 7) as u8
}

#[allow(dead_code)]
fn insn_ldr_imm_imm(data: &[u8], offset: usize) -> u8 {
    ((halfword(data, offset) >> 6) & 0x1F) as u8
}

#[allow(dead_code)]
fn insn_is_ldrb_imm(data: &[u8], offset: usize) -> bool {
    (halfword(data, offset) & 0xF800) == 0x7800
}

#[allow(dead_code)]
fn insn_ldrb_imm_rt(data: &[u8], offset: usize) -> u8 {
    (halfword(data, offset) & 7) as u8
}

#[allow(dead_code)]
fn insn_ldrb_imm_rn(data: &[u8], offset: usize) -> u8 {
    ((halfword(data, offset) >> 3) & 7) as u8
}

#[allow(dead_code)]
fn insn_ldrb_imm_imm(data: &[u8], offset: usize) -> u8 {
    ((halfword(data, offset) >> 6) & 0x1F) as u8
}

#[allow(dead_code)]
fn insn_is_ldr_reg(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xFE00) == 0x5800 || ((i & 0xFFF0) == 0xF850 && (halfword_hi(data, offset) & 0x0FC0) == 0)
}

#[allow(dead_code)]
fn insn_ldr_reg_rn(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x5800 {
        ((i >> 3) & 7) as u8
    } else if (i & 0xFFF0) == 0xF850 && (halfword_hi(data, offset) & 0x0FC0) == 0 {
        (i & 0xF) as u8
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_ldr_reg_rt(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x5800 {
        (i & 7) as u8
    } else if (i & 0xFFF0) == 0xF850 && (halfword_hi(data, offset) & 0x0FC0) == 0 {
        ((halfword_hi(data, offset) >> 12) & 0xF) as u8
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_ldr_reg_rm(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x5800 {
        ((i >> 6) & 7) as u8
    } else if (i & 0xFFF0) == 0xF850 && (halfword_hi(data, offset) & 0x0FC0) == 0 {
        (halfword_hi(data, offset) & 0xF) as u8
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_ldr_reg_lsl(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xFE00) == 0x5800 {
        0
    } else if (i & 0xFFF0) == 0xF850 && (halfword_hi(data, offset) & 0x0FC0) == 0 {
        ((halfword_hi(data, offset) >> 4) & 3) as u8
    } else {
        0
    }
}

fn insn_is_cmp_imm(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xF800) == 0x2800
        || ((i & 0xFBF0) == 0xF1B0 && (halfword_hi(data, offset) & 0x8F00) == 0x0F00)
}

#[allow(dead_code)]
fn insn_cmp_imm_rn(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x2800 {
        ((i >> 8) & 7) as u8
    } else if (i & 0xFBF0) == 0xF1B0 && (halfword_hi(data, offset) & 0x8F00) == 0x0F00 {
        (i & 0xF) as u8
    } else {
        0
    }
}

fn insn_cmp_imm_imm(data: &[u8], offset: usize) -> u32 {
    let i = halfword(data, offset);
    let hi = halfword_hi(data, offset);
    if (i & 0xF800) == 0x2800 {
        u32::from(i & 0xFF)
    } else if (i & 0xFBF0) == 0xF1B0 && (hi & 0x8F00) == 0x0F00 {
        thumb_expand_imm_c(
            ((u32::from(i) & 0x0400) << 1 | (u32::from(hi) & 0x7000) >> 4 | u32::from(hi) & 0xFF)
                as u16,
        )
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_is_and_imm(data: &[u8], offset: usize) -> bool {
    (halfword(data, offset) & 0xFBE0) == 0xF000 && (halfword_hi(data, offset) & 0x8000) == 0
}

#[allow(dead_code)]
fn insn_and_imm_rn(data: &[u8], offset: usize) -> u8 {
    (halfword(data, offset) & 0xF) as u8
}

#[allow(dead_code)]
fn insn_and_imm_rd(data: &[u8], offset: usize) -> u8 {
    ((halfword_hi(data, offset) >> 8) & 0xF) as u8
}

#[allow(dead_code)]
fn insn_and_imm_imm(data: &[u8], offset: usize) -> u32 {
    let i = u32::from(halfword(data, offset));
    let hi = u32::from(halfword_hi(data, offset));
    thumb_expand_imm_c((((i & 0x0400) << 1) | ((hi & 0x7000) >> 4) | (hi & 0xFF)) as u16)
}

/// Push whose register list contains LR (function preamble).
fn insn_is_preamble_push(data: &[u8], offset: usize) -> bool {
    insn_is_push(data, offset) && (insn_push_registers(data, offset) & (1 << 14)) != 0
}

#[allow(dead_code)]
fn insn_is_str_imm(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xF800) == 0x6000
        || (i & 0xF800) == 0x9000
        || (i & 0xFFF0) == 0xF8C0
        || ((i & 0xFFF0) == 0xF840 && (halfword_hi(data, offset) & 0x0800) == 0x0800)
}

#[allow(dead_code)]
fn insn_str_imm_postindexed(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    if (i & 0xFFF0) == 0xF840 && (halfword_hi(data, offset) & 0x0800) == 0x0800 {
        (halfword_hi(data, offset) >> 10) & 1 == 1
    } else {
        (i & 0xF800) == 0x6000 || (i & 0xF800) == 0x9000 || (i & 0xFFF0) == 0xF8C0
    }
}

#[allow(dead_code)]
fn insn_str_imm_wback(data: &[u8], offset: usize) -> bool {
    let i = halfword(data, offset);
    (i & 0xFFF0) == 0xF840
        && (halfword_hi(data, offset) & 0x0800) == 0x0800
        && (halfword_hi(data, offset) >> 8) & 1 == 1
}

#[allow(dead_code)]
fn insn_str_imm_imm(data: &[u8], offset: usize) -> u16 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x6000 {
        (i & 0x07C0) >> 4
    } else if (i & 0xF800) == 0x9000 {
        (i & 0xFF) << 2
    } else if (i & 0xFFF0) == 0xF8C0 {
        halfword_hi(data, offset) & 0xFFF
    } else if (i & 0xFFF0) == 0xF840 && (halfword_hi(data, offset) & 0x0800) == 0x0800 {
        halfword_hi(data, offset) & 0xFF
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_str_imm_rt(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x6000 {
        (i & 7) as u8
    } else if (i & 0xF800) == 0x9000 {
        ((i >> 8) & 7) as u8
    } else if (i & 0xFFF0) == 0xF8C0
        || ((i & 0xFFF0) == 0xF840 && (halfword_hi(data, offset) & 0x0800) == 0x0800)
    {
        ((halfword_hi(data, offset) >> 12) & 0xF) as u8
    } else {
        0
    }
}

#[allow(dead_code)]
fn insn_str_imm_rn(data: &[u8], offset: usize) -> u8 {
    let i = halfword(data, offset);
    if (i & 0xF800) == 0x6000 {
        ((i >> 3) & 7) as u8
    } else if (i & 0xF800) == 0x9000 {
        13
    } else if (i & 0xFFF0) == 0xF8C0
        || ((i & 0xFFF0) == 0xF840 && (halfword_hi(data, offset) & 0x0800) == 0x0800)
    {
        (i & 0xF) as u8
    } else {
        0
    }
}

/// Search backwards from `current` for an instruction matching `match_fn`.
/// Upstream's step-back rule differs from [`step_back`]: two halfwords back
/// when the halfword two back starts a 32-bit instruction and the one three
/// back does not.
fn find_last_insn_matching(
    data: &[u8],
    current: usize,
    match_fn: fn(&[u8], usize) -> bool,
) -> Option<usize> {
    let mut cur = current;
    while cur > 0 {
        let at = |back: usize| {
            cur.checked_sub(back)
                .is_some_and(|o| insn_is_32bit(data, o))
        };
        if at(4) && !at(6) {
            cur -= 4;
        } else {
            cur -= 2;
        }
        if match_fn(data, cur) {
            return Some(cur);
        }
    }
    None
}

/// PC-relative value left in `reg` by the time the scan reaches `insn`,
/// walking back to the last instruction that wiped the register and then
/// replaying forward. Returns `None` where upstream returns 0 (no wipe found,
/// or an unhandled add form).
fn find_pc_rel_value(data: &[u8], insn: usize, reg: u8) -> Option<u32> {
    let mut cur = insn;
    // Upstream's step-back here checks only the halfword two back.
    let start = loop {
        if cur == 0 {
            return None;
        }
        let back = if cur.checked_sub(4).is_some_and(|o| insn_is_32bit(data, o)) {
            4
        } else {
            2
        };
        cur -= back;
        if (insn_is_mov_imm(data, cur) && insn_mov_imm_rd(data, cur) == reg)
            || (insn_is_ldr_literal(data, cur) && insn_ldr_literal_rt(data, cur) == reg)
        {
            break cur;
        }
    };

    let mut value = 0u32;
    let mut cur = start;
    while cur < insn {
        if insn_is_mov_imm(data, cur) && insn_mov_imm_rd(data, cur) == reg {
            value = insn_mov_imm_imm(data, cur);
        } else if insn_is_ldr_literal(data, cur) && insn_ldr_literal_rt(data, cur) == reg {
            let literal =
                ((cur + 4) & !3).checked_add_signed(insn_ldr_literal_imm(data, cur) as isize);
            value = literal.and_then(|p| word(data, p)).unwrap_or(0);
        } else if insn_is_movt(data, cur) && insn_movt_rd(data, cur) == reg {
            value |= insn_movt_imm(data, cur) << 16;
        } else if insn_is_add_reg(data, cur) && insn_add_reg_rd(data, cur) == reg {
            if insn_add_reg_rm(data, cur) != 15 || insn_add_reg_rn(data, cur) != reg {
                // Can't handle this kind of operation!
                return None;
            }
            value = value.wrapping_add(cur as u32 + 4);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    Some(value)
}

/// Search for a series of halfwords matching the given (mask, value) pairs,
/// stepping two bytes at a time. A zero mask is a wildcard.
fn find_with_search_mask(data: &[u8], masks: &[(u16, u16)]) -> Option<usize> {
    let tail = masks.len().checked_mul(2)?;
    if data.len() < tail {
        return None;
    }
    let mut cur = 0;
    while cur + tail <= data.len() {
        let matched = masks
            .iter()
            .enumerate()
            .all(|(i, &(mask, value))| halfword(data, cur + 2 * i) & mask == value);
        if matched {
            return Some(cur);
        }
        cur += 2;
    }
    None
}

/// First BL at or after `from`.
fn find_next_bl(data: &[u8], from: usize) -> Option<usize> {
    let mut cur = from;
    while cur + 2 <= data.len() {
        if insn_is_bl(data, cur) {
            return Some(cur);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    None
}

/// Follow a BL to its stub and resolve the stub's first PC-relative address
/// computation to a file offset (the GOT entry the stub loads).
fn find_got_from_stub_bl(data: &[u8], bl: usize) -> Option<usize> {
    let target = (bl as u32)
        .wrapping_add(4)
        .wrapping_add(insn_bl_imm32(data, bl)) as usize;
    // Upstream rejects only targets past the buffer size.
    if target > data.len() {
        return None;
    }
    let mut cur = target;
    while cur + 2 <= data.len() {
        if insn_is_add_reg(data, cur) && insn_add_reg_rm(data, cur) == 15 {
            let rd = insn_add_reg_rd(data, cur);
            cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
            return find_pc_rel_value(data, cur, rd).map(|v| v as usize);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    None
}

/// Shared shape of the forward-walking GOT finders: locate a string, find the
/// code referencing it, then follow the first (or second) BL into a stub.
/// `needle` includes the trailing NUL, as upstream's `sizeof` searches do.
fn find_got_via_string(data: &[u8], needle: &[u8], second_bl: bool) -> Option<usize> {
    let str_offset = find_bytes(data, needle)?;
    let reference = find_literal_ref(data, 0, str_offset as u32)?;
    let mut bl = find_next_bl(data, reference)?;
    if second_bl {
        // Push one instruction past the first BL (always 32-bit).
        bl = find_next_bl(data, bl + 4)?;
    }
    find_got_from_stub_bl(data, bl)
}

/// Offset of the `movs r0, #0; bx lr` gadget plus the Thumb bit. Upstream's
/// NULL check happens after the `+ 1` and never fires; here a miss is `None`.
pub(crate) fn find_ret0_gadget(data: &[u8]) -> Option<usize> {
    find_bytes(data, &[0x00, 0x20, 0x70, 0x47]).map(|o| o + 1)
}

/// Offset of the `movs r0, #1; bx lr` gadget plus the Thumb bit.
pub(crate) fn find_ret1_gadget(data: &[u8]) -> Option<usize> {
    find_bytes(data, &[0x01, 0x20, 0x70, 0x47]).map(|o| o + 1)
}

/// vn_getpath entry point (Thumb bit set), iOS 6 variant.
pub(crate) fn find_vn_getpath(data: &[u8]) -> Option<usize> {
    // A string inside the vn_getpath function.
    const SEARCH: [u8; 14] = [
        0x01, 0x20, 0xCD, 0xE9, 0x00, 0x01, 0x28, 0x46, 0x41, 0x46, 0x32, 0x46, 0x23, 0x46,
    ];
    let insn = find_bytes(data, &SEARCH)?;
    find_last_insn_matching(data, insn, insn_is_preamble_push).map(|start| start | 1)
}

/// memcmp entry point (Thumb bit set), iOS 6 variant. The search is the
/// entire text of memcmp to distinguish it from bcmp.
pub(crate) fn find_memcmp(data: &[u8]) -> Option<usize> {
    const SEARCH: [u8; 42] = [
        0x00, 0x23, 0x62, 0xB1, 0x91, 0xF8, 0x00, 0x90, 0x03, 0x78, 0x4B, 0x45, 0x09, 0xD1, 0x01,
        0x3A, 0x00, 0xF1, 0x01, 0x00, 0x01, 0xF1, 0x01, 0x01, 0x4F, 0xF0, 0x00, 0x03, 0xF2, 0xD1,
        0x18, 0x46, 0x70, 0x47, 0xA3, 0xEB, 0x09, 0x03, 0x18, 0x46, 0x70, 0x47,
    ];
    // Upstream quirk: `(ptr + 1) | 1`.
    find_bytes(data, &SEARCH).map(|o| (o + 1) | 1)
}

pub(crate) fn find_vm_fault_enter_patch(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 8] = [
        (0xF800, 0x6800), // LDR R2, [Ry,#X]
        (0xF8FF, 0x2800), // CMP Rx, #0
        (0xFF00, 0xD100), // BNE x
        (0xFBF0, 0xF010), // TST.W Rx, #0x200000
        (0x0F00, 0x0F00),
        (0xFF00, 0xD100), // BNE x
        (0xFFF0, 0xF400), // AND.W Rx, Ry, #0x100000
        (0xF0FF, 0x1080),
    ];
    find_with_search_mask(data, &MASKS)
}

/// Site of the TST.W to replace with NOP; CMP R0, R0.
pub(crate) fn find_vm_map_enter_patch(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 6] = [
        (0xFFF0, 0xF010), // TST.W Rz, #4
        (0xFFFF, 0x0F04),
        (0xFF78, 0x4600), // MOV Rx, R0 (?)
        (0xFFF0, 0xBF10), // IT NE (?)
        (0xFFF0, 0xF020), // BICNE.W Rk, Rk, #4
        (0xF0FF, 0x0004),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 8)
}

/// Site of the BICNE.W with 4 to NOP out.
pub(crate) fn find_vm_map_protect_patch(data: &[u8]) -> Option<usize> {
    const MASKS_A6: [(u16, u16); 10] = [
        (0xFBF0, 0xF010), // TST.W Rx, #0x20000000
        (0x8F00, 0x0F00),
        (0xFFC0, 0x6840), // LDR Rz, [Ry,#4]
        (0xFFF0, 0xF000), // AND.W Ry, Rk, #6
        (0xF0FF, 0x0006),
        (0xFFC0, 0x68C0), // LDR Rs, [Ry,#0xC]
        (0xFF00, 0x4600), // MOV Rx, Ry (?)
        (0xFFF0, 0xBF00), // IT EQ (?)
        (0xFFF0, 0xF020), // BICNE.W Rk, Rk, #4
        (0xF0FF, 0x0004),
    ];
    const MASKS_A5: [(u16, u16); 10] = [
        (0xFBF0, 0xF010), // TST.W Rx, #0x20000000
        (0x8F00, 0x0F00),
        (0xFFC0, 0x6840), // LDR Rz, [Ry,#4]
        (0xFFC0, 0x68C0), // LDR Rs, [Ry,#0xC]
        (0xFF00, 0x4600), // MOV Rx, Ry (?)
        (0xFFF0, 0xF000), // AND.W Ry, Rk, #6
        (0xF0FF, 0x0006),
        (0xFFF0, 0xBF00), // IT EQ (?)
        (0xFFF0, 0xF020), // BICNE.W Rk, Rk, #4
        (0xF0FF, 0x0004),
    ];
    find_with_search_mask(data, &MASKS_A6)
        .or_else(|| find_with_search_mask(data, &MASKS_A5))
        .map(|o| o + 16)
}

/// mac_mount patch site (odd: it carries the Thumb bit upstream because the
/// patch is a single byte write).
pub(crate) fn find_mount(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 7] = [
        (0xFF00, 0xD100), // bne loc_x
        (0xF0FF, 0x2001), // movs rx, #0x1
        (0xFF00, 0xE000), // b loc_x
        (0xF0FF, 0x2001), // movs rx, #0x1
        (0xFF00, 0xE000), // b loc_x
        (0xFFF0, 0xF440), // orr fp, fp, #0x10000
        (0xF0FF, 0x3080),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 1)
}

/// iOS 9.1 variant of [`find_mount`].
pub(crate) fn find_mount_90(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 9] = [
        (0xFFF0, 0xF420),
        (0xF0FF, 0x3080),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F20),
        (0xFFFF, 0xBF08),
        (0xFFF0, 0xF440),
        (0xF0FF, 0x3080),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F01),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 18 + 1)
}

pub(crate) fn find_csops(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 10] = [
        (0xFFF0, 0xF100),
        (0x0000, 0x0000),
        (0xFF80, 0x4600),
        (0xFC00, 0xF400),
        (0x0000, 0x0000),
        (0xFFF0, 0xF890),
        (0x0000, 0x0000),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F01),
        (0xF800, 0xD000),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 18)
}

/// task_for_pid PID-check branch site.
pub(crate) fn find_tfp0_patch(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 11] = [
        (0xF8FF, 0x9003), // str rx, [sp, #0xc]
        (0xF8FF, 0x9002), // str rx, [sp, #0x8]
        (0xF800, 0x2800), // cmp rx, #0
        (0xFBC0, 0xF000), // beq <-- NOP
        (0xD000, 0x8000),
        (0xF800, 0xF000), // bl _port_name_to_task
        (0xF800, 0xF800),
        (0xF8FF, 0x9003), // str rx, [sp, #0xc]
        (0xF800, 0x2800), // cmp rx, #0
        (0xFBC0, 0xF000), // beq
        (0xD000, 0x8000),
    ];
    const MASKS_A5: [(u16, u16); 11] = [
        (0xF8FF, 0x9003), // str rx, [sp, #0xc]
        (0xF800, 0x2800), // cmp rx, #0
        (0xF8FF, 0x9002), // str rx, [sp, #0x8]
        (0xFBC0, 0xF000), // beq <-- NOP
        (0xD000, 0x8000),
        (0xF800, 0xF000), // bl _port_name_to_task
        (0xF800, 0xF800),
        (0xF8FF, 0x9003), // str rx, [sp, #0xc]
        (0xF800, 0x2800), // cmp rx, #0
        (0xFBC0, 0xF000), // beq
        (0xD000, 0x8000),
    ];
    find_with_search_mask(data, &MASKS)
        .or_else(|| find_with_search_mask(data, &MASKS_A5))
        .map(|o| o + 6)
}

/// AMFI execve return site, where the shellcode jump is written (iOS 9).
pub(crate) fn find_amfi_execve_ret(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 14] = [
        (0xFFFF, 0xF8DA), // ldr.w rx, [sl]
        (0x0FFF, 0x0000),
        (0xFFF0, 0xF010), // tst.w rx, #8
        (0xFFFF, 0x0F08),
        (0xFFF0, 0xBF10), // it ne
        (0xFFF0, 0xF440), // orr rx, rx, #0x800000
        (0xF0FF, 0x0000),
        (0xFFFF, 0xF8CA), // str.w rx, [sl]
        (0x0FFF, 0x0000),
        (0xF8FF, 0x2000), // movs rk, #0
        (0xFF80, 0xB000), // add sp, #x <- replaced with the shellcode jump
        (0xFFFF, 0xE8BD), // pop.w {r8, sl, fp}
        (0xFFFF, 0x0D00),
        (0xFFFF, 0xBDF0), // pop {r4, r5, r6, r7, pc}
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 20)
}

/// AMFI `_cs_enforcement` GOT entry (iOS 9).
pub(crate) fn find_amfi_cs_enforcement_got(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"failed getting entitlements\0", false)
}

/// AMFI `_PE_i_can_has_debugger` GOT entry (iOS 9).
pub(crate) fn find_amfi_pe_i_can_has_debugger_got(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"failed getting entitlements\0", true)
}

/// LwVM `_PE_i_can_has_kernel_configuration` GOT entry (9.3+; 9.3–9.3.1 call
/// `_PE_i_can_has_debugger` at the same site).
pub(crate) fn find_pe_i_can_has_kernel_configuration_got(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"_mapForIO\0", true)
}

/// LwVM patch site whose address (with Thumb bit) replaces the GOT entry.
pub(crate) fn find_lwvm_jump(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 6] = [
        (0xF800, 0x6800), // LDR Rx, [Ry, #z]
        (0xFF00, 0x4400), // ADD Rx, Ry
        (0xF800, 0x7800), // LDRB Rx, [Ry, #z]
        (0xFFF0, 0xF010), // TST.W Rx, #0x1
        (0xFFFF, 0x0F01),
        (0xFF00, 0xD000), // BEQ.N
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 1)
}

/// Sandbox `mac_policy_ops` table, found through the mac_policy_conf whose
/// fullname is "Seatbelt sandbox policy". `region` is the kext's __TEXT
/// vmaddr, used to recognize the pointer to the string.
pub(crate) fn find_sandbox_mac_policy_ops(region: u32, data: &[u8]) -> Option<usize> {
    let fullname = find_bytes(data, b"Seatbelt sandbox policy\0")? as u32;
    let search = fullname.wrapping_add(region).to_le_bytes();
    let find_ptr = find_bytes(data, &search)?;
    // mpc_top = find_ptr - 4; ops_off = mpc_top + 0x10.
    let ops_off = find_ptr.checked_sub(4)?.checked_add(0x10)?;
    let ops = word(data, ops_off)?.wrapping_sub(region);
    Some(ops as usize)
}

/// Sandbox kext `_PE_i_can_has_debugger` GOT entry (iOS 9). Upstream takes an
/// unused `ops` parameter; it is always 0 and is dropped here.
pub(crate) fn find_sb_pe_i_can_has_debugger_got(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"amfi_copy_seatbelt_profile_names() failed\0", true)
}

/// xnu major version from the "root:xnu-<major>.<minor>" version string.
/// Digit collection uses the `(b & ~0x0F) == 0x30` test (which also admits
/// ':', ';', '<', '=', '>', '?'), then `strtol(str, NULL, 0)` — a leading
/// zero would parse as octal, and the collected set can never contain 'x',
/// so the hex path of base 0 is unreachable.
pub(crate) fn find_xnu_major_version(data: &[u8]) -> Option<u32> {
    let start = find_bytes(data, b"root:xnu-")? + 9;
    Some(strtol0(collect_strtol_digits(data, start)))
}

/// xnu minor version: digits after the first '.' following "root:xnu-".
pub(crate) fn find_xnu_minor_version(data: &[u8]) -> Option<u32> {
    let start = find_bytes(data, b"root:xnu-")? + 9;
    let dot = start + data.get(start..)?.iter().position(|&b| b == 0x2E)?;
    Some(strtol0(collect_strtol_digits(data, dot + 1)))
}

fn collect_strtol_digits(data: &[u8], start: usize) -> &[u8] {
    let mut end = start;
    while data.get(end).is_some_and(|b| (b & !0x0F) == 0x30) {
        end += 1;
    }
    data.get(start..end).unwrap_or(&[])
}

/// `strtol(str, NULL, 0)` over bytes whose high nibble is 0x3: decimal,
/// unless a leading zero makes it octal.
fn strtol0(digits: &[u8]) -> u32 {
    let (base, digits) = if digits.first() == Some(&b'0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let mut value = 0u32;
    for &b in digits {
        let digit = u32::from(b).wrapping_sub(u32::from(b'0'));
        if digit >= base {
            break;
        }
        value = value.wrapping_mul(base).wrapping_add(digit);
    }
    value
}

// --- iOS 6 (xnu 2107) variants ---

/// iOS 6 vm_map_enter conditional-branch site.
pub(crate) fn find_vm_map_enter_patch_ios6(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 3] = [
        (0xFFF0, 0xF000), // AND Rx, Ry, #6
        (0xF0FF, 0x0006),
        (0xF8FF, 0x2806), // CMP Rx, #6
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 6)
}

/// iOS 6 vm_map_protect conditional-branch site.
pub(crate) fn find_vm_map_protect_patch_ios6(data: &[u8]) -> Option<usize> {
    const SEARCH: [u8; 6] = [0x08, 0xBF, 0x10, 0xF0, 0x80, 0x4F];
    find_bytes(data, &SEARCH).map(|o| o + 6)
}

/// iOS 6 task_for_pid PID-check branch site.
pub(crate) fn find_tfp0_patch_ios6(data: &[u8]) -> Option<usize> {
    // The task_for_pid function.
    const SEARCH: [u8; 8] = [0x02, 0x46, 0x30, 0x46, 0x21, 0x46, 0x53, 0x46];
    let func = find_bytes(data, &SEARCH)?;
    let func_start = find_last_insn_matching(data, func, insn_is_preamble_push)?;

    // Where something is checked to be 0 (the PID check).
    let mut cur = func_start;
    loop {
        if cur >= func {
            return None;
        }
        if insn_is_cmp_imm(data, cur) && insn_cmp_imm_imm(data, cur) == 0 {
            break;
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }

    // The next conditional branch; an unconditional branch is also accepted
    // to detect an already patched function and still return the right site.
    loop {
        if cur >= func {
            return None;
        }
        if insn_is_b_conditional(data, cur) || insn_is_b_unconditional(data, cur) {
            return Some(cur);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
}

/// Step-back-and-count helper for the iOS 6 / 8.4 AMFI GOT backward walks.
/// Returns the new cursor and the upstream `i` counter delta (4 for a 32-bit
/// predecessor, 2 otherwise).
fn step_back_counted(data: &[u8], cur: usize) -> Option<(usize, u32)> {
    let pref = cur.checked_sub(4)?;
    if insn_is_32bit(data, pref) {
        Some((pref, 4))
    } else {
        Some((pref + 2, 2))
    }
}

/// AMFI `_PE_i_can_has_debugger` GOT entry (iOS 6): two backward BL walks
/// from the reference to "amfi_unrestrict_task_for_pid". Upstream quirks
/// kept: the walk bounded by the `i < 0x100` counter (which does not stop at
/// the buffer start in C; here it does), the `0xBF00BF00` already-patched
/// check, and a second walk that finds nothing leaves the first walk's BL.
pub(crate) fn find_amfi_pe_i_can_has_debugger_got_ios6(data: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, b"amfi_unrestrict_task_for_pid\0")?;
    let mut cur = find_literal_ref(data, 0, str_offset as u32)?;

    let mut bl = None;
    let mut i = 0u32;
    for round in 0..2 {
        if round == 1 {
            let (pref, delta) = step_back_counted(data, cur)?;
            cur = pref;
            i = i.wrapping_add(delta);
        }
        while i < 0x100 {
            if word(data, cur) == Some(0xBF00_BF00) {
                // Already patched.
                break;
            }
            if insn_is_bl(data, cur) {
                bl = Some(cur);
                break;
            }
            let Some((pref, delta)) = step_back_counted(data, cur) else {
                break;
            };
            cur = pref;
            i = i.wrapping_add(delta);
        }
        bl?;
    }
    find_got_from_stub_bl(data, bl?)
}

/// Sandbox kext `_PE_i_can_has_debugger` GOT entry (iOS 6).
pub(crate) fn find_sb_pe_i_can_has_debugger_got_ios6(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"smalloc() failed\0", true)
}

/// sb_evaluate function start (iOS 6 and 8.x): the function referencing the
/// "control_name" string. A push of {r0, r1} is also accepted to detect an
/// already patched version.
pub(crate) fn find_sb_patch(data: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, b"control_name\0")?;
    let reference = find_literal_ref(data, 0, str_offset as u32)?;
    let mut from = reference;
    loop {
        let fn_start = find_last_insn_matching(data, from, insn_is_push)?;
        let registers = insn_push_registers(data, fn_start);
        if (registers & (1 << 14)) != 0 || (registers & 0b11) == 0b11 {
            return Some(fn_start);
        }
        from = fn_start;
    }
}

// --- iOS 8.0–8.4.1 (xnu 2783/2784) variants ---

pub(crate) fn find_vm_fault_enter_patch_84(data: &[u8]) -> Option<usize> {
    const MASKS_A5: [(u16, u16); 10] = [
        // A5(x&rA) 8.4.1
        (0xF0F0, 0xF000), // AND.W Rx, Ry, #0x40
        (0xF0FF, 0x0040),
        (0xFFF0, 0xF8D0), // ldr.w x, [Ry, #z]
        (0x0000, 0x0000),
        (0xFFF0, 0xF8D0), // ldr.w x, [Ry, #z]
        (0x0000, 0x0000),
        (0xFBF0, 0xF010), // TST.W Rx, #0x200000
        (0x0F00, 0x0F00),
        (0xFF00, 0xD100), // BNE x  <- NOP
        (0xF800, 0x6800), // LDR R2, [Ry,#X] <- movs r2, #1
    ];
    if let Some(insn) = find_with_search_mask(data, &MASKS_A5) {
        return Some(insn + 16);
    }

    const MASKS: [(u16, u16); 4] = [
        (0xF0F0, 0xF000), // AND.W Rx, Ry, #0x40
        (0xF0FF, 0x0040),
        (0xFBF0, 0xF010), // TST.W Rx, #0x200000
        (0x0F00, 0x0F00),
    ];
    let insn = find_with_search_mask(data, &MASKS)?;

    // The first conditional branch after the match.
    let first = find_next_if(data, insn, insn_is_b_conditional)?;
    // The second one after it.
    let second = find_next_if(
        data,
        first + if insn_is_32bit(data, first) { 4 } else { 2 },
        insn_is_b_conditional,
    )?;
    // The instruction before it must be a CMP immediate.
    let before = second - if insn_is_32bit(data, second) { 4 } else { 2 };
    if !insn_is_cmp_imm(data, before) {
        return None;
    }
    Some(first)
}

/// First instruction at or after `from` matching `match_fn`.
fn find_next_if(data: &[u8], from: usize, match_fn: fn(&[u8], usize) -> bool) -> Option<usize> {
    let mut cur = from;
    while cur + 2 <= data.len() {
        if match_fn(data, cur) {
            return Some(cur);
        }
        cur += if insn_is_32bit(data, cur) { 4 } else { 2 };
    }
    None
}

/// Site of the TST.W to replace with NOP; CMP R0, R0 (8.x).
pub(crate) fn find_vm_map_enter_patch_84(data: &[u8]) -> Option<usize> {
    const MASKS_84: [(u16, u16); 8] = [
        (0xFFF0, 0xF000), // AND.W Rx, Ry, #2
        (0xF0FF, 0x0002),
        (0xFFF0, 0xF010), // TST.W Rz, #2
        (0xFFFF, 0x0F02),
        (0xFF00, 0xD000), // BEQ loc_xxx
        (0xF8FF, 0x2000), // MOVS Rk, #0
        (0xFFF0, 0xF010), // TST.W Rz, #4
        (0xFFFF, 0x0F04),
    ];
    const MASKS: [(u16, u16); 8] = [
        (0xFBE0, 0xF000),
        (0x8000, 0x0000),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F02),
        (0xFF00, 0xD000),
        (0xF8FF, 0x2000),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F04),
    ];
    find_with_search_mask(data, &MASKS_84)
        .or_else(|| find_with_search_mask(data, &MASKS))
        .map(|o| o + 4)
}

/// Site of the BICNE.W with 4 to NOP out (8.x).
pub(crate) fn find_vm_map_protect_patch_84(data: &[u8]) -> Option<usize> {
    const MASKS_84: [(u16, u16); 19] = [
        (0xFBF0, 0xF010), // TST.W Rx, #0x20000000
        (0x8F00, 0x0F00),
        (0xFBFF, 0xF04F), // MOV.W Rx, #0
        (0x8000, 0x0000),
        (0xFFF0, 0xBF00), // IT EQ
        (0xF8FF, 0x2001), // MOVEQ Rx, #1
        (0xFFC0, 0x6840), // LDR Rz, [Ry,#4]
        (0xFFC0, 0x68C0), // LDR Rs, [Ry,#0xC]
        (0xFFF0, 0xF000), // AND.W Ry, Rk, #6
        (0xF0FF, 0x0006),
        (0xF8FF, 0x2806), // CMP Ry, #6
        (0xFBFF, 0xF04F), // MOV.W Ry, #0
        (0x8000, 0x0000),
        (0xFFF0, 0xBF00), // IT EQ (?)
        (0xF8FF, 0x2001), // MOVEQ Ry, #1
        (0xFFC0, 0x4200), // TST Ry, Rx
        (0xFFF0, 0xBF10), // IT NE (?)
        (0xFFF0, 0xF020), // BICNE.W Rk, Rk, #4
        (0xF0FF, 0x0004),
    ];
    const MASKS: [(u16, u16); 17] = [
        (0xFBF0, 0xF010),
        (0x8F00, 0x0F00),
        (0xFBFF, 0xF04F),
        (0x8000, 0x0000),
        (0xFFF0, 0xF000),
        (0xF0FF, 0x0006),
        (0xFFF0, 0xBF00),
        (0xF8FF, 0x2001),
        (0xF8FF, 0x2806),
        (0xFBFF, 0xF04F),
        (0x8000, 0x0000),
        (0xFFF0, 0xBF00),
        (0xF8FF, 0x2001),
        (0xFFC0, 0x4200),
        (0xFFF0, 0xBF10),
        (0xFFF0, 0xF020),
        (0xF0FF, 0x0004),
    ];
    if let Some(insn) = find_with_search_mask(data, &MASKS_84) {
        Some(insn + 34)
    } else {
        find_with_search_mask(data, &MASKS).map(|o| o + 30)
    }
}

pub(crate) fn find_mount_84(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 9] = [
        (0xFFF0, 0xF420),
        (0xF0FF, 0x3080),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F20),
        (0xFFFF, 0xBF08),
        (0xFFF0, 0xF440),
        (0xF0FF, 0x3080),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F01),
    ];
    // Upstream quirk: one halfword back, then the Thumb bit — an odd byte
    // offset, fine for the single-byte patch written there.
    find_with_search_mask(data, &MASKS).map(|o| o.wrapping_sub(2).wrapping_add(1))
}

/// csops site to replace with NOP (8.x).
pub(crate) fn find_csops_84(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 16] = [
        (0xFC00, 0xF400),
        (0x0000, 0x0000),
        (0xF800, 0xE000),
        (0x0000, 0x0000),
        (0xFFF0, 0xF100),
        (0x0000, 0x0000),
        (0xFF80, 0x4600),
        (0xF800, 0xF000),
        (0x0000, 0x0000),
        (0xFF80, 0x4600),
        (0xFFF0, 0xF890),
        (0x0000, 0x0000),
        (0xFFF0, 0xF010),
        (0xFFFF, 0x0F01),
        (0xFC00, 0xF000),
        (0x0000, 0x0000),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 28)
}

/// Second csops site, where 0x20 is written (8.x).
pub(crate) fn find_csops2_84(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 9] = [
        (0xF800, 0x9800),
        (0xFBF0, 0xF100),
        (0x8000, 0x0000),
        (0xFFC0, 0x4600),
        (0xF800, 0xF000),
        (0xF800, 0xE800),
        (0xFFF0, 0xF8D0),
        (0x0000, 0x0000),
        (0xFAF0, 0xF040),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o + 16)
}

/// AMFI `_cs_enforcement` GOT entry (8.x).
pub(crate) fn find_amfi_cs_enforcement_got_84(data: &[u8]) -> Option<usize> {
    find_got_via_string(data, b"missing or invalid entitlement hash\0", false)
}

/// AMFI `_PE_i_can_has_debugger` GOT entry (8.x): two backward BL walks from
/// the reference to "amfi_unrestrict_task_for_pid". Upstream quirk kept: the
/// `i -= 1` accounting sits outside the `if` (missing braces), so `i` nets
/// +1 per step; a second walk that finds nothing leaves the first walk's BL.
pub(crate) fn find_amfi_pe_i_can_has_debugger_got_84(data: &[u8]) -> Option<usize> {
    let str_offset = find_bytes(data, b"amfi_unrestrict_task_for_pid\0")?;
    let mut cur = find_literal_ref(data, 0, str_offset as u32)?;

    let mut bl = None;
    let mut i = 0u32;
    for round in 0..2 {
        if round == 1 {
            cur = step_back(data, cur)?;
        }
        while i < 0x100 {
            if insn_is_bl(data, cur) {
                bl = Some(cur);
                break;
            }
            cur = step_back(data, cur)?;
            // `pref -= 2; i += 2; if (!32bit) pref += 1; i -= 1;` — the
            // decrement is unconditional upstream, so every step nets +1.
            i = i.wrapping_add(1);
        }
        bl?;
    }
    find_got_from_stub_bl(data, bl?)
}

/// Sandbox kext `_PE_i_can_has_debugger` GOT entry (8.x): a fixed function
/// pattern whose fifth halfword group is the BL into the stub.
pub(crate) fn find_sb_pe_i_can_has_debugger_got_84(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 7] = [
        (0xFFFF, 0xB590), // PUSH {R4,R7,LR}
        (0xFFFF, 0x2000), // MOVS R0, #0
        (0xFFFF, 0xAF01), // ADD R7, SP, #4
        (0xFFFF, 0x2400), // MOVS R4, #0
        (0xF800, 0xF000), // BL i_can_has_debugger
        (0xD000, 0xD000),
        (0xFD07, 0xB100), // CBZ R0, loc_xxx
    ];
    let bl = find_with_search_mask(data, &MASKS)? + 8;
    if !insn_is_bl(data, bl) {
        return None;
    }
    find_got_from_stub_bl(data, bl)
}

/// mapForIO conditional-branch site to NOP (prevents the
/// kIOReturnLockedWrite error); used for 8.x and 9.0–9.2.1.
pub(crate) fn find_map_for_io_84(data: &[u8]) -> Option<usize> {
    // Checked on iPhone5,2 8.2 and iPhone5,1 8.4.
    const MASKS_84: [(u16, u16); 8] = [
        (0xFFF0, 0xF8D0),
        (0x0000, 0x0000),
        (0xFFF0, 0xF890),
        (0x0000, 0x0000),
        (0xFF00, 0x4800),
        (0xFFFF, 0x2900),
        (0xFBC0, 0xF040),
        (0xD000, 0x8000),
    ];
    const MASKS: [(u16, u16); 8] = [
        (0xFFF0, 0xF8D0),
        (0x0000, 0x0000),
        (0xFF00, 0x4800),
        (0xFFF0, 0xF890),
        (0x0000, 0x0000),
        (0xFFFF, 0x2900),
        (0xFBC0, 0xF040),
        (0xD000, 0x8000),
    ];
    find_with_search_mask(data, &MASKS_84)
        .or_else(|| find_with_search_mask(data, &MASKS))
        .map(|o| o + 12)
}

/// vn_getpath entry point (Thumb bit set), 8.x variant.
pub(crate) fn find_vn_getpath_84(data: &[u8]) -> Option<usize> {
    const MASKS_84: [(u16, u16); 7] = [
        (0xF8FF, 0x2001),
        (0xFFFF, 0xE9CD),
        (0x0000, 0x0000),
        (0xFF00, 0x4600),
        (0xFF00, 0x4600),
        (0xFF00, 0x4600),
        (0xFF00, 0x4600),
    ];
    const MASKS: [(u16, u16); 8] = [
        (0xFF00, 0x4600),
        (0xF8FF, 0x2001),
        (0xFF00, 0x4600),
        (0xFF00, 0x4600),
        (0xFFFF, 0xE9CD),
        (0x0000, 0x0000),
        (0xFF00, 0x4600),
        (0xFF00, 0x4600),
    ];
    let insn =
        find_with_search_mask(data, &MASKS_84).or_else(|| find_with_search_mask(data, &MASKS))?;
    find_last_insn_matching(data, insn, insn_is_preamble_push).map(|start| start | 1)
}

/// memcmp entry point (Thumb bit set), 8.x variant. The mask series covers
/// the entire text of memcmp to distinguish it from bcmp.
pub(crate) fn find_memcmp_84(data: &[u8]) -> Option<usize> {
    const MASKS: [(u16, u16); 17] = [
        (0xFD00, 0xB100),
        (0xFFF0, 0xF890),
        (0x0000, 0x0000),
        (0xF800, 0x7800),
        (0xFF00, 0x4500),
        (0xFF00, 0xBF00),
        (0xFFF0, 0xEBA0),
        (0x8030, 0x0000),
        (0xFFFF, 0x4770),
        (0xF8FF, 0x3801),
        (0xFFF0, 0xF100),
        (0xF0FF, 0x0001),
        (0xFFF0, 0xF100),
        (0xF0FF, 0x0001),
        (0xFF00, 0xD100),
        (0xF8FF, 0x2000),
        (0xFFFF, 0x4770),
    ];
    find_with_search_mask(data, &MASKS).map(|o| o | 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn insn_width_detection() {
        let buf = [0x00, 0xBF, 0x40, 0xF2, 0x00, 0x00];
        assert!(!insn_is_32bit(&buf, 0)); // nop
        assert!(insn_is_32bit(&buf, 2)); // movw
        assert!(!insn_is_32bit(&buf, 4)); // zeros
    }

    #[test]
    fn thumb_expand_imm_matches_reference() {
        // 0x00A: plain 8-bit value.
        assert_eq!(thumb_expand_imm_c(0x00A), 0x0A);
        // 0x1AB: replicated byte pattern (mode 1).
        assert_eq!(thumb_expand_imm_c(0x1AB), 0x00AB_00AB);
        // 0x3CD: four-byte replication (mode 3).
        assert_eq!(thumb_expand_imm_c(0x3CD), 0xCDCD_CDCD);
        // 0xC05: rotated form: ror(0x85, 24) via rotate_right(bit_range(11,7)=24? ) — just check nonzero deterministic.
        assert_eq!(thumb_expand_imm_c(0xC05), 0x85u32.rotate_right(24));
    }

    #[test]
    fn make_b_w_round_trips_forward() {
        let insn = make_b_w(0x100, 0x200).expect("in range");
        let prefix = insn & 0xFFFF;
        let suffix = insn >> 16;
        assert_eq!(prefix & 0xF000, 0xF000);
        assert_eq!(suffix & 0xF800, 0xB800);
        let delta = ((prefix & 0x7FF) << 12) | ((suffix & 0x7FF) << 1);
        assert_eq!(0x100 + 4 + delta as usize, 0x200);
    }

    #[test]
    fn make_b_w_rejects_out_of_range() {
        assert!(make_b_w(0, 0x100_0000 + 4).is_none());
    }

    #[test]
    fn make_bl_round_trips_through_decoder() {
        // Independent Thumb-2 BL decode of the encoded instruction.
        let pos = 0x300usize;
        let tgt = 0x280usize;
        let insn = make_bl(pos, tgt);
        let first = (insn & 0xFFFF) as u16;
        let second = (insn >> 16) as u16;
        let buf = insn.to_le_bytes();
        assert!(insn_is_bl(&buf, 0));
        let s = u32::from((first >> 10) & 1);
        let j1 = u32::from((second >> 13) & 1);
        let j2 = u32::from((second >> 11) & 1);
        let imm10 = u32::from(first & 0x3FF);
        let imm11 = u32::from(second & 0x7FF);
        let imm = (imm11 << 1)
            | (imm10 << 12)
            | ((!(j2 ^ s) & 1) << 22)
            | ((!(j1 ^ s) & 1) << 23)
            | if s == 1 { 0xFF00_0000 } else { 0 };
        let target = (pos as u32).wrapping_add(4).wrapping_add(imm);
        assert_eq!(target, tgt as u32);
    }

    /// movw rd, #imm16 / movt rd, #imm16 encoders for fixtures.
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

    #[test]
    fn movw_movt_decoders_agree_with_encoders() {
        let mut buf = [0u8; 8];
        w32(&mut buf, 0, movw(3, 0x5254));
        w32(&mut buf, 4, movt(3, 0x4345));
        assert!(insn_is_mov_imm(&buf, 0));
        assert_eq!(insn_mov_imm_rd(&buf, 0), 3);
        assert_eq!(insn_mov_imm_imm(&buf, 0), 0x5254);
        assert!(insn_is_movt(&buf, 4));
        assert_eq!(insn_movt_rd(&buf, 4), 3);
        assert_eq!(insn_movt_imm(&buf, 4), 0x4345);
    }

    #[test]
    fn xref_begin_via_movw_movt() {
        let mut buf = vec![0u8; 0x200];
        w16(&mut buf, 0, 0xBF00); // keep the anchor off offset 0
        w32(&mut buf, 2, movw(3, 0x100));
        w32(&mut buf, 6, movt(3, 0));
        buf[0x100..0x100 + 13].copy_from_slice(b"debug-enabled");
        assert_eq!(find_xref_begin(&buf, b"debug-enabled"), Some(2));
    }

    #[test]
    fn iboot_version_and_type() {
        let mut buf = vec![0u8; 0x400];
        buf[0x100..0x110].copy_from_slice(b"iBoot-2261.3.2\0\0");
        buf[0x200..0x205].copy_from_slice(b"iBEC ");
        assert_eq!(find_iboot_version(&buf), Some(2261));
        assert_eq!(find_iboot_type(&buf).as_deref(), Some("iBEC"));
        assert_eq!(find_iboot_version(&buf[0x400..]), None);
        // strtol semantics: a ':' passes the collection test but stops parsing.
        let mut odd = b"iBoot-12:34".to_vec();
        odd.resize(0x20, 0);
        assert_eq!(find_iboot_version(&odd), Some(12));
    }

    #[test]
    fn iboot_base_from_arm_literal() {
        let mut buf = vec![0u8; 0x100];
        w16(&mut buf, 0x40, 0x0010); // LDR r0, [PC, #0x10] (low halfword = imm12)
        w16(&mut buf, 0x42, 0xE59F);
        w32(&mut buf, 0x40 + 12 + 0x10, 0x4FF0_0000);
        assert_eq!(find_iboot_base(&buf), Some(0x4FF0_0000));
    }

    #[test]
    fn verify_shsh_chain() {
        let mut buf = vec![0u8; 0x400];
        w16(&mut buf, 0x80, 0xB510); // push {r4, lr}
        w32(&mut buf, 0x82, movw(1, 0x5254));
        w32(&mut buf, 0x86, movt(1, 0x4345));
        w32(&mut buf, 0x100, make_bl(0x100, 0x80));
        assert_eq!(find_verify_shsh(&buf), Some(0x100));
    }

    #[test]
    fn verify_shsh_post_8_ldr_variant() {
        let mut buf = vec![0u8; 0x400];
        // LDR r0, [PC, #0x4] at 0x80 loads the literal at 0x88.
        w16(&mut buf, 0x80, 0x4801);
        w32(&mut buf, 0x88, 0x4345_5254);
        // Containing function start (walk back finds the push).
        w16(&mut buf, 0x70, 0xB510); // push {r4, lr}
        w32(&mut buf, 0x100, make_bl(0x100, 0x70));
        assert_eq!(find_verify_shsh(&buf), Some(0x100));
    }

    #[test]
    fn debug_enabled_second_bl() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        buf[0x2C0..0x2CD].copy_from_slice(b"debug-enabled");
        w32(&mut buf, 0x340, BASE + 0x2C0); // pointer to the string
        // LDR r0, [PC, #0x1C] at 0x320 loads from 0x340.
        w16(&mut buf, 0x320, 0x4807);
        w16(&mut buf, 0x322, 0xBF00);
        w32(&mut buf, 0x324, make_bl(0x324, 0x300));
        w32(&mut buf, 0x328, make_bl(0x328, 0x300));
        assert_eq!(find_debug_enabled(BASE, &buf), Some(0x328));
    }

    #[test]
    fn debug_enabled_already_patched_is_not_found() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        buf[0x2C0..0x2CD].copy_from_slice(b"debug-enabled");
        w32(&mut buf, 0x340, BASE + 0x2C0);
        w16(&mut buf, 0x320, 0x4807);
        w32(&mut buf, 0x322, 0xbf00_2001); // patched form spans the next BLs
        assert_eq!(find_debug_enabled(BASE, &buf), None);
    }

    #[test]
    fn boot_args_xref_includes_nul_in_string_search() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        buf[0x210..0x210 + 40].copy_from_slice(b"rd=md0 nand-enable-reformat=1 -progress\0");
        w32(&mut buf, 0x3A0, BASE + 0x210);
        assert_eq!(find_boot_args_xref(BASE, &buf), Some(0x3A0));
        // Without the trailing NUL the sizeof-based search misses.
        let mut short = vec![0u8; 0x400];
        short[0x210..0x210 + 39].copy_from_slice(b"rd=md0 nand-enable-reformat=1 -progress");
        short[0x210 + 39] = b'X';
        w32(&mut short, 0x3A0, BASE + 0x210);
        assert_eq!(find_boot_args_xref(BASE, &short), None);
    }

    #[test]
    fn boot_args_null_xref_points_at_empty_string_literal() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        buf[0x210..0x210 + 40].copy_from_slice(b"rd=md0 nand-enable-reformat=1 -progress\0");
        w32(&mut buf, 0x3A0, BASE + 0x210);
        // LDR r0, [PC, #0xC] at 0x390 loads from 0x3A0.
        w16(&mut buf, 0x390, 0x4803);
        // Next LDR literal loads a pointer to a NUL byte inside the image.
        w16(&mut buf, 0x3A4, 0x4806); // LDR r0, [PC, #0x18] -> literal at 0x3C0
        w32(&mut buf, 0x3C0, BASE + 0x260); // points at a zero byte
        assert_eq!(find_boot_args_null_xref(BASE, &buf), Some(0x3C0));
    }

    #[test]
    fn ticket_anchors() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        w32(&mut buf, 0x350, BASE + 0x280); // ref1
        for off in [0x380usize, 0x384, 0x388] {
            w32(&mut buf, off, BASE + 0x350); // three matches; ref2 = 0x388
        }
        // LDR r0, [PC, #0x54] at 0x330 loads from 0x388.
        w16(&mut buf, 0x330, 0x4815);
        w16(&mut buf, 0x332, 0xBF00);
        w32(&mut buf, 0x334, make_bl(0x334, 0x300)); // ticket BL
        // Nops up to a conditional branch, then the pop.
        for off in (0x338..0x344).step_by(2) {
            w16(&mut buf, off, 0xBF00);
        }
        w16(&mut buf, 0x344, 0xD001); // beq
        w16(&mut buf, 0x346, 0xBF00);
        w16(&mut buf, 0x348, 0xBDF0); // pop {r4-r7, pc}
        assert_eq!(find_ticket1(BASE, &buf), Some(0x338));
        assert_eq!(find_ticket2(BASE, &buf), Some(0x346));
    }

    #[test]
    fn boot_partition_and_ramdisk() {
        const BASE: u32 = 0x4FF0_0000;
        let mut buf = vec![0u8; 0x400];
        buf[0x2E0..0x2EE].copy_from_slice(b"boot-partition");
        buf[0x2F0..0x2FC].copy_from_slice(b"boot-ramdisk");
        w32(&mut buf, 0x360, BASE + 0x2E0);
        w32(&mut buf, 0x364, BASE + 0x2F0);
        // LDR r0, [PC, #0x10] at 0x34C loads from 0x360; next BL is the patch site.
        w16(&mut buf, 0x34C, 0x4804);
        w16(&mut buf, 0x34E, 0xBF00);
        w32(&mut buf, 0x350, make_bl(0x350, 0x300));
        assert_eq!(find_boot_partition(BASE, &buf), Some(0x350));
        // boot-ramdisk: LDR r0, [PC, #0xC] at 0x354 loads from 0x364, BL follows.
        w16(&mut buf, 0x354, 0x4803);
        w32(&mut buf, 0x356, make_bl(0x356, 0x300));
        assert_eq!(find_boot_ramdisk(BASE, &buf), Some(0x356));
    }

    #[test]
    fn sys_setup_default_environment_walks_back_to_bl() {
        const BASE: u32 = 0x4FF0_0000;
        let path = b"/System/Library/Caches/com.apple.kernelcaches/kernelcache";
        let mut buf = vec![0u8; 0x400];
        buf[0x2A0..0x2A0 + path.len()].copy_from_slice(path);
        w32(&mut buf, 0x398, BASE + 0x2A0);
        // LDR r0, [PC, #0x8] at 0x38C loads from 0x398.
        w16(&mut buf, 0x38C, 0x4802);
        w32(&mut buf, 0x384, make_bl(0x384, 0x300)); // BL before the xref
        w16(&mut buf, 0x388, 0xBF00);
        w16(&mut buf, 0x38A, 0xBF00);
        assert_eq!(find_sys_setup_default_environment(BASE, &buf), Some(0x384));
    }

    #[test]
    fn reliance_str_offset() {
        let mut buf = vec![0u8; 0x100];
        buf[0x40..0x40 + 29].copy_from_slice(b"Reliance on this certificate ");
        assert_eq!(find_reliance_str(&buf), Some(0x40));
        assert_eq!(find_reliance_str(&buf[0x60..]), None);
    }

    #[test]
    fn bl_imm32_decodes_make_bl() {
        // make_bl is exact in range; insn_bl_imm32 must recover its delta.
        for (pos, tgt) in [(0x100usize, 0x200usize), (0x400, 0x40), (0x1000, 0x1004)] {
            let insn = make_bl(pos, tgt);
            let buf = insn.to_le_bytes();
            let imm = insn_bl_imm32(&buf, 0);
            let target = (pos as u32).wrapping_add(4).wrapping_add(imm);
            assert_eq!(target, tgt as u32);
        }
    }

    #[test]
    fn ldr_imm_family_decoders() {
        // ldr r2, [r3, ...]: 0110 1 imm5 rn rt -> 0x6800|0x400|0x18|0x2
        // (imm5 = 0x10, i.e. byte offset 0x40).
        let buf = 0x6C1Au16.to_le_bytes();
        assert!(insn_is_ldr_imm(&buf, 0));
        assert_eq!(insn_ldr_imm_rt(&buf, 0), 2);
        assert_eq!(insn_ldr_imm_rn(&buf, 0), 3);
        // Upstream returns the raw imm5, not the scaled byte offset.
        assert_eq!(insn_ldr_imm_imm(&buf, 0), 0x10);
        assert!(!insn_is_ldr_imm(&0xBF00u16.to_le_bytes(), 0));
    }

    #[test]
    fn ldrb_imm_family_decoders() {
        // ldrb r1, [r4, #0x12] -> 0111 1 imm5 rn rt = 0x7800|0x480|0x20|0x1
        let buf = 0x7CA1u16.to_le_bytes();
        assert!(insn_is_ldrb_imm(&buf, 0));
        assert_eq!(insn_ldrb_imm_rt(&buf, 0), 1);
        assert_eq!(insn_ldrb_imm_rn(&buf, 0), 4);
        assert_eq!(insn_ldrb_imm_imm(&buf, 0), 0x12);
    }

    #[test]
    fn ldr_reg_family_decoders() {
        // 16-bit: ldr r2, [r1, r3] -> 0101 100 rm rn rt = 0x58CA
        let buf = 0x58CAu16.to_le_bytes();
        assert!(insn_is_ldr_reg(&buf, 0));
        assert_eq!(insn_ldr_reg_rt(&buf, 0), 2);
        assert_eq!(insn_ldr_reg_rn(&buf, 0), 1);
        assert_eq!(insn_ldr_reg_rm(&buf, 0), 3);
        assert_eq!(insn_ldr_reg_lsl(&buf, 0), 0);
        // 32-bit: ldr.w r5, [r6, r7, lsl #2] -> F856 5027
        let buf32 = [0x56, 0xF8, 0x27, 0x50];
        assert!(insn_is_ldr_reg(&buf32, 0));
        assert_eq!(insn_ldr_reg_rt(&buf32, 0), 5);
        assert_eq!(insn_ldr_reg_rn(&buf32, 0), 6);
        assert_eq!(insn_ldr_reg_rm(&buf32, 0), 7);
        assert_eq!(insn_ldr_reg_lsl(&buf32, 0), 2);
    }

    #[test]
    fn cmp_imm_family_decoders() {
        // cmp r3, #0x42 -> 0010 1 011 01000010 = 0x2B42
        let buf = 0x2B42u16.to_le_bytes();
        assert!(insn_is_cmp_imm(&buf, 0));
        assert_eq!(insn_cmp_imm_rn(&buf, 0), 3);
        assert_eq!(insn_cmp_imm_imm(&buf, 0), 0x42);
        // 32-bit: cmp.w r4, #0x100 -> F1B4 0F40? build via expand: 0x100 is
        // ror(0x81, 24)? use plain imm8=0x7F form instead: F1B4 0F7F
        let buf32 = [0xB4, 0xF1, 0x7F, 0x0F];
        assert!(insn_is_cmp_imm(&buf32, 0));
        assert_eq!(insn_cmp_imm_rn(&buf32, 0), 4);
        assert_eq!(insn_cmp_imm_imm(&buf32, 0), 0x7F);
    }

    #[test]
    fn and_imm_family_decoders() {
        // and.w r2, r3, #0xF0 -> F003 0278? imm pattern 0x0F0 replication...
        // Use imm8=0x55 (no i/imm3): F003 0255
        let buf = [0x03, 0xF0, 0x55, 0x02];
        assert!(insn_is_and_imm(&buf, 0));
        assert_eq!(insn_and_imm_rn(&buf, 0), 3);
        assert_eq!(insn_and_imm_rd(&buf, 0), 2);
        assert_eq!(insn_and_imm_imm(&buf, 0), 0x55);
        assert!(!insn_is_and_imm(&0xBF00u16.to_le_bytes(), 0));
    }

    #[test]
    fn str_imm_family_decoders() {
        // str r2, [r3, #0x40] -> 0110 0 imm5 rn rt = 0x6000|0x400|0x18|0x2
        let buf = 0x641Au16.to_le_bytes();
        assert!(insn_is_str_imm(&buf, 0));
        assert!(insn_str_imm_postindexed(&buf, 0));
        assert!(!insn_str_imm_wback(&buf, 0));
        assert_eq!(insn_str_imm_imm(&buf, 0), 0x40);
        assert_eq!(insn_str_imm_rt(&buf, 0), 2);
        assert_eq!(insn_str_imm_rn(&buf, 0), 3);
        // str r1, [sp, #0x10] -> 1001 0 001 00000100 = 0x9104
        let sp = 0x9104u16.to_le_bytes();
        assert!(insn_is_str_imm(&sp, 0));
        assert_eq!(insn_str_imm_rn(&sp, 0), 13);
        assert_eq!(insn_str_imm_imm(&sp, 0), 0x10);
        // 32-bit: str.w r4, [r5, #0x80] -> F8C5 4080. Upstream quirk: the
        // "postindexed" accessor reports 1 for every non-writeback form.
        let w = [0xC5, 0xF8, 0x80, 0x40];
        assert!(insn_is_str_imm(&w, 0));
        assert_eq!(insn_str_imm_rt(&w, 0), 4);
        assert_eq!(insn_str_imm_rn(&w, 0), 5);
        assert_eq!(insn_str_imm_imm(&w, 0), 0x80);
        assert!(insn_str_imm_postindexed(&w, 0));
        assert!(!insn_str_imm_wback(&w, 0));
        // Pre-indexed form (bit 11 and the P bit set): F845 4C7F.
        let post = [0x45, 0xF8, 0x7F, 0x4C];
        assert!(insn_is_str_imm(&post, 0));
        assert!(insn_str_imm_postindexed(&post, 0));
        assert!(!insn_str_imm_wback(&post, 0));
        assert_eq!(insn_str_imm_imm(&post, 0), 0x7F);
    }

    #[test]
    fn preamble_push_requires_lr() {
        let with_lr = 0xB510u16.to_le_bytes(); // push {r4, lr}
        assert!(insn_is_preamble_push(&with_lr, 0));
        let plain = 0xB430u16.to_le_bytes(); // push {r4, r5}
        assert!(!insn_is_preamble_push(&plain, 0));
    }

    #[test]
    fn with_search_mask_finds_first_sequence() {
        let mut buf = vec![0u8; 0x40];
        w16(&mut buf, 0x10, 0xF012);
        w16(&mut buf, 0x12, 0x0F04);
        w16(&mut buf, 0x14, 0xBF10);
        let masks = [(0xFFF0u16, 0xF010u16), (0xFFFF, 0x0F04), (0xFFF0, 0xBF10)];
        assert_eq!(find_with_search_mask(&buf, &masks), Some(0x10));
        // A mismatching tail misses.
        w16(&mut buf, 0x14, 0xBF20);
        assert_eq!(find_with_search_mask(&buf, &masks), None);
        // Zero mask entries are wildcards.
        let wild = [(0xFFF0u16, 0xF010u16), (0x0000, 0x0000), (0xFFF0, 0xBF20)];
        assert_eq!(find_with_search_mask(&buf, &wild), Some(0x10));
    }

    #[test]
    fn last_insn_matching_steps_back_over_32bit() {
        let mut buf = vec![0u8; 0x40];
        w16(&mut buf, 0x08, 0xB510); // push {r4, lr}
        w16(&mut buf, 0x0A, 0xBF00); // nop
        w32(&mut buf, 0x0C, movw(0, 1)); // 32-bit
        // From 0x10: step back sees the 32-bit instruction at 0x0C.
        assert_eq!(
            find_last_insn_matching(&buf, 0x10, insn_is_preamble_push),
            Some(0x08)
        );
    }

    #[test]
    fn pc_rel_value_replays_movw_movt() {
        let mut buf = vec![0u8; 0x40];
        w32(&mut buf, 0x08, movw(2, 0x1234));
        w32(&mut buf, 0x0C, movt(2, 0x5678));
        w16(&mut buf, 0x10, 0xBF00);
        // From 0x12, register 2 holds 0x56781234.
        assert_eq!(find_pc_rel_value(&buf, 0x12, 2), Some(0x5678_1234));
        // An unrelated register finds no wipe before the buffer start.
        assert_eq!(find_pc_rel_value(&buf, 0x12, 5), None);
    }

    #[test]
    fn pc_rel_value_add_to_pc() {
        let mut buf = vec![0u8; 0x40];
        w32(&mut buf, 0x08, movw(1, 0));
        // add.w r1, r1, pc: 0xEB01 010F. The 16-bit add-to-pc form is not
        // recognized: upstream's insn_add_reg_rm extracts only 3 Rm bits
        // there, so it never reads as 15.
        w32(&mut buf, 0x0C, 0x010F_EB01);
        w16(&mut buf, 0x10, 0xBF00);
        assert_eq!(find_pc_rel_value(&buf, 0x12, 1), Some(0x0C + 4));
    }

    #[test]
    fn pc_rel_value_rejects_unhandled_add() {
        let mut buf = vec![0u8; 0x40];
        w32(&mut buf, 0x08, movw(1, 0));
        w16(&mut buf, 0x0C, 0x4449); // add r1, r1 (rm=1 != pc)
        assert_eq!(find_pc_rel_value(&buf, 0x0E, 1), None);
    }

    #[test]
    fn ret_gadgets_carry_thumb_bit() {
        let mut buf = vec![0u8; 0x20];
        buf[0x08..0x0C].copy_from_slice(&[0x00, 0x20, 0x70, 0x47]);
        buf[0x10..0x14].copy_from_slice(&[0x01, 0x20, 0x70, 0x47]);
        assert_eq!(find_ret0_gadget(&buf), Some(0x09));
        assert_eq!(find_ret1_gadget(&buf), Some(0x11));
        assert_eq!(find_ret0_gadget(&buf[..4]), None);
    }

    #[test]
    fn xnu_version_parsing() {
        let mut buf = vec![0u8; 0x100];
        let version = b"root:xnu-3248.60.1~1\0";
        buf[0x20..0x20 + version.len()].copy_from_slice(version);
        assert_eq!(find_xnu_major_version(&buf), Some(3248));
        assert_eq!(find_xnu_minor_version(&buf), Some(60));
        // strtol base-0 quirk: a leading zero parses as octal.
        let mut octal = vec![0u8; 0x40];
        let v = b"root:xnu-0107.7\0";
        octal[..v.len()].copy_from_slice(v);
        assert_eq!(find_xnu_major_version(&octal), Some(0o107));
        // ':' passes the collection mask but stops strtol.
        let mut colon = vec![0u8; 0x40];
        let v = b"root:xnu-21:7.2\0";
        colon[..v.len()].copy_from_slice(v);
        assert_eq!(find_xnu_major_version(&colon), Some(21));
        assert_eq!(find_xnu_major_version(&buf[..8]), None);
    }

    /// A stub function computing a PC-relative address, plus a BL to it,
    /// exercises find_got_from_stub_bl end to end.
    #[test]
    fn got_from_stub_bl_chain() {
        let mut buf = vec![0u8; 0x100];
        // Stub at 0x40: movw r3, #0, then add.w r3, r3, pc -> 0x44 + 4 = 0x48.
        w32(&mut buf, 0x40, movw(3, 0));
        w32(&mut buf, 0x44, 0x030F_EB03);
        // BL at 0x10 targeting 0x40.
        w32(&mut buf, 0x10, make_bl(0x10, 0x40));
        assert_eq!(find_got_from_stub_bl(&buf, 0x10), Some(0x48));
    }

    #[test]
    fn got_via_string_two_bl_walk() {
        let mut buf = vec![0u8; 0x200];
        // String at 0x180, referenced by movw/movt at 0x20.
        buf[0x180..0x185].copy_from_slice(b"stub\0");
        w32(&mut buf, 0x20, movw(3, 0x180));
        w32(&mut buf, 0x24, movt(3, 0));
        // First BL (to 0x60), then padding, then the second BL (to 0x40).
        w32(&mut buf, 0x28, make_bl(0x28, 0x60));
        w16(&mut buf, 0x2C, 0xBF00);
        w32(&mut buf, 0x2E, make_bl(0x2E, 0x40));
        // Stub at 0x40: movw r3, #0; add.w r3, r3, pc -> 0x44 + 4 = 0x48.
        w32(&mut buf, 0x40, movw(3, 0));
        w32(&mut buf, 0x44, 0x030F_EB03);
        w16(&mut buf, 0x60, 0xBF00);
        assert_eq!(find_got_via_string(&buf, b"stub\0", true), Some(0x48));
        assert_eq!(find_got_via_string(&buf, b"stub\0", false), None);
    }

    #[test]
    fn mask_finders_match_their_sequences() {
        // vm_fault_enter: lay down halfwords satisfying each mask entry.
        let mut buf = vec![0u8; 0x100];
        let hws = [
            0x6801u16, 0x2800, 0xD101, 0xF010, 0x0F00, 0xD102, 0xF400, 0x1080,
        ];
        for (i, hw) in hws.iter().enumerate() {
            w16(&mut buf, 0x20 + 2 * i, *hw);
        }
        assert_eq!(find_vm_fault_enter_patch(&buf), Some(0x20));
        // vm_map_enter: 6 halfwords, result +8.
        let hws = [0xF010u16, 0x0F04, 0x4600, 0xBF10, 0xF020, 0x0004];
        let mut buf = vec![0u8; 0x100];
        for (i, hw) in hws.iter().enumerate() {
            w16(&mut buf, 0x30 + 2 * i, *hw);
        }
        assert_eq!(find_vm_map_enter_patch(&buf), Some(0x38));
    }
}
