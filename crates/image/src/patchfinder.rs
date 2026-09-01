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
//! and ASR patchers. Deferred to the kernel patcher slice: the
//! `find_with_search_mask`/`find_pc_rel_value`/`find_last_insn_matching`
//! machinery, the ldr-imm/ldrb/ldr-reg/cmp/and/str decoder families,
//! `insn_bl_imm32`, and every kernel finder (`find_vm_*`, `find_mount*`,
//! `find_csops*`, `find_tfp0*`, `find_amfi_*`, LwVM and sandbox finders, the
//! `_ios6`/`_84`/`_90` variants, and the xnu version finders).
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
}
