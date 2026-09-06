//! ARM64 instruction decode/encode and file-offset finders, ported from
//! tihmstar's libpatchfinder `patchfinder64.cpp` on top of libinsn
//! (`arm64_decode.cpp`, `arm64_encode.cpp`, `vmem.cpp`).
//!
//! The model is a single read-write-execute segment: the whole image buffer
//! mapped at `base`. All finder inputs and outputs are virtual addresses
//! (`loc_t` upstream); converting to a file offset is `loc - base`. Every
//! read is bounds-checked: out-of-range instruction fetches, dereferences,
//! and iterations yield `None`, which is how upstream's thrown
//! `out_of_range` exceptions surface here. `memmem` scans raw bytes with no
//! NUL termination, matching the platform `memmem` upstream links against
//! (its `#ifndef HAVE_MEMMEM` fallback, which stops at NUL, is never used
//! on macOS/Linux and is not ported).
//!
//! Ported upstream quirks, deliberately:
//!
//! - `bl` immediates sign-extend from bit 24 and `b` immediates from bit 25
//!   of the *shifted* value (libinsn's `signExtend64` arguments are one and
//!   three positions off, respectively); `tbz`/`tbnz` sign-extend from bit
//!   12. All only diverge from the architectural decode for displacements of
//!   32 MiB or more, which never occur inside an iBoot image.
//! - `ldr`/`str`/`strb` pre/post-indexed immediates are returned as the raw
//!   unsigned `imm9` field (no sign extension).
//! - `cmp` is the same decoded kind as `subs` (upstream's `insn::cmp` is an
//!   enum alias), so `== cmp` matches any `subs`; the ported code checks
//!   [`Kind::Subs`] and documents the sites where upstream wrote `cmp`.
//! - Iteration mirrors `vmem::operator++`: stepping forward fails once the
//!   new position covers the last word of the buffer (`off + 4 >= len`), so
//!   the final instruction is unreachable via forward scans.
//! - `find_literal_ref` aborts the *entire* search (returning `None`) when
//!   an inner adrp/movz chain walk runs out of bounds, and follows `b`
//!   redirects inside movz/movk chains except `b .` self-loops.
//! - `find_branch_ref` with a negative limit only spends the limit on
//!   non-branch instructions; branch instructions themselves are free.
//!
//! Only the instruction kinds and encoders used by the ported iBoot patch
//! methods are implemented: adr, adrp, add, movz/movk, mov (register), bl,
//! b, b.cond, cbz/cbnz, tbz/tbnz, csel, ret, nop, pacibsp, ldr, str, strb,
//! stp, ldp, sub, subs. The and_/orr/lsl/br/blr/mrs/msr/madd/ccmp/pac
//! families and the bitmask-immediate decoder (`DecodeBitMasks`) are only
//! referenced by patchers that are not ported (always-production, tz0, ...)
//! and are deliberately omitted.

/// A decoded ARM64 instruction: raw word plus its virtual address.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Insn {
    opcode: u32,
    pc: u64,
}

/// Instruction kinds, a subset of libinsn's `insn::type`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Unknown,
    Add,
    Adr,
    Adrp,
    B,
    Bcond,
    Bl,
    Cbnz,
    Cbz,
    Csel,
    Ldp,
    Ldr,
    Mov,
    Movk,
    Movz,
    Nop,
    Pacibsp,
    Ret,
    Stp,
    Str,
    Strb,
    Sub,
    Subs,
    Tbnz,
    Tbz,
}

/// libinsn `insn::supertype`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Supertype {
    General,
    BranchImm,
    Memory,
}

/// libinsn `insn::subtype`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Subtype {
    General,
    Register,
    Immediate,
    Literal,
}

fn bit_range(v: u32, begin: u32, end: u32) -> u32 {
    (v >> begin) & ((1 << (end - begin + 1)) - 1)
}

/// libinsn's `signExtend64`: replicate bit `size - 1` into every higher bit.
fn sign_extend(v: u64, size: u32) -> i64 {
    let e = (v >> (size - 1)) & 1;
    let mut v = v;
    for i in size..64 {
        v |= e << i;
    }
    v as i64
}

/// Stage-2 decoder for the stp/ldp top bytes (0x28, 0x29, 0xa8, 0xa9).
fn decode_stp_ldp(opcode: u32) -> Kind {
    if bit_range(opcode, 25, 30) == 0b10100 && bit_range(opcode, 23, 24) != 0 {
        if opcode & (1 << 22) == 0 {
            return Kind::Stp;
        }
        return Kind::Ldp;
    }
    Kind::Unknown
}

/// Stage-2 decoder for the 0x38/0x39 top bytes (is_strb; the is_ldrb half of
/// upstream's decoder list is unneeded and not ported — no ldrb encoding can
/// satisfy the strb masks, so detection is unaffected).
fn decode_strb(opcode: u32) -> Kind {
    if bit_range(opcode, 21, 31) == 0b001_1100_0000 // immediate post/pre-indexed
        || bit_range(opcode, 22, 31) == 0b00_1110_0100 // unsigned offset
        || (bit_range(opcode, 21, 31) == 0b001_1100_0001 && bit_range(opcode, 10, 11) == 0b10)
    {
        return Kind::Strb;
    }
    Kind::Unknown
}

fn decode_str(opcode: u32) -> Kind {
    if bit_range(opcode, 22, 29) == 0b1110_0100 && opcode >> 31 == 1 {
        return Kind::Str; // immediate
    }
    if bit_range(opcode | (1 << 30), 21, 31) == 0b111_1100_0001 && bit_range(opcode, 10, 11) == 0b10
    {
        return Kind::Str; // register
    }
    Kind::Unknown
}

fn decode_ldr(opcode: u32) -> Kind {
    if (bit_range(opcode, 22, 29) == 0b1110_0001 && opcode & (1 << 10) != 0 && opcode >> 31 == 1)
        || (bit_range(opcode, 22, 29) == 0b1110_0101 && opcode >> 31 == 1)
    {
        return Kind::Ldr; // immediate
    }
    if bit_range(opcode | (1 << 30), 21, 31) == 0b111_1100_0011 && bit_range(opcode, 10, 11) == 0b10
    {
        return Kind::Ldr; // register
    }
    if bit_range(opcode | (1 << 23), 22, 29) == 0b1111_0111 // SIMD ldr
        || bit_range(opcode | (1 << 30), 22, 31) == 0b11_1110_0101
    {
        return Kind::Ldr;
    }
    Kind::Unknown
}

/// The libinsn two-stage decoder: stage 1 dispatches on the top byte, stage 2
/// on further bit patterns. Only the entries reachable from the ported
/// patchers are implemented; everything else decodes to [`Kind::Unknown`].
fn decode(opcode: u32) -> Kind {
    let top = opcode >> 24;
    // Stage-2 bytes first (upstream's `defineDecoder` entries overwrite any
    // direct stage-1 assignment for the same byte).
    match top {
        0x28 | 0x29 | 0xa8 | 0xa9 => return decode_stp_ldp(opcode),
        0x38 | 0x39 => return decode_strb(opcode),
        0xb8 | 0xf8 => {
            // Upstream order: is_str, then is_ldr.
            let kind = decode_str(opcode);
            if kind != Kind::Unknown {
                return kind;
            }
            return decode_ldr(opcode);
        }
        0xb9 | 0xf9 => {
            // Upstream order: is_ldr, then is_str.
            let kind = decode_ldr(opcode);
            if kind != Kind::Unknown {
                return kind;
            }
            return decode_str(opcode);
        }
        0x52 | 0xd2 => {
            if bit_range(opcode, 23, 30) == 0b1010_0101 {
                return Kind::Movz;
            }
            return Kind::Unknown;
        }
        0x72 | 0xf2 => {
            if bit_range(opcode, 23, 30) == 0b1110_0101 {
                return Kind::Movk;
            }
            return Kind::Unknown;
        }
        0x54 => {
            if opcode & (1 << 4) == 0 {
                return Kind::Bcond;
            }
            return Kind::Unknown;
        }
        0xd5 => {
            if opcode == 0xd503_201f {
                return Kind::Nop;
            }
            if opcode == 0xd503_237f {
                return Kind::Pacibsp;
            }
            // is_mrs / is_msr are not needed by the ported patchers.
            return Kind::Unknown;
        }
        0xd6 => {
            // is_ret: `(i | 0xfff) == 0xd65f0fff`, which also matches
            // retaa/retab and any low-bits garbage under 0xd65f0000.
            if opcode | 0xfff == 0xd65f_0fff {
                return Kind::Ret;
            }
            return Kind::Unknown;
        }
        0x1a | 0x9a => {
            if bit_range(opcode, 21, 30) == 0b00_1101_0100 && bit_range(opcode, 10, 11) == 0 {
                return Kind::Csel;
            }
            return Kind::Unknown;
        }
        _ => {}
    }
    // Stage-1 direct mappings.
    if top & 0x9f == 0x90 {
        Kind::Adrp
    } else if top & 0x9f == 0x10 {
        Kind::Adr
    } else if top & 0xfc == 0x94 {
        Kind::Bl
    } else if top & 0x7f == 0x34 {
        Kind::Cbz
    } else if top & 0x7f == 0x35 {
        Kind::Cbnz
    } else if top & 0x7f == 0x36 {
        Kind::Tbz
    } else if top & 0x7f == 0x37 {
        Kind::Tbnz
    } else if top & 0xfc == 0x14 {
        Kind::B
    } else if top & 0x7f == 0x2a {
        Kind::Mov
    } else if top & 0x7f == 0x71 || top & 0x7f == 0x6b {
        Kind::Subs
    } else if top & 0x7f == 0x11 || top & 0x7f == 0x0b {
        Kind::Add
    } else if top & 0x7f == 0x51 || top & 0x7f == 0x4b {
        Kind::Sub
    } else if top == 0x18 || top == 0x58 {
        Kind::Ldr // literal
    } else {
        Kind::Unknown
    }
}

impl Insn {
    pub(crate) fn opcode(&self) -> u32 {
        self.opcode
    }

    pub(crate) fn kind(self) -> Kind {
        decode(self.opcode)
    }

    pub(crate) fn supertype(&self) -> Supertype {
        match self.kind() {
            Kind::Bl | Kind::Cbz | Kind::Cbnz | Kind::Tbnz | Kind::Tbz | Kind::Bcond | Kind::B => {
                Supertype::BranchImm
            }
            Kind::Ldr | Kind::Str | Kind::Strb | Kind::Stp => Supertype::Memory,
            _ => Supertype::General,
        }
    }

    pub(crate) fn subtype(&self) -> Subtype {
        let opcode = self.opcode;
        match self.kind() {
            Kind::Add => {
                if bit_range(opcode, 24, 28) == 0b1_0001 {
                    Subtype::Immediate
                } else {
                    Subtype::Register
                }
            }
            Kind::Ldr => {
                if ((opcode >> 22) | 0x100) == 0b11_1110_0001 && bit_range(opcode, 10, 11) == 0b10 {
                    Subtype::Register
                } else if opcode >> 31 == 1
                    || bit_range(opcode | (1 << 30), 22, 31) == 0b11_1110_0101
                {
                    Subtype::Immediate
                } else {
                    Subtype::Literal
                }
            }
            Kind::Str | Kind::Strb => {
                if bit_range(opcode, 21, 29) == 0b1_1100_0001 && bit_range(opcode, 10, 11) == 0b10 {
                    Subtype::Register
                } else {
                    Subtype::Immediate
                }
            }
            _ => Subtype::General,
        }
    }

    /// libinsn `insn::imm()`. Returns `None` where upstream throws
    /// ("failed to get imm value").
    pub(crate) fn imm(&self) -> Option<i64> {
        let opcode = self.opcode;
        let pc = self.pc;
        match self.kind() {
            Kind::Adrp => {
                let page = ((opcode & 0xff_ffff) >> 5) << 2 | bit_range(opcode, 29, 30);
                Some(
                    (pc & !0xfff) as i64 + i64::from(sign_extend(u64::from(page) << 12, 32) as i32),
                )
            }
            Kind::Adr => {
                let imm = ((opcode & 0xff_ffff) >> 5) << 2 | bit_range(opcode, 29, 30);
                Some(pc as i64 + sign_extend(u64::from(imm), 21))
            }
            Kind::Add | Kind::Sub | Kind::Subs => {
                Some((bit_range(opcode, 10, 21) << (((opcode >> 22) & 1) * 12)) as i64)
            }
            Kind::Bl => {
                // Upstream quirk: sign-extends from bit 24 of imm26.
                Some(pc as i64 + (sign_extend(u64::from(opcode & 0x3ff_ffff), 25) << 2))
            }
            Kind::Cbz | Kind::Cbnz | Kind::Bcond => {
                Some(pc as i64 + (sign_extend(u64::from(bit_range(opcode, 5, 23)), 19) << 2))
            }
            Kind::Tbz | Kind::Tbnz => {
                // Upstream quirk: sign-extends from bit 12 of imm14.
                Some(pc as i64 + (sign_extend(u64::from(bit_range(opcode, 5, 18)), 13) << 2))
            }
            Kind::Movz | Kind::Movk => Some(
                (u64::from(bit_range(opcode, 5, 20)) << (bit_range(opcode, 21, 22) * 16)) as i64,
            ),
            Kind::Ldr | Kind::Str | Kind::Strb => {
                // Upstream quirk: the st_immediate check is a no-op (`if
                // (st_immediate)` tests the enum constant), and pre/post
                // indexed imm9 is not sign-extended.
                if bit_range(opcode | (1 << 22), 22, 29) == 0b1110_0101 {
                    // unsigned offset
                    Some((bit_range(opcode, 10, 21) << bit_range(opcode, 30, 31)) as i64)
                } else {
                    // pre/post indexed
                    Some(bit_range(opcode, 12, 20) as i64)
                }
            }
            Kind::B => {
                // Upstream quirk: sign-extends the shifted offset from bit 25.
                Some(pc as i64 + sign_extend(u64::from(opcode & 0x3ff_ffff) << 2, 26))
            }
            _ => None,
        }
    }

    /// libinsn `insn::rd()` for the kinds the ported patchers use.
    pub(crate) fn rd(&self) -> Option<u8> {
        match self.kind() {
            Kind::Subs
            | Kind::Adrp
            | Kind::Adr
            | Kind::Add
            | Kind::Sub
            | Kind::Movk
            | Kind::Movz
            | Kind::Mov
            | Kind::Csel => Some((self.opcode & 0x1f) as u8),
            _ => None,
        }
    }

    /// libinsn `insn::rn()` for the kinds the ported patchers use.
    pub(crate) fn rn(&self) -> Option<u8> {
        match self.kind() {
            Kind::Subs
            | Kind::Add
            | Kind::Sub
            | Kind::Ret
            | Kind::Str
            | Kind::Strb
            | Kind::Ldr
            | Kind::Stp
            | Kind::Ldp
            | Kind::Csel
            | Kind::Mov => Some(bit_range(self.opcode, 5, 9) as u8),
            _ => None,
        }
    }

    /// libinsn `insn::rt2()` (stp/ldp second register).
    pub(crate) fn rt2(&self) -> Option<u8> {
        match self.kind() {
            Kind::Stp | Kind::Ldp => Some(bit_range(self.opcode, 10, 14) as u8),
            _ => None,
        }
    }

    /// libinsn `insn::rm()` for csel/mov/subs.
    pub(crate) fn rm(&self) -> Option<u8> {
        match self.kind() {
            Kind::Csel | Kind::Mov | Kind::Subs => Some(bit_range(self.opcode, 16, 20) as u8),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Encoders (libinsn `insn::new_*`). `None` is returned where upstream's
// `retassure` range checks fail.
// ---------------------------------------------------------------------------

/// libinsn `new_general_adr`: `adr rd, imm` at `pc`.
pub(crate) fn new_general_adr(pc: u64, imm: i64, rd: u8) -> Option<u32> {
    let pc = pc as i64;
    let delta = imm.wrapping_sub(pc);
    if delta.unsigned_abs() >= (1 << 20) {
        return None;
    }
    let delta = delta as u64;
    Some(
        0b10000 << 24
            | u32::from(rd & 0b11111)
            | ((delta as u32 & 0b11) << 29)
            | ((bit_range(delta as u32, 2, 20)) << 5),
    )
}

/// libinsn `new_general_adrp`: `adrp rd, imm` at `pc`; `imm` must be page
/// aligned and within 32 bits of the instruction's page.
pub(crate) fn new_general_adrp(pc: u64, imm: i64, rd: u8) -> Option<u32> {
    if imm & 0xfff != 0 {
        return None;
    }
    let pc_page = (pc & !0xfff) as i64;
    let delta = imm.wrapping_sub(pc_page);
    if delta.unsigned_abs() >= (1 << 32) {
        return None;
    }
    let pages = (delta >> 12) as u64;
    Some(
        0b1001_0000 << 24
            | u32::from(rd & 0b11111)
            | ((pages as u32 & 0b11) << 29)
            | ((pages as u32 >> 2 & 0x7_ffff) << 5),
    )
}

/// libinsn `new_immediate_add`: `add rd, rn, #imm` (64-bit, no shift).
pub(crate) fn new_immediate_add(imm: i64, rn: u8, rd: u8) -> Option<u32> {
    if !(imm < (1 << 12) || (!imm) >> 12 == 0) {
        return None;
    }
    Some(
        0b1001_0001 << 24
            | ((imm as u32 & 0xfff) << 10)
            | (u32::from(rn & 0b11111) << 5)
            | u32::from(rd & 0b11111),
    )
}

/// libinsn `new_immediate_b`: `b imm` at `pc`. Upstream only checks
/// 4-byte alignment; out-of-range displacements silently wrap.
pub(crate) fn new_immediate_b(pc: u64, imm: i64) -> Option<u32> {
    let delta = imm.wrapping_sub(pc as i64);
    if delta & 0b11 != 0 {
        return None;
    }
    Some(0b00_0101 << 26 | ((delta >> 2) as u32 & 0x3ff_ffff))
}

/// libinsn `new_immediate_movz`: `movz rd, #imm, lsl #lsl` (64-bit).
pub(crate) fn new_immediate_movz(imm: i64, rd: u8, lsl: u8) -> Option<u32> {
    let hw: u32 = match lsl {
        0 => 0,
        16 => 1,
        32 => 2,
        48 => 3,
        _ => return None,
    };
    Some(
        1 << 31
            | 0b1010_0101 << 23
            | hw << 21
            | ((imm as u32 & 0xffff) << 5)
            | u32::from(rd & 0b11111),
    )
}

/// libinsn `new_immediate_strb_unsigned`: `strb rt, [rn, #imm]`.
pub(crate) fn new_immediate_strb_unsigned(imm: i64, rn: u8, rt: u8) -> u32 {
    0b00_1110_0100 << 22
        | ((imm as u32 & 0xfff) << 10)
        | (u32::from(rn & 0b11111) << 5)
        | u32::from(rt & 0b11111)
}

/// libinsn `new_register_mov` with the default `rn = 0x1f`: `mov rd, rm`.
pub(crate) fn new_register_mov(rd: u8, rm: u8) -> u32 {
    0b1010_1010 << 24 | (u32::from(rm & 0b11111) << 16) | (0b11111 << 5) | u32::from(rd & 0b11111)
}

/// libinsn `new_general_nop`.
pub(crate) fn new_general_nop() -> u32 {
    0xd503_201f
}

// ---------------------------------------------------------------------------
// Patchfinder64: the vmem/finder layer over a single RWX image segment.
// ---------------------------------------------------------------------------

/// A cursor into the image, kept as a file offset; `loc()` converts to the
/// virtual addresses the upstream algorithms operate on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cursor {
    off: usize,
}

pub(crate) struct Patchfinder64<'a> {
    image: &'a [u8],
    base: u64,
}

impl<'a> Patchfinder64<'a> {
    pub(crate) fn new(image: &'a [u8], base: u64) -> Self {
        Self { image, base }
    }

    /// vmem's `operator=(loc_t)`: location 0 maps to offset 0 (upstream
    /// quirk — `pos == 0` selects the segment start instead of failing).
    pub(crate) fn cursor_at(&self, loc: u64) -> Option<Cursor> {
        if loc == 0 {
            return Some(Cursor { off: 0 });
        }
        let off = usize::try_from(loc.checked_sub(self.base)?).ok()?;
        (off < self.image.len()).then_some(Cursor { off })
    }

    pub(crate) fn loc(&self, cursor: Cursor) -> u64 {
        self.base + cursor.off as u64
    }

    /// Instruction at the cursor; `None` when the word is out of bounds
    /// (vmem's `value()` assure).
    pub(crate) fn insn(&self, cursor: Cursor) -> Option<Insn> {
        let word = self.image.get(cursor.off..cursor.off + 4)?;
        Some(Insn {
            opcode: u32::from_le_bytes(word.try_into().expect("four-byte read")),
            pc: self.loc(cursor),
        })
    }

    /// vmem's `operator++`. On overflow upstream throws with the offset
    /// already advanced; no ported finder observes that state, so the cursor
    /// is left unmodified here.
    pub(crate) fn next(&self, cursor: &mut Cursor) -> Option<Insn> {
        let off = cursor.off + 4;
        if off + 4 >= self.image.len() {
            return None;
        }
        cursor.off = off;
        self.insn(*cursor)
    }

    /// vmem's `operator--`: fails (leaving the cursor in place) below
    /// offset 4.
    pub(crate) fn prev(&self, cursor: &mut Cursor) -> Option<Insn> {
        if cursor.off < 4 {
            return None;
        }
        cursor.off -= 4;
        self.insn(*cursor)
    }

    /// vmem's `operator+`/`operator-`: the instruction `n` steps away without
    /// moving the cursor.
    pub(crate) fn at(&self, cursor: Cursor, n: i32) -> Option<Insn> {
        let off = cursor.off.checked_add_signed((n as isize) * 4)?;
        self.insn(Cursor { off })
    }

    /// `vmem::memmem`: raw byte search over the image, optionally starting at
    /// `start` (0 = from the beginning). Returns the virtual address.
    pub(crate) fn memmem(&self, needle: &[u8], start: u64) -> Option<u64> {
        let start_off = if start == 0 {
            0
        } else {
            usize::try_from(start.checked_sub(self.base)?).ok()?
        };
        let haystack = self.image.get(start_off..)?;
        let found = haystack
            .windows(needle.len())
            .position(|window| window == needle)?;
        Some(self.base + (start_off + found) as u64)
    }

    /// `vmem::memstr`: `memmem` without the NUL terminator.
    pub(crate) fn memstr(&self, needle: &[u8]) -> Option<u64> {
        self.memmem(needle, 0)
    }

    /// `patchfinder64::findstr`: `memmem`, including the NUL terminator when
    /// `null_terminated` is set.
    pub(crate) fn findstr(&self, needle: &[u8], null_terminated: bool, start: u64) -> Option<u64> {
        if null_terminated {
            let mut owned = needle.to_vec();
            owned.push(0);
            self.memmem(&owned, start)
        } else {
            self.memmem(needle, start)
        }
    }

    /// `vmem::deref`: 8-byte little-endian read at a virtual address.
    pub(crate) fn deref(&self, loc: u64) -> Option<u64> {
        let off = usize::try_from(loc.checked_sub(self.base)?).ok()?;
        let bytes = self.image.get(off..off + 8)?;
        Some(u64::from_le_bytes(
            bytes.try_into().expect("eight-byte read"),
        ))
    }

    /// `vmem::memoryForLoc`: the bytes at a virtual address, or `None` when
    /// the range is not fully inside the image (upstream throws).
    pub(crate) fn read_at(&self, loc: u64, len: usize) -> Option<&'a [u8]> {
        let off = usize::try_from(loc.checked_sub(self.base)?).ok()?;
        self.image.get(off..off.checked_add(len)?)
    }

    /// `patchfinder64::find_bof`: walk back from `pos` to the function's
    /// frame-setup `stp x29, x30, [sp, ...]`, skipping any preceding stp, an
    /// optional `sub sp, sp, ...`, and an optional `pacibsp`. With
    /// `may_lack_prologue`, a `ret` ends the search at the next instruction.
    pub(crate) fn find_bof(&self, pos: u64, may_lack_prologue: bool) -> Option<u64> {
        let mut cur = self.cursor_at(pos)?;
        loop {
            let insn = self.insn(cur)?;
            if insn.kind() == Kind::Stp && insn.rt2() == Some(30) && insn.rn() == Some(31) {
                break;
            }
            let prev = self.prev(&mut cur)?;
            if prev.kind() == Kind::Ret && may_lack_prologue {
                return Some(self.loc(cur) + 4);
            }
        }
        // Skip earlier stp instructions (pre-indexed frame pairs). On
        // upstream's out-of-range throw the catch swallows it and the
        // forward step is skipped; the next() here failing does the same.
        loop {
            match self.prev(&mut cur) {
                Some(insn) if insn.kind() == Kind::Stp => {}
                Some(_) => {
                    let _ = self.next(&mut cur);
                    break;
                }
                None => break,
            }
        }
        // Optional `sub sp, sp, ...` before the frame setup.
        if let Some(insn) = self.prev(&mut cur)
            && !(insn.kind() == Kind::Sub && insn.rd() == Some(31) && insn.rn() == Some(31))
        {
            let _ = self.next(&mut cur);
        }
        // Optional `pacibsp`.
        if let Some(insn) = self.prev(&mut cur)
            && insn.kind() != Kind::Pacibsp
        {
            let _ = self.next(&mut cur);
        }
        Some(self.loc(cur))
    }

    /// `patchfinder64::find_literal_ref`: the first instruction (from
    /// `start`) computing the address `pos` — an `adr`, an `adrp`+`add` or
    /// `adrp`+load/store pair (matched at the second instruction), or a
    /// `movz`/`movk` chain (matched at the final movk).
    pub(crate) fn find_literal_ref(
        &self,
        pos: u64,
        mut ignore_times: i64,
        start: u64,
    ) -> Option<u64> {
        let mut cur = self.cursor_at(start)?;
        loop {
            let insn = self.insn(cur)?;
            match insn.kind() {
                Kind::Adr => {
                    if insn.imm()? as u64 == pos {
                        if ignore_times > 0 {
                            ignore_times -= 1;
                        } else {
                            return Some(self.loc(cur));
                        }
                    }
                }
                Kind::Adrp => {
                    let rd = insn.rd()?;
                    let imm = insn.imm()?;
                    let mut iter = cur;
                    for _ in 0..10 {
                        // Upstream quirk: an out-of-range step here aborts
                        // the whole search, not just this chain.
                        let next = self.next(&mut iter)?;
                        // The add and load/store forms share the same body
                        // upstream.
                        let computes_address = (next.kind() == Kind::Add
                            || (next.supertype() == Supertype::Memory
                                && next.subtype() == Subtype::Immediate))
                            && next.rn() == Some(rd);
                        if computes_address {
                            if (imm as u64).wrapping_add(next.imm()? as u64) == pos {
                                if ignore_times > 0 {
                                    ignore_times -= 1;
                                    break;
                                }
                                return Some(self.loc(iter));
                            }
                        } else if matches!(next.kind(), Kind::Adr | Kind::Adrp)
                            && next.rd() == Some(rd)
                        {
                            break; // rd gets overwritten
                        }
                    }
                }
                Kind::Movz => {
                    let rd = insn.rd()?;
                    let mut imm = insn.imm()? as u64;
                    if imm == pos {
                        // Upstream `continue`s the outer loop here, skipping
                        // the movk chain walk; falling out of the match runs
                        // the loop-increment `next` below, which is the same.
                        if ignore_times > 0 {
                            ignore_times -= 1;
                        } else {
                            return Some(self.loc(cur));
                        }
                    } else {
                        let mut iter = cur;
                        'chain: for _ in 0..10 {
                            self.next(&mut iter)?;
                            loop {
                                let next = self.insn(iter)?;
                                if next.kind() == Kind::Movk && next.rd() == Some(rd) {
                                    imm |= next.imm()? as u64;
                                    if imm == pos {
                                        if ignore_times > 0 {
                                            ignore_times -= 1;
                                            break 'chain;
                                        }
                                        return Some(self.loc(iter));
                                    }
                                    break;
                                }
                                if next.kind() == Kind::Movz && next.rd() == Some(rd) {
                                    break 'chain;
                                }
                                if next.kind() == Kind::B {
                                    let target = next.imm()? as u64;
                                    if self.loc(iter) == target {
                                        break 'chain; // `b .` self-loop
                                    }
                                    match self.cursor_at(target) {
                                        Some(redirect) => {
                                            iter = redirect;
                                            continue;
                                        }
                                        None => break 'chain,
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
            self.next(&mut cur)?;
        }
    }

    /// `patchfinder64::find_call_ref`: the `ignore_times + 1`-th `bl` to
    /// `pos` starting at `start`.
    pub(crate) fn find_call_ref(&self, pos: u64, mut ignore_times: i64, start: u64) -> Option<u64> {
        let mut cur = self.cursor_at(start)?;
        // Upstream checks the instruction at `start` before scanning forward.
        let mut have_bl = self.insn(cur)?.kind() == Kind::Bl;
        loop {
            if !have_bl {
                loop {
                    if self.next(&mut cur)?.kind() == Kind::Bl {
                        break;
                    }
                }
            }
            have_bl = false;
            let insn = self.insn(cur)?;
            if insn.imm()? as u64 == pos {
                ignore_times -= 1;
                if ignore_times < 0 {
                    return Some(self.loc(cur));
                }
            }
        }
    }

    /// `patchfinder64::find_branch_ref`: an immediate branch targeting `pos`.
    /// `limit` bounds the scan in bytes; 0 scans forward without a limit.
    /// Upstream quirk: only non-branch instructions spend the limit.
    pub(crate) fn find_branch_ref(
        &self,
        pos: u64,
        limit: i64,
        mut ignore_times: i64,
        start: u64,
    ) -> Option<u64> {
        if limit == 0 {
            let mut cur = self.cursor_at(start)?;
            loop {
                let insn = self.insn(cur)?;
                if insn.supertype() == Supertype::BranchImm && insn.imm()? as u64 == pos {
                    if ignore_times <= 0 {
                        return Some(self.loc(cur));
                    }
                    ignore_times -= 1;
                }
                self.next(&mut cur)?;
            }
        }
        let mut cur = self.cursor_at(if start == 0 { pos } else { start })?;
        let negative = limit < 0;
        let mut limit = limit;
        loop {
            let insn = loop {
                let insn = if negative {
                    self.prev(&mut cur)?
                } else {
                    self.next(&mut cur)?
                };
                if insn.supertype() == Supertype::BranchImm {
                    break insn;
                }
                // retassure(limit < 0) / retassure(limit > 0): the limit is
                // only spent on non-branch instructions (upstream quirk).
                limit += if negative { 4 } else { -4 };
                if limit == 0 || (limit < 0) != negative {
                    return None;
                }
            };
            if insn.imm()? as u64 == pos {
                if ignore_times <= 0 {
                    return Some(self.loc(cur));
                }
                ignore_times -= 1;
            }
        }
    }
}
