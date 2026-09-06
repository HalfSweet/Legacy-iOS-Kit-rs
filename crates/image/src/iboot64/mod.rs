//! 64-bit iBoot patcher, a Rust port of tihmstar's libpatchfinder
//! `ibootpatchfinder64` (ibootpatchfinder64.cpp factory,
//! ibootpatchfinder64_base.cpp, and the per-version subclasses
//! ibootpatchfinder64_iOS{7,9,10,12,13,14,15,16}), driven the way
//! libipatcher's `iBoot64Patch` drives it: always the sigcheck patch, and
//! when the image has a kernel load routine also debug-enabled, boot-args
//! (only when given), unlock-nvram, and freshnonce.
//!
//! Operates on decrypted, headerless arm64 iBoot/iBSS/iBEC images (the raw
//! bytes libipatcher's `patchfile64` produces after IM4P decryption and
//! decompression). Where the C++ collects `patch{_location, bytes}` records
//! and libipatcher applies them at `location - find_base()` file offsets at
//! the very end, the methods here write in place at `location - base` and
//! record every write as an [`Iboot64Patch`]. For the libipatcher call order
//! the result is identical: no patch writes over a byte range a later patch
//! scans for (verified patch-by-patch while porting), and the fallback
//! paths (iOS 7 sigcheck, iOS 14.5 boot-args) stage their writes so a failed
//! first strategy leaves the buffer untouched, like upstream's discarded
//! patch vector.
//!
//! Ported upstream quirks, deliberately:
//!
//! - Factory validation order and checks: size, `iBoot` at 0x280, magic at
//!   offset 0, version via `atoi` at 0x286, then dispatch. The iOS 14 class
//!   (and newer, by inheritance) reads the base address from 0x300 instead
//!   of 0x318.
//! - `get_sigcheck_patch` is `get_sigcheck_img4_patch` (upstream's IMG3
//!   fallback is `FAIL_UNIMPLEMENTED` for 64-bit and only rethrows).
//! - iOS 7 retries a failed multi-strb sigcheck with the callback strategy;
//!   iOS 10 falls back from the second to the first caller of the image
//!   loader; iOS 14 boot-args try the base method before the 14.5 method.
//! - The boot-args string longer than the *pre-iOS-13* default is relocated
//!   onto the "Reliance on this certificate" text (`CERT_STR` "Apple Inc.1"),
//!   even when the found default was the shorter iOS 13 variant.
//! - The iOS 14.5 boot-args method locates the default string with
//!   `memstr("rd=md0")` (no NUL, so a longer "rd=md0 ..." string also
//!   matches), unconditionalizes the branch before its reference, and
//!   relocates onto "setpicture optmask" or the kernelcache path string.
//! - The iOS 14.5 method's `findnops` fallback is dead upstream (its
//!   `findstr` throws when both relocation strings are missing, so the
//!   `if (!cert_str_loc)` check never fires). Because the finders here
//!   return `Option`, the fallback is live — this matches the evident
//!   intent of the upstream code and is documented as a deviation.
//! - `findnops` drops nop ranges past the end of code (everything beyond
//!   the function prologue preceding the "Apple Mobile Device" string).
//!
//! iBoot-10000 and newer (iOS 17) is rejected with
//! [`Iboot64PatchError::UnsupportedVersion`]: the devices this crate targets
//! max out at iOS 16, so the iOS 17 subclass is not ported.

mod patchfinder64;

use thiserror::Error;
use tracing::{debug, info};

use patchfinder64::{
    Insn, Kind, Patchfinder64, Supertype, new_general_adr, new_general_adrp, new_general_nop,
    new_immediate_add, new_immediate_b, new_immediate_movz, new_immediate_strb_unsigned,
    new_register_mov,
};

const IBOOT_VERS_STR_OFFSET: usize = 0x280;
const IBOOT_BASE_OFFSET: usize = 0x318;
const IBOOT_14_BASE_OFFSET: usize = 0x300;

const KERNELCACHE_PREP_STRING: &[u8] = b"__PAGEZERO";
const RECOVERY_CONSOLE_STRING: &[u8] = b"Entering recovery mode, starting command prompt";
const DEFAULT_BOOTARGS_STR: &[u8] = b"rd=md0 nand-enable-reformat=1 -progress";
const DEFAULT_BOOTARGS_STR_13: &[u8] = b"rd=md0 -progress -restore";
const DEFAULT_BOOTARGS_STR_14_5: &[u8] = b"rd=md0";
/// Substring of the "Reliance on this certificate ..." disclaimer whose
/// storage the long-boot-args relocation overwrites.
const CERT_STR: &[u8] = b"Apple Inc.1";
const KERNELCACHE_PATH_STRING: &[u8] = b"/System/Library/Caches/com.apple.kernelcaches/kernelcache";
const SETPICTURE_OPTMASK_STRING: &[u8] = b"setpicture optmask";
const APPLE_MOBILE_DEVICE_STRING: &[u8] = b"Apple Mobile Device";

const PATCH_SIGCHECK: &str = "sigcheck";
const PATCH_DEBUG_ENABLED: &str = "debug-enabled";
const PATCH_BOOT_ARGS: &str = "boot-args";
const PATCH_UNLOCK_NVRAM: &str = "unlock-nvram";
const PATCH_FRESHNONCE: &str = "freshnonce";

/// `movz x0, #0; ret`, the blacklist-stub write of the unlock-nvram patch.
const MOVZ_X0_0_RET: [u8; 8] = [0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6];
/// `movz x0, #1`, written over the second call after the "debug-enabled"
/// reference.
const MOVZ_X0_1: [u8; 4] = [0x20, 0x00, 0x80, 0xd2];

/// The libpatchfinder subclass selected for an image, mirroring the
/// `make_ibootpatchfinder64` dispatch chain. Ordering matters: later classes
/// inherit the behavior of the earlier ones they derive from.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Class {
    Base,
    Ios7,
    Ios9,
    Ios10,
    Ios12,
    Ios13,
    Ios14,
    Ios15,
    Ios16,
}

/// A single in-place write produced by a patch method: `bytes` written at
/// file offset `offset` (`location - base` in upstream terms).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Iboot64Patch {
    patch: &'static str,
    offset: usize,
    bytes: Vec<u8>,
}

impl Iboot64Patch {
    /// Name of the patch method that produced the write (e.g. `"sigcheck"`).
    pub fn patch(&self) -> &'static str {
        self.patch
    }

    /// File offset the bytes were written to.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The written bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Record of a [`patch_iboot64_with_report`] run: the detected image
/// properties plus every applied write, in application order.
#[derive(Clone, Debug)]
pub struct Iboot64PatchReport {
    version: u32,
    base_address: u64,
    patches: Vec<Iboot64Patch>,
}

impl Iboot64PatchReport {
    /// The parsed iBoot version (e.g. 6603 for iBoot-6603).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The image load address from the iBoot header.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Every write the patch set applied, in the order they were applied.
    pub fn patches(&self) -> &[Iboot64Patch] {
        &self.patches
    }
}

/// A pending in-place write, addressed by virtual address like upstream's
/// `patch{_location, bytes}`.
struct Write {
    loc: u64,
    bytes: Vec<u8>,
}

impl Write {
    fn insn(loc: u64, opcode: u32) -> Self {
        Self {
            loc,
            bytes: opcode.to_le_bytes().to_vec(),
        }
    }

    fn bytes(loc: u64, bytes: &[u8]) -> Self {
        Self {
            loc,
            bytes: bytes.to_vec(),
        }
    }
}

fn not_found(patch: &'static str, reason: &'static str) -> Iboot64PatchError {
    Iboot64PatchError::PatternNotFound { patch, reason }
}

/// C `atoi`: optional whitespace and sign, then decimal digits; 0 when the
/// text does not start a number.
fn atoi(data: &[u8]) -> u32 {
    let mut index = 0;
    while index < data.len() && matches!(data[index], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        index += 1;
    }
    let mut negative = false;
    if index < data.len() && (data[index] == b'+' || data[index] == b'-') {
        negative = data[index] == b'-';
        index += 1;
    }
    let mut value = 0i64;
    while index < data.len() && data[index].is_ascii_digit() {
        value = value
            .wrapping_mul(10)
            .wrapping_add(i64::from(data[index] - b'0'));
        index += 1;
    }
    (if negative { -value } else { value }) as u32
}

/// The 64-bit iBoot patcher: a mutable decrypted image plus the detected
/// version, base address, and class-dispatched patch behavior.
pub struct IBoot64<'a> {
    buf: &'a mut [u8],
    version: u32,
    base: u64,
    class: Class,
    /// findnops nop-range cache, populated on first use like upstream's
    /// `_unusedNops`.
    unused_nops: Option<Vec<(u64, u64)>>,
    applied: Vec<Iboot64Patch>,
}

impl<'a> IBoot64<'a> {
    /// Validate the image and select the patch behavior, mirroring
    /// `make_ibootpatchfinder64` (plus the subclass constructors' base
    /// address read).
    pub fn new(buf: &'a mut [u8]) -> Result<Self, Iboot64PatchError> {
        if buf.len() <= 0x1000 {
            return Err(Iboot64PatchError::ImageTooSmall);
        }
        if &buf[IBOOT_VERS_STR_OFFSET..IBOOT_VERS_STR_OFFSET + 5] != b"iBoot" {
            return Err(Iboot64PatchError::MissingVersionString);
        }
        // Index into the buffer as a u32 array, like upstream's casts.
        let word = |index: usize| {
            u32::from_le_bytes(buf[index * 4..index * 4 + 4].try_into().expect("word"))
        };
        let magic_ok = word(0) == 0x9000_0000
            || (word(0) == 0x1400_0001 && word(4) == 0x9000_0000)
            || (word(0) == 0xd53c_1102 && word(3) == 0xd51c_1102);
        if !magic_ok {
            return Err(Iboot64PatchError::BadMagic);
        }
        let version = atoi(&buf[IBOOT_VERS_STR_OFFSET + 6..]);
        if version == 0 {
            return Err(Iboot64PatchError::VersionNotFound);
        }
        let class = match version {
            10000.. => return Err(Iboot64PatchError::UnsupportedVersion(version)),
            8400.. => Class::Ios16,
            7400.. => Class::Ios15,
            6603.. => Class::Ios14,
            5540.. => Class::Ios13,
            4510.. => Class::Ios12,
            3300.. => Class::Ios10,
            2800.. => Class::Ios9,
            1940.. => Class::Ios7,
            _ => Class::Base,
        };
        // The iOS 14 subclass constructor re-reads the base from 0x300; the
        // iOS 15/16 subclasses inherit its constructor.
        let base_offset = if class >= Class::Ios14 {
            IBOOT_14_BASE_OFFSET
        } else {
            IBOOT_BASE_OFFSET
        };
        let base = u64::from_le_bytes(
            buf[base_offset..base_offset + 8]
                .try_into()
                .expect("base address field"),
        );
        debug!(version, base, class = ?class, "detected 64-bit iBoot");
        Ok(Self {
            buf,
            version,
            base,
            class,
            unused_nops: None,
            applied: Vec::new(),
        })
    }

    /// The parsed iBoot version (e.g. 6603 for iBoot-6603).
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The image load address (`find_base` upstream).
    pub const fn base_address(&self) -> u64 {
        self.base
    }

    /// True when the image loads a kernelcache (`memstr "__PAGEZERO"`).
    pub fn has_kernel_load(&self) -> bool {
        self.finder().memstr(KERNELCACHE_PREP_STRING).is_some()
    }

    /// True when the image has a recovery console.
    pub fn has_recovery_console(&self) -> bool {
        self.finder().memstr(RECOVERY_CONSOLE_STRING).is_some()
    }

    /// The writes applied so far, in application order.
    pub fn applied_patches(&self) -> &[Iboot64Patch] {
        &self.applied
    }

    fn finder(&self) -> Patchfinder64<'_> {
        Patchfinder64::new(self.buf, self.base)
    }

    /// Apply the staged writes at `loc - base`, recording each one.
    fn commit(&mut self, patch: &'static str, writes: Vec<Write>) -> Result<(), Iboot64PatchError> {
        let count = writes.len();
        for write in writes {
            let offset = write
                .loc
                .checked_sub(self.base)
                .and_then(|off| usize::try_from(off).ok())
                .filter(|off| off + write.bytes.len() <= self.buf.len())
                .ok_or(Iboot64PatchError::WriteOutOfBounds {
                    patch,
                    loc: write.loc,
                })?;
            self.buf[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
            self.applied.push(Iboot64Patch {
                patch,
                offset,
                bytes: write.bytes,
            });
        }
        info!(patch, writes = count, "iBoot patch applied");
        Ok(())
    }

    /// `ibootpatchfinder64::findnops`: locate a run of at least `nop_count`
    /// words that are `nop_opcode` or zero. The first scan caches the range
    /// list and drops every range starting past the end of code (the
    /// function prologue found walking back from the "Apple Mobile Device"
    /// string); `use_nops` consumes the chosen range.
    fn findnops(&mut self, nop_count: u16, use_nops: bool, nop_opcode: u32) -> Option<u64> {
        if self.unused_nops.is_none() {
            let mut ranges = Vec::new();
            {
                let finder = self.finder();
                let mut cursor = finder.cursor_at(0)?;
                let mut running: Option<u64> = None;
                while let Some(insn) = finder.next(&mut cursor) {
                    if insn.opcode() == nop_opcode || insn.opcode() == 0 {
                        if running.is_none() {
                            running = Some(finder.loc(cursor));
                        }
                    } else if let Some(start) = running.take() {
                        let size = finder.loc(cursor) - start;
                        if size >= 4 * 11 {
                            ranges.push((start, size));
                        }
                    }
                }
                let string_section = finder.findstr(APPLE_MOBILE_DEVICE_STRING, false, 0)? & !3;
                let end_of_code = finder.find_bof(string_section, true)?;
                ranges.retain(|(start, _)| *start <= end_of_code);
            }
            // The sentinel marks the list initialized even when empty.
            ranges.push((0, 0));
            self.unused_nops = Some(ranges);
        }
        let ranges = self.unused_nops.as_mut().expect("initialized above");
        let target = u64::from(nop_count) * 4;
        let mut best: Option<usize> = None;
        for (index, &(_, size)) in ranges.iter().enumerate() {
            if target <= size && best.is_none_or(|chosen| size < ranges[chosen].1) {
                best = Some(index);
            }
        }
        let best = best?;
        let (start, size) = ranges[best];
        if use_nops {
            ranges.remove(best);
            if target < size {
                ranges.push((start + target, size - target));
            }
        }
        debug!(start, size, "consuming nop space");
        Some(start)
    }

    /// `get_sigcheck_patch`: disable IM4M value validation. Dispatches to
    /// the per-class strategy (see the module docs).
    pub fn get_sigcheck_patch(&mut self) -> Result<(), Iboot64PatchError> {
        let writes = match self.class {
            Class::Base => self.sigcheck_base(),
            // iOS 7 tries the base multi-strb strategy first and falls back
            // to the callback strategy on any failure.
            Class::Ios7 => self
                .sigcheck_base()
                .or_else(|_| self.sigcheck_callback_7_9()),
            Class::Ios9 => self.sigcheck_callback_7_9(),
            Class::Ios10 | Class::Ios12 | Class::Ios13 => self.sigcheck_callback_10(),
            Class::Ios14 => self.sigcheck_ios14(),
            Class::Ios15 | Class::Ios16 => self.sigcheck_ios15(),
        }?;
        self.commit(PATCH_SIGCHECK, writes)
    }

    /// `ibootpatchfinder64_base::get_sigcheck_img4_patch`: find seven
    /// consecutive `strb` instructions (the IM4M field-by-field copies),
    /// overwrite them with `movz x1, #1` plus stores that keep the result
    /// nonzero, and redirect the trailing overwrite branch.
    fn sigcheck_base(&self) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let mut cursor = finder
            .cursor_at(0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "image start not mapped"))?;
        let stores = loop {
            loop {
                let insn = finder
                    .next(&mut cursor)
                    .ok_or_else(|| not_found(PATCH_SIGCHECK, "no seven consecutive strb found"))?;
                if insn.kind() == Kind::Strb {
                    break;
                }
            }
            let mut probe = cursor;
            let mut all_strb = true;
            for _ in 0..6 {
                match finder.next(&mut probe) {
                    Some(insn) if insn.kind() == Kind::Strb => {}
                    // An out-of-range step fails the patch upstream (the
                    // throw escapes the inner loop).
                    None => {
                        return Err(not_found(
                            PATCH_SIGCHECK,
                            "strb run cut off by the end of the image",
                        ));
                    }
                    Some(_) => {
                        all_strb = false;
                        break;
                    }
                }
            }
            if all_strb {
                break cursor;
            }
        };
        debug!(stores = finder.loc(stores), "sigcheck: found strb run");

        // The lowest store offset of the seven (upstream scans from
        // `stores - 4` forward, reading each strb immediate).
        let mut lowest_offset = u64::MAX;
        let mut probe = finder
            .cursor_at(finder.loc(stores).wrapping_sub(4))
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb run out of range"))?;
        for _ in 0..7 {
            let imm = finder
                .next(&mut probe)
                .and_then(|insn| insn.imm())
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb immediate unreadable"))?;
            if (imm as u64) < lowest_offset {
                lowest_offset = imm as u64;
            }
        }
        let rn = finder
            .insn(stores)
            .and_then(|insn| insn.rn())
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb base register unreadable"))?;

        let stores_loc = finder.loc(stores);
        let mut writes = vec![
            // movz x1, #1
            Write::insn(
                stores_loc,
                new_immediate_movz(1, 1, 0).expect("movz x1, #1 encodes"),
            ),
            Write::insn(
                stores_loc + 4,
                new_immediate_strb_unsigned(lowest_offset as i64 + 1, rn, 1),
            ),
            Write::insn(
                stores_loc + 8,
                new_immediate_strb_unsigned(lowest_offset as i64 + 3, rn, 1),
            ),
            Write::insn(
                stores_loc + 12,
                new_immediate_strb_unsigned(lowest_offset as i64 + 4, rn, 1),
            ),
            Write::insn(stores_loc + 16, new_general_nop()),
            Write::insn(stores_loc + 20, new_general_nop()),
            Write::insn(stores_loc + 24, new_general_nop()),
        ];

        let mut cursor = finder
            .cursor_at(stores_loc + 28)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb run tail out of range"))?;
        // May be along the lines of `mov x11, x25` / `ldr x10, [sp, #0x80]`.
        if finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb run tail out of range"))?
            .kind()
            != Kind::B
        {
            finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb run tail out of range"))?;
        }
        let insn = finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "strb run tail out of range"))?;
        if insn.kind() != Kind::B {
            return Err(not_found(PATCH_SIGCHECK, "unimplemented sigpatch case"));
        }
        let overwrite_branch = finder.loc(cursor);
        // The failure of the backward branch-ref search falls back to the
        // overwrite branch itself (upstream catches the throw).
        let stores_ref = finder
            .find_branch_ref(stores_loc, -0x300, 0, 0)
            .unwrap_or(overwrite_branch);
        writes.push(Write::insn(
            overwrite_branch,
            new_immediate_b(overwrite_branch, (stores_ref + 4) as i64)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "overwrite branch out of range"))?,
        ));
        Ok(writes)
    }

    /// The iOS 7 fallback / iOS 9 callback strategy: find the IMG4 string
    /// reference, walk two call levels up, and find the verification
    /// callback passed in x2; patch the branch in its epilogue to
    /// `movz x0, #0`.
    fn sigcheck_callback_7_9(&self) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let img4str = finder
            .findstr(b"IMG4", true, 0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "\"IMG4\" string not found"))?;
        let img4strref = finder
            .find_literal_ref(img4str, 0, 0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "no reference to the \"IMG4\" string"))?;
        let f1top = finder
            .find_bof(img4strref, false)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "image loader prologue not found"))?;
        let f1topref = finder
            .find_call_ref(f1top, 1, 0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "image loader caller not found"))?;
        let f2top = finder
            .find_bof(f1topref, false)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "caller prologue not found"))?;
        let callback = self.find_x2_x3_callback(&finder, f2top)?;

        let mut cursor = finder
            .cursor_at(callback)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback out of range"))?;
        loop {
            if finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback has no ret"))?
                .kind()
                == Kind::Ret
            {
                break;
            }
        }
        // Skip the ldp epilogue; one sub, then the branch to overwrite.
        while finder
            .prev(&mut cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?
            .kind()
            == Kind::Ldp
        {}
        if finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?
            .kind()
            != Kind::Sub
        {
            return Err(not_found(
                PATCH_SIGCHECK,
                "expected sub in the callback epilogue",
            ));
        }
        if finder
            .prev(&mut cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?
            .supertype()
            != Supertype::BranchImm
        {
            return Err(not_found(
                PATCH_SIGCHECK,
                "expected a branch before the callback epilogue",
            ));
        }
        let branch = finder.loc(cursor);
        debug!(branch, "sigcheck: patching callback branch");
        Ok(vec![Write::insn(
            branch,
            new_immediate_movz(0, 0, 0).expect("movz x0, #0 encodes"),
        )])
    }

    /// The iOS 10-13 callback strategy: like the iOS 9 one, but the callback
    /// is read from the pointer the `adr x2` targets, the second image
    /// loader caller falls back to the first, and the epilogue walk accepts
    /// an `add sp, sp` / `mov x0, ...` / `sub sp, ...` shapes.
    fn sigcheck_callback_10(&self) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let img4str = finder
            .findstr(b"IMG4", true, 0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "\"IMG4\" string not found"))?;
        let img4strref = finder
            .find_literal_ref(img4str, 0, 0)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "no reference to the \"IMG4\" string"))?;
        let f1top = finder
            .find_bof(img4strref, false)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "image loader prologue not found"))?;
        // Upstream quirk: "don't ignore i guess?" — the second caller, then
        // the first.
        let f1topref = finder
            .find_call_ref(f1top, 1, 0)
            .or_else(|| finder.find_call_ref(f1top, 0, 0))
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "image loader caller not found"))?;
        let f2top = finder
            .find_bof(f1topref, false)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "caller prologue not found"))?;

        let mut cursor = finder
            .cursor_at(f2top)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "caller out of range"))?;
        let (mut adr_x2, mut adr_x3) = (None, None);
        loop {
            let insn = finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback setup not found"))?;
            match insn.kind() {
                Kind::Adr if insn.rd() == Some(2) => adr_x2 = Some(cursor),
                Kind::Adr if insn.rd() == Some(3) => adr_x3 = Some(cursor),
                Kind::Bl => {
                    if adr_x2.is_some() && adr_x3.is_some() {
                        break;
                    }
                    adr_x2 = None;
                    adr_x3 = None;
                }
                _ => {}
            }
        }
        let adr_x2 = adr_x2.ok_or_else(|| not_found(PATCH_SIGCHECK, "no adr x2 found"))?;
        let callback_ptr = finder
            .insn(adr_x2)
            .and_then(|insn| insn.imm())
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback reference unreadable"))?;
        let callback = finder
            .deref(callback_ptr as u64)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback pointer out of range"))?;

        let mut cursor = finder
            .cursor_at(callback)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback out of range"))?;
        loop {
            if finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback has no ret"))?
                .kind()
                == Kind::Ret
            {
                break;
            }
        }
        let prev = finder
            .prev(&mut cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?;
        if prev.kind() == Kind::Add {
            // `add sp, sp, #something`
            if prev.rd() != Some(31) || prev.rn() != Some(31) {
                return Err(not_found(
                    PATCH_SIGCHECK,
                    "expected add sp, sp in the callback epilogue",
                ));
            }
        } else if prev.kind() != Kind::Ldp {
            return Err(not_found(
                PATCH_SIGCHECK,
                "expected ldp in the callback epilogue",
            ));
        }
        while finder
            .prev(&mut cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?
            .kind()
            == Kind::Ldp
        {}
        let insn = finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?;
        // Are we writing to x0 from some register?
        if insn.kind() != Kind::Mov || insn.rd() != Some(0) {
            if insn.kind() == Kind::Sub && insn.rd() == Some(31) {
                finder
                    .prev(&mut cursor)
                    .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?;
            }
            // If not, we must be at the stack-check branch.
            if finder
                .insn(cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback epilogue out of range"))?
                .supertype()
                != Supertype::BranchImm
            {
                return Err(not_found(
                    PATCH_SIGCHECK,
                    "expected a branch before the callback epilogue",
                ));
            }
        }
        let branch = finder.loc(cursor);
        debug!(branch, "sigcheck: patching callback branch");
        Ok(vec![Write::insn(
            branch,
            new_immediate_movz(0, 0, 0).expect("movz x0, #0 encodes"),
        )])
    }

    /// The shared x2/x3 callback hunt of the iOS 7/9 strategy: from `f2top`,
    /// track adr/adrp/add writes to x2 and x3; the first `bl` with both set
    /// ends the search with x2 as the callback.
    fn find_x2_x3_callback(
        &self,
        finder: &Patchfinder64<'_>,
        f2top: u64,
    ) -> Result<u64, Iboot64PatchError> {
        let mut cursor = finder
            .cursor_at(f2top)
            .ok_or_else(|| not_found(PATCH_SIGCHECK, "caller out of range"))?;
        let (mut val_x2, mut val_x3) = (0u64, 0u64);
        loop {
            let insn = finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback setup not found"))?;
            match insn.kind() {
                Kind::Adr | Kind::Adrp => {
                    let imm = insn
                        .imm()
                        .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback address unreadable"))?;
                    match insn.rd() {
                        Some(2) => val_x2 = imm as u64,
                        Some(3) => val_x3 = imm as u64,
                        _ => {}
                    }
                }
                Kind::Add => {
                    let imm = insn
                        .imm()
                        .ok_or_else(|| not_found(PATCH_SIGCHECK, "callback address unreadable"))?;
                    match insn.rd() {
                        Some(2) => val_x2 = val_x2.wrapping_add(imm as u64),
                        Some(3) => val_x3 = val_x3.wrapping_add(imm as u64),
                        _ => {}
                    }
                }
                Kind::Bl => {
                    if val_x2 != 0 && val_x3 != 0 {
                        return Ok(val_x2);
                    }
                    val_x2 = 0;
                    val_x3 = 0;
                }
                _ => {}
            }
        }
    }

    /// The iOS 14 strategy: find the `cmp #1; b; ldr [x, #0x10]; cmp #4; b;
    /// cmp #2; b; cmp #1; b` sequence, then walk to the function end and
    /// overwrite the first `mov x0, ...` or branch before it with
    /// `movz x0, #0`. (`cmp` matches any `subs`, like upstream's enum
    /// alias.)
    fn sigcheck_ios14(&self) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let miss = || not_found(PATCH_SIGCHECK, "cmp/branch chain not found");
        let mut cursor = finder.cursor_at(0).ok_or_else(miss)?;
        loop {
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(1) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Ldr || insn.imm() != Some(0x10) {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(4) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(2) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(1) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            break;
        }
        loop {
            if finder.next(&mut cursor).ok_or_else(miss)?.kind() == Kind::Ret {
                break;
            }
        }
        loop {
            let insn = finder.prev(&mut cursor).ok_or_else(miss)?;
            let is_mov_x0 = insn.kind() == Kind::Mov && insn.rd() == Some(0);
            if is_mov_x0 || insn.supertype() == Supertype::BranchImm {
                break;
            }
        }
        let overwrite = finder.loc(cursor);
        debug!(overwrite, "sigcheck: patching mov x0");
        Ok(vec![Write::insn(
            overwrite,
            new_immediate_movz(0, 0, 0).expect("movz x0, #0 encodes"),
        )])
    }

    /// The iOS 15/16 strategy: the same chain without the leading `cmp #1`,
    /// then four consecutive `ldp` before the function end, then back to the
    /// `mov x0, ...`.
    fn sigcheck_ios15(&self) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let miss = || not_found(PATCH_SIGCHECK, "ldr/cmp chain not found");
        let mut cursor = finder.cursor_at(0).ok_or_else(miss)?;
        loop {
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Ldr || insn.imm() != Some(0x10) {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(4) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(2) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            let insn = finder.next(&mut cursor).ok_or_else(miss)?;
            if insn.kind() != Kind::Subs || insn.imm() != Some(1) {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.supertype() != Supertype::BranchImm {
                continue;
            }
            break;
        }
        loop {
            loop {
                if finder.next(&mut cursor).ok_or_else(miss)?.kind() == Kind::Ldp {
                    break;
                }
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.kind() != Kind::Ldp {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.kind() != Kind::Ldp {
                continue;
            }
            if finder.next(&mut cursor).ok_or_else(miss)?.kind() != Kind::Ldp {
                continue;
            }
            finder.next(&mut cursor).ok_or_else(miss)?;
            break;
        }
        loop {
            let insn = finder.prev(&mut cursor).ok_or_else(miss)?;
            if insn.kind() == Kind::Mov && insn.rd() == Some(0) {
                break;
            }
        }
        let overwrite = finder.loc(cursor);
        debug!(overwrite, "sigcheck: patching mov x0");
        Ok(vec![Write::insn(
            overwrite,
            new_immediate_movz(0, 0, 0).expect("movz x0, #0 encodes"),
        )])
    }

    /// `ibootpatchfinder64_base::get_debug_enabled_patch`: overwrite the
    /// second `bl` after the "debug-enabled" string reference with
    /// `movz x0, #1`.
    pub fn get_debug_enabled_patch(&mut self) -> Result<(), Iboot64PatchError> {
        let writes = {
            let finder = self.finder();
            let debug_enabled = finder.findstr(b"debug-enabled", true, 0).ok_or_else(|| {
                not_found(PATCH_DEBUG_ENABLED, "\"debug-enabled\" string not found")
            })?;
            let xref = finder
                .find_literal_ref(debug_enabled, 0, 0)
                .ok_or_else(|| {
                    not_found(
                        PATCH_DEBUG_ENABLED,
                        "no reference to the \"debug-enabled\" string",
                    )
                })?;
            let mut cursor = finder
                .cursor_at(xref)
                .ok_or_else(|| not_found(PATCH_DEBUG_ENABLED, "reference out of range"))?;
            for _ in 0..2 {
                loop {
                    if finder
                        .next(&mut cursor)
                        .ok_or_else(|| not_found(PATCH_DEBUG_ENABLED, "call target not found"))?
                        .kind()
                        == Kind::Bl
                    {
                        break;
                    }
                }
            }
            debug!(
                target = finder.loc(cursor),
                "debug-enabled: forcing return 1"
            );
            vec![Write::bytes(finder.loc(cursor), &MOVZ_X0_1)]
        };
        self.commit(PATCH_DEBUG_ENABLED, writes)
    }

    /// `get_boot_arg_patch`: hardcode custom boot-args. iOS 14+ first tries
    /// the base method and falls back to the iOS 14.5 method.
    pub fn get_boot_arg_patch(&mut self, bootargs: &str) -> Result<(), Iboot64PatchError> {
        let writes = if self.class >= Class::Ios14 {
            match self.boot_arg_base(bootargs) {
                Ok(writes) => writes,
                Err(error) => {
                    debug!(%error, "old-style boot-args failed, trying the iOS 14.5 method");
                    self.boot_arg_14_5(bootargs)?
                }
            }
        } else {
            self.boot_arg_base(bootargs)?
        };
        self.commit(PATCH_BOOT_ARGS, writes)
    }

    /// `ibootpatchfinder64_base::get_boot_arg_patch`: overwrite the default
    /// boot-args string, point the csel at the stock value, and fix up the
    /// trailing adr. Strings longer than the pre-iOS-13 default are
    /// relocated onto the CERT_STR storage.
    fn boot_arg_base(&self, bootargs: &str) -> Result<Vec<Write>, Iboot64PatchError> {
        let finder = self.finder();
        let default_boot_args_str_loc = finder
            .memstr(DEFAULT_BOOTARGS_STR)
            .or_else(|| {
                debug!("DEFAULT_BOOTARGS_STR not found, trying DEFAULT_BOOTARGS_STR_13");
                finder.memstr(DEFAULT_BOOTARGS_STR_13)
            })
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "default boot-args string not found"))?;
        let default_boot_args_xref = finder
            .find_literal_ref(default_boot_args_str_loc, 0, 0)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no reference to the default boot-args"))?;
        debug!(
            default_boot_args_str_loc,
            default_boot_args_xref, "boot-args reference"
        );

        let mut writes = Vec::new();
        let mut boot_args_str_loc = default_boot_args_str_loc;
        if bootargs.len() > DEFAULT_BOOTARGS_STR.len() {
            debug!("relocating boot-args string onto the CERT_STR storage");
            let cert_str_loc = finder
                .memstr(CERT_STR)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "\"Apple Inc.1\" string not found"))?;
            boot_args_str_loc = cert_str_loc;
            let cursor = finder
                .cursor_at(default_boot_args_xref)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference out of range"))?;
            let insn = finder
                .insn(cursor)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference out of range"))?;
            let rd = insn
                .rd()
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference has no destination"))?;
            if insn.kind() == Kind::Adr {
                writes.push(Write::insn(
                    default_boot_args_xref,
                    new_general_adr(default_boot_args_xref, cert_str_loc as i64, rd)
                        .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr out of range"))?,
                ));
            } else if insn.kind() == Kind::Add
                && finder.at(cursor, -1).map(Insn::kind) == Some(Kind::Adrp)
            {
                writes.push(Write::insn(
                    default_boot_args_xref - 4,
                    new_general_adrp(
                        default_boot_args_xref - 4,
                        (cert_str_loc & !0xfff) as i64,
                        rd,
                    )
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adrp out of range"))?,
                ));
                writes.push(Write::insn(
                    default_boot_args_xref,
                    new_immediate_add((cert_str_loc & 0xfff) as i64, rd, rd)
                        .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "add out of range"))?,
                ));
            } else {
                return Err(not_found(PATCH_BOOT_ARGS, "unexpected instructions"));
            }
        }

        let mut string = bootargs.as_bytes().to_vec();
        string.push(0);
        writes.push(Write::bytes(boot_args_str_loc, &string));

        let mut cursor = finder
            .cursor_at(default_boot_args_xref)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference out of range"))?;
        let xref_rd = finder
            .insn(cursor)
            .and_then(|insn| insn.rd())
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference has no destination"))?;
        loop {
            if finder
                .next(&mut cursor)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no csel after the reference"))?
                .kind()
                == Kind::Csel
            {
                break;
            }
        }
        let csel = finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "csel out of range"))?;
        if csel.rn() != Some(xref_rd) && csel.rm() != Some(xref_rd) {
            return Err(not_found(
                PATCH_BOOT_ARGS,
                "csel does not select the boot-args register",
            ));
        }
        let csel_rd = csel
            .rd()
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "csel has no destination"))?;
        // `mov csel.rd, xref.rd`: always pick the stock-args operand.
        writes.push(Write::insn(
            finder.loc(cursor),
            new_register_mov(csel_rd, xref_rd),
        ));

        // Walk back to the nearest non-bl immediate branch, follow it, and
        // retarget the adr there (or the next one) at the new string.
        loop {
            let insn = finder
                .prev(&mut cursor)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no branch before the csel"))?;
            if insn.supertype() == Supertype::BranchImm && insn.kind() != Kind::Bl {
                break;
            }
        }
        let branch_dst = finder
            .insn(cursor)
            .and_then(|insn| insn.imm())
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target unreadable"))?;
        let mut cursor = finder
            .cursor_at(branch_dst as u64)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target out of range"))?;
        if finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target out of range"))?
            .kind()
            != Kind::Adr
        {
            loop {
                if finder
                    .next(&mut cursor)
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no adr at the branch target"))?
                    .kind()
                    == Kind::Adr
                {
                    break;
                }
            }
        }
        let insn = finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target out of range"))?;
        let rd = insn
            .rd()
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr has no destination"))?;
        writes.push(Write::insn(
            finder.loc(cursor),
            new_general_adr(finder.loc(cursor), boot_args_str_loc as i64, rd)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr out of range"))?,
        ));
        Ok(writes)
    }

    /// `ibootpatchfinder64_iOS14::get_boot_arg_patch` fallback: the iOS 14.5
    /// method. Unconditionalize the branch before the "rd=md0" reference,
    /// then point the adr (or adrp/add) in the taken block at the relocated
    /// string.
    fn boot_arg_14_5(&mut self, bootargs: &str) -> Result<Vec<Write>, Iboot64PatchError> {
        let mut writes = Vec::new();
        let (mut cursor, relocation) = {
            let finder = self.finder();
            // memstr without NUL: also matches a longer "rd=md0 ..." string.
            let default_boot_args_str_loc = finder
                .memstr(DEFAULT_BOOTARGS_STR_14_5)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "\"rd=md0\" string not found"))?;
            // Upstream quirk: no assure on the xref; a miss starts the scan
            // at the image start (vmem's loc 0), which fails on the first
            // backward step.
            let default_boot_args_xref = finder
                .find_literal_ref(default_boot_args_str_loc, 0, 0)
                .unwrap_or(0);
            let mut cursor = finder
                .cursor_at(default_boot_args_xref)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference out of range"))?;
            for _ in 0..10 {
                if finder
                    .prev(&mut cursor)
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no branch before the reference"))?
                    .supertype()
                    == Supertype::BranchImm
                {
                    break;
                }
            }
            let branch = finder
                .insn(cursor)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no branch before the reference"))?;
            if branch.supertype() != Supertype::BranchImm {
                return Err(not_found(PATCH_BOOT_ARGS, "case unimplemented"));
            }
            let branch_loc = finder.loc(cursor);
            let branch_dst = branch
                .imm()
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target unreadable"))?;
            // Always go to the "no bootarg"-case.
            writes.push(Write::insn(
                branch_loc,
                new_immediate_b(branch_loc, branch_dst)
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch out of range"))?,
            ));
            let cursor = finder
                .cursor_at(branch_dst as u64)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target out of range"))?;
            let relocation = finder
                .findstr(SETPICTURE_OPTMASK_STRING, false, 0)
                .or_else(|| finder.findstr(KERNELCACHE_PATH_STRING, true, 0));
            (cursor, relocation)
        };
        // Upstream deviation: upstream's findstr throws when both relocation
        // strings are missing, so its `if (!cert_str_loc)` findnops fallback
        // is unreachable; with Option-returning finders the fallback is live
        // here, as the upstream code evidently intends.
        let args_len = bootargs.len() + 1;
        let nop_count = (args_len / 4 + usize::from(args_len % 4 != 0)) as u16;
        let boot_args_str_loc = match relocation {
            Some(loc) => loc,
            None => self
                .findnops(nop_count, true, 0)
                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "no boot-args relocation target"))?,
        };

        let finder = self.finder();
        if finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "branch target out of range"))?
            .kind()
            != Kind::Adr
        {
            // Fallback method: find the adr/adrp computing the existing
            // empty ("-v" or "%s") args string and rewrite that.
            let mut found = false;
            for _ in 0..5 {
                loop {
                    let insn = finder.next(&mut cursor).ok_or_else(|| {
                        not_found(PATCH_BOOT_ARGS, "no adr near the branch target")
                    })?;
                    if matches!(insn.kind(), Kind::Adr | Kind::Adrp) {
                        break;
                    }
                    if insn.kind() == Kind::Ret {
                        return Err(not_found(PATCH_BOOT_ARGS, "reached end of function"));
                    }
                }
                let mut insn = finder
                    .insn(cursor)
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr out of range"))?;
                let mut empty_args_addr = insn
                    .imm()
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr immediate unreadable"))?;
                if insn.kind() == Kind::Adrp {
                    insn = finder
                        .next(&mut cursor)
                        .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adrp pair out of range"))?;
                    // Upstream also accepts a nop here but then throws on its
                    // immediate; only add actually passes.
                    if insn.kind() != Kind::Add {
                        return Err(not_found(PATCH_BOOT_ARGS, "invalid address reference"));
                    }
                    empty_args_addr =
                        empty_args_addr.wrapping_add(insn.imm().ok_or_else(|| {
                            not_found(PATCH_BOOT_ARGS, "add immediate unreadable")
                        })?);
                }
                let empty_args_addr = empty_args_addr as u64;
                // Upstream's `memoryForLoc(...) == 0` check is dead
                // (memoryForLoc throws instead of returning NULL); an
                // unmapped address simply skips the candidate.
                let Some(bytes) = finder.read_at(empty_args_addr, 2) else {
                    continue;
                };
                if bytes == b"-v" || bytes == b"%s" {
                    match finder.at(cursor, -1) {
                        Some(prev) if prev.kind() == Kind::Adrp => {
                            finder
                                .prev(&mut cursor)
                                .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adrp out of range"))?;
                        }
                        // Upstream: the `iter - 1` throw is caught and moves
                        // on to the next candidate.
                        None => continue,
                        Some(_) => {}
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(not_found(
                    PATCH_BOOT_ARGS,
                    "failed to find default boot args",
                ));
            }
        }
        let insn = finder
            .insn(cursor)
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference out of range"))?;
        let rd = insn
            .rd()
            .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "reference has no destination"))?;
        match insn.kind() {
            Kind::Adr => writes.push(Write::insn(
                finder.loc(cursor),
                new_general_adr(finder.loc(cursor), boot_args_str_loc as i64, rd)
                    .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adr out of range"))?,
            )),
            Kind::Adrp => {
                writes.push(Write::insn(
                    finder.loc(cursor),
                    new_general_adrp(finder.loc(cursor), (boot_args_str_loc & !0xfff) as i64, rd)
                        .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "adrp out of range"))?,
                ));
                writes.push(Write::insn(
                    finder.loc(cursor) + 4,
                    new_immediate_add((boot_args_str_loc & 0xfff) as i64, rd, rd)
                        .ok_or_else(|| not_found(PATCH_BOOT_ARGS, "add out of range"))?,
                ));
            }
            _ => return Err(not_found(PATCH_BOOT_ARGS, "bad reference instruction")),
        }

        let mut string = bootargs.as_bytes().to_vec();
        string.push(0);
        writes.push(Write::bytes(boot_args_str_loc, &string));
        Ok(writes)
    }

    /// `ibootpatchfinder64_base::get_unlock_nvram_patch`: stub out the three
    /// nvram blacklist functions (`movz x0, #0; ret`) so any variable can be
    /// read and written.
    pub fn get_unlock_nvram_patch(&mut self) -> Result<(), Iboot64PatchError> {
        let writes = {
            let finder = self.finder();
            let debug_uarts_str = finder
                .findstr(b"debug-uarts", true, 0)
                .ok_or_else(|| not_found(PATCH_UNLOCK_NVRAM, "\"debug-uarts\" string not found"))?;
            let debug_uarts_ref = finder
                .memmem(&debug_uarts_str.to_le_bytes(), 0)
                .ok_or_else(|| {
                    not_found(
                        PATCH_UNLOCK_NVRAM,
                        "no reference to the \"debug-uarts\" string",
                    )
                })?;

            // The setenv whitelist table starts after the zero entry
            // preceding the debug-uarts pointer.
            let mut setenv_whitelist = debug_uarts_ref;
            loop {
                setenv_whitelist = setenv_whitelist.wrapping_sub(8);
                if finder
                    .deref(setenv_whitelist)
                    .ok_or_else(|| not_found(PATCH_UNLOCK_NVRAM, "whitelist table out of range"))?
                    == 0
                {
                    break;
                }
            }
            setenv_whitelist = setenv_whitelist.wrapping_add(8);
            let blacklist1 = finder
                .find_literal_ref(setenv_whitelist, 0, 0)
                .ok_or_else(|| not_found(PATCH_UNLOCK_NVRAM, "no setenv whitelist reference"))?;
            let blacklist1_top = finder.find_bof(blacklist1, false).ok_or_else(|| {
                not_found(PATCH_UNLOCK_NVRAM, "setenv blacklist prologue not found")
            })?;
            let mut writes = vec![Write::bytes(blacklist1_top, &MOVZ_X0_0_RET)];

            // The getenv whitelist follows the zero entry terminating the
            // setenv table.
            let mut env_whitelist = setenv_whitelist;
            loop {
                env_whitelist = env_whitelist.wrapping_add(8);
                if finder
                    .deref(env_whitelist)
                    .ok_or_else(|| not_found(PATCH_UNLOCK_NVRAM, "whitelist table out of range"))?
                    == 0
                {
                    break;
                }
            }
            env_whitelist = env_whitelist.wrapping_add(8);
            let blacklist2 = finder
                .find_literal_ref(env_whitelist, 0, 0)
                .ok_or_else(|| not_found(PATCH_UNLOCK_NVRAM, "no getenv whitelist reference"))?;
            let blacklist2_top = finder.find_bof(blacklist2, false).ok_or_else(|| {
                not_found(PATCH_UNLOCK_NVRAM, "getenv blacklist prologue not found")
            })?;
            writes.push(Write::bytes(blacklist2_top, &MOVZ_X0_0_RET));

            let com_apple_system =
                finder
                    .findstr(b"com.apple.System.", true, 0)
                    .ok_or_else(|| {
                        not_found(PATCH_UNLOCK_NVRAM, "\"com.apple.System.\" string not found")
                    })?;
            let xref = finder
                .find_literal_ref(com_apple_system, 0, 0)
                .ok_or_else(|| {
                    not_found(PATCH_UNLOCK_NVRAM, "no \"com.apple.System.\" reference")
                })?;
            let func3_top = finder.find_bof(xref, false).ok_or_else(|| {
                not_found(PATCH_UNLOCK_NVRAM, "third blacklist prologue not found")
            })?;
            writes.push(Write::bytes(func3_top, &MOVZ_X0_0_RET));
            writes
        };
        self.commit(PATCH_UNLOCK_NVRAM, writes)
    }

    /// `ibootpatchfinder64_base::get_freshnonce_patch`: nop the branch that
    /// skips nonce regeneration, so every request gets a fresh nonce.
    pub fn get_freshnonce_patch(&mut self) -> Result<(), Iboot64PatchError> {
        let writes = {
            let finder = self.finder();
            let noncevar_str = finder
                .findstr(b"com.apple.System.boot-nonce", true, 0)
                .ok_or_else(|| {
                    not_found(
                        PATCH_FRESHNONCE,
                        "\"com.apple.System.boot-nonce\" string not found",
                    )
                })?;
            let noncevar_ref = finder.find_literal_ref(noncevar_str, 0, 0).ok_or_else(|| {
                not_found(PATCH_FRESHNONCE, "no reference to the boot-nonce string")
            })?;
            let noncefun1 = finder
                .find_bof(noncevar_ref, false)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "nonce function not found"))?;
            let noncefun1_blref = finder
                .find_call_ref(noncefun1, 0, 0)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "nonce function caller not found"))?;
            let noncefun2 = finder
                .find_bof(noncefun1_blref, false)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "second nonce function not found"))?;
            let noncefun2_blref = finder
                .find_call_ref(noncefun2, 0, 0)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "second caller not found"))?;
            let mut cursor = finder
                .cursor_at(noncefun2_blref)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "caller out of range"))?;
            if finder
                .prev(&mut cursor)
                .ok_or_else(|| not_found(PATCH_FRESHNONCE, "caller out of range"))?
                .supertype()
                != Supertype::BranchImm
            {
                return Err(not_found(
                    PATCH_FRESHNONCE,
                    "no branch before the nonce call",
                ));
            }
            let branch = finder.loc(cursor);
            debug!(branch, "freshnonce: nopping the skip branch");
            vec![Write::insn(branch, new_general_nop())]
        };
        self.commit(PATCH_FRESHNONCE, writes)
    }
}

/// Apply the libipatcher `iBoot64Patch` patch set on a decrypted, headerless
/// arm64 iBoot image and return the patched copy together with the record of
/// every applied write: always the sigcheck patch, and when the image has a
/// kernel load routine also the debug-enabled, boot-args (when given),
/// unlock-nvram, and freshnonce patches, in that order.
pub fn patch_iboot64_with_report(
    image: &[u8],
    boot_args: Option<&str>,
) -> Result<(Vec<u8>, Iboot64PatchReport), Iboot64PatchError> {
    let mut buf = image.to_vec();
    let mut patches = Vec::new();
    let (version, base_address);
    {
        let mut iboot = IBoot64::new(&mut buf)?;
        version = iboot.version();
        base_address = iboot.base_address();
        iboot.get_sigcheck_patch()?;
        if iboot.has_kernel_load() {
            iboot.get_debug_enabled_patch()?;
            if let Some(boot_args) = boot_args {
                iboot.get_boot_arg_patch(boot_args)?;
            }
            iboot.get_unlock_nvram_patch()?;
            iboot.get_freshnonce_patch()?;
        } else {
            info!("no kernel load routine; skipping the boot patches");
        }
        patches.append(&mut iboot.applied);
    }
    Ok((
        buf,
        Iboot64PatchReport {
            version,
            base_address,
            patches,
        },
    ))
}

/// Apply the libipatcher `iBoot64Patch` patch set and return only the
/// patched image; see [`patch_iboot64_with_report`].
pub fn patch_iboot64(image: &[u8], boot_args: Option<&str>) -> Result<Vec<u8>, Iboot64PatchError> {
    Ok(patch_iboot64_with_report(image, boot_args)?.0)
}

#[derive(Debug, Error)]
pub enum Iboot64PatchError {
    #[error("the image is too small to be a 64-bit iBoot (need more than 0x1000 bytes)")]
    ImageTooSmall,
    #[error("no \"iBoot\" version string at offset 0x280")]
    MissingVersionString,
    #[error("the image is not a 64-bit iBoot (invalid magic)")]
    BadMagic,
    #[error("no iBoot version found in the version string")]
    VersionNotFound,
    #[error("iBoot-{0} (iOS 17 or newer) is not supported; the target devices max out at iOS 16")]
    UnsupportedVersion(u32),
    #[error("{patch} patch: {reason}")]
    PatternNotFound {
        patch: &'static str,
        reason: &'static str,
    },
    #[error("{patch} patch: computed write at address 0x{loc:016x} is outside the image")]
    WriteOutOfBounds { patch: &'static str, loc: u64 },
}

#[cfg(test)]
mod tests;
