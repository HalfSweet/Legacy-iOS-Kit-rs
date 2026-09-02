//! KPlooshFinder 64-bit kernelcache AMFI patcher, a Rust port of
//! plooshi/KPlooshFinder @def9baff (amfi-only branch: `src/patcher.c` and
//! `patches/amfi.c`) on top of plooshi/plooshfinder @e4b0962
//! (`src/formats/macho.c`, `src/plooshfinder.c`, `src/plooshfinder32.c`).
//! This is the tool Legacy iOS Kit's `ipsw_prepare_ipx` runs on the extracted
//! iPhone X kernelcache before repacking it.
//!
//! # Integration contract
//!
//! The input is the **raw kernelcache payload** (the bytes `img4 -i
//! kernelcache -o kcache.raw` produces upstream; here:
//! [`crate::extract_im4p_payload`]): a 64-bit Mach-O in prelinked form,
//! optionally wrapped in a fat header. For a fat image the arm64 slice
//! (`CPU_TYPE_ARM64`) is patched in place and the rest of the file passes
//! through untouched, so the output always has the same length as the input.
//! The kit-side ipx builder rewraps the patched bytes with
//! [`crate::replace_im4p_payload`]; upstream's `kerneldiff`/`img4 -P` bpatch
//! round-trip is deliberately not ported because the patched bytes are
//! consumed directly here, leaving no consumer for a textual byte diff.
//!
//! Ported scope: the five AMFI patch points (`patches/amfi.c`: sha1 hash
//! type check, launch constraints, developer mode, old/new trustcache) and
//! the APFS snapshot rename (`patcher.c`). KPlooshFinder's sandbox, sbops,
//! and `__TEXT_EXEC` patches are jailbreak-oriented and are not used by the
//! ipx flow, so they are not ported.
//!
//! # Error semantics
//!
//! Upstream prints and writes an unpatched copy when a patch point is not
//! found. Here, version-gated patches whose gate string is missing are
//! skipped (logged at `debug`), non-gated patches that miss are collected in
//! [`Kernel64PatchOutcome::missed`], and if no patch applied at all the
//! whole operation fails with [`Kernel64Error::NoPatchesApplied`].
//!
//! # Deviations from upstream
//!
//! - Every access is bounds-checked; upstream reads/writes out of bounds on
//!   malformed input (pattern sequences at section tails, NULL dereferences
//!   after failed translations, unlimited `b` redirect chasing) and that is
//!   not ported. Backward searches stop at the start of the scanned section
//!   and the trustcache redirect chain is capped at 32 hops.
//! - `macho_get_segment` upstream stops the load-command walk at the first
//!   non-`LC_SEGMENT_64` command; the parser here collects every segment.
//! - A missing APFS kext aborts the whole patch run upstream (before AMFI is
//!   touched); here only the snapshot rename is reported missing.
//! - Pattern matching at a given word checks the patches in upstream's
//!   patchset order, so first-hit-wins semantics (including the shared
//!   old/new trustcache flag) are preserved.

use thiserror::Error;
use tracing::{debug, info};

use crate::patchfinder::find_bytes;

const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `FAT_MAGIC`, stored big-endian on disk.
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const LC_SEGMENT_64: u32 = 0x19;
const LC_BUILD_VERSION: u32 = 0x32;

const RET: u32 = 0xD65F_03C0;

const AMFI_BUNDLE: &str = "com.apple.driver.AppleMobileFileIntegrity";
const APFS_BUNDLE: &str = "com.apple.filesystems.apfs";

/// Gate strings, searched in the kernel's `__TEXT,__cstring`. The constraint
/// and developer-mode gates include the trailing NUL (upstream uses
/// `sizeof(str)`); the rootvp check is a partial match (upstream uses
/// `sizeof(str) - 1`).
const ROOTVP_STRING: &[u8] = b"rootvp not authenticated after mounting";
const CONSTRAINTS_GATE: &[u8] = b"mac_proc_check_launch_constraints\0";
const DEVMODE_GATE: &[u8] = b"AMFI: developer mode is force enabled\n\0";
const SNAPSHOT_STRING: &[u8] = b"com.apple.os.update-\0";

const ENABLE_DEVMODE_PREFIX: &[u8] = b"AMFI: Enabling developer mode since ";
const DISABLE_DEVMODE_PREFIX: &[u8] = b"AMFI: Disable developer mode since ";

/// Safety cap for the trustcache `b` redirect chase; upstream loops forever
/// on a redirect cycle.
const MAX_REDIRECTS: usize = 32;

#[derive(Debug, Error)]
pub enum Kernel64Error {
    #[error("not a 64-bit Mach-O or fat kernelcache (bad magic)")]
    BadMagic,
    #[error("fat kernelcache contains no arm64 slice")]
    NoArm64Slice,
    #[error("malformed kernelcache: {0}")]
    Malformed(&'static str),
    #[error("kernelcache has no LC_BUILD_VERSION")]
    PlatformNotFound,
    #[error("unsupported kernelcache platform {0} (supported: 1-5)")]
    UnsupportedPlatform(u32),
    #[error("cannot locate {0}")]
    AnchorNotFound(&'static str),
    #[error("no kernel patches applied")]
    NoPatchesApplied,
}

type Result<T> = std::result::Result<T, Kernel64Error>;

/// A patch point of the KPlooshFinder AMFI patch set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel64Patch {
    /// AMFI sha1 hash type check: `cmp w0, 2` -> `cmp w0, w0`.
    AmfiHashTypeCheck,
    /// `mac_proc_check_launch_constraints` replaced with `mov w0, 0; ret`.
    AmfiLaunchConstraints,
    /// AMFI disable-developer-mode redirected to the enable function.
    AmfiDeveloperMode,
    /// Trustcache lookup forced to succeed (old or new variant).
    AmfiTrustcache,
    /// `com.apple.os.update-` renamed in the APFS kext.
    ApfsSnapshotRename,
}

/// The patched kernelcache plus the structured patch report the kit layer
/// records.
#[derive(Debug)]
pub struct Kernel64PatchOutcome {
    image: Vec<u8>,
    applied: Vec<Kernel64Patch>,
    missed: Vec<Kernel64Patch>,
}

impl Kernel64PatchOutcome {
    /// The patched kernelcache, same length as the input.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    pub fn into_image(self) -> Vec<u8> {
        self.image
    }

    /// Patches that were applied, in application order.
    pub fn applied(&self) -> &[Kernel64Patch] {
        &self.applied
    }

    /// Non-gated patches whose patch point was not found.
    pub fn missed(&self) -> &[Kernel64Patch] {
        &self.missed
    }
}

fn r32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("length")))
}

fn r64(buf: &[u8], offset: usize) -> Option<u64> {
    buf.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("length")))
}

fn w32(buf: &mut [u8], offset: usize, val: u32) -> Result<()> {
    buf.get_mut(offset..offset + 4)
        .ok_or(Kernel64Error::Malformed("patch write out of bounds"))?
        .copy_from_slice(&val.to_le_bytes());
    Ok(())
}

fn maskmatch(insn: u32, value: u32, mask: u32) -> bool {
    insn & mask == value
}

/// `macho_xnu_untag_va`.
fn untag_va(addr: u64) -> u64 {
    if (addr >> 32) & 0xffff == 0xfff0 {
        addr | 0xffff_0000_0000_0000
    } else {
        addr
    }
}

struct Section64 {
    name: [u8; 16],
    addr: u64,
    size: u64,
    offset: u64,
}

struct Segment64 {
    name: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    sections: Vec<Section64>,
}

/// strcmp against a 16-byte char field: equal up to the first NUL, or all 16
/// bytes when unterminated.
fn name_eq(name: &[u8; 16], want: &[u8]) -> bool {
    let end = name.iter().position(|&b| b == 0).unwrap_or(16);
    &name[..end] == want
}

/// A parsed 64-bit Mach-O header view. `base` is the offset of the header
/// within the file buffer (nonzero for a fat slice); all file offsets handed
/// out by the translation methods are absolute buffer offsets.
struct Macho64 {
    base: usize,
    platform: Option<u32>,
    segments: Vec<Segment64>,
}

impl Macho64 {
    fn parse(buf: &[u8], base: usize) -> Result<Macho64> {
        if r32(buf, base) != Some(MH_MAGIC_64) {
            return Err(Kernel64Error::BadMagic);
        }
        let ncmds = r32(buf, base + 16).ok_or(Kernel64Error::Malformed("header"))?;
        let mut macho = Macho64 {
            base,
            platform: None,
            segments: Vec::new(),
        };
        let mut cmd = base
            .checked_add(32)
            .ok_or(Kernel64Error::Malformed("load commands"))?;
        for _ in 0..ncmds {
            let cmd_id = r32(buf, cmd).ok_or(Kernel64Error::Malformed("load commands"))?;
            let cmdsize =
                r32(buf, cmd + 4).ok_or(Kernel64Error::Malformed("load commands"))? as usize;
            if cmdsize < 8 {
                return Err(Kernel64Error::Malformed("load command size"));
            }
            if cmd_id == LC_SEGMENT_64 {
                let nsects =
                    r32(buf, cmd + 64).ok_or(Kernel64Error::Malformed("segment command"))? as usize;
                if cmdsize < 72 || 72 + 80 * nsects > cmdsize {
                    return Err(Kernel64Error::Malformed("segment command size"));
                }
                let mut name = [0; 16];
                name.copy_from_slice(&buf[cmd + 8..cmd + 24]);
                let mut segment = Segment64 {
                    name,
                    vmaddr: r64(buf, cmd + 24).ok_or(Kernel64Error::Malformed("segment"))?,
                    vmsize: r64(buf, cmd + 32).ok_or(Kernel64Error::Malformed("segment"))?,
                    fileoff: r64(buf, cmd + 40).ok_or(Kernel64Error::Malformed("segment"))?,
                    filesize: r64(buf, cmd + 48).ok_or(Kernel64Error::Malformed("segment"))?,
                    sections: Vec::with_capacity(nsects),
                };
                for i in 0..nsects {
                    let sec = cmd + 72 + 80 * i;
                    let mut name = [0; 16];
                    name.copy_from_slice(&buf[sec..sec + 16]);
                    segment.sections.push(Section64 {
                        name,
                        addr: r64(buf, sec + 32).ok_or(Kernel64Error::Malformed("section"))?,
                        size: r64(buf, sec + 40).ok_or(Kernel64Error::Malformed("section"))?,
                        offset: r64(buf, sec + 48).ok_or(Kernel64Error::Malformed("section"))?,
                    });
                }
                macho.segments.push(segment);
            } else if cmd_id == LC_BUILD_VERSION && macho.platform.is_none() {
                macho.platform = Some(
                    r32(buf, cmd + 8).ok_or(Kernel64Error::Malformed("build version command"))?,
                );
            }
            cmd = cmd
                .checked_add(cmdsize)
                .ok_or(Kernel64Error::Malformed("load commands"))?;
        }
        Ok(macho)
    }

    fn find_section(&self, segment: &[u8], section: &[u8]) -> Option<&Section64> {
        self.segments
            .iter()
            .find(|seg| name_eq(&seg.name, segment))?
            .sections
            .iter()
            .find(|sec| name_eq(&sec.name, section))
    }

    /// `macho_va_to_ptr`: translate a virtual address to an absolute buffer
    /// offset using this Mach-O's segment map.
    fn va_to_offset(&self, va: u64) -> Option<usize> {
        for seg in &self.segments {
            if seg.vmaddr <= va && va - seg.vmaddr < seg.vmsize {
                if seg.vmaddr == va {
                    return usize::try_from(seg.fileoff)
                        .ok()
                        .and_then(|off| self.base.checked_add(off));
                }
                for sec in &seg.sections {
                    if sec.addr <= va && va - sec.addr < sec.size {
                        let off = sec.offset.checked_add(va - sec.addr)?;
                        return usize::try_from(off)
                            .ok()
                            .and_then(|off| self.base.checked_add(off));
                    }
                }
                return None;
            }
        }
        None
    }

    /// `macho_ptr_to_va`: translate an absolute buffer offset to a virtual
    /// address.
    fn offset_to_va(&self, offset: usize) -> Option<u64> {
        let rel = u64::try_from(offset.checked_sub(self.base)?).ok()?;
        for seg in &self.segments {
            if seg.fileoff <= rel && rel - seg.fileoff < seg.filesize {
                for sec in &seg.sections {
                    if sec.offset <= rel && rel - sec.offset < sec.size {
                        return Some(sec.addr + (rel - sec.offset));
                    }
                }
                return None;
            }
        }
        None
    }

    /// `macho_find_kext`: locate a prelinked kext's Mach-O header via
    /// `__PRELINK_INFO`. iOS 14 kernelcaches carry `__kmod_info` /
    /// `__kmod_start` pointer arrays; iOS 15 carries an `__info` plist.
    fn find_kext(&self, buf: &[u8], bundle: &str) -> Option<usize> {
        let prelink = self
            .segments
            .iter()
            .find(|seg| name_eq(&seg.name, b"__PRELINK_INFO"))?;
        match prelink
            .sections
            .iter()
            .find(|sec| name_eq(&sec.name, b"__kmod_info"))
        {
            Some(kmod_info) => {
                let kmod_start = prelink
                    .sections
                    .iter()
                    .find(|sec| name_eq(&sec.name, b"__kmod_start"))?;
                self.parse_kmod_info(buf, kmod_info, kmod_start, bundle)
            }
            None => {
                let info = prelink
                    .sections
                    .iter()
                    .find(|sec| name_eq(&sec.name, b"__info"))?;
                self.parse_prelink_info(buf, info, bundle)
            }
        }
    }

    /// `macho_parse_kmod_info`. Upstream keeps scanning after a match, so the
    /// last match wins; that is preserved.
    fn parse_kmod_info(
        &self,
        buf: &[u8],
        kmod_info: &Section64,
        kmod_start: &Section64,
        bundle: &str,
    ) -> Option<usize> {
        let info_base = self
            .base
            .checked_add(usize::try_from(kmod_info.offset).ok()?)?;
        let start_base = self
            .base
            .checked_add(usize::try_from(kmod_start.offset).ok()?)?;
        let mut found = None;
        for i in 0..(kmod_info.size >> 3) {
            let i = usize::try_from(i).ok()?;
            let Some(info_va) = r64(buf, info_base.checked_add(8 * i)?) else {
                break;
            };
            let Some(info_off) = self.va_to_offset(untag_va(info_va)) else {
                continue;
            };
            // struct kmod_info: name[64] at offset 16.
            let Some(name_field) = buf.get(info_off + 16..info_off + 80) else {
                continue;
            };
            let end = name_field.iter().position(|&b| b == 0).unwrap_or(64);
            if &name_field[..end] != bundle.as_bytes() {
                continue;
            }
            let start_va = r64(buf, start_base.checked_add(8 * i)?)?;
            found = self.va_to_offset(untag_va(start_va));
        }
        found
    }

    /// `macho_parse_prelink_info`: substring search in the `__info` plist
    /// text. Where upstream would dereference NULL on a truncated plist, this
    /// returns None.
    fn parse_prelink_info(&self, buf: &[u8], info: &Section64, bundle: &str) -> Option<usize> {
        let start = self.base.checked_add(usize::try_from(info.offset).ok()?)?;
        let size = usize::try_from(info.size).ok()?;
        let text = buf.get(start..start.checked_add(size)?)?;
        let info_dict = find_bytes(text, b"PrelinkInfoDictionary")?;
        let mut last_dict =
            find_bytes(&text[info_dict..], b"<array>").map(|p| info_dict + p + 7)?;
        loop {
            let mut dict_end = last_dict + find_bytes(&text[last_dict..], b"</dict>")?;
            // Skip nested dicts so the identifier lookup below spans one
            // top-level entry.
            let mut nested =
                find_bytes(&text[last_dict + 1..], b"<dict>").map(|p| last_dict + 1 + p);
            while let Some(d2) = nested {
                if d2 > dict_end {
                    break;
                }
                nested = find_bytes(&text[d2 + 1..], b"<dict>").map(|p| d2 + 1 + p);
                dict_end = dict_end + 1 + find_bytes(&text[dict_end + 1..], b"</dict>")?;
            }
            if let Some(identifier) =
                find_bytes(&text[last_dict..], b"CFBundleIdentifier").map(|p| last_dict + p)
            {
                if let Some(value) = find_bytes(&text[identifier..], b"<string>") {
                    let value = identifier + value + b"<string>".len();
                    if let Some(key_end) = find_bytes(&text[value..], b"</string>") {
                        if &text[value..value + key_end] == bundle.as_bytes() {
                            let addr_key = last_dict
                                + find_bytes(&text[last_dict..], b"_PrelinkExecutableLoadAddr")?;
                            let va = parse_plist_integer(&text[addr_key..])?;
                            return self.va_to_offset(va);
                        }
                    }
                }
            }
            last_dict = dict_end + find_bytes(&text[dict_end..], b"<dict>")?;
        }
    }
}

/// `macho_parse_plist_integer`: strtoull with base 0 after the `<integer...>`
/// tag (decimal, `0x` hex, or `0`-prefixed octal).
fn parse_plist_integer(text: &[u8]) -> Option<u64> {
    let tag = find_bytes(text, b"<integer")?;
    let gt = tag + find_bytes(&text[tag..], b">")? + 1;
    let mut digits = &text[gt..];
    while digits.first().is_some_and(u8::is_ascii_whitespace) {
        digits = &digits[1..];
    }
    let (digits, radix) = if digits.len() > 2
        && digits[0] == b'0'
        && (digits[1] | 0x20) == b'x'
        && digits[2].is_ascii_hexdigit()
    {
        (&digits[2..], 16)
    } else if digits.len() > 1 && digits[0] == b'0' && (b'0'..=b'7').contains(&digits[1]) {
        (&digits[1..], 8)
    } else {
        (digits, 10)
    };
    let end = digits
        .iter()
        .position(|&b| (b as char).to_digit(radix).is_none())
        .unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(&digits[..end]).ok()?, radix).ok()
}

/// `pf_adrp_offset`: the sign-extended 33-bit ADRP immediate (already
/// shifted left by 12).
fn adrp_offset(adrp: u32) -> i64 {
    let immhi = u64::from((adrp >> 5) & 0x7ffff);
    let immlo = u64::from((adrp >> 29) & 3);
    let imm = ((immhi << 2) | immlo) << 12;
    ((imm << 31) as i64) >> 31
}

/// `pf_follow_veneer`: if the branch target is an adrp/ldr/br veneer, resolve
/// it; otherwise (or when resolution fails) the target itself.
fn follow_veneer(buf: &[u8], macho: &Macho64, offset: usize, va: u64) -> usize {
    let (Some(w0), Some(w1), Some(w2)) =
        (r32(buf, offset), r32(buf, offset + 4), r32(buf, offset + 8))
    else {
        return offset;
    };
    if !maskmatch(w0, 0x9000_0010, 0x9f00_001f)
        || !maskmatch(w1, 0xf940_0210, 0xffc0_03ff)
        || w2 != 0xd61f_0200
    {
        return offset;
    }
    let addr_va = (va & !0xfff)
        .wrapping_add(adrp_offset(w0) as u64)
        .wrapping_add((u64::from(w1 >> 10) & 0xfff) << 3);
    let Some(addr_off) = macho.va_to_offset(addr_va) else {
        return offset;
    };
    let Some(ptr_va) = r64(buf, addr_off) else {
        return offset;
    };
    macho.va_to_offset(ptr_va).unwrap_or(offset)
}

/// `pf_follow_branch` for `b`/`bl` (the only forms the AMFI patches follow):
/// returns the absolute buffer offset of the branch target.
fn follow_branch(buf: &[u8], macho: &Macho64, insn_off: usize) -> Option<usize> {
    let op = r32(buf, insn_off)?;
    if !maskmatch(op, 0x1400_0000, 0x7c00_0000) {
        return None;
    }
    let insn_va = macho.offset_to_va(insn_off)?;
    let imm26 = i64::from((op << 6) as i32 >> 6);
    let target_va = insn_va.wrapping_add((imm26 << 2) as u64);
    let target = macho.va_to_offset(target_va)?;
    Some(follow_veneer(buf, macho, target, target_va))
}

/// `pf_follow_xref`: resolve the adrp+add pair at `adrp_off` to the absolute
/// buffer offset of the referenced data. The add shift bit is ignored, as
/// upstream.
fn follow_xref(buf: &[u8], macho: &Macho64, adrp_off: usize) -> Option<usize> {
    let (Some(adrp), Some(add)) = (r32(buf, adrp_off), r32(buf, adrp_off + 4)) else {
        return None;
    };
    if !maskmatch(adrp, 0x9000_0000, 0x9f00_0000) || !maskmatch(add, 0x9100_0000, 0xff80_0000) {
        return None;
    }
    let va = macho.offset_to_va(adrp_off)?;
    let target = (va & !0xfff)
        .wrapping_add(adrp_offset(adrp) as u64)
        .wrapping_add(u64::from((add >> 10) & 0xfff));
    macho.va_to_offset(target)
}

/// `pf_find_prev` over word indices: checks `from`, `from - 1`, ...,
/// `from - (count - 1)`, bounded below by word 0 of the scanned section.
fn find_prev_word(
    buf: &[u8],
    text_off: usize,
    from: usize,
    count: usize,
    value: u32,
    mask: u32,
) -> Option<usize> {
    for back in 0..count {
        let index = from.checked_sub(back)?;
        if r32(buf, text_off + 4 * index).is_some_and(|w| maskmatch(w, value, mask)) {
            return Some(index);
        }
    }
    None
}

fn bytes_at(buf: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    buf.get(offset..offset.checked_add(len)?)
}

/// Scanner state shared by the AMFI patch callbacks (`patches/amfi.c`'s
/// file-scope globals).
struct AmfiScan {
    sha1_done: bool,
    found_launch_constraints: bool,
    found_trustcache: bool,
    enable_developer_mode: Option<usize>,
    disable_developer_mode: Option<usize>,
    devmode_written: bool,
}

/// `patch_amfi_kext`: single pass over the AMFI kext's `__TEXT_EXEC,__text`,
/// checking all five patch patterns at each word in upstream's patchset
/// order.
#[allow(clippy::too_many_arguments)]
fn patch_amfi_text(
    buf: &mut [u8],
    macho: &Macho64,
    text_off: usize,
    text_size: usize,
    has_constraints: bool,
    has_devmode: bool,
    applied: &mut Vec<Kernel64Patch>,
    missed: &mut Vec<Kernel64Patch>,
) -> Result<()> {
    let mut scan = AmfiScan {
        sha1_done: false,
        found_launch_constraints: false,
        found_trustcache: false,
        enable_developer_mode: None,
        disable_developer_mode: None,
        devmode_written: false,
    };
    let n_words = text_size / 4;
    for i in 0..n_words {
        let word = r32(buf, text_off + 4 * i).expect("word in range");

        // patch_amfi_sha1: tbz w2, 0x1a, * then cmp w0, 2 within 0x10 words.
        if !scan.sha1_done && maskmatch(word, 0x36d0_0002, 0xfff8_001f) {
            let limit = 0x10.min(n_words - i);
            if let Some(k) =
                (0..limit).find(|&k| r32(buf, text_off + 4 * (i + k)) == Some(0x7100_081f))
            {
                w32(buf, text_off + 4 * (i + k), 0x6b00_001f)?; // cmp w0, w0
                scan.sha1_done = true;
                applied.push(Kernel64Patch::AmfiHashTypeCheck);
                debug!(
                    offset = format_args!("{:#x}", text_off + 4 * i),
                    "amfi sha1 check"
                );
            }
        }

        // patch_launch_constraints (gated on the kernel cstring containing
        // "mac_proc_check_launch_constraints").
        if has_constraints
            && !scan.found_launch_constraints
            && i + 5 <= n_words
            && word == 0x5280_6088 // mov w8, 0x304
            && r32(buf, text_off + 4 * (i + 1)).is_some_and(|w| maskmatch(w, 0x1400_0000, 0xfc00_0000))
            && r32(buf, text_off + 4 * (i + 2)) == Some(0x5280_2088) // mov w8, 0x104
            && r32(buf, text_off + 4 * (i + 3)).is_some_and(|w| maskmatch(w, 0x1400_0000, 0xfc00_0000))
            && r32(buf, text_off + 4 * (i + 4)) == Some(0x5280_4088)
        {
            scan.found_launch_constraints = true;
            let stp = find_prev_word(buf, text_off, i, 0x200, 0xa900_7bfd, 0xffc0_7fff);
            let start = stp
                .and_then(|s| find_prev_word(buf, text_off, s, 10, 0xa980_03e0, 0xffc0_03e0))
                .or_else(|| {
                    stp.and_then(|s| find_prev_word(buf, text_off, s, 10, 0xd100_03ff, 0xffc0_03ff))
                });
            if let Some(start) = start {
                w32(buf, text_off + 4 * start, 0x5280_0000)?; // mov w0, 0
                w32(buf, text_off + 4 * (start + 1), RET)?;
                applied.push(Kernel64Patch::AmfiLaunchConstraints);
                debug!(
                    offset = format_args!("{:#x}", text_off + 4 * start),
                    "launch constraints"
                );
            } else {
                missed.push(Kernel64Patch::AmfiLaunchConstraints);
            }
        }

        // patch_developer_mode (gated on "AMFI: developer mode is force
        // enabled\n" in the AMFI cstring).
        if has_devmode
            && i + 4 <= n_words
            && maskmatch(word, 0x9000_0000, 0x9f00_001f) // adrp
            && r32(buf, text_off + 4 * (i + 1)).is_some_and(|w| maskmatch(w, 0x9100_0000, 0xffc0_03ff))
            && r32(buf, text_off + 4 * (i + 2)).is_some_and(|w| maskmatch(w, 0x9400_0000, 0xfc00_0000))
            && r32(buf, text_off + 4 * (i + 3)).is_some_and(|w| maskmatch(w, 0x9400_0000, 0xfc00_0000))
        {
            if let Some(xref) = follow_xref(buf, macho, text_off + 4 * i) {
                let branch = follow_branch(buf, macho, text_off + 4 * (i + 3));
                if bytes_at(buf, xref, ENABLE_DEVMODE_PREFIX.len()) == Some(ENABLE_DEVMODE_PREFIX) {
                    if scan.enable_developer_mode.is_none() {
                        scan.enable_developer_mode = branch;
                    }
                } else if bytes_at(buf, xref, DISABLE_DEVMODE_PREFIX.len())
                    == Some(DISABLE_DEVMODE_PREFIX)
                    && scan.disable_developer_mode.is_none()
                {
                    scan.disable_developer_mode = branch;
                }
            }
            if !scan.devmode_written {
                if let (Some(enable), Some(disable)) =
                    (scan.enable_developer_mode, scan.disable_developer_mode)
                {
                    // b enable: the imm26 is a signed word offset.
                    let delta = (enable as i64 - disable as i64) / 4;
                    w32(
                        buf,
                        disable,
                        0x1400_0000 | (delta as u64 as u32 & 0x03ff_ffff),
                    )?;
                    scan.devmode_written = true;
                    applied.push(Kernel64Patch::AmfiDeveloperMode);
                    debug!(offset = format_args!("{disable:#x}"), "developer mode");
                }
            }
        }

        // patch_trustcache_old: mov w8, 0x101 preceded by the lookup call.
        if !scan.found_trustcache && word == 0x5280_2028 {
            scan.found_trustcache = true;
            // The call site is the previous word, or the one before when a
            // mov x{16-31}, x0 sits in between.
            let mut bl_index = i.checked_sub(1);
            if let Some(index) = bl_index {
                if r32(buf, text_off + 4 * index)
                    .is_some_and(|w| maskmatch(w, 0xaa00_03f0, 0xffff_03f0))
                {
                    bl_index = index.checked_sub(1);
                }
            }
            let mut target = bl_index.and_then(|index| {
                r32(buf, text_off + 4 * index)
                    .filter(|w| maskmatch(*w, 0x9400_0000, 0xfc00_0000))?;
                follow_branch(buf, macho, text_off + 4 * index)
            });
            // Skip any b redirects to the real function.
            let mut hops = 0;
            while let Some(t) = target {
                if !r32(buf, t).is_some_and(|w| maskmatch(w, 0x1400_0000, 0xfc00_0000)) {
                    break;
                }
                target = follow_branch(buf, macho, t);
                hops += 1;
                if hops >= MAX_REDIRECTS {
                    target = None;
                    break;
                }
            }
            if let Some(target) = target {
                w32(buf, target, 0xd280_2020)?; // mov x0, 0x101
                w32(buf, target + 4, RET)?;
                applied.push(Kernel64Patch::AmfiTrustcache);
                debug!(offset = format_args!("{target:#x}"), "trustcache (old)");
            } else {
                missed.push(Kernel64Patch::AmfiTrustcache);
            }
        }

        // patch_trustcache_new: trustCacheQueryGetFlags call site.
        if !scan.found_trustcache
            && i + 5 <= n_words
            && word == 0x9100_03e0 // mov x0, sp
            && r32(buf, text_off + 4 * (i + 1)) == Some(0xaa13_03e1) // mov x1, x19
            && r32(buf, text_off + 4 * (i + 2)).is_some_and(|w| maskmatch(w, 0x9400_0000, 0xfc00_0000))
            && r32(buf, text_off + 4 * (i + 3)) == Some(0x7100_029f) // cmp w20, 0
            && r32(buf, text_off + 4 * (i + 4)) == Some(0x1a9f_17e0)
        // cset w0, eq
        {
            scan.found_trustcache = true;
            if let Some(start) = find_prev_word(buf, text_off, i, 20, 0xd100_03ff, 0xffc0_03ff) {
                w32(buf, text_off + 4 * start, 0xd280_0020)?; // mov x0, 1
                w32(buf, text_off + 4 * (start + 1), 0xb400_0042)?; // cbz x2, .+0x8
                w32(buf, text_off + 4 * (start + 2), 0xf900_0040)?; // str x0, [x2]
                w32(buf, text_off + 4 * (start + 3), RET)?;
                applied.push(Kernel64Patch::AmfiTrustcache);
                debug!(
                    offset = format_args!("{:#x}", text_off + 4 * start),
                    "trustcache (new)"
                );
            } else {
                missed.push(Kernel64Patch::AmfiTrustcache);
            }
        }
    }

    if !scan.sha1_done {
        missed.push(Kernel64Patch::AmfiHashTypeCheck);
    }
    if has_constraints && !scan.found_launch_constraints {
        missed.push(Kernel64Patch::AmfiLaunchConstraints);
    }
    if has_devmode && !scan.devmode_written {
        missed.push(Kernel64Patch::AmfiDeveloperMode);
    }
    if !scan.found_trustcache {
        missed.push(Kernel64Patch::AmfiTrustcache);
    }
    Ok(())
}

/// The kernelcache's arm64 slice offset: 0 for a thin Mach-O, the fat_arch
/// offset for a fat image (`macho_find_arch`).
fn arm64_slice(buf: &[u8]) -> Result<usize> {
    let magic = r32(buf, 0).ok_or(Kernel64Error::BadMagic)?;
    if magic == MH_MAGIC_64 {
        return Ok(0);
    }
    // Fat headers are big-endian; the bytes ca fe ba be read as 0xbebafeca
    // in upstream's little-endian host order.
    if magic != FAT_MAGIC.swap_bytes() {
        return Err(Kernel64Error::BadMagic);
    }
    let nfat = r32(buf, 4)
        .map(u32::swap_bytes)
        .ok_or(Kernel64Error::Malformed("fat header"))?;
    for i in 0..nfat as usize {
        let arch = 8 + 20 * i;
        let cputype = r32(buf, arch)
            .map(u32::swap_bytes)
            .ok_or(Kernel64Error::Malformed("fat arch"))?;
        if cputype == CPU_TYPE_ARM64 {
            let offset = r32(buf, arch + 8)
                .map(u32::swap_bytes)
                .ok_or(Kernel64Error::Malformed("fat arch"))?;
            let offset =
                usize::try_from(offset).map_err(|_| Kernel64Error::Malformed("fat arch"))?;
            if r32(buf, offset).is_none() {
                return Err(Kernel64Error::Malformed("fat slice offset"));
            }
            return Ok(offset);
        }
    }
    Err(Kernel64Error::NoArm64Slice)
}

/// The section's file range as (absolute offset, size). Kernel sections are
/// addressed by their direct file offset (as upstream's `kernel_buf +
/// section->offset`); kext sections go through the kernel's va map
/// (`addr_to_ptr`).
fn section_range(
    macho: &Macho64,
    section: &Section64,
    what: &'static str,
) -> Result<(usize, usize)> {
    let offset = usize::try_from(section.offset).map_err(|_| Kernel64Error::Malformed(what))?;
    let size = usize::try_from(section.size).map_err(|_| Kernel64Error::Malformed(what))?;
    let start = macho
        .base
        .checked_add(offset)
        .ok_or(Kernel64Error::Malformed(what))?;
    Ok((start, size))
}

fn kext_section_range(
    kernel: &Macho64,
    section: &Section64,
    what: &'static str,
) -> Result<(usize, usize)> {
    let start = kernel
        .va_to_offset(untag_va(section.addr))
        .ok_or(Kernel64Error::Malformed(what))?;
    let size = usize::try_from(section.size).map_err(|_| Kernel64Error::Malformed(what))?;
    Ok((start, size))
}

fn region<'a>(buf: &'a [u8], range: (usize, usize), what: &'static str) -> Result<&'a [u8]> {
    buf.get(range.0..range.0 + range.1)
        .ok_or(Kernel64Error::Malformed(what))
}

/// Apply the KPlooshFinder AMFI patch set to an iOS 14/15 arm64 kernelcache,
/// returning the patched image and the patch report. See the module docs for
/// the integration contract.
pub fn patch_kernel64(kernelcache: &[u8]) -> Result<Kernel64PatchOutcome> {
    let mut buf = kernelcache.to_vec();
    let base = arm64_slice(&buf)?;
    let macho = Macho64::parse(&buf, base)?;

    // macho_get_platform: platform must be present and in 1..=5.
    let platform = macho.platform.ok_or(Kernel64Error::PlatformNotFound)?;
    if platform == 0 || platform > 5 {
        return Err(Kernel64Error::UnsupportedPlatform(platform));
    }
    debug!(platform, "kernelcache platform");

    let cstring = macho
        .find_section(b"__TEXT", b"__cstring")
        .ok_or(Kernel64Error::AnchorNotFound("kernel __TEXT,__cstring"))?;
    let cstring_range = section_range(&macho, cstring, "truncated __cstring")?;
    let kernel_cstring = region(&buf, cstring_range, "truncated __cstring")?;
    let has_rootvp = find_bytes(kernel_cstring, ROOTVP_STRING).is_some();
    let has_constraints = find_bytes(kernel_cstring, CONSTRAINTS_GATE).is_some();
    if !has_constraints {
        debug!("launch constraints gate string missing, patch skipped");
    }

    let amfi_off = macho
        .find_kext(&buf, AMFI_BUNDLE)
        .ok_or(Kernel64Error::AnchorNotFound("AMFI kext"))?;
    let amfi = Macho64::parse(&buf, amfi_off)
        .map_err(|_| Kernel64Error::Malformed("AMFI kext Mach-O header"))?;
    let amfi_text = amfi
        .find_section(b"__TEXT_EXEC", b"__text")
        .ok_or(Kernel64Error::AnchorNotFound("AMFI __TEXT_EXEC,__text"))?;
    let text_off = macho
        .va_to_offset(untag_va(amfi_text.addr))
        .ok_or(Kernel64Error::Malformed("AMFI __text address"))?;
    let text_size = usize::try_from(amfi_text.size)
        .map_err(|_| Kernel64Error::Malformed("AMFI __text size"))?;
    if buf.len() < text_off + text_size {
        return Err(Kernel64Error::Malformed("truncated AMFI __text"));
    }

    // Developer mode gate: the AMFI kext's own __cstring when it has one,
    // the kernel's otherwise (patcher.c's devmode_cstring fallback).
    let devmode_range = match amfi.find_section(b"__TEXT", b"__cstring") {
        Some(section) => kext_section_range(&macho, section, "AMFI __cstring")?,
        None => cstring_range,
    };
    let has_devmode =
        find_bytes(region(&buf, devmode_range, "AMFI __cstring")?, DEVMODE_GATE).is_some();
    if !has_devmode {
        debug!("developer mode gate string missing, patch skipped");
    }

    let mut applied = Vec::new();
    let mut missed = Vec::new();
    patch_amfi_text(
        &mut buf,
        &macho,
        text_off,
        text_size,
        has_constraints,
        has_devmode,
        &mut applied,
        &mut missed,
    )?;

    // patcher.c: with the rootvp string absent (iOS 14), disable the APFS
    // snapshot rename by rewriting the "com.apple.os.update-" prefix.
    if !has_rootvp {
        let renamed = match macho.find_kext(&buf, APFS_BUNDLE) {
            Some(apfs_off) => {
                let apfs = Macho64::parse(&buf, apfs_off).ok();
                let range = match apfs
                    .as_ref()
                    .and_then(|apfs| apfs.find_section(b"__TEXT", b"__cstring"))
                {
                    Some(section) => kext_section_range(&macho, section, "APFS __cstring")?,
                    None => cstring_range,
                };
                find_bytes(region(&buf, range, "APFS __cstring")?, SNAPSHOT_STRING)
                    .map(|p| range.0 + p)
            }
            None => None,
        };
        if let Some(offset) = renamed {
            buf[offset] = b'x';
            applied.push(Kernel64Patch::ApfsSnapshotRename);
            debug!(offset = format_args!("{offset:#x}"), "apfs snapshot rename");
        } else {
            debug!("APFS snapshot string not found");
            missed.push(Kernel64Patch::ApfsSnapshotRename);
        }
    }

    if applied.is_empty() {
        return Err(Kernel64Error::NoPatchesApplied);
    }
    info!(
        applied = format_args!("{applied:?}"),
        missed = format_args!("{missed:?}"),
        "kernelcache AMFI patches"
    );
    Ok(Kernel64PatchOutcome {
        image: buf,
        applied,
        missed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every virtual address is VA_BASE + file offset, so the va map is
    /// transparent and translations still go through the segment tables.
    const VA_BASE: u64 = 0xffff_fff0_0700_4000;
    const CSTR: usize = 0x4000; // kernel __TEXT,__cstring
    const PLINFO: usize = 0x6000; // __PRELINK_INFO
    const KTEXT: usize = 0x8000; // __PRELINK_TEXT start
    const AMFI: usize = 0x8000; // AMFI kext header
    const AMFI_TEXT: usize = 0x9000;
    const AMFI_CSTR: usize = 0xB000;
    const APFS: usize = 0xC000; // APFS kext header
    const APFS_CSTR: usize = 0xE000;
    const LEN: usize = 0x1_0000;

    const NOP: u32 = 0xd503_201f;

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn w32be(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn w64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn r32at(buf: &[u8], offset: usize) -> u32 {
        r32(buf, offset).unwrap()
    }

    fn put_str(buf: &mut [u8], offset: usize, s: &str) {
        buf[offset..offset + s.len()].copy_from_slice(s.as_bytes());
        buf[offset + s.len()] = 0;
    }

    fn header(buf: &mut [u8], base: usize, ncmds: u32) {
        w32(buf, base, MH_MAGIC_64);
        w32(buf, base + 16, ncmds);
    }

    /// Writes a segment_command_64 plus its sections at `cmd`; returns the
    /// command size.
    #[allow(clippy::too_many_arguments)]
    fn segment64(
        buf: &mut [u8],
        cmd: usize,
        name: &str,
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        sections: &[(&str, u64, u64, u64)],
    ) -> usize {
        let cmdsize = 72 + 80 * sections.len();
        w32(buf, cmd, LC_SEGMENT_64);
        w32(buf, cmd + 4, cmdsize as u32);
        buf[cmd + 8..cmd + 8 + name.len()].copy_from_slice(name.as_bytes());
        w64(buf, cmd + 24, vmaddr);
        w64(buf, cmd + 32, vmsize);
        w64(buf, cmd + 40, fileoff);
        w64(buf, cmd + 48, filesize);
        w32(buf, cmd + 64, sections.len() as u32);
        for (i, &(secname, addr, size, offset)) in sections.iter().enumerate() {
            let sec = cmd + 72 + 80 * i;
            buf[sec..sec + secname.len()].copy_from_slice(secname.as_bytes());
            w64(buf, sec + 32, addr);
            w64(buf, sec + 40, size);
            w32(buf, sec + 48, offset as u32);
        }
        cmdsize
    }

    fn build_version(buf: &mut [u8], cmd: usize, platform: u32) -> usize {
        w32(buf, cmd, LC_BUILD_VERSION);
        w32(buf, cmd + 4, 24);
        w32(buf, cmd + 8, platform);
        24
    }

    fn bl(from: usize, to: usize) -> u32 {
        let delta = (to as i64 - from as i64) / 4;
        0x9400_0000 | (delta as u64 as u32 & 0x03ff_ffff)
    }

    /// adrp x0, page; add x0, x0, #lo referencing `target_off` from
    /// `insn_off`.
    fn adrp_add(insn_off: usize, target_off: usize) -> (u32, u32) {
        let insn_va = VA_BASE + insn_off as u64;
        let target_va = VA_BASE + target_off as u64;
        let imm = ((target_va & !0xfff) as i64 - (insn_va & !0xfff) as i64) >> 12;
        let imm = imm as u64;
        let adrp = 0x9000_0000 | (((imm >> 2) & 0x7ffff) << 5) as u32 | (((imm & 3) << 29) as u32);
        let add = 0x9100_0000 | (((target_va & 0xfff) as u32) << 10);
        (adrp, add)
    }

    fn amfi_kext(buf: &mut [u8]) {
        header(buf, AMFI, 2);
        let mut cmd = AMFI + 32;
        cmd += segment64(
            buf,
            cmd,
            "__TEXT_EXEC",
            VA_BASE + AMFI_TEXT as u64,
            0x1000,
            AMFI_TEXT as u64,
            0x1000,
            &[(
                "__text",
                VA_BASE + AMFI_TEXT as u64,
                0x1000,
                AMFI_TEXT as u64,
            )],
        );
        segment64(
            buf,
            cmd,
            "__TEXT",
            VA_BASE + AMFI_CSTR as u64,
            0x1000,
            AMFI_CSTR as u64,
            0x1000,
            &[(
                "__cstring",
                VA_BASE + AMFI_CSTR as u64,
                0x1000,
                AMFI_CSTR as u64,
            )],
        );
    }

    fn apfs_kext(buf: &mut [u8]) {
        header(buf, APFS, 1);
        segment64(
            buf,
            APFS + 32,
            "__TEXT",
            VA_BASE + APFS_CSTR as u64,
            0x1000,
            APFS_CSTR as u64,
            0x1000,
            &[(
                "__cstring",
                VA_BASE + APFS_CSTR as u64,
                0x1000,
                APFS_CSTR as u64,
            )],
        );
    }

    fn prelink_plist(buf: &mut [u8]) {
        let plist = format!(
            "<dict><key>PrelinkInfoDictionary</key><array>\
             <dict><key>CFBundleIdentifier</key><string>{AMFI_BUNDLE}</string>\
             <key>_PrelinkExecutableLoadAddr</key><integer>0x{:x}</integer></dict>\
             <dict><key>CFBundleIdentifier</key><string>{APFS_BUNDLE}</string>\
             <key>_PrelinkExecutableLoadAddr</key><integer>0x{:x}</integer></dict>\
             </array></dict>",
            VA_BASE + AMFI as u64,
            VA_BASE + APFS as u64
        );
        put_str(buf, PLINFO, &plist);
    }

    fn prelink_kmod(buf: &mut [u8]) {
        // __kmod_info points at kmod_info structs, __kmod_start at the kext
        // headers. struct kmod_info: name[64] at offset 16.
        w64(buf, PLINFO, VA_BASE + (PLINFO + 0x100) as u64);
        w64(buf, PLINFO + 8, VA_BASE + (PLINFO + 0x180) as u64);
        w64(buf, PLINFO + 0x10, VA_BASE + AMFI as u64);
        w64(buf, PLINFO + 0x18, VA_BASE + APFS as u64);
        put_str(buf, PLINFO + 0x110, AMFI_BUNDLE);
        put_str(buf, PLINFO + 0x190, APFS_BUNDLE);
    }

    /// A minimal prelinked kernelcache: kernel header with __TEXT (__cstring),
    /// __PRELINK_INFO and __PRELINK_TEXT, the AMFI and APFS kexts, and the
    /// AMFI __text nop-filled.
    fn kernel(platform: Option<u32>, kmod_style: bool) -> Vec<u8> {
        let mut buf = vec![0u8; LEN];
        for i in 0..0x1000 / 4 {
            w32(&mut buf, AMFI_TEXT + 4 * i, NOP);
        }
        let ncmds = if platform.is_some() { 4 } else { 3 };
        header(&mut buf, 0, ncmds);
        let mut cmd = 32;
        cmd += segment64(
            &mut buf,
            cmd,
            "__TEXT",
            VA_BASE,
            0x5000,
            0,
            0x5000,
            &[("__cstring", VA_BASE + CSTR as u64, 0x1000, CSTR as u64)],
        );
        let prelink_sections: &[(&str, u64, u64, u64)] = if kmod_style {
            &[
                ("__kmod_info", VA_BASE + PLINFO as u64, 16, PLINFO as u64),
                (
                    "__kmod_start",
                    VA_BASE + (PLINFO + 0x10) as u64,
                    16,
                    (PLINFO + 0x10) as u64,
                ),
                (
                    "__data",
                    VA_BASE + (PLINFO + 0x100) as u64,
                    0x100,
                    (PLINFO + 0x100) as u64,
                ),
            ]
        } else {
            &[("__info", VA_BASE + PLINFO as u64, 0x1000, PLINFO as u64)]
        };
        cmd += segment64(
            &mut buf,
            cmd,
            "__PRELINK_INFO",
            VA_BASE + PLINFO as u64,
            0x1000,
            PLINFO as u64,
            0x1000,
            prelink_sections,
        );
        cmd += segment64(
            &mut buf,
            cmd,
            "__PRELINK_TEXT",
            VA_BASE + KTEXT as u64,
            (LEN - KTEXT) as u64,
            KTEXT as u64,
            (LEN - KTEXT) as u64,
            &[(
                "__text",
                VA_BASE + KTEXT as u64,
                (LEN - KTEXT) as u64,
                KTEXT as u64,
            )],
        );
        if let Some(platform) = platform {
            build_version(&mut buf, cmd, platform);
        }
        if kmod_style {
            prelink_kmod(&mut buf);
        } else {
            prelink_plist(&mut buf);
        }
        amfi_kext(&mut buf);
        apfs_kext(&mut buf);
        buf
    }

    fn word(index: usize) -> usize {
        AMFI_TEXT + 4 * index
    }

    /// trustcache old site: `bl lookup; mov w8, 0x101`, with the lookup
    /// function at `fn_index`.
    fn trustcache_old_site(buf: &mut [u8], site: usize, fn_index: usize) {
        w32(buf, word(site), bl(word(site), word(fn_index)));
        w32(buf, word(site + 1), 0x5280_2028);
    }

    /// sha1 site: tbz w2, 0x1a, * then cmp w0, 2.
    fn sha1_site(buf: &mut [u8], site: usize) {
        w32(buf, word(site), 0x36d0_0002);
        w32(buf, word(site + 1), 0x7100_081f);
    }

    #[test]
    fn applies_sha1_trustcache_and_snapshot_rename() {
        let mut buf = kernel(Some(2), false);
        sha1_site(&mut buf, 0x10);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x11)), 0x6b00_001f); // cmp w0, w0
        assert_eq!(r32at(out.image(), word(0x60)), 0xd280_2020); // mov x0, 0x101
        assert_eq!(r32at(out.image(), word(0x61)), RET);
        assert_eq!(out.image()[APFS_CSTR], b'x');
        assert_eq!(
            out.applied(),
            [
                Kernel64Patch::AmfiHashTypeCheck,
                Kernel64Patch::AmfiTrustcache,
                Kernel64Patch::ApfsSnapshotRename
            ]
        );
        assert!(out.missed().is_empty());
    }

    #[test]
    fn applies_sha1_trustcache_via_kmod_info() {
        let mut buf = kernel(Some(2), true);
        sha1_site(&mut buf, 0x10);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x11)), 0x6b00_001f);
        assert_eq!(r32at(out.image(), word(0x60)), 0xd280_2020);
        assert_eq!(out.image()[APFS_CSTR], b'x');
        assert!(out.missed().is_empty());
    }

    #[test]
    fn applies_launch_constraints_when_gated() {
        let mut buf = kernel(Some(2), false);
        put_str(&mut buf, CSTR, "mac_proc_check_launch_constraints");
        sha1_site(&mut buf, 0x10);
        // Function start (stp!), stack frame (stp x29, x30), then the
        // 5-word launch constraints sequence.
        w32(&mut buf, word(0x20), 0xa980_03e0);
        w32(&mut buf, word(0x22), 0xa900_7bfd);
        w32(&mut buf, word(0x28), 0x5280_6088);
        w32(&mut buf, word(0x29), 0x1400_0002);
        w32(&mut buf, word(0x2a), 0x5280_2088);
        w32(&mut buf, word(0x2b), 0x1400_0002);
        w32(&mut buf, word(0x2c), 0x5280_4088);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x20)), 0x5280_0000); // mov w0, 0
        assert_eq!(r32at(out.image(), word(0x21)), RET);
        assert!(
            out.applied()
                .contains(&Kernel64Patch::AmfiLaunchConstraints)
        );
        assert!(!out.missed().contains(&Kernel64Patch::AmfiLaunchConstraints));
    }

    #[test]
    fn skips_launch_constraints_without_gate() {
        let mut buf = kernel(Some(2), false);
        sha1_site(&mut buf, 0x10);
        w32(&mut buf, word(0x20), 0xa980_03e0);
        w32(&mut buf, word(0x22), 0xa900_7bfd);
        w32(&mut buf, word(0x28), 0x5280_6088);
        w32(&mut buf, word(0x29), 0x1400_0002);
        w32(&mut buf, word(0x2a), 0x5280_2088);
        w32(&mut buf, word(0x2b), 0x1400_0002);
        w32(&mut buf, word(0x2c), 0x5280_4088);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x20)), 0xa980_03e0); // untouched
        assert!(
            !out.applied()
                .contains(&Kernel64Patch::AmfiLaunchConstraints)
        );
        // Gated off: not reported as missed either.
        assert!(!out.missed().contains(&Kernel64Patch::AmfiLaunchConstraints));
    }

    #[test]
    fn applies_developer_mode_when_gated() {
        let mut buf = kernel(Some(2), false);
        put_str(
            &mut buf,
            AMFI_CSTR,
            "AMFI: developer mode is force enabled\n",
        );
        put_str(
            &mut buf,
            AMFI_CSTR + 0x100,
            "AMFI: Enabling developer mode since x",
        );
        put_str(
            &mut buf,
            AMFI_CSTR + 0x180,
            "AMFI: Disable developer mode since x",
        );
        // Enable site at 0x10, disable site at 0x18, functions at 0x30/0x38.
        let (adrp, add) = adrp_add(word(0x10), AMFI_CSTR + 0x100);
        w32(&mut buf, word(0x10), adrp);
        w32(&mut buf, word(0x11), add);
        w32(&mut buf, word(0x12), bl(word(0x12), word(0x30)));
        w32(&mut buf, word(0x13), bl(word(0x13), word(0x30)));
        let (adrp, add) = adrp_add(word(0x18), AMFI_CSTR + 0x180);
        w32(&mut buf, word(0x18), adrp);
        w32(&mut buf, word(0x19), add);
        w32(&mut buf, word(0x1a), bl(word(0x1a), word(0x38)));
        w32(&mut buf, word(0x1b), bl(word(0x1b), word(0x38)));
        sha1_site(&mut buf, 0x40);
        trustcache_old_site(&mut buf, 0x50, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        // disable's first word becomes `b enable` (backward 8 words).
        assert_eq!(r32at(out.image(), word(0x38)), 0x17ff_fff8);
        assert_eq!(r32at(out.image(), word(0x30)), NOP); // enable untouched
        assert!(out.applied().contains(&Kernel64Patch::AmfiDeveloperMode));
        assert!(out.missed().is_empty());
    }

    #[test]
    fn skips_developer_mode_without_gate() {
        let mut buf = kernel(Some(2), false);
        put_str(
            &mut buf,
            AMFI_CSTR + 0x100,
            "AMFI: Enabling developer mode since x",
        );
        put_str(
            &mut buf,
            AMFI_CSTR + 0x180,
            "AMFI: Disable developer mode since x",
        );
        let (adrp, add) = adrp_add(word(0x10), AMFI_CSTR + 0x100);
        w32(&mut buf, word(0x10), adrp);
        w32(&mut buf, word(0x11), add);
        w32(&mut buf, word(0x12), bl(word(0x12), word(0x30)));
        w32(&mut buf, word(0x13), bl(word(0x13), word(0x30)));
        let (adrp, add) = adrp_add(word(0x18), AMFI_CSTR + 0x180);
        w32(&mut buf, word(0x18), adrp);
        w32(&mut buf, word(0x19), add);
        w32(&mut buf, word(0x1a), bl(word(0x1a), word(0x38)));
        w32(&mut buf, word(0x1b), bl(word(0x1b), word(0x38)));
        trustcache_old_site(&mut buf, 0x50, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x38)), NOP);
        assert!(!out.missed().contains(&Kernel64Patch::AmfiDeveloperMode));
    }

    #[test]
    fn applies_trustcache_new() {
        let mut buf = kernel(Some(2), false);
        sha1_site(&mut buf, 0x10);
        w32(&mut buf, word(0x4e), 0xd100_43ff); // sub sp, sp, #0x10
        w32(&mut buf, word(0x50), 0x9100_03e0);
        w32(&mut buf, word(0x51), 0xaa13_03e1);
        w32(&mut buf, word(0x52), bl(word(0x52), word(0x60)));
        w32(&mut buf, word(0x53), 0x7100_029f);
        w32(&mut buf, word(0x54), 0x1a9f_17e0);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x4e)), 0xd280_0020); // mov x0, 1
        assert_eq!(r32at(out.image(), word(0x4f)), 0xb400_0042); // cbz x2, .+0x8
        assert_eq!(r32at(out.image(), word(0x50)), 0xf900_0040); // str x0, [x2]
        assert_eq!(r32at(out.image(), word(0x51)), RET);
        assert!(out.applied().contains(&Kernel64Patch::AmfiTrustcache));
    }

    #[test]
    fn trustcache_first_hit_wins() {
        let mut buf = kernel(Some(2), false);
        sha1_site(&mut buf, 0x10);
        // New variant at the lower offset wins; the old site stays untouched.
        w32(&mut buf, word(0x4e), 0xd100_43ff);
        w32(&mut buf, word(0x50), 0x9100_03e0);
        w32(&mut buf, word(0x51), 0xaa13_03e1);
        w32(&mut buf, word(0x52), bl(word(0x52), word(0x60)));
        w32(&mut buf, word(0x53), 0x7100_029f);
        w32(&mut buf, word(0x54), 0x1a9f_17e0);
        trustcache_old_site(&mut buf, 0x70, 0x78);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(r32at(out.image(), word(0x4e)), 0xd280_0020);
        assert_eq!(r32at(out.image(), word(0x78)), NOP);
        assert_eq!(
            out.applied()
                .iter()
                .filter(|&&p| p == Kernel64Patch::AmfiTrustcache)
                .count(),
            1
        );
    }

    #[test]
    fn skips_snapshot_rename_with_rootvp() {
        let mut buf = kernel(Some(2), false);
        put_str(&mut buf, CSTR, "rootvp not authenticated after mounting");
        sha1_site(&mut buf, 0x10);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert_eq!(out.image()[APFS_CSTR], b'c');
        assert!(!out.applied().contains(&Kernel64Patch::ApfsSnapshotRename));
        assert!(!out.missed().contains(&Kernel64Patch::ApfsSnapshotRename));
    }

    #[test]
    fn reports_missing_snapshot_string() {
        let mut buf = kernel(Some(2), false);
        sha1_site(&mut buf, 0x10);
        trustcache_old_site(&mut buf, 0x40, 0x60);

        let out = patch_kernel64(&buf).unwrap();
        assert!(out.missed().contains(&Kernel64Patch::ApfsSnapshotRename));
    }

    #[test]
    fn reports_sha1_miss() {
        let mut buf = kernel(Some(2), false);
        // tbz without the cmp nearby: the patch is reported, not applied.
        w32(&mut buf, word(0x10), 0x36d0_0002);
        trustcache_old_site(&mut buf, 0x40, 0x60);
        put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");

        let out = patch_kernel64(&buf).unwrap();
        assert!(out.missed().contains(&Kernel64Patch::AmfiHashTypeCheck));
        assert!(out.applied().contains(&Kernel64Patch::AmfiTrustcache));
    }

    #[test]
    fn patches_arm64_fat_slice_in_place() {
        let thin = {
            let mut buf = kernel(Some(2), false);
            sha1_site(&mut buf, 0x10);
            trustcache_old_site(&mut buf, 0x40, 0x60);
            put_str(&mut buf, APFS_CSTR, "com.apple.os.update-");
            buf
        };
        let mut fat = vec![0xAAu8; 0x1000];
        fat.extend_from_slice(&thin);
        fat.extend_from_slice(&[0xAA; 0x100]);
        w32be(&mut fat, 0, FAT_MAGIC);
        w32be(&mut fat, 4, 2);
        w32be(&mut fat, 8, 0x0100_0007); // x86_64
        w32be(&mut fat, 8 + 8, 0x100);
        w32be(&mut fat, 8 + 12, 0x100);
        w32be(&mut fat, 8 + 20, CPU_TYPE_ARM64);
        w32be(&mut fat, 8 + 20 + 8, 0x1000);
        w32be(&mut fat, 8 + 20 + 12, LEN as u32);

        let out = patch_kernel64(&fat).unwrap();
        let base = 0x1000;
        assert_eq!(r32at(out.image(), base + word(0x11)), 0x6b00_001f);
        assert_eq!(r32at(out.image(), base + word(0x60)), 0xd280_2020);
        assert_eq!(out.image()[base + APFS_CSTR], b'x');
        // Header and the other slice pass through untouched.
        assert_eq!(out.image()[8..12], fat[8..12]);
        assert!(out.image()[0x100..0x200].iter().all(|&b| b == 0xAA));
        assert!(out.image()[base + LEN..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn rejects_fat_without_arm64() {
        let mut fat = vec![0u8; 0x200];
        w32be(&mut fat, 0, FAT_MAGIC);
        w32be(&mut fat, 4, 1);
        w32be(&mut fat, 8, 0x0100_0007);
        w32be(&mut fat, 8 + 8, 0x100);
        w32be(&mut fat, 8 + 12, 0x100);
        let err = patch_kernel64(&fat).unwrap_err();
        assert!(matches!(err, Kernel64Error::NoArm64Slice));
    }

    #[test]
    fn rejects_bad_magic() {
        let err = patch_kernel64(&[0u8; 0x100]).unwrap_err();
        assert!(matches!(err, Kernel64Error::BadMagic));
    }

    #[test]
    fn rejects_platform() {
        let err = patch_kernel64(&kernel(Some(6), false)).unwrap_err();
        assert!(matches!(err, Kernel64Error::UnsupportedPlatform(6)));
        let err = patch_kernel64(&kernel(Some(0), false)).unwrap_err();
        assert!(matches!(err, Kernel64Error::UnsupportedPlatform(0)));
        let err = patch_kernel64(&kernel(None, false)).unwrap_err();
        assert!(matches!(err, Kernel64Error::PlatformNotFound));
    }

    #[test]
    fn errors_when_nothing_applies() {
        let mut buf = kernel(Some(2), false);
        // rootvp present blocks the rename; no AMFI patterns at all.
        put_str(&mut buf, CSTR, "rootvp not authenticated after mounting");
        let err = patch_kernel64(&buf).unwrap_err();
        assert!(matches!(err, Kernel64Error::NoPatchesApplied));
    }
}
