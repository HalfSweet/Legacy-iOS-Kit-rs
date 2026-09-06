//! Tests on synthetic arm64 iBoot images: just enough instruction and string
//! structure for each patch strategy to find its anchors. No real firmware
//! bytes are used.

use super::patchfinder64::{
    Kind, Patchfinder64, new_general_adr, new_immediate_add, new_immediate_b, new_immediate_movz,
};
use super::*;

const BASE: u64 = 0x1_8000_0000;
const SIZE: usize = 0x4000;

// ---------------------------------------------------------------------------
// Instruction encoders for fixture construction.
// ---------------------------------------------------------------------------

fn adr(off: usize, target: usize, rd: u8) -> u32 {
    let imm = target as i64 - off as i64;
    (0x10 << 24)
        | (((imm as u64 & 0b11) << 29) as u32)
        | ((((imm >> 2) & 0x7_ffff) << 5) as u32)
        | u32::from(rd)
}

fn adrp(off: usize, target: usize, rd: u8) -> u32 {
    let imm = ((BASE + target as u64) >> 12) as i64 - ((BASE + off as u64) >> 12) as i64;
    (0x90 << 24)
        | (((imm as u64 & 0b11) << 29) as u32)
        | ((((imm >> 2) & 0x7_ffff) << 5) as u32)
        | u32::from(rd)
}

fn add(rd: u8, rn: u8, imm: u32) -> u32 {
    0x9100_0000 | (imm << 10) | (u32::from(rn) << 5) | u32::from(rd)
}

fn sub(rd: u8, rn: u8, imm: u32) -> u32 {
    0xd100_0000 | (imm << 10) | (u32::from(rn) << 5) | u32::from(rd)
}

/// `mov xd, xm` (orr with xzr).
fn mov(rd: u8, rm: u8) -> u32 {
    0xaa00_0000 | (u32::from(rm) << 16) | (31 << 5) | u32::from(rd)
}

fn movz(rd: u8, imm: u32, hw: u32) -> u32 {
    0xd280_0000 | (hw << 21) | (imm << 5) | u32::from(rd)
}

fn movk(rd: u8, imm: u32, hw: u32) -> u32 {
    0xf280_0000 | (hw << 21) | (imm << 5) | u32::from(rd)
}

fn bl(off: usize, target: usize) -> u32 {
    let imm = (target as i64 - off as i64) >> 2;
    0x9400_0000 | (imm as u32 & 0x3ff_ffff)
}

fn b(off: usize, target: usize) -> u32 {
    let imm = (target as i64 - off as i64) >> 2;
    0x1400_0000 | (imm as u32 & 0x3ff_ffff)
}

fn bcond(off: usize, target: usize, cond: u32) -> u32 {
    let imm = (target as i64 - off as i64) >> 2;
    0x5400_0000 | ((imm as u32 & 0x7_ffff) << 5) | cond
}

fn cbz(off: usize, target: usize, rt: u8) -> u32 {
    let imm = (target as i64 - off as i64) >> 2;
    0x3400_0000 | ((imm as u32 & 0x7_ffff) << 5) | u32::from(rt)
}

fn cbnz(off: usize, target: usize, rt: u8) -> u32 {
    cbz(off, target, rt) | 0x0100_0000
}

fn csel(rd: u8, rn: u8, rm: u8, cond: u32) -> u32 {
    0x9a80_0000 | (u32::from(rm) << 16) | (cond << 12) | (u32::from(rn) << 5) | u32::from(rd)
}

fn strb_u(rt: u8, rn: u8, imm: u32) -> u32 {
    0x3900_0000 | (imm << 10) | (u32::from(rn) << 5) | u32::from(rt)
}

/// `ldr xt, [xn, #imm]` (64-bit unsigned offset).
fn ldr_u(rt: u8, rn: u8, imm: u32) -> u32 {
    0xf940_0000 | ((imm >> 3) << 10) | (u32::from(rn) << 5) | u32::from(rt)
}

/// `subs xzr, xn, #imm` (64-bit cmp).
fn cmp64(rn: u8, imm: u32) -> u32 {
    0xf100_0000 | (imm << 10) | (u32::from(rn) << 5) | 31
}

/// `subs wzr, wn, #imm` (32-bit cmp).
fn cmp32(rn: u8, imm: u32) -> u32 {
    0x7100_0000 | (imm << 10) | (u32::from(rn) << 5) | 31
}

/// `stp x29, x30, [sp, #-16]!`
fn stp_fp_lr() -> u32 {
    0xa9bf_7bfd
}

/// `ldp x29, x30, [sp], #16`
fn ldp_fp_lr() -> u32 {
    0xa8c1_7bfd
}

/// `ldp xt, xt2, [sp], #imm` (post-index).
fn ldp_post(rt: u8, rt2: u8, imm: u32) -> u32 {
    0xa8c0_0000 | ((imm >> 3) << 15) | (u32::from(rt2) << 10) | (31 << 5) | u32::from(rt)
}

fn ret() -> u32 {
    0xd65f_03c0
}

const fn nop() -> u32 {
    0xd503_201f
}

const MOVZ_X0_0: u32 = 0xd280_0000;
const MOVZ_X1_1: u32 = 0xd280_0021;

// ---------------------------------------------------------------------------
// Image fixture builder.
// ---------------------------------------------------------------------------

struct Image(Vec<u8>);

impl Image {
    /// A valid-header image: magic, "iBoot-<version>" at 0x280, base address
    /// at both 0x300 and 0x318.
    fn new(version: &str) -> Self {
        let mut image = Self(vec![0u8; SIZE]);
        image.w32(0, 0x9000_0000);
        let version_string = format!("iBoot-{version}.1");
        image.strz(IBOOT_VERS_STR_OFFSET, version_string.as_bytes());
        image.w64(IBOOT_BASE_OFFSET, BASE);
        image.w64(IBOOT_14_BASE_OFFSET, BASE);
        image
    }

    fn w32(&mut self, off: usize, value: u32) {
        self.0[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn w64(&mut self, off: usize, value: u64) {
        self.0[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn strz(&mut self, off: usize, s: &[u8]) {
        self.0[off..off + s.len()].copy_from_slice(s);
        self.0[off + s.len()] = 0;
    }

    fn word(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.0[off..off + 4].try_into().unwrap())
    }
}

fn loc(off: usize) -> u64 {
    BASE + off as u64
}

// ---------------------------------------------------------------------------
// Factory / validation.
// ---------------------------------------------------------------------------

#[test]
fn factory_validates_the_header() {
    assert!(matches!(
        IBoot64::new(&mut vec![0u8; 0x1000]),
        Err(Iboot64PatchError::ImageTooSmall)
    ));

    let mut no_version_string = Image::new("5540").0;
    no_version_string[0x280] = b'X';
    assert!(matches!(
        IBoot64::new(&mut no_version_string),
        Err(Iboot64PatchError::MissingVersionString)
    ));

    let mut bad_magic = Image::new("5540").0;
    bad_magic[0..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    assert!(matches!(
        IBoot64::new(&mut bad_magic),
        Err(Iboot64PatchError::BadMagic)
    ));

    // Alternate magics: branch-over-header and PAC-style prologue.
    let mut branch_magic = Image::new("5540").0;
    branch_magic[0..4].copy_from_slice(&0x1400_0001u32.to_le_bytes());
    branch_magic[0x10..0x14].copy_from_slice(&0x9000_0000u32.to_le_bytes());
    assert!(IBoot64::new(&mut branch_magic).is_ok());

    let mut pac_magic = Image::new("5540").0;
    pac_magic[0..4].copy_from_slice(&0xd53c_1102u32.to_le_bytes());
    pac_magic[0xc..0x10].copy_from_slice(&0xd51c_1102u32.to_le_bytes());
    assert!(IBoot64::new(&mut pac_magic).is_ok());

    // atoi of a non-numeric version yields 0, which is rejected.
    let mut bad_version = Image::new("5540").0;
    bad_version[0x286] = b'x';
    assert!(matches!(
        IBoot64::new(&mut bad_version),
        Err(Iboot64PatchError::VersionNotFound)
    ));

    // iOS 17 is out of scope.
    assert!(matches!(
        IBoot64::new(&mut Image::new("10101").0),
        Err(Iboot64PatchError::UnsupportedVersion(10101))
    ));
}

#[test]
fn factory_dispatches_on_version() {
    let cases: &[(&str, Class)] = &[
        ("1700", Class::Base),
        ("1940", Class::Ios7),
        ("2800", Class::Ios9),
        ("3300", Class::Ios10),
        ("4510", Class::Ios12),
        ("5540", Class::Ios13),
        ("6603", Class::Ios14),
        ("7400", Class::Ios15),
        ("8400", Class::Ios16),
    ];
    for &(version, class) in cases {
        let mut image = Image::new(version).0;
        let iboot = IBoot64::new(&mut image).unwrap();
        assert_eq!(iboot.class, class, "version {version}");
        assert_eq!(iboot.version(), version.parse::<u32>().unwrap());
    }
}

#[test]
fn ios14_reads_the_base_address_from_0x300() {
    let mut image = Image::new("5540").0;
    image[0x300..0x308].copy_from_slice(&0x1111_u64.to_le_bytes());
    image[0x318..0x320].copy_from_slice(&0x2222_u64.to_le_bytes());
    assert_eq!(IBoot64::new(&mut image).unwrap().base_address(), 0x2222);

    let mut image = Image::new("6603").0;
    image[0x300..0x308].copy_from_slice(&0x1111_u64.to_le_bytes());
    image[0x318..0x320].copy_from_slice(&0x2222_u64.to_le_bytes());
    assert_eq!(IBoot64::new(&mut image).unwrap().base_address(), 0x1111);
}

#[test]
fn detects_kernel_load_and_recovery_console() {
    let mut image = Image::new("5540");
    image.strz(0x2000, b"__PAGEZERO");
    image.strz(0x2100, b"Entering recovery mode, starting command prompt");
    let iboot = IBoot64::new(&mut image.0).unwrap();
    assert!(iboot.has_kernel_load());
    assert!(iboot.has_recovery_console());

    let mut empty = Image::new("5540");
    let iboot = IBoot64::new(&mut empty.0).unwrap();
    assert!(!iboot.has_kernel_load());
    assert!(!iboot.has_recovery_console());
}

// ---------------------------------------------------------------------------
// Decoder / encoder primitives.
// ---------------------------------------------------------------------------

#[test]
fn decodes_and_encodes_branch_and_address_instructions() {
    let mut image = Image::new("5540");
    image.w32(0x100, adrp(0x100, 0x3000, 8));
    image.w32(0x104, add(8, 8, 0));
    image.w32(0x108, adr(0x108, 0x200, 9));
    image.w32(0x10c, bl(0x10c, 0x400));
    image.w32(0x110, b(0x110, 0x80));
    image.w32(0x114, csel(8, 8, 9, 0));
    image.w32(0x118, ldr_u(8, 19, 0x10));
    image.w32(0x11c, strb_u(1, 2, 0x25));

    let pf = Patchfinder64::new(&image.0, BASE);
    let cursor = |off| pf.cursor_at(loc(off)).unwrap();
    let insn = |off| pf.insn(cursor(off)).unwrap();

    let insn_adrp = insn(0x100);
    assert_eq!(insn_adrp.kind(), Kind::Adrp);
    assert_eq!(insn_adrp.imm(), Some(loc(0x3000) as i64));
    assert_eq!(insn_adrp.rd(), Some(8));

    let insn_adr = insn(0x108);
    assert_eq!(insn_adr.kind(), Kind::Adr);
    assert_eq!(insn_adr.imm(), Some(loc(0x200) as i64));

    let insn_bl = insn(0x10c);
    assert_eq!(insn_bl.kind(), Kind::Bl);
    assert_eq!(insn_bl.imm(), Some(loc(0x400) as i64));
    assert_eq!(insn_bl.supertype(), Supertype::BranchImm);

    let insn_b = insn(0x110);
    assert_eq!(insn_b.imm(), Some(loc(0x80) as i64));

    let insn_csel = insn(0x114);
    assert_eq!(insn_csel.kind(), Kind::Csel);
    assert_eq!(
        (insn_csel.rd(), insn_csel.rn(), insn_csel.rm()),
        (Some(8), Some(8), Some(9))
    );

    let insn_ldr = insn(0x118);
    assert_eq!(insn_ldr.kind(), Kind::Ldr);
    assert_eq!(insn_ldr.imm(), Some(0x10));
    assert_eq!(insn_ldr.rn(), Some(19));

    let insn_strb = insn(0x11c);
    assert_eq!(insn_strb.kind(), Kind::Strb);
    assert_eq!(insn_strb.imm(), Some(0x25));
    assert_eq!(insn_strb.rn(), Some(2));
}

#[test]
fn encoders_round_trip_through_the_decoder() {
    let image = Image::new("5540").0;
    let decode = |opcode: u32, off: usize| {
        let mut buf = image.clone();
        buf[off..off + 4].copy_from_slice(&opcode.to_le_bytes());
        let pf = Patchfinder64::new(&buf, BASE);
        pf.insn(pf.cursor_at(loc(off)).unwrap()).unwrap()
    };

    // new_general_adr produces an adr with the right target.
    let opcode = new_general_adr(loc(0x100), loc(0x300) as i64, 5).unwrap();
    let insn = decode(opcode, 0x100);
    assert_eq!(insn.kind(), Kind::Adr);
    assert_eq!(insn.imm(), Some(loc(0x300) as i64));
    assert_eq!(insn.rd(), Some(5));

    // new_immediate_b / new_immediate_movz / new_immediate_add.
    let insn = decode(
        new_immediate_b(loc(0x100), loc(0x80) as i64).unwrap(),
        0x100,
    );
    assert_eq!(insn.kind(), Kind::B);
    assert_eq!(insn.imm(), Some(loc(0x80) as i64));

    let insn = decode(new_immediate_movz(0x1234, 7, 16).unwrap(), 0x100);
    assert_eq!(insn.kind(), Kind::Movz);
    assert_eq!(insn.imm(), Some(0x1234_0000));
    assert_eq!(insn.rd(), Some(7));

    let insn = decode(new_immediate_add(0x40, 8, 9).unwrap(), 0x100);
    assert_eq!(insn.kind(), Kind::Add);
    assert_eq!(insn.imm(), Some(0x40));
    assert_eq!(insn.rn(), Some(8));

    // Range checks reject what upstream's retassure rejects.
    assert!(new_general_adr(loc(0x100), loc(0x100) as i64 + (1 << 20), 5).is_none());
    assert!(new_immediate_b(loc(0x100), loc(0x102) as i64).is_none());
    assert!(new_immediate_movz(1, 0, 8).is_none());
}

// ---------------------------------------------------------------------------
// Finder primitives.
// ---------------------------------------------------------------------------

#[test]
fn find_literal_ref_supports_movz_movk_chains() {
    let mut image = Image::new("5540");
    image.w32(0x100, movz(5, 0x2000, 0));
    image.w32(0x104, movk(5, 0x8000, 1));
    image.w32(0x108, movk(5, 0x1, 2));

    let pf = Patchfinder64::new(&image.0, BASE);
    assert_eq!(
        pf.find_literal_ref(loc(0x2000), 0, 0),
        Some(loc(0x108)),
        "the chain ends at the final movk"
    );
    // A partial sum is not a reference.
    assert_eq!(pf.find_literal_ref(loc(0x2000) - 0x1_0000, 0, 0), None);
}

#[test]
fn find_call_ref_honors_ignore_times() {
    let mut image = Image::new("5540");
    image.w32(0x100, bl(0x100, 0x400));
    image.w32(0x200, bl(0x200, 0x400));

    let pf = Patchfinder64::new(&image.0, BASE);
    assert_eq!(pf.find_call_ref(loc(0x400), 0, 0), Some(loc(0x100)));
    assert_eq!(pf.find_call_ref(loc(0x400), 1, 0), Some(loc(0x200)));
    assert_eq!(pf.find_call_ref(loc(0x400), 2, 0), None);
}

#[test]
fn find_branch_ref_spends_the_limit_on_non_branch_instructions() {
    let mut image = Image::new("5540");
    // 4 nops and one branch to 0x400 walking back from 0x200.
    for off in (0x180..0x1fc).step_by(4) {
        image.w32(off, nop());
    }
    image.w32(0x1c0, bcond(0x1c0, 0x400, 1));

    let pf = Patchfinder64::new(&image.0, BASE);
    // 0x200 - 0x1c0 = 0x40 bytes back: 15 non-branch instructions = 60 bytes
    // of limit; branches do not spend it (upstream quirk).
    assert_eq!(
        pf.find_branch_ref(loc(0x400), -0x40, 0, loc(0x200)),
        Some(loc(0x1c0))
    );
    assert_eq!(pf.find_branch_ref(loc(0x400), -0x3c, 0, loc(0x200)), None);
}

#[test]
fn find_bof_skips_sub_sp_and_pacibsp() {
    let mut image = Image::new("5540");
    image.w32(0x100, 0xd503_237f); // pacibsp
    image.w32(0x104, sub(31, 31, 0x40));
    image.w32(0x108, stp_fp_lr());
    image.w32(0x10c, nop());
    image.w32(0x110, ret());

    let pf = Patchfinder64::new(&image.0, BASE);
    assert_eq!(pf.find_bof(loc(0x10c), false), Some(loc(0x100)));
    // Without pacibsp the sub leads the function.
    image.w32(0x100, nop());
    let pf = Patchfinder64::new(&image.0, BASE);
    assert_eq!(pf.find_bof(loc(0x10c), false), Some(loc(0x104)));
}

// ---------------------------------------------------------------------------
// The sigcheck patch, per strategy.
// ---------------------------------------------------------------------------

/// Base-strategy image (version < 1940): seven consecutive strb and a
/// trailing overwrite branch, plus a branch back to the run.
fn base_sigcheck_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.w32(0x0c0, bcond(0x0c0, 0x100, 0)); // b.eq to the strb run
    for i in 0..7u32 {
        image.w32(0x100 + 4 * i as usize, strb_u(1, 2, 0x20 + i));
    }
    image.w32(0x11c, b(0x11c, 0x140)); // the overwrite branch
    image
}

#[test]
fn sigcheck_base_strategy_rewrites_the_strb_run() {
    let mut image = base_sigcheck_image("1700");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_sigcheck_patch().unwrap();

    let image = Image(iboot.buf.to_vec());
    assert_eq!(image.word(0x100), MOVZ_X1_1); // movz x1, #1
    // lowestOffset is 0x20: strb w1, [x2, #0x21] / #0x23 / #0x24.
    assert_eq!(image.word(0x104), strb_u(1, 2, 0x21));
    assert_eq!(image.word(0x108), strb_u(1, 2, 0x23));
    assert_eq!(image.word(0x10c), strb_u(1, 2, 0x24));
    assert_eq!(image.word(0x110), nop());
    assert_eq!(image.word(0x114), nop());
    assert_eq!(image.word(0x118), nop());
    // The overwrite branch now jumps just past the branch reference.
    assert_eq!(image.word(0x11c), b(0x11c, 0x0c4));

    let patches = iboot.applied_patches();
    assert!(patches.iter().all(|patch| patch.patch() == "sigcheck"));
    assert_eq!(patches.len(), 8);
    assert_eq!(patches[0].offset(), 0x100);
    assert_eq!(patches[0].bytes(), MOVZ_X1_1.to_le_bytes());
}

/// Callback-strategy image shared by iOS 7 (fallback) and 9: the IMG4 string
/// reference inside the loader, two call levels up, and the callback whose
/// epilogue branch gets replaced with `movz x0, #0`.
fn callback_sigcheck_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x3000, b"IMG4");
    // First caller of the image loader (ignored: the strategy wants the
    // second).
    image.w32(0x200, bl(0x200, 0x600));
    // The verification callback.
    image.w32(0x400, cbnz(0x400, 0x418, 8));
    image.w32(0x404, sub(31, 31, 0x20));
    image.w32(0x408, ldp_fp_lr());
    image.w32(0x40c, ldp_post(20, 21, 0x20));
    image.w32(0x410, ret());
    // The caller that sets up the callback (f2).
    image.w32(0x500, stp_fp_lr());
    image.w32(0x504, adr(0x504, 0x400, 2)); // x2 = callback
    image.w32(0x508, adr(0x508, 0x700, 3)); // x3 = context
    image.w32(0x50c, bl(0x50c, 0x780));
    image.w32(0x510, bl(0x510, 0x600)); // second call to the loader
    image.w32(0x514, ret());
    // The image loader (f1) referencing "IMG4".
    image.w32(0x600, stp_fp_lr());
    image.w32(0x604, adrp(0x604, 0x3000, 8));
    image.w32(0x608, add(8, 8, 0));
    image.w32(0x60c, ret());
    image
}

#[test]
fn sigcheck_callback_strategy_ios9() {
    let mut image = callback_sigcheck_image("2817");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_sigcheck_patch().unwrap();

    assert_eq!(iboot.buf[0x400..0x404], MOVZ_X0_0.to_le_bytes());
    let patches = iboot.applied_patches();
    assert_eq!(patches.len(), 1);
    assert_eq!(
        (patches[0].patch(), patches[0].offset()),
        ("sigcheck", 0x400)
    );
}

#[test]
fn sigcheck_ios7_falls_back_to_the_callback_strategy() {
    // No seven-strb run in this image: the base strategy fails and iOS 7
    // falls back to the callback strategy.
    let mut image = callback_sigcheck_image("1940");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_sigcheck_patch().unwrap();

    assert_eq!(iboot.buf[0x400..0x404], MOVZ_X0_0.to_le_bytes());
    assert_eq!(iboot.applied_patches().len(), 1);
}

/// iOS 10-13 callback-strategy image: the callback is read through the
/// pointer the `adr x2` targets, and the epilogue has the `sub x29` shape.
fn callback10_sigcheck_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x3000, b"IMG4");
    image.w32(0x200, bl(0x200, 0x600)); // first call ref (ignored)
    // The verification callback: branch, sub sp, x29, ..., ldp, ret.
    image.w32(0x400, cbnz(0x400, 0x420, 8));
    image.w32(0x404, sub(31, 29, 0x40)); // sub sp, x29, #0x40
    image.w32(0x408, ldp_fp_lr());
    image.w32(0x40c, ret());
    // f2: sets up the callback through a pointer.
    image.w32(0x500, stp_fp_lr());
    image.w32(0x504, adr(0x504, 0x800, 2));
    image.w32(0x508, adr(0x508, 0x900, 3));
    image.w32(0x50c, bl(0x50c, 0x780));
    image.w32(0x510, bl(0x510, 0x600)); // second call to the loader
    image.w32(0x514, ret());
    image.w64(0x800, loc(0x400)); // callback pointer
    // f1: the image loader referencing "IMG4".
    image.w32(0x600, stp_fp_lr());
    image.w32(0x604, adrp(0x604, 0x3000, 8));
    image.w32(0x608, add(8, 8, 0));
    image.w32(0x60c, ret());
    image
}

#[test]
fn sigcheck_callback_strategy_ios10_through_13() {
    for version in ["3393", "4510", "5540"] {
        let mut image = callback10_sigcheck_image(version);
        let mut iboot = IBoot64::new(&mut image.0).unwrap();
        iboot.get_sigcheck_patch().unwrap();

        assert_eq!(
            iboot.buf[0x400..0x404],
            MOVZ_X0_0.to_le_bytes(),
            "version {version}"
        );
    }
}

/// iOS 14 cmp/branch chain image.
fn ios14_sigcheck_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.w32(0x100, cmp32(8, 1));
    image.w32(0x104, bcond(0x104, 0x200, 1));
    image.w32(0x108, ldr_u(8, 19, 0x10));
    image.w32(0x10c, cmp64(8, 4));
    image.w32(0x110, bcond(0x110, 0x204, 0));
    image.w32(0x114, cmp64(8, 2));
    image.w32(0x118, bcond(0x118, 0x208, 0));
    image.w32(0x11c, cmp64(8, 1));
    image.w32(0x120, bcond(0x120, 0x20c, 1));
    image.w32(0x124, mov(0, 20)); // mov x0, x20
    image.w32(0x128, ldp_fp_lr());
    image.w32(0x12c, ret());
    image
}

#[test]
fn sigcheck_ios14_cmp_chain() {
    let mut image = ios14_sigcheck_image("6603");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_sigcheck_patch().unwrap();

    assert_eq!(iboot.buf[0x124..0x128], MOVZ_X0_0.to_le_bytes());
}

/// iOS 15/16 chain image: ldr/cmp chain, then four consecutive ldp, then the
/// `mov x0, ...` going back.
fn ios15_sigcheck_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.w32(0x100, ldr_u(8, 19, 0x10));
    image.w32(0x104, cmp64(8, 4));
    image.w32(0x108, bcond(0x108, 0x200, 0));
    image.w32(0x10c, cmp64(8, 2));
    image.w32(0x110, bcond(0x110, 0x204, 0));
    image.w32(0x114, cmp64(8, 1));
    image.w32(0x118, bcond(0x118, 0x208, 1));
    image.w32(0x11c, mov(0, 20)); // mov x0, x20
    image.w32(0x120, ldp_post(20, 21, 0x20));
    image.w32(0x124, ldp_post(22, 23, 0x20));
    image.w32(0x128, ldp_post(24, 25, 0x20));
    image.w32(0x12c, ldp_fp_lr());
    image.w32(0x130, ret());
    image
}

#[test]
fn sigcheck_ios15_and_ios16_chain() {
    for version in ["7400", "8400"] {
        let mut image = ios15_sigcheck_image(version);
        let mut iboot = IBoot64::new(&mut image.0).unwrap();
        iboot.get_sigcheck_patch().unwrap();

        assert_eq!(
            iboot.buf[0x11c..0x120],
            MOVZ_X0_0.to_le_bytes(),
            "version {version}"
        );
    }
}

#[test]
fn sigcheck_reports_a_typed_error_when_the_pattern_is_missing() {
    let mut image = Image::new("5540").0; // no IMG4 string at all
    let mut iboot = IBoot64::new(&mut image).unwrap();
    assert!(matches!(
        iboot.get_sigcheck_patch(),
        Err(Iboot64PatchError::PatternNotFound {
            patch: "sigcheck",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// debug-enabled.
// ---------------------------------------------------------------------------

fn debug_enabled_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x2000, b"debug-enabled");
    image.w32(0x200, adrp(0x200, 0x2000, 8));
    image.w32(0x204, add(8, 8, 0));
    image.w32(0x208, bl(0x208, 0x700));
    image.w32(0x20c, bl(0x20c, 0x704)); // <- overwritten
    image
}

#[test]
fn debug_enabled_patches_the_second_call() {
    let mut image = debug_enabled_image("5540");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_debug_enabled_patch().unwrap();

    assert_eq!(iboot.buf[0x20c..0x210], [0x20, 0x00, 0x80, 0xd2]); // movz x0, #1
    assert_eq!(iboot.buf[0x208..0x20c], bl(0x208, 0x700).to_le_bytes());
    assert_eq!(iboot.applied_patches()[0].patch(), "debug-enabled");
}

// ---------------------------------------------------------------------------
// boot-args.
// ---------------------------------------------------------------------------

/// Base-method image: the default boot-args string with an adr reference, a
/// csel consuming it, and the trailing adr behind a conditional branch. The
/// reference sits at `ref_off` (iOS 14-class images keep code clear of the
/// base-address field at 0x300).
fn boot_args_image_at(version: &str, ref_off: usize) -> Image {
    let mut image = Image::new(version);
    image.strz(0x3000, b"rd=md0 nand-enable-reformat=1 -progress");
    // The trailing adr must sit past the reference: find_literal_ref
    // returns the first reference to the string.
    image.w32(ref_off - 4, bcond(ref_off - 4, 0x700, 0)); // b.eq
    image.w32(ref_off, adr(ref_off, 0x3000, 8)); // the default-args reference
    image.w32(ref_off + 4, nop());
    image.w32(ref_off + 8, csel(8, 8, 9, 0)); // csel x8, x8, x9, eq
    image.w32(0x700, adr(0x700, 0x3000, 10));
    image
}

fn boot_args_image(version: &str) -> Image {
    boot_args_image_at(version, 0x300)
}

#[test]
fn boot_args_base_method_short_args() {
    let mut image = boot_args_image("5540");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v").unwrap();

    assert_eq!(iboot.buf[0x3000..0x3003], *b"-v\0");
    // The csel became `mov x8, x8`: always pick the stock-args operand.
    assert_eq!(iboot.buf[0x308..0x30c], mov(8, 8).to_le_bytes());
    // The trailing adr still points at the (rewritten) default string.
    assert_eq!(
        iboot.buf[0x700..0x704],
        adr(0x700, 0x3000, 10).to_le_bytes()
    );

    let patches = iboot.applied_patches();
    assert_eq!(patches.len(), 3);
    assert!(patches.iter().all(|patch| patch.patch() == "boot-args"));
    assert_eq!(patches[0].offset(), 0x3000); // the string
    assert_eq!(patches[0].bytes(), b"-v\0");
    assert_eq!(patches[1].offset(), 0x308); // the csel fixup
    assert_eq!(patches[2].offset(), 0x700); // the trailing adr
}

#[test]
fn boot_args_long_args_relocate_onto_the_cert_string() {
    let mut image = boot_args_image("5540");
    image.strz(0x3100, b"Apple Inc.1");
    let long_args = "rd=md0 nand-enable-reformat=1 -progress -v serial=3";
    assert!(long_args.len() > b"rd=md0 nand-enable-reformat=1 -progress".len());

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch(long_args).unwrap();

    // The adr reference now points at the cert string storage.
    assert_eq!(iboot.buf[0x300..0x304], adr(0x300, 0x3100, 8).to_le_bytes());
    // The args landed there, NUL-terminated.
    let mut expected = long_args.as_bytes().to_vec();
    expected.push(0);
    assert_eq!(iboot.buf[0x3100..0x3100 + expected.len()], expected);
    // And the trailing adr follows the relocation.
    assert_eq!(
        iboot.buf[0x700..0x704],
        adr(0x700, 0x3100, 10).to_le_bytes()
    );

    let patches = iboot.applied_patches();
    assert_eq!(patches[0].offset(), 0x300); // adr rewrite first
    assert_eq!(patches[1].offset(), 0x3100); // then the string
}

#[test]
fn boot_args_relocation_rewrites_an_adrp_add_pair() {
    let mut image = boot_args_image("5540");
    image.strz(0x3100, b"Apple Inc.1");
    // Same reference, but formed as adrp+add.
    image.w32(0x300, adrp(0x300, 0x3000, 8));
    image.w32(0x304, add(8, 8, 0));
    let long_args = "rd=md0 nand-enable-reformat=1 -progress -v serial=3";

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch(long_args).unwrap();

    assert_eq!(
        iboot.buf[0x300..0x304],
        adrp(0x300, 0x3100, 8).to_le_bytes()
    );
    assert_eq!(iboot.buf[0x304..0x308], add(8, 8, 0x100).to_le_bytes());
}

/// iOS 14.5-method image: only "rd=md0", a conditional branch before its
/// reference, and the adr in the always-taken block. The code sits at 0x600
/// because the iOS 14 class reads the base address from 0x300.
fn boot_args_14_5_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x3000, b"rd=md0");
    image.w32(0x5fc, cbz(0x5fc, 0x700, 8));
    image.w32(0x600, adrp(0x600, 0x3000, 8));
    image.w32(0x604, add(8, 8, 0)); // the reference
    image.w32(0x700, adr(0x700, 0x3400, 0)); // the "no bootarg"-case adr
    image
}

#[test]
fn boot_args_ios14_5_method() {
    let mut image = boot_args_14_5_image("6603");
    image.strz(0x3100, b"setpicture optmask");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v keepsize").unwrap();

    // The conditional branch became an unconditional b to its target.
    assert_eq!(iboot.buf[0x5fc..0x600], b(0x5fc, 0x700).to_le_bytes());
    // The adr in the taken block now points at the relocated string.
    assert_eq!(iboot.buf[0x700..0x704], adr(0x700, 0x3100, 0).to_le_bytes());
    assert_eq!(iboot.buf[0x3100..0x310c], *b"-v keepsize\0");

    let patches = iboot.applied_patches();
    assert_eq!(patches.len(), 3);
    assert!(patches.iter().all(|patch| patch.patch() == "boot-args"));
}

#[test]
fn boot_args_ios14_5_fallback_scans_for_the_empty_args_adr() {
    let mut image = boot_args_14_5_image("6603");
    image.strz(0x3100, b"setpicture optmask");
    image.strz(0x3500, b"-v");
    // The taken block does not start with the adr; the fallback scan finds
    // the reference to the "-v" placeholder.
    image.w32(0x700, mov(0, 1));
    image.w32(0x704, adr(0x704, 0x3500, 8));

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v keepsize").unwrap();

    assert_eq!(iboot.buf[0x704..0x708], adr(0x704, 0x3100, 8).to_le_bytes());
    assert_eq!(iboot.buf[0x3100..0x310c], *b"-v keepsize\0");
}

#[test]
fn boot_args_ios14_tries_the_base_method_first() {
    // Full base-method structure on an iOS 14 image (code at 0x600, clear
    // of the 0x300 base field): the base method wins and the 14.5 method's
    // branch rewrite never happens.
    let mut image = boot_args_image_at("6603", 0x600);
    let bcond_before = image.word(0x5fc);
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v").unwrap();

    assert_eq!(iboot.buf[0x3000..0x3003], *b"-v\0");
    assert_eq!(iboot.buf[0x5fc..0x600], bcond_before.to_le_bytes());
    assert_eq!(iboot.buf[0x608..0x60c], mov(8, 8).to_le_bytes()); // the csel fixup
    assert_eq!(iboot.applied_patches().len(), 3);
}

#[test]
fn boot_args_ios14_falls_back_when_the_base_method_fails() {
    // The default string has a reference but no csel follows: the base
    // method fails after its (staged) string write; the 14.5 method then
    // runs on an untouched buffer.
    let mut image = boot_args_14_5_image("6603");
    image.strz(0x3100, b"setpicture optmask");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v keepsize").unwrap();

    assert_eq!(iboot.buf[0x5fc..0x600], b(0x5fc, 0x700).to_le_bytes());
    assert_eq!(iboot.buf[0x700..0x704], adr(0x700, 0x3100, 0).to_le_bytes());
    assert_eq!(iboot.buf[0x3100..0x310c], *b"-v keepsize\0");
    // The base method's string write was staged and discarded.
    assert_eq!(iboot.buf[0x3000..0x3007], *b"rd=md0\0");
}

// ---------------------------------------------------------------------------
// unlock-nvram and freshnonce.
// ---------------------------------------------------------------------------

fn unlock_nvram_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x2000, b"debug-uarts");
    image.strz(0x2040, b"com.apple.System.");
    // The whitelist pointer tables: zero entry, two pointers, zero
    // terminator, then the getenv table.
    image.w64(0x2080, 0);
    image.w64(0x2088, loc(0x2000));
    image.w64(0x2090, loc(0x2040));
    image.w64(0x2098, 0);
    image.w64(0x20a0, loc(0x2040));
    image.w64(0x20a8, 0);
    // Three blacklist functions referencing the tables / string.
    image.w32(0x4fc, stp_fp_lr());
    image.w32(0x500, adrp(0x500, 0x2088, 9));
    image.w32(0x504, add(9, 9, 0x88));
    image.w32(0x508, ret());
    image.w32(0x51c, stp_fp_lr());
    image.w32(0x520, adrp(0x520, 0x20a0, 10));
    image.w32(0x524, add(10, 10, 0xa0));
    image.w32(0x528, ret());
    image.w32(0x53c, stp_fp_lr());
    image.w32(0x540, adrp(0x540, 0x2040, 11));
    image.w32(0x544, add(11, 11, 0x40));
    image.w32(0x548, ret());
    image
}

#[test]
fn unlock_nvram_stubs_three_blacklist_functions() {
    let mut image = unlock_nvram_image("5540");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_unlock_nvram_patch().unwrap();

    for off in [0x4fc, 0x51c, 0x53c] {
        assert_eq!(
            iboot.buf[off..off + 8],
            [0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6], // movz x0, #0; ret
            "function at {off:#x}"
        );
    }
    let patches = iboot.applied_patches();
    assert_eq!(patches.len(), 3);
    assert!(patches.iter().all(|patch| patch.patch() == "unlock-nvram"));
}

fn freshnonce_image(version: &str) -> Image {
    let mut image = Image::new(version);
    image.strz(0x2000, b"com.apple.System.boot-nonce");
    // noncefun1: references the boot-nonce variable.
    image.w32(0x600, stp_fp_lr());
    image.w32(0x604, adrp(0x604, 0x2000, 12));
    image.w32(0x608, add(12, 12, 0));
    image.w32(0x60c, ret());
    // noncefun2: calls noncefun1.
    image.w32(0x640, stp_fp_lr());
    image.w32(0x644, nop());
    image.w32(0x648, bl(0x648, 0x600));
    image.w32(0x64c, ret());
    // caller: branches over the noncefun2 call.
    image.w32(0x680, cbnz(0x680, 0x6a0, 8));
    image.w32(0x684, bl(0x684, 0x640));
    image.w32(0x688, ret());
    image
}

#[test]
fn freshnonce_nops_the_skip_branch() {
    let mut image = freshnonce_image("5540");
    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_freshnonce_patch().unwrap();

    assert_eq!(iboot.buf[0x680..0x684], nop().to_le_bytes());
    assert_eq!(iboot.applied_patches()[0].patch(), "freshnonce");
}

// ---------------------------------------------------------------------------
// findnops with the end-of-code filter.
// ---------------------------------------------------------------------------

#[test]
fn findnops_filters_ranges_past_the_end_of_code() {
    let mut image = Image::new("5540");
    image.w32(0x4, movz(0, 1, 0)); // code fence
    // zero run A: [0x8, 0x40)
    image.w32(0x40, movz(0, 1, 0));
    // zero run B: [0x44, 0x100)
    image.w32(0x100, ret());
    image.w32(0x104, movz(0, 1, 0));
    // zero run C: [0x108, 0x280), past the end of code
    image.strz(0x2000, b"Apple Mobile Device");

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    // The end of code is the ret at 0x100 (+4): run C is filtered out.
    assert_eq!(iboot.findnops(4, true, 0), Some(loc(0x8)));
    assert_eq!(iboot.findnops(4, true, 0), Some(loc(0x18)));
    assert_eq!(iboot.findnops(4, true, 0), Some(loc(0x28)));
    assert_eq!(iboot.findnops(4, true, 0), Some(loc(0x44)));
}

#[test]
fn findnops_fails_when_everything_is_past_the_end_of_code() {
    let mut image = Image::new("5540");
    for off in (0x4..0x40).step_by(4) {
        image.w32(off, movz(0, 1, 0));
    }
    image.w32(0x44, ret());
    image.w32(0x48, movz(0, 1, 0)); // fence so the run starts past 0x48
    image.strz(0x2000, b"Apple Mobile Device");

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    assert_eq!(iboot.findnops(4, true, 0), None);
}

#[test]
fn boot_args_ios14_5_relocate_into_nop_space() {
    // No "setpicture optmask" and no kernelcache path: the relocation target
    // comes out of nop space (the live fallback; see the module docs).
    let mut image = boot_args_14_5_image("6603");
    image.strz(0x3100, b"Apple Mobile Device");
    image.w32(0x710, ret()); // end of code right after the adr block

    let mut iboot = IBoot64::new(&mut image.0).unwrap();
    iboot.get_boot_arg_patch("-v keepsize").unwrap();

    let patches = iboot.applied_patches();
    let string_patch = patches
        .iter()
        .find(|patch| patch.bytes() == b"-v keepsize\0")
        .expect("the boot-args string write");
    let offset = string_patch.offset();
    assert!(
        offset < 0x714,
        "the string must land before the end of code"
    );
    assert_eq!(iboot.buf[offset..offset + 12], *b"-v keepsize\0");
    assert_eq!(iboot.buf[0x700..0x704], adr(0x700, offset, 0).to_le_bytes());
}

// ---------------------------------------------------------------------------
// The full libipatcher iBoot64Patch flow.
// ---------------------------------------------------------------------------

/// One image with every structure the five patches need, in disjoint
/// regions, plus "__PAGEZERO" for the kernel-load gate. iOS 13 class, so the
/// sigcheck goes through the iOS 10 callback strategy.
fn full_flow_image() -> Image {
    let mut image = Image::new("5540");
    // Strings.
    image.strz(0x2000, b"debug-enabled");
    image.strz(0x2040, b"com.apple.System.");
    image.strz(0x2080, b"com.apple.System.boot-nonce");
    image.strz(0x20c0, b"debug-uarts");
    image.strz(0x2100, b"rd=md0 nand-enable-reformat=1 -progress");
    image.strz(0x2160, b"IMG4");
    image.strz(0x2180, b"__PAGEZERO");
    // Whitelist tables for unlock-nvram.
    image.w64(0x2200, 0);
    image.w64(0x2208, loc(0x20c0));
    image.w64(0x2210, loc(0x2040));
    image.w64(0x2218, 0);
    image.w64(0x2220, loc(0x2040));
    image.w64(0x2228, 0);

    // debug-enabled reference.
    image.w32(0x200, adrp(0x200, 0x2000, 8));
    image.w32(0x204, add(8, 8, 0));
    image.w32(0x208, bl(0x208, 0x700));
    image.w32(0x20c, bl(0x20c, 0x704));

    // boot-args: branch, adr reference, csel, trailing adr.
    image.w32(0x2fc, bcond(0x2fc, 0x400, 0));
    image.w32(0x300, adr(0x300, 0x2100, 8));
    image.w32(0x304, nop());
    image.w32(0x308, csel(8, 8, 9, 0));
    image.w32(0x400, adr(0x400, 0x2100, 10));

    // unlock-nvram blacklist functions.
    image.w32(0x4fc, stp_fp_lr());
    image.w32(0x500, adrp(0x500, 0x2208, 9));
    image.w32(0x504, add(9, 9, 0x208));
    image.w32(0x508, ret());
    image.w32(0x51c, stp_fp_lr());
    image.w32(0x520, adrp(0x520, 0x2220, 10));
    image.w32(0x524, add(10, 10, 0x220));
    image.w32(0x528, ret());
    image.w32(0x53c, stp_fp_lr());
    image.w32(0x540, adrp(0x540, 0x2040, 11));
    image.w32(0x544, add(11, 11, 0x40));
    image.w32(0x548, ret());

    // sigcheck (iOS 10 callback strategy).
    image.w32(0x1c0, bl(0x1c0, 0x600)); // first loader call (ignored)
    image.w32(0x600, stp_fp_lr()); // f1: the image loader
    image.w32(0x604, adrp(0x604, 0x2160, 8));
    image.w32(0x608, add(8, 8, 0x160));
    image.w32(0x60c, ret());
    image.w32(0x640, stp_fp_lr()); // f2: sets up the callback
    image.w32(0x644, adr(0x644, 0x900, 2));
    image.w32(0x648, adr(0x648, 0x980, 3));
    image.w32(0x64c, bl(0x64c, 0x9c0));
    image.w32(0x650, bl(0x650, 0x600)); // second loader call
    image.w32(0x654, ret());
    image.w64(0x900, loc(0x800)); // callback pointer
    // The verification callback.
    image.w32(0x800, cbnz(0x800, 0x820, 8));
    image.w32(0x804, sub(31, 29, 0x40));
    image.w32(0x808, ldp_fp_lr());
    image.w32(0x80c, ret());

    // freshnonce.
    image.w32(0x6c0, stp_fp_lr()); // noncefun1
    image.w32(0x6c4, adrp(0x6c4, 0x2080, 12));
    image.w32(0x6c8, add(12, 12, 0x80));
    image.w32(0x6cc, ret());
    image.w32(0x6e0, stp_fp_lr()); // noncefun2
    image.w32(0x6e4, nop());
    image.w32(0x6e8, bl(0x6e8, 0x6c0));
    image.w32(0x6ec, ret());
    image.w32(0x740, cbnz(0x740, 0x760, 8)); // the skip branch
    image.w32(0x744, bl(0x744, 0x6e0));
    image.w32(0x748, ret());
    image
}

#[test]
fn patch_iboot64_applies_the_libipatcher_patch_set_in_order() {
    let image = full_flow_image();
    let (patched, report) = patch_iboot64_with_report(&image.0, Some("-v")).unwrap();

    assert_eq!(report.version(), 5540);
    assert_eq!(report.base_address(), BASE);
    let names: Vec<&str> = report.patches().iter().map(Iboot64Patch::patch).collect();
    assert_eq!(
        names,
        [
            "sigcheck",
            "debug-enabled",
            "boot-args",
            "boot-args",
            "boot-args",
            "unlock-nvram",
            "unlock-nvram",
            "unlock-nvram",
            "freshnonce",
        ]
    );

    // Spot-check the patched bytes through the report.
    for patch in report.patches() {
        assert_eq!(
            &patched[patch.offset()..patch.offset() + patch.bytes().len()],
            patch.bytes(),
            "patch at {:#x}",
            patch.offset()
        );
    }
    assert_eq!(patched[0x800..0x804], MOVZ_X0_0.to_le_bytes()); // sigcheck
    assert_eq!(patched[0x20c..0x210], [0x20, 0x00, 0x80, 0xd2]); // debug
    assert_eq!(patched[0x2100..0x2103], *b"-v\0"); // boot-args
    assert_eq!(patched[0x740..0x744], nop().to_le_bytes()); // freshnonce
}

#[test]
fn patch_iboot64_skips_the_boot_patches_without_kernel_load() {
    let mut image = full_flow_image();
    // Remove the kernel-load marker.
    for byte in &mut image.0[0x2180..0x218b] {
        *byte = 0;
    }

    let (patched, report) = patch_iboot64_with_report(&image.0, Some("-v")).unwrap();
    let names: Vec<&str> = report.patches().iter().map(Iboot64Patch::patch).collect();
    assert_eq!(names, ["sigcheck"]);
    assert_eq!(patched[0x800..0x804], MOVZ_X0_0.to_le_bytes());
    // Nothing else was touched.
    assert_eq!(patched[0x2100..0x2103], *b"rd=");
    assert_eq!(patched[0x20c..0x210], bl(0x20c, 0x704).to_le_bytes());

    // The plain entry point returns the same bytes.
    assert_eq!(patch_iboot64(&image.0, Some("-v")).unwrap(), patched);
}
