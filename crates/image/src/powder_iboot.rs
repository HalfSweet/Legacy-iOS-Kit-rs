//! powdersn0w iBoot patcher, a Rust port of xpwn's `iboot/iboot.c`
//! (`patchiBoot`) from LukeZGD/powdersn0w_pub.
//!
//! This is a different patch set from [`crate::iboot32`] (iBoot32Patcher):
//! different finders, different patch bytes, and a fixed per-image-type patch
//! selection instead of command-line flags. Operates on decrypted,
//! headerless LLB/iBSS/iBoot/iBEC binaries.
//!
//! Unlike the C original, which silently skips a patch when a finder misses,
//! every required anchor is reported as
//! [`PowderIBootError::AnchorNotFound`].

use thiserror::Error;
use tracing::{debug, info};

use crate::patchfinder as pf;

const RESET_VECTOR: u32 = 0xEA00_000E;

/// `MAX_BOOTARGS_LEN` from the C header: the boot-args string is written over
/// the "Reliance on this certificate" string and must fit in 128 bytes.
pub const MAX_BOOTARGS_LEN: usize = 128;

/// `RAMDISK_BOOT` from the C header, appended to the boot-args of iBEC
/// images.
pub const RAMDISK_BOOT_ARGS: &str = "-progress rd=md0 nand-enable-reformat=1";

/// Options mirroring `patchiBoot`'s `customBootArgs` and `debugFlags`
/// parameters. The patch set itself is selected by image type, as upstream.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PowderIBootPatchOptions {
    /// Custom boot-args written over the reliance string (`PATCH_BOOTARGS`).
    /// The image must already contain enough room; see [`MAX_BOOTARGS_LEN`].
    pub boot_args: Option<String>,
    /// `PATCH_DEBUG` for iBoot images (upstream passes it when jailbreaking).
    /// LLB/iBSS ignore it and iBEC is always debug-patched.
    pub debug: bool,
}

#[derive(Debug, Error)]
pub enum PowderIBootError {
    #[error("the image is not a 32-bit iBoot (bad reset vector)")]
    NotIBoot,
    #[error("unknown iBoot image type: {0:?}")]
    UnknownImageType(String),
    #[error("boot-args exceed the 128-byte reliance string budget")]
    BootArgsTooLong,
    #[error("cannot locate {0}")]
    AnchorNotFound(&'static str),
    #[error("image is too small for the required access")]
    OutOfBounds,
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> Result<(), PowderIBootError> {
    buf.get_mut(offset..offset + 2)
        .ok_or(PowderIBootError::OutOfBounds)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> Result<(), PowderIBootError> {
    buf.get_mut(offset..offset + 4)
        .ok_or(PowderIBootError::OutOfBounds)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Apply the powdersn0w iBoot patch set, returning the patched image.
///
/// Patch selection follows `patchiBoot`: LLB/iBSS get only the RSA check
/// patch; iBoot additionally gets boot-partition, boot-ramdisk, boot-args and
/// (version > 2261) the setenv call NOP; iBEC gets the debug, ticket and
/// ramdisk-boot-args patches instead of the boot-partition/ramdisk ones.
pub fn patch_powder_iboot(
    image: &[u8],
    options: &PowderIBootPatchOptions,
) -> Result<Vec<u8>, PowderIBootError> {
    if image.len() < 4 || u32::from_le_bytes(image[..4].try_into().expect("length")) != RESET_VECTOR
    {
        return Err(PowderIBootError::NotIBoot);
    }
    let mut buf = image.to_vec();

    let version = pf::find_iboot_version(&buf).unwrap_or(0);
    let image_type = pf::find_iboot_type(&buf).ok_or(PowderIBootError::OutOfBounds)?;
    info!(version, image_type, "powder iBoot patch");

    /// Patch selection per image type, mirroring the C PATCH_* bitmask.
    #[derive(Default)]
    struct Patches {
        rsa: bool,
        debug: bool,
        ticket: bool,
        boot_partition: bool,
        boot_ramdisk: bool,
        bootargs: bool,
        ramdisk_boot: bool,
        call_setenv: bool,
    }

    let patches = match image_type.as_str() {
        "LLB" | "iBSS" => Patches {
            rsa: true,
            ..Patches::default()
        },
        "iBoot" => Patches {
            rsa: true,
            debug: options.debug,
            boot_partition: true,
            boot_ramdisk: true,
            bootargs: true,
            call_setenv: version > 2261,
            ..Patches::default()
        },
        "iBEC" => Patches {
            rsa: true,
            debug: true,
            ticket: true,
            bootargs: true,
            ramdisk_boot: true,
            call_setenv: version > 2261,
            ..Patches::default()
        },
        _ => return Err(PowderIBootError::UnknownImageType(image_type)),
    };
    let Patches {
        rsa,
        debug: debug_patch,
        ticket,
        boot_partition,
        boot_ramdisk,
        bootargs,
        ramdisk_boot,
        call_setenv,
    } = patches;

    let base = pf::find_iboot_base(&buf).ok_or(PowderIBootError::AnchorNotFound("iBoot base"))?;
    debug!(base = format_args!("{base:08x}"), "iBoot base");

    if rsa {
        // movs r0, #0; str r0, [r8]
        let site = pf::find_verify_shsh(&buf)
            .ok_or(PowderIBootError::AnchorNotFound("verify_shsh call"))?;
        debug!(site = format_args!("{site:08x}"), "RSA check patch");
        write_u32(&mut buf, site, 0x6018_2000)?;
    }

    if debug_patch {
        // movs r0, #1; nop over the second BL after the debug-enabled xref.
        let site = pf::find_debug_enabled(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("debug-enabled call"))?;
        debug!(site = format_args!("{site:08x}"), "debug patch");
        write_u32(&mut buf, site, 0xbf00_2001)?;
    }

    if ticket {
        let patch1 = pf::find_ticket1(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("ticket patch start"))?;
        let patch2 = pf::find_ticket2(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("ticket patch end"))?;
        if patch2 <= patch1 || patch2 - patch1 <= 8 {
            return Err(PowderIBootError::AnchorNotFound("ticket patch range"));
        }
        debug!(
            patch1 = format_args!("{patch1:08x}"),
            patch2 = format_args!("{patch2:08x}"),
            "ticket patch"
        );
        // mov.w r0, #0; mov.w r1, #0, then NOP the rest of the range.
        write_u32(&mut buf, patch1, 0x0000_f04f)?;
        write_u32(&mut buf, patch1 + 4, 0x0100_f04f)?;
        let mut offset = patch1 + 8;
        while offset < patch2 {
            write_u16(&mut buf, offset, 0xbf00)?;
            offset += 2;
        }
        // A trailing `mov.w r0, #0x30` (error return) is also neutralized.
        if buf
            .get(patch2..patch2 + 4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("length")))
            == Some(0x30ff_f04f)
            && pf::insn_is_32bit(&buf, patch2)
        {
            write_u32(&mut buf, patch2, 0x0000_f04f)?;
        }
    }

    if boot_partition {
        // movs r0, #0; nop over the boot-partition command handler call.
        let site = pf::find_boot_partition(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("boot-partition call"))?;
        debug!(site = format_args!("{site:08x}"), "boot-partition patch");
        write_u32(&mut buf, site, 0xbf00_2000)?;
    }

    if boot_ramdisk {
        let site = pf::find_boot_ramdisk(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("boot-ramdisk call"))?;
        debug!(site = format_args!("{site:08x}"), "boot-ramdisk patch");
        write_u32(&mut buf, site, 0xbf00_2000)?;
    }

    if call_setenv {
        // Two NOPs over the sys_setup_default_environment call.
        let site = pf::find_sys_setup_default_environment(base, &buf).ok_or(
            PowderIBootError::AnchorNotFound("sys_setup_default_environment call"),
        )?;
        debug!(site = format_args!("{site:08x}"), "call-setenv patch");
        write_u32(&mut buf, site, 0xbf00_bf00)?;
    }

    // Boot-args are written only when there is something to write, matching
    // the C `customBootArgs || PATCH_RAMDISK_BOOT` gate.
    if bootargs && (options.boot_args.is_some() || ramdisk_boot) {
        let null_xref = pf::find_boot_args_null_xref(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("boot-args NULL xref"))?;
        let args_xref = pf::find_boot_args_xref(base, &buf)
            .ok_or(PowderIBootError::AnchorNotFound("boot-args xref"))?;
        let reliance = pf::find_reliance_str(&buf)
            .ok_or(PowderIBootError::AnchorNotFound("reliance string"))?;
        if reliance + MAX_BOOTARGS_LEN > buf.len() {
            return Err(PowderIBootError::OutOfBounds);
        }

        let mut args = options.boot_args.clone().unwrap_or_default();
        if options
            .boot_args
            .as_ref()
            .is_some_and(|a| a.len() + 1 > MAX_BOOTARGS_LEN)
        {
            return Err(PowderIBootError::BootArgsTooLong);
        }
        if ramdisk_boot {
            if args.len() + RAMDISK_BOOT_ARGS.len() + 1 > MAX_BOOTARGS_LEN {
                return Err(PowderIBootError::BootArgsTooLong);
            }
            if options.boot_args.is_some() {
                args.push(' ');
            }
            args.push_str(RAMDISK_BOOT_ARGS);
        }

        info!(args, "boot-args patch");
        buf[reliance..reliance + args.len()].copy_from_slice(args.as_bytes());
        buf[reliance + args.len()] = 0;
        let new_args = base.wrapping_add(reliance as u32);
        write_u32(&mut buf, null_xref, new_args)?;
        write_u32(&mut buf, args_xref, new_args)?;
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u32 = 0x4FF0_0000;

    fn w16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
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

    /// Reset vector, ARM base-address LDR, and image type string.
    fn header(buf: &mut [u8], image_type: &[u8]) {
        w32(buf, 0, RESET_VECTOR);
        w16(buf, 0x40, 0x0010); // LDR r0, [PC, #0x10]
        w16(buf, 0x42, 0xE59F);
        w32(buf, 0x40 + 12 + 0x10, BASE);
        buf[0x200..0x200 + image_type.len()].copy_from_slice(image_type);
        buf[0x200 + image_type.len()] = b' ';
    }

    /// verify_shsh function at 0x300 and a call site at 0x310.
    fn verify_shsh(buf: &mut [u8]) {
        w16(buf, 0x300, 0xB510); // push {r4, lr}
        w32(buf, 0x302, movw(1, 0x5254));
        w32(buf, 0x306, movt(1, 0x4345));
        w32(buf, 0x310, pf::make_bl(0x310, 0x300));
    }

    #[test]
    fn llb_gets_only_the_rsa_patch() {
        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"LLB");
        verify_shsh(&mut buf);
        let patched = patch_powder_iboot(&buf, &PowderIBootPatchOptions::default()).unwrap();
        // movs r0, #0; str r0, [r8] over the BL to verify_shsh.
        assert_eq!(&patched[0x310..0x314], &[0x00, 0x20, 0x18, 0x60]);
        assert_eq!(&patched[..0x310], &buf[..0x310]);
        assert_eq!(&patched[0x314..], &buf[0x314..]);
    }

    #[test]
    fn rejects_non_iboot_and_unknown_type() {
        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"LLB");
        verify_shsh(&mut buf);
        buf[0] = 0;
        assert!(matches!(
            patch_powder_iboot(&buf, &PowderIBootPatchOptions::default()),
            Err(PowderIBootError::NotIBoot)
        ));

        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"wtf");
        verify_shsh(&mut buf);
        assert!(matches!(
            patch_powder_iboot(&buf, &PowderIBootPatchOptions::default()),
            Err(PowderIBootError::UnknownImageType(_))
        ));
    }

    /// Full iBEC fixture exercising every iBEC patch: RSA, debug, ticket, and
    /// ramdisk boot-args. The layout mirrors a real decrypted iBEC: ARM
    /// header, string area at 0x200+, Thumb code, then literal pools.
    fn ibec_fixture() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"iBEC");
        verify_shsh(&mut buf);

        // Stock boot-args string and the reliance string it overwrites.
        buf[0x210..0x210 + 40].copy_from_slice(b"rd=md0 nand-enable-reformat=1 -progress\0");
        buf[0x240..0x240 + 29].copy_from_slice(b"Reliance on this certificate ");
        // 0x260 stays NUL: the boot-args-NULL xref points at it.

        // debug-enabled chain: string, pointer, LDR, two BLs.
        buf[0x2C0..0x2CD].copy_from_slice(b"debug-enabled");
        w32(&mut buf, 0x360, BASE + 0x2C0);
        w16(&mut buf, 0x320, 0x480F); // LDR r0, [PC, #0x3C] -> 0x360
        w16(&mut buf, 0x322, 0xBF00);
        w32(&mut buf, 0x324, pf::make_bl(0x324, 0x300));
        w32(&mut buf, 0x328, pf::make_bl(0x328, 0x300)); // debug patch site

        // Ticket chain: pointer to base+0x280, three pointers to it, LDR, BL.
        w32(&mut buf, 0x370, BASE + 0x280);
        for off in [0x380usize, 0x384, 0x388] {
            w32(&mut buf, off, BASE + 0x370);
        }
        w16(&mut buf, 0x330, 0x4815); // LDR r0, [PC, #0x54] -> 0x388
        w16(&mut buf, 0x332, 0xBF00);
        w32(&mut buf, 0x334, pf::make_bl(0x334, 0x300)); // ticket BL; patch1 = 0x338
        for off in (0x338..0x344).step_by(2) {
            w16(&mut buf, off, 0xBF00);
        }
        w16(&mut buf, 0x344, 0xD001); // beq; patch2 = 0x346
        w16(&mut buf, 0x346, 0xBF00);
        w16(&mut buf, 0x348, 0xBDF0); // pop {r4-r7, pc}

        // Boot-args chain: pointer to the stock string, LDR, then an LDR
        // literal pointing at a NUL byte.
        w32(&mut buf, 0x3A0, BASE + 0x210);
        w16(&mut buf, 0x390, 0x4803); // LDR r0, [PC, #0xC] -> 0x3A0
        w16(&mut buf, 0x3A4, 0x4806); // LDR r0, [PC, #0x18] -> 0x3C0
        w32(&mut buf, 0x3C0, BASE + 0x260);
        buf
    }

    #[test]
    fn ibec_full_patch_set() {
        let buf = ibec_fixture();
        let patched = patch_powder_iboot(&buf, &PowderIBootPatchOptions::default()).unwrap();

        // RSA: movs r0, #0; str r0, [r8]
        assert_eq!(&patched[0x310..0x314], &[0x00, 0x20, 0x18, 0x60]);
        // Debug: movs r0, #1; nop
        assert_eq!(&patched[0x328..0x32C], &[0x01, 0x20, 0x00, 0xBF]);
        // Ticket: mov.w r0, #0; mov.w r1, #0; NOPs to patch2.
        assert_eq!(&patched[0x338..0x33C], &[0x4F, 0xF0, 0x00, 0x00]);
        assert_eq!(&patched[0x33C..0x340], &[0x4F, 0xF0, 0x00, 0x01]);
        for off in (0x340..0x346).step_by(2) {
            assert_eq!(&patched[off..off + 2], &[0x00, 0xBF]);
        }
        // Boot-args: RAMDISK_BOOT written over the reliance string, and both
        // xrefs repointed at it.
        let mut expected = [0u8; 40];
        expected[..39].copy_from_slice(RAMDISK_BOOT_ARGS.as_bytes());
        assert_eq!(&patched[0x240..0x240 + 40], &expected);
        let new_args = (BASE + 0x240).to_le_bytes();
        assert_eq!(&patched[0x3C0..0x3C4], &new_args);
        assert_eq!(&patched[0x3A0..0x3A4], &new_args);
    }

    #[test]
    fn iboot_requires_all_anchors_when_debug_requested() {
        // An iBoot without the optional anchors fails strictly, unlike the C
        // original which silently skipped missing patches.
        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"iBoot");
        verify_shsh(&mut buf);
        let options = PowderIBootPatchOptions {
            boot_args: None,
            debug: true,
        };
        assert!(matches!(
            patch_powder_iboot(&buf, &options),
            Err(PowderIBootError::AnchorNotFound("debug-enabled call"))
        ));
    }

    #[test]
    fn iboot_without_boot_args_skips_bootargs_anchors() {
        // With no custom boot-args and no ramdisk-boot flag, the bootargs
        // anchors are not required (the C gate writes nothing either) — but
        // the boot-partition anchor still is, so this fails there.
        let mut buf = vec![0u8; 0x400];
        header(&mut buf, b"iBoot");
        verify_shsh(&mut buf);
        assert!(matches!(
            patch_powder_iboot(&buf, &PowderIBootPatchOptions::default()),
            Err(PowderIBootError::AnchorNotFound("boot-partition call"))
        ));
    }

    #[test]
    fn boot_args_budget_is_enforced() {
        let buf = ibec_fixture();
        let options = PowderIBootPatchOptions {
            boot_args: Some("x".repeat(MAX_BOOTARGS_LEN)),
            debug: false,
        };
        assert!(matches!(
            patch_powder_iboot(&buf, &options),
            Err(PowderIBootError::BootArgsTooLong)
        ));
    }
}
