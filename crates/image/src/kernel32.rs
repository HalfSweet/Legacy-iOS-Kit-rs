//! powdersn0w 32-bit kernelcache patcher, a Rust port of xpwn's
//! `kernel/kernel.c` (`patchKernel`) from LukeZGD/powdersn0w_pub @300c54a.
//!
//! Supported kernels (gated on the xnu version parsed from the kernelcache,
//! as upstream): 2107.2/2107.7 (iOS 6.0/6.1), 2783 (8.0–8.2), 2784
//! (8.3–8.4.1), and 3248 (9.0–9.3.x). Anything else is
//! [`Kernel32Error::UnsupportedVersion`].
//!
//! # Integration contract
//!
//! The input is the **decrypted and LZSS-decompressed** kernelcache: a raw
//! 32-bit Mach-O (`MH_MAGIC` at offset 0) in prelinked form, with the AMFI,
//! sandbox, and LwVM kexts embedded. This matches what xpwn's AbstractFile
//! layering hands to `patchKernel` (img3 decryption plus complzss
//! decompression are transparent upstream). Callers therefore run
//! `image::payload`/`image::img3` payload extraction and
//! `image::lzss::decompress_lzss` first, and re-wrap the output (LZSS
//! recompression, IMG3 replacement, optional re-encryption) themselves; the
//! kit-side powder builder owns that wiring.
//!
//! The output buffer has the same length as the input; the patcher writes in
//! place. Kexts are located by searching for the bundle identifier string
//! and walking back to the kext's `MH_MAGIC`, exactly like `init_kext` —
//! `__PRELINK_INFO` is never parsed (the C original does not either).
//! Branch encodings are computed in upstream's "unbased" space, which mixes
//! file offsets and vmaddrs under the assumption that the kernel `__TEXT`
//! segment starts at file offset 0.
//!
//! Unlike the C original, which reads and writes out of bounds on malformed
//! input and whose `make_b_w` out-of-range value (-1) slips through the
//! caller's `!val` check, every access here is bounds-checked and an
//! out-of-range branch is [`Kernel32Error::BranchOutOfRange`]. Anchor misses
//! are reported by name as [`Kernel32Error::AnchorNotFound`].

use thiserror::Error;
use tracing::{debug, info};

use crate::patchfinder as pf;

const MH_MAGIC: u32 = 0xFEED_FACE;
const LC_SEGMENT: u32 = 0x1;

#[derive(Debug, Error)]
pub enum Kernel32Error {
    #[error("not a 32-bit Mach-O kernelcache (bad magic)")]
    NotMachO,
    #[error("malformed kernelcache: {0}")]
    Malformed(&'static str),
    #[error("cannot locate the xnu version string")]
    VersionNotFound,
    #[error("unsupported xnu version {major}.{minor} (supported: 2107.2/7, 2783, 2784, 3248)")]
    UnsupportedVersion { major: u32, minor: u32 },
    #[error("cannot locate {0}")]
    AnchorNotFound(&'static str),
    #[error("branch target is out of Thumb-2 B.W range for {0}")]
    BranchOutOfRange(&'static str),
    #[error("image is too small for the required access")]
    OutOfBounds,
}

type Result<T> = std::result::Result<T, Kernel32Error>;

/// kernel.c's `struct macho_address`. The `delta` field is log-only upstream
/// and is not ported; the per-section addresses only feed the `last_section`
/// computation.
#[derive(Default)]
struct MachoLayout {
    /// Offset of the Mach-O header within the kernelcache buffer.
    text_buf_base: usize,
    /// __TEXT segment vmaddr and vmsize.
    text_base: u32,
    text_size: u32,
    /// __DATA segment vmaddr and vmsize.
    data_base: u32,
    data_size: u32,
    /// Kernel only: runtime address of the __TEXT free area the payloads are
    /// written into.
    last_section: u32,
}

#[derive(Default)]
struct HelperOffsets {
    ret0_gadget: u32,
    ret1_gadget: u32,
    vn_getpath: u32,
    memcmp: u32,
}

#[derive(Default)]
struct TextOffsets {
    vm_fault_enter: usize,
    vm_map_enter: usize,
    vm_map_protect: usize,
    mac_mount: usize,
    csops: usize,
    csops2: usize,
    pid_check: usize,
}

#[derive(Default)]
struct AmfiOffsets {
    debugger_got: usize,
    cs_enforcement_got: usize,
    execve_hook: usize,
}

#[derive(Default)]
struct SandboxOffsets {
    debugger_got: usize,
    ops: usize,
    sb_evaluate: usize,
}

#[derive(Default)]
struct LwvmOffsets {
    kernel_conf_got: usize,
    jump: u32,
    map_for_io: usize,
}

/// AMFI execve hook payload written into the kernel __TEXT free area (iOS 9),
/// from kernel.c `write_amfi_execve_hook_payload` (powdersn0w_pub @300c54a).
/// It forces CS_PLATFORM_BINARY and the debug-ish flags into the cs_flags and
/// clears CS_HARD/CS_KILL/CS_REQUIRE_LV and friends.
const AMFI_EXECVE_HOOK_PAYLOAD: [u8; 30] = [
    0xDA, 0xF8, 0x00, 0x00, // ldr.w   r0, [sl]           @ cs_flags
    0x40, 0xF0, 0x80, 0x60, // orr     r0, r0, #0x4000000 @ CS_PLATFORM_BINARY
    0x40, 0xF0, 0x0F,
    0x00, // orr     r0, r0, #0x000f    @ CS_VALID|CS_ADHOC|CS_GET_TASK_ALLOW|CS_INSTALLER
    0x20, 0xF4, 0x7C,
    0x50, // bic     r0, r0, #0x3f00    @ clear CS_HARD|CS_KILL|CS_EXPIRATION|CS_RESTRICT|CS_ENFORCEMENT|CS_REQUIRE_LV
    0xCA, 0xF8, 0x00, 0x00, // str.w   r0, [sl]
    0x00, 0x20, // movs    r0, #0x0
    0x06, 0xB0, // add     sp, #0x18
    0xBD, 0xE8, 0x00, 0x0D, // pop.w   {r8, sl, fp}
    0xF0, 0xBD, // pop     {r4, r5, r6, r7, pc}
];

/// sb_evaluate hook payloads, embedded byte constants from
/// `xpwn/include/sb_payload.h` (powdersn0w_pub @300c54a): the evasi0n6
/// variant for xnu 2107 and the taig variant for xnu 2783/2784. The `0x41..`
/// /`0x42..` words and the `0x43`/`0x44` dwords are placeholders patched with
/// BLs to vn_getpath/memcmp, the saved opcode, and the jumpback.
const SB_PAYLOAD6: [u8; 232] = [
    0x03, 0xb4, 0x78, 0x46, 0x00, 0xf1, 0x05, 0x00, 0x00, 0x47, 0x03, 0xbc, 0x1f, 0xb5, 0x91, 0xb0,
    0x5c, 0x69, 0x00, 0x2c, 0x26, 0xd0, 0x69, 0x46, 0x40, 0x20, 0x10, 0xaa, 0x10, 0x60, 0x20, 0x46,
    0x41, 0x41, 0x41, 0x41, 0x1c, 0x28, 0x01, 0xd0, 0x00, 0x28, 0x1b, 0xd1, 0x68, 0x46, 0x12, 0xa1,
    0x13, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0d, 0xd1, 0x68, 0x46, 0x13, 0xa1, 0x31, 0x22,
    0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0d, 0xd0, 0x68, 0x46, 0x1d, 0xa1, 0x27, 0x22, 0x42, 0x42,
    0x42, 0x42, 0x00, 0x28, 0x06, 0xd1, 0x11, 0xb0, 0x01, 0xbc, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21,
    0x41, 0x60, 0x1e, 0xbd, 0x11, 0xb0, 0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc, 0x01, 0xb0, 0xff, 0xe7,
    0x43, 0x43, 0x43, 0x43, 0x44, 0x44, 0x44, 0x44, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
    0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x00, 0x2f, 0x70, 0x72, 0x69,
    0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f,
    0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e,
    0x63, 0x65, 0x73, 0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0xc0, 0x46,
    0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62,
    0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66,
    0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x00,
];

const SB_PAYLOAD: [u8; 204] = [
    0x1f, 0xb5, 0x06, 0x9b, 0xad, 0xf5, 0x82, 0x6d, 0x1c, 0x6b, 0x01, 0x2c, 0x32, 0xd1, 0x5c, 0x6b,
    0x00, 0x2c, 0x2f, 0xd0, 0x69, 0x46, 0x5f, 0xf4, 0x80, 0x60, 0x0d, 0xf5, 0x80, 0x62, 0x10, 0x60,
    0x20, 0x46, 0x41, 0x41, 0x41, 0x41, 0x1c, 0x28, 0x08, 0xd0, 0x00, 0x28, 0x22, 0xd1, 0x68, 0x46,
    0x15, 0xa1, 0x10, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x1b, 0xd0, 0x68, 0x46, 0x0f, 0xf2,
    0x59, 0x01, 0x13, 0x22, 0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0b, 0xd1, 0x68, 0x46, 0x31, 0x22,
    0x42, 0x42, 0x42, 0x42, 0x00, 0x28, 0x0d, 0xd0, 0x68, 0x46, 0x27, 0x22, 0x42, 0x42, 0x42, 0x42,
    0x00, 0x28, 0x07, 0xd1, 0x0d, 0xf5, 0x82, 0x6d, 0x01, 0xbc, 0x00, 0x21, 0x01, 0x60, 0x18, 0x21,
    0x01, 0x71, 0x1e, 0xbd, 0x0d, 0xf5, 0x82, 0x6d, 0x05, 0x98, 0x86, 0x46, 0x1f, 0xbc, 0x01, 0xb0,
    0x43, 0x43, 0x43, 0x43, 0x44, 0x44, 0x44, 0x44, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
    0x2f, 0x76, 0x61, 0x72, 0x2f, 0x74, 0x6d, 0x70, 0x00, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74,
    0x65, 0x2f, 0x76, 0x61, 0x72, 0x2f, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2f, 0x4c, 0x69, 0x62,
    0x72, 0x61, 0x72, 0x79, 0x2f, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x73,
    0x2f, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x00, 0x00,
];

/// Where the patchable words live inside each payload (sb_payload.h).
struct SbPayloadLayout {
    vn_getpath_bl: usize,
    memcmp_bl: &'static [usize],
    restore: usize,
    jumpback: usize,
}

const SB_PAYLOAD6_LAYOUT: SbPayloadLayout = SbPayloadLayout {
    vn_getpath_bl: 0x20,
    memcmp_bl: &[0x32, 0x40, 0x4e],
    restore: 0x70,
    jumpback: 0x74,
};

const SB_PAYLOAD_LAYOUT: SbPayloadLayout = SbPayloadLayout {
    vn_getpath_bl: 0x22,
    memcmp_bl: &[0x34, 0x44, 0x50, 0x5c],
    restore: 0x80,
    jumpback: 0x84,
};

/// sizeof(struct mac_policy_ops) from `xpwn/include/mac.h`: 335 u32 slots.
const MAC_POLICY_OPS_SIZE: usize = 335 * 4;

/// offsetof() values into `struct mac_policy_ops` (mac.h) for the slots
/// patch_sbops replaces with the ret0 gadget. The `mac_policy_ops90` layout
/// used for xnu 3248 minor ≤ 11 places every one of these fields at the same
/// offset (verified against mac.h), so one table serves both branches.
const SBOPS_PATCH_OFFSETS: [usize; 27] = [
    0x278, // mpo_proc_check_fork
    0x4f4, // mpo_iokit_check_open
    0x150, // mpo_mount_check_fsctl
    0x1e0, // mpo_vnode_check_rename
    0x3f0, // mpo_vnode_check_access
    0x3f8, // mpo_vnode_check_chroot
    0x3fc, // mpo_vnode_check_create
    0x400, // mpo_vnode_check_deleteextattr
    0x404, // mpo_vnode_check_exchangedata
    0x40c, // mpo_vnode_check_getattrlist
    0x410, // mpo_vnode_check_getextattr
    0x414, // mpo_vnode_check_ioctl
    0x420, // mpo_vnode_check_link
    0x424, // mpo_vnode_check_listextattr
    0x42c, // mpo_vnode_check_open
    0x438, // mpo_vnode_check_readlink
    0x444, // mpo_vnode_check_revoke
    0x44c, // mpo_vnode_check_setattrlist
    0x450, // mpo_vnode_check_setextattr
    0x454, // mpo_vnode_check_setflags
    0x458, // mpo_vnode_check_setmode
    0x45c, // mpo_vnode_check_setowner
    0x460, // mpo_vnode_check_setutimes
    0x464, // mpo_vnode_check_stat
    0x468, // mpo_vnode_check_truncate
    0x46c, // mpo_vnode_check_unlink
    0x090, // mpo_file_check_mmap
];

fn read_u32(buf: &[u8], offset: usize) -> Result<u32> {
    buf.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("length")))
        .ok_or(Kernel32Error::OutOfBounds)
}

/// kernel.c's write8/16/32: `offset` and `limit` are relative to the slice
/// base (`base`), and writes past `limit` are rejected even when the buffer
/// itself is large enough.
fn write_bytes(
    buf: &mut [u8],
    base: usize,
    offset: usize,
    limit: usize,
    bytes: &[u8],
) -> Result<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(Kernel32Error::OutOfBounds)?;
    if end > limit {
        return Err(Kernel32Error::OutOfBounds);
    }
    let start = base.checked_add(offset).ok_or(Kernel32Error::OutOfBounds)?;
    buf.get_mut(start..start + bytes.len())
        .ok_or(Kernel32Error::OutOfBounds)?
        .copy_from_slice(bytes);
    Ok(())
}

fn write_u8(buf: &mut [u8], base: usize, offset: usize, limit: usize, val: u8) -> Result<()> {
    write_bytes(buf, base, offset, limit, &[val])
}

fn write_u16(buf: &mut [u8], base: usize, offset: usize, limit: usize, val: u16) -> Result<()> {
    write_bytes(buf, base, offset, limit, &val.to_le_bytes())
}

fn write_u32(buf: &mut [u8], base: usize, offset: usize, limit: usize, val: u32) -> Result<()> {
    write_bytes(buf, base, offset, limit, &val.to_le_bytes())
}

/// A finder result, mapping both a miss and upstream's 0 return to
/// [`Kernel32Error::AnchorNotFound`].
fn anchor(found: Option<usize>, name: &'static str) -> Result<usize> {
    found
        .filter(|&offset| offset != 0)
        .ok_or(Kernel32Error::AnchorNotFound(name))
}

/// Walk the load commands at `base` and collect the __TEXT/__DATA layout.
/// `sections` controls whether the __TEXT section ends are gathered for the
/// free-area computation (kernel only).
fn parse_macho(buf: &[u8], base: usize, sections: bool) -> Result<MachoLayout> {
    if read_u32(buf, base)? != MH_MAGIC {
        return Err(Kernel32Error::NotMachO);
    }
    let mut layout = MachoLayout {
        text_buf_base: base,
        ..MachoLayout::default()
    };
    let mut text_text_end = 0u32;
    let mut text_const_end = 0u32;
    let mut text_cstring_end = 0u32;

    let ncmds = read_u32(buf, base + 16)?;
    let mut cmd = base + 28; // sizeof(struct mach_header)
    for _ in 0..ncmds {
        let cmdsize = read_u32(buf, cmd + 4)? as usize;
        if cmdsize < 8 {
            return Err(Kernel32Error::Malformed("load command size"));
        }
        if read_u32(buf, cmd)? == LC_SEGMENT {
            if cmdsize < 56 {
                return Err(Kernel32Error::Malformed("segment command size"));
            }
            let segname_end = buf[cmd + 8..cmd + 24]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(16);
            let segname = &buf[cmd + 8..cmd + 8 + segname_end];
            let vmaddr = read_u32(buf, cmd + 24)?;
            let vmsize = read_u32(buf, cmd + 28)?;
            debug!(
                vmaddr = format_args!("{vmaddr:08x}"),
                end = format_args!("{:08x}", vmaddr.wrapping_add(vmsize)),
                segname = String::from_utf8_lossy(segname).as_ref(),
                "segment"
            );
            match segname {
                b"__TEXT" => {
                    layout.text_base = vmaddr;
                    layout.text_size = vmsize;
                    if sections {
                        let nsects = read_u32(buf, cmd + 48)? as usize;
                        if 56 + 68 * nsects > cmdsize {
                            return Err(Kernel32Error::Malformed("section table size"));
                        }
                        for j in 0..nsects {
                            let sec = cmd + 56 + 68 * j;
                            let name_end = buf[sec..sec + 16]
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(16);
                            let end =
                                read_u32(buf, sec + 32)?.wrapping_add(read_u32(buf, sec + 36)?);
                            match &buf[sec..sec + name_end] {
                                b"__text" => text_text_end = end,
                                b"__const" => text_const_end = end,
                                b"__cstring" => text_cstring_end = end,
                                _ => {}
                            }
                        }
                    }
                }
                b"__DATA" => {
                    layout.data_base = vmaddr;
                    layout.data_size = vmsize;
                }
                _ => {}
            }
        }
        cmd = cmd.checked_add(cmdsize).ok_or(Kernel32Error::OutOfBounds)?;
    }

    if sections {
        if layout.text_size == 0 {
            return Err(Kernel32Error::Malformed("no __TEXT segment"));
        }
        // Search the __TEXT free area, exactly as init_kernel does: the
        // aligned end of the last section, padded by 0x100 (or squeezed into
        // 0xE0 when the segment is nearly full).
        let text_last = layout.text_base.wrapping_add(layout.text_size);
        if layout.data_base != text_last {
            return Err(Kernel32Error::Malformed("__DATA does not follow __TEXT"));
        }
        let last = text_text_end.max(text_const_end).max(text_cstring_end);
        if layout.text_base > last {
            return Err(Kernel32Error::Malformed(
                "__TEXT sections precede its vmaddr",
            ));
        }
        layout.last_section = if text_last < last.wrapping_add(0x100) {
            if text_last < last.wrapping_add(0xE0) {
                return Err(Kernel32Error::Malformed("no __TEXT free area"));
            }
            last.wrapping_add(0xE0) & !0xDF
        } else {
            last.wrapping_add(0x100) & !0xFF
        };
        debug!(
            last_section = format_args!("{:08x}", layout.last_section),
            "__TEXT free area"
        );
    }
    Ok(layout)
}

/// init_kernel: parse the kernel Mach-O, locate the __TEXT free area, and
/// parse the xnu version.
fn init_kernel(buf: &[u8]) -> Result<(MachoLayout, u32, u32)> {
    let kernel = parse_macho(buf, 0, true)?;
    let ktext = kernel_text(buf, &kernel)?;
    let major = pf::find_xnu_major_version(ktext).ok_or(Kernel32Error::VersionNotFound)?;
    if major == 0 {
        return Err(Kernel32Error::VersionNotFound);
    }
    let minor = pf::find_xnu_minor_version(ktext).unwrap_or(0);
    info!(xnu = format_args!("{major}.{minor}"), "kernelcache version");
    Ok((kernel, major, minor))
}

/// init_kext: find the kext by its bundle identifier string (its kmod_info
/// name) and walk back to its Mach-O header. Upstream bounds the walk by the
/// `i += 4` per byte quirk, covering at most ident_off / 4 bytes back.
fn init_kext(buf: &[u8], ident: &'static [u8]) -> Result<MachoLayout> {
    let ident_off = pf::find_bytes(buf, ident)
        .ok_or(Kernel32Error::AnchorNotFound("kext bundle identifier"))?;
    let mut offset = ident_off;
    let mut i = 0;
    let base = loop {
        if i >= ident_off {
            return Err(Kernel32Error::Malformed("kext Mach-O header"));
        }
        if read_u32(buf, offset).ok() == Some(MH_MAGIC) {
            break offset;
        }
        offset -= 1;
        i += 4;
    };
    debug!(
        kext = String::from_utf8_lossy(ident).as_ref(),
        base = format_args!("{base:08x}"),
        "kext"
    );
    parse_macho(buf, base, false).map_err(|e| match e {
        Kernel32Error::NotMachO => Kernel32Error::Malformed("kext Mach-O header"),
        e => e,
    })
}

/// The kernel's __TEXT, as every kernel finder sees it.
fn kernel_text<'a>(buf: &'a [u8], kernel: &MachoLayout) -> Result<&'a [u8]> {
    buf.get(..kernel.text_size as usize)
        .ok_or(Kernel32Error::Malformed("truncated __TEXT"))
}

/// A kext slice: `text_only` selects __TEXT, otherwise __TEXT+__DATA (the
/// GOT finders' range).
fn kext_slice<'a>(buf: &'a [u8], kext: &MachoLayout, text_only: bool) -> Result<&'a [u8]> {
    let size = if text_only {
        kext.text_size
    } else {
        kext.text_size.wrapping_add(kext.data_size)
    };
    buf.get(kext.text_buf_base..kext.text_buf_base + size as usize)
        .ok_or(Kernel32Error::Malformed("truncated kext"))
}

/// find_helper_offset.
fn find_helper_offsets(ktext: &[u8], kernel: &MachoLayout, major: u32) -> Result<HelperOffsets> {
    let ret0 = anchor(pf::find_ret0_gadget(ktext), "ret0_gadget")? as u32;
    let ret0_gadget = kernel.text_base.wrapping_add(ret0);
    debug!(ret0_gadget = format_args!("{ret0_gadget:08x}"), "helper");
    let ret1 = anchor(pf::find_ret1_gadget(ktext), "ret1_gadget")? as u32;
    let ret1_gadget = kernel.text_base.wrapping_add(ret1);
    debug!(ret1_gadget = format_args!("{ret1_gadget:08x}"), "helper");

    let mut offsets = HelperOffsets {
        ret0_gadget,
        ret1_gadget,
        ..HelperOffsets::default()
    };
    if major == 2107 {
        offsets.vn_getpath = anchor(pf::find_vn_getpath(ktext), "vn_getpath")? as u32;
        offsets.memcmp = anchor(pf::find_memcmp(ktext), "memcmp")? as u32;
    } else if major == 2784 || major == 2783 {
        offsets.vn_getpath = anchor(pf::find_vn_getpath_84(ktext), "vn_getpath")? as u32;
        offsets.memcmp = anchor(pf::find_memcmp_84(ktext), "memcmp")? as u32;
    }
    Ok(offsets)
}

/// find_text_offset.
fn find_text_offsets(ktext: &[u8], major: u32, minor: u32) -> Result<TextOffsets> {
    let mut offsets = TextOffsets::default();
    if major == 3248 {
        // iOS 9.x
        offsets.vm_fault_enter = anchor(pf::find_vm_fault_enter_patch(ktext), "vm_fault_enter")?;
        offsets.vm_map_enter = anchor(pf::find_vm_map_enter_patch(ktext), "vm_map_enter")?;
        offsets.vm_map_protect = anchor(pf::find_vm_map_protect_patch(ktext), "vm_map_protect")?;
        offsets.mac_mount = if minor == 1 {
            anchor(pf::find_mount_90(ktext), "mac_mount_90")?
        } else {
            anchor(pf::find_mount(ktext), "mac_mount")?
        };
        offsets.csops = anchor(pf::find_csops(ktext), "csops")?;
        offsets.pid_check = anchor(pf::find_tfp0_patch(ktext), "task_for_pid")?;
    } else if major == 2107 {
        // iOS 6.x
        offsets.vm_map_enter = anchor(pf::find_vm_map_enter_patch_ios6(ktext), "vm_map_enter")?;
        offsets.vm_map_protect =
            anchor(pf::find_vm_map_protect_patch_ios6(ktext), "vm_map_protect")?;
        offsets.pid_check = anchor(pf::find_tfp0_patch_ios6(ktext), "task_for_pid")?;
    } else if major == 2784 || major == 2783 {
        offsets.vm_fault_enter = anchor(pf::find_vm_fault_enter_patch_84(ktext), "vm_fault_enter")?;
        offsets.vm_map_enter = anchor(pf::find_vm_map_enter_patch_84(ktext), "vm_map_enter")?;
        offsets.vm_map_protect = anchor(pf::find_vm_map_protect_patch_84(ktext), "vm_map_protect")?;
        offsets.mac_mount = anchor(pf::find_mount_84(ktext), "mac_mount")?;
        offsets.csops = anchor(pf::find_csops_84(ktext), "csops")?;
        offsets.csops2 = anchor(pf::find_csops2_84(ktext), "csops")?;
        offsets.pid_check = anchor(pf::find_tfp0_patch(ktext), "task_for_pid")?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    Ok(offsets)
}

/// find_amfi_offset.
fn find_amfi_offsets(
    buf: &[u8],
    kext: &MachoLayout,
    major: u32,
    minor: u32,
) -> Result<AmfiOffsets> {
    let mut offsets = AmfiOffsets::default();
    if major == 3248 {
        // iOS 9.x
        let full = kext_slice(buf, kext, false)?;
        offsets.debugger_got = anchor(
            pf::find_amfi_pe_i_can_has_debugger_got(full),
            "amfi PE_i_can_has_debugger GOT",
        )?;
        offsets.cs_enforcement_got = anchor(
            pf::find_amfi_cs_enforcement_got(full),
            "amfi cs_enforcement GOT",
        )?;
        offsets.execve_hook = anchor(
            pf::find_amfi_execve_ret(kext_slice(buf, kext, true)?),
            "amfi execve hook",
        )?;
    } else if major == 2784 || major == 2783 {
        let full = kext_slice(buf, kext, false)?;
        offsets.debugger_got = anchor(
            pf::find_amfi_pe_i_can_has_debugger_got_84(full),
            "amfi PE_i_can_has_debugger GOT",
        )?;
        offsets.cs_enforcement_got = anchor(
            pf::find_amfi_cs_enforcement_got_84(full),
            "amfi cs_enforcement GOT",
        )?;
    } else if major == 2107 {
        // iOS 6.x
        offsets.debugger_got = anchor(
            pf::find_amfi_pe_i_can_has_debugger_got_ios6(kext_slice(buf, kext, false)?),
            "amfi PE_i_can_has_debugger GOT",
        )?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    Ok(offsets)
}

/// find_sandbox_offset.
fn find_sandbox_offsets(
    buf: &[u8],
    kext: &MachoLayout,
    major: u32,
    minor: u32,
) -> Result<SandboxOffsets> {
    let mut offsets = SandboxOffsets::default();
    if major == 3248 {
        let full = kext_slice(buf, kext, false)?;
        offsets.debugger_got = anchor(
            pf::find_sb_pe_i_can_has_debugger_got(full),
            "sandbox PE_i_can_has_debugger GOT",
        )?;
        offsets.ops = anchor(
            pf::find_sandbox_mac_policy_ops(kext.text_base, full),
            "sandbox mac_policy_ops",
        )?;
    } else if major == 2784 || major == 2783 {
        offsets.debugger_got = anchor(
            pf::find_sb_pe_i_can_has_debugger_got_84(kext_slice(buf, kext, false)?),
            "sandbox PE_i_can_has_debugger GOT",
        )?;
        offsets.sb_evaluate = anchor(
            pf::find_sb_patch(kext_slice(buf, kext, true)?),
            "sb_evaluate",
        )?;
    } else if major == 2107 {
        // iOS 6.x
        offsets.debugger_got = anchor(
            pf::find_sb_pe_i_can_has_debugger_got_ios6(kext_slice(buf, kext, false)?),
            "sandbox PE_i_can_has_debugger GOT",
        )?;
        offsets.sb_evaluate = anchor(
            pf::find_sb_patch(kext_slice(buf, kext, true)?),
            "sb_evaluate",
        )?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    Ok(offsets)
}

/// find_lwvm_offset.
fn find_lwvm_offsets(
    buf: &[u8],
    kext: &MachoLayout,
    major: u32,
    minor: u32,
) -> Result<LwvmOffsets> {
    let mut offsets = LwvmOffsets::default();
    if major == 3248 {
        if minor > 32 {
            // iOS 9.3-9.3.6
            offsets.kernel_conf_got = anchor(
                pf::find_pe_i_can_has_kernel_configuration_got(kext_slice(buf, kext, false)?),
                "lwvm i_can_has_kernel_configuration GOT",
            )?;
            let jump = anchor(
                pf::find_lwvm_jump(kext_slice(buf, kext, true)?),
                "lwvm jump",
            )? as u32;
            offsets.jump = kext.text_base.wrapping_add(jump);
        } else {
            // iOS 9.0-9.2.1
            offsets.map_for_io = anchor(
                pf::find_map_for_io_84(kext_slice(buf, kext, true)?),
                "mapForIO",
            )?;
        }
    } else if major == 2784 || major == 2783 {
        offsets.map_for_io = anchor(
            pf::find_map_for_io_84(kext_slice(buf, kext, true)?),
            "mapForIO",
        )?;
    } else if major != 2107 {
        // 2107 skips LwVM entirely.
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    Ok(offsets)
}

/// patch_text. All writes are bounded by the kernel's __TEXT size, as
/// upstream's `write*(buf, addr->text_size, ...)`.
fn patch_text(
    buf: &mut [u8],
    kernel: &MachoLayout,
    offsets: &TextOffsets,
    major: u32,
    minor: u32,
) -> Result<()> {
    let limit = kernel.text_size as usize;
    if major == 3248 {
        // iOS 9.x
        write_u32(buf, 0, offsets.pid_check, limit, 0xBF00_BF00)?;
        write_u16(buf, 0, offsets.vm_fault_enter, limit, 0x2201)?;
        write_u32(buf, 0, offsets.vm_map_enter, limit, 0xBF00_BF00)?;
        write_u32(buf, 0, offsets.vm_map_protect, limit, 0xBF00_BF00)?;
        write_u32(buf, 0, offsets.csops, limit, 0xBF00_BF00)?;
        write_u8(
            buf,
            0,
            offsets.mac_mount,
            limit,
            if minor == 1 { 0xE7 } else { 0xE0 },
        )?;
    } else if major == 2784 || major == 2783 {
        write_u32(buf, 0, offsets.pid_check, limit, 0xBF00_BF00)?;
        write_u32(buf, 0, offsets.vm_fault_enter, limit, 0x2201_BF00)?;
        write_u32(buf, 0, offsets.vm_map_enter, limit, 0x4280_BF00)?;
        write_u32(buf, 0, offsets.vm_map_protect, limit, 0xBF00_BF00)?;
        write_u32(buf, 0, offsets.csops, limit, 0xBF00_BF00)?;
        write_u8(buf, 0, offsets.csops2, limit, 0x20)?;
        write_u8(buf, 0, offsets.mac_mount, limit, 0xE0)?;
    } else if major == 2107 {
        // iOS 6.x
        write_u16(buf, 0, offsets.vm_map_enter, limit, 0xBF00)?;
        write_u16(buf, 0, offsets.vm_map_protect, limit, 0xE005)?;
        write_u16(buf, 0, offsets.pid_check, limit, 0xE006)?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    debug!("patched __TEXT");
    Ok(())
}

/// patch_amfi.
fn patch_amfi(
    buf: &mut [u8],
    kext: &MachoLayout,
    kernel: &MachoLayout,
    offsets: &AmfiOffsets,
    helper: &HelperOffsets,
    major: u32,
    minor: u32,
) -> Result<()> {
    let base = kext.text_buf_base;
    let maxrange = kext.text_size.wrapping_add(kext.data_size) as usize;
    if major == 3248 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
        write_u32(
            buf,
            base,
            offsets.cs_enforcement_got,
            maxrange,
            helper.ret0_gadget,
        )?;

        let unbase_addr = (offsets.execve_hook as u32)
            .wrapping_add(kext.text_base)
            .wrapping_sub(kernel.text_base);
        let unbase_shc = kernel.last_section.wrapping_sub(kernel.text_base);
        if unbase_addr == 0 || unbase_shc == 0 {
            return Err(Kernel32Error::Malformed("unbased execve hook offsets"));
        }
        // Upstream checks `!val`, which never catches make_b_w's -1; an
        // out-of-range branch is an error here instead of a 0xFFFFFFFF write.
        let branch = pf::make_b_w(unbase_addr as usize, unbase_shc as usize)
            .ok_or(Kernel32Error::BranchOutOfRange("amfi execve hook"))?;
        debug!(
            unbase_addr = format_args!("{unbase_addr:08x}"),
            unbase_shc = format_args!("{unbase_shc:08x}"),
            branch = format_args!("{branch:08x}"),
            "execve hook branch"
        );
        write_u32(
            buf,
            base,
            offsets.execve_hook,
            kext.text_size as usize,
            branch,
        )?;

        let payload_at = kernel
            .last_section
            .wrapping_sub(kernel.text_base.wrapping_sub(kernel.text_buf_base as u32))
            as usize;
        write_bytes(
            buf,
            0,
            payload_at,
            kernel.text_size as usize,
            &AMFI_EXECVE_HOOK_PAYLOAD,
        )?;
    } else if major == 2784 || major == 2783 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
        write_u32(
            buf,
            base,
            offsets.cs_enforcement_got,
            maxrange,
            helper.ret0_gadget,
        )?;
    } else if major == 2107 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    debug!("patched AMFI");
    Ok(())
}

/// patch_sbops: replace non-zero sandbox policy callbacks with the ret0
/// gadget. Zero slots are skipped (and logged) upstream; here they are
/// skipped silently.
fn patch_sbops(
    buf: &mut [u8],
    base: usize,
    ops: usize,
    limit: usize,
    ret0_gadget: u32,
) -> Result<()> {
    if ops
        .checked_add(MAC_POLICY_OPS_SIZE)
        .is_none_or(|end| end > limit)
    {
        return Err(Kernel32Error::OutOfBounds);
    }
    for slot in SBOPS_PATCH_OFFSETS {
        let at = base + ops + slot;
        if read_u32(buf, at)? != 0 {
            write_u32(buf, base, ops + slot, limit, ret0_gadget)?;
        }
    }
    Ok(())
}

/// hook_sb_evaluate6 / hook_sb_evaluate: write the payload into the kernel
/// __TEXT free area and branch sb_evaluate to it.
fn hook_sb_evaluate(
    buf: &mut [u8],
    kext: &MachoLayout,
    kernel: &MachoLayout,
    sb_evaluate: usize,
    helper: &HelperOffsets,
    payload: &[u8],
    layout: &SbPayloadLayout,
) -> Result<()> {
    let base = kext.text_buf_base;
    let backup = read_u32(buf, base + sb_evaluate)?;
    if backup == 0 {
        return Err(Kernel32Error::Malformed("sb_evaluate backup opcode"));
    }
    debug!(backup = format_args!("{backup:08x}"), "sb_evaluate");

    // Opcode sanity check: a 16-bit first halfword must be followed by
    // another 16-bit instruction (the overwritten word spans two).
    if !pf::insn_is_32bit(buf, base + sb_evaluate) && pf::insn_is_32bit(buf, base + sb_evaluate + 2)
    {
        return Err(Kernel32Error::Malformed("sb_evaluate instruction pair"));
    }

    let unbase_last = kernel.last_section.wrapping_sub(kernel.text_base);
    if unbase_last == 0 {
        return Err(Kernel32Error::Malformed("unbased __TEXT free area"));
    }
    let unbase_orig = (sb_evaluate as u32)
        .wrapping_add(kext.text_base)
        .wrapping_sub(kernel.text_base);
    if unbase_orig == 0 {
        return Err(Kernel32Error::Malformed("unbased sb_evaluate"));
    }

    let opcode = pf::make_b_w(unbase_orig as usize, unbase_last as usize)
        .ok_or(Kernel32Error::BranchOutOfRange("sb_evaluate"))?;
    let vn_getpath_bl = pf::make_bl(
        (unbase_last as usize) + layout.vn_getpath_bl,
        helper.vn_getpath as usize,
    );
    let memcmp_bl = layout
        .memcmp_bl
        .iter()
        .map(|&off| pf::make_bl((unbase_last as usize) + off, helper.memcmp as usize))
        .collect::<Vec<_>>();
    let jumpback = pf::make_b_w(
        (unbase_last as usize) + layout.jumpback,
        (unbase_orig as usize) + 4,
    )
    .ok_or(Kernel32Error::BranchOutOfRange("sb_evaluate jumpback"))?;

    if payload.len() > 0x100 {
        return Err(Kernel32Error::Malformed("sandbox payload size"));
    }
    let mut patched = payload.to_vec();
    let plen = patched.len();
    write_u32(&mut patched, 0, layout.vn_getpath_bl, plen, vn_getpath_bl)?;
    for (&off, bl) in layout.memcmp_bl.iter().zip(&memcmp_bl) {
        write_u32(&mut patched, 0, off, plen, *bl)?;
    }
    write_u32(&mut patched, 0, layout.restore, plen, backup)?;
    write_u32(&mut patched, 0, layout.jumpback, plen, jumpback)?;

    write_u32(buf, base, sb_evaluate, kext.text_size as usize, opcode)?;
    let at = unbase_last as usize;
    buf.get_mut(at..at + patched.len())
        .ok_or(Kernel32Error::OutOfBounds)?
        .copy_from_slice(&patched);
    debug!("hooked sb_evaluate");
    Ok(())
}

/// patch_sandbox.
fn patch_sandbox(
    buf: &mut [u8],
    kext: &MachoLayout,
    kernel: &MachoLayout,
    offsets: &SandboxOffsets,
    helper: &HelperOffsets,
    major: u32,
    minor: u32,
) -> Result<()> {
    let base = kext.text_buf_base;
    let maxrange = kext.text_size.wrapping_add(kext.data_size) as usize;
    if major == 3248 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
        patch_sbops(buf, base, offsets.ops, maxrange, helper.ret0_gadget)?;
    } else if major == 2784 || major == 2783 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
        hook_sb_evaluate(
            buf,
            kext,
            kernel,
            offsets.sb_evaluate,
            helper,
            &SB_PAYLOAD,
            &SB_PAYLOAD_LAYOUT,
        )?;
    } else if major == 2107 {
        write_u32(
            buf,
            base,
            offsets.debugger_got,
            maxrange,
            helper.ret1_gadget,
        )?;
        hook_sb_evaluate(
            buf,
            kext,
            kernel,
            offsets.sb_evaluate,
            helper,
            &SB_PAYLOAD6,
            &SB_PAYLOAD6_LAYOUT,
        )?;
    } else {
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    debug!("patched sandbox");
    Ok(())
}

/// patch_lwvm.
fn patch_lwvm(
    buf: &mut [u8],
    kext: &MachoLayout,
    offsets: &LwvmOffsets,
    major: u32,
    minor: u32,
) -> Result<()> {
    let base = kext.text_buf_base;
    let maxrange = kext.text_size.wrapping_add(kext.data_size) as usize;
    if major == 3248 {
        if minor > 32 {
            write_u32(buf, base, offsets.kernel_conf_got, maxrange, offsets.jump)?;
        } else {
            write_u32(
                buf,
                base,
                offsets.map_for_io,
                kext.text_size as usize,
                0xBF00_BF00,
            )?;
        }
    } else if major == 2784 || major == 2783 {
        write_u32(
            buf,
            base,
            offsets.map_for_io,
            kext.text_size as usize,
            0xBF00_BF00,
        )?;
    } else if major != 2107 {
        // 2107 skips LwVM entirely.
        return Err(Kernel32Error::UnsupportedVersion { major, minor });
    }
    debug!("patched LwVM");
    Ok(())
}

/// Apply the powdersn0w 32-bit kernel patch set, returning the patched
/// kernelcache. See the module docs for the integration contract.
pub fn patch_kernel32(kernelcache: &[u8]) -> Result<Vec<u8>> {
    let mut buf = kernelcache.to_vec();

    let (kernel, major, minor) = init_kernel(&buf)?;

    // The version gate from patchKernel.
    let family = match (major, minor) {
        (2107, 2) => "6.0",
        (2107, 7) => "6.1",
        (2783, _) => "8.0-8.2",
        (2784, _) => "8.3-8.4.1",
        (3248, m) if m < 32 => "9.0-9.2.1",
        (3248, m) if m < 42 => "9.3-9.3.1",
        (3248, _) => "9.3.2+",
        _ => return Err(Kernel32Error::UnsupportedVersion { major, minor }),
    };
    info!(family, "patching kernelcache");

    let amfi = init_kext(&buf, b"com.apple.driver.AppleMobileFileIntegrity")?;
    let sandbox = init_kext(&buf, b"com.apple.security.sandbox")?;
    let lwvm = init_kext(&buf, b"com.apple.driver.LightweightVolumeManager")?;

    // All finders run before any patch, as upstream (patching mutates bytes
    // that some finders' already-patched checks rely on).
    let ktext = kernel_text(&buf, &kernel)?;
    let helper = find_helper_offsets(ktext, &kernel, major)?;
    let text = find_text_offsets(ktext, major, minor)?;
    let amfi_offsets = find_amfi_offsets(&buf, &amfi, major, minor)?;
    let sandbox_offsets = find_sandbox_offsets(&buf, &sandbox, major, minor)?;
    let lwvm_offsets = find_lwvm_offsets(&buf, &lwvm, major, minor)?;

    patch_text(&mut buf, &kernel, &text, major, minor)?;
    patch_amfi(
        &mut buf,
        &amfi,
        &kernel,
        &amfi_offsets,
        &helper,
        major,
        minor,
    )?;
    patch_sandbox(
        &mut buf,
        &sandbox,
        &kernel,
        &sandbox_offsets,
        &helper,
        major,
        minor,
    )?;
    patch_lwvm(&mut buf, &lwvm, &lwvm_offsets, major, minor)?;

    info!("kernelcache patched");
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF_LEN: usize = 0xD800;
    const TEXT_BASE: u32 = 0x1000;
    const TEXT_SIZE: u32 = 0x3000;
    /// __TEXT free area file offset: last_section(0x2B00) - text_base.
    const FREE: usize = 0x1B00;
    const AMFI: usize = 0x4000;
    const SANDBOX: usize = 0x8000;
    const LWVM: usize = 0xC000;
    const LWVM_VM: u32 = 0xA000;
    /// Gadget addresses as written into GOT entries (Thumb bit set).
    const RET0: u32 = TEXT_BASE + 0x201;
    const RET1: u32 = TEXT_BASE + 0x205;

    fn w16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn r16(buf: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
    }

    fn r32(buf: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
    }

    /// nop; mov r0, r8 filler: 16-bit encodings that match no finder's first
    /// mask entry and never read as a BL, push, or literal reference.
    fn fill(buf: &mut [u8], from: usize, to: usize) {
        let mut cur = from;
        while cur + 4 <= to {
            w16(buf, cur, 0xBF00);
            w16(buf, cur + 2, 0x4640);
            cur += 4;
        }
    }

    fn put_str(buf: &mut [u8], offset: usize, s: &str) {
        buf[offset..offset + s.len()].copy_from_slice(s.as_bytes());
        buf[offset + s.len()] = 0;
    }

    fn hw_seq(buf: &mut [u8], offset: usize, hws: &[u16]) {
        for (i, hw) in hws.iter().enumerate() {
            w16(buf, offset + 2 * i, *hw);
        }
    }

    fn bl(buf: &mut [u8], at: usize, target: usize) {
        w32(buf, at, pf::make_bl(at, target));
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

    /// add.w rd, rd, pc (rn == rd, rm == pc), the GOT-stub form the finders
    /// recognize.
    fn add_w_pc(rd: u8) -> u32 {
        (0xEB00 | u32::from(rd)) | (((u32::from(rd) << 8) | 0xF) << 16)
    }

    /// movw/movt pair referencing `target` (a file offset within the slice).
    fn literal_ref(buf: &mut [u8], offset: usize, rd: u8, target: u16) {
        w32(buf, offset, movw(rd, target));
        w32(buf, offset + 4, movt(rd, 0));
    }

    /// GOT reference stub: movw rd, #0; add.w rd, rd, pc computes offset + 8,
    /// where the GOT entry sits (0xFFFFFFFF until patched).
    fn stub(buf: &mut [u8], offset: usize, rd: u8) {
        w32(buf, offset, movw(rd, 0));
        w32(buf, offset + 4, add_w_pc(rd));
        w32(buf, offset + 8, 0xFFFF_FFFF);
    }

    fn header(buf: &mut [u8], base: usize, ncmds: u32) {
        w32(buf, base, MH_MAGIC);
        w32(buf, base + 16, ncmds);
    }

    fn segment(buf: &mut [u8], cmd: usize, name: &str, vmaddr: u32, vmsize: u32, nsects: u32) {
        w32(buf, cmd, LC_SEGMENT);
        w32(buf, cmd + 4, 56 + 68 * nsects);
        buf[cmd + 8..cmd + 24].fill(0);
        buf[cmd + 8..cmd + 8 + name.len()].copy_from_slice(name.as_bytes());
        w32(buf, cmd + 24, vmaddr);
        w32(buf, cmd + 28, vmsize);
        w32(buf, cmd + 48, nsects);
    }

    fn section(buf: &mut [u8], sec: usize, name: &str, addr: u32, size: u32) {
        buf[sec..sec + 16].fill(0);
        buf[sec..sec + name.len()].copy_from_slice(name.as_bytes());
        w32(buf, sec + 32, addr);
        w32(buf, sec + 36, size);
    }

    /// Kernel Mach-O: __TEXT (0x1000, 0x3000) with __text/__const/__cstring
    /// sections ending at 0x2A00 (free area at file offset 0x1B00), then
    /// __DATA. No ret gadgets; the version builders add them.
    fn kernel_skeleton(version: &str) -> Vec<u8> {
        let mut buf = vec![0u8; BUF_LEN];
        fill(&mut buf, 0, BUF_LEN);
        header(&mut buf, 0, 2);
        segment(&mut buf, 28, "__TEXT", TEXT_BASE, TEXT_SIZE, 3);
        let sect = 28 + 56;
        section(&mut buf, sect, "__text", TEXT_BASE, 0x1800);
        section(&mut buf, sect + 68, "__const", TEXT_BASE + 0x1800, 0x100);
        section(&mut buf, sect + 136, "__cstring", TEXT_BASE + 0x1900, 0x100);
        segment(
            &mut buf,
            28 + 56 + 204,
            "__DATA",
            TEXT_BASE + TEXT_SIZE,
            0x1000,
            0,
        );
        put_str(&mut buf, 0x600, version);
        buf
    }

    fn gadgets(buf: &mut [u8]) {
        w16(buf, 0x200, 0x2000); // movs r0, #0
        w16(buf, 0x202, 0x4770); // bx lr
        w16(buf, 0x204, 0x2001); // movs r0, #1
        w16(buf, 0x206, 0x4770); // bx lr
    }

    /// A prelinked kext: Mach-O header, __TEXT (vmaddr, 0x1000) and __DATA
    /// (0x800), and the bundle identifier string at +0x200.
    fn kext(buf: &mut [u8], base: usize, vmaddr: u32, ident: &str) {
        header(buf, base, 2);
        segment(buf, base + 28, "__TEXT", vmaddr, 0x1000, 0);
        segment(buf, base + 28 + 56, "__DATA", vmaddr + 0x1000, 0x800, 0);
        put_str(buf, base + 0x200, ident);
    }

    fn kernel_2107() -> Vec<u8> {
        let mut buf = kernel_skeleton("root:xnu-2107.7.55.1");
        gadgets(&mut buf);
        w16(&mut buf, 0x208, 0xB510); // vn_getpath push {r4, lr}
        buf[0x210..0x210 + 14].copy_from_slice(&[
            0x01, 0x20, 0xCD, 0xE9, 0x00, 0x01, 0x28, 0x46, 0x41, 0x46, 0x32, 0x46, 0x23, 0x46,
        ]);
        buf[0x230..0x230 + 42].copy_from_slice(&[
            0x00, 0x23, 0x62, 0xB1, 0x91, 0xF8, 0x00, 0x90, 0x03, 0x78, 0x4B, 0x45, 0x09, 0xD1,
            0x01, 0x3A, 0x00, 0xF1, 0x01, 0x00, 0x01, 0xF1, 0x01, 0x01, 0x4F, 0xF0, 0x00, 0x03,
            0xF2, 0xD1, 0x18, 0x46, 0x70, 0x47, 0xA3, 0xEB, 0x09, 0x03, 0x18, 0x46, 0x70, 0x47,
        ]);
        // vm_map_enter, with the patched conditional branch at 0x286.
        hw_seq(&mut buf, 0x280, &[0xF000, 0x0006, 0x2806, 0xD101]);
        buf[0x290..0x296].copy_from_slice(&[0x08, 0xBF, 0x10, 0xF0, 0x80, 0x4F]);
        w16(&mut buf, 0x2A0, 0xB510); // task_for_pid push {r4, lr}
        w16(&mut buf, 0x2A2, 0x2800); // cmp r0, #0
        w16(&mut buf, 0x2A4, 0xD001); // beq <- patched
        buf[0x2C0..0x2C8].copy_from_slice(&[0x02, 0x46, 0x30, 0x46, 0x21, 0x46, 0x53, 0x46]);
        amfi_2107(&mut buf);
        sandbox_2107(&mut buf);
        lwvm_plain(&mut buf);
        buf
    }

    fn kernel_2784() -> Vec<u8> {
        let mut buf = kernel_skeleton("root:xnu-2784.57.2");
        gadgets(&mut buf);
        w16(&mut buf, 0x208, 0xB510); // vn_getpath push
        hw_seq(
            &mut buf,
            0x210,
            &[0x2001, 0xE9CD, 0x0000, 0x4600, 0x4600, 0x4600, 0x4600],
        );
        hw_seq(
            &mut buf,
            0x240,
            &[
                0xB100, 0xF890, 0x0000, 0x7800, 0x4500, 0xBF00, 0xEBA0, 0x0000, 0x4770, 0x3801,
                0xF100, 0x0001, 0xF100, 0x0001, 0xD100, 0x2000, 0x4770,
            ],
        );
        hw_seq(
            &mut buf,
            0x280,
            &[
                0xF000, 0x0040, 0xF8D0, 0x0000, 0xF8D0, 0x0000, 0xF010, 0x0F00, 0xD100, 0x6800,
            ],
        );
        hw_seq(
            &mut buf,
            0x2A0,
            &[
                0xF000, 0x0002, 0xF010, 0x0F02, 0xD000, 0x2000, 0xF010, 0x0F04,
            ],
        );
        hw_seq(
            &mut buf,
            0x2C0,
            &[
                0xF010, 0x0F00, 0xF04F, 0x0000, 0xBF00, 0x2001, 0x6840, 0x68C0, 0xF000, 0x0006,
                0x2806, 0xF04F, 0x0000, 0xBF00, 0x2001, 0x4200, 0xBF10, 0xF020, 0x0004,
            ],
        );
        hw_seq(
            &mut buf,
            0x300,
            &[
                0xF420, 0x3080, 0xF010, 0x0F20, 0xBF08, 0xF440, 0x3080, 0xF010, 0x0F01,
            ],
        );
        hw_seq(
            &mut buf,
            0x320,
            &[
                0xF400, 0x0000, 0xE000, 0x0000, 0xF100, 0x0000, 0x4600, 0xF000, 0x0000, 0x4600,
                0xF890, 0x0000, 0xF010, 0x0F01, 0xF000, 0x0000,
            ],
        );
        hw_seq(
            &mut buf,
            0x360,
            &[
                0x9800, 0xF100, 0x0000, 0x4600, 0xF000, 0xE800, 0xF8D0, 0x0000, 0xF040,
            ],
        );
        hw_seq(
            &mut buf,
            0x380,
            &[
                0x9003, 0x9002, 0x2800, 0xF000, 0x8000, 0xF000, 0xF800, 0x9003, 0x2800, 0xF000,
                0x8000,
            ],
        );
        amfi_2784(&mut buf);
        sandbox_2784(&mut buf);
        lwvm_map_for_io(&mut buf);
        buf
    }

    fn kernel_3248(version: &str, mount_90: bool) -> Vec<u8> {
        let mut buf = kernel_skeleton(version);
        gadgets(&mut buf);
        hw_seq(
            &mut buf,
            0x210,
            &[
                0x6800, 0x2800, 0xD100, 0xF010, 0x0F00, 0xD100, 0xF400, 0x1080,
            ],
        );
        hw_seq(
            &mut buf,
            0x230,
            &[0xF010, 0x0F04, 0x4600, 0xBF10, 0xF020, 0x0004],
        );
        hw_seq(
            &mut buf,
            0x250,
            &[
                0xF010, 0x0F00, 0x6840, 0xF000, 0x0006, 0x68C0, 0x4600, 0xBF00, 0xF020, 0x0004,
            ],
        );
        if mount_90 {
            hw_seq(
                &mut buf,
                0x280,
                &[
                    0xF420, 0x3080, 0xF010, 0x0F20, 0xBF08, 0xF440, 0x3080, 0xF010, 0x0F01,
                ],
            );
        } else {
            hw_seq(
                &mut buf,
                0x280,
                &[0xD100, 0x2001, 0xE000, 0x2001, 0xE000, 0xF440, 0x3080],
            );
        }
        hw_seq(
            &mut buf,
            0x2A0,
            &[
                0xF100, 0x0000, 0x4600, 0xF400, 0x0000, 0xF890, 0x0000, 0xF010, 0x0F01, 0xD000,
            ],
        );
        hw_seq(
            &mut buf,
            0x2C0,
            &[
                0x9003, 0x9002, 0x2800, 0xF000, 0x8000, 0xF000, 0xF800, 0x9003, 0x2800, 0xF000,
                0x8000,
            ],
        );
        amfi_3248(&mut buf);
        sandbox_3248(&mut buf);
        buf
    }

    fn amfi_2107(buf: &mut [u8]) {
        kext(
            buf,
            AMFI,
            0x8000,
            "com.apple.driver.AppleMobileFileIntegrity",
        );
        literal_ref(buf, AMFI + 0x100, 3, 0x240);
        // Three call sites into the same stub: the backward walk's second
        // round must find another BL to the debugger stub (as in real AMFI),
        // not some unrelated BL above.
        bl(buf, AMFI + 0xF0, AMFI + 0x160);
        bl(buf, AMFI + 0xF4, AMFI + 0x160);
        bl(buf, AMFI + 0xF8, AMFI + 0x160);
        stub(buf, AMFI + 0x160, 3); // debugger GOT at +0x168
        put_str(buf, AMFI + 0x240, "amfi_unrestrict_task_for_pid");
    }

    fn amfi_2784(buf: &mut [u8]) {
        kext(
            buf,
            AMFI,
            0x8000,
            "com.apple.driver.AppleMobileFileIntegrity",
        );
        literal_ref(buf, AMFI + 0x90, 3, 0x280);
        bl(buf, AMFI + 0x98, AMFI + 0x140);
        stub(buf, AMFI + 0x140, 4); // cs_enforcement GOT at +0x148
        // The backward walk's second round keeps scanning down from the first
        // BL it finds; the nearest BL below the cluster must target the same
        // debugger stub, or it would steal the result (here: the cs BL).
        bl(buf, AMFI + 0xA0, AMFI + 0x160);
        bl(buf, AMFI + 0xF0, AMFI + 0x160);
        bl(buf, AMFI + 0xF4, AMFI + 0x160);
        bl(buf, AMFI + 0xF8, AMFI + 0x160);
        literal_ref(buf, AMFI + 0x100, 3, 0x240);
        stub(buf, AMFI + 0x160, 3); // debugger GOT at +0x168
        put_str(buf, AMFI + 0x240, "amfi_unrestrict_task_for_pid");
        put_str(buf, AMFI + 0x280, "missing or invalid entitlement hash");
    }

    fn amfi_3248(buf: &mut [u8]) {
        kext(
            buf,
            AMFI,
            0x8000,
            "com.apple.driver.AppleMobileFileIntegrity",
        );
        literal_ref(buf, AMFI + 0x100, 3, 0x240);
        bl(buf, AMFI + 0x108, AMFI + 0x140);
        bl(buf, AMFI + 0x110, AMFI + 0x160);
        stub(buf, AMFI + 0x140, 4); // cs_enforcement GOT at +0x148
        stub(buf, AMFI + 0x160, 3); // debugger GOT at +0x168
        hw_seq(
            buf,
            AMFI + 0x1A0,
            &[
                0xF8DA, 0x0000, 0xF010, 0x0F08, 0xBF10, 0xF440, 0x0000, 0xF8CA, 0x0000, 0x2000,
                0xB000, 0xE8BD, 0x0D00, 0xBDF0,
            ],
        );
        put_str(buf, AMFI + 0x240, "failed getting entitlements");
    }

    fn sandbox_2107(buf: &mut [u8]) {
        kext(buf, SANDBOX, 0x9000, "com.apple.security.sandbox");
        w16(buf, SANDBOX + 0x90, 0xB510); // sb_evaluate push {r4, lr}
        w16(buf, SANDBOX + 0x92, 0xBF00); // nop: the saved opcode word is 0xBF00B510
        literal_ref(buf, SANDBOX + 0xA0, 2, 0x280);
        literal_ref(buf, SANDBOX + 0x100, 3, 0x240);
        bl(buf, SANDBOX + 0x108, SANDBOX + 0x140);
        bl(buf, SANDBOX + 0x110, SANDBOX + 0x160);
        stub(buf, SANDBOX + 0x140, 4);
        stub(buf, SANDBOX + 0x160, 3); // debugger GOT at +0x168
        put_str(buf, SANDBOX + 0x240, "smalloc() failed");
        put_str(buf, SANDBOX + 0x280, "control_name");
    }

    fn sandbox_2784(buf: &mut [u8]) {
        kext(buf, SANDBOX, 0x9000, "com.apple.security.sandbox");
        w16(buf, SANDBOX + 0xA0, 0xB510); // sb_evaluate push {r4, lr}
        w16(buf, SANDBOX + 0xA2, 0xBF00); // nop: the saved opcode word is 0xBF00B510
        literal_ref(buf, SANDBOX + 0xB0, 2, 0x280);
        hw_seq(buf, SANDBOX + 0x100, &[0xB590, 0x2000, 0xAF01, 0x2400]);
        bl(buf, SANDBOX + 0x108, SANDBOX + 0x140);
        w16(buf, SANDBOX + 0x10C, 0xB100);
        stub(buf, SANDBOX + 0x140, 3); // debugger GOT at +0x148
        put_str(buf, SANDBOX + 0x280, "control_name");
    }

    fn sandbox_3248(buf: &mut [u8]) {
        kext(buf, SANDBOX, 0x9000, "com.apple.security.sandbox");
        literal_ref(buf, SANDBOX + 0x100, 3, 0x240);
        bl(buf, SANDBOX + 0x108, SANDBOX + 0x140);
        bl(buf, SANDBOX + 0x110, SANDBOX + 0x160);
        stub(buf, SANDBOX + 0x140, 4);
        stub(buf, SANDBOX + 0x160, 3); // debugger GOT at +0x168
        put_str(
            buf,
            SANDBOX + 0x240,
            "amfi_copy_seatbelt_profile_names() failed",
        );
        put_str(buf, SANDBOX + 0x280, "Seatbelt sandbox policy");
        w32(buf, SANDBOX + 0x300, 0x9000 + 0x280); // mac_policy_conf fullname ptr
        w32(buf, SANDBOX + 0x30C, 0x9000 + 0x800); // mac_policy_conf ops ptr
        for off in (0..MAC_POLICY_OPS_SIZE).step_by(4) {
            w32(buf, SANDBOX + 0x800 + off, 0xFFFF_FFFF);
        }
    }

    fn lwvm_plain(buf: &mut [u8]) {
        kext(
            buf,
            LWVM,
            LWVM_VM,
            "com.apple.driver.LightweightVolumeManager",
        );
    }

    fn lwvm_map_for_io(buf: &mut [u8]) {
        lwvm_plain(buf);
        hw_seq(
            buf,
            LWVM + 0x100,
            &[
                0xF8D0, 0x0000, 0xF890, 0x0000, 0x4800, 0x2900, 0xF040, 0x8000,
            ],
        );
    }

    fn lwvm_932(buf: &mut [u8]) {
        lwvm_plain(buf);
        literal_ref(buf, LWVM + 0x100, 3, 0x240);
        bl(buf, LWVM + 0x108, LWVM + 0x140);
        bl(buf, LWVM + 0x110, LWVM + 0x160);
        stub(buf, LWVM + 0x140, 4);
        stub(buf, LWVM + 0x160, 3); // kernel-configuration GOT at +0x168
        hw_seq(
            buf,
            LWVM + 0x180,
            &[0x6800, 0x4400, 0x7800, 0xF010, 0x0F01, 0xD000],
        );
        put_str(buf, LWVM + 0x240, "_mapForIO");
    }

    #[test]
    fn patches_ios6_kernelcache() {
        let out = patch_kernel32(&kernel_2107()).unwrap();
        assert_eq!(out.len(), BUF_LEN);
        // __TEXT: vm_map_enter, vm_map_protect, task_for_pid.
        assert_eq!(r16(&out, 0x286), 0xBF00);
        assert_eq!(r16(&out, 0x296), 0xE005);
        assert_eq!(r16(&out, 0x2A4), 0xE006);
        // AMFI GOT -> ret1.
        assert_eq!(r32(&out, AMFI + 0x168), RET1);
        // Sandbox GOT -> ret1, sb_evaluate branched to the payload.
        assert_eq!(r32(&out, SANDBOX + 0x168), RET1);
        assert_eq!(
            r32(&out, SANDBOX + 0x90),
            pf::make_b_w(0x8090, 0x1B00).unwrap()
        );
        // evasi0n6 payload slots.
        assert_eq!(r32(&out, FREE + 0x20), pf::make_bl(FREE + 0x20, 0x209));
        for &off in &[0x32usize, 0x40, 0x4E] {
            assert_eq!(r32(&out, FREE + off), pf::make_bl(FREE + off, 0x231));
        }
        assert_eq!(r32(&out, FREE + 0x70), 0xBF00_B510); // saved push {r4, lr}; nop
        assert_eq!(
            r32(&out, FREE + 0x74),
            pf::make_b_w(FREE + 0x74, 0x8094).unwrap()
        );
    }

    #[test]
    fn patches_ios84_kernelcache() {
        let out = patch_kernel32(&kernel_2784()).unwrap();
        assert_eq!(out.len(), BUF_LEN);
        assert_eq!(r32(&out, 0x386), 0xBF00_BF00); // task_for_pid
        assert_eq!(r32(&out, 0x290), 0x2201_BF00); // vm_fault_enter
        assert_eq!(r32(&out, 0x2A4), 0x4280_BF00); // vm_map_enter
        assert_eq!(r32(&out, 0x2E2), 0xBF00_BF00); // vm_map_protect
        assert_eq!(r32(&out, 0x33C), 0xBF00_BF00); // csops
        assert_eq!(out[0x370], 0x20); // csops2
        assert_eq!(out[0x2FF], 0xE0); // mac_mount
        // AMFI GOTs.
        assert_eq!(r32(&out, AMFI + 0x168), RET1);
        assert_eq!(r32(&out, AMFI + 0x148), RET0);
        // Sandbox GOT -> ret1, sb_evaluate branched to the payload.
        assert_eq!(r32(&out, SANDBOX + 0x148), RET1);
        assert_eq!(
            r32(&out, SANDBOX + 0xA0),
            pf::make_b_w(0x80A0, 0x1B00).unwrap()
        );
        // taig payload slots.
        assert_eq!(r32(&out, FREE + 0x22), pf::make_bl(FREE + 0x22, 0x209));
        for &off in &[0x34usize, 0x44, 0x50, 0x5C] {
            assert_eq!(r32(&out, FREE + off), pf::make_bl(FREE + off, 0x241));
        }
        assert_eq!(r32(&out, FREE + 0x80), 0xBF00_B510);
        assert_eq!(
            r32(&out, FREE + 0x84),
            pf::make_b_w(FREE + 0x84, 0x80A4).unwrap()
        );
        // LwVM mapForIO.
        assert_eq!(r32(&out, LWVM + 0x10C), 0xBF00_BF00);
    }

    #[test]
    fn patches_ios9_kernelcache() {
        let mut buf = kernel_3248("root:xnu-3248.20.1", false);
        lwvm_map_for_io(&mut buf);
        let out = patch_kernel32(&buf).unwrap();
        assert_eq!(out.len(), BUF_LEN);
        assert_eq!(r16(&out, 0x210), 0x2201); // vm_fault_enter
        assert_eq!(r32(&out, 0x238), 0xBF00_BF00); // vm_map_enter
        assert_eq!(r32(&out, 0x260), 0xBF00_BF00); // vm_map_protect
        assert_eq!(r32(&out, 0x2B2), 0xBF00_BF00); // csops
        assert_eq!(r32(&out, 0x2C6), 0xBF00_BF00); // task_for_pid
        assert_eq!(out[0x281], 0xE0); // mac_mount
        // AMFI GOTs and the execve hook branch + payload.
        assert_eq!(r32(&out, AMFI + 0x168), RET1);
        assert_eq!(r32(&out, AMFI + 0x148), RET0);
        assert_eq!(
            r32(&out, AMFI + 0x1B4),
            pf::make_b_w(0x71B4, 0x1B00).unwrap()
        );
        assert_eq!(&out[FREE..FREE + 30], &AMFI_EXECVE_HOOK_PAYLOAD);
        // Sandbox GOT and mac_policy_ops slots.
        assert_eq!(r32(&out, SANDBOX + 0x168), RET1);
        assert_eq!(r32(&out, SANDBOX + 0x800 + 0x278), RET0); // proc_check_fork
        assert_eq!(r32(&out, SANDBOX + 0x800 + 0x90), RET0); // file_check_mmap
        assert_eq!(r32(&out, SANDBOX + 0x800 + 0x8C), 0xFFFF_FFFF); // untouched slot
        // LwVM mapForIO (minor <= 32).
        assert_eq!(r32(&out, LWVM + 0x10C), 0xBF00_BF00);
    }

    #[test]
    fn patches_ios932_kernelcache() {
        let mut buf = kernel_3248("root:xnu-3248.60.1", false);
        lwvm_932(&mut buf);
        let out = patch_kernel32(&buf).unwrap();
        // Same __TEXT patch set as 9.0-9.2.1.
        assert_eq!(r16(&out, 0x210), 0x2201);
        assert_eq!(out[0x281], 0xE0);
        // LwVM: the kernel-configuration GOT now points at the lwvm jump code
        // (text_base + offset with Thumb bit).
        assert_eq!(r32(&out, LWVM + 0x168), LWVM_VM + 0x181);
    }

    #[test]
    fn patches_ios91_mount_variant() {
        let mut buf = kernel_3248("root:xnu-3248.1.1", true);
        lwvm_map_for_io(&mut buf);
        let out = patch_kernel32(&buf).unwrap();
        // mount_90 site is patched with 0xE7 instead of 0xE0.
        assert_eq!(out[0x293], 0xE7);
        assert_eq!(r32(&out, LWVM + 0x10C), 0xBF00_BF00);
    }

    #[test]
    fn rejects_unsupported_versions() {
        let err = patch_kernel32(&kernel_skeleton("root:xnu-2787.1.1")).unwrap_err();
        assert!(matches!(
            err,
            Kernel32Error::UnsupportedVersion {
                major: 2787,
                minor: 1
            }
        ));
        let err = patch_kernel32(&kernel_skeleton("root:xnu-2107.3.1")).unwrap_err();
        assert!(matches!(
            err,
            Kernel32Error::UnsupportedVersion {
                major: 2107,
                minor: 3
            }
        ));
    }

    #[test]
    fn rejects_missing_version_string() {
        let err = patch_kernel32(&kernel_skeleton("no xnu version here")).unwrap_err();
        assert!(matches!(err, Kernel32Error::VersionNotFound));
    }

    #[test]
    fn rejects_non_macho() {
        let mut buf = kernel_skeleton("root:xnu-3248.20.1");
        buf[0] ^= 0xFF;
        let err = patch_kernel32(&buf).unwrap_err();
        assert!(matches!(err, Kernel32Error::NotMachO));
    }

    #[test]
    fn reports_anchor_miss_by_name() {
        let mut buf = kernel_skeleton("root:xnu-3248.20.1");
        amfi_3248(&mut buf);
        sandbox_3248(&mut buf);
        lwvm_map_for_io(&mut buf);
        // No gadgets, so the ret0 gadget finder misses first.
        let err = patch_kernel32(&buf).unwrap_err();
        assert!(matches!(err, Kernel32Error::AnchorNotFound("ret0_gadget")));
    }
}
