//! 32-bit iBoot patcher, a Rust port of iH8sn0w's iBoot32Patcher (GPL-3.0),
//! tracking the Merculous fork that Legacy iOS Kit bundles.
//!
//! Operates on decrypted, headerless iBoot/iBSS/iBEC binaries. All addressing
//! is done in file offsets; `base_address` converts to the device's view.
//! [`patch_iboot32_with_options`] applies the selected patches in the same
//! order as the reference tool's `main`.

mod finder;
mod patch;

use thiserror::Error;

use finder::{find_bytes, read_u32};

const RESET_VECTOR: u32 = 0xea00_000e;
const VERS_OFFSET: usize = 0x286;
const KERNELCACHE_PREP_STRING: &[u8] = b"__PAGEZERO";
const RECOVERY_CONSOLE_STRING: &[u8] = b"Entering recovery mode, starting command prompt";

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

    fn os_version(&self) -> u32 {
        OS_INTERVALS
            .iter()
            .find(|(low, high, _)| (low..=high).contains(&&self.version))
            .map(|(_, _, os)| *os)
            .unwrap_or(0)
    }
}

/// iOS 10 boot mode forced by the `--local-boot`/`--remote-boot` patches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootMode {
    Local,
    Remote,
}

/// Variant of the boot-partition patch; the iOS 9+ variant also mangles the
/// "boot-partition" string for De Rebus Antiquis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootPartition {
    Standard,
    Ios9OrLater,
}

/// Patch selection mirroring the iBoot32Patcher command-line flags. The RSA
/// check patch is applied by [`patch_iboot32_with_options`] unless `skip_rsa`
/// is set, since nearly every Legacy iOS Kit invocation passes `--rsa`; the
/// exception is the powdersn0w two-bundle `patch_iboot --logo` re-patch of an
/// iBoot2 whose RSA check the powdersn0w iBoot patcher already removed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Iboot32PatchOptions {
    /// `-b`: hardcode custom boot-args (conflicts with `env_boot_args`).
    pub boot_args: Option<String>,
    /// `-a`: read boot-args from the environment variable.
    pub env_boot_args: bool,
    /// `-c CMD PTR`: redirect a recovery console command handler.
    pub command_handler: Option<(String, u32)>,
    /// `--debug`: force the debug-enabled DeviceTree property.
    pub debug: bool,
    /// `--ticket`: patch out the APTicket check.
    pub ticket: bool,
    /// `--local-boot`/`--remote-boot` (iOS 10).
    pub boot_mode: Option<BootMode>,
    /// `--boot-partition`/`--boot-partition9` (De Rebus Antiquis).
    pub boot_partition: Option<BootPartition>,
    /// `--boot-ramdisk`.
    pub boot_ramdisk: bool,
    /// `--setenv`: allow the setenv command to touch every variable.
    pub setenv: bool,
    /// `--disable-kaslr`.
    pub disable_kaslr: bool,
    /// `--bgcolor RRGGBB`.
    pub bgcolor: Option<String>,
    /// `--logo`: fix AppleLogo for iOS 5+ iBoot.
    pub logo: bool,
    /// `--logo4`: fix AppleLogo for iOS 4 iBoot.
    pub logo4: bool,
    /// `--433`: enable jumping to an iOS 4.3.3-or-lower iBoot.
    pub jump_iboot_433: bool,
    /// `--dualboot`: De Rebus Antiquis dualboot patches for iBSS/iBEC.
    pub dualboot: bool,
    /// Omit the RSA check patch (upstream's `patch_iboot` drops `--rsa` for
    /// the `--logo` pass over an already RSA-patched iBoot2).
    pub skip_rsa: bool,
}

impl Iboot32PatchOptions {
    fn validate(&self) -> Result<(), IbootPatchError> {
        if self.boot_args.is_some() && self.env_boot_args {
            return Err(IbootPatchError::ConflictingBootArgs);
        }
        Ok(())
    }
}

/// Apply the selected patches, in the order the reference tool's `main`
/// applies them:
///
/// 1. with a kernel load routine: boot-args, env boot-args, debug, KASLR,
///    bgcolor, boot mode
/// 2. logo, logo4, jump-to-iBoot (4.3.3 or lower), ticket
/// 3. command handler (only with a recovery console)
/// 4. RSA check (unless `skip_rsa`)
/// 5. boot-partition, boot-ramdisk, setenv, dualboot
pub fn patch_iboot32_with_options(
    image: &[u8],
    options: &Iboot32PatchOptions,
) -> Result<Vec<u8>, IbootPatchError> {
    options.validate()?;
    let mut buf = image.to_vec();
    let mut iboot = IBoot32::new(&mut buf)?;

    // Only bootloaders with the kernel load routine pass the DeviceTree.
    if iboot.has_kernel_load() {
        if let Some(boot_args) = &options.boot_args {
            iboot.patch_boot_args(boot_args)?;
        }
        if options.env_boot_args {
            iboot.patch_env_boot_args()?;
        }
        if options.debug {
            iboot.patch_debug_enabled()?;
        }
        if options.disable_kaslr {
            iboot.disable_kaslr()?;
        }
        if let Some(bgcolor) = &options.bgcolor {
            iboot.patch_bgcolor(bgcolor)?;
        }
        if let Some(mode) = options.boot_mode {
            iboot.patch_boot_mode(mode)?;
        }
    }

    if options.logo {
        iboot.patch_logo()?;
    }
    if options.logo4 {
        iboot.patch_logo4()?;
    }
    if options.jump_iboot_433 {
        iboot.patch_jump_iboot_433()?;
    }
    if options.ticket {
        iboot.patch_ticket_check()?;
    }

    // Ensure that the loader has a shell before redirecting a command.
    if iboot.has_recovery_console()
        && let Some((command, pointer)) = &options.command_handler
    {
        iboot.patch_cmd_handler(command, *pointer)?;
    }

    // All loaders have the RSA check, unless the caller knows it is already
    // patched out (powdersn0w's two-bundle iBoot2 re-patch).
    if !options.skip_rsa {
        iboot.patch_rsa_check()?;
    }

    if let Some(partition) = options.boot_partition {
        iboot.patch_boot_partition(partition)?;
    }
    if options.boot_ramdisk {
        iboot.patch_boot_ramdisk()?;
    }
    if options.setenv {
        iboot.patch_setenv_cmd()?;
    }
    if options.dualboot {
        iboot.patch_dualboot()?;
    }
    Ok(buf)
}

/// Apply the iBoot32Patcher default patch set: boot-args (optional),
/// debug-enabled, command handler (optional), and the RSA check.
pub fn patch_iboot32(
    image: &[u8],
    boot_args: Option<&str>,
    command_handler: Option<(&str, u32)>,
) -> Result<Vec<u8>, IbootPatchError> {
    patch_iboot32_with_options(
        image,
        &Iboot32PatchOptions {
            boot_args: boot_args.map(str::to_owned),
            command_handler: command_handler
                .map(|(command, pointer)| (command.to_owned(), pointer)),
            debug: true,
            ..Iboot32PatchOptions::default()
        },
    )
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

#[derive(Debug, Error)]
pub enum IbootPatchError {
    #[error("the image is an IMG3 container; strip the header and decrypt first")]
    Img3Container,
    #[error("the image is not a 32-bit iBoot (bad reset vector)")]
    NotIBoot32,
    #[error("no iBoot version string found")]
    VersionNotFound,
    #[error("cannot locate {0}")]
    AnchorNotFound(&'static str),
    #[error("the background color must be six hexadecimal digits (RRGGBB)")]
    InvalidBgcolor,
    #[error("custom boot-args conflict with the env boot-args patch")]
    ConflictingBootArgs,
    #[error("the dualboot patch requires an iBSS or iBEC image")]
    NotIbssOrIbec,
    #[error("pre-iOS 5 iBSS images cannot be dualboot-patched; use an iBEC instead")]
    PreIos5Ibss,
    #[error("unsupported dualboot platform 0x{0:08x}")]
    UnsupportedDualbootPlatform(u32),
    #[error("image is too small for the required access")]
    OutOfBounds,
}

#[cfg(test)]
mod tests {
    use super::finder::{make_b_w, resolve_bl32};
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

        assert_eq!(
            &iboot.buf[BL_VERIFY_SHSH..BL_VERIFY_SHSH + 4],
            &[0x00, 0x20, 0x18, 0x60]
        );
    }

    #[test]
    fn rsa_patch_fails_on_patched_image() {
        let mut buf = fixture();
        let mut iboot = IBoot32::new(&mut buf).unwrap();
        iboot.patch_rsa_check().unwrap();

        assert!(matches!(
            iboot.patch_rsa_check(),
            Err(IbootPatchError::AnchorNotFound(_))
        ));
    }

    #[test]
    fn skip_rsa_tolerates_a_patched_image() {
        // The powdersn0w `--logo` re-patch of iBoot2 runs on an image whose
        // RSA check the powdersn0w iBoot patcher already removed.
        let mut buf = fixture();
        IBoot32::new(&mut buf).unwrap().patch_rsa_check().unwrap();

        let options = Iboot32PatchOptions::default();
        assert!(matches!(
            patch_iboot32_with_options(&buf, &options),
            Err(IbootPatchError::AnchorNotFound(_))
        ));
        let options = Iboot32PatchOptions {
            skip_rsa: true,
            ..Iboot32PatchOptions::default()
        };
        assert_eq!(patch_iboot32_with_options(&buf, &options).unwrap(), buf);
    }

    #[test]
    fn resolves_bl32_targets() {
        let buf = fixture();
        assert_eq!(resolve_bl32(&buf, BL_VERIFY_SHSH), Some(PUSH_TOP + 1));
    }

    #[test]
    fn make_b_w_round_trips_through_resolve_bl32() {
        let mut buf = vec![0u8; 0x400];
        write32(&mut buf, 0x100, make_b_w(0x100, 0x200));
        assert_eq!(resolve_bl32(&buf, 0x100), Some(0x200 + 1));
        write32(&mut buf, 0x200, make_b_w(0x200, 0x180));
        assert_eq!(resolve_bl32(&buf, 0x200), Some(0x180 + 1));
    }

    #[test]
    fn rejects_conflicting_boot_args_options() {
        let options = Iboot32PatchOptions {
            boot_args: Some("-v".to_owned()),
            env_boot_args: true,
            ..Iboot32PatchOptions::default()
        };
        assert!(matches!(
            patch_iboot32_with_options(&fixture(), &options),
            Err(IbootPatchError::ConflictingBootArgs)
        ));
    }

    #[test]
    fn rejects_malformed_bgcolor() {
        let mut buf = fixture();
        buf[0x4000..0x4000 + KERNELCACHE_PREP_STRING.len()]
            .copy_from_slice(KERNELCACHE_PREP_STRING);
        for bgcolor in ["fff", "zzzzzz"] {
            let options = Iboot32PatchOptions {
                bgcolor: Some(bgcolor.to_owned()),
                ..Iboot32PatchOptions::default()
            };
            assert!(
                matches!(
                    patch_iboot32_with_options(&buf, &options),
                    Err(IbootPatchError::InvalidBgcolor)
                ),
                "bgcolor {bgcolor} must be rejected"
            );
        }
    }

    #[test]
    fn dualboot_requires_ibss_or_ibec() {
        let options = Iboot32PatchOptions {
            dualboot: true,
            ..Iboot32PatchOptions::default()
        };
        assert!(matches!(
            patch_iboot32_with_options(&fixture(), &options),
            Err(IbootPatchError::NotIbssOrIbec)
        ));
    }
}
