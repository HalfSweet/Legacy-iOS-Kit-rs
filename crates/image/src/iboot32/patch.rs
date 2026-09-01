//! The individual patch routines, ported from `patchers.c` of the Merculous
//! iBoot32Patcher fork. Each method locates its anchors with the [`finder`]
//! primitives and reports a short static description on failure.

use tracing::debug;

use super::finder::{
    bl_search_down, branch_search_up, branch_thumb_conditional_search, build_bl_long, build_mov,
    find_boot_args_mov, find_bytes, find_last_ldr_rd, find_next_bl_to, find_next_bl_to_from,
    find_next_cmp, find_next_movt, find_next_movw, ldr_pcrel_search_up, ldr_search_up, ldr_to,
    make_b_w, pop_search, push_r4_r7_lr_search_up, push_r4_to_r7_lr_search_up, push_search_up,
    read_u16, read_u32, resolve_bl_long, resolve_bl32, search_up, search_up_u16, write_u16,
    write_u32,
};
use super::{BootMode, BootPartition, IBoot32, IbootPatchError};

const DEBUG_ENABLED_DTRE_VAR: &[u8] = b"debug-enabled";
const DEFAULT_BOOT_ARGS: &[u8] = b"rd=md0 nand-enable-reformat=1 -progress";
const RELIANCE_CERT_STRING: &[u8] = b"Reliance on this certificate";
const PLATFORM_INIT_STRING: &[u8] = b"platform/s5l";
const IBSS_READY_STRING: &[u8] = b"iBSS ready, asking for DFU...\n";
const DFU_MODE_STRING: &[u8] = b"Apple Mobile Device (DFU Mode)";

/// MOVW R0, #'RT' immediate (multi-character constant 'RT' as emitted).
const RT_CONSTANT: u32 = 0x5254;
/// Literal pool constant for the 'CERT' image tag.
const CERT_CONSTANT: u32 = 0x4345_5254;

/// IT EQ / IT NE / ITE NE (Thumb T1).
const IT_EQ: u16 = 0xbf08;
const IT_NE: u16 = 0xbf18;
const ITE_NE: u16 = 0xbf14;

const NOP: u16 = 0xbf00;
/// MOVS R0, #0; MOVS R0, #0 (little-endian pair).
const MOVS_R0_0_TWICE: u32 = 0x2000_2000;
/// MOVS R0, #0; STR R0, [R3].
const RSA_PATCH: u32 = 0x6018_2000;
/// MOVS R0, #1; MOVS R0, #1.
const DEBUG_PATCH: u32 = 0x0120_0120;
/// NOP; NOP.
const NOP_TWICE: u32 = 0xbf00_bf00;
/// MOVW R0, #0 / MOVW R1, #0 / MOVW R0, #-1 (little-endian words).
const MOVW_R0_0: u32 = 0x0000_f04f;
const MOVW_R1_0: u32 = 0x0100_f04f;
const MOVW_R0_NEG1: u32 = 0x30ff_f04f;
/// MOVS R0, #0; BX LR (local boot) / MOVS R0, #1; BX LR (remote boot).
const RETURN_0: u32 = 0x4770_2000;
const RETURN_1: u32 = 0x4770_2001;

/// STR R1, [R4, R0]; LDR Rd, [PC, #imm] helper from xerub's iloader.
const STR_R1_R4_R0: u16 = 0x5021;
const fn ldr_r_pc(rd: u16, imm: u16) -> u16 {
    0x4800 | ((rd & 7) << 8) | (imm / 4)
}

/// MOVW/MOVT R1, #'logo' instruction pair.
const MOV_R1_LOGO: [u8; 8] = [0x46, 0xf2, 0x6f, 0x70, 0xc6, 0xf6, 0x6f, 0x40];
/// MOVW R0, #'logo' (patched to 'logb' by [`IBoot32::patch_logo`]).
const MOV_LOGO: [u8; 4] = [0x46, 0xf2, 0x6f, 0x70];
/// setbgcolor() arguments: MOVS R0, #r; MOVS R1, #g; MOVS R2, #b.
const SETBGCOLOR_ARGS: [u8; 6] = [0x00, 0x20, 0x00, 0x21, 0x00, 0x22];

/// iOS 4.3.3-or-lower anchors. The C original searches these with `sizeof`,
/// so the trailing NUL of each literal is part of the needle.
const JUMP_433_PATCH_SITE: [u8; 9] = [0x00, 0x28, 0x08, 0xbf, 0x01, 0x20, 0x80, 0xbd, 0x00];
const JUMP_433_PAYLOAD_HEADER: [u8; 9] = [0x10, 0xff, 0x2f, 0xe1, 0xfe, 0xff, 0xff, 0xea, 0x00];

const IBSS_TYPE: u32 = u32::from_le_bytes(*b"iBSS");
const IBEC_TYPE: u32 = u32::from_le_bytes(*b"iBEC");

impl IBoot32<'_> {
    /// BL verify_shsh → `MOVS R0, #0; STR R0, [R3]`.
    pub(super) fn patch_rsa_check(&mut self) -> Result<(), IbootPatchError> {
        let os_version = self.os_version();
        let anchor = if (5..=7).contains(&os_version) {
            find_next_movw(self.buf, 0, self.buf.len(), RT_CONSTANT)
        } else {
            self.find_next_ldr(CERT_CONSTANT)
        }
        .ok_or(IbootPatchError::AnchorNotFound(
            "the verify_shsh anchor instruction",
        ))?;
        let top = search_up_u16(self.buf, anchor, 0x500, 0xb5f0, 0xffff)
            .ok_or(IbootPatchError::AnchorNotFound("the top of verify_shsh"))?
            + 1; // Thumb bit
        let first =
            find_next_bl_to(self.buf, top as u32).ok_or(IbootPatchError::AnchorNotFound(
                "the BL verify_shsh call (image may already be patched)",
            ))?;
        // iOS 5-7 images carry a second call site, which is the real one.
        let call = if (5..=7).contains(&os_version) {
            find_next_bl_to_from(self.buf, first + 1, top as u32).unwrap_or(first)
        } else {
            first
        };
        debug!(offset = call, "patching BL verify_shsh");
        write_u32(self.buf, call, RSA_PATCH)
    }

    /// BL get_value_for_dtre_var("debug-enabled") → `MOVS R0, #1; MOVS R0, #1`.
    pub(super) fn patch_debug_enabled(&mut self) -> Result<(), IbootPatchError> {
        let call = self.find_dtre_get_value_bl(DEBUG_ENABLED_DTRE_VAR).ok_or(
            IbootPatchError::AnchorNotFound("the debug-enabled DeviceTree lookup"),
        )?;
        debug!(offset = call, "patching debug-enabled check");
        write_u32(self.buf, call, DEBUG_PATCH)
    }

    pub(super) fn patch_boot_args(&mut self, boot_args: &str) -> Result<(), IbootPatchError> {
        let mut args_string = find_bytes(self.buf, DEFAULT_BOOT_ARGS).ok_or(
            IbootPatchError::AnchorNotFound("the default boot-args string"),
        )?;
        let xref = self
            .iboot_memmem(args_string)
            .ok_or(IbootPatchError::AnchorNotFound("the boot-args string xref"))?;

        if boot_args.len() > DEFAULT_BOOT_ARGS.len() {
            let relocated = find_bytes(self.buf, RELIANCE_CERT_STRING).ok_or(
                IbootPatchError::AnchorNotFound("the \"Reliance on this certificate\" string"),
            )?;
            let target = (relocated as u32).wrapping_add(self.base_address);
            debug!(offset = relocated, "relocating the boot-args string");
            write_u32(self.buf, xref, target)?;
            args_string = relocated;
        }
        let end = args_string + boot_args.len();
        if end >= self.buf.len() {
            return Err(IbootPatchError::OutOfBounds);
        }
        self.buf[args_string..end].copy_from_slice(boot_args.as_bytes());
        self.buf[end] = 0;

        let ldr = ldr_to(self.buf, xref)
            .or_else(|| self.find_next_ldr((args_string as u32).wrapping_add(self.base_address)))
            .ok_or(IbootPatchError::AnchorNotFound(
                "the boot-args LDR instruction",
            ))?;
        let ldr_rd = (read_u16(self.buf, ldr)? >> 8) as u8 & 0x7;

        // The IT instruction, when present, sits within 0x30 halfwords of the LDR.
        let mut it = None;
        let mut cursor = ldr;
        while cursor < ldr + 0x60 {
            let Ok(value) = read_u16(self.buf, cursor) else {
                break;
            };
            if matches!(value, IT_EQ | IT_NE | ITE_NE) {
                it = Some(cursor);
                break;
            }
            cursor += 2;
        }

        let os_version = self.os_version();
        if (2..=4).contains(&os_version) {
            // On the old loaders patching the CMP immediate is sufficient.
            let cmp = if let Some(it) = it {
                find_next_cmp(self.buf, it.saturating_sub(2), 0x10, 0)
            } else if os_version == 2 {
                find_next_cmp(self.buf, ldr.saturating_sub(0x40), 0x10, 0)
            } else {
                find_next_cmp(self.buf, ldr.saturating_sub(0x10), 0x20, 0)
            }
            .ok_or(IbootPatchError::AnchorNotFound(
                "the boot-args CMP instruction",
            ))?;
            debug!(offset = cmp, "patching the boot-args CMP");
            self.buf[cmp] = 1; // CMP Rx, #0 → CMP Rx, #1
            return Ok(());
        }

        let cmp = find_next_cmp(self.buf, ldr, 0x100, 0).ok_or(IbootPatchError::AnchorNotFound(
            "the boot-args CMP instruction",
        ))?;
        debug!(offset = cmp, "patching the boot-args CMP");
        self.buf[cmp] = 1; // CMP Rx, #0 → CMP Rx, #1

        // MOV Rd, Rs usually follows right after the IT instruction.
        let mov = it.unwrap_or(ldr) + 2;
        let mov_insn = read_u16(self.buf, mov)?;
        let (mov_rd, mov_rs) = ((mov_insn & 0x7) as u8, ((mov_insn >> 3) & 0x7) as u8);
        let null_str_reg = if ldr_rd == mov_rs { mov_rd } else { mov_rs };

        // Some iBoots have the null string load after the CMP instruction.
        let null_ldr = find_last_ldr_rd(self.buf, cmp + 0x10, 0x200, null_str_reg)
            .or_else(|| find_last_ldr_rd(self.buf, cmp + 0x9, 0x200, null_str_reg))
            .ok_or(IbootPatchError::AnchorNotFound("the null-string LDR"))?;
        let diff = xref - null_ldr;
        // T1 LDR PC-based instructions use the immediate 8 bits multiplied by 4.
        debug!(
            offset = null_ldr,
            "pointing the null-string LDR at the boot-args xref"
        );
        self.buf[null_ldr] = (diff / 4) as u8;
        Ok(())
    }

    /// Use the `boot-args` environment variable instead of the compiled-in
    /// default: redirect the default-args LDR at the variable string and call
    /// getenv from the boot-args selection site.
    pub(super) fn patch_env_boot_args(&mut self) -> Result<(), IbootPatchError> {
        let ldr = self
            .find_next_ldr_with_str(DEFAULT_BOOT_ARGS)
            .ok_or(IbootPatchError::AnchorNotFound("the rd=md0 LDR"))?;
        let ldr_rd = (read_u16(self.buf, ldr)? >> 8) as u8 & 0x7;
        let cmp = find_next_cmp(self.buf, ldr, 0x100, 0).ok_or(IbootPatchError::AnchorNotFound(
            "the CMP after the rd=md0 LDR",
        ))?;
        let mov = find_boot_args_mov(self.buf, cmp).ok_or(IbootPatchError::AnchorNotFound(
            "the boot-args MOV instruction",
        ))?;
        let mov_insn = read_u16(self.buf, mov)?;
        let (mov_rd, mov_rs) = ((mov_insn & 0x7) as u8, ((mov_insn >> 3) & 0x7) as u8);
        let boot_args_string = find_bytes(self.buf, b"boot-args").ok_or(
            IbootPatchError::AnchorNotFound("the boot-args variable string"),
        )?;
        let default_string = find_bytes(self.buf, DEFAULT_BOOT_ARGS).ok_or(
            IbootPatchError::AnchorNotFound("the default boot-args string"),
        )?;
        let xref = self
            .iboot_memmem(default_string)
            .ok_or(IbootPatchError::AnchorNotFound("the rd=md0 string xref"))?;
        let getenv = self
            .find_getenv_addr()
            .ok_or(IbootPatchError::AnchorNotFound("the getenv function"))?;

        debug!(
            offset = xref,
            "pointing the rd=md0 xref at the boot-args variable string"
        );
        write_u32(
            self.buf,
            xref,
            (boot_args_string as u32).wrapping_add(self.base_address),
        )?;

        let null_str_reg = if ldr_rd == mov_rs { mov_rd } else { mov_rs };
        let null_ldr = ldr_search_up(self.buf, mov, 0x50)
            .filter(|candidate| {
                read_u16(self.buf, *candidate)
                    .is_ok_and(|insn| (insn >> 8) as u8 & 0x7 == null_str_reg)
            })
            .ok_or(IbootPatchError::AnchorNotFound("the null-string LDR"))?;

        let mut cursor = cmp.min(null_ldr);
        debug!(offset = cursor, "building the getenv call for boot-args");
        write_u16(self.buf, cursor, build_mov(0, ldr_rd))?;
        cursor += 2;
        let device_address = (cursor as u32).wrapping_add(self.base_address);
        write_u32(self.buf, cursor, build_bl_long(getenv, device_address))?;
        cursor += 4;
        write_u16(self.buf, cursor, build_mov(mov_rd, 0))?;
        cursor += 2;
        while cursor <= mov {
            write_u16(self.buf, cursor, NOP)?;
            cursor += 2;
        }
        Ok(())
    }

    /// Point a recovery console command handler at a different address.
    pub(super) fn patch_cmd_handler(
        &mut self,
        command: &str,
        pointer: u32,
    ) -> Result<(), IbootPatchError> {
        let mut needle = Vec::with_capacity(command.len() + 2);
        needle.push(0);
        needle.extend_from_slice(command.as_bytes());
        needle.push(0);
        let string = find_bytes(self.buf, &needle).ok_or(IbootPatchError::AnchorNotFound(
            "the recovery console command",
        ))? + 1;
        let reference = self
            .iboot_memmem(string)
            .ok_or(IbootPatchError::AnchorNotFound("the command table entry"))?;
        debug!(offset = reference, "redirecting a command handler");
        write_u32(self.buf, reference + 4, pointer)
    }

    /// iOS 10 boot mode: force the platform boot-mode function to return
    /// local (iBoot) or remote (iBEC).
    pub(super) fn patch_boot_mode(&mut self, mode: BootMode) -> Result<(), IbootPatchError> {
        let string = find_bytes(self.buf, b"debug-uarts")
            .ok_or(IbootPatchError::AnchorNotFound("the debug-uarts string"))?;
        let xref = self
            .iboot_memmem(string)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the debug-uarts string xref",
            ))?;
        let ldr =
            ldr_to(self.buf, xref).ok_or(IbootPatchError::AnchorNotFound("the debug-uarts LDR"))?;
        let first = bl_search_down(self.buf, ldr + 4, 0x10)
            .ok_or(IbootPatchError::AnchorNotFound("the first boot-mode BL"))?;
        let second = bl_search_down(self.buf, first + 4, 0x10)
            .ok_or(IbootPatchError::AnchorNotFound("the second boot-mode BL"))?;
        let function_call = bl_search_down(self.buf, second + 4, 0x10)
            .ok_or(IbootPatchError::AnchorNotFound("the boot-mode function BL"))?;
        let after = bl_search_down(self.buf, function_call + 4, 0x10).ok_or(
            IbootPatchError::AnchorNotFound("the BL after the boot-mode call"),
        )?;
        if after - 4 == function_call {
            return Err(IbootPatchError::AnchorNotFound(
                "a boot-mode function BL with room to patch",
            ));
        }
        let target = resolve_bl32(self.buf, function_call)
            .ok_or(IbootPatchError::AnchorNotFound("the boot-mode function"))?
            - 1; // Thumb bit
        let value = match mode {
            BootMode::Local => RETURN_0,
            BootMode::Remote => RETURN_1,
        };
        debug!(offset = target, "patching the boot mode");
        write_u32(self.buf, target, value)
    }

    /// NOP the conditional branch that randomizes the kernel load address.
    pub(super) fn disable_kaslr(&mut self) -> Result<(), IbootPatchError> {
        let text_ldr = self
            .find_next_ldr_with_str(b"__TEXT")
            .ok_or(IbootPatchError::AnchorNotFound("the __TEXT LDR"))?;
        let push = push_search_up(self.buf, text_ldr, 0x200).ok_or(
            IbootPatchError::AnchorNotFound("the PUSH above the __TEXT LDR"),
        )?;
        let branch = branch_thumb_conditional_search(self.buf, push, 0x50)
            .ok_or(IbootPatchError::AnchorNotFound("the KASLR branch"))?;
        debug!(offset = branch, "nopping the KASLR branch");
        write_u16(self.buf, branch, NOP)
    }

    /// Override the recovery background color; `bgcolor` is `RRGGBB`.
    pub(super) fn patch_bgcolor(&mut self, bgcolor: &str) -> Result<(), IbootPatchError> {
        let [red, green, blue] = parse_bgcolor(bgcolor)?;
        let logo_mov = find_bytes(self.buf, &MOV_R1_LOGO).ok_or(
            IbootPatchError::AnchorNotFound("the MOV R1, #'logo' instruction"),
        )?;
        let from = logo_mov.saturating_sub(0x80);
        let args = self
            .buf
            .get(from..logo_mov)
            .and_then(|window| find_bytes(window, &SETBGCOLOR_ARGS))
            .map(|relative| from + relative)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the setbgcolor() arguments",
            ))?;
        debug!(
            offset = args,
            red, green, blue, "overwriting the setbgcolor() arguments"
        );
        self.buf[args] = red;
        self.buf[args + 2] = green;
        self.buf[args + 4] = blue;
        Ok(())
    }

    /// Fix the AppleLogo reference for iOS 5+ iBoot ('logo' → 'logb').
    pub(super) fn patch_logo(&mut self) -> Result<(), IbootPatchError> {
        let logo = find_bytes(self.buf, &MOV_LOGO)
            .ok_or(IbootPatchError::AnchorNotFound("the AppleLogo MOVW"))?;
        debug!(offset = logo, "patching logo -> logb");
        write_u32(self.buf, logo, 0x7062_f246)
    }

    /// Fix the AppleLogo reference for iOS 4 iBoot ('logo' → 'log4').
    pub(super) fn patch_logo4(&mut self) -> Result<(), IbootPatchError> {
        let logo = find_bytes(self.buf, b"ogol")
            .ok_or(IbootPatchError::AnchorNotFound("the logo string"))?;
        debug!(offset = logo, "patching logo -> log4");
        self.buf[logo] = b'4';
        Ok(())
    }

    /// BL the ticket check away: zero the result registers and NOP the
    /// failure path, as in the C patch_ticket_check.
    pub(super) fn patch_ticket_check(&mut self) -> Result<(), IbootPatchError> {
        let vers_string = find_bytes(self.buf, b"iBoot-")
            .ok_or(IbootPatchError::AnchorNotFound("the iBoot version string"))?;
        let vers_address = (vers_string as u32).wrapping_add(self.base_address);
        let str_pointer = self
            .buf
            .get(vers_string..)
            .and_then(|tail| find_bytes(tail, &vers_address.to_le_bytes()))
            .map(|relative| vers_string + relative)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the version string pointer",
            ))?;
        let str_pointer_address = (str_pointer as u32).wrapping_add(self.base_address);

        // The ticket check consumes the third xref of the string pointer.
        let needle = str_pointer_address.to_le_bytes();
        let mut xref = 0;
        for _ in 0..3 {
            xref = self
                .buf
                .get(xref + 1..)
                .and_then(|tail| find_bytes(tail, &needle))
                .map(|relative| xref + 1 + relative)
                .ok_or(IbootPatchError::AnchorNotFound(
                    "the version string pointer xref",
                ))?;
        }

        let ldr = ldr_pcrel_search_up(self.buf, xref, 0x100)
            .ok_or(IbootPatchError::AnchorNotFound("the version string LDR"))?;
        let last_good_bl = bl_search_down(self.buf, ldr, 0x100)
            .ok_or(IbootPatchError::AnchorNotFound("the last good BL"))?;
        let next_pop = pop_search(self.buf, last_good_bl + 4, 0x100).ok_or(
            IbootPatchError::AnchorNotFound("the POP after the ticket check"),
        )?;

        let mut last_branch = branch_search_up(self.buf, next_pop, 0x20);
        let prev_mov_fail = search_up(self.buf, next_pop, 0x20, MOVW_R0_NEG1, MOVW_R0_NEG1, 2);
        if let Some(fail) = prev_mov_fail
            && last_branch.is_none_or(|branch| fail > branch)
        {
            last_branch = Some(fail - 2); // the preceding BL
        }
        let last_branch =
            last_branch.ok_or(IbootPatchError::AnchorNotFound("the ticket failure branch"))?;

        let mut cursor = last_good_bl + 4;
        debug!(offset = cursor, "patching in mov.w r0, #0 / mov.w r1, #0");
        write_u32(self.buf, cursor, MOVW_R0_0)?;
        cursor += 4;
        write_u32(self.buf, cursor, MOVW_R1_0)?;
        cursor += 4;
        let nop_stop = last_branch + 2;
        while cursor < nop_stop {
            write_u16(self.buf, cursor, NOP)?;
            cursor += 2;
        }
        if read_u32(self.buf, nop_stop).is_ok_and(|value| value == MOVW_R0_NEG1) {
            debug!(offset = nop_stop, "patching the trailing mov.w r0, #-1");
            write_u32(self.buf, nop_stop, MOVW_R0_0)?;
        }
        Ok(())
    }

    /// Jump from iBoot to an iOS 4.3.3-or-lower iBoot via the go command:
    /// write a small Thumb payload into the recovery payload slack and hook
    /// the main command handler.
    pub(super) fn patch_jump_iboot_433(&mut self) -> Result<(), IbootPatchError> {
        let main_string = find_bytes(self.buf, b"main").ok_or(IbootPatchError::AnchorNotFound(
            "the \"main\" command string",
        ))?;
        let main_entry = self
            .iboot_memmem(main_string)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the \"main\" command table entry",
            ))?;
        let main_handler_offset = main_entry + 4;
        let patch_site = find_bytes(self.buf, &JUMP_433_PATCH_SITE)
            .ok_or(IbootPatchError::AnchorNotFound("the iBoot 4 fix site"))?;
        let payload = find_bytes(self.buf, &JUMP_433_PAYLOAD_HEADER)
            .map(|offset| offset + JUMP_433_PAYLOAD_HEADER.len())
            .ok_or(IbootPatchError::AnchorNotFound("the payload site"))?;

        let original_handler = read_u32(self.buf, main_handler_offset)?;
        let original_fix = read_u32(self.buf, patch_site)?;
        let original_fix_next = read_u32(self.buf, patch_site + 4)?;

        debug!(offset = payload, "writing the iBoot jump payload");
        let mut cursor = payload;
        write_u16(self.buf, cursor, ldr_r_pc(4, 0x14))?;
        cursor += 2;
        write_u16(self.buf, cursor, ldr_r_pc(0, 0x18))?;
        cursor += 2;
        write_u16(self.buf, cursor, ldr_r_pc(1, 0x18))?;
        cursor += 2;
        write_u16(self.buf, cursor, STR_R1_R4_R0)?;
        cursor += 2;
        write_u16(self.buf, cursor, ldr_r_pc(0, 0x18))?;
        cursor += 2;
        write_u16(self.buf, cursor, ldr_r_pc(1, 0x1c))?;
        cursor += 2;
        write_u16(self.buf, cursor, STR_R1_R4_R0)?;
        cursor += 2;
        write_u32(self.buf, cursor, original_handler)?;
        cursor += 4;
        write_u32(
            self.buf,
            cursor,
            make_b_w(payload + 0x12, main_handler_offset + 4),
        )?;
        cursor += 4;
        write_u16(self.buf, cursor, NOP)?;
        cursor += 2;
        write_u32(self.buf, cursor, self.base_address)?;
        cursor += 4;
        write_u32(self.buf, cursor, patch_site as u32)?;
        cursor += 4;
        write_u32(self.buf, cursor, original_fix)?;
        cursor += 4;
        write_u32(self.buf, cursor, patch_site as u32 + 4)?;
        cursor += 4;
        write_u32(self.buf, cursor, original_fix_next)?;

        debug!(
            offset = main_handler_offset,
            "hooking the main command handler"
        );
        write_u32(
            self.buf,
            main_handler_offset,
            make_b_w(main_handler_offset, payload),
        )?;

        debug!(offset = patch_site, "fixing the jump to iBoot");
        write_u32(self.buf, patch_site, 0xbf98_2801)?;
        write_u32(self.buf, patch_site + 4, 0xbd80_2002)?;
        Ok(())
    }

    /// BL boot-partition → `MOVS R0, #0; MOVS R0, #0`. The iOS 9+ variant for
    /// De Rebus Antiquis also mangles the "boot-partition" string.
    pub(super) fn patch_boot_partition(
        &mut self,
        partition: BootPartition,
    ) -> Result<(), IbootPatchError> {
        let ldr = self.find_next_ldr_with_str(b"boot-partition").ok_or(
            IbootPatchError::AnchorNotFound("the boot-partition string LDR"),
        )?;
        let call = bl_search_down(self.buf, ldr, 0x100).ok_or(IbootPatchError::AnchorNotFound(
            "the boot-partition BL (image may already be patched)",
        ))?;
        debug!(offset = call, "patching the boot-partition BL");
        write_u32(self.buf, call, MOVS_R0_0_TWICE)?;

        if partition == BootPartition::Ios9OrLater {
            let string = find_bytes(self.buf, b"boot-partition")
                .ok_or(IbootPatchError::AnchorNotFound("the boot-partition string"))?;
            debug!(
                offset = string,
                "mangling the boot-partition string for De Rebus Antiquis"
            );
            write_u16(self.buf, string, 0x0032)?;
        }
        Ok(())
    }

    /// BL boot-ramdisk → `MOVS R0, #0; MOVS R0, #0`.
    pub(super) fn patch_boot_ramdisk(&mut self) -> Result<(), IbootPatchError> {
        let ldr =
            self.find_next_ldr_with_str(b"boot-ramdisk")
                .ok_or(IbootPatchError::AnchorNotFound(
                    "the boot-ramdisk string LDR",
                ))?;
        let call = bl_search_down(self.buf, ldr, 0x100).ok_or(IbootPatchError::AnchorNotFound(
            "the boot-ramdisk BL (image may already be patched)",
        ))?;
        debug!(offset = call, "patching the boot-ramdisk BL");
        write_u32(self.buf, call, MOVS_R0_0_TWICE)
    }

    /// Allow the setenv command to touch every variable: BL the environment
    /// variable check → `MOVS R0, #0; MOVS R0, #0`.
    pub(super) fn patch_setenv_cmd(&mut self) -> Result<(), IbootPatchError> {
        const SETENV_NEEDLE: &[u8] = b"\0setenv\0";
        let string = find_bytes(self.buf, SETENV_NEEDLE)
            .ok_or(IbootPatchError::AnchorNotFound("the setenv command string"))?
            + 1;
        let entry = self
            .iboot_memmem(string)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the setenv command table entry",
            ))?;
        let handler = read_u32(self.buf, entry + 4)?.wrapping_sub(self.base_address) as usize;
        let first = bl_search_down(self.buf, handler, 0x50)
            .ok_or(IbootPatchError::AnchorNotFound("the first setenv BL"))?;
        let check = bl_search_down(self.buf, first + 4, 0x50).ok_or(
            IbootPatchError::AnchorNotFound("the setenv environment check BL"),
        )?;
        debug!(offset = check, "patching the setenv environment check");
        write_u32(self.buf, check, MOVS_R0_0_TWICE)
    }

    /// De Rebus Antiquis dualboot: dispatch on the image type tag at 0x200.
    pub(super) fn patch_dualboot(&mut self) -> Result<(), IbootPatchError> {
        match read_u32(self.buf, 0x200)? {
            IBSS_TYPE => self.patch_dualboot_ibss(),
            IBEC_TYPE => self.patch_dualboot_ibec(),
            _ => Err(IbootPatchError::NotIbssOrIbec),
        }
    }

    /// iBSS: retarget the kloader address (per platform) and NOP
    /// usb_wait_for_image so the loader drops to the command loop.
    fn patch_dualboot_ibss(&mut self) -> Result<(), IbootPatchError> {
        if self.os_version() < 5 && self.has_kernel_load() {
            return Err(IbootPatchError::PreIos5Ibss);
        }

        let kloader = self
            .find_kloader_addr()
            .ok_or(IbootPatchError::AnchorNotFound("the kloader MOV"))?;
        let platform_string = find_bytes(self.buf, PLATFORM_INIT_STRING)
            .ok_or(IbootPatchError::AnchorNotFound("the platform string"))?;
        let platform = read_u32(self.buf, platform_string + PLATFORM_INIT_STRING.len())?;
        let value = match &platform.to_le_bytes() {
            b"8920" | b"8922" => 0x71d0_f6c6,
            b"8930" | b"8950" | b"8955" => 0x74d0_f6c7,
            b"8940" | b"8942" | b"8945" | b"8947" => 0x74d0_f6cb,
            _ => return Err(IbootPatchError::UnsupportedDualbootPlatform(platform)),
        };
        debug!(offset = kloader, "patching the kloader address");
        write_u32(self.buf, kloader, value)?;

        let usb = self
            .find_usb_wait_for_image()
            .ok_or(IbootPatchError::AnchorNotFound("usb_wait_for_image"))?;
        debug!(offset = usb, "nopping usb_wait_for_image");
        write_u32(self.buf, usb, NOP_TWICE)?;

        let blt = branch_thumb_conditional_search(self.buf, usb, 10).ok_or(
            IbootPatchError::AnchorNotFound("the usb_wait_for_image BLT"),
        )?;
        write_u16(self.buf, blt, NOP)
    }

    /// iBEC: boot the upgrade command instead of fsboot and force
    /// auto-boot true.
    fn patch_dualboot_ibec(&mut self) -> Result<(), IbootPatchError> {
        let fsboot = find_bytes(self.buf, b"fsboot")
            .ok_or(IbootPatchError::AnchorNotFound("the fsboot string"))?;
        let fsboot_xref = self
            .iboot_memmem(fsboot)
            .ok_or(IbootPatchError::AnchorNotFound(
                "the fsboot command table entry",
            ))?;
        let upgrade = find_bytes(self.buf, b"upgrade")
            .ok_or(IbootPatchError::AnchorNotFound("the upgrade string"))?;
        debug!(offset = fsboot_xref, "pointing fsboot at upgrade");
        write_u32(
            self.buf,
            fsboot_xref,
            (upgrade as u32).wrapping_add(self.base_address),
        )?;

        let false_string = find_bytes(self.buf, b"false").ok_or(
            IbootPatchError::AnchorNotFound("the auto-boot false string"),
        )?;
        let false_xref = self
            .iboot_memmem(false_string)
            .ok_or(IbootPatchError::AnchorNotFound("the auto-boot=false xref"))?;
        let true_string = find_bytes(self.buf, b"true")
            .ok_or(IbootPatchError::AnchorNotFound("the true string"))?;
        debug!(offset = false_xref, "pointing auto-boot at true");
        write_u32(
            self.buf,
            false_xref,
            (true_string as u32).wrapping_add(self.base_address),
        )
    }

    /// Search for the 4-byte little-endian device-address reference to the
    /// given file offset.
    fn iboot_memmem(&self, offset: usize) -> Option<usize> {
        let address = (offset as u32)
            .wrapping_add(self.base_address)
            .to_le_bytes();
        find_bytes(self.buf, &address)
    }

    /// find_next_LDR_insn_with_value: locate the literal pool entry holding
    /// `value` and resolve it back to the LDR instruction.
    fn find_next_ldr(&self, value: u32) -> Option<usize> {
        let xref = find_bytes(self.buf, &value.to_le_bytes())?;
        ldr_to(self.buf, xref)
    }

    /// find_next_LDR_insn_with_str: locate a string, then the LDR that loads
    /// its device address.
    fn find_next_ldr_with_str(&self, needle: &[u8]) -> Option<usize> {
        let string = find_bytes(self.buf, needle)?;
        self.find_next_ldr((string as u32).wrapping_add(self.base_address))
    }

    fn find_dtre_get_value_bl(&self, variable: &[u8]) -> Option<usize> {
        let string = find_bytes(self.buf, variable)?;
        let xref = self.iboot_memmem(string)?;
        let ldr = ldr_to(self.buf, xref)?;
        let first = bl_search_down(self.buf, ldr, 0x100)?;
        bl_search_down(self.buf, first + 1, 0x100)
    }

    /// find_GETENV_Addr: resolve the BL after the "network-type" getenv LDR.
    fn find_getenv_addr(&self) -> Option<u32> {
        let ldr = self.find_next_ldr_with_str(b"network-type")?;
        let call = bl_search_down(self.buf, ldr, 0x10)?;
        resolve_bl_long(
            self.buf,
            call,
            (call as u32).wrapping_add(self.base_address),
        )
    }

    /// find_kloader_addr: the MOVT building the kloader address, anchored on
    /// the "iBSS ready" print. The C finder tries progressively further
    /// adjustments, including a MOVT above the LDR.
    fn find_kloader_addr(&self) -> Option<usize> {
        let ldr = self.find_next_ldr_with_str(IBSS_READY_STRING)?;
        find_next_movt(self.buf, ldr + 10, 14)
            .or_else(|| find_next_movt(self.buf, ldr + 12, 14))
            .or_else(|| find_next_movt(self.buf, ldr + 0x22, 2))
            .or_else(|| find_next_movt(self.buf, ldr.saturating_sub(0x30), 0x10))
    }

    /// find_usb_wait_for_image: chase the DFU-mode print to the function
    /// prologue two call levels out.
    fn find_usb_wait_for_image(&self) -> Option<usize> {
        let ldr = self.find_next_ldr_with_str(DFU_MODE_STRING)?;
        let push = push_r4_r7_lr_search_up(self.buf, ldr, 0x20)?;
        let push_xref = find_next_bl_to(self.buf, (push + 1) as u32)?;
        let next_push = push_r4_to_r7_lr_search_up(self.buf, push_xref, 0x10)
            .or_else(|| push_r4_r7_lr_search_up(self.buf, push_xref, 0x10))?;
        find_next_bl_to(self.buf, (next_push + 1) as u32)
    }
}

fn parse_bgcolor(bgcolor: &str) -> Result<[u8; 3], IbootPatchError> {
    let bytes = bgcolor.as_bytes();
    if bytes.len() != 6 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(IbootPatchError::InvalidBgcolor);
    }
    let parse = |pair: &[u8]| u8::from_str_radix(str::from_utf8(pair).expect("hex"), 16);
    Ok([
        parse(&bytes[0..2]).expect("hex"),
        parse(&bytes[2..4]).expect("hex"),
        parse(&bytes[4..6]).expect("hex"),
    ])
}
