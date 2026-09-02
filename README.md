# Legacy iOS Kit (Rust)

A pure-Rust, embeddable reimplementation of
[Legacy iOS Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) (behavioral
baseline: upstream commit `1ff4be07ea2946ccaeff2db60c4426488b8f6e32`) — a
toolkit for restoring, downgrading, jailbreaking, and managing legacy iOS
devices (iPhoneOS 1.x through iOS 16, S5L8900 through A11).

- `legacy-ios-kit` — the public async library (Tokio-native).
- `lik` — the reference command-line interface.

## What makes this different from the upstream Bash project

- **No host tooling.** No shells, no bundled executables, no C FFI, no
  subprocess fallbacks. Every protocol (usbmux, lockdownd, AFC, restored,
  ASR, FDR, TSS, SSH), every image format (IPSW, IMG1–IMG4, IM4P/IM4M,
  HFS+, DMG), and every patch pipeline (iBoot32Patcher, powdersn0w
  patchfinders, KPlooshFinder-class kernel patching) is implemented in Rust.
- **Embeddable library first.** Operations follow a strict
  `Request → Plan → explicit destructive consent → Execute → event stream`
  model. Nothing erases or flashes a device without a resolved plan and a
  consent token bound to that plan's identity.
- **Cross-platform by design.** macOS 12+, Windows 10 22H2+, Linux
  (kernel 5.10+ / glibc 2.31+). Platform-specific code is confined to the
  USB transport adapters; host problems (udev rules, USB drivers, backend
  contention) are reported as actionable diagnostics, never worked around
  by restarting system services or escalating privileges.

## Status

**Development preview (`0.1.0`).** The feature surface of the upstream
baseline is implemented, but most device-facing paths are **not yet
verified on real hardware** — every such entry is marked ⚠️ in the
[compatibility matrix](docs/COMPATIBILITY.md). Do not use this on devices
holding data you care about.

There is intentionally **no license file** yet; a licensing decision is
pending.

## Building

Rust 1.88.0 or newer (see `rust-toolchain.toml`):

```sh
cargo build --release -p legacy-ios-kit-cli
```

The binary is `target/release/lik`. Nothing else is needed at build time —
no macFUSE, no libimobiledevice, no compiled tools.

Host preconditions at runtime:

- **Linux**: udev permissions for the Apple USB device nodes (run
  `lik device host-requirements` to diagnose).
- **macOS**: nothing; the system usbmuxd is used as-is.
- **Windows**: the Apple Mobile Device USB driver (from iTunes) for the
  system backend, or a diagnosable WinUSB binding for the direct backend.

## Configuration

Resolution order: CLI flags > `LIK_*` environment variables > user
`config.toml` (platform config directory) > built-in defaults.

```sh
lik config path   # where the user config lives
lik config show   # effective configuration
```

The config holds only cache/data paths, the normal-mode USB backend
(`auto | system | direct`), firmware/TSS endpoints, and download
concurrency. Secrets (passwords, Apple ID credentials, pairing records)
never go into the config file.

## CLI overview

Global flags: `--output json` for stable machine-readable results (stdout
carries only the command result; logs always go to stderr), `-v` / `-vv`
for DEBUG/TRACE tracing, `--quiet` for WARN only, `--config <path>` to
override the config file.

Destructive operations ask for interactive confirmation; pass `--yes` for
automation. Device interactions that need a human (DFU button sequences,
Trust prompts, replugging) surface as step-by-step prompts.

### Devices

```sh
lik device list                 # all attached devices, every USB mode
lik device host-requirements    # diagnose udev / drivers / contention
lik device pair <udid>
lik device battery|activation|syslog|restart|shutdown <udid>
lik device enter-recovery|exit-recovery ...
lik device erase <udid>         # erase all content (mobilebackup2)
lik device set-nonce ...        # write a boot-nonce generator in Recovery
lik device pwn-wtf              # Pwnage 2.0 WTF (S5L8900)
lik device install-alloc8 ...   # alloc8 NOR installer (new-bootrom 3GS)
lik device enter-kdfu ...       # kDFU via kloader on a jailbroken device
lik device hacktivate|revert-hacktivate ...
lik device trollrestore ...     # TrollStore via sparserestore (iOS 15.2–17.0)
lik device jailbreak-gilbert    # g1lbertJB, A5 iOS 5.0–5.1.1
lik device fourthree-check|step2|step3|app|boot   # FourThree dualboot
```

### Firmware inspection, images, and custom IPSWs

```sh
lik firmware inspect <ipsw>            # BuildManifest summary
lik firmware inspect-remote <url>      # same, via HTTP range requests
lik firmware hfs <subcommand>          # inspect/mutate HFS+ images
lik firmware image extract|replace     # IMG3/IM4P payloads
lik firmware image patch-iboot32 ...   # the full iBoot32Patcher patch set
lik firmware decrypt-dmg ...           # FileVault root filesystems
lik firmware build|build-rootfs ...    # generic custom IPSW assembly
lik firmware powder-prepare ...        # powdersn0w custom IPSW
lik firmware classic-prepare ...       # xpwn-class IPSW (S5L8900–A4)
lik firmware multipart-prepare ...     # two-stage iOS 3.x/4.x restore pair
lik firmware fourthree-prepare ...     # FourThree 6.1.3 IPSW + 4.3.x parts
lik firmware ipx-prepare ...           # iPhone X 14.3–15.x rdsk/rkrn pair
lik firmware fetch-resource <id>       # verified catalog resource download
```

### Restoring and downgrading

Every restore starts with a plan; execution requires destructive consent:

```sh
lik restore plan   --device <type> --board <cfg> --ecid <hex> --firmware <ipsw>
lik restore execute ... [--ticket <blob> | --onboard-ticket | --skip-blob] \
    [--baseband <path> | --no-baseband] [--sep <path> | --no-sep] \
    [--rsep | --no-rsep] [--cryptex-ipsw <path> | --no-cryptex] \
    [--set-nonce] [--exploit auto|none|already-pwned]
lik restore powder ...        # powdersn0w restore (ticket rules per SoC)
lik restore classic ...       # self-built classic IPSW (3.1.3/4.x)
lik restore custom-ipsw ...   # foreign IPSW, ticket-free (incl. iOS 2.x)
lik restore multipart ...     # two-stage iOS 3.x/4.x restore
```

iPhone X (iPhone10,3/10,6) downgrades to iOS 14.3–15.x:

```sh
lik firmware ipx-prepare --ipsw <stock-14.3-15.x.ipsw> --output-dir out
lik restore execute ... --rdsk out/rdsk.im4p --rkrn out/kcache.im4p
```

### SSH ramdisk

```sh
lik ramdisk build ...           # patched RestoreRamDisk from an IPSW
lik ramdisk boot ...            # boot it (omit --ramdisk for tethered boot)
lik ramdisk ssh|push|pull ...   # non-interactive SSH/SCP
lik ramdisk jailbreak ...       # 32-bit jailbreak (3.1.3–9.3.4 matrix)
lik ramdisk bootstrap|untether7 ...
lik ramdisk trollstore ...      # TrollStore via ramdisk (iOS 14/15)
lik ramdisk dump-onboard|dump-activation|dump-baseband ...
lik ramdisk nvram-clear|fix-datetime|erase78|erase9 ...
```

### SHSH

```sh
lik shsh save --firmware <ipsw> --board <cfg> --ecid <hex> --cpid <n> \
    --bdid <n> --destination <dir>
```

### Apps and data

```sh
lik app list <udid> [--filter user|system|all]
lik app install|uninstall|files|pull|push|icon|refresh-icons ...
lik app sign <ipa> ...          # AltServer-equivalent Apple ID signing
lik data backup|restore|encryption ...
lik data list|info|storage|pull|push|mkdir|remove|move ...   # AFC file API
```

## Feature matrix

Condensed from [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md), which is the
authoritative per-feature record including hardware-verification caveats.
⚠️ = implemented, not yet verified on hardware.

### Exploits and pwned entry

| Family | Coverage | Status |
|---|---|---|
| S5L8900 | Pwnage 2.0 WTF | ✅ |
| S5L8720/8920/8922, A4 | limera1n | ✅ |
| A5/A5X | external checkm8-a5 guidance + verification | ✅ |
| A5X, A6/A6X | checkm8 armv7 | ✅ |
| A7–A11 | checkm8 arm64 | ✅ |
| iPhone2,1 new bootrom | alloc8 NOR installer | ✅ |

### Restore and custom IPSW

| Feature | Status |
|---|---|
| Signed (TSS) restores, 32/64-bit | ✅ |
| Blob restores (provided/onboard ticket), set-nonce, skip-blob | ✅ |
| SEP/baseband/RSEP policies, Cryptex1 strategy (iOS 16+) | ✅ ⚠️ |
| powdersn0w (single / two-bundle / ios4powder) | ✅ ⚠️ |
| classic xpwn IPSW build + restore (S5L8900–A4) | ✅ ⚠️ |
| Foreign custom IPSW restore incl. iOS 2.x | ✅ ⚠️ |
| iOS 3.x/4.x two-stage multipart restore | ✅ ⚠️ |
| iPhone X restored_external flow (14.3–15.x) | ✅ ⚠️ |
| FourThree dualboot (iPad 2) | 🟡 ⚠️ |

### Jailbreak, activation, services

| Feature | Status |
|---|---|
| SSH ramdisk jailbreak 3.1.3–9.3.4, bootstraps, iOS 7 untethers | ✅ |
| g1lbertJB (A5 iOS 5.x), TrollStore, TrollRestore | ✅ ⚠️ |
| Hacktivation (data_ark / lockdownd / IPSW-based) | ✅ ⚠️ |
| Pairing, lockdownd, AFC file API, app install/list/files | ✅ |
| Backup/restore/encryption, erase, syslog, battery, power controls | ✅ |
| Apple ID IPA signing (AltServer equivalent) | ✅ ⚠️ |

### Not implemented yet (upstream parity gaps)

- DFU IPSW creation (force true DFU on devices with broken buttons)
- 32-bit iOS 10 tethered restores (kuroutadori / turdus_merula path)
- Gasgauge / multipatch builds (third-party battery error 29 fix)
- iOS 7 on iPod4,1/iPad1,1 (specialios7) and iOS 6 on iPod3,1/iPad1,1
  (SundanceInH2A) custom builds
- Attempt Activation (requesting activation from Apple over
  mobileactivationd; state query and deactivate exist)
- 32-bit onboard SHSH dump (pwned iBEC "go blobs") and IMG3-era raw dump
  conversion
- Baseband dump stitching into powdersn0w IPSWs (`ipsw_bbreplace`; the
  classic builder has it)
- 32-bit tethered-downgrade IPSW builds ("Other (Tethered)")
- Disable/Enable Exploit for iOS 3.x (fdisk + exploit ramdisk)
- Dump installed apps as IPA; standalone ramdisk OpenSSH install;
  appinst-style installs; IPSW downloader; Cydia blob queries;
  just-boot build-id resolution and boot history

### Out of scope by design

Upstream's interactive menus and Zenity UI, self-updating, package-manager
dependency installation, and host-OS mounting of device filesystems
(`lik data mount` was removed; device files are reachable through the AFC
API instead).

## Development

Repository conventions, architecture rules, and quality gates live in
[AGENTS.md](AGENTS.md). In short: `cargo fmt --all`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-features`, and an MSRV check with Rust 1.88.0
must pass; network- and hardware-dependent tests stay opt-in.
