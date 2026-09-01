# Compatibility Matrix

Status of the pure-Rust `lik` implementation against the Legacy-iOS-Kit
feature baseline (upstream commit `1ff4be07ea2946ccaeff2db60c4426488b8f6e32`).

Legend: ✅ implemented · 🟡 partial / bounded · ❌ not implemented ·
⚠️ implemented but not yet verified on hardware.

**Everything below is ⚠️ until the hardware acceptance matrix has been run.**

## Exploits / pwned DFU entry

| Family | SoC | Method | Status |
|---|---|---|---|
| S5L8900 | iPhone1,1/1,2, iPod1,1 | Pwnage 2.0 WTF (`lik device pwn-wtf`) | ✅ |
| S5L8720/8920/8922, A4 | iPod2,1–iPod4,1, iPhone2,1–3,3, iPad1,1 | limera1n (`--exploit auto`) | ✅ |
| A5/A5X | iPhone4,1, iPad2,*, iPad3,1–3, iPod5,1 | external checkm8-a5 hardware (guided, verified) | ✅ |
| A5X, A6/A6X | iPad2,4/iPad3,*, iPhone5,*, iPad3,4+ | checkm8 armv7 | ✅ |
| A7–A11 | iPhone5s–X, iPads | checkm8 arm64 | ✅ |
| alloc8 (new-bootrom 3GS) | iPhone2,1 | alloc8 NOR installer (`lik device install-alloc8`) | ✅ |

## Boot / ramdisk

| Feature | Status | Notes |
|---|---|---|
| SSH ramdisk boot 32/64-bit (`lik ramdisk boot`) | ✅ | iBSS/iBEC/ticket/ramdisk/devicetree/trustcache/kernel, custom boot-args |
| Tethered just boot | ✅ | omit `--ramdisk` |
| kDFU via kloader (`lik device enter-kdfu`) | ✅ | iBSS patch + kloader resource |
| ramdisk SSH/SCP/push/pull | ✅ | |
| onboard SHSH / activation / baseband dump | ✅ | version-aware paths |
| NVRAM clear / erase iOS 7-8 / erase iOS 9+ / fix datetime | ✅ | |
| iBoot32Patcher | ✅ | full Merculous patch set: RSA, debug, boot-args/env boot-args, cmd handler, ticket, local/remote boot, boot-partition(9), boot-ramdisk, setenv, disable-kaslr, bgcolor, logo/logo4, --433, dualboot |

## Restore

| Feature | Status | Notes |
|---|---|---|
| Signed restore (TSS) 32/64-bit | ✅ | full restored/ASR/FDR/baseband chain |
| Blob restore (provided/onboard ticket) | ✅ | |
| skip-blob pwned restore | ✅ | `--skip-blob` requires pwned boot chain |
| SEP from file / no SEP | ✅ | `--sep` / `--no-sep` |
| set-nonce from ticket generator | ✅ | `--set-nonce` |
| iOS 3.x/4.x multipart two-stage restore | ✅ ⚠️ | part1 NOR IPSW (5.1.1 components, target iBoot/DeviceTree/AppleLogo, bundled ASR patch, APTicket scab); part2 built by `lik firmware powder-prepare`; `--skip-first` resume; optional `--part2-ticket` for upstream `-w` parity; hardware-unverified |
| powdersn0w custom IPSW + restore | ✅ ⚠️ | builder (single/two-bundle/ios4powder) via `lik firmware powder-prepare`; single-stage powder restore via `lik restore powder` (A4 fetches the latest-version ticket from TSS, A5/A5X/A6/A6X take a base-version blob; kDFU/pwnDFU entry, external checkm8-a5/litera1n guidance); hardware-unverified |
| classic xpwn custom IPSW (old devices) | ✅ ⚠️ | builder via `lik firmware classic-prepare` (S5L8900 and S5L8720/8920/8922/A4 classic targets: jailbreak payload matrix, hacktivation lockdownd patch, 24kpwn/alloc8-era old mode, greenpois0n/aquila tars, baseband/activation tar merge, patchcomp/iOS 4.1 post-build steps); restore via `lik restore classic` (self-built; iPod2,1/iPhone2,1 require `--ticket`, upstream `-w`) and `lik restore custom-ipsw` (foreign, ticket-free, incl. iOS 2.x targets: S5L8900 enters stock WTF mode via buttons and gets the IPSW's own unpatched WTF, old-bootrom iPod2,1 enters 24kpwn DFU; pre-iOS 3 restored sessions skip HardwareInfo and answer FlashVersion1 NOR requests with the component-keyed dictionary; live baseband TSS for foreign IPSWs with a signable BasebandFirmware, else upstream's retry advice): pwnage-WTF/limera1n chain entry, per-component personalization, restored/ASR session; classic baseband replace (`ipsw_bbreplace`) is not applicable — upstream early-returns for `device_proc < 5` (restore.sh:4350); hardware-unverified (2.x WTF button entry, 2.x ramdisk handshake, live baseband TSS, old-ramdisk restored QueryValue replies, skipped RestoreLogo/setpicture and pre-bootx control transfer, iPod2,1 new bootrom cannot be pwned) |
| RSEP / Cryptex policies | ❌ | |
| iPhone X restored_external | ❌ | |
| FourThree dualboot (iPad2) | 🟡 | step 1 custom IPSW + dualboot components ✅ (`lik firmware fourthree-prepare`, unit-tested only — no end-to-end fixture test with real IPSWs yet); steps 2/3/app/boot ✅ |

## Jailbreak / activation

| Feature | Status | Notes |
|---|---|---|
| SSH ramdisk jailbreak 3.1.3–9.3.4 | ✅ | aquila/everuntether/daibutsu/greenpois0n matrix |
| g1lbertJB (A5 iOS 5.x) | ✅ ⚠️ | untethered userland chain over lockdown/AFC/file_relay/mobilebackup2 for iPhone4,1, iPad2,1–2,4, iPad3,1–3,3 on iOS 5.0–5.1.1 (`lik device jailbreak-gilbert`); interactive DemoApp remount step is surfaced as an `ActionRequired` event with AFC polling; unit-tested only — not yet run against a live device |
| bootstrap 64-bit iOS 7/8/9 | ✅ | Cydia + OpenSSH |
| iOS 7 untethers | ✅ | panguaxe / evasi0n7 |
| TrollStore (iOS 14/15) | ✅ | Tips persistence helper |
| TrollStore via TrollRestore (iOS 15.2–16.6.1, 16.7 RC, 17.0; A9+) | ✅ ⚠️ | sparserestore exploit (CVE-2024-44252) over mobilebackup2, `lik device trollrestore`; unit-tested only — not yet run against a live device |
| hacktivate / revert | ✅ | data_ark fast path + lockdownd patches |
| Hacktivation via IPSW (iPhone 2G/3G/3GS) | ✅ ⚠️ | `--hacktivate` of `lik firmware classic-prepare` (lockdownd patch merged into the root filesystem, gated to jailbroken iPhone/iPad1,1 on iOS 3.1-6.x); hardware-unverified |

## Services / data

| Feature | Status | Notes |
|---|---|---|
| pairing / lockdown / AFC / app install+list+files | ✅ | |
| backup / restore / encryption | ✅ | |
| activation state / deactivate / erase | ✅ | |
| Apple ID sign + install (`lik app sign`) | ✅ ⚠️ | untested against live Apple services |
| OS mount over FUSE | 🟡 | Linux/BSD ✅; macOS stub (needs macFUSE build link); Windows ❌ (WinFsp) |
| syslog / battery / restart / shutdown / uicache | ✅ | |

## Platform / host

| Item | Status |
|---|---|
| Device discovery, Normal/Recovery/DFU/WTF/KIS | ✅ all three OSes |
| Normal backend: system usbmux / direct rusbmux | ✅ |
| Host requirement diagnostics (udev, drivers, contention) | ✅ |
| Mount driver as declared host precondition | ✅ Linux/BSD, 🟡 macOS, ❌ Windows |
