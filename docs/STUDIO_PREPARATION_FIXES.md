# Pocket Studio preparation integration

Pocket Studio consumes this checkout through local Cargo path dependencies. The
preparation fixes below are library behavior; Studio retains resource manifests,
cache policy, authorization, device targeting, and localized operation events.

## DFU reset and ramdisk boot

`IbootClient::reset` releases its claimed interface before resetting the retained
USB device. `upload_image` uses the same consuming reset after DFU manifestation,
including the legacy iOS 1 path. Reset errors propagate instead of being hidden.
The ramdisk workflow waits one second after DFU reset before reconnecting by ECID.

This addresses a macOS failure where nusb refuses reset while interfaces remain
claimed. Before this fix, a connected iPod touch 4 was observed with a limera1n
PWND marker and DFU state 8, waiting for reset after the failed ramdisk boot step.
A preceding isolated reset experiment restored GETSTATE communication, but does
not establish successful ramdisk boot or jailbreak installation.

The workflow now emits redacted command stages alongside component progress.
`RecoveryError` and `RamdiskBootError` expose diagnostic categories so embedding
applications can retain the failed stage without logging identifiers or payloads.

## A4 entry

`A4Limera1n` accepts patched shellcode without heap headers. It implements the
compact layout and reset sequence used by the local Legacy iOS Kit macOS path:

1. Reset, then reconnect to the original ECID and hardware identity.
2. Send sixteen 64-byte heap headers plus the shellcode, then read one byte.
3. Perform the short transfer and trigger, then reset and reconnect.
4. Finalize the transfer, issue three status requests, reset and verify PWND.

Required payload and preparation transfers must succeed. Deliberate timeout/stall
outcomes in the trigger/finalization transfers are accepted only with final PWND
evidence. An already-pwned, matching A4 device is reused. The facade selects this
path for A4; the existing `Limera1n` API remains for the classic layout.

`patch_a4_shellcode` validates the placeholder table before applying
`constants_574_4`. The caller still authenticates downloaded assets. No payload
binary or host executable is added here. Source references:

- Local Legacy iOS Kit `restore.sh`, baseline `1ff4be07ea2946ccaeff2db60c4426488b8f6e32`.
- ipwndfu `limera1n.py`, revision `0e28932ec6a2a570b10fd77e50bda4216418cd98`.
- ipwnder_lite `src/exploit/limera1n.c`, revision `cf6d1e6e60727e79c281cd559ebcafd43149e4c1`.

## Synchronized resource and installation fixes

- HFS tar import accepts a zero-size `./` directory header without replacing root
  metadata. Directory symlinks resolve inside the image, so `/etc` remains a link
  while archive children are installed under `/private/etc`. Cycles and resolution
  above the image root are rejected; no host path resolution is involved.
- Remote ZIP discovery reads the HTTP HEAD `Content-Length` header, rather than
  the empty HEAD body's size hint. The regression test uses a local HTTP server.
- Jailbreak tar extraction uses `&&` before cleanup so an extraction failure
  remains visible. Optional patcyh removal uses `rm -f` after a successful `cd`.

## Verification boundary

Unit tests cover the compact transfer transcript, required transfer failures,
missing PWND evidence, shellcode placeholders, HFS root/link handling, and HTTP
HEAD length discovery. These tests need neither hardware nor Apple services.
Full workspace format, lint, tests, and Rust 1.88 checks are required before commit.
Hardware validation of the complete boot, install, and reboot flow remains
separate from these checks; existing DFU state 8 from a failed attempt is not
silently treated as a fresh DFU session.

## IMG3 boot-image parity regression

A later hardware attempt successfully uploaded iBSS and reset USB, but the device
did not re-enumerate. An offline comparison against the local Legacy iOS Kit
`xpwntool` and `iBoot32Patcher` identified two image bugs:

- `decrypt_img3_payload` kept KBAG elements next to decrypted DATA. The reference
  removes both keybags, so the device must not decrypt the plaintext again. The
  library now removes all KBAGs, preserves the other element bodies and padding,
  and updates sizes and the SHSH offset.
- The iBoot32 debug patch used the wrong byte order for Thumb `MOVS R0, #1`.
  It now writes the same two instructions as the reference patcher.

For the iPod4,1 / 10B500 inputs, decrypted containers, raw payloads, patched
payloads, and final containers for both iBSS and iBEC now match the reference
byte-for-byte. Reference binaries were used only for offline development checks;
no executable or subprocess fallback was added to the library. Regression tests
use synthetic containers and instructions rather than distributing Apple images.

The same hardware investigation verified that ABORT moves this A4 device from
DFU WAIT_RESET (8) to idle (2). Before a new explicit upload, the library now
aborts that old transfer and checks GETSTATE again. It proceeds only on confirmed
idle and preserves abort failures; it never boots the old buffered image. The
legacy iOS 2 upload path's existing WAIT_RESET behavior is unchanged. Transcript
tests cover successful recovery, a rejected ABORT, a device that stays non-idle,
and legacy/error-state handling. Full hardware boot and SSH validation remain
separate from image parity and these automated checks.

## A4 ramdisk-delay query

The next fresh-DFU attempt verified A4 PWND, iBSS, and iBEC and reached Recovery.
A4 iBEC rejected `getenv ramdisk-delay` with STALL, while `ramdisk` activation
succeeded on the same connection. Both boot workflows now issue this query only
for S5L8900, the chip for which the local upstream script marks it required.
Transcript tests retain that ordering on S5L8900 and omit the query on A4/64-bit
chains. Required command transfer failures still propagate.

A Recovery continuation then sent the ramdisk, device tree, and kernel and
completed boot commands. USB SSH did not appear within 100 seconds, so no device
filesystem was mounted or modified. Kernel/device-tree containers were also
verified byte-identical to local xpwntool output. Ramdisk filesystem structure
and device-screen boot output remain the next diagnostic boundary.
