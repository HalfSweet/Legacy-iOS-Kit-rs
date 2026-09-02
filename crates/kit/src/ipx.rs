//! iPhone X (iPhone10,3/10,6) restore component preparation for iOS 14.3-15.x
//! downgrades, porting restore.sh's `ipsw_prepare_ipx` (restore.sh:6908-6963,
//! triggered at restore.sh:6840-6843 for iPhone10,3/10,6 targets with major
//! version <= 15).
//!
//! The kernelcache is extracted, decompressed (LZFSE/LZSS dispatch of the
//! img4 tool's vfs layer), patched with the KPlooshFinder AMFI patch set
//! ([`patch_kernel64`]), LZSS-recompressed, and repacked as an `rkrn` IM4P
//! (`img4 -T rkrn -J`; upstream's kerneldiff/bpatch round-trip is skipped —
//! the patched bytes are consumed directly, see the `kernel64` module docs).
//! The restore ramdisk's `usr/local/bin/restored_external` is patched with
//! the FaceID fix ([`patch_restored_external`]), ad-hoc re-signed with its
//! original entitlements (the `ldid -e` / `ldid -Sent.xml` pair), swapped
//! back into the HFS+ volume, and repacked as an `rdsk` IM4P (`img4 -T rdsk
//! -A`; the description string is kept from the source component instead of
//! the `-A` stub's "Unknown" — cosmetic, the field is not signed).
//!
//! The outputs (`kcache.im4p`, `rdsk.im4p`) are the files futurerestore takes
//! via `--rkrn`/`--rdsk`; here they feed [`crate::RestoreRequest`]'s
//! `rkrn`/`rdsk` overrides.

use std::path::PathBuf;

use legacy_ios_firmware::FirmwareArchive;
use legacy_ios_image::{
    HfsImage, compress_lzss, decode_im4p_payload, patch_kernel64, patch_restored_external,
    rebuild_im4p,
};
use tracing::{info, warn};

use crate::KitError;

/// Path of the patched binary inside the restore ramdisk.
const RESTORED_EXTERNAL_PATH: &str = "usr/local/bin/restored_external";

/// Code Directory identifier of the ad-hoc re-signature; ldid derives it from
/// the file name.
const RESTORED_EXTERNAL_IDENTIFIER: &str = "restored_external";

/// Output file names, matching upstream's working-directory artifacts.
const KCACHE_OUTPUT: &str = "kcache.im4p";
const RDSK_OUTPUT: &str = "rdsk.im4p";

/// Request for the iPhone X restore component build: a stock iOS 14.3-15.x
/// iPhone X IPSW and the directory `kcache.im4p`/`rdsk.im4p` are written to.
pub struct IpxPrepareRequest {
    ipsw: PathBuf,
    output_dir: PathBuf,
}

impl IpxPrepareRequest {
    pub fn new(ipsw: impl Into<PathBuf>, output_dir: impl Into<PathBuf>) -> Self {
        Self {
            ipsw: ipsw.into(),
            output_dir: output_dir.into(),
        }
    }
}

/// Artifacts produced by the iPhone X restore component build.
#[derive(Debug)]
pub struct IpxPrepareOutcome {
    kcache: PathBuf,
    rdsk: PathBuf,
    version: String,
    build: String,
}

impl IpxPrepareOutcome {
    /// AMFI-patched kernelcache IM4P (type `rkrn`), the `--rkrn` override.
    pub fn kcache(&self) -> &std::path::Path {
        &self.kcache
    }

    /// Ramdisk IM4P (type `rdsk`) with the patched restored_external, the
    /// `--rdsk` override.
    pub fn rdsk(&self) -> &std::path::Path {
        &self.rdsk
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn build(&self) -> &str {
        &self.build
    }
}

/// Build the patched `kcache.im4p` and `rdsk.im4p` of an iPhone X downgrade
/// restore, mirroring `ipsw_prepare_ipx`.
pub(crate) async fn prepare(request: IpxPrepareRequest) -> Result<IpxPrepareOutcome, KitError> {
    let archive = FirmwareArchive::open(&request.ipsw)?;
    let manifest = archive.build_manifest()?;
    if !manifest
        .supported_product_types()
        .iter()
        .any(|product| matches!(product.as_str(), "iPhone10,3" | "iPhone10,6"))
    {
        return Err(KitError::IpxUnsupportedDevice(
            manifest
                .supported_product_types()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    let version = manifest.product_version().to_string();
    let mut parts = version.split('.').map(|part| part.parse::<u32>());
    let (major, minor) = (
        parts.next().and_then(Result::ok),
        parts.next().and_then(Result::ok).unwrap_or(0),
    );
    if !matches!(major, Some(14) if minor >= 3) && !matches!(major, Some(15)) {
        return Err(KitError::IpxUnsupportedVersion(version));
    }
    // restore.sh reads BuildIdentities:0 unconditionally; iPhone X IPSWs
    // carry a single board, so the first identity is the Erase identity.
    let identity = manifest
        .identities()
        .first()
        .ok_or(KitError::IpxInvalidManifest)?;
    let kernelcache_path = identity.component_path("KernelCache")?.to_owned();
    let ramdisk_path = identity.component_path("RestoreRamDisk")?.to_owned();
    info!(
        kernelcache = kernelcache_path,
        ramdisk = ramdisk_path,
        "ipx component paths"
    );

    let kcache = prepare_kernelcache(&archive, &kernelcache_path)?;
    let rdsk = prepare_ramdisk(&archive, &ramdisk_path)?;

    tokio::fs::create_dir_all(&request.output_dir).await?;
    let kcache_output = request.output_dir.join(KCACHE_OUTPUT);
    let rdsk_output = request.output_dir.join(RDSK_OUTPUT);
    tokio::fs::write(&kcache_output, &kcache).await?;
    tokio::fs::write(&rdsk_output, &rdsk).await?;
    info!(
        kcache = %kcache_output.display(),
        rdsk = %rdsk_output.display(),
        "iPhone X restore components prepared"
    );
    Ok(IpxPrepareOutcome {
        kcache: kcache_output,
        rdsk: rdsk_output,
        version,
        build: manifest.build_id().to_string(),
    })
}

/// The kernelcache chain: extract, decompress, AMFI-patch, LZSS-recompress,
/// repack as `rkrn` without the compression DER element (`img4 -T rkrn -J`).
fn prepare_kernelcache(archive: &FirmwareArchive, path: &str) -> Result<Vec<u8>, KitError> {
    let component = archive.read_entry(path)?;
    let kernelcache = decode_im4p_payload(&component)?;
    let outcome = patch_kernel64(&kernelcache)?;
    for missed in outcome.missed() {
        warn!(patch = ?missed, "kernelcache patch point not found");
    }
    info!(applied = ?outcome.applied(), "kernelcache patched");
    let compressed = compress_lzss(outcome.image())?;
    Ok(rebuild_im4p(&component, b"rkrn", &compressed)?)
}

/// The ramdisk chain: extract, decompress, patch and re-sign
/// restored_external, swap it back into the HFS+ volume, repack as `rdsk`
/// without compression (`img4 -T rdsk -A`).
fn prepare_ramdisk(archive: &FirmwareArchive, path: &str) -> Result<Vec<u8>, KitError> {
    let component = archive.read_entry(path)?;
    let ramdisk = decode_im4p_payload(&component)?;
    let mut image = HfsImage::parse(ramdisk)?;
    let original = image.read(RESTORED_EXTERNAL_PATH)?;
    let patched = patch_restored_external(&original)?;
    // ldid -e restored_external.orig > ent.xml; ldid -Sent.xml restored_external
    let entitlements = legacy_ios_services::signing::extract_entitlements(&original)?;
    let signed = legacy_ios_services::signing::adhoc_sign(
        &patched,
        RESTORED_EXTERNAL_IDENTIFIER,
        entitlements.as_deref(),
    )?;
    image.remove(RESTORED_EXTERNAL_PATH, false)?;
    image.add_file(RESTORED_EXTERNAL_PATH, &signed)?;
    image.chmod(RESTORED_EXTERNAL_PATH, 0o755)?;
    Ok(rebuild_im4p(&component, b"rdsk", &image.into_bytes())?)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use legacy_ios_image::{decompress_lzss, extract_im4p_payload, is_lzss_compressed};
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    // --- Minimal DER/IM4P fixture helpers ---

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if content.len() < 0x80 {
            output.push(content.len() as u8);
        } else if content.len() < 0x1_0000 {
            output.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
        } else {
            output.extend_from_slice(&[
                0x83,
                (content.len() >> 16) as u8,
                (content.len() >> 8) as u8,
                content.len() as u8,
            ]);
        }
        output.extend_from_slice(content);
        output
    }

    fn im4p(image_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut content = der(0x16, b"IM4P");
        content.extend_from_slice(&der(0x16, image_type));
        content.extend_from_slice(&der(0x16, b"fixture"));
        content.extend_from_slice(&der(0x04, payload));
        der(0x30, &content)
    }

    // --- Minimal kernelcache Mach-O that patch_kernel64 can hit ---
    //
    // Kernel at file offset 0 with every VA at VA_BASE + file offset, a
    // __kmod_info/__kmod_start pair resolving the AMFI kext, and an AMFI
    // __TEXT_EXEC,__text holding the sha1-check pattern (tbz + cmp w0, 2).

    const VA_BASE: u64 = 0xffff_fff0_0700_4000;
    const K_CSTRING: usize = 0x1000;
    const K_KMOD_INFO: usize = 0x4000;
    const K_KMOD_START: usize = 0x4800;
    const K_KMOD_STRUCT: usize = 0x9000;
    const K_AMFI: usize = 0xA000;
    const K_AMFI_TEXT: usize = 0xB000;
    const K_LEN: usize = 0xC000;

    fn w32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn w64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn macho_header(buf: &mut [u8], base: usize, ncmds: u32) {
        w32(buf, base, 0xFEED_FACF);
        w32(buf, base + 4, 0x0100_000C); // CPU_TYPE_ARM64
        w32(buf, base + 16, ncmds);
    }

    fn segment64(
        buf: &mut [u8],
        cmd: usize,
        name: &str,
        fileoff: u64,
        filesize: u64,
        sections: &[(&str, u64, u64, u64)], // (name, addr, size, offset)
    ) {
        let cmdsize = 72 + 80 * sections.len();
        w32(buf, cmd, 0x19); // LC_SEGMENT_64
        w32(buf, cmd + 4, cmdsize as u32);
        buf[cmd + 8..cmd + 8 + name.len()].copy_from_slice(name.as_bytes());
        w64(buf, cmd + 24, VA_BASE + fileoff); // vmaddr
        w64(buf, cmd + 32, filesize); // vmsize
        w64(buf, cmd + 40, fileoff);
        w64(buf, cmd + 48, filesize);
        w32(buf, cmd + 64, sections.len() as u32); // nsects
        for (i, (name, addr, size, offset)) in sections.iter().enumerate() {
            let sec = cmd + 72 + 80 * i;
            buf[sec..sec + name.len()].copy_from_slice(name.as_bytes());
            buf[sec + 16..sec + 16 + name.len()].copy_from_slice(name.as_bytes());
            w64(buf, sec + 32, VA_BASE + addr);
            w64(buf, sec + 40, *size);
            w64(buf, sec + 48, *offset);
        }
    }

    fn kernelcache() -> Vec<u8> {
        let mut buf = vec![0u8; K_LEN];
        macho_header(&mut buf, 0, 4);
        let mut cmd = 32;
        segment64(
            &mut buf,
            cmd,
            "__TEXT",
            0,
            0x4000,
            &[("__cstring", K_CSTRING as u64, 0x100, K_CSTRING as u64)],
        );
        cmd += 72 + 80;
        segment64(
            &mut buf,
            cmd,
            "__PRELINK_INFO",
            0x4000,
            0x2000,
            &[
                ("__kmod_info", K_KMOD_INFO as u64, 8, K_KMOD_INFO as u64),
                ("__kmod_start", K_KMOD_START as u64, 8, K_KMOD_START as u64),
            ],
        );
        cmd += 72 + 160;
        segment64(
            &mut buf,
            cmd,
            "__PRELINK_TEXT",
            0x8000,
            0x4000,
            &[("__text", 0x8000, 0x4000, 0x8000)],
        );
        cmd += 72 + 80;
        w32(&mut buf, cmd, 0x32); // LC_BUILD_VERSION
        w32(&mut buf, cmd + 4, 24);
        w32(&mut buf, cmd + 8, 2); // PLATFORM_IOS

        // __kmod_info[0] -> kmod_info struct, __kmod_start[0] -> AMFI Mach-O.
        w64(&mut buf, K_KMOD_INFO, VA_BASE + K_KMOD_STRUCT as u64);
        w64(&mut buf, K_KMOD_START, VA_BASE + K_AMFI as u64);
        buf[K_KMOD_STRUCT + 16..K_KMOD_STRUCT + 16 + 41]
            .copy_from_slice(b"com.apple.driver.AppleMobileFileIntegrity");

        // AMFI kext Mach-O.
        macho_header(&mut buf, K_AMFI, 1);
        segment64(
            &mut buf,
            K_AMFI + 32,
            "__TEXT_EXEC",
            K_AMFI_TEXT as u64,
            0x100,
            &[("__text", K_AMFI_TEXT as u64, 0x100, K_AMFI_TEXT as u64)],
        );
        // patch_amfi_sha1: tbz w2, 0x1a, * then cmp w0, 2.
        w32(&mut buf, K_AMFI_TEXT, 0x36d0_0002);
        w32(&mut buf, K_AMFI_TEXT + 4, 0x7100_081f);
        buf
    }

    // --- restored_external Mach-O with the FaceID patch point ---

    const R_TEXT: usize = 0x400;
    const R_STRLEN_AT: usize = 0x600;

    fn restored_external() -> Vec<u8> {
        // A minimal signable arm64 executable (see services' signing tests)
        // whose __text carries the refFrame patch point: adrp/add xref to the
        // string, then `mov x0, x1; ret`.
        let mut data = vec![0u8; 0x1000];
        macho_header(&mut data, 0, 2);
        w32(&mut data, 12, 2); // MH_EXECUTE
        w32(&mut data, 20, (72 + 80 + 72) as u32); // sizeofcmds
        // __TEXT with one __text section, vmaddr 0 (vaddr == file offset).
        w32(&mut data, 32, 0x19);
        w32(&mut data, 36, (72 + 80) as u32);
        data[40..46].copy_from_slice(b"__TEXT");
        w64(&mut data, 56, 0x1000); // vmsize
        w64(&mut data, 72, 0x1000); // filesize
        w64(&mut data, 88, 5); // maxprot
        w64(&mut data, 96, 5); // initprot
        w32(&mut data, 104 - 8, 1); // nsects
        let section = 32 + 72;
        data[section..section + 6].copy_from_slice(b"__text");
        data[section + 16..section + 22].copy_from_slice(b"__TEXT");
        w64(&mut data, section + 32, R_TEXT as u64); // addr
        w64(&mut data, section + 40, 0x200); // size
        w32(&mut data, section + 48, R_TEXT as u32); // offset
        // __LINKEDIT, last segment.
        let linkedit = 32 + 72 + 80;
        w32(&mut data, linkedit, 0x19);
        w32(&mut data, linkedit + 4, 72);
        data[linkedit + 8..linkedit + 18].copy_from_slice(b"__LINKEDIT");
        w64(&mut data, linkedit + 24, 0x1000); // vmaddr
        w64(&mut data, linkedit + 40, 0x1000); // fileoff

        // refFrame string and its adrp/add xref (linked at base 0).
        data[R_STRLEN_AT..R_STRLEN_AT + 8].copy_from_slice(b"refFrame");
        let adrp_at = R_TEXT + 0x40;
        // Same page: adrp x8, #0; add x8, x8, #(R_STRLEN_AT & 0xfff).
        w32(&mut data, adrp_at, 0x9000_0008);
        w32(
            &mut data,
            adrp_at + 4,
            0x9100_0008 | (((R_STRLEN_AT & 0xfff) as u32) << 10) | (8 << 5),
        );
        w32(&mut data, adrp_at + 8, 0xaa01_03e0); // mov x0, x1
        w32(&mut data, adrp_at + 12, 0xd65f_03c0); // ret
        data
    }

    // --- Growable HFS+ image holding usr/local/bin/restored_external ---
    //
    // Mirrors the growable_image fixture of image::hfs tests (volume header
    // at 1024, totalBlocks +44, freeBlocks +48, allocation fork +112), sized
    // to hold the signed replacement binary.

    fn ramdisk_hfs(restored_external: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 4096;
        const BLOCKS: usize = 64;
        let mut builder = hfsplus::testutil::HfsPlusImageBuilder::new();
        builder.add_file("seed", restored_external, 0o755);
        let mut data = builder.build();
        data.resize(BLOCKS * BLOCK, 0);
        // Blocks 0-3 hold metadata, the seed file data follows, then the
        // (relocated) allocation bitmap block; the last block holds the
        // alternate volume header.
        let file_blocks = restored_external.len().div_ceil(BLOCK);
        let used = 4 + file_blocks;
        let alloc_block = used;
        let primary = 1024;
        let put32 = |data: &mut [u8], offset: usize, value: u32| {
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        };
        let put64 = |data: &mut [u8], offset: usize, value: u64| {
            data[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        };
        put32(&mut data, primary + 44, BLOCKS as u32); // totalBlocks
        put32(&mut data, primary + 48, (BLOCKS - used - 2) as u32); // freeBlocks
        put64(&mut data, primary + 112, 1); // allocation logical size
        put32(&mut data, primary + 112 + 12, 1); // allocation total blocks
        put32(&mut data, primary + 112 + 16, alloc_block as u32); // start block
        put32(&mut data, primary + 112 + 20, 1); // block count
        // Bitmap: blocks 0..used, the allocation block, and the last block.
        for block in 0..used {
            data[alloc_block * BLOCK + block / 8] |= 0x80 >> (block % 8);
        }
        data[alloc_block * BLOCK + alloc_block / 8] |= 0x80 >> (alloc_block % 8);
        data[alloc_block * BLOCK + (BLOCKS - 1) / 8] |= 0x80 >> ((BLOCKS - 1) % 8);
        let header = data[primary..primary + 512].to_vec();
        let alternate = BLOCKS * BLOCK - 1024;
        data[alternate..alternate + 512].copy_from_slice(&header);

        let mut image = HfsImage::parse(data).unwrap();
        image.mkdir("/usr").unwrap();
        image.mkdir("/usr/local").unwrap();
        image.mkdir("/usr/local/bin").unwrap();
        image
            .move_entry("/seed", &format!("/{RESTORED_EXTERNAL_PATH}"))
            .unwrap();
        image.into_bytes()
    }

    // --- Fake IPSW ---

    fn ipsw(directory: &std::path::Path) -> PathBuf {
        let path = directory.join("target.ipsw");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>15.7</string>
<key>ProductBuildVersion</key><string>19H12</string>
<key>SupportedProductTypes</key><array><string>iPhone10,3</string><string>iPhone10,6</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>d221ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict>
<key>KernelCache</key><dict><key>Info</key><dict><key>Path</key><string>kernelcache.release iphone10</string></dict></dict>
<key>RestoreRamDisk</key><dict><key>Info</key><dict><key>Path</key><string>ramdisk.dmg</string></dict></dict>
</dict></dict></array></dict></plist>"#;
        let entitlements = r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>platform-application</key><true/></dict></plist>"#;
        let signed_restored = legacy_ios_services::signing::adhoc_sign(
            &restored_external(),
            RESTORED_EXTERNAL_IDENTIFIER,
            Some(entitlements),
        )
        .unwrap();
        for (name, data) in [
            ("BuildManifest.plist", manifest.as_slice()),
            (
                "kernelcache.release iphone10",
                &im4p(b"krnl", &kernelcache()),
            ),
            (
                "ramdisk.dmg",
                &im4p(b"rdsk", &ramdisk_hfs(&signed_restored)),
            ),
        ] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[tokio::test]
    async fn prepares_kcache_and_rdsk() {
        let work = tempfile::tempdir().unwrap();
        let ipsw = ipsw(work.path());
        let output = work.path().join("out");

        let outcome = prepare(IpxPrepareRequest::new(ipsw, &output))
            .await
            .unwrap();

        // kcache.im4p: rkrn IM4P whose complzss payload decodes to the
        // AMFI-patched kernelcache.
        let kcache = std::fs::read(outcome.kcache()).unwrap();
        assert!(kcache.windows(4).any(|window| window == b"rkrn"));
        let payload = extract_im4p_payload(&kcache).unwrap();
        assert!(is_lzss_compressed(payload));
        let patched = patch_kernel64(&kernelcache()).unwrap().into_image();
        assert_eq!(decompress_lzss(payload).unwrap(), patched);

        // rdsk.im4p: rdsk IM4P whose raw payload is the HFS+ volume with the
        // patched, re-signed, 0o755 restored_external.
        let rdsk = std::fs::read(outcome.rdsk()).unwrap();
        let image = HfsImage::parse(extract_im4p_payload(&rdsk).unwrap().to_vec()).unwrap();
        let stat = image.stat(RESTORED_EXTERNAL_PATH).unwrap();
        assert_eq!(stat.mode(), 0o100755);
        let replaced = image.read(RESTORED_EXTERNAL_PATH).unwrap();
        assert_ne!(replaced, restored_external());
        let entitlements = legacy_ios_services::signing::extract_entitlements(&replaced)
            .unwrap()
            .unwrap();
        assert!(entitlements.contains("platform-application"));
    }

    #[tokio::test]
    async fn rejects_non_ipx_ipsw() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("other.ipsw");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>15.7</string>
<key>ProductBuildVersion</key><string>19H12</string>
<key>SupportedProductTypes</key><array><string>iPhone8,1</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>n71ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict></dict></dict></array></dict></plist>"#,
            )
            .unwrap();
        writer.finish().unwrap();

        let error = prepare(IpxPrepareRequest::new(path, work.path().join("out")))
            .await
            .unwrap_err();
        assert!(matches!(error, KitError::IpxUnsupportedDevice(_)));
    }

    #[tokio::test]
    async fn rejects_out_of_range_version() {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("old.ipsw");
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .start_file("BuildManifest.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductVersion</key><string>14.2</string>
<key>ProductBuildVersion</key><string>18B92</string>
<key>SupportedProductTypes</key><array><string>iPhone10,3</string></array>
<key>BuildIdentities</key><array><dict>
<key>Info</key><dict><key>DeviceClass</key><string>d221ap</string><key>RestoreBehavior</key><string>Erase</string></dict>
<key>Manifest</key><dict></dict></dict></array></dict></plist>"#,
            )
            .unwrap();
        writer.finish().unwrap();

        let error = prepare(IpxPrepareRequest::new(path, work.path().join("out")))
            .await
            .unwrap_err();
        assert!(matches!(error, KitError::IpxUnsupportedVersion(_)));
    }
}
