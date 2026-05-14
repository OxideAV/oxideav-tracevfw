//! `encode` subcommand — drive `ICCompress` on uncompressed input.
//!
//! Mirrors `decode.rs`: load the DLL, run DllMain, install the
//! codec, open the codec in compress mode, then drive the full
//! `ICCompressQuery` → `ICCompressGetFormat` → `ICCompressGetSize`
//! → `ICCompressBegin` → `ICCompress` → `ICCompressEnd` lifecycle.
//!
//! ## Round 5 — fully wired
//!
//! `oxideav-vfw r51` (commit `dcc9c37`) landed the encode half of
//! the host surface, so the cross-crate followup the round-3 stub
//! was blocked on is resolved. This subcommand now produces real
//! encoded bytes against any codec that accepts `ICMODE_COMPRESS`
//! at `DRV_OPEN`. The earlier "synthetic-pattern + open-only smoke
//! test" path is preserved as a fallback for the `--pattern` case
//! when no `--input` file is supplied.

use anyhow::{Context, Result};
use oxideav_vfw::{Sandbox, DLL_PROCESS_ATTACH};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::{InputFormat, Pattern};

/// `vfw.h`: `ICMODE_COMPRESS = 1`. (The earlier round-3 stub
/// transposed this with `ICMODE_DECOMPRESS = 2`; corrected in
/// round 5 to match `oxideav_vfw::win32::vfw32::ic_open` docs
/// and the working `oxideav-vfw` round-51 encode test.)
const ICMODE_COMPRESS: u32 = 1;

/// `vfw.h`: `ICCOMPRESS_KEYFRAME = 0x00000001`. Caller-side
/// `dwFlags` bit asking the codec to emit an I-frame.
const ICCOMPRESS_KEYFRAME: u32 = 0x0000_0001;

/// Default `ICCOMPRESS::lpckid` value — `'00dc'` is the AVI
/// per-frame chunk-id for "compressed video".
const CKID_00DC: u32 = u32::from_le_bytes(*b"00dc");

/// Run the `encode` subcommand.
#[allow(clippy::too_many_arguments)]
pub fn run(
    sandbox: &mut Sandbox,
    dll_path: &Path,
    fcc_handler: Option<&str>,
    input: Option<PathBuf>,
    width: u32,
    height: u32,
    input_format: InputFormat,
    pattern: Pattern,
    quality: u32,
    pquant: Option<u8>,
    keyframe: bool,
    output_fourcc: Option<&str>,
    output: Option<PathBuf>,
) -> Result<()> {
    let bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let name = dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.dll".to_string());

    // Materialise the input pixel buffer — either read it from
    // disk (raw bytes, no header) or synthesise from --pattern.
    let pixels = if let Some(ref p) = input {
        let buf =
            std::fs::read(p).with_context(|| format!("reading input pixels {}", p.display()))?;
        let expected = input_format.frame_bytes(width, height) as usize;
        if buf.len() != expected {
            anyhow::bail!(
                "input {} has {} bytes, expected {} for {}x{} {:?}",
                p.display(),
                buf.len(),
                expected,
                width,
                height,
                input_format,
            );
        }
        buf
    } else {
        synth_pattern(width, height, pattern)
    };

    let img = sandbox.load(&name, &bytes)?;
    let _ = sandbox.call_dll_main(&img, DLL_PROCESS_ATTACH)?;
    sandbox.install_codec(&img)?;

    let fcc_handler = fcc_handler
        .map(str::to_owned)
        .unwrap_or_else(|| crate::probe::derive_default_fcc_for_test(dll_path));
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = crate::probe::fourcc_to_u32_for_test(&fcc_handler);

    println!(
        "[encode] opening codec for compress: fccType=VIDC fccHandler={} ({}x{}, format={:?}, quality={}, keyframe={})",
        fcc_handler, width, height, input_format, quality, keyframe,
    );
    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_COMPRESS)
        .context("ICOpen(ICMODE_COMPRESS)")?;
    if hic == 0 {
        anyhow::bail!("codec refused DRV_OPEN for ICMODE_COMPRESS");
    }
    println!("[encode] HIC = {hic}");

    // Build the input BITMAPINFOHEADER from the operator-supplied
    // shape. `size_image` carries the uncompressed byte count.
    let in_bih = oxideav_vfw::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: input_format.bi_bit_count(),
        compression: input_format.bi_compression(),
        size_image: pixels.len() as u32,
        ..oxideav_vfw::Bih::default()
    };

    // ICCompressQuery — does the codec accept this input format?
    let q = sandbox
        .ic_compress_query(hic, &in_bih, None)
        .context("ICCompressQuery")?;
    println!(
        "[encode] ICCompressQuery = {} (expected 0 / ICERR_OK)",
        q as i32
    );
    if q != 0 {
        let _ = sandbox.ic_close(hic);
        anyhow::bail!(
            "ICCompressQuery rejected input shape {}x{} {:?} with lresult={:#x}",
            width,
            height,
            input_format,
            q
        );
    }

    // ICCompressGetFormat — let the codec describe its output BIH.
    let (gf_lr, mut out_bih) = sandbox
        .ic_compress_get_format(hic, &in_bih)
        .context("ICCompressGetFormat")?;
    println!(
        "[encode] ICCompressGetFormat = {:#x} (output FOURCC = {:?})",
        gf_lr,
        std::str::from_utf8(&out_bih.compression).unwrap_or("?"),
    );

    // Honour an operator override of the output FOURCC.
    if let Some(fcc) = output_fourcc {
        let mut b = [b' '; 4];
        for (i, c) in fcc.bytes().take(4).enumerate() {
            b[i] = c;
        }
        out_bih.compression = b;
        println!(
            "[encode] output FOURCC overridden to {:?}",
            std::str::from_utf8(&out_bih.compression).unwrap_or("?")
        );
    }

    // If the codec couldn't decide a format, synthesise a sensible
    // default — bit_count matching the input, FOURCC matching the
    // codec's fccHandler. This is what real-vfw32 hosts do when
    // they cycle through registry-listed codecs.
    if gf_lr != 0 && out_bih.bi_size == 0 {
        out_bih = oxideav_vfw::Bih {
            bi_size: 40,
            width: width as i32,
            height: height as i32,
            planes: 1,
            bit_count: input_format.bi_bit_count(),
            compression: fcc_handler_u32.to_le_bytes(),
            size_image: pixels.len() as u32,
            ..oxideav_vfw::Bih::default()
        };
        println!(
            "[encode] synthesised default output BIH ({} FOURCC)",
            fcc_handler,
        );
    }

    // ICCompressGetSize — bound the output buffer.
    let max_out_size = match sandbox.ic_compress_get_size(hic, &in_bih, &out_bih) {
        Ok(n) if n > 0 => n,
        other => {
            // Codec couldn't size; fall back to "encoded fits in
            // uncompressed worst case" = width × height × 4.
            let fallback = width.saturating_mul(height).saturating_mul(4);
            println!(
                "[encode] ICCompressGetSize = {:?}; using fallback {} bytes",
                other, fallback,
            );
            fallback
        }
    };
    println!("[encode] max output size = {max_out_size} bytes");

    // ICCompressBegin — set up the encoder pipeline.
    let begin = sandbox
        .ic_compress_begin(hic, &in_bih, &out_bih)
        .context("ICCompressBegin")?;
    println!("[encode] ICCompressBegin = {:#x}", begin);
    if begin != 0 {
        let _ = sandbox.ic_close(hic);
        anyhow::bail!("ICCompressBegin returned non-zero ({begin:#x})");
    }

    // ICCompress — encode the frame.
    let flags = if keyframe { ICCOMPRESS_KEYFRAME } else { 0 };
    let outcome = sandbox
        .ic_compress(
            hic,
            flags,
            &in_bih,
            &pixels,
            &out_bih,
            max_out_size,
            CKID_00DC,
            0, // frame_num — single-frame encode
            0, // frame_size_limit — no cap
            quality,
            None, // prev_bih (keyframe encode has no prev)
            None, // prev_bytes
        )
        .context("ICCompress")?;
    println!(
        "[encode] ICCompress lresult={:#x}, {} bytes encoded (returned_flags={:#x}, ckid={:?})",
        outcome.lresult,
        outcome.bytes.len(),
        outcome.returned_flags,
        std::str::from_utf8(&outcome.ckid.to_le_bytes()).unwrap_or("?"),
    );

    // ICCompressEnd — tear down regardless of ICCompress outcome.
    let end = sandbox.ic_compress_end(hic);
    println!("[encode] ICCompressEnd = {:?}", end);
    let _ = sandbox.ic_close(hic);

    if outcome.lresult != 0 {
        anyhow::bail!(
            "ICCompress returned non-zero lresult ({:#x})",
            outcome.lresult
        );
    }
    if outcome.bytes.is_empty() {
        anyhow::bail!("ICCompress returned zero encoded bytes");
    }

    // Optional post-processing: rewrite the picture-header PQUANT
    // field. Targets the MS-MPEG-4 v3 picture-header layout
    // (2-bit picture_type, 5-bit pquant, MSB-first within the
    // first byte). See `oxideav-msmpeg4::header::MsV3PictureHeader`
    // for the authoritative layout citation. Documented as a
    // workaround in `README.md` "Limitations" — the proper path
    // is `Sandbox::ic_get_state` / `ic_set_state` once oxideav-vfw
    // exposes them.
    let mut bytes = outcome.bytes;
    if let Some(q) = pquant {
        let q5 = q & 0x1F; // already validated 1..=31 by clap range
        if let Some(byte0) = bytes.first_mut() {
            let before = *byte0;
            *byte0 = (before & 0b1100_0001) | (q5 << 1);
            println!(
                "[encode] --pquant {q}: rewrote picture-header byte 0 \
                 from 0x{before:02x} to 0x{:02x} \
                 (5-bit PQUANT field at bit offset 2, MSB-first)",
                *byte0,
            );
        } else {
            println!("[encode] --pquant {q}: encoded output is empty; nothing to patch");
        }
    }

    if let Some(path) = output {
        let mut f = std::fs::File::create(&path)
            .with_context(|| format!("creating output {}", path.display()))?;
        f.write_all(&bytes)?;
        println!(
            "[encode] wrote {} encoded bytes to {}",
            bytes.len(),
            path.display()
        );
    } else {
        std::io::stdout().write_all(&bytes)?;
    }

    Ok(())
}

/// Generate a synthetic 24-bit packed BGR/RGB buffer of the
/// requested pattern. (The byte order is "the same as whatever
/// the caller's input format expects" — for `Bgr24` the test
/// patterns are visually trivial and the codec doesn't care
/// about colour fidelity per se.)
pub fn synth_pattern(width: u32, height: u32, pattern: Pattern) -> Vec<u8> {
    let n = (width * height * 3) as usize;
    let mut buf = vec![0u8; n];
    match pattern {
        Pattern::Gradient => {
            for y in 0..height {
                for x in 0..width {
                    let off = ((y * width + x) * 3) as usize;
                    buf[off] = (x & 0xFF) as u8;
                    buf[off + 1] = (y & 0xFF) as u8;
                    buf[off + 2] = ((x ^ y) & 0xFF) as u8;
                }
            }
        }
        Pattern::Solid => {
            for b in buf.iter_mut() {
                *b = 0x80;
            }
        }
        Pattern::Checkerboard => {
            for y in 0..height {
                for x in 0..width {
                    let off = ((y * width + x) * 3) as usize;
                    let hit = ((x / 8) + (y / 8)) & 1 == 0;
                    let v = if hit { 0xFF } else { 0x00 };
                    buf[off] = v;
                    buf[off + 1] = v;
                    buf[off + 2] = v;
                }
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solid_pattern_is_uniform_0x80() {
        let b = synth_pattern(4, 4, Pattern::Solid);
        assert!(b.iter().all(|&x| x == 0x80));
        assert_eq!(b.len(), 4 * 4 * 3);
    }

    #[test]
    fn gradient_pattern_is_xy_progression() {
        let b = synth_pattern(16, 16, Pattern::Gradient);
        // (0, 0) → (0, 0, 0); (1, 0) → (1, 0, 1); …
        assert_eq!(b[0], 0);
        assert_eq!(b[1], 0);
        assert_eq!(b[2], 0);
        assert_eq!(b[3], 1);
        assert_eq!(b[4], 0);
        assert_eq!(b[5], 1);
    }

    #[test]
    fn checkerboard_pattern_alternates_every_8_pixels() {
        let b = synth_pattern(16, 16, Pattern::Checkerboard);
        // Column 0..7 of row 0 should all be 0xFF (top-left
        // square). Column 8..15 of row 0 should all be 0x00.
        for x in 0..8 {
            let off = (x * 3) as usize;
            assert_eq!(b[off], 0xFF, "x={x}");
        }
        for x in 8..16 {
            let off = (x * 3) as usize;
            assert_eq!(b[off], 0x00, "x={x}");
        }
    }

    #[test]
    fn input_format_frame_bytes_matches_bi_bit_count() {
        // 4×4 BGR24 = 48 bytes.
        assert_eq!(InputFormat::Bgr24.frame_bytes(4, 4), 48);
        // 4×4 BGR32 = 64 bytes.
        assert_eq!(InputFormat::Bgr32.frame_bytes(4, 4), 64);
        // 4×4 YV12 = 24 bytes (4*4 luma + 4 + 4 chroma).
        assert_eq!(InputFormat::Yv12.frame_bytes(4, 4), 24);
        assert_eq!(InputFormat::I420.frame_bytes(4, 4), 24);
        // 4×4 YUY2 = 32 bytes.
        assert_eq!(InputFormat::Yuy2.frame_bytes(4, 4), 32);
    }

    #[test]
    fn input_format_bi_compression_matches_fourcc() {
        assert_eq!(InputFormat::Bgr24.bi_compression(), [0; 4]);
        assert_eq!(InputFormat::Yv12.bi_compression(), *b"YV12");
        assert_eq!(InputFormat::I420.bi_compression(), *b"I420");
        assert_eq!(InputFormat::Yuy2.bi_compression(), *b"YUY2");
    }
}
