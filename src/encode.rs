//! `encode` subcommand — drive the codec with a synthetic frame
//! through the round-1 host-side surface.
//!
//! ## Round 3 status — blocked on a cross-crate followup
//!
//! `oxideav-vfw 0.1.0` ships the decompress half of the VfW host
//! surface (`ic_decompress_query` / `ic_decompress_begin` /
//! `ic_decompress` / `ic_decompress_end`) but not the compress
//! half. The encode subcommand therefore can only:
//!
//! 1. Verify the codec accepts `DRV_OPEN(ICMODE_COMPRESS = 2)`
//!    (most legacy VfW codecs accept compress-mode open even when
//!    they refuse the bitstream-format query later).
//! 2. Generate the requested synthetic RGB24 input pattern.
//! 3. Write the synthetic input out (proving the CLI plumbing).
//!
//! Round-4 candidate: when `oxideav-vfw` grows
//! `Sandbox::ic_compress_query` / `ic_compress_begin` /
//! `ic_compress` / `ic_compress_end` (mirroring the existing
//! decompress wrappers + dispatching to `ICM_COMPRESS_QUERY` /
//! `ICM_COMPRESS_BEGIN` / `ICM_COMPRESS` / `ICM_COMPRESS_END` —
//! `vfw.h` macro values 0x4008 / 0x4001 / 0x4002 / 0x4007 in the
//! Windows 10 SDK), the encode subcommand wires through the same
//! pattern as `decode.rs`. Until then this path stays a
//! synthetic-frame generator + open-only smoke test.

use anyhow::{Context, Result};
use oxideav_vfw::{Sandbox, DLL_PROCESS_ATTACH};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::Pattern;

/// `vfw.h`: `ICMODE_COMPRESS = 2`.
const ICMODE_COMPRESS: u32 = 2;

/// Run the `encode` subcommand.
pub fn run(
    sandbox: &mut Sandbox,
    dll_path: &Path,
    fcc_handler: Option<&str>,
    width: u32,
    height: u32,
    pattern: Pattern,
    output: Option<PathBuf>,
) -> Result<()> {
    let bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let name = dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.dll".to_string());

    let img = sandbox.load(&name, &bytes)?;
    let _ = sandbox.call_dll_main(&img, DLL_PROCESS_ATTACH)?;
    sandbox.install_codec(&img)?;

    let fcc_handler = fcc_handler
        .map(str::to_owned)
        .unwrap_or_else(|| crate::probe::derive_default_fcc_for_test(dll_path));
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = crate::probe::fourcc_to_u32_for_test(&fcc_handler);

    println!(
        "[encode] opening codec for compress: fccType=VIDC fccHandler={} ({}x{}, pattern={:?})",
        fcc_handler, width, height, pattern
    );
    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_COMPRESS)
        .context("ICOpen(ICMODE_COMPRESS)")?;
    if hic == 0 {
        println!("[encode] codec refused DRV_OPEN for ICMODE_COMPRESS — encode side not exposed by this codec");
        return Ok(());
    }
    println!("[encode] HIC = {hic}");

    let synthetic = synth_pattern(width, height, pattern);
    println!(
        "[encode] generated synthetic RGB24 input ({} bytes); ICCompress wiring blocked on \
         a cross-crate followup — `oxideav-vfw 0.1.0` exposes `ic_decompress*` only, not \
         `ic_compress*`. See the round-3 status note in src/encode.rs.",
        synthetic.len()
    );

    if let Some(path) = output {
        let mut f = std::fs::File::create(&path)
            .with_context(|| format!("creating output {}", path.display()))?;
        f.write_all(&synthetic)?;
        println!(
            "[encode] wrote {} bytes of synthetic input to {}",
            synthetic.len(),
            path.display()
        );
    } else {
        std::io::stdout().write_all(&synthetic)?;
    }

    let _ = sandbox.ic_close(hic);
    Ok(())
}

/// Generate a synthetic RGB24 buffer of the requested pattern.
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
}
