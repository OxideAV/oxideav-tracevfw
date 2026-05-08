//! `encode` subcommand — drive the codec with a synthetic frame
//! through the round-1 host-side surface.
//!
//! The full encoder pipeline lands when `oxideav-vfw` grows the
//! `ICCompress` host-side wrapper (round 2 of this crate). For
//! round 1 we accept the encode subcommand, generate the
//! requested synthetic input, and report what the host's
//! existing surface can do — primarily proving the path through
//! `Sandbox::install_codec` + `ic_open` works for compress mode
//! (`ICMODE_COMPRESS = 2`) on the operator's chosen DLL.

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
        "[encode] generated synthetic RGB24 input ({} bytes); ICCompress wiring lands in round 2 of this CLI",
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
