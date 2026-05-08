//! `decode` subcommand — drive `ICDecompress` on a codec
//! bitstream-only file.
//!
//! The operator is responsible for extracting the codec frame
//! from any container (AVI / MOV / etc.) before passing it in;
//! this CLI does not own a demux surface.

use anyhow::{Context, Result};
use oxideav_vfw::{Sandbox, DLL_PROCESS_ATTACH};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::PixFormat;

/// `vfw.h`: ICMODE_DECOMPRESS.
const ICMODE_DECOMPRESS: u32 = 1;

/// Run the `decode` subcommand.
#[allow(clippy::too_many_arguments)]
pub fn run(
    sandbox: &mut Sandbox,
    dll_path: &Path,
    fcc_handler: Option<&str>,
    input: &Path,
    width: u32,
    height: u32,
    pix_format: PixFormat,
    output: Option<PathBuf>,
) -> Result<()> {
    let bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let name = dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.dll".to_string());

    let frame =
        std::fs::read(input).with_context(|| format!("reading input {}", input.display()))?;

    let img = sandbox.load(&name, &bytes)?;
    let _ = sandbox.call_dll_main(&img, DLL_PROCESS_ATTACH)?;
    sandbox.install_codec(&img)?;

    let fcc_handler = fcc_handler
        .map(str::to_owned)
        .unwrap_or_else(|| crate::probe::derive_default_fcc_for_test(dll_path));
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = crate::probe::fourcc_to_u32_for_test(&fcc_handler);

    let in_bih = oxideav_vfw::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: fcc_handler_u32.to_le_bytes(),
        size_image: frame.len() as u32,
        ..oxideav_vfw::Bih::default()
    };
    let out_bih = oxideav_vfw::Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: pix_format.bi_bit_count(),
        compression: pix_format.bi_compression().to_le_bytes(),
        size_image: width * height * pix_format.bytes_per_pixel(),
        ..oxideav_vfw::Bih::default()
    };

    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_DECOMPRESS)
        .context("ICOpen(ICMODE_DECOMPRESS)")?;
    if hic == 0 {
        anyhow::bail!("codec refused DRV_OPEN");
    }
    println!("[decode] HIC = {hic}");

    let q = sandbox
        .ic_decompress_query(hic, &in_bih, Some(&out_bih))
        .context("ICDecompressQuery")?;
    println!(
        "[decode] ICDecompressQuery = {} (expected 0 / ICERR_OK)",
        q as i32
    );

    if (q as i32) == 0 {
        let _ = sandbox.ic_decompress_begin(hic, &in_bih, &out_bih);
        let out_capacity = width * height * pix_format.bytes_per_pixel();
        match sandbox.ic_decompress(hic, 0, &in_bih, &frame, &out_bih, out_capacity) {
            Ok((rc, decoded)) => {
                println!(
                    "[decode] ICDecompress = {} (output {} bytes)",
                    rc as i32,
                    decoded.len()
                );
                if let Some(path) = output {
                    let mut f = std::fs::File::create(&path)
                        .with_context(|| format!("creating output {}", path.display()))?;
                    f.write_all(&decoded)?;
                    println!(
                        "[decode] wrote {} bytes to {}",
                        decoded.len(),
                        path.display()
                    );
                } else {
                    std::io::stdout().write_all(&decoded)?;
                }
            }
            Err(e) => {
                println!("[decode] ICDecompress failed: {e}");
            }
        }
        let _ = sandbox.ic_decompress_end(hic);
    }

    let _ = sandbox.ic_close(hic);
    Ok(())
}
