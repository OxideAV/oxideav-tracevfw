//! `probe` subcommand — load DLL, run DllMain(DLL_PROCESS_ATTACH),
//! call ICOpen + ICGetInfo + ICDecompressQuery, print findings.
//!
//! Default subcommand if the operator passes none. Builds a
//! sensible default `BITMAPINFOHEADER` for the codec's input
//! (the codec's natural FOURCC) and a 24-bit RGB output, then
//! reports back what each step produced.

use anyhow::{Context, Result};
use oxideav_vfw::{Bih, Sandbox, DLL_PROCESS_ATTACH};
use std::path::Path;

/// Run the probe sequence.
///
/// The operator-supplied `fcc_handler` is the codec's wire FOURCC
/// (`IV31` / `IV41` / `IV50` / `cvid` / etc.). When `None`, we
/// derive a sensible default from the file extension or fall back
/// to the round-1 default (`IV31`).
pub fn run(sandbox: &mut Sandbox, dll_path: &Path, fcc_handler: Option<&str>) -> Result<()> {
    let bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let name = dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.dll".to_string());

    println!("[probe] loaded {} ({} bytes)", name, bytes.len());
    let img = sandbox
        .load(&name, &bytes)
        .with_context(|| format!("oxideav-vfw load() of {name}"))?;
    println!(
        "[probe] PE image base = 0x{:08x}, entry = 0x{:08x}",
        img.image_base, img.entry_point
    );

    let dll_main_ret = sandbox
        .call_dll_main(&img, DLL_PROCESS_ATTACH)
        .context("DllMain(DLL_PROCESS_ATTACH)")?;
    println!("[probe] DllMain returned 0x{dll_main_ret:08x}");

    if let Err(e) = sandbox.install_codec(&img) {
        // Synthetic / non-VfW DLLs don't export `DriverProc`.
        // Round 1's probe surfaces this as a soft failure so an
        // operator running `oxidetracevfw <synth.dll>` doesn't
        // see a hard exit; later subcommands will reject the
        // codec for the same reason.
        println!("[probe] install_codec: {e}");
        println!("[probe] DLL does not expose `DriverProc` — skipping ICOpen / ICGetInfo / ICDecompressQuery");
        return Ok(());
    }

    let fcc_handler_str = fcc_handler
        .map(|s| s.to_owned())
        .unwrap_or_else(|| derive_default_fcc(dll_path));
    let fcc_type = u32::from_le_bytes(*b"VIDC");
    let fcc_handler_u32 = fourcc_to_u32(&fcc_handler_str);
    println!(
        "[probe] opening codec fccType=VIDC fccHandler={} (0x{:08x})",
        fcc_handler_str, fcc_handler_u32
    );

    let hic = sandbox
        .ic_open(fcc_type, fcc_handler_u32, ICMODE_DECOMPRESS)
        .context("ICOpen")?;
    println!("[probe] ICOpen returned HIC = {hic}");
    if hic == 0 {
        println!("[probe] ICOpen failed — codec refused DRV_OPEN");
        return Ok(());
    }

    // `vfw32::ICINFO` is 112 bytes (4 dwords + 64 wchar szName +
    // 32 wchar szDescription + … etc — we ask for the full
    // structure, which the round-17 short-return fallback in
    // oxideav-vfw will fill in if the codec returns less).
    const ICINFO_SIZE: u32 = 112;
    let icinfo = sandbox.ic_get_info(hic, ICINFO_SIZE).context("ICGetInfo")?;
    println!(
        "[probe] ICGetInfo returned {} bytes; first 32 = {}",
        icinfo.len(),
        format_hex_dump(&icinfo, 32)
    );
    if icinfo.len() >= 16 {
        let dw_size = u32::from_le_bytes(icinfo[0..4].try_into().unwrap());
        let icinfo_fcc_type = u32::from_le_bytes(icinfo[4..8].try_into().unwrap());
        let icinfo_fcc_handler = u32::from_le_bytes(icinfo[8..12].try_into().unwrap());
        let dw_flags = u32::from_le_bytes(icinfo[12..16].try_into().unwrap());
        println!(
            "[probe]   dwSize=0x{dw_size:x}  fccType={}  fccHandler={}  dwFlags=0x{dw_flags:x}",
            fourcc_label(icinfo_fcc_type),
            fourcc_label(icinfo_fcc_handler),
        );
    }

    // ICDecompressQuery against an RGB24 320×240 default (the
    // codec's "can you produce RGB24 from your wire format?"
    // question).
    let in_bih = bih_input(64, 48, fcc_handler_u32);
    let out_bih = bih_rgb24_out(64, 48);
    match sandbox.ic_decompress_query(hic, &in_bih, Some(&out_bih)) {
        Ok(rc) => {
            println!(
                "[probe] ICDecompressQuery({}→RGB24 64x48) = {} ({})",
                fcc_handler_str,
                rc as i32,
                ic_err_label(rc as i32)
            );
        }
        Err(e) => {
            println!("[probe] ICDecompressQuery failed: {e}");
        }
    }

    let _ = sandbox.ic_close(hic);
    println!("[probe] ICClose done");

    Ok(())
}

/// `vfw.h`: ICMODE_DECOMPRESS.
const ICMODE_DECOMPRESS: u32 = 1;

/// Build an input-side `Bih` from `(width, height, fccHandler)`
/// — the codec's own wire FOURCC. `bit_count = 24` is fine for
/// the round-1 probe sequence; the codec will reject any value
/// it doesn't accept.
pub(crate) fn bih_input(width: u32, height: u32, fcc_handler: u32) -> Bih {
    Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: fcc_handler.to_le_bytes(),
        size_image: width * height * 3 / 2,
        ..Bih::default()
    }
}

/// Build a 24-bit RGB output-side `Bih` for the requested
/// resolution. `compression = 0 = BI_RGB`.
pub(crate) fn bih_rgb24_out(width: u32, height: u32) -> Bih {
    Bih {
        bi_size: 40,
        width: width as i32,
        height: height as i32,
        planes: 1,
        bit_count: 24,
        compression: [0; 4],
        size_image: width * height * 3,
        ..Bih::default()
    }
}

/// Stringify a 4-byte FOURCC into the printable dotted form when
/// every byte is ASCII-printable, otherwise hex.
fn fourcc_label(v: u32) -> String {
    let bytes = v.to_le_bytes();
    if bytes.iter().all(|b| b.is_ascii_graphic()) {
        format!(
            "{}{}{}{} (0x{v:08x})",
            bytes[0] as char, bytes[1] as char, bytes[2] as char, bytes[3] as char,
        )
    } else {
        format!("0x{v:08x}")
    }
}

/// Public test alias so sibling modules can share without
/// duplicating the parser. (The CLI surface uses this from
/// `encode` / `decode` too.)
pub(crate) fn fourcc_to_u32_for_test(s: &str) -> u32 {
    fourcc_to_u32(s)
}

/// Public test alias for the file-extension → FOURCC heuristic.
pub(crate) fn derive_default_fcc_for_test(p: &Path) -> String {
    derive_default_fcc(p)
}

fn fourcc_to_u32(s: &str) -> u32 {
    let mut b = [b' '; 4];
    for (i, c) in s.bytes().take(4).enumerate() {
        b[i] = c;
    }
    u32::from_le_bytes(b)
}

fn derive_default_fcc(p: &Path) -> String {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_uppercase())
        .unwrap_or_default();
    if stem.contains("IR32") {
        "IV31".into()
    } else if stem.contains("IR41") {
        "IV41".into()
    } else if stem.contains("IR50") {
        "IV50".into()
    } else if stem.contains("CVID") || stem.contains("ICCVID") {
        "cvid".into()
    } else {
        "IV31".into()
    }
}

fn format_hex_dump(bytes: &[u8], n: usize) -> String {
    let n = n.min(bytes.len());
    let mut s = String::with_capacity(n * 3);
    for (i, b) in bytes.iter().take(n).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn ic_err_label(rc: i32) -> &'static str {
    match rc {
        0 => "ICERR_OK",
        -1 => "ICERR_UNSUPPORTED",
        -2 => "ICERR_BADFORMAT",
        -100 => "ICERR_BADIMAGE",
        _ => "(other)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_default_fcc_matches_indeo_and_cvid_filenames() {
        assert_eq!(derive_default_fcc(Path::new("IR32_32.DLL")), "IV31");
        assert_eq!(derive_default_fcc(Path::new("ir41_32.ax")), "IV41");
        assert_eq!(derive_default_fcc(Path::new("IR50_32.DLL")), "IV50");
        assert_eq!(derive_default_fcc(Path::new("ICCVID.DLL")), "cvid");
        assert_eq!(derive_default_fcc(Path::new("Unknown.dll")), "IV31");
    }

    #[test]
    fn fourcc_to_u32_is_little_endian() {
        // 'V' 'I' 'D' 'C' => 0x43_44_49_56
        assert_eq!(fourcc_to_u32("VIDC"), 0x43444956);
    }

    #[test]
    fn fourcc_label_prints_printable_bytes() {
        let s = fourcc_label(0x43444956);
        assert!(s.starts_with("VIDC"));
    }

    #[test]
    fn fourcc_label_hex_for_non_printable() {
        let s = fourcc_label(0x0000_0001);
        assert!(s.starts_with("0x"));
    }
}
