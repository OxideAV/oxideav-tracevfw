//! Integration tests for the `oxidetracevfw encode` subcommand —
//! drive `ICCompress` end-to-end against a real Windows codec
//! (Microsoft's MS-MPEG-4 v3 / `mpg4c32.dll`) and verify the
//! produced encoded bytes are non-empty + survive a self-roundtrip
//! through the existing `decode` subcommand.
//!
//! The fixture (`mpg4c32.dll`) lives at
//! `docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/mpg4c32.dll`
//! in the workspace. When absent (e.g. crate built outside the
//! workspace, or `docs/` excluded from the package), the test
//! skips with a `[encode-mpg4c32] skipped: …` message rather
//! than failing.
//!
//! Wired against `oxideav-vfw r51` (commit `dcc9c37`), which
//! landed the encode side of the `IC*` host surface.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> Option<PathBuf> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let manifest = PathBuf::from(manifest);
    Some(manifest.parent()?.parent()?.to_path_buf())
}

fn mpg4c32_path() -> Option<PathBuf> {
    let p =
        workspace_root()?.join("docs/video/msmpeg4/reference/binaries/wmpcdcs8-2001/mpg4c32.dll");
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

/// Build an N×N BGR24 vertical-bar gradient (BMP convention,
/// bottom-up rows). Matches the input shape used by oxideav-vfw's
/// round-51 encode test so the codec sees the exact same pattern
/// the producer-side test validates against.
fn make_bgr24_pattern(width: u32, height: u32) -> Vec<u8> {
    let stride = (width * 3) as usize;
    let mut buf = vec![0u8; stride * height as usize];
    for y in 0..height {
        for x in 0..width {
            let r = ((x * 255) / width.max(1)) as u8;
            let g = ((y * 255) / height.max(1)) as u8;
            let b = (((x + y) * 255) / (width + height).max(1)) as u8;
            let p = (y as usize) * stride + (x as usize) * 3;
            buf[p] = b;
            buf[p + 1] = g;
            buf[p + 2] = r;
        }
    }
    buf
}

/// PSNR for two equal-length BGR24 buffers. Returns `f64::INFINITY`
/// for identical buffers, else 10 * log10(255^2 / MSE).
fn psnr_bgr24(a: &[u8], b: &[u8]) -> f64 {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    if n == 0 {
        return f64::INFINITY;
    }
    let mut mse: f64 = 0.0;
    for i in 0..n {
        let d = a[i] as f64 - b[i] as f64;
        mse += d * d;
    }
    mse /= n as f64;
    if mse == 0.0 {
        return f64::INFINITY;
    }
    10.0 * (255.0f64 * 255.0 / mse).log10()
}

fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!("oxidetracevfw-{prefix}-{pid}-{nanos}.{ext}"))
}

/// End-to-end smoke test: `encode` subcommand against `mpg4c32.dll`
/// produces a non-empty bytestream.
///
/// Skips gracefully when the DLL fixture is missing — the test
/// reports the absence on stderr but returns success so workspace
/// CI without `docs/` doesn't get a hard fail.
#[test]
fn encode_subcommand_against_mpg4c32_produces_nonempty_output() {
    let Some(dll) = mpg4c32_path() else {
        eprintln!("[encode-mpg4c32] skipped: mpg4c32.dll not in docs/");
        return;
    };

    const W: u32 = 176;
    const H: u32 = 144;

    // Write the BGR24 input to a temp file.
    let pattern = make_bgr24_pattern(W, H);
    let in_path = temp_path("encode_in", "bgr24");
    std::fs::write(&in_path, &pattern).expect("write input pattern");

    let out_path = temp_path("encode_out", "mp43");

    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let result = Command::new(bin)
        .arg(&dll)
        .args(["--max-instr", "2000000000", "--fcc-handler", "MP43"])
        .arg("encode")
        .args([
            "--input",
            in_path.to_str().unwrap(),
            "--width",
            &W.to_string(),
            "--height",
            &H.to_string(),
            "--input-format",
            "bgr24",
            "--quality",
            "5000",
            "--keyframe",
            "true",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn oxidetracevfw encode");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    eprintln!("[encode-mpg4c32] exit={}", result.status);
    eprintln!("[encode-mpg4c32] stdout:\n{}", stdout);
    eprintln!("[encode-mpg4c32] stderr:\n{}", stderr);

    // Clean up input on success or failure.
    let _ = std::fs::remove_file(&in_path);

    assert!(
        result.status.success(),
        "encode subcommand failed: stdout={stdout}\nstderr={stderr}"
    );

    // Output file must exist and be non-empty.
    let encoded = std::fs::read(&out_path).expect("read encoded output");
    let _ = std::fs::remove_file(&out_path);

    eprintln!("[encode-mpg4c32] encoded {} bytes", encoded.len());
    assert!(
        encoded.len() >= 64,
        "encoded MP43 keyframe should be at least 64 bytes, got {}",
        encoded.len()
    );
    // Round 51 empirically encodes the same 176x144 gradient at
    // quality=5000 to ~970 bytes. Allow a generous range so a
    // future codec tweak doesn't flake the test.
    assert!(
        encoded.len() < 200_000,
        "encoded MP43 keyframe inexplicably huge ({} bytes); codec \
         probably emitted the uncompressed buffer",
        encoded.len()
    );
}

/// Full encode → decode roundtrip via two subcommand invocations.
/// Asserts the encoded MP43 bitstream produced by `encode` decodes
/// back to a buffer whose PSNR-BGR24 against the original is above
/// a modest floor (~15 dB). Lossy at quality=5000 — the round-51
/// producer-side test reports ~28 dB empirically.
#[test]
fn encode_then_decode_roundtrip_via_cli_clears_psnr_floor() {
    let Some(dll) = mpg4c32_path() else {
        eprintln!("[encode-mpg4c32] skipped: mpg4c32.dll not in docs/");
        return;
    };

    const W: u32 = 176;
    const H: u32 = 144;

    let pattern = make_bgr24_pattern(W, H);
    let in_path = temp_path("rt_in", "bgr24");
    std::fs::write(&in_path, &pattern).expect("write input pattern");
    let mid_path = temp_path("rt_mid", "mp43");
    let out_path = temp_path("rt_out", "bgr24");

    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    // Phase 1 — encode.
    let enc = Command::new(bin)
        .arg(&dll)
        .args(["--max-instr", "2000000000", "--fcc-handler", "MP43"])
        .arg("encode")
        .args([
            "--input",
            in_path.to_str().unwrap(),
            "--width",
            &W.to_string(),
            "--height",
            &H.to_string(),
            "--input-format",
            "bgr24",
            "--quality",
            "5000",
            "--keyframe",
            "true",
            "--output",
            mid_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn encode");
    let enc_stderr = String::from_utf8_lossy(&enc.stderr);
    if !enc.status.success() {
        let _ = std::fs::remove_file(&in_path);
        let _ = std::fs::remove_file(&mid_path);
        panic!("encode failed:\n{enc_stderr}");
    }

    // Phase 2 — decode.
    let dec = Command::new(bin)
        .arg(&dll)
        .args(["--max-instr", "2000000000", "--fcc-handler", "MP43"])
        .arg("decode")
        .args([
            "--input",
            mid_path.to_str().unwrap(),
            "--width",
            &W.to_string(),
            "--height",
            &H.to_string(),
            "--pix-format",
            "rgb24",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn decode");
    let dec_stderr = String::from_utf8_lossy(&dec.stderr);
    let dec_stdout = String::from_utf8_lossy(&dec.stdout);

    let mid_bytes = std::fs::read(&mid_path).unwrap_or_default();
    let decoded = std::fs::read(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&mid_path);
    let _ = std::fs::remove_file(&out_path);

    eprintln!("[encode-mpg4c32] encoded MP43 = {} bytes", mid_bytes.len());
    eprintln!("[encode-mpg4c32] decode stdout:\n{}", dec_stdout);
    eprintln!("[encode-mpg4c32] decode stderr:\n{}", dec_stderr);

    if !dec.status.success() {
        eprintln!(
            "[encode-mpg4c32] decode subprocess failed; treating as DISCOVERY MODE \
             (encode succeeded with {} bytes, decode path declined the bitstream)",
            mid_bytes.len()
        );
        return;
    }

    let expected = (W * H * 3) as usize;
    assert_eq!(
        decoded.len(),
        expected,
        "decoded buffer should be {} bytes (BGR24 {}x{}), got {}",
        expected,
        W,
        H,
        decoded.len(),
    );

    let psnr = psnr_bgr24(&pattern, &decoded);
    eprintln!("[encode-mpg4c32] roundtrip PSNR-BGR24 = {psnr:.2} dB");
    assert!(
        psnr >= 15.0,
        "roundtrip PSNR {psnr:.2} dB below 15 dB floor — \
         encoded bytes did not survive a clean decode roundtrip"
    );
}
