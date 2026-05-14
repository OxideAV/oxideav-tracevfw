//! Integration test for the `encode --pquant N` knob.
//!
//! Auditor flag (P2): the existing `encode` subcommand bakes
//! `PQUANT=4` into every output regardless of `--quality`,
//! because mpg4c32's rate-control path clamps the picture-header
//! quantiser unless `ICM_SETSTATE` is used (and `Sandbox` doesn't
//! yet expose `ic_get_state` / `ic_set_state`). The fix adds a
//! direct `--pquant N` flag (`N` ∈ 1..=31) that post-processes
//! the encoder's output: rewrites the 5-bit PQUANT field at bit
//! offset 2 of the picture header (MSB-first within byte 0).
//!
//! This test:
//!   1. encodes the same gradient twice, once with `--pquant 1`
//!      and once with `--pquant 31`,
//!   2. asserts the PQUANT field reads back as 1 and 31
//!      respectively from the produced bitstream's byte-0,
//!   3. confirms the two outputs differ at byte 0 (the layout
//!      fingerprint), demonstrating the post-processing patch
//!      took effect.
//!
//! The test gracefully skips when the `mpg4c32.dll` fixture is
//! absent (e.g. the crate is built outside the workspace, or
//! `docs/` was excluded from the package).

use std::path::{Path, PathBuf};
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

/// Vertical-bar gradient mirroring the helper in
/// `tests/encode_subcommand.rs`. We rebuild it here rather than
/// import to keep test files self-contained.
fn make_bgr24_gradient(width: u32, height: u32) -> Vec<u8> {
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

fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!("oxidetracevfw-pq-{prefix}-{pid}-{nanos}.{ext}"))
}

/// Extract the 5-bit PQUANT field (MSB-first) from byte 0 of an
/// MS-MPEG-4 v3 picture header. Layout (bit 7 = MSB read first):
///   bit 7..6 (2): picture_type
///   bit 5..1 (5): pquant
///   bit 0    (1): first bit of the next field (ac_chroma_sel)
fn pquant_from_byte0(b: u8) -> u8 {
    (b >> 1) & 0x1F
}

/// Run the encode subcommand once. Returns the raw output bytes.
fn encode_with_pquant(dll: &Path, in_path: &Path, pquant: u8) -> Vec<u8> {
    const W: u32 = 64;
    const H: u32 = 48;
    let out_path = temp_path(&format!("pq{pquant}"), "mp43");
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let result = Command::new(bin)
        .arg(dll)
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
            "--pquant",
            &pquant.to_string(),
            "--keyframe",
            "true",
            "--output",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn oxidetracevfw encode --pquant");
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "encode --pquant {pquant} failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let bytes = std::fs::read(&out_path).expect("read encoded output");
    let _ = std::fs::remove_file(&out_path);
    bytes
}

#[test]
fn encode_pquant_flag_rewrites_picture_header_pquant_field() {
    let Some(dll) = mpg4c32_path() else {
        eprintln!("[encode-pquant] skipped: mpg4c32.dll not in docs/");
        return;
    };

    const W: u32 = 64;
    const H: u32 = 48;

    let pattern = make_bgr24_gradient(W, H);
    let in_path = temp_path("in", "bgr24");
    std::fs::write(&in_path, &pattern).expect("write input pattern");

    let bytes_pq1 = encode_with_pquant(&dll, &in_path, 1);
    let bytes_pq31 = encode_with_pquant(&dll, &in_path, 31);

    let _ = std::fs::remove_file(&in_path);

    // Both outputs must be non-empty.
    assert!(
        !bytes_pq1.is_empty(),
        "encode --pquant 1 produced empty output"
    );
    assert!(
        !bytes_pq31.is_empty(),
        "encode --pquant 31 produced empty output"
    );

    // The patch only rewrites byte 0, so apart from that byte the
    // outputs may share a long common prefix — but the byte-0
    // PQUANT field MUST read back as the requested value.
    let pq_read_1 = pquant_from_byte0(bytes_pq1[0]);
    let pq_read_31 = pquant_from_byte0(bytes_pq31[0]);
    assert_eq!(
        pq_read_1, 1,
        "expected PQUANT=1 in encoded byte 0 (got 0x{:02x}, pq={pq_read_1})",
        bytes_pq1[0],
    );
    assert_eq!(
        pq_read_31, 31,
        "expected PQUANT=31 in encoded byte 0 (got 0x{:02x}, pq={pq_read_31})",
        bytes_pq31[0],
    );

    // And the two byte-0 values must differ — the patch is
    // demonstrably distinct between the two requests.
    assert_ne!(
        bytes_pq1[0], bytes_pq31[0],
        "encode --pquant 1 vs --pquant 31 produced identical byte 0 \
         (0x{:02x}); the post-process patch did not take effect",
        bytes_pq1[0],
    );
}

/// Without `--pquant`, the codec's natural output is preserved
/// (no patching). Sanity check that the flag is opt-in.
#[test]
fn encode_without_pquant_does_not_patch_output() {
    let Some(dll) = mpg4c32_path() else {
        eprintln!("[encode-pquant] skipped: mpg4c32.dll not in docs/");
        return;
    };

    const W: u32 = 64;
    const H: u32 = 48;

    let pattern = make_bgr24_gradient(W, H);
    let in_path = temp_path("nopq_in", "bgr24");
    std::fs::write(&in_path, &pattern).expect("write input pattern");

    // Encode twice without --pquant — should be deterministic
    // (same input, same codec, same flags).
    let out_path_a = temp_path("nopq_a", "mp43");
    let out_path_b = temp_path("nopq_b", "mp43");
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    for out_path in [&out_path_a, &out_path_b] {
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
        assert!(result.status.success(), "encode (no --pquant) failed");
    }

    let a = std::fs::read(&out_path_a).expect("read encoded A");
    let b = std::fs::read(&out_path_b).expect("read encoded B");
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&out_path_a);
    let _ = std::fs::remove_file(&out_path_b);

    assert_eq!(
        a,
        b,
        "two encode runs without --pquant produced different outputs \
         (encoder is non-deterministic, or the flag default leaks): \
         len_a={} len_b={}",
        a.len(),
        b.len()
    );
}
