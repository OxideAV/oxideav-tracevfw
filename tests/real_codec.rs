//! Round-6 P1 — real-codec smoke matrix.
//!
//! Gated behind the `integration-real-codec` Cargo feature so the
//! default `cargo test` flow stays self-contained (the rest of the
//! crate's tests build a synthetic minimal-PE32 DLL on the fly).
//! When the feature is on, these tests download the canonical
//! Indeo Video 3 / 4 / 5 VfW codecs from
//! `https://samples.oxideav.org/codecs/windows/IV5PLAY/`, cache the
//! bytes under `target/oxideav-tracevfw-fixtures/<name>`, verify
//! the SHA-256 against the entries in
//! `docs/winmf/windows-codecs.md`, then drive the
//! `oxidetracevfw <fixture> probe --trace-output <jsonl>` end-to-end
//! and assert (a) exit code 0, (b) at least one expected JSONL
//! event line surfaced.
//!
//! Network-unavailable / bad-checksum / write-failure cases skip
//! gracefully (printing `[real-codec] skipped: <reason>` to stderr
//! and `return`-ing) so a CI host without outbound HTTPS still
//! passes — `cargo test --features integration-real-codec` is a
//! best-effort path, not a hard CI gate.
//!
//! Fetch uses the host's `curl` binary (which any modern
//! macOS / Linux / Windows-with-WSL CI host has) instead of pulling
//! a Rust HTTP client into `[dev-dependencies]` — the dependency
//! tree stays minimal and the tests fail closed (skip) when curl
//! is missing.

#![cfg(feature = "integration-real-codec")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One fixture in the real-codec matrix: a remote URL + expected
/// SHA-256 + the JSONL substring we expect to see in the trace
/// output once the probe sequence has run.
struct Fixture {
    /// Pretty name shown in skip messages.
    name: &'static str,
    /// Remote URL on `samples.oxideav.org`. SHA-256 of the body
    /// must match `sha256_hex` exactly.
    url: &'static str,
    /// Expected SHA-256 of the body, as 64 lowercase hex chars.
    /// Pulled from `docs/winmf/windows-codecs.md`.
    sha256_hex: &'static str,
    /// `--fcc-handler` value to pass on the command line so the
    /// `probe` sequence runs an `ICDecompressQuery` for the
    /// codec's natural FOURCC instead of falling back to the
    /// filename heuristic.
    fcc_handler: &'static str,
}

const IR32: Fixture = Fixture {
    name: "IR32_32.DLL (Indeo 3, FOURCC IV31)",
    url: "https://samples.oxideav.org/codecs/windows/IV5PLAY/IR32_32.DLL",
    sha256_hex: "98975f98b7b51d87971facea4458f008ecd566a160f1059290b783e457f8ef18",
    fcc_handler: "IV31",
};

const IR41: Fixture = Fixture {
    name: "IR41_32.AX (Indeo 4, FOURCC IV41)",
    url: "https://samples.oxideav.org/codecs/windows/IV5PLAY/IR41_32.AX",
    sha256_hex: "68a140ba28b5f39d7747326b30c24e8448860bd00b9991f9841a52d7795a2dd3",
    fcc_handler: "IV41",
};

const IR50: Fixture = Fixture {
    name: "IR50_32.DLL (Indeo 5, FOURCC IV50)",
    url: "https://samples.oxideav.org/codecs/windows/IV5PLAY/IR50_32.DLL",
    sha256_hex: "56760e0ea8c8709f4a0c34bee7289a87188aedd8bddfd05f8f62bee2f3f91238",
    fcc_handler: "IV50",
};

/// Resolve the cache directory under `target/oxideav-tracevfw-fixtures/`
/// using the build-time `OUT_DIR` as an anchor (always lives inside
/// the host's target dir). Returns the directory path; caller is
/// responsible for ensuring it exists.
fn fixture_cache_dir() -> PathBuf {
    // env!("OUT_DIR") only works inside build.rs. For tests we
    // walk up from CARGO_MANIFEST_DIR to find a sibling target/
    // — this matches what `cargo test` sets up, including
    // CARGO_TARGET_DIR overrides.
    if let Ok(target) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target).join("oxideav-tracevfw-fixtures");
    }
    // Fall back: `<manifest>/target/oxideav-tracevfw-fixtures`.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .join("target")
        .join("oxideav-tracevfw-fixtures")
}

/// Compute the SHA-256 of `bytes` as 64 lowercase hex chars.
///
/// Implements SHA-256 directly (~80 LOC) so the test crate doesn't
/// need to take a `[dev-dependencies]` on `sha2` purely for fixture
/// verification. Reference: NIST FIPS 180-4 §6.2.
///
/// (We're hashing on the order of 1 MB per fixture, so a pure-Rust
/// scalar implementation is fast enough — the network fetch
/// dominates wall-clock anyway.)
fn sha256_hex(bytes: &[u8]) -> String {
    // Initial hash values (FIPS 180-4 §5.3.3).
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Round constants (FIPS 180-4 §4.2.2).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pad: append 0x80, then zeros, then 64-bit big-endian bit length.
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(bytes.len() + 9 + 63);
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut s = String::with_capacity(64);
    for word in h.iter() {
        s.push_str(&format!("{word:08x}"));
    }
    s
}

/// Fetch `url` into `out_path`, atomically replacing any prior
/// contents. Uses `curl --silent --show-error --fail --location
/// --max-time 60 --output <tmp>` and then renames. Returns
/// `Ok(())` on success, `Err(reason)` on any failure (network
/// down, curl missing, non-200 status, write error).
fn fetch_with_curl(url: &str, out_path: &Path) -> Result<(), String> {
    let parent = out_path.parent().ok_or("no parent dir")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create_dir_all: {e}"))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        out_path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let status = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "60",
            "--output",
        ])
        .arg(&tmp)
        .arg(url)
        .status()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("curl failed: status {status:?}"));
    }
    std::fs::rename(&tmp, out_path).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

/// Resolve a fixture: return the path on disk if the cache is
/// already populated AND its SHA-256 matches; otherwise fetch it
/// fresh and verify. Returns `Err(reason)` on any failure (which
/// the caller treats as a graceful skip, not a test failure).
fn resolve_fixture(f: &Fixture) -> Result<PathBuf, String> {
    let dir = fixture_cache_dir();
    let local = dir.join(
        f.url
            .rsplit('/')
            .next()
            .ok_or("malformed url — no filename")?,
    );

    // Check existing cache first.
    if local.exists() {
        let mut buf = Vec::new();
        if let Ok(mut fp) = std::fs::File::open(&local) {
            if fp.read_to_end(&mut buf).is_ok() {
                let got = sha256_hex(&buf);
                if got == f.sha256_hex {
                    return Ok(local);
                }
                // Stale / partial cache entry: fall through and refetch.
                eprintln!(
                    "[real-codec] cached {} has sha {} (expected {}), refetching",
                    local.display(),
                    got,
                    f.sha256_hex
                );
            }
        }
    }

    // Fetch.
    fetch_with_curl(f.url, &local).map_err(|e| format!("fetch {}: {e}", f.url))?;

    // Verify.
    let mut buf = Vec::new();
    let mut fp =
        std::fs::File::open(&local).map_err(|e| format!("open {}: {e}", local.display()))?;
    fp.read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", local.display()))?;
    let got = sha256_hex(&buf);
    if got != f.sha256_hex {
        let _ = std::fs::remove_file(&local);
        return Err(format!(
            "sha256 mismatch for {}: got {}, expected {}",
            f.url, got, f.sha256_hex
        ));
    }
    Ok(local)
}

/// Drive `oxidetracevfw <fixture> --fcc-handler <fcc>
/// --trace-output <jsonl> probe` end-to-end. Asserts:
///   1. exit status is success,
///   2. stdout mentions the probe completion lines,
///   3. the JSONL trace file exists and contains at least one
///      `kind=` event line — the basic sanity check that the
///      sandbox actually executed something instead of failing
///      at PE load.
///
/// Skips gracefully when the fixture can't be resolved (network
/// down, curl missing, sha mismatch).
fn run_probe_against(f: &Fixture) {
    let dll = match resolve_fixture(f) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("[real-codec] skipped {} ({reason})", f.name);
            return;
        }
    };

    // Pick a unique trace-output path inside the same cache dir.
    let trace_path = fixture_cache_dir().join(format!(
        ".trace-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    // Touch so the binary's File::create overwrites cleanly even
    // if a stale file remains from a prior crashed invocation.
    if let Err(e) = std::fs::File::create(&trace_path).and_then(|mut f| f.write_all(b"")) {
        eprintln!(
            "[real-codec] skipped {} (cannot create trace file {}: {e})",
            f.name,
            trace_path.display()
        );
        return;
    }

    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = match Command::new(bin)
        .arg(&dll)
        .arg("--fcc-handler")
        .arg(f.fcc_handler)
        .arg("--trace-output")
        .arg(&trace_path)
        .arg("probe")
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_file(&trace_path);
            eprintln!("[real-codec] skipped {} (spawn failed: {e})", f.name);
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{} probe failed: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        f.name,
        out.status
    );
    // The probe always emits these markers regardless of whether
    // ICOpen / ICDecompressQuery succeed — they prove load + DllMain
    // ran cleanly.
    assert!(
        stdout.contains("[probe] loaded") && stdout.contains("[probe] DllMain returned"),
        "{} probe missing expected output:\n{stdout}",
        f.name
    );

    // The trace file must contain at least one JSONL event. The
    // probe sequence's `ic_open` + `ic_get_info` + the codec's
    // own DllMain + DriverProc activity always touches at least
    // one `kind=win32_call` (kernel32 / user32 / GetProcAddress
    // type lookups) so we don't need to hard-pin a specific kind.
    let trace_bytes = std::fs::read(&trace_path)
        .unwrap_or_else(|e| panic!("read trace output {}: {e}", trace_path.display()));
    let trace_str = String::from_utf8_lossy(&trace_bytes);
    let _ = std::fs::remove_file(&trace_path); // best-effort cleanup

    assert!(
        trace_str.contains(r#""kind":"#),
        "{} trace output had no JSONL `kind=` events:\n{trace_str}",
        f.name
    );
}

#[test]
fn ir32_indeo3_probe_drives_real_codec() {
    run_probe_against(&IR32);
}

#[test]
fn ir41_indeo4_probe_drives_real_codec() {
    run_probe_against(&IR41);
}

#[test]
fn ir50_indeo5_probe_drives_real_codec() {
    run_probe_against(&IR50);
}

/// Sanity: our standalone SHA-256 computes the FIPS 180-4 sample
/// "abc" digest correctly. Guards against subtle bit-twiddling
/// regressions in the hand-rolled implementation.
#[test]
fn sha256_hex_matches_fips_180_4_abc_vector() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}
