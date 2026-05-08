//! Integration tests for the `oxidetracevfw` CLI binary.
//!
//! Drives the binary via `Command::new(env!("CARGO_BIN_EXE_oxidetracevfw"))`
//! against a synthetic minimal-PE32 DLL — generated on the fly
//! by `oxideav_vfw::pe::test_image::build_minimal_dll` — so the
//! tests don't pull codec binaries into the test surface.
//! Real-codec smoke (e.g. `IR32_32.DLL probe`) is documented in
//! the README and verifiable by the operator with a staged DLL.

use std::io::Write;
use std::process::Command;

/// Build a temp file containing the synthetic minimal DLL bytes
/// the round-1 `m1_load_dll_main` test uses.
fn write_synth_dll() -> tempfile_path::TempPath {
    let bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
    tempfile_path::write_temp("synth_dll", "dll", &bytes)
}

#[test]
fn probe_subcommand_against_synth_dll_succeeds() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit failure: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("[probe] loaded"),
        "expected probe output, got: {stdout:?}"
    );
    assert!(
        stdout.contains("[probe] DllMain returned"),
        "expected DllMain output, got: {stdout:?}"
    );
}

#[test]
fn help_lists_subcommands() {
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("probe"), "got: {stdout}");
    assert!(stdout.contains("encode"), "got: {stdout}");
    assert!(stdout.contains("decode"), "got: {stdout}");
}

#[test]
fn gdb_flag_returns_round_2_error() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:1234")
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("round-2"), "stderr: {stderr}");
}

#[test]
fn trace_mem_flag_parses() {
    // Just verify the CLI accepts the flag without erroring on
    // parse — actual emission happens once a guest store hits
    // the watched range. Probe sequence's DllMain doesn't touch
    // the synthetic 0x12340000 region, so this only confirms
    // the parser path.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--trace-mem")
        .arg("0x12340000:16:rw")
        .arg("probe")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn break_flag_echoes_count_to_stderr() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--break")
        .arg("0x10004A17")
        .arg("probe")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("breakpoint(s) registered"),
        "expected breakpoint registration log on stderr, got: {stderr:?}"
    );
}

/// Tiny helper namespace — temp-file path with auto-delete on
/// drop. We avoid pulling `tempfile` as a dev-dep purely to
/// keep this crate's dependency tree light; this is ~30 LOC.
mod tempfile_path {
    use std::path::{Path, PathBuf};

    pub struct TempPath(PathBuf);

    impl TempPath {
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    pub fn write_temp(prefix: &str, ext: &str, bytes: &[u8]) -> TempPath {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let suffix = format!("{pid}-{n}-{nanos}");
        let p = dir.join(format!("{prefix}-{suffix}.{ext}"));
        let mut f = std::fs::File::create(&p).expect("create temp");
        use super::Write;
        f.write_all(bytes).expect("write temp");
        TempPath(p)
    }
}
