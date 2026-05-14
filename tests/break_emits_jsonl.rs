//! Integration test for the `--break PC` (CLI mode, no `--gdb`)
//! path — verifies that registered breakpoints DO surface as
//! `kind=breakpoint` JSONL events into the trace sink, not just
//! the stderr "registered" echo.
//!
//! Auditor flag (P1): before this round, `--break PC` outside
//! `--gdb` was a no-op against the trace sink; the operator had
//! to attach via `--gdb HOST:PORT` to get the same evidence.
//! The fix uses the per-instruction register-snapshot hook
//! (`Cpu::add_register_watchpoint`) to capture the integer
//! register file at the matched EIP, then drains the snapshots
//! at subcommand exit and emits one `kind=breakpoint` line per
//! hit.
//!
//! Synth-DLL strategy: the round-1 minimal-PE DLL exports a
//! single 3-byte `DllMain` (`C2 0C 00` = `RET 12`) at VA
//! `0x10001000`. Setting `--break 0x10001000` and running the
//! `probe` subcommand should fire the snapshot hook on the FIRST
//! step — `call_dll_main` jumps to that address; the `Cpu::step`
//! entry checks `register_watchpoints.contains(0x10001000)` and
//! captures the snapshot.

use std::process::Command;

/// Build a temp file containing the synthetic minimal DLL bytes.
/// Mirrors the helper in `tests/cli.rs`.
fn write_synth_dll() -> tempfile_path::TempPath {
    let bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
    tempfile_path::write_temp("synth_dll_break", "dll", &bytes)
}

#[test]
fn break_pc_emits_kind_breakpoint_into_trace_output_in_cli_mode() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    // Allocate a unique trace-output file.
    let trace_path = tempfile_path::write_temp("break_cli_trace", "jsonl", b"");

    // The synth DLL's `DllMain` lives at the PE entry point —
    // image base `0x1000_0000` + `AddressOfEntryPoint = 0x1000`,
    // so VA `0x10001000`. The first instruction the CPU executes
    // when `call_dll_main` invokes it is at exactly that EIP.
    const BP_PC: u32 = 0x1000_1000;

    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--break")
        .arg(format!("0x{BP_PC:08X}"))
        .arg("--trace-output")
        .arg(trace_path.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw probe --break");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit failure: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );

    // The probe path emits its own diagnostics on stdout; we
    // expect the trace JSONL on disk.
    let bytes = std::fs::read(trace_path.path()).expect("read trace output");
    let s = String::from_utf8_lossy(&bytes);
    assert!(
        !s.is_empty(),
        "expected non-empty trace output; stderr was:\n{stderr}"
    );

    // Find at least one kind=breakpoint event with the matching
    // eip and a non-empty regs map.
    let mut found = false;
    let pc_str = format!("0x{BP_PC:08x}");
    for line in s.lines() {
        if !line.contains(r#""kind":"breakpoint""#) {
            continue;
        }
        if !line.contains(&pc_str) {
            continue;
        }
        // regs map must be non-empty: the emitted shape always
        // includes eax/ecx/edx/ebx/esp/ebp/esi/edi/eflags, so
        // the regs JSON object will contain at least one of
        // these key strings when populated.
        assert!(
            line.contains(r#""eax":""#)
                && line.contains(r#""edi":""#)
                && line.contains(r#""eflags":""#),
            "kind=breakpoint line missing register snapshot fields: {line}"
        );
        found = true;
        break;
    }
    assert!(
        found,
        "expected a kind=breakpoint event with eip={pc_str} in trace output, got:\n{s}\n\
         (stderr: {stderr})"
    );
}

/// Sanity check: with no `--break PC`, the trace file contains
/// no `kind=breakpoint` lines (the hook is dormant and the drain
/// emits nothing).
#[test]
fn no_break_flag_emits_no_kind_breakpoint_events() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    let trace_path = tempfile_path::write_temp("no_break_cli_trace", "jsonl", b"");

    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--trace-output")
        .arg(trace_path.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw probe (no --break)");
    assert!(out.status.success(), "probe exit failure: {:?}", out.status);

    let bytes = std::fs::read(trace_path.path()).unwrap_or_default();
    let s = String::from_utf8_lossy(&bytes);
    assert!(
        !s.contains(r#""kind":"breakpoint""#),
        "no --break PC was passed yet trace file contains a kind=breakpoint event:\n{s}"
    );
}

// Required so the in-tree tempfile helper compiles standalone.
// (We use a tiny inline shim mirroring the one used by `cli.rs`
// — kept in-tree per workspace policy that forbids cross-crate
// dev-dependencies.)
mod tempfile_path {
    use std::fs;
    use std::path::{Path, PathBuf};

    pub struct TempPath {
        path: PathBuf,
    }
    impl TempPath {
        pub fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    pub fn write_temp(prefix: &str, ext: &str, contents: &[u8]) -> TempPath {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("oxidetracevfw-{prefix}-{pid}-{nanos}.{ext}"));
        let mut f = fs::File::create(&path).expect("create temp file");
        use std::io::Write;
        f.write_all(contents).expect("write temp contents");
        TempPath { path }
    }
}
