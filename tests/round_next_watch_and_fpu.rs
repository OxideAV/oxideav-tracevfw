//! Integration tests for the round-NEXT Auditor enhancements:
//! `--watch ADDR[,LEN]` memory watchpoints and the
//! `--break-include-fpu` switch on `--break PC`.
//!
//! Both tests drive the binary against the synthetic minimal-PE32
//! DLL (`oxideav_vfw::pe::test_image::build_minimal_dll`) so no
//! codec fixtures are pulled into the test surface.

use std::process::Command;

/// Synth DLL — single `DllMain` at VA 0x10001000 that's just
/// `ret 12` (C2 0C 00). The first thing `call_dll_main` does
/// after jumping to it is `pop` the return address from
/// `[esp]`, which is a `mem_read` the MMU's trace probe will
/// fire on.
fn write_synth_dll() -> tempfile_path::TempPath {
    let bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
    tempfile_path::write_temp("synth_dll_round_next", "dll", &bytes)
}

/// VA of the stack slot that `ret 12` pops on the very first
/// instruction. The runtime sets `esp = STACK_TOP - 0x100`
/// (=`0x9010_0000 - 0x100`), then `call_guest` pushes three
/// 4-byte stdcall args (hModule, fdwReason, lpvReserved) plus
/// `RET_SENTINEL` onto the stack, so when control reaches
/// `DllMain` the value being popped sits four dwords below the
/// fresh-stack baseline.
///
/// `STACK_TOP - 0x100 - 4*4 = 0x900F_FEF0`. The `ret 12` then
/// reads that dword.
const POP_ADDR: u32 = 0x900F_FEF0;

#[test]
fn watch_flag_emits_kind_mem_watch_for_stack_pop() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    let trace_path = tempfile_path::write_temp("watch_trace", "jsonl", b"");

    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--watch")
        .arg(format!("0x{POP_ADDR:08X},4"))
        .arg("--trace-output")
        .arg(trace_path.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw probe --watch");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit failure: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );

    let bytes = std::fs::read(trace_path.path()).expect("read trace output");
    let s = String::from_utf8_lossy(&bytes);
    assert!(
        !s.is_empty(),
        "expected non-empty trace output; stderr:\n{stderr}"
    );

    // The stack slot at POP_ADDR is touched twice during
    // `call_dll_main`: once by a `push32` from `call_guest`
    // (write, eip=0 — pre-run setup) when staging the
    // RET_SENTINEL onto the stack, and once by the guest
    // `ret 12` (read) when the CPU pops it back. We accept
    // either as a passing observation, but at minimum:
    //   * one mem_watch line is on disk
    //   * with op ∈ {read,write}
    //   * with the watched addr in the addr field
    //   * with a populated value + eip
    //   * with size=4 (the dword pop / push width)
    let mut found_write = false;
    let mut found_read = false;
    let addr_str = format!("0x{POP_ADDR:08x}");
    for line in s.lines() {
        if !line.contains(r#""kind":"mem_watch""#) {
            continue;
        }
        if !line.contains(&addr_str) {
            continue;
        }
        assert!(
            line.contains(r#""op":""#),
            "missing op field in mem_watch line: {line}"
        );
        assert!(
            line.contains(r#""value":""#),
            "missing value field in mem_watch line: {line}"
        );
        assert!(
            line.contains(r#""eip":""#),
            "missing eip field in mem_watch line: {line}"
        );
        if line.contains(r#""op":"read""#) {
            found_read = true;
        } else if line.contains(r#""op":"write""#) {
            found_write = true;
        }
    }
    assert!(
        found_write || found_read,
        "expected at least one kind=mem_watch event with addr={addr_str}; got:\n{s}\n\
         (stderr: {stderr})"
    );

    // Sanity check: the legacy `kind=mem_read` / `kind=mem_write`
    // shape MUST NOT appear for the same addr — the sink wrapper
    // transformed every matched event into kind=mem_watch.
    for line in s.lines() {
        if (line.contains(r#""kind":"mem_read""#) || line.contains(r#""kind":"mem_write""#))
            && line.contains(&addr_str)
        {
            panic!(
                "legacy kind=mem_read/mem_write line for watched addr {addr_str} should have \
                 been rewritten by the sink wrapper:\n{line}"
            );
        }
    }
}

#[test]
fn watch_flag_default_len_is_four() {
    // Same shape as above but omitting the `,LEN` suffix —
    // expect identical behaviour because the default (4) covers
    // the same dword.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    let trace_path = tempfile_path::write_temp("watch_default_trace", "jsonl", b"");

    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--watch")
        .arg(format!("0x{POP_ADDR:08X}"))
        .arg("--trace-output")
        .arg(trace_path.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw probe --watch (default len)");
    assert!(
        out.status.success(),
        "exit failure: {:?}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = std::fs::read(trace_path.path()).expect("read trace");
    let s = String::from_utf8_lossy(&bytes);
    let addr_str = format!("0x{POP_ADDR:08x}");
    assert!(
        s.lines()
            .any(|l| l.contains(r#""kind":"mem_watch""#) && l.contains(&addr_str)),
        "expected mem_watch event with default len; got:\n{s}"
    );
}

#[test]
fn break_include_fpu_appends_fpu_field_to_breakpoint_event() {
    // The synth DLL's `DllMain` lives at VA 0x10001000; the
    // first instruction the CPU executes when `call_dll_main`
    // invokes it is at exactly that EIP. Setting `--break
    // 0x10001000 --break-include-fpu` should capture an
    // integer-register snapshot AND append a populated `fpu`
    // sub-object (st[0..7], mm[0..7], tag, status, control) at
    // drain time.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    let trace_path = tempfile_path::write_temp("break_fpu_trace", "jsonl", b"");

    const BP_PC: u32 = 0x1000_1000;
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--break")
        .arg(format!("0x{BP_PC:08X}"))
        .arg("--break-include-fpu")
        .arg("--trace-output")
        .arg(trace_path.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw probe --break --break-include-fpu");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit failure: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status,
    );

    let bytes = std::fs::read(trace_path.path()).expect("read trace");
    let s = String::from_utf8_lossy(&bytes);

    let pc_str = format!("0x{BP_PC:08x}");
    let mut found = false;
    for line in s.lines() {
        if !line.contains(r#""kind":"breakpoint""#) || !line.contains(&pc_str) {
            continue;
        }
        // Without `--break-include-fpu` the line would not
        // contain `"fpu":{` at all — the round-NEXT switch
        // is opt-in.
        assert!(
            line.contains(r#""fpu":{"#),
            "expected fpu sub-object in breakpoint line, got: {line}"
        );
        // The fpu sub-object must include all the documented
        // sub-fields: st (array of 8 hex doubles), mm (array
        // of 8 hex u64), tag, status, control.
        assert!(line.contains(r#""st":["#), "missing st[] in {line}");
        assert!(line.contains(r#""mm":["#), "missing mm[] in {line}");
        assert!(line.contains(r#""tag":""#), "missing tag in {line}");
        assert!(line.contains(r#""status":""#), "missing status in {line}");
        assert!(line.contains(r#""control":""#), "missing control in {line}");
        // The integer regs must still be present — the FPU
        // field is additive, not a replacement.
        assert!(line.contains(r#""eax":""#), "missing eax in {line}");
        assert!(line.contains(r#""edi":""#), "missing edi in {line}");
        assert!(line.contains(r#""eflags":""#), "missing eflags in {line}");
        found = true;
        break;
    }
    assert!(
        found,
        "expected kind=breakpoint with fpu field at eip={pc_str}; got:\n{s}\n\
         (stderr: {stderr})"
    );
}

#[test]
fn break_without_include_fpu_keeps_gp_only_shape() {
    // Sanity check that the new flag is opt-in: WITHOUT
    // `--break-include-fpu`, the emitted breakpoint line stays
    // GP-only (no `fpu` sub-object), matching the round-77e061d
    // shape exactly.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    let trace_path = tempfile_path::write_temp("break_no_fpu_trace", "jsonl", b"");

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

    assert!(
        out.status.success(),
        "exit failure: {:?}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let bytes = std::fs::read(trace_path.path()).unwrap_or_default();
    let s = String::from_utf8_lossy(&bytes);
    let pc_str = format!("0x{BP_PC:08x}");
    let mut found = false;
    for line in s.lines() {
        if !line.contains(r#""kind":"breakpoint""#) || !line.contains(&pc_str) {
            continue;
        }
        assert!(
            !line.contains(r#""fpu":"#),
            "default mode should not include fpu field, got: {line}"
        );
        found = true;
        break;
    }
    assert!(found, "expected a breakpoint line; got:\n{s}");
}

// In-tree helper mirroring the shim in tests/cli.rs / tests/break_emits_jsonl.rs
// (workspace policy forbids cross-crate dev-dependencies, hence
// the in-line tempfile shim).
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
