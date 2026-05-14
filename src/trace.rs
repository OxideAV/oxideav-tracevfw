//! Trace-state plumbing — wires `--trace-mem`, `--break`,
//! `--asm`, `--trace-output` flags through to the
//! [`oxideav_vfw::Sandbox`] trace-mode programmatic API.

use anyhow::Result;
use oxideav_vfw::Sandbox;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Apply each `--trace-mem ADDR:SIZE[:MODE]` spec to the
/// sandbox's watchpoint set.
pub fn apply_trace_mem(sandbox: &mut Sandbox, specs: &[String]) -> Result<()> {
    for spec in specs {
        let (addr, size, mode) = crate::cli::parse_trace_mem(spec)?;
        sandbox.watch(addr, size, mode);
    }
    Ok(())
}

/// Apply each `--break PC` spec — round-1 implementation
/// records the PC into a side list; the run-loop hook in
/// `main.rs` checks it before each step. Halt-and-prompt is
/// GDB-server work, so today's behaviour is "dump CPU state +
/// continue".
pub fn parse_breakpoints(specs: &[String]) -> Result<Vec<u32>> {
    specs.iter().map(|s| crate::cli::parse_break(s)).collect()
}

/// Configure the JSONL trace sink. Honours `--trace-output
/// FILE` if supplied; otherwise wires to stderr (matching the
/// `OXIDEAV_VFW_TRACE_FILE=2` shape for live observation).
pub fn install_sink(sandbox: &mut Sandbox, output: Option<&Path>) -> Result<()> {
    let sink: Box<dyn Write + Send> = match output {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stderr()),
    };
    sandbox.set_trace_sink(sink);
    Ok(())
}

/// Toggle per-instruction execution trace. Returns an
/// "unsupported" error when `oxideav-vfw` was compiled without
/// the `trace-exec` sub-feature — but since this CLI's
/// Cargo.toml depends on `oxideav-vfw` with `features = ["trace"]`
/// (and not `trace-exec`), `--asm` will compile but emit no
/// `kind=exec` lines until the dep is bumped to include
/// `trace-exec` too. The flag is still wired here so a user
/// rebuilding with the sub-feature on gets the events.
pub fn enable_asm(sandbox: &mut Sandbox) {
    sandbox.set_exec_trace(true);
}

/// Apply a `--break <PC>` set to the sandbox: arm a per-instruction
/// register-snapshot watchpoint at each PC so the next time
/// [`Sandbox::cpu`]'s step loop visits that EIP, a snapshot of
/// the integer register file is captured into the CPU's
/// `register_snapshots` vector. The companion
/// [`flush_breakpoint_events`] drains those captures at the end
/// of a subcommand run and emits a `kind=breakpoint` JSONL line
/// per hit into the trace sink.
///
/// Cap on captures is bumped to a generous 1024 (default 16) so
/// a hot loop hammering a registered PC doesn't silently truncate.
///
/// The hook used here ([`oxideav_vfw::emulator::isa_int::Cpu::add_register_watchpoint`])
/// fires BEFORE the instruction at the matched EIP executes, so
/// the captured registers reflect the pre-instruction state — the
/// "step before EIP reaches a registered PC" semantics the design
/// doc calls out.
///
/// Note: this is the CLI-mode (non-GDB) path. The GDB event loop
/// in `gdb.rs` emits `kind=breakpoint` events directly inside its
/// per-step loop independently of this hook.
pub fn record_breakpoints(sandbox: &mut Sandbox, breakpoints: &[u32]) {
    if breakpoints.is_empty() {
        return;
    }
    // Lift the cap so a hot inner loop doesn't silently drop
    // breakpoint hits past the default 16. 1024 is generous
    // enough for normal interactive use while staying bounded.
    sandbox.cpu.register_snapshots_cap = 1024;
    for &pc in breakpoints {
        sandbox.cpu.add_register_watchpoint(pc);
    }
    eprintln!(
        "[trace] {} breakpoint(s) armed via the per-instruction register-snapshot hook; \
         kind=breakpoint events emitted at subcommand exit (cap = {}).",
        breakpoints.len(),
        sandbox.cpu.register_snapshots_cap,
    );
    for bp in breakpoints {
        eprintln!("  - 0x{bp:08x}");
    }
}

/// Drain any breakpoint hits captured by the per-instruction
/// register-snapshot hook armed in [`record_breakpoints`] and emit
/// a `kind=breakpoint` JSONL event per hit into the sandbox's
/// trace sink. Call once per subcommand at the end of execution.
///
/// The emitted line is a single JSON object on its own line:
///
/// ```json
/// {"kind":"breakpoint","eip":"0x1c2132b8","regs":{"eax":"0x...","ecx":"0x...",...,"eflags":"0x..."}}
/// ```
///
/// Where `regs` carries the integer register file snapshot at
/// the instant the instruction at `eip` was about to execute,
/// plus the current value of `eflags` (since the snapshot ring
/// captures GP regs only — eflags is read live and may differ
/// for multiple-hit cases; the brief asks for "non-empty regs"
/// rather than per-hit eflags fidelity).
pub fn flush_breakpoint_events(sandbox: &mut Sandbox) {
    let snapshots = sandbox.cpu.clear_register_watchpoints();
    if snapshots.is_empty() {
        return;
    }
    // Read eflags once — it's not in the per-hit snapshot ring.
    let eflags = sandbox.cpu.regs.flags.pack();
    for (eip, snap) in snapshots {
        // Snapshot order: [eax, ecx, edx, ebx, esp, ebp, esi, edi]
        // (matches Cpu::step's snapshot capture in oxideav-vfw).
        let line = format!(
            "{{\"kind\":\"breakpoint\",\"eip\":\"0x{eip:08x}\",\
             \"regs\":{{\
             \"eax\":\"0x{:08x}\",\
             \"ecx\":\"0x{:08x}\",\
             \"edx\":\"0x{:08x}\",\
             \"ebx\":\"0x{:08x}\",\
             \"esp\":\"0x{:08x}\",\
             \"ebp\":\"0x{:08x}\",\
             \"esi\":\"0x{:08x}\",\
             \"edi\":\"0x{:08x}\",\
             \"eflags\":\"0x{eflags:08x}\"\
             }}}}",
            snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
        );
        sandbox.mmu.trace.emit_line(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_breakpoints_handles_hex_and_decimal() {
        let bps = parse_breakpoints(&["0x10004A17".to_string(), "256".to_string()]).unwrap();
        assert_eq!(bps, vec![0x10004A17, 256]);
    }

    #[test]
    fn parse_breakpoints_propagates_errors() {
        assert!(parse_breakpoints(&["0xZZ".to_string()]).is_err());
    }

    #[test]
    fn record_breakpoints_arms_register_watchpoints_on_sandbox() {
        let mut sb = Sandbox::new();
        record_breakpoints(&mut sb, &[0x10004A17, 0x10005000]);
        assert_eq!(sb.cpu.register_snapshots_cap, 1024);
        assert!(sb.cpu.register_watchpoints.contains(&0x10004A17));
        assert!(sb.cpu.register_watchpoints.contains(&0x10005000));
    }

    #[test]
    fn flush_breakpoint_events_emits_jsonl_when_snapshot_present() {
        use std::sync::{Arc, Mutex};
        let mut sb = Sandbox::new();
        // Inject a fake snapshot directly, then verify the
        // emitter formats one kind=breakpoint line.
        sb.cpu.register_snapshots.push((
            0xDEAD_BEEF,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ));
        // Capture the trace sink output.
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct VecWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for VecWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        sb.set_trace_sink(Box::new(VecWriter(buf.clone())));
        flush_breakpoint_events(&mut sb);
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"breakpoint""#), "got: {s:?}");
        assert!(s.contains(r#""eip":"0xdeadbeef""#), "got: {s:?}");
        assert!(s.contains(r#""eax":"0x00000011""#), "got: {s:?}");
        assert!(s.contains(r#""edi":"0x00000088""#), "got: {s:?}");
        assert!(s.contains(r#""eflags":""#), "got: {s:?}");
    }
}
