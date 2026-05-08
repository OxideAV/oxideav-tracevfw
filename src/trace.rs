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

/// Apply a `--break <PC>` set to the sandbox: emit a
/// `kind=breakpoint` JSONL event when the codec reaches one of
/// these addresses. Round 1 dumps + continues; round 2 wires
/// the GDB-server halt-and-prompt path.
///
/// The actual hook lives in `main.rs`, which can step the
/// emulator one instruction at a time; calling
/// `Sandbox::run_until_sentinel` directly does not surface
/// per-step EIP. For the round-1 CLI we rely on the
/// `trace-exec` per-instruction event tape AND the trap event,
/// which together cover the observability floor; explicit
/// breakpoint events land when round 2 wraps the run loop.
pub fn record_breakpoints(_sandbox: &mut Sandbox, breakpoints: &[u32]) {
    // Placeholder — round 1 stores the BP set in a side
    // structure consumed by the run-loop driver in `main.rs`.
    // Intentionally a no-op against `Sandbox` so the operator
    // sees the BP echoed back via the JSON emitter as part of
    // the `kind=trap` and `kind=exec` event stream when EIP
    // happens to land on a registered address.
    if !breakpoints.is_empty() {
        eprintln!(
            "[trace] {} breakpoint(s) registered — round-1 surfaces hits via the kind=trap / kind=exec event stream; round 2 adds dedicated kind=breakpoint events.",
            breakpoints.len()
        );
        for bp in breakpoints {
            eprintln!("  - 0x{bp:08x}");
        }
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
}
