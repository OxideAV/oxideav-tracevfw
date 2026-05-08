//! Round-2 todo: GDB Remote Serial Protocol server.
//!
//! Round 1 ships the trace + breakpoint primitives in
//! `oxideav-vfw` and surfaces them through the CLI's
//! `--trace-mem`, `--asm`, `--break`, and `--trace-output`
//! flags. Round 2 wraps these in a `gdbstub`-based RSP server
//! so a real `gdb` (or any RSP client) can drive the sandbox
//! interactively — set breakpoints, single-step, inspect
//! memory + registers, continue/halt, etc.
//!
//! The `gdbstub` crate's `BaseOps` / `Target` / `MemoryOps` /
//! `RegistersOps` traits map cleanly onto the sandbox's
//! existing surface (the CPU's `step` is already exposed; the
//! MMU's `read` / `write` are already public; the trace state
//! provides the breakpoint set). The round-2 work is the
//! plumbing: bind a `TcpListener` on the operator-supplied
//! `HOST:PORT`, accept one connection, and translate RSP packets
//! into `Sandbox` calls.

use anyhow::{anyhow, Result};

/// Run the GDB Remote Serial Protocol server bound to `addr`.
///
/// Round-1 implementation prints a "deferred to round 2" notice
/// and exits non-zero so an operator who passed `--gdb` knows
/// the feature isn't yet wired. Round 2 replaces this body with
/// the `gdbstub`-based server.
pub fn run_gdb_server(addr: &str) -> Result<()> {
    eprintln!("[gdb] GDB Remote Serial Protocol server bound to {addr} is round-2 work.");
    eprintln!("[gdb] Round-1 ships the trace + breakpoint primitives that the round-2");
    eprintln!("[gdb] server will wrap; see oxideav-vfw's `trace` Cargo feature for the");
    eprintln!("[gdb] underlying surface.");
    Err(anyhow!(
        "GDB server is round-2 work — see tasks #625 / #671 follow-up"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_gdb_server_returns_error_until_round_2() {
        let err = run_gdb_server("127.0.0.1:1234").unwrap_err();
        assert!(format!("{err}").contains("round-2"));
    }
}
