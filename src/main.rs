//! `oxidetracevfw` — trace + debug CLI for the `oxideav-vfw`
//! Windows-codec sandbox.
//!
//! See `README.md` for the high-level CLI surface and
//! `cli.rs` / `probe.rs` / `encode.rs` / `decode.rs` /
//! `trace.rs` / `gdb.rs` for the per-feature implementations.

mod cli;
mod decode;
mod encode;
mod gdb;
mod probe;
mod trace;

use anyhow::Result;
use clap::Parser;
use oxideav_vfw::Sandbox;

use crate::cli::{Cli, Command};

fn main() -> Result<()> {
    let args = Cli::parse();

    if let Some(addr) = args.gdb.as_deref() {
        return gdb::run_gdb_server(addr, &args.dll_or_ax_file, args.max_instr);
    }

    let mut sandbox = Sandbox::new();
    sandbox.cpu.set_instr_limit(args.max_instr);

    // Trace-mode wiring (gated upstream on the `trace` Cargo
    // feature in `oxideav-vfw`). All four surfaces reach
    // through to the same JSONL sink.
    trace::install_sink(&mut sandbox, args.trace_output.as_deref())?;
    trace::apply_trace_mem(&mut sandbox, &args.trace_mem)?;
    let breakpoints = trace::parse_breakpoints(&args.breakpoints)?;
    trace::record_breakpoints(&mut sandbox, &breakpoints);
    if args.asm {
        trace::enable_asm(&mut sandbox);
    }

    match args.command.unwrap_or(Command::Probe) {
        Command::Probe => probe::run(
            &mut sandbox,
            &args.dll_or_ax_file,
            args.fcc_handler.as_deref(),
        )?,
        Command::Encode {
            width,
            height,
            pattern,
            output,
        } => encode::run(
            &mut sandbox,
            &args.dll_or_ax_file,
            args.fcc_handler.as_deref(),
            width,
            height,
            pattern,
            output,
        )?,
        Command::Decode {
            input,
            width,
            height,
            pix_format,
            output,
        } => decode::run(
            &mut sandbox,
            &args.dll_or_ax_file,
            args.fcc_handler.as_deref(),
            &input,
            width,
            height,
            pix_format,
            output,
        )?,
    }

    Ok(())
}
