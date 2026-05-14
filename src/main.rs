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
        // Round-5 P2 — `--break PC` is now honoured under
        // `--gdb`: PCs are pre-registered as software breakpoints
        // (so a GDB client that attaches halts at each one) AND
        // the event loop emits `kind=breakpoint` JSONL lines into
        // `--trace-output FILE` whenever guest EIP lands on one.
        let breakpoints = trace::parse_breakpoints(&args.breakpoints)?;
        return gdb::run_gdb_server(
            addr,
            &args.dll_or_ax_file,
            args.max_instr,
            args.trace_output.as_deref(),
            &breakpoints,
        );
    }

    let mut sandbox = Sandbox::new();
    sandbox.cpu.set_instr_limit(args.max_instr);

    // Trace-mode wiring (gated upstream on the `trace` Cargo
    // feature in `oxideav-vfw`). All five surfaces reach
    // through to the same JSONL sink.
    let watches = trace::parse_watch_specs(&args.watch)?;
    trace::install_sink(&mut sandbox, args.trace_output.as_deref(), &watches)?;
    trace::apply_trace_mem(&mut sandbox, &args.trace_mem)?;
    trace::apply_watch(&mut sandbox, &watches);
    let breakpoints = trace::parse_breakpoints(&args.breakpoints)?;
    trace::record_breakpoints(&mut sandbox, &breakpoints);
    if args.asm {
        trace::enable_asm(&mut sandbox);
    }

    let result = match args.command.unwrap_or(Command::Probe) {
        Command::Probe => probe::run(
            &mut sandbox,
            &args.dll_or_ax_file,
            args.fcc_handler.as_deref(),
        ),
        Command::Encode {
            input,
            width,
            height,
            input_format,
            pattern,
            quality,
            pquant,
            keyframe,
            output_fourcc,
            output,
        } => encode::run(
            &mut sandbox,
            &args.dll_or_ax_file,
            args.fcc_handler.as_deref(),
            input,
            width,
            height,
            input_format,
            pattern,
            quality,
            pquant,
            keyframe,
            output_fourcc.as_deref(),
            output,
        ),
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
        ),
    };

    // Always drain breakpoint hits — even on subcommand failure
    // the operator gets to see which registered PCs the codec
    // reached before the error surfaced.
    trace::flush_breakpoint_events(&mut sandbox, args.break_include_fpu);

    result
}
