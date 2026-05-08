//! `clap` 4 derive layer — defines the CLI argument tree and
//! decoders for the round-1 `--trace-mem ADDR:SIZE[:MODE]` syntax.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// `oxidetracevfw` CLI — top-level argument tree.
#[derive(Parser, Debug)]
#[command(
    name = "oxidetracevfw",
    version,
    about = "Trace + debug CLI for the oxideav-vfw Windows-codec sandbox",
    long_about = "Loads a Windows codec DLL (or .ax DirectShow filter) into the \
                  pure-Rust oxideav-vfw emulator, runs `probe` / `encode` / `decode` \
                  workloads against it, and emits JSONL trace events at the four \
                  oxideav-vfw probe sites (Win32 calls, memory watchpoints, traps, \
                  optional per-instruction execution trace).\n\n\
                  GDB Remote Serial Protocol support is deferred to round 2; see \
                  src/gdb.rs."
)]
pub struct Cli {
    /// Path to the Windows codec DLL or AX filter to load.
    pub dll_or_ax_file: PathBuf,

    /// Enable per-instruction execution trace. Requires the
    /// `oxideav-vfw` build to include the `trace-exec` Cargo
    /// feature; emits a warning + exit otherwise.
    #[arg(long, default_value_t = false)]
    pub asm: bool,

    /// Watch a memory region. `ADDR:SIZE[:MODE]` where ADDR is
    /// hex (`0x...`) or decimal, SIZE is decimal bytes, MODE is
    /// `r` / `w` / `rw` (default `rw`). Repeatable.
    #[arg(long = "trace-mem", value_name = "ADDR:SIZE[:MODE]")]
    pub trace_mem: Vec<String>,

    /// Set a PC breakpoint. Dumps CPU state when guest EIP
    /// reaches this value (and continues execution — halt-and-
    /// prompt is GDB-server work, deferred to round 2).
    /// Repeatable.
    #[arg(long = "break", value_name = "PC")]
    pub breakpoints: Vec<String>,

    /// JSONL trace events output file. Defaults to stderr.
    #[arg(long = "trace-output", value_name = "FILE")]
    pub trace_output: Option<PathBuf>,

    /// Cap the emulator's total executed-instruction count.
    /// Defaults to a generous 100M to bound runaway loops.
    #[arg(long, default_value_t = 100_000_000)]
    pub max_instr: u64,

    /// FourCC handler override (e.g. `IV31`/`IV41`/`IV50`).
    /// When omitted, derived from the file extension or
    /// detected from the DLL's exports / imports.
    #[arg(long = "fcc-handler", value_name = "FCC")]
    pub fcc_handler: Option<String>,

    /// Stub for round-2 GDB Remote Serial Protocol server. Today
    /// this flag prints "round-2 todo" via `src/gdb.rs` and
    /// exits non-zero.
    #[arg(long = "gdb", value_name = "HOST:PORT")]
    pub gdb: Option<String>,

    /// Subcommand. Defaults to `probe`.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// CLI subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Load + DllMain + DRV_OPEN + ICGetInfo + ICDecompressQuery
    /// against an RGB24 default; print results in human-readable
    /// form. The default subcommand if none supplied.
    Probe,

    /// Drive `ICCompress` on synthetic input. Round-1 stub
    /// passes the synthetic frame through `vfw32::ic_*` and
    /// reports any traps / errors; full encode pipeline lands
    /// when the encoder side of the host shim grows.
    Encode {
        /// Synthetic input width.
        #[arg(long, default_value_t = 320)]
        width: u32,

        /// Synthetic input height.
        #[arg(long, default_value_t = 240)]
        height: u32,

        /// Synthetic-frame pattern.
        #[arg(long, value_enum, default_value_t = Pattern::Gradient)]
        pattern: Pattern,

        /// Output file for the encoded frame. Defaults to
        /// stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Drive `ICDecompress` on a codec-bitstream-only input
    /// file (raw codec frame, NOT containerised — the operator
    /// is responsible for extracting the frame from any AVI /
    /// MOV / etc. wrapper before passing it in).
    Decode {
        /// Path to the raw codec frame.
        #[arg(long, value_name = "FILE")]
        input: PathBuf,

        /// Output buffer width (RGB24/RGB32/YUV).
        #[arg(long)]
        width: u32,

        /// Output buffer height.
        #[arg(long)]
        height: u32,

        /// Output pixel format.
        #[arg(long = "pix-format", value_enum, default_value_t = PixFormat::Rgb24)]
        pix_format: PixFormat,

        /// Where to write decoded pixels. Defaults to stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

/// Synthetic input patterns for the `encode` subcommand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Pattern {
    /// Linear horizontal gradient — bytes 0, 1, 2, … per row.
    Gradient,
    /// All pixels middle-gray (0x80).
    Solid,
    /// 8×8 black/white squares.
    Checkerboard,
}

/// Pixel formats accepted by the `decode` subcommand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum PixFormat {
    Rgb24,
    Rgb32,
    Yuv,
}

impl PixFormat {
    /// Bytes per output pixel — used to size the decode buffer.
    pub fn bytes_per_pixel(self) -> u32 {
        match self {
            PixFormat::Rgb24 => 3,
            PixFormat::Rgb32 => 4,
            PixFormat::Yuv => 2,
        }
    }

    /// `BITMAPINFOHEADER.biCompression` value for the format.
    pub fn bi_compression(self) -> u32 {
        match self {
            PixFormat::Rgb24 | PixFormat::Rgb32 => 0, // BI_RGB
            PixFormat::Yuv => u32::from_le_bytes(*b"YUY2"),
        }
    }

    /// `BITMAPINFOHEADER.biBitCount`.
    pub fn bi_bit_count(self) -> u16 {
        match self {
            PixFormat::Rgb24 => 24,
            PixFormat::Rgb32 => 32,
            PixFormat::Yuv => 16,
        }
    }
}

/// Parse a single `--trace-mem` ADDR:SIZE[:MODE] string into a
/// `(addr, size, WatchMode)` tuple. ADDR may be `0x`-prefixed
/// hex or plain decimal; SIZE is decimal bytes; MODE is `r` /
/// `w` / `rw` (default `rw`).
pub fn parse_trace_mem(spec: &str) -> Result<(u32, u32, oxideav_vfw::WatchMode)> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(anyhow!(
            "expected ADDR:SIZE[:MODE], got {spec:?} ({} parts)",
            parts.len()
        ));
    }
    let addr = parse_u32(parts[0]).context("parsing ADDR")?;
    let size = parse_u32(parts[1]).context("parsing SIZE")?;
    let mode = if parts.len() == 3 {
        match parts[2] {
            "r" => oxideav_vfw::WatchMode::Read,
            "w" => oxideav_vfw::WatchMode::Write,
            "rw" => oxideav_vfw::WatchMode::Both,
            other => return Err(anyhow!("MODE must be one of r / w / rw, got {other:?}")),
        }
    } else {
        oxideav_vfw::WatchMode::Both
    };
    Ok((addr, size, mode))
}

/// Parse a `--break` PC argument: `0x`-prefixed hex or decimal.
pub fn parse_break(spec: &str) -> Result<u32> {
    parse_u32(spec).context("parsing breakpoint PC")
}

fn parse_u32(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16).map_err(|e| anyhow!("hex parse: {e}"))
    } else {
        s.parse::<u32>().map_err(|e| anyhow!("decimal parse: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_mem_default_mode_is_both() {
        let (addr, size, mode) = parse_trace_mem("0x10000:8").unwrap();
        assert_eq!(addr, 0x10000);
        assert_eq!(size, 8);
        assert_eq!(mode, oxideav_vfw::WatchMode::Both);
    }

    #[test]
    fn parse_trace_mem_explicit_modes() {
        let (_, _, m) = parse_trace_mem("0x10000:4:r").unwrap();
        assert_eq!(m, oxideav_vfw::WatchMode::Read);
        let (_, _, m) = parse_trace_mem("0x10000:4:w").unwrap();
        assert_eq!(m, oxideav_vfw::WatchMode::Write);
        let (_, _, m) = parse_trace_mem("0x10000:4:rw").unwrap();
        assert_eq!(m, oxideav_vfw::WatchMode::Both);
    }

    #[test]
    fn parse_trace_mem_rejects_bad_mode() {
        assert!(parse_trace_mem("0x1000:4:x").is_err());
    }

    #[test]
    fn parse_trace_mem_rejects_too_many_parts() {
        assert!(parse_trace_mem("0x1000:4:rw:extra").is_err());
    }

    #[test]
    fn parse_break_accepts_hex_and_decimal() {
        assert_eq!(parse_break("0x10004A17").unwrap(), 0x10004A17);
        assert_eq!(parse_break("256").unwrap(), 256);
    }

    #[test]
    fn pix_format_bytes_per_pixel_is_correct() {
        assert_eq!(PixFormat::Rgb24.bytes_per_pixel(), 3);
        assert_eq!(PixFormat::Rgb32.bytes_per_pixel(), 4);
        assert_eq!(PixFormat::Yuv.bytes_per_pixel(), 2);
    }
}
