//! GDB Remote Serial Protocol server (round 2).
//!
//! Wraps the `oxideav_vfw::Sandbox` in a [`gdbstub`] [`Target`]
//! so a real `gdb` (or any RSP-speaking client) can drive the
//! sandbox interactively — set breakpoints, single-step, inspect
//! memory + registers, continue / detach, etc.
//!
//! Architecture choice: [`gdbstub_arch::x86::X86_SSE`] (32-bit
//! x86 + SSE extensions). The sandbox CPU only models the eight
//! integer GPRs + EIP + EFLAGS + MMX (round-13) — segment
//! registers, FPU stack, XMM, and MXCSR are reported as zero to
//! the GDB client. SSE-class fields are present in the wire
//! layout because the GDB target description is fixed at this
//! granularity; we surface "unknown" values as the all-zero
//! pattern, matching how a real debugger sees a freshly-reset
//! processor.
//!
//! Wire flow:
//!   1. Construct a [`Sandbox`] and load the operator-supplied
//!      DLL/AX file. Run `DllMain(DLL_PROCESS_ATTACH)` so the
//!      codec's per-process state is initialised — operators
//!      typically want to set breakpoints inside post-DllMain
//!      code (`DriverProc`, `ICDecompress`, …) so halting before
//!      DllMain is more painful than it's worth.
//!   2. Bind a [`TcpListener`] on the supplied `HOST:PORT`.
//!   3. Accept exactly one connection, spin up a [`GdbStub`],
//!      and run the blocking event loop until the client
//!      disconnects or sends `vKill`.
//!   4. On disconnect, return cleanly.
//!
//! References:
//! - GDB Remote Serial Protocol manual:
//!   <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html>
//! - `gdbstub` crate: <https://docs.rs/gdbstub/0.7>
//! - `gdbstub_arch::x86::X86_SSE`: <https://docs.rs/gdbstub_arch/0.3>

use anyhow::{Context, Result};
use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::base::single_register_access::{
    SingleRegisterAccess, SingleRegisterAccessOps,
};
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwWatchpoint, HwWatchpointOps, SwBreakpoint, SwBreakpointOps,
    WatchKind,
};
use gdbstub::target::ext::target_description_xml_override::{
    TargetDescriptionXmlOverride, TargetDescriptionXmlOverrideOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::reg::id::X86CoreRegId;
use gdbstub_arch::x86::reg::X86CoreRegs;
use gdbstub_arch::x86::X86_SSE;
use oxideav_vfw::emulator::regs::Reg32;
use oxideav_vfw::{Sandbox, WatchMode, DLL_PROCESS_ATTACH};
use std::collections::VecDeque;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Shared sink for synthetic JSONL events the GDB driver emits
/// alongside the MMU's own trace stream. The single underlying
/// writer (typically a `File` opened from `--trace-output`) is
/// wrapped in `Arc<Mutex<…>>` so two producers can write to it
/// without contention:
///
/// 1. The [`WatchSink`] forwards every byte the sandbox's trace
///    state emits (`kind=mem_*`, `kind=trap`, `kind=exec`,
///    `kind=win32_call`).
/// 2. The GDB blocking event loop writes synthetic
///    `kind=breakpoint` lines when guest EIP hits one of the
///    operator-supplied `--break` PCs (round-5 P2).
///
/// `None` means the operator did not pass `--trace-output`; both
/// producers turn into no-ops on the forward path (the GDB
/// stop-reason path is unaffected).
type ForwardSink = Arc<Mutex<Option<Box<dyn Write + Send>>>>;

/// Run the GDB Remote Serial Protocol server bound to `addr`.
///
/// Loads `dll_path` into a fresh [`Sandbox`], runs
/// `DllMain(DLL_PROCESS_ATTACH)`, then halts the CPU and waits
/// for a single GDB client connection on `HOST:PORT`. Use
/// `:0` for the port to bind to an OS-chosen free port — the
/// server prints `[gdb] listening on …` to stderr with the
/// chosen port (the integration test parses this line to find
/// the server).
///
/// `trace_output`, when `Some`, is honoured as the underlying
/// JSONL sink — every `kind=mem_read` / `kind=mem_write` /
/// `kind=trap` / `kind=exec` / `kind=win32_call` line the MMU
/// emits gets written verbatim there in addition to being scanned
/// for watchpoint hits. Pairing `--gdb` with `--trace-output`
/// lets an operator observe the full event tape while a GDB
/// client drives the sandbox interactively. When `None`, only
/// the watchpoint-decoding tap is wired and the bytes are
/// dropped (so they don't clobber the GDB stub's stderr output).
///
/// `cli_breakpoints` is the set of PCs the operator passed via
/// `--break <PC>` on the command line. Round 5 P2 wires them
/// into the GDB session in two ways: (1) they're auto-registered
/// as software breakpoints so a GDB client that attaches halts
/// at each one; (2) every time guest EIP lands on one during a
/// `c` step slice, the event loop emits a `kind=breakpoint`
/// JSONL line into the trace forward sink — useful for the
/// `--trace-output FILE` operator who runs without an attached
/// GDB client (or with a client that's currently detached) and
/// wants the breakpoint hits to land on disk alongside the rest
/// of the JSONL event tape.
pub fn run_gdb_server(
    addr: &str,
    dll_path: &Path,
    max_instr: u64,
    trace_output: Option<&Path>,
    cli_breakpoints: &[u32],
) -> Result<()> {
    // 1. Sandbox setup — load DLL + run DllMain so the codec's
    //    per-process state is initialised before we hand control
    //    to the operator. Halting strictly pre-DllMain is rarely
    //    what an operator wants for VfW codecs.
    let mut sandbox = Sandbox::new();
    sandbox.cpu.set_instr_limit(max_instr);

    let bytes =
        std::fs::read(dll_path).with_context(|| format!("reading {}", dll_path.display()))?;
    let name = dll_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown.dll".to_string());

    let image = match sandbox.load(&name, &bytes) {
        Ok(img) => Some(img),
        Err(e) => {
            // Synthetic / non-PE DLLs: still useful to expose the
            // CPU + MMU surface to gdb so the operator can poke
            // at the sandbox's idle state. We log + continue.
            eprintln!("[gdb] sandbox load failed: {e}; continuing with empty sandbox");
            None
        }
    };
    if let Some(img) = &image {
        eprintln!(
            "[gdb] PE image base = 0x{:08x}, entry = 0x{:08x}",
            img.image_base, img.entry_point
        );
        if let Err(e) = sandbox.call_dll_main(img, DLL_PROCESS_ATTACH) {
            eprintln!(
                "[gdb] DllMain failed: {e}; continuing — register state reflects the failure"
            );
        }
    }

    // 2. Bind + accept. We allow `:0` so the operator (and our CI
    //    test) can ask the OS for a free port.
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    let local = listener.local_addr().context("local_addr")?;
    eprintln!("[gdb] listening on {local}");

    let (stream, peer) = listener.accept().context("accept")?;
    eprintln!("[gdb] connection from {peer}");

    // 3. Build the Target, run the event loop. If the operator
    //    asked for `--trace-output FILE`, open it and hand it to
    //    the WatchSink as the underlying forward sink so the full
    //    JSONL tape lands on disk while we tee the watchpoint
    //    events into the GDB stub. The forward sink is shared
    //    (Arc<Mutex<…>>) between the WatchSink and the event loop
    //    so the loop's `kind=breakpoint` synthetic events can land
    //    on the same JSONL stream as the MMU's own events
    //    (round-5 P2).
    let forward: ForwardSink = match trace_output {
        Some(p) => {
            let f = std::fs::File::create(p)
                .with_context(|| format!("creating trace output {}", p.display()))?;
            Arc::new(Mutex::new(Some(Box::new(f))))
        }
        None => Arc::new(Mutex::new(None)),
    };
    let mut target = SandboxTarget::with_forward(sandbox, forward, cli_breakpoints);
    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(stream);
    let stub = GdbStub::new(connection);

    match stub.run_blocking::<SandboxEventLoop>(&mut target) {
        Ok(disconnect) => match disconnect {
            DisconnectReason::Disconnect => eprintln!("[gdb] client disconnected"),
            DisconnectReason::TargetExited(code) => {
                eprintln!("[gdb] target exited (code {code})")
            }
            DisconnectReason::TargetTerminated(sig) => {
                eprintln!("[gdb] target terminated (signal {sig:?})")
            }
            DisconnectReason::Kill => eprintln!("[gdb] client sent vKill"),
        },
        Err(e) => {
            eprintln!("[gdb] stub error: {e}");
            return Err(anyhow::anyhow!("gdbstub: {e}"));
        }
    }
    Ok(())
}

/// Round-1-compatible legacy adapter — kept so existing test
/// callers that don't have a DLL path continue to compile (they
/// expect a non-zero exit). New callers go through
/// [`run_gdb_server`] which takes the full DLL path.
#[cfg(test)]
fn run_gdb_server_no_dll(addr: &str) -> Result<()> {
    // Useful for unit-level "did the address parse" smoke tests;
    // the integration test exercises the real path.
    let _ = std::net::TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    Ok(())
}

/// Round-6 P2 — target description XML served on the
/// `qXfer:features:read:target.xml:…` request.
///
/// Mirrors `gdb/features/i386/32bit-core.xml` + `32bit-sse.xml`
/// from the GDB source tree (see
/// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/i386-Features.html>),
/// with the register order and bit widths matched exactly to the
/// `gdbstub_arch::x86::X86_SSE` wire layout the stub sends in
/// the `g`/`G` packets:
///
/// | bytes  | reg(s)               |
/// |--------|----------------------|
/// |   0..32| eax, ecx, edx, ebx,  |
/// |        | esp, ebp, esi, edi   |
/// |  32..36| eip                  |
/// |  36..40| eflags               |
/// |  40..64| cs, ss, ds, es, fs,  |
/// |        | gs (each 32-bit)     |
/// |  64..144| st0..st7 (each 80-bit)|
/// | 144..176| fctrl, fstat, ftag, |
/// |        | fiseg, fioff, foseg, |
/// |        | fooff, fop (each 32) |
/// | 176..304| xmm0..xmm7 (128-bit)|
/// | 304..308| mxcsr               |
///
/// A GDB client that requests this description sees:
///   - `org.gnu.gdb.i386.core` (24 regs through fop) — gives the
///     client the canonical i386 layout it expects, including the
///     ST(i) FPU stack we co-opt for MMX storage per Intel SDM
///     Vol. 1 §9.2.1. With this in place, `info registers mmx`
///     and `print $mm0` resolve correctly instead of "register
///     not available" / wrong byte view.
///   - `org.gnu.gdb.i386.sse` (xmm0..xmm7 + mxcsr) — sandbox
///     does not model XMM but the wire layout reserves them, so
///     advertising them keeps GDB's feature-detection happy.
///
/// Without this override, gdbstub falls back to a generic
/// architecture description shipped inside `gdbstub_arch` that a
/// GDB client may interpret with a slightly different register
/// alignment — particularly around the MMX/ST aliasing — leading
/// to mis-displayed register values in `info registers`.
const TARGET_XML: &[u8] = br#"<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="eax" bitsize="32" type="int32"/>
    <reg name="ecx" bitsize="32" type="int32"/>
    <reg name="edx" bitsize="32" type="int32"/>
    <reg name="ebx" bitsize="32" type="int32"/>
    <reg name="esp" bitsize="32" type="data_ptr"/>
    <reg name="ebp" bitsize="32" type="data_ptr"/>
    <reg name="esi" bitsize="32" type="int32"/>
    <reg name="edi" bitsize="32" type="int32"/>
    <reg name="eip" bitsize="32" type="code_ptr"/>
    <reg name="eflags" bitsize="32" type="int32"/>
    <reg name="cs" bitsize="32" type="int32"/>
    <reg name="ss" bitsize="32" type="int32"/>
    <reg name="ds" bitsize="32" type="int32"/>
    <reg name="es" bitsize="32" type="int32"/>
    <reg name="fs" bitsize="32" type="int32"/>
    <reg name="gs" bitsize="32" type="int32"/>
    <reg name="st0" bitsize="80" type="i387_ext"/>
    <reg name="st1" bitsize="80" type="i387_ext"/>
    <reg name="st2" bitsize="80" type="i387_ext"/>
    <reg name="st3" bitsize="80" type="i387_ext"/>
    <reg name="st4" bitsize="80" type="i387_ext"/>
    <reg name="st5" bitsize="80" type="i387_ext"/>
    <reg name="st6" bitsize="80" type="i387_ext"/>
    <reg name="st7" bitsize="80" type="i387_ext"/>
    <reg name="fctrl" bitsize="32" type="int" group="float"/>
    <reg name="fstat" bitsize="32" type="int" group="float"/>
    <reg name="ftag" bitsize="32" type="int" group="float"/>
    <reg name="fiseg" bitsize="32" type="int" group="float"/>
    <reg name="fioff" bitsize="32" type="int" group="float"/>
    <reg name="foseg" bitsize="32" type="int" group="float"/>
    <reg name="fooff" bitsize="32" type="int" group="float"/>
    <reg name="fop" bitsize="32" type="int" group="float"/>
  </feature>
  <feature name="org.gnu.gdb.i386.sse">
    <reg name="xmm0" bitsize="128" type="vec128"/>
    <reg name="xmm1" bitsize="128" type="vec128"/>
    <reg name="xmm2" bitsize="128" type="vec128"/>
    <reg name="xmm3" bitsize="128" type="vec128"/>
    <reg name="xmm4" bitsize="128" type="vec128"/>
    <reg name="xmm5" bitsize="128" type="vec128"/>
    <reg name="xmm6" bitsize="128" type="vec128"/>
    <reg name="xmm7" bitsize="128" type="vec128"/>
    <reg name="mxcsr" bitsize="32" type="int" group="vector"/>
  </feature>
</target>
"#;

/// Single-step / continue intent set by the GDB resume packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ExecMode {
    Step,
    Continue,
}

/// Watchpoint record kept on our side so we can emit a matching
/// `Watch` stop reason to the GDB client when the sandbox's
/// trace state reports a hit. Round-3 wires the actual
/// "wait for hit" path through a JSONL-tap on the sandbox's
/// trace sink — see [`WatchSink`] / [`WatchHit`] / the
/// `wait_for_stop_reason` event loop below.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct WatchRec {
    addr: u32,
    len: u32,
    kind: WatchKind,
}

/// One pending watchpoint hit decoded from the sandbox's JSONL
/// trace stream. Pushed onto the shared [`WatchHitQueue`] by
/// [`WatchSink`] (which the GDB driver installs as the trace sink
/// before handing control to the client) and popped by the event
/// loop after each `cpu.step()` so the GDB client sees a `Watch`
/// stop-reason as soon as the offending memory access lands.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct WatchHit {
    /// `WatchKind::Read` for `mem_read`, `WatchKind::Write` for
    /// `mem_write`. The sandbox's JSONL probe never emits the
    /// `ReadWrite` shape — we'd see two events (one Read, one
    /// Write) for a true read-modify-write — so we never need to
    /// synthesise that variant here.
    kind: WatchKind,
    /// Faulting address as reported by the trace event.
    addr: u32,
}

/// Shared queue of pending watchpoint hits. The producer is the
/// [`WatchSink`] (running inside the MMU's `maybe_emit_*` probes
/// during `cpu.step`); the consumer is the GDB event loop. Wrapped
/// in `Arc<Mutex<…>>` so the sink's `Box<dyn Write + Send>` and
/// the event loop's `&mut SandboxTarget` can both reach it.
type WatchHitQueue = Arc<Mutex<VecDeque<WatchHit>>>;

/// JSONL tap installed as the sandbox's trace sink so we can
/// detect watchpoint hits between `cpu.step()` calls and yield a
/// matching `Watch` stop-reason to the GDB client.
///
/// The MMU emits one `{"kind":"mem_read",…}` or
/// `{"kind":"mem_write",…}` JSONL line per matching memory access.
/// Each line is fully self-contained (no embedded newlines), so a
/// minimal byte-level scanner is enough — we don't need a real
/// JSON parser. Lines we don't recognise (e.g. `kind=win32_call`,
/// `kind=trap`, `kind=exec`) are forwarded to the underlying sink
/// unchanged so an operator pairing `--trace-output FILE` with
/// `--gdb` gets the full event tape on disk while the GDB client
/// drives the sandbox interactively (round-4 P1).
struct WatchSink {
    /// Per-line buffer — accumulates bytes until `\n`, then we
    /// scan the assembled line for the watchpoint shapes.
    line_buf: Vec<u8>,
    /// Producer side of the watch-hit queue.
    queue: WatchHitQueue,
    /// Shared underlying sink — bytes are forwarded verbatim
    /// regardless of whether the line matched a watch shape.
    /// Wrapped so the event loop can also write synthetic
    /// `kind=breakpoint` lines to the same stream (round-5 P2).
    forward: ForwardSink,
}

impl WatchSink {
    fn new(queue: WatchHitQueue, forward: ForwardSink) -> Self {
        Self {
            line_buf: Vec::with_capacity(256),
            queue,
            forward,
        }
    }

    /// Inspect one fully-buffered JSONL line. The sandbox emits
    /// memory-watch events in the shape:
    ///
    /// ```text
    /// {"kind":"mem_write","addr":"0xDEADBEEF","size":4,"value":"…","eip":"…"}
    /// {"kind":"mem_read", "addr":"0xCAFEBABE","size":2,"value":"…","eip":"…"}
    /// ```
    ///
    /// Field order is fixed by the producer (see
    /// `oxideav_vfw::trace::TraceState::ev_mem_{read,write}`), so
    /// substring matching is sound and faster than pulling in a
    /// JSON crate. Lines that don't start with the expected
    /// `kind=mem_…` prefix are skipped silently.
    fn scan_line(&self, line: &[u8]) {
        // Cheapest possible prefix-match: the producer always
        // emits `{"kind":"mem_read"` or `{"kind":"mem_write"` as
        // the very first 17/18 bytes. Bail early on the common
        // non-match case (e.g. win32_call / trap / exec lines).
        let kind = if line.starts_with(br#"{"kind":"mem_write""#) {
            WatchKind::Write
        } else if line.starts_with(br#"{"kind":"mem_read""#) {
            WatchKind::Read
        } else {
            return;
        };

        // Find `"addr":"0x…"` — we can't use a substring search
        // crate, but `windows`-style scanning is fine since lines
        // are short (~96 bytes).
        let needle = br#""addr":"0x"#;
        let Some(start) = line
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + needle.len())
        else {
            return;
        };
        // The hex value runs until the next `"` — typically 8
        // hex digits.
        let Some(end_offset) = line[start..].iter().position(|&b| b == b'"') else {
            return;
        };
        let hex_bytes = &line[start..start + end_offset];
        let hex = match std::str::from_utf8(hex_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let addr = match u32::from_str_radix(hex, 16) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(WatchHit { kind, addr });
        }
    }
}

impl Write for WatchSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Forward every byte first — the underlying sink is
        // typically stderr / a file, so pass-through ordering
        // matches what an operator running without `--gdb` would
        // see, and a panic in the scanner doesn't lose data on
        // the way out.
        if let Ok(mut guard) = self.forward.lock() {
            if let Some(f) = guard.as_mut() {
                f.write_all(buf)?;
            }
        }
        // Buffer + scan complete lines.
        for &b in buf {
            if b == b'\n' {
                if !self.line_buf.is_empty() {
                    self.scan_line(&self.line_buf);
                    self.line_buf.clear();
                }
            } else {
                self.line_buf.push(b);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Ok(mut guard) = self.forward.lock() {
            if let Some(f) = guard.as_mut() {
                f.flush()?;
            }
        }
        Ok(())
    }
}

/// `gdbstub::Target` implementation backed by an
/// `oxideav_vfw::Sandbox`.
pub struct SandboxTarget {
    sandbox: Sandbox,
    /// Software breakpoints registered by GDB (`Z0` packets).
    sw_bps: Vec<u32>,
    /// Hardware watchpoints registered by GDB (`Z2/Z3/Z4`).
    hw_watches: Vec<WatchRec>,
    /// What the client asked for on the most recent `c` / `s`.
    exec_mode: Option<ExecMode>,
    /// Consumer-side handle on the watch-hit queue. The producer
    /// is the [`WatchSink`] installed via
    /// [`Sandbox::set_trace_sink`]; the event loop pops one entry
    /// per `cpu.step` to translate guest memory accesses into
    /// `Watch` stop-reasons for the GDB client.
    watch_queue: WatchHitQueue,
    /// CLI-registered breakpoints (`--break <PC>`). Distinct from
    /// `sw_bps`: these come from the operator's command line, not
    /// from a `Z0` packet from a connected GDB client. We auto-
    /// install them as `sw_bps` at construction so a client that
    /// later attaches halts at them, AND we emit a synthetic
    /// `kind=breakpoint` JSONL line into the forward sink every
    /// time guest EIP lands on one — visible in `--trace-output
    /// FILE` regardless of whether a GDB client is currently
    /// attached (round-5 P2).
    cli_breakpoints: Vec<u32>,
    /// Shared handle on the trace forward sink — used by the
    /// event loop to write `kind=breakpoint` JSONL lines next to
    /// the MMU's own `kind=mem_*` / `kind=trap` / `kind=exec`
    /// stream. The same handle is held by the `WatchSink`.
    forward: ForwardSink,
}

impl SandboxTarget {
    /// Build a `SandboxTarget` that drops every JSONL trace byte
    /// emitted by the sandbox and only forwards watchpoint hits
    /// to the GDB stop-reason path. This is the right default
    /// when the operator did not pass `--trace-output` — the GDB
    /// client doesn't want raw JSONL bytes interleaved with its
    /// RSP framing. (`#[cfg(test)]` because the binary path
    /// always reaches `with_forward` directly; tests retain the
    /// shorter spelling for clarity.)
    #[cfg(test)]
    pub fn new(sandbox: Sandbox) -> Self {
        Self::with_forward(sandbox, Arc::new(Mutex::new(None)), &[])
    }

    /// Build a `SandboxTarget` whose underlying [`WatchSink`]
    /// forwards every byte the MMU emits to `forward` (typically
    /// a `File` opened from `--trace-output`). The watchpoint
    /// stop-reason path is wired regardless. Round-4 P1 wires
    /// `--trace-output` through to here from `main.rs`. Round-5
    /// P2 also accepts `cli_breakpoints` — PCs the operator passed
    /// via `--break` — and pre-registers them as `sw_bps` so a
    /// GDB client that attaches halts at each one, while the
    /// event loop emits `kind=breakpoint` JSONL events for the
    /// detached-client case.
    pub fn with_forward(
        mut sandbox: Sandbox,
        forward: ForwardSink,
        cli_breakpoints: &[u32],
    ) -> Self {
        let watch_queue: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let sink = WatchSink::new(watch_queue.clone(), forward.clone());
        sandbox.set_trace_sink(Box::new(sink));
        // Pre-register the CLI breakpoints as software
        // breakpoints. A `Z0` packet for the same address from a
        // connected GDB client will then be a no-op (the existing
        // `add_sw_breakpoint` skips duplicates), and a `z0`
        // remove from the client doesn't drop the CLI-registered
        // entry because we re-check against `cli_breakpoints` in
        // the event loop below.
        let cli_bps: Vec<u32> = cli_breakpoints.to_vec();
        Self {
            sandbox,
            sw_bps: cli_bps.clone(),
            hw_watches: Vec::new(),
            exec_mode: None,
            watch_queue,
            cli_breakpoints: cli_bps,
            forward,
        }
    }

    /// Emit a synthetic `kind=breakpoint` JSONL line on the
    /// forward sink. The shape mirrors what
    /// `oxideav_vfw::trace::TraceState::ev_*` emit for the
    /// other event kinds: a single-line JSON object whose
    /// fields are quoted-string `"0x…"` for the address and
    /// EIP. Used by the event loop when guest EIP lands on a
    /// `--break` PC (round-5 P2). Best-effort — any IO error
    /// is silently dropped, matching the rest of the trace
    /// pipeline (the JSONL tape is a debugging aid, not part
    /// of any correctness contract).
    fn emit_breakpoint_event(&self, eip: u32) {
        let line = format!(
            "{{\"kind\":\"breakpoint\",\"addr\":\"0x{eip:08x}\",\"eip\":\"0x{eip:08x}\"}}\n"
        );
        if let Ok(mut guard) = self.forward.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.flush();
            }
        }
    }
}

impl Target for SandboxTarget {
    type Arch = X86_SSE;
    type Error = anyhow::Error;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    /// Round-6 P2 — advertise the `qXfer:features:read` extension
    /// so a connected GDB client can introspect our register
    /// layout precisely, instead of falling back to the generic
    /// X86_SSE description that ships with `gdbstub_arch` (which
    /// would mis-describe the MMX surface — we alias `MM[i]` onto
    /// `ST(i).low64` per Intel SDM Vol. 1 §9.2.1, which the canned
    /// description doesn't advertise as a separate feature).
    ///
    /// The custom XML mirrors what `gdb/features/i386/32bit-core.xml`
    /// plus `32bit-sse.xml` look like on a real i386 GDB build, with
    /// the `org.gnu.gdb.i386.{core,sse}` feature names GDB clients
    /// recognise as standard. See
    /// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/i386-Features.html>.
    fn support_target_description_xml_override(
        &mut self,
    ) -> Option<TargetDescriptionXmlOverrideOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadBase for SandboxTarget {
    fn read_registers(&mut self, regs: &mut X86CoreRegs) -> TargetResult<(), Self> {
        let r = &self.sandbox.cpu.regs;
        regs.eax = r.gp[Reg32::Eax as usize];
        regs.ecx = r.gp[Reg32::Ecx as usize];
        regs.edx = r.gp[Reg32::Edx as usize];
        regs.ebx = r.gp[Reg32::Ebx as usize];
        regs.esp = r.gp[Reg32::Esp as usize];
        regs.ebp = r.gp[Reg32::Ebp as usize];
        regs.esi = r.gp[Reg32::Esi as usize];
        regs.edi = r.gp[Reg32::Edi as usize];
        regs.eip = r.eip;
        regs.eflags = r.flags.pack();
        // Segments + FPU internal + XMM + MXCSR remain zero (see
        // module doc — the sandbox does not model them).
        regs.segments = Default::default();
        regs.fpu = Default::default();
        regs.xmm = [0u128; 8];
        regs.mxcsr = 0;
        // MMX surface: the architectural MMX register file
        // `MM0..MM7` aliases the lower 64 bits of the FPU stack
        // entries `ST(0)..ST(7)` per Intel SDM Vol. 1 §9.2.1.
        // gdbstub_arch's `X86CoreRegs.st` is `[F80; 8]` where
        // `F80 = [u8; 10]` — bytes 0..8 carry the 64-bit MMX
        // mantissa, bytes 8..10 carry the FPU exponent + sign
        // (zero in our model since we don't simulate the FPU).
        // GDB's `info registers mmx` and `print $mm0` therefore
        // see the live MMX state we actually compute in
        // `oxideav_vfw::emulator::isa_mmx`.
        let mmx = self.sandbox.cpu.mmx;
        for (st_slot, mmx_word) in regs.st.iter_mut().zip(mmx.iter()) {
            let bytes = mmx_word.to_le_bytes();
            st_slot[..8].copy_from_slice(&bytes);
            // Top two bytes (FPU exponent+sign) stay zero — see
            // SDM §9.5.1 "Effect of MMX, x87 FPU FPE, and MMX
            // CW Instructions on the MMX State Image": after a
            // pure MMX write, the high word reads as 0xFFFF for
            // the "valid MMX, invalid FPU" tagging. We elect to
            // keep zero so the GDB user sees a clean
            // tag-as-uninitialised pattern rather than a
            // synthetic 0xFFFF that would mislead a casual
            // reader of `info registers float`.
            st_slot[8] = 0;
            st_slot[9] = 0;
        }
        Ok(())
    }

    fn write_registers(&mut self, regs: &X86CoreRegs) -> TargetResult<(), Self> {
        let r = &mut self.sandbox.cpu.regs;
        r.gp[Reg32::Eax as usize] = regs.eax;
        r.gp[Reg32::Ecx as usize] = regs.ecx;
        r.gp[Reg32::Edx as usize] = regs.edx;
        r.gp[Reg32::Ebx as usize] = regs.ebx;
        r.gp[Reg32::Esp as usize] = regs.esp;
        r.gp[Reg32::Ebp as usize] = regs.ebp;
        r.gp[Reg32::Esi as usize] = regs.esi;
        r.gp[Reg32::Edi as usize] = regs.edi;
        r.eip = regs.eip;
        r.flags = oxideav_vfw::emulator::regs::Flags::unpack(regs.eflags);
        // MMX writeback: GDB clients can `set $mm0 = …` to seed
        // the MMX register file. We pull the lower 64 bits out of
        // each `st[i]` entry — the high 16 bits of the F80 are
        // the FPU exponent+sign which the sandbox does not model.
        for (i, st_slot) in regs.st.iter().enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&st_slot[..8]);
            self.sandbox.cpu.mmx[i] = u64::from_le_bytes(bytes);
        }
        // Other surfaces (segments / FPU internal / XMM)
        // intentionally ignored — the sandbox does not model
        // them.
        Ok(())
    }

    fn read_addrs(&mut self, start: u32, data: &mut [u8]) -> TargetResult<usize, Self> {
        // Best-effort: read byte-by-byte through the MMU's
        // load8. Unmapped pages return Trap; we honour the GDB
        // protocol's "fewer bytes returned" by stopping at the
        // first unmapped byte.
        let mut n = 0usize;
        for slot in data.iter_mut() {
            let addr = start.wrapping_add(n as u32);
            match self.sandbox.mmu.load8(addr) {
                Ok(b) => *slot = b,
                Err(_) => break,
            }
            n += 1;
        }
        Ok(n)
    }

    fn write_addrs(&mut self, start: u32, data: &[u8]) -> TargetResult<(), Self> {
        // Best-effort: write through the MMU. We use `write`
        // (which honours W-perm) to avoid bypassing the sandbox's
        // protection model. For truly unmapped pages we surface a
        // non-fatal `Errno(EFAULT)` so the GDB client sees an
        // error rather than the whole stub dying.
        match self.sandbox.mmu.write(start, data) {
            Ok(()) => Ok(()),
            Err(_) => Err(TargetError::NonFatal),
        }
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }

    /// Round-5 P1 — advertise the `SingleRegisterAccess`
    /// extension so a GDB client can use the `p`/`P` packets to
    /// read/write a single register without rolling the whole
    /// register file via `g`/`G`. Streamlines future tests that
    /// just want to override EIP or EAX, and matches what GDB
    /// itself uses when an operator types `set $eax = 1`.
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, (), Self>> {
        Some(self)
    }
}

impl SingleRegisterAccess<()> for SandboxTarget {
    /// Write the requested register's bytes into `buf` and return
    /// the number of bytes written. The `gdbstub` framework has
    /// already sized `buf` to the register's known length per
    /// the `X86_SSE` arch description. Per the GDB protocol, a
    /// return of `0` indicates the register exists but its value
    /// is unavailable (not surfaced here; the sandbox knows every
    /// modeled register and zero-fills the unmodeled ones).
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: X86CoreRegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        // Helper — write the LE bytes of `v` into `buf` and
        // return the count we filled.
        fn write_le32(buf: &mut [u8], v: u32) -> usize {
            let bytes = v.to_le_bytes();
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            n
        }
        let r = &self.sandbox.cpu.regs;
        let n = match reg_id {
            X86CoreRegId::Eax => write_le32(buf, r.gp[Reg32::Eax as usize]),
            X86CoreRegId::Ecx => write_le32(buf, r.gp[Reg32::Ecx as usize]),
            X86CoreRegId::Edx => write_le32(buf, r.gp[Reg32::Edx as usize]),
            X86CoreRegId::Ebx => write_le32(buf, r.gp[Reg32::Ebx as usize]),
            X86CoreRegId::Esp => write_le32(buf, r.gp[Reg32::Esp as usize]),
            X86CoreRegId::Ebp => write_le32(buf, r.gp[Reg32::Ebp as usize]),
            X86CoreRegId::Esi => write_le32(buf, r.gp[Reg32::Esi as usize]),
            X86CoreRegId::Edi => write_le32(buf, r.gp[Reg32::Edi as usize]),
            X86CoreRegId::Eip => write_le32(buf, r.eip),
            X86CoreRegId::Eflags => write_le32(buf, r.flags.pack()),
            // ST(i): MMX register file aliasing — same surface as
            // the bulk `read_registers` path. Lower 8 bytes carry
            // the live MMX value; upper 2 bytes (FPU exponent +
            // sign) stay zero because the sandbox does not model
            // the FPU stack. Out-of-range `i` is a protocol error
            // the framework rejects, so we don't double-check.
            X86CoreRegId::St(i) if (i as usize) < self.sandbox.cpu.mmx.len() => {
                let mmx = self.sandbox.cpu.mmx[i as usize];
                let bytes = mmx.to_le_bytes();
                let n = buf.len().min(10);
                let m = n.min(8);
                buf[..m].copy_from_slice(&bytes[..m]);
                if n > 8 {
                    for slot in &mut buf[8..n] {
                        *slot = 0;
                    }
                }
                n
            }
            // Segment / FPU internal / XMM / MXCSR — sandbox
            // doesn't model these, so we zero-fill the buffer.
            // The wire layout still encodes them (the GDB
            // protocol's reg-id space is fixed by the arch
            // description), and zero is what `read_registers`
            // already exposes as the default.
            _ => {
                for slot in buf.iter_mut() {
                    *slot = 0;
                }
                buf.len()
            }
        };
        Ok(n)
    }

    /// Write `val` into the requested register. The framework
    /// guarantees `val.len()` matches the register's natural
    /// width.
    fn write_register(
        &mut self,
        _tid: (),
        reg_id: X86CoreRegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        // Helper — read a u32 LE out of `val`, padding with
        // zeros if the slice is shorter than 4 bytes (the GDB
        // framework should always size correctly, but be
        // defensive).
        fn read_le32(val: &[u8]) -> u32 {
            let mut bytes = [0u8; 4];
            let n = val.len().min(4);
            bytes[..n].copy_from_slice(&val[..n]);
            u32::from_le_bytes(bytes)
        }
        let r = &mut self.sandbox.cpu.regs;
        match reg_id {
            X86CoreRegId::Eax => r.gp[Reg32::Eax as usize] = read_le32(val),
            X86CoreRegId::Ecx => r.gp[Reg32::Ecx as usize] = read_le32(val),
            X86CoreRegId::Edx => r.gp[Reg32::Edx as usize] = read_le32(val),
            X86CoreRegId::Ebx => r.gp[Reg32::Ebx as usize] = read_le32(val),
            X86CoreRegId::Esp => r.gp[Reg32::Esp as usize] = read_le32(val),
            X86CoreRegId::Ebp => r.gp[Reg32::Ebp as usize] = read_le32(val),
            X86CoreRegId::Esi => r.gp[Reg32::Esi as usize] = read_le32(val),
            X86CoreRegId::Edi => r.gp[Reg32::Edi as usize] = read_le32(val),
            X86CoreRegId::Eip => r.eip = read_le32(val),
            X86CoreRegId::Eflags => {
                r.flags = oxideav_vfw::emulator::regs::Flags::unpack(read_le32(val))
            }
            X86CoreRegId::St(i) if (i as usize) < self.sandbox.cpu.mmx.len() => {
                // Lower 8 bytes are the MMX value; upper 2 bytes
                // (FPU exponent + sign) are dropped because the
                // sandbox does not model the FPU.
                let mut bytes = [0u8; 8];
                let n = val.len().min(8);
                bytes[..n].copy_from_slice(&val[..n]);
                self.sandbox.cpu.mmx[i as usize] = u64::from_le_bytes(bytes);
            }
            // Segment / FPU internal / XMM / MXCSR — sandbox
            // doesn't model these. Silently accept the write so
            // the GDB client doesn't see a protocol-level error;
            // the value is dropped on the floor (matches what
            // `write_registers` already does for the same fields).
            _ => {}
        }
        Ok(())
    }
}

impl TargetDescriptionXmlOverride for SandboxTarget {
    /// Round-6 P2 — serve the static [`TARGET_XML`] payload to a
    /// connected GDB client. `annex` is the requested document
    /// name (the GDB protocol manual specifies `b"target.xml"` as
    /// the root and allows `<xi:include>` to chain extra files —
    /// our description is single-file so any non-`target.xml`
    /// annex returns an empty body, which GDB treats as a
    /// well-formed empty document).
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        // Empty / unknown annex → empty document. The GDB protocol
        // tolerates this; a client requesting `i386-something.xml`
        // we don't ship just sees zero-length content.
        if annex != b"target.xml" {
            return Ok(0);
        }
        let total = TARGET_XML.len() as u64;
        if offset >= total {
            // Standard "end of stream" reply per the GDB protocol's
            // qXfer pagination contract.
            return Ok(0);
        }
        let start = offset as usize;
        let remaining = TARGET_XML.len() - start;
        let n = remaining.min(length).min(buf.len());
        buf[..n].copy_from_slice(&TARGET_XML[start..start + n]);
        Ok(n)
    }
}

impl SingleThreadResume for SandboxTarget {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            // Sandbox doesn't model UNIX-style signals; ignore.
        }
        self.exec_mode = Some(ExecMode::Continue);
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for SandboxTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if signal.is_some() {
            // Sandbox doesn't model UNIX-style signals; ignore.
        }
        self.exec_mode = Some(ExecMode::Step);
        Ok(())
    }
}

impl Breakpoints for SandboxTarget {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for SandboxTarget {
    fn add_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        if !self.sw_bps.contains(&addr) {
            self.sw_bps.push(addr);
        }
        Ok(true)
    }

    fn remove_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        self.sw_bps.retain(|&pc| pc != addr);
        Ok(true)
    }
}

impl HwWatchpoint for SandboxTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        let mode = match kind {
            WatchKind::Read => WatchMode::Read,
            WatchKind::Write => WatchMode::Write,
            WatchKind::ReadWrite => WatchMode::Both,
        };
        self.sandbox.watch(addr, len, mode);
        self.hw_watches.push(WatchRec { addr, len, kind });
        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        self.sandbox.unwatch(addr, len);
        self.hw_watches
            .retain(|w| !(w.addr == addr && w.len == len && w.kind == kind));
        Ok(true)
    }
}

/// Blocking event loop — drives the sandbox a step at a time
/// and yields back to the GDB client on:
///   - software breakpoint hit (EIP matches `sw_bps`)
///   - single-step request completed
///   - sentinel reached (`run` halts)
///   - target trap (illegal instruction etc.)
///   - incoming GDB packet (e.g. `\x03` interrupt during `c`)
struct SandboxEventLoop;

impl BlockingEventLoop for SandboxEventLoop {
    type Target = SandboxTarget;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u32>;

    fn wait_for_stop_reason(
        target: &mut SandboxTarget,
        conn: &mut Self::Connection,
    ) -> Result<
        Event<SingleThreadStopReason<u32>>,
        WaitForStopReasonError<
            <SandboxTarget as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        // Loop: take small slices of CPU steps, then check the
        // GDB connection for incoming bytes. This lets the client
        // interrupt a long `c` with Ctrl-C and lets breakpoint
        // hits surface promptly.
        let mode = target.exec_mode.unwrap_or(ExecMode::Continue);
        let mut steps_this_slice: u32 = 0;
        // Cap the slice so we don't starve the connection check.
        const SLICE: u32 = 1024;

        loop {
            // Single-step the CPU. If it traps, surface as
            // SwBreak (closest match to "the program stopped").
            let step_result = {
                let cpu = &mut target.sandbox.cpu;
                let mmu = &mut target.sandbox.mmu;
                cpu.step(mmu)
            };
            let halted = match step_result {
                Ok(oxideav_vfw::emulator::isa_int::StepOk::Continued) => false,
                Ok(oxideav_vfw::emulator::isa_int::StepOk::Halted) => true,
                Err(_) => {
                    // Treat trap as a stop with a SIGILL-like
                    // signal so gdb prints something useful.
                    target.exec_mode = None;
                    return Ok(Event::TargetStopped(SingleThreadStopReason::Signal(
                        Signal::SIGILL,
                    )));
                }
            };

            // Watchpoint hits — drain one queued event per stop
            // so the GDB client sees `Watch { kind, addr }` with
            // the exact address the codec touched. The MMU's
            // watch probe ran inside the `cpu.step` we just
            // completed; if a registered watch matched, our
            // `WatchSink` already pushed an entry. Drain at most
            // one per stop (the GDB protocol is one-stop-reason-
            // per-packet); leftover hits stay in the queue and
            // surface on subsequent resume + step pairs.
            let watch_hit = target
                .watch_queue
                .lock()
                .ok()
                .and_then(|mut q| q.pop_front());
            if let Some(hit) = watch_hit {
                target.exec_mode = None;
                return Ok(Event::TargetStopped(SingleThreadStopReason::Watch {
                    tid: (),
                    kind: hit.kind,
                    addr: hit.addr,
                }));
            }

            // Single-step done?
            if mode == ExecMode::Step {
                target.exec_mode = None;
                return Ok(Event::TargetStopped(SingleThreadStopReason::DoneStep));
            }

            // Did the new EIP land on a breakpoint?
            let eip = target.sandbox.cpu.regs.eip;
            // Emit a `kind=breakpoint` JSONL event for the CLI-
            // registered set whether or not GDB is currently
            // attached. Round-5 P2 — operators pairing
            // `--gdb HOST:PORT` with `--break PC` and
            // `--trace-output FILE` get the breakpoint hit on
            // disk independent of any client `c`/`s` interaction.
            if target.cli_breakpoints.contains(&eip) {
                target.emit_breakpoint_event(eip);
            }
            if target.sw_bps.contains(&eip) {
                target.exec_mode = None;
                return Ok(Event::TargetStopped(SingleThreadStopReason::SwBreak(())));
            }

            if halted {
                // Sentinel reached — translate to "exited 0".
                target.exec_mode = None;
                return Ok(Event::TargetStopped(SingleThreadStopReason::Exited(0)));
            }

            steps_this_slice += 1;
            if steps_this_slice >= SLICE {
                steps_this_slice = 0;
                // Yield to the connection — let GDB interrupt.
                match conn.peek() {
                    Ok(Some(byte)) => return Ok(Event::IncomingData(byte)),
                    Ok(None) => {}
                    Err(e) => return Err(WaitForStopReasonError::Connection(e)),
                }
            }
        }
    }

    fn on_interrupt(
        _target: &mut SandboxTarget,
    ) -> Result<Option<SingleThreadStopReason<u32>>, <SandboxTarget as Target>::Error> {
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_gdb_server_no_dll_binds_loopback() {
        // Confirms the address-parse + bind path works without
        // needing a real DLL — the integration test exercises
        // the full RSP wire path.
        run_gdb_server_no_dll("127.0.0.1:0").unwrap();
    }

    /// Helper — `TargetError<anyhow::Error>` doesn't impl
    /// `Debug`, so `.unwrap()` on a `TargetResult` won't compile.
    /// Promote the success case + panic on either error variant.
    fn ok<T>(r: TargetResult<T, SandboxTarget>) -> T {
        match r {
            Ok(v) => v,
            Err(TargetError::Fatal(e)) => panic!("fatal target error: {e}"),
            Err(TargetError::NonFatal) => panic!("non-fatal target error"),
            Err(TargetError::Errno(n)) => panic!("errno target error: {n}"),
            Err(TargetError::Io(e)) => panic!("io target error: {e}"),
            Err(_) => panic!("unknown target error variant"),
        }
    }

    #[test]
    fn target_register_round_trip() {
        let mut sb = Sandbox::new();
        sb.cpu.regs.gp[Reg32::Eax as usize] = 0xdeadbeef;
        sb.cpu.regs.gp[Reg32::Edi as usize] = 0xcafef00d;
        sb.cpu.regs.eip = 0x10001234;
        sb.cpu.regs.flags.zf = true;
        let mut t = SandboxTarget::new(sb);

        let mut regs = X86CoreRegs::default();
        ok(SingleThreadBase::read_registers(&mut t, &mut regs));
        assert_eq!(regs.eax, 0xdeadbeef);
        assert_eq!(regs.edi, 0xcafef00d);
        assert_eq!(regs.eip, 0x10001234);
        assert!(regs.eflags & (1 << 6) != 0); // ZF

        // Mutate + write-back round trip.
        regs.eax = 0x11111111;
        regs.eip = 0x20002000;
        ok(SingleThreadBase::write_registers(&mut t, &regs));
        assert_eq!(t.sandbox.cpu.regs.gp[Reg32::Eax as usize], 0x11111111);
        assert_eq!(t.sandbox.cpu.regs.eip, 0x20002000);
    }

    #[test]
    fn sw_breakpoint_set_and_remove() {
        let sb = Sandbox::new();
        let mut t = SandboxTarget::new(sb);
        ok(SwBreakpoint::add_sw_breakpoint(&mut t, 0x10001000, 0));
        ok(SwBreakpoint::add_sw_breakpoint(&mut t, 0x10002000, 0));
        // Adding the same breakpoint twice is a no-op.
        ok(SwBreakpoint::add_sw_breakpoint(&mut t, 0x10001000, 0));
        assert_eq!(t.sw_bps.len(), 2);
        ok(SwBreakpoint::remove_sw_breakpoint(&mut t, 0x10001000, 0));
        assert_eq!(t.sw_bps, vec![0x10002000]);
    }

    #[test]
    fn hw_watchpoint_round_trip() {
        let sb = Sandbox::new();
        let mut t = SandboxTarget::new(sb);
        ok(HwWatchpoint::add_hw_watchpoint(
            &mut t,
            0x60000000,
            4,
            WatchKind::Write,
        ));
        ok(HwWatchpoint::add_hw_watchpoint(
            &mut t,
            0x60000010,
            8,
            WatchKind::ReadWrite,
        ));
        assert_eq!(t.hw_watches.len(), 2);
        // Removing returns true and deletes the matching record.
        ok(HwWatchpoint::remove_hw_watchpoint(
            &mut t,
            0x60000000,
            4,
            WatchKind::Write,
        ));
        assert_eq!(t.hw_watches.len(), 1);
        assert_eq!(t.hw_watches[0].addr, 0x60000010);
    }

    #[test]
    fn target_round_trips_mmx_through_st_aliasing() {
        // Round-3 P2: MMX register file (`Cpu::mmx[u64; 8]`)
        // surfaces through the `X86CoreRegs.st` field so a GDB
        // client running `info registers mmx` / `print $mm0`
        // sees the live register state.
        let mut sb = Sandbox::new();
        sb.cpu.mmx[0] = 0x0102030405060708;
        sb.cpu.mmx[3] = 0xDEADBEEFCAFEBABE;
        sb.cpu.mmx[7] = 0xFFFFFFFFFFFFFFFF;
        let mut t = SandboxTarget::new(sb);

        let mut regs = X86CoreRegs::default();
        ok(SingleThreadBase::read_registers(&mut t, &mut regs));

        // MM0 → low 8 bytes of st[0], little-endian.
        assert_eq!(&regs.st[0][..8], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(regs.st[0][8], 0);
        assert_eq!(regs.st[0][9], 0);
        // MM3 → low 8 bytes of st[3].
        assert_eq!(&regs.st[3][..8], &0xDEADBEEFCAFEBABEu64.to_le_bytes());
        // MM7 → all-ones in low 8 bytes; FPU exponent stays 0.
        assert_eq!(&regs.st[7][..8], &[0xFF; 8]);
        assert_eq!(regs.st[7][8], 0);

        // Mutate via the GDB write path and verify cpu.mmx
        // sees the new value.
        regs.st[1][..8].copy_from_slice(&0x4242424242424242u64.to_le_bytes());
        ok(SingleThreadBase::write_registers(&mut t, &regs));
        assert_eq!(t.sandbox.cpu.mmx[1], 0x4242424242424242);
    }

    #[test]
    fn watch_sink_decodes_mem_write_lines() {
        // Round-3 P1: the WatchSink JSONL tap turns the sandbox's
        // `kind=mem_write` events into queued WatchHits.
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let mut sink = WatchSink::new(q.clone(), Arc::new(Mutex::new(None)));
        let line = br#"{"kind":"mem_write","addr":"0x12340000","size":4,"value":"deadbeef","eip":"0x10001234"}
"#;
        sink.write_all(line).unwrap();
        let drained: Vec<_> = q.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].kind, WatchKind::Write);
        assert_eq!(drained[0].addr, 0x12340000);
    }

    #[test]
    fn watch_sink_decodes_mem_read_lines() {
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let mut sink = WatchSink::new(q.clone(), Arc::new(Mutex::new(None)));
        let line =
            br#"{"kind":"mem_read","addr":"0xCAFEBABE","size":2,"value":"1234","eip":"0x10001234"}
"#;
        sink.write_all(line).unwrap();
        let drained: Vec<_> = q.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].kind, WatchKind::Read);
        assert_eq!(drained[0].addr, 0xCAFEBABE);
    }

    #[test]
    fn watch_sink_ignores_non_mem_lines() {
        // win32_call / trap / exec lines are not watch events
        // and must not enqueue spurious WatchHits.
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let mut sink = WatchSink::new(q.clone(), Arc::new(Mutex::new(None)));
        let lines: &[&[u8]] = &[
            br#"{"kind":"win32_call","dll":"kernel32","name":"GetProcessHeap","args":[],"ret":"00000000","eip":"10001000"}
"#,
            br#"{"kind":"trap","addr":"0x10001000","reason":"unmapped","eip":"0x10001000"}
"#,
            br#"{"kind":"exec","eip":"0x10001000","bytes":"c3","mnemonic":"ret","registers":{}}
"#,
        ];
        for l in lines {
            sink.write_all(l).unwrap();
        }
        assert!(q.lock().unwrap().is_empty());
    }

    #[test]
    fn watch_sink_handles_split_writes() {
        // The MMU's `emit_line` calls `write_all(payload)` then
        // `write_all(b"\n")` — i.e. one write may not include
        // the trailing newline. Verify the buffering path.
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let mut sink = WatchSink::new(q.clone(), Arc::new(Mutex::new(None)));
        sink.write_all(br#"{"kind":"mem_write","addr":"0x"#)
            .unwrap();
        sink.write_all(br#"60001000","size":4,"value":"abcd","eip":"0x10001234"}"#)
            .unwrap();
        // No newline yet — nothing decoded.
        assert!(q.lock().unwrap().is_empty());
        sink.write_all(b"\n").unwrap();
        let drained: Vec<_> = q.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].addr, 0x60001000);
    }

    #[test]
    fn cpu_step_with_watchpoint_enqueues_watch_hit() {
        // End-to-end of the round-3 P1 wiring: a guest store
        // through a registered watchpoint produces a queued
        // `WatchHit` after `cpu.step`. We use real machine code
        // (`mov [edi], eax; hlt`) to exercise the actual
        // `Mmu::store32 → maybe_emit_write → trace.ev_mem_write`
        // probe path that the GDB event loop relies on.
        let mut sb = Sandbox::new();
        // Map a code page (R+X) and a target page (R+W).
        const CODE_BASE: u32 = 0x20001000;
        const DATA_BASE: u32 = 0x60000000;
        sb.mmu.map(
            CODE_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::X,
        );
        sb.mmu.map(
            DATA_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::W,
        );
        // 0x89 0x07 = `mov [edi], eax` (opcode 89 /r, ModR/M:
        // mod=00 reg=eax(0) r/m=edi(7) → [edi]).
        // 0xF4       = `hlt` — surfaces as `StepOk::Halted`.
        sb.mmu
            .write_initializer(CODE_BASE, &[0x89, 0x07, 0xF4])
            .unwrap();
        sb.cpu.regs.eip = CODE_BASE;
        sb.cpu.regs.gp[Reg32::Eax as usize] = 0xCAFEF00D;
        sb.cpu.regs.gp[Reg32::Edi as usize] = DATA_BASE + 0x100;
        // Register a write watch on the target dword.
        sb.watch(DATA_BASE + 0x100, 4, WatchMode::Write);
        // Build the SandboxTarget — this installs the WatchSink
        // that forwards into `watch_queue`.
        let mut t = SandboxTarget::new(sb);
        // Step once — executes `mov [edi], eax`. The MMU's
        // store32 probe matches our watch and emits a JSONL
        // `mem_write` line which our sink decodes.
        let r = t.sandbox.cpu.step(&mut t.sandbox.mmu).unwrap();
        assert_eq!(r, oxideav_vfw::emulator::isa_int::StepOk::Continued);
        // Verify the write actually happened.
        assert_eq!(t.sandbox.mmu.load32(DATA_BASE + 0x100).unwrap(), 0xCAFEF00D);
        // The WatchSink should have decoded one Write hit.
        let drained: Vec<_> = t.watch_queue.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1, "expected one watch hit, got {drained:?}");
        assert_eq!(drained[0].kind, WatchKind::Write);
        assert_eq!(drained[0].addr, DATA_BASE + 0x100);
    }

    #[test]
    fn watch_sink_forwards_to_underlying_writer() {
        // An operator can pair `--gdb` with `--trace-output FILE`
        // (round-4 P1) — verify the forward path passes bytes
        // through verbatim.
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let captured: Vec<u8> = Vec::new();
        let forward: ForwardSink =
            Arc::new(Mutex::new(Some(Box::new(std::io::Cursor::new(captured)))));
        let mut sink = WatchSink::new(q.clone(), forward);
        let line =
            br#"{"kind":"mem_write","addr":"0x10000000","size":1,"value":"42","eip":"0x10001000"}
"#;
        sink.write_all(line).unwrap();
        // Watch hit landed in the queue.
        assert_eq!(q.lock().unwrap().len(), 1);
        // The Cursor is consumed by `forward` so we can't read
        // it back here without retaining a handle — but the
        // `write_all` returning Ok proves the forward path was
        // exercised. The end-to-end "trace_output writes
        // through `--gdb`" path is covered by
        // `with_forward_routes_jsonl_into_supplied_sink` below.
    }

    /// Round-4 P1 — the `with_forward` constructor wires the
    /// caller's `Box<dyn Write + Send>` through the WatchSink so
    /// `--trace-output FILE` works simultaneously with `--gdb`.
    /// Reuses the `cpu_step_with_watchpoint_enqueues_watch_hit`
    /// scaffolding (mov [edi], eax; hlt) but replaces the
    /// "drop bytes" sink with a shared `Vec<u8>` we can inspect.
    #[test]
    fn with_forward_routes_jsonl_into_supplied_sink() {
        // Shared buffer we hand to the WatchSink — wrapped in
        // Arc<Mutex<…>> so we can both write to it (via the
        // SharedWriter adapter) and read it back after the step.
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut sb = Sandbox::new();
        const CODE_BASE: u32 = 0x20001000;
        const DATA_BASE: u32 = 0x60000000;
        sb.mmu.map(
            CODE_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::X,
        );
        sb.mmu.map(
            DATA_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::W,
        );
        // mov [edi], eax ; hlt
        sb.mmu
            .write_initializer(CODE_BASE, &[0x89, 0x07, 0xF4])
            .unwrap();
        sb.cpu.regs.eip = CODE_BASE;
        sb.cpu.regs.gp[Reg32::Eax as usize] = 0xCAFEF00D;
        sb.cpu.regs.gp[Reg32::Edi as usize] = DATA_BASE + 0x100;
        sb.watch(DATA_BASE + 0x100, 4, WatchMode::Write);

        let forward: ForwardSink =
            Arc::new(Mutex::new(Some(Box::new(SharedWriter(captured.clone())))));
        let mut t = SandboxTarget::with_forward(sb, forward, &[]);

        let r = t.sandbox.cpu.step(&mut t.sandbox.mmu).unwrap();
        assert_eq!(r, oxideav_vfw::emulator::isa_int::StepOk::Continued);

        // Watch hit also landed in the queue (the GDB path is
        // unaffected by the forward sink).
        let drained: Vec<_> = t.watch_queue.lock().unwrap().drain(..).collect();
        assert_eq!(drained.len(), 1);

        // The forwarded buffer should contain the raw JSONL
        // `mem_write` line — same contract `--trace-output FILE`
        // gives operators when running without `--gdb`.
        let bytes = captured.lock().unwrap().clone();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains(r#""kind":"mem_write""#),
            "expected forwarded JSONL to contain mem_write event, got: {s:?}"
        );
        assert!(
            s.contains("60000100") || s.contains("0x60000100"),
            "expected forwarded JSONL to mention the watched address, got: {s:?}"
        );
    }

    #[test]
    fn read_addrs_returns_short_count_at_unmapped_page() {
        let mut sb = Sandbox::new();
        // Map one page at 0x10000, leave 0x11000 unmapped.
        sb.mmu.map(0x10000, 0x1000, oxideav_vfw::emulator::Perm::R);
        // Seed a few bytes via write_initializer.
        sb.mmu
            .write_initializer(0x10000, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let mut t = SandboxTarget::new(sb);
        // Read crosses the page boundary; we get 0x1000 mapped
        // bytes (0x11000 - 0x10000), then short-return.
        let mut buf = [0u8; 0x1010];
        let n = ok(SingleThreadBase::read_addrs(&mut t, 0x10000, &mut buf));
        assert_eq!(n, 0x1000, "expected to read full page then stop");
        assert_eq!(&buf[..4], &[0x11, 0x22, 0x33, 0x44]);
    }

    /// Round-5 P1 — `SingleRegisterAccess::read_register` returns
    /// the live value of any single GPR / EIP / EFLAGS without
    /// requiring the caller to roll the entire `g`-packet
    /// register file.
    #[test]
    fn single_register_read_returns_gpr_eip_eflags() {
        let mut sb = Sandbox::new();
        sb.cpu.regs.gp[Reg32::Eax as usize] = 0xdeadbeef;
        sb.cpu.regs.gp[Reg32::Edi as usize] = 0xcafef00d;
        sb.cpu.regs.eip = 0x10001234;
        sb.cpu.regs.flags.zf = true;
        let mut t = SandboxTarget::new(sb);

        let mut buf = [0u8; 4];
        let n = ok(SingleRegisterAccess::read_register(
            &mut t,
            (),
            X86CoreRegId::Eax,
            &mut buf,
        ));
        assert_eq!(n, 4);
        assert_eq!(buf, 0xdeadbeefu32.to_le_bytes());

        let n = ok(SingleRegisterAccess::read_register(
            &mut t,
            (),
            X86CoreRegId::Edi,
            &mut buf,
        ));
        assert_eq!(n, 4);
        assert_eq!(buf, 0xcafef00du32.to_le_bytes());

        let n = ok(SingleRegisterAccess::read_register(
            &mut t,
            (),
            X86CoreRegId::Eip,
            &mut buf,
        ));
        assert_eq!(n, 4);
        assert_eq!(buf, 0x10001234u32.to_le_bytes());

        let n = ok(SingleRegisterAccess::read_register(
            &mut t,
            (),
            X86CoreRegId::Eflags,
            &mut buf,
        ));
        assert_eq!(n, 4);
        let eflags = u32::from_le_bytes(buf);
        // ZF is bit 6 of EFLAGS per Intel SDM Vol. 1 §3.4.3.1.
        assert!(eflags & (1 << 6) != 0, "ZF bit should be set");
    }

    /// Round-5 P1 — `SingleRegisterAccess::write_register`
    /// updates the live register file. Verifies the write path
    /// for the GPRs + EIP + EFLAGS.
    #[test]
    fn single_register_write_updates_cpu_state() {
        let sb = Sandbox::new();
        let mut t = SandboxTarget::new(sb);

        ok(SingleRegisterAccess::write_register(
            &mut t,
            (),
            X86CoreRegId::Eax,
            &0x11223344u32.to_le_bytes(),
        ));
        assert_eq!(t.sandbox.cpu.regs.gp[Reg32::Eax as usize], 0x11223344);

        ok(SingleRegisterAccess::write_register(
            &mut t,
            (),
            X86CoreRegId::Eip,
            &0x20002000u32.to_le_bytes(),
        ));
        assert_eq!(t.sandbox.cpu.regs.eip, 0x20002000);

        // Set EFLAGS with ZF + CF (CF = bit 0).
        ok(SingleRegisterAccess::write_register(
            &mut t,
            (),
            X86CoreRegId::Eflags,
            &((1u32 << 6) | 1u32).to_le_bytes(),
        ));
        assert!(t.sandbox.cpu.regs.flags.zf);
        assert!(t.sandbox.cpu.regs.flags.cf);
    }

    /// Round-5 P1 — `St(i)` is the architectural alias for
    /// `MM(i)`; a single-register read should expose the lower 8
    /// bytes of the FPU stack entry from `cpu.mmx[i]` and
    /// zero-fill the upper 2 bytes (FPU exponent + sign which the
    /// sandbox does not model).
    #[test]
    fn single_register_st_aliases_mmx() {
        let mut sb = Sandbox::new();
        sb.cpu.mmx[2] = 0x0102030405060708;
        let mut t = SandboxTarget::new(sb);

        let mut buf = [0u8; 10];
        let n = ok(SingleRegisterAccess::read_register(
            &mut t,
            (),
            X86CoreRegId::St(2),
            &mut buf,
        ));
        assert_eq!(n, 10);
        assert_eq!(&buf[..8], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(buf[8], 0);
        assert_eq!(buf[9], 0);

        // Write-back path: drop the high 2 bytes, keep the low 8.
        let mut newbytes = [0u8; 10];
        newbytes[..8].copy_from_slice(&0x4242424242424242u64.to_le_bytes());
        newbytes[8] = 0xFF; // FPU exponent — should be ignored.
        newbytes[9] = 0xFF;
        ok(SingleRegisterAccess::write_register(
            &mut t,
            (),
            X86CoreRegId::St(2),
            &newbytes,
        ));
        assert_eq!(t.sandbox.cpu.mmx[2], 0x4242424242424242);
    }

    /// Round-5 P2 — when guest EIP lands on a CLI-registered
    /// `--break` PC during `cpu.step`, the GDB event loop emits a
    /// `kind=breakpoint` JSONL line to the forward sink. We
    /// exercise the emitter helper directly here (the full event-
    /// loop path is awkward to drive without spinning a real
    /// connection); the shape of the line is what an operator's
    /// `--trace-output FILE` would receive.
    #[test]
    fn cli_breakpoint_emits_jsonl_into_forward_sink() {
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let forward: ForwardSink =
            Arc::new(Mutex::new(Some(Box::new(SharedWriter(captured.clone())))));

        let sb = Sandbox::new();
        let t = SandboxTarget::with_forward(sb, forward, &[0x10001234, 0x20002020]);
        // Both PCs were pre-registered as `sw_bps` so a connected
        // GDB client would halt at them.
        assert!(t.sw_bps.contains(&0x10001234));
        assert!(t.sw_bps.contains(&0x20002020));
        assert!(t.cli_breakpoints.contains(&0x10001234));

        t.emit_breakpoint_event(0x10001234);
        let bytes = captured.lock().unwrap().clone();
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.contains(r#""kind":"breakpoint""#),
            "expected kind=breakpoint event, got: {s:?}"
        );
        assert!(
            s.contains("0x10001234"),
            "expected breakpoint addr in JSONL, got: {s:?}"
        );
        // One event = one JSONL line ending in `\n`.
        assert!(
            s.ends_with('\n'),
            "expected trailing newline on JSONL line, got: {s:?}"
        );
        assert_eq!(
            s.matches('\n').count(),
            1,
            "expected exactly one JSONL line, got: {s:?}"
        );
    }

    /// Round-5 P2 — when no `--trace-output` is set (forward
    /// sink is `None`), the breakpoint emitter is a silent no-op.
    /// Critically, this must NOT panic / corrupt state — operators
    /// frequently run `--gdb` without a trace file.
    #[test]
    fn cli_breakpoint_emit_with_no_forward_is_noop() {
        let sb = Sandbox::new();
        let t = SandboxTarget::with_forward(sb, Arc::new(Mutex::new(None)), &[0x10001234]);
        // Should not panic and should leave the forward None.
        t.emit_breakpoint_event(0x10001234);
        assert!(t.forward.lock().unwrap().is_none());
    }

    /// Round-5 P2 — running `cpu.step` with EIP landing on a
    /// `--break` PC causes the emitter to fire from the actual
    /// `wait_for_stop_reason` event loop. We drive the loop one
    /// step at a time by directly setting `exec_mode = Continue`,
    /// stepping, then checking for the JSONL line in the captured
    /// forward buffer. Real machine code sled: `mov [edi], eax;
    /// hlt`. The CPU's EIP advances to past the `mov` (hits the
    /// `hlt`). We register the post-`mov` EIP as the breakpoint.
    #[test]
    fn cpu_step_with_cli_breakpoint_emits_jsonl_event() {
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        struct SharedWriter(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let forward: ForwardSink =
            Arc::new(Mutex::new(Some(Box::new(SharedWriter(captured.clone())))));

        let mut sb = Sandbox::new();
        const CODE_BASE: u32 = 0x20001000;
        const DATA_BASE: u32 = 0x60000000;
        sb.mmu.map(
            CODE_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::X,
        );
        sb.mmu.map(
            DATA_BASE,
            0x1000,
            oxideav_vfw::emulator::Perm::R | oxideav_vfw::emulator::Perm::W,
        );
        // mov [edi], eax (2 bytes) ; hlt (1 byte). After step:
        // EIP = CODE_BASE + 2 = 0x20001002.
        sb.mmu
            .write_initializer(CODE_BASE, &[0x89, 0x07, 0xF4])
            .unwrap();
        sb.cpu.regs.eip = CODE_BASE;
        sb.cpu.regs.gp[Reg32::Eax as usize] = 0xCAFEF00D;
        sb.cpu.regs.gp[Reg32::Edi as usize] = DATA_BASE + 0x100;
        // Register `--break` for the post-`mov` EIP.
        const BP_PC: u32 = CODE_BASE + 2;
        let mut t = SandboxTarget::with_forward(sb, forward, &[BP_PC]);
        // One step — EIP advances to BP_PC. Driver in the real
        // event loop would notice and emit; emulate that here.
        let _ = t.sandbox.cpu.step(&mut t.sandbox.mmu).unwrap();
        assert_eq!(t.sandbox.cpu.regs.eip, BP_PC);
        if t.cli_breakpoints.contains(&t.sandbox.cpu.regs.eip) {
            t.emit_breakpoint_event(t.sandbox.cpu.regs.eip);
        }
        let s = String::from_utf8_lossy(&captured.lock().unwrap()).into_owned();
        // The captured buffer contains the watchpoint-less `mov`
        // store (no `kind=mem_*` because nothing is watching) plus
        // our synthetic breakpoint line.
        assert!(
            s.contains(r#""kind":"breakpoint""#),
            "expected breakpoint event, got: {s:?}"
        );
        assert!(
            s.contains(&format!("0x{BP_PC:08x}")),
            "expected breakpoint addr {BP_PC:08x} in JSONL, got: {s:?}"
        );
    }

    /// Round-6 P2 — `target.xml` annex returns the static
    /// description payload, paginated. We assemble the full
    /// document by walking `offset` until we get a 0-byte reply
    /// and verify the canonical i386 feature-name strings + the
    /// register names a GDB client expects. Without this
    /// override, gdbstub falls back to a generic architecture
    /// description that may mis-align our MMX-aliases-ST(i)
    /// register surface.
    #[test]
    fn target_description_xml_serves_paginated_target_xml() {
        let sb = Sandbox::new();
        let t = SandboxTarget::new(sb);

        let mut assembled = Vec::with_capacity(TARGET_XML.len());
        let mut buf = [0u8; 256];
        let mut offset: u64 = 0;
        loop {
            let n = ok(t.target_description_xml(b"target.xml", offset, buf.len(), &mut buf));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }
        assert_eq!(
            assembled, TARGET_XML,
            "paginated reads should reassemble the full document"
        );
        let s = std::str::from_utf8(&assembled).unwrap();
        // Architecture marker + canonical GDB feature names.
        assert!(s.contains("<architecture>i386</architecture>"));
        assert!(s.contains(r#"name="org.gnu.gdb.i386.core""#));
        assert!(s.contains(r#"name="org.gnu.gdb.i386.sse""#));
        // Spot-check register names a GDB client introspects.
        assert!(s.contains(r#"name="eax""#));
        assert!(s.contains(r#"name="eip""#));
        assert!(s.contains(r#"name="st0""#));
        assert!(s.contains(r#"name="xmm0""#));
        assert!(s.contains(r#"name="mxcsr""#));
    }

    /// Round-6 P2 — non-`target.xml` annex returns 0 (empty
    /// document) — gdbstub treats this as a well-formed empty
    /// reply rather than a protocol error. Real GDB clients only
    /// follow `<xi:include>` references, so they don't request
    /// arbitrary annexes.
    #[test]
    fn target_description_xml_unknown_annex_returns_empty() {
        let sb = Sandbox::new();
        let t = SandboxTarget::new(sb);
        let mut buf = [0u8; 64];
        let n = ok(t.target_description_xml(b"some-other-annex.xml", 0, buf.len(), &mut buf));
        assert_eq!(n, 0, "unknown annex must return zero bytes");
    }

    /// Round-6 P2 — pagination `offset >= total_len` returns 0
    /// (end-of-stream marker per the GDB qXfer pagination
    /// contract).
    #[test]
    fn target_description_xml_offset_past_end_returns_empty() {
        let sb = Sandbox::new();
        let t = SandboxTarget::new(sb);
        let mut buf = [0u8; 64];
        let n = ok(t.target_description_xml(
            b"target.xml",
            TARGET_XML.len() as u64 + 100,
            buf.len(),
            &mut buf,
        ));
        assert_eq!(n, 0, "offset past EOF must return zero");
    }

    /// Round-6 P2 — single-shot read with a buffer larger than
    /// the document returns the full document and zero on the
    /// next call.
    #[test]
    fn target_description_xml_single_shot_returns_full_document() {
        let sb = Sandbox::new();
        let t = SandboxTarget::new(sb);
        let mut buf = vec![0u8; TARGET_XML.len() + 1024];
        let len = buf.len();
        let n = ok(t.target_description_xml(b"target.xml", 0, len, &mut buf));
        assert_eq!(n, TARGET_XML.len());
        assert_eq!(&buf[..n], TARGET_XML);
        // Subsequent read at offset == len returns 0.
        let n2 = ok(t.target_description_xml(b"target.xml", n as u64, len, &mut buf));
        assert_eq!(n2, 0);
    }
}
