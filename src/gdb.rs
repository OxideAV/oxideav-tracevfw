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
use gdbstub::common::Pid;
use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::auxv::{Auxv, AuxvOps};
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
use gdbstub::target::ext::exec_file::{ExecFile, ExecFileOps};
use gdbstub::target::ext::host_io::{
    HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoOpen, HostIoOpenFlags,
    HostIoOpenMode, HostIoOpenOps, HostIoOps, HostIoPread, HostIoPreadOps, HostIoResult,
};
use gdbstub::target::ext::libraries::{Libraries, LibrariesOps};
use gdbstub::target::ext::memory_map::{MemoryMap, MemoryMapOps};
use gdbstub::target::ext::monitor_cmd::{outputln, ConsoleOutput, MonitorCmd, MonitorCmdOps};
use gdbstub::target::ext::target_description_xml_override::{
    TargetDescriptionXmlOverride, TargetDescriptionXmlOverrideOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::reg::id::X86CoreRegId;
use gdbstub_arch::x86::reg::X86CoreRegs;
use gdbstub_arch::x86::X86_SSE;
use oxideav_vfw::emulator::mmu::Perm;
use oxideav_vfw::emulator::regs::Reg32;
use oxideav_vfw::pe::sections::Section;
use oxideav_vfw::pe::Image;
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
    let mut target = SandboxTarget::with_forward(
        sandbox,
        forward,
        cli_breakpoints,
        image,
        name.clone(),
        bytes,
    );
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

/// Map a PE section's permission bits onto one of the three
/// values the GDB memory-map DTD admits (`ram` / `rom` /
/// `flash`). Writable sections become `ram` (matches the
/// "operator can poke this" intuition); read-only or
/// read-execute sections become `rom`. `flash` is reserved for
/// the embedded-flash semantics GDB attaches to it (separate
/// erase-block protocol) and is never the right answer for a
/// PE image.
fn section_memory_kind(sec: &Section) -> &'static str {
    if sec.perm.contains(Perm::W) {
        "ram"
    } else {
        "rom"
    }
}

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
    /// Round-7 P1 — memory-map XML rendered from the loaded PE
    /// image's section table at construction time. Lazily
    /// computed via [`SandboxTarget::build_memory_map_xml`] and
    /// stored as a single owned `String` so the
    /// `qXfer:memory-map:read` reader can paginate over a stable
    /// byte-slice without re-walking the section list per
    /// chunk. Empty when no PE image was loaded (e.g. operator
    /// passed a non-PE blob).
    memory_map_xml: String,
    /// Round-7 P2 — DLL/AX file basename a connected GDB client
    /// receives via `qXfer:exec-file:read`. Stored as a single
    /// `String` (rather than the path) so we don't expose the
    /// operator's local filesystem layout to the wire — `info
    /// file` shows the codec's natural name (`IR32_32.DLL`,
    /// `INDEO5.AX`, …) which is what an operator wants. Empty
    /// when no name was available.
    exec_file_name: String,
    /// Round-8 P1 — `<library-list>` XML rendered from the
    /// sandbox's loaded-module registry (`HostState::modules`)
    /// at construction time, served paginated over
    /// `qXfer:libraries:read`. One `<library>` element per
    /// `(name, image_base)` entry, with a single `<segment>`
    /// child whose `address` is the load base. Captures both
    /// the primary codec DLL the operator passed on the CLI
    /// AND every cascade-loaded module the kernel32 stubs
    /// recorded during `DllMain` (e.g. `kernel32.dll` itself,
    /// plus anything the codec pulled in via `LoadLibraryA`).
    /// Empty (`""`) when no modules are loaded — the
    /// `support_libraries` predicate is gated on non-empty so
    /// gdbstub doesn't advertise the extension to a client
    /// that would then mis-display the empty payload.
    library_list_xml: String,
    /// Round-9 P1 — synthetic ELF-style auxiliary-vector blob
    /// served over `qXfer:auxv:read`. We're emulating a Win32
    /// PE codec (no real ELF executable), but a connected GDB
    /// client's `info auxv` is happier with a non-empty
    /// well-formed reply than with the "auxv unsupported" path.
    /// The blob is a sequence of `(u32 key, u32 value)` pairs
    /// in little-endian terminated by `(AT_NULL=0, 0)`. The
    /// keys are the canonical System V ABI / Linux ELF auxv
    /// constants (see `<elf.h>` / `getauxval(3)` man page) so a
    /// real GDB client decodes them correctly. Empty when no
    /// PE image is available. Built eagerly at `with_forward`
    /// construction time by [`SandboxTarget::build_auxv_blob`].
    auxv_blob: Vec<u8>,
    /// Round-10 P2 — raw bytes of the codec DLL/AX file the
    /// operator passed on the CLI, retained so the round-10
    /// `vFile:open`/`vFile:pread`/`vFile:close` host_io extension
    /// can serve the file back to a connected GDB client. A
    /// remote GDB session that runs
    /// `add-symbol-file remote:<basename>` then triggers a
    /// `vFile:open` for that name; we match by basename and
    /// hand back the in-memory bytes paginated. Empty
    /// (`Vec::new()`) when no file was passed (e.g. tests that
    /// build a bare sandbox); the `support_host_io` predicate
    /// gates the extension on non-empty so gdbstub doesn't
    /// advertise a feature we'd answer with `ENOENT`.
    dll_bytes: Vec<u8>,
    /// Round-10 P2 — open `vFile:open` file descriptors. Each
    /// successful `vFile:open` allocates a new `u32` fd that
    /// indexes into this vector; `vFile:pread` looks the entry
    /// up + slices into [`Self::dll_bytes`]; `vFile:close`
    /// nulls the entry. We never deallocate fully so a stale
    /// `vFile:pread` after `close` returns `EBADF` rather than
    /// silently aliasing onto a future `open`. The shape is
    /// `Vec<Option<()>>` rather than `Vec<bool>` so a future
    /// expansion to multi-file (e.g. opening the codec's
    /// cascade-loaded DLLs) can carry per-fd state without a
    /// schema break. fd value 0 is reserved (POSIX stdin) so we
    /// always start allocations at 1; lookup uses
    /// `fd as usize - 1`.
    open_files: Vec<Option<()>>,
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
        Self::with_forward(
            sandbox,
            Arc::new(Mutex::new(None)),
            &[],
            None,
            String::new(),
            Vec::new(),
        )
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
    /// detached-client case. Round-7 P1+P2 also accept the loaded
    /// `Image` (used to render a `qXfer:memory-map:read` XML
    /// document) and the codec's filename (returned to the GDB
    /// client via `qXfer:exec-file:read` so `info file` shows
    /// `IR32_32.DLL` rather than the placeholder `<process N>`).
    pub fn with_forward(
        mut sandbox: Sandbox,
        forward: ForwardSink,
        cli_breakpoints: &[u32],
        image: Option<Image>,
        exec_file_name: String,
        dll_bytes: Vec<u8>,
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
        // Render the memory-map XML eagerly. Empty when no PE
        // image is available (the GDB protocol tolerates an empty
        // `qXfer:memory-map:read` reply — a client just sees no
        // entries in `info mem`).
        let memory_map_xml = match image.as_ref() {
            Some(img) => Self::build_memory_map_xml(img),
            None => String::new(),
        };
        // Render the `<library-list>` XML eagerly from the
        // sandbox's loaded-module registry. After `Sandbox::load`
        // + `call_dll_main` the registry contains the primary
        // DLL plus every cascade-loaded module the kernel32 /
        // user32 / gdi32 / vfw32 stubs registered. Empty when
        // no modules are loaded yet (e.g. a non-PE blob that
        // failed to load).
        let library_list_xml = Self::build_library_list_xml(&sandbox);
        // Round-9 P1 — render the synthetic auxv blob from the
        // loaded PE image. Empty when no image is available; the
        // `support_auxv` predicate gates the extension on this so
        // gdbstub reports "unsupported" cleanly rather than
        // serving an empty payload a client might mis-display.
        let auxv_blob = match image.as_ref() {
            Some(img) => Self::build_auxv_blob(img),
            None => Vec::new(),
        };
        Self {
            sandbox,
            sw_bps: cli_bps.clone(),
            hw_watches: Vec::new(),
            exec_mode: None,
            watch_queue,
            cli_breakpoints: cli_bps,
            forward,
            memory_map_xml,
            exec_file_name,
            library_list_xml,
            auxv_blob,
            dll_bytes,
            open_files: Vec::new(),
        }
    }

    /// Render a GDB `memory-map` XML document describing the
    /// loaded PE image's section ranges. Each section becomes a
    /// `<memory>` element whose `start` is the section's
    /// `va_start`, whose `length` is its `mapped_size` (already
    /// page-aligned), and whose `type` is `rom` for read-only or
    /// read-execute sections (`.text`, `.rdata`, …) and `ram`
    /// for writable ones (`.data`, `.bss`). The GDB DTD only
    /// admits `ram` / `rom` / `flash` (see
    /// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory-Map-Format.html>),
    /// so an executable + writable section (rare for a real codec
    /// but possible) is reported as `ram` to honour the
    /// "writable" precedence.
    ///
    /// Section names are emitted as XML comments preceding each
    /// `<memory>` element so an operator running
    /// `gdb> show memory-map` sees `.text` / `.data` annotations
    /// alongside the address ranges.
    fn build_memory_map_xml(image: &Image) -> String {
        let mut s = String::with_capacity(256 + image.sections.len() * 96);
        s.push_str(
            "<?xml version=\"1.0\"?>\n\
             <!DOCTYPE memory-map\n\
                       PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\"\n\
                              \"http://sourceware.org/gdb/gdb-memory-map.dtd\">\n\
             <memory-map>\n",
        );
        for sec in &image.sections {
            let kind = section_memory_kind(sec);
            // Sanitize the section name for use inside an XML
            // comment — strip embedded `--` (which would close
            // the comment) and any non-printable bytes. PE
            // section names are typically `.text` / `.data` / …
            // so this is defensive padding for the malformed
            // case.
            let mut safe = String::with_capacity(sec.name.len());
            let mut last_dash = false;
            for c in sec.name.chars() {
                if c.is_ascii_graphic() || c == ' ' {
                    if c == '-' && last_dash {
                        // skip — never emit `--` in a comment
                        continue;
                    }
                    last_dash = c == '-';
                    safe.push(c);
                } else {
                    last_dash = false;
                }
            }
            s.push_str("  <!-- ");
            s.push_str(&safe);
            s.push_str(" -->\n");
            s.push_str(&format!(
                "  <memory type=\"{}\" start=\"0x{:08x}\" length=\"0x{:x}\"/>\n",
                kind, sec.va_start, sec.mapped_size
            ));
        }
        s.push_str("</memory-map>\n");
        s
    }

    /// Render a GDB `<library-list>` XML document describing
    /// every module currently registered in the sandbox's
    /// `HostState::modules` map. Each entry becomes a
    /// `<library name="…"><segment address="0x…"/></library>`
    /// element, where `name` is the original case-folded module
    /// key (`kernel32.dll`, `synth.dll`, `ir50_32.dll`, …) and
    /// `address` is the load-base the loader assigned (the same
    /// value `LoadLibraryA` / `GetModuleHandleA` would return
    /// for that name).
    ///
    /// The schema follows the GDB protocol manual's "Library
    /// List Format" §, with the segment-style child preferred
    /// over `<section>` because a PE image's segment-equivalent
    /// (the `image_base`) is one stable address, whereas
    /// reproducing every PE section as a `<section>` would
    /// duplicate the `qXfer:memory-map:read` payload (round 7).
    /// See <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Library-List-Format.html>.
    ///
    /// XML attribute escaping is minimal — module names are
    /// canonicalised to lowercase ASCII by the loader so they
    /// don't contain `<` / `>` / `&` / `"`. Defensive escaping
    /// is still applied for robustness (e.g. in case a future
    /// codec passes a path-style name through `LoadLibraryA`).
    ///
    /// Returns `String::new()` when no modules are registered;
    /// the `support_libraries` predicate is gated on this so
    /// gdbstub doesn't advertise an extension we'd answer with
    /// an empty payload.
    fn build_library_list_xml(sandbox: &Sandbox) -> String {
        let modules = &sandbox.host.modules;
        if modules.is_empty() {
            return String::new();
        }
        let mut s = String::with_capacity(96 + modules.len() * 80);
        s.push_str("<?xml version=\"1.0\"?>\n");
        s.push_str("<library-list version=\"1.0\">\n");
        for (name, base) in modules.iter() {
            // XML attribute-value escaping for the five reserved
            // characters: `<` / `>` / `&` / `"` / `'`. Module
            // names are lowercase ASCII in practice, but be
            // defensive — a malformed `LoadLibraryA` argument
            // could otherwise corrupt the document.
            let mut safe = String::with_capacity(name.len());
            for c in name.chars() {
                match c {
                    '<' => safe.push_str("&lt;"),
                    '>' => safe.push_str("&gt;"),
                    '&' => safe.push_str("&amp;"),
                    '"' => safe.push_str("&quot;"),
                    '\'' => safe.push_str("&apos;"),
                    c if c.is_ascii_graphic() || c == ' ' => safe.push(c),
                    // Drop unprintable characters silently —
                    // attribute values can't carry them.
                    _ => {}
                }
            }
            s.push_str("  <library name=\"");
            s.push_str(&safe);
            s.push_str("\"><segment address=\"0x");
            s.push_str(&format!("{base:08x}"));
            s.push_str("\"/></library>\n");
        }
        s.push_str("</library-list>\n");
        s
    }

    /// Build a synthetic ELF-style auxiliary-vector blob
    /// describing the loaded PE image — surfaced to a connected
    /// GDB client's `info auxv` over `qXfer:auxv:read`.
    ///
    /// Encoding: a sequence of `(u32 key, u32 value)` pairs in
    /// little-endian, terminated by `(AT_NULL=0, 0)`. The keys
    /// are the canonical System V ABI / Linux ELF auxv constants
    /// (`<elf.h>` / `getauxval(3)`):
    ///
    /// - `AT_PHDR  = 3` — VA of the PE image headers (= `image_base`).
    ///   PE has no ELF program headers, but a real GDB client's
    ///   `info auxv` shows this as the "executable program-header
    ///   table" pointer; pointing it at the PE headers is the
    ///   closest semantic match.
    /// - `AT_PHENT = 4` — size of one PE `IMAGE_SECTION_HEADER`
    ///   (40 bytes per the PE/COFF spec). ELF clients expecting
    ///   `Elf32_Phdr` (32 bytes) will mis-decode the entries, but
    ///   the synthetic value is still the right shape for the
    ///   tracevfw operator who wants to see "PE section headers
    ///   are 40 bytes wide".
    /// - `AT_PHNUM = 5` — number of PE sections.
    /// - `AT_PAGESZ = 6` — emulator page size (= 0x1000).
    /// - `AT_BASE  = 7` — load base of the codec DLL
    ///   (= `image_base`). The PE's preferred load address.
    /// - `AT_FLAGS = 8` — zero (no auxv flags relevant for our
    ///   sandbox; honouring the "advertise the key, value=0 if
    ///   unknown" Linux ABI convention).
    /// - `AT_ENTRY = 9` — codec entry-point VA (= `entry_point`,
    ///   already resolved to `image_base + AddressOfEntryPoint`).
    /// - `AT_NULL  = 0` — terminator, encoded as `(0, 0)`.
    ///
    /// Width: 32-bit because the sandbox is i386 (matches our
    /// `X86_SSE` arch description); a 64-bit GDB client connected
    /// to an i386 target reads auxv entries as 32-bit pairs per
    /// the GDB protocol manual's qXfer:auxv:read note.
    ///
    /// References:
    /// - GDB RSP manual §"qXfer:auxv:read" — payload semantics.
    ///   <https://sourceware.org/gdb/current/onlinedocs/gdb.html/General-Query-Packets.html>
    /// - `getauxval(3)` man page — AT_* key meanings.
    ///   <https://man7.org/linux/man-pages/man3/getauxval.3.html>
    fn build_auxv_blob(image: &Image) -> Vec<u8> {
        const AT_NULL: u32 = 0;
        const AT_PHDR: u32 = 3;
        const AT_PHENT: u32 = 4;
        const AT_PHNUM: u32 = 5;
        const AT_PAGESZ: u32 = 6;
        const AT_BASE: u32 = 7;
        const AT_FLAGS: u32 = 8;
        const AT_ENTRY: u32 = 9;
        // Eight (key,value) pairs × 8 bytes each = 64 bytes.
        let mut out = Vec::with_capacity(64);
        let mut push = |key: u32, val: u32| {
            out.extend_from_slice(&key.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        };
        push(AT_PHDR, image.image_base);
        // PE/COFF spec — `IMAGE_SECTION_HEADER` is 40 bytes
        // (`IMAGE_SIZEOF_SECTION_HEADER`). We surface this for
        // operators who want a hint that PE section headers are
        // _not_ ELF Elf32_Phdr (28-byte) entries.
        push(AT_PHENT, 40);
        push(AT_PHNUM, image.sections.len() as u32);
        push(AT_PAGESZ, 0x1000);
        push(AT_BASE, image.image_base);
        push(AT_FLAGS, 0);
        push(AT_ENTRY, image.entry_point);
        // AT_NULL terminator — value field is also 0 per the
        // ELF ABI convention.
        push(AT_NULL, 0);
        out
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

    /// Round-7 P1 — advertise `qXfer:memory-map:read` so a
    /// connected GDB client's `info mem` / `maintenance info
    /// sections` shows the loaded codec's PE section table
    /// (`.text` r-x, `.data` rw-, `.rdata` r--, `.bss` rw-, …)
    /// instead of "no memory regions". The XML document is
    /// rendered eagerly at `with_forward` time from the loaded
    /// `Image::sections` and stored on `Self::memory_map_xml`,
    /// so the per-chunk reader is a flat byte-slice paginator.
    /// See
    /// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory-Map-Format.html>
    /// for the schema we follow.
    fn support_memory_map(&mut self) -> Option<MemoryMapOps<'_, Self>> {
        if self.memory_map_xml.is_empty() {
            None
        } else {
            Some(self)
        }
    }

    /// Round-7 P2 — advertise `qXfer:exec-file:read` so a GDB
    /// client's `info file` shows the codec's basename
    /// (`IR32_32.DLL`, `INDEO5.AX`, …) instead of the placeholder
    /// `<process N>` gdbstub falls back to. We never had a real
    /// executable path to surface here in earlier rounds, but
    /// the operator-facing `--gdb` UX improves significantly
    /// when stack frames + `info file` show the codec's actual
    /// name. Returns `None` when no DLL name was available so
    /// gdbstub can report "unsupported" cleanly rather than
    /// returning an empty string the client might mis-display.
    fn support_exec_file(&mut self) -> Option<ExecFileOps<'_, Self>> {
        if self.exec_file_name.is_empty() {
            None
        } else {
            Some(self)
        }
    }

    /// Round-8 P1 — advertise `qXfer:libraries:read` so a
    /// connected GDB client's `info sharedlibrary` shows the
    /// loaded-module registry the codec built up during
    /// `DllMain` (the primary DLL the operator passed on the
    /// CLI plus every cascade-loaded module the kernel32 /
    /// user32 / gdi32 / vfw32 stubs registered while the codec
    /// pulled in its dependencies via `LoadLibraryA`).
    ///
    /// Many VfW codec DLLs cascade-load other system DLLs at
    /// runtime — `mpg4c32` typically pulls in `msacm32.dll`
    /// for codec configuration UI, `IR50_32.DLL` calls
    /// `LoadLibraryA("INDEO5.DLL")` to delegate to its
    /// helper module, etc. Surfacing the full list lets a GDB
    /// client step into those cascade-loaded modules and
    /// inspect their address ranges without hand-crafting a
    /// `add-symbol-file <path> <base>` command per cascade.
    ///
    /// Returns `None` when the registry is empty (e.g. operator
    /// passed a non-PE blob that failed to load) so gdbstub can
    /// report "unsupported" cleanly rather than serving an empty
    /// payload a client might mis-display. See
    /// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Library-List-Format.html>
    /// for the schema.
    fn support_libraries(&mut self) -> Option<LibrariesOps<'_, Self>> {
        if self.library_list_xml.is_empty() {
            None
        } else {
            Some(self)
        }
    }

    /// Round-9 P1 — advertise `qXfer:auxv:read` so a connected
    /// GDB client's `info auxv` shows the codec's PE entry,
    /// image base, and section count instead of "auxv
    /// unsupported". The blob was rendered eagerly at
    /// `with_forward` time from the loaded `Image`'s
    /// `entry_point` / `image_base` / `sections.len()`. Returns
    /// `None` when no PE image is available so gdbstub doesn't
    /// advertise an extension we'd answer with an empty payload.
    /// See the GDB protocol manual §"qXfer:auxv:read" and
    /// `getauxval(3)` for the AT_* key semantics.
    fn support_auxv(&mut self) -> Option<AuxvOps<'_, Self>> {
        if self.auxv_blob.is_empty() {
            None
        } else {
            Some(self)
        }
    }

    /// Round-10 P1 — advertise `qRcmd` (the GDB `monitor`
    /// command) so an operator at a connected GDB prompt can
    /// introspect sandbox state without leaving the debugger.
    /// We surface the four most operator-useful pieces of
    /// state as monitor commands:
    ///
    /// - `monitor stats` — instruction count, sw breakpoints
    ///   count, hw watchpoints count, loaded modules count,
    ///   open vFile fds count.
    /// - `monitor watches` — one line per registered hw
    ///   watchpoint (`addr len kind`).
    /// - `monitor breakpoints` — one line per registered sw
    ///   breakpoint (PC). Includes both client-installed
    ///   `Z0`-packet breakpoints and CLI `--break` ones.
    /// - `monitor modules` — one line per loaded module
    ///   (`name image_base`), mirroring what
    ///   `qXfer:libraries:read` shows but human-readable.
    /// - `monitor help` — list of known commands.
    ///
    /// The extension is always available — these queries do
    /// not depend on a loaded image. See the GDB protocol
    /// manual §"qRcmd" for the wire-level contract: payload
    /// is hex-decoded by gdbstub before reaching our
    /// `handle_monitor_cmd` impl, output is hex-encoded back
    /// over the wire by the `outputln!` / `output!` macros.
    fn support_monitor_cmd(&mut self) -> Option<MonitorCmdOps<'_, Self>> {
        Some(self)
    }

    /// Round-10 P2 — advertise the host_io extension
    /// (`vFile:open` / `vFile:pread` / `vFile:close`) so a
    /// connected GDB client can `add-symbol-file remote:<NAME>`
    /// to fetch the codec DLL bytes back over the wire and
    /// resolve symbols in the loaded image. The fileserver
    /// only knows one file — the codec DLL the operator passed
    /// on the CLI — and matches by basename. Other paths
    /// resolve to `ENOENT`. Returns `None` when no DLL bytes
    /// were retained (e.g. the test-only `SandboxTarget::new`
    /// shorthand) so gdbstub cleanly reports "unsupported"
    /// rather than answering every `open` with `ENOENT`. See
    /// the GDB RSP manual §"Host I/O Packets" for the wire
    /// contract:
    /// <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Host-I_002fO-Packets.html>
    fn support_host_io(&mut self) -> Option<HostIoOps<'_, Self>> {
        if self.dll_bytes.is_empty() {
            None
        } else {
            Some(self)
        }
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

impl MemoryMap for SandboxTarget {
    /// Round-7 P1 — serve the pre-rendered memory-map XML
    /// document over the `qXfer:memory-map:read` paginated
    /// transfer. The document was assembled from the loaded
    /// PE image's `Image::sections` at construction time (see
    /// [`SandboxTarget::build_memory_map_xml`]) so per-chunk
    /// reads are a flat byte-slice walk. Pagination contract
    /// matches the GDB protocol: an `offset` past the end
    /// returns `0` (empty / EOF), shorter trailing chunks are
    /// the natural end-of-document signal.
    fn memory_map_xml(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let total = self.memory_map_xml.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let bytes = self.memory_map_xml.as_bytes();
        let start = offset as usize;
        let remaining = bytes.len() - start;
        let n = remaining.min(length).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }
}

impl Libraries for SandboxTarget {
    /// Round-8 P1 — serve the pre-rendered `<library-list>` XML
    /// document over the `qXfer:libraries:read` paginated
    /// transfer. The document was assembled at construction
    /// time from the sandbox's `HostState::modules` map (see
    /// [`SandboxTarget::build_library_list_xml`]) so per-chunk
    /// reads are a flat byte-slice walk. Pagination matches the
    /// GDB qXfer contract — `offset` past the end returns `0`
    /// (gdbstub frames this as the `l<empty>` end-of-stream
    /// reply).
    fn get_libraries(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let bytes = self.library_list_xml.as_bytes();
        let total = bytes.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        let remaining = bytes.len() - start;
        let n = remaining.min(length).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }
}

impl Auxv for SandboxTarget {
    /// Round-9 P1 — serve the pre-rendered ELF-style auxiliary
    /// vector blob over the `qXfer:auxv:read` paginated
    /// transfer. The blob was assembled at construction time
    /// from the loaded `Image`'s `image_base` / `entry_point` /
    /// `sections.len()` (see [`SandboxTarget::build_auxv_blob`])
    /// so per-chunk reads are a flat byte-slice walk.
    /// Pagination matches the GDB qXfer contract — `offset`
    /// past the end returns `0` (gdbstub frames this as the
    /// `l<empty>` end-of-stream reply).
    fn get_auxv(&self, offset: u64, length: usize, buf: &mut [u8]) -> TargetResult<usize, Self> {
        let bytes = self.auxv_blob.as_slice();
        let total = bytes.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        let remaining = bytes.len() - start;
        let n = remaining.min(length).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }
}

impl MonitorCmd for SandboxTarget {
    /// Round-10 P1 — handle a `monitor <cmd>` packet from a
    /// connected GDB client. The first whitespace-separated
    /// token is the command name; remaining tokens are
    /// arguments (currently only `help` consumes them, by
    /// ignoring them). Output goes back to the GDB console via
    /// the `outputln!` macro.
    ///
    /// Unknown commands respond with `unknown monitor command:
    /// <cmd>; try 'monitor help'` so the operator gets a hint
    /// instead of silent failure. UTF-8 decoding is best-effort
    /// per the GDB protocol contract — the `cmd` payload is
    /// already hex-decoded into bytes by gdbstub before
    /// reaching here, but the spec doesn't mandate UTF-8.
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ConsoleOutput<'_>,
    ) -> Result<(), Self::Error> {
        // Lossy UTF-8: monitor commands are always typed by a
        // human at a `(gdb)` prompt so non-UTF-8 is a malformed
        // request we can flag with an unknown-command reply.
        let cmd_str = String::from_utf8_lossy(cmd);
        let trimmed = cmd_str.trim();
        // First token is the command name; we don't use args
        // for any of the round-10 commands but split for
        // future-proofing (e.g. `monitor watches add 0x… 4 r`
        // could land in a later round).
        let mut parts = trimmed.split_whitespace();
        let head = parts.next().unwrap_or("");
        match head {
            "" => {
                outputln!(out, "(empty monitor command; try 'monitor help')");
            }
            "help" => {
                outputln!(out, "oxidetracevfw monitor commands:");
                outputln!(out, "  stats         sandbox + GDB-state counters");
                outputln!(out, "  watches       list registered HW watchpoints");
                outputln!(out, "  breakpoints   list registered SW breakpoints");
                outputln!(out, "  modules       list loaded PE modules");
                outputln!(out, "  help          this help");
            }
            "stats" => {
                outputln!(out, "instr_count={}", self.sandbox.cpu.instr_count);
                outputln!(out, "sw_breakpoints={}", self.sw_bps.len());
                outputln!(out, "cli_breakpoints={}", self.cli_breakpoints.len());
                outputln!(out, "hw_watchpoints={}", self.hw_watches.len());
                outputln!(out, "loaded_modules={}", self.sandbox.host.modules.len());
                outputln!(out, "open_vfile_fds={}", self.live_open_fds());
                outputln!(out, "exec_file={}", self.exec_file_name);
            }
            "watches" => {
                if self.hw_watches.is_empty() {
                    outputln!(out, "(no HW watchpoints registered)");
                } else {
                    for w in &self.hw_watches {
                        let kind = match w.kind {
                            WatchKind::Read => "r",
                            WatchKind::Write => "w",
                            WatchKind::ReadWrite => "rw",
                        };
                        outputln!(out, "0x{:08x} len={} kind={}", w.addr, w.len, kind);
                    }
                }
            }
            "breakpoints" => {
                if self.sw_bps.is_empty() {
                    outputln!(out, "(no SW breakpoints registered)");
                } else {
                    for pc in &self.sw_bps {
                        let tag = if self.cli_breakpoints.contains(pc) {
                            " (cli)"
                        } else {
                            ""
                        };
                        outputln!(out, "0x{:08x}{}", pc, tag);
                    }
                }
            }
            "modules" => {
                if self.sandbox.host.modules.is_empty() {
                    outputln!(out, "(no modules loaded)");
                } else {
                    for (name, base) in self.sandbox.host.modules.iter() {
                        outputln!(out, "0x{:08x} {}", base, name);
                    }
                }
            }
            other => {
                outputln!(
                    out,
                    "unknown monitor command: {}; try 'monitor help'",
                    other
                );
            }
        }
        Ok(())
    }
}

impl HostIo for SandboxTarget {
    /// Round-10 P2 — wire `vFile:open`. The codec DLL is the
    /// only file we serve, matched by basename so an operator
    /// running `(gdb) add-symbol-file remote:IR32_32.DLL`
    /// resolves regardless of the codec's local path on the
    /// debugger host.
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    /// Round-10 P2 — wire `vFile:pread`. Reads slice into the
    /// retained DLL bytes; returns `EBADF` on stale fd.
    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    /// Round-10 P2 — wire `vFile:close`. Frees the slot in our
    /// `open_files` table; never fails for a known fd, returns
    /// `EBADF` for unknown ones.
    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for SandboxTarget {
    /// Round-10 P2 — open the requested filename if it matches
    /// our retained codec DLL's basename (case-insensitive,
    /// matching how Win32 `LoadLibraryA` treats DLL names).
    /// Returns `ENOENT` for any other name. We ignore `flags`
    /// because we only ever serve a read-only in-memory view —
    /// `O_WRONLY` / `O_RDWR` requests are also accepted (we
    /// just won't honour writes via `support_pwrite` — which we
    /// don't advertise — so the client will get a "not
    /// supported" wire-level reply if it tries to write).
    /// `mode` is similarly ignored: nothing here creates a
    /// new file.
    fn open(
        &mut self,
        filename: &[u8],
        _flags: HostIoOpenFlags,
        _mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        // Lossy UTF-8: filenames in the GDB host_io packet are
        // always ASCII in practice (a `vFile:open
        // remote:<NAME>` decoded by `add-symbol-file`).
        let name = String::from_utf8_lossy(filename);
        // Strip a single leading slash so the GDB form
        // `vFile:open /IR32_32.DLL` (which gdb-on-host
        // sometimes sends) and the bare-basename form both
        // resolve. Then take the basename (everything after
        // the final `/` or `\`).
        let trimmed = name.trim_start_matches('/');
        let basename = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
        if !basename.eq_ignore_ascii_case(&self.exec_file_name) {
            return Err(HostIoError::Errno(HostIoErrno::ENOENT));
        }
        // Allocate a fresh fd. fd=0 is reserved per POSIX
        // convention; our wire fd is `slot_index + 1`.
        self.open_files.push(Some(()));
        let fd = self.open_files.len() as u32;
        Ok(fd)
    }
}

impl HostIoPread for SandboxTarget {
    /// Round-10 P2 — paginated read into the retained DLL
    /// bytes. `offset` past EOF returns 0 (EOF marker per
    /// the GDB host_io contract); short trailing reads are
    /// the natural document terminator.
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        // Validate fd: 1..=open_files.len() and slot must be Some.
        if fd == 0 {
            return Err(HostIoError::Errno(HostIoErrno::EBADF));
        }
        let idx = fd as usize - 1;
        match self.open_files.get(idx) {
            Some(Some(())) => {}
            _ => return Err(HostIoError::Errno(HostIoErrno::EBADF)),
        }
        let total = self.dll_bytes.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        let remaining = self.dll_bytes.len() - start;
        let n = remaining.min(count).min(buf.len());
        buf[..n].copy_from_slice(&self.dll_bytes[start..start + n]);
        Ok(n)
    }
}

impl HostIoClose for SandboxTarget {
    /// Round-10 P2 — release the fd slot. Stale `vFile:close`
    /// after a previous close returns `EBADF` rather than
    /// silently succeeding.
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        if fd == 0 {
            return Err(HostIoError::Errno(HostIoErrno::EBADF));
        }
        let idx = fd as usize - 1;
        match self.open_files.get_mut(idx) {
            Some(slot @ Some(())) => {
                *slot = None;
                Ok(())
            }
            _ => Err(HostIoError::Errno(HostIoErrno::EBADF)),
        }
    }
}

impl SandboxTarget {
    /// Count of currently-open `vFile` fds. Used by `monitor
    /// stats`. We don't store this as a counter because
    /// `Vec<Option<()>>` is the source of truth and divergence
    /// would be a worse bug than the O(n) walk on every
    /// `monitor stats` invocation (where n is bounded by a
    /// real GDB session's lifetime symbol-loads — typically
    /// 1 or 2).
    fn live_open_fds(&self) -> usize {
        self.open_files.iter().filter(|s| s.is_some()).count()
    }
}

impl ExecFile for SandboxTarget {
    /// Round-7 P2 — return the codec's filename (the basename
    /// the operator passed via the CLI `dll_or_ax_file`
    /// argument). The GDB client uses this for `info file` and
    /// frame display. We ignore `_pid` because the sandbox is
    /// strictly single-process; any `pid` GDB might supply
    /// resolves to the same DLL.
    ///
    /// Pagination matches the GDB qXfer contract — `offset`
    /// past the end returns `0` (gdbstub frames this as the
    /// `l<empty>` end-of-stream reply).
    fn get_exec_file(
        &self,
        _pid: Option<Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let bytes = self.exec_file_name.as_bytes();
        let total = bytes.len() as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        let remaining = bytes.len() - start;
        let n = remaining.min(length).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
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

    /// Helper — `HostIoError<anyhow::Error>` mirrors the
    /// TargetError shape but doesn't impl Debug, so the same
    /// promote-or-panic helper is needed for the host_io tests.
    /// Returns the success value or formats the errno on the
    /// way to the panic.
    fn ok_io<T>(r: HostIoResult<T, SandboxTarget>) -> T {
        match r {
            Ok(v) => v,
            Err(HostIoError::Errno(n)) => panic!("host_io errno: {n:?}"),
            Err(HostIoError::Fatal(e)) => panic!("host_io fatal: {e}"),
        }
    }

    /// Helper — assert a host_io call returned `EBADF`. We
    /// can't take a `HostIoErrno` parameter because that enum
    /// doesn't impl `PartialEq` in gdbstub 0.7.10, so each
    /// expected errno gets its own asserter. The two we
    /// exercise (ENOENT, EBADF) cover the round-10 surface.
    fn assert_io_ebadf<T>(r: HostIoResult<T, SandboxTarget>, what: &str) {
        match r {
            Err(HostIoError::Errno(HostIoErrno::EBADF)) => {}
            Err(HostIoError::Errno(_)) => panic!("{what}: expected EBADF, got other errno"),
            Err(HostIoError::Fatal(e)) => panic!("{what}: expected EBADF, got fatal: {e}"),
            Ok(_) => panic!("{what}: expected EBADF, got Ok(_)"),
        }
    }

    /// Helper — assert a host_io call returned `ENOENT`.
    fn assert_io_enoent<T>(r: HostIoResult<T, SandboxTarget>, what: &str) {
        match r {
            Err(HostIoError::Errno(HostIoErrno::ENOENT)) => {}
            Err(HostIoError::Errno(_)) => panic!("{what}: expected ENOENT, got other errno"),
            Err(HostIoError::Fatal(e)) => panic!("{what}: expected ENOENT, got fatal: {e}"),
            Ok(_) => panic!("{what}: expected ENOENT, got Ok(_)"),
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
        let mut t = SandboxTarget::with_forward(sb, forward, &[], None, String::new(), Vec::new());

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
        let t = SandboxTarget::with_forward(
            sb,
            forward,
            &[0x10001234, 0x20002020],
            None,
            String::new(),
            Vec::new(),
        );
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
        let t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[0x10001234],
            None,
            String::new(),
            Vec::new(),
        );
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
        let mut t =
            SandboxTarget::with_forward(sb, forward, &[BP_PC], None, String::new(), Vec::new());
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

    /// Helper — load the synthetic minimal-PE32 DLL into a fresh
    /// sandbox and return both the `Sandbox` and the `Image` so
    /// we can drive the round-7 P1 (memory-map) tests against
    /// real PE section data without dragging in a full codec.
    fn synth_sandbox_with_image() -> (Sandbox, Image) {
        let bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
        let mut sb = Sandbox::new();
        let img = sb.load("synth.dll", &bytes).expect("load synth dll");
        (sb, img)
    }

    /// Round-7 P1 — `build_memory_map_xml` walks the loaded PE
    /// image's sections and produces a well-formed GDB memory-map
    /// document that lists each section's `va_start` + length and
    /// classifies it as `ram` (writable) or `rom` (read-only).
    /// We assert the canonical wrapper plus at least one
    /// `<memory>` element for the synthetic DLL's `.text`
    /// section, which is mapped at `image_base + 0x1000` in
    /// `build_minimal_dll`.
    #[test]
    fn build_memory_map_xml_contains_section_entries() {
        let (_, img) = synth_sandbox_with_image();
        let xml = SandboxTarget::build_memory_map_xml(&img);

        // Canonical document boundaries.
        assert!(
            xml.starts_with("<?xml version=\"1.0\"?>"),
            "missing XML prologue: {xml:?}"
        );
        assert!(
            xml.contains("<!DOCTYPE memory-map"),
            "missing memory-map DOCTYPE: {xml:?}"
        );
        assert!(
            xml.contains("<memory-map>"),
            "missing root element: {xml:?}"
        );
        assert!(
            xml.trim_end().ends_with("</memory-map>"),
            "missing closing tag: {xml:?}"
        );

        // The synthetic DLL has a `.text` section. The exact
        // byte-window depends on the test image but the section
        // start address is well-known to be `image_base + 0x1000`.
        let expected_text_start = format!("0x{:08x}", img.image_base.wrapping_add(0x1000));
        assert!(
            xml.contains(&expected_text_start),
            "missing .text VA `{expected_text_start}` in: {xml:?}"
        );

        // `.text` is execute-only or read+execute — never
        // writable — so its kind should be `rom`. We don't need
        // to over-fit the test; a literal `type="rom"` somewhere
        // is sufficient evidence the perm classifier ran.
        assert!(
            xml.contains(r#"type="rom""#),
            "expected at least one rom section in: {xml:?}"
        );
    }

    /// Round-7 P1 — `support_memory_map` returns `Some` when an
    /// `Image` was provided and `None` otherwise. Honours the
    /// "advertise extension only when we have data" contract so
    /// gdbstub doesn't tell a connected GDB client we support
    /// the extension and then return an empty document on every
    /// chunk (which clients sometimes mishandle).
    #[test]
    fn support_memory_map_gated_on_image_presence() {
        // No image — extension should be unavailable.
        let mut t_none = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_memory_map(&mut t_none).is_none());

        // With an image — extension is wired.
        let (sb, img) = synth_sandbox_with_image();
        let mut t_some = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            Some(img),
            "synth.dll".to_string(),
            Vec::new(),
        );
        assert!(Target::support_memory_map(&mut t_some).is_some());
    }

    /// Round-7 P1 — `qXfer:memory-map:read` paginates the
    /// rendered XML correctly: assembling chunks of arbitrary
    /// length yields the full document, offset-past-end returns 0.
    #[test]
    fn memory_map_xml_paginates_correctly() {
        let (sb, img) = synth_sandbox_with_image();
        let t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            Some(img),
            "synth.dll".to_string(),
            Vec::new(),
        );
        let mut assembled: Vec<u8> = Vec::new();
        let mut buf = [0u8; 32];
        let mut offset: u64 = 0;
        loop {
            let n = ok(MemoryMap::memory_map_xml(&t, offset, buf.len(), &mut buf));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }
        assert_eq!(assembled.as_slice(), t.memory_map_xml.as_bytes());

        // Past-EOF read returns 0.
        let mut buf2 = [0u8; 32];
        let n = ok(MemoryMap::memory_map_xml(
            &t,
            t.memory_map_xml.len() as u64 + 100,
            buf2.len(),
            &mut buf2,
        ));
        assert_eq!(n, 0);
    }

    /// Round-7 P2 — `support_exec_file` returns `Some` only
    /// when a non-empty filename was provided. Empty name is
    /// the "no DLL loaded" case (e.g. operator passed a non-PE
    /// blob) and we shouldn't advertise the extension to a
    /// client that would then mis-display the empty payload.
    #[test]
    fn support_exec_file_gated_on_name_presence() {
        let mut t_none = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_exec_file(&mut t_none).is_none());

        let mut t_some = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "IR32_32.DLL".to_string(),
            Vec::new(),
        );
        assert!(Target::support_exec_file(&mut t_some).is_some());
    }

    /// Round-7 P2 — `get_exec_file` returns the codec basename
    /// across paginated reads regardless of `pid` (the sandbox
    /// is single-process, so `Some(_)` and `None` resolve the
    /// same name).
    #[test]
    fn get_exec_file_returns_basename_paginated() {
        let t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "INDEO5.AX".to_string(),
            Vec::new(),
        );
        // Single-shot read covers the whole name.
        let mut buf = [0u8; 64];
        let n = ok(ExecFile::get_exec_file(&t, None, 0, buf.len(), &mut buf));
        assert_eq!(n, "INDEO5.AX".len());
        assert_eq!(&buf[..n], b"INDEO5.AX");

        // Paginated read — 4 bytes per chunk — assembles the
        // same string.
        let mut assembled: Vec<u8> = Vec::new();
        let mut tiny = [0u8; 4];
        let mut offset: u64 = 0;
        loop {
            let n = ok(ExecFile::get_exec_file(
                &t,
                None,
                offset,
                tiny.len(),
                &mut tiny,
            ));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&tiny[..n]);
            offset += n as u64;
        }
        assert_eq!(assembled, b"INDEO5.AX");

        // `pid` is ignored — single-process sandbox.
        let pid: Pid = std::num::NonZeroUsize::new(42).expect("non-zero pid");
        let mut buf2 = [0u8; 64];
        let n = ok(ExecFile::get_exec_file(
            &t,
            Some(pid),
            0,
            buf2.len(),
            &mut buf2,
        ));
        assert_eq!(&buf2[..n], b"INDEO5.AX");
    }

    /// Round-7 P1 — `section_memory_kind` classifier maps the
    /// PE section permission bits onto the GDB memory-map DTD's
    /// `ram` / `rom` axis.
    #[test]
    fn section_memory_kind_classifies_perms() {
        // R-only → rom, R+X → rom, R+W → ram, R+W+X → ram.
        let mk = |perm: Perm| Section {
            name: "test".to_string(),
            va_start: 0,
            mapped_size: 0x1000,
            perm,
        };
        assert_eq!(section_memory_kind(&mk(Perm::R)), "rom");
        assert_eq!(section_memory_kind(&mk(Perm::R | Perm::X)), "rom");
        assert_eq!(section_memory_kind(&mk(Perm::R | Perm::W)), "ram");
        assert_eq!(section_memory_kind(&mk(Perm::R | Perm::W | Perm::X)), "ram");
    }

    /// Round-8 P1 — `build_library_list_xml` walks the sandbox's
    /// loaded-module registry and produces a well-formed GDB
    /// `<library-list>` document. We seed three entries with
    /// distinct image bases (the synthetic loader inserts the
    /// primary DLL keyed lowercase; we add cascade-loaded
    /// modules manually to mirror what `kernel32!LoadLibraryA`
    /// would do during `DllMain`).
    #[test]
    fn build_library_list_xml_contains_all_modules() {
        let mut sb = Sandbox::new();
        // Mirror the production loader's insertion shape:
        // lowercase ASCII name → image_base.
        sb.host.modules.insert("synth.dll".into(), 0x1000_0000);
        sb.host.modules.insert("kernel32.dll".into(), 0x7700_0000);
        sb.host.modules.insert("indeo5.dll".into(), 0x6800_0000);

        let xml = SandboxTarget::build_library_list_xml(&sb);

        // Canonical document boundaries.
        assert!(
            xml.starts_with("<?xml version=\"1.0\"?>"),
            "missing XML prologue: {xml:?}"
        );
        assert!(
            xml.contains("<library-list version=\"1.0\">"),
            "missing <library-list> root with version: {xml:?}"
        );
        assert!(
            xml.trim_end().ends_with("</library-list>"),
            "missing </library-list> closing tag: {xml:?}"
        );

        // Each module surfaces as a <library> with one segment.
        // The primary DLL's image base + names land in the doc.
        assert!(
            xml.contains(r#"<library name="synth.dll">"#),
            "missing synth.dll entry: {xml:?}"
        );
        assert!(
            xml.contains(r#"<library name="kernel32.dll">"#),
            "missing kernel32.dll entry: {xml:?}"
        );
        assert!(
            xml.contains(r#"<library name="indeo5.dll">"#),
            "missing indeo5.dll entry: {xml:?}"
        );
        // Image bases land inside <segment address="0x…"/>.
        assert!(
            xml.contains(r#"<segment address="0x10000000"/>"#),
            "missing synth.dll segment: {xml:?}"
        );
        assert!(
            xml.contains(r#"<segment address="0x77000000"/>"#),
            "missing kernel32.dll segment: {xml:?}"
        );
        assert!(
            xml.contains(r#"<segment address="0x68000000"/>"#),
            "missing indeo5.dll segment: {xml:?}"
        );
    }

    /// Round-8 P1 — `build_library_list_xml` returns the empty
    /// string when no modules are registered. The
    /// `support_libraries` predicate uses this to refuse to
    /// advertise the extension to a client that would otherwise
    /// see an empty payload.
    #[test]
    fn build_library_list_xml_empty_for_empty_registry() {
        let sb = Sandbox::new();
        // Fresh `Sandbox::new` doesn't load anything, so the
        // module map starts empty.
        assert!(sb.host.modules.is_empty());
        let xml = SandboxTarget::build_library_list_xml(&sb);
        assert!(
            xml.is_empty(),
            "expected empty XML for empty registry, got: {xml:?}"
        );
    }

    /// Round-8 P1 — `build_library_list_xml` escapes XML
    /// reserved characters in module names so a malformed
    /// `LoadLibraryA` argument can't corrupt the document.
    #[test]
    fn build_library_list_xml_escapes_attribute_specials() {
        let mut sb = Sandbox::new();
        sb.host
            .modules
            .insert(r#"weird<&">.dll"#.into(), 0x4000_0000);
        let xml = SandboxTarget::build_library_list_xml(&sb);
        // None of the raw `<` / `&` / `"` (other than the ones
        // delimiting attributes themselves) survive into the
        // `name=` attribute value.
        assert!(xml.contains("&lt;"), "expected &lt; escape, got: {xml:?}");
        assert!(xml.contains("&amp;"), "expected &amp; escape, got: {xml:?}");
        assert!(
            xml.contains("&quot;"),
            "expected &quot; escape, got: {xml:?}"
        );
        // The escaped form should not include a stray un-escaped
        // double-quote between the `name="` and `">` boundaries.
        // We extract the substring inside `name="…"` and check it.
        let attr_start = xml.find(r#"name=""#).unwrap() + r#"name=""#.len();
        let attr_end = xml[attr_start..]
            .find(r#"">"#)
            .map(|p| attr_start + p)
            .expect("attribute terminator");
        let attr = &xml[attr_start..attr_end];
        assert!(
            !attr.contains('"'),
            "attribute body should not contain raw quotes: {attr:?}"
        );
        assert!(
            !attr.contains('<'),
            "attribute body should not contain raw <: {attr:?}"
        );
    }

    /// Round-8 P1 — `support_libraries` returns `Some` when the
    /// registry is non-empty and `None` when empty, matching
    /// the contract of the round-7 `support_memory_map` /
    /// `support_exec_file` predicates: don't advertise a qXfer
    /// extension we'd answer with an empty payload.
    #[test]
    fn support_libraries_gated_on_registry_population() {
        // Empty registry — extension unavailable.
        let mut t_empty = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_libraries(&mut t_empty).is_none());

        // Registry populated via the synthetic-DLL load path —
        // extension wired.
        let (sb, _img) = synth_sandbox_with_image();
        let mut t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            Vec::new(),
        );
        assert!(Target::support_libraries(&mut t).is_some());
    }

    /// Round-8 P1 — `qXfer:libraries:read` paginates the rendered
    /// XML correctly: assembling chunks of arbitrary length
    /// yields the full document, offset-past-end returns 0.
    #[test]
    fn libraries_xml_paginates_correctly() {
        let (sb, _img) = synth_sandbox_with_image();
        let t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            Vec::new(),
        );

        let mut assembled: Vec<u8> = Vec::new();
        let mut buf = [0u8; 24];
        let mut offset: u64 = 0;
        loop {
            let n = ok(Libraries::get_libraries(&t, offset, buf.len(), &mut buf));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }
        assert_eq!(assembled.as_slice(), t.library_list_xml.as_bytes());

        // Past-EOF read returns 0.
        let mut buf2 = [0u8; 32];
        let n = ok(Libraries::get_libraries(
            &t,
            t.library_list_xml.len() as u64 + 100,
            buf2.len(),
            &mut buf2,
        ));
        assert_eq!(n, 0);
    }

    /// Round-8 P1 — after the synthetic DLL is loaded, the
    /// `<library-list>` document references the DLL's lowercase
    /// name + its image-base segment. `pe::test_image::build_minimal_dll`
    /// fixes the image_base at 0x10000000.
    #[test]
    fn libraries_xml_contains_synth_dll_entry_after_load() {
        let (sb, _img) = synth_sandbox_with_image();
        let t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            Vec::new(),
        );
        let xml = &t.library_list_xml;
        assert!(
            xml.contains(r#"<library name="synth.dll">"#),
            "expected synth.dll library entry, got: {xml:?}"
        );
        assert!(
            xml.contains(r#"<segment address="0x10000000"/>"#),
            "expected synth.dll image-base segment, got: {xml:?}"
        );
    }

    /// Round-9 P1 — `build_auxv_blob` walks the loaded PE image
    /// and produces a sequence of `(u32 key, u32 value)` pairs in
    /// little-endian terminated by `(AT_NULL=0, 0)`. We assert
    /// the encoding shape + every key surfaces with the expected
    /// value derived from the synthetic DLL's `image_base` /
    /// `entry_point` / `sections.len()`.
    #[test]
    fn build_auxv_blob_encodes_canonical_at_keys() {
        let (_, img) = synth_sandbox_with_image();
        let blob = SandboxTarget::build_auxv_blob(&img);

        // 8 entries × 8 bytes/entry = 64 bytes.
        assert_eq!(
            blob.len(),
            64,
            "expected 64-byte auxv blob (8 entries), got {} bytes",
            blob.len()
        );

        // Decode (u32 key, u32 value) pairs in little-endian.
        let read_le32 = |off: usize| -> u32 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&blob[off..off + 4]);
            u32::from_le_bytes(b)
        };
        let pairs: Vec<(u32, u32)> = (0..blob.len())
            .step_by(8)
            .map(|off| (read_le32(off), read_le32(off + 4)))
            .collect();

        // Canonical order matches `build_auxv_blob`'s layout —
        // PHDR/PHENT/PHNUM/PAGESZ/BASE/FLAGS/ENTRY/NULL.
        assert_eq!(
            pairs[0],
            (3, img.image_base),
            "AT_PHDR(3) should equal image_base, got: {pairs:?}"
        );
        assert_eq!(
            pairs[1],
            (4, 40),
            "AT_PHENT(4) should equal IMAGE_SIZEOF_SECTION_HEADER (40), got: {pairs:?}"
        );
        assert_eq!(
            pairs[2],
            (5, img.sections.len() as u32),
            "AT_PHNUM(5) should equal section count, got: {pairs:?}"
        );
        assert_eq!(
            pairs[3],
            (6, 0x1000),
            "AT_PAGESZ(6) should equal 0x1000, got: {pairs:?}"
        );
        assert_eq!(
            pairs[4],
            (7, img.image_base),
            "AT_BASE(7) should equal image_base, got: {pairs:?}"
        );
        assert_eq!(pairs[5], (8, 0), "AT_FLAGS(8) should be 0, got: {pairs:?}");
        assert_eq!(
            pairs[6],
            (9, img.entry_point),
            "AT_ENTRY(9) should equal entry_point, got: {pairs:?}"
        );
        assert_eq!(pairs[7], (0, 0), "AT_NULL(0) terminator, got: {pairs:?}");
    }

    /// Round-9 P1 — `support_auxv` returns `Some` when an
    /// `Image` was provided and `None` otherwise. Same gating
    /// contract the round-7 `support_memory_map` /
    /// `support_exec_file` predicates use: don't advertise a
    /// qXfer extension we'd answer with an empty payload.
    #[test]
    fn support_auxv_gated_on_image_presence() {
        let mut t_none = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_auxv(&mut t_none).is_none());

        let (sb, img) = synth_sandbox_with_image();
        let mut t_some = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            Some(img),
            "synth.dll".to_string(),
            Vec::new(),
        );
        assert!(Target::support_auxv(&mut t_some).is_some());
    }

    /// Round-9 P1 — `qXfer:auxv:read` paginates the rendered
    /// blob correctly: assembling chunks of arbitrary length
    /// yields the full payload, offset-past-end returns 0.
    /// Mirrors the round-7 / round-8 pagination tests.
    #[test]
    fn auxv_blob_paginates_correctly() {
        let (sb, img) = synth_sandbox_with_image();
        let t = SandboxTarget::with_forward(
            sb,
            Arc::new(Mutex::new(None)),
            &[],
            Some(img),
            "synth.dll".to_string(),
            Vec::new(),
        );

        let mut assembled: Vec<u8> = Vec::new();
        let mut buf = [0u8; 7]; // odd chunk size to exercise the slicer
        let mut offset: u64 = 0;
        loop {
            let n = ok(Auxv::get_auxv(&t, offset, buf.len(), &mut buf));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }
        assert_eq!(
            assembled.as_slice(),
            t.auxv_blob.as_slice(),
            "paginated reads should reassemble the full auxv blob"
        );

        // Past-EOF read returns 0.
        let mut buf2 = [0u8; 32];
        let n = ok(Auxv::get_auxv(
            &t,
            t.auxv_blob.len() as u64 + 100,
            buf2.len(),
            &mut buf2,
        ));
        assert_eq!(n, 0);
    }

    /// Round-9 P1 — `build_auxv_blob` returns a 64-byte blob
    /// even when the image has no sections (degenerate case the
    /// PE loader generally rejects, but the auxv builder must
    /// not panic on it). `AT_PHNUM` ends up as 0 and the rest
    /// of the keys still encode.
    #[test]
    fn build_auxv_blob_empty_sections_still_yields_terminator() {
        let img = Image {
            name: "empty".into(),
            image_base: 0x40000000,
            entry_point: 0x40001234,
            size_of_image: 0x1000,
            sections: Vec::new(),
            exports: std::collections::BTreeMap::new(),
        };
        let blob = SandboxTarget::build_auxv_blob(&img);
        assert_eq!(blob.len(), 64);
        // AT_PHNUM (5) → 0 — section count is zero.
        let phnum = u32::from_le_bytes(blob[20..24].try_into().unwrap());
        let phnum_key = u32::from_le_bytes(blob[16..20].try_into().unwrap());
        assert_eq!(phnum_key, 5);
        assert_eq!(phnum, 0);
        // AT_NULL terminator at the tail.
        assert_eq!(&blob[56..64], &[0u8; 8]);
    }

    /// Round-10 P2 — the host_io extension is gated on the
    /// retained DLL bytes. Empty bytes → no extension; non-
    /// empty → extension wired. Same gating contract as the
    /// other "advertise only when we have data" predicates
    /// (memory_map / exec_file / libraries / auxv).
    #[test]
    fn support_host_io_gated_on_dll_bytes_presence() {
        let mut t_none = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_host_io(&mut t_none).is_none());

        let mut t_some = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "IR32_32.DLL".to_string(),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        assert!(Target::support_host_io(&mut t_some).is_some());
    }

    /// Round-10 P2 — `support_monitor_cmd` is unconditionally
    /// available (commands work regardless of whether a DLL is
    /// loaded — `monitor stats` is useful in either case).
    #[test]
    fn support_monitor_cmd_always_available() {
        let mut t = SandboxTarget::new(Sandbox::new());
        assert!(Target::support_monitor_cmd(&mut t).is_some());
    }

    /// Round-10 P2 — `vFile:open` matches the codec basename
    /// case-insensitively (Win32 `LoadLibraryA` lookup is
    /// case-insensitive too) and returns a non-zero fd. Other
    /// names resolve to `ENOENT` so a stray `add-symbol-file`
    /// against the wrong name fails cleanly.
    #[test]
    fn host_io_open_matches_basename_case_insensitive() {
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "IR32_32.DLL".to_string(),
            vec![0u8; 256],
        );
        // Exact-case match.
        let fd = ok_io(HostIoOpen::open(
            &mut t,
            b"IR32_32.DLL",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        assert_ne!(fd, 0);
        // Case-insensitive match.
        let fd2 = ok_io(HostIoOpen::open(
            &mut t,
            b"ir32_32.dll",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        assert_ne!(fd2, 0);
        assert_ne!(fd, fd2, "each open should allocate a distinct fd");

        // Mismatched name → ENOENT.
        assert_io_enoent(
            HostIoOpen::open(
                &mut t,
                b"NOT_THE_DLL.DLL",
                HostIoOpenFlags::O_RDONLY,
                HostIoOpenMode::empty(),
            ),
            "open NOT_THE_DLL.DLL",
        );
    }

    /// Round-10 P2 — `vFile:open` accepts both bare-basename
    /// and slash-prefixed forms (`/IR32_32.DLL`,
    /// `path/IR32_32.DLL`, `path\IR32_32.DLL`). The basename
    /// extractor strips everything before the final `/` or
    /// `\`. This matters because GDB clients sometimes send
    /// path-style names through `add-symbol-file remote:…`.
    #[test]
    fn host_io_open_strips_path_prefixes() {
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "INDEO5.AX".to_string(),
            vec![0u8; 32],
        );
        for name in [
            &b"INDEO5.AX"[..],
            &b"/INDEO5.AX"[..],
            &b"/some/path/INDEO5.AX"[..],
            &b"C:\\Windows\\System32\\INDEO5.AX"[..],
        ] {
            let fd = ok_io(HostIoOpen::open(
                &mut t,
                name,
                HostIoOpenFlags::O_RDONLY,
                HostIoOpenMode::empty(),
            ));
            assert_ne!(fd, 0, "open {name:?} returned fd=0");
        }
    }

    /// Round-10 P2 — `vFile:pread` returns the requested slice
    /// of the DLL bytes. Past-EOF returns 0 (terminator).
    /// Reads short trailing chunks. Verifies the byte-for-byte
    /// fidelity an `add-symbol-file remote:…` client needs to
    /// resolve symbols against the in-memory image.
    #[test]
    fn host_io_pread_returns_dll_bytes_paginated() {
        // Build a 1024-byte payload with a recognisable shape.
        let dll: Vec<u8> = (0..1024u32).map(|i| (i & 0xff) as u8).collect();
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            dll.clone(),
        );
        let fd = ok_io(HostIoOpen::open(
            &mut t,
            b"synth.dll",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        // Single-shot full read.
        let mut buf = vec![0u8; dll.len()];
        let n = ok_io(HostIoPread::pread(&mut t, fd, dll.len(), 0, &mut buf));
        assert_eq!(n, dll.len());
        assert_eq!(buf, dll);

        // Past-EOF returns 0.
        let mut tail = [0u8; 16];
        let n = ok_io(HostIoPread::pread(
            &mut t,
            fd,
            tail.len(),
            dll.len() as u64,
            &mut tail,
        ));
        assert_eq!(n, 0);

        // Paginated reassembly with odd chunk size.
        let mut assembled: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 17];
        let mut offset: u64 = 0;
        loop {
            let n = ok_io(HostIoPread::pread(
                &mut t,
                fd,
                chunk.len(),
                offset,
                &mut chunk,
            ));
            if n == 0 {
                break;
            }
            assembled.extend_from_slice(&chunk[..n]);
            offset += n as u64;
        }
        assert_eq!(assembled, dll, "paginated reads should reassemble dll");
    }

    /// Round-10 P2 — `vFile:pread` against a stale fd (after
    /// `vFile:close`) returns `EBADF` instead of silently
    /// aliasing onto a future `open`. Matches POSIX semantics.
    #[test]
    fn host_io_pread_after_close_returns_ebadf() {
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            vec![0xAB; 64],
        );
        let fd = ok_io(HostIoOpen::open(
            &mut t,
            b"synth.dll",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        ok_io(HostIoClose::close(&mut t, fd));

        let mut buf = [0u8; 4];
        assert_io_ebadf(
            HostIoPread::pread(&mut t, fd, 4, 0, &mut buf),
            "pread after close",
        );
        // Closing twice is also EBADF.
        assert_io_ebadf(HostIoClose::close(&mut t, fd), "double close");
    }

    /// Round-10 P2 — `vFile:pread` / `vFile:close` with fd=0
    /// (POSIX stdin reservation) returns `EBADF`. We never
    /// allocate fd=0 ourselves; this guards against a buggy
    /// or hostile client passing the reserved value.
    #[test]
    fn host_io_fd_zero_is_always_ebadf() {
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            vec![0u8; 8],
        );
        let mut buf = [0u8; 4];
        assert_io_ebadf(HostIoPread::pread(&mut t, 0, 4, 0, &mut buf), "pread fd=0");
        assert_io_ebadf(HostIoClose::close(&mut t, 0), "close fd=0");
    }

    /// Round-10 P1 — `live_open_fds` reflects the current
    /// open-file count (used by `monitor stats`). Starts at 0,
    /// rises with each `open`, drops on `close`. Verifies the
    /// counter is consistent with the actual `open_files`
    /// table (the source of truth).
    #[test]
    fn live_open_fds_tracks_open_close_balance() {
        let mut t = SandboxTarget::with_forward(
            Sandbox::new(),
            Arc::new(Mutex::new(None)),
            &[],
            None,
            "synth.dll".to_string(),
            vec![0u8; 8],
        );
        assert_eq!(t.live_open_fds(), 0);
        let fd_a = ok_io(HostIoOpen::open(
            &mut t,
            b"synth.dll",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        assert_eq!(t.live_open_fds(), 1);
        let fd_b = ok_io(HostIoOpen::open(
            &mut t,
            b"synth.dll",
            HostIoOpenFlags::O_RDONLY,
            HostIoOpenMode::empty(),
        ));
        assert_eq!(t.live_open_fds(), 2);
        ok_io(HostIoClose::close(&mut t, fd_a));
        assert_eq!(t.live_open_fds(), 1);
        ok_io(HostIoClose::close(&mut t, fd_b));
        assert_eq!(t.live_open_fds(), 0);
    }
}
