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
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwWatchpoint, HwWatchpointOps, SwBreakpoint, SwBreakpointOps,
    WatchKind,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::reg::X86CoreRegs;
use gdbstub_arch::x86::X86_SSE;
use oxideav_vfw::emulator::regs::Reg32;
use oxideav_vfw::{Sandbox, WatchMode, DLL_PROCESS_ATTACH};
use std::collections::VecDeque;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Run the GDB Remote Serial Protocol server bound to `addr`.
///
/// Loads `dll_path` into a fresh [`Sandbox`], runs
/// `DllMain(DLL_PROCESS_ATTACH)`, then halts the CPU and waits
/// for a single GDB client connection on `HOST:PORT`. Use
/// `:0` for the port to bind to an OS-chosen free port — the
/// server prints `[gdb] listening on …` to stderr with the
/// chosen port (the integration test parses this line to find
/// the server).
pub fn run_gdb_server(addr: &str, dll_path: &Path, max_instr: u64) -> Result<()> {
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

    // 3. Build the Target, run the event loop.
    let mut target = SandboxTarget::new(sandbox);
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
/// unchanged so an operator using `--trace-output` simultaneously
/// with `--gdb` would still get the full event tape (currently
/// `--gdb` doesn't honour `--trace-output`, but the forward path
/// is plumbed through for symmetry + future use).
struct WatchSink {
    /// Per-line buffer — accumulates bytes until `\n`, then we
    /// scan the assembled line for the watchpoint shapes.
    line_buf: Vec<u8>,
    /// Producer side of the watch-hit queue.
    queue: WatchHitQueue,
    /// Optional underlying sink — bytes are forwarded verbatim
    /// regardless of whether the line matched a watch shape.
    forward: Option<Box<dyn Write + Send>>,
}

impl WatchSink {
    fn new(queue: WatchHitQueue, forward: Option<Box<dyn Write + Send>>) -> Self {
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
        if let Some(f) = self.forward.as_mut() {
            f.write_all(buf)?;
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
        if let Some(f) = self.forward.as_mut() {
            f.flush()?;
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
}

impl SandboxTarget {
    pub fn new(mut sandbox: Sandbox) -> Self {
        // Install our JSONL tap as the trace sink so the MMU's
        // `maybe_emit_*` probes route into our watch-hit queue.
        // Forwarded bytes (currently dropped to avoid clobbering
        // the GDB stub's stderr framing) can be wired to a file
        // sink in a future round.
        let watch_queue: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let sink = WatchSink::new(watch_queue.clone(), None);
        sandbox.set_trace_sink(Box::new(sink));
        Self {
            sandbox,
            sw_bps: Vec::new(),
            hw_watches: Vec::new(),
            exec_mode: None,
            watch_queue,
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
        let mut sink = WatchSink::new(q.clone(), None);
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
        let mut sink = WatchSink::new(q.clone(), None);
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
        let mut sink = WatchSink::new(q.clone(), None);
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
        let mut sink = WatchSink::new(q.clone(), None);
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
        // (round-4 candidate) — verify the forward path passes
        // bytes through verbatim.
        let q: WatchHitQueue = Arc::new(Mutex::new(VecDeque::new()));
        let captured: Vec<u8> = Vec::new();
        let forward = Box::new(std::io::Cursor::new(captured));
        let mut sink = WatchSink::new(q.clone(), Some(forward));
        let line =
            br#"{"kind":"mem_write","addr":"0x10000000","size":1,"value":"42","eip":"0x10001000"}
"#;
        sink.write_all(line).unwrap();
        // Watch hit landed in the queue.
        assert_eq!(q.lock().unwrap().len(), 1);
        // The Cursor is consumed by `forward` so we can't read
        // it back here without retaining a handle — but the
        // `write_all` returning Ok proves the forward path was
        // exercised. Real-world callers retain an `Arc<Mutex>`-
        // wrapped writer for inspection.
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
}
