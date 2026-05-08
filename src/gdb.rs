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
use std::net::TcpListener;
use std::path::Path;

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
/// trace state reports a hit. Round-2 implementation is purely a
/// bookkeeping mirror — the real "wait for hit" wiring is a
/// future enhancement (see Round-3 candidates) since the round-1
/// `Sandbox` API runs to a sentinel rather than yielding per
/// memory access.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct WatchRec {
    addr: u32,
    len: u32,
    kind: WatchKind,
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
}

impl SandboxTarget {
    pub fn new(sandbox: Sandbox) -> Self {
        Self {
            sandbox,
            sw_bps: Vec::new(),
            hw_watches: Vec::new(),
            exec_mode: None,
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
        // Segment / FPU / XMM / MXCSR are zero — see module doc.
        regs.segments = Default::default();
        regs.st = Default::default();
        regs.fpu = Default::default();
        regs.xmm = [0u128; 8];
        regs.mxcsr = 0;
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
        // Other surfaces (segments / FPU / XMM) intentionally
        // ignored — the sandbox does not model them.
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
