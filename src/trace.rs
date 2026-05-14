//! Trace-state plumbing — wires `--trace-mem`, `--break`,
//! `--watch`, `--asm`, `--trace-output` flags through to the
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

/// Parse each `--watch ADDR[,LEN]` spec into a list of
/// `(addr, len)` tuples for downstream wiring. Errors propagate
/// (unparseable spec, zero length).
pub fn parse_watch_specs(specs: &[String]) -> Result<Vec<(u32, u32)>> {
    specs.iter().map(|s| crate::cli::parse_watch(s)).collect()
}

/// Apply each parsed `--watch (addr, len)` spec to the
/// sandbox: installs a `WatchMode::Both` watchpoint covering
/// `[addr, addr+len)` via the existing `Sandbox::watch` API so
/// the MMU's hot path emits a `kind=mem_read`/`kind=mem_write`
/// event on every overlapping access. The [`install_sink`]
/// wrapper then transforms those events into the new
/// `kind=mem_watch` shape (with `op` field) before they hit the
/// operator's `--trace-output` file.
pub fn apply_watch(sandbox: &mut Sandbox, watches: &[(u32, u32)]) {
    for &(addr, len) in watches {
        sandbox.watch(addr, len, oxideav_vfw::WatchMode::Both);
    }
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
///
/// When `watches` is non-empty, the sink is wrapped in a
/// [`MemWatchSink`] transformer that rewrites `kind=mem_read`
/// / `kind=mem_write` events whose addr falls inside any
/// watched range to the `kind=mem_watch` shape (with an `op`
/// field of `read` or `write`). This is what surfaces the
/// `--watch ADDR[,LEN]` flag's JSONL contract.
pub fn install_sink(
    sandbox: &mut Sandbox,
    output: Option<&Path>,
    watches: &[(u32, u32)],
) -> Result<()> {
    let raw: Box<dyn Write + Send> = match output {
        Some(p) => Box::new(File::create(p)?),
        None => Box::new(io::stderr()),
    };
    let sink: Box<dyn Write + Send> = if watches.is_empty() {
        raw
    } else {
        Box::new(MemWatchSink::new(raw, watches.to_vec()))
    };
    sandbox.set_trace_sink(sink);
    Ok(())
}

/// `Write` wrapper that intercepts `kind=mem_read` /
/// `kind=mem_write` JSONL events. Lines whose addr falls inside
/// any registered `--watch (addr, len)` range are rewritten as
/// `{"kind":"mem_watch","op":"read|write","addr":"…","size":…,
/// "value":"…","eip":"…"}`. Lines that don't match the schema
/// (or match it but fall outside every watched range) pass
/// through verbatim — so `--trace-mem` consumers keep their
/// existing event shape.
pub struct MemWatchSink {
    inner: Box<dyn Write + Send>,
    watches: Vec<(u32, u32)>,
    buf: Vec<u8>,
}

impl MemWatchSink {
    pub fn new(inner: Box<dyn Write + Send>, watches: Vec<(u32, u32)>) -> Self {
        Self {
            inner,
            watches,
            buf: Vec::with_capacity(256),
        }
    }

    /// True iff `addr` falls within any registered watch range.
    fn matches(&self, addr: u32) -> bool {
        self.watches
            .iter()
            .any(|&(a, l)| addr >= a && addr < a.wrapping_add(l))
    }

    /// Emit one complete line — either rewriting a matched
    /// `mem_read`/`mem_write` event to `mem_watch`, or passing
    /// the original bytes through unchanged.
    fn flush_line(&mut self, line: &[u8]) -> io::Result<()> {
        if let Some((op, addr_hex)) = parse_mem_event_op_addr(line) {
            if let Some(addr) = parse_hex32(addr_hex) {
                if self.matches(addr) {
                    let rewritten = rewrite_mem_to_mem_watch(line, op);
                    self.inner.write_all(rewritten.as_bytes())?;
                    self.inner.write_all(b"\n")?;
                    return Ok(());
                }
            }
        }
        self.inner.write_all(line)?;
        self.inner.write_all(b"\n")?;
        Ok(())
    }
}

impl Write for MemWatchSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &b in buf {
            if b == b'\n' {
                let line = std::mem::take(&mut self.buf);
                self.flush_line(&line)?;
            } else {
                self.buf.push(b);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.flush_line(&line)?;
        }
        self.inner.flush()
    }
}

impl Drop for MemWatchSink {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Return `("read" or "write", addr_hex_str)` for a JSONL line
/// that matches `{"kind":"mem_read|mem_write","addr":"0x...",…`.
/// Cheap byte-level scan — no JSON parser to pull in.
fn parse_mem_event_op_addr(line: &[u8]) -> Option<(&'static str, &[u8])> {
    let s = std::str::from_utf8(line).ok()?;
    let op = if s.contains(r#""kind":"mem_read""#) {
        "read"
    } else if s.contains(r#""kind":"mem_write""#) {
        "write"
    } else {
        return None;
    };
    // Find `"addr":"…"` — value lies between the next two
    // double-quote characters after the literal `"addr":"`.
    let needle = r#""addr":""#;
    let i = s.find(needle)?;
    let after = &s[i + needle.len()..];
    let end = after.find('"')?;
    Some((op, &after.as_bytes()[..end]))
}

/// Decode a `"0x12345678"` hex string into u32. Accepts the
/// shape oxideav-vfw's event helpers emit (`0x` + 1..=8 hex
/// digits). Returns `None` for anything else so we don't
/// accidentally rewrite a hand-rolled / future event we don't
/// understand.
fn parse_hex32(b: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(b).ok()?;
    let rest = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u32::from_str_radix(rest, 16).ok()
}

/// Rewrite an oxideav-vfw `kind=mem_read|mem_write` JSONL line
/// into the `kind=mem_watch` shape with an explicit `op` field.
/// We preserve every other field by transforming the event in
/// place — the trailing `addr`/`size`/`value`/`eip` fields keep
/// their original encoding (including the hex `value` width
/// honouring the access size).
fn rewrite_mem_to_mem_watch(line: &[u8], op: &str) -> String {
    let s = std::str::from_utf8(line).unwrap_or("");
    let rest = s
        .strip_prefix(r#"{"kind":"mem_read","#)
        .or_else(|| s.strip_prefix(r#"{"kind":"mem_write","#))
        .unwrap_or(s);
    format!(r#"{{"kind":"mem_watch","op":"{op}",{rest}"#)
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
///
/// When `include_fpu` is true, an additional `fpu` field is
/// appended carrying the live x87 ST(0..7) values (as IEEE-754
/// double hex), MMX register file (MM0..MM7 as u64 hex), tag
/// word + status word + control word. Like `eflags`, these are
/// read LIVE at drain time — the snapshot ring upstream does
/// not capture FPU state, so for multi-hit traces the FPU
/// values reflect the END-of-run state (matching what an
/// operator would see at the same place via `gdb` after a
/// `continue`). For per-hit FPU fidelity, attach via `--gdb`
/// and step manually.
pub fn flush_breakpoint_events(sandbox: &mut Sandbox, include_fpu: bool) {
    let snapshots = sandbox.cpu.clear_register_watchpoints();
    if snapshots.is_empty() {
        return;
    }
    // Read live state once — these are not in the per-hit ring.
    let eflags = sandbox.cpu.regs.flags.pack();
    let fpu_field = if include_fpu {
        Some(format_fpu_field(&sandbox.cpu))
    } else {
        None
    };
    for (eip, snap) in snapshots {
        // Snapshot order: [eax, ecx, edx, ebx, esp, ebp, esi, edi]
        // (matches Cpu::step's snapshot capture in oxideav-vfw).
        let mut line = format!(
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
             }}",
            snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
        );
        if let Some(fpu) = fpu_field.as_deref() {
            line.push(',');
            line.push_str(fpu);
        }
        line.push('}');
        sandbox.mmu.trace.emit_line(&line);
    }
}

/// Render the `"fpu":{…}` JSON sub-object covering x87 ST(0..7),
/// MMX MM0..MM7, tag word (one bit per slot, packed MSB-first
/// where bit 0 of the resulting nibble is ST(0)), status word,
/// and control word. ST(i) values are emitted as IEEE-754
/// double bit-patterns (16-char hex) — operators decode to f64
/// via `f64::from_bits` if they want a numeric view; the hex
/// form is lossless and avoids JSON's float-encoding ambiguity.
fn format_fpu_field(cpu: &oxideav_vfw::emulator::isa_int::Cpu) -> String {
    // ST(i) follows architectural order — ST(0) is at
    // physical index `top` (mod 8) per FpuState::push semantics.
    let top = cpu.fpu.top as usize;
    let mut st_hex: [String; 8] = Default::default();
    let mut tag_packed: u16 = 0;
    for (i, slot) in st_hex.iter_mut().enumerate() {
        let phys = (top + i) & 7;
        let bits = cpu.fpu.regs[phys].to_bits();
        *slot = format!("\"0x{bits:016x}\"");
        if cpu.fpu.tag_valid[phys] {
            tag_packed |= 1 << i;
        }
    }
    let mut mm_hex: [String; 8] = Default::default();
    for (i, slot) in mm_hex.iter_mut().enumerate() {
        *slot = format!("\"0x{:016x}\"", cpu.mmx[i]);
    }
    format!(
        "\"fpu\":{{\
         \"st\":[{},{},{},{},{},{},{},{}],\
         \"mm\":[{},{},{},{},{},{},{},{}],\
         \"tag\":\"0x{:04x}\",\
         \"status\":\"0x{:04x}\",\
         \"control\":\"0x{:04x}\"\
         }}",
        st_hex[0],
        st_hex[1],
        st_hex[2],
        st_hex[3],
        st_hex[4],
        st_hex[5],
        st_hex[6],
        st_hex[7],
        mm_hex[0],
        mm_hex[1],
        mm_hex[2],
        mm_hex[3],
        mm_hex[4],
        mm_hex[5],
        mm_hex[6],
        mm_hex[7],
        tag_packed,
        cpu.fpu.sw,
        cpu.fpu_cw,
    )
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
        flush_breakpoint_events(&mut sb, false);
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"breakpoint""#), "got: {s:?}");
        assert!(s.contains(r#""eip":"0xdeadbeef""#), "got: {s:?}");
        assert!(s.contains(r#""eax":"0x00000011""#), "got: {s:?}");
        assert!(s.contains(r#""edi":"0x00000088""#), "got: {s:?}");
        assert!(s.contains(r#""eflags":""#), "got: {s:?}");
        // Default-off: no `fpu` field.
        assert!(!s.contains(r#""fpu":"#), "got: {s:?}");
    }

    #[test]
    fn flush_breakpoint_events_with_include_fpu_appends_fpu_field() {
        use std::sync::{Arc, Mutex};
        let mut sb = Sandbox::new();
        // Seed FPU + MMX state so we can verify the emitted hex.
        sb.cpu.fpu.push(1.5_f64);
        sb.cpu.fpu.push(2.5_f64);
        sb.cpu.mmx[0] = 0xCAFE_BABE_DEAD_BEEF;
        sb.cpu.mmx[7] = 0x0011_2233_4455_6677;
        sb.cpu.fpu_cw = 0x027F;
        sb.cpu.fpu.sw = 0x4080;
        sb.cpu.register_snapshots.push((
            0xDEAD_BEEF,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ));
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
        flush_breakpoint_events(&mut sb, true);
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"breakpoint""#), "got: {s}");
        assert!(s.contains(r#""fpu":{"#), "got: {s}");
        // ST(0) was the second push (2.5) — see FpuState::push.
        let st0 = 2.5_f64.to_bits();
        let st1 = 1.5_f64.to_bits();
        assert!(
            s.contains(&format!("0x{st0:016x}")),
            "expected ST(0) bits in {s}"
        );
        assert!(
            s.contains(&format!("0x{st1:016x}")),
            "expected ST(1) bits in {s}"
        );
        // MMX seeds.
        assert!(s.contains("0xcafebabedeadbeef"), "got: {s}");
        assert!(s.contains("0x0011223344556677"), "got: {s}");
        // Tag word: 2 valid slots → bits 0 and 1 set → 0x0003.
        assert!(s.contains(r#""tag":"0x0003""#), "got: {s}");
        // Control + status echoed.
        assert!(s.contains(r#""status":"0x4080""#), "got: {s}");
        assert!(s.contains(r#""control":"0x027f""#), "got: {s}");
    }

    #[test]
    fn parse_watch_specs_returns_addr_len_pairs() {
        let v =
            parse_watch_specs(&["0x600002c0,2928".to_string(), "0x70000000".to_string()]).unwrap();
        assert_eq!(v, vec![(0x600002c0, 2928), (0x70000000, 4)]);
    }

    #[test]
    fn mem_watch_sink_rewrites_mem_write_inside_range() {
        let buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for VecWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = MemWatchSink::new(Box::new(VecWriter(buf.clone())), vec![(0x6000_0000, 64)]);
        let line = r#"{"kind":"mem_write","addr":"0x60000010","size":4,"value":"0xdeadbeef","eip":"0x10001000"}"#;
        sink.write_all(line.as_bytes()).unwrap();
        sink.write_all(b"\n").unwrap();
        sink.flush().unwrap();
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"mem_watch""#), "got: {s}");
        assert!(s.contains(r#""op":"write""#), "got: {s}");
        assert!(s.contains(r#""addr":"0x60000010""#), "got: {s}");
        assert!(s.contains(r#""value":"0xdeadbeef""#), "got: {s}");
        // The original kind=mem_write event MUST be gone — we
        // transform, not duplicate.
        assert!(!s.contains(r#""kind":"mem_write""#), "got: {s}");
    }

    #[test]
    fn mem_watch_sink_passes_through_unrelated_lines_unchanged() {
        let buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for VecWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = MemWatchSink::new(Box::new(VecWriter(buf.clone())), vec![(0x6000_0000, 64)]);
        // mem_write outside the range — should pass through.
        let out_of_range = r#"{"kind":"mem_write","addr":"0x70000000","size":4,"value":"0x01","eip":"0x10001000"}"#;
        // win32_call — also passes through.
        let win32 = r#"{"kind":"win32_call","dll":"kernel32.dll","name":"HeapAlloc","args":[],"ret":"0x0","eip":"0x10001000"}"#;
        sink.write_all(out_of_range.as_bytes()).unwrap();
        sink.write_all(b"\n").unwrap();
        sink.write_all(win32.as_bytes()).unwrap();
        sink.write_all(b"\n").unwrap();
        sink.flush().unwrap();
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"mem_write""#), "got: {s}");
        assert!(s.contains(r#""kind":"win32_call""#), "got: {s}");
        assert!(!s.contains(r#""kind":"mem_watch""#), "got: {s}");
    }

    #[test]
    fn mem_watch_sink_rewrites_mem_read_with_op_read() {
        let buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct VecWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for VecWriter {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = MemWatchSink::new(Box::new(VecWriter(buf.clone())), vec![(0x6000_0000, 64)]);
        let line =
            r#"{"kind":"mem_read","addr":"0x60000004","size":4,"value":"0x42","eip":"0x10001000"}"#;
        sink.write_all(line.as_bytes()).unwrap();
        sink.write_all(b"\n").unwrap();
        sink.flush().unwrap();
        let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(s.contains(r#""kind":"mem_watch""#), "got: {s}");
        assert!(s.contains(r#""op":"read""#), "got: {s}");
    }
}
