//! Integration tests for the `oxidetracevfw` CLI binary.
//!
//! Drives the binary via `Command::new(env!("CARGO_BIN_EXE_oxidetracevfw"))`
//! against a synthetic minimal-PE32 DLL — generated on the fly
//! by `oxideav_vfw::pe::test_image::build_minimal_dll` — so the
//! tests don't pull codec binaries into the test surface.
//! Real-codec smoke (e.g. `IR32_32.DLL probe`) is documented in
//! the README and verifiable by the operator with a staged DLL.

use std::io::Write;
use std::process::Command;

/// Build a temp file containing the synthetic minimal DLL bytes
/// the round-1 `m1_load_dll_main` test uses.
fn write_synth_dll() -> tempfile_path::TempPath {
    let bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
    tempfile_path::write_temp("synth_dll", "dll", &bytes)
}

/// Build a temp file containing the synthetic minimal DLL with a
/// `mov [edi], eax ; hlt` sled patched into `.text` at RVA 0x1008
/// (file offset 0x208). The `.text` section has 0x10 bytes of
/// `virtual_size` and DllMain itself (`C2 0C 00`) sits at 0x1000,
/// so 0x1008 is comfortably reserved padding. Used by the round-4
/// P2 watchpoint protocol test below — it overrides EIP via the
/// GDB `G` packet (full register file) to point here, sets EDI
/// to a writable `.rdata` address, then runs `c` and waits for
/// the `T05watch:…;` reply.
fn write_synth_dll_with_writer_sled() -> tempfile_path::TempPath {
    let mut bytes = oxideav_vfw::pe::test_image::build_minimal_dll();
    // .text raw data starts at file offset 0x200 (FILE_ALIGN). The
    // entry-point opcode (`ret 12` = C2 0C 00) lives at 0x200..0x203;
    // we patch the writer at 0x208 so a single-step from VA
    // 0x10001008 executes `mov [edi], eax` (a write the MMU's
    // watch probe will see) followed by `hlt` (which stops the
    // CPU cleanly via `StepOk::Halted`).
    let sled_off = 0x208;
    bytes[sled_off] = 0x89; // mov r/m32, r32 (opcode)
    bytes[sled_off + 1] = 0x07; // ModR/M: mod=00 reg=eax(0) r/m=edi(7) → [edi]
    bytes[sled_off + 2] = 0xF4; // hlt
    tempfile_path::write_temp("synth_dll_sled", "dll", &bytes)
}

#[test]
fn probe_subcommand_against_synth_dll_succeeds() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("probe")
        .output()
        .expect("spawn oxidetracevfw");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "exit failure: status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("[probe] loaded"),
        "expected probe output, got: {stdout:?}"
    );
    assert!(
        stdout.contains("[probe] DllMain returned"),
        "expected DllMain output, got: {stdout:?}"
    );
}

#[test]
fn help_lists_subcommands() {
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("probe"), "got: {stdout}");
    assert!(stdout.contains("encode"), "got: {stdout}");
    assert!(stdout.contains("decode"), "got: {stdout}");
}

#[test]
fn gdb_flag_starts_rsp_server_and_speaks_protocol() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    // `:0` asks the OS for a free port; the server prints
    // `[gdb] listening on …` to stderr with the chosen port.
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    // Read stderr line-by-line until we see the "listening on"
    // marker; parse the port out of it. The PE image base /
    // entry log lines may appear before it.
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered_stderr = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered_stderr.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            // rest is e.g. "127.0.0.1:54321\n" (possibly with a v4-mapped form).
            if let Some(colon) = rest.rfind(':') {
                let p = rest[colon + 1..].trim();
                port = p.parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("did not see [gdb] listening on …; stderr so far:\n{buffered_stderr}");
    });

    // Connect and exchange a handful of GDB RSP packets.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // The server expects a `+` ack early in the exchange, but
    // gdbstub's first response to a query packet is a packet of
    // its own. Send `qSupported` and read the framed response.
    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    /// Read until we have a `$…#XX` packet (with optional leading
    /// `+` ack bytes). Returns the payload between `$` and `#`.
    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        // Skip ack bytes.
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            // `+` or `-` are RSP acks. Anything else is a
            // protocol violation we tolerate by stopping.
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        // We already saw `$`. Read until `#`.
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        // Read the 2-char hex checksum.
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        // Send `+` ack so the server knows we accepted it.
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported — must respond with a non-empty packet.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+"))
        .expect("write qSupported");
    let resp = read_packet(&mut sock);
    assert!(
        !resp.is_empty(),
        "expected non-empty qSupported response, got empty"
    );
    // gdbstub usually advertises `PacketSize` in the reply.
    assert!(
        resp.contains("PacketSize") || resp.contains("hwbreak") || resp.contains("swbreak"),
        "qSupported response looked unexpected: {resp:?}"
    );

    // 2. `g` — read general regs. Must come back as a hex blob
    //    significantly larger than zero (X86_SSE register set is
    //    several hundred bytes). The reply may use RSP run-length
    //    encoding (`*` followed by a count byte) to compress
    //    long runs of the same byte (e.g. zero-init segment /
    //    FPU registers), so we accept hex digits, `x` for
    //    unavailable, and `*` plus its count byte (any printable
    //    ASCII byte > 0x20).
    sock.write_all(&rsp_packet("g")).expect("write g");
    let regs_resp = read_packet(&mut sock);
    assert!(
        regs_resp.len() >= 32,
        "expected non-empty register hex blob, got {regs_resp:?}"
    );
    let printable = regs_resp.bytes().all(|b| (0x20..0x7f).contains(&b));
    assert!(
        printable,
        "expected printable ASCII register blob, got {regs_resp:?}"
    );

    // 3. `D` — detach. Must reply `OK`.
    sock.write_all(&rsp_packet("D")).expect("write D");
    let detach_resp = read_packet(&mut sock);
    assert_eq!(
        detach_resp, "OK",
        "expected OK to detach, got {detach_resp:?}"
    );

    // The server should exit cleanly after the detach. Give it a
    // moment, then reap.
    drop(sock);
    let _ = child.wait();
}

/// Round-5 P2 — `--gdb` paired with `--break` PCs and
/// `--trace-output FILE` writes a `kind=breakpoint` JSONL event
/// every time guest EIP lands on a registered `--break`. We
/// pre-seed the synth-DLL writer sled (mov [edi], eax; hlt at
/// VA 0x10001008), set EIP via the GDB `G` packet, register a
/// breakpoint at 0x1000100A (post-`mov`, on the `hlt`), continue
/// until halt, then inspect the trace file. Because the
/// breakpoint is on the `hlt` (which `StepOk::Halted`s
/// immediately), we expect at least one `kind=breakpoint` entry
/// matching that PC.
#[test]
fn gdb_break_flag_emits_kind_breakpoint_into_trace_output() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll_with_writer_sled();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");

    // Allocate a unique trace-output file. We let the test
    // helper handle cleanup by holding a TempPath we'll inspect
    // before drop.
    let trace_path = tempfile_path::write_temp("trace_bp", "jsonl", b"");

    // Breakpoint = post-`mov` PC. The sled at file offset 0x208
    // → VA 0x10001008. After `mov [edi], eax` (2 bytes), EIP
    // = 0x1000100A which lands on `hlt`.
    const BP_PC: u32 = 0x1000100A;

    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .arg("--break")
        .arg(format!("0x{BP_PC:08X}"))
        .arg("--trace-output")
        .arg(trace_path.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // Handshake.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+"))
        .expect("write qSupported");
    let _ = read_packet(&mut sock);

    // Override EIP / EAX / EDI via single-register P packets
    // (the round-5 P1 path) so we don't need to roll the whole
    // register file. EIP = 0x10001008 (sled), EAX = 0xCAFEF00D
    // (sentinel store value), EDI = 0x10002800 (.rdata is R+W
    // here per the synth DLL layout).
    let writes = [
        ("P0=0df0feca", "EAX"),
        ("P7=00280010", "EDI"),
        ("P8=08100010", "EIP"),
    ];
    for (pkt, what) in writes {
        sock.write_all(&rsp_packet(pkt))
            .unwrap_or_else(|e| panic!("write {what}: {e}"));
        let resp = read_packet(&mut sock);
        assert_eq!(resp, "OK", "{what} write failed: {resp:?}");
    }

    // Continue. CPU executes `mov [edi], eax` then advances EIP
    // to BP_PC = 0x1000100A which is the `hlt` instruction.
    // Before the next step the event loop notices EIP matches
    // our `--break` PC and emits `kind=breakpoint`. Then the
    // `hlt` halts the CPU and the loop returns Exited(0).
    sock.write_all(&rsp_packet("c")).expect("write c");
    let stop = read_packet(&mut sock);
    // Either SwBreak (we auto-installed BP_PC into sw_bps too)
    // or Exited — both are fine. The breakpoint event itself is
    // what we're testing, not the GDB stop-reason.
    assert!(
        stop.starts_with("S05") || stop.starts_with("T05") || stop.starts_with("W"),
        "unexpected stop reply: {stop:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();

    // Inspect the trace file.
    let bytes = std::fs::read(trace_path.path()).expect("read trace output");
    let s = String::from_utf8_lossy(&bytes);
    assert!(
        s.contains(r#""kind":"breakpoint""#),
        "expected kind=breakpoint event in trace file, got:\n{s}"
    );
    let pc_str = format!("0x{BP_PC:08x}");
    assert!(
        s.contains(&pc_str),
        "expected breakpoint PC {pc_str} in trace file, got:\n{s}"
    );
}

/// Round-5 P1 — exercise the `P` (single-register write) and
/// `p` (single-register read) RSP packets. The server now
/// advertises the `SingleRegisterAccess` extension on
/// `SandboxTarget`, so a GDB client can roll a single register
/// without sending the entire `G`-packet register file. We
/// confirm `P0=…` (write EAX) is acknowledged with `OK` and
/// `p0` (read EAX) returns the updated 8-hex-char value.
///
/// Register IDs in the `gdbstub_arch::x86::X86_SSE` description
/// match GDB's standard X86_32 ordering: 0=EAX, 1=ECX, 2=EDX,
/// 3=EBX, 4=ESP, 5=EBP, 6=ESI, 7=EDI, 8=EIP, 9=EFLAGS, …
#[test]
fn p_packet_single_register_write_is_acknowledged() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported handshake — advertises packet sizes / features.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+"))
        .expect("write qSupported");
    let _ = read_packet(&mut sock);

    // 2. P0=…  → write EAX = 0xDEADBEEF (LE hex bytes).
    //    The wire encoding is `P<reg_id_hex>=<value_le_hex>`. For
    //    EAX (reg id 0) holding 0xDEADBEEF, that's
    //    "P0=efbeadde". gdbstub replies `OK` if accepted.
    sock.write_all(&rsp_packet("P0=efbeadde"))
        .expect("write P0");
    let resp = read_packet(&mut sock);
    assert_eq!(
        resp, "OK",
        "expected OK to P0 single-register write, got {resp:?}"
    );

    // 3. p0 → read EAX back. Expect 8 hex chars = "efbeadde"
    //    (LE encoding of 0xDEADBEEF).
    sock.write_all(&rsp_packet("p0")).expect("write p0");
    let resp = read_packet(&mut sock);
    assert!(
        resp.eq_ignore_ascii_case("efbeadde"),
        "expected EAX read to return efbeadde, got {resp:?}"
    );

    // 4. P8=… → write EIP = 0x10001234. Reg id 8 = EIP.
    sock.write_all(&rsp_packet("P8=34120010"))
        .expect("write P8");
    let resp = read_packet(&mut sock);
    assert_eq!(resp, "OK", "expected OK to P8 (EIP) write, got {resp:?}");

    // 5. p8 → read EIP back.
    sock.write_all(&rsp_packet("p8")).expect("write p8");
    let resp = read_packet(&mut sock);
    assert!(
        resp.eq_ignore_ascii_case("34120010"),
        "expected EIP read to return 34120010, got {resp:?}"
    );

    // 6. Detach + reap.
    sock.write_all(&rsp_packet("D")).expect("write D");
    let detach_resp = read_packet(&mut sock);
    assert_eq!(detach_resp, "OK", "expected OK to D, got {detach_resp:?}");
    drop(sock);
    let _ = child.wait();
}

/// Round-4 P2 — drive the GDB Remote Serial Protocol over a
/// real TCP socket, set a `Z2` write watchpoint at a known
/// `.rdata` address, point EIP at the patched `mov [edi], eax;
/// hlt` sled in `.text`, send `c`, and verify the server
/// replies with the `T05watch:…;` stop-reason packet that GDB
/// uses to surface watchpoint hits.
///
/// No `gdb` binary needed — we hand-craft RSP frames so the
/// test runs unmodified on any host with a TCP loopback.
#[test]
fn z2_watchpoint_via_rsp_returns_t05_watch_stop_reason() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll_with_writer_sled();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    // Find the chosen port by reading stderr until "[gdb] listening on …".
    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered_stderr = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered_stderr.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                let p = rest[colon + 1..].trim();
                port = p.parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("did not see [gdb] listening on …; stderr so far:\n{buffered_stderr}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    fn expect_ok(sock: &mut TcpStream, payload: &str, what: &str) -> String {
        sock.write_all(&rsp_packet(payload))
            .unwrap_or_else(|e| panic!("write {what}: {e}"));
        read_packet(sock)
    }

    // 1. qSupported handshake — sets up packet sizes / features.
    let resp = expect_ok(
        &mut sock,
        "qSupported:multiprocess+;swbreak+;hwbreak+",
        "qSupported",
    );
    assert!(
        !resp.is_empty() && (resp.contains("PacketSize") || resp.contains("hwbreak")),
        "qSupported reply unexpected: {resp:?}"
    );

    // 2. Read the entire register file with `g`, then write it
    //    back via `G` with EAX / EDI / EIP overridden. The
    //    `gdbstub` 0.7 stub does not advertise `SingleRegisterAccess`
    //    here (we never enabled the extension on `SandboxTarget`),
    //    so `P` would return an empty reply — the bulk-register
    //    `G` path is what the GDB protocol guarantees is always
    //    available.
    //
    //    The X86_SSE register layout starts with the eight 32-bit
    //    GP regs (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI), then
    //    EIP and EFLAGS. Each is encoded as 4 little-endian hex
    //    bytes (= 8 hex chars). RSP run-length encoding may
    //    compress runs in the response, so we expand it before
    //    editing.
    //
    //    EIP ← 0x10001008 (the patched sled — `mov [edi], eax; hlt`).
    //    EAX ← 0xCAFEF00D (sentinel value to be stored).
    //    EDI ← 0x10002800 (.rdata is R+W from VA 0x10002000 to
    //          0x10004000 in the synth DLL — well clear of the
    //          export / import / IAT ranges below 0x10002800).
    const TARGET_ADDR: u32 = 0x10002800;
    const SLED_VA: u32 = 0x10001008;
    const SENTINEL: u32 = 0xCAFEF00D;

    /// Decode the gdbstub `g` reply, expanding any run-length
    /// encoding (`X*N` → repeat-N-1-times of `X`, where N is the
    /// printable byte after `*`, decoded as `N - 29` repeats per
    /// the GDB protocol manual).
    fn rsp_unrle(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' && i + 1 < bytes.len() && !out.is_empty() {
                let n = bytes[i + 1] as i32 - 29;
                let last = *out.as_bytes().last().unwrap() as char;
                for _ in 0..n {
                    out.push(last);
                }
                i += 2;
            } else {
                out.push(c);
                i += 1;
            }
        }
        out
    }

    fn write_le32_at(hex: &mut String, byte_offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        let s = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        );
        let char_offset = byte_offset * 2;
        hex.replace_range(char_offset..char_offset + 8, &s);
    }

    sock.write_all(&rsp_packet("g")).expect("write g");
    let regs_hex_raw = read_packet(&mut sock);
    let mut regs_hex = rsp_unrle(&regs_hex_raw);
    // X86_SSE: GPRs occupy bytes 0..32 (8 × 4), EIP at byte 32,
    // EFLAGS at byte 36, then segment / FPU / XMM / MXCSR.
    write_le32_at(&mut regs_hex, 0, SENTINEL); // EAX
    write_le32_at(&mut regs_hex, 28, TARGET_ADDR); // EDI (offset 7 × 4)
    write_le32_at(&mut regs_hex, 32, SLED_VA); // EIP

    let resp = expect_ok(&mut sock, &format!("G{regs_hex}"), "G all regs");
    assert_eq!(resp, "OK", "G reply: {resp:?}");

    // 3. Set a write watchpoint at TARGET_ADDR, length 4. RSP `Z2`
    //    is the wire packet for `WatchKind::Write` — gdbstub
    //    routes it into our `HwWatchpoint::add_hw_watchpoint`.
    let resp = expect_ok(
        &mut sock,
        &format!("Z2,{:x},4", TARGET_ADDR),
        "Z2 watchpoint",
    );
    assert_eq!(resp, "OK", "Z2 reply: {resp:?}");

    // 4. Continue. The CPU executes `mov [edi], eax` — a
    //    4-byte store to TARGET_ADDR — which trips the watch.
    //    The server should reply with `T05watch:<addr>;<rest>`.
    sock.write_all(&rsp_packet("c")).expect("write c");
    let stop = read_packet(&mut sock);
    assert!(
        stop.starts_with("T05"),
        "expected T05 stop reason after watchpoint hit, got {stop:?}"
    );
    assert!(
        stop.contains("watch:"),
        "expected `watch:` field in stop reason, got {stop:?}"
    );
    // The `watch:` field carries the faulting address as
    // big-endian hex (per the GDB protocol's stop-reply syntax).
    // gdbstub may emit a leading-zero-trimmed form, so we check
    // for the address as-written or its ascii substring.
    let target_hex = format!("{:x}", TARGET_ADDR);
    assert!(
        stop.contains(&target_hex) || stop.contains(&target_hex.to_uppercase()),
        "expected watched address {target_hex} in stop reply, got {stop:?}"
    );

    // 5. Detach + reap.
    let resp = expect_ok(&mut sock, "D", "detach");
    assert_eq!(resp, "OK", "detach reply: {resp:?}");
    drop(sock);
    let _ = child.wait();
}

#[test]
fn trace_mem_flag_parses() {
    // Just verify the CLI accepts the flag without erroring on
    // parse — actual emission happens once a guest store hits
    // the watched range. Probe sequence's DllMain doesn't touch
    // the synthetic 0x12340000 region, so this only confirms
    // the parser path.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--trace-mem")
        .arg("0x12340000:16:rw")
        .arg("probe")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn encode_subcommand_documents_iccompress_blocker_in_output() {
    // Round-3 P3: ICCompress wiring is blocked on a cross-crate
    // followup (`oxideav-vfw 0.1.0` ships only the decompress
    // half of the host surface). The encode subcommand should
    // surface that fact in its console output so an operator
    // running it doesn't expect a fully-driven encode.
    //
    // Synthetic DLL has no DriverProc → install_codec fails →
    // anyhow propagates the error. Exit non-zero is OK; we just
    // assert the subcommand's pre-error output mentions the
    // blocker.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("encode")
        .args(["--width", "8", "--height", "8", "--pattern", "solid"])
        .output()
        .expect("spawn oxidetracevfw");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    // Either the synth-DLL DriverProc-missing error, or — if
    // `install_codec` ever stops being a hard error — our own
    // "blocked on cross-crate followup" diagnostic. Either way,
    // the user gets a clear signal.
    assert!(
        combined.contains("ICCompress")
            || combined.to_lowercase().contains("driverproc")
            || combined.contains("install_codec")
            || combined.contains("DRV_OPEN"),
        "expected encode subcommand to mention ICCompress or surface \
         DriverProc/DRV_OPEN — got:\nstdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn decode_subcommand_drives_ic_decompress_path() {
    // Round-3 P3: the `decode` subcommand wires through to
    // `Sandbox::ic_open(ICMODE_DECOMPRESS)` +
    // `Sandbox::ic_decompress_query` + `Sandbox::ic_decompress`
    // rather than just printing the codec's identity card.
    //
    // The synthetic DLL doesn't expose `DriverProc`, so
    // `install_codec` will surface the error and we exit non-
    // zero — the outer CLI propagates the anyhow error. We
    // still want to verify the subcommand at least *attempts*
    // the decompress path; this test asserts the produced
    // diagnostic mentions DriverProc / DRV_OPEN, proving we got
    // past the load + DllMain stage.
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    // Empty input frame — sufficient since we don't expect to
    // reach `ic_decompress` proper on the synthetic DLL.
    let in_path = tempfile_path::write_temp("dec_in", "bin", b"");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("decode")
        .args([
            "--input",
            in_path.path().to_str().unwrap(),
            "--width",
            "64",
            "--height",
            "48",
            "--pix-format",
            "rgb24",
        ])
        .output()
        .expect("spawn oxidetracevfw");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    // Synthetic DLL has no DriverProc — the error message
    // should reflect that. (`anyhow` prints the error chain on
    // stderr.)
    assert!(
        combined.to_lowercase().contains("driverproc")
            || combined.to_lowercase().contains("drv_open")
            || combined.contains("install_codec")
            || combined.contains("DRV_OPEN")
            || combined.contains("ICOpen"),
        "expected decode subcommand to surface a codec-side \
         error mentioning DriverProc / DRV_OPEN / ICOpen — got:\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn break_flag_echoes_count_to_stderr() {
    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let out = Command::new(bin)
        .arg(dll.path())
        .arg("--break")
        .arg("0x10004A17")
        .arg("probe")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("breakpoint(s) registered"),
        "expected breakpoint registration log on stderr, got: {stderr:?}"
    );
}

/// Round-6 P2 — `qXfer:features:read:target.xml:…` returns our
/// custom register-description XML so a connected GDB client can
/// introspect the layout precisely (rather than falling back to
/// the generic X86_SSE description that ships with
/// `gdbstub_arch`, which doesn't advertise the MMX/ST(i) aliasing
/// we actually expose). The test asserts:
///   1. `qSupported` reply now contains `qXfer:features:read+`,
///   2. `qXfer:features:read:target.xml:0,200` returns a chunk
///      that begins with our XML prologue (and either `m…` for
///      "more data follows" or `l…` for "last chunk"),
///   3. The reassembled stream contains the canonical GDB
///      feature names `org.gnu.gdb.i386.core` +
///      `org.gnu.gdb.i386.sse`.
#[test]
fn qxfer_features_read_returns_target_xml_with_i386_features() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported handshake — gdbstub will only advertise
    //    qXfer:features:read+ when the client side also
    //    advertises support for it (typical real GDB clients do).
    sock.write_all(&rsp_packet(
        "qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:features:read+",
    ))
    .expect("write qSupported");
    let resp = read_packet(&mut sock);
    assert!(
        resp.contains("qXfer:features:read+"),
        "expected qXfer:features:read+ in qSupported reply, got: {resp:?}"
    );

    // 2. Read the target description in chunks. GDB's qXfer
    //    pagination uses `qXfer:features:read:annex:offset,length`
    //    and the reply is `m<data>` (more follows) or `l<data>`
    //    (last). Empty / past-EOF replies are `l`.
    let mut assembled = String::new();
    let mut offset: u64 = 0;
    let chunk_len: u64 = 256;
    loop {
        let pkt = format!("qXfer:features:read:target.xml:{offset:x},{chunk_len:x}");
        sock.write_all(&rsp_packet(&pkt)).expect("write qXfer");
        let resp = read_packet(&mut sock);
        if resp.is_empty() {
            // gdbstub's bare-empty reply means "unsupported" —
            // would indicate our extension didn't wire correctly.
            panic!("qXfer:features:read returned empty (extension not advertised)");
        }
        let last = resp.starts_with('l');
        let data = &resp[1..];
        // The qXfer reply may RLE-compress runs; expand them.
        let bytes = data.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' && i + 1 < bytes.len() && !assembled.is_empty() {
                let n = bytes[i + 1] as i32 - 29;
                let last_ch = assembled.chars().last().unwrap();
                for _ in 0..n {
                    assembled.push(last_ch);
                }
                i += 2;
            } else {
                assembled.push(c);
                i += 1;
            }
        }
        offset = assembled.len() as u64;
        if last {
            break;
        }
        if offset > 200_000 {
            panic!("runaway qXfer pagination — assembled {offset} bytes");
        }
    }

    // 3. Sanity-check the contents.
    assert!(
        assembled.contains("<architecture>i386</architecture>"),
        "expected i386 architecture marker, got: {assembled:?}"
    );
    assert!(
        assembled.contains(r#"name="org.gnu.gdb.i386.core""#),
        "expected i386.core feature, got: {assembled:?}"
    );
    assert!(
        assembled.contains(r#"name="org.gnu.gdb.i386.sse""#),
        "expected i386.sse feature, got: {assembled:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-7 P1 — `qXfer:memory-map:read` returns a GDB-DTD
/// memory-map document populated from the loaded PE image's
/// section table. Connected GDB clients use this for
/// `info mem` / `maintenance info sections`. The test asserts:
///   1. `qSupported` reply now contains `qXfer:memory-map:read+`,
///   2. paginated `qXfer:memory-map:read::<offset>,<length>`
///      reads reassemble into a well-formed `<memory-map>` document,
///   3. the document references the synthetic DLL's `.text`
///      section (mapped at `image_base + 0x1000` per
///      `pe::test_image::build_minimal_dll`).
#[test]
fn qxfer_memory_map_read_returns_section_table() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported handshake — clients advertise what they want;
    //    gdbstub only enables `qXfer:memory-map:read+` in the
    //    response if both ends agree.
    sock.write_all(&rsp_packet(
        "qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:memory-map:read+",
    ))
    .expect("write qSupported");
    let resp = read_packet(&mut sock);
    assert!(
        resp.contains("qXfer:memory-map:read+"),
        "expected qXfer:memory-map:read+ in qSupported reply, got: {resp:?}"
    );

    // 2. Paginated read of the memory-map document. The annex is
    //    empty for memory-map (the GDB protocol leaves the slot
    //    blank for `qXfer:memory-map:read::offset,length`).
    let mut assembled = String::new();
    let mut offset: u64 = 0;
    let chunk_len: u64 = 256;
    loop {
        let pkt = format!("qXfer:memory-map:read::{offset:x},{chunk_len:x}");
        sock.write_all(&rsp_packet(&pkt)).expect("write qXfer");
        let resp = read_packet(&mut sock);
        if resp.is_empty() {
            panic!("qXfer:memory-map:read returned empty (extension not advertised)");
        }
        let last = resp.starts_with('l');
        let data = &resp[1..];
        // Expand qXfer's RLE compression (`*N` = repeat last char).
        let bytes = data.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' && i + 1 < bytes.len() && !assembled.is_empty() {
                let n = bytes[i + 1] as i32 - 29;
                let last_ch = assembled.chars().last().unwrap();
                for _ in 0..n {
                    assembled.push(last_ch);
                }
                i += 2;
            } else {
                assembled.push(c);
                i += 1;
            }
        }
        offset = assembled.len() as u64;
        if last {
            break;
        }
        if offset > 200_000 {
            panic!("runaway qXfer pagination — assembled {offset} bytes");
        }
    }

    // 3. Sanity-check the document.
    assert!(
        assembled.starts_with("<?xml version=\"1.0\"?>"),
        "missing XML prologue, got: {assembled:?}"
    );
    assert!(
        assembled.contains("<memory-map>"),
        "missing root element, got: {assembled:?}"
    );
    // The synthetic DLL maps `.text` at `image_base + 0x1000`. The
    // `build_minimal_dll` helper uses image_base = 0x10000000 (see
    // `oxideav_vfw::pe::test_image`). We assert on the .text VA.
    assert!(
        assembled.contains("0x10001000"),
        "missing .text VA in memory-map, got: {assembled:?}"
    );
    // At least one rom-typed section (.text is read-execute, never
    // writable).
    assert!(
        assembled.contains(r#"type="rom""#),
        "expected at least one rom section, got: {assembled:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-7 P2 — `qXfer:exec-file:read` returns the codec's
/// basename so a connected GDB client's `info file` shows
/// `synth_dll-…dll` rather than the placeholder
/// `<process N>` gdbstub falls back to. The test asserts:
///   1. `qSupported` reply contains `qXfer:exec-file:read+`,
///   2. paginated read reassembles to a string ending in `.dll`
///      (the operator-supplied DLL filename — the `tempfile`
///      helper appends a unique suffix so we don't pin to an
///      exact basename).
#[test]
fn qxfer_exec_file_read_returns_dll_basename() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let dll_basename = dll
        .path()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .expect("temp file has basename");

    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported handshake — exec-file extension is gated on
    //    both ends advertising support.
    sock.write_all(&rsp_packet(
        "qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:exec-file:read+",
    ))
    .expect("write qSupported");
    let resp = read_packet(&mut sock);
    assert!(
        resp.contains("qXfer:exec-file:read+"),
        "expected qXfer:exec-file:read+ in qSupported reply, got: {resp:?}"
    );

    // 2. Paginated read — the exec-file annex carries the pid; we
    //    leave it empty (== current process) and read the whole
    //    name. Real GDB clients also send the pid as a hex string,
    //    but the empty-annex path is well-defined per the GDB
    //    protocol manual §"qXfer:exec-file:read".
    let mut assembled = String::new();
    let mut offset: u64 = 0;
    let chunk_len: u64 = 64;
    loop {
        let pkt = format!("qXfer:exec-file:read::{offset:x},{chunk_len:x}");
        sock.write_all(&rsp_packet(&pkt)).expect("write qXfer");
        let resp = read_packet(&mut sock);
        if resp.is_empty() {
            panic!("qXfer:exec-file:read returned empty (extension not advertised)");
        }
        let last = resp.starts_with('l');
        let data = &resp[1..];
        // RLE expansion — exec-file payloads are short so this is
        // mostly a no-op, but we keep parity with the other qXfer
        // readers.
        let bytes = data.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' && i + 1 < bytes.len() && !assembled.is_empty() {
                let n = bytes[i + 1] as i32 - 29;
                let last_ch = assembled.chars().last().unwrap();
                for _ in 0..n {
                    assembled.push(last_ch);
                }
                i += 2;
            } else {
                assembled.push(c);
                i += 1;
            }
        }
        offset = assembled.len() as u64;
        if last {
            break;
        }
        if offset > 4096 {
            panic!("runaway exec-file pagination — assembled {offset} bytes");
        }
    }

    // 3. The reassembled string is the temp-file basename the
    //    helper generated (a suffix-randomised string ending in
    //    `.dll`).
    assert_eq!(
        assembled, dll_basename,
        "exec-file payload should match DLL basename"
    );
    assert!(
        assembled.ends_with(".dll"),
        "expected .dll suffix in exec-file payload, got: {assembled:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-8 P1 — `qXfer:libraries:read` returns a GDB-format
/// `<library-list>` document populated from the sandbox's
/// loaded-module registry. Connected GDB clients use this for
/// `info sharedlibrary` and to step into cascade-loaded modules.
/// A real codec like `mpg4c32` typically pulls in `msacm32.dll`
/// plus `winmm.dll` during DllMain — this extension surfaces
/// those to the client. The test asserts:
///
/// 1. `qSupported` reply contains `qXfer:libraries:read+`,
/// 2. paginated `qXfer:libraries:read::<offset>,<length>` reads
///    reassemble into a well-formed `<library-list version="1.0">`
///    document,
/// 3. the document references the synthetic DLL's basename
///    and its image base (`pe::test_image::build_minimal_dll`
///    pins image_base = 0x10000000).
#[test]
fn qxfer_libraries_read_returns_module_registry() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // 1. qSupported handshake — gdbstub only enables
    //    `qXfer:libraries:read+` in the response when both ends
    //    advertise support.
    sock.write_all(&rsp_packet(
        "qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:libraries:read+",
    ))
    .expect("write qSupported");
    let resp = read_packet(&mut sock);
    assert!(
        resp.contains("qXfer:libraries:read+"),
        "expected qXfer:libraries:read+ in qSupported reply, got: {resp:?}"
    );

    // 2. Paginated read of the libraries document. The annex is
    //    empty for libraries (`qXfer:libraries:read::offset,length`).
    let mut assembled = String::new();
    let mut offset: u64 = 0;
    let chunk_len: u64 = 128;
    loop {
        let pkt = format!("qXfer:libraries:read::{offset:x},{chunk_len:x}");
        sock.write_all(&rsp_packet(&pkt)).expect("write qXfer");
        let resp = read_packet(&mut sock);
        if resp.is_empty() {
            panic!("qXfer:libraries:read returned empty (extension not advertised)");
        }
        let last = resp.starts_with('l');
        let data = &resp[1..];
        // RLE expansion — `*N` repeats the previous char (N - 29).
        let bytes = data.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' && i + 1 < bytes.len() && !assembled.is_empty() {
                let n = bytes[i + 1] as i32 - 29;
                let last_ch = assembled.chars().last().unwrap();
                for _ in 0..n {
                    assembled.push(last_ch);
                }
                i += 2;
            } else {
                assembled.push(c);
                i += 1;
            }
        }
        offset = assembled.len() as u64;
        if last {
            break;
        }
        if offset > 100_000 {
            panic!("runaway qXfer pagination — assembled {offset} bytes");
        }
    }

    // 3. Sanity-check the document.
    assert!(
        assembled.starts_with("<?xml version=\"1.0\"?>"),
        "missing XML prologue, got: {assembled:?}"
    );
    assert!(
        assembled.contains(r#"<library-list version="1.0">"#),
        "missing <library-list> root with version, got: {assembled:?}"
    );
    assert!(
        assembled.contains("</library-list>"),
        "missing </library-list> closing tag, got: {assembled:?}"
    );
    // The synthetic DLL's basename gets keyed lowercase by the
    // PE loader (`name.to_ascii_lowercase()`); the helper writes
    // a temp file with prefix `synth_dll-…` — so the lowercase
    // name surfaces in the registry entry.
    assert!(
        assembled.contains("<library name=\"synth_dll-"),
        "missing synth DLL library entry, got: {assembled:?}"
    );
    // `pe::test_image::build_minimal_dll` pins image_base at
    // 0x10000000 — the segment address in the document should
    // match.
    assert!(
        assembled.contains(r#"<segment address="0x10000000"/>"#),
        "missing image-base segment, got: {assembled:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-9 P1 — `qXfer:auxv:read` returns a synthetic
/// ELF-style auxiliary-vector blob describing the loaded PE
/// image. The blob is a sequence of `(u32 key, u32 value)`
/// pairs in little-endian terminated by `(AT_NULL=0, 0)`. We
/// drive the binary through the GDB protocol and assert:
///
/// 1. `qSupported` reply contains `qXfer:auxv:read+`,
/// 2. paginated `qXfer:auxv:read::<offset>,<length>` reads
///    reassemble into a 64-byte blob (8 entries × 8 bytes),
/// 3. the canonical AT_* keys + values surface — particularly
///    AT_BASE/AT_PHDR (= image_base 0x10000000), AT_ENTRY
///    (= entry_point), AT_PAGESZ (= 0x1000), AT_NULL terminator.
#[test]
fn qxfer_auxv_read_returns_synthetic_aux_vector() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> Vec<u8> {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        payload
    }

    // 1. qSupported handshake — gdbstub only enables
    //    `qXfer:auxv:read+` when the client side advertises it.
    sock.write_all(&rsp_packet(
        "qSupported:multiprocess+;swbreak+;hwbreak+;qXfer:auxv:read+",
    ))
    .expect("write qSupported");
    let resp = String::from_utf8_lossy(&read_packet(&mut sock)).into_owned();
    assert!(
        resp.contains("qXfer:auxv:read+"),
        "expected qXfer:auxv:read+ in qSupported reply, got: {resp:?}"
    );

    // 2. Paginated read of the auxv blob. The annex is empty
    //    for auxv (`qXfer:auxv:read::offset,length`). We pull
    //    raw bytes (no UTF-8 lossy here — the blob is binary).
    let mut assembled: Vec<u8> = Vec::new();
    let mut offset: u64 = 0;
    let chunk_len: u64 = 32;
    loop {
        let pkt = format!("qXfer:auxv:read::{offset:x},{chunk_len:x}");
        sock.write_all(&rsp_packet(&pkt)).expect("write qXfer");
        let resp = read_packet(&mut sock);
        if resp.is_empty() {
            panic!("qXfer:auxv:read returned empty (extension not advertised)");
        }
        let last = resp[0] == b'l';
        let data = &resp[1..];
        // RLE expansion — `*N` repeats the previous char (N - 29).
        let mut i = 0;
        while i < data.len() {
            let c = data[i];
            if c == b'*' && i + 1 < data.len() && !assembled.is_empty() {
                let n = data[i + 1] as i32 - 29;
                let last_b = *assembled.last().unwrap();
                for _ in 0..n {
                    assembled.push(last_b);
                }
                i += 2;
            } else {
                assembled.push(c);
                i += 1;
            }
        }
        offset = assembled.len() as u64;
        if last {
            break;
        }
        if offset > 1024 {
            panic!("runaway qXfer:auxv pagination — assembled {offset} bytes");
        }
    }

    // 3. Sanity-check the blob shape: 8 entries × 8 bytes.
    assert_eq!(
        assembled.len(),
        64,
        "expected 64-byte auxv blob, got {}",
        assembled.len()
    );
    let read_le32 = |off: usize| -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&assembled[off..off + 4]);
        u32::from_le_bytes(b)
    };
    let pairs: Vec<(u32, u32)> = (0..assembled.len())
        .step_by(8)
        .map(|off| (read_le32(off), read_le32(off + 4)))
        .collect();
    // Synthetic DLL pins image_base = 0x10000000 and entry_point
    // = image_base + 0x1000 (round-1 default in
    // `pe::test_image::build_minimal_dll`).
    assert_eq!(pairs[0], (3, 0x10000000), "AT_PHDR mismatch: {pairs:?}");
    assert_eq!(pairs[1], (4, 40), "AT_PHENT mismatch: {pairs:?}");
    assert_eq!(pairs[3], (6, 0x1000), "AT_PAGESZ mismatch: {pairs:?}");
    assert_eq!(pairs[4], (7, 0x10000000), "AT_BASE mismatch: {pairs:?}");
    assert_eq!(pairs[5], (8, 0), "AT_FLAGS mismatch: {pairs:?}");
    assert_eq!(pairs[6], (9, 0x10001000), "AT_ENTRY mismatch: {pairs:?}");
    assert_eq!(pairs[7], (0, 0), "AT_NULL terminator mismatch: {pairs:?}");

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-10 P1 — `qRcmd` (the `monitor` command) surfaces
/// sandbox state introspection from the GDB prompt. We exercise
/// `monitor stats`, `monitor watches`, `monitor breakpoints`,
/// `monitor modules`, and `monitor help` — verifying the wire-
/// level qRcmd hex-encoded request + the hex-encoded `O…`
/// progress packets gdbstub uses to deliver console output, plus
/// the trailing `OK` (or `Enn`) response.
///
/// The qRcmd packet is `qRcmd,<HEX>` where HEX is the lowercase
/// hex-encoding of the bytes the operator typed after `monitor `.
/// Output comes back as one or more `O<HEX>` packets (each carrying
/// hex-encoded ASCII), followed by an `OK` terminator. We
/// reassemble the hex chunks into a String and assert each command
/// surfaces the expected operator-facing labels.
#[test]
fn qrcmd_monitor_commands_return_sandbox_state() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--break")
        .arg("0x10001234")
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload: Vec<u8> = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            // RSP run-length: `*N` repeats the previous byte
            // (N - 29) times. The `O…` console-output packets
            // gdbstub emits use this when there's a long run of
            // identical hex chars.
            if buf[0] == b'*' {
                let mut nb = [0u8; 1];
                sock.read_exact(&mut nb).expect("read RLE count");
                let n = (nb[0] as i32 - 29).max(0) as usize;
                if let Some(&last) = payload.last() {
                    for _ in 0..n {
                        payload.push(last);
                    }
                }
                continue;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    /// Build a `qRcmd,<HEX>` packet from a human-readable
    /// monitor command body (`stats`, `help`, etc.).
    fn rcmd(cmd: &str) -> Vec<u8> {
        let hex: String = cmd.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        rsp_packet(&format!("qRcmd,{hex}"))
    }

    /// Drain `O<HEX>` console-output packets from the stub
    /// until we see the terminator (`OK` or `Enn` or empty);
    /// reassemble the hex into a String. Returns the assembled
    /// output and the terminator string. `OK` itself starts
    /// with `O` but is the terminator (not a hex-output
    /// packet); `OK`-shaped console output would be `O4f4b` so
    /// we special-case the bare-`OK` form.
    fn drain_monitor_output(sock: &mut TcpStream) -> (String, String) {
        let mut out = String::new();
        loop {
            let resp = read_packet(sock);
            // `OK` (literal two chars) is the terminator — not
            // a console-output packet (which would be `O4f4b`).
            if resp == "OK" {
                return (out, resp);
            }
            if let Some(rest) = resp.strip_prefix('O') {
                // Console output: lowercase-hex chunk, even
                // length. Hex-decode by 2-char windows.
                if rest.len() % 2 == 0 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let bytes = (0..rest.len())
                        .step_by(2)
                        .filter_map(|i| u8::from_str_radix(&rest[i..i + 2], 16).ok())
                        .collect::<Vec<u8>>();
                    out.push_str(&String::from_utf8_lossy(&bytes));
                    continue;
                }
                // Not pure hex — treat as terminator.
                return (out, resp);
            }
            // Anything not starting with 'O' (E-error, empty,
            // …) is the terminator.
            return (out, resp);
        }
    }

    // qSupported handshake — required so the stub negotiates
    // packet sizes that fit the qRcmd reply.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+"))
        .expect("write qSupported");
    let _ = read_packet(&mut sock);

    // 1. monitor help — lists known commands.
    sock.write_all(&rcmd("help")).expect("write monitor help");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(
        term, "OK",
        "expected OK terminator after help, got: {term:?}"
    );
    assert!(out.contains("stats"), "monitor help missing stats: {out:?}");
    assert!(
        out.contains("watches"),
        "monitor help missing watches: {out:?}"
    );
    assert!(
        out.contains("breakpoints"),
        "monitor help missing breakpoints: {out:?}"
    );
    assert!(
        out.contains("modules"),
        "monitor help missing modules: {out:?}"
    );

    // 2. monitor stats — instr_count + counters lines.
    sock.write_all(&rcmd("stats")).expect("write monitor stats");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(term, "OK");
    assert!(
        out.contains("instr_count="),
        "monitor stats missing instr_count: {out:?}"
    );
    assert!(
        out.contains("loaded_modules="),
        "monitor stats missing loaded_modules: {out:?}"
    );
    assert!(
        out.contains("exec_file="),
        "monitor stats missing exec_file: {out:?}"
    );
    assert!(
        out.contains("cli_breakpoints=1"),
        "monitor stats expected cli_breakpoints=1 (we passed --break), got: {out:?}"
    );

    // 3. monitor breakpoints — lists the CLI-registered PC.
    sock.write_all(&rcmd("breakpoints"))
        .expect("write monitor breakpoints");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(term, "OK");
    assert!(
        out.contains("0x10001234"),
        "monitor breakpoints missing CLI PC: {out:?}"
    );
    assert!(
        out.contains("(cli)"),
        "monitor breakpoints missing (cli) annotation: {out:?}"
    );

    // 4. monitor modules — lists loaded modules (synth.dll +
    //    cascade-loaded kernel32 etc.). We just check that the
    //    primary DLL surfaces (lowercase basename per the
    //    loader's case-folding contract).
    sock.write_all(&rcmd("modules"))
        .expect("write monitor modules");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(term, "OK");
    let lower = out.to_ascii_lowercase();
    assert!(
        lower.contains(".dll") || lower.contains(".ax"),
        "monitor modules missing any module entry: {out:?}"
    );

    // 5. monitor watches — empty (we registered none) yields
    //    the placeholder line.
    sock.write_all(&rcmd("watches"))
        .expect("write monitor watches");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(term, "OK");
    assert!(
        out.contains("no HW watchpoints"),
        "monitor watches expected empty placeholder, got: {out:?}"
    );

    // 6. unknown command — informative reply, still OK.
    sock.write_all(&rcmd("frobnicate"))
        .expect("write monitor frobnicate");
    let (out, term) = drain_monitor_output(&mut sock);
    assert_eq!(term, "OK");
    assert!(
        out.contains("unknown monitor command"),
        "expected unknown-command reply, got: {out:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-10 P2 — host_io `vFile:open` + `vFile:pread` +
/// `vFile:close` round-trip the codec DLL bytes back to a
/// connected GDB client. Operator-facing this enables
/// `(gdb) add-symbol-file remote:<basename>` for symbol
/// resolution against the in-memory image without manual
/// file transfer.
///
/// The wire contract per the GDB RSP manual §"Host I/O Packets":
/// - `vFile:open:FILENAME,FLAGS,MODE` — FILENAME is hex-encoded;
///   reply `Ffd[,errno]` (lowercase hex); `fd >= 0` on success.
/// - `vFile:pread:FD,COUNT,OFFSET` — all three fields lowercase
///   hex; reply `Fbytes_read[;DATA]` where DATA is the binary
///   payload (with `}xx` escaping for `$`/`#`/`}`/`*`).
/// - `vFile:close:FD` — reply `F0` on success.
#[test]
fn vfile_open_pread_close_round_trips_dll_bytes() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let dll_path = dll.path().to_path_buf();
    let dll_bytes = std::fs::read(&dll_path).expect("read synth dll");
    let basename = dll_path
        .file_name()
        .and_then(|n| n.to_str())
        .expect("basename")
        .to_string();

    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(&dll_path)
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    /// Read a packet, returning the raw payload bytes. The
    /// vFile:pread reply is binary — we MUST NOT lose bytes to
    /// UTF-8 lossy conversion. Handles two layers of decoding
    /// per the GDB RSP framing:
    ///   - `}xx` binary escape (xx XOR 0x20 = original byte).
    ///   - `*N` run-length encoding (N - 29 = repeat count of
    ///     the previously-emitted byte).
    fn read_packet_raw(sock: &mut TcpStream) -> Vec<u8> {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            // GDB binary escape: `}` followed by (orig XOR 0x20).
            if buf[0] == b'}' {
                let mut esc = [0u8; 1];
                sock.read_exact(&mut esc).expect("read escape byte");
                payload.push(esc[0] ^ 0x20);
                continue;
            }
            // RSP run-length: `*N` repeats the previous byte
            // (N - 29) times. Per GDB protocol manual.
            if buf[0] == b'*' {
                let mut nb = [0u8; 1];
                sock.read_exact(&mut nb).expect("read RLE count");
                let n = (nb[0] as i32 - 29).max(0) as usize;
                if let Some(&last) = payload.last() {
                    for _ in 0..n {
                        payload.push(last);
                    }
                }
                continue;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        payload
    }

    // qSupported handshake — required so the stub negotiates the
    // correct packet sizes for vFile replies.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+"))
        .expect("write qSupported");
    let _ = read_packet_raw(&mut sock);

    // 1. vFile:open — hex-encode the basename, flags=0
    //    (O_RDONLY), mode=0.
    let name_hex: String = basename
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let open_pkt = format!("vFile:open:{name_hex},0,0");
    sock.write_all(&rsp_packet(&open_pkt))
        .expect("write vFile:open");
    let resp = String::from_utf8_lossy(&read_packet_raw(&mut sock)).into_owned();
    assert!(
        resp.starts_with('F'),
        "expected 'F<fd>' reply to vFile:open, got: {resp:?}"
    );
    // The reply format is `Ffd[,errno]`; success has no errno.
    let body = &resp[1..];
    let fd_str = body.split(',').next().unwrap_or("");
    let fd = i64::from_str_radix(fd_str, 16).unwrap_or_else(|_| panic!("parse fd from: {resp:?}"));
    assert!(fd >= 1, "expected fd >= 1 (fd=0 is reserved), got: {fd}");

    // 2. vFile:pread — full read in one shot. Reply is
    //    `F<count>;<binary-data>`.
    let count = dll_bytes.len();
    let pread_pkt = format!("vFile:pread:{fd:x},{count:x},0");
    sock.write_all(&rsp_packet(&pread_pkt))
        .expect("write vFile:pread");
    let raw = read_packet_raw(&mut sock);
    // Find the `;` that separates `F<count>` from the data.
    let semi = raw
        .iter()
        .position(|&b| b == b';')
        .unwrap_or_else(|| panic!("no ';' in pread reply: {:?}", String::from_utf8_lossy(&raw)));
    let header = &raw[..semi];
    let data = &raw[semi + 1..];
    assert_eq!(
        header[0],
        b'F',
        "expected 'F<count>' header, got: {:?}",
        String::from_utf8_lossy(header)
    );
    let count_hex = std::str::from_utf8(&header[1..]).expect("count utf8");
    let n = usize::from_str_radix(count_hex, 16).expect("parse count");
    assert_eq!(
        n,
        dll_bytes.len(),
        "expected pread to return all {} bytes, got {n}",
        dll_bytes.len()
    );
    assert_eq!(
        data,
        &dll_bytes[..],
        "vFile:pread payload should equal the codec DLL bytes"
    );

    // 3. vFile:pread past EOF — count = 0; EOF marker. The
    //    exact wire shape varies by gdbstub version (`F0`,
    //    `F0;`, `F00`, `F00;…`); accept any reply whose
    //    decoded `<count>` is 0.
    let past = dll_bytes.len();
    let eof_pkt = format!("vFile:pread:{fd:x},20,{past:x}");
    sock.write_all(&rsp_packet(&eof_pkt))
        .expect("write vFile:pread eof");
    let raw = read_packet_raw(&mut sock);
    let resp = String::from_utf8_lossy(&raw).into_owned();
    assert!(
        resp.starts_with('F'),
        "expected 'F<count>' EOF reply, got: {resp:?}"
    );
    let body = &resp[1..];
    let count_hex = body.split(';').next().unwrap_or("");
    let n = i64::from_str_radix(count_hex, 16).unwrap_or_else(|_| panic!("parse count: {resp:?}"));
    assert_eq!(n, 0, "expected EOF (count=0), got {n} in {resp:?}");

    // 4. vFile:close — F0 on success.
    let close_pkt = format!("vFile:close:{fd:x}");
    sock.write_all(&rsp_packet(&close_pkt))
        .expect("write vFile:close");
    let resp = String::from_utf8_lossy(&read_packet_raw(&mut sock)).into_owned();
    assert_eq!(resp, "F0", "expected 'F0' on close, got: {resp:?}");

    // 5. vFile:open against an unknown name — `F-1,2` (errno
    //    ENOENT = 2).
    let bad_hex: String = "no_such.dll"
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bad_pkt = format!("vFile:open:{bad_hex},0,0");
    sock.write_all(&rsp_packet(&bad_pkt))
        .expect("write vFile:open bad");
    let resp = String::from_utf8_lossy(&read_packet_raw(&mut sock)).into_owned();
    // gdbstub formats the errno as `F-1,<hex>` where the hex
    // is at least 1 char wide (often zero-padded — `,02`).
    // ENOENT = 2 per POSIX (and gdbstub's `HostIoErrno::ENOENT`).
    assert!(
        resp.starts_with("F-1,"),
        "expected 'F-1,<errno>' for unknown name, got: {resp:?}"
    );
    let errno_str = resp.trim_start_matches("F-1,");
    let errno =
        i64::from_str_radix(errno_str, 16).unwrap_or_else(|_| panic!("parse errno: {resp:?}"));
    assert_eq!(errno, 2, "expected ENOENT (2), got {errno} in {resp:?}");

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet_raw(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Round-9 P2 — `qfThreadInfo` / `qsThreadInfo` advertise the
/// single fixed thread the SingleThreadBase target presents.
/// gdbstub auto-serves these queries on the strength of our
/// `BaseOps::SingleThread` choice — there's no Target-side
/// extension to wire. We assert the wire-level reply shape so
/// a connected GDB client's `info threads` shows one entry
/// instead of an empty list:
///
/// - `qfThreadInfo` returns `m<thread-id>` (one TID).
/// - `qsThreadInfo` returns `l` (end-of-list, per the GDB
///   protocol manual's iterative discovery contract).
///
/// The exact thread-id format depends on whether multiprocess
/// extensions are negotiated — gdbstub uses `pPID.TID`
/// (`p01.01`) in the multiprocess form. We accept either the
/// multiprocess form or a bare TID (`1` / `01`).
#[test]
fn qfthreadinfo_advertises_single_thread() {
    use std::io::{BufRead, BufReader, Read, Write as _};
    use std::net::TcpStream;
    use std::process::Stdio;
    use std::time::Duration;

    let dll = write_synth_dll();
    let bin = env!("CARGO_BIN_EXE_oxidetracevfw");
    let mut child = Command::new(bin)
        .arg(dll.path())
        .arg("--gdb")
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn oxidetracevfw");

    let stderr = child.stderr.take().expect("stderr piped");
    let mut reader = BufReader::new(stderr);
    let mut port: Option<u16> = None;
    let mut buffered = String::new();
    for _ in 0..32 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        buffered.push_str(&line);
        if let Some(idx) = line.find("listening on ") {
            let rest = &line[idx + "listening on ".len()..];
            if let Some(colon) = rest.rfind(':') {
                port = rest[colon + 1..].trim().parse::<u16>().ok();
            }
            break;
        }
    }
    let port = port.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("no listening line; stderr: {buffered}");
    });

    let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    fn rsp_packet(payload: &str) -> Vec<u8> {
        let mut sum: u32 = 0;
        for &b in payload.as_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.push(b'$');
        out.extend_from_slice(payload.as_bytes());
        out.push(b'#');
        out.extend_from_slice(format!("{:02x}", sum & 0xff).as_bytes());
        out
    }

    fn read_packet(sock: &mut TcpStream) -> String {
        let mut buf = [0u8; 1];
        loop {
            sock.read_exact(&mut buf).expect("read ack/start");
            if buf[0] == b'$' {
                break;
            }
            if buf[0] != b'+' && buf[0] != b'-' {
                break;
            }
        }
        let mut payload = Vec::new();
        loop {
            sock.read_exact(&mut buf).expect("read payload");
            if buf[0] == b'#' {
                break;
            }
            payload.push(buf[0]);
        }
        let mut csum = [0u8; 2];
        sock.read_exact(&mut csum).expect("read checksum");
        sock.write_all(b"+").expect("write ack");
        String::from_utf8_lossy(&payload).into_owned()
    }

    // qSupported with multiprocess+ — required so the stub
    // emits the multiprocess form `pPID.TID` in qfThreadInfo,
    // matching what a real GDB client expects.
    sock.write_all(&rsp_packet("qSupported:multiprocess+;swbreak+;hwbreak+"))
        .expect("write qSupported");
    let _ = read_packet(&mut sock);

    // qfThreadInfo — returns `m<thread-id>` for the first (and
    // only) thread.
    sock.write_all(&rsp_packet("qfThreadInfo"))
        .expect("write qfThreadInfo");
    let resp = read_packet(&mut sock);
    assert!(
        resp.starts_with('m'),
        "expected qfThreadInfo to start with 'm<tid>', got: {resp:?}"
    );
    let tid_part = &resp[1..];
    // Accept either multiprocess form (`p01.01` etc.) or a bare
    // hex TID. Anything non-empty is an actionable thread-id
    // for the GDB client.
    assert!(
        !tid_part.is_empty(),
        "qfThreadInfo TID should not be empty, got: {resp:?}"
    );
    // gdbstub uses lowercase hex with the multiprocess form
    // when the client advertised `multiprocess+`.
    if tid_part.starts_with('p') {
        assert!(
            tid_part.contains('.'),
            "multiprocess thread-id should contain '.', got: {resp:?}"
        );
    }

    // qsThreadInfo — returns `l` (end-of-list) for the
    // single-threaded sandbox.
    sock.write_all(&rsp_packet("qsThreadInfo"))
        .expect("write qsThreadInfo");
    let resp = read_packet(&mut sock);
    assert_eq!(
        resp, "l",
        "expected qsThreadInfo to terminate with 'l' (end-of-list), got: {resp:?}"
    );

    sock.write_all(&rsp_packet("D")).expect("write D");
    let _ = read_packet(&mut sock);
    drop(sock);
    let _ = child.wait();
}

/// Tiny helper namespace — temp-file path with auto-delete on
/// drop. We avoid pulling `tempfile` as a dev-dep purely to
/// keep this crate's dependency tree light; this is ~30 LOC.
mod tempfile_path {
    use std::path::{Path, PathBuf};

    pub struct TempPath(PathBuf);

    impl TempPath {
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    pub fn write_temp(prefix: &str, ext: &str, bytes: &[u8]) -> TempPath {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let suffix = format!("{pid}-{n}-{nanos}");
        let p = dir.join(format!("{prefix}-{suffix}.{ext}"));
        let mut f = std::fs::File::create(&p).expect("create temp");
        use super::Write;
        f.write_all(bytes).expect("write temp");
        TempPath(p)
    }
}
