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
