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
