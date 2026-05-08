# Changelog

All notable changes to this crate are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Round 7 — `qXfer:memory-map:read` PE section table (P1).**
  `SandboxTarget` now implements
  `gdbstub::target::ext::memory_map::MemoryMap`, advertised via
  `support_memory_map`. The XML document is rendered eagerly at
  `with_forward` construction time from the loaded
  `oxideav_vfw::pe::Image::sections` table — each PE section
  becomes a `<memory>` element with `start = va_start`,
  `length = mapped_size`, and `type = "rom"` (read-only or
  read-execute) or `"ram"` (writable), per the GDB memory-map
  DTD (only `ram` / `rom` / `flash` are admitted; see
  <https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory-Map-Format.html>).
  A connected GDB client's `info mem` /
  `maintenance info sections` now shows the codec's actual
  loaded layout (`.text` r-x at `image_base + 0x1000`, `.data`
  rw-, `.rdata` r--, …) instead of "no memory regions". Three
  unit tests cover the XML builder + the gating predicate +
  pagination; one TCP-protocol integration test
  (`qxfer_memory_map_read_returns_section_table`) drives the
  binary end-to-end and asserts on the assembled document
  containing `.text`'s VA + at least one rom-typed section.
- **Round 7 — `qXfer:exec-file:read` codec basename (P2).**
  `SandboxTarget` now implements
  `gdbstub::target::ext::exec_file::ExecFile`, advertised via
  `support_exec_file`. The DLL/AX filename the operator passed
  on the CLI is captured at construction time and returned to
  the GDB client across paginated `qXfer:exec-file:read::…`
  reads — so `info file` shows `IR32_32.DLL` / `INDEO5.AX` /
  the operator's actual basename instead of the placeholder
  `<process N>` gdbstub falls back to. The path is intentionally
  stripped to a basename so we don't leak the host filesystem
  layout to the wire. Two unit tests cover the gating predicate
  + paginated reads + `pid`-ignoring contract; one
  TCP-protocol integration test
  (`qxfer_exec_file_read_returns_dll_basename`) drives the
  binary end-to-end and asserts the reassembled string matches
  the temp-file's `.dll` basename exactly.

- **Round 6 — `qXfer:features:read` register-description override (P2).**
  `SandboxTarget` now implements
  `gdbstub::target::ext::target_description_xml_override::TargetDescriptionXmlOverride`,
  advertised via `support_target_description_xml_override`. A connected
  GDB client requesting `qXfer:features:read:target.xml:…` gets a
  paginated read of a hand-rolled i386 description that matches the
  `gdbstub_arch::x86::X86_SSE` wire layout exactly: GPRs + EIP +
  EFLAGS + segment regs + ST(0..7) (which alias `MM(0..7)` per
  Intel SDM Vol. 1 §9.2.1) + FPU internal regs + XMM(0..7) +
  MXCSR. Without this override, gdbstub falls back to a generic
  X86_SSE description that may mis-align our MMX-aliases-ST(i)
  surface in `info registers`. Three new unit tests cover
  paginated assembly, unknown-annex empty reply, and offset-past-EOF;
  one new TCP-protocol integration test
  (`qxfer_features_read_returns_target_xml_with_i386_features`)
  drives the binary end-to-end and asserts the canonical
  `org.gnu.gdb.i386.{core,sse}` feature names land in the assembled
  document.
- **Round 6 — real-codec smoke matrix (P1, opt-in).** New
  `integration-real-codec` Cargo feature; `cargo test
  --features integration-real-codec` fetches the canonical
  Indeo Video 3 / 4 / 5 VfW codecs from
  `samples.oxideav.org/codecs/windows/IV5PLAY/` (URLs +
  SHA-256s pinned to the `docs/winmf/windows-codecs.md`
  manifest), caches under `target/oxideav-tracevfw-fixtures/`,
  drives `oxidetracevfw <fixture> probe --trace-output` against
  each, and asserts exit code 0 plus at least one `kind=…` JSONL
  event lands on disk. Off by default so the standard `cargo
  test` flow stays self-contained; tests skip gracefully (with a
  `[real-codec] skipped: …` stderr message) when curl is missing
  or the network is unreachable. Fetcher uses the host's `curl`
  binary instead of pulling a Rust HTTP client into
  `[dev-dependencies]`; SHA-256 verification is implemented
  inline (~80 LOC) so no `sha2` dev-dep either. Three fixture
  tests (IR32_32.DLL / IR41_32.AX / IR50_32.DLL) plus one
  FIPS 180-4 self-check on the standalone hash.

### Changed

- `oxideav-vfw` dep bumped to `version = "0.1"` (was `"0.0"`).
  `oxideav-vfw 0.1.0` shipped 2026-05-08 with the `trace` Cargo
  feature, so the path-dep workaround the round-1 commit message
  contemplated was never needed: the consumer side resolves
  cleanly off the published producer.
- **Round 5 — `gdb::run_gdb_server` signature gains `cli_breakpoints`.**
  Existing callers (`main.rs`) now pass the `--break` PC list
  through. `SandboxTarget::with_forward` likewise grew the
  `cli_breakpoints` argument; the `Box<dyn Write + Send>` forward
  parameter is now `Arc<Mutex<Option<…>>>` (`ForwardSink`) so the
  GDB event loop and the sandbox's trace tap can both write to
  the same JSONL stream without serialising through one owner.

### Added

- **Round 5 — single-register `P`/`p` packet support (P1).**
  `SandboxTarget` now implements `gdbstub::target::ext::base::
  single_register_access::SingleRegisterAccess<()>`, advertised
  via `support_single_register_access`. GDB clients can read
  (`p<reg>`) or write (`P<reg>=<le-hex>`) a single register
  without rolling the whole `g`/`G` register file. Reg IDs cover
  the eight GPRs (0..=7), EIP (8), EFLAGS (9), and the eight
  ST(i) MMX-aliased FPU stack entries; segments / FPU internal
  / XMM / MXCSR are accepted but zero-filled because the sandbox
  does not model them — same surface as the existing bulk
  register-file path. New TCP-only integration test
  `p_packet_single_register_write_is_acknowledged` exercises
  `P0=…` (EAX) → `p0` (read-back) → `P8=…` (EIP) → `p8` over a
  real RSP socket.
- **Round 5 — `--break <PC>` JSONL events under `--gdb` (P2).**
  The CLI `--break` flag is now honoured by the GDB event loop:
  PCs are auto-installed as software breakpoints (so a connected
  GDB client halts at each one) AND every time guest EIP lands
  on one during a `c` step slice, the loop emits a synthetic
  `{"kind":"breakpoint","addr":"0x…","eip":"0x…"}` JSONL line
  into the `--trace-output FILE` forward sink. Useful for the
  detached-client case: an operator running
  `oxidetracevfw codec.dll --gdb :1234 --break 0x10001234
  --trace-output run.jsonl` gets the breakpoint hits on disk
  alongside the rest of the JSONL event tape, independent of
  any client `c`/`s` interaction. New integration test
  `gdb_break_flag_emits_kind_breakpoint_into_trace_output`
  drives the binary end-to-end via RSP and inspects the
  resulting trace file.

- **Round 4 — `--gdb` honours `--trace-output FILE` (P1).**
  `run_gdb_server` now accepts an optional trace-output path and
  threads it through a new `SandboxTarget::with_forward`
  constructor that hands the underlying `Box<dyn Write + Send>`
  to the existing `WatchSink` forward path. Operators pairing
  `--gdb HOST:PORT` with `--trace-output run.jsonl` get the
  full `kind=mem_*` / `kind=trap` / `kind=exec` /
  `kind=win32_call` event tape on disk while a GDB client drives
  the sandbox interactively. Watchpoint stop-reasons still surface
  to the GDB client unchanged.
- **Round 4 — Z2 watchpoint protocol-level integration test (P2).**
  New `z2_watchpoint_via_rsp_returns_t05_watch_stop_reason` test
  spawns the binary, parses the OS-chosen port from
  `[gdb] listening on …`, hand-crafts RSP packets over a real
  TCP socket: `qSupported` → `g` (read regs, expanding RSP
  run-length encoding) → `G` (write regs back with EAX, EDI, EIP
  overridden to point at a `mov [edi], eax; hlt` sled patched
  into a synthetic minimal-PE32 DLL's `.text` padding) → `Z2`
  (write watchpoint at the destination address) → `c` (continue).
  Asserts the server replies with `T05…watch:<addr>;…` — the GDB
  stop-reply syntax for hardware-watchpoint hits — without
  needing any `gdb` binary on the test host.
- **Round 3 — watchpoint-hit `Watch` stop-reason wiring (P1).**
  `gdb.rs` now installs a JSONL tap on the sandbox's trace sink
  (`WatchSink`) that decodes `kind=mem_read` / `kind=mem_write`
  events into a shared `WatchHit` queue. After each `cpu.step`
  in the GDB blocking event loop we drain one entry and yield
  `SingleThreadStopReason::Watch { tid: (), kind, addr }` so a
  GDB client running `watch *(int *)0xDEADBEEF` + `c` halts at
  the offending memory access. Tested end-to-end via a guest
  `mov [edi], eax; hlt` micro-program.
- **Round 3 — MMX register surface (P2).** `read_registers` /
  `write_registers` now map `Cpu::mmx[u64; 8]` onto the lower
  64 bits of `X86CoreRegs.st[i]` per Intel SDM Vol. 1 §9.2.1
  (architectural alias `MM0..MM7` ↔ `ST(0)..ST(7).low64`). GDB
  clients see the live MMX state through `info registers float`
  and can `set $st0 = …` to seed `cpu.mmx[0]`. The high 16 bits
  of each F80 (FPU exponent + sign) stay zero because the
  sandbox does not model the FPU stack.
- **Round 3 — encode/decode subcommand status notes (P3).**
  `decode.rs` already wired `ic_open` →
  `ic_decompress_query` → `ic_decompress_begin` →
  `ic_decompress` → `ic_decompress_end` → `ic_close` against
  the operator-supplied codec frame; a new integration test
  asserts the path is exercised. `encode.rs` is blocked on a
  cross-crate followup: `oxideav-vfw 0.1.0` exposes only the
  `ic_decompress*` half of the VfW host surface, so encode
  remains an open-only smoke test until `oxideav-vfw` grows
  `Sandbox::ic_compress_query` / `ic_compress_begin` /
  `ic_compress` / `ic_compress_end` (mirroring the existing
  decompress wrappers; `ICM_COMPRESS*` macro values 0x4001 /
  0x4002 / 0x4007 / 0x4008 in `vfw.h`).

- **Round 2 — GDB Remote Serial Protocol server (`--gdb HOST:PORT`).**
  `src/gdb.rs` is now a complete `gdbstub::Target` implementation
  (architecture `gdbstub_arch::x86::X86_SSE`) wired to the
  `oxideav_vfw::Sandbox`: read/write registers (8 GPRs + EIP +
  EFLAGS), read/write memory through the MMU, single-step and
  continue, software breakpoints (`Z0`/`z0`), and hardware
  watchpoints (`Z2`/`Z3`/`Z4` → `Sandbox::watch`/`unwatch`).
  Bind `:0` to pick a free port; the chosen port is logged as
  `[gdb] listening on …`. Disconnects (`vKill` / `D`) tear down
  cleanly. New TCP-only RSP wire-protocol integration test
  (`gdb_flag_starts_rsp_server_and_speaks_protocol`) exchanges
  `qSupported` / `g` / `D` packets without needing an actual
  `gdb` binary on the test host, so CI can validate the server
  stand-alone.
- Initial round — **`oxidetracevfw` CLI driving the
  `oxideav-vfw` `trace` Cargo feature.** New CLI binary with
  three subcommands (`probe`, `encode`, `decode`) plus four
  global flags (`--asm`, `--trace-mem`, `--break`,
  `--trace-output`) that surface the trace primitives behind
  ergonomic command-line invocation. Memwatch flag accepts
  `ADDR:SIZE[:MODE]` (MODE ∈ `r|w|rw`, default `rw`); break
  flag dumps a `kind=breakpoint` JSONL event when guest EIP
  matches a registered PC breakpoint and continues execution.
  Tests run against a synthetic minimal-PE32 DLL built via
  `oxideav_vfw::pe::test_image::build_minimal_dll` to avoid
  pulling codec binaries into the test surface.
