# Changelog

All notable changes to this crate are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
