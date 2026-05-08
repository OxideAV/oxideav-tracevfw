# Changelog

All notable changes to this crate are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial round — **`oxidetracevfw` CLI driving the
  `oxideav-vfw` `trace` Cargo feature.** New CLI binary with
  three subcommands (`probe`, `encode`, `decode`) plus four
  global flags (`--asm`, `--trace-mem`, `--break`,
  `--trace-output`) that surface the trace primitives behind
  ergonomic command-line invocation. Memwatch flag accepts
  `ADDR:SIZE[:MODE]` (MODE ∈ `r|w|rw`, default `rw`); break
  flag dumps a `kind=breakpoint` JSONL event when guest EIP
  matches a registered PC breakpoint and continues execution
  (halt-and-prompt is GDB-server work, deferred to round 2).
  GDB Remote Serial Protocol server placeholder (`src/gdb.rs`)
  errors cleanly today; `gdbstub`-based implementation tracked
  for round 2. Tests run against a synthetic minimal-PE32 DLL
  built via `oxideav_vfw::pe::test_image::build_minimal_dll`
  to avoid pulling codec binaries into the test surface.
