# oxideav-tracevfw

Trace + debug CLI for [`oxideav-vfw`][oxideav-vfw] — load a Windows codec
DLL or AX filter into the pure-Rust VfW emulator, probe its driver
surface, drive synthetic encode/decode workloads, log memory
watchpoints, and dump CPU state at PC breakpoints. Output is JSONL,
one event per line, on a sink configured by `--trace-output` or
the `OXIDEAV_VFW_TRACE_FILE` environment variable.

GDB Remote Serial Protocol server support is **deferred to round 2**
of this crate; see `src/gdb.rs` for the placeholder + the design
note for what the round-2 wrapper around `gdbstub` will look like.

[oxideav-vfw]: https://github.com/OxideAV/oxideav-vfw

## Quick start

```sh
# Probe a codec DLL — load, run DllMain, ICOpen, ICGetInfo,
# ICDecompressQuery, print results in human-readable form.
oxidetracevfw IR32_32.DLL probe

# Decode a raw codec frame, watching a 32-byte region for
# stores, with per-instruction trace enabled, output JSONL to
# /tmp/decode-trace.jsonl.
oxidetracevfw IR32_32.DLL \
    --trace-mem 0x100A0000:32:rw \
    --asm \
    --trace-output /tmp/decode-trace.jsonl \
    decode --input keyframe.iv31 --width 64 --height 48

# Drive synthetic encode against the codec.
oxidetracevfw IR32_32.DLL encode --width 320 --height 240 \
    --pattern gradient --output /tmp/encoded.iv31
```

## CLI surface

```
oxidetracevfw <DLL_OR_AX_FILE> [OPTIONS] [SUBCOMMAND]

Subcommands:
  probe             (default) load + DllMain + ICGetInfo + ICDecompressQuery
  encode            drive ICCompress on synthetic input
  decode            drive ICDecompress on input file

Global options:
  --asm                          enable per-instruction trace (requires
                                 oxideav-vfw built with `trace-exec`)
  --trace-mem <ADDR:SIZE[:MODE]> watch memory region; MODE = r|w|rw
                                 (default rw); repeatable
  --break <PC>                   PC breakpoint; dump CPU state when reached
  --trace-output <FILE>          JSONL events output (default: stderr)
  --max-instr <N>                cap total instructions to prevent runaway
  --fcc-handler <FCC>            FourCC handler override
```

## Provenance

Built atop `oxideav-vfw`'s `trace` Cargo feature. The emulator is
pure-Rust (no JIT, no host-FFI codec execution); a buggy or
malicious DLL can corrupt only the emulator's sandbox.
