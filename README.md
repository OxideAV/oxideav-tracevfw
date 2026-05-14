# oxideav-tracevfw

Trace + debug CLI for [`oxideav-vfw`][oxideav-vfw] — load a Windows codec
DLL or AX filter into the pure-Rust VfW emulator, probe its driver
surface, drive synthetic encode/decode workloads, log memory
watchpoints, and dump CPU state at PC breakpoints. Output is JSONL,
one event per line, on a sink configured by `--trace-output` or
the `OXIDEAV_VFW_TRACE_FILE` environment variable.

Round 2 adds a **GDB Remote Serial Protocol server** so a real
`gdb` (or any RSP-speaking client) can drive the sandbox
interactively — see `--gdb HOST:PORT` below + `src/gdb.rs` for
the `gdbstub`-backed `Target` implementation.

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

# Encode raw BGR24 pixels into a codec bitstream. Drives the full
# ICCompressQuery → ICCompressGetFormat → ICCompressGetSize →
# ICCompressBegin → ICCompress → ICCompressEnd lifecycle.
oxidetracevfw mpg4c32.dll encode \
    --input frame.bgr24 --width 176 --height 144 \
    --input-format bgr24 --quality 5000 --keyframe true \
    --output /tmp/encoded.mp43

# Drive synthetic encode against the codec (no input file —
# generates a gradient/solid/checkerboard pattern internally).
oxidetracevfw IR32_32.DLL encode --width 320 --height 240 \
    --pattern gradient --output /tmp/encoded.iv31

# Watch a 2928-byte codec-context allocation and dump FPU/MMX
# state at a known breakpoint — the Auditor's mpg4c32 recipe
# for sandbox-01 §6.
oxidetracevfw mpg4c32.dll decode --input frame.mp43 \
    --watch 0x600002c0,2928 \
    --break 0x1c2132b8 --break-include-fpu \
    --trace-output /tmp/audit.jsonl \
    --width 176 --height 144

# GDB-attached interactive session: bind on port 1234, halt
# the CPU pre-execution, and wait for `gdb`.
oxidetracevfw IR32_32.DLL --gdb 0.0.0.0:1234

# In another terminal:
#   $ gdb
#   (gdb) target remote :1234
#   (gdb) hbreak *0x10001000
#   (gdb) c              # continue; runs until breakpoint
#   (gdb) si             # single-step
#   (gdb) info reg
#   (gdb) x/16xb 0x60000000
#   (gdb) monitor stats         # round 10: instr_count, watch/break/module counters
#   (gdb) monitor breakpoints   # round 10: list registered SW breakpoints
#   (gdb) monitor watches       # round 10: list registered HW watchpoints
#   (gdb) monitor modules       # round 10: list loaded PE modules
#   (gdb) monitor files         # round 11: list host_io files (vFile:open targets)
#   (gdb) add-symbol-file remote:IR32_32.DLL  # round 10: fetch DLL bytes via vFile:open/pread
#   (gdb) add-symbol-file remote:kernel32.dll # round 12: cascade stub is now a valid PE32
#   (gdb) detach
```

## CLI surface

```
oxidetracevfw <DLL_OR_AX_FILE> [OPTIONS] [SUBCOMMAND]

Subcommands:
  probe             (default) load + DllMain + ICGetInfo + ICDecompressQuery
  encode            drive full ICCompress* lifecycle on raw / synthetic input
  decode            drive ICDecompress on input file

Global options:
  --asm                          enable per-instruction trace (requires
                                 oxideav-vfw built with `trace-exec`)
  --trace-mem <ADDR:SIZE[:MODE]> watch memory region; MODE = r|w|rw
                                 (default rw); repeatable. Emits
                                 kind=mem_read / kind=mem_write events
                                 in the oxideav-vfw schema
  --watch <ADDR[,LEN]>           watch memory region (read + write);
                                 LEN defaults to 4 (one dword);
                                 repeatable. Emits kind=mem_watch JSONL
                                 events with an explicit `op` field
                                 (`read` / `write`). Distinct from
                                 --trace-mem — pick one or the other
                                 per audit recipe
  --break <PC>                   PC breakpoint; emits kind=breakpoint JSONL
                                 with the integer register file at hit time
                                 (works in both CLI and --gdb modes)
  --break-include-fpu            append a populated `fpu` sub-object to
                                 every kind=breakpoint event — x87
                                 ST(0..7), MMX MM0..MM7, tag, status,
                                 control. Default off; see "Limitations"
                                 for the live-read fidelity caveat
  --trace-output <FILE>          JSONL events output (default: stderr)
  --max-instr <N>                cap total instructions to prevent runaway
  --fcc-handler <FCC>            FourCC handler override
  --gdb <HOST:PORT>              bind a GDB Remote Serial Protocol server;
                                 use `:0` to pick a free port (printed
                                 to stderr as `[gdb] listening on …`)

encode subcommand options:
  --input <FILE>                 raw uncompressed pixel bytes (header-less)
  --width <N> --height <N>       frame dimensions (also used for synthesis)
  --input-format <FORMAT>        bgr24 (default) | bgr32 | yv12 | i420 | yuy2
  --pattern <NAME>               gradient (default) | solid | checkerboard
                                 (only used when --input is absent)
  --quality <0..=10000>          ICCOMPRESS::dwQuality; default 5000
  --pquant <1..=31>              override the picture-header PQUANT field
                                 directly on the encoded bitstream (see
                                 "Limitations" below)
  --keyframe <BOOL>              ICCOMPRESS_KEYFRAME flag; default true
  --output-fourcc <FCC>          override the codec's chosen output FOURCC
  --output <FILE>                where to write encoded bytes (default stdout)
```

## Limitations

- **`--pquant N` is a post-processing patch, not an encoder
  knob.** The MS-MPEG-4 v3 codec (`mpg4c32.dll`) clamps its
  picture-header PQUANT to a constant (PQUANT=4) regardless of
  the `--quality` value passed in `ICCOMPRESS::dwQuality`. The
  proper override path is `ICM_GETSTATE` / `ICM_SETSTATE`, but
  `oxideav_vfw::Sandbox` does not yet expose `ic_get_state` /
  `ic_set_state` as host helpers (cross-crate followup tracked
  in OxideAV/oxideav-vfw). As a workaround, `--pquant N` rewrites
  the 5-bit PQUANT field at bit offset 2 of the picture header
  (MSB-first within byte 0) on the bitstream returned by
  `ICCompress`. The rewrite targets the v3 layout — operators
  using v1/v2/v4 codecs need a different bit offset.

- **`--break PC` register snapshot has GP-register fidelity, not
  full FPU/SSE state.** The per-instruction snapshot hook
  ([`Cpu::add_register_watchpoint`]) captures the eight integer
  registers (eax/ecx/edx/ebx/esp/ebp/esi/edi) plus a live
  `eflags` read at drain time. Floating-point / MMX / SSE state
  at the breakpoint instant is not captured — attach via
  `--gdb HOST:PORT` and use `info reg all` for the full
  register file. Default cap on captures per run is 1024;
  hot-loop breakpoints past the cap are silently truncated.

  Passing `--break-include-fpu` appends a `"fpu":{…}` sub-object
  to every emitted `kind=breakpoint` line carrying x87
  ST(0..7) (as IEEE-754 double bit-patterns in hex),
  MMX MM0..MM7 (as u64 hex), tag word, status word, and control
  word. Like `eflags`, these values are read LIVE at flush time
  rather than from the snapshot ring — the underlying
  `oxideav-vfw` snapshot hook does not preserve FPU state per
  hit. For single-breakpoint runs this is identical to the
  breakpoint-instant value; for multi-hit traces the emitted
  FPU values reflect the END-of-run state. For per-hit FPU
  fidelity, attach via `--gdb` and use `info reg all`.

- **`--watch ADDR[,LEN]` and `--trace-mem ADDR:SIZE[:MODE]` are
  parallel surfaces.** Both install a watchpoint via
  `oxideav_vfw::Sandbox::watch`; the difference is the JSONL
  schema and the convenience syntax:
    * `--trace-mem` retains the original `kind=mem_read` /
      `kind=mem_write` shape (one event per access; mode-
      selectable; size required).
    * `--watch` rewrites every matching access to the
      `kind=mem_watch` shape with an explicit `op:"read"` /
      `op:"write"` field; size defaults to 4 (one dword); both
      reads and writes always fire.
  An operator running both flags against overlapping ranges
  will see the watched access rewritten to `kind=mem_watch`
  (the wrapper short-circuits before the legacy schema emits).

[`Cpu::add_register_watchpoint`]: https://docs.rs/oxideav-vfw/latest/oxideav_vfw/emulator/isa_int/struct.Cpu.html

## Provenance

Built atop `oxideav-vfw`'s `trace` Cargo feature. The emulator is
pure-Rust (no JIT, no host-FFI codec execution); a buggy or
malicious DLL can corrupt only the emulator's sandbox.
