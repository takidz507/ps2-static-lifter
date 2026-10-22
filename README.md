# PS2 Static Lifter

**An audited experiment: can a PlayStation 2 program be converted — ahead of
time, instruction by instruction, with no emulator inside — into native code
that runs on a modern phone?**

This repository contains the complete toolchain, targets, generated code,
measurements, and Android apps of the experiment. Every number below was
produced by the tools here and **independently reproduced by a second agent
(the auditor) before being accepted** — the project's working rule is that a
claim counts only when someone else can re-derive it.

There is **no emulator, interpreter, or JIT** anywhere in this project. The
guest code you see running was translated statically (PS2 EE / MIPS R5900 →
C → native ARM64/x86-64 machine code) and executes against a small,
explicitly-modeled runtime of kernel services and device boundaries.

## The ladder (all rungs independently audited)

| Rung | What was proven | Key measured results |
|---|---|---|
| **M1** — Analyzer | An ELF32/R5900 parser + disassembler built from scratch | Blind test on a real toolchain-built sample: **99.77%** of 30,090 instructions decoded; every structural field matched `readelf` exactly |
| **M2** — First lift | 100-instruction synthetic sample lifted to C with correct branch-delay-slot handling, mini runtime | Native build prints `Hello world!`, exit 0; packaged as an Android APK and run on a real phone (OnePlus Ace 3) |
| **M2.1** — Hardening | Lifter survived a *wild* real-world ELF (indirect `$t9`/PIC calls, jump tables) by declaring blockers instead of crashing | 30,060 / 30,090 lifted (**99.90%**); 30 blockers, all declared INDIRECT; generated C compiles `-Wall -Wextra -Werror` clean |
| **M2.2** — Real execution | The real 30,090-instruction ps2sdk program executed end-to-end from lifted code: entry → crt0 → newlib stdio → declared FILEIO boundary → clean exit | 27,340 guest instructions; 199 syscalls (7 lifted / 166 service / 26 boundary); 18/18 indirect calls resolved at runtime; APK on the phone reproduced the host run **bit-for-bit** (incl. 385 SyncBarrier calls) |
| **M2.3** — Graphics | COP1 FPU completed with true EE (non-IEEE-754) semantics; a GS/GIF boundary model rasterizes the guest's own packets into a 512×512 framebuffer | graph sample: 34,384 / 34,420 lifted (**99.90%**, 0 unlifted); 45/45 FPU numerical tests; 3 full frames, FRAME_LIMIT stop @ `graph_wait_vsync`; all 8 **pre-registered** pixel probes matched (predictions were sealed before the first run); the Android app steps the animation frame-by-frame on the phone (verified to 18 frames) |

### Bonus measurement — a real homebrew game

`500 Card Game` (a homebrew PS2 game published by its author, see NOTICE)
was analyzed and lifted with the same untouched tools:

- 52,294 instructions / 597 functions; lifted **52,249 (99.91%)** under the
  M2.3 lifter — blockers collapsed from 2,008 (M2.2) to **45** (43 indirect +
  2 unlifted) as a side effect of the FPU work.
- First execution (host + phone probe APK): **116,220 guest instructions**
  retired through crt0/libc init, stopping at the first unmodeled kernel
  service — EE syscall `0x74` (`SetSyscall`), called from the game's own
  `setup()`. The probe app turns that stop point into a progress meter:
  every newly modeled service moves it forward.

## Targets (all legal, all reproducible)

| File (in `targets/`) | What it is | SHA-256 |
|---|---|---|
| `hello_kernel_min.elf` | Declared synthetic ELF mirroring the official ps2sdk minimal kernel sample | `c0c4a947a0bd425697afd34265953d0c67cbc65d82a801f74eab626284524209` |
| `hello_real.elf` | Official ps2sdk `hello` sample built with the real ps2dev toolchain (ee-gcc 15.2), 1.2 MB, 30,090 instructions | `e972d608aef3b16c70e558b8a298084e2c322f8cb6cebb4fb7f19fa09a556d95` |
| `graph.elf` | Official ps2sdk GS graphics sample (libgraph/libdraw/libdma), 34,420 instructions | `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239` |

The card game's binary is **not** redistributed here; get it from the
author's own release (see NOTICE) — its measured reports are in `results/`
and `docs/`.

## Repository layout

- `tools/` — the analyzer (`ps2_lifter_m1.py`), the lifter v2.3
  (`ps2_lifter_m2.py`, plus the frozen v2.2 for baseline reproduction), the
  runtime model (`ps2_runtime.c/.h`), host runners, the FPU proof suite
  (`test_fpu_m23.c`), the census builder, and `run_m23.sh` — one command
  that rebuilds and re-verifies every M2.3 gate.
- `targets/` — the three target ELFs above.
- `lifted/` — the generated C for each target, **byte-identical to a fresh
  regeneration** by the lifter (no manual edits, ever — that is a project
  red line).
- `docs/` — the milestone specifications given to the builder agent
  (`RADAR-PROMPT-*.md`), the M2.3 census, the **sealed pre-registration** of
  expected pixels (`PREREG-M23.md`), and the builder's report.
- `results/` — lift reports (JSON), the FPU test log, the pixel-probe log,
  the GS boundary trace, and `frame3.ppm` / `frame3.png` — the first frame
  ever rendered by lifted code in this project (black clear + two sprite
  layers; the full-surface histogram is 249,344 / 2,800 / 10,000 pixels with
  zero other colors).
- `android/` — the four Android apps' sources (see `android/BUILDING.md`
  for the manual NDK build pipeline; prebuilt APKs are attached to the
  GitHub Release).

## Reproduce

```bash
cd tools && bash run_m23.sh   # P0 baseline, census, lifts, FPU tests,
                              # regression gates, 3-frame graphics run
```

Host requirements: `gcc`, `python3`. Android builds: NDK r26d + SDK
build-tools 35 (manual pipeline documented in `android/BUILDING.md`).

## Rules the project runs by

1. **Legal inputs only.** Official open-source samples and author-published
   homebrew. No commercial game files, no BIOS dumps, no downloaded ISOs —
   ever, for any sub-step.
2. **Nothing is skipped silently.** Undecoded/unlifted instructions and
   unresolved calls are counted, classified, and reported.
3. **No manual edits to generated code.** Fix the tool, regenerate.
4. **No host cheating at boundaries.** Output (text or pixels) must come
   from the guest's own code and data, interpreted by declared models.
5. **Pre-register predictions** before runs whose results could be
   rationalized after the fact.

## Credits

- **Direction & device testing:** Taqi (takidz507) — a first-year
  engineering student; this is his project.
- **Builder:** "Radar" (Gemini Argon) — wrote the analyzer, lifter, runtime
  models, and reports under the specifications in `docs/`.
- **Specs, independent audit & Android packaging:** Muse (Muse Spark) —
  every accepted figure in this README was re-derived on the auditor's own
  runs, and every APK was built and byte-verified by hand.
- Targets and toolchain: the **ps2dev / ps2sdk** community projects.

See `NOTICE.md` for provenance and licensing details.
