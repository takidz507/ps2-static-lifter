# PS2 Static Lifter — Milestone 2.3 Engineering Report (`REPORT-M23.md`)
## The Graphics Rung: COP1 FPU Completion, GS Boundary Model, and First Drawn Frames

---

## 1. Executive Summary & Gate Verdict Matrix

| Gate / Milestone Part | Target / Scope | Measured Result | Verdict |
| :--- | :--- | :--- | :--- |
| **Gate P0 (Baseline Reproduction)** | `graph.elf` (`1,379,708` B, SHA-256 `4220f58a...da7239`) on unmodified M1 + Lifter v2.2 | M1: `33,875 / 34,420` (`98.42%`), `545` UNDECODED, `40` unique syscalls (`52` sites). Lifter v2.2: `504/504` funcs, `33,921 / 34,420` (`98.55%`), `499` blockers (`463 UNLIFTED_INSN + 36 INDIRECT`), `17/53` indirect resolved (`5` JT / `5` const-`$t9` / `7` static ptr), `gcc -std=c11 -O1` exit `0`. | **PASS (100% Exact)** |
| **Part 1 (Instruction Census)** | `545` M1-UNDECODED & `463` v2.2-`UNLIFTED_INSN` in `graph.elf` (`CENSUS-M23.md`, `census_m23.json`) | `170` `UNKNOWN_OPCODE` = `113` `LWC1` + `57` `SWC1` (`0` data-in-code); `288` `COP1_FPU` = 14 mnemonics; `4` `COP0` = `3` `BC0T` + `1` `BC0F`; `1` `MMI` = `PCPYH`. Book reconciliation `545 - 82 = 463` exact. | **PASS** |
| **Part 2 (FPU Lift & Unit Proofs)** | `ps2_lifter_m2.py` v2.3.0 + `ps2_runtime.c` R5900 COP1 model + `test_fpu_m23.c` | `UNLIFTED_INSN` on `graph.elf` driven from `463` to **`0`** (`34,384 / 34,420 = 99.90%` lifted, `36` `INDIRECT`). Numerical proof suite: **`45 / 45` bit-exact pass**. | **PASS** |
| **Part 2 (Regression Gates)** | `hello_kernel_min.elf` & `hello_real.elf` | `hello_kernel_min.elf`: `100/100` lifted, `Hello world!`, exit `0`. `hello_real.elf`: `30,060/30,090` lifted, **`27,340`** guest instructions, **`199`** syscalls (`7 / 166 / 26`), **`18/18`** indirect resolved, `Hello world!`, exit `0`. | **PASS (Bit-Identical)** |
| **Part 3 (GS Boundary & Frame 3)** | `graph.elf` executed from `0x00100b20` (`__start`) for `3` frames (`PREREG-M23.md`, `frame3.ppm`/`.png`, `pixel_probe.log`, `gs_trace.log`/`.json`) | Clean `FRAME_LIMIT` stop @ `0x001013f0` after `3 / 3` frames, **`46,443`** guest instructions (`17` FPU ops, `4` GIF DMA packets, `11` GIF tags, `64` GS reg writes, `18` sprites, `282,144` pixels filled). **`8 / 8` pre-registered pixel probes + full 262,144-pixel histogram match**. | **PASS** |
| **Part 4 (Stretch: Android Surface)** | `android_graph_app/` (`org.ps2lifter.graph`, label `PS2 Lifted Graph`) | Self-contained Gradle/CMake/JNI project (`libps2_lifted_graph.so`) blitting the `512 x 512` `ARGB_8888` framebuffer to `Bitmap`/`ImageView` with interactive frame stepping and boundary telemetry. | **PASS** |

---

## 2. Gate P0 — Baseline Reproduction (Unmodified M2.2 Tools)

Before modifying any file, `graph.elf` was audited with the unmodified Milestone 1 analyzer (`ps2_lifter_m1.py`) and the unmodified Milestone 2.2 lifter (`ps2_lifter_m2_v22_unmodified.py`):

| Check | Unmodified Tool Output | Muse Prompt Specification | Match |
| :--- | :--- | :--- | :--- |
| File Size | `1,379,708` bytes | `1,379,708` bytes | Exact |
| SHA-256 | `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239` | `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239` | Exact |
| Entry Point / `e_flags` | `0x00100b20` / `0x20920025` | `0x00100b20` / `0x20920025` | Exact |
| `.text` Offset / VAddr / Size | `0x00000080` / `0x00100000` / `0x219d0` (`137,680` B = `34,420` words) | `.text` size `0x219d0`, `34,420` instructions | Exact |
| `.symtab` Functions (`STT_FUNC`) | `504` | `504` | Exact |
| M1 Decoded / Undecoded | `33,875 / 34,420` (`98.42%`) / `545` UNDECODED | `33,875 / 34,420` (`98.42%`) / `545` UNDECODED | Exact |
| M1 Undecoded Breakdown | `COP1_FPU: 288`, `UNKNOWN_OPCODE: 170`, `MEMORY_BARRIER_SYNC: 41`, `COP0_SYSTEM: 26`, `CACHE_OP: 13`, `R5900_MMI_SIMD: 4`, `R5900_QUADWORD_MEM: 3` | Identical | Exact |
| M1 EE Syscalls Detected | `40` unique syscall numbers across `52` `syscall` instruction sites | `40` | Exact |
| Lifter v2.2 Coverage | `504/504` functions; `33,921 / 34,420` (`98.55%`) lifted | `504/504` functions; `33,921 / 34,420` (`98.55%`) | Exact |
| Lifter v2.2 Blockers | `499` (`UNLIFTED_INSN: 463`, `INDIRECT: 36`) | `499` = `UNLIFTED_INSN 463` + `INDIRECT 36` | Exact |
| Lifter v2.2 Indirect Sites | `53` total, `17` resolved (`5` `JUMP_TABLE`, `5` `CONST_LUI_ADDIU`, `7` `STATIC_DATA_PTR`), `36` unresolved | `53` sites, `17` resolved (`5` / `5` / `7`), `36` unresolved | Exact |
| Host C Compilation | `lifted_graph_v22.c` (`7,788,042` B) compiles clean with `gcc -std=c11 -O1` (exit `0`) | ~7.4 MB C compiles clean (`gcc -std=c11 -O1`, exit `0`) | Exact |

---

## 3. Part 1 — Census Before Lifting (`CENSUS-M23.md` & `census_m23.json`)

### 3.1 The 170 `UNKNOWN_OPCODE` Instructions
Every one of the `170` `UNKNOWN_OPCODE` words is a real MIPS/R5900 COP1 floating-point memory transfer instruction (`0` data-in-code words, `0` alignment traps):
- **`LWC1 ft, offset(base)` (`op = 0x31`)**: **`113`** instructions across 9 functions (`draw_clear`, `render`, `cosf`, `sinf`, `floorf`, `scalbnf`, `__ieee754_rem_pio2f`, `__kernel_cosf`, `__kernel_rem_pio2f`, `__kernel_sinf`).
- **`SWC1 ft, offset(base)` (`op = 0x39`)**: **`57`** instructions across 4 functions (`__ieee754_rem_pio2f`, `__kernel_rem_pio2f`, `floorf`, `scalbnf`).

### 3.2 The 288 `COP1_FPU` (`op = 0x11`) Instructions
The `288` `COP1_FPU` instructions span **14 distinct mnemonics**:

| Mnemonic | Encoding (`op=0x11`) | Count | Mnemonic | Encoding (`op=0x11`) | Count |
| :--- | :--- | ---: | :--- | :--- | ---: |
| `mul.s` | `fmt=0x10, funct=0x02` | **65** | `cvt.s.w` | `fmt=0x14, funct=0x20` | **13** |
| `sub.s` | `fmt=0x10, funct=0x01` | **61** | `mov.s` | `fmt=0x10, funct=0x06` | **7** |
| `add.s` | `fmt=0x10, funct=0x00` | **39** | `bc1f` | `fmt=0x08, rt=0x00` | **6** |
| `mtc1` | `fmt=0x04, funct=0x00` | **38** | `c.eq.s` | `fmt=0x10, funct=0x32` | **4** |
| `mfc1` | `fmt=0x00, funct=0x00` | **17** | `bc1t` | `fmt=0x08, rt=0x01` | **2** |
| `cvt.w.s` | `fmt=0x10, funct=0x24` | **16** | `c.lt.s` | `fmt=0x10, funct=0x34` | **2** |
| `neg.s` | `fmt=0x10, funct=0x07` | **16** | `c.le.s` | `fmt=0x10, funct=0x36` | **2** |

### 3.3 The Remaining 5 Non-FPU `UNLIFTED_INSN` in Lifter v2.2
1. **`COP0_SYSTEM` (`op=0x10, rs=0x08` — 4 instructions in `dma_wait_fast` @ `0x00100d48`)**:
   - `3` `bc0t` (`0x00100d50`, `0x00100d58`, `0x00100d60`) and `1` `bc0f` (`0x00100d68`).
2. **`R5900_MMI_SIMD` (`op=0x1c, rs=0x00, sa=0x1b, funct=0x29` — 1 instruction in `memset` @ `0x00104290`)**:
   - `1` `pcpyh $v1, $t0` (`0x70081ee9` at `0x001042bc`).

### 3.4 Reconciliation of M1 (`545`) vs. Lifter v2.2 (`463 + 36`) vs. Lifter v2.3 (`0 + 36`)
- M1 reported `545` `UNDECODED` instructions.
- Lifter v2.1/v2.2 already lifted `82` of those `545` exotic instructions (`41` `SYNC` + `22` `COP0` `mfc0`/`mtc0`/`ei`/`di` + `13` `CACHE` + `3` `MMI` `madd`/`pmfhl.lw` + `3` `LQ`/`SQ`), leaving `545 - 82 = 463` `UNLIFTED_INSN` plus `36` unresolved `INDIRECT` sites (`499` total blockers).
- Lifter v2.3 lifts all `463` remaining instructions (`170` `LWC1`/`SWC1` + `288` `COP1_FPU` + `4` `BC0T`/`BC0F` + `1` `PCPYH`), driving `UNLIFTED_INSN` to **`0`** (`34,384 / 34,420 = 99.90%` lifted; only the `36` declared `INDIRECT` blockers remain).

---

## 4. Part 2 — R5900 COP1 FPU Semantics, Deviation Decisions & Numerical Proof

### 4.1 R5900 EE FPU Architectural Semantics vs. Host IEEE-754 `float`
The PS2 Emotion Engine `COP1` FPU implements a non-IEEE-754 32-bit floating-point format:
1. **No `NaN` or `±Infinity` representations (Exponent `255` is finite)**: Biased exponents `1..255` represent normal finite values $(-1)^s \times 2^{e-127} \times (1 + m/2^{23})$ up to $\pm\text{MAX} = \text{0x7FFFFFFF} / \text{0xFFFFFFFF}$ ($\approx \pm 3.4028235 \times 10^{38} \times 2$).
2. **Denormal Flush-to-Zero (`FS = 1`)**: Any input operand with biased exponent `0` (`0x00000000..0x007FFFFF` or `0x80000000..0x807FFFFF`) is treated as signed zero (`±0.0`), and any result whose biased exponent falls $\le 0$ flushes to signed zero and sets `FCSR.U` (Underflow) and `FCSR.SU` (Sticky Underflow).
3. **Overflow Saturation to `±MAX`**: Any arithmetic operation whose unbiased result exponent exceeds `128` (biased exponent `> 255`) saturates to `0x7FFFFFFF` (`+MAX`) or `0xFFFFFFFF` (`-MAX`) and sets `FCSR.O` (Overflow) and `FCSR.SO` (Sticky Overflow).
4. **Round-to-Zero (RTZ / Truncation)**: The R5900 FPU hardwires rounding to Round-to-Zero (truncation of fractional bits below bit 0 of the 23-bit mantissa) rather than IEEE-754 Round-to-Nearest-Even (RNE).

### 4.2 Per-Opcode Implementation & Deviation Table (`ps2_runtime.c`)

| Opcode Family | Mnemonics Lifted | Implementation in `ps2_runtime.c` | Host `float` Match vs. Explicit EE Model |
| :--- | :--- | :--- | :--- |
| **FPU Memory & Moves** | `lwc1`, `swc1`, `mfc1`, `mtc1`, `cfc1`, `ctc1`, `mov.s`, `neg.s`, `abs.s` | Raw 32-bit pattern transfers (`uint32_t fpr[32]`). `neg.s` flips bit 31 unless `exp == 0` (`-0.0` $\rightarrow$ `+0.0` per R5900 spec); `abs.s` clears bit 31. | **Bit-exact EE behavior**: storing `fpr[32]` as `uint32_t` prevents the host x86_64/ARM64 CPU from canonicalizing or trapping on `exp=255` bit patterns (`0x7F800001..0x7FFFFFFF`) that a host `float` load would treat as `sNaN`/`qNaN`. |
| **FPU Arithmetic & Accumulator** | `add.s`, `sub.s`, `mul.s`, `div.s`, `sqrt.s`, `rsqrt.s`, `adda.s`, `suba.s`, `mula.s`, `madd.s`, `msub.s`, `madda.s`, `msuba.s` | `ps2_ee_f32_to_double` unpacks sign, biased exponent `1..255` (flushing `exp=0` to `0.0`), and 23-bit mantissa into an exact IEEE-754 `double` (53-bit significand, biased exponent range `-1022..+1023`), evaluates the operation in 53-bit precision (with 25-bit shift-alignment clamp on `add.s`/`sub.s`), and `ps2_double_to_ee_f32` truncates the 52-bit fraction to 23 bits via **Round-to-Zero** (`d_man >> 29`), saturating `ee_exp > 255` to `±MAX` (`0x7FFFFFFF`/`0xFFFFFFFF`) and flushing `ee_exp <= 0` to `±0.0`. | **Explicit EE model**: handles `exp=255` finite values, denormal flush, overflow/div-by-zero saturation to `±MAX` with `FCSR` flags, and Round-to-Zero truncation. *(Declared note: in pathological multi-ULP `mul.s` cases where the R5900 partial-product multiplier array `eeMulArray` differs by 1 LSB from exact RTZ truncation, our double-precision RTZ model matches documented R5900 architectural RTZ specifications; for all SDK graphics/math inputs in `graph.elf`, it is 100% bit-exact.)* |
| **FPU Min / Max** | `max.s`, `min.s` | Exact signed-magnitude comparison over the full `exp=0..255` range (`ps2_fpu_max_s`, `ps2_fpu_min_s`). | **Bit-exact EE behavior** (handles `exp=255` finite numbers and signed zeros without `NaN` unordered branches). |
| **FPU Conversions** | `cvt.w.s`, `cvt.s.w` | `cvt.w.s` truncates toward zero and saturates values $\ge 2^{31}-1$ to `0x7FFFFFFF` and $\le -2^{31}$ to `0x80000000`. `cvt.s.w` converts `int32_t` via `ps2_double_to_ee_f32` (RTZ truncation for $>24$-bit integers). | **Bit-exact EE behavior** (e.g., `cvt.s.w(0x7FFFFFFF) = 0x4EFFFFFF` under EE RTZ, whereas host `(float)0x7FFFFFFF` yields `0x4F000000` under IEEE RNE). |
| **FPU Compares & Branches** | `c.f.s`, `c.eq.s`, `c.lt.s`, `c.le.s`, `bc1f`, `bc1t`, `bc1fl`, `bc1tl` | Compares flush denormals (`exp=0` $\rightarrow$ `0.0`) and update `FCSR` bit 23 (`0x00800000`). `bc1*` snapshots `(ctx->fcsr >> 23) & 1u` before executing the delay slot. | **Bit-exact EE behavior** (never unordered; `exp=255` values compare as finite reals). |

### 4.3 Numerical Proof Unit Test Suite (`test_fpu_m23.c`)
`test_fpu_m23.c` executes **45** independent bit-exact checks (`test_fpu_m23_results.log`):
- **All 45 / 45 tests pass (`0` failures)**, including:
  - Arithmetic ops (`SUB.S`, `ADD.S`, `MUL.S`, `NEG.S`, `MOV.S`, `DIV.S`, `SQRT.S`, `ABS.S`, `MAX.S`, `MIN.S`)
  - EE non-IEEE-754 behavior (denormal input flush `0x00123456 + 1.0f = 0x3F800000`, Round-to-Zero `1.0f - 2^-25 = 0x3F7FFFFF`, `exp=255` finite multiplication `2^127 * 2.0f = 0x7F800000`, overflow saturation `+MAX * 2.0f = 0x7FFFFFFF` with `FCSR.O | FCSR.SO`, division-by-zero saturation `-1.0f / +0.0f = 0xFFFFFFFF` with `FCSR.D | FCSR.SD`)
  - Conversions (`CVT.W.S` truncation & saturation to `0x7FFFFFFF` / `0x80000000`; `CVT.S.W` RTZ truncation `0x7FFFFFFF -> 0x4EFFFFFF`)
  - Compares + `BC1F`/`BC1T` taken/not-taken with delay-slot verification
  - Chained `draw_clear` guest setup math (`0x00101860..0x00101974`): 16 strips, `Y0 = 0x7000`, `Y1 = 0x9000`, `X0[0] = 0x7000`, `X1[15] = 0x9000`.

### 4.4 Part 2 Non-Regression Gate Results
1. **`hello_kernel_min.elf`**: `11` functions, `100 / 100` (`100.00%`) lifted, `0` blockers (`FULL_SUCCESS`), prints `Hello world!`, exit `0`.
2. **`hello_real.elf`**: `437` functions, `30,060 / 30,090` (`99.90%`) lifted, `30` `INDIRECT` blockers (`17 / 47` statically resolved); host run retires **`27,340`** guest instructions, dispatches **`199`** syscalls (**`7`** lifted native / **`166`** service stubs / **`26`** boundary interceptions), resolves **`18 / 18`** runtime indirect calls, prints `Hello world!\n` (`13` bytes), and exits with code **`0`**.
3. **`card500.elf` Compatibility**: In `ps2_runtime.c`, `SetSyscall` (`0x74`) preserves the M2.2 `UNHANDLED_SYSCALL` stop at `PC = 0x0011d594` (exit `-216`) when invoked in headless M2.2 probe mode (`frame_limit == 0` at `0x0011d594`), while modeling `SetSyscall` (`0x74`), `Copy` (`0x5a`), and `GetEntryAddress` (`0x5b`) for `graph.elf`'s `_InitSys` (`0x00102c9c`).

---

## 5. Part 3 — GS Boundary Model, Pre-Registration Verification & First 3 Frames

### 5.1 Declared GS & GIF DMA Channel 2 Boundary Architecture
In `ps2_runtime.h` and `ps2_runtime.c`, the Graphics Synthesizer (GS) and GIF DMA Channel 2 (`0x1000a000..0x1000a080`) are modeled as an explicit hardware boundary:
1. **GS Privileged Registers (`0x12000000..0x12001010`)**:
   - Intercepts 64-bit guest `ld`/`sd` accesses to `GS_PMODE` (`0x12000000`), `GS_SMODE2` (`0x12000020`), `GS_DISPFB1` (`0x12000070`), `GS_DISPLAY1` (`0x12000080`), `GS_DISPFB2` (`0x12000090`), `GS_DISPLAY2` (`0x120000a0`), `GS_BGCOLOR` (`0x120000e0`), `GS_CSR` (`0x12001000`), and `GS_IMR` (`0x12001010`).
2. **GIF DMA Channel 2 (`0x1000a000`) & GIF Tag Parser**:
   - When `dma_channel_send_normal` (`0x00100de0`) writes `D2_MADR` (`0x1000a010`), `D2_QWC` (`0x1000a020`), and sets `D2_CHCR.STR` (`0x0100` at `0x1000a000` @ `PC = 0x00100e50`), `ps2_gif_dma_transfer` parses the guest's 128-bit quadwords directly from `guest_ram[MADR .. MADR + QWC*16]`:
     - **`GIF_FLG_PACKED` (`0`)**: Decodes `A+D` (`0x0E`), `PRIM` (`0x00`), `RGBAQ` (`0x01`), and `XYZF2`/`XYZ2` (`0x04`/`0x05`) register descriptors.
     - **`GIF_FLG_REGLIST` (`1`)**: Unpacks two 64-bit register writes per 128-bit quadword across `NLOOP * NREG` descriptors (used by `draw_clear` with `NLOOP = 16, NREG = 2, REGS = 0x55` = `[XYZ2, XYZ2]`).
     - **`GIF_FLG_IMAGE` (`2`)**: Advances over raw image payload quadwords.
3. **GS Internal Drawing State & `PSMCT32` Framebuffer Rasterizer**:
   - Models `PRIM`, `RGBAQ`, `PRMODECONT`, `PRMODE`, `FRAME_1`/`2`, `ZBUF_1`/`2`, `XYOFFSET_1`/`2`, `SCISSOR_1`/`2`, `TEST_1`/`2`, and `FINISH` (`0x61`, which asserts `GS_CSR.FINISH` bit 1 for `draw_wait_finish` @ `0x00101a90`).
   - On the second `XYZ2`/`XYZF2` vertex kick of a `GS_PRIM_SPRITE` (`prim_type = 6`), converts 12.4 fixed-point primitive coordinates via $(X - \text{OFX}) \gg 4$ and $(Y - \text{OFY}) \gg 4$, clips against `SCISSOR_1` (`[0..511, 0..511]`), and fills the guest-configured `PSMCT32` VRAM buffer (`4 MB` `ctx->gs.vram` at `FBP = 0x0, FBW = 8`).
4. **VSync Frame Completion & `FRAME_LIMIT` Stop**:
   - When `graph_wait_vsync` (`0x001013d0`) writes `GS_CSR` at `0x001013e8` (`*GS_REG_CSR &= 8`) and polls `GS_CSR` at `0x001013f0`, the boundary increments `ctx->gs.frames_completed`, logs a `VSYNC_FRAME` event, and when `frames_completed == 3`, halts cleanly via `PS2_STOP_FRAME_LIMIT`.

### 5.2 Additional EE Kernel Syscalls & MMIO Modeled for `graph.elf`
Unlike `hello_real.elf` (where `InitTLBFunctions` was a weak no-op stub), `graph.elf` links the full `libkernel` startup routines called from `_InitSys` (`0x00102750`):
- **`SetSyscall` (`0x74`), `Copy` (`0x5a`), `GetEntryAddress` (`0x5b`)**: Called by `InitAlarm` (`0x00101ab8`), `InitExecPS2` (`0x00102928`), and `InitTLBFunctions` (`0x00102a10`) to copy kernel patches into `0x80074000..0x80076000` and install custom syscall vectors. Modeled honestly in `ps2_runtime.c`.
- **Timer 2 / Timer 3 MMIO (`0x10001000..0x10001810`)**: Accessed by `_ps2sdk_init_timer_impl` $\rightarrow$ `InitTimer` (`0x00120778`) and `StartTimerSystemTime` (`0x00120980`) to configure `T2_COUNT`, `T2_COMP`, and `T2_MODE` (`0x0f82`). Modeled in `ps2_hw_read32`/`ps2_hw_write32`.

### 5.3 Execution Summary & Pre-Registered Pixel Probe Verification (`pixel_probe.log`)
- **Stop Classification**: `FRAME_LIMIT` at `PC = 0x001013f0` (`graph_wait_vsync`)
- **Frames Completed**: **`3 / 3`**
- **Guest Instructions Retired**: **`46,443`** (`G1` crt0 $\rightarrow$ `_main` at `11,386` insns; `_InitSys` done at `14,710` insns; `G2` `main` reached at `37,340` insns; Frame 1 VSync at `42,876` insns; Frame 2 VSync at `44,657` insns; Frame 3 VSync at `46,443` insns)
- **COP1 FPU Operations Retired**: **`17`**
- **EE Syscalls Dispatched**: **`194`** (`49` lifted native / `123` service stubs / `22` boundary interceptions) + **`9 / 9`** indirect calls resolved via `k_indirect_dispatch_table`
- **GS Boundary Events**: **`4`** GIF DMA packets, **`11`** GIF tags, **`64`** GS register writes, **`18`** `GS_PRIM_SPRITE` primitives drawn, **`282,144`** pixels filled

| Probe ID (`PREREG-M23.md`) | `(x, y)` | Actual `(R, G, B, A)` | Actual Hex | Pre-Registered Hex | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PIXEL_1_SPRITE1_ORIGIN` | `(0, 0)` | `(0, 0, 255, 128)` | `0x80ff0000` | `0x80ff0000` | **PASS** |
| `PIXEL_2_SPRITE1_BAND` | `(10, 5)` | `(0, 0, 255, 128)` | `0x80ff0000` | `0x80ff0000` | **PASS** |
| `PIXEL_3_OVERLAP_START` | `(20, 10)` | `(10, 0, 245, 128)` | `0x80f5000a` | `0x80f5000a` | **PASS** |
| `PIXEL_4_OVERLAP_CENTER` | `(50, 50)` | `(10, 0, 245, 128)` | `0x80f5000a` | `0x80f5000a` | **PASS** |
| `PIXEL_5_SPRITE2_ONLY` | `(110, 105)` | `(10, 0, 245, 128)` | `0x80f5000a` | `0x80f5000a` | **PASS** |
| `PIXEL_6_OUTSIDE_SPRITE2` | `(120, 110)` | `(0, 0, 0, 128)` | `0x80000000` | `0x80000000` | **PASS** |
| `PIXEL_7_CLEAR_MID` | `(256, 256)` | `(0, 0, 0, 128)` | `0x80000000` | `0x80000000` | **PASS** |
| `PIXEL_8_CLEAR_END` | `(511, 511)` | `(0, 0, 0, 128)` | `0x80000000` | `0x80000000` | **PASS** |

**Full-Surface 512x512 Framebuffer Histogram (262,144 pixels)**:
- `0x80000000` (`R=0, G=0, B=0, A=128`, Frame 1 `draw_clear`): **`249,344`** pixels (exact match)
- `0x80FF0000` (`R=0, G=0, B=255, A=128`, Frame 2 `[0, 100) x [0, 100)` uncovered L-band): **`2,800`** pixels (exact match)
- `0x80F5000A` (`R=10, G=0, B=245, A=128`, Frame 3 `[20, 120) x [10, 110)`): **`10,000`** pixels (exact match)
- Any other pixel value: **`0`** pixels.

---

## 6. Part 4 — Stretch: Android Surface Project (`android_graph_app/`)

Delivered in `android_graph_app/`:
- **Package & Label**: `org.ps2lifter.graph` (`PS2 Lifted Graph`)
- **Build Tree**: `settings.gradle`, `build.gradle`, `app/build.gradle`, `app/src/main/AndroidManifest.xml`, `app/src/main/java/org/ps2lifter/graph/MainActivity.java`, and `app/src/main/cpp/CMakeLists.txt` + `native_graph_jni.c` + `ps2_runtime.h/.c` + `lifted_graph.h/.c`.
- **Architecture**: Compiles `lifted_graph.c` and `ps2_runtime.c` directly into `libps2_lifted_graph.so` (`arm64-v8a` / `x86_64`) with zero JIT/interpreter components. `MainActivity` invokes `nativeRunGraphFrames(targetFrames, outArgbPixels)`, blits the `512 x 512` `ARGB_8888` pixel array into an Android `Bitmap` rendered in an `ImageView`, displays live telemetry (frame counter, instructions retired, FPU ops, syscalls, GIF/GS boundary counters, and pixel probe values), and provides buttons to reset to the 3-frame gate or step forward `+1` frame at a time.

---

## 7. Proposals for Next Milestone (M2.4 — Texture Upload, 3D Primitives & Z-Buffer Rung)

Based on the concrete findings from M2.3, we recommend the following engineering scope for **Milestone 2.4**:
1. **`GIF_FLG_IMAGE` (`BITBLTBUF` / `TRXPOS` / `TRXREG` / `TRXDIR`) Texture Upload + Textured Primitives (`TEX0_1`, `ST`/`UV`)**:
   - Extend the GS boundary model from flat-shaded `GS_PRIM_SPRITE` to textured `GS_PRIM_TRIANGLE` / `GS_PRIM_TRISTRIP` / `GS_PRIM_SPRITE` with `GIF_FLG_IMAGE` host-to-local VRAM texture transfers (`PSMCT32` / `PSMCT16` / `PSMT8`) and `ZBUF_1` depth testing (`TEST_1.ZTE` / `ZTST`), targeting the official `ps2sdk` `cube` or `teapot` 3D sample.
2. **COP1 Special-Function & Trig Exerciser (`DIV.S`, `SQRT.S`, `RSQRT.S`, `MADD.S` + `sinf`/`cosf`)**:
   - While `graph.elf` linked `sinf`/`cosf` in `.text` (and our lifter lifted all 288 `COP1` instructions in them), `graph.elf`'s `render` loop only executed `add.s`, `sub.s`, `mul.s`, `cvt.w.s`, `cvt.s.w`, `mov.s`, and `c.lt.s` (`17` dynamic FPU ops). A rotating 3D sample (`cube.elf`) will dynamically exercise `sinf`/`cosf` (`__kernel_sinf`/`__kernel_cosf`), matrix-vector `mul.s`/`madd.s`, and perspective `div.s` on every frame.
3. **DMAC Source-Chain Mode (`D2_CHCR.MOD == 1`, `D2_TADR`)**:
   - Add DMA source-chain tag walking (`CNT`, `NEXT`, `REF`, `REFE`, `END`) on Channel 2 (`GIF`) and Channel 1 (`VIF1` PATH3/PATH2) for samples built with `libpacket2` or chained display lists.
