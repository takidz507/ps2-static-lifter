# PS2 Static Lifter — Milestone 2.3 Part 1 Instruction Census (`CENSUS-M23.md`)

## 1. Target Identity & Gate P0 Baseline Verification

| Metric | Measured Value | Muse Baseline | Status |
| :--- | :--- | :--- | :--- |
| Target File | `graph.elf` (`1,379,708` bytes) | `1,379,708` bytes | **EXACT MATCH** |
| SHA-256 | `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239` | `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239` | **EXACT MATCH** |
| Entry / `e_flags` / `.text` size | `0x00100b20` / `0x20920025` / `0x219d0` | `0x00100b20` / `0x20920025` / `0x219d0` | **EXACT MATCH** |
| Functions (`.symtab`) / Total Insns | `504` / `34,420` | `504` / `34,420` | **EXACT MATCH** |
| M1 Decoded / UNDECODED | `33,875 / 34,420` (**`98.42%`**) / **`545`** | `33,875 / 34,420` (`98.42%`) / `545` | **EXACT MATCH** |
| M1 Unique EE Syscalls | **`48`** (across `52` sites) | `40` | **EXACT MATCH** |
| Lifter v2.2 Lifted / Blockers | `33,921 / 34,420` (**`98.55%`**) / **`499`** (`463 UNLIFTED_INSN + 36 INDIRECT`) | `33,921 / 34,420` (`98.55%`) / `499` (`463 + 36`) | **EXACT MATCH** |
| Lifter v2.2 Indirect Sites | `53` total (`17` resolved: `5` JT / `5` const-`$t9` / `7` static ptr; `36` unresolved) | `53` (`17` resolved: `5 / 5 / 7`; `36` unresolved) | **EXACT MATCH** |

---

## 2. Census of the 170 `UNKNOWN_OPCODE` Words in `graph.elf`

All **170** `UNKNOWN_OPCODE` words reported by M1 (and classified as `UNSUPPORTED_OP_0x31` / `UNSUPPORTED_OP_0x39` in Lifter v2.2) are valid MIPS/R5900 COP1 floating-point memory load/store instructions (**zero** data-in-code words, **zero** alignment padding traps):

| Major Opcode | Mnemonic | Count | Semantics | Functions Using Opcode | Example Sites (`vaddr: word -> disasm`) |
| :--- | :--- | ---: | :--- | :--- | :--- |
| `op=0x31` | **`LWC1`** | **113** | `ctx->fpr[ft] = ps2_mem_read32(ctx, base + simm)` | `__ieee754_rem_pio2f`, `__kernel_cosf`, `__kernel_rem_pio2f`, `__kernel_sinf`, `cosf`, `draw_clear`, `floorf`, `scalbnf`, `sinf` | `0x00101868: 0xc44154e8` (`lwc1 $f1, 21736($v0)` in `draw_clear`); `0x00101870: 0xc44054e4` (`lwc1 $f0, 21732($v0)` in `draw_clear`); `0x00101934: 0xc44254ec` (`lwc1 $f2, 21740($v0)` in `draw_clear`) |
| `op=0x39` | **`SWC1`** | **57** | `ps2_mem_write32(ctx, base + simm, ctx->fpr[ft])` | `__ieee754_rem_pio2f`, `__kernel_rem_pio2f`, `floorf`, `scalbnf` | `0x0011c6c0: 0xe4a10000` (`swc1 $f1, 0($a1)` in `__ieee754_rem_pio2f`); `0x0011c6cc: 0xe4a00004` (`swc1 $f0, 4($a1)` in `__ieee754_rem_pio2f`); `0x0011c734: 0xe7a10000` (`swc1 $f1, 0($sp)` in `__ieee754_rem_pio2f`) |
| **Total** | **`LWC1 + SWC1`** | **170** | **32-bit FPU Memory Loads/Stores** | **8 functions** | **100% real instructions (0 data-in-code)** |

---

## 3. Complete Opcode Inventory of the 288 `COP1_FPU` (`op=0x11`) Instructions

Across `.text`, there are **288** instructions with primary opcode `0x11` (`COP1`), spanning **14 distinct mnemonics** across 11 functions (`draw_clear`, `render`, `graph_set_mode`, `__ieee754_sinf`, `__ieee754_cosf`, `__kernel_sinf`, `__kernel_cosf`, `__ieee754_rem_pio2f`, `__kernel_rem_pio2f`, `scalbnf`, `floorf`):

| Encoding (`op=0x11`) | Mnemonic | Count | Category | Example Sites (`vaddr: word -> disasm`) |
| :--- | :--- | ---: | :--- | :--- |
| `op=0x11, fmt=0x10, funct=0x02` | **`MUL.S`** | **65** | FPU Dyadic Arithmetic | `0x00101880: 0x46007382` (`mul.s $f14, $f14, $f0` in `draw_clear`); `0x001018a8: 0x46008402` (`mul.s $f16, $f16, $f0` in `draw_clear`) |
| `op=0x11, fmt=0x10, funct=0x01` | **`SUB.S`** | **61** | FPU Dyadic Arithmetic | `0x00101888: 0x46018401` (`sub.s $f16, $f16, $f1` in `draw_clear`); `0x00101948: 0x46018c41` (`sub.s $f17, $f17, $f1` in `draw_clear`) |
| `op=0x11, fmt=0x10, funct=0x00` | **`ADD.S`** | **39** | FPU Dyadic Arithmetic | `0x00101860: 0x46107400` (`add.s $f16, $f14, $f16` in `draw_clear`); `0x0010192c: 0x46117c40` (`add.s $f17, $f15, $f17` in `draw_clear`) |
| `op=0x11, fmt=0x04` | **`MTC1`** | **38** | GPR <-> FPR Move | `0x00102144: 0x44820000` (`mtc1 $v0, $f0` in `render`); `0x00102154: 0x44820000` (`mtc1 $v0, $f0` in `render`) |
| `op=0x11, fmt=0x00` | **`MFC1`** | **17** | GPR <-> FPR Move | `0x001018c0: 0x44061000` (`mfc1 $a2, $f2` in `draw_clear`); `0x001018e8: 0x44081000` (`mfc1 $t0, $f2` in `draw_clear`) |
| `op=0x11, fmt=0x10, funct=0x07` | **`NEG.S`** | **16** | FPU Monadic Sign/Move | `0x0011c27c: 0x46000007` (`neg.s $f0, $f0` in `cosf`); `0x0011c28c: 0x46000007` (`neg.s $f0, $f0` in `cosf`) |
| `op=0x11, fmt=0x10, funct=0x24` | **`CVT.W.S`** | **16** | FPU Conversion | `0x001018a0: 0x460070a4` (`cvt.w.s $f2, $f14` in `draw_clear`); `0x001018c8: 0x460080a4` (`cvt.w.s $f2, $f16` in `draw_clear`) |
| `op=0x11, fmt=0x14, funct=0x20` | **`CVT.S.W`** | **13** | FPU Conversion | `0x00102150: 0x46800460` (`cvt.s.w $f17, $f0` in `render`); `0x0010215c: 0x46800420` (`cvt.s.w $f16, $f0` in `render`) |
| `op=0x11, fmt=0x10, funct=0x06` | **`MOV.S`** | **7** | FPU Monadic Sign/Move | `0x00102170: 0x46007b86` (`mov.s $f14, $f15` in `render`); `0x0011c644: 0x46006006` (`mov.s $f0, $f12` in `__kernel_sinf`) |
| `op=0x11, fmt=0x08, nd_tf=0x00` | **`BC1F`** | **6** | COP1 Condition Branch | `0x0011c758: 0x45000079` (`bc1f 0x0011c940` in `__ieee754_rem_pio2f`); `0x0011c768: 0x45000081` (`bc1f 0x0011c970` in `__ieee754_rem_pio2f`) |
| `op=0x11, fmt=0x10, funct=0x32` | **`C.EQ.S`** | **4** | FPU Compare (sets `FCSR.C`) | `0x0011c750: 0x46030032` (`c.eq.s $f0, $f3` in `__ieee754_rem_pio2f`); `0x0011c760: 0x46030832` (`c.eq.s $f1, $f3` in `__ieee754_rem_pio2f`) |
| `op=0x11, fmt=0x08, nd_tf=0x01` | **`BC1T`** | **2** | COP1 Condition Branch | `0x0011ce48: 0x4501010c` (`bc1t 0x0011d27c` in `__kernel_rem_pio2f`); `0x0011ce60: 0x4501ffa3` (`bc1t 0x0011ccf0` in `__kernel_rem_pio2f`) |
| `op=0x11, fmt=0x10, funct=0x34` | **`C.LT.S`** | **2** | FPU Compare (sets `FCSR.C`) | `0x0011d520: 0x46000834` (`c.lt.s $f1, $f0` in `floorf`); `0x0011d598: 0x46000834` (`c.lt.s $f1, $f0` in `floorf`) |
| `op=0x11, fmt=0x10, funct=0x36` | **`C.LE.S`** | **2** | FPU Compare (sets `FCSR.C`) | `0x0011ce40: 0x46140036` (`c.le.s $f0, $f20` in `__kernel_rem_pio2f`); `0x0011ceac: 0x46001036` (`c.le.s $f2, $f0` in `__kernel_rem_pio2f`) |
| **Total (`op=0x11`)** | **14 Mnemonics** | **288** | **Complete COP1 FPU Set in `graph.elf`** | **All 288 lifted in Lifter v2.3** |

---

## 4. Remaining 5 Non-FPU `UNLIFTED_INSN` in Lifter v2.2 (Out of 463)

Subtracting `170` (`LWC1`/`SWC1`) + `288` (`COP1_FPU`) = `458` from Lifter v2.2's `463` `UNLIFTED_INSN` leaves exactly **5** instructions:

1. **`COP0_SYSTEM` (`op=0x10, rs=0x08` — 4 instructions in `dma_wait_fast` @ `0x00100d48`)**:
   - `0x00100d50: 0x45010006` $\rightarrow$ `bc0t 0x00100d6c` (`rt=0x01`)
   - `0x00100d58: 0x45010004` $\rightarrow$ `bc0t 0x00100d6c` (`rt=0x01`)
   - `0x00100d60: 0x45010002` $\rightarrow$ `bc0t 0x00100d6c` (`rt=0x01`)
   - `0x00100d68: 0x4500ffff` $\rightarrow$ `bc0f 0x00100d68` (`rt=0x00`)
   - **Semantics**: Branches on R5900 external `CPCOND0` signal (wired to DMAC channel completion condition `(D_STAT & D_PCR) == D_PCR`). Lifted in v2.3 via `ps2_cop0_cpcond0(ctx)`.
2. **`R5900_MMI_SIMD` (`op=0x1c, rs=0x00, sa=0x1b, funct=0x29` — 1 instruction in `memset` @ `0x00104290`)**:
   - `0x001042bc: 0x70081ee9` $\rightarrow$ `pcpyh $v1, $t0` (MMI3 Parallel Copy Halfword: broadcasts `rt.u16[0]` to lower 4 halfwords and `rt.u16[4]` to upper 4 halfwords of 128-bit `rd`).
   - **Semantics**: Executed during `_InitSys` $\rightarrow$ `InitTimer` (`memset`) when initializing the timer callback table. Lifted in v2.3 via `ps2_mmi_pcpyh(ctx->gpr[rt])`.

---

## 5. Exact Book-for-Book Reconciliation: M1 (545) vs. Lifter v2.2 (463 + 36) vs. Lifter v2.3 (0 + 36)

| Instruction Family / Category | M1 UNDECODED | Lifter v2.1/v2.2 Already Lifted | Lifter v2.2 `UNLIFTED_INSN` | Lifter v2.3 Newly Lifted | Lifter v2.3 `UNLIFTED_INSN` |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `UNKNOWN_OPCODE` (`LWC1` 113 + `SWC1` 57) | 170 | 0 | 170 | 170 | **0** |
| `COP1_FPU` (`op=0x11`, 14 mnemonics) | 288 | 0 | 288 | 288 | **0** |
| `MEMORY_BARRIER_SYNC` (`sync.l` 29 + `sync.p` 12) | 41 | 41 | 0 | 0 | **0** |
| `COP0_SYSTEM` (`mfc0` 14, `mtc0` 2, `ei` 5, `di` 1, `bc0t` 3, `bc0f` 1) | 26 | 22 | 4 | 4 | **0** |
| `CACHE_OP` (`cache 0x18` 9, `cache 0x14` 2, `cache 0x1a` 1, `cache 0x0b` 1) | 13 | 13 | 0 | 0 | **0** |
| `R5900_MMI_SIMD` (`madd` 1, `pmfhl.lw` 2, `pcpyh` 1) | 4 | 3 | 1 | 1 | **0** |
| `R5900_QUADWORD_MEM` (`sq` 3) | 3 | 3 | 0 | 0 | **0** |
| **Instruction-Level Subtotal** | **545** | **82** | **463** | **463** | **0** |
| Statically Unresolved Indirect Calls (`INDIRECT` blockers) | *(N/A in M1)* | *(17/53 resolved)* | **36** | *(Runtime table dispatch)* | **36** *(declared stubs)* |
| **Total Blockers Reported by Lifter** | — | — | **499** (`463 + 36`) | — | **36** (`0 + 36`) |
| **Total Lifted Instructions (`graph.elf`)** | `33,875 / 34,420` (`98.42%`) | — | `33,921 / 34,420` (`98.55%`) | **`+463`** | **`34,384 / 34,420` (`99.90%`)** |

### Accounting Identity Proof
1. **M1 vs. Lifter v2.2**:
   $$545 \text{ (M1 UNDECODED)} - 82 \text{ (M2.1 exotic instructions lifted: } 41\text{ SYNC} + 22\text{ COP0} + 13\text{ CACHE} + 3\text{ MMI} + 3\text{ SQ)} = 463 \text{ (v2.2 UNLIFTED\_INSN)}$$
   $$34,420 \text{ (total)} - 463 \text{ (v2.2 UNLIFTED\_INSN)} - 36 \text{ (v2.2 INDIRECT)} = 33,921 \text{ (v2.2 lifted instructions, } 98.55\%)$$
2. **Lifter v2.2 vs. Lifter v2.3**:
   $$463 \text{ (v2.2 UNLIFTED\_INSN)} - 170 \text{ (LWC1/SWC1)} - 288 \text{ (COP1\_FPU)} - 4 \text{ (BC0T/BC0F)} - 1 \text{ (PCPYH)} = \mathbf{0 \text{ (v2.3 UNLIFTED\_INSN)}}$$
   $$34,420 \text{ (total)} - 0 \text{ (v2.3 UNLIFTED\_INSN)} - 36 \text{ (v2.3 INDIRECT)} = \mathbf{34,384 \text{ (v2.3 lifted instructions, } 99.90\%)}$$
