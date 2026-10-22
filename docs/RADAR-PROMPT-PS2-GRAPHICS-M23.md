# RADAR TASK — PS2 Static Lifter M2.3: The Graphics Rung
## (FPU completion + GS boundary model + first drawn frames)

You are continuing the PS2 Static Lifter project. Previous milestones, all
independently audited and reproduced by Muse: M1 (analyzer), M2 (synthetic
lift + native run), M2.1 (lifter hardening on the real ELF), M2.2 (first real
end-to-end execution of `hello_real.elf`: 27,340 guest instructions,
entry → crt0 → newlib stdio → FILEIO boundary → clean `Exit(0)`).

This milestone takes the ladder's **graphics rung**: a real GS program must
execute from lifted code and produce **actual pixels** in a modeled
framebuffer — on the host first, and (stretch) on Android.

---

## 1. Target and measured baseline (reproduce FIRST, exactly)

Target: `graph.elf` — the official ps2sdk GS graphics sample (`graph.c`,
linked against libpacket/libdma/libgraph/libdraw/libkernel/libcglue), built
by Muse with the official ps2dev toolchain (ee-gcc 15.2.0) from the SDK's
own sample sources. No strip. Muse ferries the file with this prompt.

Integrity:
- File size: 1,379,708 bytes
- SHA-256: `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239`
- Entry: `0x00100b20`, e_flags `0x20920025`, `.text` size `0x219d0`
- Functions (.symtab): 504 — Total instructions: 34,420

Muse's measured baseline with the **current, unmodified** tools
(M1 analyzer + lifter v2.2 + M2.2 runtime):

- M1: Decoded 33,875 / 34,420 (**98.42%**); UNDECODED **545**, census:
  `COP1_FPU 288, UNKNOWN_OPCODE 170, MEMORY_BARRIER_SYNC 41,
  COP0_SYSTEM 26, CACHE_OP 13, R5900_MMI_SIMD 4, R5900_QUADWORD_MEM 3`.
  EE syscalls detected: 40.
- Lifter v2.2: 504/504 functions lifted; **33,921 / 34,420 (98.55%)**;
  blockers **499** = `UNLIFTED_INSN 463` + `INDIRECT 36`
  (53 indirect sites, 17 resolved: 5 jump tables / 5 const-$t9 / 7 static
  data pointers). Generated C (~7.4 MB) compiles clean on the host
  (`gcc -std=c11 -O1`, exit 0). **Not yet executed.**

**Gate P0:** Before changing anything, reproduce this baseline with the
unmodified M2.2 package tools and confirm every figure. If any figure
differs, STOP and report the discrepancy — do not proceed on a shifted
baseline.

## 2. Standing red lines (unchanged, non-negotiable)

1. **Legal inputs only.** This target and the regression targets below are
   the only inputs. No commercial game files, no BIOS, no downloaded ISOs —
   in any form, for any sub-step. A step that seems to need one is a stop
   condition, not a detour.
2. **No manual edits to generated C.** If the output is wrong, the lifter
   changes and the file is regenerated. A hand-patched generated file voids
   the milestone.
3. **Nothing is skipped silently.** Every undecoded/unlifted instruction and
   every unresolved call is counted, classified, and reported.
4. **No host cheating at boundaries.** The framebuffer must be filled by the
   **guest's own** GS register writes and GIF packet stream, interpreted by
   your GS boundary model. Pre-drawing the expected picture, special-casing
   this sample's constants in the model, or copying pixels from any external
   renderer voids the milestone.
5. **Reproducibility.** Every claimed number must be re-derivable by Muse
   re-running your delivered scripts on the delivered inputs.

## 3. Part 1 — Census before lifting

Produce a complete census of the 545 M1-UNDECODED and the 463
lifter-UNLIFTED instructions in `graph.elf`:

- For the 170 `UNKNOWN_OPCODE`: identify each distinct encoding — name the
  instruction (or state precisely why it is data-in-code / alignment / a
  decoder-table gap). Group by encoding pattern, with counts and example
  addresses.
- For the 288 `COP1_FPU`: the full opcode inventory actually present
  (e.g. ADD.S/SUB.S/MUL.S/DIV.S/SQRT.S, MOV.S, CVT.*, C.* compares, MADD*,
  BC1* branches), with counts.
- Reconcile the two tools' books: explain exactly how M1's 545 and the
  lifter's 463 + 36 relate (the 2.1 exotic families already lifted, etc.).

Deliverable: `CENSUS-M23.md` + machine-readable `census_m23.json`.

## 4. Part 2 — Lift the FPU (and the identified unknowns)

Extend the lifter to model the inventoried COP1 instructions, plus any
UNKNOWN encodings Part 1 proved to be real instructions:

- **EE FPU semantics, not host-float wishful thinking.** The R5900 FPU is
  single-precision and *not* fully IEEE-754 (denormal handling, rounding and
  exception behavior differ). Model the documented EE behavior; where the
  host's `float` math provably matches, say so per-opcode; where it does
  not, implement the EE behavior explicitly. Document every deviation
  decision in the report.
- The FPU register file, FCSR condition bit, and BC1 branch behavior
  (including delay slots) join the existing context model.
- **Numerical proof, per opcode family:** unit tests whose expected outputs
  are derived independently of your implementation (documented EE semantics
  / hand-computed vectors), covering at minimum: arithmetic ops present,
  conversions present, compares + BC1 taken/not-taken, and one chained
  sequence copied from the guest's own draw-setup math. Bit-exact pass
  required. (This is the same standard as the M2.1 `__muldi3` check.)
- Success metric: UNLIFTED_INSN on `graph.elf` driven to **zero**, or every
  remaining one individually named with the reason it cannot be lifted in
  this milestone. INDIRECT blockers may remain only as declared stubs,
  counted as before.

Regression gates for Part 2 (all must still pass, bit-identical):
- Synthetic `hello_kernel_min.elf`: 100/100 lifted, runs, `Hello world!`,
  exit 0.
- `hello_real.elf`: 30,060/30,090 lifted; host run = 27,340 guest
  instructions, 199 syscalls (7 lifted / 166 service / 26 boundary), 18/18
  indirect resolved, `Hello world!`, exit 0.
- `card500.elf` (500 Card Game): 50,286/52,294 lifted; host probe run =
  116,220 instructions, stop `UNHANDLED_SYSCALL` @ `0x0011d594`
  (syscall 0x74), guest exit −216.

## 5. Part 3 — GS boundary model + first frames (host)

Extend the runtime with a **declared GS boundary**, in the same spirit as
M2.2's FILEIO boundary (guest code runs lifted; the device exists only as a
modeled boundary):

- Model the path the guest actually uses: DMA channel 2 (GIF) packet
  transfer + GS privileged registers written via the CSR/register interface
  the SDK libraries use (libgraph/libdraw path — follow the code, do not
  assume a different sample's habits). GIF tags (PACKED/REGLIST/IMAGE modes
  as encountered) are parsed; A+D register writes update GS state.
- Implement the GS state the sample needs: framebuffer configuration
  (FRAME, ZBUF, XYOFFSET, SCISSOR, PRMODE/context as used), DISPLAY/DISP FB
  registers, and a real guest-visible framebuffer memory (PSM format as
  configured by the guest — expect PSMCT32; if the guest chooses another,
  model that).
- **Pre-registration (before your first run):** read `graph.c` (public
  ps2sdk source) and publish in `PREREG-M23.md` what the frame must contain:
  the clear color the code sets, the primitive(s) it draws, ≥5 named pixel
  coordinates with their expected values *derived from the source and the
  guest's own constants*, and the expected frame structure. Sealed before
  execution — no adjusting expectations after seeing output.
- Run policy: the sample loops forever. Define a clean harness stop:
  after the guest completes **3 full frames** (frame completion = the
  guest's own frame-end/vsync path through your boundary), the harness
  stops execution with a declared `FRAME_LIMIT` outcome. A hang, a budget
  blowout, or a crash is a failed run — report it as such with the stop
  PC/reason from the runtime, as in M2.2.
- Deliverable proof: the framebuffer after frame 3, exported as an image
  (PPM or PNG) **plus** a pixel-probe log checking the ≥5 pre-registered
  pixels, **plus** the GS boundary event trace (register writes + GIF
  packets, in M2.2 trace style).
- Any EE syscall or service the run hits that the current runtime does not
  model: model it honestly (named, semantics stated) or declare it — the
  M2.2 discipline. (Note: `card500`'s SetSyscall wall is a different target's
  business; model it here only if `graph.elf` itself calls it.)

Acceptance for Part 3: 3 frames complete; pre-registered pixels match;
framebuffer image is demonstrably a product of the guest's packet stream
(trace ↔ image correspondence spot-checkable by Muse).

## 6. Part 4 — Stretch: Android surface (project only)

Only if Parts 1–3 pass: deliver an Android **project** (same pattern as M2:
Gradle/CMake tree, JNI bridge, no APK — Muse builds it) that runs the same
lifted `graph.elf` code + runtime + GS model and presents the modeled
framebuffer on screen (bitmap blit), with the frame counter and boundary
stats shown. Package `org.ps2lifter.graph`, label `PS2 Lifted Graph`.
Zero emulator/interpreter components — AOT lifted code only, as always.

## 7. Package and reporting

Deliver one ZIP (`PS2-LIFTER-M23`) with a `MANIFEST.sha256`, containing:
updated lifter + runtime sources, the one-command host build/run script,
`CENSUS-M23.md` + `census_m23.json`, `PREREG-M23.md`, FPU test sources +
results, the frame-3 framebuffer image + pixel-probe log + GS trace,
`REPORT-M23.md` (baseline reproduction, per-part results with exact
numbers, every blocker and deviation declared), and the Android project if
Part 4 was attempted.

Report format: exact figures, no adjectives doing the work of evidence.
If a gate fails, the report leads with the failure and the measured stop
point — a clean failure report outranks a decorated partial success.
