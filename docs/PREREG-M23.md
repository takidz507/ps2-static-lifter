# PS2 Static Lifter — Milestone 2.3 Pre-Registration (`PREREG-M23.md`)

**Status:** SEALED BEFORE EXECUTION  
**Target Binary:** `graph.elf` (`1,379,708` bytes, SHA-256 `4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239`, entry `0x00100b20`)  
**Source Provenance:** Official `ps2sdk` `ee/graph/samples/graph/graph.c` linked with `libpacket`, `libdma`, `libgraph`, `libdraw`, `libkernel`, and `libcglue` (built with `ee-gcc 15.2.0`).

---

## 1. Framebuffer & GS Configuration (Derived from `init_gs` @ `0x00102028` and `init_drawing_environment` @ `0x001020a8`)

By statically inspecting the disassembled machine code of `main` (`0x00121870`), `init_gs` (`0x00102028`), `init_drawing_environment` (`0x001020a8`), `draw_setup_environment` (`0x00101640`), `draw_clear` (`0x00101860`), and `render` (`0x00102100`) in `graph.elf`:

1. **Framebuffer (`framebuffer_t` @ `$sp + 24` in `init_gs` @ `0x00102028`)**:
   - `fb->width = 512` (`0x0010203c: addiu $v0, $zero, 512; sw $v0, 8($a0)`)
   - `fb->height = 512` (`0x00102048: sw $v0, 12($a0)`)
   - `fb->mask = 0` (`0x0010204c: sw $zero, 4($a0)`)
   - `fb->psm = GS_PSM_32` (`0`, i.e., `PSMCT32`, 32-bit RGBA8888, `0x00102050: sw $zero, 16($a0)`)
   - `fb->address = graph_vram_allocate(512, 512, GS_PSM_32, GRAPH_ALIGN_PAGE)` (`0x00102054: jal 0x00100be0`) $\rightarrow$ returns VRAM word address **`0x00000000`** (`FBP = 0x000`, `FBW = 512 / 64 = 8`).
2. **Z-Buffer (`zbuffer_t` @ `$sp + 0` in `init_gs` @ `0x00102028`)**:
   - Disabled (`zb->enable = 0`, `zb->address = 0`, `zb->mask = 0`, `zb->zsm = 0`, `zb->method = 0`; `ZMSK = 1` in `ZBUF_1` when `zb->enable == 0`).
3. **Display Mode (`graph_initialize` @ `0x00101090`)**:
   - Calls `graph_initialize(fb->address = 0, fb->width = 512, fb->height = 512, fb->psm = 0, 0, 0)`, which resets the GS via `GS_CSR = 0x200`, calls `SetGsCrt`, and configures `GS_PMODE`, `GS_SMODE2`, `GS_DISPFB1`, `GS_DISPLAY1`, `GS_DISPFB2`, `GS_DISPLAY2`, and `GS_BGCOLOR` via MMIO writes in `0x12000000..0x12001000`.
4. **Drawing Environment (`init_drawing_environment` @ `0x001020a8` $\rightarrow$ `draw_setup_environment` @ `0x00101640`)**:
   - Sends an 18-quadword `GIF_FLG_PACKED` (`A+D`, `REGS = 0xE`) packet via `dma_channel_send_normal(DMA_CHANNEL_GIF = 2, ...)` configuring Context 1 (`FRAME_1`, `ZBUF_1`, `PRMODECONT = 1`, `XYOFFSET_1`, `SCISSOR_1`, `TEST_1`, `CLAMP_1`, `DIMX`, `DTHE`, `COLCLAMP`, `PABE`, `FBA_1`, `ALPHA_1`, and `FINISH`):
     - **`FRAME_1` (`0x4C`)**: `FBP = 0x000`, `FBW = 8` (`512` pixels wide), `PSM = 0x00` (`PSMCT32`), `FBMSK = 0x00000000`.
     - **`XYOFFSET_1` (`0x18`)**: `OFX = 0x8000` (`2048.0`), `OFY = 0x8000` (`2048.0`) in 12.4 fixed-point.
     - **`SCISSOR_1` (`0x40`)**: `SCX0 = 0`, `SCX1 = 511`, `SCY0 = 0`, `SCY1 = 511`.

---

## 2. Per-Frame Execution & Drawing Structure (`render` @ `0x00102100`)

Inside `render(int dma_chan, framebuffer_t *fb)` (`0x00102100`):

### Frame 1 (Initial Clear Frame — Completed at `graph_wait_vsync` #1 @ `0x001021d4`)
1. **Clear Packet (`draw_clear` @ `0x00101860` + `draw_finish` @ `0x00101a60`)**:
   - Called at `0x0010219c` with `context = 0`, `x = 2048.0f - 256.0f` (relative to `2048.0f` center, i.e., `2048.0f` primitive origin), `width = 512.0f`, `height = 512.0f`, `r = 0, g = 0, b = 0`.
   - `draw_clear` emits:
     - `GIFTAG` (`PACKED`, `A+D`): sets `PRMODECONT = 0`, `PRMODE = 0x400`, `PRIM = 0x06` (`GS_PRIM_SPRITE`), and `RGBAQ` with **`R = 0, G = 0, B = 0, A = 0x80 (128), Q = 1.0f`** (`0x3f80000080000000`).
     - `GIFTAG` (`REGLIST`, `FLG = 1`, `NLOOP = 16`, `NREG = 2`, `REGS = 0x55` (`XYZ2, XYZ2`)): emits **16 vertical sprite strips**, each 32 pixels wide by 512 pixels tall (`[32*j, 32*(j+1)) x [0, 512)` for `j = 0..15`), covering the entire `512 x 512` framebuffer `[0, 512) x [0, 512)` with **`RGBA = (0, 0, 0, 128)`** (`0x80000000` in `PSMCT32`).
     - Restores `PRMODECONT = 1` and writes `FINISH` (`0x61`).
   - Waits for `FINISH` via `draw_wait_finish` (`0x001021cc`) and waits for VSync via `graph_wait_vsync` (`0x001021d4`).
   - **End of Frame 1**: All `512 x 512 = 262,144` pixels in the framebuffer are cleared to **`(R=0, G=0, B=0, A=128)`** (`0x80000000`).

### Frame 2 (Loop Iteration `k = 0`, `$s0 = 0` — Completed at `graph_wait_vsync` #2 @ `0x0010226c`)
Inside `render`, the `while (1)` loop (`0x001021dc..0x00102274`) does not re-clear the framebuffer; it draws successive moving `100 x 100` `GS_PRIM_SPRITE` rectangles onto the persistent framebuffer.
On the first iteration (`i = 0`, `$s0 = 0`):
- **Primitive**: 1 `GS_PRIM_SPRITE` (`prim_type = 6`, `FLG = PACKED`, `NLOOP = 1`, `NREG = 3`, `REGS = 0x551` = `[RGBAQ, XYZ2, XYZ2]`), followed by `draw_finish` (`A+D` write to `FINISH` `0x61`), total packet size = `5` quadwords (`80` bytes).
- **Color (`RGBAQ`)**:
  - `R = $s0 = 0` (`0x00`)
  - `G = 0` (`0x00`)
  - `B = 255 - $s0 = 255` (`0xFF`)
  - `A = 0x80` (`128`)
  - Packed `PSMCT32` word: **`0x80FF0000`** (`R=0, G=0, B=255, A=128`, pure blue).
- **Screen Coordinates (`XYZ2` #1 and `XYZ2` #2 after subtracting `XYOFFSET_1 = 0x8000`)**:
  - Vertex 0: `X0 = 2 * $s0 = 0`, `Y0 = $s0 = 0`, `Z0 = 0`
  - Vertex 1: `X1 = 2 * $s0 + 100 = 100`, `Y1 = $s0 + 100 = 100`, `Z1 = 0`
  - Fills **`[0, 100) x [0, 100)`** (`10,000` pixels) with **`(R=0, G=0, B=255, A=128)`** (`0x80FF0000`).

### Frame 3 (Loop Iteration `k = 1`, `$s0 = 10` — Completed at `graph_wait_vsync` #3 @ `0x0010226c`)
On the second iteration (`i = 1`), `0x001021fc: addiu $s0, $s0, 10` advances `$s0` from `0` to `10`, and `0x00102200: sll $v0, $s0, 1` computes `$v0 = 2 * $s0 = 20`:
- **Primitive**: 1 `GS_PRIM_SPRITE` (`[20, 120) x [10, 110)`).
- **Color (`RGBAQ`)**:
  - `R = $s0 = 10` (`0x0A`)
  - `G = 0` (`0x00`)
  - `B = 255 - $s0 = 245` (`0xF5`)
  - `A = 0x80` (`128`)
  - Packed `PSMCT32` word: **`0x80F5000A`** (`R=10, G=0, B=245, A=128`).
- **Screen Coordinates**:
  - Vertex 0: `X0 = 20`, `Y0 = 10`, `Z0 = 0`
  - Vertex 1: `X1 = 120`, `Y1 = 110`, `Z1 = 0`
  - Fills **`[20, 120) x [10, 110)`** (`10,000` pixels) with **`(R=10, G=0, B=245, A=128)`** (`0x80F5000A`), overwriting the `[20, 100) x [10, 100)` (`80 x 90 = 7,200` pixels) overlap region of Frame 2's sprite and leaving `10,000 - 7,200 = 2,800` pixels of Frame 2's sprite visible in the top/left L-shaped band (`[0, 100) x [0, 10)` and `[0, 20) x [10, 100)`).

---

## 3. Pre-Registered Pixel Coordinates & Expected Bit-Exact Values After Frame 3

After **Frame 3** completes (`3` calls to `graph_wait_vsync`), the `512 x 512` `PSMCT32` framebuffer MUST contain the following exact pixel values at these 8 named coordinates:

| Probe ID | Coordinate `(x, y)` | Region Description | Expected `(R, G, B, A)` | Expected `PSMCT32` (`uint32_t`) |
| :--- | :--- | :--- | :--- | :--- |
| **`PIXEL_1_SPRITE1_ORIGIN`** | `(0, 0)` | Top-left corner of Frame 2 sprite (`[0, 100) x [0, 100)`), uncovered by Frame 3 | `(0, 0, 255, 128)` | `0x80FF0000` |
| **`PIXEL_2_SPRITE1_BAND`** | `(10, 5)` | Top-left L-band of Frame 2 sprite (`x=10 < 20, y=5 < 10`), uncovered by Frame 3 | `(0, 0, 255, 128)` | `0x80FF0000` |
| **`PIXEL_3_OVERLAP_START`** | `(20, 10)` | Top-left corner of Frame 3 sprite (`[20, 120) x [10, 110)`), overwriting Frame 2 | `(10, 0, 245, 128)` | `0x80F5000A` |
| **`PIXEL_4_OVERLAP_CENTER`** | `(50, 50)` | Center of overlap region `[20, 100) x [10, 100)` — overwritten by Frame 3 sprite | `(10, 0, 245, 128)` | `0x80F5000A` |
| **`PIXEL_5_SPRITE2_ONLY`** | `(110, 105)` | Bottom-right region exclusive to Frame 3 sprite (`[100, 120) x [100, 110)`) | `(10, 0, 245, 128)` | `0x80F5000A` |
| **`PIXEL_6_OUTSIDE_SPRITE2`** | `(120, 110)` | Just outside bottom-right exclusive boundary of Frame 3 sprite (`x=120, y=110`) | `(0, 0, 0, 128)` | `0x80000000` |
| **`PIXEL_7_CLEAR_MID`** | `(256, 256)` | Center of the `512 x 512` framebuffer (cleared in Frame 1 `draw_clear`) | `(0, 0, 0, 128)` | `0x80000000` |
| **`PIXEL_8_CLEAR_END`** | `(511, 511)` | Bottom-right corner of the `512 x 512` framebuffer (cleared in Frame 1 `draw_clear`) | `(0, 0, 0, 128)` | `0x80000000` |

### Summary of Expected Framebuffer Histogram After Frame 3
- Total pixels in `512 x 512` framebuffer: **`262,144`**
- Pixels with `0x80F5000A` (`(10, 0, 245, 128)`, Frame 3 sprite `[20, 120) x [10, 110)`): **`10,000`** (`100 x 100`)
- Pixels with `0x80FF0000` (`(0, 0, 255, 128)`, Frame 2 sprite `[0, 100) x [0, 100)` minus the `80 x 90 = 7,200` overlap with Frame 3): **`2,800`** (`10,000 - 7,200`)
- Pixels with `0x80000000` (`(0, 0, 0, 128)`, Frame 1 `draw_clear` background): **`249,344`** (`262,144 - 12,800`)
- Total primitives rasterized across the 3 frames: **`18`** (`16` vertical `32 x 512` clear strips in Frame 1 + `1` sprite in Frame 2 + `1` sprite in Frame 3).
- Total pixel writes (`pixels_filled`): **`282,144`** (`262,144` in Frame 1 + `10,000` in Frame 2 + `10,000` in Frame 3).
