/*
 * host_graph_runner.c — Milestone 2.3 Part 3 Execution Harness for Lifted `graph.elf`
 * ===================================================================================
 * Executes the lifted R5900 code of `graph.elf` (`lifted_graph.c`, 504 functions,
 * 34,384 / 34,420 lifted instructions, 0 UNLIFTED_INSN, 36 INDIRECT) from its true
 * ELF entry point (`0x00100b20`, `fn_00100b20___start`) through:
 *   1. `crt0` (`__start` -> `_main`)
 *   2. `_InitSys` (`InitAlarm`, `_ps2sdk_init_timer`, `InitThread`, `InitExecPS2`, `InitTLBFunctions`)
 *   3. `_libcglue_init` & `_init` (`.ctors`)
 *   4. `main` (`0x00121870`):
 *      - `ResetEE(0x32)`
 *      - `dma_channel_initialize(DMA_CHANNEL_GIF = 2, NULL, 0)`
 *      - `dma_channel_fast_waits(DMA_CHANNEL_GIF = 2)`
 *      - `init_gs(&fb, &zb)` (`0x00102028`): 512x512 PSMCT32 framebuffer at VRAM 0x0
 *      - `init_drawing_environment(&fb, &zb)` (`0x001020a8`): Context 1 setup via GIF DMA Ch2
 *      - `render(DMA_CHANNEL_GIF, &fb)` (`0x00102100`):
 *          * Frame 1: `draw_clear` (16 vertical 32x512 sprite strips, RGBA=(0,0,0,128)) + `graph_wait_vsync` #1
 *          * Frame 2: Loop i=0 ($s0=0): 100x100 sprite at [0,100)x[0,100), RGBA=(0,0,255,128) + `graph_wait_vsync` #2
 *          * Frame 3: Loop i=1 ($s0=10): 100x100 sprite at [20,120)x[10,110), RGBA=(10,0,245,128) + `graph_wait_vsync` #3
 *   5. Clean harness stop on `FRAME_LIMIT` (`ctx.frame_limit = 3`) at `0x001013f0` inside `graph_wait_vsync`.
 *
 * Exports:
 *   - `frame3.ppm`: Modeled 512x512 framebuffer after Frame 3
 *   - `pixel_probe.log`: Bit-exact check of the 8 pre-registered pixel coordinates from `PREREG-M23.md`
 *   - `gs_trace.log` & `gs_trace.json`: Complete GS boundary event trace (privileged register writes + GIF DMA packets)
 *   - `syscall_trace_graph.log` & `syscall_trace_graph.json`: Full EE syscall, indirect call, and boundary trace
 *   - `execution_state_graph.log`: Final CPU/FPU/GS state and 100-PC ring buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "ps2_runtime.h"
#include "lifted_graph.h"

typedef struct {
    const char *name;
    uint32_t    x;
    uint32_t    y;
    uint8_t     exp_r;
    uint8_t     exp_g;
    uint8_t     exp_b;
    uint8_t     exp_a;
    uint32_t    exp_word;
    const char *region_desc;
} prereg_pixel_probe_t;

static const prereg_pixel_probe_t k_prereg_probes[8] = {
    { "PIXEL_1_SPRITE1_ORIGIN",  0,   0,  0,  0, 255, 128, 0x80FF0000U, "Top-left corner of Frame 2 sprite [0,100)x[0,100), uncovered by Frame 3" },
    { "PIXEL_2_SPRITE1_BAND",   10,   5,  0,  0, 255, 128, 0x80FF0000U, "Top-left L-band of Frame 2 sprite (x=10<20, y=5<10), uncovered by Frame 3" },
    { "PIXEL_3_OVERLAP_START",  20,  10, 10,  0, 245, 128, 0x80F5000AU, "Top-left corner of Frame 3 sprite [20,120)x[10,110), overwriting Frame 2" },
    { "PIXEL_4_OVERLAP_CENTER", 50,  50, 10,  0, 245, 128, 0x80F5000AU, "Center of overlap region [20,100)x[10,100), overwritten by Frame 3" },
    { "PIXEL_5_SPRITE2_ONLY",  110, 105, 10,  0, 245, 128, 0x80F5000AU, "Bottom-right region exclusive to Frame 3 sprite [100,120)x[100,110)" },
    { "PIXEL_6_OUTSIDE_SPRITE2",120, 110,  0,  0,   0, 128, 0x80000000U, "Just outside bottom-right exclusive boundary of Frame 3 sprite" },
    { "PIXEL_7_CLEAR_MID",     256, 256,  0,  0,   0, 128, 0x80000000U, "Center of 512x512 framebuffer (cleared in Frame 1 draw_clear)" },
    { "PIXEL_8_CLEAR_END",     511, 511,  0,  0,   0, 128, 0x80000000U, "Bottom-right corner of 512x512 framebuffer (cleared in Frame 1 draw_clear)" },
};

int main(int argc, char **argv) {
    const char *ppm_path        = "frame3.ppm";
    const char *probe_log_path  = "pixel_probe.log";
    const char *gs_log_path     = "gs_trace.log";
    const char *gs_json_path    = "gs_trace.json";
    const char *trace_log_path  = "syscall_trace_graph.log";
    const char *trace_json_path = "syscall_trace_graph.json";
    const char *state_log_path  = "execution_state_graph.log";
    uint32_t    target_frames   = 3U;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
            target_frames = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--ppm") == 0 && i + 1 < argc) {
            ppm_path = argv[++i];
        } else if (strcmp(argv[i], "--probe-log") == 0 && i + 1 < argc) {
            probe_log_path = argv[++i];
        } else if (strcmp(argv[i], "--gs-log") == 0 && i + 1 < argc) {
            gs_log_path = argv[++i];
        } else if (strcmp(argv[i], "--gs-json") == 0 && i + 1 < argc) {
            gs_json_path = argv[++i];
        }
    }

    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        fprintf(stderr, "[host_graph_runner] Failed to initialize PS2 runtime context\n");
        return 1;
    }
    ctx.frame_limit = target_frames;

    int rc = ps2_init_guest_memory(&ctx);
    if (rc != 0) {
        fprintf(stderr, "[host_graph_runner] Failed to initialize Guest Memory Image (rc=%d)\n", rc);
        ps2_runtime_destroy(&ctx);
        return 2;
    }

    /* Execute lifted code starting strictly at ELF entry point 0x00100b20 (fn_00100b20___start) */
    int exec_rc = ps2_runtime_execute(&ctx, fn_00100b20___start);
    (void)exec_rc;

    /* Export Frame 3 framebuffer as PPM */
    int ppm_rc = ps2_export_framebuffer_ppm(&ctx, ppm_path);

    /* Export GS traces, Syscall traces, and Execution State */
    (void)ps2_write_gs_trace_log(&ctx, gs_log_path);
    (void)ps2_write_gs_trace_json(&ctx, gs_json_path);
    (void)ps2_write_syscall_trace_log(&ctx, trace_log_path);
    (void)ps2_write_syscall_trace_json(&ctx, trace_json_path);

    FILE *sfp = fopen(state_log_path, "w");
    if (sfp) {
        ps2_dump_execution_state(&ctx, sfp);
        fclose(sfp);
    }

    /* Compute full 512x512 framebuffer color histogram & verify pre-registered pixel probes */
    uint32_t count_clear   = 0; /* 0x80000000 */
    uint32_t count_sprite1 = 0; /* 0x80FF0000 */
    uint32_t count_sprite2 = 0; /* 0x80F5000A */
    uint32_t count_other   = 0;
    for (uint32_t y = 0; y < 512U; ++y) {
        for (uint32_t x = 0; x < 512U; ++x) {
            uint32_t px = ps2_gs_read_pixel_psmct32(&ctx, x, y);
            if (px == 0x80000000U)      count_clear++;
            else if (px == 0x80FF0000U) count_sprite1++;
            else if (px == 0x80F5000AU) count_sprite2++;
            else                        count_other++;
        }
    }

    FILE *pfp = fopen(probe_log_path, "w");
    int probes_passed = 0;
    int probes_total  = (int)(sizeof(k_prereg_probes) / sizeof(k_prereg_probes[0]));

    for (int pass = 0; pass < 2; ++pass) {
        FILE *out = (pass == 0) ? stdout : pfp;
        if (!out) continue;
        fprintf(out, "====================================================================================================\n");
        fprintf(out, "PS2-LIFTER Milestone 2.3 Part 3 — Frame %u Pre-Registered Pixel Probe Verification (`PREREG-M23.md`)\n",
                ctx.gs.frames_completed);
        fprintf(out, "====================================================================================================\n");
        fprintf(out, "Target ELF          : graph.elf (entry=0x00100b20, SHA-256=4220f58a2826000f496420b4c2c1a97b1b769a88079f08af9261eaeb6ada7239)\n");
        fprintf(out, "Stop Reason         : %s at PC=0x%08x\n",
                (ctx.stop_reason == PS2_STOP_FRAME_LIMIT) ? "FRAME_LIMIT (PASS)" : "UNEXPECTED_STOP (FAIL)",
                ctx.stop_pc);
        fprintf(out, "Frames Completed    : %u / %u\n", ctx.gs.frames_completed, ctx.frame_limit);
        fprintf(out, "Instructions Retired: %" PRIu64 " (FPU ops retired: %" PRIu64 ")\n",
                ctx.insn_retired, ctx.fpu_ops_retired);
        fprintf(out, "GS Boundary Stats   : GIF DMA Packets=%u, GIF Tags=%u, GS Reg Writes=%u, Primitives=%u, Pixels Filled=%" PRIu64 "\n",
                ctx.gs.gif_packets_processed, ctx.gs.gif_tags_processed,
                ctx.gs.gs_reg_writes, ctx.gs.primitives_drawn, ctx.gs.pixels_filled);
        fprintf(out, "Framebuffer Geometry: %ux%u PSMCT32 (FBP=0x%x, FBW=%u, OFX=0x%04x, OFY=0x%04x)\n",
                ctx.gs.fb_width, ctx.gs.fb_height, ctx.gs.ctx[0].fbp, ctx.gs.ctx[0].fbw,
                ctx.gs.ctx[0].ofx, ctx.gs.ctx[0].ofy);
        fprintf(out, "----------------------------------------------------------------------------------------------------\n");
        fprintf(out, "ID                        | (X, Y)     | ACTUAL RGBA         | ACTUAL HEX | EXPECTED HEX | VERDICT\n");
        fprintf(out, "----------------------------------------------------------------------------------------------------\n");

        for (int i = 0; i < probes_total; ++i) {
            const prereg_pixel_probe_t *p = &k_prereg_probes[i];
            uint32_t actual = ps2_gs_read_pixel_psmct32(&ctx, p->x, p->y);
            uint8_t ar = (uint8_t)(actual & 0xFFU);
            uint8_t ag = (uint8_t)((actual >> 8) & 0xFFU);
            uint8_t ab = (uint8_t)((actual >> 16) & 0xFFU);
            uint8_t aa = (uint8_t)((actual >> 24) & 0xFFU);
            bool ok = (actual == p->exp_word);
            if (pass == 0 && ok) {
                probes_passed++;
            }
            fprintf(out, "%-25s | (%3u, %3u) | (%3u, %3u, %3u, %3u) | 0x%08x | 0x%08x   | %s\n",
                    p->name, p->x, p->y, ar, ag, ab, aa, actual, p->exp_word,
                    ok ? "PASS" : "FAIL");
        }
        fprintf(out, "----------------------------------------------------------------------------------------------------\n");
        fprintf(out, "Framebuffer Full-Surface Histogram (512 x 512 = 262,144 pixels):\n");
        fprintf(out, "  - Clear background   0x80000000 (R=  0, G=  0, B=  0, A=128) : %6u pixels (expected: 249344)\n", count_clear);
        fprintf(out, "  - Frame 2 sprite     0x80FF0000 (R=  0, G=  0, B=255, A=128) : %6u pixels (expected:   2800)\n", count_sprite1);
        fprintf(out, "  - Frame 3 sprite     0x80F5000A (R= 10, G=  0, B=245, A=128) : %6u pixels (expected:  10000)\n", count_sprite2);
        fprintf(out, "  - Any other color                                            : %6u pixels (expected:      0)\n", count_other);
        fprintf(out, "----------------------------------------------------------------------------------------------------\n");
        fprintf(out, "Pre-Registered Probe Result: %d / %d PASSED | Histogram Exact Match: %s | Overall Verdict: %s\n",
                probes_passed, probes_total,
                (count_clear == 249344U && count_sprite1 == 2800U && count_sprite2 == 10000U && count_other == 0U) ? "YES" : "NO",
                (ctx.stop_reason == PS2_STOP_FRAME_LIMIT && probes_passed == probes_total && ppm_rc == 0) ? "PASS" : "FAIL");
        fprintf(out, "====================================================================================================\n");
    }

    if (pfp) {
        fclose(pfp);
    }

    bool all_ok = (ctx.stop_reason == PS2_STOP_FRAME_LIMIT) &&
                  (ctx.gs.frames_completed == target_frames) &&
                  (probes_passed == probes_total) &&
                  (count_clear == 249344U && count_sprite1 == 2800U && count_sprite2 == 10000U && count_other == 0U) &&
                  (ppm_rc == 0);

    ps2_runtime_destroy(&ctx);
    return all_ok ? 0 : 1;
}
