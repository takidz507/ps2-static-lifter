/*
 * native_graph_jni.c — JNI Bridge for PS2 Lifted Graph (`org.ps2lifter.graph`)
 * ============================================================================
 * Executes the AOT-lifted `graph.elf` (`fn_00100b20___start` in `lifted_graph.c`)
 * for `targetFrames` frames via `ps2_runtime_execute`, converts the modeled 512x512
 * PSMCT32 framebuffer (`0xAABBGGRR`) into Android `ARGB_8888` (`0xFFRRGGBB`) pixels
 * for direct bitmap blit, and returns a structured telemetry summary string.
 *
 * Also supports standalone host compilation (`-DPS2_JNI_HOST_TEST`) so the JNI bridge
 * logic can be verified on the host alongside the lifted binary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "ps2_runtime.h"
#include "lifted_graph.h"

static int ps2_run_and_blit_argb(uint32_t target_frames, uint32_t *out_argb_512x512, char *summary_buf, size_t summary_cap) {
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        snprintf(summary_buf, summary_cap, "ERROR: ps2_runtime_init failed");
        return -1;
    }
    ctx.frame_limit = (target_frames > 0U) ? target_frames : 3U;

    if (ps2_init_guest_memory(&ctx) != 0) {
        snprintf(summary_buf, summary_cap, "ERROR: ps2_init_guest_memory failed");
        ps2_runtime_destroy(&ctx);
        return -2;
    }

    (void)ps2_runtime_execute(&ctx, fn_00100b20___start);

    if (out_argb_512x512 != NULL) {
        for (uint32_t y = 0; y < 512U; ++y) {
            for (uint32_t x = 0; x < 512U; ++x) {
                uint32_t psm32 = ps2_gs_read_pixel_psmct32(&ctx, x, y);
                uint32_t r = psm32 & 0xFFU;
                uint32_t g = (psm32 >> 8) & 0xFFU;
                uint32_t b = (psm32 >> 16) & 0xFFU;
                out_argb_512x512[y * 512U + x] = 0xFF000000U | (r << 16) | (g << 8) | b;
            }
        }
    }

    uint32_t p_origin  = ps2_gs_read_pixel_psmct32(&ctx, 0U, 0U);
    uint32_t p_overlap = ps2_gs_read_pixel_psmct32(&ctx, 20U, 10U);
    uint32_t p_center  = ps2_gs_read_pixel_psmct32(&ctx, 256U, 256U);

    snprintf(summary_buf, summary_cap,
             "Package             : org.ps2lifter.graph (PS2 Lifted Graph)\n"
             "Execution Mode      : 100%% Static AOT Lifted C (Zero JIT/Interpreter)\n"
             "Target ELF          : graph.elf (504 funcs, 34,384/34,420 insns lifted)\n"
             "Stop Outcome        : %s @ PC=0x%08x\n"
             "Frames Completed    : %u / %u\n"
             "Instructions Retired: %" PRIu64 " (COP1 FPU Ops: %" PRIu64 ")\n"
             "Syscalls Dispatched : %" PRIu64 " (Lifted=%u, Service=%u, Boundary=%u)\n"
             "GS Boundary Stats   : GIF Packets=%u, Tags=%u, RegWrites=%u, Prims=%u\n"
             "Pixels Filled       : %" PRIu64 " (512x512 PSMCT32 @ VRAM 0x0)\n"
             "Probe (0,0)         : 0x%08x\n"
             "Probe (20,10)       : 0x%08x\n"
             "Probe (256,256)     : 0x%08x\n",
             (ctx.stop_reason == PS2_STOP_FRAME_LIMIT) ? "FRAME_LIMIT" : "OTHER",
             ctx.stop_pc,
             ctx.gs.frames_completed, ctx.frame_limit,
             ctx.insn_retired, ctx.fpu_ops_retired,
             ctx.syscalls_dispatched,
             ctx.syscall_lifted_native_count,
             ctx.syscall_service_stub_count,
             ctx.syscall_boundary_intercept_count,
             ctx.gs.gif_packets_processed,
             ctx.gs.gif_tags_processed,
             ctx.gs.gs_reg_writes,
             ctx.gs.primitives_drawn,
             ctx.gs.pixels_filled,
             p_origin, p_overlap, p_center);

    ps2_runtime_destroy(&ctx);
    return 0;
}

#ifndef PS2_JNI_HOST_TEST
#include <jni.h>

JNIEXPORT jstring JNICALL
Java_org_ps2lifter_graph_MainActivity_nativeRunGraphFrames(
    JNIEnv *env,
    jclass clazz,
    jint target_frames,
    jintArray out_argb_pixels
) {
    (void)clazz;
    char summary[2048];
    memset(summary, 0, sizeof(summary));

    uint32_t *argb_buf = (uint32_t *)malloc(512U * 512U * sizeof(uint32_t));
    if (!argb_buf) {
        return (*env)->NewStringUTF(env, "ERROR: Out of memory allocating 512x512 ARGB buffer");
    }

    (void)ps2_run_and_blit_argb((uint32_t)target_frames, argb_buf, summary, sizeof(summary));

    if (out_argb_pixels != NULL) {
        jsize len = (*env)->GetArrayLength(env, out_argb_pixels);
        if (len >= 512 * 512) {
            (*env)->SetIntArrayRegion(env, out_argb_pixels, 0, 512 * 512, (const jint *)argb_buf);
        }
    }

    free(argb_buf);
    return (*env)->NewStringUTF(env, summary);
}
#else
int main(void) {
    uint32_t *argb = (uint32_t *)malloc(512U * 512U * sizeof(uint32_t));
    char summary[2048];
    int rc = ps2_run_and_blit_argb(3U, argb, summary, sizeof(summary));
    printf("%s", summary);
    /* Verify ARGB conversion: (0,0) = 0xFF0000FF (blue), (20,10) = 0xFF0A00F5, (256,256) = 0xFF000000 */
    int ok = (rc == 0) &&
             (argb[0] == 0xFF0000FFU) &&
             (argb[10U * 512U + 20U] == 0xFF0A00F5U) &&
             (argb[256U * 512U + 256U] == 0xFF000000U);
    printf("Android JNI Bridge Host Verification: %s (argb[0,0]=0x%08x, argb[20,10]=0x%08x, argb[256,256]=0x%08x)\n",
           ok ? "PASS" : "FAIL",
           argb[0], argb[10U * 512U + 20U], argb[256U * 512U + 256U]);
    free(argb);
    return ok ? 0 : 1;
}
#endif
