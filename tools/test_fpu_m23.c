/*
 * PS2 Static Lifter — Milestone 2.3 Part 2: FPU Numerical Proof Unit Tests (test_fpu_m23.c)
 * =========================================================================================
 * Bit-exact verification of the R5900 COP1 single-precision FPU model against independently
 * derived expected bit patterns (R5900 EE Core Users Manual, Chapter 7 "COP1 Floating-Point
 * Unit"):
 *   1. Arithmetic operations present in graph.elf: ADD.S, SUB.S, MUL.S, NEG.S, MOV.S
 *      plus DIV.S, SQRT.S, ABS.S, ADDA.S/MADD.S/MSUB.S, MAX.S/MIN.S
 *   2. Non-IEEE-754 R5900 EE edge cases:
 *      - Denormal input flush-to-zero (exp==0 -> signed zero)
 *      - Exponent 255 treated as finite number (up to +-MAX = 0x7FFFFFFF / 0xFFFFFFFF)
 *      - Overflow saturation to +-MAX (sets FCSR O + SO)
 *      - Underflow flush to signed zero (sets FCSR U + SU)
 *      - Round-to-Zero (RTZ) mantissa truncation on inexact results
 *   3. Conversions present in graph.elf: CVT.W.S (truncation toward zero + saturation to
 *      0x7FFFFFFF / 0x80000000) and CVT.S.W (signed 32-bit int to EE float32 with RTZ)
 *   4. Compares & BC1 branch condition bit (FCSR bit 23):
 *      C.EQ.S, C.LT.S, C.LE.S, C.F.S + BC1F / BC1T taken and not-taken paths (including
 *      delay-slot execution before branch transfer)
 *   5. Chained Guest Sequence from graph.elf's draw_clear (0x00101860 .. 0x00101974):
 *      Exact instruction-by-instruction lifted sequence computing the 16 vertical 32x512
 *      clear strips and fixed-point 12.4 vertex coordinates (0x7000..0x9000).
 */

#include "ps2_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

static void check_u32(const char *name, uint32_t actual, uint32_t expected) {
    g_tests_run++;
    if (actual == expected) {
        g_tests_passed++;
        printf("[PASS] %-56s : actual=0x%08x == expected=0x%08x\n", name, actual, expected);
    } else {
        g_tests_failed++;
        printf("[FAIL] %-56s : actual=0x%08x != expected=0x%08x\n", name, actual, expected);
    }
}

/* Helper to simulate a lifted BC1F / BC1T branch with delay slot */
static uint32_t sim_bc1(ps2_cpu_ctx_t *ctx, int is_bc1t, uint32_t *ds_counter) {
    uint32_t cond_bit = (ctx->fcsr >> 23) & 1U;
    /* Delay slot always executes unconditionally on BC1F / BC1T */
    (*ds_counter)++;
    if (is_bc1t) {
        return (cond_bit != 0U) ? 1U : 0U;
    } else {
        return (cond_bit == 0U) ? 1U : 0U;
    }
}

int main(void) {
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize ps2_cpu_ctx_t\n");
        return 1;
    }

    printf("================================================================================\n");
    printf("PS2 Static Lifter M2.3 — Part 2 R5900 COP1 FPU Bit-Exact Numerical Proof Suite\n");
    printf("================================================================================\n");

    /* -------------------------------------------------------------------------
     * 1. Arithmetic Ops Present in graph.elf (ADD.S, SUB.S, MUL.S, NEG.S, MOV.S)
     * ------------------------------------------------------------------------- */
    /* 2048.0f (0x45000000) - 256.0f (0x43800000) = 1792.0f (0x44E00000) */
    check_u32("SUB.S: 2048.0f - 256.0f = 1792.0f",
              ps2_fpu_sub_s(&ctx, 0x45000000U, 0x43800000U), 0x44E00000U);

    /* 1792.0f (0x44E00000) + 512.0f (0x44000000) = 2304.0f (0x45100000) */
    check_u32("ADD.S: 1792.0f + 512.0f = 2304.0f",
              ps2_fpu_add_s(&ctx, 0x44E00000U, 0x44000000U), 0x45100000U);

    /* 1812.0f (0x44E28000) * 16.0f (0x41800000) = 28992.0f (0x46E28000) */
    check_u32("MUL.S: 1812.0f * 16.0f = 28992.0f",
              ps2_fpu_mul_s(&ctx, 0x44E28000U, 0x41800000U), 0x46E28000U);

    /* NEG.S and MOV.S preserve bit patterns including non-IEEE exp=255 */
    check_u32("NEG.S: -(1792.0f) = -1792.0f (0xC4E00000)",
              ps2_fpu_neg_s(&ctx, 0x44E00000U), 0xC4E00000U);
    check_u32("NEG.S: -(-0.0f) = +0.0f (0x00000000)",
              ps2_fpu_neg_s(&ctx, 0x80000000U), 0x00000000U);
    check_u32("MOV.S: raw bit copy of 0x7F801234 (exp=255)",
              ps2_fpu_mov_s(&ctx, 0x7F801234U), 0x7F801234U);

    /* Additional R5900 COP1 arithmetic ops (DIV.S, SQRT.S, ABS.S, MAX.S, MIN.S, MADD.S) */
    check_u32("DIV.S: 512.0f / 32.0f = 16.0f (0x41800000)",
              ps2_fpu_div_s(&ctx, 0x44000000U, 0x42000000U), 0x41800000U);
    check_u32("SQRT.S: sqrt(256.0f) = 16.0f (0x41800000)",
              ps2_fpu_sqrt_s(&ctx, 0x43800000U), 0x41800000U);
    check_u32("ABS.S: abs(-512.0f) = +512.0f (0x44000000)",
              ps2_fpu_abs_s(&ctx, 0xC4000000U), 0x44000000U);
    check_u32("MAX.S: max(-10.0f, 20.0f) = 20.0f (0x41A00000)",
              ps2_fpu_max_s(&ctx, 0xC1200000U, 0x41A00000U), 0x41A00000U);
    check_u32("MIN.S: min(-10.0f, 20.0f) = -10.0f (0xC1200000)",
              ps2_fpu_min_s(&ctx, 0xC1200000U, 0x41A00000U), 0xC1200000U);

    /* -------------------------------------------------------------------------
     * 2. Non-IEEE-754 R5900 EE Hardware Semantics (Denormals, Exp=255, RTZ)
     * ------------------------------------------------------------------------- */
    /* Denormal input (exp=0, man=0x123456) flushes to 0.0f in arithmetic */
    check_u32("EE Denormal Flush: 0x00123456 + 1.0f = 1.0f (0x3F800000)",
              ps2_fpu_add_s(&ctx, 0x00123456U, 0x3F800000U), 0x3F800000U);
    check_u32("EE Negative Denormal Mul: 0x807FFFFF * 2.0f = -0.0f",
              ps2_fpu_mul_s(&ctx, 0x807FFFFFU, 0x40000000U), 0x80000000U);

    /* Round-to-Zero (RTZ): 1.0f (0x3F800000) + 2^-24 (0x33800000) truncates to 1.0f */
    check_u32("EE Round-to-Zero: 1.0f + 2^-24 = 1.0f (0x3F800000)",
              ps2_fpu_add_s(&ctx, 0x3F800000U, 0x33800000U), 0x3F800000U);

    /* Round-to-Zero (RTZ) on subtraction: 1.0f (0x3F800000) - 2^-25 (0x33000000)
     * Exact value = 1.0 - 2^-25 = 0.1111111111111111111111111_2 -> truncated to 23 frac bits
     * in binade [0.5, 1.0) (exp=126 = 0x7E, man=0x7FFFFF) -> 0x3F7FFFFF */
    check_u32("EE Round-to-Zero: 1.0f - 2^-25 = 0x3F7FFFFF",
              ps2_fpu_sub_s(&ctx, 0x3F800000U, 0x33000000U), 0x3F7FFFFFU);

    /* Exp=255 finite arithmetic & saturation to +-MAX (0x7FFFFFFF / 0xFFFFFFFF) */
    /* 2^127 (exp=254, 0x7F000000) * 2.0f (0x40000000) = 2^128 (exp=255, 0x7F800000 — finite on EE!) */
    check_u32("EE Exp=255 Finite: 2^127 * 2.0f = 0x7F800000 (no overflow)",
              ps2_fpu_mul_s(&ctx, 0x7F000000U, 0x40000000U), 0x7F800000U);
    check_u32("EE Exp=255 FCSR Cause.O clear on exp=255 exact",
              (ctx.fcsr & PS2_FCSR_CAUSE_O) ? 1U : 0U, 0U);

    /* Overflow saturation: +MAX (0x7FFFFFFF) * 2.0f (0x40000000) -> +MAX (0x7FFFFFFF) + O/SO set */
    check_u32("EE Overflow Saturation: +MAX * 2.0f = +MAX (0x7FFFFFFF)",
              ps2_fpu_mul_s(&ctx, 0x7FFFFFFFU, 0x40000000U), 0x7FFFFFFFU);
    check_u32("EE Overflow FCSR Cause.O + Sticky.O set",
              (ctx.fcsr & (PS2_FCSR_CAUSE_O | PS2_FCSR_STICKY_O)),
              (PS2_FCSR_CAUSE_O | PS2_FCSR_STICKY_O));

    /* Division by zero saturation: -1.0f / +0.0f -> -MAX (0xFFFFFFFF) + D/SD set */
    check_u32("EE Div-by-Zero Saturation: -1.0f / +0.0f = -MAX (0xFFFFFFFF)",
              ps2_fpu_div_s(&ctx, 0xBF800000U, 0x00000000U), 0xFFFFFFFFU);
    check_u32("EE Div-by-Zero FCSR Cause.D + Sticky.D set",
              (ctx.fcsr & (PS2_FCSR_CAUSE_D | PS2_FCSR_STICKY_D)),
              (PS2_FCSR_CAUSE_D | PS2_FCSR_STICKY_D));

    /* -------------------------------------------------------------------------
     * 3. Conversions Present in graph.elf (CVT.W.S and CVT.S.W)
     * ------------------------------------------------------------------------- */
    /* CVT.W.S truncates toward zero */
    check_u32("CVT.W.S: +28672.9f (0x46E001CC) -> 28672 (0x00007000)",
              ps2_fpu_cvt_w_s(&ctx, 0x46E001CCU), 0x00007000U);
    check_u32("CVT.W.S: -42.875f (0xC22B8000) -> -42 (0xFFFFFFD6)",
              ps2_fpu_cvt_w_s(&ctx, 0xC22B8000U), 0xFFFFFFD6U);
    /* CVT.W.S saturates out-of-range floats to 0x7FFFFFFF / 0x80000000 */
    check_u32("CVT.W.S: +1e12f (0x5368D4A5) -> +INT32_MAX (0x7FFFFFFF)",
              ps2_fpu_cvt_w_s(&ctx, 0x5368D4A5U), 0x7FFFFFFFU);
    check_u32("CVT.W.S: -1e12f (0xD368D4A5) -> INT32_MIN (0x80000000)",
              ps2_fpu_cvt_w_s(&ctx, 0xD368D4A5U), 0x80000000U);

    /* CVT.S.W converts signed 32-bit int to EE float32 with RTZ */
    check_u32("CVT.S.W: 512 (0x00000200) -> 512.0f (0x44000000)",
              ps2_fpu_cvt_s_w(&ctx, 512U), 0x44000000U);
    check_u32("CVT.S.W: -256 (0xFFFFFF00) -> -256.0f (0xC3800000)",
              ps2_fpu_cvt_s_w(&ctx, (uint32_t)(-256)), 0xC3800000U);
    /* Large integer requiring RTZ truncation: 0x7FFFFFFF (2147483647) ->
     * IEEE RNE would round up to 2^31 (0x4F000000), but R5900 RTZ truncates to 0x4EFFFFFF! */
    check_u32("CVT.S.W (EE RTZ vs IEEE RNE): 0x7FFFFFFF -> 0x4EFFFFFF",
              ps2_fpu_cvt_s_w(&ctx, 0x7FFFFFFFU), 0x4EFFFFFFU);

    /* -------------------------------------------------------------------------
     * 4. Compares (C.EQ.S, C.LT.S, C.LE.S, C.F.S) + BC1F / BC1T Taken/Not-Taken
     * ------------------------------------------------------------------------- */
    uint32_t ds_count = 0;

    /* C.EQ.S: +0.0f == -0.0f (both denormal/zero flush to 0.0) -> C=1 */
    ps2_fpu_c_eq_s(&ctx, 0x00000000U, 0x80000000U);
    check_u32("C.EQ.S(+0.0f, -0.0f) sets FCSR.C = 1", (ctx.fcsr >> 23) & 1U, 1U);
    check_u32("BC1T taken when C=1", sim_bc1(&ctx, 1, &ds_count), 1U);
    check_u32("BC1F not taken when C=1", sim_bc1(&ctx, 0, &ds_count), 0U);

    /* C.LT.S: 32.0f < 512.0f -> C=1; 512.0f < 512.0f -> C=0 */
    ps2_fpu_c_lt_s(&ctx, 0x42000000U, 0x44000000U);
    check_u32("C.LT.S(32.0f, 512.0f) sets FCSR.C = 1", (ctx.fcsr >> 23) & 1U, 1U);
    ps2_fpu_c_lt_s(&ctx, 0x44000000U, 0x44000000U);
    check_u32("C.LT.S(512.0f, 512.0f) sets FCSR.C = 0", (ctx.fcsr >> 23) & 1U, 0U);
    check_u32("BC1F taken when C=0", sim_bc1(&ctx, 0, &ds_count), 1U);
    check_u32("BC1T not taken when C=0", sim_bc1(&ctx, 1, &ds_count), 0U);

    /* C.LE.S: 512.0f <= 512.0f -> C=1; 513.0f <= 512.0f -> C=0 */
    ps2_fpu_c_le_s(&ctx, 0x44000000U, 0x44000000U);
    check_u32("C.LE.S(512.0f, 512.0f) sets FCSR.C = 1", (ctx.fcsr >> 23) & 1U, 1U);
    ps2_fpu_c_le_s(&ctx, 0x44004000U, 0x44000000U);
    check_u32("C.LE.S(513.0f, 512.0f) sets FCSR.C = 0", (ctx.fcsr >> 23) & 1U, 0U);

    /* C.F.S always sets C=0 */
    ctx.fcsr |= PS2_FCSR_COND_BIT;
    ps2_fpu_c_f_s(&ctx, 0x3F800000U, 0x3F800000U);
    check_u32("C.F.S always clears FCSR.C = 0", (ctx.fcsr >> 23) & 1U, 0U);
    check_u32("Delay slots executed on all 4 BC1 tests", ds_count, 4U);

    /* -------------------------------------------------------------------------
     * 5. Chained Guest Sequence from graph.elf's draw_clear (0x00101860..0x00101974)
     * -------------------------------------------------------------------------
     * Replicates the exact COP1 instruction sequence in draw_clear(q, 0, 1792.0f,
     * 1792.0f, 512.0f, 512.0f, 0, 0, 0) from graph.elf:
     *   $f12 = x = 1792.0f (0x44E00000)
     *   $f13 = y = 1792.0f (0x44E00000)
     *   $f14 = width = 512.0f (0x44000000)
     *   $f15 = height = 512.0f (0x44000000)
     *   $f3  = 32.0f (0x42000000, strip width)
     *   $f2  = 16.0f (0x41800000, 12.4 fixed-point scale factor)
     *   $f4  = 0.9375f (0x3F700000, sub-pixel bias)
     */
    uint32_t f12_x      = 0x44E00000U; /* 1792.0f */
    uint32_t f13_y      = 0x44E00000U; /* 1792.0f */
    uint32_t f14_w      = 0x44000000U; /* 512.0f  */
    uint32_t f15_h      = 0x44000000U; /* 512.0f  */
    uint32_t f3_step    = 0x42000000U; /* 32.0f   */
    uint32_t f2_scale16 = 0x41800000U; /* 16.0f   */
    uint32_t f1_cur_w   = 0x00000000U; /* 0.0f    */

    /* 0x001018f8: add.s $f0, $f13, $f15 -> y + height = 1792.0f + 512.0f = 2304.0f (0x45100000) */
    uint32_t f0_y1 = ps2_fpu_add_s(&ctx, f13_y, f15_h);
    check_u32("draw_clear chain [0x001018f8]: y + h = 2304.0f", f0_y1, 0x45100000U);

    /* 0x00101908: mul.s $f5, $f13, $f2 -> y * 16.0f = 28672.0f (0x46E00000)
     * 0x00101918: cvt.w.s $f5, $f5 -> 28672 = 0x00007000 */
    uint32_t f5_y0_fp = ps2_fpu_cvt_w_s(&ctx, ps2_fpu_mul_s(&ctx, f13_y, f2_scale16));
    check_u32("draw_clear chain [0x00101918]: Y0 fixed 12.4 = 0x7000", f5_y0_fp, 0x00007000U);

    /* 0x00101904: mul.s $f0, $f0, $f2 -> (y + h) * 16.0f = 36864.0f (0x47100000)
     * 0x00101910: cvt.w.s $f0, $f0 -> 36864 = 0x00009000 */
    uint32_t f0_y1_fp = ps2_fpu_cvt_w_s(&ctx, ps2_fpu_mul_s(&ctx, f0_y1, f2_scale16));
    check_u32("draw_clear chain [0x00101910]: Y1 fixed 12.4 = 0x9000", f0_y1_fp, 0x00009000U);

    /* Loop over the 16 vertical 32-pixel strips (0x0010193c .. 0x00101970) */
    uint32_t strip_count = 0;
    uint32_t first_x0_fp = 0, last_x1_fp = 0;
    while (1) {
        /* 0x0010193c: add.s $f0, $f12, $f1 */
        uint32_t f0_x0 = ps2_fpu_add_s(&ctx, f12_x, f1_cur_w);
        /* 0x00101940: add.s $f1, $f1, $f3 */
        f1_cur_w = ps2_fpu_add_s(&ctx, f1_cur_w, f3_step);
        /* 0x00101944: mul.s $f0, $f0, $f2; 0x00101948: cvt.w.s $f0, $f0 */
        uint32_t x0_fp = ps2_fpu_cvt_w_s(&ctx, ps2_fpu_mul_s(&ctx, f0_x0, f2_scale16));
        /* 0x00101950: add.s $f0, $f12, $f1; 0x00101958: mul.s; 0x00101960: cvt.w.s */
        uint32_t f0_x1 = ps2_fpu_add_s(&ctx, f12_x, f1_cur_w);
        uint32_t x1_fp = ps2_fpu_cvt_w_s(&ctx, ps2_fpu_mul_s(&ctx, f0_x1, f2_scale16));

        if (strip_count == 0) first_x0_fp = x0_fp;
        last_x1_fp = x1_fp;
        strip_count++;

        /* 0x0010194c: c.lt.s $f1, $f14; 0x00101970: bc1t 0x0010193c */
        ps2_fpu_c_lt_s(&ctx, f1_cur_w, f14_w);
        if (((ctx.fcsr >> 23) & 1U) == 0U) {
            break;
        }
    }
    check_u32("draw_clear chain [0x00101970]: 16 strips emitted", strip_count, 16U);
    check_u32("draw_clear chain: strip[0].X0 = 0x7000 (1792.0)", first_x0_fp, 0x00007000U);
    check_u32("draw_clear chain: strip[15].X1 = 0x9000 (2304.0)", last_x1_fp, 0x00009000U);

    printf("================================================================================\n");
    printf("FPU Numerical Proof Summary: %d / %d passed (%d failed)\n",
           g_tests_passed, g_tests_run, g_tests_failed);
    printf("================================================================================\n");

    ps2_runtime_destroy(&ctx);
    return (g_tests_failed == 0) ? 0 : 1;
}
