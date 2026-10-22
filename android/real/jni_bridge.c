/*
 * jni_bridge.c — JNI Bridge for the REAL lifted PS2 program (M2.2 engine)
 * =======================================================================
 * Runs the statically lifted code of the official ps2sdk sample
 * `hello_real.elf` (ee-gcc 15.2 build; 30,090 instructions, 437 functions,
 * 30,060 lifted) from its true entry point 0x00100b20 through the M2.2
 * runtime model, and returns the execution summary + the verbatim guest
 * output (produced by the guest's own lifted newlib stdio chain at the
 * declared FILEIO boundary) to org.ps2lifter.real.MainActivity.
 * Zero emulator/interpreter components: native AOT code only.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "ps2_runtime.h"
#include "lifted_hello_real.h"

static int run_real_program(ps2_cpu_ctx_t *ctx) {
    if (ps2_runtime_init(ctx) != 0) {
        return -100;
    }
    if (ps2_init_guest_memory(ctx) != 0) {
        ps2_runtime_destroy(ctx);
        return -101;
    }
    return ps2_runtime_execute(ctx, fn_00100b20___start);
}

JNIEXPORT jstring JNICALL
Java_org_ps2lifter_real_MainActivity_nativeRunLiftedProgram(JNIEnv *env, jobject thiz) {
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    int exit_code = run_real_program(&ctx);
    if (exit_code <= -100) {
        return (*env)->NewStringUTF(env, "ERROR: PS2 runtime init failed");
    }

    char guest[1200];
    size_t gl = ctx.stdout_len < sizeof(guest) - 1 ? ctx.stdout_len : sizeof(guest) - 1;
    memcpy(guest, ctx.stdout_buf, gl);
    guest[gl] = '\0';

    char result_buf[4096];
    snprintf(
        result_buf,
        sizeof(result_buf),
        "=== PS2 Static Lifter - REAL Program (M2.2) ===\n"
        "Source ELF  : hello_real.elf (ps2sdk, ee-gcc 15.2)\n"
        "Code        : 30,090 instructions / 437 functions\n"
        "Lifted      : 30,060 (99.90%%), 30 declared blockers\n"
        "Entry Point : 0x%08x (_start)\n"
        "Stack Init  : 0x%08x\n"
        "Heap Range  : 0x%08x .. 0x%08x\n"
        "FlushCache  : %u calls (AOT No-op)\n"
        "SyncBarrier : %u calls\n"
        "Syscalls    : %llu total (%u lifted / %u service / %u boundary)\n"
        "Indirect    : %u dispatches (%u resolved at runtime)\n"
        "Exit Code   : %d\n"
        "--- Verbatim Guest Output ---\n"
        "%s",
        0x00100b20u,
        ctx.thread_sp_init,
        ctx.heap_base,
        ctx.heap_end,
        ctx.flush_cache_calls,
        ctx.sync_barrier_calls,
        (unsigned long long)ctx.syscalls_dispatched,
        ctx.syscall_lifted_native_count,
        ctx.syscall_service_stub_count,
        ctx.syscall_boundary_intercept_count,
        ctx.indirect_dispatches,
        ctx.indirect_lifted_resolved_count,
        exit_code,
        guest
    );

    ps2_runtime_destroy(&ctx);
    return (*env)->NewStringUTF(env, result_buf);
}

JNIEXPORT jint JNICALL
Java_org_ps2lifter_real_MainActivity_nativeRunAndGetExitCode(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    int exit_code = run_real_program(&ctx);
    if (exit_code <= -100) {
        return (jint)exit_code;
    }
    ps2_runtime_destroy(&ctx);
    return (jint)exit_code;
}
