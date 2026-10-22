/*
 * jni_bridge.c — Minimal JNI Bridge for Lifted PS2 Native Android App (Path C)
 * ============================================================================
 * Invokes the statically lifted `_start` function (`fn_00100000__start`) against
 * the embedded `hello_kernel_min.elf` PT_LOAD image and returns a formatted summary
 * string containing the verbatim guest stdout (`Hello world!\n`) and exit code (`0`)
 * to `org.ps2lifter.m2.MainActivity`.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "ps2_runtime.h"
#include "lifted_hello_kernel_min.h"

JNIEXPORT jstring JNICALL
Java_org_ps2lifter_m2_MainActivity_nativeRunLiftedProgram(JNIEnv *env, jobject thiz) {
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        return (*env)->NewStringUTF(env, "ERROR: ps2_runtime_init failed");
    }

    int load_rc = ps2_load_embedded_hello_kernel_min(&ctx);
    if (load_rc != 0) {
        ps2_runtime_destroy(&ctx);
        return (*env)->NewStringUTF(env, "ERROR: ps2_load_embedded_hello_kernel_min failed");
    }

    int exit_code = ps2_runtime_execute(&ctx, fn_00100000__start);

    char result_buf[4608];
    snprintf(
        result_buf,
        sizeof(result_buf),
        "=== PS2 Static Lifter M2 (Native AOT) ===\n"
        "Entry Point : 0x%08x (_start)\n"
        "Stack Init  : 0x%08x\n"
        "Heap Range  : 0x%08x .. 0x%08x\n"
        "FlushCache  : %u calls (AOT No-op)\n"
        "SyncBarrier : %u calls\n"
        "Exit Code   : %d\n"
        "--- Verbatim Guest Output ---\n"
        "%s",
        LIFTED_ELF_ENTRY_VADDR,
        ctx.thread_sp_init,
        ctx.heap_base,
        ctx.heap_end,
        ctx.flush_cache_calls,
        ctx.sync_barrier_calls,
        exit_code,
        ctx.stdout_buf
    );

    ps2_runtime_destroy(&ctx);
    return (*env)->NewStringUTF(env, result_buf);
}

JNIEXPORT jint JNICALL
Java_org_ps2lifter_m2_MainActivity_nativeRunAndGetExitCode(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) return -1;
    if (ps2_load_embedded_hello_kernel_min(&ctx) != 0) {
        ps2_runtime_destroy(&ctx);
        return -2;
    }
    int exit_code = ps2_runtime_execute(&ctx, fn_00100000__start);
    ps2_runtime_destroy(&ctx);
    return (jint)exit_code;
}
