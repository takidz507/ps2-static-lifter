/*
 * jni_bridge.c — Execution PROBE for the lifted homebrew game "500 Card Game"
 * ==========================================================================
 * Runs the game's statically lifted code (52,294 instructions, 597 functions,
 * 96.16% lifted) from its true entry point 0x001280d0 through the M2.2
 * runtime model and reports exactly how far execution gets and where it
 * stops. This is a measurement instrument, NOT a playable build: the game
 * currently halts inside its own setup() at the first unmodeled EE kernel
 * service (syscall 0x74, SetSyscall). Every modeled service moves the stop
 * point forward on this same screen.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "ps2_runtime.h"
#include "lifted_card500.h"

static const char *reason_name(ps2_stop_reason_t r) {
    switch (r) {
        case PS2_STOP_NONE:                return "NONE";
        case PS2_STOP_CLEAN_EXIT:          return "CLEAN_EXIT";
        case PS2_STOP_BUDGET_EXCEEDED:     return "BUDGET_EXCEEDED";
        case PS2_STOP_UNRESOLVED_INDIRECT: return "UNRESOLVED_INDIRECT";
        case PS2_STOP_NULL_WEAK_CALL:      return "NULL_WEAK_CALL";
        case PS2_STOP_TRAP_EXCEPTION:      return "TRAP_EXCEPTION";
        case PS2_STOP_UNHANDLED_SYSCALL:   return "UNHANDLED_SYSCALL";
        default:                           return "?";
    }
}

/* Run status is kept strictly separate from the guest exit code:
 * a stopped guest legitimately returns negative codes (e.g. -216),
 * which must never be mistaken for a runtime failure. */
typedef enum { RUN_OK = 0, RUN_INIT_FAILED = 1, RUN_MEM_FAILED = 2 } run_status_t;

static run_status_t run_game_probe(ps2_cpu_ctx_t *ctx, int *guest_exit_out) {
    if (ps2_runtime_init(ctx) != 0) {
        return RUN_INIT_FAILED;
    }
    if (ps2_init_guest_memory(ctx) != 0) {
        ps2_runtime_destroy(ctx);
        return RUN_MEM_FAILED;
    }
    *guest_exit_out = ps2_runtime_execute(ctx, fn_001280d0___start);
    return RUN_OK;
}

JNIEXPORT jstring JNICALL
Java_org_ps2lifter_game500_MainActivity_nativeRunLiftedProgram(JNIEnv *env, jobject thiz) {
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    int exit_code = 0;
    run_status_t status = run_game_probe(&ctx, &exit_code);
    if (status == RUN_INIT_FAILED) {
        return (*env)->NewStringUTF(env, "ERROR: PS2 runtime init failed");
    }
    if (status == RUN_MEM_FAILED) {
        return (*env)->NewStringUTF(env, "ERROR: guest memory init failed");
    }

    char guest[600];
    size_t gl = ctx.stdout_len < sizeof(guest) - 1 ? ctx.stdout_len : sizeof(guest) - 1;
    memcpy(guest, ctx.stdout_buf, gl);
    guest[gl] = '\0';

    char result_buf[4096];
    snprintf(
        result_buf,
        sizeof(result_buf),
        "=== PS2 Game 500 - Execution Probe ===\n"
        "NOT playable yet: this probe runs the game's\n"
        "lifted code and reports where it stops.\n"
        "Game        : 500 Card Game (homebrew, legal)\n"
        "Code        : 52,294 instructions / 597 functions\n"
        "Lifted      : 50,286 (96.16%%), 2,008 blockers\n"
        "Entry Point : 0x%08x (_start)\n"
        "Insns Run   : %llu\n"
        "Stopped     : %s at PC 0x%08x\n"
        "Detail      : %s\n"
        "Syscalls    : %llu total (%u lifted / %u service / %u boundary)\n"
        "Indirect    : %u dispatches (%u resolved at runtime)\n"
        "Guest Exit  : %d\n"
        "--- Guest Output So Far ---\n"
        "%s",
        0x001280d0u,
        (unsigned long long)ctx.insn_retired,
        reason_name(ctx.stop_reason),
        ctx.stop_pc,
        ctx.stop_detail,
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
Java_org_ps2lifter_game500_MainActivity_nativeRunAndGetExitCode(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    ps2_cpu_ctx_t ctx;
    int exit_code = 0;
    run_status_t status = run_game_probe(&ctx, &exit_code);
    if (status != RUN_OK) {
        return (jint)-1;
    }
    ps2_runtime_destroy(&ctx);
    return (jint)exit_code;
}
