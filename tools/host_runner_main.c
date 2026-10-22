/*
 * host_runner_main.c — Host Acceptance Test Harness for Lifted PS2 Executable (M2)
 * ================================================================================
 * Initializes the minimal PS2 runtime (`ps2_cpu_ctx_t`), loads the `PT_LOAD` segments
 * of `hello_kernel_min.elf` into the 32 MB Guest RAM, invokes the lifted `_start`
 * function (`fn_00100000__start`), and returns the exact guest exit code.
 */

#include <stdio.h>
#include "ps2_runtime.h"
#include "lifted_hello_kernel_min.h"

int main(int argc, char **argv) {
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize PS2 runtime context\n");
        return 1;
    }

    int load_rc = 0;
    if (argc > 1) {
        load_rc = ps2_runtime_load_elf(&ctx, argv[1]);
    } else {
        load_rc = ps2_load_embedded_hello_kernel_min(&ctx);
    }
    if (load_rc != 0) {
        fprintf(stderr, "Failed to load ELF image into Guest RAM (rc=%d)\n", load_rc);
        ps2_runtime_destroy(&ctx);
        return 2;
    }

    int exit_code = ps2_runtime_execute(&ctx, fn_00100000__start);
    ps2_runtime_destroy(&ctx);
    return exit_code;
}
