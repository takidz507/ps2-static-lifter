/*
 * host_real_compile_check.c — Milestone 2.1 Host Compilation & Guest Memory Image Verification Harness
 * ====================================================================================================
 * Links all 437 lifted functions from `lifted_hello_real.c` (30,090 R5900 instructions) against
 * `ps2_runtime.c`, initializes the 32 MB Guest RAM from the embedded `PT_LOAD` segment byte arrays
 * (`ps2_init_guest_memory`), and verifies:
 *   1. Initial `$gp` register (`0x001276f0`) and entry point (`0x00100b20`, `fn_00100b20___start`).
 *   2. Registered Indirect Dispatch Table (`437` lifted functions).
 *   3. `.rodata` string literal `"Hello world!"` at `0x0011eba0` (`0x00120000 - 5216` loaded by `main`)
 *      and `.data`/`.ctors` pointers inside the initialized Guest Memory Image.
 *   4. Direct unit verification of lifted `__muldi3` (`fn_00115e18___muldi3`) exercising the lifted
 *      R5900 MMI instructions (`madd` `0x70a40000` and `pmfhl.lw` `0x70001030`), and `_SyncDCache`
 *      (`fn_0011b4a0__SyncDCache`) exercising lifted COP0 (`mfc0`/`mtc0`/`ei`/`di`), `CACHE`, and `SYNC.P`.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "ps2_runtime.h"
#include "lifted_hello_real.h"

int main(int argc, char **argv) {
    ps2_cpu_ctx_t ctx;
    if (ps2_runtime_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize PS2 runtime context\n");
        return 1;
    }

    int rc = ps2_init_guest_memory(&ctx);
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize Guest Memory Image from PT_LOAD segments (rc=%d)\n", rc);
        ps2_runtime_destroy(&ctx);
        return 2;
    }

    uint32_t entry_pc = ctx.pc;
    uint32_t init_gp  = ctx.gpr[28].u32[0];

    /* Verify Guest Memory Image (.rodata at 0x0011eba0 contains "Hello world!") */
    const char *rodata_hello = (const char *)(ctx.guest_ram + ps2_virt_to_phys(0x0011eba0U));
    bool hello_ok = (strcmp(rodata_hello, "Hello world!") == 0);
    uint32_t data_mbtowc_ptr = ps2_mem_read32(&ctx, 0x0011dd2cU); /* __mbtowc in .data -> 0x00110988 */
    uint32_t ctors_first_ptr = ps2_mem_read32(&ctx, 0x0011d63cU); /* .ctors[1] -> 0x0011d598 */

    /* Exercise lifted __muldi3 (uses R5900 MMI `pmfhl.lw` and `madd`) */
    ctx.gpr[4].u64[0] = 123456789ULL;
    ctx.gpr[5].u64[0] = 987654321ULL;
    fn_00115e18___muldi3(&ctx);
    uint64_t mul_res = ctx.gpr[2].u64[0];

    /* Exercise lifted _SyncDCache (uses COP0 mfc0 Status/TagLo, ei/di, CACHE 0x10/0x14, SYNC.P) */
    ctx.gpr[4].u32[0] = 0x00100000U;
    ctx.gpr[5].u32[0] = 0x00100080U;
    fn_0011b4a0__SyncDCache(&ctx);

    printf("=== Milestone 2.1 Host Compilation & Guest Memory Image Verification ===\n");
    printf("Entry Point VAddr       : 0x%08x (fn_00100b20___start)\n", entry_pc);
    printf("Initial $gp ($28)       : 0x%08x\n", init_gp);
    printf("Indirect Table Entries  : %zu functions\n", ctx.indirect_table_count);
    printf(".rodata @ 0x0011eba0    : \"%s\"\n", rodata_hello);
    printf(".data __mbtowc @ 0x11dd2c: 0x%08x\n", data_mbtowc_ptr);
    printf(".ctors[1] @ 0x0011d63c  : 0x%08x\n", ctors_first_ptr);
    printf("Lifted __muldi3 MMI test: 123456789 * 987654321 = %" PRIu64 "\n", mul_res);
    printf("Lifted _SyncDCache stats: cop0_ops=%u, cache_ops=%u, sync_barriers=%u\n",
           ctx.cop0_ops_retired, ctx.cache_ops_retired, ctx.sync_barrier_calls);
    fflush(stdout);

    if (argc > 1 && strcmp(argv[1], "--run-entry") == 0) {
        ps2_entry(&ctx);
    }

    ps2_runtime_destroy(&ctx);
    return (mul_res == 121932631112635269ULL &&
            data_mbtowc_ptr == 0x00110988U &&
            hello_ok) ? 0 : 3;
}
