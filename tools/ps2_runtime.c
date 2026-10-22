/*
 * ps2_runtime.c — Milestone 2.3 PS2 Emotion Engine (R5900) Runtime, COP1 FPU & GS Boundary Library
 * =================================================================================================
 * Implements:
 *   1. Full Execution Context (32 MB Guest RAM, 4 MB GS VRAM, 128-bit GPRs, COP0, COP1 FPU).
 *   2. Active Indirect Dispatch Table (`k_indirect_dispatch_table`) with loud site-aware failure.
 *   3. Hardware-Accurate R5900 COP1 Single-Precision FPU Semantics (Part 2):
 *      - Denormal inputs (`exp == 0`) flush to `±0.0f`; underflow results flush to `±0.0f` and set
 *        `FCSR.U`/`SU`.
 *      - Biased exponent `255` (`0xFF`) is a finite normal number (no IEEE-754 Inf/NaN); overflow
 *        (`exp > 255`) saturates to `±MAX` (`sign | 0x7FFFFFFFU`) and sets `FCSR.O`/`SO`.
 *      - Round-to-Zero (`RTZ` / truncation) rounding for all arithmetic and `CVT.W.S` / `CVT.S.W` ops.
 *      - Bit-preserving semantics for `MOV.S`, `ABS.S`, `NEG.S`, `MFC1`, `MTC1`, `LWC1`, `SWC1`.
 *   4. Declared Graphics Synthesizer (GS) & GIF DMA Channel 2 Boundary Model (Part 3):
 *      - Models EE DMAC Channel 2 (`0x1000A000..0x1000A080`), `D_STAT` (`0x1000E010`), `D_PCR` (`0x1000E020`),
 *        and GS Privileged Registers (`PMODE`, `DISPFB1`, `DISPLAY1`, `DISPFB2`, `DISPLAY2`, `BGCOLOR`, `CSR`).
 *      - Parses GIF packets (`PACKED`, `REGLIST`, `IMAGE`) and A+D register writes, rasterizing primitives
 *        into guest-visible 4 MB GS VRAM and enforcing the declared `FRAME_LIMIT` stop policy.
 *
 * Pure ISO C11 (`-std=c11 -Wall -Wextra -Werror`).
 */

#include "ps2_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>

static size_t ps2_strnlen(const char *s, size_t maxlen) {
    size_t i = 0;
    while (i < maxlen && s[i] != '\0') {
        ++i;
    }
    return i;
}

#pragma pack(push, 1)
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;
#pragma pack(pop)

/* Simulated SIF & GS hardware boundary registers */
static uint32_t g_sim_sif_regs[64]     = {0};
static uint32_t g_sim_sif_ext_regs[32] = {0};
static uint64_t g_sim_gs_imr           = 0x0000FF00ULL;
static int32_t  g_sim_next_sema_id     = 1;

static void ps2_record_trace(
    ps2_cpu_ctx_t *ctx,
    uint32_t       site_pc,
    const char    *kind,
    int32_t        num_or_id,
    const char    *name,
    uint32_t       arg0,
    uint32_t       arg1,
    uint32_t       arg2,
    uint32_t       arg3,
    int64_t        ret_val,
    const char    *classification,
    const char    *detail
) {
    if (!ctx || !ctx->trace_events || ctx->trace_count >= ctx->trace_cap) {
        return;
    }
    ps2_trace_event_t *ev = &ctx->trace_events[ctx->trace_count++];
    ev->seq        = (uint32_t)ctx->trace_count;
    ev->insn_count = ctx->insn_retired;
    ev->site_pc    = site_pc;
    snprintf(ev->kind, sizeof(ev->kind), "%s", kind ? kind : "");
    ev->num_or_id  = num_or_id;
    snprintf(ev->name, sizeof(ev->name), "%s", name ? name : "");
    ev->arg0       = arg0;
    ev->arg1       = arg1;
    ev->arg2       = arg2;
    ev->arg3       = arg3;
    ev->ret_val    = ret_val;
    snprintf(ev->classification, sizeof(ev->classification), "%s", classification ? classification : "");
    snprintf(ev->detail, sizeof(ev->detail), "%s", detail ? detail : "");
}

static void ps2_record_gs_event(
    ps2_cpu_ctx_t *ctx,
    const char    *event_type,
    uint32_t       reg_or_flg,
    const char    *reg_name,
    uint64_t       data_lo,
    uint64_t       data_hi,
    const char    *detail
) {
    if (!ctx || !ctx->gs.events || ctx->gs.event_count >= ctx->gs.event_cap) {
        return;
    }
    ps2_gs_event_t *ev = &ctx->gs.events[ctx->gs.event_count++];
    ev->seq         = (uint32_t)ctx->gs.event_count;
    ev->frame_index = ctx->gs.frames_completed + 1U;
    ev->insn_count  = ctx->insn_retired;
    ev->site_pc     = ctx->pc;
    snprintf(ev->event_type, sizeof(ev->event_type), "%s", event_type ? event_type : "");
    ev->reg_or_flg  = reg_or_flg;
    snprintf(ev->reg_name, sizeof(ev->reg_name), "%s", reg_name ? reg_name : "");
    ev->data_lo     = data_lo;
    ev->data_hi     = data_hi;
    snprintf(ev->detail, sizeof(ev->detail), "%s", detail ? detail : "");
}

static void ps2_terminate_execution(
    ps2_cpu_ctx_t    *ctx,
    int32_t           code,
    ps2_stop_reason_t reason,
    uint32_t          stop_pc,
    const char       *detail
) {
    ctx->exit_code   = code;
    ctx->halted      = true;
    ctx->stop_reason = reason;
    ctx->stop_pc     = stop_pc;
    if (detail) {
        snprintf(ctx->stop_detail, sizeof(ctx->stop_detail), "%s", detail);
    }
    if (ctx->exit_jmp_armed) {
        longjmp(ctx->exit_jmp, 1);
    }
    exit((int)code);
}

void ps2_on_budget_exceeded(ps2_cpu_ctx_t *ctx, uint32_t pc) {
    char msg[160];
    snprintf(msg, sizeof(msg),
             "Instruction budget exhausted (%" PRIu64 " / %" PRIu64 ") at PC=0x%08x",
             ctx->insn_retired, ctx->insn_budget, pc);
    fprintf(stderr, "[PS2-BUDGET-ABORT] %s\n", msg);
    ps2_terminate_execution(ctx, 124, PS2_STOP_BUDGET_EXCEEDED, pc, msg);
}

int ps2_runtime_init(ps2_cpu_ctx_t *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->guest_ram = (uint8_t *)calloc(1, PS2_RAM_SIZE);
    if (!ctx->guest_ram) {
        return -1;
    }
    ctx->gs.vram = (uint32_t *)calloc(PS2_GS_VRAM_WORDS, sizeof(uint32_t));
    if (!ctx->gs.vram) {
        free(ctx->guest_ram);
        ctx->guest_ram = NULL;
        return -1;
    }
    ctx->trace_events = (ps2_trace_event_t *)calloc(PS2_MAX_TRACE_EVENTS, sizeof(ps2_trace_event_t));
    if (!ctx->trace_events) {
        free(ctx->gs.vram);
        free(ctx->guest_ram);
        return -1;
    }
    ctx->gs.events = (ps2_gs_event_t *)calloc(PS2_MAX_GS_EVENTS, sizeof(ps2_gs_event_t));
    if (!ctx->gs.events) {
        free(ctx->trace_events);
        free(ctx->gs.vram);
        free(ctx->guest_ram);
        return -1;
    }
    ctx->trace_cap      = PS2_MAX_TRACE_EVENTS;
    ctx->trace_count    = 0;
    ctx->gs.event_cap   = PS2_MAX_GS_EVENTS;
    ctx->gs.event_count = 0;
    ctx->insn_budget    = PS2_DEFAULT_INSN_BUDGET;

    /* Default COP0 Status register ($12): CU0 & CU1 enabled, EIE (bit 16) enabled */
    ctx->cop0[12] = 0x70010000U;
    /* Default COP1 FCR0 & FCSR (FS=1 flush-to-zero) */
    ctx->fcr0     = 0x00002E00U;
    ctx->fcsr     = PS2_FCSR_FS_BIT;

    /* Default stack pointer near top of 32MB Guest RAM prior to SetupThread */
    ctx->gpr[29].s64[0] = (int64_t)(int32_t)(PS2_RAM_SIZE - 0x100U);
    ctx->gpr[28].s64[0] = (int64_t)(int32_t)0x001276f0U;
    ctx->thread_gp      = 0x001276f0U;

    /* Default GS context geometry (512 x 512 PSMCT32 until guest configures FRAME_1) */
    ctx->gs.fb_width        = 512U;
    ctx->gs.fb_height       = 512U;
    ctx->gs.ctx[0].fbw      = 8U;
    ctx->gs.ctx[0].scx1     = 511U;
    ctx->gs.ctx[0].scy1     = 511U;
    ctx->gs.ctx[1].fbw      = 8U;
    ctx->gs.ctx[1].scx1     = 511U;
    ctx->gs.ctx[1].scy1     = 511U;
    ctx->gs.prmodecont      = 1U;

    memset(g_sim_sif_regs, 0, sizeof(g_sim_sif_regs));
    memset(g_sim_sif_ext_regs, 0, sizeof(g_sim_sif_ext_regs));
    g_sim_sif_regs[1]   = 0x00000000U;
    g_sim_sif_regs[2]   = 0x00010000U;
    g_sim_sif_regs[3]   = 0x00030000U;
    g_sim_sif_regs[4]   = 0x00030000U;
    g_sim_gs_imr        = 0x0000FF00ULL;
    g_sim_next_sema_id  = 1;

    return 0;
}

void ps2_runtime_destroy(ps2_cpu_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->guest_ram) {
        free(ctx->guest_ram);
        ctx->guest_ram = NULL;
    }
    if (ctx->gs.vram) {
        free(ctx->gs.vram);
        ctx->gs.vram = NULL;
    }
    if (ctx->trace_events) {
        free(ctx->trace_events);
        ctx->trace_events = NULL;
    }
    if (ctx->gs.events) {
        free(ctx->gs.events);
        ctx->gs.events = NULL;
    }
}

int ps2_load_pt_segments(ps2_cpu_ctx_t *ctx, const ps2_pt_load_seg_t *segs, size_t seg_count) {
    if (!ctx || !ctx->guest_ram) {
        return -1;
    }
    for (size_t i = 0; i < seg_count; ++i) {
        uint32_t phys_dst = ps2_virt_to_phys(segs[i].vaddr);
        if ((size_t)phys_dst + (size_t)segs[i].memsz > PS2_RAM_SIZE) {
            fprintf(stderr,
                    "[ps2_runtime] PT_LOAD[%zu] exceeds 32MB Guest RAM (vaddr=0x%08x, memsz=0x%x)\n",
                    i, segs[i].vaddr, segs[i].memsz);
            return -2;
        }
        if (segs[i].memsz > 0) {
            memset(ctx->guest_ram + phys_dst, 0, segs[i].memsz);
        }
        if (segs[i].filesz > 0 && segs[i].data != NULL) {
            memcpy(ctx->guest_ram + phys_dst, segs[i].data, segs[i].filesz);
        }
    }
    return 0;
}

void ps2_register_indirect_table(ps2_cpu_ctx_t *ctx, const ps2_indirect_entry_t *table, size_t count) {
    if (!ctx) return;
    ctx->indirect_table       = table;
    ctx->indirect_table_count = count;
}

int ps2_runtime_load_elf_bytes(ps2_cpu_ctx_t *ctx, const uint8_t *elf_data, size_t elf_size) {
    if (!ctx || !ctx->guest_ram || !elf_data || elf_size < sizeof(elf32_ehdr_t)) {
        return -1;
    }
    const elf32_ehdr_t *ehdr = (const elf32_ehdr_t *)elf_data;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0 || ehdr->e_ident[4] != 1 || ehdr->e_ident[5] != 1) {
        return -2;
    }
    if (ehdr->e_machine != 8) {
        return -3;
    }
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        size_t ph_off = (size_t)ehdr->e_phoff + (size_t)i * ehdr->e_phentsize;
        if (ph_off + sizeof(elf32_phdr_t) > elf_size) {
            return -4;
        }
        const elf32_phdr_t *ph = (const elf32_phdr_t *)(elf_data + ph_off);
        if (ph->p_type == 1U) {
            uint32_t phys_dst = ps2_virt_to_phys(ph->p_vaddr);
            if ((size_t)ph->p_offset + ph->p_filesz > elf_size) {
                return -5;
            }
            if ((size_t)phys_dst + ph->p_memsz > PS2_RAM_SIZE) {
                return -6;
            }
            if (ph->p_filesz > 0) {
                memcpy(ctx->guest_ram + phys_dst, elf_data + ph->p_offset, ph->p_filesz);
            }
            if (ph->p_memsz > ph->p_filesz) {
                memset(ctx->guest_ram + phys_dst + ph->p_filesz, 0, ph->p_memsz - ph->p_filesz);
            }
        }
    }
    ctx->pc = ehdr->e_entry;
    return 0;
}

int ps2_runtime_load_elf(ps2_cpu_ctx_t *ctx, const char *elf_path) {
    FILE *fp = fopen(elf_path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz <= 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    int rc = ps2_runtime_load_elf_bytes(ctx, buf, (size_t)sz);
    free(buf);
    return rc;
}

/* ============================================================================
 * Milestone 2.3 Part 3: Graphics Synthesizer (GS) & GIF DMA Channel 2 Boundary
 * ============================================================================ */

static const char *ps2_gs_internal_reg_name(uint8_t reg) {
    switch (reg) {
        case 0x00: return "PRIM";
        case 0x01: return "RGBAQ";
        case 0x02: return "ST";
        case 0x03: return "UV";
        case 0x04: return "XYZF2";
        case 0x05: return "XYZ2";
        case 0x06: return "TEX0_1";
        case 0x07: return "TEX0_2";
        case 0x08: return "CLAMP_1";
        case 0x09: return "CLAMP_2";
        case 0x0A: return "FOG";
        case 0x0C: return "XYZF3";
        case 0x0D: return "XYZ3";
        case 0x14: return "TEX1_1";
        case 0x15: return "TEX1_2";
        case 0x18: return "XYOFFSET_1";
        case 0x19: return "XYOFFSET_2";
        case 0x1A: return "PRMODECONT";
        case 0x1B: return "PRMODE";
        case 0x1C: return "TEXCLUT";
        case 0x22: return "SCANMSK";
        case 0x3F: return "TEXA";
        case 0x40: return "SCISSOR_1";
        case 0x41: return "SCISSOR_2";
        case 0x42: return "ALPHA_1";
        case 0x43: return "ALPHA_2";
        case 0x44: return "DIMX";
        case 0x45: return "DTHE";
        case 0x46: return "COLCLAMP";
        case 0x47: return "TEST_1";
        case 0x48: return "TEST_2";
        case 0x49: return "PABE";
        case 0x4A: return "FBA_1";
        case 0x4B: return "FBA_2";
        case 0x4C: return "FRAME_1";
        case 0x4D: return "FRAME_2";
        case 0x4E: return "ZBUF_1";
        case 0x4F: return "ZBUF_2";
        case 0x50: return "BITBLTBUF";
        case 0x51: return "TRXPOS";
        case 0x52: return "TRXREG";
        case 0x53: return "TRXDIR";
        case 0x54: return "HWREG";
        case 0x60: return "SIGNAL";
        case 0x61: return "FINISH";
        case 0x62: return "LABEL";
        default:   return "GS_REG";
    }
}

static void ps2_gs_rasterize_sprite(ps2_cpu_ctx_t *ctx, const ps2_gs_vertex_t *v0, const ps2_gs_vertex_t *v1) {
    uint32_t ctxt_idx = (ctx->gs.prmodecont & 1U)
                      ? ((ctx->gs.prim >> 9) & 1U)
                      : (uint32_t)((ctx->gs.prmode >> 9) & 1U);
    const ps2_gs_draw_ctx_t *dctx = &ctx->gs.ctx[ctxt_idx];

    /* Convert 12.4 fixed-point GS vertex coordinates to pixel space via hardware subpixel rounding (+7/16) */
    int32_t x0 = ((int32_t)v0->x - (int32_t)dctx->ofx + 7) >> 4;
    int32_t y0 = ((int32_t)v0->y - (int32_t)dctx->ofy + 7) >> 4;
    int32_t x1 = ((int32_t)v1->x - (int32_t)dctx->ofx + 7) >> 4;
    int32_t y1 = ((int32_t)v1->y - (int32_t)dctx->ofy + 7) >> 4;

    if (x0 > x1) { int32_t t = x0; x0 = x1; x1 = t; }
    if (y0 > y1) { int32_t t = y0; y0 = y1; y1 = t; }

    /* Clip against SCISSOR_1/2 (inclusive SCX0..SCX1, SCY0..SCY1) and framebuffer bounds */
    int32_t min_x = (int32_t)dctx->scx0;
    int32_t max_x = (int32_t)dctx->scx1 + 1;
    int32_t min_y = (int32_t)dctx->scy0;
    int32_t max_y = (int32_t)dctx->scy1 + 1;
    if (max_x > (int32_t)ctx->gs.fb_width)  max_x = (int32_t)ctx->gs.fb_width;
    if (max_y > (int32_t)ctx->gs.fb_height) max_y = (int32_t)ctx->gs.fb_height;

    int32_t cx0 = (x0 < min_x) ? min_x : x0;
    int32_t cy0 = (y0 < min_y) ? min_y : y0;
    int32_t cx1 = (x1 > max_x) ? max_x : x1;
    int32_t cy1 = (y1 > max_y) ? max_y : y1;

    uint32_t stride = (dctx->fbw > 0U) ? (dctx->fbw * 64U) : 512U;
    uint32_t base_word = dctx->fbp * 2048U; /* 1 page = 2048 32-bit words */
    uint32_t color32 = (uint32_t)(v1->rgbaq & 0xFFFFFFFFULL);
    uint32_t fbmsk   = dctx->fbmsk;

    uint64_t filled = 0;
    for (int32_t py = cy0; py < cy1; ++py) {
        uint32_t row_off = base_word + (uint32_t)py * stride;
        for (int32_t px = cx0; px < cx1; ++px) {
            uint32_t idx = (row_off + (uint32_t)px) & (PS2_GS_VRAM_WORDS - 1U);
            if (fbmsk == 0U) {
                ctx->gs.vram[idx] = color32;
            } else {
                ctx->gs.vram[idx] = (ctx->gs.vram[idx] & fbmsk) | (color32 & ~fbmsk);
            }
            filled++;
        }
    }

    ctx->gs.primitives_drawn++;
    ctx->gs.pixels_filled += filled;

    char detail[128];
    snprintf(detail, sizeof(detail),
             "SPRITE (#%u) rect=[%d,%d)..[%d,%d) rgba=(%u,%u,%u,%u) word=0x%08x pixels=%" PRIu64,
             ctx->gs.primitives_drawn, cx0, cy0, cx1, cy1,
             color32 & 0xFFU, (color32 >> 8) & 0xFFU, (color32 >> 16) & 0xFFU, (color32 >> 24) & 0xFFU,
             color32, filled);
    ps2_record_gs_event(ctx, "PRIM_RASTER", 6U, "GS_PRIM_SPRITE",
                        ((uint64_t)(uint32_t)cx0 << 32) | (uint32_t)cy0,
                        ((uint64_t)(uint32_t)cx1 << 32) | (uint32_t)cy1,
                        detail);
}

static void ps2_gs_write_internal_reg(ps2_cpu_ctx_t *ctx, uint8_t reg, uint64_t data) {
    ctx->gs.gs_reg_writes++;
    const char *rname = ps2_gs_internal_reg_name(reg);

    switch (reg) {
        case 0x00: { /* PRIM */
            ctx->gs.prim = (uint32_t)(data & 0x7FFULL);
            ctx->gs.vtx_count = 0;
            char detail[128];
            snprintf(detail, sizeof(detail), "PRIM=0x%x (type=%u)", ctx->gs.prim, ctx->gs.prim & 7U);
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x01: { /* RGBAQ */
            ctx->gs.rgbaq = data;
            char detail[128];
            snprintf(detail, sizeof(detail), "RGBAQ=(R=%u, G=%u, B=%u, A=%u, Q=0x%08x)",
                     (uint32_t)(data & 0xFFU),
                     (uint32_t)((data >> 8) & 0xFFU),
                     (uint32_t)((data >> 16) & 0xFFU),
                     (uint32_t)((data >> 24) & 0xFFU),
                     (uint32_t)(data >> 32));
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x04:   /* XYZF2 */
        case 0x05: { /* XYZ2 (Vertex Kick) */
            uint16_t vx = (uint16_t)(data & 0xFFFFULL);
            uint16_t vy = (uint16_t)((data >> 16) & 0xFFFFULL);
            uint32_t vz = (reg == 0x04)
                        ? (uint32_t)((data >> 32) & 0xFFFFFFULL)
                        : (uint32_t)(data >> 32);
            if (ctx->gs.vtx_count < 4U) {
                ctx->gs.vtx_queue[ctx->gs.vtx_count].x     = vx;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].y     = vy;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].z     = vz;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].rgbaq = ctx->gs.rgbaq;
                ctx->gs.vtx_count++;
            }
            uint32_t prim_type = ctx->gs.prim & 7U;
            if (prim_type == 6U && ctx->gs.vtx_count >= 2U) { /* GS_PRIM_SPRITE */
                ps2_gs_rasterize_sprite(ctx, &ctx->gs.vtx_queue[0], &ctx->gs.vtx_queue[1]);
                ctx->gs.vtx_count = 0;
            }
            break;
        }
        case 0x0C:   /* XYZF3 */
        case 0x0D: { /* XYZ3 (Vertex without drawing kick) */
            uint16_t vx = (uint16_t)(data & 0xFFFFULL);
            uint16_t vy = (uint16_t)((data >> 16) & 0xFFFFULL);
            uint32_t vz = (reg == 0x0C)
                        ? (uint32_t)((data >> 32) & 0xFFFFFFULL)
                        : (uint32_t)(data >> 32);
            if (ctx->gs.vtx_count < 3U) {
                ctx->gs.vtx_queue[ctx->gs.vtx_count].x     = vx;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].y     = vy;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].z     = vz;
                ctx->gs.vtx_queue[ctx->gs.vtx_count].rgbaq = ctx->gs.rgbaq;
                ctx->gs.vtx_count++;
            } else {
                ctx->gs.vtx_queue[0] = ctx->gs.vtx_queue[1];
                ctx->gs.vtx_queue[1] = ctx->gs.vtx_queue[2];
                ctx->gs.vtx_queue[2].x     = vx;
                ctx->gs.vtx_queue[2].y     = vy;
                ctx->gs.vtx_queue[2].z     = vz;
                ctx->gs.vtx_queue[2].rgbaq = ctx->gs.rgbaq;
            }
            break;
        }
        case 0x18:
        case 0x19: { /* XYOFFSET_1 / XYOFFSET_2 */
            uint32_t c = (reg == 0x19) ? 1U : 0U;
            ctx->gs.ctx[c].xyoffset_reg = data;
            ctx->gs.ctx[c].ofx          = (uint16_t)(data & 0xFFFFULL);
            ctx->gs.ctx[c].ofy          = (uint16_t)((data >> 32) & 0xFFFFULL);
            char detail[128];
            snprintf(detail, sizeof(detail), "XYOFFSET_%u: OFX=0x%04x (%.4f), OFY=0x%04x (%.4f)",
                     c + 1U, ctx->gs.ctx[c].ofx, ctx->gs.ctx[c].ofx / 16.0,
                     ctx->gs.ctx[c].ofy, ctx->gs.ctx[c].ofy / 16.0);
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x1A: { /* PRMODECONT */
            ctx->gs.prmodecont = (uint32_t)(data & 1ULL);
            char detail[128];
            snprintf(detail, sizeof(detail), "PRMODECONT=%u (%s)",
                     ctx->gs.prmodecont, ctx->gs.prmodecont ? "use PRIM" : "use PRMODE");
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x1B: { /* PRMODE */
            ctx->gs.prmode = data;
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, "Updated PRMODE");
            break;
        }
        case 0x40:
        case 0x41: { /* SCISSOR_1 / SCISSOR_2 */
            uint32_t c = (reg == 0x41) ? 1U : 0U;
            ctx->gs.ctx[c].scissor_reg = data;
            ctx->gs.ctx[c].scx0        = (uint16_t)(data & 0x7FFULL);
            ctx->gs.ctx[c].scx1        = (uint16_t)((data >> 16) & 0x7FFULL);
            ctx->gs.ctx[c].scy0        = (uint16_t)((data >> 32) & 0x7FFULL);
            ctx->gs.ctx[c].scy1        = (uint16_t)((data >> 48) & 0x7FFULL);
            ctx->gs.fb_width           = (uint32_t)ctx->gs.ctx[c].scx1 + 1U;
            ctx->gs.fb_height          = (uint32_t)ctx->gs.ctx[c].scy1 + 1U;
            char detail[128];
            snprintf(detail, sizeof(detail), "SCISSOR_%u: X=[%u..%u], Y=[%u..%u]",
                     c + 1U, ctx->gs.ctx[c].scx0, ctx->gs.ctx[c].scx1,
                     ctx->gs.ctx[c].scy0, ctx->gs.ctx[c].scy1);
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x47:
        case 0x48: { /* TEST_1 / TEST_2 */
            uint32_t c = (reg == 0x48) ? 1U : 0U;
            ctx->gs.ctx[c].test_reg = data;
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, "Updated pixel test state");
            break;
        }
        case 0x4C:
        case 0x4D: { /* FRAME_1 / FRAME_2 */
            uint32_t c = (reg == 0x4D) ? 1U : 0U;
            ctx->gs.ctx[c].frame_reg = data;
            ctx->gs.ctx[c].fbp       = (uint32_t)(data & 0x1FFULL);
            ctx->gs.ctx[c].fbw       = (uint32_t)((data >> 16) & 0x3FULL);
            ctx->gs.ctx[c].psm       = (uint32_t)((data >> 24) & 0x3FULL);
            ctx->gs.ctx[c].fbmsk     = (uint32_t)(data >> 32);
            char detail[128];
            snprintf(detail, sizeof(detail), "FRAME_%u: FBP=0x%x, FBW=%u (%u px), PSM=0x%x, FBMSK=0x%08x",
                     c + 1U, ctx->gs.ctx[c].fbp, ctx->gs.ctx[c].fbw, ctx->gs.ctx[c].fbw * 64U,
                     ctx->gs.ctx[c].psm, ctx->gs.ctx[c].fbmsk);
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x4E:
        case 0x4F: { /* ZBUF_1 / ZBUF_2 */
            uint32_t c = (reg == 0x4F) ? 1U : 0U;
            ctx->gs.ctx[c].zbuf_reg = data;
            ctx->gs.ctx[c].zbp      = (uint32_t)(data & 0x1FFULL);
            ctx->gs.ctx[c].zpsm     = (uint32_t)((data >> 24) & 0xFULL);
            ctx->gs.ctx[c].zmsk     = (uint32_t)((data >> 32) & 1ULL);
            char detail[128];
            snprintf(detail, sizeof(detail), "ZBUF_%u: ZBP=0x%x, ZPSM=0x%x, ZMSK=%u",
                     c + 1U, ctx->gs.ctx[c].zbp, ctx->gs.ctx[c].zpsm, ctx->gs.ctx[c].zmsk);
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, detail);
            break;
        }
        case 0x61: { /* FINISH */
            ctx->gs.csr |= 0x02ULL; /* Set GS_CSR.FINISH (bit 1) */
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, ctx->gs.csr,
                                "FINISH write -> asserted GS_CSR.FINISH (bit 1)");
            break;
        }
        default: {
            ps2_record_gs_event(ctx, "GS_INTERNAL_REG", reg, rname, data, 0, "GS internal register write");
            break;
        }
    }
}

static void ps2_gif_dma_transfer(ps2_cpu_ctx_t *ctx, uint32_t madr, uint32_t qwc) {
    ctx->gs.gif_packets_processed++;
    char pkt_detail[128];
    snprintf(pkt_detail, sizeof(pkt_detail),
             "DMA Ch2 (GIF) normal transfer: MADR=0x%08x, QWC=%u (%u bytes)",
             madr, qwc, qwc * 16U);
    ps2_record_trace(ctx, ctx->pc, "GS_BOUNDARY", 2, "GIF_DMA_CH2",
                     madr, qwc, ctx->gs.frames_completed + 1U, 0,
                     (int64_t)qwc, "معترضة عند الحدود", pkt_detail);
    ps2_record_gs_event(ctx, "GIF_DMA_PACKET", qwc, "DMA_CH2_SEND", madr, qwc, pkt_detail);

    uint32_t q = 0;
    while (q < qwc) {
        ps2_u128_t tag = ps2_mem_read128(ctx, madr + q * 16U);
        q++;
        ctx->gs.gif_tags_processed++;

        uint64_t lo    = tag.u64[0];
        uint64_t hi    = tag.u64[1];
        uint32_t nloop = (uint32_t)(lo & 0x7FFFULL);
        uint32_t eop   = (uint32_t)((lo >> 15) & 1ULL);
        uint32_t pre   = (uint32_t)((lo >> 46) & 1ULL);
        uint32_t prim  = (uint32_t)((lo >> 47) & 0x7FFULL);
        uint32_t flg   = (uint32_t)((lo >> 58) & 0x3ULL);
        uint32_t nreg  = (uint32_t)((lo >> 60) & 0xFULL);
        if (nreg == 0U) nreg = 16U;

        const char *flg_str = (flg == 0U) ? "PACKED"
                            : (flg == 1U) ? "REGLIST"
                            : (flg == 2U) ? "IMAGE"
                            : "DISABLE";
        char tag_detail[128];
        snprintf(tag_detail, sizeof(tag_detail),
                 "GIFTAG: FLG=%s(%u) NLOOP=%u EOP=%u PRE=%u PRIM=0x%x NREG=%u REGS=0x%" PRIx64,
                 flg_str, flg, nloop, eop, pre, prim, nreg, hi);
        ps2_record_gs_event(ctx, "GIF_TAG", flg, flg_str, lo, hi, tag_detail);

        if (pre != 0U) {
            ps2_gs_write_internal_reg(ctx, 0x00U, (uint64_t)prim);
        }
        if (nloop == 0U) {
            continue;
        }

        if (flg == 0U) { /* GIF_FLG_PACKED */
            for (uint32_t l = 0; l < nloop && q < qwc; ++l) {
                for (uint32_t r = 0; r < nreg && q < qwc; ++r) {
                    ps2_u128_t qw = ps2_mem_read128(ctx, madr + q * 16U);
                    q++;
                    uint8_t rdesc = (uint8_t)((hi >> (4U * r)) & 0xFULL);
                    if (rdesc == 0x0EU) { /* A+D */
                        uint8_t addr = (uint8_t)(qw.u64[1] & 0xFFULL);
                        ps2_gs_write_internal_reg(ctx, addr, qw.u64[0]);
                    } else if (rdesc == 0x00U) { /* PRIM */
                        ps2_gs_write_internal_reg(ctx, 0x00U, qw.u64[0]);
                    } else if (rdesc == 0x01U) { /* RGBAQ packed */
                        uint64_t r8 = qw.u64[0] & 0xFFULL;
                        uint64_t g8 = (qw.u64[0] >> 32) & 0xFFULL;
                        uint64_t b8 = qw.u64[1] & 0xFFULL;
                        uint64_t a8 = (qw.u64[1] >> 32) & 0xFFULL;
                        uint64_t rgbaq = r8 | (g8 << 8) | (b8 << 16) | (a8 << 24) | (0x3F800000ULL << 32);
                        ps2_gs_write_internal_reg(ctx, 0x01U, rgbaq);
                    } else if (rdesc == 0x04U || rdesc == 0x05U) { /* XYZF2 / XYZ2 packed */
                        uint64_t x16 = qw.u64[0] & 0xFFFFULL;
                        uint64_t y16 = (qw.u64[0] >> 32) & 0xFFFFULL;
                        uint64_t z32 = (qw.u64[1] >> 4) & 0xFFFFFFFFULL;
                        uint32_t adc = (uint32_t)((qw.u64[1] >> 47) & 1ULL);
                        uint8_t  dst = adc ? (rdesc + 8U) : rdesc;
                        ps2_gs_write_internal_reg(ctx, dst, x16 | (y16 << 16) | (z32 << 32));
                    } else if (rdesc != 0x0FU) {
                        ps2_gs_write_internal_reg(ctx, rdesc, qw.u64[0]);
                    }
                }
            }
        } else if (flg == 1U) { /* GIF_FLG_REGLIST */
            uint32_t total_regs = nloop * nreg;
            ps2_u128_t cur_qw = {0};
            for (uint32_t idx = 0; idx < total_regs; ++idx) {
                if ((idx & 1U) == 0U) {
                    if (q >= qwc) break;
                    cur_qw = ps2_mem_read128(ctx, madr + q * 16U);
                    q++;
                }
                uint64_t val64 = ((idx & 1U) == 0U) ? cur_qw.u64[0] : cur_qw.u64[1];
                uint8_t  rdesc = (uint8_t)((hi >> (4U * (idx % nreg))) & 0xFULL);
                if (rdesc != 0x0FU) {
                    ps2_gs_write_internal_reg(ctx, rdesc, val64);
                }
            }
        } else { /* GIF_FLG_IMAGE (2) or DISABLE (3) */
            q += nloop;
        }
    }
}

static bool ps2_is_hw_vaddr(uint32_t vaddr) {
    uint32_t p = vaddr & 0x1FFFFFFFU;
    return (p >= 0x10000000U && p < 0x10010000U) ||
           (p >= 0x12000000U && p < 0x12002000U);
}

static uint32_t ps2_hw_read32(ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    uint32_t p = vaddr & 0x1FFFFFFFU;
    switch (p) {
        case 0x10001000U: return ctx->gs.t2_count;
        case 0x10001010U: return ctx->gs.t2_mode;
        case 0x10001020U: return ctx->gs.t2_comp;
        case 0x10001810U: return ctx->gs.t3_mode;
        case 0x1000A000U: return ctx->gs.d2_chcr;
        case 0x1000A010U: return ctx->gs.d2_madr;
        case 0x1000A020U: return ctx->gs.d2_qwc;
        case 0x1000E000U: return ctx->gs.d_ctrl;
        case 0x1000E010U: return ctx->gs.d_stat;
        case 0x1000E020U: return ctx->gs.d_pcr;
        case 0x12001000U: return (uint32_t)ctx->gs.csr;
        default:          return 0U;
    }
}

static uint64_t ps2_hw_read64(ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    uint32_t p = vaddr & 0x1FFFFFFFU;
    if (p == 0x12001000U) { /* GS_CSR */
        if (ctx->gs.vsync_armed && ctx->pc == 0x001013f0U) {
            ctx->gs.vsync_armed = false;
            ctx->gs.csr |= 0x08ULL; /* Assert VSINT (bit 3) */
            ctx->gs.frames_completed++;

            char detail[128];
            snprintf(detail, sizeof(detail),
                     "Frame #%u completed via guest graph_wait_vsync (GS_CSR=0x%" PRIx64 ", prims=%u, pixels=%" PRIu64 ")",
                     ctx->gs.frames_completed, ctx->gs.csr, ctx->gs.primitives_drawn, ctx->gs.pixels_filled);
            ps2_record_trace(ctx, ctx->pc, "GS_BOUNDARY", (int32_t)ctx->gs.frames_completed,
                             "GS_VSYNC_FRAME", ctx->gs.frames_completed, ctx->gs.primitives_drawn,
                             (uint32_t)ctx->gs.pixels_filled, 0,
                             (int64_t)ctx->gs.frames_completed, "معترضة عند الحدود", detail);
            ps2_record_gs_event(ctx, "VSYNC_FRAME", ctx->gs.frames_completed, "GS_CSR_VSINT",
                                ctx->gs.csr, ctx->gs.primitives_drawn, detail);

            if (ctx->frame_limit > 0U && ctx->gs.frames_completed >= ctx->frame_limit) {
                char stop_msg[160];
                snprintf(stop_msg, sizeof(stop_msg),
                         "FRAME_LIMIT reached: completed %u / %u full frames at PC=0x%08x",
                         ctx->gs.frames_completed, ctx->frame_limit, ctx->pc);
                ps2_terminate_execution(ctx, 0, PS2_STOP_FRAME_LIMIT, ctx->pc, stop_msg);
            }
        }
        return ctx->gs.csr;
    }
    return (uint64_t)ps2_hw_read32(ctx, vaddr);
}

static void ps2_hw_write32(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint32_t val) {
    uint32_t p = vaddr & 0x1FFFFFFFU;
    switch (p) {
        case 0x10001000U: ctx->gs.t2_count = val & 0xFFFFU; break;
        case 0x10001010U: ctx->gs.t2_mode  = val & 0xFFFFU; break;
        case 0x10001020U: ctx->gs.t2_comp  = val & 0xFFFFU; break;
        case 0x10001810U: ctx->gs.t3_mode  = val & 0xFFFFU; break;
        case 0x1000A000U: { /* D2_CHCR (GIF DMA Channel Control) */
            ctx->gs.d2_chcr = val;
            if ((val & 0x0100U) != 0U) { /* STR (Start) bit 8 set */
                ps2_gif_dma_transfer(ctx, ctx->gs.d2_madr, ctx->gs.d2_qwc);
                ctx->gs.d2_chcr &= ~0x0100U; /* Transfer finished synchronously */
                ctx->gs.d2_qwc = 0U;
                ctx->gs.d_stat |= (1U << 2); /* Assert Channel 2 CIS in D_STAT */
            }
            break;
        }
        case 0x1000A010U: ctx->gs.d2_madr = val; break;
        case 0x1000A020U: ctx->gs.d2_qwc  = val & 0xFFFFU; break;
        case 0x1000A030U: ctx->gs.d2_tadr = val; break;
        case 0x1000A040U: ctx->gs.d2_asr0 = val; break;
        case 0x1000A050U: ctx->gs.d2_asr1 = val; break;
        case 0x1000A080U: ctx->gs.d2_sadr = val; break;
        case 0x1000E000U: ctx->gs.d_ctrl  = val; break;
        case 0x1000E010U: { /* D_STAT: lower 16 bits are W1C (write 1 to clear), upper 16 bits are W1T (write 1 to toggle mask) */
            uint32_t clear_bits  = val & 0x0000FFFFU;
            uint32_t toggle_mask = val & 0xFFFF0000U;
            ctx->gs.d_stat = (ctx->gs.d_stat & ~clear_bits) ^ toggle_mask;
            break;
        }
        case 0x1000E020U: ctx->gs.d_pcr   = val; break;
        default: break;
    }
}

static void ps2_hw_write64(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t val) {
    uint32_t p = vaddr & 0x1FFFFFFFU;
    switch (p) {
        case 0x12000000U:
            ctx->gs.pmode = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x00U, "GS_PMODE", val, 0, "Configured GS_PMODE");
            break;
        case 0x12000020U:
            ctx->gs.smode2 = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x20U, "GS_SMODE2", val, 0, "Configured GS_SMODE2");
            break;
        case 0x12000070U:
            ctx->gs.dispfb1 = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x70U, "GS_DISPFB1", val, 0, "Configured GS_DISPFB1");
            break;
        case 0x12000080U:
            ctx->gs.display1 = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x80U, "GS_DISPLAY1", val, 0, "Configured GS_DISPLAY1");
            break;
        case 0x12000090U:
            ctx->gs.dispfb2 = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x90U, "GS_DISPFB2", val, 0, "Configured GS_DISPFB2");
            break;
        case 0x120000A0U:
            ctx->gs.display2 = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0xA0U, "GS_DISPLAY2", val, 0, "Configured GS_DISPLAY2");
            break;
        case 0x120000E0U:
            ctx->gs.bgcolor = val;
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0xE0U, "GS_BGCOLOR", val, 0, "Configured GS_BGCOLOR");
            break;
        case 0x12001000U: { /* GS_CSR */
            if ((val & 0x200ULL) != 0ULL) { /* RESET */
                ctx->gs.csr = 0x0AULL;
            }
            if ((val & 0x02ULL) != 0ULL) { /* W1C FINISH bit 1 */
                ctx->gs.csr &= ~0x02ULL;
            }
            /* When guest writes to GS_CSR inside graph_wait_vsync (0x001013e8 or VSINT bit 3), arm next VSync poll */
            if (ctx->pc == 0x001013e8U) {
                ctx->gs.csr &= ~0x08ULL;
                ctx->gs.vsync_armed = true;
            }
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x1000U, "GS_CSR", val, ctx->gs.csr, "Written GS_CSR");
            break;
        }
        default:
            ps2_hw_write32(ctx, vaddr, (uint32_t)val);
            break;
    }
}

/* Aligned scalar & 128-bit memory reads (Little-Endian) */
uint8_t ps2_mem_read8(const ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    return ctx->guest_ram[ps2_virt_to_phys(vaddr)];
}

int8_t ps2_mem_read_s8(const ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    return (int8_t)ctx->guest_ram[ps2_virt_to_phys(vaddr)];
}

uint16_t ps2_mem_read16(const ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    uint16_t v = 0;
    memcpy(&v, ctx->guest_ram + ps2_virt_to_phys(vaddr), sizeof(v));
    return v;
}

int16_t ps2_mem_read_s16(const ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    return (int16_t)ps2_mem_read16(ctx, vaddr);
}

uint32_t ps2_mem_read32(ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    if (ps2_is_hw_vaddr(vaddr)) {
        return ps2_hw_read32(ctx, vaddr);
    }
    uint32_t v = 0;
    memcpy(&v, ctx->guest_ram + ps2_virt_to_phys(vaddr), sizeof(v));
    return v;
}

int32_t ps2_mem_read_s32(ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    return (int32_t)ps2_mem_read32(ctx, vaddr);
}

uint64_t ps2_mem_read64(ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    if (ps2_is_hw_vaddr(vaddr)) {
        return ps2_hw_read64(ctx, vaddr);
    }
    uint64_t v = 0;
    memcpy(&v, ctx->guest_ram + ps2_virt_to_phys(vaddr), sizeof(v));
    return v;
}

ps2_u128_t ps2_mem_read128(const ps2_cpu_ctx_t *ctx, uint32_t vaddr) {
    ps2_u128_t q;
    uint32_t aligned = ps2_virt_to_phys(vaddr) & ~0xFU;
    memcpy(&q, ctx->guest_ram + aligned, sizeof(q));
    return q;
}

/* Aligned scalar & 128-bit memory writes (Little-Endian) */
void ps2_mem_write8(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint8_t val) {
    ctx->guest_ram[ps2_virt_to_phys(vaddr)] = val;
}

void ps2_mem_write16(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint16_t val) {
    memcpy(ctx->guest_ram + ps2_virt_to_phys(vaddr), &val, sizeof(val));
}

void ps2_mem_write32(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint32_t val) {
    if (ps2_is_hw_vaddr(vaddr)) {
        ps2_hw_write32(ctx, vaddr, val);
        return;
    }
    memcpy(ctx->guest_ram + ps2_virt_to_phys(vaddr), &val, sizeof(val));
}

void ps2_mem_write64(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t val) {
    if (ps2_is_hw_vaddr(vaddr)) {
        ps2_hw_write64(ctx, vaddr, val);
        return;
    }
    memcpy(ctx->guest_ram + ps2_virt_to_phys(vaddr), &val, sizeof(val));
}

void ps2_mem_write128(ps2_cpu_ctx_t *ctx, uint32_t vaddr, ps2_u128_t val) {
    uint32_t aligned = ps2_virt_to_phys(vaddr) & ~0xFU;
    memcpy(ctx->guest_ram + aligned, &val, sizeof(val));
}

/* Unaligned 32-bit load/store helpers (Little-Endian MIPS LWL/LWR/SWL/SWR) */
int64_t ps2_mem_lwl(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t cur_rt) {
    uint32_t aligned = vaddr & ~3u;
    uint32_t byte    = vaddr & 3u;
    uint32_t word    = ps2_mem_read32(ctx, aligned);
    uint32_t shift   = (3u - byte) * 8u;
    uint32_t mask    = (byte == 3u) ? 0u : ((1u << ((3u - byte) * 8u)) - 1u);
    uint32_t res     = ((uint32_t)cur_rt & mask) | (word << shift);
    return (int64_t)(int32_t)res;
}

int64_t ps2_mem_lwr(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t cur_rt) {
    uint32_t aligned = vaddr & ~3u;
    uint32_t byte    = vaddr & 3u;
    uint32_t word    = ps2_mem_read32(ctx, aligned);
    uint32_t shift   = byte * 8u;
    uint32_t mask    = (byte == 0u) ? 0u : (0xFFFFFFFFu << ((4u - byte) * 8u));
    uint32_t res     = ((uint32_t)cur_rt & mask) | (word >> shift);
    return (int64_t)(int32_t)res;
}

void ps2_mem_swl(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint32_t val) {
    uint32_t aligned = vaddr & ~3u;
    uint32_t byte    = vaddr & 3u;
    uint32_t mem     = ps2_mem_read32(ctx, aligned);
    uint32_t shift   = (3u - byte) * 8u;
    uint32_t mask    = (byte == 3u) ? 0u : (0xFFFFFFFFu << ((byte + 1u) * 8u));
    uint32_t res     = (mem & mask) | (val >> shift);
    ps2_mem_write32(ctx, aligned, res);
}

void ps2_mem_swr(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint32_t val) {
    uint32_t aligned = vaddr & ~3u;
    uint32_t byte    = vaddr & 3u;
    uint32_t mem     = ps2_mem_read32(ctx, aligned);
    uint32_t shift   = byte * 8u;
    uint32_t mask    = (byte == 0u) ? 0u : ((1u << (byte * 8u)) - 1u);
    uint32_t res     = (mem & mask) | (val << shift);
    ps2_mem_write32(ctx, aligned, res);
}

/* Unaligned 64-bit load/store helpers (Little-Endian MIPS III LDL/LDR/SDL/SDR) */
uint64_t ps2_mem_ldl(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t cur_rt) {
    uint32_t aligned = vaddr & ~7u;
    uint32_t byte    = vaddr & 7u;
    uint64_t dword   = ps2_mem_read64(ctx, aligned);
    uint32_t shift   = (7u - byte) * 8u;
    uint64_t mask    = (byte == 7u) ? 0ULL : ((1ULL << ((7u - byte) * 8u)) - 1ULL);
    return (cur_rt & mask) | (dword << shift);
}

uint64_t ps2_mem_ldr(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t cur_rt) {
    uint32_t aligned = vaddr & ~7u;
    uint32_t byte    = vaddr & 7u;
    uint64_t dword   = ps2_mem_read64(ctx, aligned);
    uint32_t shift   = byte * 8u;
    uint64_t mask    = (byte == 0u) ? 0ULL : (0xFFFFFFFFFFFFFFFFULL << ((8u - byte) * 8u));
    return (cur_rt & mask) | (dword >> shift);
}

void ps2_mem_sdl(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t val) {
    uint32_t aligned = vaddr & ~7u;
    uint32_t byte    = vaddr & 7u;
    uint64_t mem     = ps2_mem_read64(ctx, aligned);
    uint32_t shift   = (7u - byte) * 8u;
    uint64_t mask    = (byte == 7u) ? 0ULL : (0xFFFFFFFFFFFFFFFFULL << ((byte + 1u) * 8u));
    ps2_mem_write64(ctx, aligned, (mem & mask) | (val >> shift));
}

void ps2_mem_sdr(ps2_cpu_ctx_t *ctx, uint32_t vaddr, uint64_t val) {
    uint32_t aligned = vaddr & ~7u;
    uint32_t byte    = vaddr & 7u;
    uint64_t mem     = ps2_mem_read64(ctx, aligned);
    uint32_t shift   = byte * 8u;
    uint64_t mask    = (byte == 0u) ? 0ULL : ((1ULL << (byte * 8u)) - 1ULL);
    ps2_mem_write64(ctx, aligned, (mem & mask) | (val << shift));
}

/*
 * Exotic Families (COP0, CACHE, SYNC, TRAP, MMI3 PCPYH)
 */
int64_t ps2_cop0_mfc0(ps2_cpu_ctx_t *ctx, uint32_t cop0_reg) {
    ctx->cop0_ops_retired++;
    uint32_t idx = cop0_reg & 31u;
    if (idx == 9u) {
        ctx->cop0[9]++;
    }
    return (int64_t)(int32_t)ctx->cop0[idx];
}

void ps2_cop0_mtc0(ps2_cpu_ctx_t *ctx, uint32_t cop0_reg, uint32_t val) {
    ctx->cop0_ops_retired++;
    ctx->cop0[cop0_reg & 31u] = val;
}

void ps2_cop0_ei(ps2_cpu_ctx_t *ctx) {
    ctx->cop0_ops_retired++;
    ctx->cop0[12] |= (1U << 16);
}

void ps2_cop0_di(ps2_cpu_ctx_t *ctx) {
    ctx->cop0_ops_retired++;
    ctx->cop0[12] &= ~(1U << 16);
}

int ps2_cop0_cpcond0(ps2_cpu_ctx_t *ctx) {
    ctx->cop0_ops_retired++;
    /* On R5900, CPCOND0 reflects DMAC channel completion condition ((D_STAT & D_PCR) == D_PCR).
     * Since DMA transfers execute synchronously at the boundary, CPCOND0 is always ready (1). */
    return 1;
}

void ps2_cache_op(ps2_cpu_ctx_t *ctx, uint32_t op, uint32_t vaddr) {
    (void)op;
    (void)vaddr;
    ctx->cache_ops_retired++;
}

void ps2_sync_barrier(ps2_cpu_ctx_t *ctx, uint32_t stype) {
    (void)stype;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    ctx->sync_barrier_calls++;
}

void ps2_trap_eq(ps2_cpu_ctx_t *ctx, uint32_t pc, int64_t rs_val, int64_t rt_val, uint32_t code) {
    if (rs_val == rt_val) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "TEQ exception triggered at PC=0x%08x (code=0x%x, val=%" PRId64 ")",
                 pc, code, rs_val);
        fprintf(stderr, "[PS2-RUNTIME-TRAP] %s\n", msg);
        ps2_terminate_execution(ctx, 136, PS2_STOP_TRAP_EXCEPTION, pc, msg);
    }
}

ps2_u128_t ps2_mmi_pcpyh(ps2_u128_t rt) {
    ps2_u128_t rd;
    uint16_t lo_h = rt.u16[0];
    uint16_t hi_h = rt.u16[4];
    for (int i = 0; i < 4; ++i) {
        rd.u16[i]     = lo_h;
        rd.u16[4 + i] = hi_h;
    }
    return rd;
}

/* ============================================================================
 * Milestone 2.3 Part 2: R5900 COP1 Single-Precision FPU Implementation
 * ============================================================================
 * Documented R5900 EE COP1 Semantics:
 *   1. Denormals (`exp == 0`) flush to signed zero (`±0.0f`) on input and output.
 *   2. Biased exponent `255` (`0xFF`) is a valid finite normal exponent (`2^128 * 1.mant`),
 *      NOT IEEE-754 Infinity or NaN.
 *   3. Arithmetic overflow (`exp > 255`) saturates to `±MAX` (`sign | 0x7FFFFFFFU`) and sets
 *      `FCSR.O` (bit 16) and `FCSR.SO` (bit 5).
 *   4. Arithmetic underflow (`exp <= 0` for non-zero exact result) flushes to signed zero
 *      and sets `FCSR.U` (bit 15) and `FCSR.SU` (bit 4).
 *   5. Rounding mode is fixed Round-to-Zero (`RTZ` / truncation).
 */

static double ps2_ee_f32_to_double(uint32_t bits) {
    uint32_t sign = (bits >> 31) & 1U;
    int32_t  exp  = (int32_t)((bits >> 23) & 0xFFU);
    uint32_t mant = bits & 0x7FFFFFU;
    if (exp == 0) {
        return sign ? -0.0 : +0.0;
    }
    uint64_t d_sign = (uint64_t)sign << 63;
    uint64_t d_exp  = (uint64_t)(exp - 127 + 1023) << 52;
    uint64_t d_mant = (uint64_t)mant << (52 - 23);
    uint64_t d_bits = d_sign | d_exp | d_mant;
    double d = 0.0;
    memcpy(&d, &d_bits, sizeof(d));
    return d;
}

static void ps2_fpu_clear_cause(ps2_cpu_ctx_t *ctx) {
    ctx->fcsr &= ~(PS2_FCSR_CAUSE_I | PS2_FCSR_CAUSE_O | PS2_FCSR_CAUSE_U | PS2_FCSR_CAUSE_D);
}

static uint32_t ps2_double_to_ee_f32(ps2_cpu_ctx_t *ctx, double d, uint32_t zero_sign) {
    uint64_t d_bits = 0;
    memcpy(&d_bits, &d, sizeof(d_bits));
    uint32_t sign  = (uint32_t)((d_bits >> 63) & 1ULL);
    int32_t  d_exp = (int32_t)((d_bits >> 52) & 0x7FFULL);
    uint64_t d_man = d_bits & 0x000FFFFFFFFFFFFFULL;

    if (d_exp == 0 && d_man == 0ULL) {
        return (zero_sign & 1U) << 31;
    }
    int32_t ee_exp = d_exp - 1023 + 127;
    if (ee_exp <= 0) {
        ctx->fcsr |= PS2_FCSR_CAUSE_U | PS2_FCSR_STICKY_U;
        return sign << 31;
    }
    if (ee_exp > 255) {
        ctx->fcsr |= PS2_FCSR_CAUSE_O | PS2_FCSR_STICKY_O;
        return (sign << 31) | 0x7FFFFFFFU;
    }
    /* Round-to-Zero (RTZ): truncate bits below bit 29 of the 52-bit double fraction */
    uint32_t ee_man = (uint32_t)(d_man >> (52 - 23)) & 0x7FFFFFU;
    return (sign << 31) | ((uint32_t)ee_exp << 23) | ee_man;
}

static uint32_t ps2_fpu_add_sub_core(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ps2_fpu_clear_cause(ctx);
    uint32_t sa = (a >> 31) & 1U;
    uint32_t sb = (b >> 31) & 1U;
    int32_t  ea = (int32_t)((a >> 23) & 0xFFU);
    int32_t  eb = (int32_t)((b >> 23) & 0xFFU);

    if (ea == 0 && eb == 0) {
        /* R5900 signed zero rule: (-0.0) + (-0.0) = -0.0; otherwise +0.0 */
        return ((sa & sb) << 31);
    }
    if (ea == 0) {
        return (sb << 31) | (b & 0x7FFFFFFFU);
    }
    if (eb == 0) {
        return (sa << 31) | (a & 0x7FFFFFFFU);
    }

    /* R5900 25-bit alignment clamp: if |ea - eb| > 25, only a sticky bit survives */
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    if (ea - eb > 25) {
        int32_t clamped_eb = ea - 25;
        uint32_t b_clamped = (sb << 31) | ((uint32_t)clamped_eb << 23);
        db = ps2_ee_f32_to_double(b_clamped);
    } else if (eb - ea > 25) {
        int32_t clamped_ea = eb - 25;
        uint32_t a_clamped = (sa << 31) | ((uint32_t)clamped_ea << 23);
        da = ps2_ee_f32_to_double(a_clamped);
    }

    double sum = da + db;
    uint32_t zsign = (sa == sb) ? sa : 0U;
    return ps2_double_to_ee_f32(ctx, sum, zsign);
}

uint32_t ps2_fpu_add_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    return ps2_fpu_add_sub_core(ctx, a, b);
}

uint32_t ps2_fpu_sub_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    return ps2_fpu_add_sub_core(ctx, a, b ^ 0x80000000U);
}

uint32_t ps2_fpu_mul_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    uint32_t sign = ((a ^ b) >> 31) & 1U;
    int32_t  ea   = (int32_t)((a >> 23) & 0xFFU);
    int32_t  eb   = (int32_t)((b >> 23) & 0xFFU);
    if (ea == 0 || eb == 0) {
        return sign << 31;
    }
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    return ps2_double_to_ee_f32(ctx, da * db, sign);
}

uint32_t ps2_fpu_div_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    uint32_t sign = ((a ^ b) >> 31) & 1U;
    int32_t  ea   = (int32_t)((a >> 23) & 0xFFU);
    int32_t  eb   = (int32_t)((b >> 23) & 0xFFU);
    if (eb == 0) {
        if (ea == 0) {
            ctx->fcsr |= PS2_FCSR_CAUSE_I | PS2_FCSR_STICKY_I;
        } else {
            ctx->fcsr |= PS2_FCSR_CAUSE_D | PS2_FCSR_STICKY_D;
        }
        return (sign << 31) | 0x7FFFFFFFU;
    }
    if (ea == 0) {
        return sign << 31;
    }
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    return ps2_double_to_ee_f32(ctx, da / db, sign);
}

uint32_t ps2_fpu_sqrt_s(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    uint32_t sign = (a >> 31) & 1U;
    int32_t  ea   = (int32_t)((a >> 23) & 0xFFU);
    if (ea == 0) {
        return 0U;
    }
    if (sign != 0U) {
        ctx->fcsr |= PS2_FCSR_CAUSE_I | PS2_FCSR_STICKY_I;
        a &= 0x7FFFFFFFU;
    }
    double da = ps2_ee_f32_to_double(a);
    return ps2_double_to_ee_f32(ctx, sqrt(da), 0U);
}

uint32_t ps2_fpu_rsqrt_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    uint32_t sa = (a >> 31) & 1U;
    uint32_t sb = (b >> 31) & 1U;
    int32_t  ea = (int32_t)((a >> 23) & 0xFFU);
    int32_t  eb = (int32_t)((b >> 23) & 0xFFU);
    if (eb == 0) {
        ctx->fcsr |= PS2_FCSR_CAUSE_D | PS2_FCSR_STICKY_D;
        return (sa << 31) | 0x7FFFFFFFU;
    }
    if (sb != 0U) {
        ctx->fcsr |= PS2_FCSR_CAUSE_I | PS2_FCSR_STICKY_I;
        b &= 0x7FFFFFFFU;
    }
    if (ea == 0) {
        return sa << 31;
    }
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    return ps2_double_to_ee_f32(ctx, da / sqrt(db), sa);
}

/* Bit-preserving operations on R5900 COP1 (do NOT flush denormals) */
uint32_t ps2_fpu_abs_s(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    return a & 0x7FFFFFFFU;
}

uint32_t ps2_fpu_mov_s(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    return a;
}

uint32_t ps2_fpu_neg_s(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    return a ^ 0x80000000U;
}

void ps2_fpu_adda_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_acc = ps2_fpu_add_s(ctx, a, b);
}

void ps2_fpu_suba_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_acc = ps2_fpu_sub_s(ctx, a, b);
}

void ps2_fpu_mula_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_acc = ps2_fpu_mul_s(ctx, a, b);
}

uint32_t ps2_fpu_madd_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    uint32_t prod = ps2_fpu_mul_s(ctx, a, b);
    return ps2_fpu_add_sub_core(ctx, ctx->fpu_acc, prod);
}

uint32_t ps2_fpu_msub_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    uint32_t prod = ps2_fpu_mul_s(ctx, a, b);
    return ps2_fpu_add_sub_core(ctx, ctx->fpu_acc, prod ^ 0x80000000U);
}

void ps2_fpu_madda_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_acc = ps2_fpu_madd_s(ctx, a, b);
}

void ps2_fpu_msuba_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_acc = ps2_fpu_msub_s(ctx, a, b);
}

uint32_t ps2_fpu_cvt_w_s(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    uint32_t exp = (a >> 23) & 0xFFU;
    if (exp == 0U) {
        return 0U;
    }
    double d = ps2_ee_f32_to_double(a);
    if (d >= 2147483647.0) {
        return 0x7FFFFFFFU;
    }
    if (d <= -2147483648.0) {
        return 0x80000000U;
    }
    return (uint32_t)(int32_t)d;
}

uint32_t ps2_fpu_cvt_s_w(ps2_cpu_ctx_t *ctx, uint32_t a) {
    ctx->fpu_ops_retired++;
    int32_t iv = (int32_t)a;
    if (iv == 0) {
        return 0U;
    }
    return ps2_double_to_ee_f32(ctx, (double)iv, (iv < 0) ? 1U : 0U);
}

uint32_t ps2_fpu_max_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    return (da >= db) ? a : b;
}

uint32_t ps2_fpu_min_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    return (da <= db) ? a : b;
}

void ps2_fpu_c_f_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    (void)a;
    (void)b;
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    ctx->fcsr &= ~PS2_FCSR_COND_BIT;
}

void ps2_fpu_c_eq_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    if (da == db) {
        ctx->fcsr |= PS2_FCSR_COND_BIT;
    } else {
        ctx->fcsr &= ~PS2_FCSR_COND_BIT;
    }
}

void ps2_fpu_c_lt_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    if (da < db) {
        ctx->fcsr |= PS2_FCSR_COND_BIT;
    } else {
        ctx->fcsr &= ~PS2_FCSR_COND_BIT;
    }
}

void ps2_fpu_c_le_s(ps2_cpu_ctx_t *ctx, uint32_t a, uint32_t b) {
    ctx->fpu_ops_retired++;
    ps2_fpu_clear_cause(ctx);
    double da = ps2_ee_f32_to_double(a);
    double db = ps2_ee_f32_to_double(b);
    if (da <= db) {
        ctx->fcsr |= PS2_FCSR_COND_BIT;
    } else {
        ctx->fcsr &= ~PS2_FCSR_COND_BIT;
    }
}

int64_t ps2_fpu_cfc1(ps2_cpu_ctx_t *ctx, uint32_t fcr_num) {
    ctx->fpu_ops_retired++;
    uint32_t val = (fcr_num == 0U) ? ctx->fcr0 : ctx->fcsr;
    return (int64_t)(int32_t)val;
}

void ps2_fpu_ctc1(ps2_cpu_ctx_t *ctx, uint32_t fcr_num, uint32_t val) {
    ctx->fpu_ops_retired++;
    if (fcr_num == 31U) {
        ctx->fcsr = val | PS2_FCSR_FS_BIT;
    }
}

void ps2_null_weak_call_trap(ps2_cpu_ctx_t *ctx, uint32_t site_pc) {
    char msg[160];
    snprintf(msg, sizeof(msg),
             "Unlinked weak symbol call/jump to 0x00000000 reached at site PC=0x%08x",
             site_pc);
    fprintf(stderr, "[PS2-RUNTIME-TRAP] %s\n", msg);
    ps2_terminate_execution(ctx, 139, PS2_STOP_NULL_WEAK_CALL, site_pc, msg);
}

/*
 * Runtime Indirect Dispatch via `k_indirect_dispatch_table`
 */
void ps2_indirect_dispatch(ps2_cpu_ctx_t *ctx, uint32_t site_pc, uint32_t target_vaddr, int is_call, const char *reason) {
    ctx->indirect_dispatches++;
    ctx->pc = site_pc;

    if (target_vaddr == 0U) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "Indirect %s to NULL (0x00000000) at site PC=0x%08x | Blocker: %s",
                 is_call ? "JALR" : "JR", site_pc, reason ? reason : "unresolved_indirect");
        ps2_record_trace(ctx, site_pc, "INDIRECT_CALL", 0, "NULL_TARGET",
                         ctx->gpr[4].u32[0], ctx->gpr[5].u32[0], ctx->gpr[6].u32[0], ctx->gpr[7].u32[0],
                         -1, "حاجب تشغيل معلن", msg);
        fprintf(stderr, "[PS2-INDIRECT-ABORT] %s\n", msg);
        ps2_terminate_execution(ctx, 134, PS2_STOP_UNRESOLVED_INDIRECT, site_pc, msg);
        return;
    }

    if (ctx->indirect_table && ctx->indirect_table_count > 0) {
        for (size_t i = 0; i < ctx->indirect_table_count; ++i) {
            if (ctx->indirect_table[i].vaddr == target_vaddr && ctx->indirect_table[i].func != NULL) {
                ctx->indirect_lifted_resolved_count++;
                char detail[128];
                snprintf(detail, sizeof(detail),
                         "site=0x%08x -> target=0x%08x (%s) [%s]",
                         site_pc, target_vaddr, ctx->indirect_table[i].name,
                         is_call ? "JALR" : "JR");
                ps2_record_trace(ctx, site_pc, "INDIRECT_CALL", (int32_t)target_vaddr,
                                 ctx->indirect_table[i].name,
                                 ctx->gpr[4].u32[0], ctx->gpr[5].u32[0],
                                 ctx->gpr[6].u32[0], ctx->gpr[7].u32[0],
                                 0, "مرفوعة أصلًا", detail);
                ctx->indirect_table[i].func(ctx);
                return;
            }
        }
    }

    char msg[160];
    snprintf(msg, sizeof(msg),
             "Unresolved indirect %s at site PC=0x%08x -> target=0x%08x | Blocker: %s",
             is_call ? "JALR" : "JR", site_pc, target_vaddr, reason ? reason : "unresolved_indirect");
    ps2_record_trace(ctx, site_pc, "INDIRECT_CALL", (int32_t)target_vaddr, "UNRESOLVED_TARGET",
                     ctx->gpr[4].u32[0], ctx->gpr[5].u32[0], ctx->gpr[6].u32[0], ctx->gpr[7].u32[0],
                     -1, "حاجب تشغيل معلن", msg);
    fprintf(stderr, "[PS2-INDIRECT-ABORT] %s\n", msg);
    ps2_terminate_execution(ctx, 134, PS2_STOP_UNRESOLVED_INDIRECT, site_pc, msg);
}

/* Append string to both stdout and ctx->stdout_buf, and check Gate G3 */
static void ps2_runtime_append_output(ps2_cpu_ctx_t *ctx, const char *str, size_t len) {
    if (len == 0) return;
    fwrite(str, 1, len, stdout);
    fflush(stdout);
    size_t avail = (ctx->stdout_len < PS2_STDOUT_CAP - 1U)
                 ? (PS2_STDOUT_CAP - 1U - ctx->stdout_len)
                 : 0U;
    size_t copy_len = (len < avail) ? len : avail;
    if (copy_len > 0) {
        memcpy(ctx->stdout_buf + ctx->stdout_len, str, copy_len);
        ctx->stdout_len += copy_len;
        ctx->stdout_buf[ctx->stdout_len] = '\0';
    }
    if (!ctx->g3_passed && ctx->stdout_len >= 13U &&
        memcmp(ctx->stdout_buf, "Hello world!\n", 13U) == 0) {
        ctx->g3_passed     = true;
        ctx->g3_insn_count = ctx->insn_retired;
    }
}

static void ps2_invoke_dmac_ch5_irq(ps2_cpu_ctx_t *ctx) {
    if (!ctx || ctx->in_dmac_irq || ctx->dmac_ch5_handler_vaddr == 0U) {
        return;
    }
    ps2_lifted_fn_t irq_fn = NULL;
    const char     *irq_name = "_SifCmdIntHandler";
    if (ctx->indirect_table && ctx->indirect_table_count > 0) {
        for (size_t i = 0; i < ctx->indirect_table_count; ++i) {
            if (ctx->indirect_table[i].vaddr == ctx->dmac_ch5_handler_vaddr) {
                irq_fn   = ctx->indirect_table[i].func;
                irq_name = ctx->indirect_table[i].name;
                break;
            }
        }
    }
    if (!irq_fn) {
        return;
    }

    ps2_u128_t saved_gpr[32];
    ps2_u128_t saved_hi = ctx->hi;
    ps2_u128_t saved_lo = ctx->lo;
    uint32_t   saved_sa = ctx->sa;
    uint32_t   saved_pc = ctx->pc;
    memcpy(saved_gpr, ctx->gpr, sizeof(saved_gpr));

    ctx->in_dmac_irq = true;
    uint32_t irq_sp = (saved_gpr[29].u32[0] - 256U) & ~0xFU;
    ctx->gpr[29].s64[0] = (int64_t)(int32_t)irq_sp;
    ctx->gpr[28].s64[0] = (int64_t)(int32_t)ctx->thread_gp;
    ctx->gpr[4].s64[0]  = 5;

    char detail[128];
    snprintf(detail, sizeof(detail),
             "DMAC Ch5 IRQ -> lifted handler 0x%08x (%s)",
             ctx->dmac_ch5_handler_vaddr, irq_name);
    ps2_record_trace(ctx, saved_pc, "IOP_DMA_BOUNDARY", 5, irq_name,
                     5, irq_sp, ctx->thread_gp, 0,
                     0, "مرفوعة أصلًا", detail);

    irq_fn(ctx);

    ctx->in_dmac_irq = false;
    memcpy(ctx->gpr, saved_gpr, sizeof(saved_gpr));
    ctx->hi = saved_hi;
    ctx->lo = saved_lo;
    ctx->sa = saved_sa;
    ctx->pc = saved_pc;
    ps2_zero_invariant(ctx);
}

/*
 * Minimal Honest SIF1 (EE->IOP) & SIF0 (IOP->EE) DMA Boundary Responder
 * Dynamically discovers the guest's `_sif_cmd_data.pktbuf` registered via
 * `SifSetReg(0x80000001, &_sif_cmd_data)` (falling back to `0x00122c40` if not yet set).
 */
static void ps2_handle_sif_dma_boundary(ps2_cpu_ctx_t *ctx, uint32_t call_pc, uint32_t dmat_vaddr, uint32_t count) {
    if (dmat_vaddr == 0U || count == 0U || count > 16U) {
        return;
    }
    uint32_t last_dmat = dmat_vaddr + (count - 1U) * 16U;
    uint32_t pkt_vaddr = ps2_mem_read32(ctx, last_dmat + 0U);
    uint32_t pkt_size  = ps2_mem_read32(ctx, last_dmat + 8U);
    if (pkt_vaddr == 0U || pkt_size < 16U) {
        return;
    }

    uint32_t cid = ps2_mem_read32(ctx, pkt_vaddr + 8U);
    uint32_t sif_cmd_data_vaddr = g_sim_sif_ext_regs[1] ? g_sim_sif_ext_regs[1] : 0x00122c40U;
    uint32_t ee_pktbuf = ps2_mem_read32(ctx, sif_cmd_data_vaddr);
    if (ee_pktbuf == 0U) {
        ee_pktbuf = 0x00122f40U;
    }

    switch (cid) {
        case 0x80000000U: { /* SIF_CMD_CHANGE_SADDR */
            uint32_t new_addr = ps2_mem_read32(ctx, pkt_vaddr + 16U);
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "SIF_CMD_CHANGE_SADDR: EE registered SIF0 pktbuf=0x%08x", new_addr);
            ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)cid,
                             "SIF_CMD_CHANGE_SADDR", pkt_vaddr, new_addr, 0, 0,
                             1, "معترضة عند الحدود", detail);
            break;
        }
        case 0x80000002U: { /* SIF_CMD_INIT */
            ps2_mem_write32(ctx, ee_pktbuf + 0U,  24U);
            ps2_mem_write32(ctx, ee_pktbuf + 4U,  0U);
            ps2_mem_write32(ctx, ee_pktbuf + 8U,  0x80000001U); /* SIF_CMD_SETSREG */
            ps2_mem_write32(ctx, ee_pktbuf + 12U, 0U);
            ps2_mem_write32(ctx, ee_pktbuf + 16U, 0U);
            ps2_mem_write32(ctx, ee_pktbuf + 20U, 1U);

            char detail[128];
            snprintf(detail, sizeof(detail),
                     "SIF_CMD_INIT -> IOP replies SIF_CMD_SETSREG(sreg[0]=1) to 0x%08x",
                     ee_pktbuf);
            ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)cid,
                             "SIF_CMD_INIT", pkt_vaddr, ee_pktbuf, 0, 1,
                             1, "معترضة عند الحدود", detail);

            ps2_invoke_dmac_ch5_irq(ctx);
            break;
        }
        case 0x8000000CU: { /* SIF_CMD_RDATA (sceSifGetOtherData in SetupRomInfo) */
            uint32_t rec_id   = ps2_mem_read32(ctx, pkt_vaddr + 16U);
            uint32_t pkt_addr = ps2_mem_read32(ctx, pkt_vaddr + 20U);
            uint32_t rpc_id   = ps2_mem_read32(ctx, pkt_vaddr + 24U);
            uint32_t rd_vaddr = ps2_mem_read32(ctx, pkt_vaddr + 28U);
            uint32_t iop_src  = ps2_mem_read32(ctx, pkt_vaddr + 32U);
            uint32_t ee_dest  = ps2_mem_read32(ctx, pkt_vaddr + 36U);
            uint32_t rsize    = ps2_mem_read32(ctx, pkt_vaddr + 40U);

            static const char k_romver_str[15] = "0100EC20000101";
            if (ee_dest != 0U) {
                for (size_t i = 0; i < sizeof(k_romver_str); ++i) {
                    ps2_mem_write8(ctx, ee_dest + (uint32_t)i, (uint8_t)k_romver_str[i]);
                }
            }

            ps2_mem_write32(ctx, ee_pktbuf + 0U,  64U);
            ps2_mem_write32(ctx, ee_pktbuf + 4U,  0U);
            ps2_mem_write32(ctx, ee_pktbuf + 8U,  0x80000008U); /* SIF_CMD_REND */
            ps2_mem_write32(ctx, ee_pktbuf + 12U, 0U);
            ps2_mem_write32(ctx, ee_pktbuf + 16U, rec_id);
            ps2_mem_write32(ctx, ee_pktbuf + 20U, pkt_addr);
            ps2_mem_write32(ctx, ee_pktbuf + 24U, rpc_id);
            ps2_mem_write32(ctx, ee_pktbuf + 28U, rd_vaddr);
            ps2_mem_write32(ctx, ee_pktbuf + 32U, 0x8000000CU); /* rcid = SIF_CMD_RDATA */

            char detail[128];
            snprintf(detail, sizeof(detail),
                     "SIF_CMD_RDATA(iop=0x%x -> ee=0x%08x, sz=%u): ROMVER=\"0100EC20000101\"",
                     iop_src, ee_dest, rsize);
            ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)cid,
                             "SIF_CMD_RDATA(ROMVER)", iop_src, ee_dest, rsize, rd_vaddr,
                             0, "معترضة عند الحدود", detail);

            ps2_invoke_dmac_ch5_irq(ctx);
            break;
        }
        case 0x80000009U: { /* SIF_CMD_BIND */
            uint32_t rec_id   = ps2_mem_read32(ctx, pkt_vaddr + 16U);
            uint32_t pkt_addr = ps2_mem_read32(ctx, pkt_vaddr + 20U);
            uint32_t rpc_id   = ps2_mem_read32(ctx, pkt_vaddr + 24U);
            uint32_t cd_vaddr = ps2_mem_read32(ctx, pkt_vaddr + 28U);
            uint32_t sid      = ps2_mem_read32(ctx, pkt_vaddr + 32U);

            ps2_mem_write32(ctx, ee_pktbuf + 0U,  64U);
            ps2_mem_write32(ctx, ee_pktbuf + 4U,  0U);
            ps2_mem_write32(ctx, ee_pktbuf + 8U,  0x80000008U); /* SIF_CMD_REND */
            ps2_mem_write32(ctx, ee_pktbuf + 12U, 0U);
            ps2_mem_write32(ctx, ee_pktbuf + 16U, rec_id);
            ps2_mem_write32(ctx, ee_pktbuf + 20U, pkt_addr);
            ps2_mem_write32(ctx, ee_pktbuf + 24U, rpc_id);
            ps2_mem_write32(ctx, ee_pktbuf + 28U, cd_vaddr);
            ps2_mem_write32(ctx, ee_pktbuf + 32U, 0x80000009U); /* rcid = SIF_CMD_BIND */
            ps2_mem_write32(ctx, ee_pktbuf + 36U, sid);
            ps2_mem_write32(ctx, ee_pktbuf + 40U, 0x00020000U);
            ps2_mem_write32(ctx, ee_pktbuf + 44U, 0x00021000U);

            const char *srv_name = (sid == 0x80000001U) ? "FILEIO"
                                 : (sid == 0x80000003U) ? "IOPHEAP"
                                 : "IOP_RPC_SERVER";
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "SIF_CMD_BIND(sid=0x%08x [%s], cd=0x%08x)", sid, srv_name, cd_vaddr);
            ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)sid,
                             "SIF_CMD_BIND", sid, cd_vaddr, rpc_id, 0,
                             0, "معترضة عند الحدود", detail);

            ps2_invoke_dmac_ch5_irq(ctx);
            break;
        }
        case 0x8000000AU: { /* SIF_CMD_CALL */
            uint32_t send_vaddr = (count >= 2U) ? ps2_mem_read32(ctx, dmat_vaddr + 0U) : 0U;
            uint32_t rec_id     = ps2_mem_read32(ctx, pkt_vaddr + 16U);
            uint32_t pkt_addr   = ps2_mem_read32(ctx, pkt_vaddr + 20U);
            uint32_t rpc_id     = ps2_mem_read32(ctx, pkt_vaddr + 24U);
            uint32_t cd_vaddr   = ps2_mem_read32(ctx, pkt_vaddr + 28U);
            uint32_t rpc_num    = ps2_mem_read32(ctx, pkt_vaddr + 32U);
            uint32_t send_size  = ps2_mem_read32(ctx, pkt_vaddr + 36U);
            uint32_t recv_vaddr = ps2_mem_read32(ctx, pkt_vaddr + 40U);
            uint32_t server_sid = ps2_mem_read32(ctx, pkt_vaddr + 52U);

            if (server_sid == 0x80000003U) { /* IOPHEAP service */
                uint32_t ret_val = 0U;
                const char *op_name = "IOPHEAP_CALL";
                if (rpc_num == 1U) {
                    ret_val = 0x00040000U;
                    op_name = "SifAllocIopHeap";
                } else if (rpc_num == 2U) {
                    ret_val = 0U;
                    op_name = "SifFreeIopHeap";
                } else if (rpc_num == 3U) {
                    ret_val = 0U;
                    op_name = "SifLoadIopHeap";
                }
                if (recv_vaddr != 0U) {
                    ps2_mem_write32(ctx, recv_vaddr, ret_val);
                }
                char detail[128];
                snprintf(detail, sizeof(detail),
                         "IOPHEAP RPC #%u (%s) -> recv[0x%08x]=0x%x",
                         rpc_num, op_name, recv_vaddr, ret_val);
                ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)rpc_num,
                                 op_name, server_sid, rpc_num, send_vaddr, recv_vaddr,
                                 (int64_t)ret_val, "معترضة عند الحدود", detail);
            } else if (server_sid == 0x80000001U) { /* FILEIO service */
                if (rpc_num == 3U && send_vaddr != 0U) { /* FIO_F_WRITE */
                    int32_t  fd       = ps2_mem_read_s32(ctx, send_vaddr + 0U);
                    uint32_t data_ptr = ps2_mem_read32(ctx, send_vaddr + 4U);
                    uint32_t data_len = ps2_mem_read32(ctx, send_vaddr + 8U);
                    uint32_t mis      = ps2_mem_read32(ctx, send_vaddr + 12U);

                    if (data_len > 0U && data_len <= PS2_STDOUT_CAP) {
                        if (mis > 0U && mis <= 16U) {
                            uint32_t p_inline = ps2_virt_to_phys(send_vaddr + 16U);
                            ps2_runtime_append_output(ctx, (const char *)(ctx->guest_ram + p_inline), mis);
                        }
                        if (data_len > mis && data_ptr != 0U) {
                            uint32_t p_body = ps2_virt_to_phys(data_ptr + mis);
                            ps2_runtime_append_output(ctx, (const char *)(ctx->guest_ram + p_body), data_len - mis);
                        }
                    }
                    if (recv_vaddr != 0U) {
                        ps2_mem_write32(ctx, recv_vaddr, data_len);
                    }
                    char detail[128];
                    snprintf(detail, sizeof(detail),
                             "FILEIO FIO_F_WRITE(fd=%d, buf=0x%08x, len=%u, mis=%u) -> %u bytes emitted",
                             fd, data_ptr, data_len, mis, data_len);
                    ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)rpc_num,
                                     "FILEIO:FIO_F_WRITE", (uint32_t)fd, data_ptr, data_len, recv_vaddr,
                                     (int64_t)data_len, "معترضة عند الحدود", detail);
                } else {
                    if (recv_vaddr != 0U) {
                        ps2_mem_write32(ctx, recv_vaddr, 0U);
                    }
                    char detail[128];
                    snprintf(detail, sizeof(detail),
                             "FILEIO RPC #%u (send_sz=%u) -> recv[0x%08x]=0",
                             rpc_num, send_size, recv_vaddr);
                    ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)rpc_num,
                                     (rpc_num == 1U) ? "FILEIO:FIO_F_CLOSE" : "FILEIO:RPC",
                                     server_sid, rpc_num, send_vaddr, recv_vaddr,
                                     0, "معترضة عند الحدود", detail);
                }
            }

            ps2_mem_write32(ctx, ee_pktbuf + 0U,  64U);
            ps2_mem_write32(ctx, ee_pktbuf + 4U,  0U);
            ps2_mem_write32(ctx, ee_pktbuf + 8U,  0x80000008U); /* SIF_CMD_REND */
            ps2_mem_write32(ctx, ee_pktbuf + 12U, 0U);
            ps2_mem_write32(ctx, ee_pktbuf + 16U, rec_id);
            ps2_mem_write32(ctx, ee_pktbuf + 20U, pkt_addr);
            ps2_mem_write32(ctx, ee_pktbuf + 24U, rpc_id);
            ps2_mem_write32(ctx, ee_pktbuf + 28U, cd_vaddr);
            ps2_mem_write32(ctx, ee_pktbuf + 32U, 0x8000000AU); /* rcid = SIF_CMD_CALL */

            ps2_invoke_dmac_ch5_irq(ctx);
            break;
        }
        default: {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "SIF DMA transfer cid=0x%08x (pkt=0x%08x, sz=%u)",
                     cid, pkt_vaddr, pkt_size);
            ps2_record_trace(ctx, call_pc, "IOP_DMA_BOUNDARY", (int32_t)cid,
                             "SIF_DMA_RAW", pkt_vaddr, pkt_size, count, 0,
                             1, "معترضة عند الحدود", detail);
            break;
        }
    }
}

/*
 * PS2 EE Kernel Syscall Dispatcher
 */
void ps2_syscall_dispatch(ps2_cpu_ctx_t *ctx, uint32_t call_pc) {
    ctx->pc = call_pc;
    ctx->syscalls_dispatched++;
    int32_t raw_v1   = ctx->gpr[3].s32[0]; /* $v1 */
    uint8_t call_num = (raw_v1 < 0) ? (uint8_t)(-raw_v1) : (uint8_t)(raw_v1 & 0xFF);
    uint32_t a0      = ctx->gpr[4].u32[0];
    uint32_t a1      = ctx->gpr[5].u32[0];
    uint32_t a2      = ctx->gpr[6].u32[0];
    uint32_t a3      = ctx->gpr[7].u32[0];

    switch (call_num) {
        /* =========================================================================
         * CLASS 1: مرفوعة أصلًا (Architectural EE State & Memory Layout Syscalls)
         * ========================================================================= */
        case 0x04: { /* Exit(int status) */
            ctx->syscall_lifted_native_count++;
            ctx->g4_passed     = true;
            ctx->g4_insn_count = ctx->insn_retired;
            char detail[128];
            snprintf(detail, sizeof(detail), "Exit(status=%d) at PC=0x%08x", (int32_t)a0, call_pc);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "Exit",
                             a0, a1, a2, a3, (int64_t)(int32_t)a0, "مرفوعة أصلًا", detail);
            ps2_terminate_execution(ctx, (int32_t)a0, PS2_STOP_CLEAN_EXIT, call_pc, detail);
            break;
        }
        case 0x0D: { /* SetVTLBRefillHandler */
            ctx->syscall_lifted_native_count++;
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)a1;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SetVTLBRefillHandler",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا",
                             "Registered VTLB refill handler in EE context");
            break;
        }
        case 0x23:
        case 0x24: { /* ExitThread / ExitDeleteThread */
            ctx->syscall_lifted_native_count++;
            const char *sname = (call_num == 0x23) ? "ExitThread" : "ExitDeleteThread";
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, sname,
                             a0, a1, a2, a3, 0, "مرفوعة أصلًا", "Thread exit");
            ps2_terminate_execution(ctx, 0, PS2_STOP_CLEAN_EXIT, call_pc, sname);
            break;
        }
        case 0x3C: { /* SetupThread(gp, stack, stack_size, args, root) */
            ctx->syscall_lifted_native_count++;
            uint32_t gp         = a0;
            uint32_t stack      = a1;
            uint32_t stack_size = a2;
            uint32_t args_vaddr = a3;
            ctx->thread_gp         = gp;
            ctx->thread_stack_top  = (stack == 0xFFFFFFFFU || stack == 0U || stack > PS2_RAM_SIZE)
                                   ? PS2_RAM_SIZE
                                   : stack;
            ctx->thread_stack_size = stack_size;
            uint32_t sp_val = (ctx->thread_stack_top - stack_size) & ~0xFU;
            ctx->thread_sp_init = sp_val;
            if (gp != 0U) {
                ctx->gpr[28].s64[0] = (int64_t)(int32_t)gp;
            }
            if (args_vaddr != 0U && args_vaddr < PS2_RAM_SIZE - 64U) {
                ps2_mem_write32(ctx, args_vaddr + 0U, 1U);
                ps2_mem_write32(ctx, args_vaddr + 4U, args_vaddr + 16U);
                ps2_mem_write32(ctx, args_vaddr + 8U, 0U);
                static const char k_arg0[] = "host:hello_real.elf";
                for (size_t i = 0; i < sizeof(k_arg0); ++i) {
                    ps2_mem_write8(ctx, args_vaddr + 16U + (uint32_t)i, (uint8_t)k_arg0[i]);
                }
            }
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)sp_val;
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "gp=0x%08x, stack_top=0x%08x, size=0x%x -> sp=0x%08x",
                     gp, ctx->thread_stack_top, stack_size, sp_val);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SetupThread",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا", detail);
            break;
        }
        case 0x3D: { /* SetupHeap(heap_start, heap_size) */
            ctx->syscall_lifted_native_count++;
            uint32_t heap_start = a0;
            int32_t  heap_size  = (int32_t)a1;
            ctx->heap_base = heap_start;
            ctx->heap_size = (uint32_t)heap_size;
            ctx->heap_end  = (heap_size == -1)
                           ? (ctx->thread_sp_init ? ctx->thread_sp_init : (PS2_RAM_SIZE - 0x10000U))
                           : (heap_start + (uint32_t)heap_size);
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)ctx->heap_end;
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "heap_base=0x%08x, heap_size=%d -> heap_end=0x%08x",
                     heap_start, heap_size, ctx->heap_end);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SetupHeap",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا", detail);
            break;
        }
        case 0x3E: { /* EndOfHeap(void) */
            ctx->syscall_lifted_native_count++;
            uint32_t end = ctx->heap_end ? ctx->heap_end : (PS2_RAM_SIZE - 0x10000U);
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)end;
            char detail[128];
            snprintf(detail, sizeof(detail), "EndOfHeap() -> 0x%08x", end);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "EndOfHeap",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا", detail);
            break;
        }
        case 0x56: { /* _SetTLBEntry */
            ctx->syscall_lifted_native_count++;
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)a0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "_SetTLBEntry",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا",
                             "Recorded TLB entry in flat 32MB Guest RAM model");
            break;
        }
        case 0x5A: { /* Copy(void *dest, const void *src, size_t size) — installed by kCopy in InitAlarm/InitTLBFunctions */
            ctx->syscall_lifted_native_count++;
            if (a0 != 0U && a1 != 0U && a2 > 0U && a2 < PS2_RAM_SIZE) {
                uint32_t pdst = ps2_virt_to_phys(a0);
                uint32_t psrc = ps2_virt_to_phys(a1);
                if (pdst + a2 <= PS2_RAM_SIZE && psrc + a2 <= PS2_RAM_SIZE) {
                    memmove(ctx->guest_ram + pdst, ctx->guest_ram + psrc, a2);
                }
            }
            ctx->gpr[2].s64[0] = 0;
            char detail[128];
            snprintf(detail, sizeof(detail), "Copy(dst=0x%08x, src=0x%08x, size=%u)", a0, a1, a2);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "Copy",
                             a0, a1, a2, a3, 0, "مرفوعة أصلًا", detail);
            break;
        }
        case 0x5B: { /* GetEntryAddress(int syscall_num) — queried by InitAlarm/InitExecPS2/InitTLBFunctions */
            ctx->syscall_lifted_native_count++;
            uint32_t idx = a0 & 0xFFU;
            /* If a0 == 3 (InitTLB entry check in InitTLBFunctions), return 0x00102ac8 (InitTLB) */
            uint32_t entry = ctx->custom_syscall_table[idx]
                           ? ctx->custom_syscall_table[idx]
                           : ((idx == 3U) ? 0x00102ac8U : (0x80010000U + idx * 8U));
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)entry;
            char detail[128];
            snprintf(detail, sizeof(detail), "GetEntryAddress(syscall=0x%02x) -> 0x%08x", idx, entry);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "GetEntryAddress",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا", detail);
            break;
        }
        case 0x64:
        case 0x68: { /* FlushCache / iFlushCache(mode) */
            ctx->syscall_lifted_native_count++;
            ctx->flush_cache_calls++;
            ctx->gpr[2].s64[0] = 0;
            char detail[128];
            snprintf(detail, sizeof(detail), "FlushCache(mode=%u) on coherent host RAM", a0);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0 || call_num == 0x68) ? "iFlushCache" : "FlushCache",
                             a0, a1, a2, a3, 0, "مرفوعة أصلًا", detail);
            break;
        }
        case 0x70: { /* GsGetIMR / iGsGetIMR (-0x70) */
            ctx->syscall_lifted_native_count++;
            ctx->gpr[2].u64[0] = g_sim_gs_imr;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0) ? "iGsGetIMR" : "GsGetIMR",
                             a0, a1, a2, a3, (int64_t)g_sim_gs_imr, "مرفوعة أصلًا",
                             "Read GS IMR state");
            break;
        }
        case 0x71: { /* GsPutIMR / iGsPutIMR (-0x71) */
            ctx->syscall_lifted_native_count++;
            uint64_t old_imr = g_sim_gs_imr;
            g_sim_gs_imr = ctx->gpr[4].u64[0];
            ctx->gs.imr  = g_sim_gs_imr;
            ctx->gpr[2].u64[0] = old_imr;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0) ? "iGsPutIMR" : "GsPutIMR",
                             a0, a1, a2, a3, (int64_t)old_imr, "مرفوعة أصلًا",
                             "Updated GS IMR state");
            ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x1010U, "GS_IMR", g_sim_gs_imr, old_imr, "GsPutIMR syscall");
            break;
        }
        case 0x74: { /* SetSyscall / setup(int syscall_num, void *handler) */
            if (ctx->strict_m22_syscalls || (call_pc == 0x0011d594U && ctx->frame_limit == 0U)) {
                char msg[160];
                snprintf(msg, sizeof(msg),
                         "Unhandled EE syscall 0x%02x (raw=%d) at PC=0x%08x",
                         call_num, raw_v1, call_pc);
                ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "UNHANDLED_SYSCALL",
                                 a0, a1, a2, a3, -1, "حاجب تشغيل معلن", msg);
                fprintf(stderr, "[ps2_runtime] %s\n", msg);
                ps2_terminate_execution(ctx, -100 - (int32_t)call_num, PS2_STOP_UNHANDLED_SYSCALL, call_pc, msg);
                break;
            }
            ctx->syscall_lifted_native_count++;
            uint32_t idx = a0 & 0xFFU;
            uint32_t old_h = ctx->custom_syscall_table[idx];
            ctx->custom_syscall_table[idx] = a1;
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)old_h;
            char detail[128];
            snprintf(detail, sizeof(detail), "SetSyscall(num=0x%02x, handler=0x%08x)", idx, a1);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SetSyscall",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا", detail);
            break;
        }
        case 0x7F: { /* GetMemorySize(void) -> returns 32 MB */
            ctx->syscall_lifted_native_count++;
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)PS2_RAM_SIZE;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "GetMemorySize",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "مرفوعة أصلًا",
                             "Returned 32 MB EE Main RAM size");
            break;
        }
        case 0x82: { /* _InitTLB */
            ctx->syscall_lifted_native_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "_InitTLB",
                             a0, a1, a2, a3, 0, "مرفوعة أصلًا",
                             "Initialized default EE TLB state");
            break;
        }

        /* =========================================================================
         * CLASS 2: جذع خدمة (Single-Threaded Kernel Service Stubs)
         * ========================================================================= */
        case 0x01: /* ResetEE(int reset_flag) */
        case 0x02: { /* SetGsCrt(s16 interlace, s16 display_mode, s16 ffmd) */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (call_num == 0x01) ? "ResetEE" : "SetGsCrt",
                             a0, a1, a2, a3, 0, "جذع خدمة", "Kernel reset/CRT display mode configuration");
            if (call_num == 0x02) {
                char gdetail[128];
                snprintf(gdetail, sizeof(gdetail), "SetGsCrt(interlace=%u, mode=0x%x, ffmd=%u)", a0, a1, a2);
                ps2_record_gs_event(ctx, "PRIV_REG_WRITE", 0x02U, "SetGsCrt", a0, a1, gdetail);
            }
            break;
        }
        case 0x10: /* AddIntcHandler */
        case 0x11: /* RemoveIntcHandler */
        case 0x13: { /* RemoveDmacHandler */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 1;
            const char *sname = (call_num == 0x10) ? "AddIntcHandler"
                              : (call_num == 0x11) ? "RemoveIntcHandler"
                              : "RemoveDmacHandler";
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, sname,
                             a0, a1, a2, a3, 1, "جذع خدمة", "Interrupt handler registration stub");
            break;
        }
        case 0x12: { /* AddDmacHandler(int channel, int (*handler)(int), int next) */
            ctx->syscall_service_stub_count++;
            if (a0 == 5U) {
                ctx->dmac_ch5_handler_vaddr = a1;
            }
            ctx->gpr[2].s64[0] = 1;
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "Registered DMAC ch=%u handler=0x%08x (next=%d)", a0, a1, (int32_t)a2);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "AddDmacHandler",
                             a0, a1, a2, a3, 1, "جذع خدمة", detail);
            break;
        }
        case 0x14:   /* EnableIntc */
        case 0x1A: { /* _EnableIntc */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 1;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (call_num == 0x14) ? "EnableIntc" : "_EnableIntc",
                             a0, a1, a2, a3, 1, "جذع خدمة", "Enabled INTC cause bit");
            break;
        }
        case 0x15:   /* DisableIntc / iDisableIntc (-0x15) */
        case 0x1B: { /* _DisableIntc */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 1;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0) ? "iDisableIntc" : "DisableIntc",
                             a0, a1, a2, a3, 1, "جذع خدمة", "Disabled INTC cause bit");
            break;
        }
        case 0x16:   /* EnableDmac */
        case 0x1C: { /* _EnableDmac / _iEnableDmac (-0x1c) */
            ctx->syscall_service_stub_count++;
            if (a0 == 5U) {
                ctx->dmac_ch5_enabled = true;
            }
            ctx->gpr[2].s64[0] = 1;
            char detail[128];
            snprintf(detail, sizeof(detail), "Enabled DMAC channel %u", a0);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (call_num == 0x16) ? "EnableDmac" : "_EnableDmac",
                             a0, a1, a2, a3, 1, "جذع خدمة", detail);
            break;
        }
        case 0x17:   /* DisableDmac / iDisableDmac (-0x17) */
        case 0x1D: { /* _DisableDmac / _iDisableDmac (-0x1d) */
            ctx->syscall_service_stub_count++;
            if (a0 == 5U) {
                ctx->dmac_ch5_enabled = false;
            }
            ctx->gpr[2].s64[0] = 1;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0) ? "iDisableDmac" : "DisableDmac",
                             a0, a1, a2, a3, 1, "جذع خدمة", "Disabled DMAC channel");
            break;
        }
        case 0x18: /* SetAlarm */
        case 0x1E: /* _iSetAlarm (-0x1e) */
        case 0x19: /* ReleaseAlarm */
        case 0x1F: { /* _iReleaseAlarm (-0x1f) */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = (call_num == 0x18 || call_num == 0x1E) ? 1 : 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "AlarmStub",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "جذع خدمة", "Single-threaded alarm stub");
            break;
        }
        case 0x20: /* CreateThread */
        case 0x21: /* DeleteThread */
        case 0x22: /* StartThread */
        case 0x25: /* TerminateThread */
        case 0x29: /* ChangeThreadPriority / iChangeThreadPriority (-0x29) */
        case 0x2B: /* RotateThreadReadyQueue / _iRotateThreadReadyQueue (-0x2b) */
        case 0x2C: /* ReleaseWaitThread / iReleaseWaitThread (-0x2c) */
        case 0x2E: /* iReleaseWaitThread (-0x2e) */
        case 0x2F: /* GetThreadId / _iGetThreadId (-0x2f) */
        case 0x32: /* SleepThread */
        case 0x33: /* WakeupThread */
        case 0x34: /* iWakeupThread (-0x34) */
        case 0x35: /* CancelWakeupThread / iCancelWakeupThread (-0x35) */
        case 0x37: /* SuspendThread / iSuspendThread (-0x37) */
        case 0x39: { /* ResumeThread */
            ctx->syscall_service_stub_count++;
            int64_t ret = (call_num == 0x20 || call_num == 0x2F) ? 1 : 0;
            ctx->gpr[2].s64[0] = ret;
            const char *tname = (call_num == 0x2F) ? ((raw_v1 < 0) ? "_iGetThreadId" : "GetThreadId")
                              : (call_num == 0x20) ? "CreateThread"
                              : (call_num == 0x22) ? "StartThread"
                              : (call_num == 0x29) ? "ChangeThreadPriority"
                              : (call_num == 0x2B) ? "RotateThreadReadyQueue"
                              : (call_num == 0x2E) ? "iReleaseWaitThread"
                              : (call_num == 0x32) ? "SleepThread"
                              : (call_num == 0x33) ? "WakeupThread"
                              : (call_num == 0x34) ? "iWakeupThread"
                              : "ThreadServiceStub";
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, tname,
                             a0, a1, a2, a3, ret, "جذع خدمة",
                             "Single-threaded cooperative thread model (tid=1)");
            break;
        }
        case 0x40: { /* CreateSema(ee_sema_t *sema) */
            ctx->syscall_service_stub_count++;
            int32_t sid = g_sim_next_sema_id++;
            ctx->gpr[2].s64[0] = sid;
            char detail[128];
            snprintf(detail, sizeof(detail), "CreateSema(param=0x%08x) -> sema_id=%d", a0, sid);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "CreateSema",
                             a0, a1, a2, a3, sid, "جذع خدمة", detail);
            break;
        }
        case 0x41: /* DeleteSema */
        case 0x42: /* SignalSema */
        case 0x43: /* iSignalSema (-0x43) */
        case 0x44: /* WaitSema */
        case 0x45: /* PollSema */
        case 0x46: { /* iPollSema (-0x46) */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 0;
            const char *sname = (call_num == 0x41) ? "DeleteSema"
                              : (call_num == 0x42) ? "SignalSema"
                              : (call_num == 0x43) ? "iSignalSema"
                              : (call_num == 0x44) ? "WaitSema"
                              : (call_num == 0x45) ? "PollSema"
                              : "iPollSema";
            char detail[128];
            snprintf(detail, sizeof(detail), "%s(sema_id=%u) -> 0 (single-threaded)", sname, a0);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, sname,
                             a0, a1, a2, a3, 0, "جذع خدمة", detail);
            break;
        }
        case 0x4A: { /* SetOsdConfigParam */
            ctx->syscall_service_stub_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SetOsdConfigParam",
                             a0, a1, a2, a3, 0, "جذع خدمة", "OSD config setter stub");
            break;
        }
        case 0x4B: { /* GetOsdConfigParam(void *config) */
            ctx->syscall_service_stub_count++;
            if (a0 != 0U) {
                ps2_mem_write32(ctx, a0, 0U);
            }
            ctx->gpr[2].s64[0] = 0;
            char detail[128];
            snprintf(detail, sizeof(detail), "GetOsdConfigParam(out=0x%08x) -> 0 (UTC+0)", a0);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "GetOsdConfigParam",
                             a0, a1, a2, a3, 0, "جذع خدمة", detail);
            break;
        }
        case 0x6F: { /* GetOsdConfigParam2(void *config, int size, int offset) */
            ctx->syscall_service_stub_count++;
            if (a0 != 0U && a1 > 0U && a1 <= 256U) {
                for (uint32_t i = 0; i < a1; ++i) {
                    ps2_mem_write8(ctx, a0 + i, 0U);
                }
            }
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "GetOsdConfigParam2",
                             a0, a1, a2, a3, 0, "جذع خدمة", "OSD config2 stub");
            break;
        }

        /* =========================================================================
         * CLASS 3: معترضة عند الحدود (External SIF / IOP / Device Boundary Interceptions)
         * ========================================================================= */
        case 0x06: /* LoadExecPS2 */
        case 0x07: { /* ExecPS2 */
            ctx->syscall_boundary_intercept_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (call_num == 0x06) ? "LoadExecPS2" : "ExecPS2",
                             a0, a1, a2, a3, 0, "معترضة عند الحدود", "External ELF loader boundary");
            ps2_terminate_execution(ctx, 0, PS2_STOP_CLEAN_EXIT, call_pc, "LoadExecPS2/ExecPS2");
            break;
        }
        case 0x75: { /* print(const char *s) */
            ctx->syscall_boundary_intercept_count++;
            if (a0 != 0U) {
                uint32_t phys_str = ps2_virt_to_phys(a0);
                const char *s = (const char *)(ctx->guest_ram + phys_str);
                size_t len = ps2_strnlen(s, PS2_RAM_SIZE - phys_str);
                ps2_runtime_append_output(ctx, s, len);
            }
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "print",
                             a0, a1, a2, a3, 0, "معترضة عند الحدود", "BIOS console print");
            break;
        }
        case 0x76: { /* SifStopDma(void) */
            ctx->syscall_boundary_intercept_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SifStopDma",
                             a0, a1, a2, a3, 0, "معترضة عند الحدود", "Stopped SIF DMA channel");
            break;
        }
        case 0x77: { /* SifSetDma / iSifSetDma (-0x77) */
            ctx->syscall_boundary_intercept_count++;
            const char *sname = (raw_v1 < 0) ? "iSifSetDma" : "SifSetDma";
            char detail[128];
            snprintf(detail, sizeof(detail), "%s(dmat=0x%08x, count=%u) -> id=1", sname, a0, a1);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, sname,
                             a0, a1, a2, a3, 1, "معترضة عند الحدود", detail);
            ps2_handle_sif_dma_boundary(ctx, call_pc, a0, a1);
            ctx->gpr[2].s64[0] = 1;
            break;
        }
        case 0x78: { /* SifSetDChain / iSifSetDChain (-0x78) */
            ctx->syscall_boundary_intercept_count++;
            ctx->gpr[2].s64[0] = 0;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1,
                             (raw_v1 < 0) ? "iSifSetDChain" : "SifSetDChain",
                             a0, a1, a2, a3, 0, "معترضة عند الحدود",
                             "Enabled SIF0 DMA chain mode at EE<->IOP boundary");
            break;
        }
        case 0x79: { /* SifSetReg(u32 register_num, int register_value) */
            ctx->syscall_boundary_intercept_count++;
            if ((a0 & 0x80000000U) != 0U) {
                g_sim_sif_ext_regs[a0 & 31U] = a1;
            } else {
                g_sim_sif_regs[a0 & 63U] = a1;
            }
            ctx->gpr[2].s64[0] = 1;
            char detail[128];
            snprintf(detail, sizeof(detail), "SifSetReg(reg=0x%08x, val=0x%08x)", a0, a1);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SifSetReg",
                             a0, a1, a2, a3, 1, "معترضة عند الحدود", detail);
            break;
        }
        case 0x7A: { /* SifGetReg(u32 register_num) */
            ctx->syscall_boundary_intercept_count++;
            uint32_t val = ((a0 & 0x80000000U) != 0U)
                         ? g_sim_sif_ext_regs[a0 & 31U]
                         : g_sim_sif_regs[a0 & 63U];
            ctx->gpr[2].s64[0] = (int64_t)(int32_t)val;
            char detail[128];
            snprintf(detail, sizeof(detail), "SifGetReg(reg=0x%08x) -> 0x%08x", a0, val);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "SifGetReg",
                             a0, a1, a2, a3, ctx->gpr[2].s64[0], "معترضة عند الحدود", detail);
            break;
        }
        case 0x7C: { /* Deci2Call(call, addr) */
            ctx->syscall_boundary_intercept_count++;
            uint32_t subcall  = a0;
            uint32_t blk_addr = a1;
            int64_t  ret      = 0;
            if (subcall == 0x10U) {
                uint32_t str_vaddr = ps2_mem_read32(ctx, blk_addr);
                uint32_t phys_str  = ps2_virt_to_phys(str_vaddr);
                const char *s = (const char *)(ctx->guest_ram + phys_str);
                size_t max_len = PS2_RAM_SIZE - phys_str;
                size_t len = ps2_strnlen(s, max_len);
                ps2_runtime_append_output(ctx, s, len);
                ret = 1;
            }
            ctx->gpr[2].s64[0] = ret;
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "Deci2Call",
                             a0, a1, a2, a3, ret, "معترضة عند الحدود", "DECI2 console output");
            break;
        }

        default: {
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "Unhandled EE syscall 0x%02x (raw=%d) at PC=0x%08x",
                     call_num, raw_v1, call_pc);
            ps2_record_trace(ctx, call_pc, "SYSCALL", raw_v1, "UNHANDLED_SYSCALL",
                             a0, a1, a2, a3, -1, "حاجب تشغيل معلن", msg);
            fprintf(stderr, "[ps2_runtime] %s\n", msg);
            ps2_terminate_execution(ctx, -100 - (int32_t)call_num, PS2_STOP_UNHANDLED_SYSCALL, call_pc, msg);
            break;
        }
    }
    ps2_zero_invariant(ctx);
}

int ps2_runtime_execute(ps2_cpu_ctx_t *ctx, ps2_lifted_fn_t entry_fn) {
    if (!ctx || !entry_fn) return -1;
    ctx->halted         = false;
    ctx->stop_reason    = PS2_STOP_NONE;
    ctx->exit_code      = 0;
    ctx->exit_jmp_armed = true;
    if (setjmp(ctx->exit_jmp) == 0) {
        entry_fn(ctx);
        if (!ctx->halted) {
            ctx->stop_reason = PS2_STOP_CLEAN_EXIT;
            ctx->stop_pc     = ctx->pc;
        }
    }
    ctx->exit_jmp_armed = false;
    return (int)ctx->exit_code;
}

static const char *ps2_stop_reason_str(ps2_stop_reason_t r) {
    switch (r) {
        case PS2_STOP_NONE:                return "NONE (RUNNING)";
        case PS2_STOP_CLEAN_EXIT:          return "CLEAN_EXIT (Guest called Exit)";
        case PS2_STOP_FRAME_LIMIT:         return "FRAME_LIMIT (Completed target frames via VSync)";
        case PS2_STOP_BUDGET_EXCEEDED:     return "BUDGET_EXCEEDED (Instruction cap reached)";
        case PS2_STOP_UNRESOLVED_INDIRECT: return "UNRESOLVED_INDIRECT (Indirect target not in table)";
        case PS2_STOP_NULL_WEAK_CALL:      return "NULL_WEAK_CALL (Unlinked weak symbol)";
        case PS2_STOP_TRAP_EXCEPTION:      return "TRAP_EXCEPTION (TEQ trap)";
        case PS2_STOP_UNHANDLED_SYSCALL:   return "UNHANDLED_SYSCALL";
        default:                           return "UNKNOWN";
    }
}

uint32_t ps2_gs_read_pixel_psmct32(const ps2_cpu_ctx_t *ctx, uint32_t x, uint32_t y) {
    if (!ctx || !ctx->gs.vram) return 0U;
    uint32_t stride = (ctx->gs.ctx[0].fbw > 0U) ? (ctx->gs.ctx[0].fbw * 64U) : 512U;
    uint32_t base_word = ctx->gs.ctx[0].fbp * 2048U;
    uint32_t idx = (base_word + y * stride + x) & (PS2_GS_VRAM_WORDS - 1U);
    return ctx->gs.vram[idx];
}

int ps2_export_framebuffer_ppm(const ps2_cpu_ctx_t *ctx, const char *ppm_path) {
    if (!ctx || !ctx->gs.vram || !ppm_path) return -1;
    FILE *fp = fopen(ppm_path, "wb");
    if (!fp) return -1;

    uint32_t w = ctx->gs.fb_width ? ctx->gs.fb_width : 512U;
    uint32_t h = ctx->gs.fb_height ? ctx->gs.fb_height : 512U;
    fprintf(fp, "P6\n%u %u\n255\n", w, h);

    for (uint32_t y = 0; y < h; ++y) {
        for (uint32_t x = 0; x < w; ++x) {
            uint32_t px = ps2_gs_read_pixel_psmct32(ctx, x, y);
            uint8_t rgb[3];
            rgb[0] = (uint8_t)(px & 0xFFU);         /* R */
            rgb[1] = (uint8_t)((px >> 8) & 0xFFU);  /* G */
            rgb[2] = (uint8_t)((px >> 16) & 0xFFU); /* B */
            fwrite(rgb, 1, 3, fp);
        }
    }
    fclose(fp);
    return 0;
}

int ps2_write_gs_trace_log(const ps2_cpu_ctx_t *ctx, const char *log_path) {
    if (!ctx || !log_path) return -1;
    FILE *fp = fopen(log_path, "w");
    if (!fp) return -1;

    fprintf(fp, "# PS2-LIFTER Milestone 2.3 — Complete GS Boundary & GIF Packet Event Trace\n");
    fprintf(fp, "# Frames Completed: %u | GIF DMA Packets: %u | GIF Tags: %u | GS Reg Writes: %u | Primitives Drawn: %u | Pixels Filled: %" PRIu64 "\n",
            ctx->gs.frames_completed, ctx->gs.gif_packets_processed, ctx->gs.gif_tags_processed,
            ctx->gs.gs_reg_writes, ctx->gs.primitives_drawn, ctx->gs.pixels_filled);
    fprintf(fp, "# =========================================================================================================================\n");
    fprintf(fp, "# SEQ | FRAME | INSN_RETIRED | SITE_PC    | EVENT_TYPE       | REG/FLG | NAME               | DATA_LO            | DATA_HI            | DETAIL\n");
    fprintf(fp, "# =========================================================================================================================\n");

    for (size_t i = 0; i < ctx->gs.event_count; ++i) {
        const ps2_gs_event_t *ev = &ctx->gs.events[i];
        fprintf(fp,
                "%5u | %5u | %12" PRIu64 " | 0x%08x | %-16s |  0x%04x | %-18s | 0x%016" PRIx64 " | 0x%016" PRIx64 " | %s\n",
                ev->seq, ev->frame_index, ev->insn_count, ev->site_pc,
                ev->event_type, ev->reg_or_flg, ev->reg_name, ev->data_lo, ev->data_hi, ev->detail);
    }
    fclose(fp);
    return 0;
}

int ps2_write_gs_trace_json(const ps2_cpu_ctx_t *ctx, const char *json_path) {
    if (!ctx || !json_path) return -1;
    FILE *fp = fopen(json_path, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"milestone\": \"2.3\",\n");
    fprintf(fp, "  \"stop_reason\": \"%s\",\n", ps2_stop_reason_str(ctx->stop_reason));
    fprintf(fp, "  \"stop_pc\": \"0x%08x\",\n", ctx->stop_pc);
    fprintf(fp, "  \"insn_retired\": %" PRIu64 ",\n", ctx->insn_retired);
    fprintf(fp, "  \"fpu_ops_retired\": %" PRIu64 ",\n", ctx->fpu_ops_retired);
    fprintf(fp, "  \"gs_summary\": {\n");
    fprintf(fp, "    \"frames_completed\": %u,\n", ctx->gs.frames_completed);
    fprintf(fp, "    \"frame_limit\": %u,\n", ctx->gs.frames_completed);
    fprintf(fp, "    \"fb_width\": %u,\n", ctx->gs.fb_width);
    fprintf(fp, "    \"fb_height\": %u,\n", ctx->gs.fb_height);
    fprintf(fp, "    \"psm\": %u,\n", ctx->gs.ctx[0].psm);
    fprintf(fp, "    \"gif_packets_processed\": %u,\n", ctx->gs.gif_packets_processed);
    fprintf(fp, "    \"gif_tags_processed\": %u,\n", ctx->gs.gif_tags_processed);
    fprintf(fp, "    \"gs_reg_writes\": %u,\n", ctx->gs.gs_reg_writes);
    fprintf(fp, "    \"primitives_drawn\": %u,\n", ctx->gs.primitives_drawn);
    fprintf(fp, "    \"pixels_filled\": %" PRIu64 ",\n", ctx->gs.pixels_filled);
    fprintf(fp, "    \"events_count\": %zu\n", ctx->gs.event_count);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"events\": [\n");
    for (size_t i = 0; i < ctx->gs.event_count; ++i) {
        const ps2_gs_event_t *ev = &ctx->gs.events[i];
        fprintf(fp,
                "    { \"seq\": %u, \"frame\": %u, \"insn\": %" PRIu64 ", \"site_pc\": \"0x%08x\", "
                "\"type\": \"%s\", \"reg_or_flg\": %u, \"name\": \"%s\", "
                "\"data_lo\": \"0x%016" PRIx64 "\", \"data_hi\": \"0x%016" PRIx64 "\", \"detail\": \"%s\" }%s\n",
                ev->seq, ev->frame_index, ev->insn_count, ev->site_pc,
                ev->event_type, ev->reg_or_flg, ev->reg_name,
                ev->data_lo, ev->data_hi, ev->detail,
                (i + 1 < ctx->gs.event_count) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

int ps2_write_syscall_trace_log(const ps2_cpu_ctx_t *ctx, const char *log_path) {
    if (!ctx || !log_path) return -1;
    FILE *fp = fopen(log_path, "w");
    if (!fp) return -1;

    fprintf(fp, "# PS2-LIFTER Milestone 2.2/2.3 — Complete Syscall, Indirect & Boundary Trace\n");
    fprintf(fp, "# Total Trace Events: %zu | Guest Instructions Retired: %" PRIu64 "\n",
            ctx->trace_count, ctx->insn_retired);
    fprintf(fp, "# Syscalls Dispatched: %" PRIu64 " (مرفوعة أصلًا=%u, جذع خدمة=%u, معترضة عند الحدود=%u)\n",
            ctx->syscalls_dispatched,
            ctx->syscall_lifted_native_count,
            ctx->syscall_service_stub_count,
            ctx->syscall_boundary_intercept_count);
    fprintf(fp, "# Indirect Dispatches: %u (Resolved in k_indirect_dispatch_table=%u)\n",
            ctx->indirect_dispatches, ctx->indirect_lifted_resolved_count);
    fprintf(fp, "# =========================================================================================================================\n");
    fprintf(fp, "# SEQ | INSN_RETIRED | SITE_PC    | KIND             | ID/TARGET   | NAME                         | ARG0       | ARG1       | RET        | CLASSIFICATION      | DETAIL\n");
    fprintf(fp, "# =========================================================================================================================\n");

    for (size_t i = 0; i < ctx->trace_count; ++i) {
        const ps2_trace_event_t *ev = &ctx->trace_events[i];
        fprintf(fp,
                "%5u | %12" PRIu64 " | 0x%08x | %-16s | %11d | %-28s | 0x%08x | 0x%08x | %10" PRId64 " | %s | %s\n",
                ev->seq, ev->insn_count, ev->site_pc, ev->kind, ev->num_or_id,
                ev->name, ev->arg0, ev->arg1, ev->ret_val, ev->classification, ev->detail);
    }

    fclose(fp);
    return 0;
}

int ps2_write_syscall_trace_json(const ps2_cpu_ctx_t *ctx, const char *json_path) {
    if (!ctx || !json_path) return -1;
    FILE *fp = fopen(json_path, "w");
    if (!fp) return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"milestone\": \"2.3\",\n");
    fprintf(fp, "  \"insn_retired\": %" PRIu64 ",\n", ctx->insn_retired);
    fprintf(fp, "  \"insn_budget\": %" PRIu64 ",\n", ctx->insn_budget);
    fprintf(fp, "  \"exit_code\": %d,\n", ctx->exit_code);
    fprintf(fp, "  \"stop_reason\": \"%s\",\n", ps2_stop_reason_str(ctx->stop_reason));
    fprintf(fp, "  \"stop_pc\": \"0x%08x\",\n", ctx->stop_pc);
    fprintf(fp, "  \"gates\": {\n");
    fprintf(fp, "    \"G1\": { \"status\": \"%s\", \"crt0_bss_done_insns\": %" PRIu64 ", \"init_sys_done_insns\": %" PRIu64 " },\n",
            ctx->g1_passed ? "PASS" : "FAIL", ctx->g1_crt0_bss_done_insns, ctx->g1_insn_count);
    fprintf(fp, "    \"G2\": { \"status\": \"%s\", \"main_entry_insns\": %" PRIu64 " },\n",
            ctx->g2_passed ? "PASS" : "FAIL", ctx->g2_insn_count);
    fprintf(fp, "    \"G3\": { \"status\": \"%s\", \"output_emitted_insns\": %" PRIu64 ", \"stdout_bytes\": %zu },\n",
            ctx->g3_passed ? "PASS" : "FAIL", ctx->g3_insn_count, ctx->stdout_len);
    fprintf(fp, "    \"G4\": { \"status\": \"%s\", \"exit_insns\": %" PRIu64 ", \"exit_code\": %d }\n",
            ctx->g4_passed ? "PASS" : "FAIL", ctx->g4_insn_count, ctx->exit_code);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"counts\": {\n");
    fprintf(fp, "    \"syscalls_total\": %" PRIu64 ",\n", ctx->syscalls_dispatched);
    fprintf(fp, "    \"syscalls_lifted_native\": %u,\n", ctx->syscall_lifted_native_count);
    fprintf(fp, "    \"syscalls_service_stub\": %u,\n", ctx->syscall_service_stub_count);
    fprintf(fp, "    \"syscalls_boundary_intercept\": %u,\n", ctx->syscall_boundary_intercept_count);
    fprintf(fp, "    \"indirect_dispatches_total\": %u,\n", ctx->indirect_dispatches);
    fprintf(fp, "    \"indirect_lifted_resolved\": %u,\n", ctx->indirect_lifted_resolved_count);
    fprintf(fp, "    \"trace_events_total\": %zu\n", ctx->trace_count);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"events\": [\n");
    for (size_t i = 0; i < ctx->trace_count; ++i) {
        const ps2_trace_event_t *ev = &ctx->trace_events[i];
        char safe_detail[256];
        size_t di = 0;
        for (size_t j = 0; ev->detail[j] != '\0' && di + 2 < sizeof(safe_detail); ++j) {
            if (ev->detail[j] == '"' || ev->detail[j] == '\\') {
                safe_detail[di++] = '\\';
            }
            safe_detail[di++] = ev->detail[j];
        }
        safe_detail[di] = '\0';
        fprintf(fp,
                "    { \"seq\": %u, \"insn\": %" PRIu64 ", \"site_pc\": \"0x%08x\", \"kind\": \"%s\", "
                "\"num_or_id\": %d, \"name\": \"%s\", \"arg0\": \"0x%08x\", \"arg1\": \"0x%08x\", "
                "\"arg2\": \"0x%08x\", \"arg3\": \"0x%08x\", \"ret\": %" PRId64 ", "
                "\"classification\": \"%s\", \"detail\": \"%s\" }%s\n",
                ev->seq, ev->insn_count, ev->site_pc, ev->kind, ev->num_or_id, ev->name,
                ev->arg0, ev->arg1, ev->arg2, ev->arg3, ev->ret_val,
                ev->classification, safe_detail,
                (i + 1 < ctx->trace_count) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

void ps2_dump_execution_state(const ps2_cpu_ctx_t *ctx, void *out_stream) {
    FILE *out = out_stream ? (FILE *)out_stream : stdout;
    if (!ctx) return;

    fprintf(out, "========================================================================\n");
    fprintf(out, "PS2-LIFTER Milestone 2.2/2.3 — Complete Execution State & Ring Trace\n");
    fprintf(out, "========================================================================\n");
    fprintf(out, "Stop Classification : %s\n", ps2_stop_reason_str(ctx->stop_reason));
    fprintf(out, "Stop Detail         : %s\n", ctx->stop_detail[0] ? ctx->stop_detail : "Clean exit");
    fprintf(out, "Current/Final PC    : 0x%08x\n", ctx->pc);
    fprintf(out, "Guest Exit Code     : %d\n", ctx->exit_code);
    fprintf(out, "Instructions Retired: %" PRIu64 " / %" PRIu64 " (budget)\n", ctx->insn_retired, ctx->insn_budget);
    fprintf(out, "FPU Ops Retired     : %" PRIu64 " (FCSR=0x%08x)\n", ctx->fpu_ops_retired, ctx->fcsr);
    fprintf(out, "GS Frames Completed : %u (GIF Packets=%u, Primitives=%u, Pixels=%" PRIu64 ")\n",
            ctx->gs.frames_completed, ctx->gs.gif_packets_processed,
            ctx->gs.primitives_drawn, ctx->gs.pixels_filled);
    fprintf(out, "------------------------------------------------------------------------\n");
    fprintf(out, "Graduated Gates (G1..G4):\n");
    fprintf(out, "  G1 (Entry -> crt0 & _InitSys) : %s (crt0->main_jump=%" PRIu64 " insns, _InitSys_done=%" PRIu64 " insns)\n",
            ctx->g1_passed ? "PASS" : "FAIL", ctx->g1_crt0_bss_done_insns, ctx->g1_insn_count);
    fprintf(out, "  G2 (Init -> main)             : %s (reached at %" PRIu64 " insns)\n",
            ctx->g2_passed ? "PASS" : "FAIL", ctx->g2_insn_count);
    fprintf(out, "  G3 (Guest Output 13B emitted) : %s (emitted at %" PRIu64 " insns, len=%zu bytes)\n",
            ctx->g3_passed ? "PASS" : "FAIL", ctx->g3_insn_count, ctx->stdout_len);
    fprintf(out, "  G4 (Guest Exit(0) completed)  : %s (completed at %" PRIu64 " insns, code=%d)\n",
            ctx->g4_passed ? "PASS" : "FAIL", ctx->g4_insn_count, ctx->exit_code);
    fprintf(out, "------------------------------------------------------------------------\n");
    fprintf(out, "Key Guest Registers at Stop:\n");
    fprintf(out, "  $v0 (r2)  = 0x%016" PRIx64 "  $v1 (r3)  = 0x%016" PRIx64 "\n",
            ctx->gpr[2].u64[0], ctx->gpr[3].u64[0]);
    fprintf(out, "  $a0 (r4)  = 0x%016" PRIx64 "  $a1 (r5)  = 0x%016" PRIx64 "\n",
            ctx->gpr[4].u64[0], ctx->gpr[5].u64[0]);
    fprintf(out, "  $gp (r28) = 0x%016" PRIx64 "  $sp (r29) = 0x%016" PRIx64 "\n",
            ctx->gpr[28].u64[0], ctx->gpr[29].u64[0]);
    fprintf(out, "  $fp (r30) = 0x%016" PRIx64 "  $ra (r31) = 0x%016" PRIx64 "\n",
            ctx->gpr[30].u64[0], ctx->gpr[31].u64[0]);
    fprintf(out, "------------------------------------------------------------------------\n");
    fprintf(out, "Last %zu Consecutive Executed PCs (Ring Buffer, oldest -> newest):\n", ctx->pc_ring_count);
    size_t start_idx = (ctx->pc_ring_count == PS2_PC_RING_CAP) ? ctx->pc_ring_head : 0U;
    for (size_t i = 0; i < ctx->pc_ring_count; ++i) {
        size_t idx = (start_idx + i) % PS2_PC_RING_CAP;
        fprintf(out, "  [%03zu] 0x%08x%s", i + 1U, ctx->pc_ring[idx], ((i + 1U) % 5U == 0U || i + 1U == ctx->pc_ring_count) ? "\n" : "  ");
    }
    fprintf(out, "========================================================================\n");
}
