// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ExpansionPak

#include "emitter.h"
#include "backend/c_cfg.h"

#include <stdlib.h>
#include <string.h>

static u32 cr_field_shift(u8 crf) {
    return 4u * (7u - (u32)crf);
}

static u32 ppc_mask32(u8 mb, u8 me) {
    u32 mask = 0;
    u8 bit = mb;

    for (;;) {
        mask |= 0x80000000u >> bit;
        if (bit == me)
            break;
        bit = (u8)((bit + 1) & 31);
    }

    return mask;
}

static void emit_set_cr0_from_gpr(FILE* out, u8 reg) {
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        s32 cr_value = (s32)ctx->gpr[%u];\n", reg);
    fprintf(out, "        if (cr_value < 0)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (cr_value > 0)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (cr_value == 0) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & 0x0FFFFFFFu) | (cr_bits << 28);\n");
}

static void emit_set_cr1_from_fpscr(FILE* out) {
    fprintf(out, "        ctx->cr = (ctx->cr & 0xF0FFFFFFu) | ((ctx->fpscr >> 4) & 0x0F000000u);\n");
}

static void emit_compare_s32(FILE* out, u8 crf, const char* lhs, const char* rhs) {
    u32 shift = cr_field_shift(crf);

    fprintf(out, "    {\n");
    fprintf(out, "        s32 val_a = (s32)(%s);\n", lhs);
    fprintf(out, "        s32 val_b = (s32)(%s);\n", rhs);
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        if (val_a < val_b)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (val_a > val_b)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (val_a == val_b) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
            shift, shift);
    fprintf(out, "    }\n");
}

static void emit_compare_u32(FILE* out, u8 crf, const char* lhs, const char* rhs) {
    u32 shift = cr_field_shift(crf);

    fprintf(out, "    {\n");
    fprintf(out, "        u32 val_a = (u32)(%s);\n", lhs);
    fprintf(out, "        u32 val_b = (u32)(%s);\n", rhs);
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        if (val_a < val_b)  cr_bits |= 0x8u;\n");
    fprintf(out, "        if (val_a > val_b)  cr_bits |= 0x4u;\n");
    fprintf(out, "        if (val_a == val_b) cr_bits |= 0x2u;\n");
    fprintf(out, "        cr_bits |= (ctx->xer >> 31) & 1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
            shift, shift);
    fprintf(out, "    }\n");
}

static void emit_fcompare(FILE* out, const PPCInst* inst) {
    u32 shift = cr_field_shift(inst->crfD);

    fprintf(out, "    {\n");
    fprintf(out, "        f64 val_a = ctx->fpr[%u];\n", inst->rA);
    fprintf(out, "        f64 val_b = ctx->fpr[%u];\n", inst->rB);
    fprintf(out, "        u32 cr_bits = 0;\n");
    fprintf(out, "        if (val_a < val_b)       cr_bits = 0x8u;\n");
    fprintf(out, "        else if (val_a > val_b)  cr_bits = 0x4u;\n");
    fprintf(out, "        else if (val_a == val_b) cr_bits = 0x2u;\n");
    fprintf(out, "        else                     cr_bits = 0x1u;\n");
    fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
            shift, shift);
    fprintf(out, "    }\n");
}

static void emit_dform_ea(FILE* out, u8 ra, s16 simm, bool update) {
    if (ra == 0 && !update) {
        fprintf(out, "(u32)(s32)(%d)", (int)simm);
    } else {
        fprintf(out, "ctx->gpr[%u] + (u32)(s32)(%d)", ra, (int)simm);
    }
}

static void emit_xform_ea(FILE* out, u8 ra, u8 rb, bool update) {
    if (ra == 0 && !update) {
        fprintf(out, "ctx->gpr[%u]", rb);
    } else {
        fprintf(out, "ctx->gpr[%u] + ctx->gpr[%u]", ra, rb);
    }
}


#if defined(_MSC_VER) && !defined(__clang__)
#define DOLRECOMP_TLS __declspec(thread)
#else
#define DOLRECOMP_TLS _Thread_local
#endif
/* ---- base-register proofs (hot pass only; see dolrecomp_base_host) ----
 * r1 (stack), r2 and r13 (small-data bases) address most loads and stores.
 * Within a block the first access off one emits a check that sets hbN and
 * bails to the cold companion at that instruction if it fails (the hot path
 * charged the whole block's cycles at its leader and the cold companion
 * charges only at leaders, so resuming there is exact). Later accesses off
 * the same base use hbN directly, as long as the base moved by at most
 * g_hb_delta through addi / update-form accesses and the access stays inside
 * DOLRECOMP_BASE_MARGIN. A label, any other write to the base, or an
 * instruction that can change the reservation/journal or run arbitrary host
 * code drops the proof. */
static DOLRECOMP_TLS bool g_hb_track;
static DOLRECOMP_TLS u32 g_hb_func;
static DOLRECOMP_TLS u32 g_hb_proven;   /* bit r: hb<r> valid */
static DOLRECOMP_TLS s32 g_hb_delta[32]; /* base moved since the check */

static bool hb_reg(u32 r) { return r == 1 || r == 2 || r == 13; }

static void hb_reset(void) { g_hb_proven = 0; }

static bool hb_is_update_dform(PPCOpcode op) {
    switch (op) {
    case PPC_OP_LWZU: case PPC_OP_LBZU: case PPC_OP_LHZU: case PPC_OP_LHAU:
    case PPC_OP_STWU: case PPC_OP_STBU: case PPC_OP_STHU:
    case PPC_OP_LFSU: case PPC_OP_LFDU: case PPC_OP_STFSU: case PPC_OP_STFDU:
        return true;
    default:
        return false;
    }
}

/* The proof state after inst. */
static void hb_update(const PPCInst* inst) {
    if (!g_hb_track)
        return;
    switch (inst->op) {
    case PPC_OP_B: case PPC_OP_BC: case PPC_OP_BCLR: case PPC_OP_BCCTR:
    case PPC_OP_SC: case PPC_OP_RFI: case PPC_OP_TW: case PPC_OP_TWI:
    case PPC_OP_MTMSR: case PPC_OP_MTSPR: case PPC_OP_MFSPR:
    case PPC_OP_UNKNOWN: case PPC_OP_LWARX: case PPC_OP_STWCX:
    case PPC_OP_LMW: case PPC_OP_LSWI: case PPC_OP_LSWX:
    case PPC_OP_DCBZ: case PPC_OP_DCBZ_L: case PPC_OP_DCBI:
        hb_reset();
        return;
    /* no general-purpose register written */
    case PPC_OP_STW: case PPC_OP_STB: case PPC_OP_STH:
    case PPC_OP_STWX: case PPC_OP_STBX: case PPC_OP_STHX:
    case PPC_OP_STWBRX: case PPC_OP_STHBRX: case PPC_OP_STMW:
    case PPC_OP_CMP: case PPC_OP_CMPI: case PPC_OP_CMPL: case PPC_OP_CMPLI:
        return;
    case PPC_OP_ADDI:
        if (inst->rD == inst->rA && hb_reg(inst->rD) &&
            (g_hb_proven >> inst->rD & 1u)) {
            g_hb_delta[inst->rD] += inst->simm;
            return;
        }
        break;
    default:
        break;
    }
    if (hb_is_update_dform(inst->op) && hb_reg(inst->rA)) {
        /* rA advanced by simm; a load's rD is never rA (invalid form) */
        if (g_hb_proven >> inst->rA & 1u)
            g_hb_delta[inst->rA] += inst->simm;
        if (inst->rD != inst->rA)
            g_hb_proven &= ~(1u << inst->rD);
        return;
    }
    if (ppc_op_uses_fpu(inst->op)) {
        /* FP ops write no GPR, except the update forms (handled above and
         * below: an indexed update writes rA) */
        switch (inst->op) {
        case PPC_OP_LFSUX: case PPC_OP_LFDUX: case PPC_OP_STFSUX:
        case PPC_OP_STFDUX: case PPC_OP_PSQ_LU: case PPC_OP_PSQ_LUX:
        case PPC_OP_PSQ_STU: case PPC_OP_PSQ_STUX:
            g_hb_proven &= ~(1u << inst->rA);
            break;
        default:
            break;
        }
        return;
    }
    g_hb_proven &= ~((1u << inst->rD) | (1u << inst->rA));
}

/* For a D-form access of `size` bytes off inst->rA: the hb variable to use
 * (emitting the check first if the block has not proven it), or NULL for
 * the ordinary helper path. */
static const char* hb_for_access(FILE* out, const PPCInst* inst, u32 size) {
    static const char* names[32] = {[1] = "hb1", [2] = "hb2", [13] = "hb13"};
    const u32 r = inst->rA;
    if (!g_hb_track || !hb_reg(r))
        return NULL;
    s64 reach = (s64)g_hb_delta[r] + inst->simm;
    if (reach < 0)
        reach = -reach;
    if (!(g_hb_proven >> r & 1u) ||
        reach + (s64)size > (s64)(0x20000 - 8)) {
        fprintf(out, "    hb%u = dolrecomp_base_host(ctx, ctx->gpr[%u]);\n", r, r);
        fprintf(out, "    if (!hb%u) { ctx->pc = 0x%08Xu; func_%08X_cold(ctx); return; }\n",
                r, inst->address, g_hb_func);
        g_hb_proven |= 1u << r;
        g_hb_delta[r] = 0;
    }
    return names[r];
}

/* "mem_readN(ctx, ea)" inside expr, rewritten to read through hb. */
static void emit_hb_expr(FILE* out, const char* expr, const char* hb) {
    const char* at = hb ? strstr(expr, "mem_read") : NULL;
    if (!at) {
        fputs(expr, out);
        return;
    }
    const char* args = strstr(at, "(ctx, ");
    fprintf(out, "%.*sdolrecomp_hb_%.*s(%s, %s", (int)(at - expr), expr,
            (int)(args - at - 4), at + 4, hb, args + 6);
}

static void emit_load(FILE* out, const PPCInst* inst, const char* read_expr,
                      bool update) {
    const u32 size = strstr(read_expr, "read32") ? 4 :
                     strstr(read_expr, "read16") ? 2 : 1;
    const char* hb = hb_for_access(out, inst, size);
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    fprintf(out, "        ctx->gpr[%u] = ", inst->rD);
    emit_hb_expr(out, read_expr, hb);
    fprintf(out, ";\n");
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_loadx(FILE* out, const PPCInst* inst, const char* read_expr,
                       bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    fprintf(out, "        ctx->gpr[%u] = %s;\n", inst->rD, read_expr);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_store(FILE* out, const PPCInst* inst, const char* write_func,
                       const char* cast_type, bool update) {
    const u32 size = strstr(write_func, "32") ? 4 :
                     strstr(write_func, "16") ? 2 : 1;
    const char* hb = hb_for_access(out, inst, size);
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    if (hb)
        fprintf(out, "        dolrecomp_hb_%s(%s, ea, (%s)ctx->gpr[%u]);\n",
                write_func + 4, hb, cast_type, inst->rS);
    else
        fprintf(out, "        %s(ctx, ea, (%s)ctx->gpr[%u]);\n",
                write_func, cast_type, inst->rS);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_storex(FILE* out, const PPCInst* inst, const char* write_func,
                        const char* cast_type, bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    fprintf(out, "        %s(ctx, ea, (%s)ctx->gpr[%u]);\n",
            write_func, cast_type, inst->rS);
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fload(FILE* out, const PPCInst* inst, bool single,
                       bool update) {
    const char* hb = hb_for_access(out, inst, single ? 4 : 8);
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        f64 value = (f64)dolrecomp_f32_from_bits(");
        emit_hb_expr(out, "mem_read32(ctx, ea)", hb);
        fprintf(out, ");\n");
        fprintf(out, "        ctx->fpr[%u] = value;\n", inst->rD);
        fprintf(out, "        ctx->ps1[%u] = value;\n", inst->rD);
    } else {
        fprintf(out, "        ctx->fpr[%u] = dolrecomp_f64_from_bits(", inst->rD);
        emit_hb_expr(out, "mem_read64(ctx, ea)", hb);
        fprintf(out, ");\n");
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_floadx(FILE* out, const PPCInst* inst, bool single,
                        bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        f64 value = (f64)dolrecomp_f32_from_bits(mem_read32(ctx, ea));\n");
        fprintf(out, "        ctx->fpr[%u] = value;\n", inst->rD);
        fprintf(out, "        ctx->ps1[%u] = value;\n", inst->rD);
    } else {
        fprintf(out, "        ctx->fpr[%u] = dolrecomp_f64_from_bits(mem_read64(ctx, ea));\n",
                inst->rD);
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fstore(FILE* out, const PPCInst* inst, bool single,
                        bool update) {
    const char* hb = hb_for_access(out, inst, single ? 4 : 8);
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_dform_ea(out, inst->rA, inst->simm, update);
    fprintf(out, ";\n");
    if (single && hb) {
        fprintf(out, "        dolrecomp_hb_write32(%s, ea, dolrecomp_f32_to_bits((f32)ctx->fpr[%u]));\n",
                hb, inst->rS);
    } else if (single) {
        fprintf(out, "        mem_write32(ctx, ea, dolrecomp_f32_to_bits((f32)ctx->fpr[%u]));\n",
                inst->rS);
    } else if (hb) {
        fprintf(out, "        dolrecomp_hb_write64(%s, ea, dolrecomp_f64_to_bits(ctx->fpr[%u]));\n",
                hb, inst->rS);
    } else {
        fprintf(out, "        mem_write64(ctx, ea, dolrecomp_f64_to_bits(ctx->fpr[%u]));\n",
                inst->rS);
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_fstorex(FILE* out, const PPCInst* inst, bool single,
                         bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, update);
    fprintf(out, ";\n");
    if (single) {
        fprintf(out, "        mem_write32(ctx, ea, dolrecomp_f32_to_bits((f32)ctx->fpr[%u]));\n",
                inst->rS);
    } else {
        fprintf(out, "        mem_write64(ctx, ea, dolrecomp_f64_to_bits(ctx->fpr[%u]));\n",
                inst->rS);
    }
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_psq_load(FILE* out, const PPCInst* inst, bool indexed,
                          bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    if (indexed) {
        emit_xform_ea(out, inst->rA, inst->rB, update);
    } else {
        emit_dform_ea(out, inst->rA, inst->simm, update);
    }
    fprintf(out, ";\n");
    /* Only the slow path can raise, so only it is followed by the exception
     * test (a return, which would otherwise stop the compiler keeping guest
     * state in registers across every psq_l). */
    fprintf(out, "        if (!dolrecomp_psq_load_fast(ctx, %uu, ea, %s, %uu, %s)) {\n",
            inst->rD, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false");
    fprintf(out, "            ppc_psq_load_slow(ctx, %uu, ea, %s, %uu, %s, 0x%08Xu);\n",
            inst->rD, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false", inst->address);
    fprintf(out, "            if (ctx->exception) return;\n");
    fprintf(out, "        }\n");
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_psq_store(FILE* out, const PPCInst* inst, bool indexed,
                           bool update) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    if (indexed) {
        emit_xform_ea(out, inst->rA, inst->rB, update);
    } else {
        emit_dform_ea(out, inst->rA, inst->simm, update);
    }
    fprintf(out, ";\n");
    fprintf(out, "        if (!dolrecomp_psq_store_fast(ctx, %uu, ea, %s, %uu, %s)) {\n",
            inst->rS, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false");
    fprintf(out, "            ppc_psq_store_slow(ctx, %uu, ea, %s, %uu, %s, 0x%08Xu);\n",
            inst->rS, inst->w ? "true" : "false", inst->i,
            indexed ? "true" : "false", inst->address);
    fprintf(out, "            if (ctx->exception) return;\n");
    fprintf(out, "        }\n");
    if (update) {
        fprintf(out, "        ctx->gpr[%u] = ea;\n", inst->rA);
    }
    fprintf(out, "    }\n");
}

static void emit_dcbz(FILE* out, const PPCInst* inst) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 ea = ");
    emit_xform_ea(out, inst->rA, inst->rB, false);
    fprintf(out, ";\n");
    fprintf(out, "        ea &= ~31u;\n");
    fprintf(out, "        for (u32 i = 0; i < 32; i += 4) mem_write32(ctx, ea + i, 0);\n");
    fprintf(out, "    }\n");
}

static void emit_branch_condition(FILE* out, u8 bo, u8 bi) {
    bool ctr_ignored = (bo & 0x04) != 0;
    bool cond_ignored = (bo & 0x10) != 0;

    if (!ctr_ignored) {
        fprintf(out, "        ctx->ctr--;\n");
        fprintf(out, "        bool ctr_ok = (((ctx->ctr != 0) ? 1u : 0u) ^ %uu) != 0;\n",
                (bo >> 1) & 1u);
    } else {
        fprintf(out, "        bool ctr_ok = true;\n");
    }

    if (!cond_ignored) {
        u32 mask = 0x80000000u >> bi;
        fprintf(out, "        bool cr_ok = (((ctx->cr & 0x%08Xu) != 0) == %s);\n",
                mask, ((bo >> 3) & 1u) ? "true" : "false");
    } else {
        fprintf(out, "        bool cr_ok = true;\n");
    }
}

/* Start addresses of guest functions emitted in function mode (fn_X). Set
 * before chunk jobs run and read-only while they run in parallel. */
static u32* g_fn_starts;
static u32 g_fn_count;

static int compare_u32(const void* a, const void* b) {
    u32 x = *(const u32*)a, y = *(const u32*)b;
    return x < y ? -1 : x > y;
}

void emitter_set_fn_set(const u32* starts, u32 count) {
    free(g_fn_starts);
    g_fn_starts = NULL;
    g_fn_count = 0;
    if (!starts || !count)
        return;
    g_fn_starts = (u32*)malloc(count * sizeof(u32));
    if (!g_fn_starts)
        return;
    memcpy(g_fn_starts, starts, count * sizeof(u32));
    qsort(g_fn_starts, count, sizeof(u32), compare_u32);
    g_fn_count = count;
}

bool emitter_fn_contains_start(u32 address) {
    return g_fn_count &&
           bsearch(&address, g_fn_starts, g_fn_count, sizeof(u32), compare_u32) != NULL;
}

static bool branch_target_is_local(u32 func_start, u32 func_end, u32 target) {
    return target >= func_start && target < func_end && ((target - func_start) & 3u) == 0;
}

static void emit_direct_branch(FILE* out, const PPCInst* inst,
                               bool local_target, bool direct_backedge,
                               u32 func_start, u32 func_end, bool cold) {
    bool local_backward = local_target && inst->branch_target <= inst->address;

    if (inst->lk) {
        u32 continuation = inst->address + 4u;
        fprintf(out, "            ctx->lr = 0x%08Xu;\n", continuation);
        if (local_target) {
            if (local_backward) {
                fprintf(out, "            if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) {\n");
                fprintf(out, "                ctx->pc = 0x%08Xu;\n", inst->branch_target);
                fprintf(out, "                return;\n");
                fprintf(out, "            }\n");
            }
            if (emitter_fn_contains_start(inst->branch_target)) {
                /* Same-chunk call to a converted function: run it natively.
                 * Status 0 means the chunk code would have returned here; 1
                 * that control reached the callee's bclr, after which this
                 * chunk's return_dispatch runs exactly as the old blr did
                 * (the continuation is one of its local return targets). */
                fprintf(out, "            { int fn_%08X_direct(CPUState* ctx); "
                             "if (!fn_%08X_direct(ctx)) return; }\n",
                        inst->branch_target, inst->branch_target);
                fprintf(out, "            goto return_dispatch_%08X;\n", func_start);
            } else {
                fprintf(out, "            goto label_%08X;\n", inst->branch_target);
            }
        } else if (!cold && continuation >= func_start && continuation < func_end) {
            /* Cross-chunk call: run the callee here rather than returning the
             * target to the dispatcher, then resume at the return address in
             * place. The guard repeats, and only repeats, what the dispatcher
             * checks between blocks: the call resolved, no exception is
             * pending, control really came back to this call's continuation
             * (an HLE'd target leaves pc at lr, a `blr` in the callee sets it),
             * and the guest is not parked in its idle loop. Any other outcome
             * returns with ctx->pc already holding the right address, exactly
             * as the old `ctx->pc = target; return;` shape did. */
            fprintf(out, "            if (dolrecomp_direct_call(ctx, 0x%08Xu) &&\n",
                    inst->branch_target);
            fprintf(out, "                !ctx->exception &&\n");
            fprintf(out, "                ctx->pc == 0x%08Xu &&\n", continuation);
            fprintf(out, "                ctx->downcount > DOLRECOMP_IDLE_PARK_THRESHOLD) {\n");
            fprintf(out, "                goto label_%08X;\n", continuation);
            fprintf(out, "            }\n");
            fprintf(out, "            return;\n");
        } else {
            fprintf(out, "            ctx->pc = 0x%08Xu;\n", inst->branch_target);
            fprintf(out, "            return;\n");
        }
        return;
    }
    if (local_backward) {
        if (direct_backedge) {
            fprintf(out, "            if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) {\n");
            fprintf(out, "                ctx->pc = 0x%08Xu;\n", inst->branch_target);
            fprintf(out, "                return;\n");
            fprintf(out, "            }\n");
            fprintf(out, "            goto label_%08X;\n", inst->branch_target);
        } else {
            fprintf(out, "            ctx->pc = 0x%08Xu;\n", inst->branch_target);
            fprintf(out, "            return;\n");
        }
    } else if (local_target) {
        fprintf(out, "            goto label_%08X;\n", inst->branch_target);
    } else {
        fprintf(out, "            ctx->pc = 0x%08Xu;\n", inst->branch_target);
        fprintf(out, "            return;\n");
    }
}

static void emit_dynamic_branch(FILE* out, const PPCInst* inst,
                                const char* target_expr,
                                bool route_local_returns,
                                u32 function_address) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 target = %s;\n", target_expr);
    emit_branch_condition(out, inst->bo, inst->bi);
    fprintf(out, "        if (ctr_ok && cr_ok) {\n");
    if (inst->lk) {
        fprintf(out, "            ctx->lr = 0x%08Xu;\n", inst->address + 4);
    }
    fprintf(out, "            ctx->pc = target;\n");
    if (route_local_returns)
        fprintf(out, "            goto return_dispatch_%08X;\n", function_address);
    else
        fprintf(out, "            return;\n");
    fprintf(out, "        }\n");
    fprintf(out, "    }\n");
}

static void emit_cr_logical(FILE* out, const PPCInst* inst, const char* expr) {
    fprintf(out, "    {\n");
    fprintf(out, "        u32 a = (ctx->cr >> (31u - %uu)) & 1u;\n", inst->rA);
    fprintf(out, "        u32 b = (ctx->cr >> (31u - %uu)) & 1u;\n", inst->rB);
    fprintf(out, "        u32 mask = 0x80000000u >> %u;\n", inst->rD);
    fprintf(out, "        u32 value = (%s) & 1u;\n", expr);
    fprintf(out, "        ctx->cr = (ctx->cr & ~mask) | (value ? mask : 0u);\n");
    fprintf(out, "    }\n");
}

static void emit_record_if_needed(FILE* out, const PPCInst* inst, u8 reg) {
    if (inst->rc) {
        emit_set_cr0_from_gpr(out, reg);
    }
}

static const char* emit_cpu_macro(DolRecompCPU cpu) {
    switch (cpu) {
    case DOLRECOMP_CPU_BROADWAY:
        return "BROADWAY";
    case DOLRECOMP_CPU_ESPRESSO:
        return "ESPRESSO";
    case DOLRECOMP_CPU_GEKKO:
    default:
        return "GEKKO";
    }
}

static const char* emit_cpu_label(DolRecompCPU cpu) {
    switch (cpu) {
    case DOLRECOMP_CPU_BROADWAY:
        return "broadway";
    case DOLRECOMP_CPU_ESPRESSO:
        return "espresso";
    case DOLRECOMP_CPU_GEKKO:
    default:
        return "gekko";
    }
}

void emit_header_for_cpu(FILE* out, DolRecompCPU cpu) {
    fprintf(out,
        "// DolRecomp output\n"
        "// cpu: %s\n"
        "\n"
        "#ifndef RECOMP_GENERATED_H\n"
        "#define RECOMP_GENERATED_H\n"
        "\n"
        "#define DOLRECOMP_CPU_%s 1\n"
        "#define DOLRECOMP_CPU_NAME \"%s\"\n"
        "\n"
        "#include <string.h>\n"
        "#include <math.h>\n"
        "#ifndef DOLRECOMP_CPU_HEADER\n"
        "#define DOLRECOMP_CPU_HEADER \"cpu/cpu.h\"\n"
        "#endif\n"
        "#include DOLRECOMP_CPU_HEADER\n"
        "\n"
        "#ifndef DOLRECOMP_C_LOOP_CYCLE_BUDGET\n"
        "#define DOLRECOMP_C_LOOP_CYCLE_BUDGET 256\n"
        "#endif\n"
        "\n"
        "static inline u32 dolrecomp_rotl32(u32 value, u32 sh) {\n"
        "    sh &= 31u;\n"
        "    return sh ? ((value << sh) | (value >> (32u - sh))) : value;\n"
        "}\n"
        "\n"
        "/* Chunk switches index by instruction slot, not by raw pc: case\n"
        " * values 4 bytes apart are too sparse over the byte range, so clang\n"
        " * lowered them to a compare tree over small tables. Slots are\n"
        " * consecutive, which gives one bounds check and one table jump. The\n"
        " * rotate sends an unaligned or out-of-chunk pc to a value no case\n"
        " * has, so it still reaches default. */\n"
        "static inline u32 dolrecomp_pc_slot(u32 pc, u32 base) {\n"
        "    u32 off = pc - base;\n"
        "    return (off >> 2) | (off << 30);\n"
        "}\n"
        "\n"
        "static inline f32 dolrecomp_f32_from_bits(u32 bits) {\n"
        "    f32 value;\n"
        "    memcpy(&value, &bits, sizeof(value));\n"
        "    return value;\n"
        "}\n"
        "\n"
        "static inline u32 dolrecomp_f32_to_bits(f32 value) {\n"
        "    u32 bits;\n"
        "    memcpy(&bits, &value, sizeof(bits));\n"
        "    return bits;\n"
        "}\n"
        "\n"
        "static inline f64 dolrecomp_f64_from_bits(u64 bits) {\n"
        "    f64 value;\n"
        "    memcpy(&value, &bits, sizeof(value));\n"
        "    return value;\n"
        "}\n"
        "\n"
        "static inline u64 dolrecomp_f64_to_bits(f64 value) {\n"
        "    u64 bits;\n"
        "    memcpy(&bits, &value, sizeof(bits));\n"
        "    return bits;\n"
        "}\n"
        "\n"
        "static inline f64 dolrecomp_ps_round(f64 value) {\n"
        "    return (f64)(f32)value;\n"
        "}\n"
        "\n"
        "static inline f64 dolrecomp_ps_from_bits(u32 bits) {\n"
        "    return (f64)dolrecomp_f32_from_bits(bits);\n"
        "}\n"
        "\n"
        "static inline u32 dolrecomp_ps_to_bits(f64 value) {\n"
        "    return dolrecomp_f32_to_bits((f32)value);\n"
        "}\n"
        "\n"
        /* Gekko paired-single rounding, inlined so ps ops need no out-of-line
         * call. Byte-identical to cpu.c force_25_bit / fma_single. */
        "#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))\n"
        "#include <immintrin.h>\n"
        "static inline f64 dolrecomp_dr_fma(f64 a, f64 b, f64 c) {\n"
        "    return _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c)));\n"
        "}\n"
        "#else\n"
        "static inline f64 dolrecomp_dr_fma(f64 a, f64 b, f64 c) { return fma(a, b, c); }\n"
        "#endif\n"
        "static inline f64 dolrecomp_ps_force25(f64 value) {\n"
        "    u64 bits = dolrecomp_f64_to_bits(value);\n"
        "    u64 fraction = bits & 0x000FFFFFFFFFFFFFull;\n"
        "    u64 keep_mask = 0xFFFFFFFFF8000000ull;\n"
        "    u64 round = 0x0000000008000000ull;\n"
        "    if ((bits & 0x7FF0000000000000ull) == 0 && fraction != 0) {\n"
        "        unsigned lz = 0; u64 f = fraction;\n"
        "        while ((f & 0x8000000000000000ull) == 0) { f <<= 1; lz++; }\n"
        "        unsigned shift = lz - 11u;\n"
        "        if (shift < 28u) { keep_mask = ~((1ull << (27u - shift)) - 1ull); round >>= shift; }\n"
        "        else { keep_mask = ~0ull; round = 0; }\n"
        "    }\n"
        "    bits = (bits & keep_mask) + (bits & round);\n"
        "    return dolrecomp_f64_from_bits(bits);\n"
        "}\n"
        /* Single-precision fused multiply-add, for operands the emitter has
         * proven hold single-precision values (see sp_known in emitter.c):
         * then force25 is the identity and fmasingle's double FMA plus its
         * double-rounding nudge is exactly one correctly rounded f32 FMA. */
        "#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))\n"
        "static inline f64 dolrecomp_sp_fma(f64 a, f64 c, f64 b) {\n"
        "    return (f64)_mm_cvtss_f32(_mm_fmadd_ss(_mm_set_ss((f32)a), _mm_set_ss((f32)c), _mm_set_ss((f32)b)));\n"
        "}\n"
        "#else\n"
        "static inline f64 dolrecomp_sp_fma(f64 a, f64 c, f64 b) { return (f64)fmaf((f32)a, (f32)c, (f32)b); }\n"
        "#endif\n"
        "static inline f64 dolrecomp_ps_fmasingle(f64 a, f64 c, f64 addend) {\n"
        "    f64 result = dolrecomp_dr_fma(a, c, addend);\n"
        "    u64 bits = dolrecomp_f64_to_bits(result);\n"
        "    if ((bits & 0x000000001FFFFFFFull) == 0x0000000010000000ull) {\n"
        "        f64 a_prime = addend - result;\n"
        "        f64 b_prime = result + a_prime;\n"
        "        f64 error = dolrecomp_dr_fma(a, c, a_prime) + (addend - b_prime);\n"
        "        if (error != 0.0) {\n"
        "            if ((error > 0.0) == (result > 0.0)) bits++;\n"
        "            else bits--;\n"
        "            result = dolrecomp_f64_from_bits(bits);\n"
        "        }\n"
        "    }\n"
        "    return result;\n"
        "}\n"
        "\n"
        ,
        emit_cpu_label(cpu),
        emit_cpu_macro(cpu),
        emit_cpu_label(cpu));
}

void emit_header(FILE* out) {
    emit_header_for_cpu(out, DOLRECOMP_CPU_GEKKO);
}

void emit_footer(FILE* out) {
    fprintf(out, "\n#endif /* RECOMP_GENERATED_H */\n\n// end\n");
}

/* ---- known-single tracking -------------------------------------------------
 * Within one straight-line run of the hot function the emitter knows which FPR
 * lanes hold a value exactly representable as f32 -- results of single and
 * paired-single ops, lfs and psq_l. For those operands Gekko's paired rounding
 * collapses: force_25_bit is the identity (an f32 mantissa has 24 bits), and
 * fmasingle (a double FMA plus a nudge that makes the later f32 rounding
 * single) is exactly one correctly rounded f32 FMA. This is Dolphin's JIT
 * "known single" register typing, done statically.
 *
 * The state is per emission pass: cleared at every label (anything can jump
 * there), at every control transfer (a callee or handler may rewrite FPRs) and
 * whenever tracking is off -- the cold companion, counted loops and standalone
 * emits never use it. Clearing is always safe; only setting needs care. */
/* Thread-local: codegen emits chunks on parallel worker threads (-j). */
#if defined(_MSC_VER) && !defined(__clang__)
#define DOLRECOMP_TLS __declspec(thread)
#else
#define DOLRECOMP_TLS _Thread_local
#endif
static DOLRECOMP_TLS bool g_sp_track;
static DOLRECOMP_TLS u64 g_sp_known; /* bit r: fpr[r] (ps0); bit 32 + r: ps1[r] */

static bool sp0(u32 r) { return g_sp_track && (g_sp_known >> r & 1u); }
static bool sp1(u32 r) { return g_sp_track && (g_sp_known >> (32u + r) & 1u); }

/* Instructions that may change MSR[FP] (directly, or through an exception,
 * rfi or a helper that runs arbitrary host code) before falling through. */
static bool fp_resets(PPCOpcode op) {
    switch (op) {
    case PPC_OP_SC: case PPC_OP_RFI: case PPC_OP_TW: case PPC_OP_TWI:
    case PPC_OP_MTMSR: case PPC_OP_MTSPR: case PPC_OP_MFSPR:
    case PPC_OP_UNKNOWN:
        return true;
    default:
        return false;
    }
}

static void sp_set(u32 r, bool ps0, bool ps1) {
    g_sp_known &= ~((1ull << r) | (1ull << (32u + r)));
    g_sp_known |= (ps0 ? 1ull << r : 0) | (ps1 ? 1ull << (32u + r) : 0);
}

/* The lane state after inst, given the state before it. */
static void sp_update(const PPCInst* inst) {
    const u32 d = inst->rD;
    switch (inst->op) {
    case PPC_OP_B: case PPC_OP_BC: case PPC_OP_BCLR: case PPC_OP_BCCTR:
    case PPC_OP_SC: case PPC_OP_RFI: case PPC_OP_TW: case PPC_OP_TWI:
    case PPC_OP_MTMSR: case PPC_OP_UNKNOWN:
        g_sp_known = 0;
        return;
    /* single results in both lanes */
    case PPC_OP_LFS: case PPC_OP_LFSU: case PPC_OP_LFSX: case PPC_OP_LFSUX:
    case PPC_OP_PSQ_L: case PPC_OP_PSQ_LU: case PPC_OP_PSQ_LX:
    case PPC_OP_PSQ_LUX:
    case PPC_OP_FADDS: case PPC_OP_FSUBS: case PPC_OP_FMULS: case PPC_OP_FDIVS:
    case PPC_OP_FRSP:
    case PPC_OP_PS_ADD: case PPC_OP_PS_SUB: case PPC_OP_PS_MUL:
    case PPC_OP_PS_DIV: case PPC_OP_PS_MADD: case PPC_OP_PS_MSUB:
    case PPC_OP_PS_NMADD: case PPC_OP_PS_NMSUB: case PPC_OP_PS_MULS0:
    case PPC_OP_PS_MULS1: case PPC_OP_PS_MADDS0: case PPC_OP_PS_MADDS1:
    case PPC_OP_PS_SUM0: case PPC_OP_PS_SUM1: case PPC_OP_PS_RES:
    case PPC_OP_PS_RSQRTE: case PPC_OP_PS_MERGE00: case PPC_OP_PS_MERGE01:
    case PPC_OP_PS_MERGE10: case PPC_OP_PS_MERGE11: case PPC_OP_PS_NEG:
    case PPC_OP_PS_ABS: case PPC_OP_PS_NABS:
        sp_set(d, true, true);
        return;
    case PPC_OP_PS_MR:
        sp_set(d, sp0(inst->rB), sp1(inst->rB));
        return;
    /* ps0 only; ps1 keeps its state */
    case PPC_OP_FMR: case PPC_OP_FNEG: case PPC_OP_FABS: case PPC_OP_FNABS:
        sp_set(d, sp0(inst->rB), sp1(d));
        return;
    /* no FPR written */
    case PPC_OP_STFIWX: case PPC_OP_STFS: case PPC_OP_STFSU: case PPC_OP_STFSX:
    case PPC_OP_STFSUX: case PPC_OP_STFD: case PPC_OP_STFDU: case PPC_OP_STFDX:
    case PPC_OP_STFDUX: case PPC_OP_PSQ_ST: case PPC_OP_PSQ_STU:
    case PPC_OP_PSQ_STX: case PPC_OP_PSQ_STUX: case PPC_OP_FCMPO:
    case PPC_OP_FCMPU: case PPC_OP_PS_CMPO0: case PPC_OP_PS_CMPO1:
    case PPC_OP_PS_CMPU0: case PPC_OP_PS_CMPU1: case PPC_OP_MTFSB0:
    case PPC_OP_MTFSB1: case PPC_OP_MTFSF: case PPC_OP_MTFSFI:
    case PPC_OP_MCRFS:
        return;
    default:
        /* Any other FP op (double arithmetic, lfd, fctiw, fsel, mffs, the
         * scalar fused single ops whose helper can leave rD unwritten, ...)
         * may leave rD holding anything. Integer ops touch no FPR. */
        if (ppc_op_uses_fpu(inst->op))
            sp_set(d, false, false);
        return;
    }
}

/* The C multiplicand of a single/paired multiply: force_25_bit unless the
 * lane is known single. */
static const char* sp_c(char* buf, size_t n, bool known, const char* lane,
                        u32 r) {
    if (known)
        snprintf(buf, n, "ctx->%s[%u]", lane, r);
    else
        snprintf(buf, n, "dolrecomp_ps_force25(ctx->%s[%u])", lane, r);
    return buf;
}

/* `cold` selects the lowering used by the cold resume companion (see
 * emit_function_cold): no local gotos, no counted-loop helpers and no direct
 * cross-chunk calls, so every control transfer leaves through ctx->pc. */
static void emit_instruction_with_range(FILE* out, const PPCInst* inst,
                                        u32 func_start, u32 func_end,
                                        bool direct_backedge,
                                        bool route_local_returns,
                                        bool emit_fp_guard,
                                        bool cold) {
    char disasm[64];
    ppc_disasm(disasm, sizeof(disasm), inst);
    fprintf(out, "    // %08X: %s\n", inst->address, disasm);

    if (inst->embedded_data) {
        fprintf(out, "    // embedded data\n\n");
        return;
    }

    if (emit_fp_guard && ppc_op_uses_fpu(inst->op))
        fprintf(out, "    if (!ppc_fp_available(ctx, 0x%08Xu)) return;\n", inst->address);

    switch (inst->op) {
    case PPC_OP_MULLI:
        fprintf(out, "    ctx->gpr[%u] = (u32)((s64)(s32)ctx->gpr[%u] * (s64)(s32)%d);\n",
                inst->rD, inst->rA, (int)inst->simm);
        break;

    case PPC_OP_SUBFIC:
        fprintf(out, "    {\n");
        fprintf(out, "        u64 res = (u64)(u32)(s32)(%d) + (u64)(~ctx->gpr[%u]) + 1u;\n",
                (int)inst->simm, inst->rA);
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(res >> 32) & 1u) << 29);\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDI:
        if (inst->rA == 0) {
            fprintf(out, "    ctx->gpr[%u] = (u32)(s32)(%d);\n",
                    inst->rD, (int)inst->simm);
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] + (u32)(s32)(%d);\n",
                    inst->rD, inst->rA, (int)inst->simm);
        }
        break;

    case PPC_OP_ADDIC:
    case PPC_OP_ADDIC_DOT:
        fprintf(out, "    {\n");
        fprintf(out, "        u64 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 b = (u32)(s32)(%d);\n", (int)inst->simm);
        fprintf(out, "        u64 res = a + b;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(res >> 32) & 1u) << 29);\n");
        if (inst->op == PPC_OP_ADDIC_DOT) {
            emit_set_cr0_from_gpr(out, inst->rD);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDIS:
        if (inst->rA == 0) {
            fprintf(out, "    ctx->gpr[%u] = ((u32)(s32)(%d) << 16);\n",
                    inst->rD, (int)inst->simm);
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] + ((u32)(s32)(%d) << 16);\n",
                    inst->rD, inst->rA, (int)inst->simm);
        }
        break;

    case PPC_OP_CMPI:
        {
            char rhs[32];
            snprintf(rhs, sizeof(rhs), "%d", (int)inst->simm);
            char lhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            emit_compare_s32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMPLI:
        {
            char rhs[32];
            snprintf(rhs, sizeof(rhs), "0x%04Xu", inst->uimm);
            char lhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            emit_compare_u32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMP:
        {
            char lhs[32], rhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            snprintf(rhs, sizeof(rhs), "ctx->gpr[%u]", inst->rB);
            emit_compare_s32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_CMPL:
        {
            char lhs[32], rhs[32];
            snprintf(lhs, sizeof(lhs), "ctx->gpr[%u]", inst->rA);
            snprintf(rhs, sizeof(rhs), "ctx->gpr[%u]", inst->rB);
            emit_compare_u32(out, inst->crfD, lhs, rhs);
        }
        break;

    case PPC_OP_ORI:
        if (inst->rS == 0 && inst->rA == 0 && inst->uimm == 0) {
            fprintf(out, "    // nop\n");
        } else {
            fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] | 0x%04Xu;\n",
                    inst->rA, inst->rS, inst->uimm);
        }
        break;

    case PPC_OP_ORIS:
        fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] | (0x%04Xu << 16);\n",
                inst->rA, inst->rS, inst->uimm);
        break;

    case PPC_OP_XORI:
        fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] ^ 0x%04Xu;\n",
                inst->rA, inst->rS, inst->uimm);
        break;

    case PPC_OP_XORIS:
        fprintf(out, "    ctx->gpr[%u] = ctx->gpr[%u] ^ (0x%04Xu << 16);\n",
                inst->rA, inst->rS, inst->uimm);
        break;

    case PPC_OP_ANDI:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ctx->gpr[%u] & 0x%04Xu;\n",
                inst->rA, inst->rS, inst->uimm);
        emit_set_cr0_from_gpr(out, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ANDIS:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ctx->gpr[%u] & (0x%04Xu << 16);\n",
                inst->rA, inst->rS, inst->uimm);
        emit_set_cr0_from_gpr(out, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADD:
    case PPC_OP_ADDO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 res = a + b;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDC:
    case PPC_OP_ADDCO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)a + (u64)b;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDE:
    case PPC_OP_ADDEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)a + (u64)b + carry;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDME:
    case PPC_OP_ADDMEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 input = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 res = (u64)input + 0xFFFFFFFFull + carry;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | ((res >> 32) ? 0x20000000u : 0u);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(input, 0xFFFFFFFFu, (u32)res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ADDZE:
    case PPC_OP_ADDZEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 wide = (u64)a + ((ctx->xer >> 29) & 1u);\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, 0u, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBF:
    case PPC_OP_SUBFO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 res = a + b + 1u;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFC:
    case PPC_OP_SUBFCO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u64 wide = (u64)b + (u64)a + 1u;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFE:
    case PPC_OP_SUBFEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 b = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 wide = (u64)a + (u64)b + carry;\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, b, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFME:
    case PPC_OP_SUBFMEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 input = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u32 carry = (ctx->xer >> 29) & 1u;\n");
        fprintf(out, "        u64 res = (u64)input + 0xFFFFFFFFull + carry;\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | ((res >> 32) ? 0x20000000u : 0u);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(input, 0xFFFFFFFFu, (u32)res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SUBFZE:
    case PPC_OP_SUBFZEO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ~ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        u64 wide = (u64)a + ((ctx->xer >> 29) & 1u);\n");
        fprintf(out, "        u32 res = (u32)wide;\n");
        fprintf(out, "        ctx->gpr[%u] = res;\n", inst->rD);
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (((u32)(wide >> 32) & 1u) << 29);\n");
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ppc_add_overflowed(a, 0u, res));\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_NEG:
    case PPC_OP_NEGO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 a = ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        ctx->gpr[%u] = (~a) + 1u;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, a == 0x80000000u);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULLW:
    case PPC_OP_MULLWO:
        fprintf(out, "    {\n");
        fprintf(out, "        s64 product = (s64)(s32)ctx->gpr[%u] * (s64)(s32)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)product;\n", inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, product < -0x80000000ll || product > 0x7fffffffll);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULHW:
        fprintf(out, "    {\n");
        fprintf(out, "        s64 product = (s64)(s32)ctx->gpr[%u] * (s64)(s32)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)(product >> 32);\n", inst->rD);
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MULHWU:
        fprintf(out, "    {\n");
        fprintf(out, "        u64 product = (u64)ctx->gpr[%u] * (u64)ctx->gpr[%u];\n",
                inst->rA, inst->rB);
        fprintf(out, "        ctx->gpr[%u] = (u32)(product >> 32);\n", inst->rD);
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DIVW:
    case PPC_OP_DIVWO:
        fprintf(out, "    {\n");
        fprintf(out, "        s32 dividend = (s32)ctx->gpr[%u];\n", inst->rA);
        fprintf(out, "        s32 divisor = (s32)ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        bool ov = divisor == 0 || ((u32)dividend == 0x80000000u && divisor == -1);\n");
        fprintf(out, "        ctx->gpr[%u] = ov ? ((dividend < 0) ? 0xFFFFFFFFu : 0u) : (u32)(dividend / divisor);\n",
                inst->rD);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, ov);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DIVWU:
    case PPC_OP_DIVWUO:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 divisor = ctx->gpr[%u];\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = divisor == 0 ? 0u : ctx->gpr[%u] / divisor;\n",
                inst->rD, inst->rA);
        if (inst->oe)
            fprintf(out, "        ppc_set_xer_ov(ctx, divisor == 0);\n");
        emit_record_if_needed(out, inst, inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_AND:
    case PPC_OP_ANDC:
    case PPC_OP_OR:
    case PPC_OP_ORC:
    case PPC_OP_XOR:
    case PPC_OP_NAND:
    case PPC_OP_NOR:
    case PPC_OP_EQV: {
        const char* expr = NULL;
        switch (inst->op) {
        case PPC_OP_AND:  expr = "ctx->gpr[%u] & ctx->gpr[%u]"; break;
        case PPC_OP_ANDC: expr = "ctx->gpr[%u] & ~ctx->gpr[%u]"; break;
        case PPC_OP_OR:   expr = "ctx->gpr[%u] | ctx->gpr[%u]"; break;
        case PPC_OP_ORC:  expr = "ctx->gpr[%u] | ~ctx->gpr[%u]"; break;
        case PPC_OP_XOR:  expr = "ctx->gpr[%u] ^ ctx->gpr[%u]"; break;
        case PPC_OP_NAND: expr = "~(ctx->gpr[%u] & ctx->gpr[%u])"; break;
        case PPC_OP_NOR:  expr = "~(ctx->gpr[%u] | ctx->gpr[%u])"; break;
        default:          expr = "~(ctx->gpr[%u] ^ ctx->gpr[%u])"; break;
        }
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = ", inst->rA);
        fprintf(out, expr, inst->rS, inst->rB);
        fprintf(out, ";\n");
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_CNTLZW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 v = ctx->gpr[%u];\n", inst->rS);
        fprintf(out, "        u32 n = 0;\n");
        fprintf(out, "        while (n < 32 && ((v & (0x80000000u >> n)) == 0)) n++;\n");
        fprintf(out, "        ctx->gpr[%u] = n;\n", inst->rA);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_EXTSB:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)(s32)(s8)ctx->gpr[%u];\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_EXTSH:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->gpr[%u] = (u32)(s32)(s16)ctx->gpr[%u];\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SLW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = sh > 31 ? 0u : (ctx->gpr[%u] << sh);\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SRW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        fprintf(out, "        ctx->gpr[%u] = sh > 31 ? 0u : (ctx->gpr[%u] >> sh);\n",
                inst->rA, inst->rS);
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SRAW:
    case PPC_OP_SRAWI:
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_SRAWI) {
            fprintf(out, "        u32 sh = %uu;\n", inst->sh);
        } else {
            fprintf(out, "        u32 sh = ctx->gpr[%u] & 0x3Fu;\n", inst->rB);
        }
        fprintf(out, "        u32 value = ctx->gpr[%u];\n", inst->rS);
        fprintf(out, "        bool ca = false;\n");
        fprintf(out, "        if (sh == 0) {\n");
        fprintf(out, "            ctx->gpr[%u] = value;\n", inst->rA);
        fprintf(out, "        } else if (sh > 31) {\n");
        fprintf(out, "            ctx->gpr[%u] = (value & 0x80000000u) ? 0xFFFFFFFFu : 0u;\n", inst->rA);
        fprintf(out, "            ca = (value & 0x80000000u) != 0;\n");
        fprintf(out, "        } else {\n");
        fprintf(out, "            ctx->gpr[%u] = (u32)((s32)value >> sh);\n", inst->rA);
        fprintf(out, "            ca = (value & 0x80000000u) && ((value << (32u - sh)) != 0);\n");
        fprintf(out, "        }\n");
        fprintf(out, "        ctx->xer = (ctx->xer & ~0x20000000u) | (ca ? 0x20000000u : 0u);\n");
        emit_record_if_needed(out, inst, inst->rA);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_RLWINM:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        ctx->gpr[%u] = dolrecomp_rotl32(ctx->gpr[%u], %uu) & 0x%08Xu;\n",
                    inst->rA, inst->rS, inst->sh, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_RLWNM:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        ctx->gpr[%u] = dolrecomp_rotl32(ctx->gpr[%u], ctx->gpr[%u]) & 0x%08Xu;\n",
                    inst->rA, inst->rS, inst->rB, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_RLWIMI:
        {
            u32 mask = ppc_mask32(inst->mb, inst->me);
            fprintf(out, "    {\n");
            fprintf(out, "        u32 rot = dolrecomp_rotl32(ctx->gpr[%u], %uu);\n",
                    inst->rS, inst->sh);
            fprintf(out, "        ctx->gpr[%u] = (ctx->gpr[%u] & ~0x%08Xu) | (rot & 0x%08Xu);\n",
                    inst->rA, inst->rA, mask, mask);
            emit_record_if_needed(out, inst, inst->rA);
            fprintf(out, "    }\n");
        }
        break;

    case PPC_OP_FADDS:
        /* Scalar single-precision results fill both paired lanes. Matrix
         * code can consume PS1 without an intervening paired load. */
        fprintf(out, "    ctx->fpr[%u] = ctx->ps1[%u] = (f64)(f32)(ctx->fpr[%u] + ctx->fpr[%u]);\n",
                inst->rD, inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FSUBS:
        fprintf(out, "    ctx->fpr[%u] = ctx->ps1[%u] = (f64)(f32)(ctx->fpr[%u] - ctx->fpr[%u]);\n",
                inst->rD, inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FMULS: {
        char c0[64];
        fprintf(out, "    ctx->fpr[%u] = ctx->ps1[%u] = (f64)(f32)(ctx->fpr[%u] * %s);\n",
                inst->rD, inst->rD, inst->rA,
                sp_c(c0, sizeof(c0), sp0(inst->rC), "fpr", inst->rC));
        break;
    }

    case PPC_OP_FDIVS:
        fprintf(out, "    ctx->fpr[%u] = ctx->ps1[%u] = (f64)(f32)(ctx->fpr[%u] / ctx->fpr[%u]);\n",
                inst->rD, inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FRES:
        fprintf(out, "    { f64 result; if (ppc_fres(ctx, ctx->fpr[%u], &result)) ctx->fpr[%u] = ctx->ps1[%u] = result; }\n",
                inst->rB, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMADDS:
    case PPC_OP_FMSUBS:
    case PPC_OP_FNMADDS:
    case PPC_OP_FNMSUBS: {
        const bool sub = inst->op == PPC_OP_FMSUBS || inst->op == PPC_OP_FNMSUBS;
        const bool neg = inst->op == PPC_OP_FNMADDS || inst->op == PPC_OP_FNMSUBS;
        fprintf(out, "    {\n");
        fprintf(out, "        f64 result;\n");
        fprintf(out, "        if (ppc_fma(ctx, ctx->fpr[%u], ctx->fpr[%u], ctx->fpr[%u], true, %s, %s, &result))\n",
                inst->rA, inst->rC, inst->rB, sub ? "true" : "false", neg ? "true" : "false");
        fprintf(out, "            ctx->fpr[%u] = ctx->ps1[%u] = result;\n", inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_FADD:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u] + ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FSUB:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u] - ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FMUL:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u] * ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rC);
        break;

    case PPC_OP_FDIV:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u] / ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rB);
        break;

    case PPC_OP_FRSQRTE:
        fprintf(out, "    { f64 result; if (ppc_frsqrte(ctx, ctx->fpr[%u], &result)) ctx->fpr[%u] = result; }\n",
                inst->rB, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMADD:
    case PPC_OP_FMSUB:
    case PPC_OP_FNMADD:
    case PPC_OP_FNMSUB: {
        const bool sub = inst->op == PPC_OP_FMSUB || inst->op == PPC_OP_FNMSUB;
        const bool neg = inst->op == PPC_OP_FNMADD || inst->op == PPC_OP_FNMSUB;
        fprintf(out, "    {\n");
        fprintf(out, "        f64 result;\n");
        fprintf(out, "        if (ppc_fma(ctx, ctx->fpr[%u], ctx->fpr[%u], ctx->fpr[%u], false, %s, %s, &result))\n",
                inst->rA, inst->rC, inst->rB, sub ? "true" : "false", neg ? "true" : "false");
        fprintf(out, "            ctx->fpr[%u] = result;\n", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_FCTIW:
    case PPC_OP_FCTIWZ:
        fprintf(out, "    { u64 result; if (ppc_fctiw(ctx, ctx->fpr[%u], %s, &result)) ctx->fpr[%u] = dolrecomp_f64_from_bits(result); }\n",
                inst->rB, inst->op == PPC_OP_FCTIWZ ? "true" : "false", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FMR:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u];\n", inst->rD, inst->rB);
        break;

    case PPC_OP_FNEG:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) ^ 0x8000000000000000ull);\n",
                inst->rD, inst->rB);
        break;

    case PPC_OP_FABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) & 0x7FFFFFFFFFFFFFFFull);\n",
                inst->rD, inst->rB);
        break;

    case PPC_OP_FNABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(dolrecomp_f64_to_bits(ctx->fpr[%u]) | 0x8000000000000000ull);\n",
                inst->rD, inst->rB);
        break;

    case PPC_OP_FRSP:
        fprintf(out, "    ctx->fpr[%u] = ctx->ps1[%u] = (f64)(f32)ctx->fpr[%u];\n", inst->rD, inst->rD, inst->rB);
        break;

    case PPC_OP_FSEL:
        fprintf(out, "    {\n");
        fprintf(out, "        ctx->fpr[%u] = (ctx->fpr[%u] >= 0.0) ? ctx->fpr[%u] : ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) {
            emit_set_cr1_from_fpscr(out);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MTFSB0:
    case PPC_OP_MTFSB1:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 mask = 0x80000000u >> %u;\n", inst->rD);
        if (inst->op == PPC_OP_MTFSB0) {
            fprintf(out, "        if (%u != 1 && %u != 2) ctx->fpscr &= ~mask;\n",
                    inst->rD, inst->rD);
        } else {
            fprintf(out, "        if (%u != 1 && %u != 2) ctx->fpscr |= mask;\n",
                    inst->rD, inst->rD);
        }
        if (inst->rc) {
            emit_set_cr1_from_fpscr(out);
        }
        fprintf(out, "    }\n");
        break;

    case PPC_OP_MFFS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_f64_from_bits(0xFFF8000000000000ull | ctx->fpscr);\n", inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_MCRFS: {
        u32 shift = cr_field_shift(inst->crfS);
        u32 dst_shift = cr_field_shift(inst->crfD);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 field = (ctx->fpscr >> %u) & 0xFu;\n", shift);
        fprintf(out, "        ctx->fpscr &= ~((0xFu << %u) & 0x83F80700u);\n", shift);
        fprintf(out, "        ppc_fpscr_updated(ctx);\n");
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (field << %u);\n", dst_shift, dst_shift);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MTFSFI: {
        u32 shift = cr_field_shift(inst->crfD);
        fprintf(out, "    ctx->fpscr = (ctx->fpscr & ~(0xFu << %u)) | (0x%Xu << %u);\n",
                shift, inst->imm, shift);
        fprintf(out, "    ppc_fpscr_updated(ctx);\n");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_MTFSF:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 mask = 0;\n");
        fprintf(out, "        for (u32 i = 0; i < 8; i++) if (0x%02Xu & (1u << i)) mask |= 0xFu << (i * 4);\n", inst->fm);
        fprintf(out, "        u32 source = (u32)dolrecomp_f64_to_bits(ctx->fpr[%u]);\n", inst->rB);
        fprintf(out, "        ctx->fpscr = (ctx->fpscr & ~mask) | (source & mask);\n");
        fprintf(out, "        ppc_fpscr_updated(ctx);\n");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        fprintf(out, "    }\n");
        break;

    /* Paired-single arithmetic must match Gekko rounding exactly: operate on
     * the full f64 register values, round the C multiplicand to 25 bits, fuse
     * multiply-adds, and round once to single precision. The cpu.c helpers
     * implement those semantics; naive inline f32 expressions do not. */
    /* Inlined; see ppc_ps_*_op in cpu.c. Two separate stores are aliasing-safe
     * because the ps0 and ps1 lanes live in different arrays, so a store to
     * ctx->fpr[rD] cannot disturb a ctx->ps1[] source (and vice versa) and the
     * RHS is evaluated before the store within each statement. */
    case PPC_OP_PS_ADD:
        fprintf(out, "    ctx->fpr[%u] = (f64)(f32)(ctx->fpr[%u] + ctx->fpr[%u]); "
                     "ctx->ps1[%u] = (f64)(f32)(ctx->ps1[%u] + ctx->ps1[%u]);\n",
                inst->rD, inst->rA, inst->rB, inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUB:
        fprintf(out, "    ctx->fpr[%u] = (f64)(f32)(ctx->fpr[%u] - ctx->fpr[%u]); "
                     "ctx->ps1[%u] = (f64)(f32)(ctx->ps1[%u] - ctx->ps1[%u]);\n",
                inst->rD, inst->rA, inst->rB, inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MUL: {
        char c0[64], c1[64];
        fprintf(out, "    ctx->fpr[%u] = (f64)(f32)(ctx->fpr[%u] * %s); "
                     "ctx->ps1[%u] = (f64)(f32)(ctx->ps1[%u] * %s);\n",
                inst->rD, inst->rA,
                sp_c(c0, sizeof(c0), sp0(inst->rC), "fpr", inst->rC),
                inst->rD, inst->rA,
                sp_c(c1, sizeof(c1), sp1(inst->rC), "ps1", inst->rC));
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_PS_DIV:
        fprintf(out, "    ctx->fpr[%u] = (f64)(f32)(ctx->fpr[%u] / ctx->fpr[%u]); "
                     "ctx->ps1[%u] = (f64)(f32)(ctx->ps1[%u] / ctx->ps1[%u]);\n",
                inst->rD, inst->rA, inst->rB, inst->rD, inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_RES:
        fprintf(out, "    { f64 a, b; ppc_ps_res(ctx, ctx->fpr[%u], ctx->ps1[%u], &a, &b); ctx->fpr[%u] = dolrecomp_ps_round(a); ctx->ps1[%u] = dolrecomp_ps_round(b); }\n",
                inst->rB, inst->rB, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_RSQRTE:
        fprintf(out, "    { f64 a, b; ppc_ps_rsqrte(ctx, ctx->fpr[%u], ctx->ps1[%u], &a, &b); ctx->fpr[%u] = dolrecomp_ps_round(a); ctx->ps1[%u] = dolrecomp_ps_round(b); }\n",
                inst->rB, inst->rB, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MADD:
    case PPC_OP_PS_MSUB:
    case PPC_OP_PS_NMADD:
    case PPC_OP_PS_NMSUB: {
        /* Inlined ppc_ps_madd_op: force the C multiplicand to 25 bits, fuse,
         * round to single. Negated forms flip the sign unless the result is
         * NaN. Locals hold both lanes so any rD/source aliasing is safe. */
        int sub = (inst->op == PPC_OP_PS_MSUB || inst->op == PPC_OP_PS_NMSUB);
        int neg = (inst->op == PPC_OP_PS_NMADD || inst->op == PPC_OP_PS_NMSUB);
        /* Per lane: all three operands known single -> one f32 FMA; else the
         * Gekko path, minus force25 when only C is known. */
        bool all0 = sp0(inst->rA) && sp0(inst->rC) && sp0(inst->rB);
        bool all1 = sp1(inst->rA) && sp1(inst->rC) && sp1(inst->rB);
        char c0[64], c1[64];
        fprintf(out,
                "    { f64 p0 = %s(ctx->fpr[%u], %s, %sctx->fpr[%u]); "
                "f64 p1 = %s(ctx->ps1[%u], %s, %sctx->ps1[%u]); ",
                all0 ? "dolrecomp_sp_fma" : "dolrecomp_ps_fmasingle", inst->rA,
                sp_c(c0, sizeof(c0), sp0(inst->rC), "fpr", inst->rC),
                sub ? "-" : "", inst->rB,
                all1 ? "dolrecomp_sp_fma" : "dolrecomp_ps_fmasingle", inst->rA,
                sp_c(c1, sizeof(c1), sp1(inst->rC), "ps1", inst->rC),
                sub ? "-" : "", inst->rB);
        if (neg)
            fprintf(out, "if (!isnan(p0)) p0 = -p0; if (!isnan(p1)) p1 = -p1; ");
        fprintf(out, "ctx->fpr[%u] = (f64)(f32)p0; ctx->ps1[%u] = (f64)(f32)p1; }\n",
                inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_PS_NEG:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) ^ 0x80000000u);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) ^ 0x80000000u);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_ABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) & 0x7FFFFFFFu);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) & 0x7FFFFFFFu);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_NABS:
        fprintf(out, "    ctx->fpr[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->fpr[%u]) | 0x80000000u);\n",
                inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = dolrecomp_ps_from_bits(dolrecomp_ps_to_bits(ctx->ps1[%u]) | 0x80000000u);\n",
                inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_MR:
        fprintf(out, "    ctx->fpr[%u] = ctx->fpr[%u];\n", inst->rD, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = ctx->ps1[%u];\n", inst->rD, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUM0:
        /* ps0 = fpr[a] + ps1[b], ps1 = ps1[c]; locals for aliasing safety. */
        fprintf(out, "    { f64 p0 = ctx->fpr[%u] + ctx->ps1[%u]; f64 p1 = ctx->ps1[%u]; "
                     "ctx->fpr[%u] = (f64)(f32)p0; ctx->ps1[%u] = (f64)(f32)p1; }\n",
                inst->rA, inst->rB, inst->rC, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_PS_SUM1:
        /* ps0 = fpr[c], ps1 = fpr[a] + ps1[b]; locals for aliasing safety. */
        fprintf(out, "    { f64 p0 = ctx->fpr[%u]; f64 p1 = ctx->fpr[%u] + ctx->ps1[%u]; "
                     "ctx->fpr[%u] = (f64)(f32)p0; ctx->ps1[%u] = (f64)(f32)p1; }\n",
                inst->rC, inst->rA, inst->rB, inst->rD, inst->rD);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    /* Inlined (see the ps helpers in the header): the scalar is forced to 25
     * bits once, then each lane is multiplied / fused-multiply-added and
     * rounded to single. The scalar is captured in a local before any write so
     * an rD that aliases a source stays correct. Matches ppc_ps_muls0/madds
     * in cpu.c byte-for-byte, minus the FPRF update the inlined scalar ops
     * also omit. */
    case PPC_OP_PS_MULS0:
    case PPC_OP_PS_MULS1: {
        bool lane1 = inst->op == PPC_OP_PS_MULS1;
        bool known = lane1 ? sp1(inst->rC) : sp0(inst->rC);
        char c[64];
        fprintf(out, "    { f64 s = %s; "
                     "ctx->fpr[%u] = (f64)(f32)(ctx->fpr[%u] * s); "
                     "ctx->ps1[%u] = (f64)(f32)(ctx->ps1[%u] * s); }\n",
                sp_c(c, sizeof(c), known, lane1 ? "ps1" : "fpr", inst->rC),
                inst->rD, inst->rA, inst->rD, inst->rA);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_PS_MADDS0:
    case PPC_OP_PS_MADDS1: {
        bool lane1 = inst->op == PPC_OP_PS_MADDS1;
        bool known = lane1 ? sp1(inst->rC) : sp0(inst->rC);
        bool all0 = known && sp0(inst->rA) && sp0(inst->rB);
        bool all1 = known && sp1(inst->rA) && sp1(inst->rB);
        char c[64];
        fprintf(out, "    { f64 s = %s; "
                     "ctx->fpr[%u] = (f64)(f32)%s(ctx->fpr[%u], s, ctx->fpr[%u]); "
                     "ctx->ps1[%u] = (f64)(f32)%s(ctx->ps1[%u], s, ctx->ps1[%u]); }\n",
                sp_c(c, sizeof(c), known, lane1 ? "ps1" : "fpr", inst->rC),
                inst->rD, all0 ? "dolrecomp_sp_fma" : "dolrecomp_ps_fmasingle",
                inst->rA, inst->rB, inst->rD,
                all1 ? "dolrecomp_sp_fma" : "dolrecomp_ps_fmasingle",
                inst->rA, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    /* ps_merge reads both sources before writing rD: when rD aliases rA or
     * rB, writing ctx->fpr[rD] first would corrupt the second read. */
    /* A source lane already known single needs no rounding. */
    case PPC_OP_PS_MERGE00:
    case PPC_OP_PS_MERGE01:
    case PPC_OP_PS_MERGE10:
    case PPC_OP_PS_MERGE11: {
        bool a1 = inst->op == PPC_OP_PS_MERGE10 || inst->op == PPC_OP_PS_MERGE11;
        bool b1 = inst->op == PPC_OP_PS_MERGE01 || inst->op == PPC_OP_PS_MERGE11;
        bool ka = a1 ? sp1(inst->rA) : sp0(inst->rA);
        bool kb = b1 ? sp1(inst->rB) : sp0(inst->rB);
        fprintf(out, "    { f64 mrg_a = ctx->%s[%u], mrg_b = ctx->%s[%u];\n",
                a1 ? "ps1" : "fpr", inst->rA, b1 ? "ps1" : "fpr", inst->rB);
        fprintf(out, "      ctx->fpr[%u] = %s(mrg_a);\n", inst->rD,
                ka ? "" : "dolrecomp_ps_round");
        fprintf(out, "      ctx->ps1[%u] = %s(mrg_b); }\n", inst->rD,
                kb ? "" : "dolrecomp_ps_round");
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;
    }

    case PPC_OP_PS_CMPU0:
    case PPC_OP_PS_CMPO0:
    case PPC_OP_PS_CMPU1:
    case PPC_OP_PS_CMPO1:
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_PS_CMPU0 || inst->op == PPC_OP_PS_CMPO0) {
            fprintf(out, "        f32 val_a = (f32)ctx->fpr[%u];\n", inst->rA);
            fprintf(out, "        f32 val_b = (f32)ctx->fpr[%u];\n", inst->rB);
        } else {
            fprintf(out, "        f32 val_a = (f32)ctx->ps1[%u];\n", inst->rA);
            fprintf(out, "        f32 val_b = (f32)ctx->ps1[%u];\n", inst->rB);
        }
        fprintf(out, "        u32 cr_bits = 0;\n");
        fprintf(out, "        if (val_a < val_b)       cr_bits = 0x8u;\n");
        fprintf(out, "        else if (val_a > val_b)  cr_bits = 0x4u;\n");
        fprintf(out, "        else if (val_a == val_b) cr_bits = 0x2u;\n");
        fprintf(out, "        else                     cr_bits = 0x1u;\n");
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (cr_bits << %u);\n",
                cr_field_shift(inst->crfD), cr_field_shift(inst->crfD));
        fprintf(out, "    }\n");
        break;

    case PPC_OP_PS_SEL:
        fprintf(out, "    ctx->fpr[%u] = ((f32)ctx->fpr[%u] >= 0.0f) ? ctx->fpr[%u] : ctx->fpr[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        fprintf(out, "    ctx->ps1[%u] = ((f32)ctx->ps1[%u] >= 0.0f) ? ctx->ps1[%u] : ctx->ps1[%u];\n",
                inst->rD, inst->rA, inst->rC, inst->rB);
        if (inst->rc) emit_set_cr1_from_fpscr(out);
        break;

    case PPC_OP_FCMPU:
    case PPC_OP_FCMPO:
        emit_fcompare(out, inst);
        break;

    case PPC_OP_LWZ:  emit_load(out, inst, "mem_read32(ctx, ea)", false); break;
    case PPC_OP_LWZU: emit_load(out, inst, "mem_read32(ctx, ea)", true); break;
    case PPC_OP_LBZ:  emit_load(out, inst, "mem_read8(ctx, ea)", false); break;
    case PPC_OP_LBZU: emit_load(out, inst, "mem_read8(ctx, ea)", true); break;
    case PPC_OP_LHZ:  emit_load(out, inst, "mem_read16(ctx, ea)", false); break;
    case PPC_OP_LHZU: emit_load(out, inst, "mem_read16(ctx, ea)", true); break;
    case PPC_OP_LHA:  emit_load(out, inst, "(u32)(s32)(s16)mem_read16(ctx, ea)", false); break;
    case PPC_OP_LHAU: emit_load(out, inst, "(u32)(s32)(s16)mem_read16(ctx, ea)", true); break;

    case PPC_OP_LWZX:  emit_loadx(out, inst, "mem_read32(ctx, ea)", false); break;
    case PPC_OP_LWZUX: emit_loadx(out, inst, "mem_read32(ctx, ea)", true); break;
    case PPC_OP_LBZX:  emit_loadx(out, inst, "mem_read8(ctx, ea)", false); break;
    case PPC_OP_LBZUX: emit_loadx(out, inst, "mem_read8(ctx, ea)", true); break;
    case PPC_OP_LHZX:  emit_loadx(out, inst, "mem_read16(ctx, ea)", false); break;
    case PPC_OP_LHZUX: emit_loadx(out, inst, "mem_read16(ctx, ea)", true); break;
    case PPC_OP_LHAX:  emit_loadx(out, inst, "(u32)(s32)(s16)mem_read16(ctx, ea)", false); break;
    case PPC_OP_LHAUX: emit_loadx(out, inst, "(u32)(s32)(s16)mem_read16(ctx, ea)", true); break;
    case PPC_OP_LWBRX: emit_loadx(out, inst, "bswap32(mem_read32(ctx, ea))", false); break;
    case PPC_OP_LHBRX: emit_loadx(out, inst, "bswap16(mem_read16(ctx, ea))", false); break;

    case PPC_OP_LFS:   emit_fload(out, inst, true,  false); break;
    case PPC_OP_LFSU:  emit_fload(out, inst, true,  true); break;
    case PPC_OP_LFD:   emit_fload(out, inst, false, false); break;
    case PPC_OP_LFDU:  emit_fload(out, inst, false, true); break;

    case PPC_OP_LFSX:  emit_floadx(out, inst, true,  false); break;
    case PPC_OP_LFSUX: emit_floadx(out, inst, true,  true); break;
    case PPC_OP_LFDX:  emit_floadx(out, inst, false, false); break;
    case PPC_OP_LFDUX: emit_floadx(out, inst, false, true); break;

    case PPC_OP_PSQ_L:   emit_psq_load(out, inst, false, false); break;
    case PPC_OP_PSQ_LU:  emit_psq_load(out, inst, false, true); break;
    case PPC_OP_PSQ_LX:  emit_psq_load(out, inst, true,  false); break;
    case PPC_OP_PSQ_LUX: emit_psq_load(out, inst, true,  true); break;

    case PPC_OP_STW:  emit_store(out, inst, "mem_write32", "u32", false); break;
    case PPC_OP_STWU: emit_store(out, inst, "mem_write32", "u32", true); break;
    case PPC_OP_STB:  emit_store(out, inst, "mem_write8", "u8", false); break;
    case PPC_OP_STBU: emit_store(out, inst, "mem_write8", "u8", true); break;
    case PPC_OP_STH:  emit_store(out, inst, "mem_write16", "u16", false); break;
    case PPC_OP_STHU: emit_store(out, inst, "mem_write16", "u16", true); break;

    case PPC_OP_STWX:  emit_storex(out, inst, "mem_write32", "u32", false); break;
    case PPC_OP_STWUX: emit_storex(out, inst, "mem_write32", "u32", true); break;
    case PPC_OP_STBX:  emit_storex(out, inst, "mem_write8", "u8", false); break;
    case PPC_OP_STBUX: emit_storex(out, inst, "mem_write8", "u8", true); break;
    case PPC_OP_STHX:  emit_storex(out, inst, "mem_write16", "u16", false); break;
    case PPC_OP_STHUX: emit_storex(out, inst, "mem_write16", "u16", true); break;

    case PPC_OP_STFS:   emit_fstore(out, inst, true,  false); break;
    case PPC_OP_STFSU:  emit_fstore(out, inst, true,  true); break;
    case PPC_OP_STFD:   emit_fstore(out, inst, false, false); break;
    case PPC_OP_STFDU:  emit_fstore(out, inst, false, true); break;

    case PPC_OP_STFSX:  emit_fstorex(out, inst, true,  false); break;
    case PPC_OP_STFSUX: emit_fstorex(out, inst, true,  true); break;
    case PPC_OP_STFDX:  emit_fstorex(out, inst, false, false); break;
    case PPC_OP_STFDUX: emit_fstorex(out, inst, false, true); break;

    case PPC_OP_PSQ_ST:   emit_psq_store(out, inst, false, false); break;
    case PPC_OP_PSQ_STU:  emit_psq_store(out, inst, false, true); break;
    case PPC_OP_PSQ_STX:  emit_psq_store(out, inst, true,  false); break;
    case PPC_OP_PSQ_STUX: emit_psq_store(out, inst, true,  true); break;

    case PPC_OP_STWBRX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        mem_write32(ctx, ea, bswap32(ctx->gpr[%u]));\n", inst->rS);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STHBRX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        mem_write16(ctx, ea, bswap16((u16)ctx->gpr[%u]));\n", inst->rS);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_LSWI:
    case PPC_OP_LSWX: {
        u32 count = inst->op == PPC_OP_LSWI ? (inst->nb ? inst->nb : 32u) : 0u;
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_LSWX) {
            fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rB);
            if (inst->rA)
                fprintf(out, "        ea += ctx->gpr[%u];\n", inst->rA);
            fprintf(out, "        u32 count = ctx->xer & 0x7Fu;\n");
            fprintf(out, "        u32 reg_count = (count + 3u) / 4u;\n");
            fprintf(out, "        for (u32 r = 0; r < reg_count; r++) {\n");
            fprintf(out, "            u32 reg = (%uu + r) & 31u;\n", inst->rD);
            fprintf(out, "            if (reg == %uu || reg == %uu) {\n", inst->rA, inst->rB);
            fprintf(out, "                ppc_program_exception(ctx, PPC_PROGRAM_ILLEGAL, 0x%08Xu);\n",
                    inst->address);
            fprintf(out, "                return;\n");
            fprintf(out, "            }\n");
            fprintf(out, "        }\n");
        } else {
            if (inst->rA) fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rA);
            else fprintf(out, "        u32 ea = 0u;\n");
            fprintf(out, "        u32 count = %uu;\n", count);
        }
        fprintf(out, "        for (u32 n = 0; n < count; n++) {\n");
        fprintf(out, "            u32 reg = (%uu + n / 4u) & 31u;\n", inst->rD);
        fprintf(out, "            if ((n & 3u) == 0) ctx->gpr[reg] = 0;\n");
        fprintf(out, "            ctx->gpr[reg] |= (u32)mem_read8(ctx, ea + n) << (24u - 8u * (n & 3u));\n");
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_STSWI:
    case PPC_OP_STSWX: {
        u32 count = inst->op == PPC_OP_STSWI ? (inst->nb ? inst->nb : 32u) : 0u;
        fprintf(out, "    {\n");
        if (inst->op == PPC_OP_STSWX) {
            fprintf(out, "        u32 ea = ctx->gpr[%u]", inst->rB);
            if (inst->rA) fprintf(out, " + ctx->gpr[%u]", inst->rA);
            fprintf(out, ";\n        u32 count = ctx->xer & 0x7Fu;\n");
        } else {
            if (inst->rA) fprintf(out, "        u32 ea = ctx->gpr[%u];\n", inst->rA);
            else fprintf(out, "        u32 ea = 0u;\n");
            fprintf(out, "        u32 count = %uu;\n", count);
        }
        fprintf(out, "        for (u32 n = 0; n < count; n++) {\n");
        fprintf(out, "            u32 reg = (%uu + n / 4u) & 31u;\n", inst->rS);
        fprintf(out, "            u8 value = (u8)(ctx->gpr[reg] >> (24u - 8u * (n & 3u)));\n");
        fprintf(out, "            mem_write8(ctx, ea + n, value);\n");
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_LWARX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        ctx->gpr[%u] = mem_read32(ctx, ea);\n", inst->rD);
        fprintf(out, "        ctx->reserve_addr = ea;\n        ctx->reserve_valid = true;\n    }\n");
        break;

    case PPC_OP_STWCX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        bool success = ctx->reserve_valid && ea == ctx->reserve_addr;\n");
        fprintf(out, "        if (success) { mem_write32(ctx, ea, ctx->gpr[%u]); ctx->reserve_valid = false; }\n", inst->rS);
        fprintf(out, "        ctx->cr = (ctx->cr & 0x0FFFFFFFu) | ((success ? 2u : 0u) << 28) | ((ctx->xer >> 3) & 0x10000000u);\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STFIWX:
        fprintf(out, "    {\n        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n        mem_write32(ctx, ea, (u32)dolrecomp_f64_to_bits(ctx->fpr[%u]));\n    }\n", inst->rS);
        break;

    case PPC_OP_DCBZ:
        emit_dcbz(out, inst);
        break;

    case PPC_OP_DCBZ_L:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        ppc_dcbz_l(ctx, ea, 0x%08Xu);\n", inst->address);
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_DCBST:
    case PPC_OP_DCBF:
    case PPC_OP_DCBI:
    case PPC_OP_ICBI:
        fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                inst->raw, inst->address);
        fprintf(out, "    return;\n");
        break;

    case PPC_OP_DCBTST:
    case PPC_OP_DCBT:
        fprintf(out, "    (void)ctx;\n");
        break;

    case PPC_OP_LMW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_dform_ea(out, inst->rA, inst->simm, false);
        fprintf(out, ";\n");
        fprintf(out, "        for (u32 r = %u; r < 32; r++, ea += 4) ctx->gpr[r] = mem_read32(ctx, ea);\n",
                inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_STMW:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_dform_ea(out, inst->rA, inst->simm, false);
        fprintf(out, ";\n");
        fprintf(out, "        for (u32 r = %u; r < 32; r++, ea += 4) mem_write32(ctx, ea, ctx->gpr[r]);\n",
                inst->rS);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_B:
        fprintf(out, "    {\n");
        emit_direct_branch(out, inst,
                           !cold && branch_target_is_local(func_start, func_end,
                                                           inst->branch_target),
                           direct_backedge, func_start, func_end, cold);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_BC:
        fprintf(out, "    {\n");
        emit_branch_condition(out, inst->bo, inst->bi);
        fprintf(out, "        if (ctr_ok && cr_ok) {\n");
        emit_direct_branch(out, inst,
                           !cold && branch_target_is_local(func_start, func_end,
                                                           inst->branch_target),
                           direct_backedge, func_start, func_end, cold);
        fprintf(out, "        }\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_BCLR:
        emit_dynamic_branch(out, inst, "ctx->lr & ~3u",
                            route_local_returns, func_start);
        break;

    case PPC_OP_BCCTR:
        emit_dynamic_branch(out, inst, "ctx->ctr & ~3u", false, func_start);
        break;

    case PPC_OP_TWI:
        fprintf(out, "    if (ppc_trap_condition(%uu, ctx->gpr[%u], (u32)(s32)%d)) {\n",
                inst->to, inst->rA, (int)inst->simm);
        fprintf(out, "        ppc_program_exception(ctx, PPC_PROGRAM_TRAP, 0x%08Xu);\n", inst->address);
        fprintf(out, "        return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_TW:
        fprintf(out, "    if (ppc_trap_condition(%uu, ctx->gpr[%u], ctx->gpr[%u])) {\n",
                inst->to, inst->rA, inst->rB);
        fprintf(out, "        ppc_program_exception(ctx, PPC_PROGRAM_TRAP, 0x%08Xu);\n", inst->address);
        fprintf(out, "        return;\n");
        fprintf(out, "    }\n");
        break;

    case PPC_OP_SC:
        fprintf(out, "    ppc_system_call_exception(ctx, 0x%08Xu);\n", inst->address);
        fprintf(out, "    return;\n");
        break;

    case PPC_OP_RFI:
        fprintf(out, "    ppc_rfi(ctx, 0x%08Xu);\n", inst->address);
        fprintf(out, "    return;\n");
        break;

    case PPC_OP_CRAND:  emit_cr_logical(out, inst, "a & b"); break;
    case PPC_OP_CRANDC: emit_cr_logical(out, inst, "a & ~b"); break;
    case PPC_OP_CREQV:  emit_cr_logical(out, inst, "~(a ^ b)"); break;
    case PPC_OP_CRNAND: emit_cr_logical(out, inst, "~(a & b)"); break;
    case PPC_OP_CRNOR:  emit_cr_logical(out, inst, "~(a | b)"); break;
    case PPC_OP_CROR:   emit_cr_logical(out, inst, "a | b"); break;
    case PPC_OP_CRORC:  emit_cr_logical(out, inst, "a | ~b"); break;
    case PPC_OP_CRXOR:  emit_cr_logical(out, inst, "a ^ b"); break;

    case PPC_OP_MCRF: {
        u32 dst_shift = cr_field_shift(inst->crfD);
        u32 src_shift = cr_field_shift(inst->crfS);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 bits = (ctx->cr >> %u) & 0xFu;\n", src_shift);
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (bits << %u);\n",
                dst_shift, dst_shift);
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MCRXR: {
        u32 dst_shift = cr_field_shift(inst->crfD);
        fprintf(out, "    {\n");
        fprintf(out, "        u32 bits = (ctx->xer >> 28) & 0xFu;\n");
        fprintf(out, "        ctx->cr = (ctx->cr & ~(0xFu << %u)) | (bits << %u);\n",
                dst_shift, dst_shift);
        fprintf(out, "        ctx->xer &= ~0xE0000000u;\n");
        fprintf(out, "    }\n");
        break;
    }

    case PPC_OP_MFCR:
        fprintf(out, "    ctx->gpr[%u] = ctx->cr;\n", inst->rD);
        break;

    case PPC_OP_MTCRF: {
        u32 mask = 0;
        for (u32 crf = 0; crf < 8; crf++) {
            if (inst->crm & (0x80u >> crf))
                mask |= 0xFu << cr_field_shift((u8)crf);
        }
        if (mask) {
            fprintf(out, "    ctx->cr = (ctx->cr & ~0x%08Xu) | (ctx->gpr[%u] & 0x%08Xu);\n",
                    mask, inst->rS, mask);
        } else {
            fprintf(out, "    // mtcrf mask selects no CR fields\n");
        }
        break;
    }

    case PPC_OP_MFMSR:
        fprintf(out, "    ctx->gpr[%u] = ctx->msr;\n", inst->rD);
        break;

    case PPC_OP_MTMSR:
        fprintf(out, "    ctx->msr = ctx->gpr[%u];\n", inst->rS);
        break;

    case PPC_OP_MFSR:
        fprintf(out, "    ctx->gpr[%u] = ctx->sr[%u];\n", inst->rD, inst->sr);
        break;

    case PPC_OP_MFSRIN:
        fprintf(out, "    ctx->gpr[%u] = ctx->sr[(ctx->gpr[%u] >> 28) & 0xFu];\n",
                inst->rD, inst->rB);
        break;

    case PPC_OP_MTSR:
        fprintf(out, "    ctx->sr[%u] = ctx->gpr[%u];\n", inst->sr, inst->rS);
        break;

    case PPC_OP_MTSRIN:
        fprintf(out, "    ctx->sr[(ctx->gpr[%u] >> 28) & 0xFu] = ctx->gpr[%u];\n",
                inst->rB, inst->rS);
        break;

    case PPC_OP_MFTB:
        fprintf(out, "    ctx->gpr[%u] = ppc_mftb(ctx, %uu, 0x%08Xu);\n",
                inst->rD, inst->spr, inst->address);
        fprintf(out, "    if (ctx->exception) return;\n");
        break;

    case PPC_OP_MFSPR:
        switch (inst->spr) {
        case 1: fprintf(out, "    ctx->gpr[%u] = ctx->xer;\n", inst->rD); break;
        case 8: fprintf(out, "    ctx->gpr[%u] = ctx->lr;\n", inst->rD); break;
        case 9: fprintf(out, "    ctx->gpr[%u] = ctx->ctr;\n", inst->rD); break;
        case 26: fprintf(out, "    ctx->gpr[%u] = ctx->srr0;\n", inst->rD); break;
        case 27: fprintf(out, "    ctx->gpr[%u] = ctx->srr1;\n", inst->rD); break;
        case 268:
        case 269:
            fprintf(out, "    ctx->gpr[%u] = ppc_mftb(ctx, %uu, 0x%08Xu);\n",
                    inst->rD, inst->spr, inst->address);
            fprintf(out, "    if (ctx->exception) return;\n");
            break;
        case 912: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[0];\n", inst->rD); break;
        case 913: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[1];\n", inst->rD); break;
        case 914: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[2];\n", inst->rD); break;
        case 915: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[3];\n", inst->rD); break;
        case 916: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[4];\n", inst->rD); break;
        case 917: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[5];\n", inst->rD); break;
        case 918: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[6];\n", inst->rD); break;
        case 919: fprintf(out, "    ctx->gpr[%u] = ctx->gqr[7];\n", inst->rD); break;
        case 282: fprintf(out, "    ctx->gpr[%u] = ctx->ear;\n", inst->rD); break;
        case 920: fprintf(out, "    ctx->gpr[%u] = ctx->hid2;\n", inst->rD); break;
        default:
            fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                    inst->raw, inst->address);
            fprintf(out, "    return;\n");
            break;
        }
        break;

    case PPC_OP_MTSPR:
        switch (inst->spr) {
        case 1: fprintf(out, "    ctx->xer = ctx->gpr[%u];\n", inst->rS); break;
        case 8: fprintf(out, "    ctx->lr = ctx->gpr[%u];\n", inst->rS); break;
        case 9: fprintf(out, "    ctx->ctr = ctx->gpr[%u];\n", inst->rS); break;
        case 26: fprintf(out, "    ctx->srr0 = ctx->gpr[%u];\n", inst->rS); break;
        case 27: fprintf(out, "    ctx->srr1 = ctx->gpr[%u];\n", inst->rS); break;
        case 282: fprintf(out, "    ctx->ear = ctx->gpr[%u];\n", inst->rS); break;
        case 912: fprintf(out, "    ctx->gqr[0] = ctx->gpr[%u];\n", inst->rS); break;
        case 913: fprintf(out, "    ctx->gqr[1] = ctx->gpr[%u];\n", inst->rS); break;
        case 914: fprintf(out, "    ctx->gqr[2] = ctx->gpr[%u];\n", inst->rS); break;
        case 915: fprintf(out, "    ctx->gqr[3] = ctx->gpr[%u];\n", inst->rS); break;
        case 916: fprintf(out, "    ctx->gqr[4] = ctx->gpr[%u];\n", inst->rS); break;
        case 917: fprintf(out, "    ctx->gqr[5] = ctx->gpr[%u];\n", inst->rS); break;
        case 918: fprintf(out, "    ctx->gqr[6] = ctx->gpr[%u];\n", inst->rS); break;
        case 919: fprintf(out, "    ctx->gqr[7] = ctx->gpr[%u];\n", inst->rS); break;
        case 920: fprintf(out, "    ctx->hid2 = ctx->gpr[%u];\n", inst->rS); break;
        default:
            fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                    inst->raw, inst->address);
            fprintf(out, "    return;\n");
            break;
        }
        break;

    case PPC_OP_TLBIE:
        fprintf(out, "    ppc_tlbie(ctx, ctx->gpr[%u], 0x%08Xu);\n", inst->rB, inst->address);
        fprintf(out, "    if (ctx->exception) return;\n");
        break;

    case PPC_OP_SYNC:
    case PPC_OP_EIEIO:
    case PPC_OP_ISYNC:
    case PPC_OP_TLBSYNC:
        fprintf(out, "    ppc_memory_fence();\n");
        break;

    case PPC_OP_ECIWX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        u32 value = ppc_eciwx(ctx, ea, 0x%08Xu);\n", inst->address);
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "        ctx->gpr[%u] = value;\n", inst->rD);
        fprintf(out, "    }\n");
        break;

    case PPC_OP_ECOWX:
        fprintf(out, "    {\n");
        fprintf(out, "        u32 ea = ");
        emit_xform_ea(out, inst->rA, inst->rB, false);
        fprintf(out, ";\n");
        fprintf(out, "        ppc_ecowx(ctx, ea, ctx->gpr[%u], 0x%08Xu);\n",
                inst->rS, inst->address);
        fprintf(out, "        if (ctx->exception) return;\n");
        fprintf(out, "    }\n");
        break;

    default:
        fprintf(out, "    ppc_fallback_instruction(ctx, 0x%08Xu, 0x%08Xu);\n",
                inst->raw, inst->address);
        fprintf(out, "    return;\n");
        break;
    }

    fprintf(out, "\n");
}

void emit_instruction_ex(FILE* out, const PPCInst* inst, u32 func_start,
                         u32 func_end, bool direct_backedge,
                         bool route_local_returns, bool emit_fp_guard) {
    emit_instruction_with_range(out, inst, func_start, func_end,
                                direct_backedge, route_local_returns,
                                emit_fp_guard, false);
}

void emit_instruction(FILE* out, const PPCInst* inst) {
    /* No block context here (standalone emit, used by tests): always guard. */
    emit_instruction_with_range(out, inst, 0, (u32)-1, false, false, true, false);
}

static void emit_counted_loop(FILE* out, const PPCInst* insts,
                              const CFunctionCFG* cfg, u32 function_address,
                              u32 function_end, u32 first, u32 last) {
    u32 loop_address = insts[first].address;
    u32 continuation = insts[last].address + 4u;

    fprintf(out, "static void loop_%08X(CPUState* ctx) {\n", loop_address);
    /* Idle-park hook (see cpu.h). The first entry into the guest OS's idle
     * spin often arrives by an intra-function branch, where no dispatcher and
     * therefore no host_call observer runs -- without this check the helper
     * spins its entire downcount budget (~667k iterations per slice) before
     * the host can notice. Cost when this is not the idle loop: one compare. */
    fprintf(out, "    if (ctx->idle_hook_pc == 0x%08Xu && ctx->idle_hook(ctx)) return;\n",
            loop_address);
    fprintf(out, "label_%08X:\n", loop_address);
    fprintf(out, "    ctx->downcount -= %u;\n", cfg->block_cycles[first]);
    for (u32 i = first; i <= last; ++i) {
        if (cfg->materialize_pc[i])
            fprintf(out, "    ctx->pc = 0x%08Xu;\n", insts[i].address);
        /* Counted-loop bodies are outlinable-only (no FP ops), so the guard
         * flag is inert here; pass true for safety. */
        emit_instruction_with_range(out, &insts[i], function_address,
                                    function_end, i == last, false, true,
                                    false);
    }
    fprintf(out, "    ctx->pc = 0x%08Xu;\n", continuation);
    fprintf(out, "}\n\n");
}

/* Opens a switch over ctx->pc by instruction slot within the chunk (see
 * dolrecomp_pc_slot in the generated header); its cases are
 * (address - func_addr) >> 2. */
static void emit_pc_switch(FILE* out, u32 func_addr) {
    fprintf(out, "    switch (dolrecomp_pc_slot(ctx->pc, 0x%08Xu)) {\n", func_addr);
}

/* Cold resume companion. The dispatcher can enter a chunk at an address the
 * hot function has no case for: an `rfi` back into the middle of a block, a
 * `bctr` jump-table target, a saved lr resumed from somewhere else. Those
 * entries are far too rare to shape the hot function around, so they land
 * here instead. This function keeps the case-per-instruction switch the hot
 * one used to carry, runs straight-line from the requested pc to the next
 * control transfer, and returns; the following dispatch then arrives at a
 * leader, which the hot function does have a case for.
 *
 * It must be bit-exact with the hot path, so it charges the same downcount at
 * the same leaders, and it takes none of the hot path's shortcuts: every FP
 * op is guarded (every cold case is dispatcher-enterable, so no guard can be
 * hoisted into a predecessor), ctx->pc is materialized before every
 * instruction, and every branch -- local or not, backward or not -- lowers to
 * `ctx->pc = target; return;`. No gotos, no counted-loop helper calls, no
 * direct cross-chunk calls. */
static void emit_function_cold(FILE* out, const PPCInst* insts,
                               const CFunctionCFG* cfg, u32 count,
                               u32 func_addr, u32 func_end) {
    fprintf(out, "static void func_%08X_cold(CPUState* ctx) {\n", func_addr);
    emit_pc_switch(out, func_addr);
    for (u32 i = 0; i < count; i++) {
        fprintf(out, "    case 0x%Xu: goto cold_%08X;\n",
                (insts[i].address - func_addr) >> 2, insts[i].address);
    }
    fprintf(out, "    default: return;\n");
    fprintf(out, "    }\n");

    for (u32 i = 0; i < count; i++) {
        fprintf(out, "cold_%08X:\n", insts[i].address);
        fprintf(out, "    ctx->pc = 0x%08Xu;\n", insts[i].address);
        if (cfg->leaders[i] && cfg->block_cycles[i] != 0)
            fprintf(out, "    ctx->downcount -= %u;\n", cfg->block_cycles[i]);
        emit_instruction_with_range(out, &insts[i], func_addr, func_end, false,
                                    false, true, true);
    }

    fprintf(out, "    ctx->pc = 0x%08Xu;\n", func_end);
    fprintf(out, "}\n\n");
}

bool emit_function(FILE* out, const PPCInst* insts, u32 count, u32 func_addr) {
    u32 func_end = func_addr + count * 4u;
    CFunctionCFG cfg;
    if (!c_function_cfg_build(&cfg, insts, count, func_addr)) {
        fprintf(stderr, "error: out of memory while analyzing function %08X\n",
                func_addr);
        return false;
    }
    bool has_local_returns = false;
    for (u32 i = 0; i < count; ++i)
        has_local_returns |= cfg.return_targets[i] != 0;

    for (u32 i = 0; i < count; ++i) {
        if (cfg.loop_ends[i] != UINT32_MAX)
            emit_counted_loop(out, insts, &cfg, func_addr, func_end, i,
                              cfg.loop_ends[i]);
    }

    emit_function_cold(out, insts, &cfg, count, func_addr, func_end);

    fprintf(out, "void func_%08X(CPUState* ctx) {\n", func_addr);
    fprintf(out, "    uintptr_t hb1 = 0, hb2 = 0, hb13 = 0;\n");
    fprintf(out, "    (void)hb1; (void)hb2; (void)hb13;\n");
    /* Entry switch, cases only for addresses control can arrive at from
     * outside this function: the chunk start, block leaders, return addresses,
     * and addresses some other chunk branches to (cfg->entry_points). Every
     * other instruction is reachable only by falling through the one before
     * it, so it carries no case and no label -- one predecessor, which is what
     * lets the compiler keep guest state in host registers across it instead
     * of spilling to ctx at every instruction boundary.
     *
     * Entries this set does not cover -- an `rfi` into the middle of a block,
     * a `bctr` jump-table target, an lr resumed from elsewhere -- go to the
     * cold companion, which handles any pc in the chunk. */
    emit_pc_switch(out, func_addr);
    for (u32 i = 0; i < count; i++) {
        if (!cfg.entry_points[i])
            continue;
        fprintf(out, "    case 0x%Xu: goto label_%08X;\n",
                (insts[i].address - func_addr) >> 2, insts[i].address);
    }
    fprintf(out, "    default:\n");
    fprintf(out, "        DOLRECOMP_COUNT(dolrecomp_cold_entries);\n");
    fprintf(out, "        func_%08X_cold(ctx);\n", func_addr);
    fprintf(out, "        return;\n");
    fprintf(out, "    }\n");

    /* FP-availability guard hoist: ppc_fp_available is emitted before every FP
     * op. Within a basic block it is redundant after the first one -- MSR[FP]
     * changes only through mtmsr, an exception or rfi (sc, tw, rfi, mtmsr, and
     * the helper-run mtspr/mfspr/unknown instructions, after which fp_known
     * resets), so if one guard passed, later FP ops in the block see FP
     * available. Every block leader is an entry point and resets it too. We may drop op i's guard only if it cannot be
     * entered except by falling through the (guarded) FP op before it: not a
     * an entry point, i.e. the entry switch has no case for it. (Entry points
     * are a superset of the leaders and return targets this used to test.)
     * The dispatcher can still re-enter here after an FP-unavailable / DSI
     * exception, but that arrives through the cold companion, which guards
     * every FP op. See ppc_fp_available in cpu.h. */
    bool fp_known = false;
    /* Known-single lanes (see sp_update): only this hot pass tracks them,
     * and a label -- an entry from anywhere -- forgets everything. */
    g_sp_track = true;
    g_sp_known = 0;
    g_hb_track = !getenv("DOLRECOMP_NO_BASE_PROOF");
    g_hb_func = func_addr;
    hb_reset();
    for (u32 i = 0; i < count; i++) {
        if (cfg.entry_points[i]) {
            fprintf(out, "label_%08X:\n", insts[i].address);
            g_sp_known = 0;
            fp_known = false;
            hb_reset();
        }
        if (cfg.loop_ends[i] != UINT32_MAX) {
            g_sp_known = 0;
            u32 continuation = insts[cfg.loop_ends[i]].address + 4u;
            fprintf(out, "    loop_%08X(ctx);\n", insts[i].address);
            if (continuation < func_end) {
                fprintf(out, "    if (ctx->pc == 0x%08Xu) goto label_%08X;\n",
                        continuation, continuation);
            }
            fprintf(out, "    return;\n");
            fp_known = false;
            hb_reset();
            continue;
        }
        if (cfg.materialize_pc[i])
            fprintf(out, "    ctx->pc = 0x%08Xu;\n", insts[i].address);
        if (cfg.leaders[i] && cfg.block_cycles[i] != 0)
            fprintf(out, "    ctx->downcount -= %u;\n", cfg.block_cycles[i]);
        bool emit_fp_guard = !(fp_known && !cfg.entry_points[i]);
        emit_instruction_with_range(
            out, &insts[i], func_addr, func_end,
            c_function_cfg_can_loop_directly(&cfg, insts, func_addr, i),
            has_local_returns, emit_fp_guard, false);
        if (insts[i].embedded_data || fp_resets(insts[i].op))
            fp_known = false;
        else if (ppc_op_uses_fpu(insts[i].op))
            fp_known = true;
        if (insts[i].embedded_data) {
            g_sp_known = 0;
            hb_reset();
        } else {
            sp_update(&insts[i]);
            hb_update(&insts[i]);
        }
    }
    g_sp_track = false;
    g_hb_track = false;
    g_sp_known = 0;

    fprintf(out, "    ctx->pc = 0x%08Xu;\n", func_end);
    if (has_local_returns) {
        fprintf(out, "    return;\n");
        fprintf(out, "return_dispatch_%08X:\n", func_addr);
        fprintf(out, "    if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) return;\n");
        emit_pc_switch(out, func_addr);
        for (u32 i = 0; i < count; ++i) {
            if (cfg.return_targets[i]) {
                fprintf(out, "    case 0x%Xu: goto label_%08X;\n",
                        (insts[i].address - func_addr) >> 2, insts[i].address);
            }
        }
        fprintf(out, "    default: return;\n");
        fprintf(out, "    }\n");
    }
    fprintf(out, "}\n\n");
    c_function_cfg_destroy(&cfg);
    return true;
}
