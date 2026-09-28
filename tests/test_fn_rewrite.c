#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/backend/fn_rewrite.h"

static int fails;

static void expect_rewrite(const char* in, const char* want, bool impure) {
    FnRewriteInfo info;
    char* got = fn_rewrite_instruction(in, &info);
    if (!got || strcmp(got, want) != 0 || info.impure != impure) {
        fprintf(stderr, "rewrite mismatch\n in:   %s\n got:  %s\n want: %s (impure=%d)\n",
                in, got ? got : "(null)", want, (int)impure);
        fails++;
    }
    free(got);
}

int main(void) {
    expect_rewrite("    ctx->gpr[3] = ctx->gpr[31] + (u32)(s32)(8);\n",
                   "    gr3 = gr31 + (u32)(s32)(8);\n", false);
    expect_rewrite("    ctx->cr = (ctx->cr & ~(0xFu << 28)) | (b << 28);\n",
                   "    gcr = (gcr & ~(0xFu << 28)) | (b << 28);\n", false);
    /* ctx->ctr must not be mangled by the cr rule */
    expect_rewrite("    ctx->ctr = ctx->gpr[12];\n", "    gctr = gr12;\n", false);
    expect_rewrite("        ctx->gpr[5] = mem_read32(ctx, ea);\n",
                   "        gr5 = mem_read32(ctx, ea);\n", false);
    expect_rewrite("    if (!ppc_fp_available(ctx, 0x80001000u)) return;\n",
                   "    if (!ppc_fp_available(ctx, 0x80001000u)) goto fn_exit;\n", false);
    expect_rewrite("    ctx->fpr[1] = ctx->ps1[1] = (f64)(f32)(ctx->fpr[2] + ctx->fpr[3]);\n",
                   "    gf1 = gp1 = (f64)(f32)(gf2 + gf3);\n", false);
    /* non-register ctx fields stay as they are in pure text */
    expect_rewrite("    ctx->pc = 0x80001000u;\n    ctx->downcount -= 3;\n",
                   "    ctx->pc = 0x80001000u;\n    ctx->downcount -= 3;\n", false);
    /* impure: helper takes ctx; registers stay ctx fields, return is raw */
    expect_rewrite("        ppc_psq_load(ctx, 1u, ea, false, 0u, false, 0x80001004u);\n"
                   "        if (ctx->exception) return;\n",
                   "        ppc_psq_load(ctx, 1u, ea, false, 0u, false, 0x80001004u);\n"
                   "        if (ctx->exception) goto fn_exit_raw;\n", true);
    /* ppc_fcmp writes ctx->cr: impure even though it takes values */
    expect_rewrite("    ppc_fcmp(ctx, 1u, ctx->fpr[1], ctx->fpr[2], false);\n",
                   "    ppc_fcmp(ctx, 1u, ctx->fpr[1], ctx->fpr[2], false);\n", true);

    /* used-register bookkeeping */
    FnRewriteInfo info;
    free(fn_rewrite_instruction("    ctx->gpr[4] = ctx->gpr[5] ^ ctx->xer;\n", &info));
    if (info.gpr_used != ((1u << 4) | (1u << 5)) || info.spr_used != FN_SPR_XER) {
        fprintf(stderr, "used bits wrong: gpr=%08X spr=%X\n", info.gpr_used, info.spr_used);
        fails++;
    }
    /* impure text still records the registers it names */
    free(fn_rewrite_instruction("    ppc_fcmp(ctx, 1u, ctx->fpr[1], ctx->fpr[2], false);\n", &info));
    if (info.fpr_used != ((1u << 1) | (1u << 2))) {
        fprintf(stderr, "impure used bits wrong: fpr=%08X\n", info.fpr_used);
        fails++;
    }
    free(fn_rewrite_instruction("    goto label_80001000;\n", &info));
    if (!info.has_goto) {
        fprintf(stderr, "has_goto not set\n");
        fails++;
    }
    if (fails)
        fprintf(stderr, "%d failures\n", fails);
    return fails != 0;
}
