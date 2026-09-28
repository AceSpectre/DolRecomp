#ifndef DOLRECOMP_FN_REWRITE_H
#define DOLRECOMP_FN_REWRITE_H

#include "../common/types.h"

/* Function-mode codegen reuses the chunk emitter's per-instruction C text and
 * rewrites it so guest registers become C locals of the enclosing fn_X.
 *
 * Pure text (touches ctx only through register fields, whitelisted helpers
 * and non-register fields) gets ctx->gpr[N] -> grN, ctx->fpr[N] -> gfN,
 * ctx->ps1[N] -> gpN, ctx->cr/xer/lr/ctr -> gcr/gxer/glr/gctr, and
 * "return;" -> "goto fn_exit;" (flush locals, then return).
 *
 * Impure text passes ctx to a helper that may read or write guest registers
 * through it; the caller brackets it with a flush and a reload, so its
 * register fields stay as ctx accesses and "return;" becomes
 * "goto fn_exit_raw;" (ctx is authoritative there, nothing to flush). */

#define FN_SPR_CR  1u
#define FN_SPR_XER 2u
#define FN_SPR_LR  4u
#define FN_SPR_CTR 8u

typedef struct {
    u32 gpr_used;  /* bit n: rN read or written */
    u32 fpr_used;  /* bit n: fpr N */
    u32 ps1_used;  /* bit n: ps1 N */
    u32 spr_used;  /* FN_SPR_* */
    bool impure;   /* passes ctx to a helper that may touch guest registers */
    bool has_goto; /* text contains "goto " */
} FnRewriteInfo;

/* Returns a malloc'd rewritten copy of text, or NULL on allocation failure. */
char* fn_rewrite_instruction(const char* text, FnRewriteInfo* info);

#endif
