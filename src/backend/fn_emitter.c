#include "backend/fn_emitter.h"

#include "backend/c_cfg.h"
#include "backend/emitter.h"
#include "backend/fn_rewrite.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    u32 gpr, fpr, ps1, spr;
} FnUsed;

/* Runs the chunk emitter for one instruction and returns its text. The
 * emitter only writes through FILE*, so capture through a scratch file. */
static char* capture_instruction(const PPCInst* inst, u32 start, u32 end,
                                 bool direct_backedge, bool fp_guard) {
    char path[512];
    const char* dir = getenv("TEMP");
    if (!dir)
        dir = getenv("TMPDIR");
    if (!dir)
        dir = ".";
    int local;
    snprintf(path, sizeof(path), "%s/dolrecomp_fn_%08X_%p.tmp", dir,
             inst->address, (void*)&local);
    FILE* f = fopen(path, "wb+");
    if (!f)
        return NULL;
    emit_instruction_ex(f, inst, start, end, direct_backedge, true, fp_guard);
    long size = ftell(f);
    char* text = size >= 0 ? (char*)malloc((size_t)size + 1u) : NULL;
    if (text) {
        rewind(f);
        text[fread(text, 1, (size_t)size, f)] = '\0';
    }
    fclose(f);
    remove(path);
    return text;
}

static void emit_flush(FILE* out, const FnUsed* u, const char* indent) {
    for (u32 n = 0; n < 32; n++) {
        if (u->gpr & (1u << n))
            fprintf(out, "%sctx->gpr[%u] = gr%u;\n", indent, n, n);
        if (u->fpr & (1u << n))
            fprintf(out, "%sctx->fpr[%u] = gf%u;\n", indent, n, n);
        if (u->ps1 & (1u << n))
            fprintf(out, "%sctx->ps1[%u] = gp%u;\n", indent, n, n);
    }
    if (u->spr & FN_SPR_CR) fprintf(out, "%sctx->cr = gcr;\n", indent);
    if (u->spr & FN_SPR_XER) fprintf(out, "%sctx->xer = gxer;\n", indent);
    if (u->spr & FN_SPR_LR) fprintf(out, "%sctx->lr = glr;\n", indent);
    if (u->spr & FN_SPR_CTR) fprintf(out, "%sctx->ctr = gctr;\n", indent);
}

static void emit_reload(FILE* out, const FnUsed* u, const char* indent) {
    for (u32 n = 0; n < 32; n++) {
        if (u->gpr & (1u << n))
            fprintf(out, "%sgr%u = ctx->gpr[%u];\n", indent, n, n);
        if (u->fpr & (1u << n))
            fprintf(out, "%sgf%u = ctx->fpr[%u];\n", indent, n, n);
        if (u->ps1 & (1u << n))
            fprintf(out, "%sgp%u = ctx->ps1[%u];\n", indent, n, n);
    }
    if (u->spr & FN_SPR_CR) fprintf(out, "%sgcr = ctx->cr;\n", indent);
    if (u->spr & FN_SPR_XER) fprintf(out, "%sgxer = ctx->xer;\n", indent);
    if (u->spr & FN_SPR_LR) fprintf(out, "%sglr = ctx->lr;\n", indent);
    if (u->spr & FN_SPR_CTR) fprintf(out, "%sgctr = ctx->ctr;\n", indent);
}

static void emit_declarations(FILE* out, const FnUsed* u) {
    for (u32 n = 0; n < 32; n++) {
        if (u->gpr & (1u << n))
            fprintf(out, "    u32 gr%u = ctx->gpr[%u];\n", n, n);
        if (u->fpr & (1u << n))
            fprintf(out, "    f64 gf%u = ctx->fpr[%u];\n", n, n);
        if (u->ps1 & (1u << n))
            fprintf(out, "    f64 gp%u = ctx->ps1[%u];\n", n, n);
    }
    if (u->spr & FN_SPR_CR) fprintf(out, "    u32 gcr = ctx->cr;\n");
    if (u->spr & FN_SPR_XER) fprintf(out, "    u32 gxer = ctx->xer;\n");
    if (u->spr & FN_SPR_LR) fprintf(out, "    u32 glr = ctx->lr;\n");
    if (u->spr & FN_SPR_CTR) fprintf(out, "    u32 gctr = ctx->ctr;\n");
}

/* The chunk code falls through into the next function when the last
 * instruction does not branch away; a converted function cannot, so it must
 * end in an unconditional b or bclr. */
static bool ends_unconditionally(const PPCInst* insts, u32 count) {
    u32 i = count;
    while (i > 0 && insts[i - 1].embedded_data)
        i--;
    if (i == 0)
        return false;
    const PPCInst* last = &insts[i - 1];
    if (last->lk)
        return false;
    if (last->op == PPC_OP_B)
        return true;
    return last->op == PPC_OP_BCLR && (last->bo & 0x14u) == 0x14u;
}

/* Replaces every occurrence of `from` in text (in place, same length). */
static void replace_same_length(char* text, const char* from, const char* to) {
    size_t n = strlen(from);
    for (char* p = text; (p = strstr(p, from)) != NULL; p += n)
        memcpy(p, to, n);
}

void emit_fn_prototype(FILE* out, u32 start) {
    fprintf(out, "void fn_%08X(CPUState* ctx);\n", start);
    fprintf(out, "void fn_%08X_direct(CPUState* ctx);\n", start);
}

bool emit_fn_function(FILE* out, const PPCInst* insts, u32 count, u32 start,
                      const FnChunkContext* chunk) {
    if (count == 0 || !ends_unconditionally(insts, count))
        return false;
    const u32 end = start + count * 4u;
    /* Analyse the containing chunk, as the chunk emitter does, and view it
     * through the function's window: o is the function's first index in it. */
    const PPCInst* cinsts = insts;
    u32 ccount = count, cstart = start;
    if (chunk && chunk->chunk_insts) {
        cinsts = chunk->chunk_insts;
        ccount = chunk->chunk_count;
        cstart = chunk->chunk_start;
    }
    if (start < cstart || end > cstart + ccount * 4u)
        return false;
    const u32 o = (start - cstart) / 4u;
    CFunctionCFG cfg;
    if (!c_function_cfg_build(&cfg, cinsts, ccount, cstart))
        return false;

    char** texts = (char**)calloc(count, sizeof(char*));
    FnRewriteInfo* infos = (FnRewriteInfo*)calloc(count, sizeof(FnRewriteInfo));
    u32* loop_header_of = (u32*)malloc(count * sizeof(u32));
    bool ok = texts && infos && loop_header_of;
    FnUsed used = {0};
    bool has_bclr = false;

    if (ok) {
        for (u32 i = 0; i < count; i++)
            loop_header_of[i] = UINT32_MAX;
        for (u32 i = 0; i < count; i++)
            if (cfg.loop_ends[o + i] != UINT32_MAX &&
                cfg.loop_ends[o + i] - o < count)
                loop_header_of[cfg.loop_ends[o + i] - o] = i;
    }

    /* Pass 1: capture and rewrite every instruction's text. The FP guard
     * follows emit_function's hoisting rule; counted-loop bodies always guard
     * (the chunk emits them in a helper that does). */
    bool prev_fpu = false;
    u32 in_loop_until = UINT32_MAX;
    for (u32 i = 0; ok && i < count; i++) {
        if (cfg.loop_ends[o + i] != UINT32_MAX)
            in_loop_until = cfg.loop_ends[o + i] - o;
        bool in_loop = in_loop_until != UINT32_MAX && i <= in_loop_until;
        bool fp_guard = in_loop || !(prev_fpu && !cfg.entry_points[o + i]);
        bool direct_backedge = loop_header_of[i] != UINT32_MAX ||
            c_function_cfg_can_loop_directly(&cfg, cinsts, cstart, o + i);
        char* raw = capture_instruction(&insts[i], start, end, direct_backedge,
                                        fp_guard);
        if (!raw) {
            ok = false;
            break;
        }
        texts[i] = fn_rewrite_instruction(raw, &infos[i]);
        free(raw);
        if (!texts[i] || (infos[i].impure && infos[i].has_goto)) {
            ok = false;
            break;
        }
        if (loop_header_of[i] != UINT32_MAX) {
            /* The loop's own backedge re-enters below the idle check, like
             * the chunk emitter's loop helper does. */
            char from[32], to[32];
            u32 header = insts[loop_header_of[i]].address;
            snprintf(from, sizeof(from), "goto label_%08X;", header);
            snprintf(to, sizeof(to), "goto loopb_%08X;", header);
            replace_same_length(texts[i], from, to);
        }
        used.gpr |= infos[i].gpr_used;
        used.fpr |= infos[i].fpr_used;
        used.ps1 |= infos[i].ps1_used;
        used.spr |= infos[i].spr_used;
        has_bclr |= !insts[i].embedded_data && insts[i].op == PPC_OP_BCLR;
        prev_fpu = !insts[i].embedded_data && ppc_op_uses_fpu(insts[i].op);
        if (in_loop && i == in_loop_until)
            in_loop_until = UINT32_MAX;
    }

    if (ok) {
        fprintf(out, "static inline void fn_%08X_impl(CPUState* ctx, int from_dispatch) {\n",
                start);
        emit_declarations(out, &used);
        fprintf(out, "    if (!from_dispatch) goto label_%08X;\n", start);
        fprintf(out, "    switch (ctx->pc) {\n");
        /* Only the chunk's own entry points resume here; any other pc (the
         * start included, when padding keeps it from being a leader) takes
         * the chunk's cold path, exactly as it would without conversion. */
        for (u32 i = 0; i < count; i++)
            if (cfg.entry_points[o + i])
                fprintf(out, "    case 0x%08Xu: goto label_%08X;\n",
                        insts[i].address, insts[i].address);
        fprintf(out, "    default: dolrecomp_find_chunk(ctx->pc)(ctx); return;\n");
        fprintf(out, "    }\n");

        for (u32 i = 0; i < count; i++) {
            fprintf(out, "label_%08X:\n", insts[i].address);
            if (cfg.loop_ends[o + i] != UINT32_MAX) {
                u32 a = insts[i].address;
                fprintf(out, "    if (ctx->idle_hook_pc == 0x%08Xu) {\n", a);
                emit_flush(out, &used, "        ");
                fprintf(out, "        if (ctx->idle_hook(ctx)) return;\n");
                emit_reload(out, &used, "        ");
                fprintf(out, "    }\n");
                fprintf(out, "loopb_%08X:\n", a);
            }
            if (cfg.materialize_pc[o + i])
                fprintf(out, "    ctx->pc = 0x%08Xu;\n", insts[i].address);
            if (cfg.leaders[o + i] && cfg.block_cycles[o + i] != 0)
                fprintf(out, "    ctx->downcount -= %u;\n", cfg.block_cycles[o + i]);
            if (infos[i].impure) {
                emit_flush(out, &used, "    ");
                fputs(texts[i], out);
                emit_reload(out, &used, "    ");
            } else {
                fputs(texts[i], out);
            }
            if (loop_header_of[i] != UINT32_MAX)
                fprintf(out, "    ctx->pc = 0x%08Xu;\n", insts[i].address + 4u);
        }
        fprintf(out, "    ctx->pc = 0x%08Xu;\n", end);
        fprintf(out, "    goto fn_exit;\n");

        if (has_bclr) {
            /* The chunk's return_dispatch: a bclr keeps running in the chunk
             * when the return address is one of its local call returns and
             * the budget allows. Only a dispatcher entry can be in that
             * position; a direct call returns to its chunk call site, which
             * performs the same checks itself. */
            fprintf(out, "return_dispatch_%08X:\n", start);
            fprintf(out, "    if (!from_dispatch) goto fn_exit;\n");
            fprintf(out, "    if (ctx->downcount <= -(s64)DOLRECOMP_C_LOOP_CYCLE_BUDGET) goto fn_exit;\n");
            if (chunk && chunk->return_target_count) {
                fprintf(out, "    switch (ctx->pc) {\n");
                for (u32 t = 0; t < chunk->return_target_count; t++)
                    fprintf(out, "    case 0x%08Xu:\n", chunk->return_targets[t]);
                emit_flush(out, &used, "        ");
                fprintf(out, "        func_%08X(ctx);\n", chunk->chunk_start);
                fprintf(out, "        return;\n");
                fprintf(out, "    default: break;\n");
                fprintf(out, "    }\n");
            }
            fprintf(out, "    goto fn_exit;\n");
        }
        fprintf(out, "fn_exit:\n");
        emit_flush(out, &used, "    ");
        fprintf(out, "fn_exit_raw:\n");
        fprintf(out, "    return;\n");
        fprintf(out, "}\n");
        fprintf(out, "void fn_%08X(CPUState* ctx) { fn_%08X_impl(ctx, 1); }\n", start, start);
        fprintf(out, "void fn_%08X_direct(CPUState* ctx) { fn_%08X_impl(ctx, 0); }\n\n",
                start, start);
    }

    for (u32 i = 0; texts && i < count; i++)
        free(texts[i]);
    free(texts);
    free(infos);
    free(loop_header_of);
    c_function_cfg_destroy(&cfg);
    return ok;
}
