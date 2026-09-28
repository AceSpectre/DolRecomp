#include "backend/fn_rewrite.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* p;
    size_t n, cap;
} Buf;

static bool put(Buf* b, const char* s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = (b->cap ? b->cap * 2 : 256) + n;
        char* p = (char*)realloc(b->p, cap);
        if (!p)
            return false;
        b->p = p;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
    return true;
}

static bool starts(const char* s, const char* prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool ident_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* Helpers that take ctx but never read or write guest registers through it.
 * Memory helpers only reach RAM, MMIO and exception state (pc/srr/msr), and
 * the FP guard and timebase read touch msr/exception/downcount. */
static const char* const k_pure_ctx_calls[] = {
    "mem_read8(ctx",  "mem_read16(ctx",  "mem_read32(ctx",  "mem_read64(ctx",
    "mem_write8(ctx", "mem_write16(ctx", "mem_write32(ctx", "mem_write64(ctx",
    "ppc_fp_available(ctx", "ppc_mftb(ctx",
};

/* True when a bare `ctx` is passed to anything outside the whitelist. */
static bool text_is_impure(const char* t) {
    for (const char* s = t; (s = strstr(s, "ctx")) != NULL; s += 3) {
        if ((s > t && ident_char(s[-1])) || ident_char(s[3]) || starts(s, "ctx->"))
            continue;
        /* Bare ctx: walk back to the '(' that opens its argument list, then
         * to the start of the callee name. */
        const char* open = s;
        while (open > t && open[-1] != '(' && open[-1] != '\n')
            open--;
        if (open == t || open[-1] != '(')
            return true;
        const char* name = open - 1;
        while (name > t && ident_char(name[-1]))
            name--;
        bool ok = false;
        for (size_t i = 0; i < sizeof(k_pure_ctx_calls) / sizeof(*k_pure_ctx_calls); i++)
            ok |= starts(name, k_pure_ctx_calls[i]) && name + strlen(k_pure_ctx_calls[i]) == s + 3;
        if (!ok)
            return true;
    }
    return false;
}

/* Parses "ctx-><field>[N]" at s; returns chars consumed or 0. */
static int indexed_field(const char* s, const char* field, unsigned* n) {
    size_t fl = strlen(field);
    if (strncmp(s, field, fl) != 0 || !isdigit((unsigned char)s[fl]))
        return 0;
    unsigned v = 0;
    size_t i = fl;
    while (isdigit((unsigned char)s[i]))
        v = v * 10u + (unsigned)(s[i++] - '0');
    if (s[i] != ']' || v >= 32u)
        return 0;
    *n = v;
    return (int)i + 1;
}

char* fn_rewrite_instruction(const char* text, FnRewriteInfo* info) {
    memset(info, 0, sizeof(*info));
    info->impure = text_is_impure(text);
    info->has_goto = strstr(text, "goto ") != NULL;

    static const struct {
        const char* field;
        const char* local;
        u32 bit;
    } sprs[] = {
        {"ctx->cr", "gcr", FN_SPR_CR},
        {"ctx->xer", "gxer", FN_SPR_XER},
        {"ctx->lr", "glr", FN_SPR_LR},
        {"ctx->ctr", "gctr", FN_SPR_CTR},
    };
    static const struct {
        const char* field;
        const char* prefix;
        int kind;
    } regs[] = {
        {"ctx->gpr[", "gr", 0},
        {"ctx->fpr[", "gf", 1},
        {"ctx->ps1[", "gp", 2},
    };

    Buf b = {0};
    const char* s = text;
    while (*s) {
        bool consumed = false;
        for (size_t r = 0; r < 3 && !consumed; r++) {
            unsigned n;
            int len = indexed_field(s, regs[r].field, &n);
            if (!len)
                continue;
            u32* used = regs[r].kind == 0 ? &info->gpr_used
                      : regs[r].kind == 1 ? &info->fpr_used : &info->ps1_used;
            *used |= 1u << n;
            if (!info->impure) {
                char tmp[8];
                int k = snprintf(tmp, sizeof(tmp), "%s%u", regs[r].prefix, n);
                if (!put(&b, tmp, (size_t)k))
                    goto oom;
                s += len;
                consumed = true;
            }
        }
        for (size_t i = 0; i < 4 && !consumed; i++) {
            size_t fl = strlen(sprs[i].field);
            if (!starts(s, sprs[i].field) || ident_char(s[fl]))
                continue;
            info->spr_used |= sprs[i].bit;
            if (!info->impure) {
                if (!put(&b, sprs[i].local, strlen(sprs[i].local)))
                    goto oom;
                s += fl;
                consumed = true;
            }
        }
        if (!consumed && starts(s, "return;") && (s == text || !ident_char(s[-1]))) {
            const char* rep = info->impure ? "goto fn_exit_raw;" : "goto fn_exit;";
            if (!put(&b, rep, strlen(rep)))
                goto oom;
            s += 7;
            consumed = true;
        }
        if (consumed)
            continue;
        /* No rule matched here: copy one character verbatim. */
        if (!put(&b, s, 1))
            goto oom;
        s++;
    }
    return b.p ? b.p : (char*)calloc(1, 1);
oom:
    free(b.p);
    return NULL;
}
