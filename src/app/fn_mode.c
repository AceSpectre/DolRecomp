#include "app/fn_mode.h"

#include "backend/c_cfg.h"
#include "backend/emitter.h"
#include "backend/fn_closure.h"
#include "backend/fn_emitter.h"
#include "backend/fn_select.h"
#include "platform/fs.h"

#include <stdlib.h>
#include <string.h>

#define FN_PER_FILE 64u

typedef struct {
    u32* v;
    u32 n, cap;
} U32Vec;

static bool vec_push(U32Vec* vec, u32 x) {
    if (vec->n == vec->cap) {
        u32 cap = vec->cap ? vec->cap * 2u : 64u;
        u32* v = (u32*)realloc(vec->v, cap * sizeof(u32));
        if (!v)
            return false;
        vec->v = v;
        vec->cap = cap;
    }
    vec->v[vec->n++] = x;
    return true;
}

static int compare_u32(const void* a, const void* b) {
    u32 x = *(const u32*)a, y = *(const u32*)b;
    return x < y ? -1 : x > y;
}

static struct {
    bool active;
    const DolRecompSymbolMap* symbols;
    U32Vec list;
    U32Vec exclude;
    const SMCAnalysis* smc;
    U32Vec accepted;
    FunctionList ranges;
    FILE* file;
    u32 file_index;
    u32 in_file;
    u32 verdicts[FN_VERDICT_COUNT];      /* listed functions */
    u32 auto_verdicts[FN_VERDICT_COUNT]; /* auto-added same-chunk callees */
} g;

static bool load_hex_list(const char* path, U32Vec* out) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "error: can't open '%s'\n", path);
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Only the leading address matters; drop the rest of a long line
         * (the list's comments carry full mangled C++ names). */
        if (!strchr(line, '\n')) {
            int ch;
            while ((ch = fgetc(f)) != EOF && ch != '\n') {
            }
        }
        char* p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;
        char* end;
        unsigned long v = strtoul(p, &end, 16);
        if (end == p || !vec_push(out, (u32)v)) {
            fclose(f);
            fprintf(stderr, "error: bad address line in '%s': %s", path, line);
            return false;
        }
    }
    fclose(f);
    qsort(out->v, out->n, sizeof(u32), compare_u32);
    return true;
}

bool fn_mode_begin(const char* list_path, const char* exclude_path,
                   const DolRecompSymbolMap* symbols) {
    memset(&g, 0, sizeof(g));
    if (!list_path)
        return true;
    if (!symbols) {
        fprintf(stderr, "error: --fn-list needs --map for function extents\n");
        return false;
    }
    if (!load_hex_list(list_path, &g.list))
        return false;
    if (exclude_path && !load_hex_list(exclude_path, &g.exclude))
        return false;
    g.symbols = symbols;
    g.active = true;
    return true;
}

bool fn_mode_active(void) {
    return g.active;
}

static bool excluded(u32 addr) {
    if (g.exclude.n &&
        bsearch(&addr, g.exclude.v, g.exclude.n, sizeof(u32), compare_u32))
        return true;
    for (u32 i = 0; g.smc && i < g.smc->range_count; i++)
        if (addr >= g.smc->ranges[i].start && addr < g.smc->ranges[i].end)
            return true;
    return false;
}

static const DolRecompSymbol* symbol_at(u32 addr) {
    for (u32 i = 0; i < g.symbols->count; i++)
        if (g.symbols->symbols[i].address == addr)
            return &g.symbols->symbols[i];
    return NULL;
}

static bool open_next_file(const char* chunks_dir, const char* chunks_label,
                           const char* include_name, FILE* manifest) {
    if (g.file)
        fclose(g.file);
    char name[64], path[1100];
    snprintf(name, sizeof(name), "fnchunk_%04u.c", g.file_index++);
    snprintf(path, sizeof(path), "%s/%s", chunks_dir, name);
    g.file = fopen(path, "w");
    if (!g.file) {
        fprintf(stderr, "error: can't open output '%s'\n", path);
        return false;
    }
    fprintf(g.file, "// DolRecomp function-mode output\n");
    fprintf(g.file, "#include \"../%s\"\n\n", include_name);
    fprintf(manifest, "// %s/%s\n", chunks_label, name);
    g.in_file = 0;
    return true;
}

#ifdef _WIN32
#define FN_NULL_DEVICE "NUL"
#else
#define FN_NULL_DEVICE "/dev/null"
#endif

typedef struct {
    u32 start, first, count, chunk_first, chunk_count;
    const char* name;
    bool listed;
    FnVerdict verdict;
    FnNeeds needs;
} FnCand;

typedef struct {
    FnCand* v;
    u32 n, cap;
} CandVec;

static FnCand* cand_push(CandVec* c) {
    if (c->n == c->cap) {
        u32 cap = c->cap ? c->cap * 2u : 64u;
        FnCand* v = (FnCand*)realloc(c->v, cap * sizeof(FnCand));
        if (!v)
            return NULL;
        c->v = v;
        c->cap = cap;
    }
    FnCand* x = &c->v[c->n++];
    memset(x, 0, sizeof(*x));
    return x;
}

static bool cand_has(const CandVec* c, u32 start) {
    for (u32 i = 0; i < c->n; i++)
        if (c->v[i].start == start)
            return true;
    return false;
}

static int compare_cand(const void* a, const void* b) {
    u32 x = ((const FnCand*)a)->start, y = ((const FnCand*)b)->start;
    return x < y ? -1 : x > y;
}

/* Fills in extents and the selection verdict for one candidate. */
static void cand_select(FnCand* c, const PPCInst* insts, u32 num_insts, u32 base_addr,
                        u32 chunk_instructions) {
    const u32 section_end = base_addr + num_insts * 4u;
    const DolRecompSymbol* sym = symbol_at(c->start);
    if (!sym || sym->size < 4u || c->start + sym->size > section_end) {
        c->verdict = FN_NO_SYMBOL;
        return;
    }
    c->name = sym->name;
    c->first = (c->start - base_addr) / 4u;
    c->count = sym->size / 4u;
    if (c->first / chunk_instructions != (c->first + c->count - 1u) / chunk_instructions) {
        c->verdict = FN_SPANS_CHUNK;
        return;
    }
    c->chunk_first = (c->first / chunk_instructions) * chunk_instructions;
    c->chunk_count = num_insts - c->chunk_first;
    if (c->chunk_count > chunk_instructions)
        c->chunk_count = chunk_instructions;
    c->verdict = fn_select_function(insts + c->first, c->count, c->start,
                                    base_addr + c->chunk_first * 4u,
                                    base_addr + (c->chunk_first + c->chunk_count) * 4u,
                                    sym->name, excluded, &c->needs);
}

/* The containing chunk's local return targets, exactly as the chunk emitter
 * computes them (see fn_emitter.h), and the emission of one candidate. */
static bool cand_emit(FILE* out, const FnCand* c, const PPCInst* insts, u32 base_addr,
                      bool* emitted) {
    CFunctionCFG cfg;
    if (!c_function_cfg_build(&cfg, insts + c->chunk_first, c->chunk_count,
                              base_addr + c->chunk_first * 4u))
        return false;
    U32Vec targets = {0};
    for (u32 i = 0; i < c->chunk_count; i++)
        if (cfg.return_targets[i] && !vec_push(&targets, insts[c->chunk_first + i].address)) {
            c_function_cfg_destroy(&cfg);
            free(targets.v);
            return false;
        }
    c_function_cfg_destroy(&cfg);
    FnChunkContext chunk = {base_addr + c->chunk_first * 4u, targets.v, targets.n,
                            insts + c->chunk_first, c->chunk_count};
    *emitted = emit_fn_function(out, insts + c->first, c->count, c->start, &chunk);
    free(targets.v);
    return true;
}

/* Sets the emitter's converted-function set to g.accepted plus this
 * section's FN_OK candidates. */
static bool set_fn_set(const CandVec* cands) {
    U32Vec set = {0};
    for (u32 i = 0; i < g.accepted.n; i++)
        if (!vec_push(&set, g.accepted.v[i]))
            return false;
    for (u32 i = 0; i < cands->n; i++)
        if (cands->v[i].verdict == FN_OK && !vec_push(&set, cands->v[i].start)) {
            free(set.v);
            return false;
        }
    emitter_set_fn_set(set.v, set.n);
    free(set.v);
    return true;
}

bool fn_mode_section(const PPCInst* insts, u32 num_insts, u32 base_addr,
                     u32 chunk_instructions, const SMCAnalysis* smc,
                     const char* chunks_dir, const char* chunks_label,
                     const char* include_name, FILE* manifest) {
    g.smc = smc;
    const u32 section_end = base_addr + num_insts * 4u;
    CandVec cands = {0};
    bool ok = true;

    /* 1. Candidates: the listed functions in this section, then (worklist)
     * every same-chunk callee an accepted candidate needs. */
    for (u32 li = 0; ok && li < g.list.n; li++) {
        u32 addr = g.list.v[li];
        if (addr < base_addr || addr >= section_end)
            continue;
        FnCand* c = cand_push(&cands);
        if (!c) {
            ok = false;
            break;
        }
        c->start = addr;
        c->listed = true;
    }
    for (u32 i = 0; ok && i < cands.n; i++) {
        cand_select(&cands.v[i], insts, num_insts, base_addr, chunk_instructions);
        if (cands.v[i].verdict != FN_OK)
            continue;
        for (u32 k = 0; k < cands.v[i].needs.count; k++) {
            u32 t = cands.v[i].needs.targets[k];
            const DolRecompSymbol* sym = symbol_at(t);
            if (!sym || t < base_addr || t >= section_end || cand_has(&cands, t))
                continue;
            FnCand* c = cand_push(&cands);
            if (!c) {
                ok = false;
                break;
            }
            c->start = t;
        }
    }

    /* 2. Dry run: anything the emitter cannot express is rejected before the
     * closure, so no accepted caller can refer to a callee that was never
     * written. */
    if (ok)
        ok = set_fn_set(&cands);
    for (u32 i = 0; ok && i < cands.n; i++) {
        FnCand* c = &cands.v[i];
        if (c->verdict != FN_OK)
            continue;
        FILE* scratch = fopen(FN_NULL_DEVICE, "w");
        bool emitted = false;
        ok = scratch && cand_emit(scratch, c, insts, base_addr, &emitted);
        if (scratch)
            fclose(scratch);
        if (ok && !emitted)
            c->verdict = FN_EMIT_FAILED;
    }

    /* 3. Closure over same-chunk callees. */
    if (ok && cands.n) {
        qsort(cands.v, cands.n, sizeof(FnCand), compare_cand);
        FnNode* nodes = (FnNode*)malloc(cands.n * sizeof(FnNode));
        ok = nodes != NULL;
        for (u32 i = 0; ok && i < cands.n; i++) {
            nodes[i].start = cands.v[i].start;
            nodes[i].verdict = cands.v[i].verdict;
            nodes[i].needs = &cands.v[i].needs;
        }
        if (ok) {
            fn_closure_resolve(nodes, cands.n, FN_MAX_CHAIN_DEPTH);
            for (u32 i = 0; i < cands.n; i++)
                cands.v[i].verdict = nodes[i].verdict;
        }
        free(nodes);
    }

    /* 4. Emit the accepted set. */
    if (ok)
        ok = set_fn_set(&cands);
    for (u32 i = 0; ok && i < cands.n; i++) {
        FnCand* c = &cands.v[i];
        if (c->listed)
            g.verdicts[c->verdict]++;
        else
            g.auto_verdicts[c->verdict]++;
        if (c->verdict != FN_OK) {
            if (c->listed)
                printf("fn: skip %08X %s: %s\n", c->start, c->name ? c->name : "",
                       fn_verdict_name(c->verdict));
            continue;
        }
        if ((!g.file || g.in_file == FN_PER_FILE) &&
            !open_next_file(chunks_dir, chunks_label, include_name, manifest)) {
            ok = false;
            break;
        }
        emit_fn_prototype(g.file, c->start);
        bool emitted = false;
        if (!cand_emit(g.file, c, insts, base_addr, &emitted) || !emitted) {
            fprintf(stderr, "error: fn emit failed after dry run at %08X\n", c->start);
            ok = false;
            break;
        }
        g.in_file++;
        if (!function_list_add(&g.ranges, c->start, c->start + c->count * 4u) ||
            !vec_push(&g.accepted, c->start))
            ok = false;
    }
    free(cands.v);
    emitter_set_fn_set(g.accepted.v, g.accepted.n);
    return ok;
}

const FunctionList* fn_mode_ranges(void) {
    return g.active ? &g.ranges : NULL;
}

void fn_mode_end(void) {
    if (!g.active)
        return;
    if (g.file)
        fclose(g.file);
    printf("fn: %u converted (%u listed, %u auto-added callees) of %u listed",
           g.verdicts[FN_OK] + g.auto_verdicts[FN_OK], g.verdicts[FN_OK],
           g.auto_verdicts[FN_OK], g.list.n);
    for (u32 v = 1; v < FN_VERDICT_COUNT; v++)
        if (g.verdicts[v])
            printf(", %u %s", g.verdicts[v], fn_verdict_name((FnVerdict)v));
    printf("\n");
    u32 auto_rejected = 0;
    for (u32 v = 1; v < FN_VERDICT_COUNT; v++)
        auto_rejected += g.auto_verdicts[v];
    if (auto_rejected) {
        printf("fn: auto-added callees rejected:");
        for (u32 v = 1; v < FN_VERDICT_COUNT; v++)
            if (g.auto_verdicts[v])
                printf(" %u %s", g.auto_verdicts[v], fn_verdict_name((FnVerdict)v));
        printf("\n");
    }
    emitter_set_fn_set(NULL, 0);
    free(g.list.v);
    free(g.exclude.v);
    free(g.accepted.v);
    function_list_free(&g.ranges);
    memset(&g, 0, sizeof(g));
}
