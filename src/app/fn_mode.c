#include "app/fn_mode.h"

#include "backend/c_cfg.h"
#include "backend/emitter.h"
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
    u32 verdicts[FN_EMPTY + 3]; /* + spans-chunk, no-symbol */
} g;

enum { FN_SKIP_SPANS_CHUNK = FN_EMPTY + 1, FN_SKIP_NO_SYMBOL = FN_EMPTY + 2 };

static bool load_hex_list(const char* path, U32Vec* out) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "error: can't open '%s'\n", path);
        return false;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
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

bool fn_mode_section(const PPCInst* insts, u32 num_insts, u32 base_addr,
                     u32 chunk_instructions, const SMCAnalysis* smc,
                     const char* chunks_dir, const char* chunks_label,
                     const char* include_name, FILE* header, FILE* manifest) {
    g.smc = smc;
    const u32 section_end = base_addr + num_insts * 4u;
    for (u32 li = 0; li < g.list.n; li++) {
        u32 addr = g.list.v[li];
        if (addr < base_addr || addr >= section_end)
            continue;
        const DolRecompSymbol* sym = symbol_at(addr);
        if (!sym || sym->size < 4u || addr + sym->size > section_end) {
            g.verdicts[FN_SKIP_NO_SYMBOL]++;
            printf("fn: skip %08X: no-symbol\n", addr);
            continue;
        }
        u32 first = (addr - base_addr) / 4u;
        u32 count = sym->size / 4u;
        if (first / chunk_instructions != (first + count - 1u) / chunk_instructions) {
            g.verdicts[FN_SKIP_SPANS_CHUNK]++;
            printf("fn: skip %08X %s: spans-chunk\n", addr, sym->name);
            continue;
        }
        FnVerdict verdict = fn_select_leaf(insts + first, count, addr, sym->name, excluded);
        if (verdict != FN_OK) {
            g.verdicts[verdict]++;
            printf("fn: skip %08X %s: %s\n", addr, sym->name, fn_verdict_name(verdict));
            continue;
        }

        /* The containing chunk's local return targets, exactly as the chunk
         * emitter computes them (see fn_emitter.h). */
        u32 chunk_first = (first / chunk_instructions) * chunk_instructions;
        u32 chunk_count = num_insts - chunk_first;
        if (chunk_count > chunk_instructions)
            chunk_count = chunk_instructions;
        CFunctionCFG cfg;
        if (!c_function_cfg_build(&cfg, insts + chunk_first, chunk_count,
                                  base_addr + chunk_first * 4u))
            return false;
        U32Vec targets = {0};
        for (u32 i = 0; i < chunk_count; i++)
            if (cfg.return_targets[i] && !vec_push(&targets, insts[chunk_first + i].address)) {
                c_function_cfg_destroy(&cfg);
                return false;
            }
        c_function_cfg_destroy(&cfg);
        FnChunkContext chunk = {base_addr + chunk_first * 4u, targets.v, targets.n,
                                insts + chunk_first, chunk_count};

        if ((!g.file || g.in_file == FN_PER_FILE) &&
            !open_next_file(chunks_dir, chunks_label, include_name, manifest)) {
            free(targets.v);
            return false;
        }
        bool ok = emit_fn_function(g.file, insts + first, count, addr, &chunk);
        free(targets.v);
        if (!ok) {
            g.verdicts[FN_EMPTY]++;
            printf("fn: skip %08X %s: emit\n", addr, sym->name);
            continue;
        }
        g.in_file++;
        g.verdicts[FN_OK]++;
        emit_fn_prototype(header, addr);
        if (!function_list_add(&g.ranges, addr, addr + count * 4u) ||
            !vec_push(&g.accepted, addr))
            return false;
    }
    emitter_set_fn_set(g.accepted.v, g.accepted.n);
    return true;
}

const FunctionList* fn_mode_ranges(void) {
    return g.active ? &g.ranges : NULL;
}

void fn_mode_end(void) {
    if (!g.active)
        return;
    if (g.file)
        fclose(g.file);
    printf("fn: %u converted of %u listed", g.verdicts[FN_OK], g.list.n);
    for (u32 v = 1; v <= FN_EMPTY; v++)
        if (g.verdicts[v])
            printf(", %u %s", g.verdicts[v], fn_verdict_name((FnVerdict)v));
    if (g.verdicts[FN_SKIP_SPANS_CHUNK])
        printf(", %u spans-chunk", g.verdicts[FN_SKIP_SPANS_CHUNK]);
    if (g.verdicts[FN_SKIP_NO_SYMBOL])
        printf(", %u no-symbol", g.verdicts[FN_SKIP_NO_SYMBOL]);
    printf("\n");
    emitter_set_fn_set(NULL, 0);
    free(g.list.v);
    free(g.exclude.v);
    free(g.accepted.v);
    function_list_free(&g.ranges);
    memset(&g, 0, sizeof(g));
}
