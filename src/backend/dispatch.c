#include "backend/dispatch.h"
#include <stdlib.h>
#include <string.h>

void emit_chunk_prototype(FILE* out, u32 func_addr) {
    fprintf(out, "void func_%08X(CPUState* ctx);\n", func_addr);
}

void function_list_free(FunctionList* list) {
    free(list->ranges);
    list->ranges = NULL;
    list->count = 0;
    list->capacity = 0;
}

int function_list_add(FunctionList* list, u32 start, u32 end) {
    if (list->count == list->capacity) {
        u32 new_capacity = list->capacity ? list->capacity * 2u : 64u;
        FunctionRange* new_ranges =
            (FunctionRange*)realloc(list->ranges, new_capacity * sizeof(*new_ranges));
        if (!new_ranges) {
            fprintf(stderr, "error: out of memory\n");
            return 0;
        }
        list->ranges = new_ranges;
        list->capacity = new_capacity;
    }

    list->ranges[list->count].start = start;
    list->ranges[list->count].end = end;
    list->count++;
    return 1;
}

static u32 uniform_run_end(const FunctionList* funcs, u32 first) {
    const FunctionRange* first_range = &funcs->ranges[first];
    if (first_range->start >= first_range->end)
        return first + 1u;

    u32 stride = first_range->end - first_range->start;
    if ((stride & 3u) != 0u)
        return first + 1u;

    // Split sections use equal-sized chunks followed by at most one short chunk.
    u32 end = first + 1u;
    while (end < funcs->count) {
        const FunctionRange* previous = &funcs->ranges[end - 1u];
        const FunctionRange* current = &funcs->ranges[end];
        if (previous->end != current->start ||
            current->start >= current->end)
            break;

        u32 width = current->end - current->start;
        if (width > stride)
            break;

        end++;
        if (width != stride)
            break;
    }

    return end;
}

static void emit_lookup_run(FILE* out, const FunctionList* funcs,
                            u32 first, u32 end) {
    const FunctionRange* first_range = &funcs->ranges[first];

    if (end == first + 1u || first_range->start >= first_range->end) {
        fprintf(out,
                "    if (address >= 0x%08Xu && address < 0x%08Xu && "
                "((address - 0x%08Xu) & 3u) == 0u) return func_%08X;\n",
                first_range->start, first_range->end,
                first_range->start, first_range->start);
        return;
    }

    const FunctionRange* last_range = &funcs->ranges[end - 1u];
    u32 stride = first_range->end - first_range->start;
    u32 span = last_range->end - first_range->start;

    fprintf(out, "    {\n");
    fprintf(out, "        u32 offset = address - 0x%08Xu;\n",
            first_range->start);
    fprintf(out,
            "        if (offset < 0x%08Xu && (offset & 3u) == 0u) {\n",
            span);
    fprintf(out,
            "            static const DolRecompFunction chunk_functions[] = {\n");
    for (u32 i = first; i < end; i++) {
        fprintf(out, "                func_%08X,\n", funcs->ranges[i].start);
    }
    fprintf(out, "            };\n");
    fprintf(out, "            return chunk_functions[offset / 0x%08Xu];\n",
            stride);
    fprintf(out, "        }\n");
    fprintf(out, "    }\n");
}

static int compare_range(const void* a, const void* b) {
    u32 x = ((const FunctionRange*)a)->start, y = ((const FunctionRange*)b)->start;
    return x < y ? -1 : x > y;
}

/* Function-mode table: converted functions take their whole address range
 * ahead of the chunk that also holds a copy of their code. Resuming anywhere
 * inside one lands in fn_X, whose entry switch handles the addresses it can
 * resume at and hands the rest to dolrecomp_find_chunk.
 *
 * The header only declares the lookup and the tables (emit_fn_lookup_decls),
 * so it does not change with the function list; emit_fn_dispatch_unit writes
 * the definitions to their own C file. The lookup runs only on a call-cache
 * miss, so it being out of line costs nothing measurable. */
static void emit_fn_lookup_decls(FILE* out) {
    fprintf(out, "\n#define DOLRECOMP_FN_MODE 1\n");
    fprintf(out, "extern const u32 dolrecomp_fn_count;\n");
    fprintf(out, "extern const u32 dolrecomp_fn_starts[];\n");
    fprintf(out, "extern const u32 dolrecomp_fn_ends[];\n");
    fprintf(out, "DolRecompFunction dolrecomp_find_original(u32 address);\n");
}

bool emit_fn_dispatch_unit(FILE* out, const FunctionList* fns, const char* include_name) {
    FunctionRange* sorted = (FunctionRange*)malloc(fns->count * sizeof(FunctionRange));
    if (!sorted)
        return false;
    memcpy(sorted, fns->ranges, fns->count * sizeof(FunctionRange));
    qsort(sorted, fns->count, sizeof(FunctionRange), compare_range);
    fprintf(out, "// DolRecomp function-mode dispatch table\n");
    fprintf(out, "#include \"../%s\"\n\n", include_name);
    for (u32 i = 0; i < fns->count; i++)
        fprintf(out, "void fn_%08X(CPUState* ctx);\n", sorted[i].start);
    fprintf(out, "\nconst u32 dolrecomp_fn_count = %uu;\n", fns->count);
    fprintf(out, "const u32 dolrecomp_fn_starts[%u] = {\n", fns->count);
    for (u32 i = 0; i < fns->count; i++)
        fprintf(out, "    0x%08Xu,\n", sorted[i].start);
    fprintf(out, "};\nconst u32 dolrecomp_fn_ends[%u] = {\n", fns->count);
    for (u32 i = 0; i < fns->count; i++)
        fprintf(out, "    0x%08Xu,\n", sorted[i].end);
    fprintf(out, "};\nstatic const DolRecompFunction dolrecomp_fn_entries[%u] = {\n",
            fns->count);
    for (u32 i = 0; i < fns->count; i++)
        fprintf(out, "    fn_%08X,\n", sorted[i].start);
    fprintf(out, "};\n");
    fprintf(out, "\nDolRecompFunction dolrecomp_find_original(u32 address) {\n");
    fprintf(out, "    u32 lo = 0, hi = %uu;\n", fns->count);
    fprintf(out, "    while (lo < hi) {\n");
    fprintf(out, "        u32 mid = (lo + hi) >> 1;\n");
    fprintf(out, "        if (dolrecomp_fn_starts[mid] <= address) lo = mid + 1u; else hi = mid;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    if (lo && address < dolrecomp_fn_ends[lo - 1u] && (address & 3u) == 0u)\n");
    fprintf(out, "        return dolrecomp_fn_entries[lo - 1u];\n");
    fprintf(out, "    return dolrecomp_find_chunk(address);\n");
    fprintf(out, "}\n");
    free(sorted);
    return true;
}

void emit_dispatch_helpers(FILE* out, const FunctionList* funcs, u32 entry_point) {
    emit_dispatch_helpers_fn(out, funcs, entry_point, NULL);
}

void emit_dispatch_helpers_fn(FILE* out, const FunctionList* funcs, u32 entry_point,
                              const FunctionList* fns) {
    const bool fn_mode = fns && fns->count;
    fprintf(out, "\n#define DOLRECOMP_ENTRY_POINT 0x%08Xu\n", entry_point);
    fprintf(out, "\ntypedef void (*DolRecompFunction)(CPUState* ctx);\n");
    fprintf(out, "\n#if defined(__GNUC__) || defined(__clang__)\n");
    fprintf(out, "#define DOLRECOMP_UNUSED __attribute__((unused))\n");
    fprintf(out, "#else\n");
    fprintf(out, "#define DOLRECOMP_UNUSED\n");
    fprintf(out, "#endif\n");
    fprintf(out, "\n#if defined(DOLRECOMP_ENABLE_REPLACEMENTS)\n");
    fprintf(out, "int dolrecomp_dispatch_replacement(CPUState* ctx, u32 address);\n");
    fprintf(out, "#else\n");
    fprintf(out, "static inline int dolrecomp_dispatch_replacement(CPUState* ctx, u32 address) {\n");
    fprintf(out, "    (void)ctx;\n");
    fprintf(out, "    (void)address;\n");
    fprintf(out, "    return 0;\n");
    fprintf(out, "}\n");
    fprintf(out, "#endif\n");
    fprintf(out, "\nstatic inline DolRecompFunction %s(u32 address) {\n",
            fn_mode ? "dolrecomp_find_chunk" : "dolrecomp_find_original");
    for (u32 first = 0; first < funcs->count;) {
        u32 end = uniform_run_end(funcs, first);
        emit_lookup_run(out, funcs, first, end);
        first = end;
    }
    fprintf(out, "    return NULL;\n");
    fprintf(out, "}\n");
    if (fn_mode)
        emit_fn_lookup_decls(out);
    fprintf(out, "\n#define DOLRECOMP_CALL_CACHE_SIZE 4096u\n");
    fprintf(out, "typedef struct { u32 addr; DolRecompFunction fn; } DolRecompCallCacheEntry;\n");
    fprintf(out, "static DolRecompCallCacheEntry g_dolrecomp_call_cache[DOLRECOMP_CALL_CACHE_SIZE];\n");
    fprintf(out, "\n/* Define DOLRECOMP_DISPATCH_STATS to count cache hits/misses. The counters\n");
    fprintf(out, " * are two global read-modify-writes on the hottest path in the runtime\n");
    fprintf(out, " * (one per dispatcher round trip), so they are compiled out by default and\n");
    fprintf(out, " * read as zero in the stats report. */\n");
    fprintf(out, "#ifdef DOLRECOMP_DISPATCH_STATS\n");
    fprintf(out, "#define DOLRECOMP_COUNT(c) ((c)++)\n");
    fprintf(out, "#else\n");
    fprintf(out, "#define DOLRECOMP_COUNT(c) ((void)0)\n");
    fprintf(out, "#endif\n");
    fprintf(out, "\nstatic inline DolRecompFunction dolrecomp_find_original_cached(u32 address) {\n");
    fprintf(out, "    /* Guest instructions are 4-byte aligned; drop the two zero bits before\n");
    fprintf(out, "     * masking so adjacent instructions land in adjacent slots. addr == 0 is\n");
    fprintf(out, "     * used as the empty sentinel, which is safe: address 0 is never a valid\n");
    fprintf(out, "     * call target (it is the null/invalid PC). */\n");
    fprintf(out, "    u32 slot = (address >> 2) & (DOLRECOMP_CALL_CACHE_SIZE - 1u);\n");
    fprintf(out, "    DolRecompCallCacheEntry* entry = &g_dolrecomp_call_cache[slot];\n");
    fprintf(out, "    if (entry->addr == address && entry->fn != NULL) {\n");
    fprintf(out, "        DOLRECOMP_COUNT(dolrecomp_call_hits);\n");
    fprintf(out, "        return entry->fn;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    DOLRECOMP_COUNT(dolrecomp_call_misses);\n");
    fprintf(out, "    DolRecompFunction fn = dolrecomp_find_original(address);\n");
    fprintf(out, "    if (fn != NULL) {\n");
    fprintf(out, "        entry->addr = address;\n");
    fprintf(out, "        entry->fn = fn;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    return fn;\n");
    fprintf(out, "}\n");
    fprintf(out, "\nstatic inline int dolrecomp_call_original(CPUState* ctx, u32 address) {\n");
    fprintf(out, "    DolRecompFunction fn = dolrecomp_find_original_cached(address);\n");
    fprintf(out, "    if (!fn) return 0;\n");
    fprintf(out, "    ctx->pc = address;\n");
    fprintf(out, "    fn(ctx);\n");
    fprintf(out, "    return 1;\n");
    fprintf(out, "}\n");
    fprintf(out, "\nstatic inline bool dolrecomp_physical_pc_alias(CPUState* ctx, u32 address, u32* alias_out) {\n");
    fprintf(out, "    if (address < ctx->ram_size) {\n");
    fprintf(out, "        *alias_out = address | GC_RAM_BASE;\n");
    fprintf(out, "        return *alias_out != address;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    return false;\n");
    fprintf(out, "}\n");
    fprintf(out, "\nstatic inline int dolrecomp_call(CPUState* ctx, u32 address) {\n");
    fprintf(out, "    u32 alias;\n");
    fprintf(out, "    ctx->pc = address;\n");
    fprintf(out, "    if (dolrecomp_dispatch_replacement(ctx, address)) return 1;\n");
    fprintf(out, "    if (ctx->host_call && ppc_host_call(ctx, address)) return 1;\n");
    fprintf(out, "    if (dolrecomp_call_original(ctx, address)) return 1;\n");
    fprintf(out, "    if (dolrecomp_physical_pc_alias(ctx, address, &alias)) {\n");
    fprintf(out, "        ctx->pc = alias;\n");
    fprintf(out, "        if (dolrecomp_dispatch_replacement(ctx, alias)) return 1;\n");
    fprintf(out, "        if (ctx->host_call && ppc_host_call(ctx, alias)) return 1;\n");
    fprintf(out, "        if (dolrecomp_call_original(ctx, alias)) return 1;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    return 0;\n");
    fprintf(out, "}\n");
    fprintf(out, "\n/* Cross-chunk `bl` calls its target here instead of handing the address\n");
    fprintf(out, " * back to dolrecomp_run_blocks. The work is exactly what the dispatcher\n");
    fprintf(out, " * would have done for that pc -- dolrecomp_call keeps the replacement,\n");
    fprintf(out, " * host-call (HLE) and chunk-lookup order -- so behaviour is unchanged;\n");
    fprintf(out, " * what is saved is the round trip out to the host loop and back in\n");
    fprintf(out, " * through the callee's and then the caller's entry switch. */\n");
    fprintf(out, "#ifndef DOLRECOMP_DIRECT_CALL_MAX_DEPTH\n");
    fprintf(out, "#define DOLRECOMP_DIRECT_CALL_MAX_DEPTH 64\n");
    fprintf(out, "#endif\n");
    fprintf(out, "static inline int dolrecomp_direct_call(CPUState* ctx, u32 address) {\n");
    fprintf(out, "    /* Two bail-outs hand the target back to the dispatcher instead, by\n");
    fprintf(out, "     * returning 0 with ctx->pc == address -- exactly the state the caller\n");
    fprintf(out, "     * returned in before this change, so the dispatcher then does what it\n");
    fprintf(out, "     * always did:\n");
    fprintf(out, "     *   - past the depth limit, so deep guest recursion cannot exhaust the\n");
    fprintf(out, "     *     host stack;\n");
    fprintf(out, "     *   - parked in the idle loop, because dolrecomp_run_blocks tests the\n");
    fprintf(out, "     *     park threshold *before* each dolrecomp_call. Checking it here\n");
    fprintf(out, "     *     keeps the direct call in step with that order, so a parked guest\n");
    fprintf(out, "     *     runs the callee in the same slice it always did. */\n");
    fprintf(out, "    if (ctx->direct_depth >= DOLRECOMP_DIRECT_CALL_MAX_DEPTH ||\n");
    fprintf(out, "        ctx->downcount <= DOLRECOMP_IDLE_PARK_THRESHOLD) {\n");
    fprintf(out, "        ctx->pc = address;\n");
    fprintf(out, "        return 0;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    ctx->direct_depth++;\n");
    fprintf(out, "    int ok = dolrecomp_call(ctx, address);\n");
    fprintf(out, "    ctx->direct_depth--;\n");
    fprintf(out, "    return ok;\n");
    fprintf(out, "}\n");
    fprintf(out, "\nstatic inline DOLRECOMP_UNUSED int dolrecomp_run_blocks(CPUState* ctx, u32 max_blocks) {\n");
    fprintf(out, "    u32 blocks = 0;\n");
    fprintf(out, "    while (max_blocks == 0u || blocks < max_blocks) {\n");
    fprintf(out, "        /* Parked in the recognised idle loop (see cpu.h): every further\n");
    fprintf(out, "         * block this call could run would be one no-op idle iteration plus\n");
    fprintf(out, "         * a dispatcher round trip. Hand control back to the host loop. */\n");
    fprintf(out, "        if (ctx->downcount <= DOLRECOMP_IDLE_PARK_THRESHOLD) return 1;\n");
    fprintf(out, "        if (!dolrecomp_call(ctx, ctx->pc)) return 0;\n");
    fprintf(out, "        if (ctx->exception) return 0;\n");
    fprintf(out, "        blocks++;\n");
    fprintf(out, "    }\n");
    fprintf(out, "    return 1;\n");
    fprintf(out, "}\n");
    fprintf(out, "\n#undef DOLRECOMP_UNUSED\n");
}
