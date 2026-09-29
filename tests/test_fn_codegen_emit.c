/* Generates the differential fn-mode test program: every test function is
 * emitted twice, as a chunk (func_<addr>, today's emitter) and as a converted
 * function (fn_<addr>), so test_fn_execute can run both from identical state
 * and demand identical results, including dispatcher round trips. */
#include <stdio.h>
#include <stdlib.h>

#include "../src/backend/c_cfg.h"
#include "../src/backend/dispatch.h"
#include "../src/backend/emitter.h"
#include "../src/backend/fn_emitter.h"
#include "../src/frontend/decoder.h"
#include "fn_programs.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s out.c\n", argv[0]);
        return 1;
    }
    FILE* out = fopen(argv[1], "w");
    if (!out) {
        perror(argv[1]);
        return 1;
    }

    FunctionList funcs = {0};
    for (u32 p = 0; p < FN_PROGRAM_COUNT; p++)
        if (!function_list_add(&funcs, fn_programs[p].addr,
                               fn_programs[p].addr + fn_programs[p].count * 4u))
            return 1;
    if (!function_list_add(&funcs, FN_PAD_CHUNK, FN_PAD_CHUNK + FN_PAD_COUNT * 4u) ||
        !function_list_add(&funcs, FN_PAIR_PLAIN, FN_PAIR_PLAIN + FN_PAIR_COUNT * 4u) ||
        !function_list_add(&funcs, FN_PAIR_FN, FN_PAIR_FN + FN_PAIR_COUNT * 4u))
        return 1;

    emit_header(out);
    for (u32 i = 0; i < funcs.count; i++)
        emit_chunk_prototype(out, funcs.ranges[i].start);
    emit_dispatch_helpers(out, &funcs, fn_programs[0].addr);
    function_list_free(&funcs);
    fprintf(out, "\nstatic inline DolRecompFunction dolrecomp_find_chunk(u32 address) {\n"
                 "    return dolrecomp_find_original(address);\n}\n\n");
    for (u32 p = 0; p < FN_PROGRAM_COUNT; p++)
        emit_fn_prototype(out, fn_programs[p].addr);
    emit_fn_prototype(out, FN_PAIR_FN + FN_PAIR_LEAF_OFFSET);
    emit_fn_prototype(out, FN_PAD_CHUNK + FN_PAD_LEAF_OFFSET);

    for (u32 p = 0; p < FN_PROGRAM_COUNT; p++) {
        const FnProgram* prog = &fn_programs[p];
        PPCInst insts[64];
        for (u32 i = 0; i < prog->count; i++)
            insts[i] = ppc_decode(prog->words[i], prog->addr + 4u * i);
        if (!emit_function(out, insts, prog->count, prog->addr)) {
            fprintf(stderr, "chunk emit failed for %s\n", prog->name);
            return 1;
        }
        FnChunkContext chunk = {prog->addr, NULL, 0};
        if (!emit_fn_function(out, insts, prog->count, prog->addr, &chunk)) {
            fprintf(stderr, "fn emit failed for %s\n", prog->name);
            return 1;
        }
    }
    /* Same-chunk call: caller and leaf share one chunk. The plain copy at
     * FN_PAIR_PLAIN is today's code; the copy at FN_PAIR_FN is emitted with
     * the leaf converted, so its bl calls fn_<leaf>_direct. */
    for (u32 copy = 0; copy < 2; copy++) {
        u32 base = copy ? FN_PAIR_FN : FN_PAIR_PLAIN;
        PPCInst pair[FN_PAIR_COUNT];
        for (u32 i = 0; i < FN_PAIR_COUNT; i++)
            pair[i] = ppc_decode(fn_pair_words[i], base + 4u * i);
        u32 leaf = base + FN_PAIR_LEAF_OFFSET;
        if (copy)
            emitter_set_fn_set(&leaf, 1);
        bool emitted = emit_function(out, pair, FN_PAIR_COUNT, base);
        emitter_set_fn_set(NULL, 0);
        if (!emitted)
            return 1;
        if (!copy)
            continue;
        CFunctionCFG cfg;
        if (!c_function_cfg_build(&cfg, pair, FN_PAIR_COUNT, base))
            return 1;
        u32 targets[FN_PAIR_COUNT];
        u32 target_count = 0;
        for (u32 i = 0; i < FN_PAIR_COUNT; i++)
            if (cfg.return_targets[i])
                targets[target_count++] = pair[i].address;
        c_function_cfg_destroy(&cfg);
        FnChunkContext chunk = {base, targets, target_count, pair, FN_PAIR_COUNT};
        u32 leaf_index = FN_PAIR_LEAF_OFFSET / 4u;
        if (!emit_fn_function(out, pair + leaf_index, FN_PAIR_COUNT - leaf_index,
                              leaf, &chunk))
            return 1;
    }

    {
        PPCInst pad[FN_PAD_COUNT];
        for (u32 i = 0; i < FN_PAD_COUNT; i++) {
            pad[i] = ppc_decode(fn_pad_words[i], FN_PAD_CHUNK + 4u * i);
            pad[i].embedded_data = fn_pad_words[i] == 0u;
        }
        if (!emit_function(out, pad, FN_PAD_COUNT, FN_PAD_CHUNK))
            return 1;
        u32 leaf_index = FN_PAD_LEAF_OFFSET / 4u;
        FnChunkContext chunk = {FN_PAD_CHUNK, NULL, 0, pad, FN_PAD_COUNT};
        if (!emit_fn_function(out, pad + leaf_index, FN_PAD_COUNT - leaf_index,
                              FN_PAD_CHUNK + FN_PAD_LEAF_OFFSET, &chunk))
            return 1;
    }

    emit_footer(out);
    fclose(out);
    return 0;
}
