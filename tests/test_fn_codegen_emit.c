/* Generates the differential fn-mode test program: every test function is
 * emitted twice, as a chunk (func_<addr>, today's emitter) and as a converted
 * function (fn_<addr>), so test_fn_execute can run both from identical state
 * and demand identical results, including dispatcher round trips. */
#include <stdio.h>
#include <stdlib.h>

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

    emit_header(out);
    for (u32 i = 0; i < funcs.count; i++)
        emit_chunk_prototype(out, funcs.ranges[i].start);
    emit_dispatch_helpers(out, &funcs, fn_programs[0].addr);
    function_list_free(&funcs);
    fprintf(out, "\nstatic inline DolRecompFunction dolrecomp_find_chunk(u32 address) {\n"
                 "    return dolrecomp_find_original(address);\n}\n\n");
    for (u32 p = 0; p < FN_PROGRAM_COUNT; p++)
        emit_fn_prototype(out, fn_programs[p].addr);

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
    emit_footer(out);
    fclose(out);
    return 0;
}
