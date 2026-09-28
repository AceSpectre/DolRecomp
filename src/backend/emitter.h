#ifndef DOLRECOMP_EMITTER_H
#define DOLRECOMP_EMITTER_H

#include "../common/types.h"
#include "../frontend/decoder.h"
#include <stdio.h>

typedef enum {
    DOLRECOMP_CPU_GEKKO,
    DOLRECOMP_CPU_BROADWAY,
    DOLRECOMP_CPU_ESPRESSO,
} DolRecompCPU;

// Split C emitter used by the command-line recompiler.

// emit the boilerplate header (includes, typedefs, etc)
void emit_header(FILE* out);
void emit_header_for_cpu(FILE* out, DolRecompCPU cpu);

// emit a single recompiled function as C code
bool emit_function(FILE* out, const PPCInst* insts, u32 count, u32 func_addr);

// emit a single instruction as C code
void emit_instruction(FILE* out, const PPCInst* inst);

// emit one instruction with explicit block context (function-mode codegen):
// branches to [func_start, func_end) are local; bclr routes through
// return_dispatch_<func_start> when route_local_returns is set
void emit_instruction_ex(FILE* out, const PPCInst* inst, u32 func_start,
                         u32 func_end, bool direct_backedge,
                         bool route_local_returns, bool emit_fp_guard);

// function-mode codegen: start addresses of converted functions. A local
// bl to one of them calls fn_<target>_direct instead of jumping into the
// chunk's copy. Pass (NULL, 0) to clear.
void emitter_set_fn_set(const u32* starts, u32 count);
bool emitter_fn_contains_start(u32 address);

// emit the boilerplate footer
void emit_footer(FILE* out);

#endif /* DOLRECOMP_EMITTER_H */
