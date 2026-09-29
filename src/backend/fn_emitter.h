#ifndef DOLRECOMP_FN_EMITTER_H
#define DOLRECOMP_FN_EMITTER_H

#include "../common/types.h"
#include "../frontend/decoder.h"
#include <stdio.h>

/* Function-mode (N64Recomp-style) emitter: one C function per guest function,
 * guest registers held in C locals.
 *
 * Exact mode keeps every guest-visible behaviour of the chunk code, including
 * the number of dispatcher round trips (the host pumps IOS and ends slices on
 * block counts). Each converted function therefore has two entries:
 *   fn_XXXXXXXX(ctx)        -- from the dispatcher; resumes at ctx->pc, and a
 *                              bclr continues into the containing chunk when
 *                              that chunk's return_dispatch would have;
 *   fn_XXXXXXXX_direct(ctx) -- from a chunk call site; starts at the entry
 *                              and returns to the caller on bclr. */

typedef struct {
    u32 chunk_start;            /* containing chunk: func_<chunk_start> */
    const u32* return_targets;  /* that chunk's local return targets */
    u32 return_target_count;
    /* The whole containing chunk. Leaders, block costs, entry points and
     * loops come from the chunk's CFG, restricted to the function, so the
     * converted code charges and resumes exactly where the chunk would.
     * NULL: the function is its own chunk (tests). */
    const PPCInst* chunk_insts;
    u32 chunk_count;
} FnChunkContext;

/* Emits fn_<start> and fn_<start>_direct for [start, start + 4 * count).
 * Returns false (nothing usable written) when the function cannot be
 * expressed: it does not end in an unconditional branch, or an instruction
 * that must run on ctx contains a goto. Needs dolrecomp_find_chunk() and
 * func_<chunk_start> declared by the including header. */
bool emit_fn_function(FILE* out, const PPCInst* insts, u32 count, u32 start,
                      const FnChunkContext* chunk);

/* Prototypes for both entries. */
void emit_fn_prototype(FILE* out, u32 start);

#endif
