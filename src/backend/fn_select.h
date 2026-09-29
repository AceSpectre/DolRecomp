#ifndef DOLRECOMP_FN_SELECT_H
#define DOLRECOMP_FN_SELECT_H

#include "../common/types.h"
#include "../frontend/decoder.h"

/* Eligibility of one guest function for function-mode codegen. Rejected
 * functions stay in the chunk code, which handles everything. */
typedef enum {
    FN_OK = 0,
    FN_NOT_LEAF,       /* linking branch the emitter cannot express yet */
    FN_SYSTEM_OP,      /* sc, rfi, mtmsr, mfmsr */
    FN_BCTR,           /* bcctr without link: switch table or ctr tail call */
    FN_MID_ENTRY,      /* another function branches into its middle */
    FN_SAVE_RESTORE,   /* __save_* / __restore_* register glue */
    FN_EXCLUDED,       /* holds a hooked or self-modified address */
    FN_OUTSIDE_BRANCH, /* direct branch leaving the function it cannot express */
    FN_EMPTY,
    FN_RECURSIVE,       /* bl to its own start, or on a same-chunk call cycle */
    FN_COND_CALL,       /* conditional linking branch, or a conditional branch
                         * to a same-chunk address outside the function */
    FN_TOO_MANY_CALLS,  /* more than FN_MAX_NEEDS distinct same-chunk targets */
    FN_CALLEE_REJECTED, /* a needed same-chunk callee is not converted */
    FN_DEEP_CHAIN,      /* same-chunk call chain deeper than FN_MAX_CHAIN_DEPTH */
    FN_EMIT_FAILED,     /* the emitter could not express it */
    FN_SPANS_CHUNK,     /* crosses a chunk boundary */
    FN_NO_SYMBOL,       /* no map symbol at the address */
    FN_VERDICT_COUNT
} FnVerdict;

/* Same-chunk addresses outside the function that it calls or tail-calls.
 * The chunk code reaches them with a goto (the callee is inlined into the
 * chunk), which a separate C function can only reproduce by calling the
 * converted callee, so each must be converted too. */
#define FN_MAX_NEEDS 64u
typedef struct {
    u32 targets[FN_MAX_NEEDS]; /* sorted, unique */
    u32 count;
} FnNeeds;

const char* fn_verdict_name(FnVerdict verdict);

/* insts/count cover exactly [start, start + 4 * count), inside the chunk
 * [chunk_start, chunk_end). excluded(addr) is true for hooked and SMC
 * addresses; it and name may be NULL. Calls (bl, bctrl, bclrl) and tail calls
 * are allowed; same-chunk targets outside the function are reported in
 * needs. Uses the finalized c_global_targets set for the mid-entry rule. */
FnVerdict fn_select_function(const PPCInst* insts, u32 count, u32 start,
                             u32 chunk_start, u32 chunk_end, const char* name,
                             bool (*excluded)(u32 addr), FnNeeds* needs);

#endif
