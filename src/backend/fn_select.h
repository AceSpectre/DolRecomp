#ifndef DOLRECOMP_FN_SELECT_H
#define DOLRECOMP_FN_SELECT_H

#include "../common/types.h"
#include "../frontend/decoder.h"

/* Eligibility of one guest function for function-mode codegen. Rejected
 * functions stay in the chunk code, which handles everything. */
typedef enum {
    FN_OK = 0,
    FN_NOT_LEAF,       /* M1: contains a linking branch (bl/bcl/bclrl/bcctrl) */
    FN_SYSTEM_OP,      /* sc, rfi, mtmsr, mfmsr */
    FN_BCTR,           /* bcctr without link: switch table or ctr tail call */
    FN_MID_ENTRY,      /* another function branches into its middle */
    FN_SAVE_RESTORE,   /* __save_* / __restore_* register glue */
    FN_EXCLUDED,       /* holds a hooked or self-modified address */
    FN_OUTSIDE_BRANCH, /* direct branch leaving the function (tail call) */
    FN_EMPTY,
} FnVerdict;

const char* fn_verdict_name(FnVerdict verdict);

/* insts/count cover exactly [start, start + 4 * count). excluded(addr) is
 * true for hooked and SMC addresses. name may be NULL. Uses the finalized
 * c_global_targets set for the mid-entry rule. */
FnVerdict fn_select_leaf(const PPCInst* insts, u32 count, u32 start,
                         const char* name, bool (*excluded)(u32 addr));

#endif
