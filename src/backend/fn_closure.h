#ifndef DOLRECOMP_FN_CLOSURE_H
#define DOLRECOMP_FN_CLOSURE_H

#include "fn_select.h"

/* Converted same-chunk callees are called on the host stack (the chunk code
 * they replace used a goto), so chains are bounded to keep that stack small
 * on the Switch main thread. */
#define FN_MAX_CHAIN_DEPTH 8u

typedef struct {
    u32 start;
    FnVerdict verdict;  /* in: selection verdict; out: final verdict */
    const FnNeeds* needs;
} FnNode;

/* Iterates to a fixpoint over nodes sorted by start: an FN_OK node whose need
 * is not an FN_OK node becomes FN_CALLEE_REJECTED; FN_OK nodes on a cycle of
 * needs become FN_RECURSIVE; an FN_OK node whose longest chain of needs
 * (itself counted as 1) exceeds max_depth becomes FN_DEEP_CHAIN. */
void fn_closure_resolve(FnNode* nodes, u32 count, u32 max_depth);

#endif
