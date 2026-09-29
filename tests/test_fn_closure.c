/* fn_closure_resolve: a caller converts only with all its same-chunk
 * callees; cycles and over-deep chains are rejected. */
#include <stdio.h>

#include "../src/backend/fn_closure.h"

static FnNeeds needs_of(u32 n, const u32* t) {
    FnNeeds x;
    x.count = n;
    for (u32 i = 0; i < n; i++)
        x.targets[i] = t[i];
    return x;
}

static int expect(const char* what, const FnNode* nodes, u32 count, const FnVerdict* want) {
    int ok = 1;
    for (u32 i = 0; i < count; i++)
        if (nodes[i].verdict != want[i]) {
            fprintf(stderr, "%s: node %08X is %s, want %s\n", what, nodes[i].start,
                    fn_verdict_name(nodes[i].verdict), fn_verdict_name(want[i]));
            ok = 0;
        }
    return ok;
}

int main(void) {
    int ok = 1;
    {   /* A -> B -> C, all OK: all accepted */
        u32 a[] = {0x200}, b[] = {0x300};
        FnNeeds na = needs_of(1, a), nb = needs_of(1, b), nc = needs_of(0, NULL);
        FnNode n[] = {{0x100, FN_OK, &na}, {0x200, FN_OK, &nb}, {0x300, FN_OK, &nc}};
        FnVerdict w[] = {FN_OK, FN_OK, FN_OK};
        fn_closure_resolve(n, 3, FN_MAX_CHAIN_DEPTH);
        ok &= expect("chain", n, 3, w);
    }
    {   /* A -> B -> C, C rejected: the rejection propagates to A */
        u32 a[] = {0x200}, b[] = {0x300};
        FnNeeds na = needs_of(1, a), nb = needs_of(1, b), nc = needs_of(0, NULL);
        FnNode n[] = {{0x100, FN_OK, &na}, {0x200, FN_OK, &nb}, {0x300, FN_BCTR, &nc}};
        FnVerdict w[] = {FN_CALLEE_REJECTED, FN_CALLEE_REJECTED, FN_BCTR};
        fn_closure_resolve(n, 3, FN_MAX_CHAIN_DEPTH);
        ok &= expect("propagate", n, 3, w);
    }
    {   /* a need with no node at all */
        u32 a[] = {0x999};
        FnNeeds na = needs_of(1, a);
        FnNode n[] = {{0x100, FN_OK, &na}};
        FnVerdict w[] = {FN_CALLEE_REJECTED};
        fn_closure_resolve(n, 1, FN_MAX_CHAIN_DEPTH);
        ok &= expect("missing", n, 1, w);
    }
    {   /* A <-> B cycle, C -> A: the cycle is recursive, C callee-rejected; D alone OK */
        u32 a[] = {0x200}, b[] = {0x100}, c[] = {0x100};
        FnNeeds na = needs_of(1, a), nb = needs_of(1, b), nc = needs_of(1, c),
                nd = needs_of(0, NULL);
        FnNode n[] = {{0x100, FN_OK, &na}, {0x200, FN_OK, &nb}, {0x300, FN_OK, &nc},
                      {0x400, FN_OK, &nd}};
        FnVerdict w[] = {FN_RECURSIVE, FN_RECURSIVE, FN_CALLEE_REJECTED, FN_OK};
        fn_closure_resolve(n, 4, FN_MAX_CHAIN_DEPTH);
        ok &= expect("cycle", n, 4, w);
    }
    {   /* X -> A <-> B: entering the cycle from outside still rejects only
         * the cycle as recursive; X is callee-rejected */
        u32 x[] = {0x200}, a[] = {0x300}, b[] = {0x200};
        FnNeeds nx = needs_of(1, x), na = needs_of(1, a), nb = needs_of(1, b);
        FnNode n[] = {{0x100, FN_OK, &nx}, {0x200, FN_OK, &na}, {0x300, FN_OK, &nb}};
        FnVerdict w[] = {FN_CALLEE_REJECTED, FN_RECURSIVE, FN_RECURSIVE};
        fn_closure_resolve(n, 3, FN_MAX_CHAIN_DEPTH);
        ok &= expect("cycle_entered", n, 3, w);
    }
    {   /* chain of 4 with max depth 3: the head is too deep, the rest fit */
        u32 a[] = {0x200}, b[] = {0x300}, c[] = {0x400};
        FnNeeds na = needs_of(1, a), nb = needs_of(1, b), nc = needs_of(1, c),
                nd = needs_of(0, NULL);
        FnNode n[] = {{0x100, FN_OK, &na}, {0x200, FN_OK, &nb}, {0x300, FN_OK, &nc},
                      {0x400, FN_OK, &nd}};
        FnVerdict w[] = {FN_DEEP_CHAIN, FN_OK, FN_OK, FN_OK};
        fn_closure_resolve(n, 4, 3);
        ok &= expect("deep_chain", n, 4, w);
    }
    if (!ok)
        fprintf(stderr, "fn closure FAILED\n");
    return ok ? 0 : 1;
}
