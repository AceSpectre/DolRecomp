#include "backend/fn_closure.h"

#include <stdlib.h>

static int find(const FnNode* nodes, u32 count, u32 start) {
    u32 lo = 0, hi = count;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2u;
        if (nodes[mid].start < start)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo < count && nodes[lo].start == start ? (int)lo : -1;
}

typedef struct {
    FnNode* nodes;
    u32 count;
    u8* state;   /* 0 unvisited, 1 on the DFS stack, 2 done */
    u32* depth;  /* longest need chain over FN_OK nodes, 1 = no needs */
    u32* stack;
    u32 top;
} Walk;

/* Depth-first over FN_OK needs. Reaching a node still on the stack marks the
 * stack from that node up as FN_RECURSIVE: exactly the cycle, not the path
 * that led into it (callers outside the cycle are rejected on the next
 * fixpoint round because their callee is no longer FN_OK). */
static u32 depth_of(Walk* w, u32 i) {
    if (w->state[i] == 2)
        return w->depth[i];
    w->state[i] = 1;
    w->stack[w->top++] = i;
    u32 best = 1;
    const FnNeeds* needs = w->nodes[i].needs;
    for (u32 k = 0; needs && k < needs->count; k++) {
        int j = find(w->nodes, w->count, needs->targets[k]);
        if (j < 0 || w->nodes[j].verdict != FN_OK)
            continue;
        if (w->state[j] == 1) {
            for (u32 s = w->top; s-- > 0;) {
                w->nodes[w->stack[s]].verdict = FN_RECURSIVE;
                if (w->stack[s] == (u32)j)
                    break;
            }
            continue;
        }
        u32 d = depth_of(w, (u32)j);
        if (w->nodes[j].verdict == FN_OK && d + 1u > best)
            best = d + 1u;
    }
    w->top--;
    w->state[i] = 2;
    w->depth[i] = best;
    return best;
}

void fn_closure_resolve(FnNode* nodes, u32 count, u32 max_depth) {
    Walk w = {nodes, count, NULL, NULL, NULL, 0};
    u32 n = count ? count : 1u;
    w.state = (u8*)malloc(n);
    w.depth = (u32*)malloc(n * sizeof(u32));
    w.stack = (u32*)malloc(n * sizeof(u32));
    if (!w.state || !w.depth || !w.stack) {
        for (u32 i = 0; i < count; i++)
            if (nodes[i].verdict == FN_OK)
                nodes[i].verdict = FN_CALLEE_REJECTED;
        free(w.state);
        free(w.depth);
        free(w.stack);
        return;
    }
    for (bool changed = true; changed;) {
        changed = false;
        for (u32 i = 0; i < count; i++) {
            if (nodes[i].verdict != FN_OK || !nodes[i].needs)
                continue;
            for (u32 k = 0; k < nodes[i].needs->count; k++) {
                int j = find(nodes, count, nodes[i].needs->targets[k]);
                if (j < 0 || nodes[j].verdict != FN_OK) {
                    nodes[i].verdict = FN_CALLEE_REJECTED;
                    changed = true;
                    break;
                }
            }
        }
        if (changed)
            continue;
        for (u32 i = 0; i < count; i++)
            w.state[i] = 0;
        w.top = 0;
        u32 ok_before = 0, ok_after = 0;
        for (u32 i = 0; i < count; i++)
            ok_before += nodes[i].verdict == FN_OK;
        for (u32 i = 0; i < count; i++)
            if (nodes[i].verdict == FN_OK)
                depth_of(&w, i);
        for (u32 i = 0; i < count; i++)
            ok_after += nodes[i].verdict == FN_OK;
        if (ok_after != ok_before) {
            changed = true; /* cycles removed: recompute depths without them */
            continue;
        }
        for (u32 i = 0; i < count; i++) {
            if (nodes[i].verdict == FN_OK && w.depth[i] > max_depth) {
                nodes[i].verdict = FN_DEEP_CHAIN;
                changed = true;
            }
        }
    }
    free(w.state);
    free(w.depth);
    free(w.stack);
}
