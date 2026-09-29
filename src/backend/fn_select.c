#include "backend/fn_select.h"

#include "backend/c_cfg.h"

#include <string.h>

const char* fn_verdict_name(FnVerdict verdict) {
    switch (verdict) {
    case FN_OK: return "ok";
    case FN_NOT_LEAF: return "not-leaf";
    case FN_SYSTEM_OP: return "system-op";
    case FN_BCTR: return "bctr";
    case FN_MID_ENTRY: return "mid-entry";
    case FN_SAVE_RESTORE: return "save-restore";
    case FN_EXCLUDED: return "excluded";
    case FN_OUTSIDE_BRANCH: return "outside-branch";
    case FN_EMPTY: return "empty";
    case FN_RECURSIVE: return "recursive";
    case FN_COND_CALL: return "cond-call";
    case FN_TOO_MANY_CALLS: return "too-many-calls";
    case FN_CALLEE_REJECTED: return "callee-rejected";
    case FN_DEEP_CHAIN: return "deep-chain";
    case FN_EMIT_FAILED: return "emit";
    case FN_SPANS_CHUNK: return "spans-chunk";
    case FN_NO_SYMBOL: return "no-symbol";
    case FN_VERDICT_COUNT: break;
    }
    return "?";
}

static bool in_range(u32 addr, u32 start, u32 end) {
    return addr >= start && addr < end;
}

static bool add_need(FnNeeds* needs, u32 target) {
    for (u32 i = 0; i < needs->count; i++)
        if (needs->targets[i] == target)
            return true;
    if (needs->count == FN_MAX_NEEDS)
        return false;
    u32 i = needs->count++;
    while (i > 0 && needs->targets[i - 1] > target) {
        needs->targets[i] = needs->targets[i - 1];
        i--;
    }
    needs->targets[i] = target;
    return true;
}

FnVerdict fn_select_function(const PPCInst* insts, u32 count, u32 start,
                             u32 chunk_start, u32 chunk_end, const char* name,
                             bool (*excluded)(u32 addr), FnNeeds* needs) {
    needs->count = 0;
    if (count == 0)
        return FN_EMPTY;
    if (name && (strncmp(name, "__save", 6) == 0 || strncmp(name, "__restore", 9) == 0))
        return FN_SAVE_RESTORE;
    const u32 end = start + count * 4u;
    for (u32 i = 0; i < count; i++)
        if (excluded && excluded(start + 4u * i))
            return FN_EXCLUDED;

    for (u32 i = 0; i < count; i++) {
        const PPCInst* in = &insts[i];
        if (in->embedded_data)
            continue;
        switch (in->op) {
        case PPC_OP_SC:
        case PPC_OP_RFI:
        case PPC_OP_MTMSR:
        case PPC_OP_MFMSR:
            return FN_SYSTEM_OP;
        default:
            break;
        }
    }
    for (u32 i = 0; i < count; i++) {
        const PPCInst* in = &insts[i];
        if (!in->embedded_data && in->op == PPC_OP_BCCTR && !in->lk)
            return FN_BCTR;
    }
    for (u32 i = 0; i < count; i++) {
        const PPCInst* in = &insts[i];
        if (in->embedded_data || (in->op != PPC_OP_B && in->op != PPC_OP_BC))
            continue;
        const u32 t = in->branch_target;
        if (in_range(t, start, end)) {
            if (in->op == PPC_OP_B && in->lk && t == start)
                return FN_RECURSIVE;
            continue;
        }
        const bool same_chunk = in_range(t, chunk_start, chunk_end);
        if (in->op == PPC_OP_BC) {
            if (in->lk || same_chunk)
                return FN_COND_CALL;
            continue;
        }
        if (same_chunk && !add_need(needs, t))
            return FN_TOO_MANY_CALLS;
    }
    /* Mid-entry: a global branch target inside the body that no branch of
     * this function explains must come from somewhere else. */
    for (u32 addr = start + 4u; addr < end; addr += 4u) {
        if (!c_global_target_contains(addr))
            continue;
        bool own = false;
        for (u32 i = 0; i < count && !own; i++) {
            const PPCInst* in = &insts[i];
            own = !in->embedded_data && (in->op == PPC_OP_B || in->op == PPC_OP_BC) &&
                  in->branch_target == addr;
        }
        if (!own)
            return FN_MID_ENTRY;
    }
    return FN_OK;
}
