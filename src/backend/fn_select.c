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
    }
    return "?";
}

static bool in_range(u32 addr, u32 start, u32 end) {
    return addr >= start && addr < end;
}

FnVerdict fn_select_leaf(const PPCInst* insts, u32 count, u32 start,
                         const char* name, bool (*excluded)(u32 addr)) {
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
        if (in->embedded_data)
            continue;
        bool branch = in->op == PPC_OP_B || in->op == PPC_OP_BC ||
                      in->op == PPC_OP_BCLR || in->op == PPC_OP_BCCTR;
        if (branch && in->lk)
            return FN_NOT_LEAF;
    }
    for (u32 i = 0; i < count; i++) {
        const PPCInst* in = &insts[i];
        if (in->embedded_data)
            continue;
        if ((in->op == PPC_OP_B || in->op == PPC_OP_BC) &&
            !in_range(in->branch_target, start, end))
            return FN_OUTSIDE_BRANCH;
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
