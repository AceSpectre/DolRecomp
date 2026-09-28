#include <stdio.h>
#include <string.h>

#include "../src/backend/c_cfg.h"
#include "../src/backend/fn_select.h"
#include "../src/frontend/decoder.h"

#define BASE 0x80001000u

static bool none(u32 a) { (void)a; return false; }
static bool hook_at_1008(u32 a) { return a == 0x80001008u; }

static int fails;

static void check(const char* what, const u32* words, u32 n, const char* name,
                  bool (*ex)(u32), FnVerdict want) {
    PPCInst insts[32];
    for (u32 i = 0; i < n; i++)
        insts[i] = ppc_decode(words[i], BASE + 4u * i);
    FnVerdict got = fn_select_leaf(insts, n, BASE, name, ex);
    if (got != want) {
        fprintf(stderr, "%s: got %s want %s\n", what, fn_verdict_name(got),
                fn_verdict_name(want));
        fails++;
    }
}

int main(void) {
    c_global_targets_reset();
    c_global_targets_finalize();

    const u32 leaf[] = {0x38630001u /* addi r3,r3,1 */, 0x4E800020u /* blr */};
    check("leaf", leaf, 2, "f", none, FN_OK);
    check("empty", leaf, 0, "f", none, FN_EMPTY);
    const u32 call[] = {0x48000011u /* bl +0x10 */, 0x4E800020u};
    check("call", call, 2, "f", none, FN_NOT_LEAF);
    const u32 bctrl[] = {0x4E800421u /* bctrl */, 0x4E800020u};
    check("bctrl", bctrl, 2, "f", none, FN_NOT_LEAF);
    const u32 rfi[] = {0x4C000064u /* rfi */};
    check("rfi", rfi, 1, "f", none, FN_SYSTEM_OP);
    const u32 sc[] = {0x44000002u /* sc */};
    check("sc", sc, 1, "f", none, FN_SYSTEM_OP);
    const u32 mfmsr[] = {0x7C6000A6u /* mfmsr r3 */, 0x4E800020u};
    check("mfmsr", mfmsr, 2, "f", none, FN_SYSTEM_OP);
    const u32 bctr[] = {0x4E800420u /* bctr */};
    check("bctr", bctr, 1, "f", none, FN_BCTR);
    const u32 loop[] = {0x3863FFFFu /* addi r3,r3,-1 */, 0x2C030000u /* cmpwi r3,0 */,
                        0x4082FFF8u /* bne -8 */, 0x4E800020u};
    check("loop", loop, 4, "f", none, FN_OK);
    const u32 out[] = {0x48001000u /* b +0x1000 */};
    check("outside", out, 1, "f", none, FN_OUTSIDE_BRANCH);
    const u32 four[] = {0x60000000u, 0x60000000u, 0x60000000u, 0x4E800020u};
    check("hook", four, 4, "f", hook_at_1008, FN_EXCLUDED);
    check("save", leaf, 2, "__save_gpr", none, FN_SAVE_RESTORE);
    check("restore", leaf, 2, "__restore_fpr", none, FN_SAVE_RESTORE);

    /* Another function branches into this one's middle. */
    c_global_targets_reset();
    PPCInst outside = ppc_decode(0x48001004u /* b +0x1004 */, BASE - 0x1000u + 4u);
    c_global_targets_add(&outside, 1);
    c_global_targets_finalize();
    check("mid_entry", four, 4, "f", none, FN_MID_ENTRY);
    /* A global target that this function's own loop explains is fine. */
    c_global_targets_reset();
    PPCInst own[4];
    for (u32 i = 0; i < 4; i++)
        own[i] = ppc_decode(loop[i], BASE + 4u * i);
    c_global_targets_add(own, 4);
    c_global_targets_finalize();
    check("own_target", loop, 4, "f", none, FN_OK);

    if (fails)
        fprintf(stderr, "%d failures\n", fails);
    return fails != 0;
}
