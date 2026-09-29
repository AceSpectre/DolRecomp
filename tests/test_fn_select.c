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
    FnNeeds needs;
    FnVerdict got = fn_select_function(insts, n, BASE, BASE - 0x1000u, BASE + 0x3000u, name,
                                       ex, &needs);
    if (got != want) {
        fprintf(stderr, "%s: got %s want %s\n", what, fn_verdict_name(got),
                fn_verdict_name(want));
        fails++;
    }
}

/* Call shapes, with the chunk [0x80004000, 0x80008000) and the function at
 * 0x80004100: which are allowed, and which same-chunk targets they need. */
typedef struct {
    const char* name;
    u32 words[8];
    u32 count;
    FnVerdict want;
    u32 want_needs;      /* expected needs.count */
    u32 want_first_need; /* expected needs.targets[0] when want_needs > 0 */
} SelectCase;

static const SelectCase cases[] = {
    {"leaf", {0x38630001u, 0x4E800020u}, 2, FN_OK, 0, 0},
    /* bl -0x100 -> 0x80004004 (same chunk, outside) */
    {"bl_same_chunk", {0x7C0802A6u, 0x4BFFFF01u, 0x7C0803A6u, 0x4E800020u}, 4, FN_OK, 1,
     0x80004004u},
    /* bl +0x10000 -> 0x80014104 (other chunk) */
    {"bl_cross_chunk", {0x7C0802A6u, 0x48010001u, 0x7C0803A6u, 0x4E800020u}, 4, FN_OK, 0, 0},
    /* bl 0 -> own start */
    {"self_call", {0x48000001u, 0x4E800020u}, 2, FN_RECURSIVE, 0, 0},
    /* bl +4: local, not a need */
    {"bl_next", {0x48000005u, 0x7D8802A6u, 0x4E800020u}, 3, FN_OK, 0, 0},
    /* b -0x100 tail call, same chunk */
    {"tail_same_chunk", {0x38630001u, 0x4BFFFF00u}, 2, FN_OK, 1, 0x80004004u},
    /* b +0x10000 tail call, other chunk */
    {"tail_cross_chunk", {0x38630001u, 0x48010000u}, 2, FN_OK, 0, 0},
    /* mtctr r12; bctrl; blr */
    {"bctrl", {0x7D8903A6u, 0x4E800421u, 0x4E800020u}, 3, FN_OK, 0, 0},
    /* mtctr r12; bctr */
    {"bctr", {0x7D8903A6u, 0x4E800420u}, 2, FN_BCTR, 0, 0},
    /* beql cr0,-0x100 (conditional link) */
    {"cond_call", {0x4182FF01u, 0x4E800020u}, 2, FN_COND_CALL, 0, 0},
    /* beq cr0,-0x100 to the same chunk, outside */
    {"cond_out_same_chunk", {0x4182FF00u, 0x4E800020u}, 2, FN_COND_CALL, 0, 0},
    /* sc */
    {"system_op", {0x44000002u, 0x4E800020u}, 2, FN_SYSTEM_OP, 0, 0},
    /* two calls to the same callee and one to another: sorted, unique */
    {"needs_sorted_unique", {0x4BFFFF05u, 0x4BFFFEFDu, 0x4BFFFEFDu, 0x4E800020u}, 4, FN_OK, 2,
     0x80004000u},
};

static void check_cases(void) {
    for (u32 k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        const SelectCase* c = &cases[k];
        PPCInst insts[8];
        for (u32 i = 0; i < c->count; i++)
            insts[i] = ppc_decode(c->words[i], 0x80004100u + 4u * i);
        FnNeeds needs;
        FnVerdict v = fn_select_function(insts, c->count, 0x80004100u, 0x80004000u,
                                         0x80008000u, "f", NULL, &needs);
        if (v != c->want || (v == FN_OK && needs.count != c->want_needs) ||
            (v == FN_OK && c->want_needs && needs.targets[0] != c->want_first_need)) {
            fprintf(stderr, "%s: verdict %s needs %u first %08X\n", c->name,
                    fn_verdict_name(v), v == FN_OK ? needs.count : 0u,
                    v == FN_OK && needs.count ? needs.targets[0] : 0u);
            fails++;
        }
    }
}

int main(void) {
    c_global_targets_reset();
    c_global_targets_finalize();

    const u32 leaf[] = {0x38630001u /* addi r3,r3,1 */, 0x4E800020u /* blr */};
    check("leaf", leaf, 2, "f", none, FN_OK);
    check("empty", leaf, 0, "f", none, FN_EMPTY);
    const u32 call[] = {0x48000011u /* bl +0x10 */, 0x4E800020u};
    check("call", call, 2, "f", none, FN_OK);
    const u32 bctrl[] = {0x4E800421u /* bctrl */, 0x4E800020u};
    check("bctrl", bctrl, 2, "f", none, FN_OK);
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
    check("outside", out, 1, "f", none, FN_OK);
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

    check_cases();

    if (fails)
        fprintf(stderr, "%d failures\n", fails);
    return fails != 0;
}
