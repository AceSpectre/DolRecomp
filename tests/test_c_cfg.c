#include <stdio.h>

#include "../src/backend/c_cfg.h"
#include "../src/frontend/decoder.h"

#define BASE 0x80004000u

static int failures;

static void check(bool condition, const char* message) {
    if (condition)
        return;
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
}

static void test_integer_loop(void) {
    static const u32 words[] = {
        0x3863FFFFu,
        0x2C030000u,
        0x4082FFF8u,
        0x4E800020u,
    };
    PPCInst insts[sizeof(words) / sizeof(words[0])];
    for (u32 i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
        insts[i] = ppc_decode(words[i], BASE + i * 4u);

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 4, BASE), "build integer loop CFG");
    check(insts[2].op == PPC_OP_BC && insts[2].branch_target == BASE,
          "decode integer loop backedge");
    check(cfg.leaders[0] && cfg.leaders[3], "discover loop blocks");
    check(cfg.block_cycles[0] == 3 && cfg.block_cycles[3] == 1,
          "charge loop blocks");
    check(c_function_cfg_can_loop_directly(&cfg, insts, BASE, 2),
          "keep integer backedge native");
    check(!cfg.materialize_pc[0] && !cfg.materialize_pc[1] &&
              !cfg.materialize_pc[2] && cfg.materialize_pc[3],
          "elide PC stores inside pure integer loop");
    check(cfg.loop_ends[0] == 2, "extract straight-line integer loop");
    c_function_cfg_destroy(&cfg);
}

static void test_timebase_loop(void) {
    static const u32 words[] = {
        0x7C6C42E6u,
        0x4BFFFFFCu,
    };
    PPCInst insts[sizeof(words) / sizeof(words[0])];
    for (u32 i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
        insts[i] = ppc_decode(words[i], BASE + i * 4u);

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 2, BASE), "build timebase loop CFG");
    check(insts[0].op == PPC_OP_MFTB, "decode timebase read");
    check(!c_function_cfg_can_loop_directly(&cfg, insts, BASE, 1),
          "yield before repeating a timebase read");
    check(cfg.materialize_pc[0] && cfg.materialize_pc[1],
          "materialize PC around timebase loop");
    c_function_cfg_destroy(&cfg);
}

static void test_local_call(void) {
    static const u32 words[] = {
        0x48000009u,
        0x60000000u,
        0x4E800020u,
    };
    PPCInst insts[sizeof(words) / sizeof(words[0])];
    for (u32 i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
        insts[i] = ppc_decode(words[i], BASE + i * 4u);

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 3, BASE), "build local call CFG");
    check(insts[0].op == PPC_OP_B && insts[0].lk &&
              insts[0].branch_target == BASE + 8,
          "decode local call");
    check(cfg.return_targets[1], "record local call continuation");
    c_function_cfg_destroy(&cfg);
}

static void test_memory_loop(void) {
    static const u32 words[] = {
        0x80850000u,
        0x38A50004u,
        0x3863FFFFu,
        0x2C030000u,
        0x4082FFF0u,
        0x4E800020u,
    };
    PPCInst insts[sizeof(words) / sizeof(words[0])];
    for (u32 i = 0; i < sizeof(words) / sizeof(words[0]); ++i)
        insts[i] = ppc_decode(words[i], BASE + i * 4u);

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 6, BASE), "build memory loop CFG");
    check(cfg.loop_ends[0] == 4, "extract ordinary RAM loop");
    check(cfg.materialize_pc[0] && !cfg.materialize_pc[1] &&
              !cfg.materialize_pc[2] && !cfg.materialize_pc[3] &&
              !cfg.materialize_pc[4],
          "materialize PC only for memory slow path");
    c_function_cfg_destroy(&cfg);
}

/* A chunk is entered at any address the rest of the program can branch to, not
 * just at its own leaders: function A's `bl` lands in the middle of chunk B's
 * address range. The global pass records those targets so B's hot entry switch
 * covers them. */
static void test_global_entry_points(void) {
    /* "chunk A", a long way off, calls into the middle of the chunk below. */
    static const u32 caller_words[] = {
        0x48004009u, /* bl 0x80008008 (= BASE + 0x4008) */
        0x4E800020u, /* blr                             */
    };
    PPCInst caller[2];
    for (u32 i = 0; i < 2; ++i)
        caller[i] = ppc_decode(caller_words[i], 0x80004000u + i * 4u);

    /* "chunk B" starts at BASE + 0x4000; index 2 is the call target, index 1
     * is only ever reached by falling through index 0. */
    const u32 b_base = BASE + 0x4000u;
    static const u32 words[] = {
        0x38630001u, /* addi r3,r3,1 */
        0x38630001u, /* addi r3,r3,1 */
        0x38630001u, /* addi r3,r3,1 <- branched to from the caller above */
        0x4E800020u, /* blr          */
    };
    PPCInst insts[4];
    for (u32 i = 0; i < 4; ++i)
        insts[i] = ppc_decode(words[i], b_base + i * 4u);

    check(caller[0].op == PPC_OP_B && caller[0].lk &&
              caller[0].branch_target == b_base + 8u,
          "decode cross-chunk call target");

    c_global_targets_reset();
    check(c_global_targets_add(caller, 2), "record caller's branch targets");
    check(c_global_targets_add(insts, 4), "record callee's branch targets");
    c_global_targets_finalize();

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 4, b_base), "build callee CFG");
    check(cfg.entry_points[0], "chunk start is an entry point");
    check(cfg.entry_points[2], "cross-chunk call target is an entry point");
    check(!cfg.entry_points[1], "fall-through instruction is not an entry point");
    check(!cfg.entry_points[3], "fall-through blr is not an entry point");
    c_function_cfg_destroy(&cfg);

    /* Without the global pass the same chunk knows of no outside entries. */
    c_global_targets_reset();
    c_global_targets_finalize();
    check(c_function_cfg_build(&cfg, insts, 4, b_base), "rebuild callee CFG");
    check(cfg.entry_points[0] && !cfg.entry_points[1] && !cfg.entry_points[2] &&
              !cfg.entry_points[3],
          "entry points fall back to local information");
    c_function_cfg_destroy(&cfg);
}

/* A local `bl` makes its return address an entry point (the callee's `blr`
 * dispatches there), and a local branch target is a leader. */
static void test_local_entry_points(void) {
    static const u32 words[] = {
        0x48000009u, /* bl  +8 (local)  */
        0x48000008u, /* b   +8 (local)  */
        0x4E800020u, /* blr             */
        0x4E800020u, /* blr             */
    };
    PPCInst insts[4];
    for (u32 i = 0; i < 4; ++i)
        insts[i] = ppc_decode(words[i], BASE + i * 4u);

    c_global_targets_reset();
    c_global_targets_finalize();

    CFunctionCFG cfg;
    check(c_function_cfg_build(&cfg, insts, 4, BASE), "build local call CFG");
    check(cfg.entry_points[0], "chunk start is an entry point");
    check(cfg.entry_points[1], "return address is an entry point");
    check(cfg.entry_points[2], "local call target is an entry point");
    check(cfg.entry_points[3], "local branch target is an entry point");
    c_function_cfg_destroy(&cfg);
}

int main(void) {
    test_integer_loop();
    test_timebase_loop();
    test_local_call();
    test_memory_loop();
    test_global_entry_points();
    test_local_entry_points();
    return failures != 0;
}
