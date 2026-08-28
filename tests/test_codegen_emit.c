#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/backend/dispatch.h"
#include "../src/backend/emitter.h"
#include "../src/common/types.h"
#include "../src/frontend/decoder.h"

#define BASE 0x80003000u

/* Emits one function to a scratch file and returns its text, or NULL. Used for
 * shape assertions that executing the code cannot make (which helper a call
 * routes through, whether a label exists). Caller frees. */
static char* emit_to_text(const PPCInst* insts, u32 count, u32 addr) {
    const char* path = "codegen_emit_check.tmp";
    FILE* f = fopen(path, "wb+");
    if (!f) {
        perror(path);
        return NULL;
    }
    if (!emit_function(f, insts, count, addr)) {
        fclose(f);
        remove(path);
        return NULL;
    }
    long size = ftell(f);
    char* text = (char*)malloc((size_t)size + 1u);
    if (text) {
        rewind(f);
        text[fread(text, 1, (size_t)size, f)] = '\0';
    }
    fclose(f);
    remove(path);
    return text;
}

static int text_check(const char* what, const char* text,
                      const char* const* expect, int expect_n,
                      const char* const* reject, int reject_n) {
    int ok = 1;
    for (int i = 0; i < expect_n; i++) {
        if (!strstr(text, expect[i])) {
            fprintf(stderr, "%s: missing expected fragment: %s\n", what,
                    expect[i]);
            ok = 0;
        }
    }
    for (int i = 0; i < reject_n; i++) {
        if (strstr(text, reject[i])) {
            fprintf(stderr, "%s: unexpected fragment present: %s\n", what,
                    reject[i]);
            ok = 0;
        }
    }
    return ok;
}

/* Copy the run of text starting at `begin` and stopping before `end` (or at
 * the end of the text when `end` is NULL). Returns NULL if either marker is
 * missing. Assertions have to be per-function: the hot function legitimately
 * uses gotos and direct calls, and the cold one legitimately uses the shape
 * the hot one no longer does. */
static char* text_slice(const char* text, const char* begin, const char* end) {
    const char* from = strstr(text, begin);
    if (!from)
        return NULL;
    const char* to = end ? strstr(from, end) : from + strlen(from);
    if (!to)
        return NULL;
    size_t span = (size_t)(to - from);
    char* out = (char*)malloc(span + 1u);
    if (!out)
        return NULL;
    memcpy(out, from, span);
    out[span] = '\0';
    return out;
}

/* Emits one function, slices out the named part of the output, and checks it.
 * Pass begin/end as for text_slice. */
static int emit_shape_check(const char* what, const PPCInst* insts, u32 count,
                            u32 addr, const char* begin, const char* end,
                            const char* const* expect, int expect_n,
                            const char* const* reject, int reject_n) {
    char* text = emit_to_text(insts, count, addr);
    if (!text)
        return 0;
    char* part = text_slice(text, begin, end);
    if (!part) {
        fprintf(stderr, "%s: could not find '%s' in the emitted output\n", what,
                begin);
        fputs(text, stderr);
        free(text);
        return 0;
    }
    int ok = text_check(what, part, expect, expect_n, reject, reject_n);
    if (!ok)
        fputs(part, stderr);
    free(part);
    free(text);
    return ok;
}

/* Cross-chunk `bl` must call the target through dolrecomp_direct_call and
 * resume inline at the return address instead of returning to the dispatcher.
 * Unconditional form at BASE+0x1060, conditional form at BASE+0x1080; both
 * target the leaf at BASE+0x1070. */
static int check_direct_call_shape(void) {
    PPCInst cross_call[3];
    cross_call[0] = ppc_decode(0x48000011u, BASE + 0x1060); /* bl  +0x10 */
    cross_call[1] = ppc_decode(0x7C8803A6u, BASE + 0x1064); /* mtlr r4   */
    cross_call[2] = ppc_decode(0x4E800020u, BASE + 0x1068); /* blr       */

    PPCInst cond_call[2];
    cond_call[0] = ppc_decode(0x4182FFF1u, BASE + 0x1080); /* beql -0x10 */
    cond_call[1] = ppc_decode(0x4E800020u, BASE + 0x1084); /* blr        */

    static const char* const expect_uncond[] = {
        "ctx->lr = 0x80004064u;",
        "dolrecomp_direct_call(ctx, 0x80004070u)",
        "goto label_80004064;",
    };
    static const char* const reject_uncond[] = {
        /* the old shape: hand the target back to the dispatcher */
        "ctx->pc = 0x80004070u;\n            return;",
    };
    static const char* const expect_cond[] = {
        "ctx->lr = 0x80004084u;",
        "dolrecomp_direct_call(ctx, 0x80004070u)",
        "goto label_80004084;",
    };

    int ok = emit_shape_check("cross-chunk bl", cross_call, 3, BASE + 0x1060,
                              "\nvoid func_80004060(", NULL, expect_uncond, 3,
                              reject_uncond, 1);
    ok &= emit_shape_check("cross-chunk conditional bl", cond_call, 2,
                           BASE + 0x1080, "\nvoid func_80004080(", NULL,
                           expect_cond, 3, NULL, 0);
    return ok;
}

/* Every chunk gets a cold resume companion carrying a case per instruction,
 * including instructions the hot entry switch has no reason to cover. Inside
 * it, control transfers all leave through ctx->pc -- no gotos, no direct
 * calls, no counted-loop helper calls. */
static int check_cold_companion_shape(void) {
    /* A local backward branch (which the hot path keeps native) and a call
     * whose return address is inside the range (which the hot path turns into
     * a direct call), so the cold lowering of both can be told apart. */
    PPCInst body[6];
    body[0] = ppc_decode(0x38630001u, BASE + 0x10A0); /* addi r3,r3,1   */
    body[1] = ppc_decode(0x38630001u, BASE + 0x10A4); /* addi r3,r3,1   */
    body[2] = ppc_decode(0x2C030000u, BASE + 0x10A8); /* cmpwi r3,0     */
    body[3] = ppc_decode(0x4082FFF8u, BASE + 0x10AC); /* bne -8 (local) */
    body[4] = ppc_decode(0x48001001u, BASE + 0x10B0); /* bl +0x1000     */
    body[5] = ppc_decode(0x4E800020u, BASE + 0x10B4); /* blr            */

    static const char* const expect[] = {
        /* index 2 is pure fall-through -- not a leader, not a return target --
         * yet the cold switch still covers it */
        "    case 0x800040A8u: goto cold_800040A8;\n",
        "cold_800040A8:\n    ctx->pc = 0x800040A8u;\n",
        /* index 1 is the backward branch's target, so it is a leader and gets
         * the same downcount charge the hot path makes */
        "cold_800040A4:\n    ctx->pc = 0x800040A4u;\n    ctx->downcount -= ",
        /* the local backward branch leaves through pc instead of looping */
        "            ctx->pc = 0x800040A4u;\n            return;\n",
        /* the cross-chunk call leaves through pc instead of calling in place */
        "            ctx->lr = 0x800040B4u;\n"
        "            ctx->pc = 0x800050B0u;\n"
        "            return;\n",
    };
    static const char* const reject[] = {
        "goto label_",
        "dolrecomp_direct_call",
        "loop_800040A4(",
        "return_dispatch_",
    };

    return emit_shape_check("cold companion", body, 6, BASE + 0x10A0,
                            "static void func_800040A0_cold(CPUState* ctx) {",
                            "\nvoid func_800040A0(", expect, 5, reject, 4);
}

/* The hot entry switch carries cases only for addresses control can actually
 * arrive at from outside -- chunk start, block leaders, return addresses, and
 * targets other chunks branch to. Everything else falls through with no label
 * and one predecessor, which is the point: it is what lets the compiler keep
 * values in registers across the instruction. Anything not covered goes to the
 * cold companion. */
static int check_hot_switch_thinning(void) {
    PPCInst body[4];
    body[0] = ppc_decode(0x48001001u, BASE + 0x10E0); /* bl +0x1000   */
    body[1] = ppc_decode(0x38630001u, BASE + 0x10E4); /* addi r3,r3,1 */
    body[2] = ppc_decode(0x38630001u, BASE + 0x10E8); /* addi r3,r3,1 */
    body[3] = ppc_decode(0x4E800020u, BASE + 0x10EC); /* blr          */

    static const char* const expect[] = {
        /* chunk start */
        "    case 0x800040E0u: goto label_800040E0;\n",
        /* the `bl`'s return address: the callee's blr dispatches here */
        "    case 0x800040E4u: goto label_800040E4;\n",
        /* anything else lands in the cold companion */
        "    default:\n",
        "        func_800040E0_cold(ctx);\n",
    };
    static const char* const reject[] = {
        /* index 2 and 3 are reachable only by falling through index 1 */
        "case 0x800040E8u:",
        "label_800040E8:",
        "case 0x800040ECu:",
        "label_800040EC:",
    };

    return emit_shape_check("hot switch", body, 4, BASE + 0x10E0,
                            "\nvoid func_800040E0(", NULL, expect, 4, reject, 4);
}

static const u32 opcode_raws[] = {
    0x1C64FFF9, 0x20850001, 0x38610010, 0x3084FFFF,
    0x34A5FFFF, 0x3CA01234, 0x2C03FFFF, 0x28038000,
    0x6064FF00, 0x64851234, 0x68A6FFFF, 0x6CC78000,
    0x70E800FF, 0x74E900FF, 0x80610000, 0x84810004,
    0x88A10008, 0x8CC1000C, 0xA0E10010, 0xA5010014,
    0xA921FFFC, 0xAD410018, 0x9061001C, 0x94810020,
    0x98A10024, 0x9CC10028, 0xB0E1002C, 0xB5010030,
    0xBA810034, 0xBE810064, 0x480000C8, 0x418200C4,
    0x4E800020, 0x4E800420, 0x4C432202, 0x4C432102,
    0x4C432242, 0x4C4321C2, 0x4C432042, 0x4C432382,
    0x4C432342, 0x4C432182, 0x4D0C0000, 0x7D400026,
    0x7D4FF120, 0x7D4802A6, 0x7D4803A6, 0x7C832000,
    0x7D032040, 0x7D4B6214, 0x7D6C6814, 0x7D8D7114,
    0x7DAE0194, 0x7DCF8050, 0x7DF08810, 0x7E119110,
    0x7E320190, 0x7E5300D0, 0x7E93A838, 0x7EB4B078,
    0x7ED5BB78, 0x7EF6C338, 0x7F17CA78, 0x7F38D3B8,
    0x7F59D8F8, 0x7F7AE238, 0x7F9B0034, 0x7FBC0774,
    0x7FDD0734, 0x7FFE1830, 0x7C7F2430, 0x7C832E30,
    0x7CA43E70, 0x54C52A2E, 0x5CE64136, 0x5107421E,
    0x7C64282E, 0x7CC4286E, 0x7CE428AE, 0x7D0428EE,
    0x7D242A2E, 0x7D442A6E, 0x7D642AAE, 0x7D842AEE,
    0x7C642C2C, 0x7CC7462C, 0x7C64292E, 0x7CC4296E,
    0x7CE429AE, 0x7D0429EE, 0x7D242B2E, 0x7D442B6E,
    0x7D2A5D2C, 0x7D8D772C, 0x7C0F87EC,
    0xC0240000, 0xC4440004, 0xC8640008, 0xCC840010,
    0xD0A40014, 0xD4C40018, 0xD8E40020, 0xDD040028,
    0x7D242C2E, 0x7D442C6E, 0x7D642CAE, 0x7D842CEE,
    0x7DA42D2E, 0x7DC42D6E, 0x7DE42DAE, 0x7E042DEE,
    0xEC22182A, 0xEC853028, 0xECE80272, 0xED4B6024,
    0xFDAE782A, 0xFE119028, 0xFE740572, 0xFED7C024,
    0xFF20D090, 0xFF60E050, 0xFFA0F210, 0xFFE00110,
    0xFC201018, 0xFC2220EE, 0xFD032000, 0xFD853040,
    0xFFE0008C, 0xFFE0004C,
    0xE0240000, 0xE4640008, 0xF0A40010, 0xF4E40018,
    0x1124280C, 0x1164284C, 0x11A4280E, 0x11E4284E,
    0x1022182A, 0x10853028, 0x10E80272, 0x114B6024,
    0x11AE83FA, 0x1232A4F8, 0x12B6C5FE, 0x133AE6FC,
    0x10201050, 0x10602210, 0x10A03110, 0x10E04090,
    0x112A62D4, 0x11AE83D6, 0x123204D8, 0x1295059A,
    0x12F8D65C, 0x137CF75E, 0x10221C20, 0x10853460,
    0x10E84CA0, 0x114B64E0, 0x110D7000, 0x118F8040,
    0x12119080, 0x1293A0C0, 0x12B6C5EE,
    0x7C6429D6, 0x7CC74096, 0x7D2A5816, 0x7D8D73D6,
    0x7DF08B96,
    0x7C6401D4, 0x7CA601D0, 0x7CEC6CAA, 0x7D34AC2A,
    0x7D8D8DAA, 0x7DCF852A, 0x7E329828, 0x7E95B12D,
    0x7EF8CFAE, 0xEC201030, 0xFC602034, 0x10A03030,
    0x10E04034, 0xFD20501C, 0xFD60601E, 0xFDAE83FA,
    0xEE32A4FA, 0xFEB6C5F8, 0xEF3AE6F8, 0xFFBE07FE,
    0xEC2220FE, 0xFCA641FC, 0xED2A62FC, 0xFDA0048E,
    0xFD0C0080, 0xFE00A10C, 0xFCB4758E, 0x7C0004AC,
    0x7C0006AC, 0x4C00012C,
    0x7D4B6614, 0x7D6C6C14, 0x7D8D7514, 0x7DAE05D4,
    0x7DCF0594, 0x7DF08C50, 0x7E119410, 0x7E329D10,
    0x7E5305D0, 0x7E740590, 0x7E9504D0, 0x7EB6BDD6,
    0x7ED7C7D6, 0x7EF8CF96, 0x0C85FFFE, 0x7CC74008,
    0x7D000400, 0x7D2000A6, 0x7D400124, 0x7D6304A6,
    0x7D806D26, 0x7DC401A4, 0x7DE081E4, 0x7C11906C,
    0x7C13A0AC, 0x7C15B1EC, 0x7C17C22C, 0x7C19D3AC,
    0x7C1BE7AC, 0x7C00046C,
    0x44000002, 0x4C000064, 0x7C6C42E6, 0x100537EC,
    0x7C003A64, 0x7D09526C, 0x7D6C6B6C,
};

int main(int argc, char** argv) {
    const int count = (int)(sizeof(opcode_raws) / sizeof(opcode_raws[0]));
    FILE* out = stdout;

    if ((PPC_OP_COUNT - 1) != count) {
        fprintf(stderr, "opcode count mismatch: enum has %d, table has %d\n",
                PPC_OP_COUNT - 1, count);
        return 1;
    }

    if (argc > 1) {
        out = fopen(argv[1], "w");
        if (!out) {
            perror(argv[1]);
            return 1;
        }
    }

    PPCInst* insts = (PPCInst*)calloc((size_t)count, sizeof(PPCInst));
    if (!insts) {
        if (out != stdout) fclose(out);
        return 1;
    }

    for (int i = 0; i < count; i++) {
        insts[i] = ppc_decode(opcode_raws[i], BASE + (u32)i * 4u);
        if (insts[i].op == PPC_OP_UNKNOWN) {
            fprintf(stderr, "raw 0x%08X decoded as unknown\n", opcode_raws[i]);
            free(insts);
            if (out != stdout) fclose(out);
            return 1;
        }
    }

    if (!check_direct_call_shape() || !check_cold_companion_shape() ||
        !check_hot_switch_thinning()) {
        free(insts);
        if (out != stdout) fclose(out);
        return 1;
    }

    /* Chunk prototypes and the dispatch helpers come first, as they do in a
     * real run: the generator puts both in the shared header that every chunk
     * includes, so a chunk body may call dolrecomp_direct_call. */
    FunctionList funcs = {0};
    if (!function_list_add(&funcs, BASE, BASE + (u32)count * 4u) ||
        !function_list_add(&funcs, BASE + 0x1000, BASE + 0x100C) ||
        !function_list_add(&funcs, BASE + 0x100C, BASE + 0x1018) ||
        !function_list_add(&funcs, BASE + 0x1018, BASE + 0x101C) ||
        !function_list_add(&funcs, BASE + 0x1020, BASE + 0x1030) ||
        !function_list_add(&funcs, BASE + 0x1030, BASE + 0x1040) ||
        !function_list_add(&funcs, BASE + 0x1040, BASE + 0x1058) ||
        !function_list_add(&funcs, BASE + 0x1060, BASE + 0x106C) ||
        !function_list_add(&funcs, BASE + 0x1070, BASE + 0x1078) ||
        !function_list_add(&funcs, BASE + 0x10C0, BASE + 0x10D4)) {
        function_list_free(&funcs);
        free(insts);
        if (out != stdout) fclose(out);
        return 1;
    }

    emit_header(out);
    for (u32 i = 0; i < funcs.count; i++)
        emit_chunk_prototype(out, funcs.ranges[i].start);
    emit_dispatch_helpers(out, &funcs, BASE);
    function_list_free(&funcs);

    if (!emit_function(out, insts, (u32)count, BASE))
        return 1;

    PPCInst external_branch[3];
    external_branch[0] = ppc_decode(0x48001000, BASE + 0x1000);
    external_branch[1] = ppc_decode(0x41821000, BASE + 0x1004);
    external_branch[2] = ppc_decode(0x4E800020, BASE + 0x1008);
    if (!emit_function(out, external_branch, 3, BASE + 0x1000))
        return 1;

    PPCInst adjacent_branch[3];
    adjacent_branch[0] = ppc_decode(0x48001000, BASE + 0x100C);
    adjacent_branch[1] = ppc_decode(0x41821000, BASE + 0x1010);
    adjacent_branch[2] = ppc_decode(0x4E800020, BASE + 0x1014);
    if (!emit_function(out, adjacent_branch, 3, BASE + 0x100C))
        return 1;

    PPCInst linked_lr_branch = ppc_decode(0x4E800021, BASE + 0x1018);
    if (!emit_function(out, &linked_lr_branch, 1, BASE + 0x1018))
        return 1;

    PPCInst native_loop[4];
    native_loop[0] = ppc_decode(0x3863FFFFu, BASE + 0x1020);
    native_loop[1] = ppc_decode(0x2C030000u, BASE + 0x1024);
    native_loop[2] = ppc_decode(0x4082FFF8u, BASE + 0x1028);
    native_loop[3] = ppc_decode(0x4E800020u, BASE + 0x102C);
    if (!emit_function(out, native_loop, 4, BASE + 0x1020))
        return 1;

    PPCInst local_call[4];
    local_call[0] = ppc_decode(0x48000009u, BASE + 0x1030);
    local_call[1] = ppc_decode(0x48000008u, BASE + 0x1034);
    local_call[2] = ppc_decode(0x4E800020u, BASE + 0x1038);
    local_call[3] = ppc_decode(0x4E800020u, BASE + 0x103C);
    if (!emit_function(out, local_call, 4, BASE + 0x1030))
        return 1;

    PPCInst memory_loop[6];
    memory_loop[0] = ppc_decode(0x80850000u, BASE + 0x1040);
    memory_loop[1] = ppc_decode(0x38A50004u, BASE + 0x1044);
    memory_loop[2] = ppc_decode(0x3863FFFFu, BASE + 0x1048);
    memory_loop[3] = ppc_decode(0x2C030000u, BASE + 0x104C);
    memory_loop[4] = ppc_decode(0x4082FFF0u, BASE + 0x1050);
    memory_loop[5] = ppc_decode(0x4E800020u, BASE + 0x1054);
    if (!emit_function(out, memory_loop, 6, BASE + 0x1040))
        return 1;

    /* Cross-chunk call pair: the caller's `bl` leaves its own range, so it
     * exercises the direct-call path; the callee returns with `blr`. */
    PPCInst cross_call[3];
    cross_call[0] = ppc_decode(0x48000011u, BASE + 0x1060); /* bl +0x10  */
    cross_call[1] = ppc_decode(0x7C8803A6u, BASE + 0x1064); /* mtlr r4   */
    cross_call[2] = ppc_decode(0x4E800020u, BASE + 0x1068); /* blr       */
    if (!emit_function(out, cross_call, 3, BASE + 0x1060))
        return 1;

    PPCInst cross_callee[2];
    cross_callee[0] = ppc_decode(0x38630001u, BASE + 0x1070); /* addi r3,r3,1 */
    cross_callee[1] = ppc_decode(0x4E800020u, BASE + 0x1074); /* blr          */
    if (!emit_function(out, cross_callee, 2, BASE + 0x1070))
        return 1;

    /* Straight-line body with exactly one leader (index 0), so entering at
     * index 2 is a mid-block entry no hot entry switch has a reason to cover.
     * test_c_execute enters it there and pins the result. */
    PPCInst midblock[5];
    for (u32 i = 0; i < 4; i++)
        midblock[i] = ppc_decode(0x38630001u, BASE + 0x10C0 + i * 4u);
    midblock[4] = ppc_decode(0x4E800020u, BASE + 0x10D0); /* blr */
    if (!emit_function(out, midblock, 5, BASE + 0x10C0))
        return 1;

    emit_footer(out);

    free(insts);
    if (out != stdout) fclose(out);
    return 0;
}
