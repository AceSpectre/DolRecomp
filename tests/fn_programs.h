/* Guest test programs shared by the fn-mode generator and executor. Each is
 * one leaf function; addresses are 0x100 apart so each is its own chunk. */
#ifndef DOLRECOMP_TEST_FN_PROGRAMS_H
#define DOLRECOMP_TEST_FN_PROGRAMS_H

typedef struct {
    const char* name;
    unsigned addr;
    unsigned count;
    unsigned words[16];
} FnProgram;

static const FnProgram fn_programs[] = {
    /* r3 = sum of r4..1 through a bdnz counted loop */
    {"sum_loop", 0x80004000u, 6,
     {0x38600000u /* li r3,0 */, 0x7C8903A6u /* mtctr r4 */,
      0x7C632214u /* add r3,r3,r4 */, 0x3884FFFFu /* addi r4,r4,-1 */,
      0x4200FFF8u /* bdnz -8 */, 0x4E800020u /* blr */}},
    /* copy r7 words from r5 to r6 */
    {"mem_copy", 0x80004100u, 7,
     {0x81050000u /* lwz r8,0(r5) */, 0x91060000u /* stw r8,0(r6) */,
      0x38A50004u /* addi r5,r5,4 */, 0x38C60004u /* addi r6,r6,4 */,
      0x34E7FFFFu /* addic. r7,r7,-1 */, 0x4082FFECu /* bne -20 */,
      0x4E800020u /* blr */}},
    /* record forms and CR materialisation */
    {"cr_record", 0x80004200u, 6,
     {0x7C632215u /* add. r3,r3,r4 */, 0x7CA41851u /* subf. r5,r4,r3 */,
      0x5466083Du /* rlwinm. r6,r3,1,0,30 */, 0x7C032000u /* cmpw r3,r4 */,
      0x7C600026u /* mfcr r3 */, 0x4E800020u /* blr */}},
    /* scalar and paired-single FP through memory */
    {"fp_ps", 0x80004300u, 7,
     {0xC0250000u /* lfs f1,0(r5) */, 0xC0450004u /* lfs f2,4(r5) */,
      0xEC61102Au /* fadds f3,f1,f2 */, 0x108118BAu /* ps_madd f4,f1,f2,f3 */,
      0x10A32460u /* ps_merge01 f5,f3,f4 */, 0xD0A50008u /* stfs f5,8(r5) */,
      0x4E800020u /* blr */}},
    /* impure helper writing fpr/ps1, consumed right after */
    {"psq_then_use", 0x80004400u, 4,
     {0xE0250000u /* psq_l f1,0(r5),0,0 */, 0x1041082Au /* ps_add f2,f1,f1 */,
      0xF0450008u /* psq_st f2,8(r5),0,0 */, 0x4E800020u /* blr */}},
    /* impure helper writing cr, consumed by a branch */
    {"fcmp_then_branch", 0x80004500u, 6,
     {0xFC811000u /* fcmpu cr1,f1,f2 */, 0x4184000Cu /* blt cr1,+12 */,
      0x38600001u /* li r3,1 */, 0x4E800020u /* blr */,
      0x38600002u /* li r3,2 */, 0x4E800020u /* blr */}},
};
/* Caller and leaf in one chunk: r3 += 2 * r4 in the leaf's bdnz loop, then
 * the caller adds 1 and returns through its saved lr. */
#define FN_PAIR_PLAIN 0x80005000u
#define FN_PAIR_FN 0x80006000u
#define FN_PAIR_LEAF_OFFSET 0x14u
#define FN_PAIR_COUNT 9u
static const unsigned fn_pair_words[FN_PAIR_COUNT] = {
    0x7D4802A6u, /* mflr r10 */
    0x48000011u, /* bl +0x10 (leaf) */
    0x38630001u, /* addi r3,r3,1 */
    0x7D4803A6u, /* mtlr r10 */
    0x4E800020u, /* blr */
    0x7C8903A6u, /* leaf: mtctr r4 */
    0x38630002u, /* addi r3,r3,2 */
    0x4200FFFCu, /* bdnz -4 */
    0x4E800020u, /* blr */
};

/* A leaf preceded by alignment padding in its chunk. The padding word is
 * embedded data, so it does not end a block: in the chunk's CFG the leaf's
 * first instruction is not a leader, and a dispatcher entry there takes the
 * chunk's cold path. The converted leaf must do exactly the same. */
#define FN_PAD_CHUNK 0x80004600u
#define FN_PAD_LEAF_OFFSET 0x8u
#define FN_PAD_COUNT 5u
static const unsigned fn_pad_words[FN_PAD_COUNT] = {
    0x4E800020u, /* blr (end of the previous function) */
    0x00000000u, /* padding (embedded data) */
    0x38630001u, /* leaf: addi r3,r3,1 */
    0x38630001u, /* addi r3,r3,1 */
    0x4E800020u, /* blr */
};

/* Calls: T (leaf, before F so F's call to it is backward), F (calls T, U,
 * cross-chunk G, F2 and F4), F2 (tail call to U), U (leaf), F3 (bl $+4, then
 * bctrl to G), F4 (backward tail call to T). G is its own chunk at +0x100.
 * The same words run at FN_CALLS_PLAIN (chunk code only) and FN_CALLS_FN
 * (T, F, F2, U, F3, F4 converted); every branch is relative. */
#define FN_CALLS_PLAIN 0x80007000u
#define FN_CALLS_FN 0x80008000u
#define FN_CALLS_COUNT 27u
#define FN_CALLS_G_OFFSET 0x100u
#define FN_CALLS_G_COUNT 4u
#define FN_CALLS_F_OFFSET 0x10u
#define FN_CALLS_F3_OFFSET 0x44u
static const unsigned fn_calls_words[FN_CALLS_COUNT] = {
    0x7C8903A6u, /* 0x00 T: mtctr r4 */
    0x38630002u, /* 0x04 addi r3,r3,2 */
    0x4200FFFCu, /* 0x08 bdnz -4 */
    0x4E800020u, /* 0x0C blr */
    0x7FE802A6u, /* 0x10 F: mflr r31 */
    0x4BFFFFEDu, /* 0x14 bl T */
    0x38630001u, /* 0x18 addi r3,r3,1 */
    0x48000021u, /* 0x1C bl U */
    0x480000E1u, /* 0x20 bl G */
    0x48000011u, /* 0x24 bl F2 */
    0x4800003Du, /* 0x28 bl F4 */
    0x7FE803A6u, /* 0x2C mtlr r31 */
    0x4E800020u, /* 0x30 blr */
    0x38630003u, /* 0x34 F2: addi r3,r3,3 */
    0x48000004u, /* 0x38 b U */
    0x38630005u, /* 0x3C U: addi r3,r3,5 */
    0x4E800020u, /* 0x40 blr */
    0x7FC802A6u, /* 0x44 F3: mflr r30 */
    0x48000005u, /* 0x48 bl +4 */
    0x7D8802A6u, /* 0x4C mflr r12 */
    0x398C00B4u, /* 0x50 addi r12,r12,0xB4 (-> G) */
    0x7D8903A6u, /* 0x54 mtctr r12 */
    0x4E800421u, /* 0x58 bctrl */
    0x7FC803A6u, /* 0x5C mtlr r30 */
    0x4E800020u, /* 0x60 blr */
    0x38630007u, /* 0x64 F4: addi r3,r3,7 */
    0x4BFFFF98u, /* 0x68 b T */
};
static const unsigned fn_calls_g_words[FN_CALLS_G_COUNT] = {
    0x7CA903A6u, /* G: mtctr r5 */
    0x38630064u, /* addi r3,r3,100 */
    0x4200FFFCu, /* bdnz -4 */
    0x4E800020u, /* blr */
};
/* Converted functions: offset and end offset within the chunk. */
#define FN_CALLS_FN_COUNT 6u
static const unsigned fn_calls_fn_offsets[FN_CALLS_FN_COUNT][2] = {
    {0x00, 0x10}, {0x10, 0x34}, {0x34, 0x3C}, {0x3C, 0x44}, {0x44, 0x64}, {0x64, 0x6C},
};

#define FN_PROGRAM_COUNT ((unsigned)(sizeof(fn_programs) / sizeof(fn_programs[0])))

#endif
