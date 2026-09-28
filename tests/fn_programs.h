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
#define FN_PROGRAM_COUNT ((unsigned)(sizeof(fn_programs) / sizeof(fn_programs[0])))

#endif
