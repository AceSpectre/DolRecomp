#include <stdio.h>

#include "../src/cpu/cpu.h"

void func_80004020(CPUState* ctx);
void func_80004040(CPUState* ctx);
void func_80004060(CPUState* ctx); /* bl 0x80004070; mtlr r4; blr */
void func_80004070(CPUState* ctx); /* addi r3,r3,1; blr */
void func_800040C0(CPUState* ctx); /* addi r3,r3,1 x4; blr */

int main(void) {
    CPUState cpu;
    if (!cpu_init(&cpu))
        return 1;

    cpu.pc = 0x80004020u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 1000;

    u32 calls = 0;
    while (cpu.pc != cpu.lr && calls < 32) {
        cpu.downcount = 0;
        func_80004020(&cpu);
        calls++;
    }

    int integer_ok = cpu.pc == cpu.lr && cpu.gpr[3] == 0 &&
                     (cpu.cr & 0xF0000000u) == 0x20000000u && calls < 20;
    if (!integer_ok) {
        fprintf(stderr, "pc=%08X r3=%u cr=%08X calls=%u\n",
                cpu.pc, cpu.gpr[3], cpu.cr, calls);
    }
    for (u32 i = 0; i < 1000; ++i)
        mem_write32(&cpu, 0x80001000u + i * 4u, i);
    cpu.pc = 0x80004040u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 1000;
    cpu.gpr[5] = 0x80001000u;
    calls = 0;
    while (cpu.pc != cpu.lr && calls < 32) {
        cpu.downcount = 0;
        func_80004040(&cpu);
        calls++;
    }
    int memory_ok = cpu.pc == cpu.lr && cpu.gpr[3] == 0 &&
                    cpu.gpr[4] == 999 && cpu.gpr[5] == 0x80001FA0u &&
                    calls < 24;
    if (!memory_ok) {
        fprintf(stderr, "memory pc=%08X r3=%u r4=%u r5=%08X calls=%u\n",
                cpu.pc, cpu.gpr[3], cpu.gpr[4], cpu.gpr[5], calls);
    }

    /* Cross-chunk call: one host call into the caller chunk must run the
     * callee and resume at the return address in place, so the caller's own
     * `blr` is reached without a dispatcher round trip. */
    cpu.pc = 0x80004060u;
    cpu.lr = 0;
    cpu.gpr[3] = 5;
    cpu.gpr[4] = 0x81234564u; /* the caller's own return address (mtlr r4) */
    cpu.downcount = 0;
    cpu.direct_depth = 0;
    func_80004060(&cpu);
    int direct_call_ok = cpu.pc == 0x81234564u && cpu.gpr[3] == 6 &&
                         cpu.direct_depth == 0;
    if (!direct_call_ok) {
        fprintf(stderr, "direct call pc=%08X r3=%u depth=%u\n", cpu.pc,
                cpu.gpr[3], cpu.direct_depth);
    }

    /* Past the depth bound the call must fall back to the pre-change shape:
     * return with the target in pc and the return address in lr, leaving the
     * dispatcher to run the callee. */
    cpu.pc = 0x80004060u;
    cpu.lr = 0;
    cpu.gpr[3] = 5;
    cpu.gpr[4] = 0x81234564u;
    cpu.downcount = 0;
    cpu.direct_depth = 1000;
    func_80004060(&cpu);
    int depth_bound_ok = cpu.pc == 0x80004070u && cpu.lr == 0x80004064u &&
                         cpu.gpr[3] == 5 && cpu.direct_depth == 1000;
    if (!depth_bound_ok) {
        fprintf(stderr, "depth bound pc=%08X lr=%08X r3=%u depth=%u\n", cpu.pc,
                cpu.lr, cpu.gpr[3], cpu.direct_depth);
    }
    cpu.direct_depth = 0;

    /* Parked in the idle loop the direct call must also stand down:
     * dolrecomp_run_blocks tests the park threshold before every dispatch, so
     * the callee must not run a block earlier than it used to. */
    cpu.pc = 0x80004060u;
    cpu.lr = 0;
    cpu.gpr[3] = 5;
    cpu.gpr[4] = 0x81234564u;
    cpu.downcount = DOLRECOMP_IDLE_PARK_DOWNCOUNT;
    func_80004060(&cpu);
    int parked_ok = cpu.pc == 0x80004070u && cpu.lr == 0x80004064u &&
                    cpu.gpr[3] == 5;
    if (!parked_ok) {
        fprintf(stderr, "parked pc=%08X lr=%08X r3=%u\n", cpu.pc, cpu.lr,
                cpu.gpr[3]);
    }

    /* Mid-block entry. 0x800040C8 is index 2 of a five-instruction chunk whose
     * only leader is index 0, so no entry switch has a reason to carry a case
     * for it -- it is exactly the address that must reach the cold resume
     * companion once the hot switch is thinned. These values are the reference:
     * they were produced while the hot function still had a case per
     * instruction, and must not move when that case goes away.
     *   two addi run (r3 += 2), the blr returns through lr, and no leader is
     *   crossed so downcount is untouched. */
    cpu.pc = 0x800040C8u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 10;
    cpu.downcount = 100;
    func_800040C0(&cpu);
    int midblock_ok = cpu.pc == 0x81234564u && cpu.gpr[3] == 12 &&
                      cpu.downcount == 100;
    if (!midblock_ok) {
        fprintf(stderr, "midblock pc=%08X r3=%u downcount=%lld\n", cpu.pc,
                cpu.gpr[3], (long long)cpu.downcount);
    }

    /* Same chunk entered at its leader: all four addi run and the block's
     * cycles are charged once. */
    cpu.pc = 0x800040C0u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 10;
    cpu.downcount = 100;
    func_800040C0(&cpu);
    int leader_entry_ok = cpu.pc == 0x81234564u && cpu.gpr[3] == 14 &&
                          cpu.downcount == 95;
    if (!leader_entry_ok) {
        fprintf(stderr, "leader entry pc=%08X r3=%u downcount=%lld\n", cpu.pc,
                cpu.gpr[3], (long long)cpu.downcount);
    }

    cpu_free(&cpu);
    return !(integer_ok && memory_ok && direct_call_ok && depth_bound_ok &&
             parked_ok && midblock_ok && leader_entry_ok);
}
