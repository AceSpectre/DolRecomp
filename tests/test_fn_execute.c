/* Differential execution: each program runs once through its chunk code
 * (func_<addr>) and once through its converted function (fn_<addr>), both
 * driven by the same dispatcher loop from identical state. Exact mode must
 * leave identical architectural state, memory and dispatcher trip count. */
#include <stdio.h>
#include <string.h>

#include "../src/cpu/cpu.h"
#include "fn_programs.h"

typedef void (*Entry)(CPUState*);

#define DECL(addr) void func_##addr(CPUState*); void fn_##addr(CPUState*);
DECL(80004000) DECL(80004100) DECL(80004200) DECL(80004300) DECL(80004400)
DECL(80004500)

static const struct {
    Entry chunk, fn;
} entries[] = {
    {func_80004000, fn_80004000}, {func_80004100, fn_80004100},
    {func_80004200, fn_80004200}, {func_80004300, fn_80004300},
    {func_80004400, fn_80004400}, {func_80004500, fn_80004500},
};

#define LR_SENTINEL 0x81234564u
#define DATA 0x80001000u

typedef struct {
    u32 r3, r4, r5, r6, r7;
    f64 f1, f2;
    bool fp_enabled;
    s64 downcount_per_trip;
    u32 entry_pc; /* 0: program start */
} Scenario;

static void seed(CPUState* c, u32 prog_addr, const Scenario* s) {
    c->pc = s->entry_pc ? s->entry_pc : prog_addr;
    c->lr = LR_SENTINEL;
    c->gpr[3] = s->r3;
    c->gpr[4] = s->r4;
    c->gpr[5] = s->r5;
    c->gpr[6] = s->r6;
    c->gpr[7] = s->r7;
    c->fpr[1] = c->ps1[1] = s->f1;
    c->fpr[2] = c->ps1[2] = s->f2;
    c->msr = s->fp_enabled ? 0x2000u : 0u;
    c->hid2 = PPC_HID2_PSE | PPC_HID2_LSQE;
    c->cr = 0x12345678u;
    c->xer = 0x80000000u;
    for (u32 i = 0; i < 64; i++)
        mem_write32(c, DATA + i * 4u, i == 0 ? 0x3F800000u : i == 1 ? 0x40000000u
                                                            : 0x01010101u * i);
}

static u32 run(CPUState* c, Entry entry, s64 per_trip) {
    u32 trips = 0;
    while (c->pc != LR_SENTINEL && !c->exception && trips < 200000) {
        c->downcount = per_trip;
        entry(c);
        trips++;
    }
    return trips;
}

static int same(const char* what, CPUState* a, CPUState* b, u32 ta, u32 tb) {
    int ok = 1;
#define CMP(field) if (memcmp(&a->field, &b->field, sizeof(a->field))) { \
        fprintf(stderr, "%s: " #field " differs\n", what); ok = 0; }
    CMP(gpr) CMP(fpr) CMP(ps1) CMP(pc) CMP(lr) CMP(ctr) CMP(cr) CMP(xer)
    CMP(fpscr) CMP(msr) CMP(srr0) CMP(srr1) CMP(exception) CMP(downcount)
#undef CMP
    for (u32 i = 0; i < 64; i++)
        if (mem_read32(a, DATA + i * 4u) != mem_read32(b, DATA + i * 4u)) {
            fprintf(stderr, "%s: memory word %u differs\n", what, i);
            ok = 0;
            break;
        }
    if (ta != tb) {
        fprintf(stderr, "%s: dispatcher trips %u vs %u\n", what, ta, tb);
        ok = 0;
    }
    return ok;
}

static int check(u32 prog, const char* what, const Scenario* s) {
    static CPUState a, b;
    if (!a.ram && (!cpu_init(&a) || !cpu_init(&b)))
        return 0;
    cpu_reset(&a);
    cpu_reset(&b);
    seed(&a, fn_programs[prog].addr, s);
    seed(&b, fn_programs[prog].addr, s);
    u32 ta = run(&a, entries[prog].chunk, s->downcount_per_trip);
    u32 tb = run(&b, entries[prog].fn, s->downcount_per_trip);
    char label[96];
    snprintf(label, sizeof(label), "%s/%s", fn_programs[prog].name, what);
    return same(label, &a, &b, ta, tb);
}

int main(void) {
    int ok = 1;
    const Scenario plain = {7, 10, DATA, DATA + 0x80, 5, 1.5, -2.25, true, 100000, 0};
    for (u32 p = 0; p < FN_PROGRAM_COUNT; p++)
        ok &= check(p, "plain", &plain);

    /* budget_exit_resume: a long loop under a tiny per-trip budget exits at
     * the backedge and is resumed by the dispatcher at the loop header. */
    const Scenario budget = {0, 5000, DATA, DATA + 0x80, 20, 1.0, 2.0, true, 64, 0};
    ok &= check(0, "budget_exit_resume", &budget);
    ok &= check(1, "budget_exit_resume", &budget);

    /* fp_unavailable_exit: MSR[FP] clear, the first FP op raises the
     * exception; locals must be flushed and the vector pc left alone. */
    const Scenario nofp = {7, 10, DATA, DATA + 0x80, 5, 1.5, -2.25, false, 100000, 0};
    ok &= check(3, "fp_unavailable_exit", &nofp);

    /* fcmp both ways: taken and not taken */
    const Scenario gt = {7, 10, DATA, DATA + 0x80, 5, 3.0, -2.25, true, 100000, 0};
    ok &= check(5, "fcmp_not_less", &gt);

    /* mid-function dispatcher entry that is not a resume label */
    const Scenario mid = {7, 10, DATA, DATA + 0x80, 5, 1.5, -2.25, true, 100000,
                          0x80004208u};
    ok &= check(2, "odd_entry_falls_back", &mid);

    if (!ok)
        fprintf(stderr, "fn differential execution FAILED\n");
    return ok ? 0 : 1;
}
