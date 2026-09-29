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
DECL(80004500) DECL(80004700)

void func_80005000(CPUState*); void func_80006000(CPUState*);
void fn_80006014(CPUState*);
void func_80004600(CPUState*); void fn_80004608(CPUState*);
int fn_80006014_direct(CPUState*);

static void dispatch_pad_fn(CPUState* c) {
    if (c->pc >= FN_PAD_CHUNK + FN_PAD_LEAF_OFFSET && c->pc < FN_PAD_CHUNK + FN_PAD_COUNT * 4u)
        fn_80004608(c);
    else
        func_80004600(c);
}

/* The fn copy's dispatcher: converted range -> fn, rest -> chunk. */
static void dispatch_pair_fn(CPUState* c) {
    if (c->pc >= FN_PAIR_FN + FN_PAIR_LEAF_OFFSET && c->pc < FN_PAIR_FN + FN_PAIR_COUNT * 4u)
        fn_80006014(c);
    else
        func_80006000(c);
}

static const struct {
    Entry chunk, fn;
} entries[] = {
    {func_80004000, fn_80004000}, {func_80004100, fn_80004100},
    {func_80004200, fn_80004200}, {func_80004300, fn_80004300},
    {func_80004400, fn_80004400}, {func_80004500, fn_80004500},
    {func_80004700, fn_80004700},
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

/* Caller + converted leaf in one chunk vs the same pair as plain chunk code.
 * The copies sit at different addresses, so lr-derived values (lr, r10) are
 * not compared. */
static int check_pair(const char* what, u32 n, s64 per_trip) {
    static CPUState a, b;
    if (!a.ram && (!cpu_init(&a) || !cpu_init(&b)))
        return 0;
    cpu_reset(&a);
    cpu_reset(&b);
    a.pc = FN_PAIR_PLAIN;
    b.pc = FN_PAIR_FN;
    a.lr = b.lr = LR_SENTINEL;
    a.gpr[3] = b.gpr[3] = 1;
    a.gpr[4] = b.gpr[4] = n;
    a.msr = b.msr = 0x2000u;
    u32 ta = run(&a, func_80005000, per_trip);
    u32 tb = run(&b, dispatch_pair_fn, per_trip);
    int ok = a.gpr[3] == b.gpr[3] && a.ctr == b.ctr && a.cr == b.cr &&
             a.xer == b.xer && a.downcount == b.downcount && a.pc == b.pc &&
             a.exception == b.exception && ta == tb && a.gpr[3] == 1u + 2u * n + 1u;
    if (!ok)
        fprintf(stderr, "%s: r3 %u/%u ctr %u/%u downcount %lld/%lld pc %08X/%08X trips %u/%u\n",
                what, a.gpr[3], b.gpr[3], a.ctr, b.ctr, (long long)a.downcount,
                (long long)b.downcount, a.pc, b.pc, ta, tb);
    return ok;
}

void func_80007000(CPUState*); void func_80007100(CPUState*);
void func_80008000(CPUState*); void func_80008100(CPUState*);
void fn_80008000(CPUState*); void fn_80008010(CPUState*); void fn_80008034(CPUState*);
void fn_8000803C(CPUState*); void fn_80008044(CPUState*); void fn_80008064(CPUState*);

static void dispatch_calls_plain(CPUState* c) {
    if (c->pc >= FN_CALLS_PLAIN + FN_CALLS_G_OFFSET)
        func_80007100(c);
    else
        func_80007000(c);
}

static void dispatch_calls_fn(CPUState* c) {
    static void (*const fns[FN_CALLS_FN_COUNT])(CPUState*) = {
        fn_80008000, fn_80008010, fn_80008034, fn_8000803C, fn_80008044, fn_80008064,
    };
    u32 o = c->pc - FN_CALLS_FN;
    if (o >= FN_CALLS_G_OFFSET) {
        func_80008100(c);
        return;
    }
    for (u32 k = 0; k < FN_CALLS_FN_COUNT; k++)
        if (o >= fn_calls_fn_offsets[k][0] && o < fn_calls_fn_offsets[k][1]) {
            fns[k](c);
            return;
        }
    func_80008000(c);
}

/* Same words at two addresses: compare everything that does not hold an
 * address (r12, r30, r31 and intermediate lr values do). */
static int check_calls(const char* what, u32 entry_offset, u32 r4, u32 r5, s64 per_trip,
                       u32 want_r3) {
    static CPUState a, b;
    if (!a.ram && (!cpu_init(&a) || !cpu_init(&b)))
        return 0;
    cpu_reset(&a);
    cpu_reset(&b);
    a.pc = FN_CALLS_PLAIN + entry_offset;
    b.pc = FN_CALLS_FN + entry_offset;
    a.lr = b.lr = LR_SENTINEL;
    a.gpr[3] = b.gpr[3] = 1;
    a.gpr[4] = b.gpr[4] = r4;
    a.gpr[5] = b.gpr[5] = r5;
    a.msr = b.msr = 0x2000u;
    u32 ta = run(&a, dispatch_calls_plain, per_trip);
    u32 tb = run(&b, dispatch_calls_fn, per_trip);
    int ok = a.gpr[3] == b.gpr[3] && a.gpr[4] == b.gpr[4] && a.gpr[5] == b.gpr[5] &&
             a.ctr == b.ctr && a.cr == b.cr && a.xer == b.xer && a.lr == b.lr &&
             a.downcount == b.downcount && a.pc == b.pc && a.exception == b.exception &&
             a.direct_depth == 0 && b.direct_depth == 0 && ta == tb && a.gpr[3] == want_r3;
    if (!ok)
        fprintf(stderr, "calls/%s: r3 %u/%u (want %u) ctr %u/%u downcount %lld/%lld "
                "pc %08X/%08X trips %u/%u depth %u/%u\n", what, a.gpr[3], b.gpr[3], want_r3,
                a.ctr, b.ctr, (long long)a.downcount, (long long)b.downcount, a.pc, b.pc,
                ta, tb, (unsigned)a.direct_depth, (unsigned)b.direct_depth);
    return ok;
}

/* fn_X_direct contract: 1 when control reached the function's return
 * dispatch (its bclr), with ctx->pc the return address; 0 when the chunk code
 * would have returned to the dispatcher, with ctx->pc the resume point. */
static int check_direct_status(void) {
    static CPUState c;
    if (!c.ram && !cpu_init(&c))
        return 0;
    int ok = 1;
    cpu_reset(&c);
    c.lr = LR_SENTINEL;
    c.msr = 0x2000u;
    c.gpr[3] = 1;
    c.gpr[4] = 3;
    c.downcount = 100000;
    int status = fn_80006014_direct(&c);
    if (status != 1 || c.pc != LR_SENTINEL || c.gpr[3] != 7u) {
        fprintf(stderr, "direct_status/returns: status %d pc %08X r3 %u\n", status, c.pc,
                c.gpr[3]);
        ok = 0;
    }
    cpu_reset(&c);
    c.lr = LR_SENTINEL;
    c.msr = 0x2000u;
    c.gpr[3] = 1;
    c.gpr[4] = 1000000;
    c.downcount = 64;
    status = fn_80006014_direct(&c);
    if (status != 0 || c.pc < FN_PAIR_FN + FN_PAIR_LEAF_OFFSET ||
        c.pc >= FN_PAIR_FN + FN_PAIR_COUNT * 4u) {
        fprintf(stderr, "direct_status/budget_exit: status %d pc %08X\n", status, c.pc);
        ok = 0;
    }
    return ok;
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
    ok &= check(6, "budget_exit_resume", &budget);

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

    {
        /* Dispatcher entry at a leaf start the chunk CFG does not treat as a
         * leader (padding before it): cold path in both. */
        static CPUState a, b;
        if (!cpu_init(&a) || !cpu_init(&b))
            return 1;
        a.pc = b.pc = FN_PAD_CHUNK + FN_PAD_LEAF_OFFSET;
        a.lr = b.lr = LR_SENTINEL;
        a.msr = b.msr = 0x2000u;
        u32 ta = run(&a, func_80004600, 100000);
        u32 tb = run(&b, dispatch_pad_fn, 100000);
        ok &= same("pad_entry/cold_start", &a, &b, ta, tb);
    }
    ok &= check_pair("same_chunk_call", 3, 100000);
    ok &= check_pair("same_chunk_call_budget", 3000, 64);

    /* F: r3 = 1 + 2*r4 (T) + 1 + 5 (U) + 100*r5 (G) + 3 + 5 (F2->U) + 7 + 2*r4 (F4->T) */
    ok &= check_calls("F", FN_CALLS_F_OFFSET, 3, 2, 100000, 1u + 4u * 3u + 100u * 2u + 21u);
    ok &= check_calls("F budget 64", FN_CALLS_F_OFFSET, 3000, 2000, 64,
                      1u + 4u * 3000u + 100u * 2000u + 21u);
    ok &= check_calls("F budget 16", FN_CALLS_F_OFFSET, 300, 200, 16,
                      1u + 4u * 300u + 100u * 200u + 21u);
    /* Every trip starts past the loop budget (256): the chunk's pre-call
     * budget check on the backward bl T, and every other budget exit, fire
     * on each trip, so progress is one block per trip. */
    ok &= check_calls("F exhausted", FN_CALLS_F_OFFSET, 3, 2, -300,
                      1u + 4u * 3u + 100u * 2u + 21u);
    /* F3: bctrl to G: r3 = 1 + 100*r5 */
    ok &= check_calls("F3 bctrl", FN_CALLS_F3_OFFSET, 3, 2, 100000, 1u + 100u * 2u);
    ok &= check_calls("F3 bctrl budget 16", FN_CALLS_F3_OFFSET, 3, 2000, 16, 1u + 100u * 2000u);

    ok &= check_direct_status();

    if (!ok)
        fprintf(stderr, "fn differential execution FAILED\n");
    return ok ? 0 : 1;
}
