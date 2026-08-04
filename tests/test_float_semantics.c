// Measures what the inlined float form drops relative to the runtime helpers.
//
// The claim this PR rests on is that emitting
//
//     ctx->fpr[d] = (f64)(f32)(ctx->fpr[a] * ctx->fpr[c]);
//
// produces a plausible value while silently dropping four things the Gekko
// does. "Plausible" is the problem: none of it shows up in the generated source
// and only one of the four is visible on screen. So rather than assert the
// helpers are correct, this counts how often each arm actually diverges, and
// prints the counts. A reviewer can run it and read the numbers off.

#include <math.h>
#include <stdio.h>
#include <string.h>

#include "../src/cpu/cpu.h"

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        failures++; \
    } \
} while (0)

// Arm A: exactly what the C backend emitted before this change.
static f64 inline_fmuls(f64 a, f64 c) {
    return (f64)(f32)(a * c);
}

// A fixed LCG rather than rand(), so the counts below are the same number on
// every machine and every run and can be quoted.
static u32 lcg_state = 0x13579BDFu;
static u32 lcg_next(void) {
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return lcg_state;
}

// A value that came from lfs: exactly single-representable, so its low 29
// mantissa bits are already zero.
static f64 sample_single(void) {
    u32 bits = (lcg_next() & 0x807FFFFFu) | (((lcg_next() % 40u) + 105u) << 23);
    f32 value;
    memcpy(&value, &bits, sizeof(value));
    return (f64)value;
}

// A value that came from lfd or from double-precision arithmetic: a full 52-bit
// mantissa, in the same exponent range.
static f64 sample_double(void) {
    u64 bits = ((u64)(lcg_next() & 0x000FFFFFu) << 32) | lcg_next();
    bits |= (u64)((lcg_next() % 40u) + 1002u) << 52;
    f64 value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static u32 count_divergent(CPUState* cpu, f64 (*sample_c)(void), u32 trials) {
    u32 differing = 0;
    for (u32 i = 0; i < trials; ++i) {
        f64 a = sample_single();
        f64 c = sample_c();
        cpu->fpr[1] = a;
        cpu->fpr[2] = c;
        ppc_fmuls(cpu, 0, 1, 2);
        if (cpu->fpr[0] != inline_fmuls(a, c))
            differing++;
    }
    return differing;
}

int main(void) {
    CPUState cpu;
    if (!cpu_init(&cpu))
        return 1;

    // 1. The 25-bit C operand. The Gekko truncates a multiply's C operand to a
    //    25-bit mantissa; the inline form multiplies in full f64.
    //
    //    Which operands reach fmuls decides whether this is visible at all. A C
    //    operand that came from lfs is already single-representable, so its low
    //    29 mantissa bits are zero and the truncation is a no-op -- those
    //    multiplies agree exactly. Only a C operand carrying more than 25
    //    mantissa bits, from lfd or from double-precision arithmetic, diverges.
    //    Reporting both makes the boundary explicit rather than leaving the
    //    impression that every fmuls is wrong.
    const u32 trials = 100000u;
    u32 diff_single = count_divergent(&cpu, sample_single, trials);
    u32 diff_double = count_divergent(&cpu, sample_double, trials);
    printf("25-bit C operand : C from lfs   %u/%u differ (%.1f%%)\n",
           diff_single, trials, 100.0 * (double)diff_single / (double)trials);
    printf("                 : C full f64   %u/%u differ (%.1f%%)\n",
           diff_double, trials, 100.0 * (double)diff_double / (double)trials);
    CHECK(diff_single == 0,
          "a single-representable C operand should survive truncation intact");
    CHECK(diff_double > 0,
          "a full-mantissa C operand should diverge from the inline form");

    // 2. ps1. A single-precision result occupies both halves of a paired-single
    //    register, and the ps_* instructions read ps1. Poison it, then check
    //    which arm updates it. This is the one that reaches the screen.
    const f64 poison = -12345.678;
    cpu.fpr[1] = 3.5;
    cpu.fpr[2] = 1.25;
    cpu.ps1[0] = poison;
    cpu.fpr[0] = inline_fmuls(cpu.fpr[1], cpu.fpr[2]);  // arm A
    int inline_left_ps1_stale = cpu.ps1[0] == poison;

    cpu.ps1[0] = poison;
    ppc_fmuls(&cpu, 0, 1, 2);                            // arm C
    int helper_wrote_ps1 = cpu.ps1[0] == cpu.fpr[0];

    printf("ps1              : inline leaves it stale=%s, helper writes it=%s\n",
           inline_left_ps1_stale ? "yes" : "no",
           helper_wrote_ps1 ? "yes" : "no");
    CHECK(inline_left_ps1_stale, "the inline form should leave ps1 untouched");
    CHECK(helper_wrote_ps1, "ppc_fmuls should mirror the result into ps1");

    // 3. FPRF. Never updated by the inline form.
    cpu.fpscr = 0;
    cpu.fpr[0] = inline_fmuls(cpu.fpr[1], cpu.fpr[2]);
    u32 fprf_after_inline = (cpu.fpscr >> 12) & 0x1Fu;
    cpu.fpscr = 0;
    ppc_fmuls(&cpu, 0, 1, 2);
    u32 fprf_after_helper = (cpu.fpscr >> 12) & 0x1Fu;
    printf("FPRF             : inline 0x%02X, helper 0x%02X\n",
           fprf_after_inline, fprf_after_helper);
    CHECK(fprf_after_inline == 0, "the inline form should leave FPRF clear");
    CHECK(fprf_after_helper != 0, "ppc_fmuls should classify its result");

    // 4. Invalid-operation gating. emit_fcompare dropped the `ordered` flag, so
    //    fcmpo and fcmpu compiled identically even though only fcmpo signals on
    //    a NaN operand. VXVC is bit 0x00080000.
    const f64 quiet_nan = (f64)NAN;
    cpu.fpscr = 0;
    ppc_fcmp(&cpu, 0, quiet_nan, 1.0, false);   // fcmpu
    u32 vxvc_unordered = cpu.fpscr & 0x00080000u;
    cpu.fpscr = 0;
    ppc_fcmp(&cpu, 0, quiet_nan, 1.0, true);    // fcmpo
    u32 vxvc_ordered = cpu.fpscr & 0x00080000u;
    printf("fcmpo vs fcmpu   : VXVC ordered=0x%08X unordered=0x%08X\n",
           vxvc_ordered, vxvc_unordered);
    CHECK(vxvc_unordered == 0, "fcmpu should not signal on a quiet NaN");
    CHECK(vxvc_ordered != 0, "fcmpo should signal on a quiet NaN");

    cpu_free(&cpu);
    return failures != 0;
}
