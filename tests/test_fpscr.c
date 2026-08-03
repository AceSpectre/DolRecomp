#include <math.h>
#include <stdio.h>

#include "../src/cpu/cpu.h"

#define FPCC(cpu) (((cpu).fpscr >> 12) & 0xFu)
#define FPRF(cpu) (((cpu).fpscr >> 12) & 0x1Fu)
#define CRF(cpu, n) (((cpu).cr >> (4u * (7u - (n)))) & 0xFu)

static int failures = 0;

#define CHECK(cond, fmt, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        failures++; \
    } \
} while (0)

int main(void) {
    CPUState cpu;
    if (!cpu_init(&cpu))
        return 1;

    // Each compare must replace FPCC, not accumulate into it. Consecutive
    // compares with different results are the case that exposes an OR.
    ppc_fcmp(&cpu, 0, 1.0, 2.0, false);
    CHECK(FPCC(cpu) == 0x8u, "less-than FPCC got %X", FPCC(cpu));
    CHECK(CRF(cpu, 0) == 0x8u, "less-than CR0 got %X", CRF(cpu, 0));

    ppc_fcmp(&cpu, 0, 2.0, 2.0, false);
    CHECK(FPCC(cpu) == 0x2u, "equal after less-than FPCC got %X", FPCC(cpu));
    CHECK(CRF(cpu, 0) == 0x2u, "equal after less-than CR0 got %X", CRF(cpu, 0));

    ppc_fcmp(&cpu, 3, 3.0, 2.0, false);
    CHECK(FPCC(cpu) == 0x4u, "greater-than FPCC got %X", FPCC(cpu));
    CHECK(CRF(cpu, 3) == 0x4u, "greater-than CR3 got %X", CRF(cpu, 3));

    ppc_fcmp(&cpu, 1, (f64)NAN, 1.0, false);
    CHECK(FPCC(cpu) == 0x1u, "unordered FPCC got %X", FPCC(cpu));
    CHECK(CRF(cpu, 1) == 0x1u, "unordered CR1 got %X", CRF(cpu, 1));

    // The fifth FPRF bit is the C class bit; a compare does not touch it.
    cpu.fpscr |= 0x1u << 16;
    ppc_fcmp(&cpu, 0, 1.0, 2.0, false);
    CHECK(FPRF(cpu) == 0x18u, "compare should preserve C, FPRF got %X", FPRF(cpu));

    cpu_free(&cpu);
    return failures != 0;
}
