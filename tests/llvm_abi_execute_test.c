#include "cpu/cpu.h"

#include <stdio.h>

void func_80004000(CPUState *cpu);

static bool block_callee(CPUState *cpu, u32 address) {
  if (address != PPC_HOST_CALL_NATIVE_REGION_QUERY)
    return false;
  bool blocked =
      0x80004100u >= cpu->external_addr && 0x80004100u < cpu->external_value;
  cpu->external_rid = PPC_NATIVE_REGION_QUERY_HANDLED;
  return blocked;
}

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__, #x);    \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  CPUState cpu;
  CHECK(cpu_init(&cpu));
  cpu.pc = 0x80004000u;
  cpu.lr = 0x81234567u;
  cpu.gpr[3] = 10u;
  cpu.gpr[4] = 20u;
  cpu.downcount = 1000;
  func_80004000(&cpu);
  CHECK(cpu.gpr[3] == 11u);
  CHECK(cpu.gpr[4] == 22u);
  CHECK(cpu.pc == 0x81234564u);
  CHECK(cpu.downcount == 992);

  cpu.pc = 0x80004000u;
  cpu.lr = 0x81234567u;
  cpu.gpr[3] = 40u;
  cpu.gpr[4] = 20u;
  cpu.exception = 0;
  cpu.downcount = 1000;
  cpu.host_call = block_callee;
  func_80004000(&cpu);
  CHECK(cpu.pc == 0x80004100u);
  CHECK(cpu.lr == 0x8000400Cu);
  CHECK(cpu.gpr[3] == 41u);
  CHECK(cpu.gpr[4] == 20u);
  cpu_free(&cpu);
  return 0;
}
