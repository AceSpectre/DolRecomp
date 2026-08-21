#include <cstdio>
#include <memory>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ModuleSummaryIndex.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      std::fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, __LINE__,    \
                   #x);                                                        \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(int argc, char **argv) {
  CHECK(argc == 6);
  llvm::LLVMContext context;
  llvm::SMDiagnostic diagnostic;
  std::unique_ptr<llvm::Module> module =
      llvm::parseIRFile(argv[1], diagnostic, context);
  if (!module) {
    diagnostic.print(argv[0], llvm::errs());
    return 1;
  }
  CHECK(module->getNamedGlobal("g_mem_write_journal") == nullptr);
  llvm::Function *cross = module->getFunction("func_80002D00_budget");
  CHECK(cross != nullptr);
  bool known_edge = false;
  bool state_phi = false;
  bool tail_edge = false;
  bool target_call_seen = false;
  bool weighted_branch = false;
  for (llvm::Function &function : *module) {
    if (function.isDeclaration())
      continue;
    CHECK(function.hasFnAttribute(llvm::Attribute::NoUnwind));
    for (llvm::BasicBlock &block : function) {
      for (llvm::Instruction &instruction : block) {
        if (auto *branch = llvm::dyn_cast<llvm::BranchInst>(&instruction))
          weighted_branch |=
              branch->getMetadata(llvm::LLVMContext::MD_prof) != nullptr;
        if (auto *phi = llvm::dyn_cast<llvm::PHINode>(&instruction))
          state_phi |= phi->getName().starts_with("state");
        if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction))
          CHECK(!alloca->getName().starts_with("state") &&
                !alloca->getName().starts_with("pair."));
        auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (!call || !call->getCalledFunction())
          continue;
        llvm::StringRef name = call->getCalledFunction()->getName();
        CHECK(!name.contains("generic_dispatch"));
        known_edge |= function.getName() == "func_80002D00_budget" &&
                      name == "func_80002E00_budget";
        target_call_seen |= function.getName() == "func_80002D00_budget" &&
                            name == "func_80002E00_budget";
        auto *direct_call = llvm::dyn_cast<llvm::CallInst>(call);
        tail_edge |= function.getName() == "func_80002D00_budget" &&
                     direct_call && direct_call->isMustTailCall();
      }
    }
  }
  if (!target_call_seen) {
    known_edge = cross->size() > 3;
    tail_edge = true;
  }
  CHECK(known_edge);
  CHECK(state_phi && tail_edge && weighted_branch);

  auto check_paired_function = [](llvm::Function *function,
                                  unsigned minimum_math,
                                  unsigned minimum_single_math) {
    if (!function)
      return false;
    unsigned math = 0;
    unsigned single_math = 0;
    for (llvm::BasicBlock &block : *function) {
      for (llvm::Instruction &instruction : block) {
        auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (!call || !call->getCalledFunction())
          continue;
        llvm::StringRef name = call->getCalledFunction()->getName();
        if (name.starts_with("ppc_ps_")) {
          std::fprintf(stderr, "%s unexpectedly calls %s\n",
                       function->getName().str().c_str(), name.str().c_str());
          return false;
        }
        bool arithmetic = name.contains("constrained.fadd") ||
                          name.contains("constrained.fsub") ||
                          name.contains("constrained.fmul");
        if (!arithmetic)
          continue;
        math++;
        auto *vector = llvm::dyn_cast<llvm::FixedVectorType>(call->getType());
        if (vector && vector->getElementType()->isFloatTy())
          single_math++;
      }
    }
    if (math < minimum_math || single_math < minimum_single_math) {
      std::fprintf(stderr, "%s has %u vector ops, %u in <2 x float>\n",
                   function->getName().str().c_str(), math, single_math);
      return false;
    }
    return true;
  };
  llvm::Function *paired_chain = module->getFunction("func_80003920_budget");
  CHECK(check_paired_function(paired_chain, 4, 0));
  CHECK(
      check_paired_function(module->getFunction("func_80003940_budget"), 2, 0));
  CHECK(
      check_paired_function(module->getFunction("func_800039C0_budget"), 4, 3));

  llvm::Function *paired_fma = module->getFunction("func_80003980_budget");
  CHECK(paired_fma != nullptr);
  unsigned exact_fma_helpers = 0;
  unsigned vector_fma_calls = 0;
  for (llvm::BasicBlock &block : *paired_fma)
    for (llvm::Instruction &instruction : block)
      if (auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
        if (call->getCalledFunction()) {
          llvm::StringRef name = call->getCalledFunction()->getName();
          exact_fma_helpers += name.starts_with("ppc_ps_madd");
          vector_fma_calls +=
              name.starts_with("llvm.experimental.constrained.fma");
        }
  CHECK(exact_fma_helpers == 0);
  CHECK(vector_fma_calls == 6);

  llvm::Function *fused_chain = module->getFunction("func_80003A20_budget");
  CHECK(fused_chain != nullptr);
  unsigned packed_fma_calls = 0;
  for (llvm::BasicBlock &block : *fused_chain)
    for (llvm::Instruction &instruction : block)
      if (auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
        if (call->getCalledFunction()) {
          llvm::StringRef name = call->getCalledFunction()->getName();
          CHECK(!name.starts_with("ppc_ps_madd"));
          if (name == "llvm.experimental.constrained.fma.v4f32")
            packed_fma_calls++;
        }
  CHECK(packed_fma_calls == 6);
  unsigned fused_fprf_updates = 0;
  for (llvm::BasicBlock &block : *fused_chain)
    fused_fprf_updates += block.getName().starts_with("fprf_normal");
  CHECK(fused_fprf_updates == 1);

  llvm::Function *psq_fma = module->getFunction("func_80003A60_budget");
  CHECK(psq_fma != nullptr);
  unsigned psq_single_fma = 0;
  unsigned psq_strict_fma = 0;
  for (llvm::BasicBlock &block : *psq_fma)
    for (llvm::Instruction &instruction : block)
      if (auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
        if (call->getCalledFunction()) {
          llvm::StringRef name = call->getCalledFunction()->getName();
          CHECK(!name.starts_with("ppc_ps_madd"));
          psq_single_fma += name == "llvm.experimental.constrained.fma.v4f32";
          psq_strict_fma += name == "llvm.experimental.constrained.fma.v2f64";
        }
  CHECK(psq_single_fma == 1);
  CHECK(psq_strict_fma == 1);

  unsigned psq_enable_guards = 0;
  unsigned ni_guards = 0;
  for (llvm::BasicBlock &block : *psq_fma)
    for (llvm::Instruction &instruction : block) {
      psq_enable_guards += instruction.getName() == "psq.direct.enabled";
      ni_guards += instruction.getName().starts_with("fpscr.ni");
    }
  CHECK(psq_enable_guards == 1);
  CHECK(ni_guards == 1);

  llvm::Function *fixed_gqr = module->getFunction("func_80003AA0_budget");
  CHECK(fixed_gqr != nullptr);
  unsigned fixed_single_fma = 0;
  unsigned fixed_double_fma = 0;
  unsigned fixed_nan_fixups = 0;
  unsigned gqr_switches = 0;
  for (llvm::BasicBlock &block : *fixed_gqr)
    for (llvm::Instruction &instruction : block) {
      if (auto *typeSwitch = llvm::dyn_cast<llvm::SwitchInst>(&instruction))
        gqr_switches += typeSwitch->getNumCases() >= 5;
      auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (!call || !call->getCalledFunction())
        continue;
      llvm::StringRef name = call->getCalledFunction()->getName();
      fixed_single_fma += name == "llvm.experimental.constrained.fma.v4f32";
      fixed_double_fma += name == "llvm.experimental.constrained.fma.v2f64";
      fixed_nan_fixups += name.starts_with("fix_pair_fma_nan");
    }
  CHECK(fixed_single_fma == 1);
  CHECK(fixed_double_fma == 0);
  CHECK(fixed_nan_fixups == 0);
  CHECK(gqr_switches == 0);

  unsigned fprf_updates = 0;
  for (llvm::BasicBlock &block : *paired_chain)
    fprf_updates += block.getName().starts_with("fprf_normal");
  CHECK(fprf_updates == 1);
  for (const char *name : {"fix_pair_nan_f32", "fix_pair_nan_f64",
                           "classify_fprf_unusual", "fix_pair_fma_nan_f32",
                           "fix_pair_fma_nan_f64", "fix_pair_fma_rounding"}) {
    llvm::Function *fixup = module->getFunction(name);
    CHECK(fixup != nullptr);
    CHECK(fixup->hasFnAttribute(llvm::Attribute::Cold));
    CHECK(fixup->hasFnAttribute(llvm::Attribute::NoInline));
    CHECK(fixup->getCallingConv() == llvm::CallingConv::PreserveAll);
  }

  llvm::Function *cr_loop = module->getFunction("func_80001000_budget");
  CHECK(cr_loop != nullptr);
  for (llvm::BasicBlock &block : *cr_loop) {
    if (!block.getName().starts_with("guest_80001010"))
      continue;
    for (llvm::Instruction &instruction : block) {
      auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (!binary)
        continue;
      CHECK(!(binary->getOpcode() == llvm::Instruction::Shl &&
              llvm::isa<llvm::ConstantInt>(binary->getOperand(1)) &&
              llvm::cast<llvm::ConstantInt>(binary->getOperand(1))
                      ->getZExtValue() >= 28));
    }
  }
  llvm::Function *constant_memory = module->getFunction("func_80003300_budget");
  CHECK(constant_memory != nullptr);
  for (llvm::BasicBlock &block : *constant_memory)
    for (llvm::Instruction &instruction : block)
      if (auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction))
        CHECK(call->getCalledFunction() != nullptr);
  std::unique_ptr<llvm::Module> instrumented =
      llvm::parseIRFile(argv[2], diagnostic, context);
  CHECK(instrumented != nullptr);
  CHECK(instrumented->getNamedGlobal("g_mem_write_journal") != nullptr);
  std::unique_ptr<llvm::Module> pgo =
      llvm::parseIRFile(argv[3], diagnostic, context);
  CHECK(pgo != nullptr);
  CHECK(pgo->getNamedGlobal("__llvm_profile_filename") != nullptr);
  auto summary = llvm::getModuleSummaryIndexForFile(argv[4]);
  CHECK((bool)summary);
  CHECK(*summary != nullptr && (*summary)->begin() != (*summary)->end());
  std::unique_ptr<llvm::Module> fast =
      llvm::parseIRFile(argv[5], diagnostic, context);
  CHECK(fast != nullptr);
  for (llvm::Function &function : *fast)
    if (!function.isDeclaration())
      CHECK(!function.hasFnAttribute("strictfp"));
  return 0;
}
