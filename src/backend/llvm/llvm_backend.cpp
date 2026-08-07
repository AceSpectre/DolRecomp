#include "backend/llvm/llvm_backend.h"
#include "backend/llvm/llvm_function_emitter.h"

#include <memory>
#include <optional>
#include <string>
#include <system_error>

#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/IR/PassInstrumentation.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Config/llvm-config.h>

#include <cstdlib>
#include <cstring>

namespace {

using namespace llvm;

// Shared by emission, cache hashing and resume validation.
static std::string resolveTriple(const char *requested) {
  return requested && requested[0] ? std::string(requested)
                                   : llvm::sys::getDefaultTargetTriple();
}

// Everything below feeds both codegen and the object cache key. Changing any of
// it must invalidate cached objects, so keep them named rather than inline: the
// fingerprint is built from these same constants, and an edit that misses the
// key produces a build that silently reuses objects from the old settings and
// reports them as a result.
static constexpr const char *kTargetCPU = "generic";
static constexpr const char *kTargetFeatures = "";

// instcombine's fixpoint check is a self-diagnostic for the pass, not a
// correctness property of the IR. Recompiled Gekko functions contain long
// straight-line integer and condition-flag sequences that can still be changing
// after one iteration, which makes the pass call report_fatal_error and take the
// whole recompilation down. Suppressing the check leaves the optimization
// itself intact.
static constexpr const char *kPassPipeline =
    "function(mem2reg,early-cse<memssa>,instcombine<no-verify-fixpoint>,"
    "simplifycfg,sccp,"
    "correlated-propagation,jump-threading,gvn,dse,adce,loop-simplify,"
    "loop-rotate,loop-mssa(licm),loop-vectorize,slp-vectorizer,vector-"
    "combine,"
    "tailcallelim),cgscc(inline),ipsccp,globaldce";

static CodeGenOptLevel codegenLevel(int level) {
  if (level <= 0)
    return CodeGenOptLevel::None;
  if (level == 1)
    return CodeGenOptLevel::Less;
  if (level == 2)
    return CodeGenOptLevel::Default;
  return CodeGenOptLevel::Aggressive;
}

static TargetMachine *targetMachine(const Target *target,
                                    const std::string &tripleName, int opt) {
  static thread_local std::string cachedTriple;
  static thread_local int cachedOpt = -1;
  static thread_local std::unique_ptr<TargetMachine> cachedMachine;
  if (!cachedMachine || cachedTriple != tripleName || cachedOpt != opt) {
    TargetOptions options;
    cachedMachine.reset(target->createTargetMachine(
        tripleName, kTargetCPU, kTargetFeatures, options, Reloc::PIC_,
        std::nullopt, codegenLevel(opt)));
    cachedTriple = tripleName;
    cachedOpt = opt;
  }
  return cachedMachine.get();
}

} // namespace

extern "C" bool dolllvm_emit_object(const DolIRModule *source,
                                    const char *object_path,
                                    const DolLLVMOptions *options,
                                    FILE *diagnostics) {
  if (!source || !object_path || !diagnostics)
    return false;
  static bool initialized = [] {
    llvm::InitializeNativeTarget();
    llvm::InitializeNativeTargetAsmPrinter();
    llvm::InitializeNativeTargetAsmParser();
    return true;
  }();
  (void)initialized;

  int opt = options ? options->optimization_level : 2;
  std::string tripleName =
      resolveTriple(options ? options->target_triple : nullptr);
  const llvm::Triple triple(tripleName);
  if (triple.getArch() != llvm::Triple::x86_64 ||
      (!triple.isOSLinux() && !triple.isOSWindows())) {
    fprintf(
        diagnostics,
        "dolllvm: supported production targets are x86-64 Linux and Windows\n");
    return false;
  }

  std::string error;
  const llvm::Target *target =
      llvm::TargetRegistry::lookupTarget(tripleName, error);
  if (!target) {
    fprintf(diagnostics, "dolllvm: %s\n", error.c_str());
    return false;
  }
  llvm::TargetMachine *machine = targetMachine(target, tripleName, opt);
  if (!machine) {
    fprintf(diagnostics, "dolllvm: failed to create target machine\n");
    return false;
  }

  llvm::LLVMContext context;
  llvm::Module module("dolrecomp_native", context);
  module.setTargetTriple(tripleName);
  module.setDataLayout(machine->createDataLayout());
  std::string diagnosticText;
  llvm::raw_string_ostream diagnosticStream(diagnosticText);
  for (u32 i = 0; i < source->function_count; i++) {
    dolllvm::FunctionEmitter emitter(
        context, module, source->functions[i],
        options ? options->function_ranges : nullptr,
        options ? options->function_range_count : 0);
    if (!emitter.emit(diagnosticStream)) {
      diagnosticStream.flush();
      fprintf(diagnostics, "%s", diagnosticText.c_str());
      return false;
    }
  }
  if (llvm::verifyModule(module, &diagnosticStream)) {
    diagnosticStream.flush();
    fprintf(diagnostics, "%s", diagnosticText.c_str());
    return false;
  }

  if (opt > 0) {
    llvm::LoopAnalysisManager lam;
    llvm::FunctionAnalysisManager fam;
    llvm::CGSCCAnalysisManager cgam;
    llvm::ModuleAnalysisManager mam;

    // DOLRECOMP_LLVM_TRACE_PASSES names the last pass and IR unit to start.
    // Without it an optimizer that fails to converge is indistinguishable from
    // one that is merely slow: the historical instcombine hang on this title
    // spun for 49 minutes at 1.00 core with nothing identifying the function.
    // Each line is flushed, so the last line printed is where it stopped.
    llvm::PassInstrumentationCallbacks callbacks;
    const bool tracePasses = getenv("DOLRECOMP_LLVM_TRACE_PASSES") != nullptr;
    if (tracePasses) {
      callbacks.registerBeforeNonSkippedPassCallback(
          [](llvm::StringRef pass, llvm::Any ir) {
            // Any holds a pointer to the IR unit, so any_cast<const T *> on
            // the Any* yields const T *const *.
            std::string unit = "<unknown>";
            const llvm::Function *const *fn =
                llvm::any_cast<const llvm::Function *>(&ir);
            const llvm::Module *const *mod =
                llvm::any_cast<const llvm::Module *>(&ir);
            if (fn && *fn)
              unit = (*fn)->getName().str();
            else if (mod && *mod)
              unit = (*mod)->getName().str();
            fprintf(stderr, "dolllvm: pass %s on %s\n", pass.str().c_str(),
                    unit.c_str());
            fflush(stderr);
          });
    }
    llvm::PassBuilder passBuilder(machine, llvm::PipelineTuningOptions(),
                                  std::nullopt,
                                  tracePasses ? &callbacks : nullptr);
    passBuilder.registerModuleAnalyses(mam);
    passBuilder.registerCGSCCAnalyses(cgam);
    passBuilder.registerFunctionAnalyses(fam);
    passBuilder.registerLoopAnalyses(lam);
    passBuilder.crossRegisterProxies(lam, fam, cgam, mam);
    llvm::ModulePassManager passes;
    if (llvm::Error error =
            passBuilder.parsePassPipeline(passes, kPassPipeline)) {
      fprintf(diagnostics,
              "dolllvm: cannot construct optimization pipeline: %s\n",
              llvm::toString(std::move(error)).c_str());
      return false;
    }
    passes.run(module, mam);
  }
  if (llvm::verifyModule(module, &diagnosticStream)) {
    diagnosticStream.flush();
    fprintf(diagnostics, "%s", diagnosticText.c_str());
    return false;
  }

  if (options && options->emit_ir && options->ir_path) {
    std::error_code irError;
    llvm::raw_fd_ostream irFile(options->ir_path, irError,
                                llvm::sys::fs::OF_Text);
    if (irError) {
      fprintf(diagnostics, "dolllvm: cannot write IR: %s\n",
              irError.message().c_str());
      return false;
    }
    module.print(irFile, nullptr);
  }

  std::error_code objectError;
  llvm::raw_fd_ostream objectFile(object_path, objectError,
                                  llvm::sys::fs::OF_None);
  if (objectError) {
    fprintf(diagnostics, "dolllvm: cannot write object: %s\n",
            objectError.message().c_str());
    return false;
  }
  llvm::legacy::PassManager codegen;
  if (machine->addPassesToEmitFile(codegen, objectFile, nullptr,
                                   llvm::CodeGenFileType::ObjectFile)) {
    fprintf(diagnostics, "dolllvm: target cannot emit objects\n");
    return false;
  }
  codegen.run(module);
  objectFile.flush();
  return true;
}

extern "C" bool dolllvm_effective_triple(const char *requested, char *out,
                                         size_t size) {
  if (!out || size == 0)
    return false;
  const std::string triple = resolveTriple(requested);
  if (triple.size() + 1 > size)
    return false;
  memcpy(out, triple.c_str(), triple.size() + 1);
  return true;
}

extern "C" bool dolllvm_object_matches_triple(const char *path,
                                              const char *requested) {
  FILE *file = fopen(path, "rb");
  if (!file)
    return false;
  unsigned char magic[4] = {0, 0, 0, 0};
  const size_t read = fread(magic, 1, sizeof(magic), file);
  fclose(file);
  if (read != sizeof(magic))
    return false;

  const llvm::Triple triple(resolveTriple(requested));
  if (triple.isOSBinFormatCOFF())
    // IMAGE_FILE_MACHINE_AMD64, little-endian, at offset 0 of a COFF object.
    return magic[0] == 0x64 && magic[1] == 0x86;
  if (triple.isOSBinFormatMachO())
    return magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED &&
           magic[3] == 0xFE;
  return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' &&
         magic[3] == 'F';
}

extern "C" bool dolllvm_codegen_fingerprint(char *out, size_t size) {
  if (!out || size == 0)
    return false;
  // Every codegen-affecting input the object cache key would otherwise miss.
  // The triple is hashed separately by the caller, which already had it.
  const std::string fingerprint = std::string(LLVM_VERSION_STRING) + "|" +
                                  kTargetCPU + "|" + kTargetFeatures + "|" +
                                  "pic|small|" + kPassPipeline;
  if (fingerprint.size() + 1 > size)
    return false;
  memcpy(out, fingerprint.c_str(), fingerprint.size() + 1);
  return true;
}
