#ifndef DOLRECOMP_LLVM_BACKEND_H
#define DOLRECOMP_LLVM_BACKEND_H

#include "ir/dolir.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    u32 start;
    u32 end;
} DolLLVMFunctionRange;

typedef struct {
    const char* target_triple;
    int optimization_level;
    int verify;
    int emit_ir;
    const char* ir_path;
    const DolLLVMFunctionRange* function_ranges;
    u32 function_range_count;
} DolLLVMOptions;

bool dolllvm_emit_object(const DolIRModule* module, const char* object_path,
                         const DolLLVMOptions* options, FILE* diagnostics);

// Writes the triple objects are actually emitted for: `requested` when set and
// non-empty, otherwise LLVM's default host triple. Returns false if `size` is
// too small. Callers need this because the emitted object *format* follows the
// triple, so anything that caches or validates objects has to agree with the
// backend about which triple is in effect.
bool dolllvm_effective_triple(const char* requested, char* out, size_t size);

// Whether `path` begins with the object-file magic implied by `requested`'s
// effective triple. Checking for ELF unconditionally silently disabled the
// object cache and DOLRECOMP_LLVM_RESUME on Windows, where the backend emits
// COFF.
bool dolllvm_object_matches_triple(const char* path, const char* requested);

#ifdef __cplusplus
}
#endif

#endif
