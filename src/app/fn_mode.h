#ifndef DOLRECOMP_APP_FN_MODE_H
#define DOLRECOMP_APP_FN_MODE_H

#include "analysis/smc.h"
#include "analysis/symbol_map.h"
#include "backend/dispatch.h"
#include "common/types.h"
#include "frontend/decoder.h"

#include <stdio.h>

/* Function-mode codegen driver (--fn-list). Selected guest functions are
 * emitted as fn_X into chunks/fnchunk_NNNN.c next to the ordinary chunks,
 * which still carry every instruction as the fallback. */

/* Loads the function list and the exclusion list (hex address per line,
 * '#' comments). Needs the --map symbols for function extents. */
bool fn_mode_begin(const char* list_path, const char* exclude_path,
                   const DolRecompSymbolMap* symbols);
bool fn_mode_active(void);

/* Selects and emits the listed functions that live in this section, then
 * installs the accepted set in the chunk emitter. Call before the section's
 * chunk jobs run. */
bool fn_mode_section(const PPCInst* insts, u32 num_insts, u32 base_addr,
                     u32 chunk_instructions, const SMCAnalysis* smc,
                     const char* chunks_dir, const char* chunks_label,
                     const char* include_name, FILE* manifest);

/* Accepted ranges, for the dispatch table (NULL when inactive). */
const FunctionList* fn_mode_ranges(void);

/* Closes output, prints the selection summary, clears emitter state. */
void fn_mode_end(void);

#endif
