// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DOLRECOMP_C_CFG_H
#define DOLRECOMP_C_CFG_H

#include "../common/types.h"
#include "../frontend/decoder.h"

typedef struct {
    u32 count;
    u8* leaders;
    u32* block_cycles;
    u8* materialize_pc;
    u8* return_targets;
    u32* loop_ends;
    /* Addresses at which control may enter this chunk from outside its own
     * straight-line flow: the chunk start, block leaders, return addresses,
     * and any address some other chunk statically branches to. */
    u8* entry_points;
} CFunctionCFG;

/* Global static-branch-target set. Chunks are cut at a fixed stride, so a
 * chunk's entry addresses cannot be derived from the chunk alone -- a `bl`
 * anywhere in the program may land in the middle of it. Collect every static
 * branch target across all sections first, then c_function_cfg_build marks
 * those addresses as entry points.
 *
 * Mutation is not thread-safe; the set is read-only after finalize, which is
 * how the parallel chunk jobs use it. An address missing from the set is a
 * performance issue, never a correctness one: the cold resume companion
 * handles any pc. */
void c_global_targets_reset(void);
bool c_global_targets_add(const PPCInst* insts, u32 count);
void c_global_targets_finalize(void);
bool c_global_target_contains(u32 address);

bool c_function_cfg_build(CFunctionCFG* cfg, const PPCInst* insts, u32 count,
                          u32 function_address);
void c_function_cfg_destroy(CFunctionCFG* cfg);

bool c_function_cfg_contains(const CFunctionCFG* cfg, u32 function_address,
                             u32 address);
bool c_function_cfg_can_loop_directly(const CFunctionCFG* cfg,
                                      const PPCInst* insts,
                                      u32 function_address,
                                      u32 branch_index);

#endif
