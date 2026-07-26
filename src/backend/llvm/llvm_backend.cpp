#include "backend/llvm/llvm_backend.h"
#include "cpu/cpu.h"

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <llvm/ADT/SmallVector.h>
#include <llvm/TargetParser/Triple.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>

namespace {

using namespace llvm;

class FunctionEmitter {
public:
    FunctionEmitter(LLVMContext& context, Module& module,
                    const DolIRFunction& source,
                    const DolLLVMFunctionRange* ranges, u32 rangeCount)
        : context_(context), module_(module), source_(source), builder_(context),
          ranges_(ranges), range_count_(rangeCount) {}

    bool emit(raw_ostream& diagnostics) {
        auto* type = FunctionType::get(Type::getVoidTy(context_),
                                       {PointerType::getUnqual(context_)}, false);
        function_ = Function::Create(type, GlobalValue::ExternalLinkage,
                                     source_.name, module_);
        function_->setCallingConv(CallingConv::C);
        function_->setVisibility(GlobalValue::HiddenVisibility);
        function_->setDSOLocal(true);
        ctx_ = function_->getArg(0);
        ctx_->setName("ctx");

        entry_ = BasicBlock::Create(context_, "entry", function_);
        for (u32 i = 0; i < source_.block_count; i++)
            blocks_.push_back(BasicBlock::Create(context_, blockName(i), function_));
        scanState();
        scanContinuations();
        scanLoopHeaders();
        emitEntry();
        for (u32 i = 0; i < source_.block_count; i++)
            if (!emitBlock(i, diagnostics))
                return false;
        return !verifyFunction(*function_, &diagnostics);
    }

private:
    std::string blockName(u32 index) const {
        char text[40];
        snprintf(text, sizeof(text), "guest_%08X_b%u",
                 source_.blocks[index].guest_address, index);
        return text;
    }

    Type* type(DolIRType t) {
        switch (t) {
        case DOLIR_TYPE_I1: return Type::getInt1Ty(context_);
        case DOLIR_TYPE_I8: return Type::getInt8Ty(context_);
        case DOLIR_TYPE_I16: return Type::getInt16Ty(context_);
        case DOLIR_TYPE_I32: return Type::getInt32Ty(context_);
        case DOLIR_TYPE_I64: return Type::getInt64Ty(context_);
        case DOLIR_TYPE_F32: return Type::getFloatTy(context_);
        case DOLIR_TYPE_F64: return Type::getDoubleTy(context_);
        case DOLIR_TYPE_V2F32: return FixedVectorType::get(Type::getFloatTy(context_), 2);
        case DOLIR_TYPE_V2F64: return FixedVectorType::get(Type::getDoubleTy(context_), 2);
        default: return Type::getVoidTy(context_);
        }
    }

    size_t stateOffset(DolIRStateSlot slot) const {
        if (slot >= DOLIR_STATE_GPR0 && slot <= DOLIR_STATE_GPR31)
            return offsetof(CPUState, gpr) + 4u * (slot - DOLIR_STATE_GPR0);
        if (slot >= DOLIR_STATE_FPR0 && slot <= DOLIR_STATE_FPR31)
            return offsetof(CPUState, fpr) + 8u * (slot - DOLIR_STATE_FPR0);
        if (slot >= DOLIR_STATE_PS1_0 && slot <= DOLIR_STATE_PS1_31)
            return offsetof(CPUState, ps1) + 8u * (slot - DOLIR_STATE_PS1_0);
        if (slot >= DOLIR_STATE_SR0 && slot <= DOLIR_STATE_SR15)
            return offsetof(CPUState, sr) + 4u * (slot - DOLIR_STATE_SR0);
        if (slot >= DOLIR_STATE_GQR0 && slot <= DOLIR_STATE_GQR7)
            return offsetof(CPUState, gqr) + 4u * (slot - DOLIR_STATE_GQR0);
        switch (slot) {
        case DOLIR_STATE_PC: return offsetof(CPUState, pc);
        case DOLIR_STATE_LR: return offsetof(CPUState, lr);
        case DOLIR_STATE_CTR: return offsetof(CPUState, ctr);
        case DOLIR_STATE_CR: return offsetof(CPUState, cr);
        case DOLIR_STATE_XER: return offsetof(CPUState, xer);
        case DOLIR_STATE_FPSCR: return offsetof(CPUState, fpscr);
        case DOLIR_STATE_MSR: return offsetof(CPUState, msr);
        case DOLIR_STATE_SRR0: return offsetof(CPUState, srr0);
        case DOLIR_STATE_SRR1: return offsetof(CPUState, srr1);
        case DOLIR_STATE_DAR: return offsetof(CPUState, dar);
        case DOLIR_STATE_DSISR: return offsetof(CPUState, dsisr);
        case DOLIR_STATE_EAR: return offsetof(CPUState, ear);
        case DOLIR_STATE_HID2: return offsetof(CPUState, hid2);
        case DOLIR_STATE_TIMEBASE: return offsetof(CPUState, timebase);
        case DOLIR_STATE_EXCEPTION: return offsetof(CPUState, exception);
        case DOLIR_STATE_PROGRAM_EXCEPTION: return offsetof(CPUState, program_exception);
        case DOLIR_STATE_RESERVE_ADDR: return offsetof(CPUState, reserve_addr);
        case DOLIR_STATE_RESERVE_VALID: return offsetof(CPUState, reserve_valid);
        case DOLIR_STATE_DOWNCOUNT: return offsetof(CPUState, downcount);
        default: return 0;
        }
    }

    Value* bytePtr(size_t offset) {
        return builder_.CreateInBoundsGEP(Type::getInt8Ty(context_), ctx_,
                                          ConstantInt::get(Type::getInt64Ty(context_), offset));
    }

    Value* loadContext(DolIRStateSlot slot) {
        return builder_.CreateLoad(type(dolir_state_type(slot)), bytePtr(stateOffset(slot)));
    }

    void storeContext(DolIRStateSlot slot, Value* value) {
        builder_.CreateStore(value, bytePtr(stateOffset(slot)));
    }

    Value* loadOffset(Type* valueType, size_t offset) {
        return builder_.CreateLoad(valueType, bytePtr(offset));
    }

    void scanState() {
        for (u32 b = 0; b < source_.block_count; b++) {
            const DolIRBlock& block = source_.blocks[b];
            for (u32 i = 0; i < block.instruction_count; i++) {
                const DolIRInstruction& inst = block.instructions[i];
                if (inst.op == DOLIR_OP_STATE_READ || inst.op == DOLIR_OP_STATE_WRITE)
                    used_[inst.aux] = true;
                if (inst.op == DOLIR_OP_STATE_WRITE)
                    dirty_[inst.aux] = true;
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_FP_AVAILABLE)
                    used_[DOLIR_STATE_MSR] = true;
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_EXACT_FLOAT)
                    scanExactFloat(inst.immediate);
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_EXACT_PAIRED)
                    scanExactPaired(inst.immediate);
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_PSQ_LOAD) {
                    u32 reg = inst.immediate & 0xFFu;
                    used_[DOLIR_STATE_FPR0 + reg] = true;
                    dirty_[DOLIR_STATE_FPR0 + reg] = true;
                    used_[DOLIR_STATE_PS1_0 + reg] = true;
                    dirty_[DOLIR_STATE_PS1_0 + reg] = true;
                }
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_STORE_CONDITIONAL) {
                    used_[DOLIR_STATE_CR] = true;
                    dirty_[DOLIR_STATE_CR] = true;
                    used_[DOLIR_STATE_RESERVE_VALID] = true;
                    dirty_[DOLIR_STATE_RESERVE_VALID] = true;
                    used_[DOLIR_STATE_RESERVE_ADDR] = true;
                }
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    (inst.aux == DOLIR_HELPER_FPSCR_UPDATED ||
                     inst.aux == DOLIR_HELPER_FPSCR_BIT)) {
                    used_[DOLIR_STATE_FPSCR] = true;
                    dirty_[DOLIR_STATE_FPSCR] = true;
                }
                if (inst.op == DOLIR_OP_HELPER_CALL &&
                    inst.aux == DOLIR_HELPER_LSWX) {
                    used_[DOLIR_STATE_XER] = true;
                    for (u32 reg = 0; reg < 32; reg++) {
                        used_[DOLIR_STATE_GPR0 + reg] = true;
                        dirty_[DOLIR_STATE_GPR0 + reg] = true;
                    }
                }
                if (inst.op == DOLIR_OP_GUEST_STORE) {
                    used_[DOLIR_STATE_RESERVE_ADDR] = true;
                    used_[DOLIR_STATE_RESERVE_VALID] = true;
                    dirty_[DOLIR_STATE_RESERVE_VALID] = true;
                }
            }
        }
    }

    void scanExactFloat(u64 descriptor) {
        auto op = static_cast<DolIRExactFloat>(descriptor & 0xFFu);
        u32 d = (descriptor >> 8) & 0xFFu;
        u32 a = (descriptor >> 16) & 0xFFu;
        u32 b = (descriptor >> 24) & 0xFFu;
        u32 c = (descriptor >> 32) & 0xFFu;
        used_[DOLIR_STATE_FPSCR] = true;
        dirty_[DOLIR_STATE_FPSCR] = true;
        if (op == DOLIR_EXACT_FCMPU || op == DOLIR_EXACT_FCMPO) {
            used_[DOLIR_STATE_CR] = true;
            dirty_[DOLIR_STATE_CR] = true;
            used_[DOLIR_STATE_FPR0 + a] = true;
            used_[DOLIR_STATE_FPR0 + b] = true;
            return;
        }
        used_[DOLIR_STATE_FPR0 + d] = true;
        dirty_[DOLIR_STATE_FPR0 + d] = true;
        if (op == DOLIR_EXACT_FRES ||
            (op >= DOLIR_EXACT_FADDS && op <= DOLIR_EXACT_FDIVS) ||
            op == DOLIR_EXACT_FRSP ||
            (op >= DOLIR_EXACT_FMADDS && op <= DOLIR_EXACT_FNMSUBS)) {
            used_[DOLIR_STATE_PS1_0 + d] = true;
            dirty_[DOLIR_STATE_PS1_0 + d] = true;
        }
        if (op == DOLIR_EXACT_FRES || op == DOLIR_EXACT_FRSQRTE ||
            op == DOLIR_EXACT_FCTIW || op == DOLIR_EXACT_FCTIWZ ||
            op == DOLIR_EXACT_FRSP) {
            used_[DOLIR_STATE_FPR0 + b] = true;
        } else if (op == DOLIR_EXACT_FMULS || op == DOLIR_EXACT_FMUL) {
            used_[DOLIR_STATE_FPR0 + a] = true;
            used_[DOLIR_STATE_FPR0 + c] = true;
        } else if ((op >= DOLIR_EXACT_FADDS && op <= DOLIR_EXACT_FDIVS) ||
                   (op >= DOLIR_EXACT_FADD && op <= DOLIR_EXACT_FDIV)) {
            used_[DOLIR_STATE_FPR0 + a] = true;
            used_[DOLIR_STATE_FPR0 + b] = true;
        } else {
            used_[DOLIR_STATE_FPR0 + a] = true;
            used_[DOLIR_STATE_FPR0 + b] = true;
            used_[DOLIR_STATE_FPR0 + c] = true;
        }
    }

    void scanExactPaired(u64 descriptor) {
        auto op = static_cast<DolIRExactPaired>(descriptor & 0xFFu);
        u32 d = (descriptor >> 8) & 0xFFu;
        u32 a = (descriptor >> 16) & 0xFFu;
        u32 b = (descriptor >> 24) & 0xFFu;
        u32 c = (descriptor >> 32) & 0xFFu;
        used_[DOLIR_STATE_FPSCR] = true;
        dirty_[DOLIR_STATE_FPSCR] = true;
        if (op >= DOLIR_EXACT_PS_CMPU0) {
            used_[DOLIR_STATE_CR] = true;
            dirty_[DOLIR_STATE_CR] = true;
            used_[DOLIR_STATE_FPR0 + a] = true;
            used_[DOLIR_STATE_PS1_0 + a] = true;
            used_[DOLIR_STATE_FPR0 + b] = true;
            used_[DOLIR_STATE_PS1_0 + b] = true;
            return;
        }
        used_[DOLIR_STATE_FPR0 + d] = true;
        dirty_[DOLIR_STATE_FPR0 + d] = true;
        used_[DOLIR_STATE_PS1_0 + d] = true;
        dirty_[DOLIR_STATE_PS1_0 + d] = true;
        auto usePair = [this](u32 reg) {
            used_[DOLIR_STATE_FPR0 + reg] = true;
            used_[DOLIR_STATE_PS1_0 + reg] = true;
        };
        if (op == DOLIR_EXACT_PS_RES || op == DOLIR_EXACT_PS_RSQRTE) {
            usePair(b);
            return;
        }
        usePair(a);
        if (op == DOLIR_EXACT_PS_MUL || op == DOLIR_EXACT_PS_MULS0 ||
            op == DOLIR_EXACT_PS_MULS1) {
            usePair(c);
            return;
        }
        usePair(b);
        if (op >= DOLIR_EXACT_PS_MADD && op <= DOLIR_EXACT_PS_SUM1)
            usePair(c);
    }

    void scanContinuations() {
        for (u32 i = 0; i < source_.block_count; i++) {
            const DolIRTerminator& term = source_.blocks[i].terminator;
            if (!term.linked)
                continue;
            u32 continuation = term.guest_pc + 4u;
            u32 block = 0;
            if (continuation >= source_.guest_start && continuation < source_.guest_end &&
                ((continuation - source_.guest_start) & 3u) == 0) {
                block = (continuation - source_.guest_start) / 4u;
                if (block < source_.block_count)
                    continuations_.push_back(block);
            }
        }
    }

    void scanLoopHeaders() {
        loop_headers_.assign(source_.block_count, false);
        for (u32 i = 0; i < source_.block_count; i++) {
            const DolIRTerminator& term = source_.blocks[i].terminator;
            u32 count = term.kind == DOLIR_TERM_COND_BRANCH ? 2u :
                        term.kind == DOLIR_TERM_BRANCH ? 1u : 0u;
            for (u32 edge = 0; edge < count; edge++) {
                if (term.targets[edge] != DOLIR_NO_BLOCK && term.targets[edge] <= i)
                    loop_headers_[term.targets[edge]] = true;
            }
        }
    }

    void emitEntry() {
        builder_.SetInsertPoint(entry_);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (!used_[slot])
                continue;
            auto stateSlot = static_cast<DolIRStateSlot>(slot);
            state_[slot] = builder_.CreateAlloca(type(dolir_state_type(stateSlot)), nullptr,
                                                  "state");
            builder_.CreateStore(loadContext(stateSlot), state_[slot]);
        }
        cycles_ = builder_.CreateAlloca(Type::getInt64Ty(context_), nullptr, "cycles");
        builder_.CreateStore(ConstantInt::get(Type::getInt64Ty(context_), 0), cycles_);
        Value* pc = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, pc));
        BasicBlock* bad = BasicBlock::Create(context_, "entry_miss", function_);
        auto* dispatch = builder_.CreateSwitch(pc, bad, source_.block_count);
        for (u32 i = 0; i < source_.block_count; i++)
            dispatch->addCase(ConstantInt::get(Type::getInt32Ty(context_),
                                               source_.blocks[i].guest_address), blocks_[i]);
        builder_.SetInsertPoint(bad);
        builder_.CreateRetVoid();
    }

    void chargeCycles(u32 cycles) {
        Value* old = builder_.CreateLoad(Type::getInt64Ty(context_), cycles_);
        Value* next = builder_.CreateAdd(old,
            ConstantInt::get(Type::getInt64Ty(context_), cycles));
        builder_.CreateStore(next, cycles_);
    }

    void materialize(u32 pc) {
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (!dirty_[slot])
                continue;
            auto stateSlot = static_cast<DolIRStateSlot>(slot);
            storeContext(stateSlot,
                         builder_.CreateLoad(type(dolir_state_type(stateSlot)), state_[slot]));
        }
        storeContext(DOLIR_STATE_PC, ConstantInt::get(Type::getInt32Ty(context_), pc));
        Value* downcount = loadOffset(Type::getInt64Ty(context_), offsetof(CPUState, downcount));
        Value* cycles = builder_.CreateLoad(Type::getInt64Ty(context_), cycles_);
        builder_.CreateStore(builder_.CreateSub(downcount, cycles),
                             bytePtr(offsetof(CPUState, downcount)));
    }

    void sideExit(u32 pc) {
        materialize(pc);
        builder_.CreateRetVoid();
    }

    void emitBudgetGuard(u32 pc) {
        Value* cycles = builder_.CreateLoad(Type::getInt64Ty(context_), cycles_);
        Value* exhausted = builder_.CreateICmpUGE(
            cycles, ConstantInt::get(Type::getInt64Ty(context_), 256));
        BasicBlock* run = BasicBlock::Create(context_, "budget_run", function_);
        BasicBlock* exit = BasicBlock::Create(context_, "budget_exit", function_);
        builder_.CreateCondBr(exhausted, exit, run);
        builder_.SetInsertPoint(exit);
        sideExit(pc);
        builder_.SetInsertPoint(run);
    }

    bool emitBlock(u32 index, raw_ostream& diagnostics) {
        const DolIRBlock& block = source_.blocks[index];
        builder_.SetInsertPoint(blocks_[index]);
        if (loop_headers_[index])
            emitBudgetGuard(block.guest_address);
        chargeCycles(block.cycle_cost);
        values_.assign(source_.value_count, nullptr);
        for (u32 i = 0; i < block.instruction_count; i++) {
            if (!emitInstruction(block.instructions[i], diagnostics))
                return false;
        }
        return emitTerminator(block.terminator, diagnostics);
    }

    Value* operand(const DolIRInstruction& inst, u32 index) {
        return values_[inst.operands[index]];
    }

    Value* castValue(DolIROp op, Type* resultType, Value* value) {
        switch (op) {
        case DOLIR_OP_TRUNC: return builder_.CreateTrunc(value, resultType);
        case DOLIR_OP_ZEXT: return builder_.CreateZExt(value, resultType);
        case DOLIR_OP_SEXT: return builder_.CreateSExt(value, resultType);
        case DOLIR_OP_BITCAST: return builder_.CreateBitCast(value, resultType);
        case DOLIR_OP_FPTRUNC: return builder_.CreateFPTrunc(value, resultType);
        case DOLIR_OP_FPEXT: return builder_.CreateFPExt(value, resultType);
        default: return nullptr;
        }
    }

    Value* bswap(Value* value) {
        auto* integer = cast<IntegerType>(value->getType());
        if (integer->getBitWidth() == 8)
            return value;
        Function* intrinsic = Intrinsic::getDeclaration(&module_, Intrinsic::bswap,
                                                        {value->getType()});
        return builder_.CreateCall(intrinsic, {value});
    }

    bool emitInstruction(const DolIRInstruction& inst, raw_ostream& diagnostics) {
        current_pc_ = inst.guest_pc;
        Value* result = nullptr;
        Type* resultType = type(inst.type);
        switch (inst.op) {
        case DOLIR_OP_CONSTANT:
            if (inst.type == DOLIR_TYPE_F32)
                result = ConstantFP::get(context_, APFloat(APFloat::IEEEsingle(), APInt(32, inst.immediate)));
            else if (inst.type == DOLIR_TYPE_F64)
                result = ConstantFP::get(context_, APFloat(APFloat::IEEEdouble(), APInt(64, inst.immediate)));
            else
                result = ConstantInt::get(resultType, inst.immediate);
            break;
        case DOLIR_OP_STATE_READ:
            result = builder_.CreateLoad(resultType, state_[inst.aux]);
            break;
        case DOLIR_OP_STATE_WRITE:
            builder_.CreateStore(operand(inst, 0), state_[inst.aux]);
            break;
        case DOLIR_OP_ADD: result = builder_.CreateAdd(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_SUB: result = builder_.CreateSub(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_MUL: result = builder_.CreateMul(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_UDIV: result = builder_.CreateUDiv(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_SDIV: result = builder_.CreateSDiv(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_AND: result = builder_.CreateAnd(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_OR: result = builder_.CreateOr(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_XOR: result = builder_.CreateXor(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_NOT: result = builder_.CreateNot(operand(inst, 0)); break;
        case DOLIR_OP_SHL: result = builder_.CreateShl(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_LSHR: result = builder_.CreateLShr(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ASHR: result = builder_.CreateAShr(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ROTL: {
            Function* intrinsic = Intrinsic::getDeclaration(&module_, Intrinsic::fshl,
                                                             {resultType});
            result = builder_.CreateCall(intrinsic,
                                         {operand(inst, 0), operand(inst, 0), operand(inst, 1)});
            break;
        }
        case DOLIR_OP_CLZ: {
            Function* intrinsic = Intrinsic::getDeclaration(&module_, Intrinsic::ctlz,
                                                             {resultType});
            result = builder_.CreateCall(intrinsic,
                                         {operand(inst, 0), ConstantInt::getFalse(context_)});
            break;
        }
        case DOLIR_OP_BSWAP: result = bswap(operand(inst, 0)); break;
        case DOLIR_OP_TRUNC: case DOLIR_OP_ZEXT: case DOLIR_OP_SEXT:
        case DOLIR_OP_BITCAST: case DOLIR_OP_FPTRUNC: case DOLIR_OP_FPEXT:
            result = castValue(inst.op, resultType, operand(inst, 0));
            break;
        case DOLIR_OP_ICMP_EQ: result = builder_.CreateICmpEQ(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ICMP_NE: result = builder_.CreateICmpNE(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ICMP_ULT: result = builder_.CreateICmpULT(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ICMP_ULE: result = builder_.CreateICmpULE(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ICMP_SLT: result = builder_.CreateICmpSLT(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_ICMP_SLE: result = builder_.CreateICmpSLE(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FCMP_OEQ: result = builder_.CreateFCmpOEQ(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FCMP_OLT: result = builder_.CreateFCmpOLT(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FCMP_OGE: result = builder_.CreateFCmpOGE(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_SELECT: result = builder_.CreateSelect(operand(inst, 0), operand(inst, 1), operand(inst, 2)); break;
        case DOLIR_OP_FADD: result = builder_.CreateFAdd(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FSUB: result = builder_.CreateFSub(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FMUL: result = builder_.CreateFMul(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FDIV: result = builder_.CreateFDiv(operand(inst, 0), operand(inst, 1)); break;
        case DOLIR_OP_FNEG: result = builder_.CreateFNeg(operand(inst, 0)); break;
        case DOLIR_OP_FABS: {
            Function* intrinsic = Intrinsic::getDeclaration(&module_, Intrinsic::fabs,
                                                             {resultType});
            result = builder_.CreateCall(intrinsic, {operand(inst, 0)});
            break;
        }
        case DOLIR_OP_VECTOR_BUILD: {
            result = PoisonValue::get(resultType);
            result = builder_.CreateInsertElement(result, operand(inst, 0), uint64_t{0});
            result = builder_.CreateInsertElement(result, operand(inst, 1), 1u);
            break;
        }
        case DOLIR_OP_VECTOR_EXTRACT:
            result = builder_.CreateExtractElement(operand(inst, 0), inst.aux);
            break;
        case DOLIR_OP_VECTOR_SHUFFLE:
            result = builder_.CreateShuffleVector(operand(inst, 0), operand(inst, 1),
                {static_cast<int>(inst.aux & 0xFFu),
                 static_cast<int>((inst.aux >> 8) & 0xFFu)});
            break;
        case DOLIR_OP_GUEST_LOAD:
            result = emitGuestLoad(operand(inst, 0), resultType, inst.aux & 0xffu,
                                   (inst.aux & 0x100u) != 0);
            break;
        case DOLIR_OP_GUEST_STORE:
            emitGuestStore(operand(inst, 0), operand(inst, 1), inst.aux & 0xffu);
            break;
        case DOLIR_OP_HELPER_CALL:
            if (inst.aux == DOLIR_HELPER_FP_AVAILABLE)
                result = emitFPAvailable(inst.guest_pc);
            else if (inst.aux == DOLIR_HELPER_MEMORY_FENCE)
                builder_.CreateFence(AtomicOrdering::SequentiallyConsistent);
            else if (inst.aux == DOLIR_HELPER_EXACT_FLOAT)
                emitExactFloat(inst.immediate);
            else if (inst.aux == DOLIR_HELPER_EXACT_PAIRED)
                emitExactPaired(inst.immediate);
            else if (inst.aux == DOLIR_HELPER_PSQ_LOAD ||
                     inst.aux == DOLIR_HELPER_PSQ_STORE)
                result = emitPSQ(inst);
            else if (inst.aux == DOLIR_HELPER_STORE_CONDITIONAL)
                emitStoreConditional(inst);
            else if (inst.aux == DOLIR_HELPER_FPSCR_UPDATED)
                emitFPSCRUpdated();
            else if (inst.aux == DOLIR_HELPER_FPSCR_BIT)
                emitFPSCRBit(inst.immediate);
            else if (inst.aux == DOLIR_HELPER_PROGRAM_EXCEPTION)
                emitProgramException(inst);
            else if (inst.aux == DOLIR_HELPER_SPR_READ)
                result = emitSPRRead(inst);
            else if (inst.aux == DOLIR_HELPER_SPR_WRITE)
                emitSPRWrite(inst);
            else if (inst.aux == DOLIR_HELPER_LSWX)
                emitLSWX(inst);
            else if (inst.aux == DOLIR_HELPER_DCBZ_L ||
                     inst.aux == DOLIR_HELPER_ECIWX ||
                     inst.aux == DOLIR_HELPER_ECOWX ||
                     inst.aux == DOLIR_HELPER_TLBIE ||
                     inst.aux == DOLIR_HELPER_CACHE_CONTROL)
                result = emitRuntimeBoundary(inst);
            else {
                diagnostics << "dolllvm: unsupported helper " << inst.aux << " at 0x"
                            << format_hex_no_prefix(inst.guest_pc, 8) << "\n";
                return false;
            }
            break;
        default:
            diagnostics << "dolllvm: unsupported DolIR op " << unsigned(inst.op) << " at 0x"
                        << format_hex_no_prefix(inst.guest_pc, 8) << "\n";
            return false;
        }
        if (inst.result)
            values_[inst.result] = result;
        return inst.type == DOLIR_TYPE_VOID || result != nullptr;
    }

    AllocaInst* temporary(Type* valueType, StringRef name) {
        IRBuilder<> allocations(entry_->getTerminator());
        return allocations.CreateAlloca(valueType, nullptr, name);
    }

    Value* stateValue(DolIRStateSlot slot) {
        return builder_.CreateLoad(type(dolir_state_type(slot)), state_[slot]);
    }

    void syncState(DolIRStateSlot slot) {
        storeContext(slot, stateValue(slot));
    }

    void reloadState(DolIRStateSlot slot) {
        builder_.CreateStore(loadContext(slot), state_[slot]);
    }

    void reloadUsedState() {
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot])
                reloadState(static_cast<DolIRStateSlot>(slot));
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
    }

    void continueAfterRuntimeBoundary(StringRef prefix) {
        Value* exception = loadOffset(Type::getInt32Ty(context_),
                                      offsetof(CPUState, exception));
        BasicBlock* resume = BasicBlock::Create(context_, prefix + "_resume", function_);
        BasicBlock* failed = BasicBlock::Create(context_, prefix + "_exit", function_);
        builder_.CreateCondBr(builder_.CreateICmpEQ(exception, builder_.getInt32(0)),
                              resume, failed);
        builder_.SetInsertPoint(failed);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        reloadUsedState();
    }

    void emitFPSCRUpdated() {
        syncState(DOLIR_STATE_FPSCR);
        auto callee = module_.getOrInsertFunction("ppc_fpscr_control_updated",
            FunctionType::get(Type::getVoidTy(context_),
                {PointerType::getUnqual(context_)}, false));
        builder_.CreateCall(callee, {ctx_});
        reloadState(DOLIR_STATE_FPSCR);
    }

    void emitFPSCRBit(u64 descriptor) {
        syncState(DOLIR_STATE_FPSCR);
        const char* name = ((descriptor >> 8) & 1u) ?
            "ppc_mtfsb1_op" : "ppc_mtfsb0_op";
        auto callee = module_.getOrInsertFunction(name,
            FunctionType::get(Type::getVoidTy(context_),
                {PointerType::getUnqual(context_), Type::getInt8Ty(context_)}, false));
        builder_.CreateCall(callee, {ctx_, builder_.getInt8(descriptor & 0xFFu)});
        reloadState(DOLIR_STATE_FPSCR);
    }

    void emitProgramException(const DolIRInstruction& inst) {
        BasicBlock* taken = BasicBlock::Create(context_, "trap_taken", function_);
        BasicBlock* resume = BasicBlock::Create(context_, "trap_resume", function_);
        builder_.CreateCondBr(operand(inst, 0), taken, resume);
        builder_.SetInsertPoint(taken);
        materialize(inst.guest_pc);
        auto callee = module_.getOrInsertFunction("ppc_program_exception",
            FunctionType::get(Type::getVoidTy(context_),
                {PointerType::getUnqual(context_), Type::getInt32Ty(context_),
                 Type::getInt32Ty(context_)}, false));
        builder_.CreateCall(callee,
            {ctx_, builder_.getInt32(inst.immediate),
             builder_.getInt32(inst.guest_pc)});
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
    }

    Value* emitSPRRead(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        auto callee = module_.getOrInsertFunction("ppc_mfspr",
            FunctionType::get(Type::getInt32Ty(context_),
                {PointerType::getUnqual(context_), Type::getInt16Ty(context_),
                 Type::getInt32Ty(context_)}, false));
        Value* result = builder_.CreateCall(callee,
            {ctx_, builder_.getInt16(inst.immediate),
             builder_.getInt32(inst.guest_pc)});
        continueAfterRuntimeBoundary("mfspr");
        return result;
    }

    void emitSPRWrite(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        auto callee = module_.getOrInsertFunction("ppc_mtspr",
            FunctionType::get(Type::getVoidTy(context_),
                {PointerType::getUnqual(context_), Type::getInt16Ty(context_),
                 Type::getInt32Ty(context_), Type::getInt32Ty(context_)}, false));
        builder_.CreateCall(callee,
            {ctx_, builder_.getInt16(inst.immediate), operand(inst, 0),
             builder_.getInt32(inst.guest_pc)});
        continueAfterRuntimeBoundary("mtspr");
    }

    void emitLSWX(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        auto callee = module_.getOrInsertFunction("ppc_lswx",
            FunctionType::get(Type::getVoidTy(context_),
                {PointerType::getUnqual(context_), Type::getInt8Ty(context_),
                 Type::getInt8Ty(context_), Type::getInt8Ty(context_),
                 Type::getInt32Ty(context_)}, false));
        builder_.CreateCall(callee,
            {ctx_, builder_.getInt8(inst.immediate & 0xFFu),
             builder_.getInt8((inst.immediate >> 8) & 0xFFu),
             builder_.getInt8((inst.immediate >> 16) & 0xFFu),
             builder_.getInt32(inst.guest_pc)});
        continueAfterRuntimeBoundary("lswx");
    }

    Value* emitRuntimeBoundary(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        Type* ptr = PointerType::getUnqual(context_);
        Value* result = nullptr;
        StringRef prefix;
        if (inst.aux == DOLIR_HELPER_DCBZ_L) {
            prefix = "dcbz_l";
            auto callee = module_.getOrInsertFunction("ppc_dcbz_l",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, Type::getInt32Ty(context_), Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, operand(inst, 0), builder_.getInt32(inst.guest_pc)});
        } else if (inst.aux == DOLIR_HELPER_ECIWX) {
            prefix = "eciwx";
            auto callee = module_.getOrInsertFunction("ppc_eciwx",
                FunctionType::get(Type::getInt32Ty(context_),
                    {ptr, Type::getInt32Ty(context_), Type::getInt32Ty(context_)}, false));
            result = builder_.CreateCall(callee,
                {ctx_, operand(inst, 0), builder_.getInt32(inst.guest_pc)});
        } else if (inst.aux == DOLIR_HELPER_ECOWX) {
            prefix = "ecowx";
            auto callee = module_.getOrInsertFunction("ppc_ecowx",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, Type::getInt32Ty(context_), Type::getInt32Ty(context_),
                     Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, operand(inst, 0), operand(inst, 1),
                 builder_.getInt32(inst.guest_pc)});
        } else if (inst.aux == DOLIR_HELPER_TLBIE) {
            prefix = "tlbie";
            auto callee = module_.getOrInsertFunction("ppc_tlbie",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, Type::getInt32Ty(context_), Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, operand(inst, 0), builder_.getInt32(inst.guest_pc)});
        } else {
            prefix = "cache";
            auto callee = module_.getOrInsertFunction("ppc_cache_control",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, Type::getInt8Ty(context_), Type::getInt32Ty(context_),
                     Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(inst.immediate), operand(inst, 0),
                 builder_.getInt32(inst.guest_pc)});
        }
        continueAfterRuntimeBoundary(prefix);
        return result;
    }

    void emitExactFloat(u64 descriptor) {
        auto op = static_cast<DolIRExactFloat>(descriptor & 0xFFu);
        u32 d = (descriptor >> 8) & 0xFFu;
        u32 a = (descriptor >> 16) & 0xFFu;
        u32 b = (descriptor >> 24) & 0xFFu;
        u32 c = (descriptor >> 32) & 0xFFu;
        u32 crfd = (descriptor >> 40) & 0xFFu;
        auto fprSlot = [](u32 reg) {
            return static_cast<DolIRStateSlot>(DOLIR_STATE_FPR0 + reg);
        };
        auto ps1Slot = [](u32 reg) {
            return static_cast<DolIRStateSlot>(DOLIR_STATE_PS1_0 + reg);
        };
        Type* ptr = PointerType::getUnqual(context_);
        Type* f64 = Type::getDoubleTy(context_);
        syncState(DOLIR_STATE_FPSCR);

        if (op == DOLIR_EXACT_FCMPU || op == DOLIR_EXACT_FCMPO) {
            syncState(DOLIR_STATE_CR);
            auto callee = module_.getOrInsertFunction("ppc_fcmp",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, Type::getInt8Ty(context_), f64, f64,
                     Type::getInt1Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(crfd), stateValue(fprSlot(a)),
                 stateValue(fprSlot(b)), builder_.getInt1(op == DOLIR_EXACT_FCMPO)});
            reloadState(DOLIR_STATE_CR);
            reloadState(DOLIR_STATE_FPSCR);
            return;
        }

        DolIRStateSlot destination = fprSlot(d);
        Value* old = stateValue(destination);
        if (op >= DOLIR_EXACT_FADDS && op <= DOLIR_EXACT_FRSP) {
            const char* name = nullptr;
            switch (op) {
            case DOLIR_EXACT_FADDS: name = "ppc_fadds"; break;
            case DOLIR_EXACT_FSUBS: name = "ppc_fsubs"; break;
            case DOLIR_EXACT_FMULS: name = "ppc_fmuls"; break;
            case DOLIR_EXACT_FDIVS: name = "ppc_fdivs"; break;
            case DOLIR_EXACT_FADD: name = "ppc_fadd"; break;
            case DOLIR_EXACT_FSUB: name = "ppc_fsub"; break;
            case DOLIR_EXACT_FMUL: name = "ppc_fmul"; break;
            case DOLIR_EXACT_FDIV: name = "ppc_fdiv"; break;
            case DOLIR_EXACT_FRSP: name = "ppc_frsp"; break;
            default: break;
            }
            syncState(destination);
            bool single = op <= DOLIR_EXACT_FDIVS || op == DOLIR_EXACT_FRSP;
            if (single)
                syncState(ps1Slot(d));
            syncState(fprSlot(op == DOLIR_EXACT_FRSP ? b : a));
            if (op != DOLIR_EXACT_FRSP)
                syncState(fprSlot(op == DOLIR_EXACT_FMULS ||
                                  op == DOLIR_EXACT_FMUL ? c : b));
            if (op == DOLIR_EXACT_FRSP) {
                auto callee = module_.getOrInsertFunction(name,
                    FunctionType::get(Type::getVoidTy(context_),
                        {ptr, Type::getInt8Ty(context_),
                         Type::getInt8Ty(context_)}, false));
                builder_.CreateCall(callee,
                    {ctx_, builder_.getInt8(d), builder_.getInt8(b)});
            } else {
                auto callee = module_.getOrInsertFunction(name,
                    FunctionType::get(Type::getVoidTy(context_),
                        {ptr, Type::getInt8Ty(context_),
                         Type::getInt8Ty(context_),
                         Type::getInt8Ty(context_)}, false));
                builder_.CreateCall(callee,
                    {ctx_, builder_.getInt8(d), builder_.getInt8(a),
                     builder_.getInt8(op == DOLIR_EXACT_FMULS ||
                                      op == DOLIR_EXACT_FMUL ? c : b)});
            }
            reloadState(destination);
            if (single)
                reloadState(ps1Slot(d));
        } else if (op == DOLIR_EXACT_FCTIW || op == DOLIR_EXACT_FCTIWZ) {
            AllocaInst* output = temporary(Type::getInt64Ty(context_), "fctiw.result");
            builder_.CreateStore(builder_.CreateBitCast(old, Type::getInt64Ty(context_)), output);
            auto callee = module_.getOrInsertFunction("ppc_fctiw",
                FunctionType::get(Type::getInt1Ty(context_),
                    {ptr, f64, Type::getInt1Ty(context_), ptr}, false));
            Value* success = builder_.CreateCall(callee,
                {ctx_, stateValue(fprSlot(b)),
                 builder_.getInt1(op == DOLIR_EXACT_FCTIWZ), output});
            Value* converted = builder_.CreateBitCast(
                builder_.CreateLoad(Type::getInt64Ty(context_), output), f64);
            builder_.CreateStore(builder_.CreateSelect(success, converted, old),
                                 state_[destination]);
        } else if (op == DOLIR_EXACT_FRES || op == DOLIR_EXACT_FRSQRTE) {
            AllocaInst* output = temporary(f64, "estimate.result");
            builder_.CreateStore(old, output);
            const char* name = op == DOLIR_EXACT_FRES ? "ppc_fres" : "ppc_frsqrte";
            auto callee = module_.getOrInsertFunction(name,
                FunctionType::get(Type::getInt1Ty(context_), {ptr, f64, ptr}, false));
            Value* success = builder_.CreateCall(callee,
                {ctx_, stateValue(fprSlot(b)), output});
            Value* estimate = builder_.CreateLoad(f64, output);
            builder_.CreateStore(builder_.CreateSelect(success, estimate, old),
                                 state_[destination]);
            if (op == DOLIR_EXACT_FRES) {
                DolIRStateSlot ps1 = ps1Slot(d);
                Value* oldPs1 = stateValue(ps1);
                builder_.CreateStore(builder_.CreateSelect(success, estimate, oldPs1),
                                     state_[ps1]);
            }
        } else {
            bool single = op >= DOLIR_EXACT_FMADDS && op <= DOLIR_EXACT_FNMSUBS;
            bool subtract = op == DOLIR_EXACT_FMSUB || op == DOLIR_EXACT_FNMSUB ||
                            op == DOLIR_EXACT_FMSUBS || op == DOLIR_EXACT_FNMSUBS;
            bool negative = op == DOLIR_EXACT_FNMADD || op == DOLIR_EXACT_FNMSUB ||
                            op == DOLIR_EXACT_FNMADDS || op == DOLIR_EXACT_FNMSUBS;
            AllocaInst* output = temporary(f64, "fma.result");
            builder_.CreateStore(old, output);
            auto callee = module_.getOrInsertFunction("ppc_fma",
                FunctionType::get(Type::getInt1Ty(context_),
                    {ptr, f64, f64, f64, Type::getInt1Ty(context_),
                     Type::getInt1Ty(context_), Type::getInt1Ty(context_), ptr}, false));
            Value* success = builder_.CreateCall(callee,
                {ctx_, stateValue(fprSlot(a)), stateValue(fprSlot(c)),
                 stateValue(fprSlot(b)), builder_.getInt1(single),
                 builder_.getInt1(subtract), builder_.getInt1(negative), output});
            Value* fused = builder_.CreateLoad(f64, output);
            builder_.CreateStore(builder_.CreateSelect(success, fused, old),
                                 state_[destination]);
            if (single) {
                DolIRStateSlot ps1 = ps1Slot(d);
                Value* oldPs1 = stateValue(ps1);
                builder_.CreateStore(builder_.CreateSelect(success, fused, oldPs1),
                                     state_[ps1]);
            }
        }
        reloadState(DOLIR_STATE_FPSCR);
    }

    void emitExactPaired(u64 descriptor) {
        auto op = static_cast<DolIRExactPaired>(descriptor & 0xFFu);
        u32 d = (descriptor >> 8) & 0xFFu;
        u32 a = (descriptor >> 16) & 0xFFu;
        u32 b = (descriptor >> 24) & 0xFFu;
        u32 c = (descriptor >> 32) & 0xFFu;
        u32 crfd = (descriptor >> 40) & 0xFFu;
        auto fprSlot = [](u32 reg) {
            return static_cast<DolIRStateSlot>(DOLIR_STATE_FPR0 + reg);
        };
        auto ps1Slot = [](u32 reg) {
            return static_cast<DolIRStateSlot>(DOLIR_STATE_PS1_0 + reg);
        };
        auto syncPair = [this, &fprSlot, &ps1Slot](u32 reg) {
            syncState(fprSlot(reg));
            syncState(ps1Slot(reg));
        };
        auto reloadPair = [this, &fprSlot, &ps1Slot](u32 reg) {
            reloadState(fprSlot(reg));
            reloadState(ps1Slot(reg));
        };
        Type* ptr = PointerType::getUnqual(context_);
        Type* i8 = Type::getInt8Ty(context_);
        Type* f64 = Type::getDoubleTy(context_);
        syncState(DOLIR_STATE_FPSCR);

        if (op >= DOLIR_EXACT_PS_CMPU0) {
            bool lane1 = op == DOLIR_EXACT_PS_CMPU1 || op == DOLIR_EXACT_PS_CMPO1;
            bool ordered = op == DOLIR_EXACT_PS_CMPO0 || op == DOLIR_EXACT_PS_CMPO1;
            syncState(DOLIR_STATE_CR);
            syncPair(a);
            syncPair(b);
            auto callee = module_.getOrInsertFunction("ppc_fcmp",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, i8, f64, f64, Type::getInt1Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(crfd),
                 stateValue(lane1 ? ps1Slot(a) : fprSlot(a)),
                 stateValue(lane1 ? ps1Slot(b) : fprSlot(b)),
                 builder_.getInt1(ordered)});
            reloadState(DOLIR_STATE_CR);
            reloadState(DOLIR_STATE_FPSCR);
            return;
        }

        syncPair(d);
        if (op == DOLIR_EXACT_PS_RES || op == DOLIR_EXACT_PS_RSQRTE) {
            syncPair(b);
            const char* name = op == DOLIR_EXACT_PS_RES ?
                "ppc_ps_res_op" : "ppc_ps_rsqrte_op";
            auto callee = module_.getOrInsertFunction(name,
                FunctionType::get(Type::getVoidTy(context_), {ptr, i8, i8}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(d), builder_.getInt8(b)});
        } else if (op == DOLIR_EXACT_PS_MADD || op == DOLIR_EXACT_PS_MSUB ||
                   op == DOLIR_EXACT_PS_NMADD || op == DOLIR_EXACT_PS_NMSUB) {
            syncPair(a);
            syncPair(b);
            syncPair(c);
            bool subtract = op == DOLIR_EXACT_PS_MSUB || op == DOLIR_EXACT_PS_NMSUB;
            bool negative = op == DOLIR_EXACT_PS_NMADD || op == DOLIR_EXACT_PS_NMSUB;
            auto callee = module_.getOrInsertFunction("ppc_ps_madd_op",
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, i8, i8, i8, i8, Type::getInt1Ty(context_),
                     Type::getInt1Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(d), builder_.getInt8(a),
                 builder_.getInt8(c), builder_.getInt8(b),
                 builder_.getInt1(subtract), builder_.getInt1(negative)});
        } else if (op == DOLIR_EXACT_PS_MADDS0 || op == DOLIR_EXACT_PS_MADDS1 ||
                   op == DOLIR_EXACT_PS_SUM0 || op == DOLIR_EXACT_PS_SUM1) {
            syncPair(a);
            syncPair(b);
            syncPair(c);
            const char* name = op == DOLIR_EXACT_PS_MADDS0 ? "ppc_ps_madds0" :
                               op == DOLIR_EXACT_PS_MADDS1 ? "ppc_ps_madds1" :
                               op == DOLIR_EXACT_PS_SUM0 ? "ppc_ps_sum0" :
                                                         "ppc_ps_sum1";
            auto callee = module_.getOrInsertFunction(name,
                FunctionType::get(Type::getVoidTy(context_),
                    {ptr, i8, i8, i8, i8}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(d), builder_.getInt8(a),
                 builder_.getInt8(c), builder_.getInt8(b)});
        } else if (op == DOLIR_EXACT_PS_MULS0 || op == DOLIR_EXACT_PS_MULS1) {
            syncPair(a);
            syncPair(c);
            const char* name = op == DOLIR_EXACT_PS_MULS0 ?
                "ppc_ps_muls0" : "ppc_ps_muls1";
            auto callee = module_.getOrInsertFunction(name,
                FunctionType::get(Type::getVoidTy(context_), {ptr, i8, i8, i8}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(d), builder_.getInt8(a), builder_.getInt8(c)});
        } else {
            syncPair(a);
            u32 rhs = op == DOLIR_EXACT_PS_MUL ? c : b;
            syncPair(rhs);
            const char* name = op == DOLIR_EXACT_PS_ADD ? "ppc_ps_add_op" :
                               op == DOLIR_EXACT_PS_SUB ? "ppc_ps_sub_op" :
                               op == DOLIR_EXACT_PS_MUL ? "ppc_ps_mul_op" :
                                                        "ppc_ps_div_op";
            auto callee = module_.getOrInsertFunction(name,
                FunctionType::get(Type::getVoidTy(context_), {ptr, i8, i8, i8}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt8(d), builder_.getInt8(a), builder_.getInt8(rhs)});
        }
        reloadPair(d);
        reloadState(DOLIR_STATE_FPSCR);
    }

    Value* emitPSQ(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        u32 reg = inst.immediate & 0xFFu;
        bool w = ((inst.immediate >> 8) & 1u) != 0;
        u32 gqr = (inst.immediate >> 9) & 7u;
        bool indexed = ((inst.immediate >> 12) & 1u) != 0;
        bool load = inst.aux == DOLIR_HELPER_PSQ_LOAD;
        Type* ptr = PointerType::getUnqual(context_);
        auto callee = module_.getOrInsertFunction(load ? "ppc_psq_load" : "ppc_psq_store",
            FunctionType::get(Type::getInt1Ty(context_),
                {ptr, Type::getInt8Ty(context_), Type::getInt32Ty(context_),
                 Type::getInt1Ty(context_), Type::getInt8Ty(context_),
                 Type::getInt1Ty(context_), Type::getInt32Ty(context_)}, false));
        Value* success = builder_.CreateCall(callee,
            {ctx_, builder_.getInt8(reg), operand(inst, 0), builder_.getInt1(w),
             builder_.getInt8(gqr), builder_.getInt1(indexed),
             builder_.getInt32(inst.guest_pc)});
        BasicBlock* resume = BasicBlock::Create(context_, "psq_resume", function_);
        BasicBlock* failed = BasicBlock::Create(context_, "psq_exit", function_);
        builder_.CreateCondBr(success, resume, failed);
        builder_.SetInsertPoint(failed);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot])
                reloadState(static_cast<DolIRStateSlot>(slot));
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
        return ConstantInt::getTrue(context_);
    }

    void emitStoreConditional(const DolIRInstruction& inst) {
        materialize(inst.guest_pc);
        Type* ptr = PointerType::getUnqual(context_);
        auto callee = module_.getOrInsertFunction("ppc_stwcx_op",
            FunctionType::get(Type::getVoidTy(context_),
                {ptr, Type::getInt8Ty(context_), Type::getInt32Ty(context_),
                 Type::getInt32Ty(context_)}, false));
        builder_.CreateCall(callee,
            {ctx_, builder_.getInt8(inst.immediate & 0xFFu), operand(inst, 0),
             builder_.getInt32(inst.guest_pc)});
        Value* exception = loadOffset(Type::getInt32Ty(context_),
                                      offsetof(CPUState, exception));
        BasicBlock* resume = BasicBlock::Create(context_, "stwcx_resume", function_);
        BasicBlock* failed = BasicBlock::Create(context_, "stwcx_exit", function_);
        builder_.CreateCondBr(builder_.CreateICmpEQ(exception, builder_.getInt32(0)),
                              resume, failed);
        builder_.SetInsertPoint(failed);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot])
                reloadState(static_cast<DolIRStateSlot>(slot));
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
    }

    Value* emitFPAvailable(u32 pc) {
        Value* msr = builder_.CreateLoad(Type::getInt32Ty(context_), state_[DOLIR_STATE_MSR]);
        Value* enabled = builder_.CreateICmpNE(
            builder_.CreateAnd(msr, builder_.getInt32(1u << 13)), builder_.getInt32(0));
        BasicBlock* fast = builder_.GetInsertBlock();
        BasicBlock* good = BasicBlock::Create(context_, "fp_ok", function_);
        BasicBlock* cold = BasicBlock::Create(context_, "fp_check", function_);
        builder_.CreateCondBr(enabled, good, cold);
        builder_.SetInsertPoint(cold);
        materialize(pc);
        auto callee = module_.getOrInsertFunction("ppc_fp_available",
            FunctionType::get(Type::getInt1Ty(context_),
                              {PointerType::getUnqual(context_), Type::getInt32Ty(context_)}, false));
        Value* available = builder_.CreateCall(callee, {ctx_, builder_.getInt32(pc)});
        BasicBlock* reload = BasicBlock::Create(context_, "fp_reload", function_);
        BasicBlock* bad = BasicBlock::Create(context_, "fp_exit", function_);
        builder_.CreateCondBr(available, reload, bad);
        builder_.SetInsertPoint(bad);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(reload);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot]) {
                auto stateSlot = static_cast<DolIRStateSlot>(slot);
                Value* reloaded = loadContext(stateSlot);
                builder_.CreateStore(reloaded, state_[slot]);
            }
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
        builder_.CreateBr(good);
        builder_.SetInsertPoint(good);
        PHINode* checked = builder_.CreatePHI(Type::getInt1Ty(context_), 2);
        checked->addIncoming(ConstantInt::getTrue(context_), fast);
        checked->addIncoming(available, reload);
        return checked;
    }

    Value* normalizeAddress(Value* address) {
        return builder_.CreateAnd(address, builder_.getInt32(~0x40000000u));
    }

    Value* rangeCheck(Value* normalized, u32 base, Value* size, u32 width) {
        Value* offset = builder_.CreateSub(normalized, builder_.getInt32(base));
        Value* largeEnough = builder_.CreateICmpUGE(size, builder_.getInt32(width));
        Value* last = builder_.CreateSub(size, builder_.getInt32(width));
        return builder_.CreateAnd(largeEnough, builder_.CreateICmpULE(offset, last));
    }

    Value* endianLoad(Value* pointer, Type* resultType, u32 width) {
        Type* integerType = IntegerType::get(context_, width * 8u);
        Value* loaded = builder_.CreateLoad(integerType, pointer);
        loaded = bswap(loaded);
        if (resultType != integerType)
            loaded = builder_.CreateZExtOrTrunc(loaded, resultType);
        return loaded;
    }

    Value* externalRead(Value* address, u32 width) {
        Type* ptr = PointerType::getUnqual(context_);
        Value* fn = loadOffset(ptr, offsetof(CPUState, external_read));
        BasicBlock* call = BasicBlock::Create(context_, "read_external", function_);
        BasicBlock* zero = BasicBlock::Create(context_, "read_unmapped", function_);
        BasicBlock* join = BasicBlock::Create(context_, "read_slow_join", function_);
        builder_.CreateCondBr(builder_.CreateIsNotNull(fn), call, zero);
        builder_.SetInsertPoint(call);
        materialize(current_pc_);
        auto* functionType = FunctionType::get(Type::getInt64Ty(context_),
            {ptr, Type::getInt32Ty(context_), Type::getInt8Ty(context_)}, false);
        Value* called = builder_.CreateCall(functionType, fn,
            {ctx_, address, builder_.getInt8(width)});
        Value* exception = loadOffset(Type::getInt32Ty(context_),
                                      offsetof(CPUState, exception));
        BasicBlock* resume = BasicBlock::Create(context_, "read_slow_resume", function_);
        BasicBlock* failed = BasicBlock::Create(context_, "read_slow_exit", function_);
        builder_.CreateCondBr(builder_.CreateICmpEQ(exception, builder_.getInt32(0)),
                              resume, failed);
        builder_.SetInsertPoint(failed);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot])
                reloadState(static_cast<DolIRStateSlot>(slot));
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
        builder_.CreateBr(join);
        BasicBlock* calledEnd = builder_.GetInsertBlock();
        builder_.SetInsertPoint(zero);
        Value* empty = builder_.getInt64(0);
        builder_.CreateBr(join);
        builder_.SetInsertPoint(join);
        PHINode* phi = builder_.CreatePHI(Type::getInt64Ty(context_), 2);
        phi->addIncoming(called, calledEnd);
        phi->addIncoming(empty, zero);
        return phi;
    }

    Value* emitGuestLoad(Value* address, Type* resultType, u32 width, bool sign) {
        Value* normalized = normalizeAddress(address);
        Value* ramSize = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, ram_size));
        Value* exramSize = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, exram_size));
        Value* mem1 = rangeCheck(normalized, GC_RAM_BASE, ramSize, width);
        BasicBlock* mem1Block = BasicBlock::Create(context_, "load_mem1", function_);
        BasicBlock* checkMem2 = BasicBlock::Create(context_, "load_check_mem2", function_);
        BasicBlock* mem2Block = BasicBlock::Create(context_, "load_mem2", function_);
        BasicBlock* slowBlock = BasicBlock::Create(context_, "load_slow", function_);
        BasicBlock* join = BasicBlock::Create(context_, "load_join", function_);
        builder_.CreateCondBr(mem1, mem1Block, checkMem2);

        builder_.SetInsertPoint(mem1Block);
        Value* ram = loadOffset(PointerType::getUnqual(context_), offsetof(CPUState, ram));
        Value* mem1Offset = builder_.CreateSub(normalized, builder_.getInt32(GC_RAM_BASE));
        Value* mem1Ptr = builder_.CreateInBoundsGEP(Type::getInt8Ty(context_), ram, mem1Offset);
        Value* mem1Value = endianLoad(mem1Ptr, resultType, width);
        builder_.CreateBr(join);

        builder_.SetInsertPoint(checkMem2);
        Value* exram = loadOffset(PointerType::getUnqual(context_), offsetof(CPUState, exram));
        Value* inMem2 = builder_.CreateAnd(builder_.CreateIsNotNull(exram),
            rangeCheck(normalized, WII_MEM2_BASE, exramSize, width));
        builder_.CreateCondBr(inMem2, mem2Block, slowBlock);

        builder_.SetInsertPoint(mem2Block);
        Value* mem2Offset = builder_.CreateSub(normalized, builder_.getInt32(WII_MEM2_BASE));
        Value* mem2Ptr = builder_.CreateInBoundsGEP(Type::getInt8Ty(context_), exram, mem2Offset);
        Value* mem2Value = endianLoad(mem2Ptr, resultType, width);
        builder_.CreateBr(join);

        builder_.SetInsertPoint(slowBlock);
        Value* slow64 = externalRead(address, width);
        Value* slowValue = builder_.CreateZExtOrTrunc(slow64, resultType);
        BasicBlock* slowEnd = builder_.GetInsertBlock();
        builder_.CreateBr(join);

        builder_.SetInsertPoint(join);
        PHINode* phi = builder_.CreatePHI(resultType, 3);
        phi->addIncoming(mem1Value, mem1Block);
        phi->addIncoming(mem2Value, mem2Block);
        phi->addIncoming(slowValue, slowEnd);
        if (sign && width * 8u < resultType->getIntegerBitWidth()) {
            Value* narrow = builder_.CreateTrunc(phi, IntegerType::get(context_, width * 8u));
            return builder_.CreateSExt(narrow, resultType);
        }
        return phi;
    }

    void clearReservation(Value* address) {
        Value* valid = builder_.CreateLoad(Type::getInt1Ty(context_), state_[DOLIR_STATE_RESERVE_VALID]);
        Value* reserved = builder_.CreateLoad(Type::getInt32Ty(context_), state_[DOLIR_STATE_RESERVE_ADDR]);
        Value* differentLine = builder_.CreateICmpNE(
            builder_.CreateAnd(builder_.CreateXor(reserved, address), builder_.getInt32(~31u)),
            builder_.getInt32(0));
        builder_.CreateStore(builder_.CreateAnd(valid, differentLine),
                             state_[DOLIR_STATE_RESERVE_VALID]);
    }

    void journal(Value* offset, u32 width) {
        Type* ptr = PointerType::getUnqual(context_);
        GlobalVariable* journal = cast<GlobalVariable>(module_.getOrInsertGlobal(
            "g_mem_write_journal", ptr));
        GlobalVariable* user = cast<GlobalVariable>(module_.getOrInsertGlobal(
            "g_mem_write_journal_user", ptr));
        Value* fn = builder_.CreateLoad(ptr, journal);
        BasicBlock* call = BasicBlock::Create(context_, "journal", function_);
        BasicBlock* done = BasicBlock::Create(context_, "journal_done", function_);
        builder_.CreateCondBr(builder_.CreateIsNotNull(fn), call, done);
        builder_.SetInsertPoint(call);
        auto* functionType = FunctionType::get(Type::getVoidTy(context_),
            {Type::getInt32Ty(context_), Type::getInt32Ty(context_), ptr}, false);
        builder_.CreateCall(functionType, fn,
            {offset, builder_.getInt32(width), builder_.CreateLoad(ptr, user)});
        builder_.CreateBr(done);
        builder_.SetInsertPoint(done);
    }

    void endianStore(Value* pointer, Value* value, u32 width) {
        Type* integerType = IntegerType::get(context_, width * 8u);
        Value* narrowed = value;
        if (value->getType() != integerType)
            narrowed = builder_.CreateZExtOrTrunc(value, integerType);
        builder_.CreateStore(bswap(narrowed), pointer);
    }

    void externalWrite(Value* address, Value* value, u32 width) {
        Type* ptr = PointerType::getUnqual(context_);
        Value* fn = loadOffset(ptr, offsetof(CPUState, external_write));
        BasicBlock* call = BasicBlock::Create(context_, "write_external", function_);
        BasicBlock* done = BasicBlock::Create(context_, "write_slow_done", function_);
        builder_.CreateCondBr(builder_.CreateIsNotNull(fn), call, done);
        builder_.SetInsertPoint(call);
        materialize(current_pc_);
        auto* functionType = FunctionType::get(Type::getVoidTy(context_),
            {ptr, Type::getInt32Ty(context_), Type::getInt64Ty(context_),
             Type::getInt8Ty(context_)}, false);
        builder_.CreateCall(functionType, fn,
            {ctx_, address, builder_.CreateZExtOrTrunc(value, Type::getInt64Ty(context_)),
             builder_.getInt8(width)});
        Value* exception = loadOffset(Type::getInt32Ty(context_),
                                      offsetof(CPUState, exception));
        BasicBlock* resume = BasicBlock::Create(context_, "write_slow_resume", function_);
        BasicBlock* failed = BasicBlock::Create(context_, "write_slow_exit", function_);
        builder_.CreateCondBr(builder_.CreateICmpEQ(exception, builder_.getInt32(0)),
                              resume, failed);
        builder_.SetInsertPoint(failed);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
            if (used_[slot])
                reloadState(static_cast<DolIRStateSlot>(slot));
        }
        builder_.CreateStore(builder_.getInt64(0), cycles_);
        builder_.CreateBr(done);
        builder_.SetInsertPoint(done);
    }

    void emitGuestStore(Value* address, Value* value, u32 width) {
        clearReservation(address);
        Value* normalized = normalizeAddress(address);
        Value* ramSize = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, ram_size));
        Value* exramSize = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, exram_size));
        BasicBlock* mem1Block = BasicBlock::Create(context_, "store_mem1", function_);
        BasicBlock* checkMem2 = BasicBlock::Create(context_, "store_check_mem2", function_);
        BasicBlock* mem2Block = BasicBlock::Create(context_, "store_mem2", function_);
        BasicBlock* slowBlock = BasicBlock::Create(context_, "store_slow", function_);
        BasicBlock* join = BasicBlock::Create(context_, "store_join", function_);
        builder_.CreateCondBr(rangeCheck(normalized, GC_RAM_BASE, ramSize, width),
                              mem1Block, checkMem2);

        builder_.SetInsertPoint(mem1Block);
        Value* ram = loadOffset(PointerType::getUnqual(context_), offsetof(CPUState, ram));
        Value* mem1Offset = builder_.CreateSub(normalized, builder_.getInt32(GC_RAM_BASE));
        journal(mem1Offset, width);
        Value* mem1Ptr = builder_.CreateInBoundsGEP(Type::getInt8Ty(context_), ram, mem1Offset);
        endianStore(mem1Ptr, value, width);
        builder_.CreateBr(join);

        builder_.SetInsertPoint(checkMem2);
        Value* exram = loadOffset(PointerType::getUnqual(context_), offsetof(CPUState, exram));
        Value* inMem2 = builder_.CreateAnd(builder_.CreateIsNotNull(exram),
            rangeCheck(normalized, WII_MEM2_BASE, exramSize, width));
        builder_.CreateCondBr(inMem2, mem2Block, slowBlock);

        builder_.SetInsertPoint(mem2Block);
        Value* mem2Offset = builder_.CreateSub(normalized, builder_.getInt32(WII_MEM2_BASE));
        Value* mem2Ptr = builder_.CreateInBoundsGEP(Type::getInt8Ty(context_), exram, mem2Offset);
        endianStore(mem2Ptr, value, width);
        builder_.CreateBr(join);

        builder_.SetInsertPoint(slowBlock);
        externalWrite(address, value, width);
        builder_.CreateBr(join);
        builder_.SetInsertPoint(join);
    }

    BasicBlock* directDestination(const DolIRTerminator& term, u32 slot) {
        if (term.targets[slot] != DOLIR_NO_BLOCK)
            return blocks_[term.targets[slot]];
        return externalDestination(term, slot);
    }

    const DolLLVMFunctionRange* rangeFor(u32 address) const {
        for (u32 i = 0; i < range_count_; i++)
            if (address >= ranges_[i].start && address < ranges_[i].end)
                return &ranges_[i];
        return nullptr;
    }

    BasicBlock* externalDestination(const DolIRTerminator& term, u32 slot) {
        u32 target = term.target_addresses[slot];
        const DolLLVMFunctionRange* range = rangeFor(target);
        if (!range)
            return nullptr;
        BasicBlock* callBlock = BasicBlock::Create(context_,
            term.linked ? "direct_call" : "direct_tail", function_);
        IRBuilderBase::InsertPoint saved = builder_.saveIP();
        builder_.SetInsertPoint(callBlock);
        materialize(target);
        char name[64];
        snprintf(name, sizeof(name), "func_%08X", range->start);
        auto callee = module_.getOrInsertFunction(name,
            FunctionType::get(Type::getVoidTy(context_),
                              {PointerType::getUnqual(context_)}, false));
        builder_.CreateCall(callee, {ctx_});
        if (!term.linked) {
            builder_.CreateRetVoid();
            builder_.restoreIP(saved);
            return callBlock;
        }
        u32 continuation = term.guest_pc + 4u;
        u32 continuationBlock = 0;
        bool local = continuation >= source_.guest_start &&
                     continuation < source_.guest_end &&
                     ((continuation - source_.guest_start) & 3u) == 0;
        if (local)
            continuationBlock = (continuation - source_.guest_start) / 4u;
        BasicBlock* resume = BasicBlock::Create(context_, "call_resume", function_);
        BasicBlock* mismatch = BasicBlock::Create(context_, "call_mismatch", function_);
        Value* returnedPC = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, pc));
        builder_.CreateCondBr(builder_.CreateICmpEQ(returnedPC, builder_.getInt32(continuation)),
                              resume, mismatch);
        builder_.SetInsertPoint(mismatch);
        builder_.CreateRetVoid();
        builder_.SetInsertPoint(resume);
        if (!local || continuationBlock >= blocks_.size()) {
            builder_.CreateRetVoid();
        } else {
            for (u32 state = 0; state < DOLIR_STATE_COUNT; state++) {
                if (!used_[state])
                    continue;
                auto stateSlot = static_cast<DolIRStateSlot>(state);
                builder_.CreateStore(loadContext(stateSlot), state_[state]);
            }
            builder_.CreateStore(builder_.getInt64(0), cycles_);
            builder_.CreateBr(blocks_[continuationBlock]);
        }
        builder_.restoreIP(saved);
        return callBlock;
    }

    BasicBlock* exitDestination(u32 pc) {
        BasicBlock* exit = BasicBlock::Create(context_, "side_exit", function_);
        IRBuilderBase::InsertPoint saved = builder_.saveIP();
        builder_.SetInsertPoint(exit);
        sideExit(pc);
        builder_.restoreIP(saved);
        return exit;
    }

    bool emitTerminator(const DolIRTerminator& term, raw_ostream& diagnostics) {
        switch (term.kind) {
        case DOLIR_TERM_BRANCH: {
            BasicBlock* destination = directDestination(term, 0);
            builder_.CreateBr(destination ? destination : exitDestination(term.target_addresses[0]));
            return true;
        }
        case DOLIR_TERM_COND_BRANCH: {
            BasicBlock* yes = directDestination(term, 0);
            BasicBlock* no = directDestination(term, 1);
            if (!yes) yes = exitDestination(term.target_addresses[0]);
            if (!no) no = exitDestination(term.target_addresses[1]);
            builder_.CreateCondBr(values_[term.condition], yes, no);
            return true;
        }
        case DOLIR_TERM_INDIRECT: {
            BasicBlock* taken = BasicBlock::Create(context_, "indirect_taken", function_);
            BasicBlock* fallthrough = directDestination(term, 1);
            if (!fallthrough)
                fallthrough = exitDestination(term.target_addresses[1]);
            builder_.CreateCondBr(values_[term.condition], taken, fallthrough);
            builder_.SetInsertPoint(taken);
            Value* target = values_[term.target_value];
            if (!continuations_.empty()) {
                BasicBlock* unknown = BasicBlock::Create(context_, "indirect_exit", function_);
                auto* dispatch = builder_.CreateSwitch(target, unknown,
                                                       continuations_.size());
                for (u32 block : continuations_)
                    dispatch->addCase(builder_.getInt32(source_.blocks[block].guest_address),
                                      blocks_[block]);
                builder_.SetInsertPoint(unknown);
            }
            for (u32 slot = 0; slot < DOLIR_STATE_COUNT; slot++) {
                if (dirty_[slot]) {
                    auto stateSlot = static_cast<DolIRStateSlot>(slot);
                    storeContext(stateSlot, builder_.CreateLoad(type(dolir_state_type(stateSlot)), state_[slot]));
                }
            }
            storeContext(DOLIR_STATE_PC, target);
            Value* downcount = loadOffset(Type::getInt64Ty(context_), offsetof(CPUState, downcount));
            Value* cycles = builder_.CreateLoad(Type::getInt64Ty(context_), cycles_);
            builder_.CreateStore(builder_.CreateSub(downcount, cycles),
                                 bytePtr(offsetof(CPUState, downcount)));
            builder_.CreateRetVoid();
            return true;
        }
        case DOLIR_TERM_SIDE_EXIT:
            sideExit(term.target_addresses[0]);
            return true;
        case DOLIR_TERM_FALLBACK: {
            materialize(term.guest_pc);
            auto callee = module_.getOrInsertFunction("ppc_fallback_instruction",
                FunctionType::get(Type::getVoidTy(context_),
                    {PointerType::getUnqual(context_), Type::getInt32Ty(context_),
                     Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee,
                {ctx_, builder_.getInt32(term.raw), builder_.getInt32(term.guest_pc)});
            u32 next = term.guest_pc + 4u;
            u32 nextBlock = 0;
            bool local = next >= source_.guest_start && next < source_.guest_end &&
                         ((next - source_.guest_start) & 3u) == 0;
            if (local)
                nextBlock = (next - source_.guest_start) / 4u;
            if (!local || nextBlock >= blocks_.size()) {
                builder_.CreateRetVoid();
                return true;
            }
            Value* returnedPC = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, pc));
            Value* exception = loadOffset(Type::getInt32Ty(context_), offsetof(CPUState, exception));
            Value* resume = builder_.CreateAnd(
                builder_.CreateICmpEQ(returnedPC, builder_.getInt32(next)),
                builder_.CreateICmpEQ(exception, builder_.getInt32(0)));
            BasicBlock* reload = BasicBlock::Create(context_, "fallback_resume", function_);
            BasicBlock* done = BasicBlock::Create(context_, "fallback_exit", function_);
            builder_.CreateCondBr(resume, reload, done);
            builder_.SetInsertPoint(done);
            builder_.CreateRetVoid();
            builder_.SetInsertPoint(reload);
            for (u32 state = 0; state < DOLIR_STATE_COUNT; state++) {
                if (!used_[state])
                    continue;
                auto stateSlot = static_cast<DolIRStateSlot>(state);
                builder_.CreateStore(loadContext(stateSlot), state_[state]);
            }
            builder_.CreateStore(builder_.getInt64(0), cycles_);
            builder_.CreateBr(blocks_[nextBlock]);
            return true;
        }
        case DOLIR_TERM_RETURN:
            materialize(term.target_addresses[0]);
            builder_.CreateRetVoid();
            return true;
        case DOLIR_TERM_SYSTEM_CALL: {
            materialize(term.guest_pc);
            auto callee = module_.getOrInsertFunction("ppc_system_call_exception",
                FunctionType::get(Type::getVoidTy(context_),
                    {PointerType::getUnqual(context_), Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee, {ctx_, builder_.getInt32(term.guest_pc)});
            builder_.CreateRetVoid();
            return true;
        }
        case DOLIR_TERM_RFI: {
            materialize(term.guest_pc);
            auto callee = module_.getOrInsertFunction("ppc_rfi",
                FunctionType::get(Type::getVoidTy(context_),
                    {PointerType::getUnqual(context_), Type::getInt32Ty(context_)}, false));
            builder_.CreateCall(callee, {ctx_, builder_.getInt32(term.guest_pc)});
            builder_.CreateRetVoid();
            return true;
        }
        default:
            diagnostics << "dolllvm: missing terminator at 0x"
                        << format_hex_no_prefix(term.guest_pc, 8) << "\n";
            return false;
        }
    }

    LLVMContext& context_;
    Module& module_;
    const DolIRFunction& source_;
    IRBuilder<> builder_;
    Function* function_ = nullptr;
    Argument* ctx_ = nullptr;
    BasicBlock* entry_ = nullptr;
    AllocaInst* cycles_ = nullptr;
    std::array<AllocaInst*, DOLIR_STATE_COUNT> state_{};
    std::array<bool, DOLIR_STATE_COUNT> used_{};
    std::array<bool, DOLIR_STATE_COUNT> dirty_{};
    std::vector<BasicBlock*> blocks_;
    std::vector<bool> loop_headers_;
    std::vector<Value*> values_;
    std::vector<u32> continuations_;
    const DolLLVMFunctionRange* ranges_ = nullptr;
    u32 range_count_ = 0;
    u32 current_pc_ = 0;
};

static CodeGenOptLevel codegenLevel(int level) {
    if (level <= 0) return CodeGenOptLevel::None;
    if (level == 1) return CodeGenOptLevel::Less;
    if (level == 2) return CodeGenOptLevel::Default;
    return CodeGenOptLevel::Aggressive;
}

static TargetMachine* targetMachine(const Target* target,
                                    const std::string& tripleName, int opt) {
    static thread_local std::string cachedTriple;
    static thread_local int cachedOpt = -1;
    static thread_local std::unique_ptr<TargetMachine> cachedMachine;
    if (!cachedMachine || cachedTriple != tripleName || cachedOpt != opt) {
        TargetOptions options;
        cachedMachine.reset(target->createTargetMachine(
            tripleName, "generic", "", options, Reloc::PIC_, std::nullopt,
            codegenLevel(opt)));
        cachedTriple = tripleName;
        cachedOpt = opt;
    }
    return cachedMachine.get();
}

}

extern "C" bool dolllvm_emit_object(const DolIRModule* source,
                                     const char* object_path,
                                     const DolLLVMOptions* options,
                                     FILE* diagnostics) {
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
    std::string tripleName = options && options->target_triple && options->target_triple[0]
        ? options->target_triple : llvm::sys::getDefaultTargetTriple();
    const llvm::Triple triple(tripleName);
    if (triple.getArch() != llvm::Triple::x86_64 ||
        (!triple.isOSLinux() && !triple.isOSWindows())) {
        fprintf(diagnostics, "dolllvm: supported production targets are x86-64 Linux and Windows\n");
        return false;
    }

    std::string error;
    const llvm::Target* target = llvm::TargetRegistry::lookupTarget(tripleName, error);
    if (!target) {
        fprintf(diagnostics, "dolllvm: %s\n", error.c_str());
        return false;
    }
    llvm::TargetMachine* machine = targetMachine(target, tripleName, opt);
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
        FunctionEmitter emitter(context, module, source->functions[i],
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
        llvm::PassBuilder passBuilder(machine);
        passBuilder.registerModuleAnalyses(mam);
        passBuilder.registerCGSCCAnalyses(cgam);
        passBuilder.registerFunctionAnalyses(fam);
        passBuilder.registerLoopAnalyses(lam);
        passBuilder.crossRegisterProxies(lam, fam, cgam, mam);
        llvm::ModulePassManager passes;
        std::string pipeline =
            "function(mem2reg,early-cse<memssa>,instcombine,simplifycfg,sccp,"
            "correlated-propagation,jump-threading,gvn,dse,adce,loop-simplify,"
            "loop-rotate,loop-mssa(licm),loop-vectorize,slp-vectorizer,vector-combine,"
            "tailcallelim),cgscc(inline),ipsccp,globaldce";
        if (llvm::Error error = passBuilder.parsePassPipeline(passes, pipeline)) {
            fprintf(diagnostics, "dolllvm: cannot construct optimization pipeline: %s\n",
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
        llvm::raw_fd_ostream irFile(options->ir_path, irError, llvm::sys::fs::OF_Text);
        if (irError) {
            fprintf(diagnostics, "dolllvm: cannot write IR: %s\n", irError.message().c_str());
            return false;
        }
        module.print(irFile, nullptr);
    }

    std::error_code objectError;
    llvm::raw_fd_ostream objectFile(object_path, objectError, llvm::sys::fs::OF_None);
    if (objectError) {
        fprintf(diagnostics, "dolllvm: cannot write object: %s\n", objectError.message().c_str());
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
