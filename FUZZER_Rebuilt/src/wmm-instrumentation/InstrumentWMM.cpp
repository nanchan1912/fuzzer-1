#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <atomic>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;

static cl::opt<std::string> MetadataFile(
    "wmm-metadata-file",
    cl::desc("Path to the SVF-generated metadata file"),
    cl::init("generated_output.pg"));

struct EventMeta {
  uint64_t uid = 0;
  uint64_t thread_id = 0;
  uint64_t loc_id = 0;
  uint32_t order = 0;
  std::string kind;
};

static std::string normalizeWhitespace(StringRef str) {
  std::string out;
  bool pendingSpace = false;
  for (char c : str) {
    if (isspace(static_cast<unsigned char>(c))) {
      pendingSpace = true;
      continue;
    }
    if (pendingSpace && !out.empty()) {
      out.push_back(' ');
    }
    pendingSpace = false;
    out.push_back(c);
  }
  return out;
}

static std::string generalizeRegisters(std::string text) {
  std::string out;
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ) {
    if (text[i] == '%') {
      // Find the end of the register name
      size_t j = i + 1;
      while (j < text.size() && (isalnum(static_cast<unsigned char>(text[j])) || 
                                 text[j] == '_' || text[j] == '-' || text[j] == '.')) {
        j++;
      }
      // Check if it is purely numeric
      bool isNumeric = (j > i + 1);
      for (size_t k = i + 1; k < j; ++k) {
        if (!isdigit(static_cast<unsigned char>(text[k]))) {
          isNumeric = false;
          break;
        }
      }
      if (isNumeric) {
        out.push_back('%');
      } else {
        out.append(text.substr(i, j - i));
      }
      i = j;
    } else {
      out.push_back(text[i]);
      i++;
    }
  }
  return out;
}

static std::string generalizeConstantExprs(std::string text) {
  std::string out;
  out.reserve(text.size());
  for (size_t i = 0; i < text.size(); ) {
    bool found = false;
    size_t len = 0;
    if (text.compare(i, 14, "getelementptr ") == 0) {
      found = true;
      len = 14;
    } else if (text.compare(i, 23, "getelementptr inbounds ") == 0) {
      found = true;
      len = 23;
    } else if (text.compare(i, 8, "bitcast ") == 0) {
      found = true;
      len = 8;
    }
    
    if (found) {
      size_t openParen = text.find('(', i);
      if (openParen == std::string::npos) {
        out.push_back(text[i]);
        i++;
        continue;
      }
      int parenCount = 1;
      size_t j = openParen + 1;
      while (j < text.size() && parenCount > 0) {
        if (text[j] == '(') parenCount++;
        else if (text[j] == ')') parenCount--;
        j++;
      }
      if (parenCount == 0) {
        out.push_back('%');
        i = j;
      } else {
        out.push_back(text[i]);
        i++;
      }
    } else {
      out.push_back(text[i]);
      i++;
    }
  }
  return out;
}

static std::string normalizeInstructionString(StringRef inst) {
  std::string text = inst.trim().str();
  if (!text.empty() && text.front() == '[' && text.back() == ']') {
    text = StringRef(text).substr(1, text.size() - 2).trim().str();
  }
  text = generalizeConstantExprs(text);
  text = generalizeRegisters(text);
  return normalizeWhitespace(text);
}

static uint64_t parseHexAddress(StringRef addr) {
  if (addr.starts_with("0x") || addr.starts_with("0X"))
    addr = addr.substr(2);
  uint64_t value = 0;
  for (char c : addr) {
    uint64_t digit = 0;
    if (c >= '0' && c <= '9')
      digit = c - '0';
    else if (c >= 'a' && c <= 'f')
      digit = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      digit = c - 'A' + 10;
    else
      break;
    value = (value << 4) + digit;
  }
  return value;
}

static uint64_t parseFieldSensitiveLocID(StringRef loc) {
  size_t idx = loc.find(":field_index=");
  if (idx == StringRef::npos) {
    return parseHexAddress(loc);
  }
  uint64_t base = parseHexAddress(loc.substr(0, idx));
  StringRef fieldIdx = loc.substr(idx + 13);
  
  uint64_t hash = 14695981039346656037ULL;
  for (char c : fieldIdx) {
    hash ^= static_cast<unsigned char>(c);
    hash *= 1099511628211ULL;
  }
  return base ^ hash;
}


typedef enum {
    NON_ATOMIC,
    RELAXED,
    ACQUIRE,
    RELEASE,
    ACQ_REL,
    SC
} Access_Mode;

static uint32_t parseMemoryOrder(StringRef order) {
  if (order.equals("SC") || order.equals("SequentiallyConsistent"))
    return static_cast<uint32_t>(SC);
  if (order.equals("AcqRel") || order.equals("AcquireRelease"))
    return static_cast<uint32_t>(ACQ_REL);
  if (order.equals("Acquire") || order.equals("Acq"))
    return static_cast<uint32_t>(ACQUIRE);
  if (order.equals("Release") || order.equals("Rel"))
    return static_cast<uint32_t>(RELEASE);
  if (order.equals("Relaxed") || order.equals("Rlx"))
    return static_cast<uint32_t>(RELAXED);
  if (order.equals("Unordered") || order.equals("NA") || order.empty())
    return static_cast<uint32_t>(NON_ATOMIC);

  errs() << "WMM instrument pass: Unrecognized memory order: '" << order << "'\n";
  report_fatal_error("Unrecognized memory order in SVF metadata");
}

struct GlobalInitEvent {
  uint64_t uid;
  uint64_t loc_id;
  std::string var_name;
};

struct UniqueInstruction {
  uint64_t uid = 0;
  uint64_t thread_id = 0;
  uint64_t loc_id = 0;
  uint32_t order = 0;
  std::string kind;
  std::string function_name;
  std::string instruction_address;
};

static bool parseMetadataFile(StringRef fileName,
                              std::vector<UniqueInstruction> &uniqueInstructions,
                              std::unordered_map<std::string, std::vector<size_t>> &keyToUniqueInstIndices,
                              std::vector<GlobalInitEvent> &globalInits) {
  std::ifstream in(fileName.str());
  if (!in.is_open()) {
    errs() << "Unable to open metadata file: " << fileName << "\n";
    return false;
  }

  std::string line;
  uint64_t lineNumber = 0;
  std::unordered_map<std::string, size_t> addrToUniqueIdx;

  while (std::getline(in, line)) {
    lineNumber++;
    if (line.empty())
      continue;
    if (line[0] == '#')
      continue;
    if (line[0] != 'E')
      continue;

    std::vector<std::string> fields;
    std::string field;
    std::stringstream splitter(line);
    while (std::getline(splitter, field, '\t'))
      fields.push_back(field);

    if (fields.size() < 10) {
      errs() << "WMM instrument pass: Malformed metadata line " << lineNumber
             << " (has " << fields.size() << " fields, expected >= 10): '" << line << "'\n";
      report_fatal_error("Malformed metadata line in SVF metadata file");
    }

    StringRef eventId = fields[1];
    StringRef threadId = fields[2];
    StringRef kind = fields[3];
    StringRef loc = fields[4];
    StringRef varName = fields[5];
    StringRef order = fields[6];
    StringRef instAddr = fields[7];
    StringRef context = fields[8];
    StringRef inst = fields[9];
    std::string funcName = (fields.size() > 10) ? fields[10] : "";
    funcName = StringRef(funcName).trim().str();

    if (!eventId.starts_with("e") || eventId.size() <= 1) {
      errs() << "WMM instrument pass: Invalid event ID format on line " << lineNumber
             << " ('" << eventId << "', expected format 'e<hex_val>'): '" << line << "'\n";
      report_fatal_error("Invalid event ID format in SVF metadata file");
    }

    bool isValidThread = !threadId.empty();
    for (char c : threadId) {
      if (!isdigit(static_cast<unsigned char>(c))) {
        isValidThread = false;
        break;
      }
    }
    if (!isValidThread) {
      errs() << "WMM instrument pass: Invalid thread ID value '" << threadId
             << "' on line " << lineNumber << " (must be a valid unsigned integer): '" << line << "'\n";
      report_fatal_error("Invalid thread ID in SVF metadata file");
    }

    // Check if it is a global variable initialization write event.
    if (threadId.equals("0") && kind.equals("W") && context.equals("[: ]") && inst.starts_with("[@")) {
      GlobalInitEvent gInit;
      gInit.uid = parseHexAddress(instAddr);
      gInit.loc_id = parseFieldSensitiveLocID(loc);
      gInit.var_name = varName.str();
      globalInits.push_back(gInit);
      errs() << "[WMM-PASS-DEBUG] Event " << eventId << " (" << kind << ") -> New Unique Inst UID: " 
             << gInit.uid << " Key: '" << normalizeInstructionString(inst) << "' Func: '" << funcName << "'\n";
      continue;
    }

    std::string key = normalizeInstructionString(inst);
    std::string instAddrStr = instAddr.str();

    auto it = addrToUniqueIdx.find(instAddrStr);
    if (it == addrToUniqueIdx.end()) {
      UniqueInstruction ui;
      ui.uid = parseHexAddress(instAddr);
      ui.thread_id = static_cast<uint64_t>(std::stoull(threadId.str()));
      ui.loc_id = parseFieldSensitiveLocID(loc);
      ui.order = parseMemoryOrder(order);
      ui.kind = kind.str();
      ui.function_name = funcName;
      ui.instruction_address = instAddrStr;

      size_t newIdx = uniqueInstructions.size();
      uniqueInstructions.push_back(ui);
      keyToUniqueInstIndices[key].push_back(newIdx);
      addrToUniqueIdx[instAddrStr] = newIdx;

      errs() << "[WMM-PASS-DEBUG] Event " << eventId << " (" << kind << ") -> New Unique Inst UID: " 
             << ui.uid << " Key: '" << key << "' Func: '" << funcName << "'\n";
    } else {
      errs() << "[WMM-PASS-DEBUG] Event " << eventId << " (" << kind 
             << ") -> Map to Existing Unique Inst UID: " << uniqueInstructions[it->second].uid << "\n";
    }
  }

  return !uniqueInstructions.empty() || !globalInits.empty();
}

static uint64_t getTypeSizeInBytes(Type *ty, const DataLayout &DL) {
  if (!ty->isSized())
    return 0;
  return DL.getTypeStoreSize(ty);
}

static Value *castToUInt64(Value *value, IRBuilder<> &builder) {
  Type *ty = value->getType();
  LLVMContext &ctx = builder.getContext();
  if (ty->isIntegerTy(64))
    return value;
  if (ty->isIntegerTy()) {
    unsigned width = ty->getIntegerBitWidth();
    if (width < 64)
      return builder.CreateZExt(value, builder.getInt64Ty());
    if (width > 64) {
      errs() << "WMM instrument pass: Integer type wider than 64 bits is not supported for castToUInt64: ";
      ty->print(errs());
      errs() << "\n";
      report_fatal_error("Unsupported integer type width (>64) for castToUInt64");
    }
  }
  if (ty->isPointerTy())
    return builder.CreatePtrToInt(value, builder.getInt64Ty());
  if (ty->isFloatingPointTy()) {
    unsigned width = ty->getPrimitiveSizeInBits();
    Type *intTy = IntegerType::get(ctx, width);
    Value *bitcast = builder.CreateBitCast(value, intTy);
    if (width < 64)
      return builder.CreateZExt(bitcast, builder.getInt64Ty());
    if (width == 64)
      return bitcast;
    if (width > 64) {
      errs() << "WMM instrument pass: Floating point type wider than 64 bits is not supported for castToUInt64: ";
      ty->print(errs());
      errs() << "\n";
      report_fatal_error("Unsupported floating point type width (>64) for castToUInt64");
    }
  }
  errs() << "WMM instrument pass: Unsupported type for castToUInt64: ";
  ty->print(errs());
  errs() << "\n";
  report_fatal_error("Unsupported type for castToUInt64");
}

static Value *castFromUInt64(Value *value, Type *destTy, IRBuilder<> &builder) {
  if (destTy->isIntegerTy(64))
    return value;
  if (destTy->isIntegerTy()) {
    unsigned width = destTy->getIntegerBitWidth();
    if (width < 64)
      return builder.CreateTrunc(value, destTy);
    if (width > 64) {
      errs() << "WMM instrument pass: Integer type wider than 64 bits is not supported for castFromUInt64: ";
      destTy->print(errs());
      errs() << "\n";
      report_fatal_error("Unsupported integer type width (>64) for castFromUInt64");
    }
  }
  if (destTy->isPointerTy())
    return builder.CreateIntToPtr(value, destTy);
  if (destTy->isFloatingPointTy()) {
    unsigned width = destTy->getPrimitiveSizeInBits();
    Type *intTy = IntegerType::get(builder.getContext(), width);
    if (width < 64) {
      Value *trunc = builder.CreateTrunc(value, intTy);
      return builder.CreateBitCast(trunc, destTy);
    }
    if (width == 64) {
      return builder.CreateBitCast(value, destTy);
    }
    if (width > 64) {
      errs() << "WMM instrument pass: Floating point type wider than 64 bits is not supported for castFromUInt64: ";
      destTy->print(errs());
      errs() << "\n";
      report_fatal_error("Unsupported floating point type width (>64) for castFromUInt64");
    }
  }
  errs() << "WMM instrument pass: Unsupported type for castFromUInt64: ";
  destTy->print(errs());
  errs() << "\n";
  report_fatal_error("Unsupported type for castFromUInt64");
}

static void reportNotInstantiable(StringRef fileName, StringRef reason) {
  errs() << "WMM instrument pass WARNING: The WMM instrumentation pass is not instantiable on metadata file '"
         << fileName << "' because " << reason << ". Proceeding with compilation but without WMM instrumentation.\n";
}

static bool isStackAllocated(const Value *V) {
  if (!V) return false;
  if (isa<AllocaInst>(V)) return true;
  if (auto *BC = dyn_cast<BitCastInst>(V)) {
    return isStackAllocated(BC->getOperand(0));
  }
  if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
    return isStackAllocated(GEP->getPointerOperand());
  }
  return false;
}

static const GEPOperator *findGEP(const Value *V) {
  if (!V) return nullptr;
  if (auto *GEP = dyn_cast<GEPOperator>(V)) {
    return GEP;
  }
  if (auto *BC = dyn_cast<BitCastInst>(V)) {
    return findGEP(BC->getOperand(0));
  }
  if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    if (CE->getOpcode() == Instruction::BitCast) {
      return findGEP(CE->getOperand(0));
    }
  }
  return nullptr;
}

static int64_t getConstantGEPOffset(const GEPOperator *gep, const DataLayout &DL) {
  int64_t offset = 0;
  for (auto it = gep_type_begin(gep), et = gep_type_end(gep); it != et; ++it) {
    if (const ConstantInt *ci = dyn_cast<ConstantInt>(it.getOperand())) {
      int64_t idx = ci->getSExtValue();
      if (idx == 0) continue;
      if (StructType *st = it.getStructTypeOrNull()) {
        const StructLayout *sl = DL.getStructLayout(st);
        offset += sl->getElementOffset(idx);
      } else {
        offset += idx * DL.getTypeAllocSize(it.getIndexedType());
      }
    }
  }
  return offset;
}

static Value *computeRuntimeLocId(Value *ptrVal, uint64_t baseLocId, const DataLayout &DL, IRBuilder<> &builder) {
  Type *int64Ty = builder.getInt64Ty();
  Value *baseLocVal = ConstantInt::get(int64Ty, baseLocId);
  
  const GEPOperator *outermostGep = findGEP(ptrVal);
  if (!outermostGep) {
    return baseLocVal;
  }
  
  Value *basePtr = const_cast<GEPOperator*>(outermostGep);
  while (GEPOperator *gep = dyn_cast<GEPOperator>(basePtr->stripPointerCasts())) {
    basePtr = gep->getPointerOperand();
  }
  
  Value *ptrValInt = builder.CreatePtrToInt(ptrVal, int64Ty);
  Value *basePtrInt = builder.CreatePtrToInt(basePtr, int64Ty);
  Value *totalOffset = builder.CreateSub(ptrValInt, basePtrInt);
  
  int64_t constOffset = getConstantGEPOffset(outermostGep, DL);
  
  Value *dynamicOffset = builder.CreateSub(totalOffset, ConstantInt::get(int64Ty, constOffset));
  
  return builder.CreateAdd(baseLocVal, dynamicOffset);
}

class WMMInstrumentPass : public PassInfoMixin<WMMInstrumentPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    std::vector<UniqueInstruction> uniqueInstructions;
    std::unordered_map<std::string, std::vector<size_t>> keyToUniqueInstIndices;
    std::vector<GlobalInitEvent> globalInits;
    if (!parseMetadataFile(MetadataFile, uniqueInstructions, keyToUniqueInstIndices, globalInits)) {
      reportNotInstantiable(MetadataFile, "the SVF metadata file could not be opened, is empty, or contains no valid events");
      return PreservedAnalyses::all();
    }
    std::unordered_set<size_t> usedUniqueInsts;

    LLVMContext &ctx = M.getContext();
    DataLayout DL = M.getDataLayout();
    Type *int64Ty = Type::getInt64Ty(ctx);
    Type *int32Ty = Type::getInt32Ty(ctx);
    Type *i8PtrTy = Type::getInt8Ty(ctx)->getPointerTo();

    FunctionCallee instrumentLoad = M.getOrInsertFunction(
        "__instrument_load",
        int64Ty,
        int64Ty,
        i8PtrTy,
        int32Ty,
        int64Ty,
        int64Ty,
        int64Ty);

    FunctionCallee instrumentStore = M.getOrInsertFunction(
        "__instrument_store",
        i8PtrTy,
        int64Ty,
        i8PtrTy,
        int64Ty,
        int32Ty,
        int64Ty,
        int64Ty,
        int64Ty);

    FunctionCallee instrumentRMW = M.getOrInsertFunction(
        "__instrument_rmw",
        int64Ty,     // Returns old value
        int64Ty,     // uid
        i8PtrTy,     // addr
        int32Ty,     // op (AtomicRMWInst::BinOp)
        int64Ty,     // value (operand)
        int32Ty,     // order
        int64Ty,     // thread_id
        int64Ty,     // loc_id
        int64Ty);    // value_size

    // Strong and weak cmpxchg are separate entry points rather than a flag
    // argument, so the runtime can apply the right instantiability rule
    // without the graph vocabulary having to carry strong/weak at all.
    //
    // The final i8* is an out-parameter for the scheduler's verdict on whether
    // the swap happened. It is an out-param rather than a {i64, i8} return
    // because a struct return would have to match clang's ABI lowering for the
    // C definition exactly (register pair vs sret, target dependent), whereas
    // a pointer is trivially portable.
    auto makeCmpXchgCallee = [&](const char *name) {
        return M.getOrInsertFunction(
            name,
            int64Ty,     // Returns old value
            int64Ty,     // uid
            i8PtrTy,     // addr
            int64Ty,     // compare_val
            int64Ty,     // new_val
            int32Ty,     // order
            int64Ty,     // thread_id
            int64Ty,     // loc_id
            int64Ty,     // value_size
            i8PtrTy);    // success_out
    };
    FunctionCallee instrumentCmpXchgStrong = makeCmpXchgCallee("__instrument_cmpxchg_strong");
    FunctionCallee instrumentCmpXchgWeak   = makeCmpXchgCallee("__instrument_cmpxchg_weak");

    FunctionCallee instrumentFence = M.getOrInsertFunction(
        "__instrument_fence",
        Type::getVoidTy(ctx),
        int64Ty,
        int32Ty,
        int64Ty);

    bool changed = false;

    Function *mainFunc = nullptr;
    for (Function &F : M) {
      if (F.isDeclaration()) continue;
      StringRef name = F.getName();
      if (name.equals("main") || name.equals("user_main") ||
          name.contains("user_main") || name.ends_with("user_main")) {
        mainFunc = &F;
        break;
      }
    }
    // COMPILE-TIME vs RUNTIME SEPARATION & PORTABILITY DESIGN:
    // To keep the runtime binary completely independent of static analysis artifacts (like `.pg` files),
    // we inject the global initializers at compile time.
    // If we were to read `.pg` at runtime, the binary would depend on static file paths, which breaks
    // execution in sandboxed, remote, or fuzzing contexts (e.g. AFL loops). In addition, parsing a text
    // file at program startup causes severe performance overhead. 
    //
    // SOLUTION: We statically resolve the global initializers from the `.pg` file here, locate the 
    // binary's entry function ('main' or 'user_main'), and directly inject '__instrument_store' call 
    // instructions at program entry. This registers all initial writes with the scheduler dynamically 
    // under Thread ID 0 (TID=0) at startup, with zero file I/O or dynamic `.pg` lookup.
    if (mainFunc && !mainFunc->isDeclaration()) {
      IRBuilder<> builder(&mainFunc->getEntryBlock().front());
      for (const auto &gInit : globalInits) {
        GlobalVariable *GV = M.getGlobalVariable(gInit.var_name, true);
        if (!GV) continue;
        
        Value *addr = builder.CreateBitCast(GV, i8PtrTy);
        uint64_t size = getTypeSizeInBytes(GV->getValueType(), DL);
        
        // Inject inline '__instrument_store' hook call:
        // - UID: The deterministic compile-time unique event ID.
        // - Addr: The run-time resolved memory address of the global variable.
        // - Value: 0 (unused dummy value, the actual runtime bytes will be read dynamically from memory).
        // - Order: 0 (Relaxed order).
        // - Thread ID: 0 (TID=0 denotes the system initializer thread context).
        // - Location ID: The deterministic FNV-1a hash of the variable name (e.g. '0x9a79ee9baa52a2b8').
        // - Size: Calculated size of the global variable type in bytes.
        builder.CreateCall(
            instrumentStore,
            {
                ConstantInt::get(int64Ty, gInit.uid),
                addr,
                ConstantInt::get(int64Ty, 0),
                ConstantInt::get(int32Ty, 0), // NON_ATOMIC
                ConstantInt::get(int64Ty, (uint64_t)-1), // Thread ID -1 for global initializer
                ConstantInt::get(int64Ty, gInit.loc_id),
                ConstantInt::get(int64Ty, size),
            });
        changed = true;
      }
    }

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      for (BasicBlock &BB : F) {
        for (auto it = BB.begin(), end = BB.end(); it != end;) {
          Instruction &I = *it++;
          std::string instText;
          raw_string_ostream stream(instText);
          I.print(stream);
          std::string rawKey = normalizeInstructionString(stream.str());
          std::string currentFunc = F.getName().str();

          auto keyIt = keyToUniqueInstIndices.find(rawKey);
          if (keyIt == keyToUniqueInstIndices.end())
            continue;

          const UniqueInstruction *matchedUI = nullptr;
          for (size_t instIdx : keyIt->second) {
            if (usedUniqueInsts.count(instIdx))
              continue;

            const UniqueInstruction &candidate = uniqueInstructions[instIdx];
            if (candidate.function_name.empty() || candidate.function_name == currentFunc) {
              matchedUI = &candidate;
              usedUniqueInsts.insert(instIdx);
              break;
            }
          }

          if (!matchedUI)
            continue;

          const UniqueInstruction &meta = *matchedUI;
          IRBuilder<> builder(&I);

          if (auto *loadInst = dyn_cast<LoadInst>(&I)) {
            if (isStackAllocated(loadInst->getPointerOperand()))
              continue;
            Value *addr = builder.CreateBitCast(loadInst->getPointerOperand(), i8PtrTy);
            uint64_t size = getTypeSizeInBytes(loadInst->getType(), DL);
            Value *locIdVal = computeRuntimeLocId(loadInst->getPointerOperand(), meta.loc_id, DL, builder);
            Value *call = builder.CreateCall(
                instrumentLoad,
                {
                    ConstantInt::get(int64Ty, meta.uid),
                    addr,
                    ConstantInt::get(int32Ty, meta.order),
                    ConstantInt::get(int64Ty, meta.thread_id),
                    locIdVal,
                    ConstantInt::get(int64Ty, size),
                });
            Value *replacement = castFromUInt64(call, loadInst->getType(), builder);
            loadInst->replaceAllUsesWith(replacement);
            loadInst->eraseFromParent();
            changed = true;
            continue;
          }

          if (auto *storeInst = dyn_cast<StoreInst>(&I)) {
            if (isStackAllocated(storeInst->getPointerOperand()))
              continue;
            Value *addr = builder.CreateBitCast(storeInst->getPointerOperand(), i8PtrTy);
            uint64_t size = getTypeSizeInBytes(storeInst->getValueOperand()->getType(), DL);
            Value *storedVal = castToUInt64(storeInst->getValueOperand(), builder);
            Value *locIdVal = computeRuntimeLocId(storeInst->getPointerOperand(), meta.loc_id, DL, builder);
            builder.CreateCall(
                instrumentStore,
                {
                    ConstantInt::get(int64Ty, meta.uid),
                    addr,
                    storedVal,
                    ConstantInt::get(int32Ty, meta.order),
                    ConstantInt::get(int64Ty, meta.thread_id),
                    locIdVal,
                    ConstantInt::get(int64Ty, size),
                });
            storeInst->eraseFromParent();
            changed = true;
            continue;
          }

          if (auto *rmwInst = dyn_cast<AtomicRMWInst>(&I)) {
            if (isStackAllocated(rmwInst->getPointerOperand()))
              continue;
            Value *addr = builder.CreateBitCast(rmwInst->getPointerOperand(), i8PtrTy);
            uint64_t size = getTypeSizeInBytes(rmwInst->getValOperand()->getType(), DL);
            Value *val = castToUInt64(rmwInst->getValOperand(), builder);
            Value *locIdVal = computeRuntimeLocId(rmwInst->getPointerOperand(), meta.loc_id, DL, builder);
            Value *call = builder.CreateCall(
                instrumentRMW,
                {
                    ConstantInt::get(int64Ty, meta.uid),
                    addr,
                    ConstantInt::get(int32Ty, static_cast<uint32_t>(rmwInst->getOperation())),
                    val,
                    ConstantInt::get(int32Ty, meta.order),
                    ConstantInt::get(int64Ty, meta.thread_id),
                    locIdVal,
                    ConstantInt::get(int64Ty, size),
                });
            Value *replacement = castFromUInt64(call, rmwInst->getType(), builder);
            rmwInst->replaceAllUsesWith(replacement);
            rmwInst->eraseFromParent();
            changed = true;
            continue;
          }

          if (auto *cmpxchg = dyn_cast<AtomicCmpXchgInst>(&I)) {
            if (isStackAllocated(cmpxchg->getPointerOperand()))
              continue;
            Value *addr = builder.CreateBitCast(cmpxchg->getPointerOperand(), i8PtrTy);
            Type *valTy = cmpxchg->getNewValOperand()->getType();
            uint64_t size = getTypeSizeInBytes(valTy, DL);
            Value *compareVal = castToUInt64(cmpxchg->getCompareOperand(), builder);
            Value *newVal = castToUInt64(cmpxchg->getNewValOperand(), builder);
            Value *locIdVal = computeRuntimeLocId(cmpxchg->getPointerOperand(), meta.loc_id, DL, builder);

            // Slot for the runtime's verdict. Allocated in the entry block so
            // a cmpxchg inside a loop does not grow the stack per iteration.
            IRBuilder<> entryBuilder(&F.getEntryBlock(),
                                     F.getEntryBlock().getFirstInsertionPt());
            AllocaInst *successSlot =
                entryBuilder.CreateAlloca(Type::getInt8Ty(ctx), nullptr, "wmm.cas.success");
            builder.CreateStore(ConstantInt::get(Type::getInt8Ty(ctx), 0), successSlot);
            Value *successPtr = builder.CreateBitCast(successSlot, i8PtrTy);

            // C11 compare_exchange_weak may fail spuriously; the scheduler
            // needs to know which flavour this is to decide instantiability.
            Value *call = builder.CreateCall(
                cmpxchg->isWeak() ? instrumentCmpXchgWeak : instrumentCmpXchgStrong,
                {
                    ConstantInt::get(int64Ty, meta.uid),
                    addr,
                    compareVal,
                    newVal,
                    ConstantInt::get(int32Ty, meta.order),
                    ConstantInt::get(int64Ty, meta.thread_id),
                    locIdVal,
                    ConstantInt::get(int64Ty, size),
                    successPtr,
                });
            Value *oldVal = castFromUInt64(call, valTy, builder);

            // Use the scheduler's verdict, NOT `oldVal == compareOperand`.
            // Recomputing the comparison here would report success whenever the
            // values happen to match, even on a weak CAS the scheduler
            // deliberately failed and did not store -- so the program would
            // take the success branch while memory still held the old value.
            Value *successByte = builder.CreateLoad(Type::getInt8Ty(ctx), successSlot);
            Value *success = builder.CreateICmpNE(
                successByte, ConstantInt::get(Type::getInt8Ty(ctx), 0));

            StructType *structTy = cast<StructType>(cmpxchg->getType());
            Value *structVal = UndefValue::get(structTy);
            structVal = builder.CreateInsertValue(structVal, oldVal, 0);
            structVal = builder.CreateInsertValue(structVal, success, 1);
            cmpxchg->replaceAllUsesWith(structVal);
            cmpxchg->eraseFromParent();
            changed = true;
            continue;
          }

          if (auto *fenceInst = dyn_cast<FenceInst>(&I)) {
            builder.CreateCall(
                instrumentFence,
                {
                    ConstantInt::get(int64Ty, meta.uid),
                    ConstantInt::get(int32Ty, meta.order),
                    ConstantInt::get(int64Ty, meta.thread_id),
                });
            fenceInst->eraseFromParent();
            changed = true;
            continue;
          }

          // If we matched an event, but the instruction is not a direct memory access instruction
          // (Load, Store, RMW, CmpXchg, or Fence), it is not directly instrumentable by hooks.
          // Under "NO fallthrough defaults", we explicitly print a diagnostic log explaining the reason
          // why it is not instrumentable, and skip it safely instead of raising a fatal error or silent bypass.
          errs() << "WMM instrument pass: Matched event in SVF metadata, but instruction is of non-memory or non-direct-access type: ";
          I.print(errs());
          errs() << " (skipping instrumentation for this instruction)\n";
        }
      }
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "WMMInstrument", "v0.1",
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [&](StringRef Name, ModulePassManager &MPM,
                ArrayRef<PassBuilder::PipelineElement>) {
              if (Name == "wmm-instrument") {
                MPM.addPass(WMMInstrumentPass());
                return true;
              }
              return false;
            });
      }};
}
