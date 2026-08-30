#include "MTA/MHP.h"
#include "MTA/MTA.h"
#include "MTA/TCT.h"
#include "SVFIR/SVFIR.h"
#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/CppUtil.h"
#include "SVF-LLVM/BasicTypes.h"
#include <llvm/Support/raw_ostream.h>



// #include "../../svf-llvm/include/SVF-LLVM/SVFIRBuilder.h"
#include <SVF-LLVM/SVFIRBuilder.h>
#include "MTA/FSMPTA.h"
#include "Util/Options.h"
#include "Util/CxtStmt.h"

#include "WPA/Andersen.h"
#include <iostream>
#include <queue>
#include <set>
#include <sstream>
#include <cctype>

#include "./anal.h"

using namespace llvm;
using namespace std;
using namespace SVF;

// Set to 1 to enable verbose static analysis debug prints (which can be very large)
#define VERBOSE_DEBUG_PRINT 0

#if !VERBOSE_DEBUG_PRINT
struct DummyStream {
    template <typename T>
    DummyStream& operator<<(const T&) { return *this; }
    DummyStream& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
    void flush() {}
};
static DummyStream dummy_stream;
#define cout dummy_stream
#define outs() nulls()
#endif

std::vector<std::pair<NodeID, NodeID>> points_to_info;
std::set<std::pair<std::string, std::string>> missing_edges;
std::ofstream outputFile("completeness_check.md");

bool is_llvm_instruction_atomic(const Value* val) {
    if (!val) return false;
    if (const LoadInst* LI = dyn_cast<LoadInst>(val)) {
        return LI->isAtomic();
    }
    if (const StoreInst* SI = dyn_cast<StoreInst>(val)) {
        return SI->isAtomic();
    }
    if (isa<AtomicRMWInst>(val) || isa<AtomicCmpXchgInst>(val) || isa<FenceInst>(val)) {
        return true;
    }
    return false;
}

bool is_call_or_invoke(const Value* val) {
    if (!val) return false;
    return isa<CallInst>(val) || isa<InvokeInst>(val);
}

typedef class event_info
{
public:
    string event_id;
    string threadID;
    string kind;
    const SVF::SVFValue* location_addr;
    string field_index = "";
    string var_name;
    string access_mode;
    string is_atomic = "unknown";

    inst_cxt_pair inst_cxt;
    bool is_global; //just a temporary thing I added for soundness check for edges within thread 0 - well, it turned out to be useful for some checks in write_to_file func as well! :)


    event_info(string eventID, string tid, string k, const SVF::SVFValue*  loc, string offset, string varName, string mode, inst_cxt_pair ic, bool is_global = false, string atomic = "unknown")
        : event_id(eventID), threadID(tid), kind(k), location_addr(loc), field_index(offset), var_name(varName), access_mode(mode), is_atomic(atomic), inst_cxt(ic), is_global(is_global){}
} event_info;

// storing the shared locations, events on those locations per thread and the control flow edges btwn events
std::set<std::pair<std::pair<const SVF::SVFValue*, std::string>, std::string>> shared_vars;  //{{location_addr, field_index}, var_name}
// threadID -> [event_info]
std::map<std::string, std::vector<event_info*>> threadEvents; 

std::unordered_map<std::string, std::set<std::string>> cfEdges_map;
std::unordered_map<std::string, std::set<std::string>> swEdges_map;

std::map<CxtThread, std::pair<const SVFValue*, bool>> thread_analysis_status;
// SVFValue here corresponds to alloca instructions like this: %t2 = alloca i64, align 8 
// I have included this as this was the only thing I could get about the joined thread - I intend to use this to get the corresponding CxtThread

LLVMModuleSet* llvmmod = LLVMModuleSet::getLLVMModuleSet();


// REVISIT: for now, I am giving event ids starting from 0, should find a way that works with the simulator
int eventCounter = 1;

// mapping each SVF instruction on shared var to an event id
std::map<inst_cxt_pair, std::string> instToEventID;
std::set <inst_cxt_pair> connect_to_next_bb;


// typedef class thread_fork_info{
//     public:
//     std::set<CxtThread> children_threads;
//     std::set<SVFInstruction*> last_encountered_events;
//     bool thread_joined;
    
//     thread_fork_info(std::set<CxtThread> children, std::set<SVFInstruction*> last_events, bool joined)
//     : children_threads(children), last_encountered_events(last_events), thread_joined(joined){}
// } thread_fork_info;

// //map from parent_thread to thread_fork_info struct
// std::map<CxtThread, thread_fork_info> forked_threads;

// I perhaps don't need to maintain all these and do a complex implementation
// All I need is the last encountered inst per thread since the prev_inst I use depends on the order in which I explore the instructions
// The API allows me to get the parents for each thread (from TCT class)
// when I encounter a join, I can simply add an sw edge from the last encountered events in the parent threads 

// std::map<CxtThread, std::string> cxtThread_to_threadID_map;
// std::map<CxtThread, std::set<SVFInstruction*>> last_encountered_events;
// These 2 are similar, so merging them into one pair
std::map<CxtThread, std::pair<std::string, std::vector<std::pair<SVFInstruction*, CallStrCxt>>>> threads_last_events_map;



typedef class ICFGSuccessor{
    public:
        ICFGNode* curr_inst;
        ICFGNode* prev_shared_inst;
        // I use this only when I enounter a callICFGNode until I reach the corresponding retICFGNode - to capture the context of the call
        const RetICFGNode* retNode = nullptr; 

        ICFGSuccessor(ICFGNode* curr_queue_entry, ICFGNode* prev, const RetICFGNode* ret)
            : curr_inst(curr_queue_entry), prev_shared_inst(prev), retNode(ret){}
}ICFGSuccessor;


string get_call_context_string(const SVF::CallStrCxt& cs_cxt){
    std::string str;
	std::stringstream rawstr(str);
	rawstr << "[:";
	for(CallStrCxt::const_iterator it = cs_cxt.begin(), eit = cs_cxt.end(); it!=eit; ++it)
	{
		rawstr << *it << " ";
	}
	rawstr << " ]";

    return rawstr.str();
}

void print_call_context(const SVF::CallStrCxt& cs_cxt){
	cout << get_call_context_string(cs_cxt) << endl;
}


string get_access_mode(const SVF::SVFInstruction* svfInstruction)
{
    AtomicOrdering access_mode; 
    auto val = dyn_cast<const SVF::SVFValue>(svfInstruction);
    if(SVFUtil::isa<SVF::LoadInst>(llvmmod->getLLVMValue(val))){
        const auto* LI = dyn_cast<LoadInst>(llvmmod->getLLVMValue(val));
        if(LI){
            access_mode = LI -> getOrdering();
        }
    }else if(SVFUtil::isa<SVF::StoreInst>(llvmmod->getLLVMValue(val))){
        const auto* SI = dyn_cast<StoreInst>(llvmmod->getLLVMValue(val));
        if(SI){
            access_mode = SI -> getOrdering();
        }
    }else if(SVFUtil::isa<SVF::FenceInst>(llvmmod->getLLVMValue(val))){
        const auto* FI = dyn_cast<FenceInst>(llvmmod->getLLVMValue(val));
        if(FI){
            access_mode = FI -> getOrdering();
        }
    }else if(SVFUtil::isa<SVF::AtomicCmpXchgInst>(llvmmod->getLLVMValue(val))){
        const auto* CXI = dyn_cast<AtomicCmpXchgInst>(llvmmod->getLLVMValue(val));
        if(CXI){
            access_mode = CXI -> getMergedOrdering();
        }
    }else if(SVFUtil::isa<SVF::AtomicRMWInst>(llvmmod->getLLVMValue(val))){
        const auto* RMWI = dyn_cast<AtomicRMWInst>(llvmmod->getLLVMValue(val));
        if(RMWI){
            access_mode = RMWI -> getOrdering();
        }
    }else{
        return "unknown inst";
    }

    switch(access_mode){
        case AtomicOrdering::NotAtomic:
            cout << "Atomic Ordering: NotAtomic" << endl;
            return "NA";
        case AtomicOrdering::Unordered:
            cout << "Atomic Ordering: Unordered" << endl;
            return "Unordered";
        case AtomicOrdering::Monotonic:
            cout << "Atomic Ordering: Monotonic" << endl;
            return "Rlx";
        case AtomicOrdering::Acquire:
            cout << "Atomic Ordering: Acquire" << endl;
            return "Acq";
        case AtomicOrdering::Release:
            cout << "Atomic Ordering: Release" << endl;
            return "Rel";
        case AtomicOrdering::AcquireRelease:
            cout << "Atomic Ordering: AcquireRelease" << endl;
            return "AcqRel";
        case AtomicOrdering::SequentiallyConsistent:
            cout << "Atomic Ordering: SequentiallyConsistent" << endl;
            return "SC";
        default:
            cout << "Atomic Ordering: unknown" << endl;
            return "unknown ordering";
    }
}


bool is_shared(const SVF::SVFValue* val){
    if (SVFUtil::isa<SVF::LoadInst>(llvmmod->getLLVMValue(val)) ||
        SVFUtil::isa<SVF::StoreInst>(llvmmod->getLLVMValue(val)) ||
        SVFUtil::isa<SVF::FenceInst>(llvmmod->getLLVMValue(val)) ||
        SVFUtil::isa<SVF::AtomicCmpXchgInst>(llvmmod->getLLVMValue(val)) ||
        SVFUtil::isa<SVF::AtomicRMWInst>(llvmmod->getLLVMValue(val)))
        {
            return true;
        }
        return false;
}


bool has_shared_location(const SVF::SVFValue* location_addr, std::string field_index){
     if (!location_addr){
        return false;
    }

    for (const auto& shared : shared_vars){
        if (shared.first.first == location_addr){
            if (shared.first.second == field_index){
                return true;
            }else{
                //insert a new entry for this location with the new field index - this is to handle the case where we have multiple accesses to the same location but different fields being accessed - we want to capture all of them as shared locations
                shared_vars.insert({{location_addr, field_index}, shared.second});
                return true;
            }
        }
    }
    return false;
}

std::string get_field_index_from_ptr(const Value* ptr){
    //printing out ptr for debugging
    cout << "\n[FIELD DEBUG get_field_index_from_ptr] ptr = ";
    ptr->print(llvm::outs());
    cout << "\n";


    if (!ptr){
        cout << "[DEBUG FIELD SENSITIVITY] No pointer found, returning empty field index" << endl;
        return "";
    }

    // const Value* stripped = ptr->stripPointerCasts();
    // cout << "\n[FIELD DEBUG get_field_index_from_ptr] Stripped pointer = ";
    // stripped->print(llvm::outs());
    // cout << "\n";

    const GEPOperator* gep = dyn_cast<GEPOperator>(ptr);
    if (!gep){
        gep = dyn_cast<GEPOperator>(ptr->stripPointerCasts());
        cout << "[DEBUG FIELD SENSITIVITY] No GEP operator found, returning empty field index" << endl;
        return "";
    }

    if (gep->getNumOperands() <= 1){
        cout << "[DEBUG FIELD SENSITIVITY] GEP has no indices, returning empty field index" << endl;
        return "";
    }

    // const Value* lastIdx = gep->getOperand(gep->getNumOperands() - 1);
    // const ConstantInt* ci = dyn_cast<ConstantInt>(lastIdx);
    // if (!ci){
    //     cout << "[DEBUG FIELD SENSITIVITY] Last index is not a constant integer, returning empty field index" << endl;

    //     return "";
    // }

    std::string path = "";

    //setting i = 2 to avoid the first index which is for the pointer (not relevant to us)
    for (unsigned i = 2; i < gep->getNumOperands(); ++i){
        if (auto* CI = dyn_cast<ConstantInt>(gep->getOperand(i))){
            if (!path.empty())
                path += ".";
            path += std::to_string(CI->getSExtValue());
        }
    }

    cout << "[DEBUG FIELD SENSITIVITY] field index path: " << path << endl;

    return path;
}




std::pair<SVFInstruction*, CallStrCxt> check_inst(SVFIR* pag, TCT* tct, const SVFInstruction* inst, const CallStrCxt cs_cxt, SVFInstruction* prevInst, CallStrCxt prevInst_cxt, CxtThread cxt_thread, bool from_a_fork_inst, bool join_encountered){
    cout << "check_inst called for the inst: " << inst->toString() << endl;
    cout << "Context of the inst: ";
    print_call_context(cs_cxt);

    SVFInstruction* prevInst_passed = prevInst;
    cout << "prevInst: " << (prevInst ? prevInst->toString() : "null") << endl;
    cout << "prevInst context: ";
    print_call_context(prevInst_cxt);

    const SVF::SVFValue* val = static_cast<const SVF::SVFValue*>(inst);

    
        bool not_fence = false;
        const SVF::SVFValue*  location_addr = nullptr;
        string field_index = "";
        std::string var_name = "";
        string kind;
        string access_mode = get_access_mode(inst);

        if(is_shared(val)){
            cout << "--> Load/Store/Fence/RMW" << endl;

            if (SVFUtil::isa<SVF::LoadInst>(llvmmod->getLLVMValue(val)) ||
            SVFUtil::isa<SVF::StoreInst>(llvmmod->getLLVMValue(val))){
                
                not_fence = true;
                cout << "[DEBUG 0] Found a load/store instruction: " << inst -> toString() << endl;
                
                // Try to extract the location (global variable name)
                const Value* ptr = nullptr;
                
                if (const auto* LI = dyn_cast<LoadInst>(llvmmod->getLLVMValue(val))){
                    ptr = LI->getPointerOperand();
                } 
                else if (const auto* SI = dyn_cast<StoreInst>(llvmmod->getLLVMValue(val))){
                    ptr = SI->getPointerOperand();
                } 

                const SVFInstruction* ptr_inst = nullptr;
                if (const auto* llvm_ptr_inst = dyn_cast<Instruction>(ptr)){
                    ptr_inst = llvmmod->getSVFInstruction(llvm_ptr_inst);
                    cout << "ptr_inst: " << ptr_inst->toString() << endl;
                    cout << endl;
                }
                
                if (ptr) {
                    //printing out ptr for debugging
                    cout << "\n";
                    llvm::outs() << "\n[FIELD DEBUG check_inst] ptr = ";
                    ptr->print(llvm::outs());
                    cout << "\n";

                    field_index = get_field_index_from_ptr(ptr);
                    ptr = ptr->stripPointerCasts();
                    if (const auto* GV = dyn_cast<GlobalVariable>(ptr)){
                        var_name = GV->getName().str();

                        location_addr = dyn_cast<const SVF::SVFValue>(llvmmod->getSVFGlobalValue(GV));
                        cout << "[line 242]pointer to shared loc (addr): " << location_addr << ", field index: " << field_index << endl;
                    }else{
                        auto loc_pair = get_location_pointed_to(pag, ptr_inst);
                        var_name = loc_pair.first;
                        location_addr = loc_pair.second.first;
                        // field_index = loc_pair.second.second;
                    }
                }

                kind = SVFUtil::isa<SVF::LoadInst>(llvmmod->getLLVMValue(val)) ? "R" : "W";
                cout << "[DEBUG 0] Load/Store location: " << location_addr << ", field index: " << field_index << ", var name: " << var_name << endl;
            }
            else if(SVFUtil::isa<SVF::FenceInst>(llvmmod->getLLVMValue(val))){
                kind = "F";
                cout << "fence identified" << endl;

            }else if (SVFUtil::isa<SVF::AtomicCmpXchgInst>(llvmmod->getLLVMValue(val)) ||
                SVFUtil::isa<SVF::AtomicRMWInst>(llvmmod->getLLVMValue(val))){
                not_fence = true;
                cout << "[DEBUG 10] Found a RMW instruction: " << inst -> toString() << endl;
                
                // Try to extract the location (global variable name)
                const Value* ptr = nullptr;
                
                if (const auto* RMWI = dyn_cast<AtomicRMWInst>(llvmmod->getLLVMValue(val))){
                    kind = "RMW";
                    ptr = RMWI->getPointerOperand();
                }else if (const auto* CXI = dyn_cast<AtomicCmpXchgInst>(llvmmod->getLLVMValue(val))){
                    kind = "CAS";
                    ptr = CXI->getPointerOperand();
                }

                if (ptr) {
                    cout << "\n[FIELD DEBUG check_inst] ptr = ";
                    ptr->print(llvm::outs());
                    cout << "\n";
                    
                    field_index = get_field_index_from_ptr(ptr);

                    ptr = ptr->stripPointerCasts();
                    // llvm::outs() << "[PTR after stripping pointer casts] " << *ptr; 
                    // cout << endl;

                    const SVFInstruction* ptr_inst = nullptr;
                    if (const auto* llvm_ptr_inst = dyn_cast<Instruction>(ptr)){
                        ptr_inst = llvmmod->getSVFInstruction(llvm_ptr_inst);
                    }


                    if (const auto* GV = dyn_cast<GlobalVariable>(ptr)){
                        var_name = GV->getName().str();

                        location_addr = dyn_cast<const SVF::SVFValue>(llvmmod->getSVFGlobalValue(GV));

                        cout << "[line 289]pointer to shared loc (addr): " << location_addr << ", field index: " << field_index << endl;

                    }else{
                        auto loc_pair = get_location_pointed_to(pag, ptr_inst);
                        var_name = loc_pair.first;
                        location_addr = loc_pair.second.first;
                        // field_index = loc_pair.second.second;
                    }
                }
                cout << "[DEBUG 10] RMW location: " << location_addr << ", field index: " << field_index << ", variable: " << var_name << endl;
            }

            if((not_fence && has_shared_location(location_addr, field_index))||(!not_fence)){
                cout << "--> This is a shared variable: " << var_name << ", addr: " << location_addr << ", field index: " << field_index << endl;
                std::string threadIDStr = threads_last_events_map[cxt_thread].first;
                write_to_thread_events(inst, cs_cxt, cxt_thread, location_addr, field_index, var_name, inst -> toString(), kind, access_mode);
                // Create CF edge from previous instruction to the current instruction within the bb
                if (prevInst){
                    cout << "Wrote inst [" << inst -> toString() << "] to thread events, prevInst: [" << prevInst -> toString() << "]" << endl;
            
                    if(instToEventID.count({prevInst, prevInst_cxt})){
                        // {
                        //     //TEMP - printing instToEventID
                        //     cout << "--------------------------------" << endl;
                        //     cout << "instToEventID mapping: " << endl;
                        //     for(auto i:instToEventID){
                        //         cout << "instToEventID: [" << i.first.first->toString() << ", ";
                        //         print_call_context(i.first.second);
                        //         cout << "] --> " << i.second << endl;
                        //     }
                        //     cout << "--------------------------------" << endl;
                        // }
                        std::string from_event_id = instToEventID[{prevInst, prevInst_cxt}];
                        std::string to_event_id = instToEventID[{const_cast<SVFInstruction*>(inst), cs_cxt}];
                        
                        cout << "prevInst has the evnt ID: " << from_event_id << endl;
                        if(instToEventID.count({const_cast<SVFInstruction*>(inst), cs_cxt})){
                            cout << "inst has the evnt ID: " << to_event_id << endl;

                            if(from_a_fork_inst || join_encountered){
                                //since we reached here from a fork instruction, we would have to add a sw edge from the prevInst to this new shared inst
                                swEdges_map[from_event_id].insert(to_event_id);
                                cout << "Inserting edge to swEdges_map: " << from_event_id << " --> " << to_event_id << endl;
                            }else{
                                // If to_event_id is not present in the map among edges from the from_event_id, add it now, else skip
                                if(find(cfEdges_map[from_event_id].begin(), cfEdges_map[from_event_id].end(), to_event_id) == cfEdges_map[from_event_id].end()){
                                    cout << "[Creating CF Edge] from: [" << prevInst->toString() << "] --> to [" << inst->toString() << "]" << endl;
                                    
                                    cout << "From (" << from_event_id << ") --> " << "To (" << to_event_id << ")" << endl;
                                    cfEdges_map[from_event_id].insert(to_event_id);
                                }else{
                                    cout << "CF edge already exists from: [" << prevInst->toString() << "] --> to [" << inst->toString() << "]" << endl;
                                }
                            }
                        }
                    }
                }
                prevInst = const_cast<SVFInstruction*>(inst);
                cout << "setting prevInst to: " << prevInst->toString() << endl;

                prevInst_cxt = cs_cxt;


                // if(instToEventID.count({prevInst, cs_cxt})){
                //     cout << "prev inst has an id" << endl;
                //     if(instToEventID.count({const_cast<SVFInstruction*>(inst), cs_cxt})){
                        
                //         cout << "[To next bb] from: [" << instToEventID[{prevInst, cs_cxt}] << ": " << prevInst->toString() << "] --> to [" << instToEventID[{const_cast<SVFInstruction*>(inst), cs_cxt}] << ": "  << inst->toString() << "]" << endl;
                //         cfEdges_map[instToEventID[{prevInst, cs_cxt}]].insert(instToEventID[{const_cast<SVFInstruction*>(inst), cs_cxt}]);
                //         prevInst = const_cast<SVFInstruction*>(inst);
                //     }
                //     cout << "inst doesn't have an id" << endl;
                // }
            }else if(!has_shared_location(location_addr, field_index) && not_fence){
                cout << "--> This is not a shared variable: " << var_name << ", " << location_addr << ": " << field_index << endl;
            }
        }else{
            cout << "--> Neither shared, nor call" << endl;
        }
    
    if(prevInst != prevInst_passed){

        cout << "Returning the prevInst from check_inst: " << (prevInst ? prevInst->toString() : "null") << endl;
        cout << "Returning the prevInst_cxt from check_inst: ";
        cout << "prevInst_cxt: ";
        print_call_context(prevInst_cxt);
    }
    return {prevInst, prevInst_cxt};
}

std::pair<std::vector<std::pair<SVFInstruction*, CallStrCxt>>, CxtThread> check_call_inst(SVFIR* pag, TCT* tct, const SVFInstruction* inst, const CallStrCxt cs_cxt, SVFInstruction* prevInst, CallStrCxt prevInst_cxt, CxtThread cxt_thread, bool from_a_fork_inst, bool join_encountered){
    cout << "[CHECK CALL INST] Checking the inst: " << inst->toString() << endl;
    cout << "Context of the inst: ";
    print_call_context(cs_cxt);

    //initializing CxtThread - this is later set to the actual cxtthread when isTDFork is true
    CallStrCxt emptyContext;
    CxtThread emptyThread(emptyContext, nullptr);

    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_inst_pairs;

    SVFInstruction* prevInst_passed = prevInst;
    cout << "prevInst: " << (prevInst ? prevInst->toString() : "null") << endl;

    cout << "prevInst context: ";
    print_call_context(prevInst_cxt);

    const SVF::SVFValue* val = static_cast<const SVF::SVFValue*>(inst);

    if(is_call_or_invoke(llvmmod->getLLVMValue(val))){

        // Checking if its a fork instruction and dealign with it
        const ThreadAPI* thread_api = ThreadAPI::getThreadAPI();
        // if(thread_api->isTDFork(inst)){
        //     deal_with_fork_inst(inst, inst -> toString(), tct, thread_api, cs_cxt, prevInst, prevInst_cxt);
        // }

        // If I encounter a call instruction, I go to the function defn and add all the instructions found in the function body, along with CF edges btwn them

        if (const auto* CB = dyn_cast<CallBase>(llvmmod->getLLVMValue(val))){
            const Function* calledFunc = CB->getCalledFunction();

            if (!calledFunc){
                const Value* calledOperand = CB->getCalledOperand();
                if (calledOperand){
                    calledOperand = calledOperand->stripPointerCasts();
                    calledFunc = dyn_cast<Function>(calledOperand);
                }
            }

            if (calledFunc){
                cout << "Called function identified: " << calledFunc->getName().str() << endl;
                const SVFFunction* calledFunc_svf = llvmmod->getSVFFunction(calledFunc);

                if(calledFunc_svf){
                    CallStrCxt new_cxt = cs_cxt;
                    ThreadCallGraph* tcg = tct -> getThreadCallGraph();
                    
                    if(!tcg->hasCallSiteID(tct->getCallICFGNode(inst), calledFunc_svf)){
                        cout << "Call site ID does not exist for the call instruction" << endl;
                        std::vector<std::pair<SVFInstruction*, CallStrCxt>> temp_last_inst_pairs;

                        temp_last_inst_pairs.push_back({prevInst, prevInst_cxt});
                        return {temp_last_inst_pairs, emptyThread};
                    }

                    if(calledFunc_svf->isDeclaration()){
                        cout << "Called function is a declaration, not a definition. No instructions to extract." << endl;
                        //is it a fork? if yes, I need to get the function being called inside the fork and use that for building the context and extracting the instructions
                        if(thread_api->isTDFork(inst)){
                            cout << "Fork instruction identified, getting the forked thread and function" << endl;
                            const SVFValue* forked_thread = thread_api->getForkedThread(inst);
                            cout << "Forked thread: " << forked_thread->toString() << endl;
                            const CallSite forked_thread_callsite = thread_api->getSVFCallSite(inst);

                            const SVFValue* forkVal = thread_api->getForkedFun(inst);
                            const SVFFunction* callee = SVFUtil::dyn_cast<SVFFunction>(forkVal);
                            const SVFFunction* callee_from_getCallee = thread_api->getCallee(inst);
                            if(callee != callee_from_getCallee){
                                cout << "Smtg is fishy?!" << endl;
                            }
                            if(callee){
                                tct->pushCxt(new_cxt, inst, callee);
                            }
                            
                            // I don't need threadIDStr, I can actually assign my own threadID for each CxtThread at the end, so changing all the fucntion signatures using threadIDStr to track CxtThread instead
                            CxtThread cxt_thread = CxtThread(new_cxt, inst);
                            if(prevInst){
                                cout << "Calling analyze_func with prevInst: " << prevInst->toString() << endl;
                            }

                            std::vector<std::pair<SVFInstruction*, CallStrCxt>> temp_last_inst_pairs;
                            from_a_fork_inst = true;
                            cout << "Calling analyze function for the callee of the fork instruction..." << endl;
                            temp_last_inst_pairs = analyze_func(pag, tct, callee, prevInst, prevInst_cxt, new_cxt, cxt_thread, from_a_fork_inst, join_encountered);

                            cout << "Last insts obtained in the function: " << endl;
                            for(auto li: temp_last_inst_pairs){
                                cout << li.first->toString() << endl;
                            }

                            cout << "Setting thread analysis status - so that I can distinguish btwn create and join in analyze_func" << endl;
                            bool registered_last_insts = false;
                            thread_analysis_status[cxt_thread] = {forked_thread, registered_last_insts};
                            // These temp_last_inst_pairs correspond to the last encountered events in the thread - we need to save these to threads_last_events_map in order to create synchronization edges
                            return {temp_last_inst_pairs, cxt_thread};

                        }else if(thread_api->isTDJoin(inst)){
                            cout << "Join instruction encountered" << endl;
                            std::vector<std::pair<SVFInstruction*, CallStrCxt>> temp_last_inst_pairs;
                            temp_last_inst_pairs.push_back({prevInst, prevInst_cxt});

                            //get the cxt_thread of the thread being joined in this inst
                            const SVFValue* joined_thread = thread_api->getJoinedThread(inst);
                            cout << "joined thread: " << joined_thread->toString() << endl;

                            // find the key for which SVFValue* matches in thread_analysis_status map
                            for(auto& entry : thread_analysis_status){
                                if(entry.second.first == joined_thread){
                                    CxtThread joined_cxt_thread = entry.first;
                                    cout << "Found the cxt_thread for the joined thread" << endl;

                                    // CHECK: IS THIS CORRECT? should I be returning temp_last_inst_pairs here?
                                    return {temp_last_inst_pairs, joined_cxt_thread};
                                }
                            }
                        }
                    }else{
                        cout << "[FUNC CALLED] Not a declaration func" << endl;
                        // cout << "Pushed context using calledFunc_svf" << endl;
                        // tct->pushCxt(new_cxt, inst, calledFunc_svf);

                        const SVFFunction* caller = inst->getFunction();
                        CallSiteID csId = tcg->getCallSiteID(tct->getCallICFGNode(inst), calledFunc_svf);
                        cout << "CallSiteID for the call instruction: " << csId << endl;

                        // if(tct->isCandidateFun(caller)){
                            tct->pushCxt(new_cxt, csId);
                        // }
                    }
                    cout << "OLD CXT: ";
                    print_call_context(cs_cxt);
                    
                    cout << "NEW CXT: ";
                    print_call_context(new_cxt);

                    last_inst_pairs = analyze_func(pag, tct, calledFunc_svf, prevInst, prevInst_cxt, new_cxt, cxt_thread, from_a_fork_inst, join_encountered);
                    cout << "Events returned from analyze_func as last_inst: " << endl;
                    for(auto p: last_inst_pairs){
                        cout << (p.first ? p.first->toString() : "null") << endl;
                        cout << "Context of the last inst: ";
                        print_call_context(p.second);
                    }
                }
            }
        }
    }

    return {last_inst_pairs, emptyThread};
}


std::vector<std::pair<SVFInstruction*, CallStrCxt>> remove_duplicates(std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_temp){
    // just a small func to remove any duplicates from the passed vector and write it to another vector
    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts;
    std::set<std::pair<SVFInstruction*, CallStrCxt>> seen;
    for(auto p: last_insts_temp){
        if(seen.find(p) == seen.end()){
            last_insts.push_back(p);
            seen.insert(p);
        }
    }
    return last_insts;
}


std::vector<std::pair<SVFInstruction*, CallStrCxt>> analyze_func(SVFIR* pag, TCT* tct, const SVFFunction* func, SVFInstruction* prevInstOfFunc, const CallStrCxt prevInstOfFunc_cxt,const CallStrCxt cs_cxt, CxtThread cxt_thread, bool from_a_fork_inst, bool join_encountered){
    // This function extracts all the shared events in a function and writes them all to thread events. 
    // It also creates CF edges btwn the shared events found in the func defn
    // prevInst and its context is passed since we need an edge from the shared event before the func call to the first shared inst in this func
    
    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts;
    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_from_joined_threads;
    std::vector<std::pair<SVFInstruction*, CallStrCxt>> return_insts;

    cout << "[DEBUG FUNC] Extracting instructions from " << func -> getName() << endl;
    cout << "cs_cxt of the func: ";
    print_call_context(cs_cxt);

    if(prevInstOfFunc){
        cout << "Prev shared inst: " << prevInstOfFunc -> toString() << endl;
    }

    cout << "Context of Prev shared inst: ";
    print_call_context(prevInstOfFunc_cxt);

    SVFInstruction* prevInst = prevInstOfFunc;
    CallStrCxt prevInst_cxt = prevInstOfFunc_cxt;

    last_insts.push_back({prevInst, prevInst_cxt});
    
    if(!func->hasBasicBlock()){
        // just return the prev inst passed as arg if the func doesn't have any basic blocks
        return {{prevInst, prevInst_cxt}};
    }
    
    const SVFBasicBlock* bb = func -> getEntryBlock();


    std::queue<std::pair<const SVF::SVFBasicBlock*, std::pair<SVFInstruction*, CallStrCxt>>> bb_to_connect_queue;
    std::set<std::pair<const SVF::SVFBasicBlock*, std::pair<SVFInstruction*, CallStrCxt>>> visited_bbs;

    for(auto inst:bb->getInstructionList()){
        if(!join_encountered){
            last_insts_from_joined_threads = {};
        }
        //if it is a return instruction, add the inst and context to the vector of events being returned
        const SVF::SVFValue* val = static_cast<const SVF::SVFValue*>(inst);
        if(inst){
            cout << "Looking at inst: " << inst->toString() << endl;
        }else{
            cout << "inst is nullptr" << endl;
        }

        if(isa<ReturnInst>(llvmmod->getLLVMValue(val))){
            // REVISIT: Here, I am assuming that the return inst isnt a shared inst
            cout << "Found a return instruction" << endl;
            for(auto prev: last_insts){
                return_insts.push_back({prev.first, prev.second});
            }
            last_insts.clear();

        }else if(is_call_or_invoke(llvmmod->getLLVMValue(val))){
            std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_temp;

            //creating an empty cxt_thread
            CallStrCxt emptyContext;
            CxtThread tempContextThread(emptyContext, nullptr);

            cout << "Exploring a call instruction" << endl;
            for(auto prev: last_insts){
                if(!prev.first){
                    cout << "prev.first is nullptr" << endl;
                }else{
                    cout << "\n >> Calling check_call_inst for " << inst->toString() << " \n with prev: " << prev.first->toString() << endl;
                }
                auto returned_lastinsts_and_cxtThread = check_call_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, cxt_thread, from_a_fork_inst, join_encountered);
                auto last_insts_per_prev = returned_lastinsts_and_cxtThread.first;

                //I would have to change the value of from_a_fork_inst to false if I encountered a shared event already
                //To identify this, I can check if the last insts returned from check_call_inst are different from the prev inst passed. If different, it means I have seen a shared inst while looking at the called fucntion - so reset the bool

                for(auto inst: last_insts_per_prev){
                    if(inst.first != prev.first){
                        from_a_fork_inst = false;
                        // join_encountered = false;
                    }else{
                        if(inst.second != prev.second){
                            from_a_fork_inst = false;
                            // join_encountered = false;
                        }
                    }
                }

                tempContextThread = returned_lastinsts_and_cxtThread.second;

                // last_insts_temp.insert(last_insts_temp.end(), last_insts_per_prev.begin(), last_insts_per_prev.end());
                for(auto i: last_insts_per_prev){
                    last_insts_temp.push_back(i);
                }

            }

            bool last_insts_returned_from_fork_or_join = false;
            //if this call inst was a pthread_create, I should add the last_insts to the threads_last_events_map
            // check the returned cxt_thread - I am checking if the SVFInstruction* is null or not
            if(tempContextThread.getThread()){
                //this could be a pthread_create or a pthread_join
                last_insts_returned_from_fork_or_join = true;
                if(thread_analysis_status[tempContextThread].second){
                    cout << "\n\n --> Join inst encountered for thread id " << threads_last_events_map[tempContextThread].first << endl;
                    join_encountered = true;
                    // I need to create synchronization edges to the shared events I encounter after this in the parent thread
                    // I also need to make sure that this happens only in the parent thread as I am now exploring threads when I encounter thread create calls - I shouldn't connect sw edges from here to the next thread being spawned -- THIS IS WRONG!
                    // if a pthread_create is there after this join, it should have a synchronization edge from each of the last instructions in the previous thread that has joined
                    for(auto i:threads_last_events_map[tempContextThread].second){
                        if(i.first){
                            cout << "last inst from thread " << threads_last_events_map[tempContextThread].first << ": " << i.first->toString() << endl;
                        }else{
                            cout << "i.first is nullptr" << endl;
                        }
                        last_insts_from_joined_threads.push_back(i);
                    }
                }else{
                    cout << "\n\n --> pthread_create inst encountered for thread id " << threads_last_events_map[tempContextThread].first << endl;

                    cout << "Writing the last insts encountered in this thread to the thread last events map.." << endl;
                    for(auto l: last_insts_temp){
                        if(l.first){
                            cout << "writing last inst: " << l.first->toString() << endl;
                        }else{
                            cout << "l.first is nullptr" << endl;
                        }
                    }
                    threads_last_events_map[tempContextThread].second = remove_duplicates(last_insts_temp);
                    cout << "Just checking the updated map.." << endl;
                    for(auto i: threads_last_events_map[tempContextThread].second)
                    thread_analysis_status[tempContextThread].second = true;
                }
            }

            if(!last_insts_returned_from_fork_or_join){
                // if the call we had encountered was a fork instruction, we don't want to use the last insts obtained from it to connect to the next instructions encountered after this
                cout << "Updating last_insts as this is not a thread create or join call" << endl;
                last_insts = remove_duplicates(last_insts_temp);
                // if it were pthread_create, the old value of last_insts would continue to be used
            }

        }else{
            cout << "Exploring a non-call instruction" << endl;
            bool shared = false;

            if(join_encountered){
                cout << "Updating last_insts to the last insts obtained from the joined threads." << endl;
                for(auto l: last_insts_from_joined_threads){
                    if(l.first){
                        cout << "last inst from joined thread: " << l.first->toString() << endl;
                    }else{
                        cout << "l.first is nullptr" << endl;
                    }
                }
                last_insts = last_insts_from_joined_threads;
            }

            std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_returned_from_check_inst;

            for(auto prev:last_insts){
                auto last_shared_inst = check_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, cxt_thread, from_a_fork_inst, join_encountered);
                last_insts_returned_from_check_inst.push_back(last_shared_inst);
                
                if(last_shared_inst.first != prev.first){
                    shared = true;
                }
            }

            //the ret value here would either be the prev inst from the function given as arg or the new inst
            //if it is new inst, I can set from_a_forked_thread to false and update prevInst and prevInst_cxt
            // for(auto li:last_insts_returned_from_check_inst){

            //     if(li.first != prev.first){
            //         shared = true;
            //         //found a new shared inst - so I need not look at the last_insts for the next inst in the bb
            //         prevInst = li.first;
            //         prevInst_cxt = li.second;
            //     }
            // }
            
            if(shared){
                from_a_fork_inst = false;
                join_encountered = false;

                last_insts = remove_duplicates(last_insts_returned_from_check_inst);
            }
        }
    }
    

    for(auto prev:last_insts){
        bb_to_connect_queue.push({bb, {prev.first, prev.second}});
    }
    

    while(!bb_to_connect_queue.empty()){
        //dequeue a bb from bb_to_connect_queue
        // <bb, <inst, cxt>>
        auto curr_bb_pair = bb_to_connect_queue.front();
        auto curr_bb = curr_bb_pair.first;
        cout << "Looking for a shared event in the successors of bb [" << curr_bb->getName() << "]" << endl;
        bb_to_connect_queue.pop();

        if (visited_bbs.find({curr_bb, curr_bb_pair.second}) != visited_bbs.end()) {
            cout << "bb [" << curr_bb->getName() << "] already visited with this inst/cxt. Skipping." << endl;
            continue;
        }
        
        
        SVFInstruction* parent_last_shared_inst = curr_bb_pair.second.first;
        if(!parent_last_shared_inst){
            cout << "parent_last_shared_inst is nullptr" << endl;
        }else{
            cout << "Last shared inst in the parent bb: " << (parent_last_shared_inst ? parent_last_shared_inst->toString() : "null") << endl;
        }
        
        CallStrCxt parent_last_shared_inst_cxt = curr_bb_pair.second.second;
        cout << "context of the last shared inst in the parent bb: ";
        print_call_context(parent_last_shared_inst_cxt);
        
        //since I push a bb to the queue only after checking all the instructions in the bb, I can just look at its successors for any shared instructions
        auto succ_list = curr_bb->getSuccessors();

        for(auto succ:succ_list){
            auto inst_list = succ->getInstructionList();
            cout << "Successor BB [" << succ->getName() << "]  instructions: " << endl;

            SVFInstruction* prevInst_bb = parent_last_shared_inst;
            CallStrCxt prevInst_bb_cxt = parent_last_shared_inst_cxt;

            last_insts = {{prevInst_bb, prevInst_bb_cxt}};

            for(auto inst:inst_list){
                //if it is a return instruction, add the inst and context to the vector of events being returned
                const SVF::SVFValue* val = static_cast<const SVF::SVFValue*>(inst);
                if(!inst){
                    cout << "inst is nullptr" << endl;
                }else{
                    cout << "Looking at succ inst: " << inst->toString() << endl;
                }

                if(isa<ReturnInst>(llvmmod->getLLVMValue(val))){
                    // REVISIT: Here, I am assuming that the return inst isnt a shared inst
                    cout << "Found a return instruction" << endl;
                    for(auto prev: last_insts){
                        return_insts.push_back({prev.first, prev.second});
                    }
                    last_insts.clear();

                }else if(is_call_or_invoke(llvmmod->getLLVMValue(val))){
                    cout << "Exploring a call instruction" << endl;
                    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_temp;
                    std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_insts_from_func;

                    //creating an empty cxt_thread
                    CallStrCxt emptyContext;
                    CxtThread tempContextThread(emptyContext, nullptr);

                    for(auto prev: last_insts){
                        auto returned_lastinsts_and_cxtThread = check_call_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, cxt_thread, from_a_fork_inst, join_encountered);
                        auto last_insts_per_prev = returned_lastinsts_and_cxtThread.first;
                        
                        //I would have to change the value of from_a_fork_inst to false if I encountered a shared event already
                        //To identify this, I can check if the last insts returned from check_call_inst are different from the prev inst passed. If different, it means I have seen a shared inst while looking at the called fucntion - so reset the bool

                        for(auto inst: last_insts_per_prev){
                            if(inst.first != prev.first){
                                from_a_fork_inst = false;
                                join_encountered = false;
                            }else{
                                if(inst.second != prev.second){
                                    from_a_fork_inst = false;
                                    join_encountered = false;
                                }
                            }
                        }
                        
                        tempContextThread = returned_lastinsts_and_cxtThread.second;
                        last_insts_temp.insert(last_insts_temp.end(), last_insts_per_prev.begin(), last_insts_per_prev.end());
                    }

                    // I don't want to write directly into last_insts as that would be necessary if this call inst we encountered is a pthread_create
                    // specifically, I would need it to correctly add a CF from the last shared inst before pthread_create to the next shared event in the parent thread before the spawned thread joins
                    last_insts_from_func = remove_duplicates(last_insts_temp);

                    //if this call inst was a pthread_create, I should add the last_insts to the threads_last_events_map
                    // check the returned cxt_thread - I am checking if the SVFInstruction* is null or not
                    if(tempContextThread.getThread()){
                        threads_last_events_map[tempContextThread].second = last_insts_from_func;
                    }else{
                        // if the call inst encountered was not a fork, I can just update the last_insts
                        last_insts = last_insts_from_func;
                    }

                }else{
                    cout << "Exploring a non-call instruction" << endl;
                    bool shared = false;
                    for(auto prev:last_insts){
                        auto last_shared_inst = check_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, cxt_thread, from_a_fork_inst, join_encountered);
                        
                        //the ret value here would either be the prev inst from the function given as arg or the new inst
                        //if it is new inst, I can set call_inst to false and update prevInst_bb and prevInst_bb_cxt
                        
                        if(last_shared_inst.first != prev.first){
                            from_a_fork_inst = false;
                            join_encountered = false;
                            shared = true;
                            //found a new shared inst - so I need not look at the last_insts for the next inst in the bb
                            prevInst_bb = last_shared_inst.first;
                            prevInst_bb_cxt = last_shared_inst.second;
                        }
                    }
                    if(shared){
                        last_insts = {{prevInst_bb, prevInst_bb_cxt}};
                    } //if not, the old last insts would remain
                }
            }
           
            for(auto prev:last_insts){
                if(visited_bbs.find({succ, {prev.first, prev.second}}) == visited_bbs.end()){
                    bb_to_connect_queue.push({succ, {prev.first, prev.second}});
                    // cout << "bb[" << succ->getName() << "] , pushing to queue" << endl;
                    cout << "bb[" << succ->getName() << "] , pushing to queue" << endl; 
                    cout << "last inst: " << (prev.first ? prev.first->toString() : "null") << endl;
                    cout << "context: ";
                    print_call_context(prev.second);
                }
            }
        }

        
        cout << "marking bb [" << curr_bb->getName() << "] as visited with last inst: " << (curr_bb_pair.second.first ? curr_bb_pair.second.first->toString() : "null") << endl;
        cout << "context: ";
        print_call_context(curr_bb_pair.second.second);
        visited_bbs.insert({curr_bb, {curr_bb_pair.second.first, curr_bb_pair.second.second}});
    }

    cout << "[DEBUG FUNC] Finished extracting instructions and edges from the function: " << func -> getName() << endl;
    
    // if the return_insts vector is empty, it means that there were no return instructions in the function, so I can return the last shared inst found in the function
    if(return_insts.empty()){
        cout << "last shared inst found in the func: " << (prevInst ? prevInst->toString() : "null") << endl;
        return {{prevInst, prevInst_cxt}};
    }else{
        cout << "last shared insts found in the func: " << endl;
        for(const auto& inst_pair : return_insts){
            cout << "  " << (inst_pair.first ? inst_pair.first->toString() : "null") << endl;
        }
        return return_insts;
    }
}


void write_to_thread_events(const SVFInstruction* inst, const CallStrCxt cs_cxt, CxtThread cxt_thread, const SVF::SVFValue* location_addr, std::string field_index, std::string var_name, std::string instStr, string kind, string access_mode){
    cout << "Writing shared inst [" << inst->toString() << "] to thread events" << endl;
    cout << "[DEBUG 2] location.size = " << var_name.size() << endl;

    // for each of these instructions, we assign an event id - these will be part of the skeleton graph
    
    //add only if the instruction is not part of instToEventID already
    if (instToEventID.find({inst, cs_cxt}) != instToEventID.end()) {
        cout << "Event already created for this instruction with event id: " << instToEventID[{inst, cs_cxt}] << endl;
        return;
    }

    std::string eventID = "e" + std::to_string(eventCounter++);
    instToEventID[std::make_pair(inst, cs_cxt)] = eventID;

    //if location.size() > 1, prefix the func name where it was declared to uniquely identify it
    //I am doing after obsevring that when llvm ir creates variable names, it creates unique names for multiple variables with the same name within a func
    // but if it is used in different funcs, it creates the same name for the variable, so I need to add the func name as prefix to uniquely identify the variables

    // if(location.size() > 1){
    //     const SVFFunction* func = inst->getFunction();
    //     if(func){
    //         location = func->getName() + "_" + location;
    //     }
    // }

    //This doesn't work here - it is not prefixing the correct function - I moved this logic to the get_location_pointed_to function where I am extracting the location from the instruction
    //TODO: check if that is working fine
    std::string threadIDStr = threads_last_events_map[cxt_thread].first;
    std::string is_atomic_str = "unknown";
    if (const Value* val = llvmmod->getLLVMValue(inst)) {
        if (is_llvm_instruction_atomic(val)) {
            is_atomic_str = "Atomic";
        } else {
            is_atomic_str = "NonAtomic";
        }
    }
    event_info* info = new event_info(eventID, threadIDStr, kind, location_addr, field_index, var_name, access_mode, std::make_pair(inst, cs_cxt), false, is_atomic_str);

    threadEvents[threadIDStr].push_back(info);

    // Printing the instruction and its extracted info for debugging
    cout << "[DEBUG]Instruction: " << instStr << endl;
    cout << "[DEBUG]Info: eventID: " << eventID << ", TID: " <<
    threadIDStr << ", " << kind << ", loc: " << location_addr << field_index << ", var_name: " << var_name << ", access_mode: " << access_mode << endl;
}


// Helper func to deal with pthread_create functions (context)
// void deal_with_fork_inst(const SVFInstruction* inst, std::string instStr, TCT* tct, const ThreadAPI* thread_api, const CallStrCxt cs_cxt, SVFInstruction* prev_inst, const CallStrCxt prev_inst_cxt){
    // cout << "[DEBUG 5] Found a fork instruction: " << instStr << endl;

    // CallICFGNode* call_node = tct->getCallICFGNode(inst);

    // const SVFValue* forked_thread = thread_api->getForkedThread(inst);

    // CallStrCxt call_string_cxt = cs_cxt;
    
    // //track the context of the thread - I realized the need for the this when I tried to get the threadID from the above SVFValue*
    // // const SVFFunction* callee = SVFUtil::dyn_cast<const SVFFunction>(inst);
    
    // const SVFValue* forkVal = thread_api->getForkedFun(inst);
    // const SVFFunction* callee = SVFUtil::dyn_cast<SVFFunction>(forkVal);
    
    // if(callee){
    //     tct->pushCxt(call_string_cxt, inst, callee);
    //     const SVFFunction* caller = inst->getFunction();
    //     ThreadCallGraph* tcg = tct -> getThreadCallGraph();
    //     CallSiteID csId = tcg->getCallSiteID(tct->getCallICFGNode(inst), callee);

    //     /// handle calling context for candidate functions only
    //     if(tct->isCandidateFun(caller) == false)
    //         cout << "[JUST CHECKING]  the fork inst is not a cand func" << endl;
    //     else
    //         cout << "[JUST CHECKING] call site id = " << csId << endl;
    // }else{
    //     cout << "[JUST CHECKING] callee is null" << endl;
    // }
    
    // if(prev_inst){
    //     forked_threads.push_back(thread_fork_info(prev_inst, prev_inst_cxt, inst, call_string_cxt));
    //     cout << "[DEBUG 8] Pushing this context to forked_threads after the instruction : " << prev_inst->toString() << endl;
    //     print_call_context(call_string_cxt);
    // }
// }

// Given an instruction, this func gets the location it is pointing to and checks if it is a shared variable 
// Returns var name and the address of the location (base address and field index, if any) it is pointing to (if it is a shared variable)
std::pair<std::string, std::pair<const SVF::SVFValue*, std::string>> get_location_pointed_to(SVFIR* pag, const SVFInstruction* ptr_inst){
    // get the var it is pointing to and check if it is a shared var
    cout << "[DEBUG get_location_pointed_to] Getting location pointed to by instruction: " << ptr_inst->toString() << endl;

    // I need the PAG node id corresponding to the instruction
    // casting the instruction to SVFValue* to get the node id
    std::string var_name;
    const SVF::SVFValue* location_addr = nullptr;
    std::string field_index = "";


    NodeID pagNodeID = pag->getValueNode(static_cast<const SVFValue*>(ptr_inst));
    // cout << "PAG node ID for the instruction's pointer operand: " << std::to_string(pagNodeID) << endl;

    for(auto p: points_to_info){
        if(p.first == pagNodeID){
            NodeID points_to_node = p.second;
            const MemObj* baseobj = pag->getObject(points_to_node);
            
            if (baseobj && !baseobj->isFunction()){
                std::string inst = baseobj->toString();
                cout << "[DEBUG PTS TO] PAG node ID " << pagNodeID << " points to node " << points_to_node << endl;
                cout << "[DEBUG] Shared variable instruction: " << inst << endl;
                const SVFValue* val = baseobj->getValue();
            
                if(val){
                    var_name = llvmmod -> getLLVMValue(val) -> getName().str();
                    cout << "SHARED LOC: " << var_name << endl;
                    location_addr = val;

                    //casting SVFValue to LLVM Value type to get the field index (if any)
                    const Value* llvm_val = llvmmod->getLLVMValue(val);
                    if (llvm_val){
                        llvm::outs() << "[FIELD DEBUG get_location_pointed_to] llvm_val = ";
                        llvm_val->print(llvm::outs());
                        llvm::outs() << "\n";

                        field_index = get_field_index_from_ptr(llvm_val);
                    }
                    cout << "[line 766]pointer to shared loc (addr): " << location_addr << ", field index: " << field_index << endl;
                }
            }
            break;
        }
    }

    return std::make_pair(var_name, std::make_pair(location_addr, field_index));
}


/**
 * @brief Generates a stable, deterministic 64-bit Location ID hex string.
 *
 * RATIONALE:
 * In the original static analysis pipeline, memory locations in the `.pg` metadata 
 * file were identified by the raw virtual memory address of the corresponding `SVFValue*` 
 * pointer (e.g., `(uint64_t)ptr`). However, due to Address Space Layout Randomization (ASLR) 
 * and dynamic memory allocations within LLVM/SVF across executions, these pointer addresses 
 * changed on every compiler run. This non-determinism caused the generated `.pg` metadata 
 * to fluctuate, breaking stable fuzzer state-caching and regression checking.
 *
 * SOLUTION:
 * We use the FNV-1a 64-bit non-cryptographic hashing algorithm to compute a deterministic, 
 * cross-run stable hash from the variable name (which is stable in the source code).
 *
 * FALLBACK & LIMITATIONS:
 * If the variable name is empty or resolved as "unknown" (typically due to compilation 
 * without debug symbols or SVF compiler-generated temporaries), we fall back to hashing 
 * the virtual memory pointer itself (`(uint64_t)ptr`). This ensures uniqueness within 
 * a single compilation run but loses cross-run stability.
 *
 * @param var_name The name of the variable as resolved by SVF.
 * @param ptr The raw pointer of the SVFValue object, used as a fallback unique ID.
 * @return A hexadecimal string representation of the deterministic 64-bit location ID.
 */
static std::string getDeterministicLocID(const std::string &var_name, const void *ptr) {
    if (var_name.empty() || var_name == "unknown") {
        uint64_t hash = 14695981039346656037ULL;
        uint64_t val = (uint64_t)ptr;
        hash ^= val;
        hash *= 1099511628211ULL;
        std::stringstream ss;
        ss << "0x" << std::hex << hash;
        return ss.str();
    }
    uint64_t hash = 14695981039346656037ULL;
    for (char c : var_name) {
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }
    std::stringstream ss;
    ss << "0x" << std::hex << hash;
    return ss.str();
}

static std::string getDeterministicInstID(const SVFInstruction* inst) {
    if (!inst) {
        uint64_t hash = 14695981039346656037ULL;
        std::stringstream ss;
        ss << "0x" << std::hex << hash;
        return ss.str();
    }

    std::string fnName = "";
    const SVFFunction* f = inst->getFunction();
    if (f) {
        fnName = f->getName();
    }

    std::string llvmStr = "";
    if (llvmmod) {
        const Value* llvmVal = llvmmod->getLLVMValue(static_cast<const SVF::SVFValue*>(inst));
        if (llvmVal) {
            std::string tempStr;
            llvm::raw_string_ostream rso(tempStr);
            llvmVal->print(rso);
            rso.flush();
            llvmStr = tempStr;
        }
    }

    if (llvmStr.empty()) {
        llvmStr = inst->toString();
    }

    // Hash fnName and llvmStr using FNV-1a 64-bit
    uint64_t hash = 14695981039346656037ULL;
    for (char c : fnName) {
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }
    for (char c : llvmStr) {
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }

    std::stringstream ss;
    ss << "0x" << std::hex << hash;
    return ss.str();
}

static std::string getDeterministicGlobalInitID(const std::string& varName) {
    uint64_t hash = 14695981039346656037ULL;
    std::string prefix = "global_init_";
    for (char c : prefix) {
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }
    for (char c : varName) {
        hash ^= (unsigned char)c;
        hash *= 1099511628211ULL;
    }
    std::stringstream ss;
    ss << "0x" << std::hex << hash;
    return ss.str();
}

std::string get_location_atomic_status(const SVF::SVFValue* loc, std::string field) {
    bool has_atomic = false;
    bool has_nonatomic = false;
    
    for (const auto& t : threadEvents) {
        if (t.first == "0") continue; // Skip thread 0 (global_init)
        for (const auto* event : t.second) {
            if (event->location_addr == loc && event->field_index == field) {
                if (event->is_atomic == "Atomic") {
                    has_atomic = true;
                } else if (event->is_atomic == "NonAtomic") {
                    has_nonatomic = true;
                }
            }
        }
    }
    
    if (has_atomic && !has_nonatomic) return "Atomic";
    if (!has_atomic && has_nonatomic) return "NonAtomic";
    if (has_atomic && has_nonatomic) return "Mixed";
    return "unknown";
}

// Write to .pg format file
void write_to_file()
{
    std::ofstream pgFile("generated_output.pg");
    // std::ofstream tempFile("tempFile.md");

    pgFile << "# Shared Locations\n";
    for (const auto& loc : shared_vars){
        std::string atomic_status = get_location_atomic_status(loc.first.first, loc.first.second);
        if(loc.first.second != ""){
            // pgFile << "LOC " << getDeterministicLocID(loc.second, loc.first) << " " << loc.second << "\n";
            // pgFile << "LOC " << loc.first.first << ":field_index=" << loc.first.second << " " << loc.second << "\n";
            pgFile << "LOC " << getDeterministicLocID(loc.second, loc.first.first) << ":field_index=" << loc.first.second << " " << loc.second << " " << atomic_status << "\n";

        }else{
            // pgFile << "LOC " << loc.first.first << " " << loc.second << "\n";
            pgFile << "LOC " << getDeterministicLocID(loc.second, loc.first.first) << " " << loc.second << " " << atomic_status << "\n";
        }
    }

    pgFile << "\n# Event: ID TID  Kind  Loc VarName  Mode  Atomic  Instruction_Address     Call_string_context     Instruction\n";

    for (const auto& t : threadEvents){
        for (const auto& event_info : t.second){
            if(!event_info){
                cout << "event info is null for thread " << t.first << endl;
                return;
            }
            if(!event_info->inst_cxt.first){
                cout << "inst_cxt.first is null for event " << event_info->event_id << " in thread " << t.first << endl;
                return;
            }

            const SVFFunction* f = nullptr;
            std::string fnName = "";
            if(!event_info->is_global){
                f = event_info->inst_cxt.first->getFunction();
                fnName = f ? f->getName() : "f is null";
            }else{
                fnName = "global_init";
            }
            // std::string fnName = f ? f->getName() : "";
            
            std::string instID = event_info->is_global ? getDeterministicGlobalInitID(event_info->var_name) : getDeterministicInstID(event_info->inst_cxt.first);
            std::string instStr = event_info->is_global ? ("@" + event_info->var_name + " = global init") : event_info->inst_cxt.first->toString();

            if(event_info->field_index != ""){  
                pgFile << "E\t" << event_info->event_id << "\t" << t.first
                   << "\t" << event_info->kind << "\t"
                   << getDeterministicLocID(event_info->var_name, event_info->location_addr) << ":field_index=" << event_info->field_index << "\t" << event_info->var_name << "\t" << event_info->access_mode << "\t" << instID << "\t" << get_call_context_string(event_info->inst_cxt.second) << "\t[" << instStr << "]\t" << fnName << "\t" << event_info->is_atomic
                   << "\n";
            }else{
                pgFile << "E\t" << event_info->event_id << "\t" << t.first
                   << "\t" << event_info->kind << "\t"
                   << getDeterministicLocID(event_info->var_name, event_info->location_addr) << "\t" << event_info->var_name << "\t" << event_info->access_mode << "\t" << instID << "\t" << get_call_context_string(event_info->inst_cxt.second) << "\t[" << instStr << "]\t" << fnName << "\t" << event_info->is_atomic
                   << "\n"; 
            }
        }
    }

    pgFile << "\n# Control Flow edges\n";
    for (const auto& cf : cfEdges_map){
        for (const auto& to : cf.second){
            pgFile << "CF " << cf.first << " " << to << "\n";
        }
    }

    pgFile << "\n# Synchronizes-with edges\n";
    for (const auto& sw : swEdges_map){
        for (const auto& to : sw.second){
            pgFile << "CF " << sw.first << " " << to << "\n";
        }
    }
    pgFile.close();

    cout << "\n=== Generated .pg file: generated_output.pg ===" << std::endl;
}


//Called from main on each TCTNode (each thread)- explores the start func and all the basic blocks, instructions in them - adding events and CF edges
void process_thread(SVFIR* pag, TCT* tct, std::_Rb_tree_iterator<std::pair<const unsigned int, SVF::TCTNode*>> it){
    const TCTNode* threadNode = it->second;
    const CxtThread &cxt_thread = threadNode->getCxtThread();
    NodeID threadID = threadNode->getId();
    std::string threadIDStr = std::to_string(threadID);
    
    CallStrCxt parent_cxt;
    
    const CallStrCxt cs_cxt = cxt_thread.getContext();
    cout << "[CALL STRING CONTEXT] Thread " << threadIDStr << ": Call string context: " << cxt_thread.cxtToStr() << endl;

    // Get the start routine function for this thread
    const SVFFunction* startFunc = tct->getStartRoutineOfCxtThread(cxt_thread);

    cout << "[DEBUG]Thread ID: " << threadIDStr << endl;
    
    SVFInstruction* prevInst = nullptr;
    if(threadEvents.find(threadIDStr) != threadEvents.end() && threadEvents[threadIDStr].size() > 0){
        // This happens only with the main thread as I have the same thread ID for global events and the events happening in main thread
        cout << "Found previous events for this thread, setting prevInst to the last event's instruction" << endl;
        prevInst = const_cast<SVFInstruction*>(threadEvents[threadIDStr].back()->inst_cxt.first);
    }

    if(startFunc){
        if(prevInst){
            cout << "Analyzing start func of thread " << threadIDStr << " with prevInst: [" << prevInst -> toString() << "]" << endl;
        }else{
            cout << "Analyzing start func of thread " << threadIDStr << " with prevInst: [ Nullptr ]" << endl;
        }

        auto call_string_cxt = parent_cxt;
        print_call_context(call_string_cxt);
        
        // ref: void analyze_func(SVFIR* pag, const SVFFunction* func, TCTNode* threadNode, TCT* tct, const CallStrCxt cs_cxt, SVFInstruction* prevInst, const CallStrCxt prevInst_cxt){

        // analyze_func(pag, startFunc, threadNode, tct, cs_cxt, prevInst, parent_cxt);
        NodeID threadID = threadNode->getId();
        std::string threadIDStr = std::to_string(threadID);
        cout << "[DEBUG FUNC] Analyzing the function: " << startFunc -> getName() << endl;

        // setting this to false as here, I only call analyze_func on the startfunc of main thread, not based on any pthread_create call
        bool from_a_fork_inst = false;
        bool join_encountered = false;

        std::vector<std::pair<SVFInstruction*, CallStrCxt>> last_inst_pairs = analyze_func(pag, tct, startFunc, prevInst, parent_cxt, cs_cxt, cxt_thread, from_a_fork_inst, join_encountered);
        // SVFInstruction* last_inst = last_inst_pair.first;
        // CallStrCxt last_inst_cxt = last_inst_pair.second;
        //TODO: I would have to use this last_inst if there are any instructions after the thread join
    }
}

//Helper func to identify shared variables
void get_points_to_info(SVFIR* pag, FSMPTA* fsmpta){
    for (auto it = pag->begin(), ie = pag->end(); it != ie; ++it){
        NodeID var = it->first;
        // cout << "NodeID: " << var << endl;
        const PointsTo& pts = fsmpta->getPts(var);

        if (!pts.empty()){
            // This could be a global var or an alloca instruction or a function call I am interested only in global vars and alloca, NOT in fn calls

            // put the info into a data structure
            // check all nodes that point to the same node
            for (NodeID n : pts){
                // Get the instruction corresponding to the node id n
                // cout << " -> " << n;
                const MemObj* baseobj = pag->getObject(n);
                if (baseobj && !baseobj->isFunction()){
                    points_to_info.push_back(std::make_pair(var, n));
                }
                cout << endl;
            }
        }
    }
}

//Helper func to identify shared variables
std::set<NodeID> get_thread_ids_for_pag_node(NodeID pagNodeID, SVFIR* pag, MHP* mhp){
    std::set<NodeID> threadIDs;

    if (!pag || !mhp || !pag->hasGNode(pagNodeID))
        return threadIDs;

    const SVFVar* node = pag->getGNode(pagNodeID);
    const SVFInstruction* inst = nullptr;

    if (node && node->hasValue()){
        // unsure if this will give the instruction. this is diff from how I do it..
        inst = SVFUtil::dyn_cast<SVFInstruction>(node->getValue());
    }

    if (inst && mhp->hasThreadStmtSet(inst)){
        const MHP::CxtThreadStmtSet& tsSet = mhp->getThreadStmtSet(inst);
        for (const CxtThreadStmt& cts : tsSet)
            threadIDs.insert(cts.getTid());
    }

    if (!threadIDs.empty())
        return threadIDs;

    // a fallback option in case threadIDs is empty
    // checking if the fn containing the instruction is the start fn of any thread
    const SVFFunction* fun = node ? node->getFunction() : nullptr;
    if (!fun)
        return threadIDs;

    TCT* tct = mhp->getTCT();
    for (auto it = tct->begin(); it != tct->end(); ++it){
        TCTNode* threadNode = it->second;
        const SVFFunction* startFunc = tct->getStartRoutineOfCxtThread(threadNode->getCxtThread());
        if (startFunc == fun){
            threadIDs.insert(threadNode->getId());
        }
    }

    return threadIDs;
}

//Helper func to identify shared variables
void print_thread_ids_for_pag_node(NodeID pagNodeID, SVFIR* pag, MHP* mhp){
    const std::set<NodeID> threadIDs = get_thread_ids_for_pag_node(pagNodeID, pag, mhp);

    cout << "[INFO] PAG node " << pagNodeID << " is executed by thread IDs: ";
    if (threadIDs.empty()){
        cout << "(none found)";
    }
    else{
        bool first = true;
        for (NodeID tid : threadIDs){
            if (!first){
                cout << ", ";
            }
            cout << tid;
            first = false;
        }
    }
    cout << std::endl;
}

//Helper func to identify shared variables
// std::set<NodeID> get_threads_executing_inst(const SVFInstruction* inst, MHP* mhp){
//     std::set<NodeID> threadIDs;

//     if (inst && mhp->hasThreadStmtSet(inst)){
//         const MHP::CxtThreadStmtSet& tsSet = mhp->getThreadStmtSet(inst);
//         for (const CxtThreadStmt& cts : tsSet){
//             threadIDs.insert(cts.getTid());
//         }
//     }

//     if (!threadIDs.empty())
//         return threadIDs;

//     // a fallback option in case threadIDs is empty
//     // checking if the fn containing the instruction is the start fn of any thread
//     const SVFFunction* fun = inst ? inst->getFunction() : nullptr;
//     if (!fun)
//         return threadIDs;

//     TCT* tct = mhp->getTCT();
//     for (auto it = tct->begin(); it != tct->end(); ++it){
//         TCTNode* threadNode = it->second;
//         const SVFFunction* startFunc = tct->getStartRoutineOfCxtThread(threadNode->getCxtThread());
//         if (startFunc == fun)
//             threadIDs.insert(threadNode->getId());
//     }
//     return threadIDs;

// }

//Helper func to identify shared variables
void identify_shared_global_variables(SVFIR* pag, MHP* mhp, SVFModule* svfModule){
    LLVMModuleSet* llvmmod = LLVMModuleSet::getLLVMModuleSet();

    std::string prevInst = "";
    
    for (auto global_it = svfModule->global_begin(); global_it != svfModule->global_end(); global_it++){
        std::set<NodeID> threadIDs;
        const SVFInstruction* inst;
        cout << "\n[GLOBAL VAR] Glob: " << (*global_it)->toString() << endl;

        const Value* val = llvmmod -> getLLVMValue(static_cast<const SVF::SVFValue*> (*global_it));

        std::vector<const SVFInstruction*> uses_of_global;
        //I want to know if this is being accessed by multiple threads that may run in parallel - if yes, I consider it shared
        if(!val){
            cout << "[DEBUG 0] No LLVM value found for the global variable, skipping..." << endl;
            continue;
        }
        // else{
        //     cout << "No prob with val" << endl;
        // }

        bool found_one_store = 0;
        
        for (Value::const_use_iterator it2 = val->use_begin(), ie = val->use_end(); it2 != ie; ++it2){
            // cout << "[DEBUG 0] Looking at a use of the global variable" << endl;
            const Use *u = &*it2;
            if(!u){
                cout << "[DEBUG 0] No use found for the global variable, skipping..." << endl;
                continue;
            }
            // else{
            //     cout << "No prob with use" << endl;
            // }
            
            const Value* user = u->getUser();
            
            if(!user){
                cout << "[DEBUG 0] No user found for the use of the global variable, skipping..." << endl;
                continue;
            }
            // cout << "[DEBUG 0] Found a use of the global variable" << endl;

            llvm ::outs() << "User of the global variable: " << *user << "\n";
            
            const Instruction* llvm_inst = SVFUtil::dyn_cast<Instruction>(user);
            
            // cout << "llvm_inst obtained" << endl;
            if(!llvm_inst){
                cout << "[DEBUG 0] No instruction found for the use of the global variable, skipping..." << endl;
                continue;
            }

            if(llvm::isa<llvm::StoreInst>(user) || llvm::isa<llvm::AtomicRMWInst>(user) || llvm::isa<llvm::AtomicCmpXchgInst>(user)){
                found_one_store = 1;
            }

            if(!llvmmod){
                cout << "[DEBUG 0] No LLVM module found, skipping..." << endl;
                continue;
            }
            // else{
            //     cout << "No prob with LLVM module" << endl;
            // }
            inst = llvmmod -> getSVFInstruction(llvm_inst);
            cout << "inst str: " << inst->toString() << endl;

            // //got the instruction, I now need to know which thread it is executed by

            // //TODO: modify the pag nodes function to use this function inside
            // std::set<NodeID> threadIDs_for_use = get_threads_executing_inst(inst, mhp);
            // for(auto t:threadIDs_for_use){
            //     threadIDs.insert(t);
            // }

            // This won't work - variables that are not shared were also being flagged as shared by this as I was just checking if threadIDs size > 1
            // Instead, I can store all of the uses of a global in a vector and for each pair of them, check if they may happen in parallel
            // If there exists atleast one such pair, the variable can be flagged as shared
            uses_of_global.push_back(inst);
            cout << "Pushed the instruction: " << inst->toString() << " to the uses of global vector" << endl;
        }
        
        // cout << "[DEBUG 0] no. of threads executing the instruction: " << threadIDs.size() << endl;
        bool shared = false;
        for(size_t i = 0; i < uses_of_global.size(); i++){
            // It is also possible that the same instruction may be executed by multiple threads in parallel
            // found this case in the mschange benchmark - 
            // succ1, succ2 are beign written to in main_task which is executed by all the spawned threads
            // however, it is not marked as a shared location since there is only one user corresponding to succ1 and succ2

            //REVISIT - assuming mhp can take the same instruction as arg twuce and say if different instances of it can run in parallel - check if this works - NO, THIS ISNT WORKING - 
            // tried mayHappenInParallel(uses_of_global[i], uses_of_global[i]) 
            // and mayHappenInParallel(uses_of_global[i], uses_of_global[i])
            // observed no change in the shared vars with either of these

            //alternate way - use getThreadStmtSet to get the threads executing the instruction - if these may execute in parallel, I can mark it as shared var

            /*
            inline const CxtThreadStmtSet& getThreadStmtSet(const SVFInstruction* inst) const
            {
                InstToThreadStmtSetMap::const_iterator it = instToTSMap.find(inst);
                assert(it!=instToTSMap.end() && "no thread access the instruction?");
                return it->second;
            }
            
            I can use this func to get a CxtThreadStmtSet and then iterate through the thread stmt and then get interleaving threads

            To Get interleaving thread for statement inst:
            const NodeBS & 	getInterleavingThreads (const CxtThreadStmt &cts)

            */
            cout << "Checking if the instruction: " << uses_of_global[i]->toString() << " may be executed by multiple threads in parallel" << endl;
            // const SVF::MHP::CxtThreadStmtSet& threadStmtSet = mhp -> getThreadStmtSet(uses_of_global[i]);
            // cout << "Found thread stmt set of size " << threadStmtSet.size() << " for instruction: " << uses_of_global[i]->toString() << endl;
            // for(auto threadStmt: threadStmtSet){
            //     const NodeBS& interleavingThreads = mhp -> getInterleavingThreads(threadStmt);
            //     for(auto t:interleavingThreads){
            //         cout << "Thread " << t << " may interleave with the thread executing the instruction: " << uses_of_global[i]->toString() << endl;
            //     }
            // }

            if(mhp -> mayHappenInParallel(uses_of_global[i], uses_of_global[i])){
                //mark the location as shared only if there is atleast one user which is a store instruction
                // if(found_one_store){
                    shared = true;
                    cout << "[DEBUG 0] Different instances of the same instruction may happen in parallel: " << uses_of_global[i]->toString() << " and " << endl;
                    break;
                // }
            }

            // this is the normal case - checking other uses
            for(size_t j = i + 1; j < uses_of_global.size(); j++){
                if(mhp -> mayHappenInParallel(uses_of_global[i], uses_of_global[j])){
                    //mark the location as shared only if there is atleast one user which is a store instruction
                    // if(found_one_store){
                        shared = true;
                        cout << "[DEBUG 0] Found a pair of instructions that may happen in parallel: " << uses_of_global[i]->toString() << " and " << uses_of_global[j]->toString() << endl;
                        break;
                    // }
                }
                if(shared){
                    break;
                }
            }
        }

        if(shared){
            const SVF::SVFValue* location_addr = nullptr;
            std::string var_name = "unknown";
            std::string field_index;

            cout << "\n For the global inst:  " << (*global_it)->toString() << endl;
            
            // Only create event if we found a valid memory access (not a call instruction parameter)
            llvm::outs() << "[LLVM VAL]" << *val;

            const auto global_inst = dyn_cast<GlobalVariable>(val); 
            if(global_inst->isConstant()){
                cout << "This global variable is a constant, skipping..." << endl;
                continue;
            }
            const SVFValue* global_val = static_cast<const SVF::SVFValue*>(*global_it);
            if(!global_val){
                cout << "global val is null" << endl;
                return;
            }
            const SVFInstruction* global_val_inst = static_cast<const SVF::SVFInstruction*>(global_val);

            if(!global_val_inst){
                cout << "global val inst is null" << endl;
                return;
            }


            //get location_addr, field_index and var_name for the global variable from the global_it 
            // insert location_addr, field_index and var_name to shared_vars set

            // const SVFValue* val = baseobj->getValue();
            var_name = llvmmod -> getLLVMValue(global_val) -> getName().str();
            cout << "[NEW WAY TO GET THE GLOBAL VAR NAME] var_name: " << var_name << endl;
            location_addr = global_val;

            const Value* llvm_val = llvmmod->getLLVMValue(global_val);
            if (llvm_val){
                field_index = get_field_index_from_ptr(llvm_val);
            }
            cout << "[NEW WAY TO GET THE GLOBAL VAR NAME] pointer to shared loc (addr): " << location_addr << ", field index: " << field_index << endl;

            shared_vars.insert({{location_addr, field_index}, var_name});
            cout << "[NEW WAY TO GET THE GLOBAL VAR NAME] Found a shared variable: " << var_name << endl;


            if(global_inst && var_name != "unknown" && location_addr != nullptr){
                llvm::StringRef var_name = global_inst->getName();
                std::string name = var_name.str();
                cout << "[DEBUG 4] global var name: " << name << endl;

                std::string eventID = "e" + std::to_string(eventCounter++);
                // since global variable access is not within any function context, creating an empty call string context for it
                const CallStrCxt empty_cxt; 

                instToEventID[std::make_pair(global_val_inst, empty_cxt)] = eventID;

                event_info* info = new event_info(eventID, "0", "W", location_addr, field_index, name, "NA", std::make_pair(global_val_inst, empty_cxt), true, "NonAtomic");

                threadEvents["0"].push_back(info);

                // Printing the instruction and its extracted info for debugging
                cout << "[DEBUG]Instruction: " << (*global_it)->toString()  << endl;
                cout << "[DEBUG]Info: eventID: " << eventID << ", TID: " <<
                "0" << ", " << "W" << ", loc: " << name << ", access_mode: " << "NA" << endl;
                
                // Create CF edge from previous instruction to the current instruction within the bb

                if (prevInst.size() > 0)
                {
                    cout << "[CF " << prevInst << " " << eventID << "] **Adding to CF edges in identify_shared_global_variables**" << endl;
                    cout << "From (" << prevInst << ") --> " << "To (" << eventID << ")" << endl;
                    cfEdges_map[prevInst].insert(eventID);
                }
                prevInst = eventID;
            }
        }
    }

}

void identify_shared_variables(SVFIR* pag, FSMPTA* fsmpta, MHP* mhp, SVFModule* svfModule){
    // Pointers
    get_points_to_info(pag, fsmpta);

    for (const auto& pair : points_to_info){
        NodeID var = pair.first;
        NodeID points_to_node = pair.second;
        // check which nodes point to the same node
        for (const auto& other_pair : points_to_info){
            if (other_pair.first != var && other_pair.second == points_to_node){
                // var and other_pair.first point to the same node, so they
                // maybe shared variables we consider them shared if we find
                // that other_pair.first is from a different thread that may run
                // in parallel with the thread of var (based on MHP analysis)

                std::set<NodeID> varThreadIDs = get_thread_ids_for_pag_node(var, pag, mhp);
                std::set<NodeID> otherVarThreadIDs = get_thread_ids_for_pag_node(other_pair.first, pag, mhp);

                if (varThreadIDs.empty() || otherVarThreadIDs.empty()){
                    continue;
                }

                bool differentThreadFound = false;
                for (NodeID tid1 : varThreadIDs){
                    for (NodeID tid2 : otherVarThreadIDs){
                        if (tid1 != tid2){
                            differentThreadFound = true;
                            break;
                        }
                    }
                    if (differentThreadFound){
                        break;
                    }
                }

                if (differentThreadFound){
                    cout << "[SHARED-CANDIDATE] PAG nodes " << var
                              << " and " << other_pair.first
                              << " point to MemObj " << points_to_node
                              << " and may be shared across threads."
                              << std::endl;
                    print_thread_ids_for_pag_node(var, pag, mhp);
                    print_thread_ids_for_pag_node(other_pair.first, pag, mhp);

                    //adding the corresponding variable to the set of shared variables
                    const MemObj* baseobj = pag->getObject(points_to_node);
                    if (baseobj && !baseobj->isFunction()){
                        if(baseobj->getValue()){
                            if(baseobj){
                                std::string inst = baseobj->toString();
                                cout << "[DEBUG] Shared variable instruction: " << inst << endl;
                            }
                        }
                        std::string var_name;
                        const SVF::SVFValue* location_addr;
                        std::string field_index = "";
                        const SVFValue* val = baseobj->getValue();
                        if(val){
                            var_name = llvmmod -> getLLVMValue(val) -> getName().str();
                            location_addr = val;

                            const Value* llvm_val = llvmmod->getLLVMValue(val);
                            if (llvm_val){
                                field_index = get_field_index_from_ptr(llvm_val);
                            }

                            shared_vars.insert({{location_addr, field_index}, var_name});
                            cout << "[DEBUG 0] Found a shared variable: " << var_name << endl;
                        }
                        cout << "location_addr is: " << location_addr << ", field_index: " << field_index << endl;
                    }
                }
            }
        }
    }

    cout << "\n=== Shared variables identified from pointer analysis ===" << endl;   
    cout << "Shared variables:" << endl;
    for(auto var : shared_vars){
        cout << "Variable name: " << var.second << ", location address: " << var.first.first << ", field index: " << var.first.second << endl;
    }
    cout << "\n IDENTIFYING SHARED VARIABLES AMONG THE GLOBAL VARIABLES \n" << endl;
    //global variables
    identify_shared_global_variables(pag, mhp, svfModule);
    cout << "Identified shared global variables" << endl;
    cout << "All shared vars identified:" << endl;
    for(auto var : shared_vars){
        cout << "Variable name: " << var.second << ", location address: " << var.first.first << ", field index: " << var.first.second << endl;
    }
}

// void add_cf_for_forked_threads(TCT* tct){
//     cout << "[DEBUG 5] Adding Cf edges for forks" << endl;

//      //get the forked thread or function and add an edge from the last instruction encountered in this thread to the first instruction of the forked thread

//     for(auto inst_thread: forked_threads){
//         cout << "[DEBUG 5] processign a forked thread" << endl;
//         auto from_inst = instToEventID.find(std::make_pair(inst_thread.prev_inst, inst_thread.prev_inst_cxt));
//         if (from_inst == instToEventID.end()){
//             cout << "[DEBUG 5] prev inst has no event id, skipping" << endl;
//             continue;
//         }
//         std::string from_event_id = from_inst->second;
//         cout << "[DEBUG 5] from event id = " << from_event_id << endl;


//         CallStrCxt c = inst_thread.new_cxt;

//         cout << "[DEBUG 8] Call string context - finding tct node corresponding to this: " << endl;
//         print_call_context(c);

//         CxtThread cs = CxtThread(c, inst_thread.inst);
//         cout << "[DEBUG 9] context thread context call string: " << cs.cxtToStr() << endl;

//         if(tct->hasTCTNode(cs)){
//             TCTNode* node = tct->getTCTNode(cs);

//             NodeID threadID = node->getId();

//             std::string threadIDStr = std::to_string(threadID);
        
//             cout << "[DEBUG 5] thread id = " << threadIDStr << endl;
            
//             auto events_vector = threadEvents.find(threadIDStr);
//             if (events_vector == threadEvents.end() || events_vector->second.empty() || events_vector->second[0] == nullptr){
//                 cout << "[DEBUG 5] no first event for thread " << threadIDStr << ", skipping" << endl;
//                 continue;
//             }
            
//             event_info* first_event = events_vector->second[0];

//             cout << "[CF " << from_event_id << " " << first_event->event_id << "] **Adding to CF edges in add_cf_for_forked_threads**" << endl;
//             cout << "[SW " << from_event_id << " " << first_event->event_id << "] **Adding to SW edges in add_cf_for_forked_threads**" << endl;

//             cout << "SW: From (" << from_event_id << ") --> " << "To (" << first_event->event_id << ")" << endl;
//             cfEdges_map[from_event_id].insert(first_event->event_id);
//             swEdges_map[from_event_id].insert(first_event->event_id);

//             cout << "[DEBUG 5] Added CF for fork: from " << from_event_id << " --> to " << first_event->event_id << " of thread " << threadIDStr << endl;
//             cout << "[DEBUG 5] Added SW for fork: from " << from_event_id << " --> to " << first_event->event_id << " of thread " << threadIDStr << endl;
//         }else{
//             cout << "[DEBUG 5] TCT doesn't have the node" << endl;
//         }
            
//     }
// }


void print_all_event_ids(){
    for(auto a:instToEventID){
        cout << a.second << ": [" << a.first.first->toString() << "]";
        auto call_string_cxt = a.first.second;
        print_call_context(call_string_cxt);
    }
}


bool check_path_in_icfg(ICFG* icfg, const SVFInstruction* from_inst, const SVFInstruction* to_inst){
    // just performing a dfs starting from the from_inst node
    ICFGNode* from_node = icfg->getICFGNode(from_inst);
    ICFGNode* to_node = icfg->getICFGNode(to_inst);

    std::set<const ICFGNode*> visited;
    std::vector<const ICFGNode*> stack;
    stack.push_back(from_node);

    while (!stack.empty()){
        const ICFGNode* current = stack.back();
        stack.pop_back();

        if (current == to_node){
            return true;
        }

        if (visited.find(current) != visited.end()){
            continue;
        }
        visited.insert(current);

        for (const auto& out_edge : current->getOutEdges()){
            ICFGNode* succ = out_edge->getDstNode();
            if (visited.find(succ) == visited.end()){
                stack.push_back(succ);
            }
        }
    }

    return false;
}


void soundness_check_added_edges(ICFG* icfg){
    //check all the edges in cfEdges_map for a corresponding edge in the CFG
    std::ofstream outputFile("soundness_check.md");
    for(const auto& cf : cfEdges_map){
        std::string from_event_id = cf.first;
        for(const auto& to_event_id : cf.second){
            // writing the check for each edge to the file
            outputFile << from_event_id << " --> " << to_event_id << ":\n";
            // I need the SVFInstruction* corresponding to these event ids so that I can get their parent basic blocks and check for an edge between those basic blocks in the CFG
            event_info* from_event_info = nullptr;
            event_info* to_event_info = nullptr;

            for (const auto& t : threadEvents){
                for (const auto& event_info_i : t.second){
                    if(event_info_i->event_id == from_event_id){
                        from_event_info = event_info_i;
                    }
                    if(event_info_i->event_id == to_event_id){
                        to_event_info = event_info_i;
                    }
                }
            }

            if(from_event_info && to_event_info){
                const SVFInstruction* from_inst = from_event_info->inst_cxt.first;
                const CallStrCxt from_cxt = from_event_info->inst_cxt.second;
                const SVFInstruction* to_inst = to_event_info->inst_cxt.first;
                const CallStrCxt to_cxt = to_event_info->inst_cxt.second;

                bool path_exists_in_icfg = check_path_in_icfg(icfg,from_inst, to_inst);
                if(path_exists_in_icfg){
                    outputFile << "[SOUND] Path exists in the ICFG \n\n";
                    continue;
                }

                if(from_event_info->threadID == "0" && to_event_info->threadID != "0"){
                    outputFile << "[?] Edge from main thread to some other thread \n\n";
                    continue;
                }
                if(from_event_info->threadID == "0" && to_event_info->threadID == "0" && from_event_info->is_global && !to_event_info->is_global){
                    // This seems to have an issue - I am ending up marking edges wrongly created from last global event to the events after join in main as not unsound 
                    // TODO: 1. check why such edges are created in the first place
                    // TODO: 2. modify this soundness check - though this is just some imprecision (which is fine), it is good to avoid such unnecessary edges
                    outputFile << "[?] Edge from global event to main thread's event \n\n";
                    continue;
                }
                if(from_event_info->threadID == "0" && to_event_info->threadID == "0" && from_event_info->is_global && to_event_info->is_global){
                    outputFile << "[?] Edge btwn global events - these may not be included in the ICFG \n\n";
                    continue;
                }

                outputFile << "**[UNSOUND!]** No corresponding path in the ICFG\n\n";
                
                // display teh event info
                outputFile << "From event info: event id: " << from_event_info->event_id << ", thread id: " << from_event_info->threadID << ", kind: " << from_event_info->kind << ", location: " << from_event_info->location_addr  << "field index: " << from_event_info->field_index << ", access mode: " << from_event_info->access_mode << "\n";
                outputFile << "From instruction: " << from_inst->toString() << "\n";
                outputFile << "To event info: event id: " << to_event_info->event_id << ", thread id: " << to_event_info->threadID << ", kind: " << to_event_info->kind << ", location: " << to_event_info->location_addr << "field index: " << to_event_info->field_index << ", access mode: " << to_event_info->access_mode << "\n";
                outputFile << "To instruction: " << to_inst->toString() << "\n";
            }else{
                outputFile << "Could not find event info for events: " << from_event_id << " or " << to_event_id << "\n";
            }
        }
    }
}

bool check_in_instToEventID_map(const SVFInstruction* inst){
    for(auto& inst_eventid:instToEventID){
        if(inst_eventid.first.first == inst){
            return true;
        }
    }
    return false;
}

//Helper func for completeness_check
bool is_shared_inst(ICFGNode* node){
    //get the SVFInstruction* corresponding to this and check if it is a shared event by checking in the instToEventID map
    
    // relevant API endpoints
    // SVF::ICFGNode class: const SVFStmtList & 	getSVFStmts () const
    // typedef std::list<const SVFStmt*> SVF::ICFGNode::SVFStmtList
    // SVF::SVFStmt class: const SVFInstruction * 	getInst () const    ---->  Get/set methods for llvm instruction. 

    const SVF::ICFGNode::SVFStmtList& stmts = node->getSVFStmts();
    for(const SVFStmt* stmt: stmts){
        const SVFInstruction* inst = stmt->getInst();
        // check if this instruction is a shared event in our graph
        // I gotta check the instToEventID map for the event id corresponding to this instruction for some context

        bool shared = check_in_instToEventID_map(inst);
        if(shared){
            return true;
        }
    }
    return false;
}


//Helper func for check_event_in_ccfg (completeness_check)
std::vector<event_info*> get_event_info(ICFGNode* node){
    std::vector<event_info*> ei_vec;
    if(!node){
        return ei_vec;
    }

    const SVF::ICFGNode::SVFStmtList& stmts = node->getSVFStmts();
    for(const SVFStmt* stmt: stmts){
        const SVFInstruction* inst = stmt->getInst();

        for (const auto& t : threadEvents){
            for (const auto& event_info_i : t.second){
                if(event_info_i && event_info_i->inst_cxt.first == inst){
                    ei_vec.push_back(event_info_i);
                }
            }
        }
    }
    return ei_vec;
}

int missing_edges_count = 0;
//Helper func for completeness_check
void check_edge_in_ccfg(ICFGNode* prev, ICFGNode* curr_queue_entry){
    //get eventinfo(s) corresponding to prev
    auto from_event = get_event_info(prev);
    auto to_event = get_event_info(curr_queue_entry);
    std::string from_event_id, to_event_id;

    //check if there is an edge from an event_id in from_event to an event_id in to_event
    // i am doing this in a context insensitive manner

    for(auto& from_ei: from_event){
        if(from_ei){
            from_event_id = from_ei->event_id;
        }
        
        if(cfEdges_map.find(from_event_id) != cfEdges_map.end()){
            cout << "Checking for the corresponding edge in ccfg: FROM: " << from_event_id << ", TO: "; 
            for(auto id:cfEdges_map[from_event_id]){
                for(auto& to_ei: to_event){
                    if(to_ei){
                        to_event_id = to_ei->event_id;
                        cout << to_event_id << ", ";
                    }
                    if(id == to_event_id){
                        //there is a corresponding edge in the ccfg
                        //so, simply returning
                        return;
                    }
                }
                cout << endl;
            }
        }
    }
    
    outputFile << "\n[Edge " << ++missing_edges_count << "]Expected edge btwn one of these: " << endl;
    cout << "\n[Edge " << missing_edges_count << "]Expected edge btwn one of these: " << endl;
    
    // cout << "\n[Edge " << missing_edges_count << "]Expected edge btwn one of these: " << endl;
    for(auto from:from_event){
        for(auto to:to_event){
            cout << "From event id: " << from->event_id << ", thread id: " << from->threadID << ", kind: " << from->kind << ", location: " << from->var_name << ", addr = " << from->location_addr << ", field index: " << from->field_index << ", access mode: " << from->access_mode << endl;
            cout << "To event id: " << to->event_id << ", thread id: " << to->threadID << ", kind: " << to->kind << ", location: " << to->var_name << ", addr = " << to->location_addr << ", field index: " << to->field_index << ", access mode: " << to->access_mode << endl;

            outputFile << "[FROM] Event id: " << from->event_id << ", thread id: " << from->threadID << ", kind: " << from->kind << ", location: " << from->var_name << ", addr = " << from->location_addr << ", field index: " << from->field_index << ", access mode: " << from->access_mode << "\n";
            outputFile << "[TO]Event id: " << to->event_id << ", thread id: " << to->threadID << ", kind: " << to->kind << ", location: " << to->var_name << ", addr = " << to->location_addr << ", field index: " << to->field_index << ", access mode: " << to->access_mode << "\n";
            
            missing_edges.insert({from->event_id, to->event_id});
        }
    }
}


RetICFGNode* get_return_node(ICFGNode* node, RetICFGNode* ret){
    if(SVFUtil::isa<CallICFGNode>(node)){
        //cast ICFGNode to CallICFGNode and then get the corresponding RetICFGNode
        const CallICFGNode* callnode = SVFUtil::cast<CallICFGNode>(node);
        ret = const_cast<RetICFGNode*>(callnode->getRetICFGNode());
    }else if(SVFUtil::isa<RetICFGNode>(node)){
        ret = nullptr;
    }

    return ret;
}


void completeness_check(ICFG* icfg){
    //check all the edge in icfg - there must be an edge btwn the corresponding instructions in our graph

    std::queue<ICFGSuccessor> explore_succs_queue;
    std::set<std::pair<ICFGNode*, ICFGNode*>> visited;

    ICFGNode* first_node = icfg->begin()->second;
    RetICFGNode* retNode = get_return_node(first_node, nullptr);
    explore_succs_queue.push(ICFGSuccessor(first_node, nullptr, retNode));

    while(!explore_succs_queue.empty()){
        auto curr_queue_entry = explore_succs_queue.front();
        explore_succs_queue.pop();

        ICFGNode* curr_inst = curr_queue_entry.curr_inst;
        ICFGNode* prev_shared_inst = curr_queue_entry.prev_shared_inst;
        RetICFGNode* retNode = const_cast<RetICFGNode*>(curr_queue_entry.retNode);
        RetICFGNode* compare_retNode = nullptr;

        if(SVFUtil::isa<FunExitICFGNode>(curr_inst)){
            //if I am at an Exit node, I may have multiple successors that return to different contexts
            // out of them I should only pick the succ with the node ptr matching the retNode
            compare_retNode = retNode;
        }

        // look at all the successors of curr_inst
        for(const ICFGEdge* outEdge: curr_inst->getOutEdges()){
            ICFGNode* succ = outEdge->getDstNode();
            retNode = get_return_node(succ, retNode);

            if(SVFUtil::isa<RetICFGNode>(succ)){
                if(succ != compare_retNode){
                    cout << "Stepped into wrong context - skipping this successor node" << endl;
                    continue;
                }
            }
            
            ICFGNode* new_shared_inst = prev_shared_inst;

            if(is_shared_inst(succ)){
                new_shared_inst = succ;

                // COMPLETENESS CHECK - check if there is an edge from prev_shared_inst to new_shared_inst
                if(prev_shared_inst && new_shared_inst){
                    cout << "[COMPLETENESS CHECK] Checking edge in ccfg for edge from [" << prev_shared_inst->getId() << "]:"<< prev_shared_inst->toString() << " to [" << new_shared_inst->getId() << "]:" << new_shared_inst->toString() << endl;
                    check_edge_in_ccfg(prev_shared_inst, new_shared_inst);
                }
            }

            if(visited.find({succ, new_shared_inst}) == visited.end()){
                //not yet visited, which means I gotta explore its successors - so push to the queue
                explore_succs_queue.push(ICFGSuccessor(succ, new_shared_inst,retNode));
            }
        }

        visited.insert({curr_queue_entry.curr_inst, curr_queue_entry.prev_shared_inst});

    }

    for(auto edge: missing_edges){
        outputFile << "Missing edge from event " << edge.first << " to " << edge.second << endl;
    }
}


int main(int argc, char** argv){
    cout << "Starting the analysis to get the CCFG..." << endl;
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
        argc, argv, "Static Generation of Concurrent Control Flow Graph",
        "[options] <input-bitcode...>");

    cout << "Building SVF module..." << endl;
    SVFModule* svfModule = LLVMModuleSet::buildSVFModule(moduleNameVec);

    // Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    cout << "Program Assignment Graph (PAG or SVFIR) built" << endl;
    cout.flush();
    
    /* Extract events in .pg format */
    cout << "Performing Multi-threaded Analysis (MTA) on the module..." << endl;
    cout.flush();
    MTA* mta = new MTA();
    mta->runOnModule(pag);
    cout << "MTA analysis completed" << endl;
    cout.flush();

    // Getting Thread Creation Tree (TCT) from MHP anal
    MHP* mhp = mta->getMHP();
    cout << "MHP analysis done, got MHP result and TCT" << endl;
    cout.flush();
    TCT* tct = mhp->getTCT();
    cout << "TCT obtained from MHP analysis" << endl;
    cout.flush();

    cout << "Running parallel pointer analysis..." << endl;
    cout.flush();
    FSMPTA* fsmpta = FSMPTA::createFSMPTA(svfModule, mhp, mta->getLockAnalysis());
    cout << "Created FSMPTA object" << endl;
    cout.flush();
    fsmpta->initialize(pag->getModule());
    fsmpta->analyze();
    // fsmpta->dumpAllPts();

    fsmpta->solveAndwritePtsToFile("pts_to_info.txt");

    identify_shared_variables(pag, fsmpta, mhp, svfModule);

    // Iterate through all threads
    for (auto it = tct->begin(); it != tct->end(); ++it){
        TCTNode* threadNode = it->second;
        NodeID threadID = threadNode->getId();
        std::string threadIDStr = std::to_string(threadID);
        CxtThread cxt_thread = threadNode->getCxtThread();
        
        cout << "Inserting to the  threads_last_events_map: " << threadIDStr << endl;
        threads_last_events_map[cxt_thread] = {threadIDStr, std::vector<std::pair<SVFInstruction*, CallStrCxt>>()};

        // cout << "Processing thread " << threadIDStr << endl;
        // process_thread(pag, tct, it);
    }
    // process the main thread (thread 0) alone - other threads will be processed when we encounter a fork instruction in the main thread
    if (tct->begin() != tct->end()) {
        process_thread(pag, tct, tct->begin());
    } else {
        cout << "No threads detected in TCT. Skipping thread analysis." << endl;
    }

    // add_cf_for_forked_threads(tct);

    print_all_event_ids();
    // SOUNDNESS CHECK: While creating an edge in our graph, I want to be sure that there exists an edge at basic block level between the parent bbs of these shared instructions
    ICFG* icfg = pag->getICFG();
    PTACallGraph* callgraph = fsmpta->getPTACallGraph();

    builder.updateCallGraph(callgraph);
    icfg->updateCallGraph(callgraph);

    soundness_check_added_edges(icfg);
    completeness_check(icfg);
    write_to_file();

    LLVMModuleSet::releaseLLVMModuleSet();
    return 0;
}
