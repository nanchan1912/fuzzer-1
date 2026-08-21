#include "SVFIR/SVFIR.h"
#include <SVF-LLVM/LLVMModule.h>
#include <SVF-LLVM/LLVMUtil.h>
#include <SVF-LLVM/CppUtil.h>
#include <SVF-LLVM/BasicTypes.h>
#include <llvm/Support/raw_ostream.h>



#include <SVF-LLVM/SVFIRBuilder.h>
#include "Util/Options.h"
#include "Util/CxtStmt.h"

#include "MTA/MHP.h"
#include "MTA/MTA.h"
#include "MTA/TCT.h"
#include "Graphs/ThreadCallGraph.h"
#include "WPA/Andersen.h"
#include <iostream>
#include <set>
#include <queue>

#include "./anal.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static std::string instToStr(const llvm::Instruction* I)
{
    std::string s;
    llvm::raw_string_ostream os(s);
    I->print(os);
    return s;
}

std::pair<std::string, const SVF::SVFValue*> get_location_pointed_to(SVFIR* pag, const Instruction* ptr_inst);

std::vector<std::pair<NodeID, NodeID>> points_to_info;
std::set<std::pair<std::string, std::string>> missing_edges;
std::ofstream outputFile("completeness_check.md");


typedef class event_info
{
public:
    string event_id;
    string threadID;
    string kind;
    const SVF::SVFValue* location_addr;
    string var_name;
    string access_mode;

    inst_cxt_pair inst_cxt;
    bool is_global; //just a temporary thing I added for soundness check for edges within thread 0


    event_info(string eventID, string tid, string k, const SVF::SVFValue*  loc, string varName, string mode, inst_cxt_pair ic, bool is_global = false)
        : event_id(eventID), threadID(tid), kind(k), location_addr(loc), var_name(varName), access_mode(mode), inst_cxt(ic), is_global(is_global){}
} event_info;

// storing the shared locations, events on those locations per thread and the control flow edges btwn events
std::set<std::pair<const SVF::SVFValue*, std::string>> shared_vars;  //{location_addr, var_name}
// threadID -> [event_info]
std::map<std::string, std::vector<event_info*>> threadEvents; 

std::unordered_map<std::string, std::set<std::string>> cfEdges_map;
LLVMModuleSet* llvmmod = LLVMModuleSet::getLLVMModuleSet();


// REVISIT: for now, I am giving event ids starting from 0, should find a way that works with the simulator
int eventCounter = 1;

// mapping each SVF instruction on shared var to an event id
typedef std::tuple<const SVF::Instruction*, SVF::CallStrCxt, const SVF::SVFValue*> inst_cxt_loc_triple;
std::map<inst_cxt_loc_triple, std::string> instToEventID;
std::set <inst_cxt_pair> connect_to_next_bb;

// Global MHP pointer
SVF::MHP* mhp_global = nullptr;

// Map from join instruction (represented by its inst_cxt_pair) to the joined thread IDs
std::map<inst_cxt_pair, std::set<std::string>> join_instruction_to_tids;

// List of actual CF edges to add at the end: from the joined thread to the destination event ID
struct pending_join_edge {
    std::string joined_tid;
    std::string to_event_id;
};
std::vector<pending_join_edge> pending_join_edges;

// Helper to get all event IDs for a given {inst, cs_cxt}
std::vector<std::string> get_event_ids(const Instruction* inst, const CallStrCxt& cs_cxt) {
    std::vector<std::string> ids;
    for (auto const& entry : instToEventID) {
        if (std::get<0>(entry.first) == inst && std::get<1>(entry.first) == cs_cxt) {
            ids.push_back(entry.second);
        }
    }
    return ids;
}

// Get all memory locations pointed to by a pointer instruction
std::vector<std::pair<std::string, const SVF::SVFValue*>> get_locations_pointed_to(SVFIR* pag, const Instruction* ptr_inst) {
    std::vector<std::pair<std::string, const SVF::SVFValue*>> locations;
    if (!ptr_inst) return locations;

    NodeID pagNodeID = llvmmod->getValueNode(ptr_inst);
    std::set<std::pair<std::string, const SVF::SVFValue*>> unique_locs;
    for (auto const& p : points_to_info) {
        if (p.first == pagNodeID) {
            NodeID points_to_node = p.second;
            const BaseObjVar* baseobj = pag->getBaseObject(points_to_node);
            
            if (baseobj && !baseobj->isFunction()) {
                if (llvmmod->hasLLVMValue(baseobj)) {
                    const SVFValue* val = baseobj;
                    std::string var_name = llvmmod->getLLVMValue(val)->getName().str();
                    unique_locs.insert({var_name, val});
                }
            }
        }
    }
    for (auto const& loc : unique_locs) {
        locations.push_back(loc);
    }
    return locations;
}

// Add control flow edges for thread joins
void add_cf_for_joined_threads() {
    for (auto const& pending : pending_join_edges) {
        std::string joined_tid = pending.joined_tid;
        std::string to_event_id = pending.to_event_id;

        auto events_vector = threadEvents.find(joined_tid);
        if (events_vector != threadEvents.end() && !events_vector->second.empty()) {
            const Instruction* last_inst = events_vector->second.back()->inst_cxt.first;
            const CallStrCxt last_cxt = events_vector->second.back()->inst_cxt.second;
            std::vector<std::string> from_event_ids = get_event_ids(last_inst, last_cxt);

            for (auto const& from_event_id : from_event_ids) {
                cfEdges_map[from_event_id].insert(to_event_id);
            }
        }
    }
}

// Forward declarations for deterministic ID generators
static std::string getDeterministicLocID(const std::string &var_name, const void *ptr);
static std::string getDeterministicInstID(const Instruction* inst);
static std::string getDeterministicGlobalInitID(const std::string& varName);

// Generate conflict report
void generate_conflict_report() {
    std::ofstream reportFile("conflict_report.md");
    reportFile << "# Event ID Conflicts Report\n\n";
    reportFile << "This report identifies events that share the same `(thread_id, instruction_id, visit_id)` but access different `location`s, which causes identification conflicts if `location` is omitted.\n\n";

    std::map<std::pair<std::string, std::string>, std::vector<event_info*>> grouped_events;

    for (const auto& t : threadEvents) {
        std::string tid = t.first;
        for (const auto& event : t.second) {
            std::string instID = event->is_global ? getDeterministicGlobalInitID(event->var_name) : getDeterministicInstID(event->inst_cxt.first);
            grouped_events[{tid, instID}].push_back(event);
        }
    }

    bool has_conflicts = false;
    for (const auto& group : grouped_events) {
        auto key = group.first;
        auto events = group.second;

        std::set<std::string> unique_locations;
        for (auto* ev : events) {
            unique_locations.insert(getDeterministicLocID(ev->var_name, ev->location_addr));
        }

        if (unique_locations.size() > 1) {
            has_conflicts = true;
            reportFile << "## Conflict for Thread " << key.first << ", Instruction ID " << key.second << "\n";
            reportFile << "- **Instruction:** `" << instToStr(events[0]->inst_cxt.first) << "`\n";
            reportFile << "- **Conflicting Events:**\n";
            for (auto* ev : events) {
                std::string locID = getDeterministicLocID(ev->var_name, ev->location_addr);
                reportFile << "  - Event `" << ev->event_id << "`: Location `" << ev->var_name << "` (" << locID << ")\n";
            }
            reportFile << "\n";
        }
    }

    if (!has_conflicts) {
        reportFile << "No conflicts detected. All events are uniquely identified by `(thread_id, instruction_id, visit_id)`.\n";
    }
    reportFile.close();
}

typedef class thread_fork_info{
    public:
        Instruction* prev_inst;
        CallStrCxt prev_inst_cxt;
        const Instruction* inst;
        CallStrCxt new_cxt;

        thread_fork_info(Instruction* fi, CallStrCxt ftc, const Instruction* ft, CallStrCxt nc)
            : prev_inst(fi), prev_inst_cxt(ftc), inst(ft), new_cxt(nc){}
} thread_fork_info;

// to store all the forks encountered to add corresponding CF edges (will be translated to sw edges in the execution graph)
std::vector<thread_fork_info> forked_threads;


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


string get_access_mode(const Instruction* inst)
{
    AtomicOrdering access_mode = AtomicOrdering::NotAtomic; 
    if(isa<LoadInst>(inst)){
        const auto* LI = dyn_cast<LoadInst>(inst);
        if(LI){
            access_mode = LI -> getOrdering();
        }
    }else if(isa<StoreInst>(inst)){
        const auto* SI = dyn_cast<StoreInst>(inst);
        if(SI){
            access_mode = SI -> getOrdering();
        }
    }else if(isa<FenceInst>(inst)){
        const auto* FI = dyn_cast<FenceInst>(inst);
        if(FI){
            access_mode = FI -> getOrdering();
        }
    }else if(isa<AtomicCmpXchgInst>(inst)){
        const auto* CXI = dyn_cast<AtomicCmpXchgInst>(inst);
        if(CXI){
            access_mode = CXI -> getMergedOrdering();
        }
    }else if(isa<AtomicRMWInst>(inst)){
        const auto* RMWI = dyn_cast<AtomicRMWInst>(inst);
        if(RMWI){
            access_mode = RMWI -> getOrdering();
        }
    }else{
        return "unknown inst";
    }

    switch(access_mode){
        case AtomicOrdering::NotAtomic:
            // cout << "Atomic Ordering: NotAtomic" << endl;
            return "NA";
        case AtomicOrdering::Unordered:
            // cout << "Atomic Ordering: Unordered" << endl;
            return "Unordered";
        case AtomicOrdering::Monotonic:
            // cout << "Atomic Ordering: Monotonic" << endl;
            return "Rlx";
        case AtomicOrdering::Acquire:
            // cout << "Atomic Ordering: Acquire" << endl;
            return "Acq";
        case AtomicOrdering::Release:
            // cout << "Atomic Ordering: Release" << endl;
            return "Rel";
        case AtomicOrdering::AcquireRelease:
            // cout << "Atomic Ordering: AcquireRelease" << endl;
            return "AcqRel";
        case AtomicOrdering::SequentiallyConsistent:
            // cout << "Atomic Ordering: SequentiallyConsistent" << endl;
            return "SC";
        default:
            // cout << "Atomic Ordering: unknown" << endl;
            return "unknown ordering";
    }
    
    
    // Value* llvmInstruction_val = llvmmod->getLLVMValue(svfInstruction);
    // Instruction* llvmInstruction = dyn_cast<Instruction>(llvmInstruction_val);

    // if(llvmInstruction->isAtomic()){
    //     if(llvmInstruction->hasAtomicStore()){
    //         auto storeInst = dyn_cast<StoreInst>(llvmInstruction);
    //         if(storeInst){
    //             return storeInst->getOrdering();
    //         }
    //     }
    // }
        // if (llvmInstruction.find("monotonic") != string::npos)
        //     return "Rlx";
        // else if (llvmInstruction.find("acquire") != string::npos)
        //     return "Acq";
        // else if (llvmInstruction.find("release") != string::npos)
        //     return "Rel";
        // else if (llvmInstruction.find("seq_cst") != string::npos)
        //     return "SC";
        // else
        //     return "NA";
}


bool is_shared(const Instruction* inst){
    if (isa<LoadInst>(inst) ||
        isa<StoreInst>(inst) ||
        isa<FenceInst>(inst) ||
        isa<AtomicCmpXchgInst>(inst) ||
        isa<AtomicRMWInst>(inst))
        {
            return true;
        }
        return false;
}


std::pair<Instruction*, CallStrCxt> check_inst(SVFIR* pag, TCT* tct, const Instruction* inst, const CallStrCxt cs_cxt, Instruction* prevInst, CallStrCxt prevInst_cxt, std::string threadIDStr){
    Instruction* prevInst_passed = prevInst;

    bool not_fence = false;
    string kind;
    string access_mode = get_access_mode(inst);

    if(is_shared(inst)){
        std::vector<std::pair<std::string, const SVF::SVFValue*>> resolved_locs;
        if (isa<LoadInst>(inst) || isa<StoreInst>(inst) || isa<AtomicCmpXchgInst>(inst) || isa<AtomicRMWInst>(inst)){
            not_fence = true;
            const Value* ptr = nullptr;
            if (const auto* LI = dyn_cast<LoadInst>(inst)) ptr = LI->getPointerOperand();
            else if (const auto* SI = dyn_cast<StoreInst>(inst)) ptr = SI->getPointerOperand();
            else if (const auto* RMWI = dyn_cast<AtomicRMWInst>(inst)) ptr = RMWI->getPointerOperand();
            else if (const auto* CXI = dyn_cast<AtomicCmpXchgInst>(inst)) ptr = CXI->getPointerOperand();

            if (ptr) {
                ptr = ptr->stripPointerCasts();
                if (const auto* GV = dyn_cast<GlobalVariable>(ptr)){
                    std::string var_name = GV->getName().str();
                    const SVF::SVFValue* location_addr = pag->getGNode(llvmmod->getObjectNode(GV));
                    resolved_locs.push_back({var_name, location_addr});
                }else{
                    const Instruction* ptr_inst = dyn_cast<Instruction>(ptr);
                    if (ptr_inst) {
                        resolved_locs = get_locations_pointed_to(pag, ptr_inst);
                    }
                }
            }
            kind = (isa<LoadInst>(inst)) ? "R" : (isa<StoreInst>(inst) ? "W" : "RMW");
        }
        else if(isa<FenceInst>(inst)){
            kind = "F";
            not_fence = false;
            resolved_locs.push_back({"", nullptr});
        }

        for (auto const& loc : resolved_locs) {
            std::string var_name = loc.first;
            const SVF::SVFValue* location_addr = loc.second;

            if((not_fence && shared_vars.find({location_addr, var_name}) != shared_vars.end())||(!not_fence)){
                write_to_thread_events(inst, cs_cxt, threadIDStr, location_addr, var_name, instToStr(inst), kind, access_mode);
            }
        }

        std::vector<std::string> curr_ids = get_event_ids(inst, cs_cxt);
        if (!curr_ids.empty()) {
            if (prevInst){
                if (join_instruction_to_tids.count({prevInst, prevInst_cxt})) {
                    for (auto const& joined_tid : join_instruction_to_tids[{prevInst, prevInst_cxt}]) {
                        for (auto const& to_id : curr_ids) {
                            pending_join_edges.push_back({joined_tid, to_id});
                        }
                    }
                }
                
                std::vector<std::string> prev_ids = get_event_ids(prevInst, prevInst_cxt);
                for (auto const& from_id : prev_ids) {
                    for (auto const& to_id : curr_ids) {
                        cfEdges_map[from_id].insert(to_id);
                    }
                }
            }
            prevInst = const_cast<Instruction*>(inst);
            prevInst_cxt = cs_cxt;
        }
    }
    
    return {prevInst, prevInst_cxt};
}

std::vector<std::pair<Instruction*, CallStrCxt>> check_call_inst(SVFIR* pag, TCT* tct, const Instruction* inst, const CallStrCxt cs_cxt, Instruction* prevInst, CallStrCxt prevInst_cxt, std::string threadIDStr){
    std::vector<std::pair<Instruction*, CallStrCxt>> last_inst_pairs;

    const CallICFGNode* callNode = nullptr;
    if (llvmmod->hasICFGNode(inst)) {
        callNode = llvmmod->getCallICFGNode(inst);
    }

    if(isa<CallInst>(inst)){
        const ThreadAPI* thread_api = ThreadAPI::getThreadAPI();
        if(callNode && thread_api->isTDFork(callNode)){
            deal_with_fork_inst(inst, instToStr(inst), tct, thread_api, cs_cxt, prevInst, prevInst_cxt);
        }

        if(callNode && thread_api->isTDJoin(callNode)){
            ThreadCallGraph* tcg = tct->getThreadCallGraph();
            if (tcg && tcg->hasThreadJoinEdge(callNode)) {
                std::set<std::string> tids;
                for (auto jit = tcg->getJoinEdgeBegin(callNode), ejit = tcg->getJoinEdgeEnd(callNode); jit != ejit; ++jit) {
                    const ThreadJoinEdge* edge = *jit;
                    const FunObjVar* calleeFunc = edge->getDstNode()->getFunction();
                    
                    // Find matching threads in TCT
                    for (auto it = tct->begin(); it != tct->end(); ++it){
                        TCTNode* threadNode = it->second;
                        const FunObjVar* startFunc = tct->getStartRoutineOfCxtThread(threadNode->getCxtThread());
                        if (startFunc == calleeFunc) {
                            tids.insert(std::to_string(threadNode->getId()));
                        }
                    }
                }
                if (!tids.empty()) {
                    join_instruction_to_tids[{inst, cs_cxt}] = tids;
                }
            }
            last_inst_pairs.push_back({const_cast<Instruction*>(inst), cs_cxt});
            return last_inst_pairs;
        }

        if (const auto* CB = dyn_cast<CallBase>(inst)){
            const Function* calledFunc = CB->getCalledFunction();

            if (!calledFunc){
                const Value* calledOperand = CB->getCalledOperand();
                if (calledOperand){
                    calledOperand = calledOperand->stripPointerCasts();
                    calledFunc = dyn_cast<Function>(calledOperand);
                }
            }

            if (calledFunc){
                const FunObjVar* calledFunc_svf = llvmmod->getFunObjVar(calledFunc);

                if(calledFunc_svf){
                    CallStrCxt new_cxt = cs_cxt;
                    ThreadCallGraph* tcg = tct -> getThreadCallGraph();
                    
                    if(callNode && !tcg->hasCallSiteID(callNode, calledFunc_svf)){
                        last_inst_pairs.push_back({prevInst, prevInst_cxt});
                        return last_inst_pairs;
                    }

                    if(calledFunc_svf->isDeclaration()){
                        if(callNode && thread_api->isTDFork(callNode)){
                            const ValVar* forked_thread = thread_api->getForkedThread(callNode);
                            const ValVar* forkVal = thread_api->getForkedFun(callNode);
                            const FunObjVar* callee = SVFUtil::dyn_cast<FunObjVar>(forkVal);
                            
                            if(callee){
                                tct->pushCxt(new_cxt, callNode, callee);
                            }
                        }
                    }
                    else{
                        const Function* caller = inst->getFunction();
                        if (callNode) {
                            tct->pushCxt(new_cxt, callNode, calledFunc_svf);
                        }
                    }

                    if (!calledFunc_svf->isDeclaration()) {
                        last_inst_pairs = extract_insts_and_edges(pag, tct, calledFunc_svf, prevInst, prevInst_cxt, new_cxt, threadIDStr);
                    }
                }
            }
        }
    }

    if (last_inst_pairs.empty()) {
        last_inst_pairs.push_back({prevInst, prevInst_cxt});
    }
    return last_inst_pairs;
}


std::vector<std::pair<Instruction*, CallStrCxt>> remove_duplicates(std::vector<std::pair<Instruction*, CallStrCxt>> last_insts_temp){
    // just a small func to remove any duplicates from the passed vector and write it to another vector
    std::vector<std::pair<Instruction*, CallStrCxt>> last_insts;
    std::set<std::pair<Instruction*, CallStrCxt>> seen;
    for(auto p: last_insts_temp){
        if(seen.find(p) == seen.end()){
            last_insts.push_back(p);
            seen.insert(p);
        }
    }
    return last_insts;
}


std::vector<std::pair<Instruction*, CallStrCxt>> extract_insts_and_edges(SVFIR* pag, TCT* tct, const FunObjVar* func, Instruction* prevInstOfFunc, const CallStrCxt prevInstOfFunc_cxt,const CallStrCxt cs_cxt, std::string threadIDStr){
    // This function extracts all the shared events in a function and writes them all to thread events. 
    // It also creates CF edges btwn the shared events found in the func defn
    // prevInst and its context is passed since we need an edge from the shared event before the func call to the first shared inst in this func
    
    std::vector<std::pair<Instruction*, CallStrCxt>> last_insts;
    std::vector<std::pair<Instruction*, CallStrCxt>> return_insts;

    // cout << "[DEBUG FUNC] Extracting instructions from " << func -> getName() << endl;
    // cout << "cs_cxt of the func: ";
    print_call_context(cs_cxt);

    if(prevInstOfFunc){
        // cout << "Prev shared inst: " << prevInstOfFunc -> toString() << endl;
    }

    // cout << "Context of Prev shared inst: ";
    print_call_context(prevInstOfFunc_cxt);

    Instruction* prevInst = prevInstOfFunc;
    CallStrCxt prevInst_cxt = prevInstOfFunc_cxt;

    last_insts.push_back({prevInst, prevInst_cxt});
    
    if(!func->hasBasicBlock()){
        // just return the prev inst passed as arg if the func doesn't have any basic blocks
        return {{prevInst, prevInst_cxt}};
    }
    
    const SVFBasicBlock* bb = func -> getEntryBlock();


    std::queue<std::pair<const SVF::SVFBasicBlock*, std::pair<Instruction*, CallStrCxt>>> bb_to_connect_queue;
    std::set<std::pair<const SVF::SVFBasicBlock*, std::pair<Instruction*, CallStrCxt>>> visited_bbs;

    for(const ICFGNode* icfgNode : *bb){
        if (!llvmmod->hasLLVMValue(icfgNode)) continue;
        const Instruction* inst = dyn_cast<Instruction>(llvmmod->getLLVMValue(icfgNode));
        if (!inst) continue;
        const SVF::SVFValue* val = icfgNode;
        //if it is a return instruction, add the inst and context to the vector of events being returned
        // cout << "Looking at inst: " << instToStr(inst) << endl;

        if(isa<ReturnInst>(inst)){
            // REVISIT: Here, I am assuming that the return inst isnt a shared inst
            // cout << "Found a return instruction" << endl;
            for(auto prev: last_insts){
                return_insts.push_back({prev.first, prev.second});
            }
            last_insts.clear();

        }else if(isa<CallInst>(inst)){
            std::vector<std::pair<Instruction*, CallStrCxt>> last_insts_temp;
            // cout << "Exploring a call instruction" << endl;
            for(auto prev: last_insts){
                auto last_insts_per_prev = check_call_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, threadIDStr);
                last_insts_temp.insert(last_insts_temp.end(), last_insts_per_prev.begin(), last_insts_per_prev.end());
            }
            last_insts = remove_duplicates(last_insts_temp);

        }else{
            // cout << "Exploring a non-call instruction" << endl;
            bool shared = false;

            for(auto prev:last_insts){
                auto last_shared_inst = check_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, threadIDStr);
                
                //the ret value here would either be the prev inst from the function given as arg or the new inst
                //if it is new inst, I can set call_inst to false and update prevInst and prevInst_cxt
                
                if(last_shared_inst.first != prev.first){
                    shared = true;
                    //found a new shared inst - so I need not look at the last_insts for the next inst in the bb
                    prevInst = last_shared_inst.first;
                    prevInst_cxt = last_shared_inst.second;
                }
            }

            if(shared){
                last_insts = {{prevInst, prevInst_cxt}};
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
        // cout << "Looking for a shared event in the successors of bb [" << curr_bb->getName() << "]" << endl;
        bb_to_connect_queue.pop();
        
        
        Instruction* parent_last_shared_inst = curr_bb_pair.second.first;
        // cout << "Last shared inst in the parent bb: " << (parent_last_shared_inst ? parent_last_shared_inst->toString() : "null") << endl;
        
        CallStrCxt parent_last_shared_inst_cxt = curr_bb_pair.second.second;
        // cout << "context of the last shared inst in the parent bb: ";
        print_call_context(parent_last_shared_inst_cxt);
        
        //since I push a bb to the queue only after checking all the instructions in the bb, I can just look at its successors for any shared instructions
        const auto& succ_list = curr_bb->succBBs;

        for(auto succ:succ_list){
            // cout << "Successor BB [" << succ->getName() << "]  instructions: " << endl;

            Instruction* prevInst_bb = parent_last_shared_inst;
            CallStrCxt prevInst_bb_cxt = parent_last_shared_inst_cxt;

            last_insts = {{prevInst_bb, prevInst_bb_cxt}};

            for(const ICFGNode* icfgNode : *succ){
                if (!llvmmod->hasLLVMValue(icfgNode)) continue;
                const Instruction* inst = dyn_cast<Instruction>(llvmmod->getLLVMValue(icfgNode));
                if (!inst) continue;
                const SVF::SVFValue* val = icfgNode;
                //if it is a return instruction, add the inst and context to the vector of events being returned
                // cout << "Looking at inst: " << instToStr(inst) << endl;

                if(isa<ReturnInst>(inst)){
                    // REVISIT: Here, I am assuming that the return inst isnt a shared inst
                    // cout << "Found a return instruction" << endl;
                    for(auto prev: last_insts){
                        return_insts.push_back({prev.first, prev.second});
                    }
                    last_insts.clear();

                }else if(isa<CallInst>(inst)){
                    // cout << "Exploring a call instruction" << endl;
                    std::vector<std::pair<Instruction*, CallStrCxt>> last_insts_temp;
                    for(auto prev: last_insts){
                        auto last_insts_per_prev = check_call_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, threadIDStr);
                        last_insts_temp.insert(last_insts_temp.end(), last_insts_per_prev.begin(), last_insts_per_prev.end());
                    }
                    last_insts = remove_duplicates(last_insts_temp);

                }else{
                    // cout << "Exploring a non-call instruction" << endl;
                    bool shared = false;
                    for(auto prev:last_insts){
                        auto last_shared_inst = check_inst(pag, tct, inst, cs_cxt, prev.first, prev.second, threadIDStr);
                        
                        //the ret value here would either be the prev inst from the function given as arg or the new inst
                        //if it is new inst, I can set call_inst to false and update prevInst_bb and prevInst_bb_cxt
                        
                        if(last_shared_inst.first != prev.first){
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
                    // // cout << "bb[" << succ->getName() << "] , pushing to queue" << endl;
                    // cout << "bb[" << succ->getName() << "] , pushing to queue" << endl; 
                    // cout << "last inst: " << (prev.first ? prev.first->toString() : "null") << endl;
                    // cout << "context: ";
                    print_call_context(prev.second);
                }
            }
        }

        
        // cout << "marking bb [" << curr_bb->getName() << "] as visited with last inst: " << (curr_bb_pair.second.first ? curr_bb_pair.second.first->toString() : "null") << endl;
        // cout << "context: ";
        print_call_context(curr_bb_pair.second.second);
        visited_bbs.insert({curr_bb, {curr_bb_pair.second.first, curr_bb_pair.second.second}});
    }

    // cout << "[DEBUG FUNC] Finished extracting instructions and edges from the function: " << func -> getName() << endl;
    
    // if the return_insts vector is empty, it means that there were no return instructions in the function, so I can return the last shared inst found in the function
    if(return_insts.empty()){
        // cout << "last shared inst found in the func: " << (prevInst ? prevInst->toString() : "null") << endl;
        return {{prevInst, prevInst_cxt}};
    }else{
        // cout << "last shared insts found in the func: " << endl;
        for(const auto& inst_pair : return_insts){
            // cout << "  " << (inst_pair.first ? inst_pair.first->toString() : "null") << endl;
        }
        return return_insts;
    }
}


void analyze_func(SVFIR* pag, const FunObjVar* func, TCTNode* threadNode, TCT* tct, const CallStrCxt cs_cxt, Instruction* prevInst, const CallStrCxt prevInst_cxt){
    NodeID threadID = threadNode->getId();
    std::string threadIDStr = std::to_string(threadID);
    // cout << "[DEBUG FUNC] Analyzing the function: " << func -> getName() << endl;

    std::vector<std::pair<Instruction*, CallStrCxt>> last_inst_pairs = extract_insts_and_edges(pag, tct, func, prevInst, prevInst_cxt, cs_cxt, threadIDStr);
    // Instruction* last_inst = last_inst_pair.first;
    // CallStrCxt last_inst_cxt = last_inst_pair.second;
    //TODO: I would have to use this last_inst if there are any instructions after the thread join
}


void write_to_thread_events(const Instruction* inst,
							const CallStrCxt cs_cxt,
							std::string threadIDStr,
							const SVF::SVFValue* location_addr,
							std::string var_name,
							std::string instStr,
							std::string kind,
							std::string access_mode){
    if (instToEventID.find(make_tuple(inst, cs_cxt, location_addr)) != instToEventID.end()) {
        return;
    }

    std::string eventID = "e" + std::to_string(eventCounter++);
    instToEventID[make_tuple(inst, cs_cxt, location_addr)] = eventID;

    event_info* info = new event_info(eventID, threadIDStr, kind, location_addr, var_name, access_mode, std::make_pair(inst, cs_cxt));
    threadEvents[threadIDStr].push_back(info);
}


// Helper func to deal with pthread_create functions (context)
void deal_with_fork_inst(const Instruction* inst, std::string instStr, TCT* tct, const ThreadAPI* thread_api, const CallStrCxt cs_cxt, Instruction* prev_inst, const CallStrCxt prev_inst_cxt){
    // cout << "[DEBUG 5] Found a fork instruction: " << instStr << endl;

    CallICFGNode* call_node = nullptr;
    if (llvmmod->hasICFGNode(inst)) {
        call_node = llvmmod->getCallICFGNode(inst);
    }

    const ValVar* forked_thread = call_node ? thread_api->getForkedThread(call_node) : nullptr;

    CallStrCxt call_string_cxt = cs_cxt;
    
    const ValVar* forkVal = call_node ? thread_api->getForkedFun(call_node) : nullptr;
    //track the context of the thread - I realized the need for the this when I tried to get the threadID from the above SVFValue*
    // const SVFFunction* callee = SVFUtil::dyn_cast<const SVFFunction>(inst);
    
    const FunObjVar* callee = SVFUtil::dyn_cast<FunObjVar>(forkVal);
    
    if(callee && call_node){
        tct->pushCxt(call_string_cxt, call_node, callee);
        const Function* caller = inst->getFunction();
        ThreadCallGraph* tcg = tct -> getThreadCallGraph();
        CallSiteID csId = tcg->getCallSiteID(call_node, callee);

        /// handle calling context for candidate functions only
        // if(tct->isCandidateFun(caller) == false)
            // cout << "[JUST CHECKING]  the fork inst is not a cand func" << endl;
        // else
            // cout << "[JUST CHECKING] call site id = " << csId << endl;
    }else{
        // cout << "[JUST CHECKING] callee is null" << endl;
    }
    
    if(prev_inst){
        forked_threads.push_back(thread_fork_info(prev_inst, prev_inst_cxt, inst, call_string_cxt));
        // cout << "[DEBUG 8] Pushing this context to forked_threads after the instruction : " << instToStr(prev_inst) << endl;
        print_call_context(call_string_cxt);
    }
}


// get_location_pointed_to was replaced by get_locations_pointed_to


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

static std::string getDeterministicInstID(const Instruction* inst) {
    if (!inst) {
        uint64_t hash = 14695981039346656037ULL;
        std::stringstream ss;
        ss << "0x" << std::hex << hash;
        return ss.str();
    }

    std::string fnName = "";
    const Function* f = inst->getFunction();
    if (f) {
        fnName = f->getName().str();
    }

    std::string llvmStr = "";
    if (inst) {
        llvmStr = instToStr(inst);
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

// Write to .pg format file
void write_to_file()
{
    std::ofstream pgFile("generated_output.pg");
    // std::ofstream tempFile("tempFile.md");

    pgFile << "# Shared Locations\n";
    for (const auto& loc : shared_vars){
        pgFile << "LOC " << getDeterministicLocID(loc.second, loc.first) << " " << loc.second << "\n";
    }

    // tempFile << "# Shared Locations\n";
    // for (const auto& loc : shared_vars){
    //     tempFile << "LOC " << loc.first << " " << loc.second << "\n";
    // }

    pgFile << "\n# Event: ID TID  Kind  Loc VarName  Mode   Instruction_Address     Call_string_context     Instruction\n";
    // tempFile << "\n# Event: ID TID  Kind  Loc   VarName  Mode\n";

    for (const auto& t : threadEvents){
        for (const auto& event_info : t.second){
            const Function* f = event_info->inst_cxt.first->getFunction();
            std::string fnName = f ? f->getName().str() : "";
            std::string instID = event_info->is_global ? getDeterministicGlobalInitID(event_info->var_name) : getDeterministicInstID(event_info->inst_cxt.first);
            std::string instStr = event_info->is_global ? ("@" + event_info->var_name + " = global init") : instToStr(event_info->inst_cxt.first);
            pgFile << "E\t" << event_info->event_id << "\t" << t.first
                   << "\t" << event_info->kind << "\t"
                   << getDeterministicLocID(event_info->var_name, event_info->location_addr) << "\t" << event_info->var_name << "\t" << event_info->access_mode << "\t" << instID << "\t" << get_call_context_string(event_info->inst_cxt.second) << "\t[" << instStr << "]\t" << fnName
                   << "\n";

            //simply replacing tab by , for my convenience of file comparsion
            // tempFile << "E," << event_info->event_id << "," << t.first
            //        << "," << event_info->kind << ","
            //        << event_info->location_addr << "," << event_info->var_name << "," << event_info->access_mode
            //        << "\n";
        }
    }

    pgFile << "\n# Control Flow edges\n";
    for (const auto& cf : cfEdges_map){
        for (const auto& to : cf.second){
            pgFile << "CF " << cf.first << " " << to << "\n";
        }
    }
    pgFile.close();

    // tempFile << "\n# Control Flow edges\n";
    // for (const auto& cf : cfEdges_map){
    //     for (const auto& to : cf.second){
    //         //finding the event info corresponding to the event id to get the instruction and its context for better understanding of the generated CF edges in temp file
    //         event_info* from_event_info = nullptr;
    //         event_info* to_event_info = nullptr;
    //         std::string from_event_threadID;
    //         std::string to_event_threadID;

    //         for (const auto& t : threadEvents){
    //             for (const auto& event_info : t.second){
    //                 if(event_info->event_id == cf.first){
    //                     from_event_info = event_info;
    //                     from_event_threadID = t.first;
    //                 }
    //                 if(event_info->event_id == to){
    //                     to_event_info = event_info;
    //                     to_event_threadID = t.first;
    //                 }
    //             }
    //         }
            
    //         tempFile << "CF [" << from_event_info->event_id << "] " << from_event_threadID << "," << from_event_info->kind << "," << from_event_info->location_addr << "," << from_event_info->access_mode << " --> [" << to_event_info->event_id << "] " << to_event_threadID << "," << to_event_info->kind << "," << to_event_info->location_addr << "," << to_event_info->access_mode << "\n";
    //     }
    // }
    // tempFile.close();

    // cout <<  << "\n=== Generated .pg file: generated_output.pg ==="
            //   << std::endl;
}


//Called from main on each TCTNode (each thread)- explores the start func and all the basic blocks, instructions in them - adding events and CF edges
void process_thread(SVFIR* pag, TCT* tct, std::_Rb_tree_iterator<std::pair<const unsigned int, SVF::TCTNode*>> it){
    TCTNode* threadNode = it->second;
    NodeID threadID = threadNode->getId();
    std::string threadIDStr = std::to_string(threadID);
    
    CallStrCxt parent_cxt;

    const CxtThread cxt_thrd = threadNode -> getCxtThread();
    
    const CallStrCxt cs_cxt = cxt_thrd.getContext();
    // cout << "[CALL STRING CONTEXT] Thread " << threadIDStr << ": Call string context: " << cxt_thrd.cxtToStr() << endl;

    // Get the start routine function for this thread
    const FunObjVar* startFunc = tct->getStartRoutineOfCxtThread(cxt_thrd);

    // cout << "[DEBUG]Thread ID: " << threadIDStr << endl;
    
    Instruction* prevInst = nullptr;
    if(threadEvents.find(threadIDStr) != threadEvents.end() && threadEvents[threadIDStr].size() > 0){
        // cout << "Found previous events for this thread, setting prevInst to the last event's instruction" << endl;
        prevInst = const_cast<Instruction*>(threadEvents[threadIDStr].back()->inst_cxt.first);
    }else{
        // cout << "No previous events found for this thread" << endl;
        //if we havent found any instructions of that thread, add an edge from the thread where it was spawned

        //REVISIT: Got a segfault somewhere here..just adding plenty of print statements with copilot to debug and find whre the srgault is - tremove these later
        if(tct->hasParentThread(threadID)){
            // cout << "This thread has a parent thread, trying to set prevInst to the last event of the parent thread" << endl;
            NodeID parent_thread_id = 0;
            for (NodeID parentTid : tct->getParentThreads(threadID)) {
                parent_thread_id = parentTid;
                break;
            }
            std::string parent_thread_id_str = std::to_string(parent_thread_id);
            // cout << "Parent thread id: " << parent_thread_id_str << endl;
            if(threadEvents.find(parent_thread_id_str) != threadEvents.end() && threadEvents[parent_thread_id_str].size() > 0){
                // cout << "Found previous events for the parent thread, setting prevInst to the last event's instruction of the parent thread" << endl;
                prevInst = const_cast<Instruction*>(threadEvents[parent_thread_id_str].back()->inst_cxt.first);
            }else{
                // cout << "No previous events found for the parent thread, trying to get the context of the parent thread from TCT" << endl;
            }
            
            for (auto it = tct->begin(); it != tct->end(); ++it){
                // cout << "Checking thread node with id: " << it->second->getId() << endl;
                if(it->second->getId() == parent_thread_id){
                    TCTNode* thread_node = it->second;
                    if(!thread_node){
                        // cout << "Thread node is null for thread id: " << parent_thread_id_str << endl;
                        break;
                    }
                    const CxtThread parent_cxt_thread = thread_node->getCxtThread();
                    parent_cxt = parent_cxt_thread.getContext();
                }
            }
        }
    }

    if(startFunc){
        if(prevInst){
            // cout << "Analyzing start func of thread " << threadIDStr << " with prevInst: [" << prevInst -> toString() << "]" << endl;
        }else{
            // cout << "Analyzing start func of thread " << threadIDStr << " with prevInst: [ Nullptr ]" << endl;

        }

        auto call_string_cxt = parent_cxt;
        print_call_context(call_string_cxt);
        
        analyze_func(pag, startFunc, threadNode, tct, cs_cxt, prevInst, parent_cxt);
    }
}

//Helper func to identify shared variables
void get_points_to_info(SVFIR* pag, PointerAnalysis* pta) {
    for (auto it = pag->begin(), ie = pag->end(); it != ie; ++it){
        NodeID var = it->first;
        // // cout << "NodeID: " << var << endl;
        const PointsTo& pts = pta->getPts(var);

        if (!pts.empty()){
            // This could be a global var or an alloca instruction or a function call I am interested only in global vars and alloca, NOT in fn calls

            // put the info into a data structure
            // check all nodes that point to the same node
            for (NodeID n : pts){
                // Get the instruction corresponding to the node id n
                // // cout << " -> " << n;
                const SVFVar* node = pag->getGNode(n);
                if (const ObjVar* obj = SVFUtil::dyn_cast<ObjVar>(node)) {
                    if (SVFUtil::isa<FunObjVar>(obj))
                        continue;
                    points_to_info.push_back(std::make_pair(var, n));
                }
                // cout << endl;
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
    const Instruction* inst = nullptr;

    if (node && llvmmod->hasLLVMValue(node)){
        // unsure if this will give the instruction. this is diff from how I do it..
        inst = SVFUtil::dyn_cast<Instruction>(llvmmod->getLLVMValue(node));
    }

    if (inst && llvmmod->hasICFGNode(inst)){
        const ICFGNode* icfgNode = llvmmod->getICFGNode(inst);
        if (mhp->hasThreadStmtSet(icfgNode)) {
            const MHP::CxtThreadStmtSet& tsSet = mhp->getThreadStmtSet(icfgNode);
            for (const CxtThreadStmt& cts : tsSet)
                threadIDs.insert(cts.getTid());
        }
    }

    if (!threadIDs.empty())
        return threadIDs;

    // a fallback option in case threadIDs is empty
    // checking if the fn containing the instruction is the start fn of any thread
    const FunObjVar* fun = node ? node->getFunction() : nullptr;
    if (!fun)
        return threadIDs;

    TCT* tct = mhp->getTCT();
    for (auto it = tct->begin(); it != tct->end(); ++it){
        TCTNode* threadNode = it->second;
        const FunObjVar* startFunc = tct->getStartRoutineOfCxtThread(threadNode->getCxtThread());
        if (startFunc == fun){
            threadIDs.insert(threadNode->getId());
        }
    }

    return threadIDs;
}

//Helper func to identify shared variables
void print_thread_ids_for_pag_node(NodeID pagNodeID, SVFIR* pag, MHP* mhp){
    const std::set<NodeID> threadIDs = get_thread_ids_for_pag_node(pagNodeID, pag, mhp);

    // cout <<  << "[INFO] PAG node " << pagNodeID << " is executed by thread IDs: ";
    if (threadIDs.empty()){
        // cout <<  << "(none found)";
    }
    else{
        bool first = true;
        for (NodeID tid : threadIDs){
            if (!first){
                // cout <<  << ", ";
            }
            // cout <<  << tid;
            first = false;
        }
    }
    // cout <<  << std::endl;
}

//Helper func to identify shared variables
std::set<NodeID> get_threads_executing_inst(const Instruction* inst, MHP* mhp){
    std::set<NodeID> threadIDs;

    if (inst && llvmmod->hasICFGNode(inst)){
        const ICFGNode* icfgNode = llvmmod->getICFGNode(inst);
        if (mhp->hasThreadStmtSet(icfgNode)) {
            const MHP::CxtThreadStmtSet& tsSet = mhp->getThreadStmtSet(icfgNode);
            for (const CxtThreadStmt& cts : tsSet){
                threadIDs.insert(cts.getTid());
            }
        }
    }

    if (!threadIDs.empty())
        return threadIDs;

    // a fallback option in case threadIDs is empty
    // checking if the fn containing the instruction is the start fn of any thread
    const Function* fun = inst ? inst->getFunction() : nullptr;
    if (!fun)
        return threadIDs;

    TCT* tct = mhp->getTCT();
    const FunObjVar* funObj = llvmmod->getFunObjVar(fun);
    for (auto it = tct->begin(); it != tct->end(); ++it){
        TCTNode* threadNode = it->second;
        const FunObjVar* startFunc = tct->getStartRoutineOfCxtThread(threadNode->getCxtThread());
        if (startFunc == funObj)
            threadIDs.insert(threadNode->getId());
    }
    return threadIDs;

}

//Helper func to identify shared variables
void identify_shared_global_variables(SVFIR* pag, MHP* mhp){
    LLVMModuleSet* llvmmod = LLVMModuleSet::getLLVMModuleSet();

    std::string prevInst = "";
    
    for (Module& mod : llvmmod->getLLVMModules()){
        for (GlobalVariable& gv : mod.globals()){
            std::set<NodeID> threadIDs;
            const Instruction* inst;
            // cout << "\n[DEBUG 0] Glob: " << gv.getName().str() << endl;

            const Value* val = &gv;

            std::vector<const Instruction*> uses_of_global;
        //I want to know if this is being accessed by multiple threads that may run in parallel - if yes, I consider it shared
        if(!val){
            // cout << "[DEBUG 0] No LLVM value found for the global variable, skipping..." << endl;
            continue;
        }
        // else{
        //     // cout << "No prob with val" << endl;
        // }

        bool found_one_store = 0;
        
        for (Value::const_use_iterator it2 = val->use_begin(), ie = val->use_end(); it2 != ie; ++it2){
            // // cout << "[DEBUG 0] Looking at a use of the global variable" << endl;
            const Use *u = &*it2;
            if(!u){
                // cout << "[DEBUG 0] No use found for the global variable, skipping..." << endl;
                continue;
            }
            // else{
            //     // cout << "No prob with use" << endl;
            // }
            
            const Value* user = u->getUser();
            
            if(!user){
                // cout << "[DEBUG 0] No user found for the use of the global variable, skipping..." << endl;
                continue;
            }
            // // cout << "[DEBUG 0] Found a use of the global variable" << endl;

            // llvm ::outs() << "User of the global variable: " << *user << "\n";
            
            const Instruction* llvm_inst = SVFUtil::dyn_cast<Instruction>(user);
            
            // // cout << "llvm_inst obtained" << endl;
            if(!llvm_inst){
                // cout << "[DEBUG 0] No instruction found for the use of the global variable, skipping..." << endl;
                continue;
            }

            if(llvm::isa<llvm::StoreInst>(user) || llvm::isa<llvm::AtomicRMWInst>(user) || llvm::isa<llvm::AtomicCmpXchgInst>(user)){
                found_one_store = 1;
            }

            if(!llvmmod){
                // cout << "[DEBUG 0] No LLVM module found, skipping..." << endl;
                continue;
            }
            // else{
            //     // cout << "No prob with LLVM module" << endl;
            // }
            inst = llvm_inst;
            // cout << "inst str: " << inst->toString() << endl;

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
            // cout << "Pushed the instruction: " << inst->toString() << " to the uses of global vector" << endl;
        }
        
        // // cout << "[DEBUG 0] no. of threads executing the instruction: " << threadIDs.size() << endl;
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
            inline const CxtThreadStmtSet& getThreadStmtSet(const Instruction* inst) const
            {
                InstToThreadStmtSetMap::const_iterator it = instToTSMap.find(inst);
                assert(it!=instToTSMap.end() && "no thread access the instruction?");
                return it->second;
            }
            
            I can use this func to get a CxtThreadStmtSet and then iterate through the thread stmt and then get interleaving threads

            To Get interleaving thread for statement inst:
            const NodeBS & 	getInterleavingThreads (const CxtThreadStmt &cts)

            */
            // cout << "Checking if the instruction: " << uses_of_global[i]->toString() << " may be executed by multiple threads in parallel" << endl;
            // const SVF::MHP::CxtThreadStmtSet& threadStmtSet = mhp -> getThreadStmtSet(uses_of_global[i]);
            // // cout << "Found thread stmt set of size " << threadStmtSet.size() << " for instruction: " << uses_of_global[i]->toString() << endl;
            // for(auto threadStmt: threadStmtSet){
            //     const NodeBS& interleavingThreads = mhp -> getInterleavingThreads(threadStmt);
            //     for(auto t:interleavingThreads){
            //         // cout << "Thread " << t << " may interleave with the thread executing the instruction: " << uses_of_global[i]->toString() << endl;
            //     }
            // }
            if (llvmmod->hasICFGNode(uses_of_global[i])) {
                const ICFGNode* n1 = llvmmod->getICFGNode(uses_of_global[i]);
                const MHP::CxtThreadStmtSet& threadStmtSet = mhp -> getThreadStmtSet(n1);
                // // cout << "Found thread stmt set of size " << threadStmtSet.size() << " for instruction: " << instToStr(uses_of_global[i]) << endl;
                
                if(mhp -> mayHappenInParallel(n1, n1)){
                    //mark the location as shared only if there is atleast one user which is a store instruction
                    // if(found_one_store){
                        shared = true;
                        // cout << "[DEBUG 0] Different instances of the same instruction may happen in parallel: " << instToStr(uses_of_global[i]) << " and " << endl;
                        break;
                    // }
                }
            }
            if(shared){
                break;
            }
            

            // this is the normal case - checking other uses
            for(size_t j = i + 1; j < uses_of_global.size(); j++){
                if(llvmmod->hasICFGNode(uses_of_global[i]) && llvmmod->hasICFGNode(uses_of_global[j])) {
                    const ICFGNode* n1 = llvmmod->getICFGNode(uses_of_global[i]);
                    const ICFGNode* n2 = llvmmod->getICFGNode(uses_of_global[j]);
                    if(mhp -> mayHappenInParallel(n1, n2)){
                        //mark the location as shared only if there is atleast one user which is a store instruction
                        // if(found_one_store){
                            shared = true;
                            // cout << "[DEBUG 0] Found a pair of instructions that may happen in parallel: " << instToStr(uses_of_global[i]) << " and " << instToStr(uses_of_global[j]) << endl;
                            break;
                        // }
                    }
                }
                if(shared){
                    break;
                }
            }
            if(shared){
                break;
            }
        }

        if(shared){
            const SVF::SVFValue* location_addr = nullptr;
            std::string var_name = "unknown";

            for(auto inst: uses_of_global){
                std::string inst_str = instToStr(inst);

                const Value* llvmVal = inst;
                const Value* ptr = nullptr;
                
                if (const auto* LI = dyn_cast<LoadInst>(llvmVal)) ptr = LI->getPointerOperand();
                else if (const auto* SI = dyn_cast<StoreInst>(llvmVal)) ptr = SI->getPointerOperand();
                // Do NOT treat arbitrary call first-arguments as memory accesses (e.g., printf @.str).
                // If specific call patterns need recognition (memcpy/memset/store wrappers), add
                // explicit checks for the callee here instead of using the generic CallInst case.

                if (ptr) {
                    ptr = ptr->stripPointerCasts();
                    
                    const Instruction* ptr_inst = nullptr;
                    if (const auto* llvm_ptr_inst = dyn_cast<Instruction>(ptr)){
                        ptr_inst = llvm_ptr_inst;
                    }

                    if (const auto* GV = dyn_cast<GlobalVariable>(ptr)){
                        var_name = GV->getName().str();

                        location_addr = pag->getGNode(llvmmod->getObjectNode(GV));
                        // cout << "[line 1242]pointer to shared loc (addr): " << location_addr << endl;
                        
                    }else{
                        if(ptr_inst){
                            auto locs = get_locations_pointed_to(pag, ptr_inst);
                            for (auto const& loc : locs) {
                                if (loc.second != nullptr && loc.first != "unknown") {
                                    var_name = loc.first;
                                    location_addr = loc.second;
                                    break;
                                }
                            }
                        }
                    }
                }

                // cout << "[DEBUG 1] location identified: " << location_addr << ", name: " << var_name << endl;
                if(var_name != "unknown" && location_addr != nullptr){
                    shared_vars.insert({location_addr, var_name});
                    // cout << "[DEBUG 0] Found a shared global variable: " << location_addr << ", name: " << var_name << endl;
                    break;
                }
            }

            // Only create event if we found a valid memory access (not a call instruction parameter)
            const auto global_inst = dyn_cast<GlobalVariable>(val); 
            if(global_inst && var_name != "unknown" && location_addr != nullptr){
                llvm::StringRef var_name = global_inst->getName();
                std::string name = var_name.str();
                // cout << "[DEBUG 4] global var name: " << name << endl;

                std::string eventID = "e" + std::to_string(eventCounter++);
                // since global variable access is not within any function context, creating an empty call string context for it
                const CallStrCxt empty_cxt; 
                instToEventID[make_tuple(inst, empty_cxt, location_addr)] = eventID;

                event_info* info = new event_info(eventID, "0", "W", location_addr, name, "NA", std::make_pair(inst, empty_cxt), true);

                threadEvents["0"].push_back(info);

                // Printing the instruction and its extracted info for debugging
                // cout << "[DEBUG]Instruction: " << (*global_it)->toString()  << endl;
                // cout << "[DEBUG]Info: eventID: " << eventID << ", TID: " <<
                // "0" << ", " << "W" << ", loc: " << name << ", access_mode: " << "NA" << endl;
                
                // Create CF edge from previous instruction to the current instruction within the bb

                if (prevInst.size() > 0)
                {
                    // cout << "[CF " << prevInst << " " << eventID << "] **Adding to CF edges in identify_shared_global_variables**" << endl;
                    // cout << "From (" << prevInst << ") --> " << "To (" << gv.getName().str() << ")" << endl;
                    cfEdges_map[prevInst].insert(eventID);
                }
                prevInst = eventID;
            }
        }
    }
}
}

void identify_shared_variables(
    SVFIR* pag,
    PointerAnalysis* pta,
    MHP* mhp)
{
    // Pointers
    get_points_to_info(pag, pta);

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
                    // cout << "[SHARED-CANDIDATE] PAG nodes " << var
                            //   << " and " << other_pair.first
                            //   << " point to MemObj " << points_to_node
                            //   << " and may be shared across threads."
                            //   << std::endl;
                    print_thread_ids_for_pag_node(var, pag, mhp);
                    print_thread_ids_for_pag_node(other_pair.first, pag, mhp);

                    //adding the corresponding variable to the set of shared variables
                    const BaseObjVar* baseobj = pag->getBaseObject(points_to_node);
                    if (baseobj && !baseobj->isFunction()){
                        if (llvmmod->hasLLVMValue(baseobj)) {
                            std::string inst = baseobj->toString();
                            // cout << "[DEBUG] Shared variable instruction: " << inst << endl;
                        }
                        std::string var_name;
                        const SVF::SVFValue* location_addr = nullptr;
                        if (llvmmod->hasLLVMValue(baseobj)) {
                            const SVFValue* val = baseobj;
                            var_name = llvmmod -> getLLVMValue(val) -> getName().str();
                            location_addr = val;

                            shared_vars.insert({location_addr, var_name});
                            // cout << "[DEBUG 0] Found a shared variable: " << var_name << endl;
                        }
                        // cout << "location_addr is: " << location_addr << endl;
                    }
                }
            }
        }
    }

    //global variables
    identify_shared_global_variables(pag, mhp);
}

void add_cf_for_forked_threads(TCT* tct){
    for(auto inst_thread: forked_threads){
        std::vector<std::string> from_event_ids = get_event_ids(inst_thread.prev_inst, inst_thread.prev_inst_cxt);
        if (from_event_ids.empty()){
            continue;
        }

        CallStrCxt c = inst_thread.new_cxt;
        CxtThread cs = CxtThread(c, llvmmod->getICFGNode(inst_thread.inst));

        if(tct->hasTCTNode(cs)){
            TCTNode* node = tct->getTCTNode(cs);
            NodeID threadID = node->getId();
            std::string threadIDStr = std::to_string(threadID);
            
            auto events_vector = threadEvents.find(threadIDStr);
            if (events_vector == threadEvents.end() || events_vector->second.empty() || events_vector->second[0] == nullptr){
                continue;
            }
            
            const Instruction* first_inst = events_vector->second[0]->inst_cxt.first;
            const CallStrCxt first_cxt = events_vector->second[0]->inst_cxt.second;
            std::vector<std::string> to_event_ids = get_event_ids(first_inst, first_cxt);

            for (auto const& from_event_id : from_event_ids) {
                for (auto const& to_event_id : to_event_ids) {
                    cfEdges_map[from_event_id].insert(to_event_id);
                }
            }
        }
    }
}


void print_all_event_ids(){
    for(auto const& a : instToEventID){
        auto call_string_cxt = std::get<1>(a.first);
        print_call_context(call_string_cxt);
    }
}


bool check_path_in_icfg(ICFG* icfg, const Instruction* from_inst, const Instruction* to_inst){
    // just performing a dfs starting from the from_inst node
    if (!from_inst || !to_inst || !llvmmod->hasICFGNode(from_inst) || !llvmmod->hasICFGNode(to_inst)) {
        return false;
    }
    ICFGNode* from_node = llvmmod->getICFGNode(from_inst);
    ICFGNode* to_node = llvmmod->getICFGNode(to_inst);

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
            // I need the Instruction* corresponding to these event ids so that I can get their parent basic blocks and check for an edge between those basic blocks in the CFG
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
                const Instruction* from_inst = from_event_info->inst_cxt.first;
                const CallStrCxt from_cxt = from_event_info->inst_cxt.second;
                const Instruction* to_inst = to_event_info->inst_cxt.first;
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
                    outputFile << "[?] Edge from global event to main thread's event \n\n";
                    continue;
                }
                if(from_event_info->threadID == "0" && to_event_info->threadID == "0" && from_event_info->is_global && to_event_info->is_global){
                    outputFile << "[?] Edge btwn global events - these may not be included in the ICFG \n\n";
                    continue;
                }

                outputFile << "**[UNSOUND!]** No corresponding path in the ICFG\n\n";
                
                // display teh event info
                outputFile << "From event info: event id: " << from_event_info->event_id << ", thread id: " << from_event_info->threadID << ", kind: " << from_event_info->kind << ", location: " << from_event_info->location_addr << ", access mode: " << from_event_info->access_mode << "\n";
                outputFile << "From instruction: " << instToStr(from_inst) << "\n";
                outputFile << "To event info: event id: " << to_event_info->event_id << ", thread id: " << to_event_info->threadID << ", kind: " << to_event_info->kind << ", location: " << to_event_info->location_addr << ", access mode: " << to_event_info->access_mode << "\n";
                outputFile << "To instruction: " << instToStr(to_inst) << "\n";
            }else{
                outputFile << "Could not find event info for events: " << from_event_id << " or " << to_event_id << "\n";
            }
        }
    }
}

bool check_in_instToEventID_map(const Instruction* inst){
    for(auto& inst_eventid:instToEventID){
        if(std::get<0>(inst_eventid.first) == inst){
            return true;
        }
    }
    return false;
}

//Helper func for completeness_check
bool is_shared_inst(ICFGNode* node){
    if (!node) return false;
    if (llvmmod->hasLLVMValue(node)) {
        if (const Instruction* inst = dyn_cast<Instruction>(llvmmod->getLLVMValue(node))) {
            return check_in_instToEventID_map(inst);
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
    if (llvmmod->hasLLVMValue(node)) {
        if (const Instruction* inst = dyn_cast<Instruction>(llvmmod->getLLVMValue(node))) {
            for (const auto& t : threadEvents){
                for (const auto& event_info_i : t.second){
                    if(event_info_i && event_info_i->inst_cxt.first == inst){
                        ei_vec.push_back(event_info_i);
                    }
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
            // cout << "Checking for the corresponding edge in ccfg: FROM: " << from_event_id << ", TO: "; 
            for(auto id:cfEdges_map[from_event_id]){
                for(auto& to_ei: to_event){
                    if(to_ei){
                        to_event_id = to_ei->event_id;
                        // cout << to_event_id << ", ";
                    }
                    if(id == to_event_id){
                        //there is a corresponding edge in the ccfg
                        //so, simply returning
                        return;
                    }
                }
                // cout << endl;
            }
        }
    }
    
    outputFile << "\n[Edge " << ++missing_edges_count << "]Expected edge btwn one of these: " << endl;
    // cout << "\n[Edge " << missing_edges_count << "]Expected edge btwn one of these: " << endl;
    
    // // cout << "\n[Edge " << missing_edges_count << "]Expected edge btwn one of these: " << endl;
    for(auto from:from_event){
        for(auto to:to_event){
            // cout << "From event id: " << from->event_id << ", thread id: " << from->threadID << ", kind: " << from->kind << ", location: " << from->var_name << ", addr = " << from->location_addr << ", access mode: " << from->access_mode << endl;
            // cout << "To event id: " << to->event_id << ", thread id: " << to->threadID << ", kind: " << to->kind << ", location: " << to->var_name << ", addr = " << to->location_addr << ", access mode: " << to->access_mode << endl;

            outputFile << "[FROM] Event id: " << from->event_id << ", thread id: " << from->threadID << ", kind: " << from->kind << ", location: " << from->var_name << ", addr = " << from->location_addr << ", access mode: " << from->access_mode << "\n";
            outputFile << "[TO]Event id: " << to->event_id << ", thread id: " << to->threadID << ", kind: " << to->kind << ", location: " << to->var_name << ", addr = " << to->location_addr << ", access mode: " << to->access_mode << "\n";
            
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
                    // cout << "Stepped into wrong context - skipping this successor node" << endl;
                    continue;
                }
            }
            
            ICFGNode* new_shared_inst = prev_shared_inst;

            if(is_shared_inst(succ)){
                new_shared_inst = succ;

                // COMPLETENESS CHECK - check if there is an edge from prev_shared_inst to new_shared_inst
                if(prev_shared_inst && new_shared_inst){
                    // cout << "[COMPLETENESS CHECK] Checking edge in ccfg for edge from [" << prev_shared_inst->getId() << "]:"<< prev_shared_inst->toString() << " to [" << new_shared_inst->getId() << "]:" << new_shared_inst->toString() << endl;
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
    std::vector<std::string> moduleNameVec;
    moduleNameVec = OptionBase::parseOptions(
        argc, argv, "Static Generation of Concurrent Control Flow Graph",
        "[options] <input-bitcode...>");

    LLVMModuleSet::buildSVFModule(moduleNameVec);

    // Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();

    /* Extract events in .pg format */
    MTA* mta = new MTA();
    mta->runOnModule(pag);

    // Getting Thread Creation Tree (TCT) from MHP anal
    MHP* mhp = mta->getMHP();
    mhp_global = mhp;
    TCT* tct = mhp->getTCT();

    AndersenWaveDiff* pta = AndersenWaveDiff::createAndersenWaveDiff(pag);

    // pta->analyze(); // Already analyzed inside MTA
    // fsmpta->dumpAllPts();

    pta->writeObjVarToFile("pts_to_info.txt");
    pta->writeToFile("pts_to_info.txt");

    identify_shared_variables(pag, pta, mhp);

    // Iterate through all threads
    for (auto it = tct->begin(); it != tct->end(); ++it){
        process_thread(pag, tct, it);
    }
    add_cf_for_forked_threads(tct);
    add_cf_for_joined_threads();
    generate_conflict_report();

    print_all_event_ids();
    // SOUNDNESS CHECK: While creating an edge in our graph, I want to be sure that there exists an edge at basic block level between the parent bbs of these shared instructions
    ICFG* icfg = pag->getICFG();
    CallGraph* callgraph = pta->getCallGraph();

    builder.updateCallGraph(callgraph);
    icfg->updateCallGraph(callgraph);

    soundness_check_added_edges(icfg);
    completeness_check(icfg);
    write_to_file();

    LLVMModuleSet::releaseLLVMModuleSet();
    return 0;
}
