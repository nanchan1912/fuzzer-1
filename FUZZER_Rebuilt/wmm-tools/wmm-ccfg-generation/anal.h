#ifndef ANAL_H
#define ANAL_H

#include "MTA/MHP.h"
#include "MTA/MTA.h"
#include "MTA/TCT.h"
#include "SVFIR/SVFIR.h"
#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/LLVMUtil.h"

#include "../../svf-llvm/include/SVF-LLVM/SVFIRBuilder.h"
#include "MTA/FSMPTA.h"
#include "Util/Options.h"
#include "WPA/Andersen.h"

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

typedef std::pair<const SVF::SVFInstruction*, SVF::CallStrCxt> inst_cxt_pair;
// Helper func for process_instructions
std::string get_access_mode(std::string llvmInstruction);

void print_call_context(const SVF::CallStrCxt& cs_cxt);

std::vector<std::pair<SVF::SVFInstruction*, SVF::CallStrCxt>> remove_duplicates(std::vector<std::pair<SVF::SVFInstruction*, SVF::CallStrCxt>> last_insts_temp);


std::pair<SVF::SVFInstruction*, SVF::CallStrCxt> check_inst(SVF::SVFIR* pag,
							SVF::TCT* tct,
							const SVF::SVFInstruction* inst, 
							const SVF::CallStrCxt cs_cxt, 
							SVF::SVFInstruction* prevInst, 
							SVF::CallStrCxt prevInst_cxt,
							SVF::CxtThread cxt_thread,
							bool from_a_fork_inst,
							bool join_encountered);

std::pair<std::vector<std::pair<SVF::SVFInstruction*, SVF::CallStrCxt>>, SVF::CxtThread> check_call_inst(SVF::SVFIR* pag,
							SVF::TCT* tct,
							const SVF::SVFInstruction* inst, 
							const SVF::CallStrCxt cs_cxt, 
							SVF::SVFInstruction* prevInst, 
							SVF::CallStrCxt prevInst_cxt,
							SVF::CxtThread cxt_thread,
							bool from_a_fork_inst,
							bool join_encountered);

std::vector<std::pair<SVF::SVFInstruction*, SVF::CallStrCxt>> analyze_func(SVF::SVFIR* pag,
											SVF::TCT* tct,
											const SVF::SVFFunction* func,
											SVF::SVFInstruction* prevInstOfFunc,
											const SVF::CallStrCxt prevInstofFunc_cxt,
											const SVF::CallStrCxt cs_cxt,
											SVF::CxtThread cxt_thread,
											bool from_a_fork_inst,
											bool join_encountered);

// void analyze_func(SVF::SVFIR* pag,
// 				  const SVF::SVFFunction* func,
// 				  SVF::TCTNode* threadNode,
// 				  SVF::TCT* tct,
// 				  const SVF::CallStrCxt cs_cxt,
// 				  SVF::SVFInstruction* prevInst,
// 				  const SVF::CallStrCxt prevInst_cxt);

void write_to_thread_events(const SVF::SVFInstruction* inst,
							const SVF::CallStrCxt cs_cxt,
							SVF::CxtThread cxt_thread,
							const SVF::SVFValue* location_addr,
							std::string field_offset,
							std::string var_name,
							std::string instStr,
							std::string kind,
							std::string access_mode);


std::pair<std::string, std::pair<const SVF::SVFValue*, std::string>> get_location_pointed_to(SVF::SVFIR* pag, const SVF::SVFInstruction* ptr_inst);


// Helper func for process_instructions
void deal_with_fork_inst(const SVF::SVFInstruction* inst,
						std::string instStr,
						SVF::TCT* tct,
						const SVF::ThreadAPI* thread_api,
						const SVF::CallStrCxt cs_cxt,
						SVF::SVFInstruction* prev_inst,
						const SVF::CallStrCxt prev_inst_cxt);

// Write to .pg format file
void write_to_file();

//Called from main on each TCTNode (each thread)- explores the start func and all the basic blocks, instructions in them - adding events and CF edges
void process_thread(SVF::SVFIR* pag, SVF::TCT* tct,
					std::_Rb_tree_iterator<std::pair<const unsigned int, SVF::TCTNode*>> it);

//Helper func to identify shared variables
void get_points_to_info(SVF::SVFIR* pag, SVF::FSMPTA* fsmpta);

//Helper func to identify shared variables
std::set<SVF::NodeID> get_thread_ids_for_pag_node(SVF::NodeID pagNodeID,
												  SVF::SVFIR* pag,
												  SVF::MHP* mhp);

//Helper func to identify shared variables
void print_thread_ids_for_pag_node(SVF::NodeID pagNodeID,
								   SVF::SVFIR* pag,
								   SVF::MHP* mhp);

//Helper func to identify shared variables
std::set<SVF::NodeID> get_threads_executing_inst(const SVF::SVFInstruction* inst,
												 SVF::MHP* mhp);

//Helper func to identify shared variables
void identify_shared_global_variables(SVF::SVFIR* pag,
									  SVF::MHP* mhp,
									  SVF::SVFModule* svfModule);

void identify_shared_variables(SVF::SVFIR* pag,
							   SVF::FSMPTA* fsmpta,
							   SVF::MHP* mhp,
							   SVF::SVFModule* svfModule);

void add_cf_for_forked_threads(SVF::TCT* tct);

void print_all_event_ids();

#endif
