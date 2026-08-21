#ifndef ANAL_H
#define ANAL_H

#include "SVFIR/SVFIR.h"
#include <SVF-LLVM/LLVMModule.h>
#include <SVF-LLVM/LLVMUtil.h>

#include <SVF-LLVM/SVFIRBuilder.h>
#include "MTA/MTA.h"
#include "MTA/MHP.h"
#include "MTA/MTA.h"
#include "MTA/TCT.h"
#include "Util/Options.h"
#include "WPA/Andersen.h"

#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

typedef std::pair<const SVF::Instruction*, SVF::CallStrCxt> inst_cxt_pair;
// Helper func for process_instructions
std::string get_access_mode(std::string llvmInstruction);

void print_call_context(const SVF::CallStrCxt& cs_cxt);

std::pair<SVF::Instruction*, SVF::CallStrCxt> check_inst(SVF::SVFIR* pag,
							SVF::TCT* tct,
							const SVF::Instruction* inst, 
							const SVF::CallStrCxt cs_cxt, 
							SVF::Instruction* prevInst, 
							SVF::CallStrCxt prevInst_cxt,
							std::string threadIDStr);

std::vector<std::pair<SVF::Instruction*, SVF::CallStrCxt>> check_call_inst(SVF::SVFIR* pag,
							SVF::TCT* tct,
							const SVF::Instruction* inst, 
							const SVF::CallStrCxt cs_cxt, 
							SVF::Instruction* prevInst, 
							SVF::CallStrCxt prevInst_cxt,
							std::string threadIDStr);

std::vector<std::pair<SVF::Instruction*, SVF::CallStrCxt>> extract_insts_and_edges(SVF::SVFIR* pag,
											 SVF::TCT* tct,
											 const SVF::FunObjVar* func,
											 SVF::Instruction* prevInstOfFunc,
											 const SVF::CallStrCxt prevInstofFunc_cxt,
											 const SVF::CallStrCxt cs_cxt,
											 std::string threadIDStr);

void analyze_func(SVF::SVFIR* pag,
				  const SVF::FunObjVar* func,
				  SVF::TCTNode* threadNode,
				  SVF::TCT* tct,
				  const SVF::CallStrCxt cs_cxt,
				  SVF::Instruction* prevInst,
				  const SVF::CallStrCxt prevInst_cxt);

void write_to_thread_events(const SVF::Instruction* inst,
							const SVF::CallStrCxt cs_cxt,
							std::string threadIDStr,
							const SVF::SVFValue* location_addr,
							std::string var_name,
							std::string instStr,
							std::string kind,
							std::string access_mode);

std::vector<std::pair<std::string, const SVF::SVFValue*>>  get_locations_pointed_to(SVF::SVFIR* pag,
									const SVF::Instruction* ptr_inst);

// Helper func for process_instructions
void deal_with_fork_inst(const SVF::Instruction* inst,
						 std::string instStr,
						 SVF::TCT* tct,
						 const SVF::ThreadAPI* thread_api,
						 const SVF::CallStrCxt cs_cxt,
						 SVF::Instruction* prev_inst,
						 const SVF::CallStrCxt prev_inst_cxt);

// Write to .pg format file
void write_to_file();

//Called from main on each TCTNode (each thread)- explores the start func and all the basic blocks, instructions in them - adding events and CF edges
void process_thread(SVF::SVFIR* pag, SVF::TCT* tct,
					std::_Rb_tree_iterator<std::pair<const unsigned int, SVF::TCTNode*>> it);

//Helper func to identify shared variables
void get_points_to_info(SVF::SVFIR* pag, SVF::PointerAnalysis* fsmpta);

//Helper func to identify shared variables
std::set<SVF::NodeID> get_thread_ids_for_pag_node(SVF::NodeID pagNodeID,
												  SVF::SVFIR* pag,
												  SVF::MHP* mhp);

//Helper func to identify shared variables
void print_thread_ids_for_pag_node(SVF::NodeID pagNodeID,
								   SVF::SVFIR* pag,
								   SVF::MHP* mhp);

//Helper func to identify shared variables
std::set<SVF::NodeID> get_threads_executing_inst(const SVF::Instruction* inst,
												 SVF::MHP* mhp);

//Helper func to identify shared variables
void identify_shared_global_variables(SVF::SVFIR* pag,
									  SVF::MHP* mhp);

void identify_shared_variables(SVF::SVFIR* pag,
							   SVF::PointerAnalysis* fsmpta,
							   SVF::MHP* mhp);

void add_cf_for_forked_threads(SVF::TCT* tct);

void print_all_event_ids();

#endif
