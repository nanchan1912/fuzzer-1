#ifndef SKELETON_GRAPH_MUTATOR_HPP
#define SKELETON_GRAPH_MUTATOR_HPP

#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#include "skeleton_graph_mutator_wrapper.h"

#include <vector>
#include <map>
#include <set>
#include "json.hpp"                 // for JSON parsing (downloaded from nlohmann/json)

using json = nlohmann::json;

void parse_program_abstraction_file(const char* filename);

// MO-guided thread bias functions
void add_mo_thread_bias(ThreadID tid, int k);
uint64_t get_mo_thread_weight(ThreadID tid);
void record_mo_thread_bias(const SkeletonGraph* graph, const Event* earlier_event, const Event* current_event);
void reset_mo_thread_bias();

#endif // SKELETON_GRAPH_MUTATOR_HPP
