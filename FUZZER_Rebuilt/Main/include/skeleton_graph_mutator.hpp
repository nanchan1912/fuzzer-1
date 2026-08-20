extern "C"{
    #include "sgf-fuzz.h"
    #include "skeleton_graph_mutator_wrapper.h"    
}

#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#include <algorithm>                // including this for std::copy
#include <fstream>
#include "json.hpp"                 // for JSON parsing (downloaded from nlohmann/json)

using json = nlohmann::json;

void parse_program_abstraction_file(const char* filename);


//mo-footprint related functions
int update_mo_coverage(EventTriple from_event_id, EventTriple to_event_id);
void update_mo_coverage_for_graph(SkeletonGraph* graph);
uint32_t get_mo_coverage_count();
void print_mo_edge_frequencies();
const uint32_t get_mo_edge_freq(EventTriple from_event_id, EventTriple to_event_id);
