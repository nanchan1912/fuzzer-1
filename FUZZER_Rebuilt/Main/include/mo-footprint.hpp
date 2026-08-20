#ifndef MO_FOOTPRINT_HPP
#define MO_FOOTPRINT_HPP

extern "C"{
    #include "sgf-fuzz.h"
    #include "skeleton_graph_mutator_wrapper.h"    
}

#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"

u32 skeleton_graph_mo_footprint_calc(SkeletonGraph* graph);


#endif