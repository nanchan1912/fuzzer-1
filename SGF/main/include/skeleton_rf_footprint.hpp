#ifndef SKELETON_RF_FOOTPRINT_HPP
#define SKELETON_RF_FOOTPRINT_HPP

#include <stdint.h>
#include <stdbool.h>

#include "sgf-fuzz.h"

#ifdef __cplusplus
#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "skeleton_graph_mutator_wrapper.h"

// RF-Footprint C API
int update_rf_footprint(EventTriple write_event, EventTriple read_event);
void update_rf_footprint_for_graph(SkeletonGraph* graph);
uint32_t get_rf_footprint_coverage_count(void);
void print_rf_edge_frequencies(void);
uint32_t get_rf_footprint_edge_freq(EventTriple write_event, EventTriple read_event);
uint32_t get_sum_rf_frequencies_for_read(EventTriple read_event);
double skeleton_graph_rf_footprint_calc(SkeletonGraph* graph);

#ifdef __cplusplus
}
#endif

#endif // SKELETON_RF_FOOTPRINT_HPP
