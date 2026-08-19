/* 
Purpose: To check the diversity of mutations in terms of RF and MO footprints 
Writing this in C so that I can easily integrate it with other parts of the AFL++ codebase calling the functions if necessary
*/


#include "diversity_checker.h"

EventGraphMap* explored_mo_edges = NULL;
EventGraphMap* explored_rf_edges = NULL;

/* Initialize the diversity checker maps - call once at startup */
void diversity_checker_init() {
    if (!explored_mo_edges) {
        explored_mo_edges = event_graph_map_create(256);
    }
    if (!explored_rf_edges) {
        explored_rf_edges = event_graph_map_create(256);
    }
}

/* 
 * Check and update MO edge coverage
 * Takes two event triples representing an MO edge (from_event -> to_event)
 * Returns: 1 if edge is new (coverage improved), 0 if already explored
 */
// int update_mo_coverage(int from_tid, long long from_iid, int from_vid, 
//                        int to_tid, long long to_iid, int to_vid) {
//     if (!explored_mo_edges) {
//         diversity_checker_init();
//     }
    
//     EventTriple from = {from_tid, from_iid, from_vid};
//     EventTriple to = {to_tid, to_iid, to_vid};
    
//     /* Check if edge already exists before incrementing */
//     bool edge_exists = event_graph_map_contains_edge(explored_mo_edges, from, to);
    
//     /* Increment frequency */
//     event_graph_map_increment(explored_mo_edges, from, to);
    
//     return edge_exists ? 0 : 1;  /* Return 1 if new edge, 0 if already explored */
// }

/* 
 * Check and update RF edge coverage
 * Takes two event triples representing an RF edge (write_event -> read_event)
 * Returns: 1 if edge is new (coverage improved), 0 if already explored
 */
int update_rf_coverage(int from_tid, long long from_iid, int from_vid, 
                       int to_tid, long long to_iid, int to_vid) {
    if (!explored_rf_edges) {
        diversity_checker_init();
    }
    
    EventTriple from = {from_tid, from_iid, from_vid};
    EventTriple to = {to_tid, to_iid, to_vid};
    
    /* Check if edge already exists before incrementing */
    bool edge_exists = event_graph_map_contains_edge(explored_rf_edges, from, to);
    
    /* Increment frequency */
    event_graph_map_increment(explored_rf_edges, from, to);
    
    return edge_exists ? 0 : 1;  /* Return 1 if new edge, 0 if already explored */
}

/* 
* Get current MO edge coverage count 
* Returns: number of unique source nodes in the MO graph (actual edge count tracked internally)
*/
// uint32_t get_mo_coverage_count() {
//     if (!explored_mo_edges) return 0;

//     return event_graph_map_edge_count(explored_mo_edges);
// }

/* 
* Get current RF edge coverage count 
* Returns: number of unique source nodes in the RF graph (actual edge count tracked internally)
*/
uint32_t get_rf_coverage_count() {
    if (!explored_rf_edges) return 0;

    return event_graph_map_edge_count(explored_rf_edges);
}

/* 
// * Get the frequency of a specific MO edge by source and destination events
// * Returns: frequency count of the edge, 0 if edge doesn't exist
// */
// uint32_t get_mo_edge_frequency(int from_tid, long long from_iid, int from_vid,
//                                 int to_tid, long long to_iid, int to_vid) {
//     if (!explored_mo_edges) return 0;
    
//     EventTriple from = {from_tid, from_iid, from_vid};
//     EventTriple to = {to_tid, to_iid, to_vid};
    
//     return event_graph_map_get_frequency(explored_mo_edges, from, to);
// }

/* 
* Get the frequency of a specific RF edge by source and destination events
* Returns: frequency count of the edge, 0 if edge doesn't exist
*/
uint32_t get_rf_edge_frequency(int from_tid, long long from_iid, int from_vid,
                                int to_tid, long long to_iid, int to_vid) {
    if (!explored_rf_edges) return 0;
    
    EventTriple from = {from_tid, from_iid, from_vid};
    EventTriple to = {to_tid, to_iid, to_vid};
    
    return event_graph_map_get_frequency(explored_rf_edges, from, to);
}

// /* Iterate over all MO edges with their exploration frequencies */
// void for_each_mo_edge(edge_frequency_iter_fn callback, void* user_data) {
//     if (!explored_mo_edges) return;
//     event_graph_map_for_each(explored_mo_edges, callback, user_data);
// }

/* Iterate over all RF edges with their exploration frequencies */
void for_each_rf_edge(edge_frequency_iter_fn callback, void* user_data) {
    if (!explored_rf_edges) return;
    event_graph_map_for_each(explored_rf_edges, callback, user_data);
}

/* Clear all tracked coverage */
void diversity_checker_clear() {
    if (explored_mo_edges) {
        event_graph_map_clear(explored_mo_edges);
    }
    if (explored_rf_edges) {
        event_graph_map_clear(explored_rf_edges);
    }
}

/* Cleanup - call at program exit */
void diversity_checker_destroy() {
    if (explored_mo_edges) {
        event_graph_map_destroy(explored_mo_edges);
        explored_mo_edges = NULL;
    }
    if (explored_rf_edges) {
        event_graph_map_destroy(explored_rf_edges);
        explored_rf_edges = NULL;
    }
}