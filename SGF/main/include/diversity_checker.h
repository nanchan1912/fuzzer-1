#ifndef DIVERSITY_CHECKER_H
#define DIVERSITY_CHECKER_H

#include <stdint.h>
#include "event_pair_set.h"

/* The main event graph maps for MO and RF edges */
/* Each map uses structure: {source_node: {dest_node: frequency, ...}, ...} */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 *  Function Prototypes
 * ============================================================ */

/* Initialize the diversity checker maps - call once at startup */
extern void diversity_checker_init();

/* 
 * Check and update MO edge coverage
 * Takes two event triples representing an MO edge (from_event -> to_event)
 * Returns: 1 if edge is new (coverage improved), 0 if already explored
 */
// extern int update_mo_coverage(int from_tid, long long from_iid, int from_vid, 
//                        int to_tid, long long to_iid, int to_vid);


/* 
 * Check and update RF edge coverage
 * Takes two event triples representing an RF edge (write_event -> read_event)
 * Returns: 1 if edge is new (coverage improved), 0 if already explored
 */
extern int update_rf_coverage(int from_tid, long long from_iid, int from_vid, 
                       int to_tid, long long to_iid, int to_vid);

/* Get current MO edge coverage count */
// extern uint32_t get_mo_coverage_count();

/* Get current RF edge coverage count */
extern uint32_t get_rf_coverage_count();

/* Get the frequency of a specific MO edge by source and destination events */
// extern uint32_t get_mo_edge_frequency(int from_tid, long long from_iid, int from_vid,
                                    //    int to_tid, long long to_iid, int to_vid);

/* Get the frequency of a specific RF edge by source and destination events */
extern uint32_t get_rf_edge_frequency(int from_tid, long long from_iid, int from_vid,
                                       int to_tid, long long to_iid, int to_vid);

/* Iterate over all MO edges with their exploration frequencies */
// extern void for_each_mo_edge(edge_frequency_iter_fn callback, void* user_data);

/* Iterate over all RF edges with their exploration frequencies */
extern void for_each_rf_edge(edge_frequency_iter_fn callback, void* user_data);

/* Clear all tracked coverage */
extern void diversity_checker_clear();

/* Cleanup - call at program exit */
extern void diversity_checker_destroy();

#ifdef __cplusplus
}
#endif

#endif /* DIVERSITY_CHECKER_H */