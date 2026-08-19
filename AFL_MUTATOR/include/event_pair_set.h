/*
 * event_pair_set.h - Data structure for storing pairs of events with frequencies
 *
 * Used in diversity checker currently.
 * 
 * This file defines a hash map that maps source event triples to destination event triples,
 * along with the frequency of each edge. It provides functions for inserting edges,
 * querying frequencies, and iterating over all edges.
 *
 * The main data structure is EventGraphMap, which contains a hash map of source nodes
 * (EventTriple) to their corresponding DestinationMap. Each DestinationMap is another
 * hash map that maps destination EventTriples to their frequencies.
 *
 * This implementation uses open addressing with linear probing for collision resolution.
 */

#ifndef EVENT_PAIR_SET_H
#define EVENT_PAIR_SET_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Event triple: (thread_id, instruction_id, visit_id) */
typedef struct {
    int thread_id;
    long long instruction_id;
    int visit_id;
} EventTriple;

/* Hash entry for destination map (EventTriple -> frequency) */
typedef struct {
    EventTriple destination;
    uint32_t frequency;
    bool occupied;
    bool deleted;
} DestinationEntry;

/* Destination map for a single source node */
typedef struct {
    DestinationEntry* entries;
    uint32_t capacity;
    uint32_t size;
    uint32_t load_factor_threshold;
} DestinationMap;

/* Hash entry for the main event map (source EventTriple -> DestinationMap) */
typedef struct {
    EventTriple source;
    DestinationMap* dest_map;
    bool occupied;
    bool deleted;
} SourceMapEntry;

/* Main event graph map: maps source nodes to their destination maps */
typedef struct {
    SourceMapEntry* entries;
    uint32_t capacity;
    uint32_t size;
    uint32_t load_factor_threshold;
} EventGraphMap;

/* Callback for iterating edges with frequencies */
typedef void (*edge_frequency_iter_fn)(EventTriple from,
                                       EventTriple to,
                                       uint32_t frequency,
                                       void* user_data);

/* ============================================================
 *  EventGraphMap Function Prototypes
 * ============================================================ */

/* Hash function for EventTriple */
uint32_t hash_event_triple(EventTriple triple, uint32_t capacity);

/* Compare two EventTriples for equality */
bool event_triple_equal(EventTriple a, EventTriple b);

/* Create a new EventGraphMap with initial capacity */
EventGraphMap* event_graph_map_create(uint32_t initial_capacity);

/* Destroy an EventGraphMap and free all memory */
void event_graph_map_destroy(EventGraphMap* map);

/* Insert or increment an edge in the map. Returns the new frequency */
uint32_t event_graph_map_increment(EventGraphMap* map, EventTriple from, EventTriple to);

/* Check if an edge exists in the map and get its frequency. Returns 0 if not found */
uint32_t event_graph_map_get_frequency(EventGraphMap* map, EventTriple from, EventTriple to);

/* Check if an edge exists in the map (true if edge exists, false otherwise) */
bool event_graph_map_contains_edge(EventGraphMap* map, EventTriple from, EventTriple to);

/* Get the number of unique source nodes in the map */
uint32_t event_graph_map_source_count(EventGraphMap* map);

/* Get the total number of edges in the map */
uint32_t event_graph_map_edge_count(EventGraphMap* map);

/* Iterate over all edges with their frequencies */
void event_graph_map_for_each(EventGraphMap* map,
                              edge_frequency_iter_fn callback,
                              void* user_data);

/* Clear all elements from the map */
void event_graph_map_clear(EventGraphMap* map);



#ifdef __cplusplus
}
#endif

#endif /* EVENT_PAIR_SET_H */