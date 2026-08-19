#include "event_pair_set.h"

/* Hash function for EventTriple */
uint32_t hash_event_triple(EventTriple triple, uint32_t capacity) {
    uint32_t h = 5381;
    uint64_t iid = (uint64_t)triple.instruction_id;
    h = ((h << 5) + h) ^ triple.thread_id;
    h = ((h << 5) + h) ^ (uint32_t)(iid & 0xffffffffu);
    h = ((h << 5) + h) ^ (uint32_t)(iid >> 32);
    h = ((h << 5) + h) ^ triple.visit_id;
    return h % capacity;
}

/* Compare two EventTriples for equality */
bool event_triple_equal(EventTriple a, EventTriple b) {
    return a.thread_id == b.thread_id && 
           a.instruction_id == b.instruction_id && 
           a.visit_id == b.visit_id;
}

/* ============================================================
 *  DestinationMap Functions (internal)
 * ============================================================ */

/* Create a destination map for a single source node */
static DestinationMap* destination_map_create(uint32_t initial_capacity) {
    if (initial_capacity < 16) initial_capacity = 16;
    
    DestinationMap* dmap = (DestinationMap*)malloc(sizeof(DestinationMap));
    if (!dmap) return NULL;
    
    dmap->entries = (DestinationEntry*)calloc(initial_capacity, sizeof(DestinationEntry));
    if (!dmap->entries) {
        free(dmap);
        return NULL;
    }
    
    dmap->capacity = initial_capacity;
    dmap->size = 0;
    dmap->load_factor_threshold = 75;
    
    return dmap;
}

/* Destroy a destination map */
static void destination_map_destroy(DestinationMap* dmap) {
    if (!dmap) return;
    free(dmap->entries);
    free(dmap);
}

/* Resize a destination map */
static bool destination_map_resize(DestinationMap* dmap, uint32_t new_capacity) {
    DestinationEntry* old_entries = dmap->entries;
    uint32_t old_capacity = dmap->capacity;
    
    dmap->entries = (DestinationEntry*)calloc(new_capacity, sizeof(DestinationEntry));
    if (!dmap->entries) {
        dmap->entries = old_entries;
        return false;
    }
    
    dmap->capacity = new_capacity;
    dmap->size = 0;
    
    /* Reinsert all old entries */
    for (uint32_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].occupied && !old_entries[i].deleted) {
            uint32_t idx = hash_event_triple(old_entries[i].destination, new_capacity);
            uint32_t start_idx = idx;
            
            while (dmap->entries[idx].occupied && !dmap->entries[idx].deleted) {
                idx = (idx + 1) % new_capacity;
                if (idx == start_idx) break;
            }
            
            dmap->entries[idx] = old_entries[i];
            dmap->entries[idx].occupied = true;
            dmap->entries[idx].deleted = false;
            dmap->size++;
        }
    }
    
    free(old_entries);
    return true;
}

/* Increment or insert a destination in the map */
static uint32_t destination_map_increment(DestinationMap* dmap, EventTriple destination) {
    if (!dmap) return 0;
    
    /* Check if resize needed */
    if (dmap->size * 100 >= dmap->capacity * dmap->load_factor_threshold) {
        destination_map_resize(dmap, dmap->capacity * 2);
    }
    
    uint32_t idx = hash_event_triple(destination, dmap->capacity);
    uint32_t start_idx = idx;
    
    while (true) {
        if (!dmap->entries[idx].occupied || dmap->entries[idx].deleted) {
            dmap->entries[idx].destination = destination;
            dmap->entries[idx].frequency = 1;
            dmap->entries[idx].occupied = true;
            dmap->entries[idx].deleted = false;
            dmap->size++;
            return 1;
        }
        
        if (event_triple_equal(dmap->entries[idx].destination, destination)) {
            dmap->entries[idx].frequency++;
            return dmap->entries[idx].frequency;
        }
        
        idx = (idx + 1) % dmap->capacity;
        if (idx == start_idx) {
            return 0;  /* Table is full */
        }
    }
}

/* Get frequency of a destination in the map */
static uint32_t destination_map_get_frequency(DestinationMap* dmap, EventTriple destination) {
    if (!dmap || dmap->size == 0) return 0;
    
    uint32_t idx = hash_event_triple(destination, dmap->capacity);
    uint32_t start_idx = idx;
    
    while (true) {
        if (!dmap->entries[idx].occupied) {
            return 0;
        }
        
        if (!dmap->entries[idx].deleted && 
            event_triple_equal(dmap->entries[idx].destination, destination)) {
            return dmap->entries[idx].frequency;
        }
        
        idx = (idx + 1) % dmap->capacity;
        if (idx == start_idx) {
            return 0;
        }
    }
}

/* Clear a destination map */
static void destination_map_clear(DestinationMap* dmap) {
    if (!dmap) return;
    memset(dmap->entries, 0, dmap->capacity * sizeof(DestinationEntry));
    dmap->size = 0;
}


/* ============================================================
 *  EventGraphMap Functions
 * ============================================================ */

/* Create a new EventGraphMap with initial capacity */
EventGraphMap* event_graph_map_create(uint32_t initial_capacity) {
    if (initial_capacity < 16) initial_capacity = 16;
    
    EventGraphMap* map = (EventGraphMap*)malloc(sizeof(EventGraphMap));
    if (!map) return NULL;
    
    map->entries = (SourceMapEntry*)calloc(initial_capacity, sizeof(SourceMapEntry));
    if (!map->entries) {
        free(map);
        return NULL;
    }
    
    map->capacity = initial_capacity;
    map->size = 0;
    map->load_factor_threshold = 75;
    
    return map;
}

/* Destroy an EventGraphMap and free all memory */
void event_graph_map_destroy(EventGraphMap* map) {
    if (!map) return;
    
    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied && !map->entries[i].deleted) {
            destination_map_destroy(map->entries[i].dest_map);
        }
    }
    
    free(map->entries);
    free(map);
}

/* Internal function to resize the main map */
static bool event_graph_map_resize(EventGraphMap* map, uint32_t new_capacity) {
    SourceMapEntry* old_entries = map->entries;
    uint32_t old_capacity = map->capacity;
    
    map->entries = (SourceMapEntry*)calloc(new_capacity, sizeof(SourceMapEntry));
    if (!map->entries) {
        map->entries = old_entries;
        return false;
    }
    
    map->capacity = new_capacity;
    map->size = 0;
    
    /* Reinsert all old entries */
    for (uint32_t i = 0; i < old_capacity; i++) {
        if (old_entries[i].occupied && !old_entries[i].deleted) {
            uint32_t idx = hash_event_triple(old_entries[i].source, new_capacity);
            uint32_t start_idx = idx;
            
            while (map->entries[idx].occupied && !map->entries[idx].deleted) {
                idx = (idx + 1) % new_capacity;
                if (idx == start_idx) break;
            }
            
            map->entries[idx].source = old_entries[i].source;
            map->entries[idx].dest_map = old_entries[i].dest_map;
            map->entries[idx].occupied = true;
            map->entries[idx].deleted = false;
            map->size++;
        }
    }
    
    free(old_entries);
    return true;
}

/* Find a source node's entry in the map, or return NULL if not found */
static SourceMapEntry* event_graph_map_find_source(EventGraphMap* map, EventTriple source) {
    if (!map || map->size == 0) return NULL;
    
    uint32_t idx = hash_event_triple(source, map->capacity);
    uint32_t start_idx = idx;
    
    while (true) {
        if (!map->entries[idx].occupied) {
            return NULL;
        }
        
        if (!map->entries[idx].deleted && 
            event_triple_equal(map->entries[idx].source, source)) {
            return &map->entries[idx];
        }
        
        idx = (idx + 1) % map->capacity;
        if (idx == start_idx) {
            return NULL;
        }
    }
}

/* Insert or increment an edge in the map. Returns the new frequency */
uint32_t event_graph_map_increment(EventGraphMap* map, EventTriple from, EventTriple to) {
    if (!map) return 0;
    
    /* Check if resize needed */
    if (map->size * 100 >= map->capacity * map->load_factor_threshold) {
        event_graph_map_resize(map, map->capacity * 2);
    }
    
    /* Find or create the source entry */
    SourceMapEntry* source_entry = event_graph_map_find_source(map, from);
    
    if (!source_entry) {
        /* Need to create a new source entry */
        uint32_t idx = hash_event_triple(from, map->capacity);
        uint32_t start_idx = idx;
        
        while (map->entries[idx].occupied && !map->entries[idx].deleted) {
            idx = (idx + 1) % map->capacity;
            if (idx == start_idx) {
                return 0;  /* Table is full */
            }
        }
        
        map->entries[idx].source = from;
        map->entries[idx].dest_map = destination_map_create(16);
        if (!map->entries[idx].dest_map) return 0;
        map->entries[idx].occupied = true;
        map->entries[idx].deleted = false;
        map->size++;
        source_entry = &map->entries[idx];
    }
    
    /* Now increment the destination in the source's map */
    return destination_map_increment(source_entry->dest_map, to);
}

/* Check if an edge exists in the map and get its frequency. Returns 0 if not found */
uint32_t event_graph_map_get_frequency(EventGraphMap* map, EventTriple from, EventTriple to) {
    if (!map) return 0;
    
    SourceMapEntry* source_entry = event_graph_map_find_source(map, from);
    if (!source_entry) return 0;
    
    return destination_map_get_frequency(source_entry->dest_map, to);
}

/* Check if an edge exists in the map (true if edge exists, false otherwise) */
bool event_graph_map_contains_edge(EventGraphMap* map, EventTriple from, EventTriple to) {
    return event_graph_map_get_frequency(map, from, to) > 0;
}

/* Get the number of unique source nodes in the map */
uint32_t event_graph_map_source_count(EventGraphMap* map) {
    return map ? map->size : 0;
}

/* Get the total number of edges in the map */
uint32_t event_graph_map_edge_count(EventGraphMap* map) {
    if (!map) return 0;

    uint32_t total_edges = 0;
    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied && !map->entries[i].deleted) {
            total_edges += map->entries[i].dest_map->size;
        }
    }

    return total_edges;
}

/* Iterate over all edges with their frequencies */
void event_graph_map_for_each(EventGraphMap* map,
                              edge_frequency_iter_fn callback,
                              void* user_data) {
    if (!map || !callback) return;

    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied && !map->entries[i].deleted) {
            DestinationMap* dmap = map->entries[i].dest_map;
            EventTriple source = map->entries[i].source;

            for (uint32_t j = 0; j < dmap->capacity; j++) {
                if (dmap->entries[j].occupied && !dmap->entries[j].deleted) {
                    callback(source,
                             dmap->entries[j].destination,
                             dmap->entries[j].frequency,
                             user_data);
                }
            }
        }
    }
}

/* Clear all elements from the map */
void event_graph_map_clear(EventGraphMap* map) {
    if (!map) return;
    
    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied && !map->entries[i].deleted) {
            destination_map_clear(map->entries[i].dest_map);
        }
    }
    
    memset(map->entries, 0, map->capacity * sizeof(SourceMapEntry));
    map->size = 0;
}
