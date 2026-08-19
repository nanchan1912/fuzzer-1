#ifndef DATA_RACE_H
#define DATA_RACE_H

#include <vector>

#include "event_pair_set.h"
#include "skeleton_graph.hpp"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque race-pair store helpers.
// The implementation keeps the actual container in C++ code so C callers only
// depend on these functions, not on the backing storage type.
// Create an empty opaque race-pair store.
void* race_pair_store_create(void);
// Destroy an opaque race-pair store returned by the helpers above.
void  race_pair_store_destroy(void* race_pair_store);
// Clone an opaque race-pair store.
void* race_pair_store_clone(const void* race_pair_store);
// Return the number of stored race pairs.
size_t race_pair_store_size(const void* race_pair_store);
// Add one race pair to the store, ignoring duplicates.
void  race_pair_store_add(void* race_pair_store, EventTriple first_event, EventTriple second_event);
// Append all unique race pairs from `source_store` into `destination_store`.
void  race_pair_store_append(void* destination_store, const void* source_store);
// Collect all race pairs from the given graph into a newly allocated store.
void* race_pair_store_collect(const struct SkeletonGraph* graph);
// Incrementally refresh the store for the event that changed in the mutation.
void  race_pair_store_update_incremental(void* race_pair_store,
						 const struct SkeletonGraph* graph,
						 EventTriple mutated_event);

// Retrieve the pair at `index` from the opaque race-pair store.
// Returns true and fills `first`/`second` on success, false otherwise.
bool race_pair_store_get_pair(const void* race_pair_store,
                              size_t index,
                              EventTriple* first_event,
                              EventTriple* second_event);

#ifdef __cplusplus
}
#endif

/*
 * Return all candidate events that race with `target_event_id`.
 * The caller can pair the target with every returned event and store the
 * resulting race pairs using `race_pair_store_add()`.
 *
 * The graph must already contain the event indexing and ordering metadata that
 * the race check relies on.
*/
std::vector<EventID> check_data_race(const struct SkeletonGraph* graph,
                                    const EventID& target_event_id);

#endif // DATA_RACE_H
