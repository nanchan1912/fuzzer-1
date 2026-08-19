#ifndef MUTATOR_WRAPPER_H
#define MUTATOR_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "afl-fuzz.h"
#include "retgraph_shm.h"
#include "shm_next_events.h"


// MO-Footprint related functions
int update_mo_coverage(EventTriple from_event_id, EventTriple to_event_id);
void update_mo_coverage_for_graph(SkeletonGraph* graph);
uint32_t get_mo_coverage_count(); 
void print_mo_edge_frequencies();
const uint32_t get_mo_edge_freq(EventTriple from_event_id, EventTriple to_event_id);


/**
 * @brief Deep-clone a skeleton graph.
 *
 * @param old Source graph to duplicate.
 * @return Newly allocated clone, or `NULL` on failure.
 */
SkeletonGraph* clone_SkeletonGraph(const SkeletonGraph* old);

/**
 * @brief Destroy a skeleton graph created by wrapper helpers.
 *
 * @param graph Graph pointer to destroy.
 */
void destroy_SkeletonGraph(SkeletonGraph* graph);

/**
 * @brief Update MO coverage map from a seed file.
 * 
 * @param filename Path to the seed JSON file.
 */
void update_mo_freq_from_seed(const char* filename);

/**
 * @brief Read a skeleton graph from JSON.
 *
 * @param filename Input JSON path.
 * @return Newly allocated graph, or `NULL` on failure.
 */
SkeletonGraph* read_from_json(const char* filename);

/**
 * @brief Serialize a skeleton graph to JSON.
 *
 * @param filename Output JSON path.
 * @param graph Graph to serialize.
 * @return Number of bytes written, or 0 on failure.
 */
size_t write_to_json(const char* filename, const SkeletonGraph* graph);   

typedef enum {
    MUT_NONE = 0,
    MUT_ADD_READ,
    MUT_ADD_WRITE,
    MUT_ADD_RMW,
    MUT_ADD_FENCE,
    MUT_MUTATE_RF
} sk_mutation_kind_t;

typedef struct MutationInfo {
    sk_mutation_kind_t kind;
    EventTriple source_id; // For RF mutations, this is the source event. For new event mutations, this is the event from which the new event is added.
    EventTriple dest_id;   // For RF mutations, this is the destination event. For new event mutations, this is the new event added.
    char location[64];
} MutationInfo;

SkeletonGraph* mutate_skeleton_graph_with_info(SkeletonGraph* original,
                                              enum skeleton_graph_mutator_phase current_phase,
                                              void* current_potential,
                                              struct SHM_next_events* current_feedback,
                                              MutationInfo* out_info,
                                              bool skel_feedback_enabled);

/**
 * @brief Set mutator RNG state from AFL state.
 *
 * @param afl AFL state pointer used by the mutator RNG helpers.
 */
void set_skeleton_graph_rng_state(afl_state_t *afl);

/**
 * @brief Load static program abstraction used by the mutator.
 *
 * @param filename Path to `.eg` abstraction file.
 */
void parse_program_abstraction_file(const char* filename);

/**
 * @brief Create an empty skeleton graph.
 *
 * @return Newly allocated empty graph.
 */
SkeletonGraph* empty_skeleton_graph();

/**
 * @brief Create a potential object.
 *
 * @param graph Input skeleton graph.
 * @return Opaque potential pointer.
 */
void* create_skeleton_potential(const SkeletonGraph* graph);

/**
 * @brief Destroy a potential object.
 *
 * @param potential Opaque Mode 1 potential pointer.
 */
void destroy_skeleton_potential(void* potential);

/**
 * @brief Get total write count from a potential object.
 *
 * @param potential Opaque potential pointer.
 * @return Potential write count.
 */
size_t get_potential_count_from_ptr(void* potential);

/**
 * @brief Clone a potential object.
 *
 * @param potential Opaque potential pointer.
 * @return Opaque clone pointer, or `NULL`.
 */
void* clone_skeleton_potential(void* potential);

/**
 * @brief Recalculate potential from scratch for RF mutation.
 *
 * @param graph Mutated skeleton graph.
 * @return Opaque potential pointer.
 */
void* potential_calculation_on_rf_mutation(const SkeletonGraph* graph);

/**
 * @brief Unified potential update entry point.
 *
 * @param potential Existing opaque Mode 1 potential pointer.
 * @param graph Current mutated graph.
 * @param mutation Mutation metadata for incremental/full update choice.
 * @return Updated (or replaced) opaque potential pointer.
 */
void* update_potential(void* potential, const SkeletonGraph* graph, const MutationInfo* mutation);

/**
 * @brief Initialize the potential cache.
 */
void initialize_skeleton_potential_cache(void);

/**
 * @brief Incrementally update potential after adding a read.
 */
void incremental_update_on_read(void* potential, const SkeletonGraph* graph, 
                                uint32_t added_thread_id);

/**
 * @brief Incrementally update potential after adding a write.
 */
void incremental_update_on_write(void* potential, const SkeletonGraph* graph,
                                                                 long long instr_id, uint32_t thread_id, 
                                 uint32_t visit_id, uint32_t added_thread_id,
                                 const char* location);

/**
 * @brief Incrementally update potential after adding a fence.
 */
void incremental_update_on_fence(void* potential, const SkeletonGraph* graph,
                                 uint32_t added_thread_id);

/**
 * @brief Incrementally update potential after adding an RMW.
 */
void incremental_update_on_rmw(void* potential, const SkeletonGraph* graph,
                                     long long instr_id, uint32_t thread_id,
                                     uint32_t visit_id, uint32_t added_thread_id,
                                     const char* location);

/**
 * @brief Compute MO-footprint score from a skeleton graph.
 */
u32 skeleton_graph_mo_footprint_calc(SkeletonGraph* graph);

// not using this anymore
// /**
//  * @brief Build mutator feedback object from a shared simulator graph.
//  *
//  * @param graph Shared graph snapshot from simulator.
//  * @return Opaque feedback pointer consumed by mutator.
//  */
// void* create_simulator_feedback_from_shared_graph(const struct SharedGraph* graph);

/**
 * @brief Destroy mutator feedback object created by wrapper.
 *
 * @param feedback Opaque feedback pointer.
 */
// void destroy_simulator_feedback(void* feedback);

//changed the type of simulator feedback arg 
void destroy_simulator_feedback(struct SHM_next_events* feedback);

bool race_pair_store_get_pair(const void* race_pair_store,
                              size_t index,
                              EventTriple* first_event,
                              EventTriple* second_event);

void dump_explored_locations();

#ifdef __cplusplus
}
#endif

#endif // MUTATOR_WRAPPER_H