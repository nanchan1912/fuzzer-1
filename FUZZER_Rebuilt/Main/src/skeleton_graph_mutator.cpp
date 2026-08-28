#include "diversity_checker.h"
#include <algorithm>  // including this for std::copy
#include <fstream>
#include "json.hpp"  // for JSON parsing (downloaded from nlohmann/json)
#include "skeleton_graph_mutator.hpp"
#include "skeleton_graph_events.hpp"
#include "skeleton_potential.hpp"
#include "static_program_abstraction.hpp"
#include "skeleton_graph.hpp"
#include "retgraph_shm.h"
#include "shm_next_events.h"
#include "consistency.hpp"
#include "skeleton_mutator_helper.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <memory>

#include <sstream>
#include <cctype>
#include <unordered_map>
#include <utility>

static bool thread_counts_loaded = false;
static bool thread_counts_valid = true;
static std::unordered_map<ThreadID, int> expected_thread_counts;


static std::unordered_map<ThreadID, uint64_t> mo_thread_weights;
static const uint64_t MAX_BIAS_THRESHOLD = 1000000000ULL; // 10^9

void add_mo_thread_bias(ThreadID tid, int k) {
    if (k <= 0) return;
    mo_thread_weights[tid] += static_cast<uint64_t>(k);

    if (mo_thread_weights[tid] >= MAX_BIAS_THRESHOLD) {
        for (auto& entry : mo_thread_weights) {
            entry.second = (entry.second + 1) / 2;
        }
    }
}

uint64_t get_mo_thread_weight(ThreadID tid) {
    auto it = mo_thread_weights.find(tid);
    if (it != mo_thread_weights.end()) {
        return it->second;
    }
    return 0;
}

void reset_mo_thread_bias() {
    mo_thread_weights.clear();
}

void record_mo_thread_bias(const SkeletonGraph* graph, const Event* earlier_event, const Event* current_event) {
    if (!graph || !earlier_event || !current_event) return;

    ThreadID earlier_tid = earlier_event->get_thread_id();
    ThreadID curr_tid = current_event->get_thread_id();
    if (earlier_tid == curr_tid) return;

    const auto& po_map = graph->get_threadwise_po();
    int curr_count = 0;
    int earlier_count = 0;

    auto it_curr = po_map.find(curr_tid);
    if (it_curr != po_map.end()) {
        curr_count = static_cast<int>(it_curr->second.size());
    }

    auto it_earlier = po_map.find(earlier_tid);
    if (it_earlier != po_map.end()) {
        earlier_count = static_cast<int>(it_earlier->second.size());
    }

    int k = std::abs(curr_count - earlier_count) + 1;
    add_mo_thread_bias(curr_tid, k);
}
extern "C" {
  #include "skeleton_graph_mutator_wrapper.h"
}

static MutationInfo last_mutation_info = {MUT_NONE, {0,0,0}, {0,0,0}, {0}};

static sgf_state_t *skel_sgf_state = nullptr;


/*
 * Used in sgf-fuzz.c to set the skeleton random state to the sgf's random state.
 * It means its done at the init, while reading env etc. 
 * So, the initial sgf state is what remains throughout for random calculations.
 * TODO: Modify if required to be better.
*/
extern "C" void set_skeleton_graph_rng_state(sgf_state_t *sgf) {
    skel_sgf_state = sgf;
}

/* 
 * Returns random u32 number below limit using the provided sgf_state_t for randomness.
 * If skel_sgf_state is not set, it falls back to using std::rand() for randomness.
 * 
 * @param limit The upper limit for the random number (exclusive).
*/
static u32 skel_rand_below(u32 limit) {
    if (!limit) { return 0; }
    if (skel_sgf_state) { return rand_below(skel_sgf_state, limit); }
    return (u32)(rand() % limit);
}

/*
 * Returns whether mode == ACQUIRE or mode == ACQ_REL or mode == SC
 * 
 * @param mode The Access_Mode to check.
*/
static bool is_acquire_like_mode(Access_Mode mode) {
    return mode == Access_Mode::ACQUIRE || mode == Access_Mode::ACQ_REL || mode == Access_Mode::SC;
}

/*
 * Returns whether mode == RELEASE or mode == ACQ_REL or mode == SC
 * 
 * @param mode The Access_Mode to check.
*/
static bool is_release_like_mode(Access_Mode mode) {
    return mode == Access_Mode::RELEASE || mode == Access_Mode::ACQ_REL || mode == Access_Mode::SC;
}

/*
 * Adds a sw edge to the graph if it doesn't already exist.
 * 
 * @param graph The SkeletonGraph to modify.
 * @param from The source event ID.
 * @param to The destination event ID.
 */
static void add_sw_if_absent(SkeletonGraph* graph, const EventID& from, const EventID& to) {
    auto& sw_vec = graph->get_sw()[from];
    if (std::find(sw_vec.begin(), sw_vec.end(), to) == sw_vec.end()) {
        graph->add_sw(from, to);
    }
}

// Changing this func as I changed the type of simulator_feedback in SkeletonGraphData to be of type SHM_next_events* instead of void*
extern "C" void destroy_simulator_feedback(struct SHM_next_events* feedback_ptr){
    //this is to free the memory allocated in update_simulator_feedback_cache function in sgf-fuzz-run.c
    ck_free(feedback_ptr);
}
/*
 * Checks if the source event has a child event in the same thread in SkeletonGraph.
 * Checks for the child in the following order:
 * 1. Check if the source event has a child in the same thread in the threadwise_po map.
 * 2. Check if the source event has a child in the same thread in the rf edges.
 * 3. Check if the source event has a child in the same thread in the sw edges.
 * 
 * @param graph The SkeletonGraph to check.
 * @param source_event_id The ID of the source event.
 * @return True if the source event has a child in the same thread, false otherwise.
 */
static bool source_has_same_thread_child(const SkeletonGraph* graph, const EventID& source_event_id) {
    const Event* source_event = graph->get_event_by_id(source_event_id);
    if (source_event == nullptr) {
        return false;
    }

    const ThreadID source_tid = source_event->get_thread_id();

    const auto& threadwise_po = graph->get_threadwise_po();
    auto thread_it = threadwise_po.find(source_tid);
    if (thread_it != threadwise_po.end()) {
        const auto& po_events = thread_it->second;
        auto pos_it = std::find(po_events.begin(), po_events.end(), source_event_id);
        if (pos_it != po_events.end() && std::next(pos_it) != po_events.end()) {
            return true;
        }
    }

    const auto has_same_thread_successor = [&](const EdgeMap& edges) {
        auto edge_it = edges.find(source_event_id);
        if (edge_it == edges.end()) {
            return false;
        }

        for (const auto& child_event_id : edge_it->second) {
            const Event* child_event = graph->get_event_by_id(child_event_id);
            if (child_event != nullptr && child_event->get_thread_id() == source_tid) {
                return true;
            }
        }

        return false;
    };

    return has_same_thread_successor(graph->get_rf()) || has_same_thread_successor(graph->get_sw());
}

/*
 * Returns a set of child thread IDs for the given source event in the SkeletonGraph.
 * Returns child for all the edges (rf, sw, tcj) of the source event.
 * 
 * @param graph The SkeletonGraph to check.
 * @param source_event_id The ID of the source event.
 * @return A set of child thread IDs for the given source event.
 */
static std::unordered_set<ThreadID> get_child_threads_for_source(const SkeletonGraph* graph, const EventID& source_event_id) {
    std::unordered_set<ThreadID> child_threads;
    const Event* source_event = graph->get_event_by_id(source_event_id);
    if (source_event == nullptr) {
        return child_threads;
    }

    const auto collect_threads = [&](const EdgeMap& edges) {
        auto edge_it = edges.find(source_event_id);
        if (edge_it == edges.end()) {
            return;
        }

        for (const auto& child_event_id : edge_it->second) {
            const Event* child_event = graph->get_event_by_id(child_event_id);
            if (child_event != nullptr) {
                child_threads.insert(child_event->get_thread_id());
            }
        }
    };

    collect_threads(graph->get_rf());
    collect_threads(graph->get_sw());
    collect_threads(graph->get_tcj());

    return child_threads;
}
/*
 * Adds release chain sw edges to an acquire event.
 * Adds only if the source_write is release-like or you have a release like FENCE in the same thread as the source write.
 * 
 * @param graph The SkeletonGraph to modify.
 * @param source_write The source write event.
 * @param acquire_event_id The ID of the acquire event.
 * @return void
*/
static void add_release_chain_sw_to_acquire(SkeletonGraph* graph,
                                            const Event& source_write,
                                            const EventID& acquire_event_id) {
    if (!is_release_like_mode(source_write.get_access_mode())) {
        return;
    }

    add_sw_if_absent(graph, source_write.get_event_id(), acquire_event_id);
    // Get threadwise_po for the source write's thread
    const auto& po_edges_in_thread = graph->get_threadwise_po()[source_write.get_thread_id()];
    if (po_edges_in_thread.empty()) {
        return;
    }
    // Find source write in po ordering
    const auto& po_index_map = graph->get_threadwise_po_index();
    if (po_index_map.find(source_write.get_event_id()) == po_index_map.end()) {
        return;
    }
    // Traverse backwards in po order to find the last release-like fence and add sw edges to the acquire event
    // Typecasting is required as the po_index_map is of type size_t, but we need to use it as an int for the while loop,
    // else it will cause segmentation faults
    int pos_it = (int)po_index_map.find(source_write.get_event_id())->second;
    while (pos_it >= 0) {
        const auto prev_event_id = po_edges_in_thread[pos_it];
        const auto* prev_event = graph->get_event_by_id(prev_event_id);
        if (prev_event != nullptr && prev_event->get_event_type() == Event_Type::FENCE && is_release_like_mode(prev_event->get_access_mode())) {
            add_sw_if_absent(graph, prev_event_id, acquire_event_id);
            break;  // Only add the last release-like fence in the same thread
        }
        pos_it--;
    }
}

// Forward declarations for functions implemented later in this file
SkeletonGraph* add_new_node(SkeletonGraph* graph, int current_phase, void* current_potential, struct SHM_next_events* current_feedback, bool skel_feedback_enabled, void* forbidden_mutations = nullptr);
SkeletonGraph* mutate_rf_edge(SkeletonGraph* graph, int current_phase, void* current_potential, void* forbidden_mutations = nullptr);
void add_cfg_incoming_tcj_edges(SkeletonGraph* graph, const Event& new_event, vector<Event*> parent_events);

// What happens in Potential Mode 1, check?
static std::set<EventID> get_consistent_writes_from_potential(const SkeletonGraph& graph,
                                                              const Event& read_event,
                                                              const std::string& location,
                                                              void* current_potential,
                                                              bool is_rmw_or_cas_success) {
    std::set<EventID> consistent_writes;

    if (!current_potential || location.empty()) {
        return consistent_writes;
    }

    const auto& rf = graph.get_rf();

    const auto collect_matching_ids = [&](const auto& write_set) {
        // Among the following check, only the rmw one is important, 
        // as if the potential is correct, then the other checks should be redundant.
        // But we keep them for safety for now.
        for (const auto& write_key : write_set) {
            EventID write_event_id = std::make_tuple((int)write_key.thread_id, write_key.instr_id, (int)write_key.visit_id);
            const Event* write_event = graph.get_event_by_id(write_event_id);
            if (write_event == nullptr) {
                continue;
            }
            if (write_event->get_location() != location) {
                continue;
            }
            if (write_event->get_event_type() != Event_Type::WRITE &&
                write_event->get_event_type() != Event_Type::RMW &&
                write_event->get_event_type() != Event_Type::CAS_SUCCESS
            ) {
                continue;
            }
            if (is_rmw_or_cas_success) {
                auto rf_it = rf.find(write_event_id);
                if(rf_it != rf.end() && rf_it->second.size() > 0){
                    bool rmw_cas_found = false;
                    for(const auto& read_id : rf_it->second){
                        const Event* read_event = graph.get_event_by_id(read_id);
                        if(read_event && (read_event->get_event_type() == Event_Type::RMW || read_event->get_event_type() == Event_Type::CAS_SUCCESS)){
                            rmw_cas_found = true;
                            break;
                        }
                    }
                    if(rmw_cas_found){
                        continue; // skip this write_id as it has an RMW or CAS success reading from it
                    }
                }                
            }
            consistent_writes.insert(write_event_id);
        }
    };

    // Potential Default to mode 2
    const auto* pot = static_cast<const SkeletonPotential*>(current_potential);
    if (pot != nullptr) {
        // thread_id and location passed as parameters to get_location, which returns the set of WriteKeys for that thread and location
        collect_matching_ids(pot->get_location((uint32_t)read_event.get_thread_id(), location));
     }

    return consistent_writes;
}
/*
 * Returns a set of consistent write EventIDs for a given read event in the SkeletonGraph,
 * either from potential or defaulting to calling find_consistent_writes if no potential is available.
 * 
 * @param graph The SkeletonGraph to check.
 * @param last_event The parent event of the events for which to find consistent writes.
 * @param location The location for which to find consistent writes.
 * @param current_potential The potential information for the current mutation.
 * @param is_rmw_or_cas_success Whether the read event is an RMW or CAS success event.
 * @return A set of consistent write EventIDs.
*/
static std::set<EventID> get_consistent_writes(const SkeletonGraph& graph,
                                               const Event& last_event,
                                               const std::string& location,
                                               void* current_potential,
                                               bool is_rmw_or_cas_success) {
    bool has_potential = false;
    if (current_potential != nullptr) {
        const auto* pot = static_cast<const SkeletonPotential*>(current_potential);
        const auto& all_threads = pot->get_all_threads();
        auto thread_it = all_threads.find((uint32_t)last_event.get_thread_id());
        if (thread_it != all_threads.end()) {
            if (thread_it->second.count(location) > 0) {
                has_potential = true;
            }
        }
    }

    if (has_potential) {
        return get_consistent_writes_from_potential(graph, last_event, location, current_potential, is_rmw_or_cas_success);
    }
    
    // In the case of adding a event we need the pass the parent of the read event, 
    // not read event as it is not added yet to the graph so there exists no edges.
    // Mutating rf its fine to pass read event itself.
    return find_consistent_writes(graph, last_event, location, is_rmw_or_cas_success);
}

static bool is_read_like_type(Event_Type type) {
    return type == Event_Type::READ || type == Event_Type::CAS || 
           type == Event_Type::CAS_FAILURE || type == Event_Type::CAS_SUCCESS || 
           type == Event_Type::RMW;
}

static EventID choose_write_weighted(const std::set<EventID>& consistent_writes, const EventID& prev_write_id, bool has_prev_write) {
    if (consistent_writes.empty()) {
        return std::make_tuple(-1, -1, -1);
    }
    if (consistent_writes.size() == 1 || !has_prev_write || consistent_writes.count(prev_write_id) == 0) {
        int idx = (int)skel_rand_below((u32)consistent_writes.size());
        auto it = consistent_writes.begin();
        std::advance(it, idx);
        return *it;
    }

    // Prefer alternate writes over the write from earlier visit (weight 10 vs weight 1)
    const uint32_t PREFER_WEIGHT = 10;
    const uint32_t PREV_WEIGHT = 1;

    std::vector<std::pair<EventID, uint32_t>> weighted_writes;
    uint32_t total_w = 0;

    for (const auto& wid : consistent_writes) {
        uint32_t w = (wid == prev_write_id) ? PREV_WEIGHT : PREFER_WEIGHT;
        weighted_writes.push_back({wid, w});
        total_w += w;
    }

    u32 r = skel_rand_below(total_w);
    uint32_t cumulative = 0;
    for (const auto& entry : weighted_writes) {
        cumulative += entry.second;
        if (r < cumulative) {
            return entry.first;
        }
    }
    return *consistent_writes.begin();
}


// This function performs a deep copy of the SkeletonGraph - required for safely
// performing mutations

// the cloning would be necessary to ensure that the original graph is kept safe
// I did this assuming we would need the old graph as well for getting coverage information
SkeletonGraph* clone_SkeletonGraph(const SkeletonGraph* old) {
    assert(old != nullptr);
    return new SkeletonGraph(*old);
}

extern "C" void destroy_SkeletonGraph(SkeletonGraph* graph) {
    delete graph;
}

struct EventIDPairHash {
    std::size_t operator()(const std::pair<EventID, EventID>& p) const noexcept {
        TripleHash th;
        std::size_t h1 = th(p.first);
        std::size_t h2 = th(p.second);
        return h1 ^ (h2 << 1);
    }
};

class ForbiddenMutations {
public:
    std::unordered_set<EventID, TripleHash> forbidden_events;
    std::unordered_set<std::pair<EventID, EventID>, EventIDPairHash> forbidden_rf_edges;

    void add_forbidden_event(const EventTriple& ev) {
        forbidden_events.insert(std::make_tuple(ev.thread_id, ev.instruction_id, ev.visit_id));
    }

    bool is_event_forbidden(const EventTriple& ev) const {
        return forbidden_events.find(std::make_tuple(ev.thread_id, ev.instruction_id, ev.visit_id)) != forbidden_events.end();
    }

    bool is_event_id_forbidden(const EventID& ev_id) const {
        return forbidden_events.find(ev_id) != forbidden_events.end();
    }

    void add_forbidden_rf(const EventTriple& src_write, const EventTriple& dest_read) {
        EventID src = std::make_tuple(src_write.thread_id, src_write.instruction_id, src_write.visit_id);
        EventID dest = std::make_tuple(dest_read.thread_id, dest_read.instruction_id, dest_read.visit_id);
        forbidden_rf_edges.insert({src, dest});
    }

    bool is_rf_forbidden(const EventTriple& src_write, const EventTriple& dest_read) const {
        EventID src = std::make_tuple(src_write.thread_id, src_write.instruction_id, src_write.visit_id);
        EventID dest = std::make_tuple(dest_read.thread_id, dest_read.instruction_id, dest_read.visit_id);
        return forbidden_rf_edges.find({src, dest}) != forbidden_rf_edges.end();
    }

    bool is_rf_id_forbidden(const EventID& src_id, const EventID& dest_id) const {
        return forbidden_rf_edges.find({src_id, dest_id}) != forbidden_rf_edges.end();
    }
};

extern "C" void* forbidden_mutations_create(void) {
    return new ForbiddenMutations();
}

extern "C" void forbidden_mutations_destroy(void* fm) {
    if (fm) {
        delete static_cast<ForbiddenMutations*>(fm);
    }
}

extern "C" void forbidden_mutations_add_event(void* fm, EventTriple ev) {
    if (fm) {
        static_cast<ForbiddenMutations*>(fm)->add_forbidden_event(ev);
    }
}

extern "C" bool forbidden_mutations_is_event_forbidden(const void* fm, EventTriple ev) {
    if (!fm) return false;
    return static_cast<const ForbiddenMutations*>(fm)->is_event_forbidden(ev);
}

extern "C" void forbidden_mutations_add_rf(void* fm, EventTriple src_write, EventTriple dest_read) {
    if (fm) {
        static_cast<ForbiddenMutations*>(fm)->add_forbidden_rf(src_write, dest_read);
    }
}

extern "C" bool forbidden_mutations_is_rf_forbidden(const void* fm, EventTriple src_write, EventTriple dest_read) {
    if (!fm) return false;
    return static_cast<const ForbiddenMutations*>(fm)->is_rf_forbidden(src_write, dest_read);
}


//REVISIT: This function is unnecessary but I am keeping it for now
// Used in sgf-fuzz-one.c to create an empty skeleton graph for the first time
// Check if needed or can be removed
extern "C" SkeletonGraph* empty_skeleton_graph() {
    // cout << "Generating an empty skeleton graph" << endl;
    SkeletonGraph* graph = new SkeletonGraph{};
    return graph;
}

// should I do the cloning everytime I do a mutation? can I reduce that overhead?
// I could do the cloning once for each input

// TODO
// If we are going to store skeleton's in memory, then we need to do cloning,
// And if we plan to read and write to files everytime, then we can remove it.
// - Hardik
SkeletonGraph* mutate_skeleton_graph(SkeletonGraph* original,
                                                    enum skeleton_graph_mutator_phase current_phase,
                                                    void* current_potential,
                                                    struct SHM_next_events* current_feedback,
                                                    bool skel_feedback_enabled,
                                                    void* forbidden_mutations = nullptr) {
    assert(original != NULL);

    //REVISIT: clonling seems unnecessary to me for now. Uncomment if necessary.
    SkeletonGraph* new_graph = clone_SkeletonGraph(original);

    // calling one of the mutation functions randomly

    // REVISIT: I could have added logic for checking the type of event before
    // adding an edge In case of po edges, I could have checked the thread id of
    // the events
    // TODO: Add this logic later
    // REVISIT: Also, I should take care of the following:
    // 1. Not adding duplicate edges
    // 2. Making the mutations source aware
    // 3. Ensuring the transitivity relationships are maintained (for instance, mo edges should be transitive)

    auto reset_graph = [&]() {
        delete new_graph;
        new_graph = clone_SkeletonGraph(original);
    };

    auto try_add_node = [&]() {
        add_new_node(new_graph, current_phase, current_potential, current_feedback, skel_feedback_enabled, forbidden_mutations);
        if (last_mutation_info.kind != MUT_NONE) {
            return true;
        }
        reset_graph();
        return false;
    };

    auto try_mutate_rf = [&]() {
        mutate_rf_edge(new_graph, current_phase, current_potential, forbidden_mutations);
        if (last_mutation_info.kind != MUT_NONE) {
            return true;
        }
        reset_graph();
        return false;
    };

    // Probability to decide which mutation to do based on phase
    bool mutated = false;
    if (current_phase == PRUNING_PHASE) {
        if (skel_rand_below(101) < 15) {
            mutated = try_add_node();
            if (!mutated) {
                mutated = try_mutate_rf();
            }
        } else {
            mutated = try_mutate_rf();
            if (!mutated) {
                mutated = try_add_node();
            }
        }
    } else if (current_phase == POTENTIAL_DRIVEN_PHASE) {
        if (skel_rand_below(101) < 50) {
            mutated = try_add_node();
            if (!mutated) {
                mutated = try_mutate_rf();
            }
        } else {
            mutated = try_mutate_rf();
        }
    } else {
        if (skel_rand_below(101) < 70) {
            mutated = try_add_node();
            if (!mutated) {
                mutated = try_mutate_rf();
            }
        } else {
            mutated = try_mutate_rf();
        }
    }

    if (!mutated) {
        // TODO: When I try to return the original graph, 
        // I get a terminate called after throwing an instance of 'std::bad_array_new_length'
        delete new_graph;
        new_graph = clone_SkeletonGraph(original); // Return the original graph if no mutation was performed
    }

    return new_graph;
}

// changing current_feedback to SHM_next_events* type as I changed the type of simulator_feedback in SkeletonGraphData to be of type SHM_next_events* instead of void*
SkeletonGraph* mutate_skeleton_graph_with_info(SkeletonGraph* original,
                                               enum skeleton_graph_mutator_phase current_phase,
                                               void* current_potential,
                                               struct SHM_next_events* current_feedback,
                                               MutationInfo* out_info,
                                               bool skel_feedback_enabled,
                                               void* forbidden_mutations) {

    // ACTF("Mutating skeleton graph with skel_feedback_enabled: %d", skel_feedback_enabled);
    //clearing last_mutation_info (as it is defined as static) before calling the mutate function 
    last_mutation_info.kind = MUT_NONE;
    last_mutation_info.source_id = {0,0,0};
    last_mutation_info.dest_id = {0,0,0};
    last_mutation_info.location[0] = '\0';
    
    //saving the current feedback data before updating it to the new feedback data, so that we can reset it back to the previous feedback after mutation is done
    // BUT, why are we doing it?
    // I am assuming this is also for reset - as skel_feedback data is initialized to nullptr, so after every mutation, instead of setting to nullptr, we are setting to previous feedback(?)
    //TODO: Understand why this is necessary and change if reqd
    // SHM_next_events* previous_feedback = nullptr;
    // if(skel_feedback_enabled){
    //     previous_feedback = skel_feedback_data;
    //     // skel_feedback_data = static_cast<const SimulatorFeedbackData*>(current_feedback);
    

    // We can remove it so removing it. So, removing setting it to previous feedback and setting it to NULL.
    // - Hardik
    // if(skel_feedback_enabled){
    //     //temporarily setting the feedback for the mutation
    //     skel_feedback_data = current_feedback;
    // }


    // ACTF("---> Mutating skeleton graph with %d events", (int)original->get_events().size());
    SkeletonGraph* out = mutate_skeleton_graph(original,
                                                current_phase,
                                                current_potential,
                                                current_feedback,
                                                skel_feedback_enabled,
                                                forbidden_mutations);
    // ACTF("---> Mutated skeleton graph has %d events", (int)out->get_events().size());

    // if(skel_feedback_enabled){
    //     skel_feedback_data = nullptr;
    // }

    if (out_info) {
        *out_info = last_mutation_info;
    }
    return out;
}

/*
 * Returns a vector of successor EventIDs for a given event in the SkeletonGraph.
 * It returns only 1 level of successors, not all the successors in the transitive closure.
 * Successors are determined based on the following edges: PO, RF, SW, and TCJ.
 * 
 * @param graph The SkeletonGraph to check.
 * @param event The EventID for which to find successors.
 * @return A vector of successor EventIDs.
*/
std::vector<EventID> get_successors(const SkeletonGraph& graph, const EventID& event){
    std::vector<EventID> successors;

    // ---------- PO ----------
    auto thread_it = graph.get_threadwise_po().find(std::get<0>(event));
    if (thread_it != graph.get_threadwise_po().end()){
        const auto& po = thread_it->second;

        auto it = std::find(po.begin(), po.end(), event);

        if (it != po.end()){
            auto next = std::next(it);

            if (next != po.end()) {
                successors.push_back(*next);
            }
        }
    }

    // ---------- RF ----------
    auto rf_it = graph.get_rf().find(event);
    if (rf_it != graph.get_rf().end()){
        successors.insert(successors.end(), rf_it->second.begin(), rf_it->second.end());
    }

    // ---------- SW ----------
    auto sw_it = graph.get_sw().find(event);
    if (sw_it != graph.get_sw().end()){
        successors.insert(successors.end(),
                          sw_it->second.begin(),
                          sw_it->second.end());
    }

    // ---------- TCJ ----------
    auto tcj_it = graph.get_tcj().find(event);
    if (tcj_it != graph.get_tcj().end()){
        successors.insert(successors.end(), tcj_it->second.begin(), tcj_it->second.end());
    }

    return successors;
}

/*
 * Performs a depth-first search (DFS) to collect all reachable events from a given starting event in the SkeletonGraph. 
 * 
 * @param graph The SkeletonGraph to traverse.
 * @param event The starting EventID for the DFS.
 * @param visited A set of already visited EventIDs to avoid cycles.
 * @param deletion_order A vector to store the order of events for deletion (post-order).
*/
void dfs_collect(const SkeletonGraph& graph,
                 const EventID& event,
                 std::unordered_set<EventID, TripleHash>& visited,
                 std::vector<EventID>& deletion_order){
    if (!visited.insert(event).second){
        return;
    }

    for (const auto& succ : get_successors(graph, event)){
        dfs_collect(graph, succ, visited, deletion_order);
    }

    deletion_order.push_back(event);
}


// Helper function to remove an event, doesn't make any modifications to other attributes of the graph.
// That is the job of graph->finalize().
void remove_event(SkeletonGraph& graph, const EventID& event_id){
    graph.get_events().erase(event_id);
}

// Helper function for mutate_rf_edge to remove all po/rf/sw successors of a given event, 
// without removing the event itself.
void remove_po_rf_sw_successors(SkeletonGraph& graph, const EventID& target){
    std::unordered_set<EventID, TripleHash> visited;
    std::vector<EventID> deletion_order;

    // Collect every node reachable from the target's successors.
    for (const auto& succ : get_successors(graph, target)){
        dfs_collect(graph, succ, visited, deletion_order);
    }

    // Delete every collected event.
    for (const auto& event : deletion_order){
        remove_event(graph, event);
    }

    // Remove all outgoing edges from the surviving target.
    graph.get_rf().erase(target);
    graph.get_sw().erase(target);
    graph.get_tcj().erase(target);

    // Rebuild all derived structures.
    graph.finalize();
}

// Helper function for mutate_rf_edge to remove the incoming rf/sw edges to a read event,
// without removing the read event itself.
void disconnect_read(SkeletonGraph& graph, const EventID& read){
    //
    // Remove incoming RF.
    //
    auto& rf = graph.get_rf();
    auto& rf_reverse = graph.get_rf_reverse();

    auto rf_rev_it = rf_reverse.find(read);
    if (rf_rev_it != rf_reverse.end()) {
        assert(rf_rev_it->second.size() == 1);

        const EventID& write = rf_rev_it->second.front();

        auto rf_it = rf.find(write);
        if (rf_it != rf.end()) {
            auto& reads = rf_it->second;

            reads.erase(std::remove(reads.begin(), reads.end(), read),
                        reads.end());

            if (reads.empty())
                rf.erase(rf_it);
        }

        rf_reverse.erase(rf_rev_it);
    }

    //
    // Remove incoming SW.
    //
    auto& sw = graph.get_sw();
    auto& sw_reverse = graph.get_sw_reverse();

    auto sw_rev_it = sw_reverse.find(read);
    if (sw_rev_it != sw_reverse.end()) {

        for (const auto& src : sw_rev_it->second) {

            auto sw_it = sw.find(src);

            if (sw_it == sw.end())
                continue;

            auto& succs = sw_it->second;

            succs.erase(std::remove(succs.begin(),
                                    succs.end(),
                                    read),
                        succs.end());

            if (succs.empty())
                sw.erase(sw_it);
        }

        sw_reverse.erase(sw_rev_it);
    }
}

// Helper function for RF mutation to insert an event into mo_by_location immediately after a given event
static void insert_mo_after(SkeletonGraph* graph, const Location& loc, const EventID& after_event, const EventID& new_event) {
    auto& mo_vec = graph->get_mo_by_location()[loc];
    // Remove new_event if already present
    mo_vec.erase(std::remove(mo_vec.begin(), mo_vec.end(), new_event), mo_vec.end());

    auto it = std::find(mo_vec.begin(), mo_vec.end(), after_event);
    if (it != mo_vec.end()) {
        mo_vec.insert(it + 1, new_event);
    } else {
        mo_vec.push_back(new_event);
    }
    graph->rebuild_mo();
}

//find an rf edge to mutate
// picking one randomly for now
//REVISIT: can I choose an edge cleverly instead of a random rf edge
// I could choose a more recently added event (assuming that the earlier read events would have less number of consistent writes to read from, besides, they would have undergone an rf edge mutation earlier - atleast, that seems more likely than the later read events undergoing muation of rf edge)

SkeletonGraph* mutate_rf_edge(SkeletonGraph* graph, int current_phase, void* current_potential, void* forbidden_mutations){
    // graph->finalize();
    int num_rf_edges = graph->get_rf_reverse().size();
    if(num_rf_edges == 0){
        last_mutation_info.kind = MUT_NONE;
        return graph;
    }

    // Updating the mutation info
    last_mutation_info.kind = MUT_MUTATE_RF;
    last_mutation_info.source_id.thread_id = 0;
    last_mutation_info.source_id.instruction_id = 0;
    last_mutation_info.source_id.visit_id = 0;
    last_mutation_info.dest_id.thread_id = 0;
    last_mutation_info.dest_id.instruction_id = 0;
    last_mutation_info.dest_id.visit_id = 0;
    last_mutation_info.location[0] = '\0';

    // Selecting index of the rf edge to mutate randomly
    int idx = (int)skel_rand_below((u32)num_rf_edges);

    //REVISIT: This is quite inefficient..find an alternative way to get the read event to mutate on
    // TODO

    // Random selection requires advancing an iterator through the unordered_map,
    // which is O(number of RF edges). This is acceptable for now.
    // - Hardik
    auto it = graph->get_rf_reverse().begin();
    std::advance(it, idx);
    auto read_event_id = it->first;
    assert(it->second.size() == 1);
    auto original_write_event = it->second.front();

    //given the <thread_id, instruction_id, visit_id> tuple, I need to get the event object - reqd for consistent write lookup
    const Event* read_event = graph->get_event_by_id(read_event_id);
    if(read_event == nullptr){
        WARNF("Error: could not find read event in the graph for event id: ");
        ACTF("num_rf_edges: %d", num_rf_edges);
        ACTF("random index chosen: %d", idx);
        ACTF("read_event_id: t%d i%lld v%d", std::get<0>(read_event_id), (long long)std::get<1>(read_event_id), std::get<2>(read_event_id));
    }

    assert(read_event != nullptr); 
    // Capture read event data before any mutations that may invalidate pointers
    const auto read_event_id_copy = read_event_id;
    const std::string read_loc = read_event->get_location();
    const Access_Mode read_mode = read_event->get_access_mode();
    const Event_Type read_type = read_event->get_event_type();

    // Remove po/rf/sw successors first, then find consistent writes on the pruned graph.
    remove_po_rf_sw_successors(*graph, read_event_id_copy);
    
    // Disconnect the surviving read from its old RF/SW predecessors.
    disconnect_read(*graph, read_event_id_copy);

    // For the read event, I need another write event to the same location that it can read from
    // This could be an older write or a new write added after the read event was added to the graph
    const Event* pruned_read_event = graph->get_event_by_id(read_event_id_copy);
    if(pruned_read_event == nullptr){
        WARNF("Error: read event disappeared after pruning successors for event id: ");
        ACTF("read_event_id: t%d i%lld v%d", std::get<0>(read_event_id_copy), (long long)std::get<1>(read_event_id_copy), std::get<2>(read_event_id_copy));
    }
    assert(pruned_read_event != nullptr);

    auto consistent_writes = get_consistent_writes(*graph,
                                                   *pruned_read_event,
                                                   read_loc,
                                                   current_potential,
                                                   (read_type == Event_Type::RMW || read_type == Event_Type::CAS_SUCCESS));

    std::vector<EventID> available_writes;
    for (const auto& w_id : consistent_writes) {
        if (forbidden_mutations) {
            auto* fm = static_cast<const ForbiddenMutations*>(forbidden_mutations);
            if (fm->is_rf_id_forbidden(w_id, read_event_id_copy)) {
                continue;
            }
        }
        if (w_id != original_write_event) {
            available_writes.push_back(w_id);
        }
    }

    if (!available_writes.empty()) {
        // Direct RF mutation: A new alternate write was found
        int w_idx = (int)skel_rand_below((u32)available_writes.size());
        EventID chosen_write_id = available_writes[w_idx];
        const Event* write_event = graph->get_event_by_id(chosen_write_id);

        graph->add_rf(chosen_write_id, read_event_id_copy);

        if (is_acquire_like_mode(read_mode) && write_event != nullptr) {
            add_release_chain_sw_to_acquire(graph, *write_event, read_event_id_copy);
        }

        // For RMW/CAS_SUCCESS, maintain MO order by placing read_event_id_copy after its write source
        if (read_type == Event_Type::RMW || read_type == Event_Type::CAS_SUCCESS) {
            insert_mo_after(graph, read_loc, chosen_write_id, read_event_id_copy);
        }

        graph->finalize();

        // Fill in the mutation info
        last_mutation_info.source_id.thread_id = std::get<0>(chosen_write_id);
        last_mutation_info.source_id.instruction_id = std::get<1>(chosen_write_id);
        last_mutation_info.source_id.visit_id = std::get<2>(chosen_write_id);

        last_mutation_info.dest_id.thread_id = std::get<0>(read_event_id_copy);
        last_mutation_info.dest_id.instruction_id = std::get<1>(read_event_id_copy);
        last_mutation_info.dest_id.visit_id = std::get<2>(read_event_id_copy);

        strncpy(last_mutation_info.location, read_loc.c_str(), sizeof(last_mutation_info.location) - 1);
        last_mutation_info.location[sizeof(last_mutation_info.location) - 1] = '\0';

    } else {
        // No alternative write directly available. Check for RMW-chain mutation:
        // When RMW_curr was reading from RMW_parent (on a different thread), we mutate RMW_parent first.
        const Event* parent_write_event = graph->get_event_by_id(original_write_event);
        bool is_curr_rmw = (read_type == Event_Type::RMW || read_type == Event_Type::CAS_SUCCESS);
        bool is_parent_rmw = (parent_write_event != nullptr && 
                             (parent_write_event->get_event_type() == Event_Type::RMW || 
                              parent_write_event->get_event_type() == Event_Type::CAS_SUCCESS));
        bool diff_threads = (parent_write_event != nullptr && 
                             parent_write_event->get_thread_id() != std::get<0>(read_event_id_copy));

        if (is_curr_rmw && is_parent_rmw && diff_threads) {
            EventID parent_write_id = original_write_event;
            Access_Mode parent_mode = parent_write_event->get_access_mode();

            // 1. Remove both RMW_curr and RMW_parent from MO ordering for this location
            auto& mo_vec = graph->get_mo_by_location()[read_loc];
            mo_vec.erase(std::remove(mo_vec.begin(), mo_vec.end(), read_event_id_copy), mo_vec.end());
            mo_vec.erase(std::remove(mo_vec.begin(), mo_vec.end(), parent_write_id), mo_vec.end());
            graph->rebuild_mo();

            // 2. Remove successors of RMW_parent (RMW_curr is preserved since RF was already disconnected)
            remove_po_rf_sw_successors(*graph, parent_write_id);

            // 3. Disconnect incoming RF and SW from RMW_parent
            disconnect_read(*graph, parent_write_id);

            // 4. Find consistent writes for RMW_parent (will include RMW_curr)
            const Event* pruned_parent_event = graph->get_event_by_id(parent_write_id);
            if (pruned_parent_event != nullptr) {
                auto parent_consistent_writes = get_consistent_writes(*graph,
                                                                      *pruned_parent_event,
                                                                      read_loc,
                                                                      current_potential,
                                                                      true);

                if (!parent_consistent_writes.empty()) {
                    // Choose write randomly for parent
                    int idx_p = (int)skel_rand_below((u32)parent_consistent_writes.size());
                    auto it_p = parent_consistent_writes.begin();
                    std::advance(it_p, idx_p);
                    EventID chosen_write_for_parent = *it_p;

                    const Event* write_ev_p = graph->get_event_by_id(chosen_write_for_parent);
                    graph->add_rf(chosen_write_for_parent, parent_write_id);

                    if (is_acquire_like_mode(parent_mode) && write_ev_p != nullptr) {
                        add_release_chain_sw_to_acquire(graph, *write_ev_p, parent_write_id);
                    }

                    // 5. Now find consistent writes for RMW_curr (the write that parent was reading from is now freed)
                    const Event* curr_event = graph->get_event_by_id(read_event_id_copy);
                    if (curr_event != nullptr) {
                        auto curr_consistent_writes = get_consistent_writes(*graph,
                                                                            *curr_event,
                                                                            read_loc,
                                                                            current_potential,
                                                                            true);

                        if (!curr_consistent_writes.empty()) {
                            // Choose write randomly for current RMW
                            int idx_c = (int)skel_rand_below((u32)curr_consistent_writes.size());
                            auto it_c = curr_consistent_writes.begin();
                            std::advance(it_c, idx_c);
                            EventID chosen_write_for_curr = *it_c;

                            const Event* write_ev_c = graph->get_event_by_id(chosen_write_for_curr);
                            graph->add_rf(chosen_write_for_curr, read_event_id_copy);

                            if (is_acquire_like_mode(read_mode) && write_ev_c != nullptr) {
                                add_release_chain_sw_to_acquire(graph, *write_ev_c, read_event_id_copy);
                            }

                            // 6. Wire MO order:
                            // Insert RMW_curr after its chosen write
                            insert_mo_after(graph, read_loc, chosen_write_for_curr, read_event_id_copy);

                            // Insert RMW_parent after its chosen write (or after RMW_curr if parent reads from RMW_curr)
                            if (chosen_write_for_parent == read_event_id_copy) {
                                insert_mo_after(graph, read_loc, read_event_id_copy, parent_write_id);
                            } else {
                                insert_mo_after(graph, read_loc, chosen_write_for_parent, parent_write_id);
                            }

                            graph->finalize();

                            // Option A: Report RMW_curr as destination in last_mutation_info
                            last_mutation_info.source_id.thread_id = std::get<0>(chosen_write_for_curr);
                            last_mutation_info.source_id.instruction_id = std::get<1>(chosen_write_for_curr);
                            last_mutation_info.source_id.visit_id = std::get<2>(chosen_write_for_curr);

                            last_mutation_info.dest_id.thread_id = std::get<0>(read_event_id_copy);
                            last_mutation_info.dest_id.instruction_id = std::get<1>(read_event_id_copy);
                            last_mutation_info.dest_id.visit_id = std::get<2>(read_event_id_copy);

                            strncpy(last_mutation_info.location, read_loc.c_str(), sizeof(last_mutation_info.location) - 1);
                            last_mutation_info.location[sizeof(last_mutation_info.location) - 1] = '\0';

                            return graph;
                        }
                    }
                }
            }
        }

        // No mutation can be performed here.
        // No restoring of edge required as we will return the original graph in this case.
        // So, no need to restore the original rf edge.
        // - Hardik
        last_mutation_info.kind = MUT_NONE;
    }
    return graph;
}

// Program CFG for static program abstraction (accessible by other modules)
ProgramCFG cfg_new;

typedef enum GET_NEW_NODE_GUIDE{
    random_new_node,
    mo_freq,
    thread_prob
}GET_NEW_NODE_GUIDE;

struct CandidateEvent {
    std::unique_ptr<Event> event;
    vector<Event*> parents;
    //Changed from Single Event* to vector<Event*> considering the cases where a single event can have more than one parent.
};

// Returns true if this candidate is a repeated visit of the same read instruction whose only available
// consistent write is the exact same write that the earlier visit read from.
static bool is_spinning_read_without_alternate_write(const SkeletonGraph* graph, const CandidateEvent& candidate, void* current_potential = nullptr) {
    if (!graph || !candidate.event || candidate.event->get_visit_id() <= 1) {
        return false;
    }
    Event_Type t = candidate.event->get_event_type();
    if (!is_read_like_type(t)) {
        return false;
    }
    if (candidate.parents.empty() || candidate.parents[0] == nullptr) {
        return false;
    }
    const Event* parent = candidate.parents[0];
    if (parent->get_thread_id() != candidate.event->get_thread_id() ||
        parent->get_instruction_id() != candidate.event->get_instruction_id()) {
        return false;
    }

    auto rf_rev_it = graph->get_rf_reverse().find(parent->get_event_id());
    if (rf_rev_it == graph->get_rf_reverse().end() || rf_rev_it->second.empty()) {
        return false;
    }
    EventID prev_write_id = rf_rev_it->second.front();

    bool is_rmw = (t == Event_Type::RMW || t == Event_Type::CAS_SUCCESS);
    auto consistent_writes = get_consistent_writes(*graph, *parent, candidate.event->get_location(), current_potential, is_rmw);

    for (const auto& wid : consistent_writes) {
        if (wid != prev_write_id) {
            return false;
        }
    }
    return true;
}

/*
 * Sets the mutation information based on the provided event.
 * Updates the last_mutation_info global variable with the event's details.
 * TODO: Update to ensure every mutation handled properly.
 * 
 * @param e The event to use for setting mutation information.
 */
static void set_mutation_info_from_event(const Event* e, const Event* parent) {
    if (!e) {
        last_mutation_info.kind = MUT_NONE;
        last_mutation_info.source_id = {0,0,0};
        last_mutation_info.dest_id = {0,0,0};
        last_mutation_info.location[0] = '\0';
        return;
    }

    switch (e->get_event_type()) {
        case Event_Type::READ:
            last_mutation_info.kind = MUT_ADD_READ;
            break;
        case Event_Type::WRITE:
            last_mutation_info.kind = MUT_ADD_WRITE;
            break;
        case Event_Type::RMW:
            last_mutation_info.kind = MUT_ADD_RMW;
            break;
        case Event_Type::CAS_SUCCESS:
            last_mutation_info.kind = MUT_ADD_CAS_SUCCESS;
            break;
        case Event_Type::CAS_FAILURE:
            last_mutation_info.kind = MUT_ADD_CAS_FAILURE;
            break;
        case Event_Type::FENCE:
            last_mutation_info.kind = MUT_ADD_FENCE;
            break;
        default:
            last_mutation_info.kind = MUT_NONE;
            break;
    }

    // dest_id is the new event added
    last_mutation_info.dest_id.thread_id = e->get_thread_id();
    last_mutation_info.dest_id.instruction_id = e->get_instruction_id();
    last_mutation_info.dest_id.visit_id = e->get_visit_id();

    // source_id is the event from which it is added (the parent)
    if (parent) {
        last_mutation_info.source_id.thread_id = parent->get_thread_id();
        last_mutation_info.source_id.instruction_id = parent->get_instruction_id();
        last_mutation_info.source_id.visit_id = parent->get_visit_id();
    } else {
        last_mutation_info.source_id.thread_id = 0;
        last_mutation_info.source_id.instruction_id = 0;
        last_mutation_info.source_id.visit_id = 0;
    }

    std::strncpy(last_mutation_info.location, e->get_location().c_str(), sizeof(last_mutation_info.location) - 1);
    last_mutation_info.location[sizeof(last_mutation_info.location) - 1] = '\0';
}

static bool is_supported_candidate_type(Event_Type type) {
    return type == Event_Type::READ ||
           type == Event_Type::CAS_FAILURE ||
           type == Event_Type::WRITE ||
           type == Event_Type::RMW ||
           type == Event_Type::CAS_SUCCESS ||
           type == Event_Type::FENCE;
}

static int pick_random_index_for_type(const std::vector<CandidateEvent>& candidates, Event_Type type) {
    std::vector<int> indices;
    indices.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].event && candidates[i].event->get_event_type() == type) {
            indices.push_back((int)i);
        }
    }

    if (indices.empty()) return -1;
    int picked = (int)skel_rand_below((u32)indices.size());
    return indices[picked];
}

// Check only cross-thread predecessors (joins). Same-thread predecessors (loops)
// are handled naturally by program order and should not block event enablement.
static bool are_all_cross_thread_pred_sources_present(const SkeletonGraph* graph, int event_id, int current_tid) {
    const auto cfg_it = cfg_new.nodes.find(event_id);
    if (cfg_it == cfg_new.nodes.end()) return false;

    const auto& preds = cfg_it->second.pred;
    if (preds.empty()) {
        return true;
    }

    for (int pred_id : preds) {
        const auto pred_it = cfg_new.nodes.find(pred_id);
        if (pred_it == cfg_new.nodes.end()) {
            return false;
        }

        const Event& pred_event = pred_it->second.event;
        
        // Skip same-thread predecessors - they are handled by program order (including loops)
        if (pred_event.get_thread_id() == current_tid) {
            continue;
        }
        
        // For cross-thread predecessors (joins), check they exist in the graph
        const int next_visit = graph->get_next_visit_id(pred_event.get_thread_id(), pred_event.get_instruction_id());
        if (next_visit <= 1) {
            return false;
        }
    }
    return true;
}

static bool has_same_thread_predecessor(int event_id, int tid) {
    const auto cfg_it = cfg_new.nodes.find(event_id);
    if (cfg_it == cfg_new.nodes.end()) return false;

    for (int pred_id : cfg_it->second.pred) {
        const auto pred_it = cfg_new.nodes.find(pred_id);
        if (pred_it == cfg_new.nodes.end()) continue;
        if (pred_it->second.event.get_thread_id() == tid) {
            return true;
        }
    }
    return false;
}

static int get_thread_static_position(int tid, int event_id) {
    auto th_it = cfg_new.thread_index.find(tid);
    if (th_it == cfg_new.thread_index.end()) return -1;

    const auto& order = th_it->second;
    for (size_t i = 0; i < order.size(); ++i) {
        if (order[i] == event_id) return (int)i;
    }
    return -1;
}

// Require dynamic availability of same-thread predecessor instances for the
// candidate visit. This prevents enabling loop-head writes before the
// corresponding loop-body event for that iteration exists.
static bool are_required_same_thread_preds_present_for_visit(const SkeletonGraph* graph,
                                                             int event_id,
                                                             int tid,
                                                             int target_visit) {
    const auto cfg_it = cfg_new.nodes.find(event_id);
    if (cfg_it == cfg_new.nodes.end()) return false;

    const int curr_pos = get_thread_static_position(tid, event_id);
    if (curr_pos < 0) return false;

    // Forward-edge same-thread preds: ALL must be present (AND).
    // Back-edge same-thread preds (loop): at least ONE must be present (OR).
    // Exclusive-branch loops (e.g. A→{B|C}→A) only take one back-edge per
    // iteration, so requiring all back-edges would make the second visit
    // unreachable when branches are mutually exclusive.
    bool has_back_preds = false;
    bool any_back_pred_satisfied = false;

    for (int pred_id : cfg_it->second.pred) {
        const auto pred_it = cfg_new.nodes.find(pred_id);
        if (pred_it == cfg_new.nodes.end()) return false;

        const Event& pred_static = pred_it->second.event;
        if (pred_static.get_thread_id() != tid) continue;

        const int pred_pos = get_thread_static_position(tid, pred_id);
        if (pred_pos < 0) return false;

        if (pred_pos >= curr_pos) {
            // Back-edge: this pred comes from the previous iteration.
            has_back_preds = true;
            int required_visit = target_visit - 1;
            if (required_visit < 1) {
                any_back_pred_satisfied = true;
                continue;
            }
            EventID required_pred = std::make_tuple(tid, pred_static.get_instruction_id(), required_visit);
            if (graph->get_event_by_id(required_pred) != nullptr) {
                any_back_pred_satisfied = true;
            }
        } else {
            // Forward-edge: must be present (AND logic).
            int required_visit = target_visit;
            EventID required_pred = std::make_tuple(tid, pred_static.get_instruction_id(), required_visit);
            if (graph->get_event_by_id(required_pred) == nullptr) return false;
        }
    }

    if (has_back_preds && !any_back_pred_satisfied) return false;
    return true;
}

static bool can_enable_visit(const SkeletonGraph* graph, int event_id, int tid, long long instruction_id) {
    const int next_visit = graph->get_next_visit_id(tid, instruction_id);
    if (next_visit <= 1) {
        return true;
    }

    // A repeated visit is only valid for CFG nodes with same-thread predecessor (loop back path).
    return has_same_thread_predecessor(event_id, tid);
}

void add_cfg_incoming_tcj_edges(SkeletonGraph* graph, const Event& new_event, vector<Event*> parent_events) {
    //Changed the if statement to accomodate the vector as parent_event is changed to vector<Event*> from Event*
    if (new_event.get_visit_id() > 1 && !parent_events.empty()) {
        for(Event* par:parent_events){
            if(par->get_thread_id() == new_event.get_thread_id())
                return;
        }
    }

    const int static_id = cfg_new.resolve_event_id(new_event.get_thread_id(), new_event.get_instruction_id());
    if (static_id < 0) {
        return;
    }

    const auto cfg_it = cfg_new.nodes.find(static_id);
    if (cfg_it == cfg_new.nodes.end()) {
        return;
    }

    const EventID new_event_id = new_event.get_event_id();

    std::unordered_set<ThreadID> cross_thread_pred_threads;
    for (int pred_id : cfg_it->second.pred) {
        const auto pred_it = cfg_new.nodes.find(pred_id);
        if (pred_it == cfg_new.nodes.end()) {
            continue;
        }

        const Event& pred_static = pred_it->second.event;
        if (pred_static.get_thread_id() == new_event.get_thread_id()) {
            continue;
        }

        cross_thread_pred_threads.insert(pred_static.get_thread_id());
    }

    const auto& threadwise_po = graph->get_threadwise_po();
    for (ThreadID pred_tid : cross_thread_pred_threads) {
        const auto po_it = threadwise_po.find(pred_tid);
        if (po_it == threadwise_po.end() || po_it->second.empty()) {
            continue;
        }

        const EventID& pred_event_id = po_it->second.back();
        if (graph->get_event_by_id(pred_event_id) == nullptr) {
            continue;
        }

        auto& tcj_vec = graph->get_tcj()[pred_event_id];
        if (std::find(tcj_vec.begin(), tcj_vec.end(), new_event_id) == tcj_vec.end()) {
            graph->add_tcj(pred_event_id, new_event_id);
        }
    }
}
/*
 * Used to collect all the enabled events for a given skeleton graph from the program CFG. 
 * It checks for each event in the graph, and for each of its next events in the CFG, whether it can be enabled based on the current state of the graph.
 * 
 * @param graph The SkeletonGraph to check for enabled events.
*/
static std::vector<CandidateEvent> collect_enabled_events(SkeletonGraph* graph, int current_phase, void* forbidden_mutations = nullptr) {
    std::vector<CandidateEvent> enabled;
    std::unordered_set<EventID, TripleHash> seen_candidates;

    //Changed data type of parent_event from Event* to vector<Event*>
    auto push_enabled = [&](std::unique_ptr<Event> e_copy, const vector<Event*> parents) {
        if (!e_copy || !is_supported_candidate_type(e_copy->get_event_type())) {
            return;
        }

        const EventID candidate_id = e_copy->get_event_id();
        if (seen_candidates.find(candidate_id) != seen_candidates.end()) {
            return;
        }

        if (forbidden_mutations) {
            auto* fm = static_cast<const ForbiddenMutations*>(forbidden_mutations);
            if (fm->is_event_id_forbidden(candidate_id)) {
                return;
            }
        }

        seen_candidates.insert(candidate_id);
        
        //removed the const_cast<Event*> as now the parent_event is vector<Event*>
        enabled.push_back({std::move(e_copy), (parents)});
    };

    for (const auto& [source_event_id, source_event] : graph->get_events()) {
        const ThreadID source_tid = source_event.get_thread_id();
        std::unordered_set<ThreadID> blocked_threads = get_child_threads_for_source(graph, source_event_id);

        std::vector<EventID> next_event_ids;

        const int static_id = cfg_new.resolve_event_id(source_tid, source_event.get_instruction_id());
        if (static_id < 0) {
            continue;
        }

        for (int next_id : cfg_new.get_next_event_ids(static_id)) {
            next_event_ids.push_back(cfg_new.nodes.at(next_id).event.get_event_id());
        }

        if (next_event_ids.empty()) {
            continue;
        }

        std::vector<CandidateEvent> source_candidates;
        source_candidates.reserve(next_event_ids.size());

        for (const auto& next_event_id : next_event_ids) {
            const int static_id = cfg_new.resolve_event_id(std::get<0>(next_event_id),
                                                           std::get<1>(next_event_id));
            if (static_id < 0) {
                continue;
            }

            const Event& cfg_event = cfg_new.nodes.at(static_id).event;
            const ThreadID next_tid = cfg_event.get_thread_id();

            if (next_tid == source_tid && source_has_same_thread_child(graph, source_event_id)) {
                // Skeleton graph should not have child for this source event on same thread!
                continue;
            }

            if (blocked_threads.find(next_tid) != blocked_threads.end()) {
                // thread join has to ensure all the other incomming nodes are present in the skeleton
                continue;
            }

            if (!can_enable_visit(graph, static_id, next_tid, cfg_event.get_instruction_id())) {
                // invarient: visit id must be increment of previous visit ids
                continue;
            }

            if (!are_all_cross_thread_pred_sources_present(graph, static_id, next_tid)) {
                // invarient: TODO?
                continue;
            }
            
            auto e_copy = std::make_unique<Event>(cfg_event);
            if (next_tid == source_tid) {
                const int new_visit_id = graph->get_next_visit_id(next_tid, e_copy->get_instruction_id());
                e_copy->set_visit_id(new_visit_id);
                
                // if (!are_required_same_thread_preds_present_for_visit(graph, static_id, next_tid, new_visit_id)) {
                //         continue;
                // }
                } else {
                    const int new_visit_id = graph->get_next_visit_id(next_tid, e_copy->get_instruction_id());
                
                // if (!are_required_same_thread_preds_present_for_visit(graph, static_id, next_tid, new_visit_id)) {
                //         continue;
                // }
                e_copy->set_visit_id(new_visit_id);
            }

            const Event* parent = &source_event;
            //Made the const_cast<Event*>(parent) -> {const_cast<Event*>(parent)} (vector)
            source_candidates.push_back({std::move(e_copy), {const_cast<Event*>(parent)}});
        }

        if (source_candidates.empty()) {
            continue;
        }

        for (auto& candidate : source_candidates) {
            push_enabled(std::move(candidate.event), candidate.parents);//changed call name from candidate.parent to candidate.parents
        }
    }

    return enabled;
}

// TODO: Need clear revision
static int score_events_phase0(SkeletonGraph* graph, const std::vector<CandidateEvent>& enabled) {
    u8 GUIDE_PICKING_NEW_NODE = GET_NEW_NODE_GUIDE::mo_freq;

    if (GUIDE_PICKING_NEW_NODE == GET_NEW_NODE_GUIDE::random_new_node) {
        // Prefer first-visit writes over loop-iteration writes.
        // This prevents loop back-edges from starving reads in other threads.
        std::vector<int> first_visit_writes;
        for (size_t i = 0; i < enabled.size(); ++i) {
            if (enabled[i].event &&
                enabled[i].event->get_event_type() == Event_Type::WRITE &&
                enabled[i].event->get_visit_id() == 1) {
                first_visit_writes.push_back((int)i);
            }
        }
        if (!first_visit_writes.empty()) {
            return first_visit_writes[(int)skel_rand_below((u32)first_visit_writes.size())];
        }

        // No first-visit writes: prefer reads/fences before loop-iteration writes.
        int read_idx = pick_random_index_for_type(enabled, Event_Type::READ);
        if (read_idx >= 0) return read_idx;

        int write_idx = pick_random_index_for_type(enabled, Event_Type::WRITE);
        if (write_idx >= 0) return write_idx;

        int rmw_idx = pick_random_index_for_type(enabled, Event_Type::RMW);
        if (rmw_idx >= 0) return rmw_idx;
    } else if (GUIDE_PICKING_NEW_NODE == GET_NEW_NODE_GUIDE::mo_freq) {
        // mo_freq scoring for writes/RMWs, but first-visit events only.
        // Loop-iteration events (visit_id > 1) are tried last, after reads/fences,
        // so that all threads can make forward progress before loops repeat.
        int min = -1;
        int chosen_index = -1;
        int total_freq = 0;

        // tie_count tracks how many candidates share the current minimum frequency,
        // enabling uniform random tie-breaking via reservoir sampling so that every
        // mutation of the same graph does NOT deterministically pick the same event.
        int tie_count = 0;

        auto process_type = [&](Event_Type type, bool first_visit_only) {
            for (size_t i = 0; i < enabled.size(); ++i) {
                const auto& candidate = enabled[i];
                if (!candidate.event || candidate.event->get_event_type() != type) {
                    continue;
                }
                if (first_visit_only && candidate.event->get_visit_id() > 1) {
                    continue;
                }

                auto loc = candidate.event->get_location();
                auto mo_last_w_loc = graph->get_mo_last_event(loc);
                auto freq_molast_e = 0;
                if (mo_last_w_loc != nullptr) {
                    //creating EventTriples for both the events
                    EventTriple mo_last_w_loc_triple = {mo_last_w_loc->get_thread_id(), mo_last_w_loc->get_instruction_id(), mo_last_w_loc->get_visit_id()};

                    EventTriple candidate_event_triple = {candidate.event->get_thread_id(), candidate.event->get_instruction_id(), candidate.event->get_visit_id()};

                    freq_molast_e = get_mo_edge_freq(mo_last_w_loc_triple, candidate_event_triple);
                }
                total_freq += freq_molast_e;
                if (min == -1 || freq_molast_e < min) {
                    min = freq_molast_e;
                    chosen_index = (int)i;
                    tie_count = 1;
                } else if (freq_molast_e == min) {
                    // Reservoir sampling: replace with probability 1/(tie_count+1)
                    tie_count++;
                    if (skel_rand_below((u32)tie_count) == 0) {
                        chosen_index = (int)i;
                    }
                }
            }
        };

        // First pass: only first-visit writes/RMWs.
        process_type(Event_Type::WRITE, true);
        process_type(Event_Type::RMW, true);

        (void)total_freq;
        if (chosen_index >= 0) {
            return chosen_index;
        }

        // No first-visit writes found: try fences and reads so that threads
        // which still need their first-visit reads can make progress.
        int fence_idx = pick_random_index_for_type(enabled, Event_Type::FENCE);
        if (fence_idx >= 0) return fence_idx;

        int read_idx = pick_random_index_for_type(enabled, Event_Type::READ);
        if (read_idx >= 0) return read_idx;

        // Last resort: loop-iteration writes/RMWs (visit_id > 1).
        // To keep all threads in lock-step across iterations, only consider
        // events at the MINIMUM visit_id that is currently pending.
        // This prevents thread A from racing ahead to v3 while thread B is
        // still waiting to add its v2 events.
        int min_pending_visit = INT_MAX;
        for (const auto& candidate : enabled) {
            if (!candidate.event) continue;
            auto t = candidate.event->get_event_type();
            if (t != Event_Type::WRITE && t != Event_Type::RMW) continue;
            int vid = candidate.event->get_visit_id();
            if (vid > 1 && vid < min_pending_visit) {
                min_pending_visit = vid;
            }
        }

        if (min_pending_visit != INT_MAX) {
            // Score only among events at the minimum visit_id.
            min = -1;
            chosen_index = -1;
            total_freq = 0;
            tie_count = 0;
            for (size_t i = 0; i < enabled.size(); ++i) {
                const auto& candidate = enabled[i];
                if (!candidate.event) continue;
                auto t = candidate.event->get_event_type();
                if (t != Event_Type::WRITE && t != Event_Type::RMW) continue;
                if (candidate.event->get_visit_id() != min_pending_visit) continue;

                auto loc = candidate.event->get_location();
                auto mo_last_w_loc = graph->get_mo_last_event(loc);
                auto freq_molast_e = 0;
                if (mo_last_w_loc != nullptr) {
                    EventTriple mo_last_w_loc_triple = {mo_last_w_loc->get_thread_id(), mo_last_w_loc->get_instruction_id(), mo_last_w_loc->get_visit_id()};

                    EventTriple candidate_event_triple = {candidate.event->get_thread_id(), candidate.event->get_instruction_id(), candidate.event->get_visit_id()};

                    freq_molast_e = get_mo_edge_freq(mo_last_w_loc_triple, candidate_event_triple);

                    // I have changed this function to get_mo_edge_freq which takes EventTriple as input instead of get_mo_edge_frequency which takes individual thread_id, instruction_id and visit_id as input. So, I have commented the below code and added the new function call above.
                    // freq_molast_e = get_mo_edge_frequency(
                    //     mo_last_w_loc->get_thread_id(),
                    //     mo_last_w_loc->get_instruction_id(),
                    //     mo_last_w_loc->get_visit_id(),
                    //     candidate.event->get_thread_id(),
                    //     candidate.event->get_instruction_id(),
                    //     candidate.event->get_visit_id()
                    // );
                }
                total_freq += freq_molast_e;
                if (min == -1 || freq_molast_e < min) {
                    min = freq_molast_e;
                    chosen_index = (int)i;
                    tie_count = 1;
                } else if (freq_molast_e == min) {
                    tie_count++;
                    if (skel_rand_below((u32)tie_count) == 0) {
                        chosen_index = (int)i;
                    }
                }
            }
            (void)total_freq;
            if (chosen_index >= 0) {
                return chosen_index;
            }
        }
    }

    int fence_idx = pick_random_index_for_type(enabled, Event_Type::FENCE);
    if (fence_idx >= 0) return fence_idx;

    return pick_random_index_for_type(enabled, Event_Type::READ);
}

// TODO: Need clear revision
static int score_events_phase1(const std::vector<CandidateEvent>& enabled) {
    int read_idx = pick_random_index_for_type(enabled, Event_Type::READ);
    if (read_idx >= 0) return read_idx;

    int rmw_idx = pick_random_index_for_type(enabled, Event_Type::RMW);
    if (rmw_idx >= 0) return rmw_idx;

    int fence_idx = pick_random_index_for_type(enabled, Event_Type::FENCE);
    if (fence_idx >= 0) return fence_idx;

    return pick_random_index_for_type(enabled, Event_Type::WRITE);
}

//Changed the return type to accomodate vector<Event*> parents from Event*.
static std::pair<Event*, vector<Event*>> choose_event(std::vector<CandidateEvent>& enabled, int index) {
    if (index < 0 || index >= (int)enabled.size()) {
        return {nullptr, {}};//return empty vector instead of nullptr
    }

    Event* selected = enabled[index].event.release();
    vector<Event*> parents = enabled[index].parents;//Changed the call name from parent to parents
    return {selected, parents};
}

std::pair<Event*, vector<Event*>> get_a_new_event(SkeletonGraph* graph, int current_phase, struct SHM_next_events* current_feedback, bool skel_feedback_enabled, void* current_potential = nullptr, void* forbidden_mutations = nullptr) {
    if(!thread_counts_loaded){
        thread_counts_valid = load_thread_event_counts(expected_thread_counts); 
        thread_counts_loaded = true;
    }
    static bool initialized = false; // See if this is done properly or not. - Hardik
    std::vector<CandidateEvent> enabled;

    if(skel_feedback_enabled){
        if(current_feedback && current_feedback->ready){
            //begin_update();
            for(int i=0;i<current_feedback->next_event_count;i++){
                struct Shared_event* se=&current_feedback->next_events[i];
                EventID se_id = std::make_tuple(se->tid, se->iid, se->vid);
                if (forbidden_mutations) {
                    auto* fm = static_cast<const ForbiddenMutations*>(forbidden_mutations);
                    if (fm->is_event_id_forbidden(se_id)) {
                        continue;
                    }
                }
                CandidateEvent temp; 
                std::stringstream loc_stream;
                loc_stream << "0x" << std::hex << se->location;
                temp.event = std::make_unique<Event>(
                                se->tid,
                                static_cast<Access_Mode>(se->access_mode), 
                                static_cast<Event_Type>(se->event_type), 
                                loc_stream.str(),
                                se->iid,
                                se->vid
                            );

                //prining all elements in the events map
                // std::unordered_map<EventID, Event, TripleHash> events;
                // ACTF("Elements in events map of the skeleton graph: %d", graph->get_events().size());
                // for(auto e: graph->events){
                //     ACTF("Event details: t%d i%lld v%d type %d mode %d loc %s", e.second.get_thread_id(), e.second.get_instruction_id(), e.second.get_visit_id(), e.second.get_event_type(), e.second.get_access_mode(), e.second.get_location().c_str());
                // }

                for(int j=0;j<se->source_nodes_count;j++){
                    // ACTF("Pushing parent event %d", j);
                    // ACTF("Parent event details: t%d i%lld v%d", se->source_nodes[j].tid, se->source_nodes[j].iid, se->source_nodes[j].vid);
                    struct Event_id_triple *par=&(se->source_nodes[j]);
                    
                    Event *parent=graph->get_event_by_id(make_tuple(par->tid,par->iid,par->vid));
                    if(parent){
                        temp.parents.push_back(parent);
                    }else{
                        ACTF("parent event is null?");
                    }
                }
                // ACTF("[FEEDBACK-MUTATOR] Added event from feedback: t%d i%lld v%d type %d mode %d loc %s with %zu parents", se->tid, se->iid, se->vid, se->event_type, se->access_mode, loc_stream.str().c_str(), temp.parents.size());
                
                // ACTF("[FEEDBACK-MUTATOR] Number of Parent event IDs for this event from skel_feedback_data: %zu", se->source_nodes_count);
                
                // there can't be a case where the parents are null as we start from initilaization events as seed
                if(temp.parents.size() == 0){
                    assert(0 && "No parents found for the event from feedback");
                    exit(0);
                }

                enabled.push_back(std::move(temp));
                    
            }

            //finish_update();
            // We do not set ready to false here so that we can perform multiple mutations on the same parent graph in a single fuzzing cycle.
            // - Hardik
            // current_feedback->ready=false;

        } else {
            // ACTF("[FEEDBACK-MUTATOR] ENABLE_FEEDBACK is on, but no simulator cache is available; falling back to CFG");
            return {nullptr, {}};//return empty vector instead of nullptr
        } 
    } else{
        // ACTF("[FEEDBACK-MUTATOR] using CFG-derived next-event selection");
        //collect_enabled_events is called only if the feedback is not expected
        if (!initialized) {
            parse_program_abstraction(eg_file.string(), cfg_new);
            // TODO: will be done only if feedack is disabled, to do correctly after discussing for with feedback also.
            // Initializing potential cache 
            initialize_skeleton_potential_cache();
            initialized = true;
        }
        enabled = collect_enabled_events(graph, current_phase, forbidden_mutations);
    }

    if (enabled.empty()) {
        return {nullptr, {}};//return empty vector instead of nullptr
    }

    int selected_index = -1;
    // if (current_phase == 0) {
    //     selected_index = score_events_phase0(graph, enabled);
    //     } else if (current_phase == 1) {
    //         selected_index = score_events_phase1(enabled);
    // }

    if (selected_index < 0) {
        // 1. Group enabled candidate event indices by thread and classify spinning reads
        std::unordered_map<ThreadID, std::vector<int>> enabled_by_thread;
        std::vector<bool> is_spinning(enabled.size(), false);

        for (size_t i = 0; i < enabled.size(); ++i) {
            if (enabled[i].event) {
                ThreadID tid = enabled[i].event->get_thread_id();
                enabled_by_thread[tid].push_back(static_cast<int>(i));
                if (is_spinning_read_without_alternate_write(graph, enabled[i], current_potential)) {
                    is_spinning[i] = true;
                }
            }
        }

        // Check which threads have only spinning candidates vs at least one non-spinning candidate
        std::unordered_map<ThreadID, bool> thread_all_spinning;
        for (const auto& pair : enabled_by_thread) {
            bool all_spin = true;
            for (int idx : pair.second) {
                if (!is_spinning[idx]) {
                    all_spin = false;
                    break;
                }
            }
            thread_all_spinning[pair.first] = all_spin;
        }

        // 2. Compute weights for each enabled thread
        std::vector<std::pair<ThreadID, uint64_t>> thread_weights;
        uint64_t total_weight = 0;

        if (thread_counts_valid) {
            // Strategy A: If THREAD_EVENT_COUNTS is specified and valid, bias by remaining expected events
            const auto& po_map = graph->get_threadwise_po();
            for (const auto& pair : enabled_by_thread) {
                ThreadID tid = pair.first;
                int expected_count = 0;
                auto it = expected_thread_counts.find(tid);
                if (it != expected_thread_counts.end()) {
                    expected_count = it->second;
                }

                int current_count = 0;
                auto po_it = po_map.find(tid);
                if (po_it != po_map.end()) {
                    current_count = static_cast<int>(po_it->second.size());
                }

                uint64_t weight = static_cast<uint64_t>(std::max(0, expected_count - current_count));
                // If this thread only has spinning reads with no alternate write, scale down weight
                if (thread_all_spinning[tid] && weight > 1) {
                    weight = std::max<uint64_t>(1ULL, weight / 8);
                }
                thread_weights.push_back({tid, weight});
                total_weight += weight;
            }
        }

        if (total_weight == 0) {
            // Strategy B: MO-guided dynamic thread bias (when THREAD_EVENT_COUNTS is absent/invalid or exhausted)
            // BASE_WEIGHT = 1 ensures equal non-zero baseline probability for all enabled threads
            thread_weights.clear();
            total_weight = 0;
            const uint64_t BASE_WEIGHT = 1;

            for (const auto& pair : enabled_by_thread) {
                ThreadID tid = pair.first;
                uint64_t weight = BASE_WEIGHT + get_mo_thread_weight(tid);
                // If this thread only has spinning reads with no alternate write, scale down weight
                if (thread_all_spinning[tid] && weight > 1) {
                    weight = std::max<uint64_t>(1ULL, weight / 8);
                }
                thread_weights.push_back({tid, weight});
                total_weight += weight;
            }
        }

        // 3. Sample a thread proportionally to its weight, then pick a candidate from that thread
        // (giving non-spinning candidates 10x weight over spinning candidates within the chosen thread)
        if (total_weight > 0) {
            u32 r = skel_rand_below(static_cast<u32>(total_weight));
            uint64_t cumulative = 0;
            ThreadID selected_tid = -1;
            for (const auto& tw : thread_weights) {
                cumulative += tw.second;
                if (r < cumulative) {
                    selected_tid = tw.first;
                    break;
                }
            }

            if (selected_tid != -1) {
                const auto& event_indices = enabled_by_thread[selected_tid];
                if (!event_indices.empty()) {
                    // Weighted selection within the thread: prefer non-spinning candidates
                    std::vector<std::pair<int, uint32_t>> candidate_weights;
                    uint32_t thread_cand_total = 0;
                    for (int ev_idx : event_indices) {
                        uint32_t w = is_spinning[ev_idx] ? 1 : 10;
                        candidate_weights.push_back({ev_idx, w});
                        thread_cand_total += w;
                    }

                    u32 r_cand = skel_rand_below(thread_cand_total);
                    uint32_t cand_cum = 0;
                    for (const auto& cw : candidate_weights) {
                        cand_cum += cw.second;
                        if (r_cand < cand_cum) {
                            selected_index = cw.first;
                            break;
                        }
                    }
                }
            }
        }

        // Fallback: Uniform random selection if no thread was chosen
        if (selected_index < 0) {
            selected_index = skel_rand_below(static_cast<u32>(enabled.size()));
        }
    }
    return choose_event(enabled, selected_index);
}

SkeletonGraph* add_new_node(SkeletonGraph* graph, int current_phase, void* current_potential, struct SHM_next_events* current_feedback, bool is_feedback_enabled, void* forbidden_mutations) {
    /*
    * FINDING NODE TO ADD LOGIC
    * Retrieve an event from the program abstraction or using feedback if in feedback mode.
    */

    auto new_event_with_parent = get_a_new_event(graph, current_phase, current_feedback, is_feedback_enabled, current_potential, forbidden_mutations);
    std::unique_ptr<Event> new_event(new_event_with_parent.first);
    if(!new_event){
        // ACTF("No new event to add to the skeleton graph");
        last_mutation_info.kind = MUT_NONE;
        return graph;
    }else{
        // ACTF("There is a new event to add to the skeleton graph");
    }

    if (forbidden_mutations) {
        auto* fm = static_cast<const ForbiddenMutations*>(forbidden_mutations);
        if (fm->is_event_forbidden(EventTriple{new_event->get_thread_id(), new_event->get_instruction_id(), new_event->get_visit_id()})) {
            last_mutation_info.kind = MUT_NONE;
            return graph;
        }
    }

    //changed the variable name from parent to parents
    auto parent_nodes = new_event_with_parent.second;
    // changed the datatype from EventID to vector as there will be multiple parent_event_ids
    vector<EventID> parent_event_ids;
    bool has_parent_node = false;
    if (!parent_nodes.empty()) { // Changed from !=nullptr to !empty()
        for(auto par:parent_nodes){
            if(par){
                parent_event_ids.push_back(par->get_event_id());
            }
        }
        has_parent_node = true;
    }

    /*
    * NODE ADDITION
    * Adding respective node to the skeleton graph.
    */

    if(new_event->get_event_type() == Event_Type::CAS){
        if(skel_rand_below(2) == 0){
            new_event->set_event_type(Event_Type::CAS_SUCCESS);
        }else{
            new_event->set_event_type(Event_Type::CAS_FAILURE);
        }
    }

    // add the event to the skeleton graph
    graph -> add_event(*new_event);
    // log the explored location of the new event
    log_explored_location(new_event->get_thread_id(), new_event->get_location());
    
    const Event* parent_event = nullptr;
    if (!parent_nodes.empty() && parent_nodes[0] != nullptr) {
        parent_event = parent_nodes[0];
    }
    set_mutation_info_from_event(new_event.get(), parent_event);

    /*
    * EDGES ADDITION LOGIC
    * Adding respective edges to the skeleton graph based on the event type and its parents.
    */

    // adding it to po_per_thread map (no need to add_po since it's derived from threadwise_po)
    graph -> add_po_threadwise(new_event->get_thread_id(), new_event->get_event_id());

    // Cross-thread incoming TCJ edges are added in add_cfg_incoming_tcj_edges().
    // Do not add a direct parent-based SW here: parent_event_id is CFG-static and
    // can point to an older visit, creating duplicate/stale SW edges.
    add_cfg_incoming_tcj_edges(graph, *new_event, parent_nodes);

    if(new_event->get_event_type() == Event_Type::READ || new_event->get_event_type() == Event_Type::CAS_FAILURE){
        //add rf edge
        
        auto consistent_writes = get_consistent_writes(*graph,
                                   *parent_nodes[0],/*Giving only one event among all the parents as the potential for all is the same*/
                                   new_event->get_location(),
                                   current_potential,
                                   new_event->get_event_type() == Event_Type::RMW || new_event->get_event_type() == Event_Type::CAS_SUCCESS);

                EventID write_event_id = std::make_tuple(-1, -1, -1);
                const Event* write_event = nullptr;

        if(!consistent_writes.empty()){
            EventID prev_write_id = std::make_tuple(-1, -1, -1);
            bool has_prev_write = false;
            if (new_event->get_visit_id() > 1 && !parent_nodes.empty() && parent_nodes[0] != nullptr) {
                if (parent_nodes[0]->get_thread_id() == new_event->get_thread_id() &&
                    parent_nodes[0]->get_instruction_id() == new_event->get_instruction_id()) {
                    auto rf_rev_it = graph->get_rf_reverse().find(parent_nodes[0]->get_event_id());
                    if (rf_rev_it != graph->get_rf_reverse().end() && !rf_rev_it->second.empty()) {
                        prev_write_id = rf_rev_it->second.front();
                        has_prev_write = true;
                    }
                }
            }

            write_event_id = choose_write_weighted(consistent_writes, prev_write_id, has_prev_write);
            write_event = graph->get_event_by_id(write_event_id);
            graph -> add_rf(write_event_id, new_event->get_event_id());

            //REVISIT: Checking the coverage when I choose the new event at random - this is temporary
            if (write_event != nullptr) {
                update_rf_coverage(write_event->get_thread_id(), write_event->get_instruction_id(), write_event->get_visit_id(), 
                                   new_event->get_thread_id(), new_event->get_instruction_id(), new_event->get_visit_id());
            }

        } else {
            auto new_ev_id = new_event->get_event_id();
            // cout << "No consistent writes found for the read event [" << std::get<0>(new_ev_id) << "," << std::get<1>(new_ev_id) << "," << std::get<2>(new_ev_id) << "]" << endl;
        }

        // add sw edges for acquire-like reads from release write/fence chains
        if (is_acquire_like_mode(new_event->get_access_mode()) && write_event != nullptr) {
            add_release_chain_sw_to_acquire(graph, *write_event, new_event->get_event_id());
        }
    } else if(new_event->get_event_type() == Event_Type::WRITE){
        //add the event to mo ordered map
        const Event* last_event = graph -> get_mo_last_event(new_event->get_location());
        graph -> add_mo(new_event->get_event_id(), new_event->get_location());
        
        //REVISIT: Checking the coverage when I choose the new event at random - this is temporary
        if(last_event != nullptr){
            EventID last_event_id = last_event->get_event_id();
            EventTriple last_event_triple = {std::get<0>(last_event_id), std::get<1>(last_event_id), std::get<2>(last_event_id)};
            EventTriple new_event_triple = {std::get<0>(new_event->get_event_id()), std::get<1>(new_event->get_event_id()), std::get<2>(new_event->get_event_id())};
            
            update_mo_coverage(last_event_triple, new_event_triple);
            record_mo_thread_bias(graph, last_event, new_event.get());
        }

    } else if(new_event->get_event_type() == Event_Type::FENCE){
        //add sw edge if applicable
        
        auto& po_edges_in_thread = graph -> get_threadwise_po()[new_event -> get_thread_id()];
        if(!po_edges_in_thread.empty()){
            //find the position of the new event in the po_threadwise vector and look at the previous events from there
            auto pos_it = std::find(po_edges_in_thread.begin(), po_edges_in_thread.end(), new_event -> get_event_id());
            if(pos_it != po_edges_in_thread.end()){
                //looking at the previous events in the po order
                auto prev_it = std::make_reverse_iterator(pos_it);
                for(; prev_it != po_edges_in_thread.rend(); ++prev_it){
                    auto prev_event_id = *prev_it;
                    if(!(graph -> get_rf_reverse()[prev_event_id].empty())){
                        auto write_event_id = graph -> get_rf_reverse()[prev_event_id][0];
                        auto write_event = graph -> get_event_by_id(write_event_id);

                        if(write_event != nullptr){

                            //case 1: W_rel --sw-->  F_acq when there is a W_rel --rf--> R --po--> F_acq 
                            if(write_event -> get_access_mode() >= Access_Mode::RELEASE){
                                graph -> add_sw(write_event_id, new_event -> get_event_id());
                            
                            }else{
                                //case 2: F_rel --sw--> F_acq when there is a F_rel --po--> W --rf--> R --po--> F_acq
                                auto& po_edges_in_thread = graph -> get_threadwise_po()[write_event -> get_thread_id()];
                                if(!po_edges_in_thread.empty()){
                                    //find the position of the write event in the po_threadwise vector and look at the previous events from there
                                    auto pos_it = std::find(po_edges_in_thread.begin(), po_edges_in_thread.end(), write_event_id);
                                    if(pos_it != po_edges_in_thread.end()){
                                        auto prev_it = std::make_reverse_iterator(pos_it);
                                        for(; prev_it != po_edges_in_thread.rend(); ++prev_it){
                                            auto prev_event_id = *prev_it;
                                            auto prev_event = graph -> get_event_by_id(prev_event_id);
                                            if(prev_event != nullptr && prev_event -> get_event_type() == Event_Type::FENCE && (prev_event -> get_access_mode() >= Access_Mode::RELEASE)){
                                                graph -> add_sw(prev_event_id, new_event -> get_event_id());
                                            }    
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if(new_event->get_event_type() == Event_Type::RMW || new_event->get_event_type() == Event_Type::CAS_SUCCESS){
        //add rf edge
        auto consistent_writes = get_consistent_writes(*graph, *parent_nodes[0], new_event->get_location(), current_potential, new_event->get_event_type() == Event_Type::RMW || new_event->get_event_type() == Event_Type::CAS_SUCCESS);

        EventID write_event_id = std::make_tuple(-1, -1, -1);
        const Event* write_event = nullptr;

        if(!consistent_writes.empty()){
            EventID prev_write_id = std::make_tuple(-1, -1, -1);
            bool has_prev_write = false;
            if (new_event->get_visit_id() > 1 && !parent_nodes.empty() && parent_nodes[0] != nullptr) {
                if (parent_nodes[0]->get_thread_id() == new_event->get_thread_id() &&
                    parent_nodes[0]->get_instruction_id() == new_event->get_instruction_id()) {
                    auto rf_rev_it = graph->get_rf_reverse().find(parent_nodes[0]->get_event_id());
                    if (rf_rev_it != graph->get_rf_reverse().end() && !rf_rev_it->second.empty()) {
                        prev_write_id = rf_rev_it->second.front();
                        has_prev_write = true;
                    }
                }
            }

            write_event_id = choose_write_weighted(consistent_writes, prev_write_id, has_prev_write);
            write_event = graph->get_event_by_id(write_event_id);
            graph -> add_rf(write_event_id, new_event->get_event_id());
            
            //REVISIT: Checking the coverage when I choose the new event at random - this is temporary
            if (write_event != nullptr) {
                update_rf_coverage(write_event->get_thread_id(), write_event->get_instruction_id(), write_event->get_visit_id(), 
                                new_event->get_thread_id(), new_event->get_instruction_id(), new_event->get_visit_id());
            }
        } else {
            auto new_ev_id = new_event->get_event_id();
            cout << "No consistent writes found for the read event [" << std::get<0>(new_ev_id) << "," << std::get<1>(new_ev_id) << "," << std::get<2>(new_ev_id) << "]" << endl;
        }

        // add sw edges for acquire-like RMW or cas from release write/fence chains
        if (is_acquire_like_mode(new_event->get_access_mode()) && write_event != nullptr) {
            add_release_chain_sw_to_acquire(graph, *write_event, new_event->get_event_id());
        }

        //add the event to mo ordered map
        auto prev_last_event = graph -> get_mo_last_event(new_event->get_location());
        graph -> add_mo(new_event->get_event_id(), new_event->get_location());

        
        //REVISIT: Checking the coverage when I choose the new event at random - this is temporary
        // if(prev_last_event != nullptr){
            // update_mo_coverage(prev_last_event->get_thread_id(), prev_last_event->get_instruction_id(), prev_last_event->get_visit_id(),
                            //    new_event->get_thread_id(), new_event->get_instruction_id(), new_event->get_visit_id());
            // EventID prev_last_event_id = prev_last_event->get_event_id();
            // EventTriple prev_last_event_triple = {std::get<0>(prev_last_event_id), std::get<1>(prev_last_event_id), std::get<2>(prev_last_event_id)};
            // EventTriple new_event_triple = {std::get<0>(new_event->get_event_id()), std::get<1>(new_event->get_event_id()), std::get<2>(new_event->get_event_id())};
            
            // Moved this logic to sgf-fuzz-one 
            // Reason: We want to update the frequency only after checking for duplicates in SG wrt the corpus 
            // update_mo_coverage(prev_last_event_triple, new_event_triple);
        // }

    }

    // Finalize to rebuild event_index with correct indices after all adds complete
    // Should not be required if we add the edges properly.
    graph->finalize();

    return graph;
}
