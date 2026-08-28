#include "skeleton_potential.hpp"
#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#include "consistency.hpp"
#include "static_program_abstraction.hpp"
#include "skeleton_graph_mutator_wrapper.h"
#include "debug.h"
#include <queue>
#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cmath>

static std::unordered_map<int, std::unordered_set<std::string>> g_potential_locations;
static bool g_potential_locations_loaded = false;

static std::unordered_set<std::string> g_interesting_locations;
static bool g_interesting_locations_loaded = false;
static bool g_interesting_locations_valid = false;

static void load_interesting_locations() {
    if (g_interesting_locations_loaded) return;
    g_interesting_locations_loaded = true;
    
    char* filepath = getenv("SGF_INTERESTING_LOCATIONS_FILE");
    if (!filepath) {
        return;
    }
    
    std::ifstream file(filepath);
    if (!file.is_open()) {
        WARNF("Failed to open interesting locations file: %s", filepath);
        return;
    }
    
    g_interesting_locations.clear();
    std::string line;
    while (std::getline(file, line)) {
        // Remove comments starting with '#'
        size_t hash_pos = line.find('#');
        if (hash_pos != std::string::npos) {
            line = line.substr(0, hash_pos);
        }
        
        // Trim leading and trailing whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue; // line is empty or only whitespace
        }
        size_t end = line.find_last_not_of(" \t\r\n");
        std::string loc = line.substr(start, end - start + 1);
        if (!loc.empty()) {
            g_interesting_locations.insert(loc);
        }
    }
    
    ACTF("Loaded %zu interesting locations from %s", g_interesting_locations.size(), filepath);
    g_interesting_locations_valid = true;
    file.close();
}

bool is_interesting_locations_valid(void) {
    if (!g_interesting_locations_loaded) {
        load_interesting_locations();
    }
    return g_interesting_locations_valid;
}

const std::unordered_set<std::string>& get_interesting_locations(void) {
    if (!g_interesting_locations_loaded) {
        load_interesting_locations();
    }
    return g_interesting_locations;
}

size_t SkeletonPotential::total_writes() const {
    bool use_interesting = is_interesting_locations_valid();
    const auto& interesting_locs = get_interesting_locations();
    
    size_t count = 0;
    for (const auto& [_, location_map] : threads) {
        for (const auto& [location, write_set] : location_map) {
            if (use_interesting && !interesting_locs.count(location)) {
                continue;
            }
            count += write_set.size();
        }
    }
    return count;
}


static void load_potential_locations(const char* filepath) {
    if (!filepath) {
        g_potential_locations_loaded = true;
        return;
    }
    g_potential_locations_loaded = true;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        WARNF("Failed to open potential locations file: %s", filepath);
        return;
    }
    
    g_potential_locations.clear();
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;
        
        std::string tid_str = line.substr(0, colon_pos);
        int thread_id = std::stoi(tid_str);
        
        std::string locs_str = line.substr(colon_pos + 1);
        std::stringstream ss(locs_str);
        std::string loc;
        while (ss >> loc) {
            if (!loc.empty()) {
                g_potential_locations[thread_id].insert(loc);
            }
        }
    }
    ACTF("Loaded potential locations for %zu threads from %s", g_potential_locations.size(), filepath);
    g_potential_locations_loaded = true;
    file.close();
}

using FutureReadCacheKey = std::pair<int, long long>;

static std::unordered_map<FutureReadCacheKey, std::unordered_set<std::string>, pair_hash> g_future_read_cache;
static bool g_future_read_cache_ready = false;

static std::unordered_set<std::string> find_future_read_locations_from_static_event(int start_static_event_id) {
    std::unordered_set<std::string> future_read_locations;
    std::queue<int> to_visit;
    std::unordered_set<int> visited;

    auto start_node_it = cfg_new.nodes.find(start_static_event_id);
    if (start_node_it == cfg_new.nodes.end()) {
        return future_read_locations;
    }

    for (int succ_id : start_node_it->second.succ) {
        to_visit.push(succ_id);
    }

    while (!to_visit.empty()) {
        int current_static_event_id = to_visit.front();
        to_visit.pop();

        if (visited.count(current_static_event_id)) {
            continue;
        }
        visited.insert(current_static_event_id);

        auto node_it = cfg_new.nodes.find(current_static_event_id);
        if (node_it == cfg_new.nodes.end()) {
            continue;
        }

        const Event& current_event = node_it->second.event;
        if (current_event.get_event_type() == Event_Type::READ ||
            current_event.get_event_type() == Event_Type::CAS_FAILURE ||
            current_event.get_event_type() == Event_Type::RMW ||
            current_event.get_event_type() == Event_Type::CAS_SUCCESS) {
            future_read_locations.insert(current_event.get_location());
        }

        for (int succ_id : node_it->second.succ) {
            to_visit.push(succ_id);
        }
    }

    return future_read_locations;
}

static void build_future_read_cache() {
    if (g_future_read_cache_ready) {
        return;
    }

    if (cfg_new.nodes.empty() && !eg_file.empty()) {
        parse_program_abstraction(eg_file.string(), cfg_new);
    }

    g_future_read_cache.clear();

    char* fb = getenv("SGF_ENABLE_FEEDBACK");
    bool feedback_enabled = (fb != nullptr && std::atoi(fb) > 0);

    if (feedback_enabled) {
        if (!g_potential_locations_loaded) {
            char* fb_locs = getenv("SGF_POTENTIAL_LOCATIONS_FILE");
            load_potential_locations(fb_locs);
        }
        bool use_file_locations = !g_potential_locations.empty();
        if (use_file_locations) {
            for (const auto& [start_static_event_id, node] : cfg_new.nodes) {
                const Event& start_event = node.event;
                FutureReadCacheKey key = {
                    static_cast<int>(start_event.get_thread_id()),
                    start_event.get_instruction_id()
                };
                int tid = key.first;
                auto it = g_potential_locations.find(tid);
                if (it != g_potential_locations.end()) {
                    g_future_read_cache[key] = it->second;
                } else {
                    g_future_read_cache[key] = std::unordered_set<std::string>();
                }
            }
        } else {
            WARNF("Feedback enabled but no potential locations loaded; falling back to static CFG locations.");
            for (const auto& [start_static_event_id, node] : cfg_new.nodes) {
                const Event& start_event = node.event;
                FutureReadCacheKey key = {
                    static_cast<int>(start_event.get_thread_id()),
                    start_event.get_instruction_id()
                };
                g_future_read_cache[key] = find_future_read_locations_from_static_event(start_static_event_id);
            }
        }
    } else {
        for (const auto& [start_static_event_id, node] : cfg_new.nodes) {
            const Event& start_event = node.event;
            FutureReadCacheKey key = {
                static_cast<int>(start_event.get_thread_id()),
                start_event.get_instruction_id()
            };
            g_future_read_cache[key] = find_future_read_locations_from_static_event(start_static_event_id);
        }
    }

    g_future_read_cache_ready = true;
}

static const std::unordered_set<std::string>& get_cached_future_read_locations(const FutureReadCacheKey& key) {
    static const std::unordered_set<std::string> empty;
    build_future_read_cache();

    auto it = g_future_read_cache.find(key);
    if (it == g_future_read_cache.end()) {
        return empty;
    }
    return it->second;
}

extern "C" void initialize_skeleton_potential_cache(void) {
    build_future_read_cache();
    if (!g_interesting_locations_loaded) {
        load_interesting_locations();
    }
}

 /* 
 * Helper: convert Event to WriteKey
 */
static WriteKey event_to_write_key(const Event& event) {
    return WriteKey{
        event.get_instruction_id(),
        static_cast<uint32_t>(event.get_thread_id()),
        static_cast<uint32_t>(event.get_visit_id())
    };
}

/**
 * @brief Compute the symmetric difference size between two write sets.
 * 
 * Optimized to iterate over the smaller set for better cache locality
 * and reduced lookup operations.
 * 
 * Complexity: O(min(|A|, |B|) + max(|A|, |B|))
 * 
 * @param A First write set
 * @param B Second write set
 * @return Size of symmetric difference
 */
size_t symmetric_difference_size(const WriteSet& A, const WriteSet& B) {
    if (A.empty() && B.empty()) {
        return 0;
    }
    
    if (A.size() < B.size()) {
        // Iterate over smaller set A
        size_t diff = 0;
        
        // Count elements in A not in B
        for (const auto& w : A) {
            if (!B.count(w)) {
                ++diff;
            }
        }
        
        // Count elements in B not in A
        size_t b_unique = B.size() - (A.size() - diff);
        diff += b_unique;
        
        return diff;
    } else {
        // Iterate over smaller set B
        size_t diff = 0;
        
        // Count elements in B not in A
        for (const auto& w : B) {
            if (!A.count(w)) {
                ++diff;
            }
        }
        
        // Count elements in A not in B
        size_t a_unique = A.size() - (B.size() - diff);
        diff += a_unique;
        
        return diff;
    }
}

/**
 * @brief Compare two skeleton graphs and compute their total difference.
 * 
 * Iterates through all threads present in either skeleton and computes
 * the symmetric difference for each thread's write set, summing the results.
 * 
 * Complexity: O(T * S) where T is the number of unique threads
 * and S is the average number of writes per thread.
 * 
 * @param A First skeleton
 * @param B Second skeleton
 * @return Total symmetric difference size across all threads
 */
// REVISIT TODO :Check whether i am calculating potential difference as expected.
double compare_skeletons(const SkeletonPotential& A,
                         const SkeletonPotential& B) {
    double total_diff = 0;

    bool use_interesting = is_interesting_locations_valid();
    const auto& interesting_locs = get_interesting_locations();

    const auto& threadsA = A.get_all_threads();
    const auto& threadsB = B.get_all_threads();

    // 1. Process threads in A
    for (const auto& [tid, locMapA] : threadsA) {
        auto b_thread_it = threadsB.find(tid);
        if (b_thread_it != threadsB.end()) {
            // Thread exists in both, compare locations
            const auto& locMapB = b_thread_it->second;

            // Locations in A
            for (const auto& [location, writeSetA] : locMapA) {
                if (use_interesting && !interesting_locs.count(location)) {
                    continue;
                }
                auto b_loc_it = locMapB.find(location);
                if (b_loc_it != locMapB.end()) {
                    total_diff += symmetric_difference_size(writeSetA, b_loc_it->second);
                } else {
                    total_diff += writeSetA.size();
                }
            }

            // Locations in B but not in A
            for (const auto& [location, writeSetB] : locMapB) {
                if (use_interesting && !interesting_locs.count(location)) {
                    continue;
                }
                if (locMapA.find(location) == locMapA.end()) {
                    total_diff += writeSetB.size();
                }
            }
        } else {
            // threads only in A, all its writes are part of diff
            for (const auto& [location, writeSetA] : locMapA) {
                if (use_interesting && !interesting_locs.count(location)) {
                    continue;
                }
                total_diff += writeSetA.size();
            }
        }
    }

    // 2. Process threads in B but not in A
    for (const auto& [tid, locMapB] : threadsB) {
        if (threadsA.find(tid) == threadsA.end()) {
            for (const auto& [location, writeSetB] : locMapB) {
                if (use_interesting && !interesting_locs.count(location)) {
                    continue;
                }
                total_diff += writeSetB.size();
            }
        }
    }

    // Symmetric Jaccard Distance Normalization:
    // |A \cup B| = (|A| + |B| + |A \triangle B|) / 2
    // Ensures compare_skeletons(A, B) is symmetric, strictly in [0.0, 100.0],
    // and doesn't artificially explode or collapse when |A| is small.
    size_t total_writes_a = A.total_writes();
    size_t total_writes_b = B.total_writes();
    size_t union_size = (total_writes_a + total_writes_b + static_cast<size_t>(total_diff)) / 2;
    if (union_size == 0) {
        return 0.0;
    }
    double normalized_diff =
        100.0 * static_cast<double>(total_diff) /
        static_cast<double>(union_size);

    if (normalized_diff > 100.0) normalized_diff = 100.0;
    if (normalized_diff < 0.0) normalized_diff = 0.0;

    return normalized_diff;
}

void LiveLocationAnalyzer::analyze(const SkeletonGraph& graph) {
    const auto& threadwise_po = graph.get_threadwise_po();
    
    // For each thread, analyze its program order
    for (const auto& [thread_id, thread_events] : threadwise_po) {
        LocationEventInfo info;
        info.total_events = thread_events.size();
        
        // First pass: collect which events access which locations
        for (size_t event_idx = 0; event_idx < thread_events.size(); ++event_idx) {
            auto event_id = thread_events[event_idx];
            const Event* ev = graph.get_event_by_id(event_id);
            
            if (!ev) continue;
            
            // Collect location if this is a read/write/rmw
            if (ev->get_event_type() == Event_Type::READ ||
                ev->get_event_type() == Event_Type::CAS_FAILURE ||
                ev->get_event_type() == Event_Type::WRITE ||
                ev->get_event_type() == Event_Type::RMW ||
                ev->get_event_type() == Event_Type::CAS_SUCCESS) {
                std::string loc = ev->get_location();
                info.location_events[loc].push_back(event_idx);
            }
        }
        
        thread_info[thread_id] = info;
        
        // Second pass: for each event position, compute live locations
        for (size_t pos = 0; pos < thread_events.size(); ++pos) {
            std::unordered_set<std::string> live_locs;
            
            // Check which locations have events after this position
            for (const auto& [loc, event_indices] : info.location_events) {
                // A location is live from position `pos` if there's any event
                // accessing it at position > pos (i.e., in the future)
                for (size_t idx : event_indices) {
                    if (idx > pos) {
                        live_locs.insert(loc);
                        break;  // Found a future event, mark location as live
                    }
                }
            }
            
            uint64_t cache_key = make_cache_key(thread_id, pos);
            live_locations_cache[cache_key] = live_locs;
        }
    }
}

const std::unordered_set<std::string>& LiveLocationAnalyzer::get_live_locations(
    uint32_t thread_id, size_t event_position) const {
    
    uint64_t cache_key = make_cache_key(thread_id, event_position);
    auto it = live_locations_cache.find(cache_key);
    
    if (it != live_locations_cache.end()) {
        return it->second;
    }
    
    static std::unordered_set<std::string> empty;
    return empty;
}

bool LiveLocationAnalyzer::is_location_live(uint32_t thread_id, size_t event_position,
                                            const std::string& location) const {
    const auto& live_locs = get_live_locations(thread_id, event_position);
    return live_locs.count(location) > 0;
}

/**
 * @brief Calculate potential for a single thread in Mode 2.
 * 
 * Considers ALL live locations (not just a single next read location):
 * 1. Get all cached future read locations from the current point in the thread
 * 2. For each location, find all potential writes to it from other threads
 * 3. Add these writes to the per-location potential map
 */
static LocationWriteMap calculate_thread_potential(
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer,
    uint32_t thread_id) {

    (void)analyzer;
    LocationWriteMap thread_potential;
    const auto& threadwise_po = graph.get_threadwise_po();
    
    auto thread_it = threadwise_po.find(thread_id);
    if (thread_it == threadwise_po.end() || thread_it->second.empty()) {
        return thread_potential;
    }
    
    const auto& thread_events = thread_it->second;
    const EventID& last_event_id = thread_events.back();
    const Event* last_event = graph.get_event_by_id(last_event_id);
    if (!last_event) {
        return thread_potential;
    }

    FutureReadCacheKey cache_key = {
        static_cast<int>(last_event->get_thread_id()),
        last_event->get_instruction_id()
    };
    const auto& future_locations = get_cached_future_read_locations(cache_key);

    for (const std::string& location : future_locations) {
        WriteSet new_writes;
        // we calculate potential considering the locations are read generally and do the check for rmw later.
        std::set<EventID> consistent_writes = find_consistent_writes(graph, *last_event, location, false);
        for (const EventID& write_event_id : consistent_writes) {
            const Event* write_event = graph.get_event_by_id(write_event_id);
            if (!write_event) {
                continue;
            }
            if (write_event->get_event_type() == Event_Type::WRITE ||
                write_event->get_event_type() == Event_Type::RMW ||
                write_event->get_event_type() == Event_Type::CAS_SUCCESS) {
                new_writes.insert(event_to_write_key(*write_event));
            }
        }
        thread_potential.emplace(location, std::move(new_writes));
    }
    
    return thread_potential;
}

SkeletonPotential calculate_skeleton_potential(
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer) {
    
    SkeletonPotential potential;
    const auto& threadwise_po = graph.get_threadwise_po();
    
    // For each thread, calculate its potential based on live locations
    for (const auto& [thread_id, _] : threadwise_po) {
        LocationWriteMap thread_locations = calculate_thread_potential(graph, analyzer, thread_id);
        potential.set_thread(thread_id, std::move(thread_locations));
    }
    
    return potential;
}

void update_potential_on_read_addition(
    SkeletonPotential& potential,
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer,
    uint32_t added_thread_id) {
    
    LocationWriteMap thread_locations = calculate_thread_potential(graph, analyzer, added_thread_id);
    potential.set_thread(added_thread_id, std::move(thread_locations));
}

void update_potential_on_write_addition(
    SkeletonPotential& potential,
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer,
    const WriteKey& added_write,
    uint32_t added_thread_id,
    const std::string& location) {
    
    // For all other threads, add this write if they have this location cached
    const auto& threadwise_po = graph.get_threadwise_po();
    for (const auto& [thread_id, thread_events] : threadwise_po) {
        if (thread_id == added_thread_id) continue;

        if (thread_events.empty()) {
            continue;
        }

        const auto& thread_locations = potential.get_thread(thread_id);
        auto loc_it = thread_locations.find(location);
        if (loc_it != thread_locations.end()) {
            WriteSet updated_writes = loc_it->second;
            updated_writes.insert(added_write);
            potential.set_location(thread_id, location, std::move(updated_writes));
        }
    }
    
    // Recalculate potential for the thread where the write was added
    LocationWriteMap thread_locations = calculate_thread_potential(graph, analyzer, added_thread_id);
    potential.set_thread(added_thread_id, std::move(thread_locations));
}

void update_potential_on_fence_addition(
    SkeletonPotential& potential,
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer,
    uint32_t added_thread_id) {
    
    LocationWriteMap thread_locations = calculate_thread_potential(graph, analyzer, added_thread_id);
    potential.set_thread(added_thread_id, std::move(thread_locations));
}

void update_potential_on_rmw_addition(
    SkeletonPotential& potential,
    const SkeletonGraph& graph,
    const LiveLocationAnalyzer& analyzer,
    const WriteKey& added_write,
    uint32_t added_thread_id,
    const std::string& location) {
    
    // Combine write and read update logic which is just write update logic.
    update_potential_on_write_addition(potential, graph, analyzer, 
                                             added_write, added_thread_id, location);
}

static void* update_potential_impl(void* potential,
                                         const SkeletonGraph* graph,
                                         const MutationInfo* mutation) {
    LiveLocationAnalyzer analyzer;

    if (!graph) {
        return potential;
    }

    if (!mutation || mutation->kind == MUT_NONE) {
        if (potential) {
            return potential;
        }
        return create_skeleton_potential(graph);
    }

    if (mutation->kind == MUT_MUTATE_RF) {
        SkeletonPotential recalculated = calculate_skeleton_potential(*graph, analyzer);
        if (potential) {
            delete static_cast<SkeletonPotential*>(potential);
        }
        return new SkeletonPotential(std::move(recalculated));
    }

    if (!potential) {
        return create_skeleton_potential(graph);
    }

    SkeletonPotential* pot = static_cast<SkeletonPotential*>(potential);
    WriteKey added_write{mutation->dest_id.instruction_id,
                         (uint32_t)mutation->dest_id.thread_id,
                         (uint32_t)mutation->dest_id.visit_id};

    switch (mutation->kind) {
        case MUT_ADD_READ:
            update_potential_on_read_addition(*pot, *graph, analyzer, (uint32_t)mutation->dest_id.thread_id);
            break;
        case MUT_ADD_CAS_FAILURE:
            update_potential_on_read_addition(*pot, *graph, analyzer, (uint32_t)mutation->dest_id.thread_id);
            break;
        case MUT_ADD_WRITE:
            update_potential_on_write_addition(*pot, *graph, analyzer, added_write,
                                                    (uint32_t)mutation->dest_id.thread_id,
                                                    std::string(mutation->location));
            break;
        case MUT_ADD_FENCE:
            update_potential_on_fence_addition(*pot, *graph, analyzer, (uint32_t)mutation->dest_id.thread_id);
            break;
        case MUT_ADD_RMW:
            update_potential_on_rmw_addition(*pot, *graph, analyzer, added_write,
                                                   (uint32_t)mutation->dest_id.thread_id,
                                                   std::string(mutation->location));
            break;
        case MUT_ADD_CAS_SUCCESS:
            update_potential_on_rmw_addition(*pot, *graph, analyzer, added_write,
                                                   (uint32_t)mutation->dest_id.thread_id,
                                                   std::string(mutation->location));
            break;
        case MUT_MUTATE_RF:
            // Already handled by the early-return recalculation block above
            // (destroy_skeleton_potential + create_skeleton_potential), so this
            // case is unreachable here. Kept as a no-op for clarity.
        case MUT_NONE:
        default:
            break;
    }

    return potential;
}

extern "C" void* update_potential(void* potential,
                                         const SkeletonGraph* graph,
                                         const MutationInfo* mutation) {
    return update_potential_impl(potential, graph, mutation);
}

/**
 * @brief C wrapper: create skeleton potential (Mode 2).
 */
extern "C" void* create_skeleton_potential(const SkeletonGraph* graph) {
    if (!graph) {
        return nullptr;
    }

    LiveLocationAnalyzer analyzer;
    SkeletonPotential potential = calculate_skeleton_potential(*graph, analyzer);
    return new SkeletonPotential(std::move(potential));
}

/**
 * @brief Clone a SkeletonPotential object.
 *
 * @param potential Opaque pointer to SkeletonPotential
 * @return New opaque pointer to SkeletonPotential clone
 */
extern "C" void* clone_skeleton_potential(void* potential) {
    if (!potential) {
        return nullptr;
    }

    SkeletonPotential* pot = static_cast<SkeletonPotential*>(potential);
    return new SkeletonPotential(*pot);
}

/**
 * @brief Destroy a SkeletonPotential object created by create_skeleton_potential.
 * 
 * @param potential Opaque pointer to SkeletonPotential
 */
extern "C" void destroy_skeleton_potential(void* potential) {
    if (potential) {
        delete static_cast<SkeletonPotential*>(potential);
    }
}

/**
 * @brief Get the total write count from a stored SkeletonPotential pointer.
 * 
 * @param potential Opaque pointer to SkeletonPotential
 * @return Total count of potential writes
 */
extern "C" size_t get_potential_count_from_ptr(void* potential) {
    if (!potential) {
        return 0;
    }
    
    SkeletonPotential* pot = static_cast<SkeletonPotential*>(potential);
    return pot->total_writes();
}

/**
 * @brief C wrapper for incrementally updating potential after adding a Read event.
 * 
 * @param potential Opaque pointer to SkeletonPotential to update
 * @param graph The mutated skeleton graph
 * @param added_thread_id The thread ID where the read was added
 */
extern "C" void incremental_update_on_read(
    void* potential, const SkeletonGraph* graph, uint32_t added_thread_id) {
    
    if (!potential || !graph) {
        return;
    }

    MutationInfo mutation{};
    mutation.kind = MUT_ADD_READ;
    mutation.source_id.thread_id = (int)added_thread_id;
    update_potential_impl(potential, graph, &mutation);
}

/**
 * @brief C wrapper for incrementally updating potential after adding a Write event.
 * 
 * @param potential Opaque pointer to SkeletonPotential to update
 * @param graph The mutated skeleton graph
 * @param instr_id Instruction ID of the added write
 * @param thread_id Thread ID of the added write
 * @param visit_id Visit ID of the added write
 * @param added_thread_id The thread ID where the write was added (same as thread_id)
 * @param location The memory location of the write (C string)
 */
extern "C" void incremental_update_on_write(
    void* potential, const SkeletonGraph* graph,
    long long instr_id, uint32_t thread_id, uint32_t visit_id,
    uint32_t added_thread_id, const char* location) {
    
    if (!potential || !graph || !location) {
        return;
    }

    MutationInfo mutation{};
    mutation.kind = MUT_ADD_WRITE;
    mutation.source_id.thread_id = (int)thread_id;
    mutation.source_id.instruction_id = instr_id;
    mutation.source_id.visit_id = (int)visit_id;
    std::strncpy(mutation.location, location, sizeof(mutation.location) - 1);
    mutation.location[sizeof(mutation.location) - 1] = '\0';
    update_potential_impl(potential, graph, &mutation);
}

/**
 * @brief C wrapper for updating potential after adding an Fence event.
 * 
 * This performs a full recalculation and returns a new potential object.
 * The caller should destroy the old potential and use the new one.
 * 
 * @param graph The mutated skeleton graph
 * @return New opaque pointer to SkeletonPotential
 */
extern "C" void incremental_update_on_fence(
    void* potential, const SkeletonGraph* graph, uint32_t added_thread_id) {
    
    if (!potential || !graph) {
        return;
    }

    MutationInfo mutation{};
    mutation.kind = MUT_ADD_FENCE;
    mutation.source_id.thread_id = (int)added_thread_id;
    update_potential_impl(potential, graph, &mutation);
}

/**
 * @brief C wrapper: incremental update on RMW.
 */
extern "C" void incremental_update_on_rmw(
    void* potential, const SkeletonGraph* graph,
    long long instr_id, uint32_t thread_id, uint32_t visit_id,
    uint32_t added_thread_id, const char* location) {
    
    if (!potential || !graph || !location) {
        return;
    }

    MutationInfo mutation{};
    mutation.kind = MUT_ADD_RMW;
    mutation.source_id.thread_id = (int)thread_id;
    mutation.source_id.instruction_id = instr_id;
    mutation.source_id.visit_id = (int)visit_id;
    std::strncpy(mutation.location, location, sizeof(mutation.location) - 1);
    mutation.location[sizeof(mutation.location) - 1] = '\0';
    update_potential_impl(potential, graph, &mutation);
}

/**
 * @brief C wrapper: compute potential for RF mutation (Mode 2).
 */
extern "C" void* potential_calculation_on_rf_mutation(const SkeletonGraph* graph) {
    if (!graph) {
        return nullptr;
    }

    LiveLocationAnalyzer analyzer;
    SkeletonPotential potential = calculate_skeleton_potential(*graph, analyzer);
    return new SkeletonPotential(std::move(potential));
}

// Local write-like/read-like classifiers for the static CFG (cfg_new), which
// uses the generic Event_Type::CAS (not yet split into CAS_SUCCESS/CAS_FAILURE
// as in the skeleton graph). Mirrors is_read_like_type's logic in
// skeleton_graph_mutator.cpp, which is file-local there.
static bool is_write_like(Event_Type type) {
    return type == Event_Type::WRITE || type == Event_Type::RMW ||
           type == Event_Type::CAS;
}

static bool is_read_like(Event_Type type) {
    return type == Event_Type::READ || type == Event_Type::CAS ||
           type == Event_Type::CAS_FAILURE || type == Event_Type::CAS_SUCCESS ||
           type == Event_Type::RMW;
}

/**
 * @brief Get the maximum possible potential writes across all threads based on static CFG.
 *
 * Computes the theoretical upper bound on total writes in SkeletonPotential by summing
 * the static write count for every memory location that can ever be read by each thread.
 * This provides a stable denominator for normalizing remaining potential capacity into [0.0, 1.0].
 */
extern "C" size_t get_max_static_potential(void) {
    if (cfg_new.nodes.empty() && !eg_file.empty()) {
        parse_program_abstraction(eg_file.string(), cfg_new);
    }
    build_future_read_cache();

    // Map location -> count of static writes
    std::unordered_map<std::string, size_t> loc_write_counts;
    for (const auto& [id, node] : cfg_new.nodes) {
        if (is_write_like(node.event.get_event_type())) {
            loc_write_counts[node.event.get_location()]++;
        }
    }

    size_t total_max = 0;
    for (const auto& [tid, event_ids] : cfg_new.thread_index) {
        std::unordered_set<std::string> thread_read_locs;
        for (int eid : event_ids) {
            auto node_it = cfg_new.nodes.find(eid);
            if (node_it != cfg_new.nodes.end()) {
                if (is_read_like(node_it->second.event.get_event_type())) {
                    thread_read_locs.insert(node_it->second.event.get_location());
                }
            }
        }
        for (const auto& loc : thread_read_locs) {
            total_max += loc_write_counts[loc];
        }
    }
    return total_max > 0 ? total_max : 1;
}
