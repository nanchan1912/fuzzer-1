#ifndef SKELETON_POTENTIAL_HPP
#define SKELETON_POTENTIAL_HPP

#include <unordered_set>
#include <unordered_map>
#include <cstdint>
#include <set>
#include <string>
#include "skeleton_graph.hpp"
#include <vector>

struct MutationInfo;

/**
 * @struct WriteKey
 * @brief Uniquely identifies a write operation in a skeleton.
 * 
 * A write is uniquely identified by:
 * - instr_id: Instruction identifier
 * - thread_id: ID of the thread that performed the write
 * - visit_id: Visit counter for this specific instruction
 */
struct WriteKey {
    long long instr_id;
    uint32_t thread_id;
    uint32_t visit_id;

    /**
     * @brief Equality comparison for WriteKey.
     */
    bool operator==(const WriteKey& other) const noexcept {
        return instr_id == other.instr_id &&
               thread_id == other.thread_id &&
               visit_id == other.visit_id;
    }
};

/**
 * @struct WriteKeyHash
 * @brief Custom hash function for WriteKey.
 * 
 * Uses a combination of bit operations to distribute keys evenly
 * across the hash table.
 */
struct WriteKeyHash {
    size_t operator()(const WriteKey& w) const noexcept {
        return ((size_t)(uint64_t)w.instr_id * 1000003ULL) ^
               ((size_t)w.thread_id << 20) ^
               w.visit_id;
    }
};

/// Type alias for a set of writes
using WriteSet = std::unordered_set<WriteKey, WriteKeyHash>;
using LocationWriteMap = std::unordered_map<std::string, WriteSet>;

/**
 * @class SkeletonPotential
 * @brief Manages potential writes considering all live locations per event.
 * 
 * - Before fuzzing, we pre-compute live locations for each thread (which locations
 *   have future read events in that thread from a given point)
 * - For each event added, we consider ALL live locations accessible from it,
 *   not just the next read's single location
 * - Potential difference considers all locations in both potentials
 * 
 * Data structure:
 * - Per-thread write sets (like Mode 1)
 * - But populated based on live locations, not just next read location
 */
class SkeletonPotential {
private:
    // Map from thread_id -> location -> set of writes for that location
    std::unordered_map<uint32_t, LocationWriteMap> threads;
public:
    /**
    * @brief Add a write to a specific thread/location set.
     * 
    * @param thread_id The ID of the thread
    * @param location The memory location
    * @param w The WriteKey to add
    */
    void add_write(uint32_t thread_id, const std::string& location, const WriteKey& w) {
        threads[thread_id][location].insert(w);
    }

    /**
    * @brief Get the location map for a specific thread.
     * 
     * @param thread_id The ID of the thread
    * @return Reference to the location map for this thread, or empty map if not found
    */
    const LocationWriteMap& get_thread(uint32_t thread_id) const {
        static LocationWriteMap empty;
        auto it = threads.find(thread_id);
        return (it != threads.end()) ? it->second : empty;
    }

    /**
     * @brief Get the write set for a specific thread/location pair.
     */
    const WriteSet& get_location(uint32_t thread_id, const std::string& location) const {
        static WriteSet empty;
        auto thread_it = threads.find(thread_id);
        if (thread_it == threads.end()) {
            return empty;
        }
        auto loc_it = thread_it->second.find(location);
        return (loc_it != thread_it->second.end()) ? loc_it->second : empty;
    }

    /**
     * @brief Get all threads in this skeleton.
     * 
     * @return Reference to the underlying thread map
     */
    const std::unordered_map<uint32_t, LocationWriteMap>& get_all_threads() const {
        return threads;
    }

    /**
     * @brief Clear all writes from this skeleton.
     */
    void clear() {
        threads.clear();
    }

    /**
     * @brief Get the total number of writes across all threads.
     * 
     * @return Total write count
     */
    size_t total_writes() const;

    /**
     * @brief Clear writes for a specific thread.
     * 
     * @param thread_id The thread ID to clear
     */
    void clear_thread(uint32_t thread_id) {
        threads.erase(thread_id);
    }

    /**
     * @brief Replace writes for a specific thread.
     * 
     * @param thread_id The thread ID to update
     * @param new_writes The new location map for this thread
     */
    void set_thread(uint32_t thread_id, const LocationWriteMap& new_writes) {
        threads[thread_id] = new_writes;
    }

    void set_thread(uint32_t thread_id, LocationWriteMap&& new_writes) {
        threads[thread_id] = std::move(new_writes);
    }

    void set_location(uint32_t thread_id, const std::string& location, const WriteSet& new_writes) {
        threads[thread_id][location] = new_writes;
    }

    void set_location(uint32_t thread_id, const std::string& location, WriteSet&& new_writes) {
        threads[thread_id][location] = std::move(new_writes);
    }
};

/**
 * @struct LocationEventInfo
 * @brief Precomputed information about a location's events in a thread.
 * 
 * Used to determine which locations are "live" (have future events) from
 * a given program point in the thread.
 */
struct LocationEventInfo {
    // For each location, store the indices of events that access it
    std::unordered_map<std::string, std::vector<size_t>> location_events;
    
    // Total events in this thread
    size_t total_events = 0;
};

/**
 * @class LiveLocationAnalyzer
 * @brief Legacy compatibility helper for analyzing future reachability.
 * 
 * The current Mode 2 implementation uses cached future-read reachability.
 * This helper remains available for compatibility with older callers.
 */
class LiveLocationAnalyzer {
public:
    /**
     * @brief Build the live location map from the skeleton graph.
     * 
     * Analyzes each thread's program order to determine which locations
     * have events after each program point.
     * 
     * @param graph The skeleton graph to analyze
     */
    void analyze(const SkeletonGraph& graph);

    /**
     * @brief Get live locations accessible from a specific event in a thread.
     * 
     * @param thread_id The thread ID
     * @param event_position Position in the thread's program order
     * @return Set of live location strings
     */
    const std::unordered_set<std::string>& get_live_locations(
        uint32_t thread_id, size_t event_position) const;

    /**
     * @brief Check if a location is live from a given event position.
     * 
     * @param thread_id The thread ID
     * @param event_position Position in the thread's program order
     * @param location The location to check
     * @return true if the location is live, false otherwise
     */
    bool is_location_live(uint32_t thread_id, size_t event_position,
                          const std::string& location) const;

private:
    // For each thread, store the location info
    std::unordered_map<uint32_t, LocationEventInfo> thread_info;
    
    // For each (thread_id, event_position), store the set of live locations
    std::unordered_map<uint64_t, std::unordered_set<std::string>> live_locations_cache;

    // Helper to create a cache key
    static uint64_t make_cache_key(uint32_t thread_id, size_t event_position) {
        return ((uint64_t)thread_id << 32) | event_position;
    }
};

/**
 * @brief Compute the location-aware potential difference between two potentials.
 * 
 * We compute difference across all locations, not just per-location.
 * Returns the sum of absolute differences in write counts for each location.
 * 
 * @param A First potential
 * @param B Second potential
 * @return Difference score considering all locations
 */
double compare_skeletons(const SkeletonPotential& A,
                                const SkeletonPotential& B);

/**
 * @brief Calculate potential using cached future reads.
 * 
 * For each thread:
 * 1. Find all future reads reachable from the thread's current static instruction
 * 2. For each read, find consistent writes using consistency checking
 * 3. Add these writes to the potential set for this thread
 * 
 * @param graph The skeleton graph to analyze
 * @param analyzer Pre-computed live location analyzer
 * @return SkeletonPotential containing potential writes per thread
 */
SkeletonPotential calculate_skeleton_potential(const SkeletonGraph& graph, const LiveLocationAnalyzer& analyzer);

/**
 * @brief Incrementally update potential when a Read event is added.
 * 
 * Recalculates the potential only for the thread where the read was added.
 * Uses the same logic as full calculation: finds next read event(s) and
 * their consistent writes.
 * 
 * @param potential The SkeletonPotential to update (in-place)
 * @param graph The mutated skeleton graph (with the new read)
 * @param added_thread_id The thread ID where the read was added
 */
void update_potential_on_read_addition(SkeletonPotential& potential,
                                              const SkeletonGraph& graph,
                                              const LiveLocationAnalyzer& analyzer,
                                              uint32_t added_thread_id);

/**
 * @brief Incrementally update potential when a Write event is added.
 * 
 * Adds the new write to the potential sets of all other threads that already
 * have potential writes at the same memory location. The thread where the
 * write is added is recalculated.
 * 
 * @param potential The SkeletonPotential to update
 * @param graph The mutated skeleton graph
 * @param analyzer Pre-computed live location analyzer
 * @param added_write The WriteKey of the newly added write
 * @param added_thread_id The thread ID where the write was added
 * @param location The memory location of the write (string)
 */
void update_potential_on_write_addition(SkeletonPotential& potential,
                                               const SkeletonGraph& graph,
                                               const LiveLocationAnalyzer& analyzer,
                                               const WriteKey& added_write,
                                               uint32_t added_thread_id,
                                               const std::string& location);

/**
 * @brief Incrementally update potential when a Fence event is added.
 *
 * Recalculates the potential only for the thread where the fence was added.
 *
 * @param potential The SkeletonPotential to update
 * @param graph The mutated skeleton graph
 * @param analyzer Pre-computed live location analyzer
 * @param added_thread_id The thread ID where the fence was added
 */
void update_potential_on_fence_addition(SkeletonPotential& potential,
                                               const SkeletonGraph& graph,
                                               const LiveLocationAnalyzer& analyzer,
                                               uint32_t added_thread_id);

/**
 * @brief Handle potential update when an RMW event is added.
 * 
 * RMW (Read-Modify-Write) operations combine read and write updates. We add
 * the new write to other threads with potential at the same location and
 * recalculate the thread where the RMW is added.
 * 
 * @param potential The SkeletonPotential to update
 * @param graph The mutated skeleton graph
 * @param analyzer Pre-computed live location analyzer
 * @param added_write The WriteKey of the newly added RMW
 * @param added_thread_id The thread ID where the RMW was added
 * @param location The memory location of the RMW (string)
 */
void update_potential_on_rmw_addition(SkeletonPotential& potential,
                                             const SkeletonGraph& graph,
                                             const LiveLocationAnalyzer& analyzer,
                                             const WriteKey& added_write,
                                             uint32_t added_thread_id,
                                             const std::string& location);

/**
 * @brief Unified Mode update entry point.
 *
 * This dispatches to the appropriate sub-update based on MutationInfo::kind.
 * It may return a replacement pointer for full RF recalculation.
 */
extern "C" void* update_potential(void* potential,
                                         const SkeletonGraph* graph,
                                         const MutationInfo* mutation);

/**
 * @brief Precompute the future-read cache once before fuzzing starts.
 */
extern "C" void initialize_skeleton_potential_cache(void);

/*
 * To check if valid interesting locations were given or not.
*/
bool is_interesting_locations_valid(void);

/*
 * To get the interesting locations set.
*/
const std::unordered_set<std::string>& get_interesting_locations(void);

#endif // SKELETON_POTENTIAL_HPP
