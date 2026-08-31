#include "data_race.hpp"

#include <algorithm>
#include <cstring>
#include <set>
#include <utility>
#include <vector>

// Internal C++ helpers for the opaque race-pair store exposed to C callers.
// Keeping the container logic here lets the header stay small and stable.
namespace data_race_internal {

using RacePair = std::pair<EventID, EventID>;
using RacePairVec = std::vector<RacePair>;

static constexpr Access_Mode kAccessModes[] = {
    Access_Mode::NON_ATOMIC, Access_Mode::RELAXED, Access_Mode::ACQUIRE,
    Access_Mode::RELEASE, Access_Mode::ACQ_REL, Access_Mode::SC};

static EventID event_id_from_triple(const EventTriple& triple) {
    return std::make_tuple(triple.thread_id, triple.instruction_id,
                           triple.visit_id);
}

static EventTriple event_triple_from_id(const EventID& id) {
    return EventTriple{std::get<0>(id), std::get<1>(id), std::get<2>(id)};
}

static bool event_id_less(const EventID& lhs, const EventID& rhs) {
    if (std::get<0>(lhs) != std::get<0>(rhs)) {
        return std::get<0>(lhs) < std::get<0>(rhs);
    }
    if (std::get<1>(lhs) != std::get<1>(rhs)) {
        return std::get<1>(lhs) < std::get<1>(rhs);
    }
    return std::get<2>(lhs) < std::get<2>(rhs);
}

static RacePair canonicalize_pair(EventID first, EventID second) {
    if (event_id_less(second, first)) {
        std::swap(first, second);
    }
    return {first, second};
}

struct RacePairLess {
    bool operator()(const RacePair& lhs, const RacePair& rhs) const {
        if (event_id_less(lhs.first, rhs.first)) {
            return true;
        }
        if (event_id_less(rhs.first, lhs.first)) {
            return false;
        }
        return event_id_less(lhs.second, rhs.second);
    }
};

struct EventIdLess {
    bool operator()(const EventID& lhs, const EventID& rhs) const {
        return event_id_less(lhs, rhs);
    }
};

static void append_event_ids(std::vector<EventID>& out,
                             const std::unordered_set<EventID, TripleHash>& ids) {
    out.insert(out.end(), ids.begin(), ids.end());
}

/*
 * Helper function to append event IDs of a certain type and mode at a location to the output vector. If only_non_atomic is true, only appends non-atomic events, otherwise appends events of all modes.
 * Note: This function assumes that the skeleton graph has been properly constructed and contains the necessary information
 * about events at the given location, type, and mode.
 * 
 * @param out The vector to append event IDs to
 * @param graph The skeleton graph to query for events
 * @param location The memory location to look for events at
 * @param type The type of events to look for (READ, WRITE, RMW, CAS, etc.)
 * @param only_non_atomic If true, only appends non-atomic events, otherwise appends events of all modes
 * @return void
*/
static void append_event_ids_by_modes(std::vector<EventID>& out,
                                      const SkeletonGraph* graph,
                                      const Location& location,
                                      Event_Type type,
                                      bool only_non_atomic) {
    if (!graph) {
        return;
    }

    if (only_non_atomic) {
        append_event_ids(out, graph->get_event_ids_by_loc_type_and_mode(location, type, Access_Mode::NON_ATOMIC));
        return;
    }

    for (Access_Mode mode : kAccessModes) {
        append_event_ids(out, graph->get_event_ids_by_loc_type_and_mode(location, type, mode));
    }
}

/*
 * Helper function to collect all event IDs at a given location that can be the target of a data race
 * Note: This function assumes that the skeleton graph has been properly constructed and contains the necessary information about events at the given location.
 * A target event is defined as any read, write, or RMW event at the location, since any of these can potentially be involved in a data race
 * 
 * @param graph The skeleton graph to query for events
 * @param location The memory location to look for events at
 * @return A vector of event IDs that are reads, writes, or RMWs at the given location
*/
/* event_type_sets is keyed by the exact Event_Type, so a structural query has
 * to enumerate every concrete type in the class. These two helpers are the
 * single place that enumeration lives, replacing what was previously three
 * separate hand-written repetitions of the same READ/WRITE/RMW/CAS_* lists
 * across this function and both case groups in
 * collect_candidate_second_events below. */

/* Events that write: a successful CAS does, a failed one does not. */
static void append_write_like_ids(std::vector<EventID>& out,
                                  const SkeletonGraph* graph,
                                  const Location& location,
                                  bool only_non_atomic) {
    append_event_ids_by_modes(out, graph, location, Event_Type::WRITE, only_non_atomic);
    append_event_ids_by_modes(out, graph, location, Event_Type::RMW, only_non_atomic);
    append_event_ids_by_modes(out, graph, location, Event_Type::CAS_SUCCESS, only_non_atomic);
}

/* Every event that touches the location, each type listed exactly once. */
static void append_all_access_ids(std::vector<EventID>& out,
                                  const SkeletonGraph* graph,
                                  const Location& location,
                                  bool only_non_atomic) {
    append_event_ids_by_modes(out, graph, location, Event_Type::READ, only_non_atomic);
    append_event_ids_by_modes(out, graph, location, Event_Type::CAS_FAIL, only_non_atomic);
    append_write_like_ids(out, graph, location, only_non_atomic);
}

static std::vector<EventID> collect_target_event_ids_at_location(
    const SkeletonGraph* graph, const Location& location) {
    std::vector<EventID> targets;
    append_all_access_ids(targets, graph, location, false);
    return targets;
}

/*
 * Helper function to collect all event IDs that can be the second event in a data race with the target event
 * Note: This function assumes that the skeleton graph has been properly constructed and contains the necessary information about events at the given location.
 * A candidate second event is defined as any event that can potentially be involved in a data race with the target event.
 *
 * @param graph The skeleton graph to query for events
 * @param target_event The target event to find candidates for
 * @return A vector of event IDs that are candidates for being the second event in a data race with the target event
*/
static std::vector<EventID> collect_candidate_second_events(const SkeletonGraph* graph, const Event* target_event) {
    std::vector<EventID> candidates;
    if (!graph || !target_event) {
        return candidates;
    }

    const Location& location = target_event->get_location();
    const bool target_is_non_atomic = target_event->get_access_mode() == Access_Mode::NON_ATOMIC;

    switch (target_event->get_event_type()) {
        // Read-only targets (READ, a failed CAS) race only against writers.
        case Event_Type::READ:
        case Event_Type::CAS_FAIL:
            append_write_like_ids(candidates, graph, location, !target_is_non_atomic);
            break;

        // Writers (WRITE, RMW, a successful CAS) race against everything that
        // touches the location.
        case Event_Type::WRITE:
        case Event_Type::RMW:
        case Event_Type::CAS_SUCCESS:
            append_all_access_ids(candidates, graph, location, !target_is_non_atomic);
            break;

        // FENCE touches no location, so it cannot participate in a race.
        // (This Event_Type has no EOP enumerator, unlike upstream.)
        case Event_Type::FENCE:
        default:
            break;
    }

    const EventID target_id = target_event->get_event_id();
    candidates.erase(std::remove(candidates.begin(), candidates.end(), target_id),
                     candidates.end());
    std::sort(candidates.begin(), candidates.end(), event_id_less);
    candidates.erase(std::unique(candidates.begin(), candidates.end()),
                     candidates.end());
    return candidates;
}

/*
 * Helper function to check if there is a happens-before path from source to target in the skeleton graph.
 * 
 * This function performs a breadth-first search starting from the source event, following both program order and synchronizes-with edges, to see if it can reach the target event. If it reaches the target, it returns true. If it exhausts all reachable events without finding the target, it returns false.
 * Note: This function assumes that the skeleton graph has been properly constructed and contains the necessary information about program order and synchronizes-with relations.
 * 
 * @param graph The skeleton graph to analyze
 * @param source The starting event ID for the search
 * @param target The event ID to search for
 * @return true if there is a happens-before path from source to target, false otherwise
*/
static bool has_happens_before_path(const struct SkeletonGraph* graph,
                                    const EventID& source,
                                    const EventID& target) {
    if (source == target) {
        return true;
    }

    const auto& threadwise_po = graph->get_threadwise_po();
    const auto& sw = graph->get_sw();
    const auto& tcj = graph->get_tcj();

    std::set<EventID, EventIdLess> visited;
    std::vector<EventID> to_explore;
    to_explore.push_back(source);

    while (!to_explore.empty()) {
        EventID curr = to_explore.back();
        to_explore.pop_back();

        if (!visited.insert(curr).second) {
            continue;
        }

        if (curr == target) {
            return true;
        }

        const int curr_thread = std::get<0>(curr);
        const auto thread_po_it = threadwise_po.find(curr_thread);
        if (thread_po_it != threadwise_po.end()) {
            const auto& thread_po = thread_po_it->second;
            const auto pos_it = std::find(thread_po.begin(), thread_po.end(), curr);
            if (pos_it != thread_po.end()) {
                for (auto it = std::next(pos_it); it != thread_po.end(); ++it) {
                    if (visited.find(*it) == visited.end()) {
                        to_explore.push_back(*it);
                    }
                }
            }
        }

        const auto sw_it = sw.find(curr);
        if (sw_it != sw.end()) {
            for (const auto& next : sw_it->second) {
                if (visited.find(next) == visited.end()) {
                    to_explore.push_back(next);
                }
            }
        }

        const auto tcj_it = tcj.find(curr);
        if (tcj_it != tcj.end()) {
            for (const auto& next : tcj_it->second) {
                if (visited.find(next) == visited.end()) {
                    to_explore.push_back(next);
                }
            }
        }
    }

    return false;
}

static bool is_read_or_write(const Event* event) {
    if (!event) {
        return false;
    }
    // Both CAS outcomes read; a successful one also writes.
    return is_read_like(event->get_event_type()) || is_write_like(event->get_event_type());
}

static bool is_write(const Event* event) {
    if (!event) {
        return false;
    }
    return is_write_like(event->get_event_type());
}

static bool is_non_atomic(const Event* event) {
    return event && event->get_access_mode() == Access_Mode::NON_ATOMIC;
}

/*
 * Helper function to collect all unique data race pairs involving the target event and add them to the unique_pairs set.
 * Note: This function assumes that the skeleton graph has been properly constructed and contains the necessary information about events and their ordering.
 * A data race pair is defined as two events that access the same memory location, 
 * at least one of them is a write, and they are not ordered by happens-before relation. 
 * This function checks all candidate second events for the target event and adds the pairs that satisfy the data race conditions to the unique_pairs set in a canonicalized form (sorted by event ID) to avoid duplicates.
 * 
 * @param graph The skeleton graph to analyze
 * @param target The target event to find race pairs for
 * @param unique_pairs The set to add unique data race pairs to
 * @return void
*/
static void collect_race_pairs_for_target(
    const SkeletonGraph* graph,
    const Event* target,
    std::set<RacePair, RacePairLess>& unique_pairs) {
    const auto candidate_ids = collect_candidate_second_events(graph, target);
    if (candidate_ids.empty()) {
        return;
    }

    const EventID target_id = target->get_event_id();

    for (const auto& candidate_id : candidate_ids) {
        const Event* candidate = graph->get_event_by_id(candidate_id);
        if (!candidate) {
            continue;
        }

        if (!is_read_or_write(candidate)) {
            continue;
        }
        if (target->get_location() != candidate->get_location()) {
            continue;
        }
        if (!is_write(target) && !is_write(candidate)) {
            continue;
        }
        if (!is_non_atomic(target) && !is_non_atomic(candidate)) {
            continue;
        }
        // No need to check both ways, as my target event will always be the latest added event, 
        // so can never have a happens-before path to the candidate event. 
        // So only need to check if the candidate event has a happens-before path to the target.
        if (has_happens_before_path(graph, candidate_id, target_id)) {
            continue;
        }

        unique_pairs.insert(canonicalize_pair(target_id, candidate_id));
    }
}

/*
 * Helper function to collect all unique data race pairs in the skeleton graph and return them as a vector. 
 * This function iterates over all memory locations in the graph, collects target events at each location, and then collects race 
 * pairs for each target event using the collect_race_pairs_for_target helper function. 
 * The unique pairs are stored in a set to avoid duplicates, and then converted to a vector before returning.
 * 
 * @param graph The skeleton graph to analyze
 * @return A vector of unique data race pairs, where each pair consists of two event IDs that are involved in a data race
*/
static RacePairVec* collect_all_race_pairs(const SkeletonGraph* graph) {
    std::set<RacePair, RacePairLess> unique_pairs;
    auto* result = new RacePairVec();

    if (!graph) {
        return result;
    }

    const auto& mo_by_location = graph->get_mo_by_location();
    for (const auto& kv : mo_by_location) {
        const auto targets = collect_target_event_ids_at_location(graph, kv.first);
        for (const auto& target_id : targets) {
            const auto candidate_ids = ::check_data_race(graph, target_id);
            for (const auto& candidate_id : candidate_ids) {
                unique_pairs.insert(canonicalize_pair(target_id, candidate_id));
            }
        }
    }

    result->assign(unique_pairs.begin(), unique_pairs.end());
    return result;
}

/*
 * Helper function to append unique data race pairs from a source vector to a destination vector.
 * This function iterates over all pairs in the source vector and adds them to the destination vector
 * if they are not already present.
 *
 * @param dst The destination vector to append pairs to
 * @param src The source vector containing pairs to append
 * @return void
 */
static void append_race_pairs(RacePairVec* dst, const RacePairVec* src) {
    if (!dst || !src) {
        return;
    }

    for (const auto& pair : *src) {
        if (std::find(dst->begin(), dst->end(), pair) == dst->end()) {
            dst->push_back(pair);
        }
    }
}

static bool pair_exists_in_graph(const SkeletonGraph* graph, const RacePair& pair) {
    if (!graph) {
        return false;
    }
    return graph->get_event_by_id(pair.first) != nullptr &&
           graph->get_event_by_id(pair.second) != nullptr;
}

static void prune_invalid_race_pairs(RacePairVec* pairs, const SkeletonGraph* graph) {
    if (!pairs) {
        return;
    }

    pairs->erase(std::remove_if(pairs->begin(), pairs->end(),
                                [&](const RacePair& pair) {
                                    return !pair_exists_in_graph(graph, pair);
                                }),
                 pairs->end());
}

static void remove_pairs_involving_target(RacePairVec* pairs, const EventID& target_id) {
    if (!pairs) {
        return;
    }

    pairs->erase(std::remove_if(pairs->begin(), pairs->end(),
                                [&](const RacePair& pair) {
                                    return pair.first == target_id || pair.second == target_id;
                                }),
                 pairs->end());
}

}  // namespace data_race_internal

extern "C" void* race_pair_store_create(void) {
    return new data_race_internal::RacePairVec();
}

extern "C" void race_pair_store_destroy(void* race_pair_store) {
    delete static_cast<data_race_internal::RacePairVec*>(race_pair_store);
}

extern "C" void* race_pair_store_clone(const void* race_pair_store) {
    if (!race_pair_store) {
        return race_pair_store_create();
    }
    return new data_race_internal::RacePairVec(*static_cast<const data_race_internal::RacePairVec*>(race_pair_store));
}

extern "C" size_t race_pair_store_size(const void* race_pair_store) {
    if (!race_pair_store) {
        return 0;
    }
    return static_cast<const data_race_internal::RacePairVec*>(race_pair_store)->size();
}

extern "C" void race_pair_store_add(void* race_pair_store, EventTriple first_event, EventTriple second_event) {
    if (!race_pair_store) {
        return;
    }

    auto* pairs = static_cast<data_race_internal::RacePairVec*>(race_pair_store);
    const data_race_internal::RacePair pair = data_race_internal::canonicalize_pair(
        data_race_internal::event_id_from_triple(first_event),
        data_race_internal::event_id_from_triple(second_event));
    if (std::find(pairs->begin(), pairs->end(), pair) == pairs->end()) {
        pairs->push_back(pair);
    }
}

extern "C" void race_pair_store_append(void* destination_store, const void* source_store) {
    if (!destination_store || !source_store) {
        return;
    }

    data_race_internal::append_race_pairs(static_cast<data_race_internal::RacePairVec*>(destination_store),
                                          static_cast<const data_race_internal::RacePairVec*>(source_store));
}

extern "C" void* race_pair_store_collect(const struct SkeletonGraph* graph) {
    return data_race_internal::collect_all_race_pairs(graph);
}

extern "C" void race_pair_store_update_incremental(void* race_pair_store,
                                                   const struct SkeletonGraph* graph,
                                                   EventTriple mutated_event) {
    if (!race_pair_store || !graph) {
        return;
    }

    auto* pairs = static_cast<data_race_internal::RacePairVec*>(race_pair_store);
    data_race_internal::prune_invalid_race_pairs(pairs, graph);

    const EventID target_id = data_race_internal::event_id_from_triple(mutated_event);
    data_race_internal::remove_pairs_involving_target(pairs, target_id);

    const auto candidate_ids = check_data_race(graph, target_id);
    for (const auto& candidate_id : candidate_ids) {
        data_race_internal::RacePair pair = data_race_internal::canonicalize_pair(target_id, candidate_id);
        if (std::find(pairs->begin(), pairs->end(), pair) == pairs->end()) {
            pairs->push_back(pair);
        }
    }
}

extern "C" bool race_pair_store_get_pair(const void* race_pair_store, size_t index, EventTriple* first_event, EventTriple* second_event) {
    if (!race_pair_store) return false;
    const data_race_internal::RacePairVec* vec = static_cast<const data_race_internal::RacePairVec*>(race_pair_store);
    if (index >= vec->size()) return false;
    const data_race_internal::RacePair& p = (*vec)[index];
    if (first_event) {
        EventTriple t = data_race_internal::event_triple_from_id(p.first);
        *first_event = t;
    }
    if (second_event) {
        EventTriple t = data_race_internal::event_triple_from_id(p.second);
        *second_event = t;
    }
    return true;
}



// Return every event that races with `target_event_id`.
std::vector<EventID> check_data_race(const struct SkeletonGraph* graph,
                                    const EventID& target_event_id) {
    std::vector<EventID> race_candidates;

    if (!graph) {
        return race_candidates;
    }

    const Event* target = graph->get_event_by_id(target_event_id);
    if (!target || !data_race_internal::is_read_or_write(target)) {
        return race_candidates;
    }

    const auto candidate_ids = data_race_internal::collect_candidate_second_events(graph, target);
    if (candidate_ids.empty()) {
        return race_candidates;
    }

    for (const auto& candidate_id : candidate_ids) {
        const Event* candidate = graph->get_event_by_id(candidate_id);
        if (!candidate) {
            continue;
        }
        if (!data_race_internal::is_read_or_write(candidate)) {
            continue;
        }
        if (target->get_location() != candidate->get_location()) {
            continue;
        }
        if (!data_race_internal::is_write(target) && !data_race_internal::is_write(candidate)) {
            continue;
        }
        if (!data_race_internal::is_non_atomic(target) && !data_race_internal::is_non_atomic(candidate)) {
            continue;
        }
        // Events race only when they are unordered by happens-before.
        if (data_race_internal::has_happens_before_path(graph, candidate_id, target_event_id) ||
            data_race_internal::has_happens_before_path(graph, target_event_id, candidate_id)) {
            continue;
        }

        race_candidates.push_back(candidate_id);
    }

    return race_candidates;
}
