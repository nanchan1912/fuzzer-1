#include "afl-fuzz.h"
#include "skeleton_graph.hpp"
// #include "diversity_checker.h"

#include <cassert>

extern "C" {
  #include "skeleton_graph_mutator_wrapper.h"
}


// Helper callback to sum frequencies for all mo-next edges from a source
// struct MoFreqSumContext {
//     int source_tid;
//     long long source_iid;
//     int source_vid;
//     uint32_t total_freq;
// };

// static void sum_mo_frequencies_callback(EventTriple from, EventTriple to, 
//                                         uint32_t frequency, void* user_data) {
//     (void)to;


//     MoFreqSumContext* ctx = (MoFreqSumContext*)user_data;
    
//     // Check if this edge starts from our source event
//     if (from.thread_id == ctx->source_tid && 
//         from.instruction_id == ctx->source_iid && 
//         from.visit_id == ctx->source_vid) {
//         ctx->total_freq += frequency;
//     }
// }

// Writing a hash function for EventID (tuple<ThreadID, InstructionID, VisitID>) to be used in unordered_map
struct EventIDHash {
    size_t operator()(const EventTriple& id) const {
        auto [tid, iid, vid] = id;

        size_t h1 = std::hash<int>{}(tid);
        size_t h2 = std::hash<long long>{}(iid);
        size_t h3 = std::hash<int>{}(vid);

        //this is a more complicated but apparently more performant
        // REVISIT: check this once, took ai generated hash function for now
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;

        // Alternative simpler hash combination (less robust but simpler)
        // return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

//function for checkign equality of 2 event triples
inline bool operator==(const EventTriple& a,
                       const EventTriple& b) {
    return a.thread_id == b.thread_id
        && a.instruction_id == b.instruction_id
        && a.visit_id == b.visit_id;
}

// Nested unordered Map to store frequencies of MO edges
std::unordered_map<EventTriple, std::unordered_map<EventTriple, uint32_t, EventIDHash>, EventIDHash> mo_edge_frequencies; 

/* 
 * Check and update MO edge coverage
 * Takes two event triples representing an MO edge (from_event -> to_event)
 * Returns: 1 if edge is new (coverage improved), 0 if already explored
 */
int update_mo_coverage(EventTriple from_event_id, EventTriple to_event_id){
    // ACTF("Updating MO coverage for edge: (%d, %lld, %d) -> (%d, %lld, %d)",
    //      from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id,
    //      to_event_id.thread_id, to_event_id.instruction_id, to_event_id.visit_id);
    
    //check in mo_edge_frequencies if this edge exists
    auto from_it = mo_edge_frequencies.find(from_event_id);
    if (from_it == mo_edge_frequencies.end()) {
        // This is a new source event, create a new entry in the map
        // ACTF("This is a new source event, creating a new entry in the map");
        mo_edge_frequencies[from_event_id] = {{to_event_id, 1}};
        return 1; // New edge, coverage improved
    } else {
        // Check if the destination event exists for this source
        auto to_it = from_it->second.find(to_event_id);
        if (to_it == from_it->second.end()) {
            // This is a new destination event for this source, add it
            // ACTF("This is a new destination event for this source, adding it");
            from_it->second[to_event_id] = 1;
            return 1; // New edge, coverage improved
        }else{
            // Edge already exists from src to dest nodes given, so incrementing the frequency
            to_it->second += 1;
            // ACTF("Edge already exists, incrementing frequency to %u", to_it->second);
        }
    }
    return 0; // Edge already explored
}

void update_mo_coverage_for_graph(SkeletonGraph* graph){
    for (const auto& [location, mo_list] : graph->get_mo_by_location()){
        if (mo_list.size() < 2) continue; // Need at least 2 writes for an MO edge
            
        // For each write event in the MO ordering (except the last one)
        for (size_t i = 0; i < mo_list.size() - 1; i++){
            const EventID& from_event_id_tuple = mo_list[i];
            const EventID& to_event_id_tuple = mo_list[i + 1]; // mo-next event in current graph
            
            //converting from the tuple EventID to EventTriple for compatibility with mo_edge_frequencies
            EventTriple from_event_id = {std::get<0>(from_event_id_tuple), std::get<1>(from_event_id_tuple), std::get<2>(from_event_id_tuple)};
            EventTriple to_event_id = {std::get<0>(to_event_id_tuple), std::get<1>(to_event_id_tuple), std::get<2>(to_event_id_tuple)};
            
            //updating the freq of this edge
            update_mo_coverage(from_event_id, to_event_id);
        }
    }
}

// func to track the number fo unique mo-next edges explored so far
// returns the number of unique source nodes in the map
uint32_t get_mo_coverage_count(){
    // ACTF("Current number of unique MO edges explored: %zu", mo_edge_frequencies.size());
    return mo_edge_frequencies.size();
}

//func to print the frequencies of all mo-next edges explored so far
void print_mo_edge_frequencies(){
    // ACTF("Printing MO edge frequencies:");
    for (const auto& [from_event_id, dest_map] : mo_edge_frequencies) {
        for (const auto& [to_event_id, freq] : dest_map) {
            // Print the source and destination event triples along with the frequency
            SAYF("(%d, %lld, %d) -> (%d, %lld, %d): %u times\n",
                   from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id,
                   to_event_id.thread_id, to_event_id.instruction_id, to_event_id.visit_id,
                   freq);
        }
    }
}


// This func gets the frequency (number of times it was explored so far) of a specific MO edge by source and destination events
const uint32_t get_mo_edge_freq(EventTriple from_event_id, EventTriple to_event_id){
    // ACTF("Getting MO edge frequency for edge: (%d, %lld, %d) -> (%d, %lld, %d)",
    //      from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id,
    //      to_event_id.thread_id, to_event_id.instruction_id, to_event_id.visit_id);
    auto from_it = mo_edge_frequencies.find(from_event_id);
    if (from_it != mo_edge_frequencies.end()) {
        auto to_it = from_it->second.find(to_event_id);
        if (to_it != from_it->second.end()) {
            return to_it->second; // Return the frequency of the edge
        }
    }

    // ACTF("Edge does not exist: (%d, %lld, %d) -> (%d, %lld, %d)", from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id, to_event_id.thread_id, to_event_id.instruction_id, to_event_id.visit_id);
    return 0; // Edge does not exist
}


// This func gets the sum of frequencies for all mo-next edges from a particular source event
const uint32_t get_sum_mo_frequencies_from_source(EventTriple from_event_id){
    // ACTF("Getting sum of MO frequencies for source: (%d, %lld, %d)",
    //      from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id);
    auto from_it = mo_edge_frequencies.find(from_event_id);
    if (from_it != mo_edge_frequencies.end()) {
        uint32_t total_freq = 0;
        for (const auto& [to_event_id, freq] : from_it->second) {
            total_freq += freq;
        }
        return total_freq; // Return the sum of frequencies for all edges from this source
    }
    // ACTF("No edges found for source: (%d, %lld, %d)", from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id);
    // ACTF("No edges found for source: (%d, %lld, %d)", from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id);
    return 0; // No edges from this source
}


extern "C" u32 skeleton_graph_mo_footprint_calc(SkeletonGraph* graph){
    double score = 1.0;

    if (!graph) return 1;

    // Iterate over all memory locations and their MO orderings
    for (const auto& [location, mo_list] : graph->get_mo_by_location()){
        if (mo_list.size() < 2) continue; // Need at least 2 writes for an MO edge
        
        // For each write event in the MO ordering (except the last one)
        for (size_t i = 0; i < mo_list.size() - 1; i++){
            const EventID& from_event_id_tuple = mo_list[i];
            const EventID& to_event_id_tuple = mo_list[i + 1]; // mo-next event in current graph

            //converting from the tuple EventID to EventTriple for compatibility with mo_edge_frequencies
            EventTriple from_event_id = {std::get<0>(from_event_id_tuple), std::get<1>(from_event_id_tuple), std::get<2>(from_event_id_tuple)};
            EventTriple to_event_id = {std::get<0>(to_event_id_tuple), std::get<1>(to_event_id_tuple), std::get<2>(to_event_id_tuple)};
            //get the freq of this edge
            const uint32_t current_edge_freq = get_mo_edge_freq(from_event_id, to_event_id);
            //get the count of all edges from from_event_id encountered so far
            const uint32_t sum_all_mo_next_freq = get_sum_mo_frequencies_from_source(from_event_id);


    //         // Get event details for the from and to events
    //         const int from_tid = std::get<0>(from_event_id);
    //         const long long from_iid = std::get<1>(from_event_id);
    //         const int from_vid = std::get<2>(from_event_id);

    //         const int to_tid = std::get<0>(to_event_id);
    //         const long long to_iid = std::get<1>(to_event_id);
    //         const int to_vid = std::get<2>(to_event_id);

    //         // Get the sum of frequencies for ALL mo-next edges from this source write
    //         // (across all possible destinations explored so far)

    //         MoFreqSumContext ctx = {from_tid, from_iid, from_vid, 0};
    //         for_each_mo_edge(sum_mo_frequencies_callback, &ctx);
    //         const uint32_t sum_all_mo_next_freq = ctx.total_freq;

    //         // Get the frequency of the specific MO edge in the current graph
    //         const uint32_t current_edge_freq = get_mo_edge_frequency(from_tid, from_iid, from_vid,
    //                                                                   to_tid, to_iid, to_vid);

            // Compute the ratio: sum / current_edge_freq
            // Higher sum with lower current_edge_freq = this specific path is less explored

            if (current_edge_freq > 0 && sum_all_mo_next_freq > 0){
                const double ratio = (double)sum_all_mo_next_freq / (double)current_edge_freq;
                score *= (1.0 + ratio);
            } else if (current_edge_freq == 0){
                // Completely unexplored source write - maximum boost
                ACTF("MO Edge: (%d, %lld, %d) -> (%d, %lld, %d), current_edge_freq: %u, sum_all_mo_next_freq: %u",
                     from_event_id.thread_id, from_event_id.instruction_id, from_event_id.visit_id,
                     to_event_id.thread_id, to_event_id.instruction_id, to_event_id.visit_id,
                     current_edge_freq, sum_all_mo_next_freq);
                ACTF("THIS CASE IS NOT POSSIBLE");
                assert(0 && "This case should not be possible: current_edge_freq is 0");
                // TODO: what should I do with score here
            } else{
                // Edge exists in graph but not in diversity tracker yet
                ACTF("THIS CASE IS ALSO NOT POSSIBLE");
                assert(0 && "This case should not be possible: sum_all_mo_next_freq is 0");
                //TODO: what should I do with score here
            }
        }
    }

    u32 final_score = (u32)score;
    if (final_score < 1) final_score = 1;
    if (final_score > 100) final_score = 100;

    return final_score;
}