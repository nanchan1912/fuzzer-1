#include "skeleton_rf_footprint.hpp"
#include "skeleton_graph.hpp"
#include "skeleton_graph_mutator.hpp"

#include <cassert>
#include <cmath>
#include <unordered_map>
#include <utility>

extern "C" {
  #include "skeleton_graph_mutator_wrapper.h"
}

struct StaticEventID {
    int thread_id;
    long long instruction_id;

    bool operator==(const StaticEventID& other) const {
        return thread_id == other.thread_id && instruction_id == other.instruction_id;
    }
};

struct StaticEventIDHash {
    size_t operator()(const StaticEventID& id) const {
        size_t h1 = std::hash<int>{}(id.thread_id);
        size_t h2 = std::hash<long long>{}(id.instruction_id);
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};

static std::unordered_map<StaticEventID,
                          std::unordered_map<StaticEventID, uint32_t, StaticEventIDHash>,
                          StaticEventIDHash> rf_edge_frequencies;

extern "C" int update_rf_footprint(EventTriple write_event, EventTriple read_event) {
    StaticEventID r_id = {read_event.thread_id, read_event.instruction_id};
    StaticEventID w_id = {write_event.thread_id, write_event.instruction_id};

    auto r_it = rf_edge_frequencies.find(r_id);
    if (r_it == rf_edge_frequencies.end()) {
        rf_edge_frequencies[r_id] = {{w_id, 1}};
        return 1;
    } else {
        auto w_it = r_it->second.find(w_id);
        if (w_it == r_it->second.end()) {
            r_it->second[w_id] = 1;
            return 1;
        } else {
            w_it->second += 1;
            return 0;
        }
    }
}

extern "C" void update_rf_footprint_for_graph(SkeletonGraph* graph) {
    if (!graph) return;
    for (const auto& [write_tuple, read_list] : graph->get_rf()) {
        EventTriple write_event = {std::get<0>(write_tuple), std::get<1>(write_tuple), std::get<2>(write_tuple)};
        for (const auto& read_tuple : read_list) {
            EventTriple read_event = {std::get<0>(read_tuple), std::get<1>(read_tuple), std::get<2>(read_tuple)};
            update_rf_footprint(write_event, read_event);
        }
    }
}

extern "C" uint32_t get_rf_footprint_coverage_count() {
    uint32_t total_edges = 0;
    for (const auto& [read_id, src_map] : rf_edge_frequencies) {
        total_edges += src_map.size();
    }
    return total_edges;
}

extern "C" void print_rf_edge_frequencies() {
    for (const auto& [read_id, src_map] : rf_edge_frequencies) {
        for (const auto& [write_id, freq] : src_map) {
            SAYF("[RF] Write (T%d, I%lld) -> Read (T%d, I%lld): %u times\n",
                 write_id.thread_id, write_id.instruction_id,
                 read_id.thread_id, read_id.instruction_id,
                 freq);
        }
    }
}

extern "C" uint32_t get_rf_footprint_edge_freq(EventTriple write_event, EventTriple read_event) {
    StaticEventID r_id = {read_event.thread_id, read_event.instruction_id};
    StaticEventID w_id = {write_event.thread_id, write_event.instruction_id};

    auto r_it = rf_edge_frequencies.find(r_id);
    if (r_it != rf_edge_frequencies.end()) {
        auto w_it = r_it->second.find(w_id);
        if (w_it != r_it->second.end()) {
            return w_it->second;
        }
    }
    return 0;
}

extern "C" uint32_t get_sum_rf_frequencies_for_read(EventTriple read_event) {
    StaticEventID r_id = {read_event.thread_id, read_event.instruction_id};

    auto r_it = rf_edge_frequencies.find(r_id);
    if (r_it != rf_edge_frequencies.end()) {
        uint32_t total_freq = 0;
        for (const auto& [write_id, freq] : r_it->second) {
            total_freq += freq;
        }
        return total_freq;
    }
    return 0;
}

extern "C" double skeleton_graph_rf_footprint_calc(SkeletonGraph* graph) {
    if (!graph) return 1.0;

    double total_ratio = 0.0;
    double max_possible_ratio = 0.0;

    for (const auto& [write_tuple, read_list] : graph->get_rf()) {
        EventTriple write_event = {std::get<0>(write_tuple), std::get<1>(write_tuple), std::get<2>(write_tuple)};
        for (const auto& read_tuple : read_list) {
            EventTriple read_event = {std::get<0>(read_tuple), std::get<1>(read_tuple), std::get<2>(read_tuple)};

            const uint32_t current_edge_freq = get_rf_footprint_edge_freq(write_event, read_event);
            const uint32_t sum_all_rf_for_read = get_sum_rf_frequencies_for_read(read_event);

            double ratio = 0.0;
            if (sum_all_rf_for_read > 0) {
                ratio = (double)current_edge_freq / (double)sum_all_rf_for_read;
                if (ratio > 1.0) ratio = 1.0;
                if (ratio < 0.0) ratio = 0.0;
            }

            total_ratio += (1.0 - ratio);
            max_possible_ratio += 1.0;
        }
    }

    if (max_possible_ratio <= 0.0) {
        return 1.0;
    }

    double normalized_score = total_ratio / max_possible_ratio;
    if (normalized_score < 0.0) normalized_score = 0.0;
    if (normalized_score > 1.0) normalized_score = 1.0;

    double final_score = 1.0 + (normalized_score * 99.0);
    if (final_score < 1.0) final_score = 1.0;
    if (final_score > 100.0) final_score = 100.0;

    return final_score;
}
