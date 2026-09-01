#include "sgf-fuzz.h"
#include "skeleton_graph.hpp"
#include "skeleton_graph_events.hpp"
#include "potential_nn.h"
#include "skeleton_queue_pruning.hpp"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" {
#include "skeleton_graph_mutator_wrapper.h"
}

// Directed edge between two graph events (MO or RF), used as a compaction key.
using DirectedEdgeKey = std::pair<EventID, EventID>;

struct DirectedEdgeKeyHash {
    size_t operator()(const DirectedEdgeKey& e) const {
        TripleHash th;
        size_t h1 = th(e.first);
        size_t h2 = th(e.second);
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};

extern "C" void clear_and_compact_queue_after_phases(sgf_state_t *sgf, uint32_t keep_per_edge) {
    if (!sgf || sgf->queued_items <= 1) return;
    if (keep_per_edge == 0) keep_per_edge = 10;

    ACTF("[*] CLEAR_QUEUE_AFTER_PHASES: Starting queue compaction at cycle %llu (current queue size: %u, keep_per_edge: %u)",
         sgf->queue_cycle, sgf->queued_items, keep_per_edge);

    // Map each unique MO edge -> vector of active queue entries containing that edge
    std::unordered_map<DirectedEdgeKey, std::vector<struct queue_entry*>, DirectedEdgeKeyHash> mo_edge_entries;
    // Map each unique RF edge -> vector of active queue entries containing that edge
    std::unordered_map<DirectedEdgeKey, std::vector<struct queue_entry*>, DirectedEdgeKeyHash> rf_edge_entries;

    // 1. Scan all active queue entries in memory and index their MO and RF edges
    for (u32 i = 0; i < sgf->queued_items; i++) {
        struct queue_entry *q = sgf->queue_buf[i];
        if (!q || !q->graph_data) continue;

        // Ensure skeleton_graph is loaded if needed
        if (!q->graph_data->skeleton_graph && q->fname) {
            q->graph_data->skeleton_graph = read_from_json((char*)q->fname);
        }

        SkeletonGraph *graph = q->graph_data->skeleton_graph;
        if (!graph) continue;

        // Extract and index all MO edges for this graph (consecutive events per location)
        for (const auto& [loc, mo_list] : graph->get_mo_by_location()) {
            if (mo_list.size() < 2) continue;
            for (size_t j = 0; j < mo_list.size() - 1; j++) {
                DirectedEdgeKey edge = { mo_list[j], mo_list[j + 1] };
                mo_edge_entries[edge].push_back(q);
            }
        }

        // Extract and index all RF edges for this graph
        for (const auto& [write_event, read_list] : graph->get_rf()) {
            for (const auto& read_event : read_list) {
                DirectedEdgeKey edge = { write_event, read_event };
                rf_edge_entries[edge].push_back(q);
            }
        }
    }

    // 2. Select top entries for each MO and RF edge based on perf_score
    std::unordered_set<struct queue_entry*> survivors;

    // Unconditionally preserve the seed entry (id 0)
    for (u32 i = 0; i < sgf->queued_items; i++) {
        struct queue_entry *q = sgf->queue_buf[i];
        if (q && q->id == 0) {
            survivors.insert(q);
        }
    }
    if (sgf->queued_items > 0 && sgf->queue_buf[0]) {
        survivors.insert(sgf->queue_buf[0]);
    }

    auto score_comparator = [](const struct queue_entry* a, const struct queue_entry* b) {
        if (a->perf_score != b->perf_score) {
            return a->perf_score > b->perf_score;
        }
        return a->id < b->id;
    };

    // Keep top entries for each MO edge
    for (auto& [edge, entries] : mo_edge_entries) {
        std::sort(entries.begin(), entries.end(), score_comparator);
        size_t count = std::min((size_t)keep_per_edge, entries.size());
        for (size_t k = 0; k < count; k++) {
            survivors.insert(entries[k]);
        }
    }

    // Keep top entries for each RF edge
    for (auto& [edge, entries] : rf_edge_entries) {
        std::sort(entries.begin(), entries.end(), score_comparator);
        size_t count = std::min((size_t)keep_per_edge, entries.size());
        for (size_t k = 0; k < count; k++) {
            survivors.insert(entries[k]);
        }
    }

    u32 prev_count = sgf->queued_items;

    // 3. Free memory for all discarded entries
    for (u32 i = 0; i < prev_count; i++) {
        struct queue_entry *q = sgf->queue_buf[i];
        if (!q) continue;

        if (survivors.find(q) == survivors.end()) {
            // Free metadata and graph structures
            if (q->graph_data) {
                if (q->graph_data->skeleton_potential) {
                    destroy_skeleton_potential(q->graph_data->skeleton_potential);
                    q->graph_data->skeleton_potential = NULL;
                }
                if (q->graph_data->race_pairs) {
                    race_pair_store_destroy(q->graph_data->race_pairs);
                    q->graph_data->race_pairs = NULL;
                }
                if (q->graph_data->simulator_feedback) {
                    destroy_simulator_feedback(q->graph_data->simulator_feedback);
                    q->graph_data->simulator_feedback = NULL;
                }
                if (q->graph_data->forbidden_mutations) {
                    forbidden_mutations_destroy(q->graph_data->forbidden_mutations);
                    q->graph_data->forbidden_mutations = NULL;
                }
                if (q->graph_data->skeleton_graph) {
                    destroy_SkeletonGraph(q->graph_data->skeleton_graph);
                    q->graph_data->skeleton_graph = NULL;
                }
                ck_free(q->graph_data);
                q->graph_data = NULL;
            }
            if (q->fname) {
                ck_free(q->fname);
                q->fname = NULL;
            }
            if (q->trace_mini) {
                ck_free(q->trace_mini);
                q->trace_mini = NULL;
            }
            if (q->testcase_buf) {
                ck_free(q->testcase_buf);
                q->testcase_buf = NULL;
            }
            ck_free(q);
            sgf->queue_buf[i] = NULL;
        } else {
            // Check if mother of surviving entry was freed
            if (q->mother && survivors.find(q->mother) == survivors.end()) {
                q->mother = NULL;
            }
        }
    }

    // 4. Compact sgf->queue_buf in place
    u32 new_count = 0;
    for (u32 i = 0; i < prev_count; i++) {
        if (sgf->queue_buf[i] != NULL) {
            sgf->queue_buf[new_count++] = sgf->queue_buf[i];
        }
    }

    sgf->queued_items = new_count;
    sgf->active_items = new_count;
    sgf->queue = (new_count > 0) ? sgf->queue_buf[0] : NULL;
    sgf->queue_top = (new_count > 0) ? sgf->queue_buf[new_count - 1] : NULL;
    sgf->queue_cur = (new_count > 0) ? sgf->queue_buf[0] : NULL;
    sgf->current_entry = 0;

    // Reset pending_not_fuzzed so surviving items are reconsidered across new cycles
    sgf->pending_not_fuzzed = new_count;
    sgf->pending_favored = 0;
    for (u32 i = 0; i < new_count; i++) {
        sgf->queue_buf[i]->was_fuzzed = false;
        sgf->queue_buf[i]->favored = 0;
    }

    // 5. Reset dynamic cutoff score to start fresh
    sgf->cutoff_score = 0.0;
    sgf->queued_mu = 0.0;
    sgf->queued_mad = 0.0;

    // 6. Reset and rebuild Potential NN Index with surviving entries only, and reset children_enqueued
    potential_nn_index_reset();
    for (u32 i = 0; i < new_count; i++) {
        struct queue_entry *q = sgf->queue_buf[i];
        if (q && q->graph_data) {
            q->graph_data->children_enqueued = 0;
            if (q->graph_data->skeleton_potential) {
                potential_nn_index_add(q, q->graph_data->skeleton_potential);
                q->graph_data->potential_indexed = 1;
            }
        }
    }

    // 7. Rebuild the alias table for queue selection
    sgf->reinit_table = 1;
    create_alias_table(sgf);

    sgf->last_cleared_queue_count = new_count;

    OKF("[+] CLEAR_QUEUE_AFTER_PHASES: Compacted queue from %u to %u entries (kept top %u per MO/RF edge + seed)",
        prev_count, new_count, keep_per_edge);
}
