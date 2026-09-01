/* Stage 6 verification: MUT_FLIP_CAS keeps the graph structurally valid.
 *
 * Drives flip_cas_outcome directly rather than through mutate_skeleton_graph,
 * so the test does not depend on the random dispatch happening to pick it.
 *
 * After every flip the graph must still satisfy the invariants the simulator
 * relies on. The two that a careless flip breaks:
 *
 *   - a CAS_FAIL must not appear in mo (it does not write), and must not be
 *     an rf source
 *   - a CAS_SUCCESS must appear exactly once in mo, and at most one rmw-like
 *     event may read any given write
 *
 * Each mutated graph is also written out so check_graph_invariants.py can
 * re-verify them independently.
 */

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "skeleton_graph_events.hpp"
#include "skeleton_graph.hpp"
#include "skeleton_graph_mutator_wrapper.h"

extern "C" SGF_RAND_RETURN rand_next(sgf_state_t *) { return 0; }

/* Defined in skeleton_graph_mutator.cpp. */
bool flip_cas_outcome(SkeletonGraph* graph);

static int failures = 0;
static void check(bool cond, const std::string& what) {
    if (!cond) { printf("  [FAIL] %s\n", what.c_str()); ++failures; }
}

/* n1 (W) -> n2 (CAS_SUCCESS) -> n3 (CAS_FAIL), all on location 0xA.
 * n2 writes so it is in mo and is a legal rf source for n3.
 *
 * n4 (W) is a second, unrelated write already sitting in mo right after n2.
 * Its only job is to distinguish "insert immediately after the rf source"
 * from "append to the end of mo": when n2 later flips back from CAS_FAIL to
 * CAS_SUCCESS (still reading from n1), a correct flip re-inserts it between
 * n1 and n4, while a buggy append-to-end would put it after n4 instead. */
static const char* kSeed = R"JSON({
  "nodes": [
    {"event_id":"1","thread_id":"0","instruction_id":"100","visit_id":"1","kind":"W","loc_id":"0xA","access_mode":"NA"},
    {"event_id":"2","thread_id":"1","instruction_id":"200","visit_id":"1","kind":"CAS_SUCCESS","loc_id":"0xA","access_mode":"RLX"},
    {"event_id":"3","thread_id":"2","instruction_id":"300","visit_id":"1","kind":"CAS_FAIL","loc_id":"0xA","access_mode":"RLX"},
    {"event_id":"4","thread_id":"3","instruction_id":"400","visit_id":"1","kind":"W","loc_id":"0xA","access_mode":"NA"}
  ],
  "rf_edges": [
    {"from":[0,100,1],"to":[[1,200,1]]},
    {"from":[1,200,1],"to":[[2,300,1]]}
  ],
  "sw_edges": [], "tcj_edges": [], "po_per_thread": [],
  "mo_per_location": [{"location":"0xA","list":[[0,100,1],[1,200,1],[3,400,1]]}]
})JSON";

/* Re-implements the invariants in C++ so a violation fails the test directly
 * rather than only showing up in the Python checker. */
static void verify(const SkeletonGraph& g, const std::string& ctx) {
    const auto& events = g.get_events();
    const auto& rf = g.get_rf();
    const auto& rf_rev = g.get_rf_reverse();
    const auto& mo = g.get_mo_by_location();

    for (const auto& kv : events) {
        const Event_Type t = kv.second.get_event_type();

        if (is_read_like(t)) {
            auto it = rf_rev.find(kv.first);
            check(it != rf_rev.end() && it->second.size() == 1,
                  ctx + ": read-like event lacks exactly one incoming rf edge");
        }

        // mo membership must track write-ness exactly
        int in_mo = 0;
        for (const auto& loc_kv : mo) {
            for (const auto& id : loc_kv.second) { if (id == kv.first) { ++in_mo; } }
        }
        check(in_mo == (is_write_like(t) ? 1 : 0),
              ctx + ": mo membership wrong for " +
              std::string(is_write_like(t) ? "write-like" : "read-only") +
              " event (found " + std::to_string(in_mo) + ")");
    }

    for (const auto& kv : rf) {
        const Event* src = g.get_event_by_id(kv.first);
        check(src && is_write_like(src->get_event_type()),
              ctx + ": rf source does not write");

        int rmw_readers = 0;
        for (const auto& r : kv.second) {
            const Event* re = g.get_event_by_id(r);
            if (re && is_rmw_like(re->get_event_type())) { ++rmw_readers; }
        }
        check(rmw_readers <= 1, ctx + ": more than one rmw-like reader of a write");
    }

    // Adjacency: a write-like event that also reads (rmw-like, e.g.
    // CAS_SUCCESS) must sit immediately after its single rf source in that
    // location's mo order -- not merely be somewhere in mo.
    for (const auto& kv : rf_rev) {
        if (kv.second.size() != 1) { continue; }
        const Event* ev = g.get_event_by_id(kv.first);
        if (!ev || !is_write_like(ev->get_event_type())) { continue; }
        const EventID& src_id = kv.second.front();
        auto mo_it = mo.find(ev->get_location());
        if (mo_it == mo.end()) { continue; }
        const auto& order = mo_it->second;
        auto src_pos = std::find(order.begin(), order.end(), src_id);
        auto ev_pos = std::find(order.begin(), order.end(), kv.first);
        check(src_pos != order.end() && ev_pos != order.end() &&
              std::next(src_pos) == ev_pos,
              ctx + ": rmw-like write is not immediately after its rf source in mo");
    }
}

int main() {
    const char* seed_path = "/tmp/cas_flip_seed.json";
    { std::ofstream f(seed_path); f << kSeed; }

    printf("Stage 6: MUT_FLIP_CAS invariants\n");

    SkeletonGraph* g = read_from_json(seed_path);
    check(g != nullptr, "seed graph parses");
    if (!g) { printf("\n%d failure(s)\n", failures); return 1; }
    verify(*g, "seed");

    // Flip repeatedly, validating after each one. Types must actually change,
    // otherwise the test would pass trivially on a no-op mutation.
    int flips = 0;
    std::set<std::string> observed;
    for (int i = 0; i < 40; ++i) {
        std::string before;
        for (const auto& kv : g->get_events()) {
            if (kv.second.get_event_type() == Event_Type::CAS_SUCCESS) { before += "S"; }
            if (kv.second.get_event_type() == Event_Type::CAS_FAIL)    { before += "F"; }
        }

        if (!flip_cas_outcome(g)) { continue; }
        ++flips;
        verify(*g, "after flip " + std::to_string(flips));

        std::string after;
        int n_succ = 0, n_fail = 0;
        for (const auto& kv : g->get_events()) {
            if (kv.second.get_event_type() == Event_Type::CAS_SUCCESS) { after += "S"; ++n_succ; }
            if (kv.second.get_event_type() == Event_Type::CAS_FAIL)    { after += "F"; ++n_fail; }
        }
        observed.insert(std::to_string(n_succ) + "/" + std::to_string(n_fail));

        char path[128];
        snprintf(path, sizeof(path), "/tmp/cas_flip_out_%02d.json", flips);
        size_t n = write_to_json(path, g);
        check(n > 0, "mutated graph serializes");
    }

    check(flips > 0, "at least one flip happened");
    printf("  %d flip(s) applied; CAS success/fail distributions seen: ", flips);
    for (const auto& o : observed) { printf("%s ", o.c_str()); }
    printf("\n");
    check(observed.size() > 1, "flips actually changed the outcome distribution");

    destroy_SkeletonGraph(g);
    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
