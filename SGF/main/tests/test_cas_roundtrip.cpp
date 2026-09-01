/* Stage 1 verification: CAS survives the AFL graph JSON round-trip.
 *
 * Isolated from the runtime and the fuzzer loop on purpose -- this exercises
 * only event_type_from_string / event_type_to_string and the graph
 * (de)serializers, which is where an unknown kind either throws outright or,
 * worse, gets swallowed by the catch(...) in serialize_graph_c and silently
 * produces no output.
 */

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "skeleton_graph_events.hpp"
#include "skeleton_graph.hpp"
#include "skeleton_graph_mutator_wrapper.h"
#include "skeleton_mutator_helper.hpp"
#include "static_program_abstraction.hpp"

/* AFL's PRNG lives in afl-performance.o, which is built as LTO bitcode and so
 * cannot be linked into a plain test binary. Nothing on the round-trip path
 * actually draws randomness, but the mutator translation unit references it,
 * so supply a deterministic stand-in to satisfy the linker. */
extern "C" SGF_RAND_RETURN rand_next(sgf_state_t *) { return 0; }

static int failures = 0;

static void check(bool cond, const std::string& what) {
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what.c_str());
    if (!cond) { ++failures; }
}

/* A graph with one write per location feeding one of each read-like kind, so
 * every RF/MO invariant is satisfiable and the only variable is the kind. */
static const char* kGraphJson = R"JSON({
  "nodes": [
    {"event_id":"1","thread_id":"0","instruction_id":"100","visit_id":"1","kind":"W","loc_id":"0xA","access_mode":"NA"},
    {"event_id":"2","thread_id":"1","instruction_id":"200","visit_id":"1","kind":"RMW","loc_id":"0xA","access_mode":"RLX"},
    {"event_id":"3","thread_id":"2","instruction_id":"300","visit_id":"1","kind":"CAS_SUCCESS","loc_id":"0xA","access_mode":"ACQ"},
    {"event_id":"4","thread_id":"3","instruction_id":"400","visit_id":"1","kind":"CAS_FAIL","loc_id":"0xA","access_mode":"RLX"},
    {"event_id":"5","thread_id":"4","instruction_id":"500","visit_id":"1","kind":"CAS_SUCCESS","loc_id":"0xB","access_mode":"RLX"},
    {"event_id":"6","thread_id":"5","instruction_id":"600","visit_id":"1","kind":"R","loc_id":"0xB","access_mode":"RLX"},
    {"event_id":"7","thread_id":"5","instruction_id":"700","visit_id":"1","kind":"W","loc_id":"0xB","access_mode":"NA"}
  ],
  "rf_edges": [
    {"from":[0,100,1],"to":[[1,200,1]]},
    {"from":[1,200,1],"to":[[2,300,1]]},
    {"from":[2,300,1],"to":[[3,400,1]]},
    {"from":[5,700,1],"to":[[4,500,1],[5,600,1]]}
  ],
  "sw_edges": [],
  "tcj_edges": [],
  "po_per_thread": [],
  "mo_per_location": [
    {"location":"0xA","list":[[0,100,1],[1,200,1],[2,300,1]]},
    {"location":"0xB","list":[[5,700,1],[4,500,1]]}
  ]
})JSON";

int main() {
    const char* in_path = "/tmp/cas_rt_in.json";
    const char* out_path = "/tmp/cas_rt_out.json";

    { std::ofstream f(in_path); f << kGraphJson; }

    printf("Stage 1: CAS graph JSON round-trip\n");

    // 1. Parse. Before this change, "CAS_SUCCESS" threw from
    //    event_type_from_string and killed the caller.
    SkeletonGraph* g = read_from_json(in_path);
    check(g != nullptr, "read_from_json accepts CAS_SUCCESS / CAS_FAIL");
    if (!g) { printf("\n%d failure(s)\n", failures); return 1; }

    // 2. Count the kinds that came back.
    int n_cas_success = 0, n_cas_fail = 0, n_rmw = 0, n_read = 0, n_write = 0;
    for (const auto& kv : g->get_events()) {
        switch (kv.second.get_event_type()) {
            case Event_Type::CAS_SUCCESS: ++n_cas_success; break;
            case Event_Type::CAS_FAIL:    ++n_cas_fail;    break;
            case Event_Type::RMW:         ++n_rmw;         break;
            case Event_Type::READ:        ++n_read;        break;
            case Event_Type::WRITE:       ++n_write;       break;
            default: break;
        }
    }
    check(n_cas_success == 2, "CAS_SUCCESS preserved (expected 2, got "
                              + std::to_string(n_cas_success) + ")");
    check(n_cas_fail == 1, "CAS_FAIL preserved (expected 1, got "
                           + std::to_string(n_cas_fail) + ")");
    check(n_rmw == 1, "RMW still means RMW (expected 1, got "
                      + std::to_string(n_rmw) + ")");

    // 3. Serialize. A missing case in event_type_to_string throws and is
    //    swallowed by serialize_graph_c's catch(...), so a zero-byte result
    //    here is the silent-failure mode we care about most.
    size_t written = write_to_json(out_path, g);
    check(written > 0, "write_to_json produced output (" + std::to_string(written) + " bytes)");

    std::ifstream chk(out_path);
    std::string body((std::istreambuf_iterator<char>(chk)), std::istreambuf_iterator<char>());
    check(body.find("CAS_SUCCESS") != std::string::npos, "serialized JSON contains CAS_SUCCESS");
    check(body.find("CAS_FAIL") != std::string::npos, "serialized JSON contains CAS_FAIL");

    // 4. Re-parse the serialized form: the vocabulary must be closed under
    //    write-then-read, which also proves to_string emits a string
    //    from_string accepts.
    SkeletonGraph* g2 = read_from_json(out_path);
    check(g2 != nullptr, "re-parse of serialized graph succeeds");
    if (g2) {
        int s2 = 0, f2 = 0;
        for (const auto& kv : g2->get_events()) {
            if (kv.second.get_event_type() == Event_Type::CAS_SUCCESS) ++s2;
            if (kv.second.get_event_type() == Event_Type::CAS_FAIL)    ++f2;
        }
        check(s2 == n_cas_success && f2 == n_cas_fail,
              "kind counts stable across round-trip (" + std::to_string(s2) + "/"
              + std::to_string(f2) + ")");
        destroy_SkeletonGraph(g2);
    }

    destroy_SkeletonGraph(g);

    // 5. Bare "CAS" means "outcome undecided" and belongs only to the two input
    //    directions that genuinely cannot know it: the .ccfg from the static
    //    analysis, and the wire byte from runtime feedback. A skeleton graph is
    //    a fuzzer *output*, by which point add_new_node has resolved every CAS,
    //    so the graph reader must reject it rather than re-guess an outcome --
    //    the old alias-to-CAS_SUCCESS behaviour is exactly what made the
    //    failure half of every CAS unreachable.
    printf("\nStage 2: bare \"CAS\" is input-only\n");

    check(parse_event_type("CAS") == Event_Type::CAS,
          "parse_event_type (.ccfg) maps \"CAS\" to the undecided type");

    /* This tree's Event_Type has no EOP enumerator (never ported -- nothing
     * references it), unlike upstream. Any non-CAS value works as the
     * sentinel here; FENCE is arbitrary. */
    Event_Type wire_type = Event_Type::FENCE;
    check(event_type_from_wire(WMM_EV_CAS, wire_type) && wire_type == Event_Type::CAS,
          "wire decode maps WMM_EV_CAS to the undecided type");

    check(!is_read_like(Event_Type::CAS) && !is_write_like(Event_Type::CAS) &&
          !is_rmw_like(Event_Type::CAS),
          "an undecided CAS matches no structural class");

    bool threw = false;
    try { (void)event_type_from_string("CAS"); } catch (...) { threw = true; }
    check(threw, "skeleton-graph reader rejects bare \"CAS\"");

    threw = false;
    try { (void)event_type_to_string(Event_Type::CAS); } catch (...) { threw = true; }
    check(threw, "skeleton-graph writer rejects an unresolved CAS");

    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
