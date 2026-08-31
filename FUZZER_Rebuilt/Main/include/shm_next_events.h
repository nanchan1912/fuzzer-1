#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <tuple>
#include <string>

using ThreadID = int;
using InstructionID = long long;
using VisitID = int;
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef int ThreadID;
typedef long long InstructionID;
typedef int VisitID;
#endif

// #define MAX_NEXT 4096
// the scheduler is restricting the number of threads to 128 currently
// there is only one node per thread, so setting this to 128 for now
#define MAX_NEXT 128
// There could be more than 1 parent for a next node - but that too cannot exceed the thread count 
#define MAX_SRC_NODES 128 

/* Wire values for Shared_event::event_type.
 *
 * This is the single numeric contract between the runtime (which writes
 * EG_OP_* from eg.h) and AFL (which reads Event_Type from
 * skeleton_graph_events.hpp). Both sides static_assert against these, so the
 * two enums can never drift apart silently.
 *
 * APPEND ONLY. Value 4 is permanently reserved for AFL's EOP, which the
 * runtime has no counterpart for and never puts on the wire -- do not reuse
 * it. Inserting rather than appending would reinterpret every value above the
 * insertion point in an already-built binary on the other side of the shm.
 */
#define WMM_EV_READ        0
#define WMM_EV_WRITE       1
#define WMM_EV_RMW         2
#define WMM_EV_FENCE       3
#define WMM_EV_EOP         4  /* AFL-only, never on the wire */
#define WMM_EV_CAS_SUCCESS 5
#define WMM_EV_CAS_FAIL    6
/* Outcome undetermined. Feedback-only: the runtime publishes this for a
 * cmpxchg it has never seen, because at that point it cannot know whether the
 * comparison will succeed -- the value the CAS reads is chosen by the rf edge
 * the fuzzer has not yet added. Only the fuzzer can decide the outcome, so it
 * resolves every CAS to CAS_SUCCESS or CAS_FAIL before serializing a graph;
 * the runtime never accepts this value as an input node type. */
#define WMM_EV_CAS         7
#define WMM_EV_MAX         7

struct Event_id_triple {
    ThreadID tid;
    InstructionID iid;
    VisitID vid;
};

struct Shared_event {

    ThreadID tid;
    InstructionID iid;
    VisitID vid;

    uint8_t event_type;
    uint8_t access_mode;
    uint64_t location;
    uint64_t source_nodes_count;
    struct Event_id_triple source_nodes[MAX_SRC_NODES];
};

struct SHM_next_events {
    bool ready;
    // next shared event & set of source nodes along each thread
    uint64_t next_event_count; //REVISIT: is this necessary?
    struct Shared_event next_events[MAX_NEXT];
};


#ifdef __cplusplus

namespace shm_next_events {

/* SGF side */
int create_shm_next_events();
void destroy_shm_next_events();

/* Target side */
bool attach_shm_next_events();

/* Common */
SHM_next_events* get_next_events();

/* Publishing helpers */
void begin_update();
void finish_update();

}

extern "C" {
#endif

/* C-compatible wrappers */
int create_shm_next_events_c(void);
void destroy_shm_next_events_c(void);
struct SHM_next_events* get_shm_next_events_c(void);
void begin_update_c(void);
void finish_update_c(void);

#ifdef __cplusplus
}
#endif
