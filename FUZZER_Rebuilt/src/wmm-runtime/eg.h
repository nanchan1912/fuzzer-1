#ifndef EG_H
#define EG_H

#include <stdint.h>
#include <stdio.h>

/* These values go on the wire to AFL via Shared_event::event_type and MUST
 * match the WMM_EV_* contract in Main/include/shm_next_events.h.
 * scheduler.c static_asserts them against that header; this file keeps plain
 * literals so it stays includable without the AFL include path (tests/run_tests.sh
 * compiles with -I<runtime dir> only).
 *
 * APPEND ONLY, and note there is deliberately no EG_OP_* at 4: that value
 * belongs to AFL's EOP, which has no runtime counterpart.
 *
 * A CAS reads unconditionally but writes only when it succeeds, which is why
 * the two outcomes are distinct types rather than one type plus a flag:
 * CAS_SUCCESS is write-like (a legal rf source), CAS_FAIL is read-like only.
 */
#define EG_OP_READ        0
#define EG_OP_WRITE       1
#define EG_OP_RMW         2
#define EG_OP_FENCE       3
/* 4 reserved for AFL's EOP */
#define EG_OP_CAS_SUCCESS 5
#define EG_OP_CAS_FAIL    6
/* Outcome undetermined -- published to AFL as feedback for a cmpxchg the
 * runtime has never executed, and never valid as an input node type. See the
 * comment on WMM_EV_CAS. Deliberately absent from the three predicates below:
 * it is neither read-like nor write-like because that is precisely what is not
 * yet decided, so any check site reached by an unresolved CAS is a bug and
 * should fail loudly rather than pick a side. */
#define EG_OP_CAS         7

/* Structural classification of an event type. These mirror
 * is_read_like/is_write_like/is_rmw_like in
 * Main/include/skeleton_graph_events.hpp -- keep the two in sync.
 * Prefer these over open-coded comparisons so a future event type only needs
 * these three functions updated. */
static inline int eg_is_read_like(int t) {
    return t == EG_OP_READ || t == EG_OP_RMW ||
           t == EG_OP_CAS_SUCCESS || t == EG_OP_CAS_FAIL;
}
static inline int eg_is_write_like(int t) {
    return t == EG_OP_WRITE || t == EG_OP_RMW || t == EG_OP_CAS_SUCCESS;
}
/* RMW atomicity: a failed CAS does not write, so it does not consume a write. */
static inline int eg_is_rmw_like(int t) {
    return t == EG_OP_RMW || t == EG_OP_CAS_SUCCESS;
}

#ifndef WMM_EXIT_EVENT_NOT_FOUND
#define WMM_EXIT_EVENT_NOT_FOUND 10
#endif

#ifndef WMM_EXIT_EVENT_MISMATCH
#define WMM_EXIT_EVENT_MISMATCH 11
#endif

#ifndef WMM_EXIT_RF_TYPE_MISMATCH
#define WMM_EXIT_RF_TYPE_MISMATCH 12
#endif

#ifndef WMM_EXIT_INVALID_INPUT
#define WMM_EXIT_INVALID_INPUT WMM_EXIT_RF_TYPE_MISMATCH
#endif

#ifndef WMM_EXIT_INSTANTIATED_BUT_NOT_DONE
#define WMM_EXIT_INSTANTIATED_BUT_NOT_DONE 20
#endif

#ifndef WMM_EXIT_NOT_INSTANTIABLE
#define WMM_EXIT_NOT_INSTANTIABLE 21
#endif

#define EXIT_EVENT_NOT_FOUND WMM_EXIT_EVENT_NOT_FOUND
#define EXIT_EVENT_MISMATCH WMM_EXIT_EVENT_MISMATCH
#define EXIT_RF_TYPE_MISMATCH WMM_EXIT_RF_TYPE_MISMATCH

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t id;                // Unique Event ID
    uint64_t tid;               // Thread ID
    long long instruction_id;   // Static Instruction ID from LLVM Pass
    uint64_t loc_id;            // Static location ID from instrumentation
    int visit_id;          // Dynamic Visit Count (loop iteration)
    int type;              // Operation Type
    char location[64];     // Symbolic location name (e.g., "x") or address string
    intptr_t value;        // Expected value (for constraints)
} eg_node_t;

typedef struct {
    uint64_t src_id;
    uint64_t dst_id;
} eg_edge_t;

typedef struct {
    eg_node_t *nodes;
    int node_count;
    int node_capacity;

    eg_edge_t *rf_edges;
    int rf_count;
    int rf_capacity;
    
    // Future: PO, MO edges
} eg_graph_t;

// API
eg_graph_t* eg_create(void);
void eg_free(eg_graph_t *g);

// Adders
void eg_add_node(eg_graph_t *g, uint64_t id, uint64_t tid, long long sid,
                 uint64_t loc_id, int vid, int type,
                 const char *loc, intptr_t val);
void eg_add_edge_rf(eg_graph_t *g, uint64_t write_id, uint64_t read_id);

// Serialization
void eg_serialize(eg_graph_t *g, const char *filename);
eg_graph_t* eg_deserialize(const char *filename);

// Legacy JSON Serialization (kept for compatibility)
void eg_serialize_json(eg_graph_t *g, const char *filename);
eg_graph_t* eg_deserialize_json(const char *filename);
eg_graph_t* eg_deserialize_json_mem(const char *buf, size_t size);

// Buffer APIs
void eg_serialize_mem(eg_graph_t *g, char **out_buf, size_t *out_size);
eg_graph_t* eg_deserialize_mem(const char *buf, size_t size);

// Helper to find nodes
eg_node_t* eg_find_node_by_id(eg_graph_t *g, uint64_t id);
eg_node_t* eg_find_node_by_dynamic(eg_graph_t *g, uint64_t tid, long long sid, int vid);
eg_node_t* eg_find_node_by_uid(eg_graph_t *g, uint64_t uid);

#ifdef __cplusplus
}
#endif

#endif
