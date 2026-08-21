#ifndef EG_H
#define EG_H

#include <stdint.h>
#include <stdio.h>

#define EG_OP_READ 0
#define EG_OP_WRITE 1
#define EG_OP_RMW   2
#define EG_OP_FENCE 3
// Add others as needed

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
