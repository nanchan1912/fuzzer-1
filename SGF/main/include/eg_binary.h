#ifndef EG_BINARY_H
#define EG_BINARY_H
/* Flat binary encoding for a skeleton graph, additive alongside the JSON
 * format: a header + packed node array + packed rf-edge array, loaded with
 * one read() and walked in place, no tokenizer, no per-node malloc, no
 * UTF-8 validation. Only carries what the simulator (src/wmm-runtime/eg.c)
 * actually reads from a graph: nodes + rf edges -- mo/sw/tcj/po are not on
 * the wire in v1 and can be added additively in a future version bump if
 * ever needed.
 *
 * Shared, single source of truth for both sides of the wire: the writer
 * (AFL_patches/src/skeleton_mutator_helper.cpp) and the reader
 * (src/wmm-runtime/eg.c) both include this file -- wmm-runtime's Makefile
 * already puts AFL_patches/include on its -I path for exactly this kind of
 * shared wire-protocol header (see shm_next_events.h).
 *
 * rf edges are addressed by (tid, instruction_id, visit_id) triples, not by
 * the runtime's internally-assigned sequential node id, mirroring exactly
 * what the JSON format already does (eg_graph_from_json_node resolves each
 * "from"/"to" via eg_find_node_by_dynamic) -- this keeps the binary reader
 * on the same node-resolution path as the JSON reader instead of inventing
 * a second id scheme the writer would have to replicate.
 */
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define EG_BIN_MAGIC   0x31424745u /* bytes "EGB1", read as a little-endian u32 */
#define EG_BIN_VERSION 1u
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t node_count;
    uint32_t rf_count;
} eg_bin_header_t;
typedef struct {
    uint64_t tid;
    int64_t  instruction_id;
    int32_t  visit_id;
    int32_t  type;       /* EG_OP_* / WMM_EV_* -- see eg.h / shm_next_events.h */
    char     location[64]; /* The location string as AFL_patches' Event model
                             * carries it (== the JSON "loc_id" field's string
                             * value, e.g. "0xA" or "0xA:field_index=..."), not
                             * the runtime's separate symbolic-name concept.
                             * The reader derives the numeric loc_id from this
                             * exactly like the JSON path does
                             * (parse_field_sensitive_loc_id), so the two
                             * loaders stay on one source of truth for that
                             * parsing instead of duplicating it here. */
    int64_t  value;
} eg_bin_node_t;
typedef struct {
    uint64_t src_tid;
    int64_t  src_instruction_id;
    int32_t  src_visit_id;
    uint64_t dst_tid;
    int64_t  dst_instruction_id;
    int32_t  dst_visit_id;
} eg_bin_edge_t;
#ifdef __cplusplus
}
#endif
#endif
