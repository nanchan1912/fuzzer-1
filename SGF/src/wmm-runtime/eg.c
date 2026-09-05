#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "eg.h"
#include "json.h"
#include "scheduler.h" /* for scheduler_terminate, used by eg_validate_cas_resolved */
#include "eg_binary.h"

#ifdef QUIET
#define EG_LOG(...) do {} while (0)
#else
#define EG_LOG(...) printf(__VA_ARGS__)
#endif

#define DEFAULT_VISIT_ID 1

eg_graph_t* eg_create(void) {
    eg_graph_t *g = malloc(sizeof(eg_graph_t));
    if (!g) return NULL;
    g->node_count = 0;
    g->node_capacity = 1024;
    g->nodes = malloc(sizeof(eg_node_t) * g->node_capacity);
    if (!g->nodes) {
        free(g);
        return NULL;
    }
    
    g->rf_count = 0;
    g->rf_capacity = 1024;
    g->rf_edges = malloc(sizeof(eg_edge_t) * g->rf_capacity);
    if (!g->rf_edges) {
        free(g->nodes);
        free(g);
        return NULL;
    }

    g->hash_table_size = EG_HASH_SIZE;
    g->hash_table = malloc(sizeof(int) * g->hash_table_size);
    if (!g->hash_table) {
        free(g->rf_edges);
        free(g->nodes);
        free(g);
        return NULL;
    }
    memset(g->hash_table, -1, sizeof(int) * g->hash_table_size);
    return g;
}

void eg_free(eg_graph_t *g) {
    if (!g) return;
    free(g->nodes);
    free(g->rf_edges);
    free(g->hash_table);
    free(g);
}

static inline uint32_t hash_dynamic(uint64_t tid, long long iid, int vid, uint32_t size) {
    uint64_t h = tid ^ (uint64_t)iid ^ (uint64_t)vid;
    h = (~h) + (h << 18);
    h = h ^ (h >> 31);
    h = h * 2654435761ULL;
    h = h ^ (h >> 16);
    return (uint32_t)(h & (size - 1));
}

static bool eg_resize_hash_table(eg_graph_t *g) {
    int old_size = g->hash_table_size;
    int new_size = old_size * 2;
    int *new_table = malloc(sizeof(int) * new_size);
    if (!new_table) return false;

    memset(new_table, -1, sizeof(int) * new_size);
    for (int i = 0; i < g->node_count; i++) {
        eg_node_t *n = &g->nodes[i];
        uint32_t idx = hash_dynamic(n->tid, n->instruction_id, n->visit_id, new_size);
        while (new_table[idx] != -1) {
            idx = (idx + 1) & (new_size - 1);
        }
        new_table[idx] = i;
    }
    free(g->hash_table);
    g->hash_table = new_table;
    g->hash_table_size = new_size;
    return true;
}

void eg_add_node(eg_graph_t *g, uint64_t id, uint64_t tid, long long iid,
                 uint64_t loc_id, int vid, int type,
                 const char *loc, intptr_t val) {
    if (!g) return;
    if (g->node_count >= g->node_capacity) {
        size_t new_capacity = g->node_capacity * 2;
        eg_node_t *tmp = realloc(g->nodes, sizeof(eg_node_t) * new_capacity);
        if (!tmp) {
            fprintf(stderr, "[EG] Error: Out of memory during eg_nodes realloc.\n");
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        g->nodes = tmp;
        g->node_capacity = new_capacity;
    }

    // Resize hash table if load factor is high (>70%)
    if (g->hash_table && g->node_count * 10 >= g->hash_table_size * 7) {
        eg_resize_hash_table(g);
    }

    int node_idx = g->node_count;
    eg_node_t *n = &g->nodes[g->node_count++];
    n->id = id;
    n->tid = tid;
    n->instruction_id = iid;
    n->loc_id = loc_id;
    n->visit_id = vid;
    n->type = type;
    strncpy(n->location, loc ? loc : "", 63);
    n->location[63] = 0;
    n->value = val;

    if (g->hash_table) {
        if (g->node_count >= g->hash_table_size) {
            fprintf(stderr, "[EG] Error: Hash table full, cannot insert node.\n");
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        uint32_t idx = hash_dynamic(tid, iid, vid, g->hash_table_size);
        int steps = 0;
        while (g->hash_table[idx] != -1 && steps < g->hash_table_size) {
            idx = (idx + 1) & (g->hash_table_size - 1);
            steps++;
        }
        if (g->hash_table[idx] != -1) {
            fprintf(stderr, "[EG] Error: Hash table collision loop limit exceeded.\n");
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        g->hash_table[idx] = node_idx;
    }
}

static uint64_t json_to_u64(const JsonNode *node, uint64_t fallback) {
    if (!node)
        return fallback;
    if (node->tag == JSON_NUMBER)
        return (uint64_t)node->number_;
    if (node->tag == JSON_STRING && node->string_)
        return (uint64_t)strtoull(node->string_, NULL, 0);
    return fallback;
}

static uint64_t parse_field_sensitive_loc_id(const char *loc_str) {
    if (!loc_str) return 0;
    char *end = NULL;
    uint64_t base = strtoull(loc_str, &end, 0);
    if (end && strncmp(end, ":field_index=", 13) == 0) {
        const char *field_idx = end + 13;
        uint64_t hash = 14695981039346656037ULL;
        for (const char *p = field_idx; *p != '\0'; p++) {
            hash ^= (unsigned char)*p;
            hash *= 1099511628211ULL;
        }
        return base ^ hash;
    }
    return base;
}


static long long json_to_ll(const JsonNode *node, long long fallback) {
    if (!node)
        return fallback;
    if (node->tag == JSON_NUMBER)
        return (long long)node->number_;
    if (node->tag == JSON_STRING && node->string_) {
        char *end = NULL;
        errno = 0;
        unsigned long long parsed = strtoull(node->string_, &end, 0);
        if (errno == ERANGE || end == node->string_ || (end && *end != '\0')) {
            return fallback;
        }
        return (long long)parsed;
    }
    return fallback;
}


static int json_to_i32(const JsonNode *node, int fallback) {
    if (!node)
        return fallback;
    if (node->tag == JSON_NUMBER)
        return (int)node->number_;
    if (node->tag == JSON_STRING && node->string_)
        return (int)strtol(node->string_, NULL, 0);
    return fallback;
}

static void eg_validate_read_nodes_have_rf(const eg_graph_t *g);
static eg_graph_t* eg_deserialize_binary_mem(const char *buf, size_t size);

void eg_add_edge_rf(eg_graph_t *g, uint64_t write_id, uint64_t read_id) {
    if (!g) return;
    if (g->rf_count >= g->rf_capacity) {
        size_t new_capacity = g->rf_capacity * 2;
        eg_edge_t *tmp = realloc(g->rf_edges, sizeof(eg_edge_t) * new_capacity);
        if (!tmp) {
            fprintf(stderr, "[EG] Error: Out of memory during rf_edges realloc.\n");
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        g->rf_edges = tmp;
        g->rf_capacity = new_capacity;
    }
    eg_edge_t *e = &g->rf_edges[g->rf_count++];
    e->src_id = write_id;
    e->dst_id = read_id;
}

void eg_serialize(eg_graph_t *g, const char *filename) {
    eg_serialize_json(g, filename);
}

eg_graph_t* eg_deserialize(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    if ((unsigned long)len >= SIZE_MAX) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, len, f);
    buf[read_bytes] = 0;
    fclose(f);

    eg_graph_t *g = eg_deserialize_mem(buf, read_bytes);
    free(buf);
    return g;
}

eg_graph_t* eg_deserialize_mem(const char *buf, size_t size) {
    if (!buf || size == 0) return NULL;
    /* Additive dispatch: a binary-format buffer starts with EG_BIN_MAGIC,
     * which never matches valid JSON (always '{'/whitespace, ASCII). Falls
     * through to the existing, unmodified JSON path otherwise. */
    if (size >= sizeof(uint32_t)) {
        uint32_t magic;
        memcpy(&magic, buf, sizeof(magic));
        if (magic == EG_BIN_MAGIC) {
            return eg_deserialize_binary_mem(buf, size);
        }
    }
    return eg_deserialize_json_mem(buf, size);
}

eg_node_t* eg_find_node_by_id(eg_graph_t *g, uint64_t id) {
    if (!g) return NULL;
    for (int i=0; i<g->node_count; i++) {
        if (g->nodes[i].id == id) return &g->nodes[i];
    }
    return NULL;
}

eg_node_t* eg_find_node_by_dynamic(eg_graph_t *g, uint64_t tid, long long iid, int vid) {
    eg_node_t *res = NULL;
    if (g && g->hash_table) {
        uint32_t idx = hash_dynamic(tid, iid, vid, g->hash_table_size);
        while (g->hash_table[idx] != -1) {
            int node_idx = g->hash_table[idx];
            eg_node_t *n = &g->nodes[node_idx];
            if (n->tid == tid && n->instruction_id == iid && n->visit_id == vid) {
                res = n;
                break;
            }
            idx = (idx + 1) & (g->hash_table_size - 1);
        }
    }
    return res;
}

/* TLV Serialization Support */
typedef struct {
    uint64_t tid;
    long long iid;
    int vid;
    uint64_t id;
} eg_id_map_t;

static int eg_map_find_id(const eg_id_map_t *map, int map_size, uint64_t tid, long long iid, int vid) {
    for (int i = 0; i < map_size; ++i) {
        if (map[i].tid == tid && map[i].iid == iid && map[i].vid == vid) return map[i].id;
    }
    return -1;
}

/* JSON Serialization Support */

static const char* eg_type_to_string(int type) {
    switch (type) {
        case EG_OP_READ: return "R";
        case EG_OP_WRITE: return "W";
        case EG_OP_FENCE: return "F";
        case EG_OP_RMW: return "RMW";
        case EG_OP_CAS_SUCCESS: return "CAS_SUCCESS";
        case EG_OP_CAS_FAIL: return "CAS_FAIL";
        case EG_OP_CAS: return "CAS";
        default: return "Unknown";
    }
}

static int eg_string_to_type(const char* str) {
    if (!str) return -1;
    if (strcmp(str, "R") == 0) return EG_OP_READ;
    if (strcmp(str, "W") == 0) return EG_OP_WRITE;
    if (strcmp(str, "F") == 0) return EG_OP_FENCE;
    if (strcmp(str, "RMW") == 0) return EG_OP_RMW;
    if (strcmp(str, "CAS_SUCCESS") == 0) return EG_OP_CAS_SUCCESS;
    if (strcmp(str, "CAS_FAIL") == 0) return EG_OP_CAS_FAIL;
    /* Bare "CAS" means "outcome not yet decided". It is parsed rather than
     * rejected here so the diagnostic can name the real problem, but a graph
     * containing one is not executable -- see eg_validate_cas_resolved. */
    if (strcmp(str, "CAS") == 0) return EG_OP_CAS;
    return -1;
}

static int eg_cmp_rf_edges(const void *a, const void *b) {
    const eg_edge_t *qa = (const eg_edge_t*)a;
    const eg_edge_t *qb = (const eg_edge_t*)b;
    if (qa->src_id < qb->src_id) return -1;
    if (qa->src_id > qb->src_id) return 1;
    if (qa->dst_id < qb->dst_id) return -1;
    if (qa->dst_id > qb->dst_id) return 1;
    return 0;
}

static bool eg_has_incoming_rf_edge(const eg_graph_t *g, uint64_t read_id) {
    if (!g)        
        return false;
    EG_LOG("[eg-debug] Checking incoming RF edges for read_id=%llu with count=%d\n", (unsigned long long)read_id, g->rf_count);
    for (int i = 0; i < g->rf_count; ++i) {
        EG_LOG("[eg-debug] Checking RF edge src_id=%llu dst_id=%llu against read_id=%llu\n",
            (unsigned long long)g->rf_edges[i].src_id,
            (unsigned long long)g->rf_edges[i].dst_id,
            (unsigned long long)read_id);
        if (g->rf_edges[i].dst_id == read_id)
            return true;
    }
    return false;
}

static void eg_validate_read_nodes_have_rf(const eg_graph_t *g) {
    if (!g)
        return;
    for (int i = 0; i < g->node_count; ++i) {
        const eg_node_t *n = &g->nodes[i];
        /* Both CAS outcomes read, so both need an rf source: a failed CAS
         * still observes a value, it just does not store one. */
        if (!eg_is_read_like(n->type))
            continue;
        if (!eg_has_incoming_rf_edge(g, n->id)) {
            fprintf(stderr,
                "[EGF] Error: read/rmw/cas event (type %d) missing rf_edge source: id=%llu tid=%llu iid=%llx vid=%d\n",
                n->type,
                (unsigned long long)n->id,
                (unsigned long long)n->tid,
                n->instruction_id,
                n->visit_id);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
    }
}

/* An input graph must commit to an outcome for every CAS.
 *
 * EG_OP_CAS travels one way only -- runtime to fuzzer, as feedback for a
 * cmpxchg whose comparison could not be known yet. Coming back the other way
 * it is meaningless: the scheduler would have no expectation to enforce, the
 * node is neither a legal rf source nor reliably a non-source, and it belongs
 * in mo only if it swaps. Rather than guess (the old behaviour, which silently
 * assumed success and made the failure half of every CAS unreachable), refuse
 * the graph and name the fuzzer's obligation. */
static void eg_validate_cas_resolved(const eg_graph_t *g) {
    for (int i = 0; i < g->node_count; ++i) {
        const eg_node_t *n = &g->nodes[i];
        if (n->type != EG_OP_CAS)
            continue;
        fprintf(stderr,
            "[EGF] Error: unresolved CAS event (kind \"CAS\") in input graph: "
            "id=%llu tid=%llu iid=%llx vid=%d. A CAS node must be CAS_SUCCESS "
            "or CAS_FAIL; \"CAS\" only exists as runtime feedback.\n",
            (unsigned long long)n->id,
            (unsigned long long)n->tid,
            n->instruction_id,
            n->visit_id);
        scheduler_terminate(WMM_EXIT_INVALID_INPUT);
    }
}

static JsonNode* eg_mk_tid_id_pair(eg_graph_t *g, uint64_t id) {
    eg_node_t *n = eg_find_node_by_id(g, id);
    uint64_t tid = n ? n->tid : 0;
    long long iid = n ? n->instruction_id : 0;
    int visit_id = n ? n->visit_id : -1;
    char TidBuf[32], IidBuf[32], VidBuf[32];
    snprintf(TidBuf, sizeof(TidBuf), "%llu", (unsigned long long)tid);
    snprintf(IidBuf, sizeof(IidBuf), "%lld", iid);
    snprintf(VidBuf, sizeof(VidBuf), "%d", visit_id);

    JsonNode *arr = json_mkarray();
    json_append_element(arr, json_mkstring(TidBuf));
    // json_append_element(arr, json_mknumber(id));
    json_append_element(arr, json_mkstring(IidBuf));
    // Optionally include visit_id if needed
    json_append_element(arr, json_mkstring(VidBuf));
    return arr;
}

static eg_graph_t* eg_graph_from_json_node(JsonNode *root) {
    if (!root) return NULL;
    eg_graph_t *g = eg_create();
    
    JsonNode *nodes_arr = json_find_member(root, "nodes");
    JsonNode *n;
    if (nodes_arr && nodes_arr->tag == JSON_ARRAY) {
        json_foreach(n, nodes_arr) {
            uint64_t id = 0, tid = 0, loc_id = 0;
            long long iid = 0;
            int vid = DEFAULT_VISIT_ID;
            const char *kind = "Unknown";
            const char *loc = "";
            intptr_t val = -1;

            JsonNode *tmp;
            if ((tmp = json_find_member(n, "event_id"))) {
                id = json_to_u64(tmp, 0);
            } else {
                id = (uint64_t)g->node_count + 1; // assign new ID
            }
            // if ((tmp = json_find_member(n, "access_mode"))) mode = tmp->string_; // TODO: add me
            if ((tmp = json_find_member(n, "thread_id"))) tid = json_to_u64(tmp, 0);
            if ((tmp = json_find_member(n, "kind"))) kind = tmp->string_;
            if ((tmp = json_find_member(n, "loc"))) loc = tmp->string_;
            if ((tmp = json_find_member(n, "value"))) val = (intptr_t)tmp->number_;
            if ((tmp = json_find_member(n, "instruction_id"))) iid = json_to_ll(tmp, 0);
            if ((tmp = json_find_member(n, "loc_id"))) {
                if (tmp->tag == JSON_STRING && tmp->string_) {
                    loc_id = parse_field_sensitive_loc_id(tmp->string_);
                } else {
                    loc_id = json_to_u64(tmp, 0);
                }
            }
            if ((tmp = json_find_member(n, "visit_id"))) vid = json_to_i32(tmp, DEFAULT_VISIT_ID);
            
            // Check for existing event with same dynamic properties
            int new_type = eg_string_to_type(kind);
            if (new_type == -1) {
                fprintf(stderr, "[EGF] Error: Invalid event kind '%s' for event_id=%llu\n", kind ? kind : "<null>", (unsigned long long)id);
                scheduler_terminate(WMM_EXIT_INVALID_INPUT);
            }

            eg_node_t *existing = eg_find_node_by_dynamic(g, tid, iid, vid);
            if (existing) {
                if (existing->type != new_type || strcmp(existing->location, loc) != 0) {
                    fprintf(stderr,
                            "[EGF] Error: Event mismatch for tid=%llu iid=%llx vid=%d. Exist: type=%d loc=%s. New: type=%d loc=%s\n",
                            (unsigned long long)tid, iid, vid,
                            existing->type, existing->location,
                            new_type, loc);
                    scheduler_terminate(WMM_EXIT_INVALID_INPUT);
                }
                continue;
            }

            eg_add_node(g, id, tid, iid, loc_id, vid, new_type, loc, val);
        }
        EG_LOG("Loaded %d nodes from JSON\n", g->node_count);
    }

    /* Before the rf edges, so an unresolved CAS is reported as itself rather
     * than as a downstream "rf edge dest must be READ/RMW/CAS_*" type error. */
    eg_validate_cas_resolved(g);

    JsonNode *edges_arr = json_find_member(root, "rf_edges");
    JsonNode *e;
    if (edges_arr && edges_arr->tag == JSON_ARRAY) {
        json_foreach(e, edges_arr) {
            JsonNode *from = json_find_member(e, "from"); // [tid, id]
            uint64_t write_id = -1;
            if (from && from->tag == JSON_ARRAY) {
                // JsonNode *eid_node = json_find_element(from, 1);
                // if (eid_node) write_id = eid_node->number_;

                // [thread_id, instruction_id] or [thread_id, instruction_id, visit_id]
                JsonNode *tid_node = json_find_element(from, 0);
                JsonNode *instr_node = json_find_element(from, 1);
                JsonNode *visit_node = json_find_element(from, 2);
                int visit_id = json_to_i32(visit_node, DEFAULT_VISIT_ID);
                if (tid_node && instr_node) {
                          uint64_t tid = json_to_u64(tid_node, 0);
                          long long instr = json_to_ll(instr_node, 0);
                          EG_LOG("Looking up write node for RF edge: tid=%llu, instr=%lld, visit_id=%d\n",
                              (unsigned long long)tid, instr, visit_id);
                    eg_node_t *n = eg_find_node_by_dynamic(g, tid, instr, visit_id);
                    if (n) {
                        write_id = n->id;
                    } else {
                        fprintf(stderr, "[EGF] Error: Write event not found for RF edge: tid=%llu, instr=%lld, visit_id=%d\n",
                            (unsigned long long)tid, instr, visit_id);
                        scheduler_terminate(EXIT_EVENT_NOT_FOUND);
                    }
                }
            } else if (from && (from->tag == JSON_NUMBER || from->tag == JSON_STRING)) {
                write_id = json_to_u64(from, -1);
            }
            
            JsonNode *to_list = json_find_member(e, "to");
            JsonNode *to_item;
            if (to_list && to_list->tag == JSON_ARRAY) {
                json_foreach(to_item, to_list) {
                    uint64_t read_id = 0;
                    if (to_item && to_item->tag == JSON_ARRAY) {
                         // JsonNode *eid_node = json_find_element(to_item, 1);
                         // if (eid_node) read_id = eid_node->number_;
                        JsonNode *tid_node = json_find_element(to_item, 0);
                        JsonNode *instr_node = json_find_element(to_item, 1);
                        JsonNode *visit_node = json_find_element(to_item, 2);
                        int visit_id = json_to_i32(visit_node, DEFAULT_VISIT_ID);
                        if (tid_node && instr_node) {
                            uint64_t tid = json_to_u64(tid_node, 0);
                            long long instr = json_to_ll(instr_node, 0);
                            EG_LOG("Looking up read node for RF edge: tid=%lu, instr=%lld, visit_id=%d\n",
                                tid, instr, visit_id);
                            eg_node_t *n = eg_find_node_by_dynamic(g, tid, instr, visit_id);
                            if (n) {
                                read_id = n->id;
                            } else {
                                fprintf(stderr, "[EGF] Error: Read event not found for RF edge: tid=%lu, instr=%lld, visit_id=%d\n",
                                    tid, instr, visit_id);
                                scheduler_terminate(EXIT_EVENT_NOT_FOUND);
                            }
                        }
                    } else if (to_item && (to_item->tag == JSON_NUMBER || to_item->tag == JSON_STRING)) {
                        read_id = json_to_u64(to_item, -1);
                    }
                    EG_LOG("[eg-debug] Parsed RF edge from JSON: write_id=%lu read_id=%lu\n", write_id, read_id);
                    if (write_id != -1 && read_id != -1) {
                        eg_node_t *wn = eg_find_node_by_id(g, write_id);
                        eg_node_t *rn = eg_find_node_by_id(g, read_id);
                        
                            /* Only an event that stores can be read from. A failed
                             * CAS is a legal rf DEST but never a legal rf SOURCE. */
                            if (wn && !eg_is_write_like(wn->type)) {
                                fprintf(stderr, "[EGF] Error: RF edge source must be WRITE/RMW/CAS_SUCCESS. Found type %d (id=%lu)\n", wn->type, write_id);
                             scheduler_terminate(EXIT_RF_TYPE_MISMATCH);
                        }
                            if (rn && !eg_is_read_like(rn->type)) {
                                fprintf(stderr, "[EGF] Error: RF edge dest must be READ/RMW/CAS_*. Found type %d (id=%lu)\n", rn->type, read_id);
                             scheduler_terminate(EXIT_RF_TYPE_MISMATCH);
                        }
                        EG_LOG("[eg-debug] Adding RF edge: write_id=(%lu) -> read_id=(%lu)\n", write_id, read_id);
                        eg_add_edge_rf(g, write_id, read_id);
                    }
                }
            }
        }
    }
    eg_validate_read_nodes_have_rf(g);
    return g;
}

void eg_serialize_json(eg_graph_t *g, const char *filename) {
    JsonNode *root = json_mkobject();
    JsonNode *nodes_arr = json_mkarray();
    
    // Nodes
    for (int i = 0; i < g->node_count; i++) {
        eg_node_t *n = &g->nodes[i];
        char EventIDBuf[32], ThreadIDBuf[32], InstrIDBuf[32], LocIDBuf[32], VisitBuf[32];
        snprintf(EventIDBuf, sizeof(EventIDBuf), "%llu", (unsigned long long)n->id);
        snprintf(ThreadIDBuf, sizeof(ThreadIDBuf), "%llu", (unsigned long long)n->tid);
        snprintf(InstrIDBuf, sizeof(InstrIDBuf), "%lld", (long long)n->instruction_id);
        snprintf(LocIDBuf, sizeof(LocIDBuf), "%llu", (unsigned long long)n->loc_id);
        snprintf(VisitBuf, sizeof(VisitBuf), "%d", n->visit_id);
        JsonNode *node_obj = json_mkobject();
        json_append_member(node_obj, "event_id", json_mkstring(EventIDBuf));
        json_append_member(node_obj, "thread_id", json_mkstring(ThreadIDBuf));
        json_append_member(node_obj, "kind", json_mkstring(eg_type_to_string(n->type)));
        json_append_member(node_obj, "loc_id", json_mkstring(LocIDBuf));
        json_append_member(node_obj, "value", json_mknumber((double)n->value));
        json_append_member(node_obj, "instruction_id", json_mkstring(InstrIDBuf));
        json_append_member(node_obj, "visit_id", json_mkstring(VisitBuf));
        json_append_member(node_obj, "access_mode", json_mkstring("RLX")); // TODO: Add support for access modes
        json_append_element(nodes_arr, node_obj);
    }
    json_append_member(root, "nodes", nodes_arr);

    // RF Edges
    JsonNode *edges_arr = json_mkarray();
    if (g->rf_count > 0) {
        eg_edge_t *sorted = (eg_edge_t*)malloc(sizeof(eg_edge_t) * g->rf_count);
        if (sorted) {
            memcpy(sorted, g->rf_edges, sizeof(eg_edge_t) * g->rf_count);
            qsort(sorted, g->rf_count, sizeof(eg_edge_t), eg_cmp_rf_edges);
            
            for (int i = 0; i < g->rf_count; ) {
                uint64_t src_id = sorted[i].src_id;
                JsonNode *edge_obj = json_mkobject();
                json_append_member(edge_obj, "from", eg_mk_tid_id_pair(g, src_id));
                
                JsonNode *to_list = json_mkarray();
                while(i < g->rf_count && sorted[i].src_id == src_id) {
                    json_append_element(to_list, eg_mk_tid_id_pair(g, sorted[i].dst_id));
                    i++;
                }
                json_append_member(edge_obj, "to", to_list);
                json_append_element(edges_arr, edge_obj);
            }
            free(sorted);
        }
    }
    json_append_member(root, "rf_edges", edges_arr);

    char *json_str = json_stringify(root, "  ");
    FILE *f = fopen(filename, "w");
    if (f) {
        fputs(json_str, f);
        fclose(f);
    }
    free(json_str);
    json_delete(root);
}

eg_graph_t* eg_deserialize_json(const char *buf) {
    if (!buf) return NULL;
    // Append the input to a log file
    // FILE *logf = fopen("eg_deserialize_json.log", "a+");
    // if (logf) {
    //     fputs(buf, logf);
    //     fputs("\n---\n", logf);
    //     fclose(logf);
    // }


    JsonNode *root = json_decode(buf);
    free((void *)buf);
    if (!root) return NULL;
    
    eg_graph_t *g = eg_graph_from_json_node(root);
    json_delete(root);
    return g;
}

/* Flat binary counterpart of eg_graph_from_json_node: a header + packed
 * eg_bin_node_t[node_count] + packed eg_bin_edge_t[rf_count] (see
 * eg_binary.h). Reuses eg_create/eg_add_node/eg_add_edge_rf so capacity
 * growth and the dynamic (tid,iid,vid)->id hash table stay in exactly one
 * implementation, and mirrors eg_graph_from_json_node's validation
 * (duplicate-node mismatch check, CAS-resolved check, rf source/dest type
 * checks, "every read has an rf edge" check) so a binary-loaded graph is
 * held to the same structural contract as a JSON-loaded one, with the same
 * scheduler_terminate() exit codes on failure. Fields are read via memcpy
 * into locals rather than dereferencing the buffer as a struct array, since
 * the wire buffer's alignment isn't guaranteed. */
static eg_graph_t* eg_deserialize_binary_mem(const char *buf, size_t size) {
    if (!buf || size < sizeof(eg_bin_header_t)) return NULL;

    eg_bin_header_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.magic != EG_BIN_MAGIC) return NULL; /* caller already checked; stay safe if called directly */
    if (hdr.version != EG_BIN_VERSION) {
        fprintf(stderr, "[EGF] Error: unsupported binary graph version %u (expected %u)\n",
                hdr.version, EG_BIN_VERSION);
        return NULL;
    }

    size_t nodes_off = sizeof(eg_bin_header_t);
    size_t nodes_bytes = (size_t)hdr.node_count * sizeof(eg_bin_node_t);
    size_t edges_off = nodes_off + nodes_bytes;
    size_t edges_bytes = (size_t)hdr.rf_count * sizeof(eg_bin_edge_t);
    size_t total_needed = edges_off + edges_bytes;
    if (total_needed > size) {
        fprintf(stderr, "[EGF] Error: truncated binary graph (need %zu bytes, have %zu)\n",
                total_needed, size);
        return NULL;
    }

    eg_graph_t *g = eg_create();
    if (!g) return NULL;

    for (uint32_t i = 0; i < hdr.node_count; i++) {
        eg_bin_node_t bn;
        memcpy(&bn, buf + nodes_off + (size_t)i * sizeof(eg_bin_node_t), sizeof(bn));
        char loc[65];
        memcpy(loc, bn.location, 64);
        loc[64] = '\0'; /* defensive; the writer always NUL-terminates within 64 */

        /* bn.location carries the same string AFL_patches' Event model uses
         * as its location (== what the JSON path receives as the "loc_id"
         * field's *string* value), so derive the numeric loc_id from it the
         * same way eg_graph_from_json_node's JSON_STRING branch does; loc
         * itself (the runtime's separate symbolic-name field) stays empty,
         * matching the JSON path's default when no "loc" key is present --
         * so duplicate-node comparison below checks loc_id, not the (always
         * empty here) location string. */
        uint64_t loc_id = parse_field_sensitive_loc_id(loc);

        /* Same duplicate-node semantics as eg_graph_from_json_node. */
        eg_node_t *existing = eg_find_node_by_dynamic(g, bn.tid, bn.instruction_id, bn.visit_id);
        if (existing) {
            bool mismatch = (existing->type != bn.type) || (existing->loc_id != loc_id);
            if (mismatch) {
                fprintf(stderr,
                        "[EGF] Error: Event mismatch (binary) for tid=%llu iid=%lld vid=%d. Exist: type=%d loc_id=%llu. New: type=%d loc_id=%llu\n",
                        (unsigned long long)bn.tid, (long long)bn.instruction_id, bn.visit_id,
                        existing->type, (unsigned long long)existing->loc_id, bn.type, (unsigned long long)loc_id);
                scheduler_terminate(WMM_EXIT_INVALID_INPUT);
            }
            continue;
        }

        uint64_t id = (uint64_t)g->node_count + 1;
        eg_add_node(g, id, bn.tid, bn.instruction_id, loc_id, bn.visit_id, bn.type, "", (intptr_t)bn.value);
    }
    EG_LOG("Loaded %d nodes from binary graph\n", g->node_count);

    /* Before the rf edges, so an unresolved CAS is reported as itself rather
     * than as a downstream rf type-mismatch error -- same ordering as the
     * JSON path. */
    eg_validate_cas_resolved(g);

    for (uint32_t i = 0; i < hdr.rf_count; i++) {
        eg_bin_edge_t be;
        memcpy(&be, buf + edges_off + (size_t)i * sizeof(eg_bin_edge_t), sizeof(be));

        eg_node_t *wn = eg_find_node_by_dynamic(g, be.src_tid, be.src_instruction_id, be.src_visit_id);
        if (!wn) {
            fprintf(stderr, "[EGF] Error: Write event not found for RF edge (binary): tid=%llu, instr=%lld, visit_id=%d\n",
                    (unsigned long long)be.src_tid, (long long)be.src_instruction_id, be.src_visit_id);
            scheduler_terminate(EXIT_EVENT_NOT_FOUND);
        }
        eg_node_t *rn = eg_find_node_by_dynamic(g, be.dst_tid, be.dst_instruction_id, be.dst_visit_id);
        if (!rn) {
            fprintf(stderr, "[EGF] Error: Read event not found for RF edge (binary): tid=%llu, instr=%lld, visit_id=%d\n",
                    (unsigned long long)be.dst_tid, (long long)be.dst_instruction_id, be.dst_visit_id);
            scheduler_terminate(EXIT_EVENT_NOT_FOUND);
        }

        /* Only an event that stores can be read from. A failed CAS is a
         * legal rf DEST but never a legal rf SOURCE -- same check as the
         * JSON path. */
        if (!eg_is_write_like(wn->type)) {
            fprintf(stderr, "[EGF] Error: RF edge source must be WRITE/RMW/CAS_SUCCESS. Found type %d (binary)\n", wn->type);
            scheduler_terminate(EXIT_RF_TYPE_MISMATCH);
        }
        if (!eg_is_read_like(rn->type)) {
            fprintf(stderr, "[EGF] Error: RF edge dest must be READ/RMW/CAS_*. Found type %d (binary)\n", rn->type);
            scheduler_terminate(EXIT_RF_TYPE_MISMATCH);
        }
        eg_add_edge_rf(g, wn->id, rn->id);
    }
    EG_LOG("Loaded %d RF edges from binary graph\n", g->rf_count);

    eg_validate_read_nodes_have_rf(g);
    return g;
}

eg_graph_t* eg_deserialize_json_mem(const char *buf, size_t size) {
    if (!buf || size == 0) return NULL;
    char *copy = (char*)malloc(size + 1);
    if (!copy) return NULL;
    memcpy(copy, buf, size);
    copy[size] = 0;


    // FILE *logf = fopen("eg_deserialize_json.log", "a+");
    // if (logf) {
    //     fputs(copy, logf);
    //     fputs("\n---\n", logf);
    //     fclose(logf);
    // }
    
    JsonNode *root = json_decode(copy);
    EG_LOG("[eg] Completed JSON decoding for EG deserialization\n");
    free(copy);
    if (!root) return NULL;
    
    EG_LOG("[eg] Building EG graph from JSON node\n");
    eg_graph_t *g = eg_graph_from_json_node(root);
    json_delete(root);
    return g;
}
