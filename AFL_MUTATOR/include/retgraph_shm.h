#pragma once

#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#include <tuple>
#include <string>

using ThreadID = int;
using InstructionID = long long;
using VisitID = int;
using EventID = std::tuple<ThreadID, InstructionID, VisitID>;
using Location = std::string;
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef int ThreadID;
typedef long long InstructionID;
typedef int VisitID;
#endif

#define MAX_NODES 4096
#define MAX_SW_EDGES 4096

struct SharedNode {

    ThreadID tid;
    InstructionID iid;
    VisitID vid;

    uint8_t event_type;
    uint8_t access_mode;

    uint32_t location_id;

    int32_t next_po;

    uint32_t sw_begin;
    uint32_t sw_count;
};

struct SharedSWEdge {

    uint32_t dst;
};

struct SharedHeader {

    uint32_t generation;

    uint32_t node_count;
    uint32_t sw_count;

    uint32_t ready;
};

struct SharedGraph {

    struct SharedHeader header;

    struct SharedNode nodes[MAX_NODES];

    struct SharedSWEdge sw_edges[MAX_SW_EDGES];
};

#ifdef __cplusplus
namespace graph_shm {

/* AFL side */
int create_shared_graph();
void destroy_shared_graph();

/* Target side */
bool attach_shared_graph();

/* Common */
SharedGraph* get();

/* Publishing helpers */
void begin_update();
void finish_update();

}

extern "C" {
#endif

/* C-compatible wrappers */
int create_shared_graph_c(void);
void destroy_shared_graph_c(void);
struct SharedGraph* get_shared_graph_c(void);

#ifdef __cplusplus
}
#endif
