#include "retgraph_shm.h"

#include <cstdlib>
#include <cstring>
#include <atomic>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

namespace graph_shm {

static int g_shm_id = -1;
static SharedGraph* g_graph = nullptr;

static constexpr const char* ENV_NAME =
    "GRAPH_SHM_ID";

SharedGraph* get() {

    return g_graph;
}

/*
 * AFL side:
 * create SHM and export GRAPH_SHM_ID
 */
int create_shared_graph() {

    if (g_graph)
        return g_shm_id;

    g_shm_id =
        shmget(
            IPC_PRIVATE,
            sizeof(SharedGraph),
            IPC_CREAT | 0600
        );

    if (g_shm_id < 0)
        return -1;

    g_graph =
        static_cast<SharedGraph*>(
            shmat(g_shm_id, nullptr, 0)
        );

    if (g_graph == reinterpret_cast<void*>(-1)) {

        g_graph = nullptr;
        return -1;
    }

    std::memset(
        g_graph,
        0,
        sizeof(SharedGraph)
    );

    char buf[64];

    std::snprintf(
        buf,
        sizeof(buf),
        "%d",
        g_shm_id
    );

    setenv(
        ENV_NAME,
        buf,
        1
    );

    std::fprintf(stderr, "[SHM-DEBUG] Created shared graph SHM ID: %d\n", g_shm_id);
    return g_shm_id;
}

/*
 * AFL side cleanup
 */
void destroy_shared_graph() {

    if (g_graph) {

        shmdt(g_graph);
        g_graph = nullptr;
    }

    if (g_shm_id >= 0) {

        shmctl(
            g_shm_id,
            IPC_RMID,
            nullptr
        );

        g_shm_id = -1;
    }
}

/*
 * Target side:
 * attach to SHM using env var
 */
bool attach_shared_graph() {

    if (g_graph)
        return true;

    const char* env =
        std::getenv(
            ENV_NAME
        );

    if (!env)
        return false;

    int shm_id =
        std::atoi(env);

    g_graph =
        static_cast<SharedGraph*>(
            shmat(
                shm_id,
                nullptr,
                0
            )
        );

    if (g_graph ==
        reinterpret_cast<void*>(-1)) {

        g_graph = nullptr;
        return false;
    }

    return true;
}

void begin_update() {

    if (!g_graph)
        return;

    g_graph->header.ready = 0;

    std::atomic_thread_fence(
        std::memory_order_release
    );
}

void finish_update() {

    if (!g_graph)
        return;

    std::atomic_thread_fence(
        std::memory_order_release
    );

    g_graph->header.generation++;

    g_graph->header.ready = 1;
}

}

extern "C" {

int create_shared_graph_c(void) {
    return graph_shm::create_shared_graph();
}

void destroy_shared_graph_c(void) {
    graph_shm::destroy_shared_graph();
}

struct SharedGraph* get_shared_graph_c(void) {
    return graph_shm::get();
}

}