#include "shm_next_events.h"

#include <cstdlib>
#include <cstring>
#include <atomic>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

namespace shm_next_events
{
    static int g_shm_id = -1;
    static SHM_next_events *g_next_events = nullptr;

    static constexpr const char *ENV_NAME = "SHM_NEXT_EVENTS_ID";

    SHM_next_events *get_next_events()
    {
        return g_next_events;
    }

    /*
     * AFL side:
     * create SHM and export SHM_NEXT_EVENTS_ID
     */
    int create_shm_next_events() {
        if (g_next_events)
            return g_shm_id;

        g_shm_id = shmget(IPC_PRIVATE, sizeof(SHM_next_events), IPC_CREAT | 0600);

        if (g_shm_id < 0)
            return -1;

        // shmat() maps the shared memory into this process's address space
        g_next_events = static_cast<SHM_next_events *>(shmat(g_shm_id, nullptr, 0));
        
        //if shmat returns (void *)-1, it indicates an error occurred while attaching to the shared memory segment - checking that and returning -1 here 
        if (g_next_events == reinterpret_cast<void *>(-1)){
            g_next_events = nullptr;
            return -1;
        }

        std::memset(g_next_events, 0, sizeof(SHM_next_events));

        //converting g_shm_id to a character string to set the env var
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%d", g_shm_id);
        setenv(ENV_NAME, buf, 1);

        std::fprintf(stderr, "[SHM-DEBUG] Created SHM ID for next events: %d\n", g_shm_id);
        return g_shm_id;
    }

    /*
     * AFL side cleanup
     */
    void destroy_shm_next_events() {
        // checking if the attach was successful in the first place (shmat)
        if (g_next_events){
            // detach the shared memory segment from the process's address space
            shmdt(g_next_events);
            g_next_events = nullptr;
        }

        if (g_shm_id >= 0){
            // IPC_RMID marks the segment to be destroyed
            shmctl(g_shm_id, IPC_RMID, nullptr);
            g_shm_id = -1;
        }
    }

    /*
     * Target side:
     * attach to SHM using env var
     */

    //TODO: figure out where exactly this should be called in the simulator code

    // TODO: Check: WHY ARE WE REWRITIGN THE SAME KIND OF CODE AS IN THE CREATE FUNCTION? THEY ARE ALL ON THE SAME OBJECT TOO - g_next_events
    bool attach_shm_next_events() {
        if (g_next_events)
            return true;

        const char *env = std::getenv(ENV_NAME);
        if (!env)
            return false;

        int shm_id = std::atoi(env);

        g_next_events = static_cast<SHM_next_events *>(shmat(shm_id, nullptr, 0));
        if (g_next_events == reinterpret_cast<void *>(-1)){
            g_next_events = nullptr;
            return false;
        }
        return true;
    }

    void begin_update(){
        if (!g_next_events)
            return;

        g_next_events->ready = 0;
        // TODO: Check why this is necessary, especially when we already have ready flag
        std::atomic_thread_fence(std::memory_order_release);
    }

    void finish_update(){
        if (!g_next_events)
            return;

        // TODO: Check why this is necessary
        std::atomic_thread_fence(std::memory_order_release);
        g_next_events->ready = 1;
    }

}

extern "C"
{

    int create_shm_next_events_c(void){
        return shm_next_events::create_shm_next_events();
    }

    void destroy_shm_next_events_c(void){
        shm_next_events::destroy_shm_next_events();
    }

    struct SHM_next_events *get_shm_next_events_c(void){
        return shm_next_events::get_next_events();
    }

    void begin_update_c(void){
        shm_next_events::begin_update();
    }

    void finish_update_c(void){
        shm_next_events::finish_update();
    }
}