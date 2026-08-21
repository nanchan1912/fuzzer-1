#include "scheduler.h"
#include "eg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <errno.h>
#include <time.h>

// TODO: This path is hardcoded - change it!
#include "/home/aritra/fuzzer-1/FUZZER_Rebuilt/Main/include/shm_next_events.h"


struct SHM_next_events *g_next_events = NULL;
const char *SHM_ENV_NAME = "SHM_NEXT_EVENTS_ID";

#undef pthread_mutex_lock
#define pthread_mutex_lock real_pthread_mutex_lock
#undef pthread_mutex_unlock
#define pthread_mutex_unlock real_pthread_mutex_unlock
#undef pthread_cond_wait
#define pthread_cond_wait real_pthread_cond_wait
#undef pthread_cond_broadcast
#define pthread_cond_broadcast real_pthread_cond_broadcast

#define MAX_THREADS 128
#define HISTLIMIT 4096

#define MAX_NODES 128
#define MAX_SW_EDGES 4096

// Simple logging switch
#ifdef QUIET
#define LOG(...)
#else
#define LOG(...) printf(__VA_ARGS__)
#endif

// --- Configuration ---
static int config_histlimit = 4096;
static enum {
    MRS_STOP = 0,
    MRS_LATEST,
    MRS_LATEST_LOCAL,
    MRS_RANDOM
} config_missing_random_sampling = MRS_STOP;
static char *config_gen_eg_output = NULL;

// --- State ---
static eg_graph_t *current_graph = NULL;
static eg_graph_t *recording_graph = NULL;
static atomic_int global_event_id_counter = 1;
static atomic_int wmm_exiting = 0;

static void scheduler_terminate_locked(int code);

// Helper to find write source for a read node
static uint64_t find_rf_source(uint64_t read_node_id) {
    if (!current_graph) return 0;
    for (int i = 0; i < current_graph->rf_count; i++) {
        if (current_graph->rf_edges[i].dst_id == read_node_id) {
            return current_graph->rf_edges[i].src_id;
        }
    }
    return 0;
}

// data type to store the info about an event
typedef struct{
    int tid;
    long long iid;
    int vid;
}event_t;

typedef struct{
    int tid;
    long long iid;
    int vid;
    Access_Mode order; //changing from memory_order to Access_Mode enum(declared in header file)
    int event_type;
    long long loc_id;
}next_event_t;

// List to return all the info about the last events of the parent thread
typedef struct event_list_t{
    event_t event;
    struct event_list_t *next;
}event_list_t;

typedef struct next_event_list_t{
    next_event_t nxt_event;
    struct next_event_list_t *next;
}next_event_list_t;

// data type to store info about the thread and map it to its children
typedef struct thread_graph_t{
    unsigned long long tid;
    event_t last_executed;
    bool joined;
    long long parent_iid_at_join;
    long long parent_vid_at_join;
    struct thread_graph_t *children;
    struct thread_graph_t *sibling;
    struct thread_graph_t *next;
}thread_graph_t;

// List to store all the threads spawned
static thread_graph_t *all_threads=NULL;
static next_event_list_t *next_events=NULL;

// remove a particular target node from all_threads
static void remove_from_all_threads(thread_graph_t *target){
    if (!all_threads || !target) return;
    
    if (all_threads == target) {
        all_threads = all_threads->next;
        free(target);
        return;
    }
    thread_graph_t *curr = all_threads;
    while(curr->next && curr->next!=target){
        curr=curr->next;
    }
    if(curr->next==target){
        curr->next=target->next;
    }
    free(target);
}

// Helper to convert Access_Mode to standard GCC __ATOMIC constants
static inline int __sched_to_gcc_order(Access_Mode mode) {
    switch (mode) {
        case NON_ATOMIC: return __ATOMIC_RELAXED;
        case RELAXED:    return __ATOMIC_RELAXED;
        case ACQUIRE:    return __ATOMIC_ACQUIRE;
        case RELEASE:    return __ATOMIC_RELEASE;
        case ACQ_REL:    return __ATOMIC_ACQ_REL;
        case SC:         return __ATOMIC_SEQ_CST;
        default:         return __ATOMIC_SEQ_CST;
    }
}

// Function to collect the joined children threads and delete them.
static void collect_and_prune_events(thread_graph_t **curr_ptr,event_list_t **list_head, long long parent_current_iid,int parent_current_vid){
    if (!curr_ptr || !*curr_ptr) return;

    while(*curr_ptr!=NULL) {
        thread_graph_t *curr=*curr_ptr;
        if(curr->joined){
            bool is_shielded = (curr->parent_iid_at_join != parent_current_iid || curr->parent_vid_at_join!=parent_current_vid);
            fprintf(stderr, "[PRUNE-TRACE] Evaluating TID %llu. Joined at IID %lld. Parent checking IID %lld. Shielded? %s\n", 
                    curr->tid, curr->parent_iid_at_join, parent_current_iid, is_shielded ? "YES" : "NO");
            event_list_t *grandchildren = NULL;
            collect_and_prune_events(&(curr->children), &grandchildren, curr->last_executed.iid,curr->last_executed.vid);

            if (is_shielded) {
                while(grandchildren) {
                    event_list_t *tmp = grandchildren;
                    grandchildren = grandchildren->next;
                    free(tmp);
                }
            } else {
                if (grandchildren != NULL) {
                    event_list_t *tail = grandchildren;
                    while(tail->next) tail = tail->next;
                    tail->next = *list_head;
                    *list_head = grandchildren;
                } else {
                    event_list_t *new_node = (event_list_t *)malloc(sizeof(event_list_t));
                    if(new_node){
                        new_node->event = curr->last_executed;
                        new_node->next = *list_head;
                        *list_head = new_node; 
                    }
                }
            }
            *curr_ptr=curr->sibling;
            remove_from_all_threads(curr);
        } else {
            fprintf(stderr, "[PRUNE-TRACE] Skipping TID %llu because joined == false\n", curr->tid);
            curr_ptr=&(curr->sibling);
        }
    }
}

// //Function to call, inorder to get the event list of a parent thread.
static event_list_t* get_executed_events_and_prune(thread_graph_t *parent){
    if (!parent || !parent->children) return NULL;

    event_list_t *collected = NULL;
    collect_and_prune_events(&(parent->children), &collected,parent->last_executed.iid,parent->last_executed.vid);
    return collected;
}

// --- Runtime State ---

// Per-address history
typedef struct WriteEvent {
    void *addr;
    intptr_t val;
    size_t size;
    unsigned char *bytes;
    uint64_t loc_id;
    uint64_t tid;
    long long instruction_id;
    int visit_id;
    uint64_t graph_node_id;
    uint64_t timestamp;
    struct WriteEvent *next;
} WriteEvent;

// Since addresses are dynamic, we use a simple list or hash table for histories mechanism
// For simplicity, a global list of all writes, filtered by addr when needed (slow but functional)
// Or a hash table: Addr -> List<WriteEvent>

#define HASH_SIZE 1024
static WriteEvent *history[HASH_SIZE]; // Hash table buckets
static uint64_t global_write_timestamp = 0;

unsigned int hash_ptr(void *ptr) {
    return ((uintptr_t)ptr >> 3) % HASH_SIZE;
}

static int *thread_event_indices[MAX_THREADS];
static int thread_event_count[MAX_THREADS];
static int thread_frontier[MAX_THREADS];


static intptr_t bytes_to_intptr(const void *data, size_t size) {
    intptr_t out = 0;
    if (!data || size == 0)
        return out;
    size_t n = size < sizeof(out) ? size : sizeof(out);
    memcpy(&out, data, n);
    return out;
}

static intptr_t write_event_value(const WriteEvent *we) {
    if (!we)
        return 0;
    if (we->bytes && we->size > 0)
        return bytes_to_intptr(we->bytes, we->size);
    return we->val;
}

static void add_history_bytes(void *addr, const void *data, size_t size,
                              uint64_t loc_id,
                              uint64_t tid, long long sid, int vid,
                              uint64_t gnid) {
    unsigned int h = hash_ptr(addr);
    
    // Count and track writes for this specific address
    WriteEvent** last_for_addr = NULL;
    int count_for_addr = 0;
    WriteEvent* oldest_for_addr = NULL;
    
    for (WriteEvent **pp = &history[h]; *pp; pp = &(*pp)->next) {
        if ((*pp)->addr == addr) {
            count_for_addr++;
            last_for_addr = pp;
            if (!oldest_for_addr || (*pp)->timestamp < oldest_for_addr->timestamp) {
                oldest_for_addr = *pp;
            }
        }
    }
    
    // Enforce per-address limit: config_histlimit bytes / sizeof(WriteEvent)
    // Assume 4096 bytes limit means roughly ~85 events per address (sizeof(WriteEvent) ~48 bytes)
    int max_per_addr = config_histlimit / (int)sizeof(WriteEvent);
    if (max_per_addr < 10) max_per_addr = 10;  // Minimum 10 events per address
    
    // If at limit, evict the oldest write for this address (LRU)
    if (count_for_addr >= max_per_addr && oldest_for_addr) {
        WriteEvent* to_remove = NULL;
        for (WriteEvent** pp = &history[h]; *pp; pp = &(*pp)->next) {
            if (*pp == oldest_for_addr) {
                to_remove = *pp;
                *pp = (*pp)->next;
                LOG("[INFO] History: Evicted oldest write for %p (gnid=%llu), keeping %d writes\n",
                    addr, (unsigned long long)to_remove->graph_node_id, max_per_addr - 1);
                free(to_remove->bytes);
                free(to_remove);
                break;
            }
        }
    }
    
    // Add new write event at head (prepend)
    WriteEvent *we = malloc(sizeof(WriteEvent));
    we->addr = addr;
    we->val = bytes_to_intptr(data, size);
    we->size = (data && size > 0) ? size : 0;
    we->bytes = NULL;
    if (we->size > 0) {
        we->bytes = (unsigned char *)malloc(we->size);
        if (we->bytes) {
            memcpy(we->bytes, data, we->size);
        } else {
            we->size = 0;
        }
    }
    we->loc_id = loc_id;
    we->tid = tid;
    we->instruction_id = sid;
    we->visit_id = vid;
    we->graph_node_id = gnid;
    we->timestamp = ++global_write_timestamp;
    we->next = history[h];
    history[h] = we;
}

static void add_history(void *addr, intptr_t val, uint64_t loc_id, uint64_t tid,
                        long long sid, int vid, uint64_t gnid) {
    add_history_bytes(addr, &val, sizeof(val), loc_id, tid, sid, vid, gnid);
}

static WriteEvent* find_write_in_history(uint64_t graph_node_id) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (WriteEvent *w = history[i]; w; w = w->next) {
            if (w->graph_node_id == graph_node_id) return w;
        }
    }
    LOG("[SCHED-DEBUG] No write found in history for graph_node_id=%llu\n", (unsigned long long)graph_node_id);
    return NULL;
}

static WriteEvent* find_latest_overlapping_write(void *addr, size_t size) {
    if (!addr) return NULL;
    uintptr_t L_start = (uintptr_t)addr;
    uintptr_t L_end = L_start + size;
    WriteEvent *best = NULL;
    for (int i = 0; i < HASH_SIZE; i++) {
        for (WriteEvent *w = history[i]; w; w = w->next) {
            if (!w->addr) continue;
            uintptr_t W_start = (uintptr_t)w->addr;
            size_t w_size = w->size;
            if (w_size == 0) {
                w_size = sizeof(w->val);
            }
            uintptr_t W_end = W_start + w_size;
            
            // Check overlap
            uintptr_t O_start = L_start > W_start ? L_start : W_start;
            uintptr_t O_end = L_end < W_end ? L_end : W_end;
            if (O_start < O_end) {
                if (!best || w->timestamp > best->timestamp) {
                    best = w;
                }
            }
        }
    }
    return best;
}

static WriteEvent* find_latest_write_by_loc(uint64_t loc_id) {
    WriteEvent *best = NULL;
    for (int i = 0; i < HASH_SIZE; i++) {
        for (WriteEvent *w = history[i]; w; w = w->next) {
            if (w->loc_id != loc_id)
                continue;
            if (!best || w->timestamp > best->timestamp)
                best = w;
        }
    }
    return best;
}

static WriteEvent* find_latest_local_overlapping_write(void *addr, size_t size, uint64_t tid) {
    if (!addr) return NULL;
    uintptr_t L_start = (uintptr_t)addr;
    uintptr_t L_end = L_start + size;
    WriteEvent *best = NULL;
    for (int i = 0; i < HASH_SIZE; i++) {
        for (WriteEvent *w = history[i]; w; w = w->next) {
            if (w->tid != tid) continue;
            if (!w->addr) continue;
            uintptr_t W_start = (uintptr_t)w->addr;
            size_t w_size = w->size;
            if (w_size == 0) {
                w_size = sizeof(w->val);
            }
            uintptr_t W_end = W_start + w_size;
            
            // Check overlap
            uintptr_t O_start = L_start > W_start ? L_start : W_start;
            uintptr_t O_end = L_end < W_end ? L_end : W_end;
            if (O_start < O_end) {
                if (!best || w->timestamp > best->timestamp) {
                    best = w;
                }
            }
        }
    }
    return best;
}

static WriteEvent* find_random_overlapping_write(void *addr, size_t size) {
    if (!addr) return NULL;
    uintptr_t L_start = (uintptr_t)addr;
    uintptr_t L_end = L_start + size;
    int count = 0;
    WriteEvent* candidates[1024];
    for (int i = 0; i < HASH_SIZE; i++) {
        for (WriteEvent *w = history[i]; w; w = w->next) {
            if (!w->addr) continue;
            uintptr_t W_start = (uintptr_t)w->addr;
            size_t w_size = w->size;
            if (w_size == 0) {
                w_size = sizeof(w->val);
            }
            uintptr_t W_end = W_start + w_size;
            
            // Check overlap
            uintptr_t O_start = L_start > W_start ? L_start : W_start;
            uintptr_t O_end = L_end < W_end ? L_end : W_end;
            if (O_start < O_end) {
                if (count < 1024) {
                    candidates[count++] = w;
                }
            }
        }
    }
    if (count == 0) return NULL;
    return candidates[rand() % count];
}

static void satisfy_load_from_write(void *buf_out, size_t buf_size, void *load_addr, const WriteEvent *we) {
    if (!buf_out || buf_size == 0) return;
    
    // First, initialize buf_out with current memory contents if load_addr is valid
    if (load_addr && (uintptr_t)load_addr >= 4096) {
        memcpy(buf_out, load_addr, buf_size);
    } else {
        memset(buf_out, 0, buf_size);
    }
    
    const unsigned char *src_bytes = we->bytes;
    size_t src_size = we->size;
    unsigned char temp_buf[sizeof(intptr_t)];
    if (!src_bytes) {
        memcpy(temp_buf, &we->val, sizeof(we->val));
        src_bytes = temp_buf;
        src_size = sizeof(we->val);
    }
    
    if (load_addr && we->addr) {
        uintptr_t L_start = (uintptr_t)load_addr;
        uintptr_t L_end = L_start + buf_size;
        uintptr_t W_start = (uintptr_t)we->addr;
        uintptr_t W_end = W_start + src_size;
        
        uintptr_t O_start = L_start > W_start ? L_start : W_start;
        uintptr_t O_end = L_end < W_end ? L_end : W_end;
        
        if (O_start < O_end) {
            // Overlap exists
            memcpy((unsigned char *)buf_out + (O_start - L_start),
                   src_bytes + (O_start - W_start),
                   O_end - O_start);
            return;
        }
    }
    
    // Fallback: copy from the beginning
    size_t n = src_size < buf_size ? src_size : buf_size;
    memcpy(buf_out, src_bytes, n);
}

static uint64_t record_event_node_locked(uint64_t tid, long long iid,
                                         uint64_t loc_id, int vid,
                                         int requested_type,
                                         const char *loc_str,
                                         intptr_t value) {
    if (!recording_graph)
        return 0;

    eg_node_t *existing = eg_find_node_by_dynamic(recording_graph, tid, iid, vid);
    if (!existing) {
        uint64_t new_id = atomic_fetch_add(&global_event_id_counter, 1);
        eg_add_node(recording_graph, new_id, tid, iid, loc_id, vid,
                    requested_type, loc_str, value);
        return new_id;
    }

    const bool is_rw_pair =
        (existing->type == EG_OP_READ && requested_type == EG_OP_WRITE) ||
        (existing->type == EG_OP_WRITE && requested_type == EG_OP_READ) ||
        (existing->type == EG_OP_RMW &&
         (requested_type == EG_OP_READ || requested_type == EG_OP_WRITE)) ||
        ((existing->type == EG_OP_READ || existing->type == EG_OP_WRITE) &&
         requested_type == EG_OP_RMW);

    if (is_rw_pair) {
        existing->type = EG_OP_RMW;
    } else if (existing->type != requested_type) {
        fprintf(stderr,
                "[SCHED] Error: recording node kind mismatch for tid=%llu iid=%llx vid=%d. existing=%d requested=%d\n",
                (unsigned long long)tid, iid, vid, existing->type, requested_type);
        scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
    }

    if (loc_id != 0 && existing->loc_id == 0)
        existing->loc_id = loc_id;
    if (loc_str && loc_str[0] != '\0' && existing->location[0] == '\0') {
        strncpy(existing->location, loc_str, 63);
        existing->location[63] = '\0';
    }
    if (requested_type == EG_OP_WRITE || requested_type == EG_OP_RMW)
        existing->value = value;

    return existing->id;
}


// Thread Control
static int active_threads = 0;
static int alive_threads = 0;
static int blocked_unknown_threads = 0;
static pthread_mutex_t sched_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sched_cond = PTHREAD_COND_INITIALIZER;
static uint64_t waiting_status[MAX_THREADS]; // initialized to 0
static bool blocked_unknown_status[MAX_THREADS]; // initialized to false
static bool join_wait_status[MAX_THREADS]; // initialized to false
static bool active_status[MAX_THREADS]; // initialized to false
static bool known_thread_status[MAX_THREADS]; // initialized to false
static bool thread_ever_started[MAX_THREADS]; // initialized to false
static bool deadlock_semantics_logged = false;

static uint64_t *covered_node_ids = NULL;
static int covered_node_count = 0;
static int covered_node_capacity = 0;
static bool *covered_rf_edges = NULL;
static bool *covered_node_by_index = NULL;

// Thread Local Data
// --- Setup ---

void scheduler_finalize(void) {
    pthread_mutex_lock(&sched_lock);
    if (recording_graph) {
        LOG("[SCHED] Program Exit. Serializing EG to %s...\n", config_gen_eg_output);
        eg_serialize(recording_graph, config_gen_eg_output);
        eg_free(recording_graph);
        recording_graph = NULL;
    }
    pthread_mutex_unlock(&sched_lock);
}

static int thread_slot(uint64_t tid) {
    if (tid < (uint64_t)MAX_THREADS)
        return (int)tid;
    return -1;
}

static const char* eg_type_to_string(int type) {
    switch (type) {
        case EG_OP_READ: return "R";
        case EG_OP_WRITE: return "W";
        case EG_OP_FENCE: return "F";
        case EG_OP_RMW: return "RMW";
        default: return "Unknown";
    }
}


static void scheduler_terminate_locked(int code) {
    if(code==WMM_EXIT_INSTANTIATED_BUT_NOT_DONE){
        if(all_threads!=NULL){
            //SHM integration
            struct SHM_next_events *shm = g_next_events;
            if(shm){
                begin_update_c();
                shm->next_event_count = 0;
            }
            //Process each NEXT EVENT one by one
            next_event_list_t *nxt_temp = next_events;
            while(nxt_temp != NULL){
                unsigned long long target_tid = nxt_temp->nxt_event.tid;
                //getting the actual node of same tid as next event, as the event details and children info are stored in only all_threads
                thread_graph_t *temp = all_threads;
                while(temp != NULL && temp->tid != target_tid){
                    temp = temp->next;
                }
                //get the specific parent nodes of the corresponding next event
                event_list_t *specific_last_events = NULL;
                if(temp != NULL){
                    event_list_t *sub_list = get_executed_events_and_prune(temp);
                    if(sub_list != NULL){
                        specific_last_events = sub_list;
                    } else {
                        //if there is no sub list that means either there are no children/the thread executed some other events after thread joins
                        event_list_t *node = (event_list_t*)malloc(sizeof(event_list_t));
                        node->event = temp->last_executed;
                        node->next = NULL;
                        specific_last_events = node;
                    }
                }
                //Gather sources specifically for this next event (temporary store)
                struct Event_id_triple sources[MAX_NODES];
                int source_count = 0;
                //traverse and store the events in sources array
                event_list_t *curr_lst = specific_last_events;
                while(curr_lst){
                    // Print LST_EVNT to console
                    fprintf(stderr, "[LST_EVNT] .tid=%d iid=%lld vid=%d. exit=%d\n",
                            curr_lst->event.tid, curr_lst->event.iid, curr_lst->event.vid, code);
                    
                    if(source_count < MAX_NODES) {
                        sources[source_count].tid = curr_lst->event.tid;
                        sources[source_count].iid = curr_lst->event.iid;
                        sources[source_count].vid = curr_lst->event.vid;
                        source_count++;
                    }
                    
                    // Safely free the node now that we've extracted its data
                    event_list_t *to_free = curr_lst;
                    curr_lst = curr_lst->next;
                    free(to_free);
                }

                // Print NXT_EVNT to console
                fprintf(stderr, "[NXT_EVNT] . tid=%d iid=%lld vid=%d event type=%s memory order=%d location id=%lld. exit=%d\n",
                        nxt_temp->nxt_event.tid, nxt_temp->nxt_event.iid, nxt_temp->nxt_event.vid,
                        eg_type_to_string(nxt_temp->nxt_event.event_type), nxt_temp->nxt_event.order, nxt_temp->nxt_event.loc_id, code);

                //Map the specific sources into SHM for THIS next event
                if (shm && shm->next_event_count < MAX_NEXT) {
                    struct Shared_event *se = &shm->next_events[shm->next_event_count];
                    
                    se->tid = nxt_temp->nxt_event.tid;
                    se->iid = nxt_temp->nxt_event.iid;
                    se->vid = nxt_temp->nxt_event.vid;
                    se->event_type = nxt_temp->nxt_event.event_type;
                    se->access_mode = nxt_temp->nxt_event.order; 
                    se->location = nxt_temp->nxt_event.loc_id;
                    se->source_nodes_count= source_count;
                    //traverse and store all the parents into the corresponding next event
                    for (int i = 0; i < source_count; i++) {
                        se->source_nodes[i] = sources[i];
                        fprintf(stderr,"source: tid=%d,iid=%lld,vid=%d\n node: tid=%d,iid=%lld,vid=%d\n",
                               sources[i].tid, sources[i].iid, sources[i].vid,
                               se->tid, se->iid, se->vid);
                    }
                    shm->next_event_count++;
                }
                nxt_temp = nxt_temp->next;
            }

            //Finalize the SHM update
            if(shm){
                finish_update_c();
                // fprintf(stderr,"[SHM] Successfully added %d next events to shared memory.\n", shm->next_event_count);
            }else{
                // fprintf(stderr,"[SHM-FAILED] Failed to retrieve SHM pointer!\n");
            }
        }
    }
    int expected = 0;
    if (atomic_compare_exchange_strong(&wmm_exiting, &expected, code)) {
        pthread_mutex_unlock(&sched_lock);
        _exit(code);
    } else {
        pthread_mutex_unlock(&sched_lock);
        for (;;) {
            pause();
        }
    }
}

void scheduler_terminate(int code) {

    int expected = 0;
    if (atomic_compare_exchange_strong(&wmm_exiting, &expected, code)) {
        _exit(code);
    } else {
        for (;;) {
            pause();
        }
    }
}

static int node_index_by_id_locked(uint64_t id) {
    if (!current_graph)
        return -1;
    for (int i = 0; i < current_graph->node_count; ++i) {
        if (current_graph->nodes[i].id == id)
            return i;
    }
    return -1;
}

static int cmp_node_idx_for_thread_order(const void *a, const void *b) {
    const int ia = *(const int *)a;
    const int ib = *(const int *)b;
    const eg_node_t *na = &current_graph->nodes[ia];
    const eg_node_t *nb = &current_graph->nodes[ib];
    if (na->visit_id < nb->visit_id) return -1;
    if (na->visit_id > nb->visit_id) return 1;
    if (na->id < nb->id) return -1;
    if (na->id > nb->id) return 1;
    return 0;
}

static void reset_thread_frontier_state(void) {
    for (int i = 0; i < MAX_THREADS; ++i) {
        free(thread_event_indices[i]);
        thread_event_indices[i] = NULL;
        thread_event_count[i] = 0;
        thread_frontier[i] = 0;
    }
    free(covered_node_by_index);
    covered_node_by_index = NULL;
}

static void init_thread_frontier_state_for_current_graph(void) {
    reset_thread_frontier_state();
    if (!current_graph)
        return;

    covered_node_by_index = (bool *)calloc((size_t)current_graph->node_count, sizeof(bool));
    if (!covered_node_by_index)
        return;

    int local_counts[MAX_THREADS] = {0};
    for (int i = 0; i < current_graph->node_count; ++i) {
        int slot = thread_slot(current_graph->nodes[i].tid);
        if (slot >= 0)
            local_counts[slot]++;
    }

    for (int t = 0; t < MAX_THREADS; ++t) {
        if (local_counts[t] <= 0)
            continue;
        thread_event_indices[t] = (int *)malloc(sizeof(int) * (size_t)local_counts[t]);
        if (!thread_event_indices[t]) {
            thread_event_count[t] = 0;
            continue;
        }
        thread_event_count[t] = local_counts[t];
    }

    int write_pos[MAX_THREADS] = {0};
    for (int i = 0; i < current_graph->node_count; ++i) {
        int slot = thread_slot(current_graph->nodes[i].tid);
        if (slot >= 0 && thread_event_indices[slot]) {
            thread_event_indices[slot][write_pos[slot]++] = i;
        }
    }

    for (int t = 0; t < MAX_THREADS; ++t) {
        if (thread_event_indices[t] && thread_event_count[t] > 1) {
            qsort(thread_event_indices[t], (size_t)thread_event_count[t], sizeof(int),
                  cmp_node_idx_for_thread_order);
        }
        thread_frontier[t] = 0;
    }
}

static void advance_thread_frontier_locked(int slot) {
    if (slot < 0 || slot >= MAX_THREADS)
        return;
    while (thread_frontier[slot] < thread_event_count[slot]) {
        int node_idx = thread_event_indices[slot][thread_frontier[slot]];
        if (!covered_node_by_index || !covered_node_by_index[node_idx])
            break;
        thread_frontier[slot]++;
    }
}

static bool is_node_frontier_locked(int node_idx) {
    if (!current_graph || node_idx < 0 || node_idx >= current_graph->node_count)
        return false;
    int slot = thread_slot(current_graph->nodes[node_idx].tid);
    if (slot < 0 || !thread_event_indices[slot])
        return false;
    if (thread_frontier[slot] >= thread_event_count[slot])
        return false;
    return thread_event_indices[slot][thread_frontier[slot]] == node_idx;
}

static bool is_node_covered_locked(int node_idx) {
    if (!covered_node_by_index || node_idx < 0 || !current_graph || node_idx >= current_graph->node_count)
        return false;
    return covered_node_by_index[node_idx];
}

static bool is_thread_runnable_locked(int slot) {
    if (slot < 0 || slot >= MAX_THREADS)
        return false;
    if (!active_status[slot])
        return false;
    if (blocked_unknown_status[slot])
        return false;
    if (join_wait_status[slot])
        return false;
    if (waiting_status[slot] != 0)
        return false;
    return true;
}

static bool is_node_producible_locked(int node_idx, bool *visiting) {
    if (!current_graph || node_idx < 0 || node_idx >= current_graph->node_count)
        return false;
    if (is_node_covered_locked(node_idx))
        return true;
    if (!is_node_frontier_locked(node_idx))
        return false;

    const eg_node_t *n = &current_graph->nodes[node_idx];
    const int slot = thread_slot(n->tid);
    if (!is_thread_runnable_locked(slot))
        return false;

    if (n->type == EG_OP_WRITE || n->type == EG_OP_RMW || n->type == EG_OP_FENCE)
        return true;
    if (n->type != EG_OP_READ)
        return false;

    uint64_t src_id = find_rf_source(n->id);
    if (src_id == 0)
        return false;
    int src_idx = node_index_by_id_locked(src_id);
    if (src_idx < 0)
        return false;
    if (is_node_covered_locked(src_idx))
        return true;

    if (!visiting)
        return false;
    if (visiting[src_idx])
        return false;
    visiting[src_idx] = true;
    bool ok = is_node_producible_locked(src_idx, visiting);
    visiting[src_idx] = false;
    return ok;
}

static bool exists_producible_uncovered_event_locked(void) {
    if (!current_graph)
        return false;
    bool *visiting = (bool *)calloc((size_t)current_graph->node_count, sizeof(bool));
    if (!visiting)
        return false;

    bool found = false;
    for (int i = 0; i < current_graph->node_count; ++i) {
        if (is_node_covered_locked(i))
            continue;
        if (is_node_producible_locked(i, visiting)) {
            found = true;
            break;
        }
    }
    free(visiting);
    return found;
}

static bool thread_has_producible_frontier_event_locked(int slot) {
    if (!current_graph)
        return false;
    if (slot < 0 || slot >= MAX_THREADS)
        return false;
    if (!thread_event_indices[slot])
        return false;
    if (thread_frontier[slot] >= thread_event_count[slot])
        return false;

    const int node_idx = thread_event_indices[slot][thread_frontier[slot]];
    if (node_idx < 0 || node_idx >= current_graph->node_count)
        return false;
    if (is_node_covered_locked(node_idx))
        return false;

    bool *visiting = (bool *)calloc((size_t)current_graph->node_count, sizeof(bool));
    if (!visiting)
        return false;
    const bool producible = is_node_producible_locked(node_idx, visiting);
    free(visiting);
    return producible;
}

static int resolve_blocking_slot_locked(uint64_t reported_tid) {
    int slot = thread_slot(reported_tid);
    if (slot >= 0)
        return slot;

    int active_slot = -1;
    int active_count = 0;
    for (int i = 0; i < MAX_THREADS; ++i) {
        if (active_status[i]) {
            active_slot = i;
            active_count++;
            if (active_count > 1)
                break;
        }
    }

    if (active_count == 1)
        return active_slot;

    return -1;
}

static pthread_key_t wmm_thread_cleanup_key;
static pthread_once_t wmm_thread_cleanup_once = PTHREAD_ONCE_INIT;

static void wmm_thread_cleanup_destructor(void *arg) {
    uint64_t slot = (uint64_t)(uintptr_t)arg - 1;
    scheduler_thread_unregistered(slot);
}

static void make_wmm_thread_cleanup_key(void) {
    pthread_key_create(&wmm_thread_cleanup_key, wmm_thread_cleanup_destructor);
}

static void ensure_event_thread_active_locked(int slot) {
    if (slot < 0 || slot >= MAX_THREADS)
        return;
    if (!known_thread_status[slot]) {
        known_thread_status[slot] = true;
        thread_ever_started[slot] = true;
        alive_threads++;
    }
    if (!active_status[slot]) {
        active_status[slot] = true;
        active_threads++;
    }
    
    // Register TLS destructor for automatic cleanup on thread exit
    pthread_once(&wmm_thread_cleanup_once, make_wmm_thread_cleanup_key);
    if (pthread_getspecific(wmm_thread_cleanup_key) == NULL) {
        pthread_setspecific(wmm_thread_cleanup_key, (void *)(uintptr_t)(slot + 1));
    }
}

static bool can_produce_write_locked(uint64_t write_node_id) {
    /*
     * RF-only approximation:
     * This check determines whether a waited write is still potentially producible
     * using scheduler-visible state (graph, coverage, and thread wait/block state).
     * It does not model full per-thread control-flow reachability (no per-thread PC),
     * so this is intentionally conservative but not fully sound.
     */
    if (!current_graph || write_node_id == 0)
        return false;

    if (find_write_in_history(write_node_id))
        return true;

    eg_node_t *write_node = eg_find_node_by_id(current_graph, write_node_id);
    if (!write_node)
        return false;
    if (write_node->type != EG_OP_WRITE && write_node->type != EG_OP_RMW)
        return false;

    for (int i = 0; i < covered_node_count; ++i) {
        if (covered_node_ids[i] == write_node_id)
            return false;
    }

    const int producer_slot = thread_slot(write_node->tid);
    if (producer_slot < 0)
        return false;
    if (!active_status[producer_slot]) {
        if (thread_ever_started[producer_slot]) {
            return false;
        }
        if (thread_event_indices[producer_slot] &&
            thread_event_count[producer_slot] > 0 &&
            thread_frontier[producer_slot] < thread_event_count[producer_slot]) {
            return true;
        }
        return false;
    }
    if (!is_thread_runnable_locked(producer_slot))
        return false;

    return true;
}

static bool is_global_wait_deadlock_locked(void) {
    bool has_blocked_thread = false;

    if (alive_threads > active_threads) {
        return false;
    }

    if (!deadlock_semantics_logged) {
        deadlock_semantics_logged = true;
        LOG("[SCHED] Deadlock detection uses RF-only producibility (no full reachability / per-thread PC modeling).\n");
    }

    for (int slot = 0; slot < MAX_THREADS; ++slot) {
        if (!active_status[slot])
            continue;

        const uint64_t target = waiting_status[slot];
        const bool blocked_on_unknown = blocked_unknown_status[slot];
        const bool blocked_on_join = join_wait_status[slot];

        if (target == 0 && !blocked_on_unknown && !blocked_on_join) {
            return false;
        }

        if (blocked_on_unknown || blocked_on_join)
            has_blocked_thread = true;

        if (target != 0) {
            has_blocked_thread = true;
            if (can_produce_write_locked(target)) {
                return false;
            }
        }
    }

    return has_blocked_thread;
}

static bool has_blocked_or_waiting_threads_locked(void);

static bool all_graph_threads_registered_locked(void) {
    if (!current_graph)
        return true;
    for (int slot = 0; slot < MAX_THREADS; ++slot) {
        if (thread_event_count[slot] > 0 && !thread_ever_started[slot] && thread_frontier[slot] < thread_event_count[slot])
            return false;
    }
    return true;
}

static bool should_exit_deadlock_locked(void) {
    if (active_threads <= 0)
        return false;

    if (alive_threads > active_threads) {
        static int print_count = 0;
        if (print_count++ % 1000 == 0) {
            fprintf(stderr, "[SCHED-DEBUG] should_exit_deadlock_locked: alive_threads=%d > active_threads=%d\n", alive_threads, active_threads);
        }
        return false;
    }



    for (int slot = 0; slot < MAX_THREADS; ++slot) {
        if (!active_status[slot])
            continue;
        if (blocked_unknown_status[slot] || join_wait_status[slot])
            continue;
        const uint64_t waited_write = waiting_status[slot];
        if (waited_write == 0) {
            // This thread is active, not blocked on unknown, not blocked on join,
            // and not waiting for any write. It is runnable and actively executing!
            // Any running thread prevents deadlock.
            static int print_count3 = 0;
            if (print_count3++ % 1000 == 0) {
                fprintf(stderr, "[SCHED-DEBUG] should_exit_deadlock_locked: slot %d is runnable/running\n", slot);
            }
            return false;
        }
        if (can_produce_write_locked(waited_write)) {
            static int print_count4 = 0;
            if (print_count4++ % 1000 == 0) {
                fprintf(stderr, "[SCHED-DEBUG] should_exit_deadlock_locked: slot %d waiting for write %llu which is producible\n", slot, (unsigned long long)waited_write);
            }
            return false;
        }
    }

    if (current_graph && covered_node_count < current_graph->node_count) {
        if (exists_producible_uncovered_event_locked()) {
            static int print_count5 = 0;
            if (print_count5++ % 1000 == 0) {
                fprintf(stderr, "[SCHED-DEBUG] should_exit_deadlock_locked: exists producible uncovered event\n");
            }
            return false;
        }
        return true;
    }

    if (!has_blocked_or_waiting_threads_locked())
        return false;

    return true;
}

static void reset_covered_nodes(void) {
    free(covered_node_ids);
    covered_node_ids = NULL;
    covered_node_count = 0;
    covered_node_capacity = 0;
}

static void reset_covered_rf_edges(void) {
    free(covered_rf_edges);
    covered_rf_edges = NULL;
}

static void init_covered_rf_edges_for_current_graph(void) {
    reset_covered_rf_edges();
    if (!current_graph || current_graph->rf_count <= 0)
        return;
    covered_rf_edges = (bool *)calloc((size_t)current_graph->rf_count, sizeof(bool));
}

static void mark_rf_edge_covered(uint64_t src_id, uint64_t dst_id) {
    if (!current_graph || !covered_rf_edges)
        return;
    for (int i = 0; i < current_graph->rf_count; ++i) {
        if (current_graph->rf_edges[i].src_id == src_id &&
            current_graph->rf_edges[i].dst_id == dst_id) {
            covered_rf_edges[i] = true;
            return;
        }
    }
}

static bool all_rf_edges_covered_locked(void) {
    if (!current_graph)
        return false;
    if (current_graph->rf_count <= 0)
        return true;
    if (!covered_rf_edges)
        return false;
    for (int i = 0; i < current_graph->rf_count; ++i) {
        if (!covered_rf_edges[i])
            return false;
    }
    return true;
}

static bool has_blocked_or_waiting_threads_locked(void) {
    for (int i = 0; i < MAX_THREADS; ++i) {
        if (!active_status[i])
            continue;
        if (waiting_status[i] != 0 || blocked_unknown_status[i] || join_wait_status[i])
            return true;
    }
    return false;
}

static bool mark_node_covered(uint64_t node_id) {
    int node_idx = node_index_by_id_locked(node_id);
    if (node_idx >= 0 && covered_node_by_index)
        covered_node_by_index[node_idx] = true;

    if (node_idx >= 0 && current_graph) {
        int slot = thread_slot(current_graph->nodes[node_idx].tid);
        if (slot >= 0)
            advance_thread_frontier_locked(slot);
    }

    for (int i = 0; i < covered_node_count; ++i) {
        if (covered_node_ids[i] == node_id)
            return false;
    }
    if (covered_node_count >= covered_node_capacity) {
        int next_capacity = covered_node_capacity == 0 ? 128 : covered_node_capacity * 2;
        uint64_t *next = (uint64_t *)realloc(covered_node_ids,
                                             sizeof(uint64_t) * (size_t)next_capacity);
        if (!next)
            return false;
        covered_node_ids = next;
        covered_node_capacity = next_capacity;
    }
    covered_node_ids[covered_node_count++] = node_id;
    return true;
}

static bool all_graph_nodes_covered(void) {
    if (!current_graph)
        return false;
    return covered_node_count >= current_graph->node_count;
}

static bool is_instantiated_but_not_done_locked(void) {
    if (!current_graph)
        return false;
    if (covered_node_count != current_graph->node_count)
        return false;
    if (!all_rf_edges_covered_locked())
        return false;
    return true;
}

static int classify_terminal_code_locked(void) {
    return is_instantiated_but_not_done_locked()
               ? WMM_EXIT_INSTANTIATED_BUT_NOT_DONE
               : WMM_EXIT_NOT_INSTANTIABLE;
}

static void scheduler_verify_atexit(void) {
    pthread_mutex_lock(&sched_lock);
    if (current_graph) {
        if (!is_instantiated_but_not_done_locked()) {
            fprintf(stderr, "[SCHED] Program exited normally but graph is NOT fully covered/instantiated. Covered nodes: %d/%d. Exiting with WMM_EXIT_NOT_INSTANTIABLE (21).\n",
                    covered_node_count, current_graph->node_count);
            scheduler_terminate_locked(WMM_EXIT_NOT_INSTANTIABLE);
        }
    }
    pthread_mutex_unlock(&sched_lock);
}

static void block_on_unknown_event_locked(uint64_t tid, uint64_t event_uid,
                                          const char *kind) {
    const int slot = resolve_blocking_slot_locked(tid);
    if (slot >= 0)
        ensure_event_thread_active_locked(slot);
    if (slot >= 0 && !blocked_unknown_status[slot]) {
        waiting_status[slot] = 0;
        blocked_unknown_status[slot] = true;
        blocked_unknown_threads++;
        pthread_cond_broadcast(&sched_cond);
    }

    if (slot < 0) {
        const int code = classify_terminal_code_locked();
        fprintf(stderr,
            "[SCHED] Unknown %s event with unmapped runtime thread (reported tid=%llu). Exiting with code=%d.\n",
                kind,
            (unsigned long long)tid,
            code);
        scheduler_terminate_locked(code);
    }

    LOG("[SCHED] Unknown %s event encountered (reported tid=%llu uid=%llx). Blocking runtime thread slot %d. Active threads=%d, alive threads=%d, blocked unknown threads=%d\n",
        kind, (unsigned long long)tid, (unsigned long long)event_uid, slot, active_threads, alive_threads, blocked_unknown_threads);
    for (;;) {
        if (should_exit_deadlock_locked()) {
            const int code = classify_terminal_code_locked();
            fprintf(stderr,
                    "[SCHED] Deadlock while blocked on unknown event(s). covered=%d/%d. exit=%d\n",
                    covered_node_count,
                    current_graph ? current_graph->node_count : 0,
                    code);
            scheduler_terminate_locked(code);
        }
        pthread_cond_wait(&sched_cond, &sched_lock);
    }
}

void scheduler_init(void) {
    reset_covered_nodes();
    reset_covered_rf_edges();
    reset_thread_frontier_state();
    blocked_unknown_threads = 0;
    memset(blocked_unknown_status, 0, sizeof(blocked_unknown_status));
    memset(join_wait_status, 0, sizeof(join_wait_status));
    memset(active_status, 0, sizeof(active_status));
    memset(known_thread_status, 0, sizeof(known_thread_status));
    memset(thread_ever_started, 0, sizeof(thread_ever_started));
    memset(waiting_status, 0, sizeof(waiting_status));
    active_threads = 0;
    alive_threads = 0;
    all_threads=NULL;
    next_events=NULL;



    // Reset write history
    for (int i = 0; i < HASH_SIZE; i++) {
        WriteEvent *w = history[i];
        while (w) {
            WriteEvent *next = w->next;
            if (w->bytes) free(w->bytes);
            free(w);
            w = next;
        }
        history[i] = NULL;
    }
    global_write_timestamp = 0;

    // Reset defaults (important for tests)
    config_missing_random_sampling = MRS_STOP;
    
    // Config
    char *env_afl = getenv("ENABLE_AFL");
    if (env_afl && strcmp(env_afl, "0") != 0) {
        LOG("[SCHED] AFL Integration Enabled (Stub). Shared Event Graph coverage would be tracked here.\n");
        // setup_afl_shm();
    }

    config_gen_eg_output = getenv("GEN_EG");
    if (config_gen_eg_output) {
        LOG("[SCHED] Generating EG to %s\n", config_gen_eg_output);
        recording_graph = eg_create();
        atexit(scheduler_finalize);
    }

    char *env = getenv("MISSING_RANDOM_SAMPLING");
    if (env) {
        if (strcmp(env, "latest") == 0) config_missing_random_sampling = MRS_LATEST;
        else if (strcmp(env, "latest_local") == 0) config_missing_random_sampling = MRS_LATEST_LOCAL;
        else if (strcmp(env, "random") == 0) config_missing_random_sampling = MRS_RANDOM;
        LOG("[SCHED] MISSING_RANDOM_SAMPLING=%d (%s)\n", config_missing_random_sampling, env);
    } else {
        LOG("[SCHED] MISSING_RANDOM_SAMPLING=STOP (Default)\n");
    }
    
    // Load Graph
    char *input_file = getenv("FUZZ_INPUT");
    if (input_file) {
        fprintf(stderr, "[SCHED INPUT JSON] Loading graph from %s\n", input_file);

        if (current_graph) {
            eg_free(current_graph);
            current_graph = NULL;
        }
        current_graph = eg_deserialize(input_file);
        if (current_graph) {
            init_covered_rf_edges_for_current_graph();
            init_thread_frontier_state_for_current_graph();
            LOG("[SCHED] Loaded %d nodes from %s\n", current_graph->node_count, input_file);
            LOG("[SCHED] Loaded %d RF edges from %s\n", current_graph->rf_count, input_file);
        } else {
            LOG("[SCHED] Failed to load graph from %s\n", input_file);
        }
    } else {
        char *input = NULL;
        size_t cap = 4096;
        size_t total = 0;
        ssize_t r;

        input = malloc(cap);
        if (!input) {
            fprintf(stderr, "Couldn't allocate memory for stdin input.\n");
            total = 0;
        } else {
            // Read until EOF, growing buffer as needed
            while (1) {
                r = read(STDIN_FILENO, input + total, (ssize_t)(cap - total));
                if (r < 0) {
                    if (errno == EINTR) continue;
                    fprintf(stderr, "Couldn't read stdin.\n");
                    break;
                }
                if (r == 0) break; // EOF
                total += (size_t)r;
                if (total == cap) {
                    size_t newcap = cap * 2;
                    char *tmp = realloc(input, newcap);
                    if (!tmp) {
                        fprintf(stderr, "Couldn't realloc stdin buffer.\n");
                        break;
                    }
                    input = tmp;
                    cap = newcap;
                }
            }
        }

        if (current_graph) {
            eg_free(current_graph);
            current_graph = NULL;
        }

        current_graph = eg_deserialize_mem(input ? input : "", total);
        if (input) free(input);
        if (current_graph) {
            init_covered_rf_edges_for_current_graph();
            init_thread_frontier_state_for_current_graph();
            LOG("[SCHED] Loaded %d nodes from stdin input\n", current_graph->node_count);
            LOG("[SCHED] Loaded %d RF edges from stdin input\n", current_graph->rf_count);
            if (current_graph->node_count == 0 && current_graph->rf_count == 0) {
                LOG("[SCHED] Empty input graph. Running without a graph.\n");
                eg_free(current_graph);
                current_graph = NULL;
                return;
            }
            // they are
            for (int i = 0; i < current_graph->node_count; i++) {
                eg_node_t *n = &current_graph->nodes[i];
                  LOG("[SCHED] Node ID=%llu TID=%llu SID=%lld VID=%d TYPE=%d LOC=%s VAL=%ld\n",
                      (unsigned long long)n->id,
                      (unsigned long long)n->tid,
                      (long long)n->instruction_id,
                      n->visit_id,
                      n->type,
                      n->location,
                      n->value);
            }
            for (int i = 0; i < current_graph->rf_count; i++) {
                eg_edge_t *e = &current_graph->rf_edges[i];
                  LOG("[SCHED] RF Edge: WRITE ID=%llu -> READ ID=%llu\n",
                      (unsigned long long)e->src_id,
                      (unsigned long long)e->dst_id);
            }
        } else {
            LOG("[SCHED] Failed to load graph from stdin input\n");
        }
    }

    if (current_graph) {
        atexit(scheduler_verify_atexit);
    }

    srand(time(NULL));
}

// --- Address to Name Mapping ---
typedef struct AddrMap {
    void *addr;
    char name[64];
    struct AddrMap *next;
} AddrMap;

static AddrMap *addr_map_head = NULL;

void scheduler_register_location(const char *name, void *addr) {
    pthread_mutex_lock(&sched_lock);
    AddrMap *m = malloc(sizeof(AddrMap));
    m->addr = addr;
    strncpy(m->name, name, 63);
    m->name[63] = '\0';
    m->next = addr_map_head;
    addr_map_head = m;
    pthread_mutex_unlock(&sched_lock);
}

static const char* lookup_addr_name(void *addr, char *fallback_buf, size_t buf_size) {
    for (AddrMap *m = addr_map_head; m; m = m->next) {
        if (m->addr == addr) return m->name;
    }
    snprintf(fallback_buf, buf_size, "%p", addr);
    return fallback_buf;
}

void __wmm_trace(long long instruction_id) {
    (void)instruction_id;
}

// Function to update the last event for a particular thread
static void update_last_executed_event(unsigned long long tid,long long iid,int vid){
    if(!all_threads){
        fprintf(stderr,"No threads stored in all_threads(no thread is registered)\n");
        return;
    }
    thread_graph_t* node=all_threads;
    //removed the g_tid thing as it is irrelevant and misunderstood the runtime_to_graph_id initially
    while(node!=NULL && node->tid!=tid){
        node=node->next;
    }
    if(node==NULL) {
        fprintf(stderr, "[SCHED-DEBUG] WARNING: update_last_executed_event failed to find TID %llu \n", tid);
        return;
    }
    node->last_executed.tid=tid;
    node->last_executed.iid=iid;
    node->last_executed.vid=vid;
}

//helper function to add child to parent
static void add_child(unsigned long long ptid,thread_graph_t * node){
    if(all_threads==NULL) return;
    thread_graph_t *parent=all_threads;
    while(parent!=NULL && parent->tid!=ptid){
        parent=parent->next;
    }
    if(!parent){
        fprintf(stderr,"[SCHED-CRITICAL] ORPHAN THREAD: Failed to find parent %llu for child %llu. Attaching to root (T0).\n",ptid,node->tid);
        parent = all_threads;
        while(parent != NULL && parent->tid != 0) parent = parent->next;
        if (!parent) return;
    }
    // append the node in the start;
    node->sibling=parent->children;
    parent->children=node;
    node->last_executed=parent->last_executed;

}

// Function to add a thread to all_threads and map child and a parent
static void add_to_all_threads(unsigned long long tid,unsigned long long parentid){
    thread_graph_t * node=(thread_graph_t *)malloc(sizeof(thread_graph_t));
    node->tid=tid;
    node->joined=false;
    node->children=NULL;
    node->sibling = NULL;
    node->next=NULL;
    node->parent_iid_at_join=-1;
    node->parent_vid_at_join=-1;
    node->last_executed.tid=tid;
    node->last_executed.iid = -1;
    node->last_executed.vid = -1;

    add_child(parentid,node);

    if(all_threads==NULL){
        all_threads=node;
    }else{
        // append the node in the start;
        node->next=all_threads;
        all_threads=node;
    }
}

void scheduler_thread_created(int tid,unsigned long long parentid) {
    pthread_mutex_lock(&sched_lock);
    if (tid >= 0 && tid < MAX_THREADS && !thread_ever_started[tid]) {
        known_thread_status[tid] = true;
        thread_ever_started[tid] = true;
        alive_threads++;
        pthread_cond_broadcast(&sched_cond);
    }
    add_to_all_threads(tid,parentid);
    fprintf(stderr,"Registered thread=%d with parent=%d\n",tid,parentid);
    pthread_mutex_unlock(&sched_lock);
}

void scheduler_thread_registered(int tid) {
    pthread_mutex_lock(&sched_lock);
    if (tid >= 0 && tid < MAX_THREADS) {
        if (!known_thread_status[tid]) {
            known_thread_status[tid] = true;
            thread_ever_started[tid] = true;
            alive_threads++;
        }
        blocked_unknown_status[tid] = false;
        join_wait_status[tid] = false;
        waiting_status[tid] = 0;
        if (!active_status[tid]) {
            active_status[tid] = true;
            active_threads++;
        }
        pthread_cond_broadcast(&sched_cond);
    }
    if(tid==0){
        add_to_all_threads(tid,-1);
        fprintf(stderr,"Registered thread 0\n");
    }
    pthread_mutex_unlock(&sched_lock);
}

void scheduler_thread_unregistered(int tid) {
    pthread_mutex_lock(&sched_lock);
    if (tid >= 0 && tid < MAX_THREADS) {
        waiting_status[tid] = 0;
        join_wait_status[tid] = false;
        if (active_status[tid]) {
            active_status[tid] = false;
            active_threads--;
        }
        if (known_thread_status[tid]) {
            known_thread_status[tid] = false;
            alive_threads--;
        }
    }
    if (tid >= 0 && tid < MAX_THREADS && blocked_unknown_status[tid]) {
        blocked_unknown_status[tid] = false;
        if (blocked_unknown_threads > 0)
            blocked_unknown_threads--;
    }
    // If threads leave, we might need to wake up others to check deadlock/termination
    pthread_cond_broadcast(&sched_cond); 

    /* Moved to atexit
    if (active_threads == 0 && recording_graph) {
        printf("[SCHED] All threads ended. Serializing EG to %s...\n", config_gen_eg_output);
        eg_serialize(recording_graph, config_gen_eg_output);
        eg_free(recording_graph);
        recording_graph = NULL;
    }
    */

    pthread_mutex_unlock(&sched_lock);
}

void scheduler_thread_join_wait_begin(int tid) {
    pthread_mutex_lock(&sched_lock);
    if (tid >= 0 && tid < MAX_THREADS && active_status[tid]) {
        join_wait_status[tid] = true;
        waiting_status[tid] = 0;
    }
    pthread_cond_broadcast(&sched_cond);
    pthread_mutex_unlock(&sched_lock);
}

// Function to mark joined as true for a thread in all_threads
static void thread_joined_mark_true(int parent_tid,int tid){
    thread_graph_t *parent = all_threads;
    thread_graph_t *child=all_threads;
    while(parent && parent->tid != parent_tid) parent = parent->next;
    while(child && child->tid!=tid){
        child=child->next;
    }
    if(child && parent) {
        child->joined = true;
        child->parent_iid_at_join = parent->last_executed.iid; 
        child->parent_vid_at_join = parent->last_executed.vid; 
    }else {
        fprintf(stderr, "[SCHED-CRITICAL] RACE DETECTED: Failed to mark Thread %d as joined by Thread %d! Child ptr: %p, Parent ptr: %p\n", 
                tid, parent_tid, (void*)child, (void*)parent);
    }
}

void scheduler_thread_join_wait_end(int tid,int child_tid) {
    pthread_mutex_lock(&sched_lock);
    if (tid >= 0 && tid < MAX_THREADS && active_status[tid]) {
        join_wait_status[tid] = false;
    }
    fprintf(stderr,"Join wait end parent =%d child=%d\n",tid,child_tid);
    thread_joined_mark_true(tid,child_tid);
    pthread_cond_broadcast(&sched_cond);
    pthread_mutex_unlock(&sched_lock);
}
// Stoeing the unknown event into the next_event_list_t
static void store_the_unknown_event(int tid, long long iid, int vid,Access_Mode order, int event_type,long long loc_id){
    next_event_list_t *node=(next_event_list_t *) malloc(sizeof(next_event_list_t));
    node->nxt_event.tid=tid;
    node->nxt_event.iid=iid;
    node->nxt_event.vid=vid;
    node->nxt_event.order=order;
    node->nxt_event.loc_id=loc_id;
    node->nxt_event.event_type=event_type;
    //prepend to the list
    node->next=next_events;
    next_events=node;
}

// --- Handlers ---

void scheduler_on_store_ex(void *addr, intptr_t val, Access_Mode order,//changed memory_order to Access_Mode enum
                          uint64_t event_uid, uint64_t thread_id,
                          uint64_t loc_id, uint64_t visit_id) {
    (void)order;
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;

    pthread_mutex_lock(&sched_lock);

    const int event_slot = thread_slot(tid);
    if (event_slot >= 0)
        ensure_event_thread_active_locked(event_slot);

    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;
    
    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_WRITE,loc_id);
            LOG("[SCHED-DEBUG] Unknown store event encountered (reported tid=%llu uid=%llx). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid);
            block_on_unknown_event_locked(tid, event_uid, "STORE");
        } else {
            if (node->type != EG_OP_WRITE && node->type != EG_OP_RMW) {
                     fprintf(stderr, "[SCHED] Error: Store event mismatch. Expected WRITE/RMW, found type %d. tid=%llu uid=%llu iid=%llx\n",
                         node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
                 scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            // printf("Executing the STORE event, tid=%d,iid=%lld,vid=%d\n",tid,iid,vid);
            update_last_executed_event(tid,iid,vid);
        }
    }

    intptr_t modeled_val = val;
    // FIXME: DO NOT USE modeled value, this must be behind a ENV flag
    if (current_graph && node && addr == NULL) {
        modeled_val = node->value;
    }

    uint64_t gn_id = node ? node->id : 0;

    if (recording_graph) {
        char loc_buf[64];
        const char *loc_str = lookup_addr_name(addr, loc_buf, sizeof(loc_buf));
        gn_id = record_event_node_locked(tid, iid, loc_id, vid,
                                         EG_OP_WRITE, loc_str, modeled_val);
    }

    // Add to history (with per-address LRU eviction if needed)
    add_history(addr, modeled_val, loc_id, tid, iid, vid, gn_id);
    LOG("[SCHED-DEBUG] Store Event: TID=%llu UID=%llx IID=%llx NodeID=%s Addr=%p Val=%ld (runtime=%ld)\n",
        (unsigned long long)tid, (unsigned long long)event_uid, iid,
        (gn_id != 0) ? "RECORDED" : "N/A", addr, (long)modeled_val, (long)val);
    
    // Broadcast to wake up any threads blocking on reads from this address
    LOG("[SCHED-DEBUG] Broadcasting after store. Active threads=%d, alive threads=%d, blocked unknown threads=%d\n",
        active_threads, alive_threads, blocked_unknown_threads);
    pthread_cond_broadcast(&sched_cond);

    pthread_mutex_unlock(&sched_lock);
}

void scheduler_on_store_bytes_ex(void *addr, const void *data, size_t size,
                                Access_Mode order,
                                uint64_t event_uid, uint64_t thread_id,
                                uint64_t loc_id, uint64_t visit_id) {
    (void)order;
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;

    pthread_mutex_lock(&sched_lock);

    const int event_slot = thread_slot(tid);
    if (event_slot >= 0)
        ensure_event_thread_active_locked(event_slot);

    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;

    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_WRITE,loc_id);
            LOG("[SCHED-DEBUG] Unknown store event encountered (reported tid=%llu uid=%llx). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid);
            block_on_unknown_event_locked(tid, event_uid, "STORE_BYTES");
        } else {
            if (node->type != EG_OP_WRITE && node->type != EG_OP_RMW) {
                fprintf(stderr, "[SCHED] Error: Store event mismatch. Expected WRITE/RMW, found type %d. tid=%llu uid=%llu iid=%llx\n",
                        node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
                scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            // printf("Executing the STORE BYTES event, tid=%d,iid=%lld,vid=%d\n",tid,iid,vid);
            update_last_executed_event(tid,iid,vid);
        }
    }

    uint64_t gn_id = node ? node->id : 0;
    intptr_t modeled_val = bytes_to_intptr(data, size);

    if (recording_graph) {
        char loc_buf[64];
        const char *loc_str = lookup_addr_name(addr, loc_buf, sizeof(loc_buf));
        gn_id = record_event_node_locked(tid, iid, loc_id, vid,
                                         EG_OP_WRITE, loc_str, modeled_val);
    }

    add_history_bytes(addr, data, size, loc_id, tid, iid, vid, gn_id);
    LOG("[SCHED-DEBUG] Store(bytes) Event: TID=%llu UID=%llx IID=%llx NodeID=%s Addr=%p Size=%zu Val=%ld\n",
        (unsigned long long)tid, (unsigned long long)event_uid, iid,
        (gn_id != 0) ? "RECORDED" : "N/A", addr, size, (long)modeled_val);

    pthread_cond_broadcast(&sched_cond);
    pthread_mutex_unlock(&sched_lock);
}

void scheduler_on_store(void *addr, intptr_t val, Access_Mode order,
                       uint64_t event_uid, uint64_t thread_id,
                       uint64_t loc_id) {
    scheduler_on_store_ex(addr, val, order, event_uid, thread_id, loc_id, 0);
}

bool scheduler_on_load_ex(void *addr, Access_Mode order, intptr_t *val_out,
                         uint64_t event_uid, uint64_t thread_id,
                         uint64_t loc_id, uint64_t visit_id) {
    return scheduler_on_load_bytes_ex(addr, order, val_out, sizeof(*val_out),
                                      event_uid, thread_id, loc_id, visit_id);
}

bool scheduler_on_load_bytes_ex(void *addr, Access_Mode order,
                               void *buf_out, size_t buf_size,
                               uint64_t event_uid, uint64_t thread_id,
                               uint64_t loc_id, uint64_t visit_id) {
    (void)order;
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;
    
    pthread_mutex_lock(&sched_lock);
    
    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;
    
    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_READ,loc_id);
            LOG("[SCHED-DEBUG] Unknown load event encountered (reported tid=%llu uid=%llx visit=%llu). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid, (unsigned long long)visit_id);
            block_on_unknown_event_locked(tid, event_uid, "LOAD");
        } else {
            if (node->type != EG_OP_READ && node->type != EG_OP_RMW) {
                 fprintf(stderr, "[SCHED] Error: Load event mismatch. Expected READ/RMW, found type %d. tid=%llu uid=%llx iid=%llx\n",
                     node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
               scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            fprintf(stderr,"Executing the LOAD event, tid=%d,iid=%lld,vid=%d\n",tid,iid,vid);
            update_last_executed_event(tid,iid,vid);
        }
    }

            uint64_t target_write_id = (node) ? find_rf_source(node->id) : 0;
            if (current_graph && node &&
                (node->type == EG_OP_READ || node->type == EG_OP_RMW) &&
                target_write_id == 0) {
                fprintf(stderr,
                        "[SCHED] Invalid input: read/rmw event tid=%llu uid=%llx has no rf_edges source write.\n",
                        (unsigned long long)tid,
                        (unsigned long long)event_uid);
                scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
                LOG("[SCHED-DEBUG] Load Event with sampling: %d TID=%llu UID=%llx IID=%llx NodeID=%s TargetWriteID=%llu\n",
               config_missing_random_sampling, (unsigned long long)tid, (unsigned long long)event_uid,
                    iid, node ? "FOUND" : "NULL", (unsigned long long)target_write_id);
            uint64_t recorded_id = 0;
    if (recording_graph) {
        char loc_buf[64];
        const char *loc_str = lookup_addr_name(addr, loc_buf, sizeof(loc_buf));
        recorded_id = record_event_node_locked(tid, iid, loc_id, vid,
                                               EG_OP_READ, loc_str, 0);
    }

            if (recording_graph && target_write_id == 0) {
                WriteEvent *latest = find_latest_overlapping_write(addr, buf_size);
                if (!latest)
                    latest = find_latest_write_by_loc(loc_id);
                if (latest && recorded_id != 0) {
                    eg_add_edge_rf(recording_graph, latest->graph_node_id, recorded_id);
                    eg_node_t *rn = eg_find_node_by_id(recording_graph, recorded_id);
                    if (rn) {
                        uint8_t temp_val_buf[sizeof(intptr_t)];
                        satisfy_load_from_write(temp_val_buf, sizeof(temp_val_buf), addr, latest);
                        rn->value = bytes_to_intptr(temp_val_buf, sizeof(temp_val_buf));
                    }
                }
            }

    if (target_write_id != 0) {
        // We have a forced read!
        const int slot = resolve_blocking_slot_locked(tid);
        if (slot >= 0)
            ensure_event_thread_active_locked(slot);
        if (slot < 0) {
            const int code = classify_terminal_code_locked();
            fprintf(stderr,
                "[SCHED] Forced read wait has unmapped runtime thread (reported tid=%llu uid=%llx write=%llu). Exiting with code=%d.\n",
                    (unsigned long long)tid,
                    (unsigned long long)event_uid,
                (unsigned long long)target_write_id,
                code);
            scheduler_terminate_locked(code);
        }
        if (slot >= 0)
            waiting_status[slot] = target_write_id;
        
        while (1) {
            WriteEvent *we = find_write_in_history(target_write_id);
            if (we) {
                satisfy_load_from_write(buf_out, buf_size, addr, we);
                intptr_t loaded_val = bytes_to_intptr(buf_out, buf_size);
                if (current_graph && node)
                    mark_rf_edge_covered(target_write_id, node->id);
                if (recording_graph) {
                    eg_add_edge_rf(recording_graph, we->graph_node_id, recorded_id);
                    // Update value
                    eg_node_t *rn = eg_find_node_by_id(recording_graph, recorded_id);
                    if (rn) rn->value = loaded_val;
                }
                if (slot >= 0)
                    waiting_status[slot] = 0;
                fprintf(stderr,"[SCHED-DEBUG] Satisfying load from write history. Write NodeID=%llu Val=%ld\n",
                    (unsigned long long)target_write_id, (long)loaded_val);
                pthread_mutex_unlock(&sched_lock);
                return true; // Used simulated value
            }


            // REVISIT this later
            // if (current_graph) {
            //     eg_node_t *wn = eg_find_node_by_id(current_graph, target_write_id);
            //     if (wn) {
            //         intptr_t forced_val = wn->value;
            //         *val_out = forced_val;
            //         if (current_graph && node)
            //             mark_rf_edge_covered(target_write_id, node->id);
            //         if (recording_graph) {
            //             eg_add_edge_rf(recording_graph, target_write_id, recorded_id);
            //             eg_node_t *rn = eg_find_node_by_id(recording_graph, recorded_id);
            //             if (rn)
            //                 rn->value = forced_val;
            //         }
            //         if (slot >= 0)
            //             waiting_status[slot] = 0;
            //         printf("[SCHED-DEBUG] Satisfying load from graph node fallback. Write NodeID=%llu Val=%ld\n",
            //                (unsigned long long)target_write_id, (long)forced_val);
            //         pthread_mutex_unlock(&sched_lock);
            //         return true;
            //     }
            // }
            
            // Check Deadlock
            if (should_exit_deadlock_locked()) {
                const int code = classify_terminal_code_locked();
                fprintf(stderr,
                    "[SCHED] Deadlock under RF/frontier approximation "
                    "(all active threads blocked and no pending waited write is scheduler-producible). exit=%d\n",
                    code);
                for (int i = 0; i < MAX_THREADS; i++) {
                    if (active_status[i] && waiting_status[i] != 0) {
                        fprintf(stderr, "Thread %d waiting for Write Node %llu.\n",
                                i, (unsigned long long)waiting_status[i]);
                    }
                }
                scheduler_terminate_locked(code);
            }
            LOG("[SCHED-DEBUG] Load waiting for write node %llu. Blocking thread slot %d. Active threads=%d, alive threads=%d, blocked unknown threads=%d\n",
                (unsigned long long)target_write_id, slot, active_threads, alive_threads, blocked_unknown_threads);
            pthread_cond_wait(&sched_cond, &sched_lock);
            LOG("[SCHED-DEBUG] Woke up load waiting for write node %llu. Re-checking history. Active threads=%d, alive threads=%d, blocked unknown threads=%d\n",
                (unsigned long long)target_write_id, active_threads, alive_threads, blocked_unknown_threads);
        }
    }
    
    // No RF edge found (or not in graph)
    // Handle MISSING_RANDOM_SAMPLING
    if (config_missing_random_sampling != MRS_STOP) {
        LOG("[SCHED-DEBUG] No RF edge for load node. Applying MRS strategy %d\n", config_missing_random_sampling);
        WriteEvent *we = NULL;
        switch(config_missing_random_sampling) {
            case MRS_LATEST: we = find_latest_overlapping_write(addr, buf_size); break;
            case MRS_LATEST_LOCAL: we = find_latest_local_overlapping_write(addr, buf_size, tid); break;
            case MRS_RANDOM: we = find_random_overlapping_write(addr, buf_size); break;
            default: break;
        }
        
        if (we) {
            satisfy_load_from_write(buf_out, buf_size, addr, we);
            intptr_t loaded_val = bytes_to_intptr(buf_out, buf_size);
            LOG("[WARN] Sampling value %ld from write %llu\n", (long)loaded_val,
                (unsigned long long)we->graph_node_id);
            if (recording_graph) {
                eg_add_edge_rf(recording_graph, we->graph_node_id, recorded_id);
                eg_node_t *rn = eg_find_node_by_id(recording_graph, recorded_id);
                if (rn) rn->value = loaded_val;
            }
            pthread_mutex_unlock(&sched_lock);
            return true;
        }
    }

    // Default: Run normally (MRS_STOP behavior is essentially "don't intervene" if we can't find node,
    // but if a graph is provided and the node has no RF, we stop as configured).
    if (config_missing_random_sampling == MRS_STOP) {
        LOG("[SCHED] No RF edge found for load node TID=%llu UID=%llx IID=%llx. Stopping execution as per MRS_STOP.\n",
            (unsigned long long)tid, (unsigned long long)event_uid, iid);
        if (current_graph) {
            pthread_mutex_unlock(&sched_lock);
            // If we strictly stop:
            exit(0);
            // Or we could block forever, but that would hang the program.
        }
        pthread_mutex_unlock(&sched_lock);
        return false; // Use hardware value
    }

    LOG("[SCHED-DEBUG] No intervention for load node. Proceeding with hardware value.\n");
    
    pthread_mutex_unlock(&sched_lock);
    return false; // Use hardware value
}

bool scheduler_on_load(void *addr, Access_Mode order, intptr_t *val_out,
                      uint64_t event_uid, uint64_t thread_id,
                      uint64_t loc_id) {
    return scheduler_on_load_ex(addr, order, val_out, event_uid, thread_id, loc_id, 0);
}

void scheduler_on_fence_ex(Access_Mode order, uint64_t event_uid,
                          uint64_t thread_id, uint64_t visit_id) {
    (void)order;
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;
    
    pthread_mutex_lock(&sched_lock);

    const int event_slot = thread_slot(tid);
    if (event_slot >= 0)
        ensure_event_thread_active_locked(event_slot);

    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;

    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_FENCE,-1);
            LOG("[SCHED-DEBUG] Unknown fence event encountered (reported tid=%llu uid=%llx). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid);
            block_on_unknown_event_locked(tid, event_uid, "FENCE");
        } else {
            if (node->type != EG_OP_FENCE) {
                 fprintf(stderr, "[SCHED] Error: Fence event mismatch. Expected FENCE, found type %d. tid=%llu uid=%llx iid=%llx\n",
                     node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
               scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            // printf("Executing the FENCE event, tid=%d,iid=%lld,vid=%d\n",tid,iid,vid);
            if(node) update_last_executed_event(tid,iid,vid);
        }
    }

    if (recording_graph) {
        uint64_t new_id = atomic_fetch_add(&global_event_id_counter, 1);
        eg_add_node(recording_graph, new_id, tid, 0, 0, vid, EG_OP_FENCE, "fence", 0);
    }
    
    pthread_mutex_unlock(&sched_lock);
}

void scheduler_on_fence(Access_Mode order, uint64_t event_uid,
                      uint64_t thread_id) {
    scheduler_on_fence_ex(order, event_uid, thread_id, 0);
}

static inline void sched_atomic_read_bytes(const void *addr, void *out,
                                           size_t size, Access_Mode order) {
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in load: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
        }
        return;
    }
    if (!out || size == 0)
        return;
    int gcc_order = __sched_to_gcc_order(order);//required as the functions like __atomic_load_n parse the current order differently
    switch (size) {
        case 1: {
            uint8_t v = __atomic_load_n((const uint8_t *)addr, gcc_order);
            memcpy(out, &v, sizeof(v));
            break;
        }
        case 2: {
            uint16_t v = __atomic_load_n((const uint16_t *)addr, gcc_order);
            memcpy(out, &v, sizeof(v));
            break;
        }
        case 4: {
            uint32_t v = __atomic_load_n((const uint32_t *)addr, gcc_order);
            memcpy(out, &v, sizeof(v));
            break;
        }
        case 8: {
            uint64_t v = __atomic_load_n((const uint64_t *)addr, gcc_order);
            memcpy(out, &v, sizeof(v));
            break;
        }
        default:
            memcpy(out, addr, size);
            break;
    }
}

static inline void sched_atomic_write_bytes(void *addr, const void *in,
                                            size_t size, Access_Mode order) {
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in store: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
        }
        return;
    }
    if (!in || size == 0)
        return;
    int gcc_order = __sched_to_gcc_order(order);//required as the functions like __atomic_store_n parse the current order differently
    switch (size) {
        case 1: {
            uint8_t v;
            memcpy(&v, in, sizeof(v));
            __atomic_store_n((uint8_t *)addr, v, gcc_order);
            break;
        }
        case 2: {
            uint16_t v;
            memcpy(&v, in, sizeof(v));
            __atomic_store_n((uint16_t *)addr, v, gcc_order);
            break;
        }
        case 4: {
            uint32_t v;
            memcpy(&v, in, sizeof(v));
            __atomic_store_n((uint32_t *)addr, v, gcc_order);
            break;
        }
        case 8: {
            uint64_t v;
            memcpy(&v, in, sizeof(v));
            __atomic_store_n((uint64_t *)addr, v, gcc_order);
            break;
        }
        default:
            memcpy(addr, in, size);
            break;
    }
}

uint64_t scheduler_on_rmw_bytes_ex(void *addr, size_t size, uint32_t op, uint64_t value,
                                   Access_Mode order, uint64_t event_uid, uint64_t thread_id,
                                   uint64_t loc_id, uint64_t visit_id, bool *forced_out) {
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;
    
    pthread_mutex_lock(&sched_lock);
    
    const int event_slot = thread_slot(tid);
    if (event_slot >= 0)
        ensure_event_thread_active_locked(event_slot);

    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;
    
    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_RMW,loc_id);
            LOG("[SCHED-DEBUG] Unknown rmw event encountered (reported tid=%llu uid=%llx visit=%llu). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid, (unsigned long long)visit_id);
            block_on_unknown_event_locked(tid, event_uid, "RMW");
        } else {
            if (node->type != EG_OP_RMW && node->type != EG_OP_READ && node->type != EG_OP_WRITE) {
                fprintf(stderr, "[SCHED] Error: RMW event mismatch. Expected RMW/READ/WRITE, found type %d. tid=%llu uid=%llx iid=%llx\n",
                        node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
                scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            // printf("Executing the RMW event, tid=%d,iid=%lld,vid=%d\n",tid,iid,vid);
            update_last_executed_event(tid,iid,vid);
        }
    }
    
    uint64_t target_write_id = (node) ? find_rf_source(node->id) : 0;
    if (current_graph && node && target_write_id == 0) {
        fprintf(stderr,
                "[SCHED] Invalid input: rmw event tid=%llu uid=%llx has no rf_edges source write.\n",
                (unsigned long long)tid,
                (unsigned long long)event_uid);
        scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
    }

    if (forced_out) {
        *forced_out = (target_write_id != 0);
    }

    uint64_t recorded_id = 0;
    if (recording_graph) {
        char loc_buf[64];
        const char *loc_str = lookup_addr_name(addr, loc_buf, sizeof(loc_buf));
        recorded_id = record_event_node_locked(tid, iid, loc_id, vid,
                                               EG_OP_RMW, loc_str, 0);
    }

    uint8_t old_buf[32];
    memset(old_buf, 0, sizeof(old_buf));
    size_t copy_size = size < sizeof(old_buf) ? size : sizeof(old_buf);
    
    WriteEvent *we = NULL;
    if (target_write_id != 0) {
        const int slot = resolve_blocking_slot_locked(tid);
        if (slot >= 0)
            ensure_event_thread_active_locked(slot);
        if (slot < 0) {
            const int code = classify_terminal_code_locked();
            fprintf(stderr,
                "[SCHED] Forced read wait has unmapped runtime thread (reported tid=%llu uid=%llx write=%llu). Exiting with code=%d.\n",
                    (unsigned long long)tid,
                    (unsigned long long)event_uid,
                (unsigned long long)target_write_id,
                code);
            scheduler_terminate_locked(code);
        }
        if (slot >= 0)
            waiting_status[slot] = target_write_id;
        
        while (1) {
            we = find_write_in_history(target_write_id);
            if (we) {
                satisfy_load_from_write(old_buf, copy_size, addr, we);
                if (current_graph && node)
                    mark_rf_edge_covered(target_write_id, node->id);
                if (recording_graph && recorded_id != 0) {
                    eg_add_edge_rf(recording_graph, we->graph_node_id, recorded_id);
                }
                if (slot >= 0)
                    waiting_status[slot] = 0;
                break;
            }
            
            if (should_exit_deadlock_locked()) {
                const int code = classify_terminal_code_locked();
                fprintf(stderr,
                    "[SCHED] Deadlock under RF/frontier approximation "
                    "(all active threads blocked and no pending waited write is scheduler-producible). exit=%d\n",
                    code);
                for (int i = 0; i < MAX_THREADS; i++) {
                    if (active_status[i] && waiting_status[i] != 0) {
                        fprintf(stderr, "Thread %d waiting for Write Node %llu.\n",
                                i, (unsigned long long)waiting_status[i]);
                    }
                }
                scheduler_terminate_locked(code);
            }
            pthread_cond_wait(&sched_cond, &sched_lock);
        }
    } else {
        if (addr && copy_size > 0) {
            sched_atomic_read_bytes(addr, old_buf, copy_size, order);
        }
        if (recording_graph && recorded_id != 0) {
            WriteEvent *latest = find_latest_overlapping_write(addr, copy_size);
            if (!latest)
                latest = find_latest_write_by_loc(loc_id);
            if (latest) {
                eg_add_edge_rf(recording_graph, latest->graph_node_id, recorded_id);
            }
        }
    }

    intptr_t old_val = bytes_to_intptr(old_buf, copy_size);
    intptr_t new_val = old_val;

    switch (op) {
        case 0: new_val = value; break; // Xchg
        case 1: new_val = old_val + value; break; // Add
        case 2: new_val = old_val - value; break; // Sub
        case 3: new_val = old_val & value; break; // And
        case 4: new_val = ~(old_val & value); break; // Nand
        case 5: new_val = old_val | value; break; // Or
        case 6: new_val = old_val ^ value; break; // Xor
        case 7: new_val = (old_val > (intptr_t)value) ? old_val : value; break; // Max
        case 8: new_val = (old_val < (intptr_t)value) ? old_val : value; break; // Min
        case 9: new_val = ((uintptr_t)old_val > (uintptr_t)value) ? old_val : value; break; // UMax
        case 10: new_val = ((uintptr_t)old_val < (uintptr_t)value) ? old_val : value; break; // UMin
        default: break;
    }

    uint8_t new_buf[32];
    memset(new_buf, 0, sizeof(new_buf));
    memcpy(new_buf, &new_val, copy_size < sizeof(new_val) ? copy_size : sizeof(new_val));

    if (recording_graph && recorded_id != 0) {
        eg_node_t *rn = eg_find_node_by_id(recording_graph, recorded_id);
        if (rn) {
            rn->value = new_val;
        }
    }

    uint64_t gn_id = node ? node->id : recorded_id;
    add_history_bytes(addr, new_buf, copy_size, loc_id, tid, iid, vid, gn_id);

    if (addr && copy_size > 0) {
        sched_atomic_write_bytes(addr, new_buf, copy_size, order);
    }

    pthread_cond_broadcast(&sched_cond);
    pthread_mutex_unlock(&sched_lock);

    return (uint64_t)old_val;
}

uint64_t scheduler_on_cmpxchg_bytes_ex(void *addr, size_t size, uint64_t compare_val, uint64_t new_val,
                                       Access_Mode order, uint64_t event_uid, uint64_t thread_id,
                                       uint64_t loc_id, uint64_t visit_id, bool *success_out, bool *forced_out) {
    uint64_t tid = thread_id;
    long long iid = (long long)event_uid;
    int vid = visit_id > 0 ? (int)visit_id : 1;
    
    pthread_mutex_lock(&sched_lock);
    
    const int event_slot = thread_slot(tid);
    if (event_slot >= 0)
        ensure_event_thread_active_locked(event_slot);

    eg_node_t *node = (current_graph) ? eg_find_node_by_dynamic(current_graph, tid, iid, vid) : NULL;
    
    if (current_graph) {
        if (!node) {
            store_the_unknown_event(tid,iid,vid,order,EG_OP_RMW,loc_id);//Fixed the incorrect event type mapping
            LOG("[SCHED-DEBUG] Unknown cmpxchg event encountered (reported tid=%llu uid=%llu visit=%llu). Bypassing scheduler.\n",
                (unsigned long long)tid, (unsigned long long)event_uid, (unsigned long long)visit_id);
            block_on_unknown_event_locked(tid, event_uid, "CMPXCHG");
        } else {
            if (node->type != EG_OP_RMW && node->type != EG_OP_READ && node->type != EG_OP_WRITE) {
                fprintf(stderr, "[SCHED] Error: CmpXchg event mismatch. Expected RMW/READ/WRITE, found type %d. tid=%llu uid=%llx iid=%llx\n",
                        node->type, (unsigned long long)tid, (unsigned long long)event_uid, iid);
                scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
            }
            (void)mark_node_covered(node->id);
            update_last_executed_event(tid,iid,vid);
        }
    }
    
    uint64_t target_write_id = (node) ? find_rf_source(node->id) : 0;
    if (current_graph && node && target_write_id == 0) {
        fprintf(stderr,
                "[SCHED] Invalid input: cmpxchg event tid=%llu uid=%llx has no rf_edges source write.\n",
                (unsigned long long)tid,
                (unsigned long long)event_uid);
        scheduler_terminate_locked(WMM_EXIT_INVALID_INPUT);
    }

    if (forced_out) {
        *forced_out = (target_write_id != 0);
    }

    uint64_t recorded_id = 0;

    uint8_t old_buf[32];
    memset(old_buf, 0, sizeof(old_buf));
    size_t copy_size = size < sizeof(old_buf) ? size : sizeof(old_buf);
    
    WriteEvent *we = NULL;
    if (target_write_id != 0) {
        const int slot = resolve_blocking_slot_locked(tid);
        if (slot >= 0)
            ensure_event_thread_active_locked(slot);
        if (slot < 0) {
            const int code = classify_terminal_code_locked();
            fprintf(stderr,
                "[SCHED] Forced read wait has unmapped runtime thread (reported tid=%llu uid=%llx write=%llu). Exiting with code=%d.\n",
                    (unsigned long long)tid,
                    (unsigned long long)event_uid,
                (unsigned long long)target_write_id,
                code);
            scheduler_terminate_locked(code);
        }
        if (slot >= 0)
            waiting_status[slot] = target_write_id;
        
        while (1) {
            we = find_write_in_history(target_write_id);
            if (we) {
                satisfy_load_from_write(old_buf, copy_size, addr, we);
                if (current_graph && node)
                    mark_rf_edge_covered(target_write_id, node->id);
                if (slot >= 0)
                    waiting_status[slot] = 0;
                break;
            }
            
            if (should_exit_deadlock_locked()) {
                const int code = classify_terminal_code_locked();
                fprintf(stderr,
                    "[SCHED] Deadlock under RF/frontier approximation "
                    "(all active threads blocked and no pending waited write is scheduler-producible). exit=%d\n",
                    code);
                for (int i = 0; i < MAX_THREADS; i++) {
                    if (active_status[i] && waiting_status[i] != 0) {
                        fprintf(stderr, "Thread %d waiting for Write Node %llu.\n",
                                i, (unsigned long long)waiting_status[i]);
                    }
                }
                scheduler_terminate_locked(code);
            }
            pthread_cond_wait(&sched_cond, &sched_lock);
        }
    } else {
        if (addr && copy_size > 0) {
            sched_atomic_read_bytes(addr, old_buf, copy_size, order);
        }
    }

    intptr_t old_val = bytes_to_intptr(old_buf, copy_size);
    bool matched = (old_val == (intptr_t)compare_val);
    *success_out = matched;

    if (recording_graph) {
        char loc_buf[64];
        const char *loc_str = lookup_addr_name(addr, loc_buf, sizeof(loc_buf));
        recorded_id = record_event_node_locked(tid, iid, loc_id, vid,
                                               matched ? EG_OP_RMW : EG_OP_READ,
                                               loc_str, matched ? new_val : old_val);
    }

    if (recording_graph && recorded_id != 0) {
        if (target_write_id != 0 && we) {
            eg_add_edge_rf(recording_graph, we->graph_node_id, recorded_id);
        } else {
            WriteEvent *latest = find_latest_overlapping_write(addr, copy_size);
            if (!latest)
                latest = find_latest_write_by_loc(loc_id);
            if (latest) {
                eg_add_edge_rf(recording_graph, latest->graph_node_id, recorded_id);
            }
        }
    }

    if (matched) {
        uint8_t new_buf[32];
        memset(new_buf, 0, sizeof(new_buf));
        memcpy(new_buf, &new_val, copy_size < sizeof(new_val) ? copy_size : sizeof(new_val));

        uint64_t gn_id = node ? node->id : recorded_id;
        add_history_bytes(addr, new_buf, copy_size, loc_id, tid, iid, vid, gn_id);

        if (addr && copy_size > 0) {
            sched_atomic_write_bytes(addr, new_buf, copy_size, order);
        }
    }

    pthread_cond_broadcast(&sched_cond);
    pthread_mutex_unlock(&sched_lock);

    return (uint64_t)old_val;
}
