#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include "assert.h"
#include "scheduler.h"
//TODO: This path is hardcoded..change it later
#include "/workspaces/EGF/AFL_patches/include/shm_next_events.h"
#include <sys/shm.h>
#include "eg.h"

__attribute__((constructor))
bool attach_shm_next_events() {
    if (g_next_events)
        return true;

    const char *env = getenv(SHM_ENV_NAME);
    if (!env)
        return false;

    int shm_id = atoi(env);

    g_next_events = (struct SHM_next_events*)(shmat(shm_id, NULL, 0));
    if (g_next_events == (void *)-1){
        g_next_events = NULL;   //attach failed
        return false;
    }
    return true;
}


#ifdef QUIET
#define WMM_RT_LOG(...) do {} while (0)
#else
#define WMM_RT_LOG(...) fprintf(stderr, __VA_ARGS__)
#endif

typedef _Bool wmm_bool_t;
typedef Access_Mode wmm_memory_order_t;//changed from memory_order to Access_Mode

typedef struct __wmm_visit_node {
    uint64_t uid;
    uint64_t count;
    struct __wmm_visit_node *next;
} __wmm_visit_node;

typedef struct {
    void *(*start_routine)(void *);
    void *arg;
    uint64_t tid;
} __wmm_thread_wrapper_arg;

#define MAX_THREADS 128

static atomic_ulong __wmm_global_tid_counter = 0;
static atomic_bool __wmm_initialized = false;

int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;
int (*real_pthread_join)(pthread_t, void **) = NULL;
int (*real_pthread_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *) = NULL;
int (*real_pthread_mutex_lock)(pthread_mutex_t *) = NULL;
int (*real_pthread_mutex_unlock)(pthread_mutex_t *) = NULL;
int (*real_pthread_cond_wait)(pthread_cond_t *, pthread_mutex_t *) = NULL;
int (*real_pthread_cond_signal)(pthread_cond_t *) = NULL;
int (*real_pthread_cond_broadcast)(pthread_cond_t *) = NULL;

static __thread __wmm_visit_node *__wmm_tls_visit_head = NULL;
static __thread uint64_t __wmm_tls_fallback_visit_id = 0;
static __thread uint64_t __wmm_tls_thread_id = 0;
static __thread uint64_t __wmm_tls_event_uid = 0;
static __thread uint64_t __wmm_tls_event_thread_id = 0;
static __thread uint64_t __wmm_tls_event_loc_id = 0;
static __thread uint64_t __wmm_tls_event_visit_id = 0;
static __thread bool __wmm_tls_event_ctx_valid = false;

static pthread_t __wmm_os_thread_map[MAX_THREADS];

static void __wmm_free_visit_state(void) {
    __wmm_visit_node *node = __wmm_tls_visit_head;
    while (node) {
        __wmm_visit_node *next = node->next;
        free(node);
        node = next;
    }
    __wmm_tls_visit_head = NULL;
    __wmm_tls_fallback_visit_id = 0;
    __wmm_tls_event_visit_id = 0;
}

static void __wmm_main_thread_atexit_cleanup(void) {
    __wmm_free_visit_state();
}

static inline uint64_t __wmm_next_visit_id(uint64_t uid) {
    for (__wmm_visit_node *node = __wmm_tls_visit_head; node; node = node->next) {
        if (node->uid == uid) {
            node->count += 1;
            return node->count;
        }
    }
    __wmm_visit_node *node = (__wmm_visit_node *)malloc(sizeof(*node));
    if (!node) {
        __wmm_tls_fallback_visit_id += 1;
        return __wmm_tls_fallback_visit_id;
    }
    node->uid = uid;
    node->count = 1;
    node->next = __wmm_tls_visit_head;
    __wmm_tls_visit_head = node;
    return node->count;
}

static inline uint64_t __wmm_current_tid(void) {
    return __wmm_tls_thread_id;
}

static inline void __wmm_set_event_context(uint64_t uid, uint64_t thread_id,
                                           uint64_t loc_id) {
    (void)thread_id;
    __wmm_tls_event_uid = uid;
    __wmm_tls_event_thread_id = __wmm_current_tid();
    __wmm_tls_event_loc_id = loc_id;
    __wmm_tls_event_visit_id = __wmm_next_visit_id(uid);
    __wmm_tls_event_ctx_valid = true;
}

static inline void __wmm_clear_event_context(void) {
    __wmm_tls_event_visit_id = 0;
    __wmm_tls_event_ctx_valid = false;
}

static inline void __wmm_scheduler_on_store(void *addr, intptr_t val,
                                            wmm_memory_order_t order) {
    scheduler_on_store_ex(addr, val, order,
                          __wmm_tls_event_uid,
                          __wmm_tls_event_thread_id,
                          __wmm_tls_event_loc_id,
                          __wmm_tls_event_visit_id);
}

static inline bool __wmm_scheduler_on_load(void *addr, wmm_memory_order_t order,
                                           intptr_t *val_out) {
    return scheduler_on_load_ex(addr, order, val_out,
                                __wmm_tls_event_uid,
                                __wmm_tls_event_thread_id,
                                __wmm_tls_event_loc_id,
                                __wmm_tls_event_visit_id);
}

static inline void __wmm_scheduler_on_fence(wmm_memory_order_t order) {
    scheduler_on_fence_ex(order,
                          __wmm_tls_event_uid,
                          __wmm_tls_event_thread_id,
                          __wmm_tls_event_visit_id);
}

static inline void __wmm_log_event(const char *kind, uint64_t uid, uint64_t thread_id,
                                   uint64_t loc_id, uint32_t order) {
    uint64_t visit_id = __wmm_tls_event_ctx_valid
                            ? __wmm_tls_event_visit_id
                            : __wmm_next_visit_id(uid);
    WMM_RT_LOG(
            "[WMM][visit=%lu][pthread=%lu][thread_id=%lu][uid=%llx][kind=%s][loc=%lu][order=%u]\n",
            (unsigned long)visit_id,
            (unsigned long)pthread_self(),
            (unsigned long)thread_id,
            (unsigned long)uid,
            kind,
            (unsigned long)loc_id,
            (unsigned int)order);
}

static inline void __wmm_log_runtime(const char *kind, const void *addr,
                                     int64_t value, uint32_t order,
                                     const char *file, int line) {
    (void)value;
    (void)file;
    (void)line;
    uint64_t uid = __wmm_tls_event_ctx_valid ? __wmm_tls_event_uid : 0;
    uint64_t tid = __wmm_tls_event_ctx_valid ? __wmm_tls_event_thread_id : __wmm_current_tid();
    uint64_t loc = __wmm_tls_event_ctx_valid ? __wmm_tls_event_loc_id : (uint64_t)(uintptr_t)addr;
    __wmm_log_event(kind, uid, tid, loc, order);
    WMM_RT_LOG("[WMM][value=%ld][addr=%p][file=%s][line=%d]\n", (long)value, addr, file, line);
}

//Map the index to Access_Mode
static inline Access_Mode __wmm_order_from_index(int index) {
    switch (index) {
        case 0: return RELAXED;
        case 1: return ACQUIRE; // Mapping memory_order_consume to ACQUIRE
        case 2: return ACQUIRE;
        case 3: return RELEASE;
        case 4: return ACQ_REL;
        case 5: return SC;
        default: return SC;
    }
}

// Convert Access_Mode back to standard GCC __ATOMIC constants for intrinsic calls
static inline int __wmm_to_gcc_order(Access_Mode mode) {
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

static inline size_t __wmm_u64_to_size(uint64_t n) {
    if (n > (uint64_t)SIZE_MAX)
        return SIZE_MAX;
    return (size_t)n;
}

static inline intptr_t __wmm_bytes_to_intptr(const void *bytes, size_t size) {
    intptr_t out = 0;
    if (!bytes || size == 0)
        return 0;
    const size_t n = size < sizeof(out) ? size : sizeof(out);
    memcpy(&out, bytes, n);
    return out;
}

static inline void __wmm_atomic_read_bytes(const void *addr, void *out,
                                           size_t size, wmm_memory_order_t order) {
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in load: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        return;
    }
    if (!out || size == 0)
        return;
        
    int gcc_order = __wmm_to_gcc_order(order);//required as the functions like __atomic_load_n parse the current order differently
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

static inline void __wmm_atomic_write_bytes(void *addr, const void *in,
                                            size_t size, wmm_memory_order_t order) {
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in store: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
        return;
    }
    if (!in || size == 0)
        return;
        
    int gcc_order = __wmm_to_gcc_order(order);//required as the functions like __atomic_store_n parse the current order differently
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

static void __wmm_init_internal(void) {
    bool expected = false;
    if (atomic_compare_exchange_strong(&__wmm_initialized, &expected, true)) {
        real_pthread_create = (int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *))dlsym(RTLD_NEXT, "pthread_create");
        real_pthread_join = (int (*)(pthread_t, void **))dlsym(RTLD_NEXT, "pthread_join");
        real_pthread_mutex_init = (int (*)(pthread_mutex_t *, const pthread_mutexattr_t *))dlsym(RTLD_NEXT, "pthread_mutex_init");
        real_pthread_mutex_lock = (int (*)(pthread_mutex_t *))dlsym(RTLD_NEXT, "pthread_mutex_lock");
        real_pthread_mutex_unlock = (int (*)(pthread_mutex_t *))dlsym(RTLD_NEXT, "pthread_mutex_unlock");
        real_pthread_cond_wait = (int (*)(pthread_cond_t *, pthread_mutex_t *))dlsym(RTLD_NEXT, "pthread_cond_wait");
        real_pthread_cond_signal = (int (*)(pthread_cond_t *))dlsym(RTLD_NEXT, "pthread_cond_signal");
        real_pthread_cond_broadcast = (int (*)(pthread_cond_t *))dlsym(RTLD_NEXT, "pthread_cond_broadcast");

        scheduler_init();
        atexit(__wmm_main_thread_atexit_cleanup);
        __wmm_tls_thread_id = 0;
        scheduler_thread_registered(0);
        WMM_RT_LOG("[WMM][runtime][kind=INIT][thread_id=0]\n");
    }
}

void wmm_init(void) {
    __wmm_init_internal();
}

void wmm_register_location(const char *name, void *addr) {
    __wmm_init_internal();
    scheduler_register_location(name, addr);
    WMM_RT_LOG(
            "[WMM][runtime][kind=REGISTER_LOCATION][thread_id=%lu][name=%s][addr=%p]\n",
            (unsigned long)__wmm_current_tid(),
            name ? name : "<unknown>",
            addr);
}

void wmm_thread_start(int tid) {
    __wmm_init_internal();
    __wmm_tls_thread_id = (uint64_t)tid;
    scheduler_thread_registered((uint64_t)tid);
    WMM_RT_LOG("[WMM][runtime][kind=THREAD_START][thread_id=%d]\n", tid);
}

void wmm_thread_end(void) {
    __wmm_init_internal();
    scheduler_thread_unregistered(__wmm_current_tid());
    __wmm_free_visit_state();
    WMM_RT_LOG("[WMM][runtime][kind=THREAD_END][thread_id=%lu]\n",
            (unsigned long)__wmm_current_tid());
}

void wmm_func_entry(const char *name) {
    __wmm_init_internal();
    WMM_RT_LOG(
            "[WMM][runtime][kind=FUNC_ENTRY][thread_id=%lu][name=%s]\n",
            (unsigned long)__wmm_current_tid(),
            name ? name : "<unknown>");
}

void wmm_func_exit(const char *name) {
    __wmm_init_internal();
    WMM_RT_LOG(
            "[WMM][runtime][kind=FUNC_EXIT][thread_id=%lu][name=%s]\n",
            (unsigned long)__wmm_current_tid(),
            name ? name : "<unknown>");
}

static void *__wmm_thread_wrapper(void *arg) {
    __wmm_thread_wrapper_arg *wrapper_arg = (__wmm_thread_wrapper_arg *)arg;
    wmm_thread_start((int)wrapper_arg->tid);
    void *ret = wrapper_arg->start_routine(wrapper_arg->arg);
    wmm_thread_end();
    free(wrapper_arg);
    return ret;
}

int wmm_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                       void *(*start_routine)(void *), void *arg) {
    __wmm_init_internal();
    __wmm_thread_wrapper_arg *wrapper_arg =
        (__wmm_thread_wrapper_arg *)malloc(sizeof(*wrapper_arg));
    if (!wrapper_arg)
        return -1;
    wrapper_arg->start_routine = start_routine;
    wrapper_arg->arg = arg;
    wrapper_arg->tid = atomic_fetch_add(&__wmm_global_tid_counter, 1) + 1;
    // moved the scheduler_thread_created to acknowledge before thread creation as the thread was being created and trying to execute the first statement before thread is registered.(very rare)
    scheduler_thread_created(wrapper_arg->tid,(unsigned long)__wmm_current_tid());
    int ret = real_pthread_create(thread, attr, __wmm_thread_wrapper, wrapper_arg);
    if (ret == 0) {
        if(wrapper_arg->tid<MAX_THREADS) __wmm_os_thread_map[wrapper_arg->tid] = *thread;
        WMM_RT_LOG(
                "[WMM][runtime][kind=PTHREAD_CREATE][creator_tid=%lu][new_tid=%lu]\n",
                (unsigned long)__wmm_current_tid(),
                (unsigned long)wrapper_arg->tid);
        return 0;
    }
    //Unregister thread incase of thread creation failure
    scheduler_thread_unregistered(__wmm_current_tid());
    free(wrapper_arg);
    return ret;
}

int wmm_pthread_join(pthread_t thread, void **retval) {
    __wmm_init_internal();
    WMM_RT_LOG("[WMM][runtime][kind=PTHREAD_JOIN][thread_id=%lu]\n",
            (unsigned long)__wmm_current_tid());
    int child_tid = -1;
    int retries = 0;
    while (child_tid == -1 && retries < 1000) {
        for (int i = 0; i < MAX_THREADS; i++) {
            if (__wmm_os_thread_map[i] == thread) {
                child_tid = i;
                break;
            }
        }
        if (child_tid == -1) {
            sched_yield();
            retries++;
        }
    }
    if (child_tid == -1) {
        printf(stderr, "[WMM-CRITICAL] pthread_join called on unmapped thread! Trace will be corrupted.\n");
    }
    scheduler_thread_join_wait_begin((int)__wmm_current_tid());
    int ret = real_pthread_join(thread, retval);
    scheduler_thread_join_wait_end((int)__wmm_current_tid(),child_tid);
    if (ret == 0 && child_tid >= 0 && child_tid < MAX_THREADS) {
        __wmm_os_thread_map[child_tid] = 0; 
    }
    return ret;
}

int wmm_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    __wmm_init_internal();
    WMM_RT_LOG("[WMM][runtime][kind=MUTEX_INIT][thread_id=%lu][addr=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)mutex);
    return real_pthread_mutex_init(mutex, attr);
}

int wmm_pthread_mutex_lock(pthread_mutex_t *mutex) {
    __wmm_init_internal();
    WMM_RT_LOG("[WMM][runtime][kind=MUTEX_LOCK][thread_id=%lu][addr=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)mutex);
    return real_pthread_mutex_lock(mutex);
}

int wmm_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    __wmm_init_internal();
    WMM_RT_LOG("[WMM][runtime][kind=MUTEX_UNLOCK][thread_id=%lu][addr=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)mutex);
    return real_pthread_mutex_unlock(mutex);
}

int wmm_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    __wmm_init_internal();
    WMM_RT_LOG(
            "[WMM][runtime][kind=COND_WAIT][thread_id=%lu][cond=%p][mutex=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)cond, (void *)mutex);
    return real_pthread_cond_wait(cond, mutex);
}

int wmm_pthread_cond_signal(pthread_cond_t *cond) {
    __wmm_init_internal();
    WMM_RT_LOG("[WMM][runtime][kind=COND_SIGNAL][thread_id=%lu][cond=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)cond);
    return real_pthread_cond_signal(cond);
}

int wmm_pthread_cond_broadcast(pthread_cond_t *cond) {
    __wmm_init_internal();
    WMM_RT_LOG(
            "[WMM][runtime][kind=COND_BROADCAST][thread_id=%lu][cond=%p]\n",
            (unsigned long)__wmm_current_tid(), (void *)cond);
    return real_pthread_cond_broadcast(cond);
}

intptr_t wmm_load(volatile void *obj, wmm_memory_order_t order, const char *file, int line) {
    __wmm_init_internal();
    intptr_t val;
    if (__wmm_scheduler_on_load((void *)obj, order, &val)) {
        __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
        return val;
    }
    if (obj) {
        val = (intptr_t)__atomic_load_n((volatile intptr_t *)obj, __wmm_to_gcc_order(order));
    } else {
        val = 0;
    }
    __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return val;
}

void wmm_store(volatile void *obj, intptr_t val, wmm_memory_order_t order,
               const char *file, int line) {
    __wmm_init_internal();
    __wmm_scheduler_on_store((void *)obj, val, order);
    if (obj) {
        __atomic_store_n((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    }
    __wmm_log_runtime("STORE", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
}

wmm_bool_t wmm_compare_exchange_strong(volatile void *obj, intptr_t *expected,
                                       intptr_t desired, wmm_memory_order_t succ,
                                       wmm_memory_order_t fail,
                                       const char *file, int line) {
    __wmm_init_internal();
    wmm_bool_t ret = __atomic_compare_exchange_n((volatile intptr_t *)obj, expected,
                                                 desired, 0, __wmm_to_gcc_order(succ), __wmm_to_gcc_order(fail));//required as the functions like __atomic_compare_exchange_n parse the current order differently
    if (ret)
        __wmm_scheduler_on_store((void *)obj, desired, succ);
    __wmm_log_runtime("CMPXCHG", (const void *)obj, (int64_t)desired,
                      (uint32_t)succ, file, line);
    return ret;
}

wmm_bool_t wmm_compare_exchange_weak(volatile void *obj, intptr_t *expected,
                                     intptr_t desired, wmm_memory_order_t succ,
                                     wmm_memory_order_t fail,
                                     const char *file, int line) {
    __wmm_init_internal();
    wmm_bool_t ret = __atomic_compare_exchange_n((volatile intptr_t *)obj, expected,
                                                 desired, 1, __wmm_to_gcc_order(succ), __wmm_to_gcc_order(fail));
    if (ret)
        __wmm_scheduler_on_store((void *)obj, desired, succ);
    __wmm_log_runtime("CMPXCHG", (const void *)obj, (int64_t)desired,
                      (uint32_t)succ, file, line);
    return ret;
}

intptr_t wmm_exchange(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                      const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_exchange_n((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

#define WMM_DEFINE_FETCH_OP(NAME, EXPR) \
intptr_t NAME(volatile void *obj, intptr_t val, wmm_memory_order_t order, \
              const char *file, int line) { \
    __wmm_init_internal(); \
    intptr_t ret = EXPR; \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)(ret op_val), order); \
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line); \
    return ret; \
}

intptr_t wmm_fetch_add(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                       const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_fetch_add((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, ret + val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

intptr_t wmm_fetch_sub(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                       const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_fetch_sub((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, ret - val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

intptr_t wmm_fetch_or(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                      const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_fetch_or((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, ret | val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

intptr_t wmm_fetch_xor(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                       const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_fetch_xor((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, ret ^ val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

intptr_t wmm_fetch_and(volatile void *obj, intptr_t val, wmm_memory_order_t order,
                       const char *file, int line) {
    __wmm_init_internal();
    intptr_t ret = __atomic_fetch_and((volatile intptr_t *)obj, val, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, ret & val, order);
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)order, file, line);
    return ret;
}

wmm_bool_t wmm_atomic_flag_test_and_set(volatile void *obj, wmm_memory_order_t order,
                                        const char *file, int line) {
    __wmm_init_internal();
    wmm_bool_t ret = __atomic_test_and_set((volatile void *)obj, __wmm_to_gcc_order(order));
    __wmm_scheduler_on_store((void *)obj, 1, order);
    __wmm_log_runtime("RMW", (const void *)obj, 1, (uint32_t)order, file, line);
    return ret;
}

void wmm_atomic_flag_clear(volatile void *obj, wmm_memory_order_t order,
                           const char *file, int line) {
    __wmm_init_internal();
    __wmm_scheduler_on_store((void *)obj, 0, order);
    __atomic_clear((volatile void *)obj, __wmm_to_gcc_order(order));
    __wmm_log_runtime("STORE", (const void *)obj, 0, (uint32_t)order, file, line);
}

void wmm_thread_fence(wmm_memory_order_t order, const char *file, int line) {
    __wmm_init_internal();
    __wmm_scheduler_on_fence(order);
    __atomic_thread_fence(__wmm_to_gcc_order(order));
    __wmm_log_runtime("FENCE", NULL, 0, (uint32_t)order, file, line);
}

#define WMM_DEFINE_PLAIN_LOAD(BITS, TYPE) \
TYPE wmm_plain_load##BITS(const TYPE *obj, const char *pos) { \
    __wmm_init_internal(); \
    intptr_t simulated; \
    if (__wmm_scheduler_on_load((void *)obj, NON_ATOMIC, &simulated)) { \
        __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)simulated, \
                          (uint32_t)NON_ATOMIC, pos, 0); \
        return (TYPE)simulated; \
    } \
    TYPE ret = __atomic_load_n(obj, __ATOMIC_RELAXED); \
    __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)ret, \
                      (uint32_t)NON_ATOMIC, pos, 0); \
    return ret; \
}

#define WMM_DEFINE_PLAIN_STORE(BITS, TYPE) \
void wmm_plain_store##BITS(TYPE *obj, TYPE val, const char *pos) { \
    __wmm_init_internal(); \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)val, NON_ATOMIC); \
    __atomic_store_n(obj, val, __ATOMIC_RELAXED); \
    __wmm_log_runtime("STORE", (const void *)obj, (int64_t)val, \
                      (uint32_t)NON_ATOMIC, pos, 0); \
}

#define WMM_DEFINE_VOLATILE_LOAD(BITS, TYPE) \
TYPE wmm_volatile_load##BITS(const volatile TYPE *obj, const char *pos) { \
    __wmm_init_internal(); \
    intptr_t simulated; \
    if (__wmm_scheduler_on_load((void *)obj, NON_ATOMIC, &simulated)) { \
        __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)simulated, \
                          (uint32_t)NON_ATOMIC, pos, 0); \
        return (TYPE)simulated; \
    } \
    TYPE ret = *(const volatile TYPE *)obj; \
    __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)ret, \
                      (uint32_t)NON_ATOMIC, pos, 0); \
    return ret; \
}

#define WMM_DEFINE_VOLATILE_STORE(BITS, TYPE) \
void wmm_volatile_store##BITS(volatile TYPE *obj, TYPE val, const char *pos) { \
    __wmm_init_internal(); \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)val, NON_ATOMIC); \
    *(volatile TYPE *)obj = val; \
    __wmm_log_runtime("STORE", (const void *)obj, (int64_t)val, \
                      (uint32_t)NON_ATOMIC, pos, 0); \
}

WMM_DEFINE_PLAIN_LOAD(8, uint8_t)
WMM_DEFINE_PLAIN_LOAD(16, uint16_t)
WMM_DEFINE_PLAIN_LOAD(32, uint32_t)
WMM_DEFINE_PLAIN_LOAD(64, uint64_t)
WMM_DEFINE_PLAIN_STORE(8, uint8_t)
WMM_DEFINE_PLAIN_STORE(16, uint16_t)
WMM_DEFINE_PLAIN_STORE(32, uint32_t)
WMM_DEFINE_PLAIN_STORE(64, uint64_t)
WMM_DEFINE_VOLATILE_LOAD(8, uint8_t)
WMM_DEFINE_VOLATILE_LOAD(16, uint16_t)
WMM_DEFINE_VOLATILE_LOAD(32, uint32_t)
WMM_DEFINE_VOLATILE_LOAD(64, uint64_t)
WMM_DEFINE_VOLATILE_STORE(8, uint8_t)
WMM_DEFINE_VOLATILE_STORE(16, uint16_t)
WMM_DEFINE_VOLATILE_STORE(32, uint32_t)
WMM_DEFINE_VOLATILE_STORE(64, uint64_t)

void wmm_atomic_init8(uint8_t *obj, uint8_t val, const char *pos) { wmm_plain_store8(obj, val, pos); }
void wmm_atomic_init16(uint16_t *obj, uint16_t val, const char *pos) { wmm_plain_store16(obj, val, pos); }
void wmm_atomic_init32(uint32_t *obj, uint32_t val, const char *pos) { wmm_plain_store32(obj, val, pos); }
void wmm_atomic_init64(uint64_t *obj, uint64_t val, const char *pos) { wmm_plain_store64(obj, val, pos); }

#define WMM_DEFINE_ATOMIC_LOAD(BITS, TYPE) \
TYPE wmm_atomic_load##BITS(const TYPE *obj, int order, const char *pos) { \
    __wmm_init_internal(); \
    Access_Mode mo = __wmm_order_from_index(order); \
    intptr_t simulated; \
    if (__wmm_scheduler_on_load((void *)obj, mo, &simulated)) { \
        __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)simulated, (uint32_t)mo, pos, 0); \
        return (TYPE)simulated; \
    } \
    TYPE ret = __atomic_load_n(obj, __wmm_to_gcc_order(mo)); \
    __wmm_log_runtime("LOAD", (const void *)obj, (int64_t)ret, (uint32_t)mo, pos, 0); \
    return ret; \
}

#define WMM_DEFINE_ATOMIC_STORE(BITS, TYPE) \
void wmm_atomic_store##BITS(TYPE *obj, TYPE val, int order, const char *pos) { \
    __wmm_init_internal(); \
    Access_Mode mo = __wmm_order_from_index(order); \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)val, mo); \
    __atomic_store_n(obj, val, __wmm_to_gcc_order(mo)); \
    __wmm_log_runtime("STORE", (const void *)obj, (int64_t)val, (uint32_t)mo, pos, 0); \
}

#define WMM_DEFINE_ATOMIC_EXCHANGE(BITS, TYPE) \
TYPE wmm_atomic_exchange##BITS(TYPE *obj, TYPE val, int order, const char *pos) { \
    __wmm_init_internal(); \
    Access_Mode mo = __wmm_order_from_index(order); \
    TYPE ret = __atomic_exchange_n(obj, val, __wmm_to_gcc_order(mo)); \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)val, mo); \
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)mo, pos, 0); \
    return ret; \
}

#define WMM_DEFINE_ATOMIC_FETCH(NAME, BITS, TYPE, EXPR_NEW) \
TYPE wmm_atomic_fetch_##NAME##BITS(TYPE *obj, TYPE val, int order, const char *pos) { \
    __wmm_init_internal(); \
    Access_Mode mo = __wmm_order_from_index(order); \
    TYPE ret = __atomic_fetch_##NAME(obj, val, __wmm_to_gcc_order(mo)); \
    __wmm_scheduler_on_store((void *)obj, (intptr_t)(EXPR_NEW), mo); \
    __wmm_log_runtime("RMW", (const void *)obj, (int64_t)val, (uint32_t)mo, pos, 0); \
    return ret; \
}

#define WMM_DEFINE_CAS_V1(BITS, TYPE) \
TYPE wmm_atomic_compare_exchange##BITS##_v1(TYPE *obj, TYPE expected, TYPE desired, \
                                            int succ, int fail, const char *pos) { \
    __wmm_init_internal(); \
    TYPE exp = expected; \
    Access_Mode mo_succ = __wmm_order_from_index(succ); \
    Access_Mode mo_fail = __wmm_order_from_index(fail); \
    __atomic_compare_exchange_n(obj, &exp, desired, 0, __wmm_to_gcc_order(mo_succ), __wmm_to_gcc_order(mo_fail)); \
    if (exp == expected) \
        __wmm_scheduler_on_store((void *)obj, (intptr_t)desired, mo_succ); \
    __wmm_log_runtime("CMPXCHG", (const void *)obj, (int64_t)desired, (uint32_t)mo_succ, pos, 0); \
    return exp; \
}

#define WMM_DEFINE_CAS_V2(BITS, TYPE) \
wmm_bool_t wmm_atomic_compare_exchange##BITS##_v2(TYPE *obj, TYPE *expected, TYPE desired, \
                                                  int succ, int fail, const char *pos) { \
    __wmm_init_internal(); \
    Access_Mode mo_succ = __wmm_order_from_index(succ); \
    Access_Mode mo_fail = __wmm_order_from_index(fail); \
    wmm_bool_t ret = __atomic_compare_exchange_n(obj, expected, desired, 0, __wmm_to_gcc_order(mo_succ), __wmm_to_gcc_order(mo_fail)); \
    if (ret) \
        __wmm_scheduler_on_store((void *)obj, (intptr_t)desired, mo_succ); \
    __wmm_log_runtime("CMPXCHG", (const void *)obj, (int64_t)desired, (uint32_t)mo_succ, pos, 0); \
    return ret; \
}

WMM_DEFINE_ATOMIC_LOAD(8, uint8_t)
WMM_DEFINE_ATOMIC_LOAD(16, uint16_t)
WMM_DEFINE_ATOMIC_LOAD(32, uint32_t)
WMM_DEFINE_ATOMIC_LOAD(64, uint64_t)
WMM_DEFINE_ATOMIC_STORE(8, uint8_t)
WMM_DEFINE_ATOMIC_STORE(16, uint16_t)
WMM_DEFINE_ATOMIC_STORE(32, uint32_t)
WMM_DEFINE_ATOMIC_STORE(64, uint64_t)
WMM_DEFINE_ATOMIC_EXCHANGE(8, uint8_t)
WMM_DEFINE_ATOMIC_EXCHANGE(16, uint16_t)
WMM_DEFINE_ATOMIC_EXCHANGE(32, uint32_t)
WMM_DEFINE_ATOMIC_EXCHANGE(64, uint64_t)
WMM_DEFINE_ATOMIC_FETCH(add, 8, uint8_t, ret + val)
WMM_DEFINE_ATOMIC_FETCH(add, 16, uint16_t, ret + val)
WMM_DEFINE_ATOMIC_FETCH(add, 32, uint32_t, ret + val)
WMM_DEFINE_ATOMIC_FETCH(add, 64, uint64_t, ret + val)
WMM_DEFINE_ATOMIC_FETCH(sub, 8, uint8_t, ret - val)
WMM_DEFINE_ATOMIC_FETCH(sub, 16, uint16_t, ret - val)
WMM_DEFINE_ATOMIC_FETCH(sub, 32, uint32_t, ret - val)
WMM_DEFINE_ATOMIC_FETCH(sub, 64, uint64_t, ret - val)
WMM_DEFINE_ATOMIC_FETCH(and, 8, uint8_t, ret & val)
WMM_DEFINE_ATOMIC_FETCH(and, 16, uint16_t, ret & val)
WMM_DEFINE_ATOMIC_FETCH(and, 32, uint32_t, ret & val)
WMM_DEFINE_ATOMIC_FETCH(and, 64, uint64_t, ret & val)
WMM_DEFINE_ATOMIC_FETCH(or, 8, uint8_t, ret | val)
WMM_DEFINE_ATOMIC_FETCH(or, 16, uint16_t, ret | val)
WMM_DEFINE_ATOMIC_FETCH(or, 32, uint32_t, ret | val)
WMM_DEFINE_ATOMIC_FETCH(or, 64, uint64_t, ret | val)
WMM_DEFINE_ATOMIC_FETCH(xor, 8, uint8_t, ret ^ val)
WMM_DEFINE_ATOMIC_FETCH(xor, 16, uint16_t, ret ^ val)
WMM_DEFINE_ATOMIC_FETCH(xor, 32, uint32_t, ret ^ val)
WMM_DEFINE_ATOMIC_FETCH(xor, 64, uint64_t, ret ^ val)
WMM_DEFINE_CAS_V1(8, uint8_t)
WMM_DEFINE_CAS_V1(16, uint16_t)
WMM_DEFINE_CAS_V1(32, uint32_t)
WMM_DEFINE_CAS_V1(64, uint64_t)
WMM_DEFINE_CAS_V2(8, uint8_t)
WMM_DEFINE_CAS_V2(16, uint16_t)
WMM_DEFINE_CAS_V2(32, uint32_t)
WMM_DEFINE_CAS_V2(64, uint64_t)

void wmm_atomic_thread_fence(int order, const char *pos) {
    __wmm_init_internal();
    Access_Mode mo = __wmm_order_from_index(order);
    __wmm_scheduler_on_fence(mo);
    __atomic_thread_fence(__wmm_to_gcc_order(mo));
    __wmm_log_runtime("FENCE", NULL, 0, (uint32_t)mo, pos, 0);
}

uint64_t __attribute__((weak)) __instrument_load(uint64_t uid, void *addr, uint32_t order,
                                                 uint64_t thread_id, uint64_t loc_id,
                                                 uint64_t value_size) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, loc_id);
    size_t size = __wmm_u64_to_size(value_size);
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in load: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
    }
    if (!addr)
        size = 0;
    uint8_t inline_buf[32];
    uint8_t *buf = inline_buf;
    if (size > sizeof(inline_buf)) {
        buf = (uint8_t *)malloc(size);
        if (!buf) {
            __wmm_clear_event_context();
            return 0;
        }
    }

    Access_Mode am_order = __wmm_order_from_index(order);
    const bool forced = scheduler_on_load_bytes_ex((void *)addr,
                                                    am_order,
                                                    buf,
                                                    size,
                                                    __wmm_tls_event_uid,
                                                    __wmm_tls_event_thread_id,
                                                    __wmm_tls_event_loc_id,
                                                    __wmm_tls_event_visit_id);
    if (forced && addr)
        __wmm_atomic_write_bytes(addr, buf, size, am_order);
    if (!forced && addr)
        __wmm_atomic_read_bytes(addr, buf, size, am_order);

    const intptr_t observed_val = __wmm_bytes_to_intptr(buf, size);
    __wmm_log_runtime("LOAD", (const void *)addr,
                      (int64_t)observed_val,
                      order,
                      "<instrument>", 0);

    if (buf != inline_buf)
        free(buf);
    __wmm_clear_event_context();
    return (uint64_t)observed_val;
}

void *__attribute__((weak)) __instrument_store(uint64_t uid, void *addr, uint64_t value,
                                               uint32_t order, uint64_t thread_id,
                                               uint64_t loc_id, uint64_t value_size) {
    __wmm_init_internal();
    uint64_t actual_thread_id = thread_id;
    bool is_global_init = false;
    if (thread_id == (uint64_t)-1) {
        is_global_init = true;
        actual_thread_id = 0;
    }
    __wmm_set_event_context(uid, actual_thread_id, loc_id);

    size_t size = __wmm_u64_to_size(value_size);
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in store: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
    }
    if (!addr)
        size = 0;
    uint8_t inline_buf[32];
    uint8_t *buf = inline_buf;
    if (size > sizeof(inline_buf)) {
        buf = (uint8_t *)malloc(size);
        if (!buf) {
            __wmm_clear_event_context();
            return NULL;
        }
    }

    if (is_global_init && addr) {
        memcpy(buf, addr, size);
    } else {
        memcpy(buf, &value, size < sizeof(value) ? size : sizeof(value));
        if (size > sizeof(value)) {
            memset(buf + sizeof(value), 0, size - sizeof(value));
        }
    }

    Access_Mode am_order = __wmm_order_from_index(order);
    scheduler_on_store_bytes_ex((void *)addr,
                                buf,
                                size,
                                am_order,
                                __wmm_tls_event_uid,
                                __wmm_tls_event_thread_id,
                                __wmm_tls_event_loc_id,
                                __wmm_tls_event_visit_id);

    if (addr && size > 0)
        __wmm_atomic_write_bytes(addr, buf, size, am_order);

    __wmm_log_runtime("STORE", (const void *)addr,
                      (int64_t)__wmm_bytes_to_intptr(buf, size),
                      order,
                      "<instrument>", 0);

    if (buf != inline_buf)
        free(buf);
    __wmm_clear_event_context();
    return NULL;
}

uint64_t __attribute__((weak)) __instrument_rmw(uint64_t uid, void *addr, uint32_t op,
                                                uint64_t value, uint32_t order,
                                                uint64_t thread_id, uint64_t loc_id,
                                                uint64_t value_size) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, loc_id);

    size_t size = __wmm_u64_to_size(value_size);
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in rmw: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
    }
    if (!addr)
        size = 0;

    bool forced = false;
    uint64_t old_val = scheduler_on_rmw_bytes_ex(addr, size, op, value,
                                                 __wmm_order_from_index(order),
                                                 uid, __wmm_tls_event_thread_id, loc_id,
                                                 __wmm_tls_event_visit_id, &forced);

    __wmm_log_runtime("RMW", (const void *)addr,
                      (int64_t)old_val,
                      order,
                      "<instrument>", 0);

    if (forced) {
        WMM_RT_LOG("[WMM][runtime][kind=RMW_LOAD_FORCED][uid=%llx][thread_id=%lu][loc=%lu]\n",
                   (unsigned long)uid,
                   (unsigned long)__wmm_tls_event_thread_id,
                   (unsigned long)loc_id);
    }

    __wmm_clear_event_context();
    return old_val;
}

uint64_t __attribute__((weak)) __instrument_cmpxchg(uint64_t uid, void *addr, uint64_t compare_val,
                                                    uint64_t new_val, uint32_t order,
                                                    uint64_t thread_id, uint64_t loc_id,
                                                    uint64_t value_size) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, loc_id);

    size_t size = __wmm_u64_to_size(value_size);
    if ((uintptr_t)addr < 4096) {
        if (size > 0) {
            fprintf(stderr, "[WMM] Error: Null/invalid pointer dereference detected in cmpxchg: addr=%p, size=%zu\n", addr, size);
            scheduler_terminate(WMM_EXIT_INVALID_INPUT);
        }
    }
    if (!addr)
        size = 0;

    bool success = false;
    bool forced = false;
    uint64_t old_val = scheduler_on_cmpxchg_bytes_ex(addr, size, compare_val, new_val,
                                                     __wmm_order_from_index(order),
                                                     uid, __wmm_tls_event_thread_id, loc_id,
                                                     __wmm_tls_event_visit_id, &success, &forced);

    if (success) {
        __wmm_log_runtime("CMPXCHG_STORE", (const void *)addr,
                          (int64_t)new_val,
                          order,
                          "<instrument>", 0);
    } else {
        __wmm_log_runtime("CMPXCHG_FAIL", (const void *)addr,
                          (int64_t)old_val,
                          order,
                          "<instrument>", 0);
    }

    if (forced) {
        WMM_RT_LOG("[WMM][runtime][kind=RMW_LOAD_FORCED][uid=%llx][thread_id=%lu][loc=%lu]\n",
                   (unsigned long)uid,
                   (unsigned long)__wmm_tls_event_thread_id,
                   (unsigned long)loc_id);
    }

    __wmm_clear_event_context();
    return old_val;
}

void __attribute__((weak)) __instrument_fence(uint64_t uid, uint32_t order,
                                              uint64_t thread_id) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, 0);

    wmm_thread_fence(__wmm_order_from_index(order),
                     "<instrument>", 0);
    __wmm_clear_event_context();
}

void __attribute__((weak)) __instrument_sop(uint64_t uid, uint64_t thread_id) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, 0);
    __wmm_log_runtime("SOP", NULL, 0, 0, "<instrument>", 0);
    __wmm_clear_event_context();

    wmm_func_entry("<instrument_sop>");
}

void __attribute__((weak)) __instrument_eop(uint64_t uid, uint64_t thread_id) {
    __wmm_init_internal();
    __wmm_set_event_context(uid, thread_id, 0);
    __wmm_log_runtime("EOP", NULL, 0, 0, "<instrument>", 0);
    __wmm_clear_event_context();

    wmm_func_exit("<instrument_eop>");
}

__attribute__((visibility("default")))
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    return wmm_pthread_create(thread, attr, start_routine, arg);
}

__attribute__((visibility("default")))
int pthread_join(pthread_t thread, void **retval) {
    return wmm_pthread_join(thread, retval);
}

__attribute__((visibility("default")))
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    return wmm_pthread_mutex_init(mutex, attr);
}

__attribute__((visibility("default")))
int pthread_mutex_lock(pthread_mutex_t *mutex) {
    return wmm_pthread_mutex_lock(mutex);
}

__attribute__((visibility("default")))
int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    return wmm_pthread_mutex_unlock(mutex);
}

__attribute__((visibility("default")))
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    return wmm_pthread_cond_wait(cond, mutex);
}

__attribute__((visibility("default")))
int pthread_cond_signal(pthread_cond_t *cond) {
    return wmm_pthread_cond_signal(cond);
}

__attribute__((visibility("default")))
int pthread_cond_broadcast(pthread_cond_t *cond) {
    return wmm_pthread_cond_broadcast(cond);
}
