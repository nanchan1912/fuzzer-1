#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include "./assert.h"
#include "./wmm.h"
#include "./scheduler.h"

// Undefine macros to avoid recursion/conflict in implementation
#undef pthread_create
#undef pthread_join
#undef pthread_mutex_init
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#undef pthread_cond_wait
#undef pthread_cond_signal
#undef pthread_cond_broadcast
#undef atomic_store_explicit
#undef atomic_load_explicit

// Simple logging switch
#ifdef QUIET
#define LOG(...)
#else
#define LOG(...) printf(__VA_ARGS__)
#endif

// Real functions
typedef int (*pthread_create_t)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
typedef int (*pthread_join_t)(pthread_t, void **);
typedef int (*pthread_mutex_init_t)(pthread_mutex_t *, const pthread_mutexattr_t *);
typedef int (*pthread_mutex_lock_t)(pthread_mutex_t *);
typedef int (*pthread_mutex_unlock_t)(pthread_mutex_t *);
typedef int (*pthread_cond_wait_t)(pthread_cond_t *, pthread_mutex_t *);
typedef int (*pthread_cond_signal_t)(pthread_cond_t *);
typedef int (*pthread_cond_broadcast_t)(pthread_cond_t *);

static pthread_create_t real_pthread_create = NULL;
static pthread_join_t real_pthread_join = NULL;
static pthread_mutex_init_t real_pthread_mutex_init = NULL;
static pthread_mutex_lock_t real_pthread_mutex_lock = NULL;
static pthread_mutex_unlock_t real_pthread_mutex_unlock = NULL;
static pthread_cond_wait_t real_pthread_cond_wait = NULL;
static pthread_cond_signal_t real_pthread_cond_signal = NULL;
static pthread_cond_broadcast_t real_pthread_cond_broadcast = NULL;

typedef struct {
    void *(*start_routine)(void *);
    void *arg;
    int tid;
} thread_wrapper_arg_t;

static atomic_int global_tid_counter;

__attribute__((constructor))
static void initialize_globals() {
    atomic_init(&global_tid_counter, 0);
}

static __thread int local_tid = 0;  // Thread ID for this thread

static memory_order order_from_index(int index) {
    switch (index) {
        case 0:
            return memory_order_relaxed;
        case 1:
            return memory_order_consume;
        case 2:
            return memory_order_acquire;
        case 3:
            return memory_order_release;
        case 4:
            return memory_order_acq_rel;
        case 5:
            return memory_order_seq_cst;
        default:
            return memory_order_seq_cst;
    }
}

void *thread_wrapper(void *arg) {
    thread_wrapper_arg_t *wrapper_arg = (thread_wrapper_arg_t *)arg;
    local_tid = wrapper_arg->tid;
    wmm_thread_start(wrapper_arg->tid);
    void *ret = wrapper_arg->start_routine(wrapper_arg->arg);
    wmm_thread_end();
    free(wrapper_arg);
    return ret;
}

void wmm_init_internal(void) {
    if (!real_pthread_create) {
        LOG("[WMM] Initializing...\n"); // Idempotent
        real_pthread_create = (pthread_create_t)dlsym(RTLD_NEXT, "pthread_create");
        real_pthread_join = (pthread_join_t)dlsym(RTLD_NEXT, "pthread_join");
        real_pthread_mutex_init = (pthread_mutex_init_t)dlsym(RTLD_NEXT, "pthread_mutex_init");
        real_pthread_mutex_lock = (pthread_mutex_lock_t)dlsym(RTLD_NEXT, "pthread_mutex_lock");
        real_pthread_mutex_unlock = (pthread_mutex_unlock_t)dlsym(RTLD_NEXT, "pthread_mutex_unlock");
        real_pthread_cond_wait = (pthread_cond_wait_t)dlsym(RTLD_NEXT, "pthread_cond_wait");
        real_pthread_cond_signal = (pthread_cond_signal_t)dlsym(RTLD_NEXT, "pthread_cond_signal");
        real_pthread_cond_broadcast = (pthread_cond_broadcast_t)dlsym(RTLD_NEXT, "pthread_cond_broadcast");
        // Assign main thread a unique ID (tid = 0)
        local_tid = 0;
        scheduler_init();
        scheduler_thread_registered(0);
    }
}

int wmm_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    wmm_init_internal();
    thread_wrapper_arg_t *wrapper_arg = malloc(sizeof(thread_wrapper_arg_t));
    if (!wrapper_arg)
        return -1;
    wrapper_arg->start_routine = start_routine;
    wrapper_arg->arg = arg;
    // Assign unique thread ID (starting from 1, main thread has 0)
    wrapper_arg->tid = atomic_fetch_add(&global_tid_counter, 1) + 1;

    int ret = real_pthread_create(thread, attr, thread_wrapper, wrapper_arg);
    if (ret == 0) {
        scheduler_thread_created(wrapper_arg->tid);
        return 0;
    }
    free(wrapper_arg);
    return ret;
}

int wmm_pthread_join(pthread_t thread, void **retval) {
    wmm_init_internal();
    scheduler_thread_join_wait_begin(local_tid);
    int ret = real_pthread_join(thread, retval);
    scheduler_thread_join_wait_end(local_tid);
    return ret;
}

// Export symbols for interposition (C++ std::thread calls these directly)
__attribute__((visibility("default"))) 
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    return wmm_pthread_create(thread, attr, start_routine, arg);
}

__attribute__((visibility("default")))
int pthread_join(pthread_t thread, void **retval) {
    return wmm_pthread_join(thread, retval);
}

int wmm_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    wmm_init_internal();
    return real_pthread_mutex_init(mutex, attr);
}

int wmm_pthread_mutex_lock(pthread_mutex_t *mutex) {
    wmm_init_internal();
    LOG("[WMM] Mutex Lock %p tid=%d\n", (void *)mutex, local_tid);
    return real_pthread_mutex_lock(mutex);
}

int wmm_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    wmm_init_internal();
    LOG("[WMM] Mutex Unlock %p tid=%d\n", (void *)mutex, local_tid);
    return real_pthread_mutex_unlock(mutex);
}

int wmm_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    wmm_init_internal();
    LOG("[WMM] Cond Wait %p %p tid=%d\n", (void *)cond, (void *)mutex, local_tid);
    return real_pthread_cond_wait(cond, mutex);
}

int wmm_pthread_cond_signal(pthread_cond_t *cond) {
    wmm_init_internal();
    LOG("[WMM] Cond Signal %p tid=%d\n", (void *)cond, local_tid);
    return real_pthread_cond_signal(cond);
}

int wmm_pthread_cond_broadcast(pthread_cond_t *cond) {
    wmm_init_internal();
    LOG("[WMM] Cond Broadcast %p tid=%d\n", (void *)cond, local_tid);
    return real_pthread_cond_broadcast(cond);
}

void wmm_thread_start(int tid) {
    LOG("[WMM] Thread %d started\n", tid);
    scheduler_thread_registered(tid);
}

void wmm_thread_end(void) {
    LOG("[WMM] Thread ended\n");
    scheduler_thread_unregistered(local_tid);
}

void wmm_func_entry(const char *name) {
    wmm_init_internal();
    (void)name;
}

void wmm_func_exit(const char *name) {
    wmm_init_internal();
    (void)name;
}

void wmm_store(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    LOG("[WMM] Store to %p val=%ld at %s:%d\n", obj, (long)val, file, line);
    scheduler_on_store((void *)obj, val, order);
    __atomic_store_n((intptr_t *)obj, val, order);
}

intptr_t wmm_load(volatile void *obj, wmm_memory_order_t order, const char *file, int line) {
    intptr_t val;
    if (scheduler_on_load((void *)obj, order, &val)) {
        LOG("[WMM] Load (simulated) from %p val=%ld at %s:%d\n", obj, (long)val, file, line);
        return val;
    }
    val = __atomic_load_n((intptr_t *)obj, order);
    LOG("[WMM] Load (real) from %p val=%ld at %s:%d\n", obj, (long)val, file, line);
    return val;
}

_Bool wmm_compare_exchange_strong(volatile void *obj, intptr_t *expected, intptr_t desired, wmm_memory_order_t succ, wmm_memory_order_t fail, const char *file, int line) {
    _Bool ret = __atomic_compare_exchange_n((intptr_t *)obj, expected, desired, 0, succ, fail);
    if (ret) {
        LOG("[WMM] CAS Strong success at %p val=%ld at %s:%d\n", obj, (long)desired, file, line);
        scheduler_on_store((void *)obj, desired, succ);
    } else {
        // LOG("[WMM] CAS Strong fail at %p expected=%ld at %s:%d\n", obj, (long)*expected, file, line);
    }
    return ret;
}

_Bool wmm_compare_exchange_weak(volatile void *obj, intptr_t *expected, intptr_t desired, wmm_memory_order_t succ, wmm_memory_order_t fail, const char *file, int line) {
    _Bool ret = __atomic_compare_exchange_n((intptr_t *)obj, expected, desired, 1, succ, fail);
    if (ret) {
        LOG("[WMM] CAS Weak success at %p val=%ld at %s:%d\n", obj, (long)desired, file, line);
        scheduler_on_store((void *)obj, desired, succ);
    }
    return ret;
}

intptr_t wmm_exchange(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_exchange_n((intptr_t *)obj, val, order);
    LOG("[WMM] Exchange at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    scheduler_on_store((void *)obj, val, order);
    return ret;
}

intptr_t wmm_fetch_add(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_fetch_add((intptr_t *)obj, val, order);
    LOG("[WMM] Fetch Add at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    // Store the NEW value (ret + val)
    scheduler_on_store((void *)obj, ret + val, order);
    return ret;
}

intptr_t wmm_fetch_sub(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_fetch_sub((intptr_t *)obj, val, order);
    LOG("[WMM] Fetch Sub at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    scheduler_on_store((void *)obj, ret - val, order);
    return ret;
}

intptr_t wmm_fetch_or(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_fetch_or((intptr_t *)obj, val, order);
    LOG("[WMM] Fetch Or at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    scheduler_on_store((void *)obj, ret | val, order);
    return ret;
}

intptr_t wmm_fetch_xor(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_fetch_xor((intptr_t *)obj, val, order);
    LOG("[WMM] Fetch Xor at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    scheduler_on_store((void *)obj, ret ^ val, order);
    return ret;
}

intptr_t wmm_fetch_and(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line) {
    intptr_t ret = __atomic_fetch_and((intptr_t *)obj, val, order);
    LOG("[WMM] Fetch And at %p val=%ld old=%ld at %s:%d\n", obj, (long)val, (long)ret, file, line);
    scheduler_on_store((void *)obj, ret & val, order);
    return ret;
}

_Bool wmm_atomic_flag_test_and_set(volatile void *obj, wmm_memory_order_t order, const char *file, int line) {
    _Bool ret = __atomic_test_and_set(obj, order);
    LOG("[WMM] Test and Set at %p at %s:%d\n", obj, file, line);
    scheduler_on_store((void *)obj, 1, order); // Assuming set to 1
    return ret;
}

void wmm_atomic_flag_clear(volatile void *obj, wmm_memory_order_t order, const char *file, int line) {
    LOG("[WMM] Flag Clear at %p at %s:%d\n", obj, file, line);
    scheduler_on_store((void *)obj, 0, order);
    __atomic_clear(obj, order);
}

void wmm_thread_fence(wmm_memory_order_t order, const char *file, int line) {
    LOG("[WMM] Fence at %s:%d\n", file, line);
    scheduler_on_fence(order);
    __atomic_thread_fence(order);
}

void wmm_init(void) {
    wmm_init_internal();
    LOG("[WMM] Initialized\n");
}

void wmm_register_location(const char *name, void *addr) {
    wmm_init_internal();
    LOG("[WMM] Register location %s at %p\n", name, addr);
    scheduler_register_location(name, addr);
}

uint8_t wmm_plain_load8(const uint8_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Plain Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint8_t)val;
    }
    val = __atomic_load_n(obj, memory_order_relaxed);
    LOG("[WMM] Plain Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)val,
        pos ? pos : "<unknown>");
    return (uint8_t)val;
}

uint16_t wmm_plain_load16(const uint16_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Plain Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint16_t)val;
    }
    val = __atomic_load_n(obj, memory_order_relaxed);
    LOG("[WMM] Plain Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)val,
        pos ? pos : "<unknown>");
    return (uint16_t)val;
}

uint32_t wmm_plain_load32(const uint32_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Plain Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint32_t)val;
    }
    val = __atomic_load_n(obj, memory_order_relaxed);
    LOG("[WMM] Plain Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)val,
        pos ? pos : "<unknown>");
    return (uint32_t)val;
}

uint64_t wmm_plain_load64(const uint64_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Plain Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint64_t)val;
    }
    val = __atomic_load_n(obj, memory_order_relaxed);
    LOG("[WMM] Plain Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)val,
        pos ? pos : "<unknown>");
    return (uint64_t)val;
}

void wmm_plain_store8(uint8_t *obj, uint8_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Plain Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    __atomic_store_n(obj, val, memory_order_relaxed);
}

void wmm_plain_store16(uint16_t *obj, uint16_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Plain Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    __atomic_store_n(obj, val, memory_order_relaxed);
}

void wmm_plain_store32(uint32_t *obj, uint32_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Plain Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    __atomic_store_n(obj, val, memory_order_relaxed);
}

void wmm_plain_store64(uint64_t *obj, uint64_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Plain Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    __atomic_store_n(obj, val, memory_order_relaxed);
}

uint8_t wmm_volatile_load8(const volatile uint8_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Volatile Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint8_t)val;
    }
    uint8_t ret = *(const volatile uint8_t *)obj;
    LOG("[WMM] Volatile Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)ret,
        pos ? pos : "<unknown>");
    return ret;
}

uint16_t wmm_volatile_load16(const volatile uint16_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Volatile Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint16_t)val;
    }
    uint16_t ret = *(const volatile uint16_t *)obj;
    LOG("[WMM] Volatile Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)ret,
        pos ? pos : "<unknown>");
    return ret;
}

uint32_t wmm_volatile_load32(const volatile uint32_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Volatile Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint32_t)val;
    }
    uint32_t ret = *(const volatile uint32_t *)obj;
    LOG("[WMM] Volatile Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)ret,
        pos ? pos : "<unknown>");
    return ret;
}

uint64_t wmm_volatile_load64(const volatile uint64_t *obj, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, memory_order_relaxed, &val)) {
        LOG("[WMM] Volatile Load (simulated) from %p val=%ld at %s\n", (const void *)obj, (long)val,
            pos ? pos : "<unknown>");
        return (uint64_t)val;
    }
    uint64_t ret = *(const volatile uint64_t *)obj;
    LOG("[WMM] Volatile Load (real) from %p val=%ld at %s\n", (const void *)obj, (long)ret,
        pos ? pos : "<unknown>");
    return ret;
}

void wmm_volatile_store8(volatile uint8_t *obj, uint8_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Volatile Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    *(volatile uint8_t *)obj = val;
}

void wmm_volatile_store16(volatile uint16_t *obj, uint16_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Volatile Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    *(volatile uint16_t *)obj = val;
}

void wmm_volatile_store32(volatile uint32_t *obj, uint32_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Volatile Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    *(volatile uint32_t *)obj = val;
}

void wmm_volatile_store64(volatile uint64_t *obj, uint64_t val, const char *pos) {
    wmm_init_internal();
    (void)pos;
    LOG("[WMM] Volatile Store to %p val=%ld at %s\n", (void *)obj, (long)val,
        pos ? pos : "<unknown>");
    scheduler_on_store((void *)obj, (intptr_t)val, memory_order_relaxed);
    *(volatile uint64_t *)obj = val;
}

void wmm_atomic_init8(uint8_t *obj, uint8_t val, const char *pos) {
    wmm_plain_store8(obj, val, pos);
}

void wmm_atomic_init16(uint16_t *obj, uint16_t val, const char *pos) {
    wmm_plain_store16(obj, val, pos);
}

void wmm_atomic_init32(uint32_t *obj, uint32_t val, const char *pos) {
    wmm_plain_store32(obj, val, pos);
}

void wmm_atomic_init64(uint64_t *obj, uint64_t val, const char *pos) {
    wmm_plain_store64(obj, val, pos);
}

uint8_t wmm_atomic_load8(const uint8_t *obj, int order, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, order_from_index(order), &val)) {
        return (uint8_t)val;
    }
    return __atomic_load_n(obj, order_from_index(order));
}

uint16_t wmm_atomic_load16(const uint16_t *obj, int order, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, order_from_index(order), &val)) {
        return (uint16_t)val;
    }
    return __atomic_load_n(obj, order_from_index(order));
}

uint32_t wmm_atomic_load32(const uint32_t *obj, int order, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, order_from_index(order), &val)) {
        return (uint32_t)val;
    }
    return __atomic_load_n(obj, order_from_index(order));
}

uint64_t wmm_atomic_load64(const uint64_t *obj, int order, const char *pos) {
    intptr_t val;
    wmm_init_internal();
    (void)pos;
    if (scheduler_on_load((void *)obj, order_from_index(order), &val)) {
        return (uint64_t)val;
    }
    return __atomic_load_n(obj, order_from_index(order));
}

void wmm_atomic_store8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    __atomic_store_n(obj, val, order_from_index(order));
}

void wmm_atomic_store16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    __atomic_store_n(obj, val, order_from_index(order));
}

void wmm_atomic_store32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    __atomic_store_n(obj, val, order_from_index(order));
}

void wmm_atomic_store64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    __atomic_store_n(obj, val, order_from_index(order));
}

uint8_t wmm_atomic_exchange8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_exchange_n(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_exchange16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_exchange_n(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_exchange32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_exchange_n(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_exchange64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_exchange_n(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)val, order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_fetch_add8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_fetch_add(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret + val), order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_fetch_add16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_fetch_add(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret + val), order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_fetch_add32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_fetch_add(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret + val), order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_fetch_add64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_fetch_add(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret + val), order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_fetch_sub8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_fetch_sub(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret - val), order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_fetch_sub16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_fetch_sub(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret - val), order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_fetch_sub32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_fetch_sub(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret - val), order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_fetch_sub64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_fetch_sub(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret - val), order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_fetch_and8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_fetch_and(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret & val), order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_fetch_and16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_fetch_and(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret & val), order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_fetch_and32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_fetch_and(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret & val), order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_fetch_and64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_fetch_and(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret & val), order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_fetch_or8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_fetch_or(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret | val), order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_fetch_or16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_fetch_or(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret | val), order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_fetch_or32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_fetch_or(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret | val), order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_fetch_or64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_fetch_or(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret | val), order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_fetch_xor8(uint8_t *obj, uint8_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t ret = __atomic_fetch_xor(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret ^ val), order_from_index(order));
    return ret;
}

uint16_t wmm_atomic_fetch_xor16(uint16_t *obj, uint16_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t ret = __atomic_fetch_xor(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret ^ val), order_from_index(order));
    return ret;
}

uint32_t wmm_atomic_fetch_xor32(uint32_t *obj, uint32_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t ret = __atomic_fetch_xor(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret ^ val), order_from_index(order));
    return ret;
}

uint64_t wmm_atomic_fetch_xor64(uint64_t *obj, uint64_t val, int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t ret = __atomic_fetch_xor(obj, val, order_from_index(order));
    scheduler_on_store((void *)obj, (intptr_t)(ret ^ val), order_from_index(order));
    return ret;
}

uint8_t wmm_atomic_compare_exchange8_v1(uint8_t *obj, uint8_t expected, uint8_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint8_t exp = expected;
    __atomic_compare_exchange_n(obj, &exp, desired, 0, order_from_index(succ), order_from_index(fail));
    if (exp == expected) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return exp;
}

uint16_t wmm_atomic_compare_exchange16_v1(uint16_t *obj, uint16_t expected, uint16_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint16_t exp = expected;
    __atomic_compare_exchange_n(obj, &exp, desired, 0, order_from_index(succ), order_from_index(fail));
    if (exp == expected) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return exp;
}

uint32_t wmm_atomic_compare_exchange32_v1(uint32_t *obj, uint32_t expected, uint32_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint32_t exp = expected;
    __atomic_compare_exchange_n(obj, &exp, desired, 0, order_from_index(succ), order_from_index(fail));
    if (exp == expected) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return exp;
}

uint64_t wmm_atomic_compare_exchange64_v1(uint64_t *obj, uint64_t expected, uint64_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    uint64_t exp = expected;
    __atomic_compare_exchange_n(obj, &exp, desired, 0, order_from_index(succ), order_from_index(fail));
    if (exp == expected) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return exp;
}

_Bool wmm_atomic_compare_exchange8_v2(uint8_t *obj, uint8_t *expected, uint8_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    _Bool ret = __atomic_compare_exchange_n(obj, expected, desired, 0, order_from_index(succ), order_from_index(fail));
    if (ret) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return ret;
}

_Bool wmm_atomic_compare_exchange16_v2(uint16_t *obj, uint16_t *expected, uint16_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    _Bool ret = __atomic_compare_exchange_n(obj, expected, desired, 0, order_from_index(succ), order_from_index(fail));
    if (ret) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return ret;
}

_Bool wmm_atomic_compare_exchange32_v2(uint32_t *obj, uint32_t *expected, uint32_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    _Bool ret = __atomic_compare_exchange_n(obj, expected, desired, 0, order_from_index(succ), order_from_index(fail));
    if (ret) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return ret;
}

_Bool wmm_atomic_compare_exchange64_v2(uint64_t *obj, uint64_t *expected, uint64_t desired, int succ, int fail, const char *pos) {
    wmm_init_internal();
    (void)pos;
    _Bool ret = __atomic_compare_exchange_n(obj, expected, desired, 0, order_from_index(succ), order_from_index(fail));
    if (ret) {
        scheduler_on_store((void *)obj, (intptr_t)desired, order_from_index(succ));
    }
    return ret;
}

void wmm_atomic_thread_fence(int order, const char *pos) {
    wmm_init_internal();
    (void)pos;
    scheduler_on_fence(order_from_index(order));
    __atomic_thread_fence(order_from_index(order));
}
