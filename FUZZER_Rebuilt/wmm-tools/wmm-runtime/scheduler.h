#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdbool.h>

// for shared mem feedback
extern struct SHM_next_events *g_next_events;
extern const char *SHM_ENV_NAME;

#ifdef __cplusplus
extern "C" {
#endif

void scheduler_init(void);
void scheduler_register_location(const char *name, void *addr);
void scheduler_terminate(int code);
//Required, due to the difference between the mutator and simulator (as simulator was using memory_order) and their mismatch of access modes
typedef enum {
    NON_ATOMIC,
    RELAXED,
    ACQUIRE,
    RELEASE,
    ACQ_REL,
    SC
} Access_Mode;
//This is used to replace memory_order at all the instances where memory_order was previously used.

// Called by __wmm_trace (injected by LLVM pass)
void __wmm_trace(long long instruction_id);

// Called by wmm hooks (use thread-local tid internally)
void scheduler_on_store(void *addr, intptr_t val, Access_Mode order,
						uint64_t event_uid, uint64_t thread_id,
						uint64_t loc_id);
void scheduler_on_store_ex(void *addr, intptr_t val, Access_Mode order,
						   uint64_t event_uid, uint64_t thread_id,
						   uint64_t loc_id, uint64_t visit_id);
void scheduler_on_store_bytes_ex(void *addr, const void *data, size_t size,
                                 Access_Mode order,
                                 uint64_t event_uid, uint64_t thread_id,
                                 uint64_t loc_id, uint64_t visit_id);
bool scheduler_on_load(void *addr, Access_Mode order, intptr_t *val_out,
					   uint64_t event_uid, uint64_t thread_id,
					   uint64_t loc_id);
bool scheduler_on_load_ex(void *addr, Access_Mode order, intptr_t *val_out,
					  uint64_t event_uid, uint64_t thread_id,
					  uint64_t loc_id, uint64_t visit_id);
bool scheduler_on_load_bytes_ex(void *addr, Access_Mode order,
                                void *buf_out, size_t buf_size,
                                uint64_t event_uid, uint64_t thread_id,
                                uint64_t loc_id, uint64_t visit_id);
uint64_t scheduler_on_rmw_bytes_ex(void *addr, size_t size, uint32_t op, uint64_t value,
                                   Access_Mode order, uint64_t event_uid, uint64_t thread_id,
                                   uint64_t loc_id, uint64_t visit_id, bool *forced_out);
uint64_t scheduler_on_cmpxchg_bytes_ex(void *addr, size_t size, uint64_t compare_val, uint64_t new_val,
                                       Access_Mode order, uint64_t event_uid, uint64_t thread_id,
                                       uint64_t loc_id, uint64_t visit_id, bool *success_out, bool *forced_out);
void scheduler_on_fence(Access_Mode order, uint64_t event_uid,
						uint64_t thread_id);
void scheduler_on_fence_ex(Access_Mode order, uint64_t event_uid,
					   uint64_t thread_id, uint64_t visit_id);

// Thread lifecycle
void scheduler_thread_created(int tid,unsigned long long parentid);
void scheduler_thread_registered(int tid);
void scheduler_thread_unregistered(int tid);
void scheduler_thread_join_wait_begin(int tid);
void scheduler_thread_join_wait_end(int tid,int child_tid);

// Real pthread function pointers to avoid recursion/interception in runtime library
#include <pthread.h>
extern int (*real_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern int (*real_pthread_join)(pthread_t, void **);
extern int (*real_pthread_mutex_init)(pthread_mutex_t *, const pthread_mutexattr_t *);
extern int (*real_pthread_mutex_lock)(pthread_mutex_t *);
extern int (*real_pthread_mutex_unlock)(pthread_mutex_t *);
extern int (*real_pthread_cond_wait)(pthread_cond_t *, pthread_mutex_t *);
extern int (*real_pthread_cond_signal)(pthread_cond_t *);
extern int (*real_pthread_cond_broadcast)(pthread_cond_t *);

#ifdef __cplusplus
}
#endif

#endif
