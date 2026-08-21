#ifndef WMM_H
#define WMM_H

#include <stdint.h>
#include <stdbool.h>

#ifndef __cplusplus
#include <stdatomic.h>
typedef memory_order wmm_memory_order_t;
#else
typedef int wmm_memory_order_t;
#endif

#ifdef __cplusplus
extern "C" {
typedef bool wmm_bool_t;
#else
typedef _Bool wmm_bool_t;
#endif

// Wrapper macros (C only). C++ uses cds_atomic.h and std::atomic.
#ifndef __cplusplus
// We undefine them first in case they are already defined
#undef atomic_store_explicit
#undef atomic_load_explicit

#define atomic_store_explicit(obj, val, order) \
    wmm_store((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#define atomic_load_explicit(obj, order) \
    wmm_load((volatile void *)(obj), (order), __FILE__, __LINE__)

#undef atomic_compare_exchange_strong_explicit
#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
    wmm_compare_exchange_strong((volatile void *)(obj), (intptr_t *)(expected), (intptr_t)(desired), (succ), (fail), __FILE__, __LINE__)

#undef atomic_compare_exchange_weak_explicit
#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
    wmm_compare_exchange_weak((volatile void *)(obj), (intptr_t *)(expected), (intptr_t)(desired), (succ), (fail), __FILE__, __LINE__)

#undef atomic_exchange_explicit
#define atomic_exchange_explicit(obj, val, order) \
    wmm_exchange((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_fetch_add_explicit
#define atomic_fetch_add_explicit(obj, val, order) \
    wmm_fetch_add((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_fetch_sub_explicit
#define atomic_fetch_sub_explicit(obj, val, order) \
    wmm_fetch_sub((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_fetch_or_explicit
#define atomic_fetch_or_explicit(obj, val, order) \
    wmm_fetch_or((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_fetch_xor_explicit
#define atomic_fetch_xor_explicit(obj, val, order) \
    wmm_fetch_xor((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_fetch_and_explicit
#define atomic_fetch_and_explicit(obj, val, order) \
    wmm_fetch_and((volatile void *)(obj), (intptr_t)(val), (order), __FILE__, __LINE__)

#undef atomic_thread_fence
#define atomic_thread_fence(order) \
    wmm_thread_fence((order), __FILE__, __LINE__)

#undef atomic_flag_test_and_set_explicit
#define atomic_flag_test_and_set_explicit(obj, order) \
    wmm_atomic_flag_test_and_set((volatile void *)(obj), (order), __FILE__, __LINE__)

#undef atomic_flag_clear_explicit
#define atomic_flag_clear_explicit(obj, order) \
    wmm_atomic_flag_clear((volatile void *)(obj), (order), __FILE__, __LINE__)
#endif

// Function prototypes
void wmm_init(void);
void wmm_register_location(const char *name, void *addr);
void wmm_thread_start(int tid);
void wmm_thread_end(void);
void wmm_func_entry(const char *name);
void wmm_func_exit(const char *name);

void wmm_store(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_load(volatile void *obj, wmm_memory_order_t order, const char *file, int line);
wmm_bool_t wmm_compare_exchange_strong(volatile void *obj, intptr_t *expected, intptr_t desired, wmm_memory_order_t succ, wmm_memory_order_t fail, const char *file, int line);
wmm_bool_t wmm_compare_exchange_weak(volatile void *obj, intptr_t *expected, intptr_t desired, wmm_memory_order_t succ, wmm_memory_order_t fail, const char *file, int line);
intptr_t wmm_exchange(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_fetch_add(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_fetch_sub(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_fetch_or(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_fetch_xor(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
intptr_t wmm_fetch_and(volatile void *obj, intptr_t val, wmm_memory_order_t order, const char *file, int line);
void wmm_thread_fence(wmm_memory_order_t order, const char *file, int line);
wmm_bool_t wmm_atomic_flag_test_and_set(volatile void *obj, wmm_memory_order_t order, const char *file, int line);
void wmm_atomic_flag_clear(volatile void *obj, wmm_memory_order_t order, const char *file, int line);

uint8_t wmm_plain_load8(const uint8_t *obj, const char *pos);
uint16_t wmm_plain_load16(const uint16_t *obj, const char *pos);
uint32_t wmm_plain_load32(const uint32_t *obj, const char *pos);
uint64_t wmm_plain_load64(const uint64_t *obj, const char *pos);
void wmm_plain_store8(uint8_t *obj, uint8_t val, const char *pos);
void wmm_plain_store16(uint16_t *obj, uint16_t val, const char *pos);
void wmm_plain_store32(uint32_t *obj, uint32_t val, const char *pos);
void wmm_plain_store64(uint64_t *obj, uint64_t val, const char *pos);

uint8_t wmm_volatile_load8(const volatile uint8_t *obj, const char *pos);
uint16_t wmm_volatile_load16(const volatile uint16_t *obj, const char *pos);
uint32_t wmm_volatile_load32(const volatile uint32_t *obj, const char *pos);
uint64_t wmm_volatile_load64(const volatile uint64_t *obj, const char *pos);
void wmm_volatile_store8(volatile uint8_t *obj, uint8_t val, const char *pos);
void wmm_volatile_store16(volatile uint16_t *obj, uint16_t val, const char *pos);
void wmm_volatile_store32(volatile uint32_t *obj, uint32_t val, const char *pos);
void wmm_volatile_store64(volatile uint64_t *obj, uint64_t val, const char *pos);

void wmm_atomic_init8(uint8_t *obj, uint8_t val, const char *pos);
void wmm_atomic_init16(uint16_t *obj, uint16_t val, const char *pos);
void wmm_atomic_init32(uint32_t *obj, uint32_t val, const char *pos);
void wmm_atomic_init64(uint64_t *obj, uint64_t val, const char *pos);
uint8_t wmm_atomic_load8(const uint8_t *obj, int order, const char *pos);
uint16_t wmm_atomic_load16(const uint16_t *obj, int order, const char *pos);
uint32_t wmm_atomic_load32(const uint32_t *obj, int order, const char *pos);
uint64_t wmm_atomic_load64(const uint64_t *obj, int order, const char *pos);
void wmm_atomic_store8(uint8_t *obj, uint8_t val, int order, const char *pos);
void wmm_atomic_store16(uint16_t *obj, uint16_t val, int order, const char *pos);
void wmm_atomic_store32(uint32_t *obj, uint32_t val, int order, const char *pos);
void wmm_atomic_store64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_exchange8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_exchange16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_exchange32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_exchange64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_fetch_add8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_fetch_add16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_fetch_add32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_fetch_add64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_fetch_sub8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_fetch_sub16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_fetch_sub32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_fetch_sub64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_fetch_and8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_fetch_and16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_fetch_and32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_fetch_and64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_fetch_or8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_fetch_or16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_fetch_or32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_fetch_or64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_fetch_xor8(uint8_t *obj, uint8_t val, int order, const char *pos);
uint16_t wmm_atomic_fetch_xor16(uint16_t *obj, uint16_t val, int order, const char *pos);
uint32_t wmm_atomic_fetch_xor32(uint32_t *obj, uint32_t val, int order, const char *pos);
uint64_t wmm_atomic_fetch_xor64(uint64_t *obj, uint64_t val, int order, const char *pos);
uint8_t wmm_atomic_compare_exchange8_v1(uint8_t *obj, uint8_t expected, uint8_t desired, int succ, int fail, const char *pos);
uint16_t wmm_atomic_compare_exchange16_v1(uint16_t *obj, uint16_t expected, uint16_t desired, int succ, int fail, const char *pos);
uint32_t wmm_atomic_compare_exchange32_v1(uint32_t *obj, uint32_t expected, uint32_t desired, int succ, int fail, const char *pos);
uint64_t wmm_atomic_compare_exchange64_v1(uint64_t *obj, uint64_t expected, uint64_t desired, int succ, int fail, const char *pos);
wmm_bool_t wmm_atomic_compare_exchange8_v2(uint8_t *obj, uint8_t *expected, uint8_t desired, int succ, int fail, const char *pos);
wmm_bool_t wmm_atomic_compare_exchange16_v2(uint16_t *obj, uint16_t *expected, uint16_t desired, int succ, int fail, const char *pos);
wmm_bool_t wmm_atomic_compare_exchange32_v2(uint32_t *obj, uint32_t *expected, uint32_t desired, int succ, int fail, const char *pos);
wmm_bool_t wmm_atomic_compare_exchange64_v2(uint64_t *obj, uint64_t *expected, uint64_t desired, int succ, int fail, const char *pos);
void wmm_atomic_thread_fence(int order, const char *pos);


#include <pthread.h>
#define pthread_create(thread, attr, start_routine, arg) \
    wmm_pthread_create(thread, attr, start_routine, arg)
#define pthread_join(thread, retval) \
    wmm_pthread_join(thread, retval)
#define pthread_mutex_init(mutex, attr) \
    wmm_pthread_mutex_init(mutex, attr)
#define pthread_mutex_lock(mutex) \
    wmm_pthread_mutex_lock(mutex)
#define pthread_mutex_unlock(mutex) \
    wmm_pthread_mutex_unlock(mutex)
#define pthread_cond_wait(cond, mutex) \
    wmm_pthread_cond_wait(cond, mutex)
#define pthread_cond_signal(cond) \
    wmm_pthread_cond_signal(cond)
#define pthread_cond_broadcast(cond) \
    wmm_pthread_cond_broadcast(cond)

int wmm_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
int wmm_pthread_join(pthread_t thread, void **retval);
int wmm_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int wmm_pthread_mutex_lock(pthread_mutex_t *mutex);
int wmm_pthread_mutex_unlock(pthread_mutex_t *mutex);
int wmm_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int wmm_pthread_cond_signal(pthread_cond_t *cond);
int wmm_pthread_cond_broadcast(pthread_cond_t *cond);

#ifdef __cplusplus
}
#endif

#endif
