// Store Buffering example with loops on shared variables.
// This program demonstrates SB violations with repeated accesses.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

#define N_VALUE 300
#define M_VALUE 200
#define K_VALUE 2

extern "C" {

__attribute__((weak))
void __VERIFY_STORE_VAR(const char *name, bool value) {
    (void)name;
    (void)value;
}

__attribute__((weak))
bool __VERIFY_ASSERT(const char *expr) {
    (void)expr;
    return true;
}

}

static atomic_int x = ATOMIC_VAR_INIT(1);
static atomic_int y = ATOMIC_VAR_INIT(0);
// static atomic_int z = ATOMIC_VAR_INIT(0);


void *thread_1(void *arg) {
    (void)arg;

    atomic_store_explicit(&x, N_VALUE, memory_order_release);

    __VERIFY_STORE_VAR("cond1", false);
        
    int c = atomic_load_explicit(&y, memory_order_acquire);
    if (c == K_VALUE) {
        if (atomic_load_explicit(&x, memory_order_acquire) == N_VALUE) {
            __VERIFY_STORE_VAR("cond1", true);
        } else {
            // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
        }
    } else {
        // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
    }
    return NULL;
}


void *thread_2(void *arg) {
    (void)arg;

    for (int j = 1; j <= K_VALUE; ++j) {
        if (atomic_load_explicit(&x, memory_order_acquire) == j) {
            atomic_store_explicit(&y, j, memory_order_release);
        } else {
            // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
        }
    }

    return NULL;
}

void *thread_3(void *arg) {
    (void)arg;

    for (int i = 1; i <= K_VALUE; ++i) {
        if (atomic_load_explicit(&y, memory_order_acquire) == i) {
            atomic_store_explicit(&x, i + 1, memory_order_release);
        } else {
            // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
        }
    }

    return NULL;
}


void *thread_4(void *arg) {
    (void)arg;

    atomic_store_explicit(&y, M_VALUE, memory_order_release);

    int d = atomic_load_explicit(&x, memory_order_acquire);

    __VERIFY_STORE_VAR("cond2", false);

    if (d == K_VALUE + 1) {
        if (atomic_load_explicit(&y, memory_order_acquire) == M_VALUE) {
            __VERIFY_STORE_VAR("cond2", true);
        } else {
            // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
        }
    } else {
        // atomic_fetch_add_explicit(&z, 1, memory_order_relaxed);
    }

    return NULL;
}

int main() {
    atomic_store_explicit(&x, 1, memory_order_relaxed);
    atomic_store_explicit(&y, 0, memory_order_relaxed);

    pthread_t t1, t2, t3, t4;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);
    pthread_create(&t3, NULL, thread_3, NULL);
    pthread_create(&t4, NULL, thread_4, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pthread_join(t4, NULL);

    __VERIFY_ASSERT("!(cond1 & cond2)");

    return 0;
}
