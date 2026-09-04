// Store Buffering test variant (T1 Loop: 3, T2 Loop: 1)
// Auto-generated for PCTWM loop scaling experiment.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

extern "C" {
__attribute__((weak)) void __VERIFY_STORE_VAR(const char *name, bool value) {
    (void)name;
    (void)value;
}
__attribute__((weak)) bool __VERIFY_ASSERT(const char *expr) {
    (void)expr;
    return true;
}
}

static atomic_int x = 0;
static atomic_int y = 0;

void *thread_1(void *arg) {
    int a = -1;
    for (int i = 0; i < 3; i++) {
        atomic_store_explicit(&x, 1, memory_order_relaxed);
        a = atomic_load_explicit(&y, memory_order_relaxed);
    }
    __VERIFY_STORE_VAR("a", a == 0);
    return NULL;
}

void *thread_2(void *arg) {
    int b = -1;
    for (int i = 0; i < 1; i++) {
        atomic_store_explicit(&y, 1, memory_order_relaxed);
        b = atomic_load_explicit(&x, memory_order_relaxed);
    }
    __VERIFY_STORE_VAR("b", b == 0);
    return NULL;
}

int main() {
    atomic_store_explicit(&x, 0, memory_order_relaxed);
    atomic_store_explicit(&y, 0, memory_order_relaxed);

    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    __VERIFY_ASSERT("!(a & b)");

    return 0;
}
