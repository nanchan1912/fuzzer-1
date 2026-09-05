// Store Buffering test variant (T1 Loop: 15, T2 Loop: 15, Eval: ANY)
// Auto-generated for PCTWM loop scaling experiment.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

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
    bool saw_zero = false;
    for (int i = 0; i < 15; i++) {
        atomic_store_explicit(&x, 1, memory_order_relaxed);
        int a = atomic_load_explicit(&y, memory_order_relaxed);
        if (a == 0) saw_zero = true;
    }
    __VERIFY_STORE_VAR("a", saw_zero);
    return NULL;
}

void *thread_2(void *arg) {
    bool saw_zero = false;
    for (int i = 0; i < 15; i++) {
        atomic_store_explicit(&y, 1, memory_order_relaxed);
        int b = atomic_load_explicit(&x, memory_order_relaxed);
        if (b == 0) saw_zero = true;
    }
    __VERIFY_STORE_VAR("b", saw_zero);
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
