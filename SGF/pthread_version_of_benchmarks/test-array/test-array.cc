#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

#define SIZE 2

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

atomic_int arr[SIZE] = {0};

void *thread_1(void *arg) {
    for (int i = 0; i < SIZE; i++) {
        atomic_store_explicit(&arr[i], i + 1, memory_order_relaxed);
    }
    return NULL;
}

void *thread_2(void *arg) {
    int a = 0, b = 0;
    for (int i = SIZE - 1; i >= 0; i--) {
        int val = atomic_load_explicit(&arr[i], memory_order_relaxed);
        if (i == SIZE - 1) {
            a = val;
        } else if (i == 0) {
            b = val;
        }
    }
    printf("a=%d, b=%d\n", a, b);
    __VERIFY_STORE_VAR("a", a == SIZE);
    __VERIFY_STORE_VAR("b", b == 0);
    return NULL;
}

int main() {
    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    __VERIFY_ASSERT("!(a & b)");

    return 0;
}
