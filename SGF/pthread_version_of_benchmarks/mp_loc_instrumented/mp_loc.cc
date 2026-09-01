// This is behaviour is modeled by our WMM semantics.
// Will be flagged as allowed in relaxed WMM models.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>
// #include "../lib/wmm.h"

atomic_int x = 0;
atomic_int y = 0;
int a,b;

void *thread_1(void *arg) {
    atomic_store_explicit(&x, 1, memory_order_relaxed);
    atomic_store_explicit(&y, 1, memory_order_relaxed);
    return NULL;
}

void *thread_2(void *arg) {
    a = atomic_load_explicit(&y, memory_order_relaxed);
    b = atomic_load_explicit(&x, memory_order_relaxed);
    return NULL;
}

int main() {
    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("a=%d, b=%d\n", a, b);

    // MP weak behavior: flag is set (a=1) but data is not seen (b=0)
    if (a == 1 && b == 0) {
        assert(0 && "MP violation detected!");
        printf("Weak memory behavior observed (MP violation)!\n");
    } else {
        printf("SC behavior observed.\n");
    }

    return 0;
}
