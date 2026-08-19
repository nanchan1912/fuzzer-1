// Out of Thin Air
// This example demonstrates the Load Buffering (LB) and our WMM semantics 
// doesn't cover OOTA behaviour for now, so don't allow this behavior.

#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>
// #include "../lib/wmm.h"

atomic_int x = 0;
atomic_int y = 0;
int a,b;

void *thread_1(void *arg) {
    a = atomic_load_explicit(&x, memory_order_relaxed);
    atomic_store_explicit(&y, 1, memory_order_relaxed);
    return NULL;
}

void *thread_2(void *arg) {
    b = atomic_load_explicit(&y, memory_order_relaxed);
    atomic_store_explicit(&x, 1, memory_order_relaxed);
    return NULL;
}

int main() {
    pthread_t t1, t2;
    
    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    
    printf("a=%d, b=%d\n", a, b);
    
    // LB weak behavior: a=1, b=1
    // This implies T1 read x=1 (from T2) before T2 wrote x=1? 
    // Or rather, T1 read x=1 (future value?)
    // In relaxed models, this is allowed if stores are reordered with loads?
    // Wait, LB r1=1, r2=1 is usually allowed by allowing reordering of load x and store y in T1, 
    // and load y and store x in T2.
    if (a == 1 && b == 1) {
        assert(0 && "LB violation detected!");
        printf("Weak memory behavior observed (LB violation)!\n");
    } else {
        printf("SC behavior observed.\n");
    }
    
    return 0;
}