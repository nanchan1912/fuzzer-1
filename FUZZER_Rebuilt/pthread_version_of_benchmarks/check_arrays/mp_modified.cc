#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

atomic_int x = 0;
int a[10];

void *thread_1(void *arg) {
   for(int i = 0; i < 10; i++){
    a[i] = i;
   }
    return NULL;
}

int main(){
    atomic_store_explicit(&x, 1, memory_order_relaxed);
    pthread_t t1;
    pthread_create(&t1,NULL,thread_1,NULL);
    pthread_join(t1,NULL);
    
    int temp = a[4];

    return 0;
}
