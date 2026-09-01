#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <assert.h>

atomic_int x = 0;
int b;

void *thread_1(void *arg) {
   for(int i = 0; i < 10; i++){
    b = i;
   }
    return NULL;
}

int main(){
    atomic_store_explicit(&x, 1, memory_order_relaxed);
    pthread_t t1;
    pthread_create(&t1,NULL,thread_1,NULL);
    pthread_join(t1,NULL);

    int temp = b;

    return 0;
}
