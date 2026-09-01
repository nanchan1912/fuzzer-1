#include <stdio.h>
#include <pthread.h>


#include "mcs-change.h"

/* For data race instrumentation */
#include "librace.h"

struct mcs_mutex *mutex;
static uint32_t shared;
atomic_uint v[20];
//std::atomic<unsigned int> x[10];
int LOOPNUM=1;
void *threadA(void *arg)
{
    (void)arg;

//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	mcs_mutex::guard g(mutex);
	printf("store: %d\n", 17);
	store_32(&shared, 17);
//	for(int i = 0; i < 10; i++){
//		v[i].store(i,std::memory_order_relaxed);
//	}
	mutex->unlock(&g);
	mutex->lock(&g);
//	for(int i = 0; i < 5; i++){
//		v[i].store(i, std::memory_order_relaxed);
//	}
	printf("load: %u\n", load_32(&shared));
	return NULL;
}

void *threadB(void *arg)
{
    (void)arg;

	for(int i = 0; i < LOOPNUM; i++){
		atomic_store_explicit(&v[i], i, memory_order_relaxed);
	}
	//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	mcs_mutex::guard g(mutex);
	printf("load: %u\n", load_32(&shared));
//	printf("load v[0]", v[0].load(std::memory_order_relaxed));
	mutex->unlock(&g);
	mutex->lock(&g);
	printf("store: %d\n", 17);
	store_32(&shared, 17);
	int tmp = atomic_load_explicit(&v[0], memory_order_relaxed);
	(void)tmp;
	return NULL;
}


int user_main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
	mutex = new mcs_mutex();
//	for(int i = 0; i < 20; i++){
//		v[i].store(0,std::memory_order_release);
//	}

    pthread_t A, B;
    pthread_create(&A, NULL, threadA, NULL);
    pthread_create(&B, NULL, threadB, NULL);

    pthread_join(A, NULL);
    pthread_join(B, NULL);
    
	return 0;
}
