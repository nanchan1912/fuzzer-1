#include <stdio.h>
#include <pthread.h>


#include "mcs2.h"

/* For data race instrumentation */
#include "librace.h"

struct mcs_mutex *mutex;
static uint32_t shared;
atomic_uint value;

void *threadA(void *arg)
{
    (void)arg;
	//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	mcs_mutex::guard g(mutex);
	printf("store: %d\n", 17);
	atomic_store_explicit(&value, 1, memory_order_relaxed);
	atomic_store_explicit(&value, 2, memory_order_relaxed);
	atomic_store_explicit(&value, 4, memory_order_relaxed);
	atomic_store_explicit(&value, 8, memory_order_relaxed);

	store_32(&shared, 17);
	mutex->unlock(&g);
	mutex->lock(&g);
	printf("load: %u\n", load_32(&shared));
	return NULL;
}

void *threadB(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	mcs_mutex::guard g(mutex);
	printf("load: %u\n", load_32(&shared));
	mutex->unlock(&g);
	atomic_store_explicit(&value, 2, memory_order_relaxed);
	mutex->lock(&g);
	atomic_store_explicit(&value, 5, memory_order_relaxed);
	printf("store: %d\n", 17);
	atomic_store_explicit(&value, 4, memory_order_relaxed);
	atomic_store_explicit(&value, 5, memory_order_relaxed);
	store_32(&shared, 17);
	
	int tmp = atomic_load_explicit(&value, memory_order_relaxed);
	return NULL;
}

int user_main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
	mutex = new mcs_mutex();

    pthread_t A, B;
    pthread_create(&A, NULL, threadA, NULL);
    pthread_create(&B, NULL, threadB, NULL);

    pthread_join(A, NULL);
    pthread_join(B, NULL);
	return 0;
}
