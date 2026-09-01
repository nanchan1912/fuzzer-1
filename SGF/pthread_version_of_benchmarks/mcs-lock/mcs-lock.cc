#include <stdio.h>
#include <pthread.h>


#include "mcs-lock.h"

/* For data race instrumentation */
#include "librace.h"

struct mcs_mutex *mutex;
static uint32_t shared;

void *threadA(void *arg)
{
    (void)arg;
	//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	mcs_mutex::guard g(mutex);
	printf("store: %d\n", 17);
	store_32(&shared, 17);
//	add store
        //store_32(&shared, 17);
//	store_32(&shared, 17);
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
//	printd("load: %u\n", load_32(&shared));
	mutex->unlock(&g);
	mutex->lock(&g);
	printf("store: %d\n", 17);
	store_32(&shared, 17);
//	add store
        //store_32(&shared, 17);
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
