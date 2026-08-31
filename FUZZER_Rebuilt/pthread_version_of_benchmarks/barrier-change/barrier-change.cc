#include <stdio.h>
#include <pthread.h>

#include "barrier-change.h"

#include "librace.h"

spinning_barrier *barr;
int var = 0;
atomic_uint value;

void* threadA(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	atomic_store_explicit(&value, 1, memory_order_relaxed);
	atomic_store_explicit(&value, 2, memory_order_relaxed);
	store_32(&var, 1);
	atomic_store_explicit(&value, 3, memory_order_relaxed);
	barr->wait();
	return NULL;
}

void* threadB(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	barr->wait();
	atomic_store_explicit(&value, 4, memory_order_relaxed);
	printf("var = %d\n", load_32(&var));
	int tmp = atomic_load_explicit(&value, memory_order_relaxed);
	(void)tmp;
	return NULL;
}

#define NUMREADERS 1
int user_main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	pthread_t A, B;
	int i;

	barr = new spinning_barrier(NUMREADERS + 1);
	atomic_init(&value, 0);
	
	// pthread_create(&A, NULL, threadA, NULL);
	// for (i = 0; i < NUMREADERS; i++)
	// 	pthread_create(&B[i], NULL, threadB, NULL);

	// for (i = 0; i < NUMREADERS; i++)
	// 	pthread_join(B[i], NULL);
	// pthread_join(A, NULL);

	pthread_create(&A, NULL, threadA, NULL);
	pthread_create(&B, NULL, threadB, NULL);

	pthread_join(B, NULL);
	pthread_join(A, NULL);

	return 0;
}
