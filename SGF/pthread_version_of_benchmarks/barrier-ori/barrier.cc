#include <stdio.h>
#include <pthread.h>

#include "barrier.h"

#include "librace.h"

spinning_barrier *barr;
int var = 0;

void* threadA(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	store_32(&var, 1);

	barr->wait();
	return NULL;
}

void* threadB(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	barr->wait();
	printf("var = %d\n", load_32(&var));
	return NULL;
}

#define NUMREADERS 3
int user_main(int argc, char **argv)
{
	pthread_t A, B1, B2, B3;
	int i;

	barr = new spinning_barrier(NUMREADERS + 1);

	pthread_create(&A, NULL, threadA, NULL);
	pthread_create(&B1, NULL, threadB, NULL);
	pthread_create(&B2, NULL, threadB, NULL);
	pthread_create(&B3, NULL, threadB, NULL);
	// for (i = 0; i < NUMREADERS; i++)
	// 	B[i] = std::thread(threadB, (void *)NULL);

	// for (i = 0; i < NUMREADERS; i++)
	// 	B[i].join();
	pthread_join(B1, NULL);
	pthread_join(B2, NULL);
	pthread_join(B3, NULL);
	pthread_join(A, NULL);

	return 0;
}
