#include <stdio.h>
#include <pthread.h>

#include "barrier.h"

#include "librace.h"

// extern "C" {
// __attribute__((weak)) void __VERIFY_STORE_VAR(const char *name, bool value) {
// 	(void)name;
// 	(void)value;
// }
// __attribute__((weak)) bool __VERIFY_ASSERT(const char *expr) {
// 	(void)expr;
// 	return true;
// }
// }

spinning_barrier *barr;
int var = 0;

void* threadA(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	store_32(&var, 1);
	//add store
//	store_32(&var, 2);
//	store_32(&var, 3);
//	store_32(&var, 4);
//	store_32(&var, 5);
//	store_32(&var, 6);
//	store_32(&var, 7);
	//store_32(&var, 3);
	barr->wait();
	return NULL;
}

void* threadB(void *arg)
{
	(void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	barr->wait();
	int r = load_32(&var);
	printf("var = %d\n", r);
	// __VERIFY_STORE_VAR("r", r == 1);
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

	// __VERIFY_ASSERT("r");

	return 0;
}
