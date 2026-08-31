// #include "cds_threads.h"

#include "queue.h"
#include <pthread.h>
#include <cstdint>

spsc_queue<int> *q;

static void *thread_func(void *arg)
{
	unsigned thread_index = (unsigned)(uintptr_t)arg;

	if (0 == thread_index)
	{
		q->enqueue(11);
	}
	else
	{
		int d = q->dequeue();
		RL_ASSERT(11 == d);
	}

	return NULL;
}

int user_main(int argc, char **argv)
{
	pthread_t A, B;

	q = new spsc_queue<int>();

	pthread_create(&A, NULL, thread_func, (void*)(uintptr_t)0);
	pthread_create(&B, NULL, thread_func, (void*)(uintptr_t)1);
	pthread_join(A, NULL);
	pthread_join(B, NULL);

	delete q;

	return 0;
}
