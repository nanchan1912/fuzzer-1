#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
//#include "cds_threads.h"

#include "my_queue.h"
#include "model-assert.h"


static int procs = 4;
static queue_t *queue;

// static pthread_t *threads;
static pthread_t thread1, thread2, thread3, thread4;
static unsigned int *input;
static unsigned int *output;
static int num_threads;

int get_thread_num()
{
	pthread_t curr = pthread_self();
	int i;
	// for (i = 0; i < num_threads; i++)
	// 	if (pthread_equal(curr, threads[i]))
	// 		return i;

	if(pthread_equal(curr,thread1)){
		return 0;
	}
	if(pthread_equal(curr,thread2)){
		return 1;
	}
	if(pthread_equal(curr,thread3)){
		return 2;
	}
	if(pthread_equal(curr,thread4)){
		return 3;
	}
	MODEL_ASSERT(0);
	return -1;
}

bool succ1, succ2;

static void *main_task(void *param)
{
	unsigned int val;
	int pid = *((int *)param);

	if (!pid) {
		input[0] = 17;
		enqueue(queue, input[0]);
		succ1 = dequeue(queue, &output[0]);
		//printf("Dequeue: %d\n", output[0]);
	} else {
		input[1] = 37;
		enqueue(queue, input[1]);
		succ2 = dequeue(queue, &output[1]);
	}
	return NULL;
}

int user_main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	int i;
	// int *param;
	unsigned int in_sum = 0, out_sum = 0;
	
	queue = (queue_t *)calloc(1, sizeof(*queue));
	MODEL_ASSERT(queue);
	num_threads = procs;
	// threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
	//here, num_threads = procs = 4, hence, creating 4 threads
	// pthread_t thread1, thread2, thread3, thread4;
	//moved this to global scope

	// param = (int *)malloc(num_threads * sizeof(*param));
	input = (unsigned *)calloc(num_threads, sizeof(*input));
	output = (unsigned *)calloc(num_threads, sizeof(*output));
	
	init_queue(queue, num_threads);
	// for (i = 0; i < num_threads; i++) {
		// param[i] = i;
		// pthread_create(&threads[i], NULL, main_task, &param[i]);
	// }
	/* main_task dereferences its argument, so it needs real pointers. Passing
	   the literals 0..3 cast to void* made every worker fault on its first
	   instruction, so no queue code ever ran. */
	static int params[4] = {0, 1, 2, 3};
	pthread_create(&thread1, NULL, main_task, &params[0]);
	pthread_create(&thread2, NULL, main_task, &params[1]);
	pthread_create(&thread3, NULL, main_task, &params[2]);
	pthread_create(&thread4, NULL, main_task, &params[3]);

	// for (i = 0; i < num_threads; i++)
	// 	pthread_join(threads[i], NULL);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	pthread_join(thread3, NULL);
	pthread_join(thread4, NULL);

	for (i = 0; i < num_threads; i++) {
		in_sum += input[i];
		out_sum += output[i];
	}
	for (i = 0; i < num_threads; i++)
		printf("input[%d] = %u\n", i, input[i]);
	for (i = 0; i < num_threads; i++)
		printf("output[%d] = %u\n", i, output[i]);

	if (succ1 && succ2)
		MODEL_ASSERT(in_sum == out_sum);
	else
		MODEL_ASSERT(false);

		// free(param);
	// free(threads);
	free(queue);

	return 0;
}
