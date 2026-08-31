#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <librace.h>

#include "mpmc-change.h"
atomic_uint v;
int LOOPNUM=1;
//atomic<unsigned int> x[5];
using queue_type = struct mpmc_boundq_1_alt<int32_t, sizeof(int32_t)>;

void* threadA(void *arg)
{
	queue_type *queue = (queue_type *)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	int32_t *bin = queue->write_prepare();
	store_32(bin, 1);
	for(int i = 0; i < LOOPNUM; i++){
		atomic_store_explicit(&v, i, memory_order_relaxed);
	}
	//v[1].store(2, memory_order_relaxed);
	//v[2].store(3, memory_order_relaxed);
	//v[3].store(4, memory_order_relaxed);
	//v[4].store(5, memory_order_relaxed);
//	for(int j = 0; j < 5; j++){
//		v[j].store(j, memory_order_release);
//	}
	//v[0].store(1, memory_order_relaxed);
	//int tmp = v[1].load(memory_order_relaxed);
	queue->write_publish();
	return NULL;
}

void* threadB(void *arg)
{
	queue_type *queue = (queue_type *)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	int32_t *bin;
	//printf("read v[0]", v[0].load(memory_order_relaxed));
//	for(int i = 0; i < 5; i++){
//		int tmp = v[i].load(memory_order_relaxed);
//	}
	while ((bin = queue->read_fetch()) != NULL) {
	//	int tmp = v[0].load(memory_order_acquire);
		printf("Read: %d\n", load_32(bin));
		queue->read_consume();
	}
	int tmp = atomic_load_explicit(&v, memory_order_relaxed);
	(void)tmp;
	return NULL;
}

void* threadC(void *arg)
{
	queue_type *queue = (queue_type *)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	int32_t *bin = queue->write_prepare();
	store_32(bin, 1);
	queue->write_publish();
//	for(int i = 0; i < 5; i++){
//		x[i].store(i, memory_order_relaxed);
//	}
	while ((bin = queue->read_fetch()) != NULL) {
		printf("Read: %d\n", load_32(bin));
		queue->read_consume();
	}
	return NULL;
}

#define MAXREADERS 3
#define MAXWRITERS 3
#define MAXRDWR 3

#ifdef CONFIG_MPMC_READERS
#define DEFAULT_READERS (CONFIG_MPMC_READERS)
#else
#define DEFAULT_READERS 2
#endif

#ifdef CONFIG_MPMC_WRITERS
#define DEFAULT_WRITERS (CONFIG_MPMC_WRITERS)
#else
#define DEFAULT_WRITERS 2
#endif

#ifdef CONFIG_MPMC_RDWR
#define DEFAULT_RDWR (CONFIG_MPMC_RDWR)
#else
#define DEFAULT_RDWR 0
#endif

int readers = DEFAULT_READERS, writers = DEFAULT_WRITERS, rdwr = DEFAULT_RDWR;

void print_usage()
{
	printf("Error: use the following options\n"
		" -r <num>              Choose number of reader threads\n"
		" -w <num>              Choose number of writer threads\n");
	exit(EXIT_FAILURE);
}

void process_params(int argc, char **argv)
{
	const char *shortopts = "hr:w:";
	int opt;
	bool error = false;

	while (!error && (opt = getopt(argc, argv, shortopts)) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			break;
		case 'r':
			readers = atoi(optarg);
			break;
		case 'w':
			writers = atoi(optarg);
			break;
		default: /* '?' */
			error = true;
			break;
		}
	}

	if (writers < 1 || writers > MAXWRITERS)
		error = true;
	if (readers < 1 || readers > MAXREADERS)
		error = true;

	if (error)
		print_usage();
}

int user_main(int argc, char **argv)
{
	queue_type queue;
	// atomic_init(&v, 0);
	//	for(int i = 0; i < 5; i++){
//		v[i].store(0, memory_order_relaxed);
//		x[i].store(0, memory_order_relaxed);
//	}
	/* Note: optarg() / optind is broken in model-checker - workaround is
	 * to just copy&paste this test a few times */
	//process_params(argc, argv);
	printf("%d reader(s), %d writer(s)\n", readers, writers);
	
	#ifndef CONFIG_MPMC_NO_INITIAL_ELEMENT
	printf("Adding initial element\n");
	int32_t *bin = queue.write_prepare();
	store_32(bin, 17);
	queue.write_publish();
	#endif
	
	printf("Start threads\n");

	// pthread_t A[MAXWRITERS], B[MAXREADERS], C[MAXRDWR];
	pthread_t A1, A2; //since writers = DEFAULT_WRITERS = 2 
	pthread_create(&A1, NULL, threadA, &queue);
	pthread_create(&A2, NULL, threadA, &queue);

	// for (int i = 0; i < writers; i++)
	// 	pthread_create(&A[i], NULL, threadA, &queue);

	pthread_t B1, B2; //since readers = DEFAULT_READERS = 2
	pthread_create(&B1, NULL, threadB, &queue);
	pthread_create(&B2, NULL, threadB, &queue);

	// for (int i = 0; i < readers; i++)
	// 	pthread_create(&B[i], NULL, threadB, &queue);

	//rdwr is 0 here, so ignoring 
	
	// for (int i = 0; i < rdwr; i++)
	// 	pthread_create(&C[i], NULL, threadC, &queue);

	pthread_join(A1, NULL);
	pthread_join(A2, NULL);
	// for (int i = 0; i < writers; i++)
	// 	pthread_join(A[i], NULL);

	pthread_join(B1, NULL);
	pthread_join(B2, NULL);
	// for (int i = 0; i < readers; i++)
	// 	pthread_join(B[i], NULL);

	// for (int i = 0; i < rdwr; i++)
	// 	pthread_join(C[i], NULL);

	printf("Threads complete\n");

	return 0;
}
