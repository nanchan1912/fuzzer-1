//#include <readerwriterqueue.h>
#include "readerwriterqueue/readerwriterqueue.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "stdlib.h"

#include "librace.h"

int shareddata;

static void *a(void *obj)
{
	int i;
	for (i = 0; i < 2; i++) {
		if ((i % 2) == 0) {
			moodycamel::ReaderWriterQueue<int> q(100);
			load_32(&shareddata);
		} else {
			moodycamel::ReaderWriterQueue<int> q(100);
			store_32(&shareddata,(unsigned int)i);
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t t1, t2;

	pthread_create(&t1, NULL, &a, NULL);
	pthread_create(&t2, NULL, &a, NULL);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	return 0;
}
/*
void threadA(struct mpmc_boundq_1_alt<int32_t, sizeof(int32_t)> *queue)
{
	//	int32_t *bin = queue->write_prepare();
	moodycamel::ReaderWriterQueue<int> q(100);
	
	load_32(&shareddata);	
//	store_32(bin, 1);
//				queue->write_publish();
}

void threadA(struct mpmc_boundq_1_alt<int32_t, sizeof(int32_t)> *queue)                                                                                                                      
{
 moodycamel::ReaderWriterQueue<int> q(100);                                                                                                                                                                                                                                                                                                                                                store_32(&shareddata); 
}
int main()
{
	
	    moodycamel::ReaderWriterQueue<int> q(100);
}*/
