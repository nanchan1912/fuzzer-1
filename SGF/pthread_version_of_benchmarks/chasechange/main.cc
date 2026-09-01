#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
//#include <atomic>

#include "model-assert.h"

#include "deque.h"

Deque *q;
int a;
int b;
int c;
int LOOPNUM=0;

atomic_int v;
static void* task(void * param) {
	(void)param;
	a=steal(q);
	return NULL;
}

int user_main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	q=create();
	pthread_t t;
	pthread_create(&t, NULL, task, NULL);
	atomic_init(&v, 0);
	for(int i = 0; i < LOOPNUM; i++){
		atomic_store_explicit(&v, 1, memory_order_relaxed);
	}
	push(q, 1);
	push(q, 2);
	push(q, 4);
	b=take(q);
	c=take(q);
	pthread_join(t, NULL);

	bool correct=true;
	if (a!=1 && a!=2 && a!=4 && a!= EMPTY)
		correct=false;
	if (b!=1 && b!=2 && b!=4 && b!= EMPTY)
		correct=false;
	if (c!=1 && c!=2 && c!=4 && a!= EMPTY)
		correct=false;
	if (a!=EMPTY && b!=EMPTY && c!=EMPTY && (a+b+c)!=7)
		correct=false;
	if (!correct)
		printf("a=%d b=%d c=%d\n",a,b,c);
	MODEL_ASSERT(correct);
	int tmp = atomic_load_explicit(&v, memory_order_relaxed);
	(void)tmp;
	return 0;
}
