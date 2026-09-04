#include "fuzzer.h"
#include <stdlib.h>
#include "threads-model.h"
#include "model.h"
#include "action.h"
#

int Fuzzer::selectWrite(ModelAction *read, SnapVector<ModelAction *> * rf_set) {
	int random_index = random() % rf_set->size();
	return random_index;
}

//pctwm
// return the idx of write-value in the rf_set
int Fuzzer::selectWriteMyThread(ModelAction *read, SnapVector<ModelAction *> * rf_set, int tid) {
	int len = rf_set->size(); // get how many rfs we have now

	// case1: only one read from value : return idx 0
	if(len <= 1) {
		model_print("only one read: select idx: 0. \n");
		return 0;
	}
	

	// case2: traverse all values: return the value in my thread
	for(int i = 0; i < len; i++){
		ModelAction *rf = (*rf_set)[i];
		if(rf->get_tid() == tid){
			model_print("current thread has value to read from: idx %d. \n", i);
			return i;
		}
	}
	
	// case3: if currently I cannot read from the current thread, randomly select ont
	int random_index = random() % rf_set->size();
	model_print("current thread does not have value to read from %d. \n", random_index);
	return random_index;
}

//pctwm
// return the idx of write-value in the rf_set
int Fuzzer::selectWriteOtherThread(ModelAction *read, SnapVector<ModelAction *> * rf_set, int tid) {
	int len = rf_set->size(); // get how many rfs we have now

	// case1: only one read from value : return idx 0
	if(len <= 1) {
		model_print("only one read: select idx: 0. \n");
		return 0;
	}

	SnapVector<int> otherThreadIdx; // the vector to save the idxs of other threads in rf-set
	for(int i = 0; i < len; i++){
		ModelAction *rf = (*rf_set)[i];
		if(rf->get_tid() != tid){//write values on other threads
			otherThreadIdx.push_back(i); // the idxs that save other threads
		}
	}
	int random_index = random() % otherThreadIdx.size();
	model_print("select from other thread : %d. \n", random_index);
	return otherThreadIdx[random_index];
}

Thread * Fuzzer::selectThread(int * threadlist, int numthreads) {
	int random_index = random() % numthreads;
	int thread = threadlist[random_index];
	thread_id_t curr_tid = int_to_id(thread);
	return model->get_thread(curr_tid);
}

// select thread by the id picked by scheduler
Thread * Fuzzer::selectThreadbyid(int threadid) {

	thread_id_t curr_tid = int_to_id(threadid);
	return model->get_thread(curr_tid);
}

Thread * Fuzzer::selectNotify(simple_action_list_t * waiters) {
	int numwaiters = waiters->size();
	int random_index = random() % numwaiters;
	sllnode<ModelAction*> * it = waiters->begin();
	while(random_index--)
		it=it->getNext();
	Thread *thread = model->get_thread(it->getVal());
	waiters->erase(it);
	return thread;
}

bool Fuzzer::shouldSleep(const ModelAction *sleep) {
	return true;
}

bool Fuzzer::shouldWake(const ModelAction *sleep) {
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

	return ((sleep->get_time()+sleep->get_value()) < lcurrtime);
}

/* Decide whether wait should spuriously fail or not */
bool Fuzzer::waitShouldFail(ModelAction * wait)
{
	if ((random() & 1) == 0) {
		struct timespec currtime;
        clock_gettime(CLOCK_MONOTONIC, &currtime);
        uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

		// The time after which wait fail spuriously, in nanoseconds
		uint64_t time = random() % 1000000;
		wait->set_time(time + lcurrtime);
		return true;
	}

	return false;
}

bool Fuzzer::waitShouldWakeUp(const ModelAction * wait)
{
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;

	return (wait->get_time() < lcurrtime);
}

bool Fuzzer::randomizeWaitTime(ModelAction * timed_wait)
{
	uint64_t abstime = timed_wait->get_time();
	struct timespec currtime;
	clock_gettime(CLOCK_MONOTONIC, &currtime);
	uint64_t lcurrtime = currtime.tv_sec * 1000000000 + currtime.tv_nsec;
	if (abstime <= lcurrtime)
		return false;

	// Shorten wait time
	if ((random() & 1) == 0) {
		uint64_t tmp = abstime - lcurrtime;
		uint64_t time_to_expire = random() % tmp + lcurrtime;
		timed_wait->set_time(time_to_expire);
	}

	return true;
}
