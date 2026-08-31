#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "librace.h"

#define RW_LOCK_BIAS            0x00100000
#define WRITE_LOCK_CMP          RW_LOCK_BIAS

/** Example implementation of linux rw lock along with 2 thread test
 *  driver... */

typedef union {
	atomic_int lock;
} rwlock_t;

static inline int read_can_lock(rwlock_t *lock)
{
	return atomic_load_explicit(&lock->lock, memory_order_relaxed) > 0;
}

static inline int write_can_lock(rwlock_t *lock)
{
	return atomic_load_explicit(&lock->lock, memory_order_relaxed) == RW_LOCK_BIAS;
}

static inline void read_lock(rwlock_t *rw)
{
    int priorvalue = atomic_fetch_sub_explicit(&rw->lock, 1, memory_order_acquire);		//e7, e22

	while (priorvalue <= 0) {
		atomic_fetch_add_explicit(&rw->lock, 1, memory_order_relaxed); 		//e8, e23
		while (atomic_load_explicit(&rw->lock, memory_order_relaxed) <= 0) {	//e9, e24
            sched_yield();
        }
		priorvalue = atomic_fetch_sub_explicit(&rw->lock, 1, memory_order_relaxed); 	//e10, e25
    }
}

static inline void write_lock(rwlock_t *rw)
{
	int priorvalue = atomic_fetch_sub_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_acquire); 	//e13, e28
	while (priorvalue != RW_LOCK_BIAS) {
		atomic_fetch_add_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_relaxed); 	//e14, e29
		while (atomic_load_explicit(&rw->lock, memory_order_relaxed) != RW_LOCK_BIAS) {		//e15, e30
            sched_yield();
        }
		priorvalue = atomic_fetch_sub_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_relaxed); 	//e16, e31
    }
}

static inline int read_trylock(rwlock_t *rw)
{
	int priorvalue = atomic_fetch_sub_explicit(&rw->lock, 1, memory_order_acquire);
	if (priorvalue > 0)
		return 1;

	atomic_fetch_add_explicit(&rw->lock, 1, memory_order_relaxed);
	return 0;
}

static inline int write_trylock(rwlock_t *rw)
{
	int priorvalue = atomic_fetch_sub_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_acquire);
	if (priorvalue == RW_LOCK_BIAS)
		return 1;

	atomic_fetch_add_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_relaxed);
	return 0;
}

static inline void read_unlock(rwlock_t *rw)
{
	atomic_fetch_add_explicit(&rw->lock, 1, memory_order_release); 	//e12, e27
}

static inline void write_unlock(rwlock_t *rw)
{
	atomic_fetch_add_explicit(&rw->lock, RW_LOCK_BIAS, memory_order_release); 		//e19, e34
}

rwlock_t mylock;	//e1
int shareddata;		//e2
atomic_int value;	//e3
int LOOPNUM=1;

void* a(void* arg)
{
    (void)arg;
//	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	int i, rs;
	for(i = 0; i < 2; i++) {
		for(int i = 0; i < LOOPNUM; i++){
            atomic_store_explicit(&value, 1, memory_order_relaxed); 	//e6, e21
		}
		if ((i%2) == 0) {
			read_lock(&mylock);	
	//		value.store(0, memory_order_relaxed);
	//		for(int i = 0; i < 2; i++){
	//			value.store(1, memory_order_relaxed);
	//		}
			load_32(&shareddata);	//e11, e26
			//rs = load_32(&shareddata);
			read_unlock(&mylock);
		} else {
			write_lock(&mylock);
	//std::this_thread::yield();
		//	for(int i = 5; i < 10; i++){
		//		value[i].store(2, memory_order_relaxed);
		//	}
		    atomic_store_explicit(&value, 1, memory_order_relaxed);		//e17, e32
			store_32(&shareddata,(unsigned int)i);		//e18, e33
			write_unlock(&mylock);
		//	int tmp = value.load(memory_order_relaxed);
		}
		//else{
		//	for(int i = 0; i < 3; i++){
		//		value[i].store(1, memory_order_relaxed);
		//	}
		//}
	}
	int tmp = atomic_load_explicit(&value, memory_order_relaxed);	//e5, e20
	tmp = tmp - 1;
    return NULL;
}

int user_main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pthread_t t1, t2;
	atomic_init(&mylock.lock, RW_LOCK_BIAS);	//e4

	//std::thread t1(a);
	//std::thread t2(a);
    pthread_create(&t1, NULL, a, NULL);
    pthread_create(&t2, NULL, a, NULL);

	//t1.join();
	//t2.join();
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

	return 0;
}
