// mcs on stack

#include <sched.h>
#include <stdatomic.h>
#include <unrelacy.h>

struct mcs_node {
	atomic_uintptr_t next;
	atomic_int gate;

	mcs_node() {
		atomic_init(&next, (uintptr_t)NULL);
		atomic_init(&gate, 0);
	}
};

struct mcs_mutex {
public:
	atomic_int value;
	// tail is null when lock is not held
	atomic_uintptr_t m_tail;

	mcs_mutex() {
		atomic_init(&m_tail, (uintptr_t)NULL);
	}
	~mcs_mutex() {
		ASSERT( (mcs_node *)atomic_load_explicit(&m_tail, memory_order_seq_cst) == NULL );
	}

	class guard {
	public:
		mcs_mutex * m_t;
		mcs_node    m_node; // node held on the stack

		guard(mcs_mutex * t) : m_t(t) { t->lock(this); }
		~guard() { m_t->unlock(this); }
	};

	void lock(guard * I) {
		mcs_node * me = &(I->m_node);

		// set up my node :
		// not published yet so relaxed :
		atomic_store_explicit(&value, 1, memory_order_relaxed);
		atomic_store_explicit(&value, 2, memory_order_relaxed);
		atomic_store_explicit(&me->next, (uintptr_t)NULL, memory_order_relaxed);
		atomic_store_explicit(&me->gate, 1, memory_order_relaxed);

		// publish my node as the new tail :
		mcs_node * pred = (mcs_node *)atomic_exchange_explicit(&m_tail, (uintptr_t)me, memory_order_acq_rel);
		if ( pred != NULL ) {
			// (*1) race here
			// unlock of pred can see me in the tail before I fill next

			// publish me to previous lock-holder :
			atomic_store_explicit(&pred->next, (uintptr_t)me, memory_order_release);

			// (*2) pred not touched any more       

			// now this is the spin -
			// wait on predecessor setting my flag -
			rl::linear_backoff bo;
//			while(me->gate.load(std::mo_acquire)){
			while ( atomic_load_explicit(&me->gate, memory_order_relaxed) ) {
				sched_yield();
			}
		}
	}

	void unlock(guard * I) {
		mcs_node * me = &(I->m_node);

		mcs_node * next = (mcs_node *)atomic_load_explicit(&me->next, memory_order_acquire);
		if ( next == NULL )
		{
			mcs_node * tail_was_me = me;
			if ( atomic_compare_exchange_strong_explicit(&m_tail, (uintptr_t *)&tail_was_me, (uintptr_t)NULL, memory_order_acq_rel, memory_order_acquire) ) {
				// got null in tail, mutex is unlocked
				return;
			}

			// (*1) catch the race :
			rl::linear_backoff bo;
			for(;;) {
				next = (mcs_node *)atomic_load_explicit(&me->next, memory_order_relaxed);
//				next = me->next.load(std::mo_acquire);
				if ( next != NULL )
					break;
				sched_yield();
			}
		}

		// (*2) - store to next must be done,
		//  so no locker can be viewing my node any more        

		// let next guy in :
		atomic_store_explicit(&next->gate, 0, memory_order_release);
	}
};
