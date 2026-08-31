// #include "cds_atomic.h"

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

class spinning_barrier {
 public:
	spinning_barrier (unsigned int n) : n_ (n) {
		atomic_init(&nwait_, 0);
		atomic_init(&step_, 0);
	}

	bool wait(){
		unsigned int step = atomic_load_explicit(&step_, memory_order_seq_cst);

		if (atomic_fetch_add_explicit(&nwait_, 1, memory_order_seq_cst) == n_ - 1) {
			/* OK, last thread to come.  */
			atomic_store_explicit(&nwait_, 0, memory_order_relaxed); // XXX: maybe can use relaxed ordering here ??
			atomic_fetch_add_explicit(&step_, 1, memory_order_relaxed);
			return true;
		} else {
			/* Run in circles and scream like a little girl.  */
			while (atomic_load_explicit(&step_, memory_order_seq_cst) == step)
				sched_yield();
			return false;
		}
	}

 protected:
	/* Number of synchronized threads. */
	const unsigned int n_;

	/* Number of threads currently spinning.  */
	atomic_uint nwait_;

	/* Number of barrier syncronizations completed so far, 
	 *      * it's OK to wrap.  */
	atomic_uint step_;
};
