// #include "cds_atomic.h"
#include <stdbool.h>
#include <unrelacy.h>
#include <sched.h>
#include <stdatomic.h>

template <typename t_element, size_t t_size>
struct mpmc_boundq_1_alt
{
private:

	// elements should generally be cache-line-size padded :
	t_element               m_array[t_size];

	// rdwr counts the reads & writes that have started
	atomic_uint    m_rdwr;
	// "read" and "written" count the number completed
	atomic_uint    m_read;
	atomic_uint    m_written;

public:

	mpmc_boundq_1_alt()
	{
		atomic_init(&m_rdwr, 0);
		atomic_init(&m_read, 0);
		atomic_init(&m_written, 0);
	}

	//-----------------------------------------------------

	t_element * read_fetch() {
		unsigned int rdwr = atomic_load_explicit(&m_rdwr, memory_order_relaxed);
		unsigned int rd,wr;
		for(;;) {
			rd = (rdwr>>16) & 0xFFFF;
			wr = rdwr & 0xFFFF;

			if ( wr == rd ) // empty
				return NULL;

			if ( atomic_compare_exchange_weak_explicit(&m_rdwr, &rdwr, rdwr+(1<<16), memory_order_acquire, memory_order_acquire) )
				break;
			else
				sched_yield();
		}

		// (*1)
		rl::backoff bo;
		while ( (atomic_load_explicit(&m_written, memory_order_acquire) & 0xFFFF) != wr ) {
			sched_yield();
		}

		t_element * p = & ( m_array[ rd % t_size ] );

		return p;
	}

	void read_consume() {
		atomic_fetch_add_explicit(&m_read, 1, memory_order_relaxed);
	}

	//-----------------------------------------------------

	t_element * write_prepare() {
		unsigned int rdwr = atomic_load_explicit(&m_rdwr, memory_order_relaxed);
		unsigned int rd,wr;
		for(;;) {
			rd = (rdwr>>16) & 0xFFFF;
			wr = rdwr & 0xFFFF;

			if ( wr == ((rd + t_size)&0xFFFF) ) // full
				return NULL;

			if (atomic_compare_exchange_weak_explicit(&m_rdwr, &rdwr, (rd << 16) | ((wr + 1) & 0xFFFF), memory_order_relaxed, memory_order_relaxed))
				break;
			else
				sched_yield();
		}

		// (*1)
		rl::backoff bo;
		while ( (atomic_load_explicit(&m_read, memory_order_acquire) & 0xFFFF) != rd ) {
			sched_yield();
		}

		t_element * p = & ( m_array[ wr % t_size ] );

		return p;
	}

	void write_publish()
	{
		atomic_fetch_add_explicit(&m_written, 1, memory_order_relaxed);
	}

	//-----------------------------------------------------


};
