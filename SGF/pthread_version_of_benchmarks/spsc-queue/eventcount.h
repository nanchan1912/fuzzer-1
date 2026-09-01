#include <unrelacy.h>
#include <stdatomic.h>
#include <mutex>
#include <condition_variable>

class eventcount
{
public:
	eventcount() : waiters(0)
	{
		count = 0;
	}

	void signal_relaxed()
	{
		unsigned cmp = atomic_load_explicit(&count, memory_order_relaxed);
		signal_impl(cmp);
	}

	void signal()
	{
		unsigned cmp = atomic_fetch_add_explicit(&count, 0u, memory_order_seq_cst);
		signal_impl(cmp);
	}

	unsigned get()
	{
		unsigned cmp = atomic_fetch_or_explicit(&count, 0x80000000u,
			memory_order_seq_cst);
		return cmp & 0x7FFFFFFF;
	}

	void wait(unsigned cmp)
	{
		unsigned ec = atomic_load_explicit(&count, memory_order_seq_cst);
		if (cmp == (ec & 0x7FFFFFFF))
		{
			//guard.lock($);
			std::unique_lock<std::mutex> lck(guard);
			ec = atomic_load_explicit(&count, memory_order_seq_cst);
			if (cmp == (ec & 0x7FFFFFFF))
			{
				waiters += 1;
				//cv.wait(guard);
				cv.wait(lck);
			}
			guard.unlock($);
			//lck.unlock();
		}
	}

private:
	_Atomic(unsigned) count;
	rl::var<unsigned> waiters;
	std::mutex guard;
	std::condition_variable cv;

	void signal_impl(unsigned cmp)
	{
		if (cmp & 0x80000000)
		{
			guard.lock($);
			while (!atomic_compare_exchange_weak_explicit(&count, &cmp,
				(cmp + 1) & 0x7FFFFFFF, memory_order_relaxed, memory_order_relaxed));
			unsigned w = waiters($);
			waiters = 0;
			guard.unlock($);
			if (w)
				cv.notify_all($);
		}
	}
};
