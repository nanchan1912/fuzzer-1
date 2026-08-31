#include <unrelacy.h>
// #include <atomic>
#include <stdatomic.h>

#include "eventcount.h"

template<typename T>
class spsc_queue
{
public:
	spsc_queue()
	{
		node* n = new node ();
		head = n;
		tail = n;
	}

	~spsc_queue()
	{
		RL_ASSERT(head == tail);
		delete ((node*)head($));
	}

	void enqueue(T data)
	{
		node* n = new node (data);
		//ori:release
		atomic_store_explicit(&(head($)->next), n, memory_order_release);
		head = n;
		ec.signal_relaxed();
	}

	T dequeue()
	{
		T data = try_dequeue();
		while (0 == data)
		{
			int cmp = ec.get();
			data = try_dequeue();
			if (data)
				break;
			ec.wait(cmp);
			data = try_dequeue();
			if (data)
				break;
		}
		return data;
	}

private:
	struct node
	{
		_Atomic(node*) next;
		rl::var<T> data;

		node(T data = T())
			: data(data)
		{
			atomic_init(&next, (node*)0);
		}
	};

	rl::var<node*> head;
	rl::var<node*> tail;

	eventcount ec;

	T try_dequeue()
	{
		node* t = tail($);
		//ori:acquire
		node* n = atomic_load_explicit(&(t->next), memory_order_acquire);
		if (0 == n)
			return 0;
		T data = n->data($);
		delete (t);
		tail = n;
		return data;
	}
};
