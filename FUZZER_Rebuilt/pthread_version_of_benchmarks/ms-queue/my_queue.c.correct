#include <threads.h>
#include <stdlib.h>
#include "librace.h"
#include "model-assert.h"

#include "queue.h"

#define relaxed memory_order_relaxed
#define release memory_order_release
#define acquire memory_order_acquire

#define MAX_FREELIST 4 /* Each thread can own up to MAX_FREELIST free nodes */
#define INITIAL_FREE 2 /* Each thread starts with INITIAL_FREE free nodes */

#define POISON_IDX 0x666

static unsigned int (*free_lists)[MAX_FREELIST];

/* Search this thread's free list for a "new" node */
static unsigned int new_node()
{
	int i;
	int t = get_thread_num();
	for (i = 0; i < MAX_FREELIST; i++) {
		//unsigned int node = load_32(&free_lists[t][i]);
		unsigned int node = free_lists[t][i];
		if (node) {
			//store_32(&free_lists[t][i], 0);
			free_lists[t][i] = 0;
			return node;
		}
	}
	/* free_list is empty? */
	MODEL_ASSERT(0);
	return 0;
}

/* Simulate the fact that when a node got recycled, it will get assigned to the
 * same queue or for other usage */
void simulateRecycledNodeUpdate(queue_t *q, unsigned int node) {
	atomic_store_explicit(&q->nodes[node].next, -1, memory_order_release);
}


/* Place this node index back on this thread's free list */
static void reclaim(unsigned int node)
{
	int i;
	int t = get_thread_num();

	/* Don't reclaim NULL node */
	//MODEL_ASSERT(node);

	for (i = 0; i < MAX_FREELIST; i++) {
		/* Should never race with our own thread here */
		//unsigned int idx = load_32(&free_lists[t][i]);
		unsigned int idx = free_lists[t][i];

		/* Found empty spot in free list */
		if (idx == 0) {
			//store_32(&free_lists[t][i], node);
			free_lists[t][i] = node;
			return;
		}
	}
	/* free list is full? */
	//MODEL_ASSERT(0);
}

void init_queue(queue_t *q, int num_threads)
{
	int i, j;

	/* Initialize each thread's free list with INITIAL_FREE pointers */
	/* The actual nodes are initialized with poison indexes */
	free_lists = ( unsigned int (*)[MAX_FREELIST] ) malloc(num_threads * sizeof(*free_lists));
	for (i = 0; i < num_threads; i++) {
		for (j = 0; j < INITIAL_FREE; j++) {
			free_lists[i][j] = 2 + i * MAX_FREELIST + j;
			atomic_init(&q->nodes[free_lists[i][j]].next, MAKE_POINTER(POISON_IDX, 0));
		}
	}

	/* initialize queue */
	atomic_init(&q->head, MAKE_POINTER(1, 0));
	atomic_init(&q->tail, MAKE_POINTER(1, 0));
	atomic_init(&q->nodes[1].next, MAKE_POINTER(0, 0));
}

/** @DeclareState: IntList *q;
@Initial: q = new IntList;
@Print:
	model_print("\tSTATE(q): ");
    printContainer(q);
	model_print("\n"); */

/** @Transition: STATE(q)->push_back(val);
@Print: model_print("\tENQ #%d: val=%d\n", ID, val); */
void enqueue(queue_t *q, unsigned int val, int n)
{
	int success = 0;
	unsigned int node;
	pointer tail;
	pointer next;
	pointer tmp;

	node = new_node();
	//store_32(&q->nodes[node].value, val);
	q->nodes[node].value = val;
	tmp = atomic_load_explicit(&q->nodes[node].next, relaxed);
	set_ptr(&tmp, 0); // NULL
    // XXX-known-bug-#1: This is a found bug in AutoMO, and testcase4 can reveal
    // this known bug.
    // To reproduce, weaken the parameter "memory_order_release" to
    // "memory_order_relaxed", run "make" to recompile, and then run:
    // "./run.sh ./ms-queue/testcase4 -m2 -y -u3 -tSPEC"
	/**********    Detected KNOWN BUG (testcase4)    **********/
	atomic_store_explicit(&q->nodes[node].next, tmp, release);

	while (!success) {
        // XXX-injection-#1: To reproduce, weaken the parameter
        // "memory_order_acquire" to "memory_order_relaxed", run "make" to
        // recompile, and then run:
        // "./run.sh ./ms-queue/testcase2 -m2 -y -u3 -tSPEC"
		/**********    Detected UL (testcase2)    **********/
		tail = atomic_load_explicit(&q->tail, acquire);
        // XXX-injection-#2: To reproduce, weaken the parameter
        // "memory_order_acquire" to "memory_order_relaxed", run "make" to
        // recompile, and then run:
        // "./run.sh ./ms-queue/testcase4 -m2 -y -u3 -tSPEC"
		/**********    Detected Correctness (testcase4)    **********/
		next = atomic_load_explicit(&q->nodes[get_ptr(tail)].next, acquire);
		if (tail == atomic_load_explicit(&q->tail, relaxed)) {

			/* Check for uninitialized 'next' */
			//MODEL_ASSERT(get_ptr(next) != POISON_IDX);

			if (get_ptr(next) == 0) { // == NULL
				pointer value = MAKE_POINTER(node, get_count(next) + 1);
                // XXX-injection-#3: To reproduce, weaken the parameter
                // "memory_order_release" to "memory_order_relaxed", run "make" to
                // recompile, and then run:
                // "./run.sh ./ms-queue/testcase1 -m2 -y -u3 -tSPEC"
				/**********    Detected Correctness (testcase1)    **********/
				success = atomic_compare_exchange_strong_explicit(&q->nodes[get_ptr(tail)].next,
						&next, value, release, release);
				/** @OPClearDefine: success */
			}
			if (!success) {
                // XXX-injection-#4: To reproduce, weaken the parameter
                // "memory_order_acquire" to "memory_order_relaxed", run "make" to
                // recompile, and then run:
                // "./run.sh ./ms-queue/testcase2 -m2 -y -u3 -tSPEC"
				/**********    Detected UL (testcase2)    **********/
				unsigned int ptr = get_ptr(atomic_load_explicit(&q->nodes[get_ptr(tail)].next, acquire));
				pointer value = MAKE_POINTER(ptr,
						get_count(tail) + 1);
                // XXX-injection-#5: To reproduce, weaken the parameter
                // "memory_order_release" to "memory_order_relaxed", run "make" to
                // recompile, and then run:
                // "./run.sh ./ms-queue/testcase2 -m2 -y -u3 -tSPEC"
				/**********    Detected Correctness (testcase2)    **********/
				atomic_compare_exchange_strong_explicit(&q->tail,
						&tail, value,
						release, release);
				thrd_yield();
			}
		}
	}

    // XXX-injection-#6: To reproduce, weaken the parameter
    // "memory_order_release" to "memory_order_relaxed", run "make" to
    // recompile, and then run:
    // "./run.sh ./ms-queue/testcase1 -m2 -y -u3 -tSPEC"
	/**********    Detected Correctness (testcase1) **********/
	atomic_compare_exchange_strong_explicit(&q->tail,
			&tail,
			MAKE_POINTER(node, get_count(tail) + 1),
			release, release);
}

/** @Transition: S_RET = STATE(q)->empty() ? 0 : STATE(q)->front();
if (S_RET && C_RET) STATE(q)->pop_front();
@JustifyingPostcondition: if (!C_RET)
    return S_RET == C_RET;
@PostCondition: return C_RET ? *retVal  == S_RET : true;
@Print: model_print("\tDEQ #%d: C_RET=%d && *retVal=%d && S_RET=%d\n", ID,
            C_RET, *retVal, S_RET);
*/
int dequeue(queue_t *q, unsigned int *retVal, unsigned int *reclaimNode)
{
	int success = 0;
	pointer head;
	pointer tail;
	pointer next;

	while (!success) {
        // XXX-injection-#7: To reproduce, weaken the parameter
        // "memory_order_acquire" to "memory_order_relaxed", run "make" to
        // recompile, and then run:
        // "./run.sh ./ms-queue/testcase3 -m2 -y -u3 -tSPEC"
		/**********    Detected Correctness (testcase3)    **********/
		head = atomic_load_explicit(&q->head, acquire);
        // To reproduce, weaken the parameter "memory_order_acquire" to
        // "memory_order_relaxed", run "make" to recompile, and then run:
        // "./run.sh ./ms-queue/testcase4 -m2 -y -u3 -tSPEC"
        // XXX-known-bug-#2: This is another known bug, and testcase2 can reveal
        // this known bug
		/**********    Detected KNOWN BUG (testcase2)    **********/
		tail = atomic_load_explicit(&q->tail, acquire);

        // XXX-injection-#8: To reproduce, weaken the parameter
        // "memory_order_acquire" to "memory_order_relaxed", run "make" to
        // recompile, and then run:
        // "./run.sh ./ms-queue/testcase1 -m2 -y -u3 -tSPEC"
		/**********    Detected Correctness (testcase1) **********/
		next = atomic_load_explicit(&q->nodes[get_ptr(head)].next, acquire);
		/** @OPClearDefine: true */
		if (atomic_load_explicit(&q->head, relaxed) == head) {
			if (get_ptr(head) == get_ptr(tail)) {

				/* Check for uninitialized 'next' */
				MODEL_ASSERT(get_ptr(next) != POISON_IDX);

				if (get_ptr(next) == 0) { // NULL
					return false; // NULL
				}

                // XXX-injection-#9: To reproduce, weaken the parameter
                // "memory_order_release" to "memory_order_relaxed", run "make" to
                // recompile, and then run:
                // "./run.sh ./ms-queue/testcase2 -m2 -y -u3 -tSPEC"
				/**********    Detected UL (testcase2)    **********/
				atomic_compare_exchange_strong_explicit(&q->tail,
						&tail,
						MAKE_POINTER(get_ptr(next), get_count(tail) + 1),
						release, release);
				thrd_yield();
			} else {
				//*retVal = load_32(&q->nodes[get_ptr(next)].value);
				*retVal = q->nodes[get_ptr(next)].value;

                // XXX-injection-#10: To reproduce, weaken the parameter
                // "memory_order_release" to "memory_order_relaxed", run "make" to
                // recompile, and then run:
                // "./run.sh ./ms-queue/testcase3 -m2 -y -u3 -tSPEC"
				/**********    Detected Correctness (testcase3)    **********/
				success = atomic_compare_exchange_strong_explicit(&q->head,
						&head,
						MAKE_POINTER(get_ptr(next), get_count(head) + 1),
						release, release);
				if (!success)
					thrd_yield();
			}
		}
	}
	*reclaimNode = get_ptr(head);
	reclaim(get_ptr(head));
	return true;
}
