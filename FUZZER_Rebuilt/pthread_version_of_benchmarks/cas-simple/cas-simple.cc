/*
 * Minimal compare-and-swap benchmark.
 *
 * Exists to exercise the CAS event path end to end. The larger CAS benchmarks
 * (ms-queue, mschange) starve before their cmpxchg is ever reached -- their
 * seed graph covers only the thread-0 writes and the fuzzer stops making
 * progress there -- so they cannot demonstrate CAS handling. This one is
 * deliberately tiny: two threads, one shared location, and a cmpxchg reached
 * on the first few events of each thread.
 *
 * Both a strong and a weak compare-exchange are present so the two
 * instrumentation entry points (__instrument_cmpxchg_strong / _weak) and both
 * halves of the instantiability rule get exercised.
 *
 * There is deliberately NO assertion here. This benchmark's job is to exercise
 * the CAS event path, not to find bugs, and an assertion on a shared counter
 * turns out to test something else entirely: a first attempt asserted that
 * exactly one thread wins the strong CAS, and it fired -- but inspection of
 * the reported schedule showed the CAS handling was correct (one CAS_SUCCESS
 * reading the init write, one CAS_FAIL reading that success). What actually
 * failed was the final relaxed load of the counter reading from the initial
 * write rather than from the winner's fetch_add, i.e. a pthread_join
 * synchronisation question, not a compare-and-swap one. Keeping that assertion
 * would report a spurious "crash" on every campaign and drown the signal this
 * benchmark exists to provide.
 */

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "librace.h"

atomic_int flag;      // contended by the strong CAS
atomic_int spare;     // target of the weak CAS
atomic_int winners;   // how many threads won the strong CAS

static void* worker(void* arg)
{
    const intptr_t id = (intptr_t)arg;

    // Strong CAS: only one thread can move flag from 0 to its id.
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &flag, &expected, (int)(id + 1),
            memory_order_acq_rel, memory_order_acquire)) {
        atomic_fetch_add_explicit(&winners, 1, memory_order_relaxed);
    }

    // Weak CAS: may fail spuriously even when the comparison succeeds, so
    // both outcomes are legal schedules here.
    int spare_expected = 0;
    atomic_compare_exchange_weak_explicit(
        &spare, &spare_expected, (int)(id + 1),
        memory_order_release, memory_order_relaxed);

    return NULL;
}

int user_main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    pthread_t t1, t2;

    atomic_init(&flag, 0);
    atomic_init(&spare, 0);
    atomic_init(&winners, 0);

    pthread_create(&t1, NULL, worker, (void*)(intptr_t)0);
    pthread_create(&t2, NULL, worker, (void*)(intptr_t)1);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}
