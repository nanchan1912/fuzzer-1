/*
 * Dekker's critical section algorithm, implemented with fences.
 *
 * URL:
 *   http://www.justsoftwaresolutions.co.uk/threading/
 */

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "librace.h"

atomic_bool flag0, flag1;   //e1, e2
atomic_int turn;    //e3
atomic_int value;
uint32_t var = 0;   //e4
int LOOPNUM = 1;

void* p0(void* arg)
{
    (void)arg;

    atomic_store_explicit(&flag0, true, memory_order_relaxed);  //e8

    for (int i = 0; i < 1; i++)
    {
        atomic_store_explicit(&value, 1, memory_order_relaxed);
    }

    while (atomic_load_explicit(&flag1, memory_order_relaxed))  //e9
    {
        if (atomic_load_explicit(&turn, memory_order_relaxed) != 0) //e10
        {
            atomic_store_explicit(&flag0, false, memory_order_relaxed); //e11
            while (atomic_load_explicit(&turn, memory_order_relaxed) != 0)  //e12
            {
                sched_yield();
            }
            atomic_store_explicit(&flag0, true, memory_order_relaxed);  //e13
            atomic_thread_fence(memory_order_seq_cst);                  //e14
        }
        else
            sched_yield();
    }
    atomic_thread_fence(memory_order_acquire);      //e15

    // critical section
    store_32(&var, 1);      //e16

    atomic_store_explicit(&turn, 1, memory_order_relaxed);      //e17
    atomic_thread_fence(memory_order_release);      //e18
    atomic_store_explicit(&flag0, false, memory_order_relaxed);     //e19

    return NULL;
}


void* p1(void* arg)
{
    (void)arg;

    atomic_store_explicit(&flag1, true, memory_order_relaxed);  //e20
    atomic_thread_fence(memory_order_seq_cst);      //e21

    while (atomic_load_explicit(&flag0, memory_order_relaxed))      //e22
    {
        if (atomic_load_explicit(&turn, memory_order_relaxed) != 1)     //e23
        {
            atomic_store_explicit(&flag1, false, memory_order_relaxed); //e24
            while (atomic_load_explicit(&turn, memory_order_relaxed) != 1)  //e25
            {
                sched_yield();
            }
            atomic_store_explicit(&flag1, true, memory_order_relaxed);  //e26
            atomic_thread_fence(memory_order_seq_cst);      //e27
        }
        else
            sched_yield();
    }
    atomic_thread_fence(memory_order_acquire);      //e28

    // critical section
    store_32(&var, 2);      //e29

    atomic_store_explicit(&turn, 0, memory_order_relaxed);  //e30
    atomic_thread_fence(memory_order_release);      //e31
    atomic_store_explicit(&flag1, false, memory_order_relaxed); //e32

    return NULL;
}

int user_main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    atomic_init(&flag0, false); //e5
    atomic_init(&flag1, false); //e6
    atomic_init(&turn, 0);      //e7

    pthread_t a, b;

    pthread_create(&a, NULL, p0, NULL);
    pthread_create(&b, NULL, p1, NULL);

    pthread_join(a, NULL);
    pthread_join(b, NULL);

    return 0;
}
