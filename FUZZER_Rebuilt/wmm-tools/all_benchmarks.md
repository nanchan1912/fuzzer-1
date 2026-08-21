# 1
**dekker-change/** - handled perfectly *[checked manually]*
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**dekker-fences/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**dekker-fences-ori/** - [redundant] no difference from dekker-fences

# 2
**mschange/** - ran without errors, gotta check the generated output
    - replaced the array of threads with a individual thread(s) and moved the thread creation and join operations outside loops
    - SOUNDNESS CHECK - passed
    - ~~CONTEXT INSENSITIVE COMPLETENESS CHECK - 250 missing edges ?~~  dealt with it by checking in a context sensitive way as ICFG is already context sensitive
    - COMPLETENESS CHECK - passed
**ms-queue/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**ms-queue-tsan11/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed

# 3
**barrier/**  
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**barrier-change/** - handled but in a field insenstive way *[checked manually]*
    - replaced the array of threads with a individual thread(s) and moved the thread creation and join operations outside loops
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**barrier-ori/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
  
# 4
**chasechange/** - ran without errors, gotta check the generated output
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**chase-lev-deque/** - ran without errors, gotta check the generated output
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**chase-lev-deque-copy/**  - [redundant] no difference from chase-lev-dequeue

# 5
**mcs2/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**mcs-change/** - ran without errors, gotta check the generated output; tried drawing the graph manually, but finding it hard..
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**mcs-lock/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**mcs-lock-oricopy/** - [redundant] no difference from mcs-lock

# 6
**mpmc2/** - [redundant] no difference from mpmc-queue
**mpmc3/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**mpmc-change/** - ~~seems to be running infinitely~~ - fixed it! running without errors now
    - replaced the array of threads with a individual thread(s) and moved the thread creation and join operations outside loops
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**mpmc-queue/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed

# 7
**linuxrwchange/**  - handled perfectly  *[checked manually]*
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
**linuxrwlocks/**
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed

# 8
**rwqueue/**
This has std::atomic constructs used in the header file. I have changed them to use stdatomic.h constructs - but there are compilation errors stemming from the #include <memory>
Without making that modification, the analysis does run, but I am afraid I might be missing some events or edges (or perhaps gettign additional ones - 
TODO: this requires checking against a small program with std::atomic and observing the behavior)

# 9
**ringbuffer/** 
This seems to be a supporting implementation which can be used in other benchmarks. 
Reason: It doesn't have any threads - so my analysis doesn't identify any shared variables
Reading about the SPSC queue at a high level, I found this - 
```
Ring Buffer Foundation: Most implementations use a fixed-size circular array (ring buffer) to avoid the overhead of dynamic memory allocation during high-speed operations
```
However, I also observed that this ringbuffer implementation is not used in the spsc-queue benchmark - 
TODO: I should also check the other set of benchmarks once (in the pctwm benchmarks dir)

# 10
**spsc-queue/**
This directory has 2 sets of files:
1. Actual Execution (`eventcount.h`, `queue.h`, `spsc-queue.cc`) - modified these to use pthreads and stdatomic.h
    - SOUNDNESS CHECK - passed
    - COMPLETENESS CHECK - passed
    - TODO: unit check: how the analysis work on std::mutex - this construct is present in `event_count.h`
2. Relacy based (`eventcount-relacy.h`, `queue-relacy.h`, `spsc-relacy.cc`)
    - Relacy framework is used to test all possible thread interleavings by simulation - I do not need to modify these files perhaps, since we are only interested in running our analysis on the actual execution using threads.

draft/
include/


# REAL WORLD BENCHMARKS

## 1. Silo
- ndb_thread class needs to be handled properly - requires careful modification to multiple .cc and .h files to use pthreads correctly in place of std::thread

## 2. Iris
- modified the benchmark to use pthreads instead of std::thread
- made an assumption that the value of n (number of worker threads) is always 10 and not passed as a command line arg - *REASON:* SVF doesn't support vector of threads. So, I hardcoded creation and joining of 10 worker threads
- was able to generate the required CCFG 
- SOUNDNESS CHECK - passed
- COMPLETENESS CHECK - passed

## 3. Mabain


