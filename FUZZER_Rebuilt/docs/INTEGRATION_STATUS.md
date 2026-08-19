# Rebuilt Fuzzer — Integration & Verification Status

**Status:** ✅ **100% INTEGRATED, COMPILED & VERIFIED**

The standalone fuzzer has been completely rebuilt, verified against `AFL_MUTATOR`, and tested with all 4 swappable queue data structures.

---

## 1. Summary of Completed Work

| Component | Status | Details |
|---|---|---|
| **Queue API Abstraction** | ✅ Complete | `include/afl-queue.h` defines clean C interface (`afl_queue_create`, `afl_queue_enqueue`, `afl_queue_dequeue`, `afl_queue_update_score`, `afl_queue_size`, `afl_queue_stats`, `afl_queue_destroy`) |
| **MaxHeap Queue** | ✅ Complete (DEFAULT) | `src/afl-queue-maxheap.c` implements `MaxHeapDS` baseline |
| **Structure 1 Queue** | ✅ Complete | `src/afl-queue-structure1.c` implements `ThresholdBucketQueueDS` (two-tier + periodic rebuild) |
| **Structure 2 Queue** | ✅ Complete | `src/afl-queue-structure2.c` implements `RunnerUpQueueDS` (three-tier incremental) |
| **Structure 3 Queue** | ✅ Complete | `src/afl-queue-structure3.c` implements `MaxHeapBucketQueueDS` (three-tier + threshold) |
| **Queue Dispatch Layer** | ✅ Complete | `src/afl-queue-dispatch.c` routes operations via function pointer table |
| **Queue State Initialization** | ✅ Complete | `src/afl-fuzz-state.c` initializes queue with `maxheap` as default |
| **Queue Integration (Selection)** | ✅ Complete | `src/afl-fuzz.c` (line 3284) dequeues candidate from bounded queue |
| **Queue Integration (Mutation)** | ✅ Complete | `src/afl-fuzz-one.c` (`mutate_run_enqueue_graph`) enqueues mutated children |
| **Initial Corpus Seeding** | ✅ Complete | `src/afl-fuzz.c` (line 2893) seeds initial corpus into bounded queue |
| **AFL Buffer Resizing Fix** | ✅ Complete | `src/afl-fuzz-state.c` preserves `SKELETON_GRAPH_MAP_SIZE` during buffer resizing |
| **Program Abstraction Parser Fix**| ✅ Complete | `src/skeleton_mutator_helper.cpp` properly handles inline comments in `.eg` files |
| **RF Coverage Integration** | ✅ Complete | `src/afl-fuzz-one.c` updates `rf_coverage` alongside `mo_coverage` matching `AFL_MUTATOR` |
| **Build System** | ✅ Complete | `GNUmakefile` updated and builds `afl-fuzz` with zero errors |
| **Unit & End-to-End Tests** | ✅ Complete | All 4 queue options tested and passed on multiple testcases |

---

## 2. Directory Layout

```
FUZZER_Rebuilt/
├── Main/                              ← Standalone Fuzzer Source & Binaries
│   ├── afl-fuzz                       ← Compiled fuzzer binary
│   ├── GNUmakefile                    ← Build system
│   ├── include/
│   │   ├── afl-queue.h                ← Swappable queue interface
│   │   ├── afl-fuzz.h                 ← Fuzzer header
│   │   ├── skeleton_graph.hpp         ← Execution graph model
│   │   ├── skeleton_potential.hpp     ← Novelty scoring model
│   │   └── ...
│   ├── src/
│   │   ├── afl-queue-maxheap.c        ← Default MaxHeap implementation
│   │   ├── afl-queue-structure1.c     ← Structure 1 implementation
│   │   ├── afl-queue-structure2.c     ← Structure 2 implementation
│   │   ├── afl-queue-structure3.c     ← Structure 3 implementation
│   │   ├── afl-queue-dispatch.c       ← Queue runtime dispatch
│   │   ├── afl-fuzz-one.c             ← Core mutation pipeline
│   │   ├── afl-fuzz.c                 ← Main loop & seed selection
│   │   └── ...
│   ├── test_all_queues.sh             ← Automated test suite for all 4 queues
│   └── testcases/                     ← Built-in testcases (msg_passing, sb, load_buffering, etc.)
│
├── pthread_version_of_benchmarks/     ← 30+ concurrent benchmark programs
│   ├── run_afl.sh                     ← Benchmark runner script
│   ├── sb-loop/                       ← Store-buffering loop scene
│   ├── barrier/                       ← Barrier synchronization benchmark
│   ├── chase-lev-deque/               ← Chase-Lev work-stealing deque
│   └── ...
│
├── docs/                              ← Documentation
└── README.md                          ← Main user guide and quick start
```

---

## 3. How to Build

```bash
cd FUZZER_Rebuilt/Main
make clean
make afl-fuzz
```

---

## 4. How to Run and Switch Queues

### Default (MaxHeap)
```bash
cd FUZZER_Rebuilt/Main
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
  ./afl-fuzz -n \
  -i testcases/msg_passing/seeds \
  -o /tmp/fuzz_out \
  -v testcases/msg_passing/mp_static_program_abstraction.eg \
  -- ./testcases/msg_passing/mp
```

### Switching to Structure 1, 2, or 3
Set `AFL_QUEUE_IMPL`:
```bash
AFL_QUEUE_IMPL=structure1 ... ./afl-fuzz ...
AFL_QUEUE_IMPL=structure2 ... ./afl-fuzz ...
AFL_QUEUE_IMPL=structure3 ... ./afl-fuzz ...
AFL_QUEUE_IMPL=maxheap    ... ./afl-fuzz ...
```

### Run All 4 Tests Automatically
```bash
cd FUZZER_Rebuilt/Main
bash test_all_queues.sh
```
