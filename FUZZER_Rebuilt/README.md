# Concurrency Fuzzer — Standalone Rebuild

A standalone fuzzer for concurrent programs, rebuilt from the AFL_MUTATOR research system. Uses skeleton graph-based mutation with swappable queue data structures for candidate selection.

---

## Quick Start

### Prerequisites

- **Linux** (Ubuntu 20.04+ recommended, or WSL2)
- GCC / G++ with C++17 support
- GNU Make

### Build

```bash
cd fuzz3/FUZZER_Rebuilt/Main
make afl-fuzz
bash test_all_queues.sh
(this is to check if the queues run)

cd testcases/msg_passing
gcc -O0 -pthread mp.c -o mp
cd ../..
(compiling the testcase bianry)

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
./afl-fuzz -n \
  -i testcases/msg_passing/seeds \
  -o /tmp/fuzz_out \
  -v testcases/msg_passing/mp_static_program_abstraction.eg \
  -- ./testcases/msg_passing/mp

  AFL_QUEUE_IMPL=structure2 \
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
./afl-fuzz -n \
  -i testcases/msg_passing/seeds \
  -o /tmp/fuzz_out_s2 \
  -v testcases/msg_passing/mp_static_program_abstraction.eg \
  -- ./testcases/msg_passing/mp
(if i wanna use a different structure instead)


cd testcases/sb && gcc -O0 -pthread sb.c -o sb && cd ../..
./afl-fuzz -n -i testcases/sb/seeds -o /tmp/out_sb -v testcases/sb/sb_static_program_abstraction.eg -- ./testcases/sb/sb
(to run sb loop)


cd testcases/sb && gcc -O0 -pthread sb.c -o sb && cd ../..
./afl-fuzz -n -i testcases/sb/seeds -o /tmp/out_sb -v testcases/sb/sb_static_program_abstraction.eg -- ./testcases/sb/sb
(to run load buffer)


```

### Run (simplest test)

```bash
cd FUZZER_Rebuilt/Main

# Prepare seeds
mkdir -p /tmp/fuzz_in /tmp/fuzz_out
cp testcases/msg_passing/seeds/* /tmp/fuzz_in/

# Run with default queue (MaxHeap)
AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 \
  ./afl-fuzz -i /tmp/fuzz_in -o /tmp/fuzz_out \
  -t 3000 -v <path-to-static-graph> \
  -- <path-to-instrumented-target>
```

### Run a benchmark

Use the `run_afl.sh` script in `pthread_version_of_benchmarks/`:

```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

# Example: barrier benchmark
./run_afl.sh ./barrier/data/barrier.instrumented.out
```

The script automatically:
- Copies the initial seed to `in/`
- Sets necessary environment variables
- Runs the fuzzer with a 100-second timeout

---

## Queue Data Structures

### Four Available Implementations

| Name | Class | Description | Config Value |
|------|-------|-------------|--------------|
| **MaxHeap** (DEFAULT) | `MaxHeapDS` | Pure max-heap, always selects highest score. Unbounded. | `maxheap` |
| Structure 1 | `ThresholdBucketQueueDS` | Two-tier (good + bad pile), periodic rebuild every T ops | `structure1` |
| Structure 2 | `RunnerUpQueueDS` | Three-tier (good + runner-up + bad), incremental promotion | `structure2` |
| Structure 3 | `MaxHeapBucketQueueDS` | Three-tier with threshold-driven admission | `structure3` |

All four share the same API: `insert(cid, score)`, `select() → (cid, score)`, `update_score(cid, score)`.

### Which Is the Default?

**MaxHeap** is the default. If you run the fuzzer without setting `AFL_QUEUE_IMPL`, it uses MaxHeap.

### Where Is the Queue Selected?

The queue implementation is selected at **runtime** via the `AFL_QUEUE_IMPL` environment variable.

The selection happens in two places (both default to `"maxheap"`):
- [`src/afl-fuzz-state.c`](file:///d:/IIITH/fuzzermax/fuzz3/FUZZER_Rebuilt/Main/src/afl-fuzz-state.c) line 177-178: reads `AFL_QUEUE_IMPL` and creates the queue
- [`src/afl-queue-dispatch.c`](file:///d:/IIITH/fuzzermax/fuzz3/FUZZER_Rebuilt/Main/src/afl-queue-dispatch.c) line 123-125: dispatch fallback default

### How to Switch Queue Implementation

**Step 1:** Set the environment variable before running:

```bash
# Use MaxHeap (default — no env var needed)
./afl-fuzz -i in -o out -- ./target

# Use Structure 1 (ThresholdBucketQueue)
AFL_QUEUE_IMPL=structure1 ./afl-fuzz -i in -o out -- ./target

# Use Structure 2 (RunnerUpQueue)
AFL_QUEUE_IMPL=structure2 ./afl-fuzz -i in -o out -- ./target

# Use Structure 3 (MaxHeapBucketQueue)
AFL_QUEUE_IMPL=structure3 ./afl-fuzz -i in -o out -- ./target
```

**Step 2:** No rebuild required. The selection is at runtime.

**Step 3:** Verify by checking stderr output at startup:
```
[AFL Queue] Using MaxHeap (baseline, unbounded)
```
or
```
[AFL Queue] Using Structure 1 (ThresholdBucketQueue)
```

### How to Add a New Data Structure

1. Create `src/afl-queue-newstruct.c` implementing the 7 functions:
   `create`, `destroy`, `enqueue`, `dequeue`, `update_score`, `size`, `stats`
2. Add forward declarations in [`src/afl-queue-dispatch.c`](file:///d:/IIITH/fuzzermax/fuzz3/FUZZER_Rebuilt/Main/src/afl-queue-dispatch.c)
3. Add an `AflQueueOps` entry in the dispatch table
4. Add a new `strcmp` branch in `afl_queue_create()`
5. Add the `.c` file to the `afl-fuzz` target in [`GNUmakefile`](file:///d:/IIITH/fuzzermax/fuzz3/FUZZER_Rebuilt/Main/GNUmakefile)
6. Rebuild: `make clean && make afl-fuzz`

---

## Architecture

### Fuzzing Pipeline (from AFL_MUTATOR)

```
Seed (JSON skeleton graph)
        ↓
Load & parse skeleton graph
        ↓
Create/clone skeleton potential
        ↓
Mutate skeleton graph (skeleton_graph_mutator)
        ↓
Duplicate check (skeleton_graph_seen_or_add)
        ↓
Run on simulator (skeleton_graph_fuzz_stuff)
        ↓
Update potential & race pairs
        ↓
Update MO/RF coverage
        ↓
Calculate score (calculate_score)
        ↓
Dynamic cutoff check
        ↓
Enqueue into bounded queue (afl_queue_enqueue)
        ↓
Write to disk (JSON)
        ↓
Next iteration: dequeue from bounded queue → select parent → mutate
```

### Queue Abstraction

```
                        Fuzzer (afl-fuzz-one.c, afl-fuzz.c)
                              |
                              | afl_queue_enqueue()
                              | afl_queue_dequeue()
                              | afl_queue_size()
                              |
                        Queue API (afl-queue.h)
                              |
                     Dispatch (afl-queue-dispatch.c)
                              |
              +-------+-------+-------+-------+
              |               |               |               |
          MaxHeap        Structure1       Structure2       Structure3
       (afl-queue-   (afl-queue-      (afl-queue-      (afl-queue-
        maxheap.c)    structure1.c)    structure2.c)    structure3.c)

                     DEFAULT = MaxHeap
```

### Key Source Files

| File | Purpose |
|------|---------|
| `src/afl-fuzz.c` | Main entry point, main loop |
| `src/afl-fuzz-one.c` | `mutate_run_enqueue_graph()` — core mutation pipeline |
| `src/afl-fuzz-run.c` | `skeleton_graph_fuzz_stuff()` — simulator execution |
| `src/afl-fuzz-queue.c` | `calculate_score()`, queue management |
| `src/afl-fuzz-state.c` | State initialization, queue creation |
| `src/afl-queue-dispatch.c` | Queue abstraction dispatch |
| `src/afl-queue-maxheap.c` | MaxHeap queue implementation |
| `src/afl-queue-structure[1-3].c` | Tiered queue implementations |
| `src/skeleton_graph_mutator.cpp` | Graph mutation engine |
| `src/skeleton_potential.cpp` | Potential/novelty scoring |
| `src/data_race.cpp` | Data race detection |
| `src/consistency.cpp` | Consistency validation (RC20) |
| `src/skeleton_mo_footprint.cpp` | Memory order footprint analysis |
| `include/afl-queue.h` | Queue API header |
| `include/afl-fuzz.h` | Main fuzzer state/types |

---

## Benchmark Programs

### Built-in Testcases (`Main/testcases/`)

| Directory | Description |
|-----------|-------------|
| `msg_passing/` | Message passing pattern |
| `sb/` | Store buffering |
| `load_buffering/` | Load buffering |
| `mp_loc/` | Message passing with locations |
| `mp_ra/` | Message passing with release-acquire |
| `input_is_json/` | JSON-based inputs |

### Extended Benchmarks (`pthread_version_of_benchmarks/`)

30+ concurrent programs including:
- `barrier/`, `barrier-change/` — Barrier synchronization
- `chase-lev-deque/`, `chasechange/` — Chase-Lev work-stealing deque
- `dekker-change/`, `dekker-fences/` — Dekker's algorithm
- `mcs-lock/`, `mcs-change/` — MCS lock
- `mpmc-queue/`, `mpmc-change/` — Multi-producer multi-consumer queue
- `ms-queue/`, `mschange/` — Michael-Scott queue
- `linuxrwlocks/`, `linuxrwchange/` — Linux reader-writer locks
- `ringbuffer/` — Ring buffer
- `sb-loop/` — Store buffering loop (SB loop scene)
- `spsc-queue/` — Single-producer single-consumer queue
- `iris/` — IRIS benchmark

Each benchmark directory typically contains:
- `data/` with `.instrumented.out` (compiled target), `init.sg.json` (initial seed), `generated_output.ccfg` (static graph)
- `generate_ir.sh` — Script to compile/instrument the benchmark

### Running Benchmarks

```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

# Run a specific benchmark
./run_afl.sh ./barrier/data/barrier.instrumented.out

# With custom settings
AFL_ENABLE_FEEDBACK=1 AFL_CHECK_DATA_RACE=1 \
  ./run_afl.sh ./sb-loop/data/sb-loop.instrumented.out
```

### Comparing Queue Implementations

```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

# Test with each queue
for impl in maxheap structure1 structure2 structure3; do
  echo "=== Testing $impl ==="
  AFL_QUEUE_IMPL=$impl OUTPUT_DIR=out_$impl \
    ./run_afl.sh ./barrier/data/barrier.instrumented.out
done

# Compare results
for impl in maxheap structure1 structure2 structure3; do
  echo "$impl: $(ls out_$impl/default/queue/ 2>/dev/null | wc -l) seeds found"
done
```

---

## SB Loop Scene

The **sb-loop** (Store Buffering Loop) benchmark is located at:

```
pthread_version_of_benchmarks/sb-loop/
├── generate_ir.sh    ← Script to compile the benchmark
└── sb-loop.cc        ← Source code
```

This implements a store-buffering pattern in a loop, which is a classic weak memory model test case. To run it:

```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

# First compile (if not already compiled)
cd sb-loop && bash generate_ir.sh && cd ..

# Then fuzz
./run_afl.sh ./sb-loop/data/sb-loop.instrumented.out
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AFL_QUEUE_IMPL` | `maxheap` | Queue data structure: `maxheap`, `structure1`, `structure2`, `structure3` |
| `AFL_ENABLE_FEEDBACK` | `0` | Enable simulator feedback for mutations |
| `AFL_CHECK_DATA_RACE` | `0` | Enable data race detection |
| `AFL_SKELETON_GRAPH_HIGHEST_STEP` | `3` | Maximum depth of mutation tree per cycle |
| `AFL_CUTOFF_PERCENTILE` | `0` | Dynamic cutoff percentile for score filtering |
| `AFL_POTENTIAL_LOCATIONS_FILE` | — | Path to potential locations file |
| `AFL_INTERESTING_LOCATIONS_FILE` | — | Path to interesting locations file |
| `THREAD_EVENT_COUNTS` | — | Path to thread event counts file |

---

## Repository Structure

```
fuzz3/
├── fuzzer-1/                         ← Original reference repository
│   ├── AFL_MUTATOR/                  ← Source of truth for fuzzer logic
│   ├── AFLplusplus/                  ← Original AFL++ (background reference)
│   ├── datastructs/                  ← Source of truth for data structures
│   └── differences.txt              ← Diff between implementations
│
└── FUZZER_Rebuilt/                   ← Standalone rebuilt fuzzer
    ├── Main/                        ← Fuzzer implementation
    │   ├── include/                 ← Header files
    │   ├── src/                     ← Source files
    │   ├── GNUmakefile              ← Build system
    │   └── testcases/               ← Test inputs
    ├── pthread_version_of_benchmarks/ ← Extended benchmarks
    └── README.md                    ← This file
```
