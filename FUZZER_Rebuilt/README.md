# SGF — Concurrency Fuzzer (Standalone Rebuild)

A standalone skeleton graph-based concurrency fuzzer with swappable runtime queue data structures for candidate selection.

---

## Quick Start

### Prerequisites

- **Linux** (Ubuntu 20.04+ recommended, or WSL2)
- GCC / G++ with C++17 support (`g++`, `gcc`)
- GNU Make (`make`)
- Python 3 with dev headers (`python3-dev`)
- `zlib1g-dev`

---

### 1. Unified One-Command Runner (`run.sh`)

The easiest way to run testcases and benchmarks is using the unified [`run.sh`](file:///d:/IIITH/fuzzermax/fuzz3/fuzzer-1/FUZZER_Rebuilt/run.sh) script located at the root of `FUZZER_Rebuilt/` (or `Main/run.sh`). It automatically builds `sgf-fuzz` and compiles testcase sources if needed.

```bash
cd FUZZER_Rebuilt

# Run built-in testcases (runs with 10s default timeout)
./run.sh msg_passing          # Message Passing testcase (alias: mp)
./run.sh sb                   # Store Buffering testcase (alias: sb-loop)
./run.sh load_buffering       # Load Buffering testcase (alias: lb)
./run.sh mp_loc               # MP with locations
./run.sh mp_ra                # MP with release-acquire
./run.sh isJson               # JSON input parser test

# Run with custom duration (e.g. 30 seconds)
./run.sh --time 30 msg_passing

# Run with a different queue data structure
./run.sh --queue structure1 msg_passing
./run.sh --queue structure2 sb
./run.sh --queue structure3 load_buffering

# Run all 4 queue data structures to verify them
./run.sh test_queues

# Run benchmarks from pthread_version_of_benchmarks
./run.sh pthread_version_of_benchmarks/sb-loop/data/sb-loop.instrumented.out
./run.sh pthread_version_of_benchmarks/barrier/data/barrier.instrumented.out

# Run custom target with explicit inputs
./run.sh -i /path/to/seeds -v /path/to/graph.ccfg -o /tmp/my_out -- /path/to/binary
```

---

### 2. Manual Build & Run

If you want to build and run manually using `make` and `sgf-fuzz`:

#### Step 1: Build the Fuzzer
```bash
cd FUZZER_Rebuilt/Main

# Build the main SGF fuzzer
make sgf-fuzz

# Or build all tools (sgf-fuzz, sgf-showmap, sgf-tmin, sgf-gotcpu, sgf-analyze)
make all
```

#### Step 2: Test All 4 Queue Data Structures
```bash
bash test_all_queues.sh
```

#### Step 3: Compile Testcase Targets
```bash
# Message Passing
gcc -O0 -pthread testcases/msg_passing/mp.c -o testcases/msg_passing/mp

# Store Buffering
gcc -O0 -pthread testcases/sb/sb.c -o testcases/sb/sb

# Load Buffering
gcc -O0 -pthread testcases/load_buffering/lb.c -o testcases/load_buffering/lb
```

#### Step 4: Run Fuzzing Commands

**Default Queue (`maxheap`):**
```bash
SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_SKIP_CPUFREQ=1 SGF_NO_AFFINITY=1 \
./sgf-fuzz -n \
  -i testcases/msg_passing/seeds \
  -o /tmp/fuzz_out_mp \
  -v testcases/msg_passing/mp_static_program_abstraction.eg \
  -- ./testcases/msg_passing/mp
```

**Store Buffering:**
```bash
SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_SKIP_CPUFREQ=1 SGF_NO_AFFINITY=1 \
./sgf-fuzz -n \
  -i testcases/sb/seeds \
  -o /tmp/fuzz_out_sb \
  -v testcases/sb/generated_output.ccfg \
  -- ./testcases/sb/sb-loop.instrumented.out
```

**Load Buffering with Structure 2:**
```bash
SGF_QUEUE_IMPL=structure2 \
SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_SKIP_CPUFREQ=1 SGF_NO_AFFINITY=1 \
./sgf-fuzz -n \
  -i testcases/load_buffering/seeds \
  -o /tmp/fuzz_out_lb \
  -v testcases/load_buffering/lb_static_program_abstraction.eg \
  -- ./testcases/load_buffering/lb
```

---

## Queue Data Structures

### Four Available Implementations

| Name | Class | Description | Config Value |
|------|-------|-------------|--------------|
| **MaxHeap** (DEFAULT) | `MaxHeapDS` | Pure max-heap, always selects highest score. Unbounded. | `maxheap` |
| **Structure 1** | `ThresholdBucketQueueDS` | Two-tier (good + bad pile), periodic rebuild every T ops | `structure1` |
| **Structure 2** | `RunnerUpQueueDS` | Three-tier (good + runner-up + bad), incremental promotion | `structure2` |
| **Structure 3** | `MaxHeapBucketQueueDS` | Three-tier with threshold-driven admission | `structure3` |

All four share the unified C interface in [`include/sgf-queue.h`](file:///d:/IIITH/fuzzermax/fuzz3/fuzzer-1/FUZZER_Rebuilt/Main/include/sgf-queue.h):
- `sgf_queue_create(impl_name, m, r, bad_cap)`
- `sgf_queue_enqueue(q, entry_id, graph_data, score)`
- `sgf_queue_dequeue(q)`
- `sgf_queue_update_score(q, entry_id, new_score)`
- `sgf_queue_size(q)`
- `sgf_queue_destroy(q)`

### Selecting a Queue at Runtime

Queue selection occurs at runtime via the `SGF_QUEUE_IMPL` environment variable (no recompilation needed):

```bash
# MaxHeap (default)
SGF_QUEUE_IMPL=maxheap ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target

# Structure 1
SGF_QUEUE_IMPL=structure1 ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target

# Structure 2
SGF_QUEUE_IMPL=structure2 ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target

# Structure 3
SGF_QUEUE_IMPL=structure3 ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target
```

Or using the runner script:
```bash
./run.sh --queue structure2 msg_passing
```

Verify the active queue at startup by checking the banner:
```
[SGF Queue] Using Structure 2 (RunnerUpQueue)
```

---

## Extended Benchmarks (`pthread_version_of_benchmarks/`)

The repository contains 30+ concurrent pthread benchmarks including:
- `barrier/`, `barrier-change/` — Barrier synchronization
- `chase-lev-deque/`, `chasechange/` — Work-stealing deque
- `dekker-change/`, `dekker-fences/` — Dekker's mutual exclusion
- `mcs-lock/`, `mcs-change/` — Scalable MCS locks
- `mpmc-queue/`, `mpmc-change/` — Multi-producer multi-consumer queue
- `ms-queue/`, `mschange/` — Michael-Scott queue
- `linuxrwlocks/`, `linuxrwchange/` — Linux reader-writer locks
- `ringbuffer/` — Lockless ring buffer
- `sb-loop/` — Store Buffering loop
- `spsc-queue/` — Single-producer single-consumer queue
- `iris/` — IRIS benchmark

### Running Benchmarks via `run_sgf.sh`
```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

# Run barrier benchmark
./run_sgf.sh ./barrier/data/barrier.instrumented.out

# Run sb-loop benchmark
./run_sgf.sh ./sb-loop/data/sb-loop.instrumented.out

# Run with custom feedback and data race checks
SGF_ENABLE_FEEDBACK=1 SGF_CHECK_DATA_RACE=1 \
  ./run_sgf.sh ./sb-loop/data/sb-loop.instrumented.out
```

### Comparing All 4 Queues on a Benchmark
```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks

for impl in maxheap structure1 structure2 structure3; do
  echo "=== Running benchmark with $impl ==="
  SGF_QUEUE_IMPL=$impl OUTPUT_DIR=out_$impl MAX_TIME=30 \
    ./run_sgf.sh ./sb-loop/data/sb-loop.instrumented.out
done
```

---

## SB Loop Benchmark

The **sb-loop** (Store Buffering Loop) benchmark is located at `pthread_version_of_benchmarks/sb-loop/` and tested via:

```bash
cd FUZZER_Rebuilt

# Via unified runner
./run.sh sb-loop

# Or directly
./pthread_version_of_benchmarks/run_sgf.sh ./pthread_version_of_benchmarks/sb-loop/data/sb-loop.instrumented.out
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SGF_QUEUE_IMPL` | `maxheap` | Active queue structure: `maxheap`, `structure1`, `structure2`, `structure3` |
| `SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES` | `0` | Skip OS core_pattern crash handling aborts |
| `SGF_SKIP_CPUFREQ` | `0` | Skip CPU frequency scaling checks |
| `SGF_NO_AFFINITY` | `0` | Disable binding to a specific CPU core |
| `SGF_ENABLE_FEEDBACK` | `0` | Enable simulator feedback for mutations (0 or 1) |
| `SGF_CHECK_DATA_RACE` | `0` | Enable data race detection (0 or 1) |
| `SGF_SKELETON_GRAPH_HIGHEST_STEP` | `3` | Maximum depth of mutation tree per cycle |
| `SGF_CUTOFF_PERCENTILE` | `0` | Dynamic cutoff percentile for score filtering |
| `SGF_POTENTIAL_LOCATIONS_FILE` | — | Path to potential locations file (`.loc`) |
| `SGF_INTERESTING_LOCATIONS_FILE` | — | Path to interesting locations file (`.loc`) |
| `THREAD_EVENT_COUNTS` | — | Path to thread event counts file (`.tc`) |

---

## Key Source Files

| File | Purpose |
|------|---------|
| `run.sh` | Top-level one-command unified runner |
| `Main/GNUmakefile` | Primary build system (`make sgf-fuzz`, `make all`) |
| `Main/test_all_queues.sh` | Automated queue verification script |
| `Main/src/sgf-fuzz.c` | Main fuzzer entry point and CLI |
| `Main/src/sgf-fuzz-one.c` | Core mutation pipeline (`mutate_run_enqueue_graph`) |
| `Main/src/sgf-fuzz-run.c` | Target execution and simulator interfacing |
| `Main/src/sgf-fuzz-queue.c` | Candidate queue scoring and management |
| `Main/src/sgf-fuzz-state.c` | State initialization and runtime queue instantiation |
| `Main/src/sgf-queue-dispatch.c` | Queue runtime selection and abstraction dispatch |
| `Main/src/sgf-queue-maxheap.c` | MaxHeap queue implementation (default) |
| `Main/src/sgf-queue-structure1.c` | Structure 1 (ThresholdBucketQueue) |
| `Main/src/sgf-queue-structure2.c` | Structure 2 (RunnerUpQueue) |
| `Main/src/sgf-queue-structure3.c` | Structure 3 (MaxHeapBucketQueue) |
| `Main/src/skeleton_graph_mutator.cpp` | Skeleton graph mutation engine |
| `Main/src/skeleton_potential.cpp` | Potential/novelty scoring algorithm |
| `Main/src/data_race.cpp` | Data race detection |
| `Main/src/consistency.cpp` | Consistency validation |
| `Main/src/skeleton_mo_footprint.cpp` | Memory order footprint analysis |
| `Main/include/sgf-queue.h` | Queue API header |
| `Main/include/sgf-fuzz.h` | Main fuzzer state and data structures |
| `pthread_version_of_benchmarks/run_sgf.sh` | Benchmark runner script |
