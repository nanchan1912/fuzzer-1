# SGF — Skeleton Graph Fuzzer (Standalone Rebuild)

A standalone concurrency fuzzer that mutates an abstract graph of memory events (reads, writes, RMWs, CASes, fences, and their reads-from/modification-order relationships) rather than raw input bytes, searching for weak-memory-model bugs — data races and hangs that only manifest under specific thread interleavings.

---

## Quick Start

### Prerequisites

- **Linux** (Ubuntu 20.04+ recommended, or WSL2)
- GCC / G++ with C++17 support (`g++`, `gcc`)
- GNU Make (`make`)
- Python 3 with dev headers (`python3-dev`)
- `zlib1g-dev`
- (Optional, only for **generating new benchmarks** from source — see below) Nix, for the SVF + LLVM 16 toolchain

### 1. Unified One-Command Runner (`run.sh`)

The easiest way to run testcases and benchmarks is the unified [`run.sh`](run.sh) at the root of `FUZZER_Rebuilt/`. It automatically builds `sgf-fuzz` and compiles testcase sources if needed.

```bash
cd FUZZER_Rebuilt

# Built-in testcases (10s default duration)
./run.sh msg_passing          # Message Passing (alias: mp)
./run.sh sb                   # Store Buffering (alias: sb-loop, store_buffering)
./run.sh load_buffering       # Load Buffering (alias: lb)
./run.sh mp_loc                # MP with locations
./run.sh mp_ra                 # MP with release-acquire
./run.sh isJson                 # JSON input parser test

# Custom duration
./run.sh --time 30 msg_passing

# Run until the first crash is found instead of a fixed duration
./run.sh barrier --until-crash

# Choose a queue implementation (see "Queue Data Structures" below)
./run.sh --queue threshold_bucket msg_passing
./run.sh --queue runner_up sb
./run.sh --queue maxheap_bucket load_buffering

# Sanity-check all 4 queue implementations
./run.sh test_queues

# Run a benchmark from pthread_version_of_benchmarks (once generated -- see below)
./run.sh barrier
./run.sh mcs-lock

# Fully custom target
./run.sh -i /path/to/seeds -v /path/to/graph.ccfg -o /tmp/my_out -- /path/to/binary
```

**All `run.sh` flags:**

| Flag | Description |
|------|-------------|
| `-q, --queue <NAME>` | Queue implementation: `maxheap` (default), `threshold_bucket`, `runner_up`, `maxheap_bucket` |
| `-t, --time <SECONDS>` | Fuzzing duration in seconds (default: 10) |
| `-c, --until-crash` | Run with no time limit, until the first crash is found |
| `-i, --input <PATH>` | Seed input directory or JSON seed file |
| `-o, --output <PATH>` | Output directory (default: `/tmp/sgf_out_<target>`) |
| `-v, --graph <PATH>` | Static abstraction graph (`.ccfg` / `.eg` / `.pg`) |
| `-h, --help` | Show help |

### 2. Manual Build & Run

```bash
cd FUZZER_Rebuilt/Main
make sgf-fuzz           # just the fuzzer
make all                 # sgf-fuzz, sgf-showmap, sgf-tmin, sgf-gotcpu, sgf-analyze
bash test_all_queues.sh  # sanity-check all 4 queue implementations
```

Compile a testcase target manually (only needed if `run.sh` hasn't already):
```bash
gcc -O0 -pthread testcases/msg_passing/mp.c -o testcases/msg_passing/mp
```

Run the fuzzer directly:
```bash
SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_SKIP_CPUFREQ=1 SGF_NO_AFFINITY=1 \
./sgf-fuzz -n \
  -i testcases/msg_passing/seeds \
  -o /tmp/fuzz_out_mp \
  -v testcases/msg_passing/mp_static_program_abstraction.eg \
  -- ./testcases/msg_passing/mp
```

With a specific queue and until-crash instead of a time limit:
```bash
SGF_QUEUE_IMPL=runner_up SGF_BENCH_UNTIL_CRASH=1 \
SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_SKIP_CPUFREQ=1 SGF_NO_AFFINITY=1 \
./sgf-fuzz -n \
  -i testcases/load_buffering/seeds \
  -o /tmp/fuzz_out_lb \
  -v testcases/load_buffering/lb_static_program_abstraction.eg \
  -- ./testcases/load_buffering/lb
```

---

## Queue Data Structures

All four queues implement candidate selection — which mutated graph to mutate next. They exist to answer one question: **does giving up strict greedy selection, in exchange for bounded memory and some randomness among top candidates, help or hurt fuzzing effectiveness?**

| Config value | Class | What it actually does |
|---|---|---|
| `maxheap` (default) | `MaxHeapDS` | Unbounded. Always pops the single true best-scoring candidate ever seen. The ground-truth baseline everything else is measured against. |
| `threshold_bucket` | `ThresholdBucketQueueDS` | Bounds the pool to the top-`m` candidates (a "good pile"), but selection pops an arbitrary leaf, not necessarily the best. Everything that doesn't make the cut goes to an unbounded "bad pile," and the whole pool is rebuilt from scratch every `T` operations (quickselect over good+bad piles combined). |
| `runner_up` | `RunnerUpQueueDS` | Same bounded top-`m` pool and same "pop a leaf, not the best" selection as `threshold_bucket`, but replaces the periodic full rebuild with a small, incrementally-maintained "runner-up" buffer (capacity `r`) that gets promoted into the pool as items are selected — no rebuild stalls. |
| `maxheap_bucket` | `MaxHeapBucketQueueDS` | The hybrid: bounded top-`m` pool and a runner-up promotion buffer like the other two tiered structures, but selection always pops the **true maximum** (a genuine max-heap), isolating whether bounded memory alone — without giving up greediness — changes fuzzing behavior. |

All four share the unified C interface in [`include/sgf-queue.h`](Main/include/sgf-queue.h):
`sgf_queue_create(impl_name, m, r, bad_cap)`, `sgf_queue_enqueue`, `sgf_queue_dequeue`, `sgf_queue_update_score`, `sgf_queue_size`, `sgf_queue_destroy`.

Reference implementations (Python + C++, used to validate the production C queues) live in [`datastructs/`](../datastructs/) at the repo root.

### Selecting a queue at runtime

No recompilation needed — set `SGF_QUEUE_IMPL` (or use `run.sh --queue`):

```bash
SGF_QUEUE_IMPL=maxheap          ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target
SGF_QUEUE_IMPL=threshold_bucket ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target
SGF_QUEUE_IMPL=runner_up        ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target
SGF_QUEUE_IMPL=maxheap_bucket   ./sgf-fuzz -n -i seeds -o out -v graph.eg -- ./target
```

Verify the active queue at startup by checking the banner, e.g.:

---

## Extended Benchmarks (`pthread_version_of_benchmarks/`)

27 real concurrent pthread programs (run `ls pthread_version_of_benchmarks/` for the exact current list), including:
- `barrier/`, `barrier-change/`, `barrier-ori/` — Barrier synchronization
- `chase-lev-deque/`, `chasechange/` — Work-stealing deque
- `dekker-change/`, `dekker-fences/` — Dekker's mutual exclusion
- `mcs-lock/`, `mcs-change/`, `mcs2/` — Scalable MCS locks
- `mpmc-queue/`, `mpmc-change/`, `mpmc3/` — Multi-producer multi-consumer queue
- `ms-queue/`, `mschange/`, `ms-queue-tsan11/` — Michael-Scott queue
- `linuxrwlocks/`, `linuxrwchange/` — Linux reader-writer locks
- `ringbuffer/`, `rwqueue/` — Lockless ring buffer / read-write queue
- `sb-loop/` — Store buffering loop
- `spsc-queue/` — Single-producer single-consumer queue
- `iris/` — IRIS benchmark
- `check_arrays/`, `check_loops/`, `test-array/`, `test-mp/`, `test-struct/` — smaller correctness checks

Unlike the built-in testcases, these ship as raw source — you generate each benchmark's compiled, instrumented binary and static graph yourself.

> **Name collision warning:** `run.sh` treats `sb-loop` as an alias for the *built-in* `sb`/`store_buffering` testcase (`Main/testcases/sb/`), not the `pthread_version_of_benchmarks/sb-loop/` folder. Running `./run.sh sb-loop` after generating the benchmark will silently fuzz the built-in testcase instead. To fuzz the generated benchmark specifically, point at its files explicitly:
> ```bash
> ./run.sh -i pthread_version_of_benchmarks/sb-loop/data/init.sg.json \
>          -v pthread_version_of_benchmarks/sb-loop/data/generated_output.ccfg \
>          -- pthread_version_of_benchmarks/sb-loop/data/sb-loop.instrumented.out
> ```

### Generating a benchmark

```bash
cd FUZZER_Rebuilt/pthread_version_of_benchmarks
./generate_one.sh barrier      # or any other benchmark name
```

This runs the real pipeline for that one benchmark: compile to LLVM IR → SVF static analysis → `.ccfg`/seed-graph generation → LLVM instrumentation (injects the scheduler hooks) → compile to native binaries. Populates `<benchmark>/data/` with everything `run.sh` needs. Requires the Nix devShell (`nix develop` from the repo root) for the SVF + LLVM 16 toolchain the first time.

### Fuzzing a generated benchmark

```bash
cd FUZZER_Rebuilt
./run.sh barrier
./run.sh barrier -q runner_up -c        # a different queue, until first crash
```

### Comparing all 4 queues on a benchmark

```bash
cd FUZZER_Rebuilt
for impl in maxheap threshold_bucket runner_up maxheap_bucket; do
  echo "=== $impl ==="
  ./run.sh barrier -q "$impl" -t 60
done
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `SGF_QUEUE_IMPL` | `maxheap` | Active queue: `maxheap`, `threshold_bucket`, `runner_up`, `maxheap_bucket` |
| `SGF_BENCH_UNTIL_CRASH` | `0` | Exit as soon as the first crashing input is found (set automatically by `run.sh -c`) |
| `SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES` | `0` | Skip OS core_pattern crash-handling abort |
| `SGF_SKIP_CPUFREQ` | `0` | Skip CPU frequency scaling checks |
| `SGF_NO_AFFINITY` | `0` | Disable binding to a specific CPU core |
| `SGF_ENABLE_FEEDBACK` | `0` | Enable simulator feedback for mutations |
| `SGF_CHECK_DATA_RACE` | `0` | Enable data race detection (adds a `saved races` row to the live UI) |
| `SGF_SKELETON_GRAPH_HIGHEST_STEP` | `3` | Maximum depth of mutation tree per cycle |
| `SGF_CUTOFF_PERCENTILE` | `0` | Dynamic cutoff percentile for score filtering |

---

## Key Source Files

| File | Purpose |
|------|---------|
| `run.sh` | Top-level one-command unified runner |
| `Main/GNUmakefile` | Primary build system |
| `Main/test_all_queues.sh` | Automated queue verification script |
| `Main/src/sgf-fuzz.c` | Main fuzzer entry point and CLI |
| `Main/src/sgf-fuzz-one.c` | Core mutation pipeline (`mutate_run_enqueue_graph`) |
| `Main/src/sgf-fuzz-run.c` | Target execution and simulator interfacing |
| `Main/src/sgf-fuzz-queue.c` | Candidate queue scoring and management |
| `Main/src/sgf-fuzz-state.c` | State initialization and runtime queue instantiation |
| `Main/src/sgf-queue-dispatch.c` | Queue runtime selection and abstraction dispatch |
| `Main/src/sgf-queue-maxheap.c` | `maxheap` implementation (default) |
| `Main/src/sgf-queue-threshold-bucket.c` | `threshold_bucket` implementation |
| `Main/src/sgf-queue-runner-up.c` | `runner_up` implementation |
| `Main/src/sgf-queue-maxheap-bucket.c` | `maxheap_bucket` implementation |
| `Main/src/skeleton_graph_mutator.cpp` | Skeleton graph mutation engine |
| `Main/src/skeleton_potential.cpp` | Potential/novelty scoring |
| `Main/src/data_race.cpp` | Data race detection |
| `Main/src/consistency.cpp` | Consistency validation |
| `Main/src/skeleton_mo_footprint.cpp` | Memory order footprint analysis |
| `Main/include/sgf-queue.h` | Queue API header |
| `Main/include/sgf-fuzz.h` | Main fuzzer state and data structures |
| `pthread_version_of_benchmarks/generate_one.sh` | Generates one benchmark's binaries/graphs |
| `pthread_version_of_benchmarks/run_all_analysis_compile.sh` | Full-suite generation pipeline (all 29 benchmarks) |
| `datastructs/` | Python + C++ reference implementations for all 4 queues |
