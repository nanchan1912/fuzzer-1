# Your Integration & Testing Plan

Everything is ready. Execute these commands in order.

## Phase 1: Code Integration (Already Partially Done ✓)

### ✓ DONE: Queue files copied to AFL_patches
```bash
# Already completed:
ls -la /home/claude/AFL_patches/src/afl-queue*.c
ls -la /home/claude/AFL_patches/include/afl-queue.h
```

### ✓ DONE: afl-fuzz.h updated
- Added: `#include "afl-queue.h"`
- Added: `afl_queue_t *bounded_queue;` to struct

### ✓ DONE: afl-fuzz-init.c updated
- Added queue initialization code

### TODO: Verify manually if needed
```bash
# Check afl-fuzz.h has the includes
grep -n "afl-queue.h" /home/claude/AFL_patches/include/afl-fuzz.h

# Check afl-fuzz-init.c has initialization
tail -20 /home/claude/AFL_patches/src/afl-fuzz-init.c
```

## Phase 2: Update GNUmakefile

The Makefile is at: `/home/claude/AFL_patches/GNUmakefile`

### Edit Line 35 (HEADERS)
**Find:**
```makefile
HEADERS = include/data_race.hpp include/afl-fuzz.h ... include/shm_next_events.h
```

**Add at the end:**
```makefile
include/afl-queue.h
```

### Edit Line ~580 (afl-fuzz build rule, dependencies)
**Find:**
```makefile
          src/shm_next_events.o \
          include/cmplog.h include/envs.h | test_x86
```

**Replace with:**
```makefile
          src/shm_next_events.o \
          src/afl-queue-maxheap.o \
          src/afl-queue-structure1.o \
          src/afl-queue-structure2.o \
          src/afl-queue-structure3.o \
          src/afl-queue-dispatch.o \
          include/cmplog.h include/envs.h | test_x86
```

### Edit Line ~595 (afl-fuzz build rule, link command)
**Find (in the CXX command):**
```makefile
    src/shm_next_events.o \
    -o $@ $(PYFLAGS) $(LDFLAGS) -lm
```

**Replace with:**
```makefile
    src/shm_next_events.o \
    src/afl-queue-maxheap.o \
    src/afl-queue-structure1.o \
    src/afl-queue-structure2.o \
    src/afl-queue-structure3.o \
    src/afl-queue-dispatch.o \
    -o $@ $(PYFLAGS) $(LDFLAGS) -lm
```

**Or use this shorthand (if vim/sed available):**
```bash
cd /home/claude/AFL_patches
sed -i '/src\/shm_next_events\.o \\$/a \          src/afl-queue-maxheap.o \\\n          src/afl-queue-structure1.o \\\n          src/afl-queue-structure2.o \\\n          src/afl-queue-structure3.o \\\n          src/afl-queue-dispatch.o \\' GNUmakefile
```

## Phase 3: Compile

```bash
cd /home/claude/AFL_patches

# Clean previous build
make clean

# Build
make -j4

# Should see at end:
# [+] afl-fuzz and supporting tools successfully built
```

## Phase 4: Verify

```bash
cd /home/claude/AFL_patches

# Test basic help
./afl-fuzz -h | head -5

# Test queue system loads (default: structure2)
./afl-fuzz -h | grep -i queue
# Should show: [AFL Queue] Using Structure 2 (RunnerUpQueue)
```

## Phase 5: Benchmark (Optional but Recommended)

### Set up test directory
```bash
cd /home/claude/AFL_patches/testcases

# Pick a test case (e.g., msg_passing)
cd msg_passing
ls -la
```

### Run all 4 queue implementations
```bash
cd /home/claude/AFL_patches

# Create output directories
mkdir -p out_maxheap out_structure1 out_structure2 out_structure3

# Test 1: MaxHeap (baseline, unbounded)
AFL_QUEUE_IMPL=maxheap timeout 60 ./afl-fuzz -i testcases/msg_passing/seeds -o out_maxheap -- ./testcases/msg_passing/mp &
sleep 2

# Test 2: Structure 1 (two-tier, periodic rebuild)
AFL_QUEUE_IMPL=structure1 timeout 60 ./afl-fuzz -i testcases/msg_passing/seeds -o out_structure1 -- ./testcases/msg_passing/mp &
sleep 2

# Test 3: Structure 2 (RECOMMENDED - three-tier, incremental)
AFL_QUEUE_IMPL=structure2 timeout 60 ./afl-fuzz -i testcases/msg_passing/seeds -o out_structure2 -- ./testcases/msg_passing/mp &
sleep 2

# Test 4: Structure 3 (three-tier, threshold-driven)
AFL_QUEUE_IMPL=structure3 timeout 60 ./afl-fuzz -i testcases/msg_passing/seeds -o out_structure3 -- ./testcases/msg_passing/mp &

# Wait for all to finish
wait
```

### Compare Results
```bash
cd /home/claude/AFL_patches

echo "=== Queue Sizes (seeds found) ==="
for impl in maxheap structure1 structure2 structure3; do
  count=$(ls out_$impl/queue/ 2>/dev/null | wc -l)
  echo "$impl: $count seeds"
done

echo ""
echo "=== Coverage stats ==="
for impl in maxheap structure1 structure2 structure3; do
  if [ -f out_$impl/fuzzer_stats ]; then
    echo "=== $impl ==="
    grep "unique" out_$impl/fuzzer_stats
  fi
done
```

## Expected Outputs

**After compilation:**
```
[+] afl-fuzz and supporting tools successfully built
```

**After verification:**
```
./afl-fuzz -h
       afl-fuzz 4.05c by Michal Zalewski, ...
...
[AFL Queue] Using Structure 2 (RunnerUpQueue)
Queue implementation: structure2 (m=500, r=100, bad_cap=100000)
```

**After benchmark (example):**
```
=== Queue Sizes (seeds found) ===
maxheap: 42 seeds
structure1: 41 seeds
structure2: 42 seeds
structure3: 40 seeds
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `afl-queue.h: No such file` | Verify: `ls /home/claude/AFL_patches/include/afl-queue.h` |
| `undefined reference to afl_queue_*` | Check: Queue .o files added to GNUmakefile line ~580-595 |
| Build fails | Run: `make clean` then `make -j4` again |
| Queue shows "not found" | Check: `AFL_QUEUE_IMPL` spelling (maxheap, structure1, structure2, structure3) |
| No queue message on startup | May already have AFL binary cached. Run `make clean && make -j4` |

## Summary

- ✅ Queue files: Already in place
- ✅ Code edits: afl-fuzz.h, afl-fuzz-init.c already done
- TODO: Update GNUmakefile (2 locations)
- TODO: Compile
- TODO: Verify & Test

**Total time: 15 minutes (manual edits) + 5 minutes (compile) + 60 minutes (benchmarks)**

---

## Files & Paths

```
/home/claude/
├── AFL_patches/
│   ├── GNUmakefile              ← EDIT THIS (2 places)
│   ├── include/
│   │   ├── afl-queue.h          ✅ DONE (copied)
│   │   └── afl-fuzz.h           ✅ DONE (edited)
│   └── src/
│       ├── afl-fuzz-init.c      ✅ DONE (edited)
│       ├── afl-queue-maxheap.c   ✅ DONE (copied)
│       ├── afl-queue-structure1.c ✅ DONE (copied)
│       ├── afl-queue-structure2.c ✅ DONE (copied)
│       ├── afl-queue-structure3.c ✅ DONE (copied)
│       └── afl-queue-dispatch.c  ✅ DONE (copied)
│
└── pthread_version_of_benchmarks/    ← TEST TARGETS
    ├── msg_passing/
    ├── barrier/
    ├── chase-lev-deque/
    ├── ... (30+ more benchmarks)
```

---

**Next: Edit GNUmakefile, compile, and test!**
