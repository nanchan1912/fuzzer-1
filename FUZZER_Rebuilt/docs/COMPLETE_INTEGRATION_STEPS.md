# Complete Integration Steps for Queue System

## Prerequisites

You have:
- `/workspaces/AFLplusplus/` — original AFL++ repo
- `AFL_patches/` directory with your modifications
- `GNUmakefile` in AFL++ src/ with afl-fuzz build rule at line 562

## Step 1: Copy Queue Code to AFL_patches

```bash
# From the outputs directory where I created the files:
cd /mnt/user-data/outputs/

# Copy queue implementation files
cp afl-queue.h ../AFL_patches/include/
cp afl-queue-maxheap.c ../AFL_patches/src/
cp afl-queue-structure1.c ../AFL_patches/src/
cp afl-queue-structure2.c ../AFL_patches/src/
cp afl-queue-structure3.c ../AFL_patches/src/
cp afl-queue-dispatch.c ../AFL_patches/src/

# Verify
ls -la ../AFL_patches/include/afl-queue.h
ls -la ../AFL_patches/src/afl-queue-*.c
```

## Step 2: Modify afl-fuzz.h (Add 2 lines)

**File:** `AFL_patches/include/afl-fuzz.h`

**Find this line** (around line 1-30):
```c
#include "afl-fuzz.h"
```

**Add after the includes section** (before the struct definition):
```c
#include "afl-queue.h"    /* NEW: bounded queue system */
```

**Find the `struct afl_state` definition** (around line 500-900), look for:
```c
  struct queue_entry **queue_buf;
```

**Add after that line:**
```c
  afl_queue_t *bounded_queue;         /* NEW: the bounded queue system */
  const char *queue_impl_name;        /* NEW: which implementation is active */
```

## Step 3: Modify afl-fuzz-init.c (Add ~10 lines)

**File:** `AFL_patches/src/afl-fuzz-init.c`

**Find:** The end of the initialization function (look for line with `setup_signal_handlers` or similar, around line 900-1000)

**Add this code block:**
```c
  /* Initialize bounded queue system */
  const char *impl_name = getenv("AFL_QUEUE_IMPL");
  if (!impl_name) {
    impl_name = "structure2";  /* Default to Structure 2 (RunnerUpQueue) */
  }
  
  afl->queue_impl_name = impl_name;
  afl->bounded_queue = afl_queue_create(impl_name, 500, 100, 100000);
  
  if (!afl->bounded_queue) {
    FATAL("Failed to initialize queue implementation: %s", impl_name);
  }
  
  ACTF("Queue implementation: %s (m=500, r=100, bad_cap=100000)", impl_name);
```

## Step 4: Modify afl-fuzz-one.c (Change 1 function call)

**File:** `AFL_patches/src/afl-fuzz-one.c`

**Find:** The function `mutate_run_enqueue_graph()` (around line 200-300)

**Look for:**
```c
    add_to_queue(afl, (u8 *)filename, (u32)json_len, 0);
```

**Replace with:**
```c
    /* Enqueue into bounded queue */
    if (afl_queue_enqueue(afl->bounded_queue, 
                          afl->queued_items,
                          NULL,  /* graph_data placeholder */
                          0.0) < 0) {
      WARNF("Failed to enqueue skeleton graph (out of memory?)");
      ck_free(filename);
      return NULL;
    }
```

(Note: `graph_data` would be the actual skeleton graph structure. This depends on your exact graph representation. If unsure, ask the programmer to map this.)

## Step 5: Modify afl-fuzz.c (Change seed selection)

**File:** `AFL_patches/src/afl-fuzz.c`

**Find:** The main fuzzing loop where `queue_buf[current_entry]` is accessed (around line 3500-3600)

**Look for something like:**
```c
afl->queue_cur = afl->queue_buf[afl->current_entry];
```

**Replace with:**
```c
/* Dequeue next seed from bounded queue */
AflQueueEntry *entry = afl_queue_dequeue(afl->bounded_queue);
if (!entry) {
  WARNF("Queue empty during fuzzing");
  continue;  /* or appropriate error handling */
}

afl->queue_cur = afl->queue_buf[entry->entry_id];
```

## Step 6: Update GNUmakefile (Add queue object files)

**File:** `AFL_patches/../GNUmakefile` (or wherever your Makefile is)

**Find line 35 (HEADERS):**
```makefile
HEADERS = include/data_race.hpp include/afl-fuzz.h ... include/shm_next_events.h
```

**Add to the end of HEADERS:**
```makefile
include/afl-queue.h
```

**Find line 562 (afl-fuzz build rule):**
```makefile
afl-fuzz: $(COMM_HDR) include/afl-fuzz.h \
          $(AFL_FUZZ_FILES:.c=.o) \
          src/afl-common.o src/afl-sharedmem.o src/afl-forkserver.o \
          ...
```

**Add these lines after `src/shm_next_events.o \` and before the CXX compile command:**
```makefile
          src/afl-queue-maxheap.o \
          src/afl-queue-structure1.o \
          src/afl-queue-structure2.o \
          src/afl-queue-structure3.o \
          src/afl-queue-dispatch.o \
```

**Also add to the CXX link command (around line 575-595), same object files.**

## Step 7: Build and Test

```bash
# Navigate to AFL++ repo
cd /workspaces/AFLplusplus/src/

# Clean any previous build
make clean

# Build
make -j4

# Verify binary was created
ls -lh afl-fuzz
./afl-fuzz -h | head -5

# Test with environment variable
AFL_QUEUE_IMPL=structure2 ./afl-fuzz -h | grep -i queue
```

## Step 8: Run Benchmark (Optional)

```bash
# If you have test targets and seeds:
for impl in maxheap structure1 structure2 structure3; do
  AFL_QUEUE_IMPL=$impl timeout 60 ./afl-fuzz -i seeds -o out_$impl -- ./test_target &
done

wait

# Compare results
for impl in maxheap structure1 structure2 structure3; do
  echo "$impl: $(ls out_$impl/queue/ | wc -l) seeds found"
done
```

## Troubleshooting

**Error: "afl-queue.h: No such file or directory"**
→ Verify you copied `afl-queue.h` to `include/afl-queue.h`

**Error: "undefined reference to `afl_queue_create`"**
→ Verify you added the `.o` files to the Makefile's afl-fuzz build rule

**Error: "queue implementation not found"**
→ Verify dispatch.c has the correct function pointers

**Runtime: "Queue implementation: structure2 (m=500, r=100, bad_cap=100000)"**
→ ✅ SUCCESS! Queue system loaded.

## What's Next

1. **Confirm build succeeds**
2. **Test with your actual targets**
3. **Compare all 4 queue implementations**
4. **Choose winner, delete losers**
5. **Hand off clean package**

---

**Need clarification on Step 4 (graph_data handling)?** Ask the programmer about your exact skeleton graph data structure.
