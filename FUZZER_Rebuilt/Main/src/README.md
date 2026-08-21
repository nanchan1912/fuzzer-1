# Source Folder

Quick explanation about the files here:

- `sgf-analyze.c`	- sgf-analyze binary tool
- `sgf-cc.c`		- sgf-cc compiler wrapper
- `sgf-common.c`	- common functions, used by sgf-analyze, sgf-fuzz, sgf-showmap and sgf-tmin
- `sgf-forkserver.c`	- forkserver implementation, used by sgf-fuzz, sgf-showmap, sgf-tmin
- `sgf-fuzz-bitmap.c`	- sgf-fuzz bitmap handling
- `sgf-fuzz.c`		- sgf-fuzz binary tool (main entrypoint and CLI options)
- `sgf-fuzz-extras.c`	- sgf-fuzz extra helper functions
- `sgf-fuzz-init.c`	- sgf-fuzz initialization
- `sgf-fuzz-mutators.c`	- sgf-fuzz custom mutator and python support
- `sgf-fuzz-one.c`      - sgf-fuzz main fuzzing cycle (graph mutation, execution, scoring)
- `sgf-performance.c`	- hashing and random number generation functions
- `sgf-fuzz-python.c`	- sgf-fuzz python mutator extension
- `sgf-fuzz-queue.c`	- sgf-fuzz queue management and scoring
- `sgf-fuzz-run.c`	- sgf-fuzz running target under forkserver / simulator
- `sgf-fuzz-state.c`	- sgf-fuzz global state and queue creation
- `sgf-fuzz-stats.c`	- sgf-fuzz statistics logging and output
- `sgf-fuzz-statsd.c`	- sgf-fuzz statsd metrics reporting
- `sgf-gotcpu.c`	- sgf-gotcpu binary tool
- `sgf-ld-lto.c`	- LTO linker helper
- `sgf-sharedmem.c`	- shared memory implementation
- `sgf-showmap.c`	- sgf-showmap binary tool
- `sgf-tmin.c`		- sgf-tmin binary tool
- `sgf-queue-dispatch.c` - Queue runtime selection and dispatch abstraction
- `sgf-queue-maxheap.c`  - MaxHeap bounded queue implementation (default)
- `sgf-queue-structure1.c` - Structure 1: ThresholdBucketQueue
- `sgf-queue-structure2.c` - Structure 2: RunnerUpQueue
- `sgf-queue-structure3.c` - Structure 3: MaxHeapBucketQueue
- `skeleton_graph_mutator.cpp` - skeleton mutation logic and static program abstraction parsing/ownership
- `skeleton_potential.cpp` - Potential calculation and incremental update logic
- `potential_nn.cpp` - Nearest-neighbor index for potential scoring
- `consistency.cpp` - Consistency validation
- `data_race.cpp` - Data race detection
- `skeleton_mo_footprint.cpp` - Memory order footprint analysis
- `skeleton_mutator_helper.cpp` - Helpers for skeleton mutator and location dumps
- `retgraph_shm.cpp` - Shared memory return graph tracking
- `shm_next_events.cpp` - Next events shared memory management
- `diversity_checker.c` - Diversity validation
- `event_pair_set.c` - Event pair set data structures

## Cohesion Note

Potential modules use shared static abstraction definitions from `include/static_program_abstraction.hpp`.
They do not redefine `CFGNode`/`ProgramCFG`, and parser/global CFG ownership stays with the mutator side.
