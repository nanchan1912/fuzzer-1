# PCTWM Custom Concurrency Test Suite Runner

This guide provides exact instructions for running custom concurrency test cases (such as `sb-loop`, `_motivating-example`, or any newly added test suite) on the **PCTWM (C11Tester Concurrency Model Checking Engine)**.

---

## 1. Overview & How It Works

PCTWM tests concurrent C/C++ programs under weak memory models and thread schedules using:
- **LLVM 8.0 Clang++ Compiler** with the **CDSPass** LLVM instrumentation pass (`libCDSPass.so`).
- **PCTWM Engine** (`libmodel.so`): Explores randomized, priority-bounded executions to catch data races, livelocks, and assertion violations.
- **Verification Runtime** (`verify_runtime.cpp`): Evaluates weak verification assertions (`__VERIFY_STORE_VAR` and `__VERIFY_ASSERT`) across threads without modifying any test case source code.

---

## 2. Quick Start: Running Test Cases

Run commands from PowerShell or WSL inside `d:\IIITH\sirji\pctwm`:

### A. Run All Test Suites (Auto-Discovery)
To automatically discover and run all custom test cases in the workspace:
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh --all
```

### B. Run a Specific Test Folder
To run tests in a single directory (e.g., `sb-loop` or `_motivating-example`):
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh sb-loop
```
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh _motivating-example
```

### C. Run a Specific Test File
You can also pass the exact path to a source file:
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh sb-loop/sb-loop.cc
```
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh _motivating-example/motivating-example.cc
```

### D. Run Multiple Test Folders Together
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh sb-loop _motivating-example
```

---

## 3. Command-Line Options & Tuning Parameters

You can customize the test execution parameters:

| Option | Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **Bug Depth** | `-b <num>`, `--bugdepth <num>` | `1` | Maximum priority change depth (bug depth bound). |
| **Event Bound** | `-i <num>`, `-k <num>`, `--eventbound <num>` | `30` | Read/event exploration bound. |
| **History Bound** | `-y <num>`, `--history <num>` | `1` | Search bound for `rf_set` (reads-from history). |
| **Repetitions** | `-r <num>`, `--runs <num>` | `20` | Number of test repetitions for statistical coverage. |
| **Executions** | `-x <num>`, `--maxexec <num>` | `1` | Max model checker executions per run. |
| **Verbose** | `-v`, `--verbose` | `off` | Prints verbose scheduling and thread event traces. |
| **Auto All** | `-a`, `--all` | `off` | Auto-detects all test suites across the repository. |

### Example with Custom Options:
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh sb-loop -r 50 -b 2 -i 40 -y 2
```

---

## 4. How to Add New Test Suites in the Future

To add a new test suite that works seamlessly:

1. Create a new folder in the root directory (e.g. `my_new_test/`).
2. Put your `.cc`, `.cpp`, or `.c` file inside it (e.g. `my_new_test/test.cc`).
3. Run the test with:
   ```bash
   wsl bash /mnt/d/IIITH/sirji/pctwm/run_custom_test.sh my_new_test
   ```
   *No manual build files, Makefiles, or modifications to PCTWM are required!*

### Writing Test Assertions
Your test cases can use:
1. **Verification annotations**:
   ```cpp
   extern "C" {
       __attribute__((weak)) void __VERIFY_STORE_VAR(const char *name, bool value) {}
       __attribute__((weak)) bool __VERIFY_ASSERT(const char *expr) { return true; }
   }
   
   // In thread 1:
   __VERIFY_STORE_VAR("cond1", condition_met);
   
   // In main:
   __VERIFY_ASSERT("!(cond1 & cond2)");
   ```
2. **Standard Assertions**:
   ```cpp
   #include <assert.h>
   assert(a == b);
   ```
3. **Data Race Checks**:
   ```cpp
   #include "librace.h"
   cds_store32(&var, 1);
   int val = cds_load32(&var);
   ```

---

## 5. Output & Logs

For every test execution:
1. **Console Summary**: Displays a clean tabular summary:
   ```text
   =================================================================================================================================
                                                     PCTWM TEST EXECUTION SUMMARY                                                   
   =================================================================================================================================
   Test Name                        |  Runs |  Bugs | Races | Locks | Clean | Bug Rate |    Time to 1st Bug | 1st Bug Run | Avg Time
   ---------------------------------------------------------------------------------------------------------------------------------
   sb-loop/sb-loop.cc               |    20 |     6 |     0 |     0 |    14 |      30% |             4962ms |      Run #9 |    518ms
   _motivating-example/motivating-example.cc |    20 |     0 |     0 |     0 |    20 |       0% |                N/A |         N/A |    381ms
   =================================================================================================================================
   ```
2. **Detailed Execution Logs**: Full event traces, thread schedule transitions, and memory actions are saved to `<test_folder>/pctwm_run.log`.
3. **Compilation Logs**: Saved to `<test_folder>/compile_pctwm.log`.

---

## 6. Existing Benchmarks
To run the full original 9 PCTWM benchmark suite (Dekker, Barrier, Chase-Lev Deque, MCS Lock, MS Queue, MPMC Queue, Linux RW Locks, RW Lock, Seq Lock):
```bash
wsl bash /mnt/d/IIITH/sirji/pctwm/run_pctwm_suite.sh
```
