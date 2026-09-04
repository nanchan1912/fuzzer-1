#!/bin/bash

# ==============================================================================
# Universal PCTWM Custom Test Runner
# Allows running any custom C/C++ concurrency test case or suite on PCTWM.
# ==============================================================================


# Base environment configuration
WORKSPACE_DIR="/mnt/d/IIITH/sirji/pctwm"
PCTWM_LIB="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/pctwmversion/c11tester"
COMPAT_LIB="$WORKSPACE_DIR/compat_libs"
LLVM_BIN="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/llvm/build/bin"
LLVM_LIB="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/llvm/build/lib"
INCLUDE_PCTWM="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/pctwmversion/include"
VERIFY_RUNTIME="$WORKSPACE_DIR/verify_runtime.cpp"

export LD_LIBRARY_PATH="$PCTWM_LIB:$COMPAT_LIB:$LD_LIBRARY_PATH"
ulimit -c 0 2>/dev/null || true

# Default configuration parameters
BUG_DEPTH=1
EVENT_BOUND=30
HISTORY_DEPTH=1
RUNS=20
MAX_EXEC=1
VERBOSE=0
USE_VERIFY_RUNTIME=1

print_usage() {
    echo "=============================================================================="
    echo "                      PCTWM CUSTOM TEST SUITE RUNNER                         "
    echo "=============================================================================="
    echo "Usage:"
    echo "  $0 [options] <test_file_or_directory> [more_tests...]"
    echo "  $0 [options] --all"
    echo ""
    echo "Options:"
    echo "  -b, --bugdepth <num>    Bug depth bound (default: 1)"
    echo "  -i, -k, --eventbound <num> Event/read count bound (default: 30)"
    echo "  -y, --history <num>     History depth bound (default: 1)"
    echo "  -r, --runs <num>        Number of repetitions per test (default: 20)"
    echo "  -x, --maxexec <num>     Max executions per run (default: 1)"
    echo "  -v, --verbose           Enable verbose engine output"
    echo "  --no-runtime            Do not link verification runtime (verify_runtime.cpp)"
    echo "  -a, --all               Auto-discover and run all custom test cases in workspace"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 sb-loop"
    echo "  $0 _motivating-example/motivating-example.cc"
    echo "  $0 sb-loop _motivating-example -r 50 -b 2"
    echo "  $0 --all"
    echo "=============================================================================="
}

TARGETS=()
RUN_ALL=0

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--bugdepth)
            BUG_DEPTH="$2"
            shift 2
            ;;
        -i|-k|--eventbound)
            EVENT_BOUND="$2"
            shift 2
            ;;
        -y|--history)
            HISTORY_DEPTH="$2"
            shift 2
            ;;
        -r|--runs)
            RUNS="$2"
            shift 2
            ;;
        -x|--maxexec)
            MAX_EXEC="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --no-runtime)
            USE_VERIFY_RUNTIME=0
            shift
            ;;
        -a|--all)
            RUN_ALL=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            TARGETS+=("$1")
            shift
            ;;
    esac
done

# If --all is requested, find all test case directories in workspace
if [[ $RUN_ALL -eq 1 ]]; then
    echo "[INFO] Auto-discovering test cases in workspace..."
    # Find directories with .cc / .cpp / .c files excluding system/build directories
    while IFS= read -r dir; do
        TARGETS+=("$dir")
    done < <(find "$WORKSPACE_DIR" -maxdepth 2 -type d \
             ! -path "$WORKSPACE_DIR" \
             ! -path "*/.*" \
             ! -path "*benchmarks_extracted*" \
             ! -path "*compat_libs*" \
             ! -path "*extracted_artifact*" \
             ! -path "*pctwm_branch*" \
             ! -path "*C11_PCT_PCTWM*" \
             -exec sh -c 'ls "$1"/*.cc "$1"/*.cpp "$1"/*.c 2>/dev/null | grep -q . && echo "$1"' _ {} \;)
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "[ERROR] No test targets specified!"
    echo ""
    print_usage
    exit 1
fi

echo "=============================================================================="
echo "                     PCTWM CUSTOM CONCURRENCY TEST RUNNER                     "
echo "=============================================================================="
echo "Engine:       PCTWM (C11Tester Concurrency Bug Detector)"
echo "Compiler:     LLVM/Clang 8.0 with CDSPass instrumentation"
echo "Parameters:   Bug Depth (d)=$BUG_DEPTH | Event Bound (k)=$EVENT_BOUND | History (h)=$HISTORY_DEPTH | Runs=$RUNS"
echo "=============================================================================="
echo ""

# Results storage for final table
declare -a RESULT_NAMES
declare -a RESULT_RUNS
declare -a RESULT_BUGS
declare -a RESULT_RACES
declare -a RESULT_LIVELOCKS
declare -a RESULT_CLEAN
declare -a RESULT_RATES
declare -a RESULT_FIRST_BUG_TIME
declare -a RESULT_FIRST_BUG_RUN
declare -a RESULT_TIMES

# Function to run a single test case
run_test_target() {
    local target="$1"
    local target_path
    
    # Resolve relative or absolute path
    if [[ "$target" = /* ]]; then
        target_path="$target"
    else
        target_path="$PWD/$target"
    fi

    local src_file=""
    local work_dir=""
    local bin_name=""

    if [[ -f "$target_path" ]]; then
        src_file="$target_path"
        work_dir=$(dirname "$target_path")
        bin_name="pctwm_$(basename "$target_path" | sed 's/\.[^.]*$//')"
    elif [[ -d "$target_path" ]]; then
        work_dir="$target_path"
        # Look for primary .cc, .cpp, or .c file in folder
        src_file=$(find "$work_dir" -maxdepth 1 -type f \( -name "*.cc" -o -name "*.cpp" -o -name "*.c" \) | head -n 1)
        if [[ -z "$src_file" ]]; then
            echo "[WARN] No C/C++ source found in $work_dir. Skipping."
            return
        fi
        bin_name="pctwm_$(basename "$src_file" | sed 's/\.[^.]*$//')"
    else
        echo "[ERROR] Target '$target' not found. Skipping."
        return
    fi

    local test_display_name=$(basename "$work_dir")/$(basename "$src_file")
    echo "------------------------------------------------------------------------------"
    echo "Target: $test_display_name"
    echo "Source: $src_file"
    echo "Output: $work_dir/$bin_name"
    echo -n "[COMPILE] Instrumenting and building binary... "

    local extra_objs=""
    if [[ $USE_VERIFY_RUNTIME -eq 1 && -f "$VERIFY_RUNTIME" ]]; then
        local runtime_obj="$WORKSPACE_DIR/verify_runtime.o"
        # Compile verify_runtime without CDSPass instrumentation so its internal table doesn't cause false data races
        if [[ ! -f "$runtime_obj" || "$VERIFY_RUNTIME" -nt "$runtime_obj" ]]; then
            "$LLVM_BIN/clang++" -c "$VERIFY_RUNTIME" -o "$runtime_obj" -std=c++11 -O2 > /dev/null 2>&1
        fi
        extra_objs="$runtime_obj"
    fi

    # Compile with clang++ and CDSPass
    if ! "$LLVM_BIN/clang++" \
        -Xclang -load -Xclang "$LLVM_LIB/libCDSPass.so" \
        -L"$PCTWM_LIB" -lmodel -Wno-unused-command-line-argument \
        -I"$INCLUDE_PCTWM" -I"$work_dir" \
        -o "$work_dir/$bin_name" "$src_file" $extra_objs \
        -std=c++0x -pthread -Wall -g > "$work_dir/compile_pctwm.log" 2>&1; then
        echo "FAILED"
        echo "[ERROR] Compilation failed. See $work_dir/compile_pctwm.log:"
        cat "$work_dir/compile_pctwm.log" | head -n 20
        return
    fi
    echo "DONE"

    # Execution configuration
    local c11tester_env="-x$MAX_EXEC -p1 -b$BUG_DEPTH -i$EVENT_BOUND -y$HISTORY_DEPTH"
    if [[ $VERBOSE -eq 1 ]]; then
        c11tester_env="-v1 $c11tester_env"
    fi
    export C11TESTER="$c11tester_env"

    echo "[RUNNING] Executing $RUNS runs under PCTWM..."
    local log_file="$work_dir/pctwm_run.log"
    echo "=== PCTWM Execution Log for $test_display_name ($(date)) ===" > "$log_file"
    echo "C11TESTER=$C11TESTER" >> "$log_file"

    local bug_count=0
    local race_count=0
    local livelock_count=0
    local clean_count=0
    local first_bug_run=0
    local first_bug_time_ms=0
    local start_time=$(date +%s%N)

    for i in $(seq 1 "$RUNS"); do
        local out
        echo "--- Run #$i ---" >> "$log_file"
        out=$(cd "$work_dir" && ./"$bin_name" 2>&1 || true)
        echo "$out" >> "$log_file"
        echo "" >> "$log_file"

        if [[ $VERBOSE -eq 1 ]]; then
            echo ""
            echo "------------------- Verbose Output (Run #$i) -------------------"
            echo "$out"
            echo "----------------------------------------------------------------"
        fi

        local is_bug=0
        # Check for bugs / assertion failures / races / livelocks
        if echo "$out" | grep -qiE "assertion failed|assert|number of buggy executions: [1-9]|pctwm assertion failed"; then
            ((bug_count++))
            is_bug=1
        elif echo "$out" | grep -qi "race"; then
            ((race_count++))
            is_bug=1
        elif echo "$out" | grep -qi "livelock"; then
            ((livelock_count++))
            is_bug=1
        else
            ((clean_count++))
        fi

        if [[ $is_bug -eq 1 && $first_bug_run -eq 0 ]]; then
            first_bug_run=$i
            local current_now=$(date +%s%N)
            first_bug_time_ms=$(( (current_now - start_time) / 1000000 ))
        fi
    done

    local end_time=$(date +%s%N)
    local total_ms=$(( (end_time - start_time) / 1000000 ))
    local avg_ms=$(( total_ms / RUNS ))
    local total_bugs=$(( bug_count + race_count + livelock_count ))
    local bug_rate=$(( total_bugs * 100 / RUNS ))

    local first_bug_display="N/A"
    local first_bug_run_display="N/A"
    if [[ $first_bug_run -gt 0 ]]; then
        first_bug_display="${first_bug_time_ms}ms"
        first_bug_run_display="Run #$first_bug_run"
    fi

    printf "  Results: Runs: %d | Assertions/Bugs: %d | Races: %d | Livelocks: %d | Clean: %d | Bug Rate: %d%% | 1st Bug: %s (%s) | Avg Time: %d ms\n" \
           "$RUNS" "$bug_count" "$race_count" "$livelock_count" "$clean_count" "$bug_rate" "$first_bug_display" "$first_bug_run_display" "$avg_ms"
    echo "  Log saved to: $log_file"

    # Store for summary table
    RESULT_NAMES+=("$test_display_name")
    RESULT_RUNS+=("$RUNS")
    RESULT_BUGS+=("$bug_count")
    RESULT_RACES+=("$race_count")
    RESULT_LIVELOCKS+=("$livelock_count")
    RESULT_CLEAN+=("$clean_count")
    RESULT_RATES+=("${bug_rate}%")
    RESULT_FIRST_BUG_TIME+=("$first_bug_display")
    RESULT_FIRST_BUG_RUN+=("$first_bug_run_display")
    RESULT_TIMES+=("${avg_ms}ms")
}

# Run all targets
for target in "${TARGETS[@]}"; do
    run_test_target "$target"
done

echo ""
echo "================================================================================================================================="
echo "                                                  PCTWM TEST EXECUTION SUMMARY                                                   "
echo "================================================================================================================================="
printf "%-32s | %5s | %5s | %5s | %5s | %5s | %8s | %18s | %11s | %8s\n" \
       "Test Name" "Runs" "Bugs" "Races" "Locks" "Clean" "Bug Rate" "Time to 1st Bug" "1st Bug Run" "Avg Time"
echo "---------------------------------------------------------------------------------------------------------------------------------"

for i in "${!RESULT_NAMES[@]}"; do
    printf "%-32s | %5s | %5s | %5s | %5s | %5s | %8s | %18s | %11s | %8s\n" \
           "${RESULT_NAMES[$i]}" "${RESULT_RUNS[$i]}" "${RESULT_BUGS[$i]}" "${RESULT_RACES[$i]}" \
           "${RESULT_LIVELOCKS[$i]}" "${RESULT_CLEAN[$i]}" "${RESULT_RATES[$i]}" \
           "${RESULT_FIRST_BUG_TIME[$i]}" "${RESULT_FIRST_BUG_RUN[$i]}" "${RESULT_TIMES[$i]}"
done
echo "================================================================================================================================="
echo "All executions finished."
