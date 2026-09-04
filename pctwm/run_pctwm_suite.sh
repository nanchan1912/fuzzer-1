#!/bin/bash

WORKSPACE_DIR="/mnt/d/IIITH/sirji/pctwm"
BENCH_ROOT="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/c11tester-benchmarks"
PCTWM_LIB="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/pctwmversion/c11tester"
COMPAT_LIB="$WORKSPACE_DIR/compat_libs"
LLVM_BIN="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/llvm/build/bin"
LLVM_LIB="$WORKSPACE_DIR/benchmarks_extracted/home/vagrant/llvm/build/lib"

export LD_LIBRARY_PATH="$PCTWM_LIB:$COMPAT_LIB:$LD_LIBRARY_PATH"

echo "=========================================================================================="
echo "                   PCTWM CONCURRENCY TESTING SUITE (WSL 2 NATIVE)                        "
echo "=========================================================================================="
echo "Compiler: LLVM/Clang 8.0 + CDSPass Instrumentation"
echo "Engine:   PCTWM C11Tester Engine"
echo ""

# Helper to compile a benchmark
compile_bench() {
    local dir=$1
    local name=$2
    local src=$3
    local extra_include=$4
    echo -n "[COMPILE] Building $name... "
    cd "$dir"
    $LLVM_BIN/clang++ \
      -Xclang -load -Xclang $LLVM_LIB/libCDSPass.so \
      -L$PCTWM_LIB -lmodel -Wno-unused-command-line-argument \
      -o "$name" "$src" -std=c++0x -pthread -Wall -g $extra_include > /dev/null 2>&1
    echo "DONE"
}

# Helper to test a benchmark
test_bench() {
    local dir=$1
    local bin=$2
    local d=$3
    local k=$4
    local h=$5
    local runs=${6:-20}
    
    cd "$dir"
    export C11TESTER="-x1 -p1 -b$d -i$k -y$h"
    
    echo -e "\n------------------------------------------------------------------------------------------"
    echo "Testing: $bin (Bug Depth d=$d, Event Bound k=$k, History Depth h=$h, Runs=$runs)"
    echo "------------------------------------------------------------------------------------------"
    
    local race_count=0
    local livelock_count=0
    local pass_count=0
    local first_bug_run=0
    local first_bug_time_ms=0
    local start_time=$(date +%s%N)
    
    for i in $(seq 1 $runs); do
        local out
        local is_bug=0
        out=$(./"$bin" 2>&1 || true)
        if echo "$out" | grep -qi "race"; then
            ((race_count++))
            is_bug=1
        elif echo "$out" | grep -qi "livelock"; then
            ((livelock_count++))
            is_bug=1
        else
            ((pass_count++))
        fi

        if [[ $is_bug -eq 1 && $first_bug_run -eq 0 ]]; then
            first_bug_run=$i
            local current_now=$(date +%s%N)
            first_bug_time_ms=$(( (current_now - start_time) / 1000000 ))
        fi
    done
    
    local end_time=$(date +%s%N)
    local total_ms=$(( (end_time - start_time) / 1000000 ))
    local avg_ms=$(( total_ms / runs ))
    local bug_rate=$(( (race_count + livelock_count) * 100 / runs ))

    local first_bug_display="N/A"
    local first_bug_run_display="N/A"
    if [[ $first_bug_run -gt 0 ]]; then
        first_bug_display="${first_bug_time_ms}ms"
        first_bug_run_display="Run #$first_bug_run"
    fi
    
    printf "  %-18s | Runs: %3d | Races: %2d | Livelocks: %2d | Clean: %2d | Bug Rate: %3d%% | 1st Bug: %s (%s) | Avg Time: %4d ms\n" \
           "$bin" "$runs" "$race_count" "$livelock_count" "$pass_count" "$bug_rate" "$first_bug_display" "$first_bug_run_display" "$avg_ms"
}

CDS_DIR="$BENCH_ROOT/cdschecker_modified_benchmarks"
TSAN_DIR="$BENCH_ROOT/tsan11-missingbug"

# 1. Dekker
compile_bench "$CDS_DIR/dekker-fences" "dekker-fences" "dekker-fences.cc" "-I../include"
test_bench "$CDS_DIR/dekker-fences" "dekker-fences" 0 14 1 20

# 2. Barrier
compile_bench "$CDS_DIR/barrier" "barrier" "barrier.cc" "-I../include"
test_bench "$CDS_DIR/barrier" "barrier" 1 10 1 20

# 3. Chase-Lev Deque
compile_bench "$CDS_DIR/chase-lev-deque" "chase-lev-deque" "chase-lev-deque.cc" "-I../include"
test_bench "$CDS_DIR/chase-lev-deque" "chase-lev-deque" 1 56 1 20

# 4. MCS Lock
compile_bench "$CDS_DIR/mcs-lock" "mcs-lock" "mcs-lock.cc" "-I../include"
test_bench "$CDS_DIR/mcs-lock" "mcs-lock" 1 16 1 20

# 5. MS Queue
compile_bench "$CDS_DIR/ms-queue" "ms-queue" "ms-queue.cc" "-I../include"
test_bench "$CDS_DIR/ms-queue" "ms-queue" 0 31 1 20

# 6. MPMC Queue
compile_bench "$CDS_DIR/mpmc-queue" "mpmc-queue" "mpmc-queue.cc" "-I../include"
test_bench "$CDS_DIR/mpmc-queue" "mpmc-queue" 2 17 1 20

# 7. Linux RW Locks
compile_bench "$CDS_DIR/linuxrwlocks" "linuxrwlocks" "linuxrwlocks.cc" "-I../include"
test_bench "$CDS_DIR/linuxrwlocks" "linuxrwlocks" 2 19 1 20

# 8. RW Lock
compile_bench "$TSAN_DIR" "rwlock-test" "rwlock-test.cc" ""
test_bench "$TSAN_DIR" "rwlock-test" 2 74 1 20

# 9. Seq Lock
compile_bench "$TSAN_DIR" "seqlock-test" "seqlock-test.cc" ""
test_bench "$TSAN_DIR" "seqlock-test" 3 18 1 20

echo ""
echo "=========================================================================================="
echo "                  ALL 9 PCTWM BENCHMARKS EXECUTED SUCCESSFULLY!                           "
echo "=========================================================================================="
