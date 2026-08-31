#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Benchmark Runner + LLVM IR Generation + SVF Instrumentation
# ============================================================

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# CWD as of startup: the script pushd's around, so relative arguments and
# relative env vars must be anchored before anything moves.
readonly INVOCATION_DIR="$PWD"
readonly LLVM_MAJOR="${LLVM_MAJOR:-16}"
readonly FILTER_SHARED="${FILTER_SHARED:-true}"

benchmark_dirs=(
    "iris"
    "mabain"
    "silo"
    "_motivating-example"
    "barrier"
    "barrier-change"
    "barrier-ori"
    "chase-lev-deque"
    "chasechange"
    "dekker-change"
    "dekker-fences"
    "linuxrwchange"
    "linuxrwlocks"
    "mcs-change"
    "mcs-lock"
    "mcs2"
    "mpmc-change"
    "mpmc-queue"
    "mpmc3"
    "ms-queue"
    "ms-queue-tsan11"
    "mschange"
    "ringbuffer"
    "rwqueue"
    "spsc-queue"

    "sb-loop"
    "test-array"
    "test-struct"
    "test-mp"
)

declare CXX_BIN
declare CC_BIN
declare OPT_BIN
declare LLVM_LINK_BIN
declare LLVM_DIS_BIN


# ------------------------------------------------------------
# Trajectory and Stage Tracking
# ------------------------------------------------------------

declare -A BENCHMARK_STAGE
declare -A INIT_GRAPH_EXIT_CODE

record_stage() {
    local dir="$1"
    local stage="$2"
    local status="$3"

    if [[ "$status" == "FAILED" ]]; then
        BENCHMARK_STAGE["$dir"]="FAILED ($stage)"
    else
        BENCHMARK_STAGE["$dir"]="$stage"
    fi
}

# ------------------------------------------------------------
# Display Final Summary
# ------------------------------------------------------------

print_benchmarks_summary() {
    echo ""
    echo "========================================================================================================================"
    echo "                                                 BENCHMARKS SUMMARY                                                     "
    echo "========================================================================================================================"
    echo "Stage Groups & Definitions:"
    echo "  [Group 1: Front-End Compilation]"
    echo "    - GEN_IR                 : Compiles C/C++ source code to uninstrumented LLVM IR (no_pass.ll)"
    echo ""
    echo "  [Group 2: SVF Graph Construction & Analysis]"
    echo "    - SVF_DUMP               : Dumps program graphs (PAG, ICFG, TCT) & generates SVF pointer metadata"
    echo "    - SVF_ANALYSIS           : Performs SVF points-to and alias analysis on the uninstrumented IR"
    echo "    - GEN_CCFG               : Converts .pg analysis output to .ccfg file"
    echo "    - INIT_SG_GRAPH          : Generates initial seed graph (.init.sg.json) from .pg analysis output"
    echo ""
    echo "  [Group 3: Instrumentation & Code Injection]"
    echo "    - INSTRUMENT             : LLVM pass injects runtime scheduler hooks using SVF metadata (instrumented.ll)"
    echo ""
    echo "  [Group 4: Back-End Binary Generation]"
    echo "    - COMPILE_UNINSTRUMENTED : Compiles uninstrumented LLVM IR to native executable (.out)"
    echo "    - COMPILE_INSTRUMENTED   : Compiles instrumented LLVM IR linked with runtime library (.instrumented.out)"
    echo ""
    echo "Expected Stage Sequence (Trajectory):"
    echo "  START -> GEN_IR -> SVF_DUMP -> SVF_ANALYSIS -> GEN_CCFG -> INIT_SG_GRAPH -> INSTRUMENT -> COMPILE_UNINSTRUMENTED -> SUCCESS"
    echo "------------------------------------------------------------------------------------------------------------------------"
    printf "%-30s %-30s %s\n" "BENCHMARK" "RESULT" "INIT GRAPH EXIT CODE"
    echo "------------------------------------------------------------------------------------------------------------------------"
    for dir in "${benchmark_dirs[@]}"; do
        local result="${BENCHMARK_STAGE["$dir"]}"
        local exit_code="${INIT_GRAPH_EXIT_CODE["$dir"]}"
        printf "%-30s %-30s %s\n" "$dir" "$result" "$exit_code"
    done
    echo "========================================================================================================================"
    echo ""
}

# ------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------

log() {
    echo "[INFO] $*"
}

err() {
    echo "[ERROR] $*" >&2
}

require_executable() {
    local path="$1"
    local name="$2"

    if [[ ! -x "$path" ]]; then
        err "$name not found or not executable: $path"
        exit 1
    fi
}

require_file() {
    local path="$1"
    local name="$2"

    if [[ ! -f "$path" ]]; then
        err "$name not found: $path"
        exit 1
    fi
}

# Turn a possibly-relative path into an absolute one. Base defaults to the
# directory the script was invoked from, so `SVF_DIR=../SVF ./run_...sh` works
# even though the script later pushd's into benchmark directories.
abspath() {
    local path="$1"
    local base="${2:-$INVOCATION_DIR}"

    [[ -n "$path" ]] || return 0
    [[ "$path" = /* ]] || path="${base}/${path}"

    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$path"
    else
        printf '%s\n' "$path"
    fi
}

# Benchmark entries are names relative to this script's directory, but an
# absolute entry is honoured as-is.
benchmark_path() {
    abspath "$1" "$SCRIPT_DIR"
}

# First existing candidate, else the last one (so error messages stay useful).
first_existing_dir() {
    local candidate
    for candidate in "$@"; do
        if [[ -d "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    printf '%s\n' "${@: -1}"
}

# ------------------------------------------------------------
# Environment Setup
# ------------------------------------------------------------

setup_environment() {
    local quiet_mode="${1:-0}"

    # Defaults are searched relative to the repo first (sibling checkout, as the
    # nix shell lays it out), then the devcontainer's absolute location.
    if [[ -z "${SVF_DIR:-}" ]]; then
        SVF_DIR="$(first_existing_dir \
            "${REPO_ROOT}/../SVF" \
            "${REPO_ROOT}/SVF" \
            "/workspaces/SVF")"
    fi

    if [[ -z "${LLVM_DIR:-}" ]]; then
        if command -v "llvm-config-${LLVM_MAJOR}" >/dev/null 2>&1; then
            LLVM_DIR="$("llvm-config-${LLVM_MAJOR}" --prefix)"
        else
            LLVM_DIR="/usr/lib/llvm-${LLVM_MAJOR}"
        fi
    fi

    # Normalise whatever we ended up with (env-provided values may be relative).
    export SVF_DIR="$(abspath "$SVF_DIR")"
    export LLVM_DIR="$(abspath "$LLVM_DIR")"
    export Z3_DIR="$(abspath "${Z3_DIR:-/usr}")"

    [[ -d "$SVF_DIR" ]] || {
        err "SVF_DIR not found: $SVF_DIR"
        exit 1
    }

    [[ -d "$LLVM_DIR" ]] || {
        err "LLVM_DIR not found: $LLVM_DIR"
        exit 1
    }

    if ! command -v "clang-${LLVM_MAJOR}" >/dev/null 2>&1; then
        err "clang-${LLVM_MAJOR} not found"
        exit 1
    fi

    if ! command -v "llvm-config-${LLVM_MAJOR}" >/dev/null 2>&1; then
        err "llvm-config-${LLVM_MAJOR} not found"
        exit 1
    fi

    actual_major="$(
        llvm-config-${LLVM_MAJOR} --version |
        cut -d. -f1
    )"

    if [[ "$actual_major" != "$LLVM_MAJOR" ]]; then
        err "Expected LLVM ${LLVM_MAJOR}, got ${actual_major}"
        exit 1
    fi
    
    export CXX_BIN="$(command -v "${CXX:-clang++-${LLVM_MAJOR}}" || command -v clang++)"
    export CC_BIN="$(command -v "${CC:-clang-${LLVM_MAJOR}}" || command -v clang)"

    export OPT_BIN="$(command -v opt-${LLVM_MAJOR} || command -v opt)"
    export LLVM_LINK_BIN="$(command -v llvm-link-${LLVM_MAJOR} || command -v llvm-link)"
    export LLVM_DIS_BIN="$(command -v llvm-dis-${LLVM_MAJOR} || command -v llvm-dis)"

    require_executable "$CXX_BIN" "clang++"
    require_executable "$OPT_BIN" "opt"
    require_executable "$LLVM_LINK_BIN" "llvm-link"
    require_executable "$LLVM_DIS_BIN" "llvm-dis"
    
    WPA_BIN="$(command -v wpa || true)"
    LLVM2SVF_BIN="$(command -v llvm2svf || true)"
    require_executable "$WPA_BIN" "SVF wpa"
    require_executable "$LLVM2SVF_BIN" "SVF llvm2svf"

    # Derived from SVF_DIR rather than hard-coded: the build directory name
    # differs between SVF's `build.sh` (Release-build) and a plain cmake build.
    if [[ -z "${SVF_EXTAPI_BC:-}" ]]; then
        local candidate
        for candidate in \
            "${SVF_DIR}/build/lib/extapi.bc" \
            "${SVF_DIR}/Release-build/lib/extapi.bc" \
            "${SVF_DIR}/lib/extapi.bc"
        do
            if [[ -f "$candidate" ]]; then
                SVF_EXTAPI_BC="$candidate"
                break
            fi
        done
    fi
    export SVF_EXTAPI_BC="$(abspath "${SVF_EXTAPI_BC:-${SVF_DIR}/build/lib/extapi.bc}")"
    require_file "$SVF_EXTAPI_BC" "SVF extapi.bc"

    # Automatically build the WMM runtime static library if not present
    local runtime_dir="${SCRIPT_DIR}/../src/wmm-runtime"
    local runtime_lib="${runtime_dir}/libwmm_runtime.a"
    local stub_c="${runtime_dir}/stub.c"

    if [[ ! -f "$runtime_lib" || ! -f "$stub_c" ]]; then
        log "WMM runtime library or stub not found. Building them now..."
        mkdir -p "$runtime_dir"
        
        # Write stub.c if missing
        if [[ ! -f "$stub_c" ]]; then
            cat << 'EOF' > "$stub_c"
int user_main(int argc, char **argv);
int main(int argc, char **argv) {
    return user_main(argc, argv);
}
EOF
        fi
        
        log "Runtime lib location: $runtime_dir"
        # Compile runtime C files and create libwmm_runtime.a
        pushd "$runtime_dir" > /dev/null
        local cc_bin="${CC_BIN}"
        local cxx_bin="${CXX_BIN}"
        local c_flags="-O0 -g -fPIC"
        if [[ "$quiet_mode" -eq 1 ]]; then
            c_flags="$c_flags -DQUIET"
        fi
        "$cc_bin" $c_flags -I"${REPO_ROOT}/Main/include" -c assert.c eg.c json.c scheduler.c wmm_hooks.c
        # shm_next_events.cpp is C++ and lives under Main/src, not here -- it must be
        # compiled and archived too, or scheduler_terminate_locked's calls to
        # begin_update_c/finish_update_c are left undefined at link time for every
        # instrumented benchmark binary. This mirrors build_project()'s complete
        # rebuild below; this lighter auto-build path had drifted out of sync with it.
        "$cxx_bin" -O0 -g -fPIC -I"${REPO_ROOT}/Main/include" -c "${REPO_ROOT}/Main/src/shm_next_events.cpp" -o shm_next_events.o
        ar rcs libwmm_runtime.a assert.o eg.o json.o scheduler.o wmm_hooks.o shm_next_events.o
        rm -f *.o
        popd > /dev/null
        log "WMM runtime library and stub successfully built."
    fi

    log "LLVM_DIR : $LLVM_DIR"
    log "SVF_DIR  : $SVF_DIR"
    log "Z3_DIR   : $Z3_DIR"
    log "extapi.bc: $SVF_EXTAPI_BC"
    log "clang++  : $CXX_BIN"
    log "opt      : $OPT_BIN"
    log "wpa      : $(command -v wpa)"
    log "LLVM version : $(llvm-config-${LLVM_MAJOR} --version)"
    log "Clang version: $("$CC_BIN" --version | head -n1)"
    log "Environment setup completed."
}

# ------------------------------------------------------------
# Build Project
# ------------------------------------------------------------

build_project() {
    local quiet_mode="${1:-0}"
    log "Building project using CMake..."
    [[ -d "$LLVM_DIR/lib/cmake/llvm" ]] || {
        err "LLVM CMake config not found"
        exit 1
    }

    # Rebuild WMM runtime static library
    log "Rebuilding WMM runtime static library..."
    local runtime_dir="${SCRIPT_DIR}/../src/wmm-runtime"
    local wmm_src_dir="${SCRIPT_DIR}/../Main/src"
    local wmm_include_dir="${SCRIPT_DIR}/../Main/include"

    pushd "$runtime_dir" > /dev/null
    local cc_bin="${CC_BIN}"
    local cxx_bin="${CXX_BIN}"
    rm -f libwmm_runtime.a *.o
    local c_flags="-O0 -g -fPIC"
    if [[ "$quiet_mode" -eq 1 ]]; then
        c_flags="$c_flags -DQUIET"
    fi
    "$cc_bin" $c_flags -I"${REPO_ROOT}/Main/include" -c assert.c eg.c json.c scheduler.c wmm_hooks.c
    "$cxx_bin" -O0 -g -fPIC -I"$wmm_include_dir" -c "$wmm_src_dir/shm_next_events.cpp" -o shm_next_events.o
    ar rcs libwmm_runtime.a assert.o eg.o json.o scheduler.o wmm_hooks.o shm_next_events.o
    rm -f *.o
    popd > /dev/null

    pushd "$SCRIPT_DIR"/../src > /dev/null


    rm -rf build/

    cmake \
        -B build \
        -S ./ \
        -DSVF_DIR="$SVF_DIR" \
        -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" \
        -DZ3_DIR="$Z3_DIR"

    cmake --build build

    # mkdir -p "${SCRIPT_DIR}/build"
    # cp build/executable "${SCRIPT_DIR}/build/executable"
    # cp build/WMMInstrument.so "${SCRIPT_DIR}/build/WMMInstrument.so"
    # cp "$SVF_EXTAPI_BC" "${SCRIPT_DIR}/build/extapi.bc"

    popd > /dev/null
    log "Build completed."
}
# ------------------------------------------------------------
# Compile Sources to LLVM Bitcode
# ------------------------------------------------------------
generate_irs() {
    local benchmark_dir="$1"

    log "Generating LLVM IRs..."

    rm -rf data/
    bash ./generate_ir.sh

}

# ------------------------------------------------------------
# Run SVF Analysis
# ------------------------------------------------------------

run_svf_analysis() {
    local data_dir="$1"
    local executable_path="$2"

    log "Running SVF analysis..."

    pushd "$data_dir" > /dev/null

    "$executable_path"  -extapi="$SVF_EXTAPI_BC" no_pass.ll >> ./instrumented_stdout.md 2>> instrumented_stderr.md

    popd > /dev/null
}

# ------------------------------------------------------------
# Instrument LLVM IR
# ------------------------------------------------------------

instrument_ir() {
    local plugin_lib="$1"
    local metadata_file="$2"
    local input_ll="$3"
    local output_ll="$4"

    log "Instrumenting LLVM IR..."

    "$OPT_BIN" \
        -load-pass-plugin "$plugin_lib" \
        -passes=wmm-instrument \
        -wmm-metadata-file="$metadata_file" \
        "$input_ll" \
        -S \
        -o "$output_ll"
}

# ------------------------------------------------------------
# Generate Initial Seed Graph from .pg File
# ------------------------------------------------------------

generate_init_seed_graph() {
    local data_dir="$1"
    local pg_file="${data_dir}/generated_output.pg"
    local init_sg_file="${data_dir}/init.sg.json"

    log "Generating initial seed graph from .pg..."

    if [[ ! -f "$pg_file" ]]; then
        err "Program graph file not found: $pg_file"
        return 1
    fi

    local pg_to_init_sg="${SCRIPT_DIR}/../src/tools/pg_to_init_sg.py"
    if [[ ! -f "$pg_to_init_sg" ]]; then
        err "pg_to_init_sg.py script not found: $pg_to_init_sg"
        return 1
    fi

    python3 "$pg_to_init_sg" "$pg_file" --out "$init_sg_file"
}

# ------------------------------------------------------------
# Generate CCFG from .pg File
# ------------------------------------------------------------

generate_ccfg() {
    local data_dir="$1"
    local pg_file="${data_dir}/generated_output.pg"
    local ccfg_file="${data_dir}/generated_output.ccfg"

    log "Generating .ccfg file from .pg..."

    if [[ ! -f "$pg_file" ]]; then
        err "Program graph file not found: $pg_file"
        return 1
    fi

    local pg_to_ccfg="${SCRIPT_DIR}/../src/tools/pg_to_ccfg.py"
    if [[ ! -f "$pg_to_ccfg" ]]; then
        err "pg_to_ccfg.py script not found: $pg_to_ccfg"
        return 1
    fi

    python3 "$pg_to_ccfg" "$pg_file" "$ccfg_file"
}

# ------------------------------------------------------------
# Compile LLVM IR to Native Executables (with Dynamic Stub Detection)
# ------------------------------------------------------------

compile_uninstrumented() {
    local benchmark_dir="$1"
    local data_dir="${benchmark_dir}/data"
    local benchmark_name
    benchmark_name="$(basename "$benchmark_dir")"

    log "Compiling uninstrumented LLVM IR to native executable..."
    if grep -q "define.*@main" "$data_dir/no_pass.ll"; then
        log "  Detected direct main() in LLVM IR. Compiling without stub.c..."
        "$CXX_BIN" \
            -O0 -g \
            -fno-discard-value-names \
            "$data_dir/no_pass.ll" \
            -lpthread \
            -o "$data_dir/${benchmark_name}.out"
    else
        log "  Detected user_main() in LLVM IR. Compiling with stub.c..."
        "$CXX_BIN" \
            -O0 -g \
            -fno-discard-value-names \
            "$data_dir/no_pass.ll" \
            "${SCRIPT_DIR}/../src/wmm-runtime/stub.c" \
            -lpthread \
            -o "$data_dir/${benchmark_name}.out"
    fi
}

compile_instrumented() {
    # Uses the same clang++ this whole pipeline already relies on
    # (CXX_BIN, set up in setup_environment). The wmm-instrument LLVM
    # pass (opt -load-pass-plugin) is what injects the scheduler hooks;
    # it has no AFL dependency, so no AFL toolchain is used here.
    local benchmark_dir="$1"
    local data_dir="${benchmark_dir}/data"
    local benchmark_name
    benchmark_name="$(basename "$benchmark_dir")"

    require_executable "$CXX_BIN" "clang++"

    log "Compiling instrumented LLVM IR to native executable..."
    if grep -Eq '^define .*@main\(' "$data_dir/no_pass.ll"; then
        log "  Detected direct main() in LLVM IR. Compiling without stub.c..."
        "$CXX_BIN" \
            -O0 -g \
            -fno-discard-value-names \
            "$data_dir/instrumented.ll" \
            -Wl,--whole-archive \
            "${SCRIPT_DIR}/../src/wmm-runtime/libwmm_runtime.a" \
            -Wl,--no-whole-archive \
            -lpthread \
            -lrt \
            -ldl \
            -o "$data_dir/${benchmark_name}.instrumented.out"
    else
        log "  Detected user_main() in LLVM IR. Compiling with stub.c..."
        "$CXX_BIN" \
            -O0 -g \
            -fno-discard-value-names \
            "$data_dir/instrumented.ll" \
            "${SCRIPT_DIR}/../src/wmm-runtime/stub.c" \
            -Wl,--whole-archive \
            "${SCRIPT_DIR}/../src/wmm-runtime/libwmm_runtime.a" \
            -Wl,--no-whole-archive \
            -lpthread \
            -lrt \
            -ldl \
            -o "$data_dir/${benchmark_name}.instrumented.out"
    fi
}

# ------------------------------------------------------------
# Run Benchmark (Stage-aware)
# ------------------------------------------------------------

phase_generate_ir() {
    local dir="$1"
    local bench_dir
    bench_dir="$(benchmark_path "$dir")"
    if ! (pushd "$bench_dir" > /dev/null && generate_irs "$bench_dir" && popd > /dev/null); then
        record_stage "$dir" "GEN_IR" "FAILED"
        return 1
    fi
    record_stage "$dir" "GEN_IR" "SUCCESS"
    return 0
}

phase_svf_analysis() {
    local dir="$1"
    local executable_path="$2"
    local plugin_lib="$3"
    local bench_dir
    bench_dir="$(benchmark_path "$dir")"
    local data_dir="${bench_dir}/data"

    if ! (pushd "$bench_dir" > /dev/null && "${executable_path}" -dump-pag -dump-icfg -dump-tct -extapi="$SVF_EXTAPI_BC" data/no_pass.ll > terminal_output.md && popd > /dev/null); then
        record_stage "$dir" "SVF_DUMP" "FAILED"
        return 1
    fi
    record_stage "$dir" "SVF_DUMP" "SUCCESS"

    if [[ ! -f "$plugin_lib" ]]; then
        err "Instrumentation plugin not found: $plugin_lib"
        record_stage "$dir" "CHECK_PLUGIN" "FAILED"
        return 1
    fi
    if [[ ! -x "$executable_path" ]]; then
        err "SVF executable not found: $executable_path"
        record_stage "$dir" "CHECK_EXECUTABLE" "FAILED"
        return 1
    fi

    mkdir -p "$data_dir"

    if ! run_svf_analysis "$data_dir" "$executable_path"; then
        record_stage "$dir" "SVF_ANALYSIS" "FAILED"
        return 1
    fi
    record_stage "$dir" "SVF_ANALYSIS" "SUCCESS"

    if ! generate_ccfg "$data_dir"; then
        record_stage "$dir" "GEN_CCFG" "FAILED"
        return 1
    fi
    record_stage "$dir" "GEN_CCFG" "SUCCESS"

    if ! generate_init_seed_graph "$data_dir"; then
        record_stage "$dir" "INIT_SG_GRAPH" "FAILED"
        return 1
    fi
    record_stage "$dir" "INIT_SG_GRAPH" "SUCCESS"

    return 0
}

phase_instrument() {
    local dir="$1"
    local plugin_lib="$2"
    local data_dir
    data_dir="$(benchmark_path "$dir")/data"

    if ! instrument_ir "$plugin_lib" "$data_dir/generated_output.pg" "$data_dir/no_pass.ll" "$data_dir/instrumented.ll"; then
        record_stage "$dir" "INSTRUMENT" "FAILED"
        return 1
    fi
    record_stage "$dir" "INSTRUMENT" "SUCCESS"
    return 0
}

phase_compile() {
    local dir="$1"
    local bench_dir
    bench_dir="$(benchmark_path "$dir")"
    if ! compile_uninstrumented "$bench_dir"; then
        record_stage "$dir" "COMPILE_UNINSTRUMENTED" "FAILED"
        return 1
    fi
    record_stage "$dir" "COMPILE_UNINSTRUMENTED" "SUCCESS"

    if ! compile_instrumented "$bench_dir"; then
        record_stage "$dir" "COMPILE_INSTRUMENTED" "FAILED"
        return 1
    fi
    record_stage "$dir" "COMPILE_INSTRUMENTED" "SUCCESS"
    return 0
}

phase_verify_status() {
    local dir="$1"
    local data_dir
    data_dir="$(benchmark_path "$dir")/data"
    local benchmark_name
    benchmark_name="$(basename "$dir")"
    local inst_bin="$data_dir/${benchmark_name}.instrumented.out"
    local init_sg_file="$data_dir/init.sg.json"

    if [[ -f "$inst_bin" && -f "$init_sg_file" ]]; then
        log "Running simple check by passing $init_sg_file to the instrumented binary (with 5s timeout)..."
        timeout 20 "$inst_bin" < "$init_sg_file" > /dev/null 2>&1
        status=$?
        if [[ $status -eq 124 ]]; then
            log "  Status code: TIMEOUT (124)"
            echo "[STATUS_CHECK] Benchmark ${benchmark_name} status code: TIMEOUT (124)"
            INIT_GRAPH_EXIT_CODE["$dir"]="TIMEOUT (124)"
        else
            log "  Status code: $status"
            echo "[STATUS_CHECK] Benchmark ${benchmark_name} status code: $status"
            INIT_GRAPH_EXIT_CODE["$dir"]="$status"
        fi
    else
        INIT_GRAPH_EXIT_CODE["$dir"]="N/A"
    fi
    return 0
}

run_benchmark() {
    local dir="$1"

    local build_dir="${REPO_ROOT}/src/build"
    local executable_path="${build_dir}/executable"
    local plugin_lib="${build_dir}/WMMInstrument.so"
    local bench_dir
    bench_dir="$(benchmark_path "$dir")"

    if [[ ! -d "$bench_dir" ]]; then
        err "Benchmark directory not found: $bench_dir"
        record_stage "$dir" "INIT" "FAILED"
        return 1
    fi

    log "Running benchmark: $dir ($bench_dir)"
    record_stage "$dir" "START" "SUCCESS"

    rm -rf "$bench_dir/data"

    if ! phase_generate_ir "$dir"; then
        return 1
    fi

    if ! phase_svf_analysis "$dir" "$executable_path" "$plugin_lib"; then
        return 1
    fi

    if ! phase_instrument "$dir" "$plugin_lib"; then
        return 1
    fi

    if ! phase_compile "$dir"; then
        return 1
    fi

    if ! phase_verify_status "$dir"; then
        return 1
    fi

    record_stage "$dir" "SUCCESS" "SUCCESS"
    log "Benchmark completed successfully: $dir"
    return 0
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

main() {
    local build_step=0
    local quiet_mode=1 # Quiet by default

    # Parse arguments
    for arg in "$@"; do
        if [[ "$arg" == "build" ]]; then
            build_step=1
        elif [[ "$arg" == "verbose" || "$arg" == "--verbose" ]]; then
            quiet_mode=0
        elif [[ "$arg" == "quiet" || "$arg" == "--quiet" ]]; then
            quiet_mode=1
        fi
    done

    # Check environment variables
    if [[ "${VERBOSE:-0}" == "1" || "${VERBOSE:-}" == "true" ]]; then
        quiet_mode=0
    fi
    if [[ "${QUIET:-1}" == "0" || "${QUIET:-}" == "false" ]]; then
        quiet_mode=0
    fi

    setup_environment "$quiet_mode"

    # Optional build step
    if [[ "$build_step" -eq 1 ]]; then
        build_project "$quiet_mode"
    else
        log "Skipping build step."
        log "Run with './run_benchmarks.sh build' to rebuild."
    fi

    # Initialize tracking
    for dir in "${benchmark_dirs[@]}"; do
        BENCHMARK_STAGE["$dir"]="NONE"
        INIT_GRAPH_EXIT_CODE["$dir"]="N/A"
    done

    # Disable set -e temporarily so individual failures don't abort the runner
    set +e
    truncate -s 0 "${SCRIPT_DIR}/instrumented_stdout.md" "${SCRIPT_DIR}/instrumented_stderr.md"
    for dir in "${benchmark_dirs[@]}"; do
        run_benchmark "$dir"
    done
    set -e

    print_benchmarks_summary
}

main "$@"
