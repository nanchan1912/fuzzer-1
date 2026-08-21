#!/usr/bin/env bash
set -euo pipefail

# ruN BUILD
# make clean afl SOURCES=./examples/sb.c
# ./run.sh ./barrier/data/barrier.instrumented.out

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Turn a possibly-relative path into an absolute one, relative to the current
# directory (i.e. how the caller typed it).
abspath() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    [[ "$path" = /* ]] || path="${PWD}/${path}"

    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$path"
    else
        printf '%s\n' "$path"
    fi
}

# Explicit arguments are resolved against the caller's directory; the fallback
# target is anchored to this script, so the default works from anywhere.
TARGET="$(abspath "${1:-${SCRIPT_DIR}/barrier/data/barrier.instrumented.out}")"
TARGET_DIR="$(dirname "$TARGET")"
STATIC_GRAPH="$(abspath "${2:-$TARGET_DIR/generated_output.ccfg}")"
INIT_SEED="$(abspath "${3:-$TARGET_DIR/init.sg.json}")"

TEST_RUN=0
AFL_POTENTIAL_LOCATIONS_FILE="${AFL_POTENTIAL_LOCATIONS_FILE:-}"     # $TARGET_DIR/locations.loc}"
AFL_INTERESTING_LOCATIONS_FILE="${AFL_INTERESTING_LOCATIONS_FILE:-}" # $TARGET_DIR/interesting_locations.loc}"
AFL_CHECK_DATA_RACE=${AFL_CHECK_DATA_RACE:-1}
AFL_ENABLE_FEEDBACK=${AFL_ENABLE_FEEDBACK:-1}
AFL_SKELETON_GRAPH_HIGHEST_STEP=${AFL_SKELETON_GRAPH_HIGHEST_STEP:-4}
THREAD_EVENT_COUNTS=${THREAD_EVENT_COUNTS:-} # "thread_event_counts.tc"}
AFL_CUTOFF_PERCENTILE=${AFL_CUTOFF_PERCENTILE:-0}
MAX_TIME=${MAX_TIME:-100}
# Stop at the first crash by default (quick manual runs). AFL treats any
# non-empty value as "on", so campaign runners must pass an *empty* string to
# spend the whole budget and get a usable bug-over-time curve. Hence ${x-1}
# rather than ${x:-1}: an explicit empty value has to survive.
AFL_BENCH_UNTIL_CRASH=${AFL_BENCH_UNTIL_CRASH-1}
RUN_QUEUE_VISUALIZER=${RUN_QUEUE_VISUALIZER:-1}
# locations.loc is copied back into the (shared) benchmark data dir. Concurrent
# runs of the same benchmark would clobber each other, so campaign runners turn
# this off and keep the per-run copy in their own output directory instead.
COPY_LOCATIONS=${COPY_LOCATIONS:-1}
AFL_TIMEOUT_GRACE=${AFL_TIMEOUT_GRACE:-30}

AFL_FUZZ="${AFL_FUZZ:-afl-fuzz}"
# Still default to the caller's directory, but pinned to an absolute path so
# every later reference agrees no matter where the script was launched from.
INPUT_DIR="$(abspath "${INPUT_DIR:-in}")"
OUTPUT_DIR="$(abspath "${OUTPUT_DIR:-out}")"

# The runtime's shared libraries live in the repo, not next to the CWD.
# Prepend rather than replace, so an SVF/LLVM search path from the surrounding
# environment survives. Trailing/duplicate ':' is stripped: an empty element in
# LD_LIBRARY_PATH means "current directory" to the loader.
RUNTIME_LIB_DIR="${REPO_ROOT}/src/build"
AFL_LD_LIBRARY_PATH="${RUNTIME_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
AFL_LD_LIBRARY_PATH="$(printf '%s' "$AFL_LD_LIBRARY_PATH" | sed -e 's/::*/:/g' -e 's/:$//')"

ensure_core_pattern_for_afl() {
    local core_pattern=""

    if [[ ! -r /proc/sys/kernel/core_pattern ]]; then
        return 0
    fi

    core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
    if [[ "${core_pattern}" != \|* ]]; then
        return 0
    fi

    echo "[*] core_pattern starts with a pipe; AFL crash handling may abort."

    if [[ -w /proc/sys/kernel/core_pattern ]]; then
        echo core > /proc/sys/kernel/core_pattern || true
    elif command -v sudo >/dev/null 2>&1; then
        # Use non-interactive sudo to avoid hanging in non-TTY runs.
        if sudo -n true 2>/dev/null; then
            echo core | sudo tee /proc/sys/kernel/core_pattern >/dev/null || true
        fi
    fi

    core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
    if [[ "${core_pattern}" == \|* ]]; then
        echo "Error: kernel.core_pattern is still piped: ${core_pattern}" >&2
        echo "Run this on the host (outside container), then rerun:" >&2
        echo "  sudo sysctl -w kernel.core_pattern=core" >&2
        echo "Or launch the container with writable /proc/sys and required privileges." >&2
        exit 1
    fi
}


if [[ ! -x "$TARGET" ]]; then
	echo "Error: target not found or not executable: $TARGET" >&2
	exit 1
fi

ensure_core_pattern_for_afl

if [[ "$TEST_RUN" -eq 1 ]]; then
    INPUT_FILE="${3:-./eg.json}"
    GEN_FILE="$INPUT_FILE"

    if [[ ! -f "$INPUT_FILE" ]]; then
        echo "Performing test run of target"
        set +e
        echo "" | env \
            LD_LIBRARY_PATH="$AFL_LD_LIBRARY_PATH" \
            GEN_EG="$GEN_FILE" \
            "$TARGET"
        RET=$?
        set -e
    else
        echo "Performing test run of target with input file: $INPUT_FILE (no gen)"
        set +e
        env \
            LD_LIBRARY_PATH="$AFL_LD_LIBRARY_PATH" \
            FUZZ_INPUT="$INPUT_FILE" \
            "$TARGET"
        RET=$?
        set -e
        # check with user and clean up
        read -p "Test run completed with input file $INPUT_FILE. Do you want to delete the input file? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f "$INPUT_FILE"
            echo "Input file $INPUT_FILE deleted."
        else
            echo "Input file $INPUT_FILE retained."
        fi
    fi

    ISABORT=0
    SIGNAL=0
    if [[ $RET -ge 128 ]]; then
        SIGNAL=$((RET - 128))
        if [[ $SIGNAL -eq 6 ]]; then
            ISABORT=1
        fi
    fi

    echo "Test run completed: EXIT=$RET SIGNAL=$SIGNAL ISABORT=$ISABORT"
    exit "$RET"
fi


# Development options (defaults):
# -d              Skip initial crash detection
# -n              Dumb fuzzing (no instrumentation needed)
# -t <timeout>    Timeout for target execution
# -m <memory>     Memory limit per process
# -p schedule     Fuzzing strategy (fast, coe, lin, quad, mopt, rare)
# -x dict_file    Fuzzing dictionary

# Environment variables:
# LD_LIBRARY_PATH  Path to shared libraries (../src/build)
# AFL_SKIP_CRASHES Skip crashes during fuzzing
# AFL_SKIP_BUSY    Skip busy processes
# AFL_DEBUG        Enable debug output
# AFL_QUIET        Suppress non-essential output
# AFL_SKIP_CPUFREQ Skip CPU frequency scaling checks
# AFL_NO_AFFINITY  Disable CPU affinity
# AFL_BENCH_UNTIL_CRASH Run in benchmark mode until a crash is found
# AFL_SKIP_BIN_CHECK Skip binary checks that if instrumented with AFL?

rm -rf "$INPUT_DIR"
mkdir -p "$INPUT_DIR"
cp "$INIT_SEED" "$INPUT_DIR/seed.json"
rm -rf "$OUTPUT_DIR"

	# AFL_QUIET=0 \
    # AFL_NO_UI=1 \
	# AFL_SKIP_BUSY=0 \
set +e
# The outer timeout is only a backstop for an AFL that ignores -V; give it
# slack so the normal case shuts down cleanly and still writes fuzzer_stats.
timeout --foreground $((MAX_TIME + AFL_TIMEOUT_GRACE)) env \
	LD_LIBRARY_PATH="$AFL_LD_LIBRARY_PATH" \
	AFL_SKIP_CRASHES=0 \
	AFL_SKIP_CPUFREQ=1 \
	AFL_NO_AFFINITY=1 \
    AFL_EXIT_WHEN_DONE=1 \
    AFL_BENCH_UNTIL_CRASH="$AFL_BENCH_UNTIL_CRASH" \
    AFL_ENABLE_FEEDBACK="$AFL_ENABLE_FEEDBACK" \
    AFL_CHECK_DATA_RACE="$AFL_CHECK_DATA_RACE" \
    AFL_SKELETON_GRAPH_HIGHEST_STEP="$AFL_SKELETON_GRAPH_HIGHEST_STEP" \
    THREAD_EVENT_COUNTS="$THREAD_EVENT_COUNTS" \
    AFL_POTENTIAL_LOCATIONS_FILE="$AFL_POTENTIAL_LOCATIONS_FILE" \
    AFL_INTERESTING_LOCATIONS_FILE="$AFL_INTERESTING_LOCATIONS_FILE" \
    AFL_CUTOFF_PERCENTILE="$AFL_CUTOFF_PERCENTILE" \
	$AFL_FUZZ -i "$INPUT_DIR" -o "$OUTPUT_DIR" -V $MAX_TIME \
    -t 30000 \
    -v ${STATIC_GRAPH} \
    -- "$TARGET"
set -e

if [[ "$COPY_LOCATIONS" == "0" ]]; then
    :
elif [[ -f "$OUTPUT_DIR/default/locations.loc" ]]; then
    echo "Copying AFL locations file to target directory: $TARGET_DIR/locations.loc"
    cp "$OUTPUT_DIR/default/locations.loc" "$TARGET_DIR/locations.loc"
else
    echo "Warning: AFL locations file not found in output directory: $OUTPUT_DIR/default/locations.loc"
fi

QUEUE_VISUALIZER="${QUEUE_VISUALIZER:-${REPO_ROOT}/src/tools/afl_queue_visualizer.py}"

if [[ "$RUN_QUEUE_VISUALIZER" != "0" && -f "$QUEUE_VISUALIZER" ]]; then
    python3 -m py_compile "$QUEUE_VISUALIZER" \
        && python3 "$QUEUE_VISUALIZER" \
            --afl-out "${OUTPUT_DIR}/default" \
            --pg "${STATIC_GRAPH}" \
            --out "${OUTPUT_DIR}/default/queue_visualizer.html"
fi
