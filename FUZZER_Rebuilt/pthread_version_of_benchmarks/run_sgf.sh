#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-./barrier/data/barrier.instrumented.out}"
TARGET_DIR="$(dirname "$TARGET")"
STATIC_GRAPH="${2:-$TARGET_DIR/generated_output.ccfg}"
INIT_SEED="${3:-$TARGET_DIR/init.sg.json}"

TEST_RUN=0
SGF_POTENTIAL_LOCATIONS_FILE="${SGF_POTENTIAL_LOCATIONS_FILE:-${AFL_POTENTIAL_LOCATIONS_FILE:-$TARGET_DIR/locations.loc}}"
SGF_INTERESTING_LOCATIONS_FILE="${SGF_INTERESTING_LOCATIONS_FILE:-${AFL_INTERESTING_LOCATIONS_FILE:-$TARGET_DIR/interesting_locations.loc}}"
SGF_CHECK_DATA_RACE="${SGF_CHECK_DATA_RACE:-${AFL_CHECK_DATA_RACE:-0}}"
SGF_ENABLE_FEEDBACK="${SGF_ENABLE_FEEDBACK:-${AFL_ENABLE_FEEDBACK:-0}}"
SGF_SKELETON_GRAPH_HIGHEST_STEP="${SGF_SKELETON_GRAPH_HIGHEST_STEP:-${AFL_SKELETON_GRAPH_HIGHEST_STEP:-3}}"
THREAD_EVENT_COUNTS="${THREAD_EVENT_COUNTS:-$TARGET_DIR/thread_event_counts.tc}"
SGF_CUTOFF_PERCENTILE="${SGF_CUTOFF_PERCENTILE:-${AFL_CUTOFF_PERCENTILE:-0}}"
SGF_QUEUE_IMPL="${SGF_QUEUE_IMPL:-${AFL_QUEUE_IMPL:-maxheap}}"
MAX_TIME="${MAX_TIME:-100}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_DIR="$(cd "$SCRIPT_DIR/../Main" && pwd)"

# Resolve sgf-fuzz binary
SGF_FUZZ="${SGF_FUZZ:-${AFL_FUZZ:-}}"
if [[ -z "$SGF_FUZZ" ]]; then
    if [[ -x "$MAIN_DIR/sgf-fuzz" ]]; then
        SGF_FUZZ="$MAIN_DIR/sgf-fuzz"
    elif command -v sgf-fuzz >/dev/null 2>&1; then
        SGF_FUZZ="sgf-fuzz"
    elif [[ -x "$MAIN_DIR/afl-fuzz" ]]; then
        SGF_FUZZ="$MAIN_DIR/afl-fuzz"
    else
        echo "[*] Building sgf-fuzz..."
        make -C "$MAIN_DIR" sgf-fuzz
        SGF_FUZZ="$MAIN_DIR/sgf-fuzz"
    fi
fi

INPUT_DIR="${INPUT_DIR:-in}"
OUTPUT_DIR="${OUTPUT_DIR:-out}"

ensure_core_pattern_for_sgf() {
    local core_pattern=""

    if [[ ! -r /proc/sys/kernel/core_pattern ]]; then
        return 0
    fi

    core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
    if [[ "${core_pattern}" != \|* ]]; then
        return 0
    fi

    echo "[*] core_pattern starts with a pipe; crash handling may abort."

    if [[ -w /proc/sys/kernel/core_pattern ]]; then
        echo core > /proc/sys/kernel/core_pattern || true
    elif command -v sudo >/dev/null 2>&1; then
        if sudo -n true 2>/dev/null; then
            echo core | sudo tee /proc/sys/kernel/core_pattern >/dev/null || true
        fi
    fi

    core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
    if [[ "${core_pattern}" == \|* ]]; then
        echo "Note: kernel.core_pattern is piped: ${core_pattern}" >&2
        echo "Set SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 to proceed without modifying core_pattern." >&2
    fi
}

if [[ ! -x "$TARGET" ]]; then
	echo "Error: target not found or not executable: $TARGET" >&2
	exit 1
fi

ensure_core_pattern_for_sgf

if [[ "$TEST_RUN" -eq 1 ]]; then
    INPUT_FILE="${3:-./eg.json}"
    GEN_FILE="$INPUT_FILE"

    if [[ ! -f "$INPUT_FILE" ]]; then
        echo "Performing test run of target"
        set +e
        echo "" | env \
            LD_LIBRARY_PATH="$MAIN_DIR/../src/build/" \
            GEN_EG="$GEN_FILE" \
            "$TARGET"
        RET=$?
        set -e
    else
        echo "Performing test run of target with input file: $INPUT_FILE (no gen)"
        set +e
        env \
            LD_LIBRARY_PATH="$MAIN_DIR/../src/build/" \
            FUZZ_INPUT="$INPUT_FILE" \
            "$TARGET"
        RET=$?
        set -e
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

rm -rf "$INPUT_DIR"
mkdir -p "$INPUT_DIR"
if [[ -f "$INIT_SEED" ]]; then
    cp "$INIT_SEED" "$INPUT_DIR/seed.json"
elif [[ -d "$INIT_SEED" ]]; then
    cp "$INIT_SEED"/* "$INPUT_DIR/"
fi
rm -rf "$OUTPUT_DIR"

set +e
timeout --foreground "$MAX_TIME" env \
	LD_LIBRARY_PATH="$MAIN_DIR/../src/build/" \
	SGF_SKIP_CRASHES=0 \
	SGF_SKIP_CPUFREQ=1 \
	SGF_NO_AFFINITY=1 \
	SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    SGF_EXIT_WHEN_DONE=1 \
    SGF_BENCH_UNTIL_CRASH=1 \
    SGF_ENABLE_FEEDBACK="$SGF_ENABLE_FEEDBACK" \
    SGF_CHECK_DATA_RACE="$SGF_CHECK_DATA_RACE" \
    SGF_SKELETON_GRAPH_HIGHEST_STEP="$SGF_SKELETON_GRAPH_HIGHEST_STEP" \
    THREAD_EVENT_COUNTS="$THREAD_EVENT_COUNTS" \
    SGF_POTENTIAL_LOCATIONS_FILE="$SGF_POTENTIAL_LOCATIONS_FILE" \
    SGF_INTERESTING_LOCATIONS_FILE="$SGF_INTERESTING_LOCATIONS_FILE" \
    SGF_CUTOFF_PERCENTILE="$SGF_CUTOFF_PERCENTILE" \
    SGF_QUEUE_IMPL="$SGF_QUEUE_IMPL" \
	"$SGF_FUZZ" -i "$INPUT_DIR" -o "$OUTPUT_DIR" -V "$MAX_TIME" \
    -t 3000 \
    -v "${STATIC_GRAPH}" \
    -- "$TARGET"
set -e

if [[ -f "$OUTPUT_DIR/default/locations.loc" ]]; then
    cp "$OUTPUT_DIR/default/locations.loc" "$TARGET_DIR/locations.loc"
fi
