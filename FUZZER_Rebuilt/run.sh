#!/usr/bin/env bash
# ==============================================================================
# SGF (Skeleton Graph Fuzzer) Unified Runner
#
# Usage:
#   ./run.sh <testcase_or_benchmark_name>
#   ./run.sh <path_to_target_binary>
#   ./run.sh -i <seeds> -v <graph> -o <out> -- <target_command>
#
# Examples:
#   ./run.sh msg_passing
#   ./run.sh sb
#   ./run.sh load_buffering
#   ./run.sh barrier
#   SGF_QUEUE_IMPL=structure2 ./run.sh msg_passing
#   ./run.sh --queue structure1 --time 30 msg_passing
#   ./run.sh test_queues
# ==============================================================================

set -euo pipefail

# Determine script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/Main" ]]; then
    ROOT_DIR="$SCRIPT_DIR"
    MAIN_DIR="$SCRIPT_DIR/Main"
    BENCHMARKS_DIR="$SCRIPT_DIR/pthread_version_of_benchmarks"
elif [[ -f "$SCRIPT_DIR/GNUmakefile" ]]; then
    MAIN_DIR="$SCRIPT_DIR"
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    BENCHMARKS_DIR="$ROOT_DIR/pthread_version_of_benchmarks"
else
    MAIN_DIR="$SCRIPT_DIR"
    ROOT_DIR="$SCRIPT_DIR"
    BENCHMARKS_DIR="$SCRIPT_DIR/pthread_version_of_benchmarks"
fi

TESTCASES_DIR="$MAIN_DIR/testcases"

# Defaults
QUEUE_IMPL="${SGF_QUEUE_IMPL:-maxheap}"
RUN_TIME="${RUN_TIME:-${MAX_TIME:-10}}"
INPUT_SRC=""
OUTPUT_DIR=""
STATIC_GRAPH=""
TARGET_CMD=()
CUSTOM_MODE=0

show_help() {
    cat << 'EOF'
==============================================================================
               SGF (Skeleton Graph Fuzzer) Runner
==============================================================================

USAGE:
  ./run.sh [OPTIONS] <TARGET_OR_TESTCASE> [-- <TARGET_ARGS...>]

BUILT-IN TESTCASES:
  ./run.sh msg_passing          (alias: mp)
  ./run.sh sb                   (alias: sb-loop, store_buffering)
  ./run.sh load_buffering       (alias: lb)
  ./run.sh mp_loc
  ./run.sh mp_ra
  ./run.sh isJson

BENCHMARKS:
  ./run.sh barrier              (or any benchmark in pthread_version_of_benchmarks)
  ./run.sh <path/to/target.instrumented.out>

SPECIAL COMMANDS:
  ./run.sh test_queues          (tests all 4 queue implementations)
  ./run.sh build                (builds sgf-fuzz and supporting tools)
  ./run.sh clean                (cleans build artifacts and temp output)

OPTIONS:
  -q, --queue <NAME>      Queue data structure: maxheap (default),
                          structure1, structure2, structure3
  -t, --time <SECONDS>    Fuzzing duration in seconds (default: 10)
  -i, --input <PATH>      Seed input directory or JSON seed file
  -o, --output <PATH>     Output directory (default: /tmp/sgf_out_<target>)
  -v, --graph <PATH>      Static abstraction graph (.ccfg / .eg / .pg)
  -h, --help              Show this help message

ENVIRONMENT VARIABLES:
  SGF_QUEUE_IMPL          Queue implementation (maxheap, structure1, structure2, structure3)
  SGF_ENABLE_FEEDBACK     Enable simulator feedback (0 or 1, default: 0)
  SGF_CHECK_DATA_RACE     Enable data race checking (0 or 1, default: 0)
  MAX_TIME / RUN_TIME     Fuzzing time limit in seconds (default: 10)
==============================================================================
EOF
}

# Ensure sgf-fuzz is built
build_sgf_fuzz() {
    if [[ ! -x "$MAIN_DIR/sgf-fuzz" ]]; then
        echo "[*] Building sgf-fuzz in $MAIN_DIR..."
        make -C "$MAIN_DIR" sgf-fuzz
    fi
}

# Compile a testcase C source file if needed
compile_testcase_if_needed() {
    local dir="$1"
    local src="$2"
    local bin="$3"

    if [[ ! -x "$dir/$bin" ]]; then
        if [[ -f "$dir/$src" ]]; then
            echo "[*] Compiling testcase: $dir/$src -> $dir/$bin"
            gcc -O0 -pthread "$dir/$src" -o "$dir/$bin"
        fi
    fi
}

# Parse command line options
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -q|--queue)
            QUEUE_IMPL="$2"
            shift 2
            ;;
        -t|--time|-V)
            RUN_TIME="$2"
            shift 2
            ;;
        -i|--input)
            INPUT_SRC="$2"
            CUSTOM_MODE=1
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--graph)
            STATIC_GRAPH="$2"
            CUSTOM_MODE=1
            shift 2
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do
                TARGET_CMD+=("$1")
                shift
            done
            CUSTOM_MODE=1
            break
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# If no arguments provided and not in custom mode, show help
if [[ ${#POSITIONAL[@]} -eq 0 ]] && [[ $CUSTOM_MODE -eq 0 ]]; then
    show_help
    exit 0
fi

TARGET_NAME="${POSITIONAL[0]:-}"

# Special command: test_queues
if [[ "$TARGET_NAME" == "test_queues" || "$TARGET_NAME" == "queues" || "$TARGET_NAME" == "test-all-queues" ]]; then
    build_sgf_fuzz
    exec bash "$MAIN_DIR/test_all_queues.sh"
fi

# Special command: build
if [[ "$TARGET_NAME" == "build" || "$TARGET_NAME" == "compile" ]]; then
    echo "[*] Building sgf-fuzz..."
    make -C "$MAIN_DIR" sgf-fuzz
    echo "[+] Build complete: $MAIN_DIR/sgf-fuzz"
    exit 0
fi

# Special command: clean
if [[ "$TARGET_NAME" == "clean" ]]; then
    echo "[*] Cleaning build artifacts..."
    make -C "$MAIN_DIR" clean || true
    rm -rf /tmp/sgf_out_* /tmp/out_* /tmp/fuzz_out* /tmp/fuzz_in*
    echo "[+] Cleanup complete."
    exit 0
fi

# Ensure fuzzer binary is ready
build_sgf_fuzz
SGF_BIN="$MAIN_DIR/sgf-fuzz"

# Resolve target configuration if named testcase / benchmark
if [[ $CUSTOM_MODE -eq 0 || -z "$STATIC_GRAPH" || -z "$INPUT_SRC" || ${#TARGET_CMD[@]} -eq 0 ]]; then
    case "$TARGET_NAME" in
        msg_passing|mp)
            TC_DIR="$TESTCASES_DIR/msg_passing"
            compile_testcase_if_needed "$TC_DIR" "mp.c" "mp"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/mp_static_program_abstraction.eg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_mp}"
            TARGET_CMD=("$TC_DIR/mp")
            ;;
        sb|sb-loop|store_buffering)
            TC_DIR="$TESTCASES_DIR/sb"
            compile_testcase_if_needed "$TC_DIR" "sb.c" "sb"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/generated_output.ccfg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_sb}"
            if [[ -x "$TC_DIR/sb-loop.instrumented.out" ]]; then
                TARGET_CMD=("$TC_DIR/sb-loop.instrumented.out")
            else
                TARGET_CMD=("$TC_DIR/sb")
            fi
            ;;
        load_buffering|lb)
            TC_DIR="$TESTCASES_DIR/load_buffering"
            compile_testcase_if_needed "$TC_DIR" "lb.c" "lb"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/lb_static_program_abstraction.eg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_lb}"
            TARGET_CMD=("$TC_DIR/lb")
            ;;
        mp_loc)
            TC_DIR="$TESTCASES_DIR/mp_loc"
            compile_testcase_if_needed "$TC_DIR" "mp.c" "mp"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/mp_static_program_abstraction.eg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_mp_loc}"
            TARGET_CMD=("$TC_DIR/mp")
            ;;
        mp_ra)
            TC_DIR="$TESTCASES_DIR/mp_ra"
            compile_testcase_if_needed "$TC_DIR" "mp.c" "mp"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/mp_static_program_abstraction.eg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_mp_ra}"
            TARGET_CMD=("$TC_DIR/mp")
            ;;
        isJson|input_is_json)
            TC_DIR="$TESTCASES_DIR/input_is_json"
            compile_testcase_if_needed "$TC_DIR" "isJson.c" "isJson"
            INPUT_SRC="${INPUT_SRC:-$TC_DIR/seeds}"
            STATIC_GRAPH="${STATIC_GRAPH:-$TC_DIR/mp_static_program_abstraction.eg}"
            OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_isJson}"
            TARGET_CMD=("$TC_DIR/isJson")
            ;;
        *)
            # Check if it is a benchmark name in pthread_version_of_benchmarks
            if [[ -d "$BENCHMARKS_DIR/$TARGET_NAME/data" ]]; then
                BM_DATA="$BENCHMARKS_DIR/$TARGET_NAME/data"
                INST_BIN="$(find "$BM_DATA" -maxdepth 1 \( -name "*.instrumented.out" -o -name "*.out" \) -executable | head -n 1)"
                STATIC_GRAPH="${STATIC_GRAPH:-$(find "$BM_DATA" -maxdepth 1 \( -name "generated_output.ccfg" -o -name "generated_output.pg" -o -name "*.eg" \) | head -n 1)}"
                INPUT_SRC="${INPUT_SRC:-$(find "$BM_DATA" -maxdepth 1 \( -name "init.sg.json" -o -name "*.json" \) | head -n 1)}"
                OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_$TARGET_NAME}"
                TARGET_CMD=("$INST_BIN")
            elif [[ -d "$BENCHMARKS_DIR/$TARGET_NAME" ]]; then
                BM_DIR="$BENCHMARKS_DIR/$TARGET_NAME"
                INST_BIN="$(find "$BM_DIR" -maxdepth 2 \( -name "*.instrumented.out" -o -name "*.out" \) -executable | head -n 1)"
                STATIC_GRAPH="${STATIC_GRAPH:-$(find "$BM_DIR" -maxdepth 2 \( -name "generated_output.ccfg" -o -name "generated_output.pg" -o -name "*.eg" \) | head -n 1)}"
                INPUT_SRC="${INPUT_SRC:-$(find "$BM_DIR" -maxdepth 2 \( -name "init.sg.json" -o -name "*.json" \) | head -n 1)}"
                OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_$TARGET_NAME}"
                if [[ -n "$INST_BIN" ]]; then
                    TARGET_CMD=("$INST_BIN")
                fi
            elif [[ -f "$TARGET_NAME" ]]; then
                # Target binary passed as path
                TARGET_BIN_DIR="$(dirname "$TARGET_NAME")"
                STATIC_GRAPH="${STATIC_GRAPH:-$(find "$TARGET_BIN_DIR" -maxdepth 1 -name "generated_output.ccfg" -o -name "generated_output.pg" -o -name "*.eg" | head -n 1)}"
                if [[ -f "$TARGET_BIN_DIR/init.sg.json" ]]; then
                    INPUT_SRC="${INPUT_SRC:-$TARGET_BIN_DIR/init.sg.json}"
                elif [[ -d "$TARGET_BIN_DIR/seeds" ]]; then
                    INPUT_SRC="${INPUT_SRC:-$TARGET_BIN_DIR/seeds}"
                elif [[ -d "$TARGET_BIN_DIR/../seeds" ]]; then
                    INPUT_SRC="${INPUT_SRC:-$TARGET_BIN_DIR/../seeds}"
                fi
                BASE_NAME="$(basename "$TARGET_NAME" | sed 's/\.instrumented\.out//; s/\.out//')"
                OUTPUT_DIR="${OUTPUT_DIR:-/tmp/sgf_out_$BASE_NAME}"
                TARGET_CMD=("$TARGET_NAME")
            else
                echo "Error: Unrecognized testcase, benchmark, or file: $TARGET_NAME" >&2
                echo "Run './run.sh --help' to see available targets." >&2
                exit 1
            fi
            ;;
    esac
fi

# Validate inputs
if [[ -z "$STATIC_GRAPH" || ! -f "$STATIC_GRAPH" ]]; then
    echo "Error: Static graph file not found: $STATIC_GRAPH" >&2
    exit 1
fi

if [[ -z "$INPUT_SRC" || (! -f "$INPUT_SRC" && ! -d "$INPUT_SRC") ]]; then
    echo "Error: Input seed directory/file not found: $INPUT_SRC" >&2
    exit 1
fi

if [[ ${#TARGET_CMD[@]} -eq 0 || ! -x "${TARGET_CMD[0]}" ]]; then
    echo "Error: Target executable not found or not executable: ${TARGET_CMD[0]:-(none)}" >&2
    exit 1
fi

# Prepare input directory
TEMP_IN_DIR="/tmp/sgf_in_$$"
rm -rf "$TEMP_IN_DIR"
mkdir -p "$TEMP_IN_DIR"

if [[ -f "$INPUT_SRC" ]]; then
    cp "$INPUT_SRC" "$TEMP_IN_DIR/seed.json"
elif [[ -d "$INPUT_SRC" ]]; then
    cp "$INPUT_SRC"/* "$TEMP_IN_DIR/"
fi

# Clean output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "=============================================================================="
echo " Starting SGF Fuzzing Run"
echo "=============================================================================="
echo " Target Binary : ${TARGET_CMD[*]}"
echo " Static Graph  : $STATIC_GRAPH"
echo " Seed Input    : $INPUT_SRC"
echo " Output Dir    : $OUTPUT_DIR"
echo " Queue Impl    : $QUEUE_IMPL"
echo " Duration      : ${RUN_TIME}s"
echo "=============================================================================="

# Export standard SGF environment variables
export SGF_QUEUE_IMPL="$QUEUE_IMPL"
export SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export SGF_SKIP_CPUFREQ=1
export SGF_NO_AFFINITY=1
export SGF_EXIT_WHEN_DONE=1

set +e
"$SGF_BIN" -n \
    -V "$RUN_TIME" \
    -i "$TEMP_IN_DIR" \
    -o "$OUTPUT_DIR" \
    -v "$STATIC_GRAPH" \
    -- "${TARGET_CMD[@]}"
RET=$?
set -e

# Cleanup temporary input dir
rm -rf "$TEMP_IN_DIR"

echo ""
echo "=============================================================================="
if [[ $RET -eq 0 ]]; then
    echo " [+] Fuzzing completed successfully (Exit Code: $RET)"
else
    echo " [*] Fuzzing terminated with code $RET"
fi
echo " Results written to: $OUTPUT_DIR"
echo "=============================================================================="

exit $RET
