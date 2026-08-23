#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <benchmark_name>" >&2
    echo "Example: $0 barrier" >&2
    exit 1
fi

BENCH_NAME="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_SCRIPT="$SCRIPT_DIR/run_all_analysis_compile.sh"

if [[ ! -d "$SCRIPT_DIR/$BENCH_NAME" ]]; then
    echo "Error: benchmark directory not found: $SCRIPT_DIR/$BENCH_NAME" >&2
    exit 1
fi

TMP_SCRIPT="$(mktemp "$SCRIPT_DIR/.generate_one.XXXXXX.sh")"
cleanup() { rm -f "$TMP_SCRIPT"; }
trap cleanup EXIT

# Copy every function from the real pipeline script, but drop its trailing
# `main "$@"` line -- we call setup_environment/run_benchmark ourselves,
# for just this one benchmark, instead of the full hardcoded suite.
head -n -1 "$MAIN_SCRIPT" > "$TMP_SCRIPT"

cat >> "$TMP_SCRIPT" << EOF
setup_environment 0
run_benchmark "$BENCH_NAME"
STATUS=\$?
echo ""
echo "Stage    : \${BENCHMARK_STAGE[$BENCH_NAME]}"
echo "InitGraph: \${INIT_GRAPH_EXIT_CODE[$BENCH_NAME]}"
exit \$STATUS
EOF

bash "$TMP_SCRIPT"
