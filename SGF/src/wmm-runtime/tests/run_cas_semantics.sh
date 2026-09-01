#!/usr/bin/env bash
# Stage 2 verification: exercise every strong-CAS row of the decision table
# plus the legacy-graph compatibility case.
#
#   ./run_cas_semantics.sh
#
# Each case builds a one-write + one-cmpxchg graph, runs the test binary
# against it, and asserts the runtime's exit code:
#
#    0  the graph was fully covered and the program ran to completion
#   21  (WMM_EXIT_NOT_INSTANTIABLE) the graph demanded an outcome the values
#       cannot produce
#
# Note 20 (INSTANTIATED_BUT_NOT_DONE) is *not* expected here: it is raised when
# execution hits an event the graph does not describe, and these fixtures
# describe every event the test performs.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${RUNTIME_DIR}/../.." && pwd)"

BIN="${SCRIPT_DIR}/test_cas_semantics.out"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "=== building ==="
clang -O0 -g -I"${RUNTIME_DIR}" -I"${REPO_ROOT}/Main/include" \
      "${SCRIPT_DIR}/test_cas_semantics.c" \
      -L"${RUNTIME_DIR}" -lwmm_runtime -lpthread -ldl -lrt -lstdc++ \
      -o "$BIN" || { echo "build failed"; exit 1; }

# $1 = cmpxchg node kind, $2 = output path
make_graph() {
    cat > "$2" <<EOF
{
  "nodes": [
    {"event_id": 1, "thread_id": 0, "kind": "W", "loc": "shared", "value": 42,
     "instruction_id": 1, "loc_id": 12345, "visit_id": 1},
    {"event_id": 2, "thread_id": 0, "kind": "$1", "loc": "shared", "value": 99,
     "instruction_id": 2, "loc_id": 12345, "visit_id": 1}
  ],
  "rf_edges": [
    {"from": ["0", "1", "1"], "to": [["0", "2", "1"]]}
  ]
}
EOF
}

pass=0; fail=0

# $1 label, $2 kind, $3 compare_val, $4 expected exit code, $5 expected swap yes/no
run_case() {
    local label="$1" kind="$2" cmp="$3" want="$4" want_swap="$5"
    local g="${WORK}/g.json" out="${WORK}/out.txt"
    make_graph "$kind" "$g"

    FUZZ_INPUT="$g" QUIET=1 "$BIN" "$cmp" > "$out" 2>&1
    local code=$?
    local swap
    swap="$(grep -o 'swapped=[a-z]*' "$out" | head -1 | cut -d= -f2)"

    local ok=1
    [[ "$code" == "$want" ]] || ok=0
    # swap is only observable on runs that completed
    if [[ -n "$want_swap" && "$code" == "0" && "$swap" != "$want_swap" ]]; then ok=0; fi

    if [[ $ok -eq 1 ]]; then
        echo "  [PASS] ${label}  (exit=${code} swapped=${swap:-n/a})"
        pass=$((pass+1))
    else
        echo "  [FAIL] ${label}  exit=${code} (want ${want}) swapped=${swap:-n/a} (want ${want_swap:-any})"
        sed 's/^/         | /' "$out" | tail -5
        fail=$((fail+1))
    fi
}

echo
echo "=== strong CAS decision table ==="
# compare 42 == stored 42 -> comparison SUCCEEDS
run_case "expected SUCCESS, compare succeeds -> swap"        CAS_SUCCESS 42  0 yes
run_case "expected FAIL,    compare fails    -> no swap"     CAS_FAIL     7  0 no
# mismatches are not instantiable
run_case "expected SUCCESS, compare fails    -> exit 21"     CAS_SUCCESS  7 21 ""
run_case "expected FAIL,    compare succeeds -> exit 21"     CAS_FAIL    42 21 ""

echo
echo "=== backward compatibility (legacy graphs carry no expectation) ==="
run_case "legacy RMW node, compare succeeds  -> swap"        RMW         42  0 yes
run_case "legacy RMW node, compare fails     -> no swap"     RMW          7  0 no
# An input graph must commit to an outcome. Bare "CAS" means "undecided", which
# is only meaningful as runtime->fuzzer feedback; arriving as input it is
# rejected (12 = WMM_EXIT_INVALID_INPUT) rather than silently read as success,
# which would make the failure half of every CAS unreachable.
run_case "unresolved CAS node in input        -> exit 12"    CAS         42 12 ""

echo
echo "${pass} passed, ${fail} failed"
rm -f "$BIN"
[[ $fail -eq 0 ]]
