#!/usr/bin/env bash
# An unknown cmpxchg is published to the fuzzer as a single outcome-free CAS
# event, whatever the flavour and whatever the values happen to be.
#
# This is the point of the test. The runtime *could* compare the value sitting
# in memory and publish CAS_SUCCESS or CAS_FAIL accordingly -- an earlier
# version did -- but that verdict is fiction: an unknown event has no rf edge,
# so the value it reads under the bypass is not the value it will read once the
# fuzzer picks a source write. Publishing it would bias every CAS toward the
# outcome of the unscheduled run. Only the fuzzer, which chooses the rf edge,
# can decide the outcome, so the runtime hands over the undecided event.
#
# So all four combinations below must produce the *same* feedback:
#
#   weak,   comparison succeeded -> 1 candidate, type CAS
#   weak,   comparison failed    -> 1 candidate, type CAS
#   strong, comparison succeeded -> 1 candidate, type CAS
#   strong, comparison failed    -> 1 candidate, type CAS
#
# A "CAS_SUCCESS"/"CAS_FAIL" here means the runtime went back to guessing; an
# "Unknown" means the duplicate eg_type_to_string in scheduler.c was missed.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${RUNTIME_DIR}/../.." && pwd)"

BIN="${SCRIPT_DIR}/test_cas_unknown.out"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; rm -f "$BIN"' EXIT

clang -O0 -g -I"${RUNTIME_DIR}" -I"${REPO_ROOT}/main/include" \
      "${SCRIPT_DIR}/test_cas_weak.c" \
      -L"${RUNTIME_DIR}" -lwmm_runtime -lpthread -ldl -lrt -lstdc++ \
      -o "$BIN" || { echo "build failed"; exit 1; }

# Graph describes ONLY the init store, so the cmpxchg is an unknown event: the
# runtime reaches it, finds no matching node, publishes it as a next-event
# candidate and exits 20 (INSTANTIATED_BUT_NOT_DONE).
cat > "${WORK}/g.json" <<'EOF'
{
  "nodes": [
    {"event_id": 1, "thread_id": 0, "kind": "W", "loc": "shared", "value": 42,
     "instruction_id": 1, "loc_id": 12345, "visit_id": 1}
  ],
  "rf_edges": []
}
EOF

pass=0; fail=0

# $1 label, $2 flavour, $3 compare_val
run_case() {
    local label="$1" flavour="$2" cmp="$3"
    local out="${WORK}/out.txt"
    FUZZ_INPUT="${WORK}/g.json" "$BIN" "$flavour" "$cmp" > "$out" 2>&1
    local code=$?

    # Candidate lines for the cmpxchg event (instruction_id 2).
    local lines n types
    lines="$(sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$out" | grep '\[NXT_EVNT\]' | grep 'iid=2 ')"
    n="$(printf '%s' "$lines" | grep -c .)"
    types="$(printf '%s\n' "$lines" | grep -oE 'event type=[A-Z_]+' | sed 's/event type=//' | sort -u | tr '\n' ' ' | sed 's/ $//')"

    local ok=1
    [[ "$code" == "20" ]] || ok=0
    [[ "$n" == "1" ]] || ok=0
    [[ "$types" == "CAS" ]] || ok=0

    if [[ $ok -eq 1 ]]; then
        echo "  [PASS] ${label}: exit=${code}, 1 candidate [CAS]"
        pass=$((pass+1))
    else
        echo "  [FAIL] ${label}: exit=${code} (want 20), got ${n} candidate(s) [${types:-<none>}] (want 1 [CAS])"
        printf '%s\n' "$lines" | sed 's/^/         | /'
        fail=$((fail+1))
    fi
}

echo "=== unknown cmpxchg published as one outcome-free CAS ==="
run_case "weak,   comparison succeeds" weak   42
run_case "weak,   comparison fails"    weak    7
run_case "strong, comparison succeeds" strong 42
run_case "strong, comparison fails"    strong  7

echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
