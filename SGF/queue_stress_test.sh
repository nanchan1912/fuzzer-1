#!/usr/bin/env bash
set -uo pipefail

QUEUES=(maxheap threshold_bucket runner_up maxheap_bucket)
TESTCASES=(msg_passing sb load_buffering barrier)
DURATION=20

echo "Queue        | Testcase      | Exit Code | Result"
echo "------------- | ------------- | --------- | ------"

for q in "${QUEUES[@]}"; do
    for t in "${TESTCASES[@]}"; do
        OUT=$(./run.sh "$t" -q "$q" -t "$DURATION" 2>&1)
        CODE=$(echo "$OUT" | grep -oP 'Exit Code: \K[0-9]+' | tail -1)
        if [[ -z "$CODE" ]]; then
            CODE=$(echo "$OUT" | grep -oP 'terminated with code \K[0-9]+' | tail -1)
        fi
        if [[ "$CODE" == "139" ]]; then
            RESULT="SEGFAULT"
        elif [[ "$CODE" == "134" ]]; then
            RESULT="ABORT"
        elif [[ "$CODE" == "0" ]]; then
            RESULT="ok"
        else
            RESULT="unknown (code=$CODE)"
        fi
        printf "%-13s | %-13s | %-9s | %s\n" "$q" "$t" "${CODE:-?}" "$RESULT"
    done
done
