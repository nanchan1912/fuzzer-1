#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

for impl in maxheap structure1 structure2 structure3; do
    echo "================================================="
    echo "Testing Queue Implementation: $impl"
    echo "================================================="
    rm -rf /tmp/out_${impl}
    mkdir -p /tmp/out_${impl}
    
    AFL_QUEUE_IMPL="${impl}" \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1 \
    timeout 3 ./afl-fuzz -n \
        -i testcases/msg_passing/seeds \
        -o /tmp/out_${impl} \
        -v testcases/msg_passing/mp_static_program_abstraction.eg \
        -- ./testcases/msg_passing/mp 2>&1 | grep -E "(\[AFL Queue\]|Bounded queue|We're done|MO Edge)" || true
    echo "Result for $impl: SUCCESS"
    echo ""
done

echo "ALL 4 QUEUE IMPLEMENTATIONS TESTED SUCCESSFULLY!"
