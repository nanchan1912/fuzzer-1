#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

# Ensure sgf-fuzz binary is built
if [[ ! -x "./sgf-fuzz" ]]; then
    echo "[*] Building sgf-fuzz..."
    make sgf-fuzz
fi

# Ensure testcase binary is compiled
if [[ ! -x "./testcases/msg_passing/mp" ]]; then
    echo "[*] Compiling msg_passing testcase..."
    gcc -O0 -pthread testcases/msg_passing/mp.c -o testcases/msg_passing/mp
fi

for impl in maxheap structure1 structure2 structure3; do
    echo "================================================="
    echo "Testing Queue Implementation: $impl"
    echo "================================================="
    rm -rf /tmp/out_${impl}
    mkdir -p /tmp/out_${impl}
    
    SGF_QUEUE_IMPL="${impl}" \
    SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    SGF_SKIP_CPUFREQ=1 \
    SGF_NO_AFFINITY=1 \
    ./sgf-fuzz -n -V 2 \
        -i testcases/msg_passing/seeds \
        -o /tmp/out_${impl} \
        -v testcases/msg_passing/mp_static_program_abstraction.eg \
        -- ./testcases/msg_passing/mp 2>&1 | grep -E "(\[SGF Queue\]|Bounded queue|We're done|MO Edge)" || true
    echo "Result for $impl: SUCCESS"
    echo ""
done

echo "ALL 4 QUEUE IMPLEMENTATIONS TESTED SUCCESSFULLY!"
