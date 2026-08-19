#!/usr/bin/env bash
shopt -s nullglob

BASE_DIR="../output/default/queue"

# Counters
c_00_23=0
c_11_23=0
c_11_24=0
c_12_23=0
bad_json=0

for f in "$BASE_DIR"/*.json; do
    # First: validate JSON
    if ! jq empty "$f" >/dev/null 2>&1; then
        echo "❌ Invalid JSON: $f"
        ((bad_json++))
        continue
    fi

    # [0,0] -> [2,3]
    jq -e 'any(.rf_edges[]?; .from == [0,0] and any(.to[]?; . == [2,3]))' "$f" >/dev/null \
        && ((c_00_23++))

    # [1,1] -> [2,3]
    jq -e 'any(.rf_edges[]?; .from == [1,1] and any(.to[]?; . == [2,3]))' "$f" >/dev/null \
        && ((c_11_23++))

    # [1,1] -> [2,4]
    jq -e 'any(.rf_edges[]?; .from == [1,1] and any(.to[]?; . == [2,4]))' "$f" >/dev/null \
        && ((c_11_24++))

    # [1,2] -> [2,3]
    jq -e 'any(.rf_edges[]?; .from == [1,2] and any(.to[]?; . == [2,3]))' "$f" >/dev/null \
        && ((c_12_23++))
done

echo
echo "===== RESULTS ====="
echo "[0,0] -> [2,3] : $c_00_23 files"
echo "[1,1] -> [2,3] : $c_11_23 files"
echo "[1,1] -> [2,4] : $c_11_24 files"
echo "[1,2] -> [2,3] : $c_12_23 files"
echo "Invalid JSON files : $bad_json"
