#!/usr/bin/env bash

VISUALIZE_SCRIPT="../../visualize.py"
BASE_DIR="../output/default/queue"

matches=( "$BASE_DIR"/src:000000,id:*.json )

if [[ ${#matches[@]} -eq 0 ]]; then
    echo "⚠️  No files found with src:000000"
    exit 0
fi

for file in "${matches[@]}"; do
    echo "▶ Visualizing $file"
    python3 "$VISUALIZE_SCRIPT" "$file"
done
