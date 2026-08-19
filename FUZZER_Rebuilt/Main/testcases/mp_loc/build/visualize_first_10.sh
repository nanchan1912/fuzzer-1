#!/usr/bin/env bash

VISUALIZE_SCRIPT="../../visualize.py"
BASE_DIR="../output/default/queue"

# Loop from id 1 to 10
for id in $(seq -w 1 10); do
    # Find file matching src:XXXXXX,id:00000{id}.json
    # file=$(ls ${BASE_DIR}/src:[0-9][0-9][0-9][0-9][0-9][0-9],id:00000${id}.json 2>/dev/null)
    pattern="${BASE_DIR}/src:[0-9][0-9][0-9][0-9][0-9][0-9],id:0000${id}.json"

    file=$(ls $pattern 2>/dev/null)

    if [[ -z "$file" ]]; then
        echo "⚠️  No file found at ${pattern}"
        continue
    fi

    echo "▶ Visualizing $file"
    python3 "$VISUALIZE_SCRIPT" "$file"
done
