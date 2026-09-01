#!/usr/bin/env bash
# Forwarder to SGF/run.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/../run.sh" "$@"
