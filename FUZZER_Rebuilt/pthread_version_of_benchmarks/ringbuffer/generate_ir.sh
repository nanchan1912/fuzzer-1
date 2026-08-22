#!/usr/bin/env bash
set -euo pipefail

mkdir -p data

"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I../include ./*.cc -o data/no_pass.ll

# echo "Generated:"
# echo "  data/no_pass.ll"


