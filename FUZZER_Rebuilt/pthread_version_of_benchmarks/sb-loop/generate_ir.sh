#!/usr/bin/env bash
set -euo pipefail

mkdir -p data

CXX_BIN="${CXX_BIN:-${CXX:-clang++}}"

"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -fno-exceptions -emit-llvm -I../include ./*.cc -o data/no_pass.ll


# # 1) mem2reg
# opt -S -p="mem2reg" data/no_pass.ll -o data/mem2reg.ll

# # 2) loop-unroll
# opt -S -p="ipsccp,function(loop-simplify,lcssa,indvars,loop-unroll)" data/no_pass.ll -o data/loop_unroll.ll -debug-pass-manager

# echo "Generated:"
# echo "  data/no_pass.ll"
# echo "  data/mem2reg.ll"
# echo "  data/loop_unroll.ll"


