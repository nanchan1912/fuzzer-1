#!/usr/bin/env bash
set -euo pipefail

mkdir -p data

"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I../include main.cc -o data/main.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I../include my_queue.cc -o data/my_queue.ll
"$LLVM_LINK_BIN" -S data/main.ll data/my_queue.ll -o data/no_pass.ll


# # 1) mem2reg
# opt -S -p="mem2reg" data/no_pass.ll -o data/mem2reg.ll

# # 2) loop-unroll
# opt -S -p="ipsccp,function(loop-simplify,lcssa,indvars,loop-unroll)" data/no_pass.ll -o data/loop_unroll.ll -debug-pass-manager

# echo "Generated:"
# echo "  data/no_pass.ll"
# echo "  data/mem2reg.ll"
# echo "  data/loop_unroll.ll"


