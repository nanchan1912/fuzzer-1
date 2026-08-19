#!/usr/bin/env bash
set -euo pipefail

CACHELINE_SIZE=$(
  if [ "$(uname)" = "Darwin" ]; then
    sysctl -n hw.cachelinesize
  else
    getconf LEVEL1_DCACHE_LINESIZE
  fi
)

mkdir -p data

"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/base_logger.cpp -o base_logger.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/buffered_writer.cpp -o buffered_writer.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/file_writer.cpp -o file_writer.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/level_logger.cpp -o level_logger.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/main.cpp -o main.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/notifier.cpp -o notifier.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/stream_writer.cpp -o stream_writer.ll
"$CXX_BIN" -S -c -Xclang -disable-O0-optnone -fno-discard-value-names -emit-llvm -I./include -DIRIS_CACHELINE_SIZE=$CACHELINE_SIZE src/utils.cpp -o utils.ll

"$LLVM_LINK_BIN" -S base_logger.ll buffered_writer.ll file_writer.ll level_logger.ll main.ll notifier.ll stream_writer.ll utils.ll -o data/no_pass.ll


# echo "Generated:"
# echo "  data/no_pass.ll"


