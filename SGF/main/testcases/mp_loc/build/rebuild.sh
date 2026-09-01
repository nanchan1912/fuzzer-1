#!/bin/sh

set -e

echo "Moving to project root..."
cd ../../.. || exit 1
echo "Now in: $PWD"

echo "Building project..."
make sgf-fuzz

cd testcases/mp_loc/build || exit 1
echo "Now in: $PWD"

rm -rf ../output
echo "Starting sgf-fuzz..."
SGF_SKIP_CPUFREQ=1 SGF_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 SGF_NO_AFFINITY=1 ../../../sgf-fuzz -n -V 100 -i ../seeds -o ../output -v ../mp_static_program_abstraction.eg -- ../mp
