#!/bin/sh

set -e

echo "Authenticating sudo..."
sudo -v

rm -rf ../output

echo "Moving to project root..."
cd ../../.. || exit 1
echo "Now in: $PWD"

echo "Building project..."
make all

echo "Installing project (sudo)..."
sudo make install

cd testcases/mp_ra/build || exit 1
echo "Now in: $PWD"

echo "Starting afl-fuzz under gdb..."
# gdb --args afl-fuzz -i ../seeds -o ../output -- ./load_buffering -someopt
# AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -z -Z -V 100 -i ../seeds -o ../output -- ./msg_passing

AFL_SKIP_BIN_CHECK=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_DISABLE_TRIM=1 afl-fuzz -Z -z -V 200 -i ../seeds -o ../output -v ../mp_static_program_abstraction.eg -- ./mp_ra
