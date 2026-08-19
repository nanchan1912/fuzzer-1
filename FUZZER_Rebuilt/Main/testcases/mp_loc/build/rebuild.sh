#!/bin/sh

set -e

echo "Authenticating sudo..."
sudo -v

echo "Moving to project root..."
cd ../../.. || exit 1
echo "Now in: $PWD"

echo "Building project..."
make all

echo "Installing project (sudo)..."
sudo make install

cd testcases/mp_loc/build || exit 1
echo "Now in: $PWD"

rm -rf ../output
echo "Starting afl-fuzz under gdb..."
# gdb --args afl-fuzz -i ../seeds -o ../output -- ./load_buffering -someopt
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -z -Z -V 100 -i ../seeds -o ../output -- ./msg_passing
