#!/bin/bash
source ../run
./test_lfringbuffer $@
./test2 $@
rm log.txt


