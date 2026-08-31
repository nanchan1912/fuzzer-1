#!/bin/bash
INSERT_MAX=10
BEFORE=1
NOW=1
for i in `seq 1 1 $INSERT_MAX` ; do
	NOW=$i
	echo -n "Now insert $i relaxed writes to mcs-lock. "
source ./update.sh $BEFORE $NOW
BEFORE=$NOW
make
cd ..
source ./change_all_test.sh "mcs-change"
cd mcs-change
done

sed -i "s/int LOOPNUM=$INSERT_MAX;/int LOOPNUM=1;/" mcs-change.cc

