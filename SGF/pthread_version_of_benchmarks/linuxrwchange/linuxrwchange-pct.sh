#!/bin/bash
INSERT_MAX=10
BEFORE=1
NOW=1
for i in `seq 1 1 $INSERT_MAX` ; do
	NOW=$i
	echo -n "Now insert $i relaxed writes to linuxrwlock. "
source ./update.sh $BEFORE $NOW
BEFORE=$NOW
make
cd ..
source ./changepct_all.sh linuxrwchange $i
cd linuxrwchange
done
sed -i "s/int LOOPNUM=$INSERT_MAX;/int LOOPNUM=1;/" linuxrwchange.cc

