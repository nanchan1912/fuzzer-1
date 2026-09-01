LAST=$1
INPUT=$2
echo -n "input num is:$INPUT"
sed -i "s/int LOOPNUM=$LAST;/int LOOPNUM=$INPUT;/" dekker-change.cc

#sed -i 's/LOOPNUM.*$/LOOPNUM = 6;/g' mcs-change.cc
