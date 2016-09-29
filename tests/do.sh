
READER="../example/ndpiReader -p ../example/protos.txt"

RC=0
PCAPS=`cd pcap; /bin/ls *.pcap`

build_results() {
    for f in $PCAPS; do 
	#echo $f
	# create result files if not present
	[ ! -f result/$f.out ] && $READER -q -i pcap/$f -w result/$f.out -v 1
    done
}

check_results() {
    for f in $PCAPS; do 
	if [ -f result/$f.out ]; then
	    CMD="$READER -q -i pcap/$f -w /tmp/reader.out -v 1"
	    $CMD
	    NUM_DIFF=`diff result/$f.out /tmp/reader.out | wc -l`
	    
	    if [ $NUM_DIFF -eq 0 ]; then
		printf "%-32s\tOK\n" "$f"
	    else
		printf "%-32s\tERROR\n" "$f"
		echo "$CMD"
		diff result/$f.out /tmp/reader.out
		RC=1
	    fi

	    /bin/rm /tmp/reader.out
	fi
    done
}

build_results
check_results

exit $RC
