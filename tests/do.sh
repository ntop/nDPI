
READER=../example/ndpiReader


PCAPS=`cd pcap; /bin/ls *.pcap`

build_results() {
    for f in $PCAPS; do 
	#echo $f
	# create result files if not present
	[ ! -f result/$f.out ] && $READER -q -i pcap/$f -w result/$f.out
    done
}

check_results() {
    for f in $PCAPS; do 
	if [ -f result/$f.out ]; then
	    $READER -q -i pcap/$f -w /tmp/reader.out
	    NUM_DIFF=`diff result/$f.out /tmp/reader.out | wc -l`
	    
	    if [ $NUM_DIFF -eq 0 ]; then
		echo "$f\t OK"
	    else
		echo "$f\t ERROR"
	    fi

	    /bin/rm /tmp/reader.out
	fi
    done
}


build_results
check_results