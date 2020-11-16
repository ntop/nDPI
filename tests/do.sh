#!/bin/sh

cd "$(dirname "${0}")"

READER="../example/ndpiReader -p ../example/protos.txt -c ../example/categories.txt"

RC=0
PCAPS=`cd pcap; /bin/ls *.pcap *.pcapng`

fuzzy_testing() {
    if [ -f ../fuzz/fuzz_ndpi_reader ]; then
	../fuzz/fuzz_ndpi_reader -max_total_time="${MAX_TOTAL_TIME:-592}" -print_pcs=1 -workers="${FUZZY_WORKERS:-0}" -jobs="${FUZZY_JOBS:-0}" pcap/
    fi
}

build_results() {
    for f in $PCAPS; do
	#echo $f
	# create result files if not present
	if [ ! -f result/$f.out ]; then
	    CMD="$READER -q -t -i pcap/$f -w result/$f.out -v 2"
	    $CMD
	fi
    done
}

check_results() {
    for f in $PCAPS; do
	if [ -f result/$f.out ]; then
	    CMD="$READER -q -t -i pcap/$f -w /tmp/reader.out -v 2"
	    $CMD
	    NUM_DIFF=`diff result/$f.out /tmp/reader.out | wc -l`

	    if [ $NUM_DIFF -eq 0 ]; then
		printf "%-32s\tOK\n" "$f"
	    else
		printf "%-32s\tERROR\n" "$f"
		echo "$CMD [old vs new]"
		diff result/$f.out /tmp/reader.out
		RC=1
	    fi

	    /bin/rm /tmp/reader.out
	fi
    done
}

fuzzy_testing
build_results
check_results

exit $RC
