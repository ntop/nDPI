#!/bin/sh

READER="valgrind -q --leak-check=full ../example/ndpiReader -p ../example/protos.txt -c ../example/categories.txt"

RC=0
PCAPS=`cd pcap; /bin/ls *.pcap`

check_results() {
    for f in $PCAPS; do 
	  CMD="$READER -q -i pcap/$f > /tmp/reader.out"
	  $CMD
	  NUM_DIFF=0

	  if [ -f /tmp/reader.out ]; then
	    NUM_DIFF=`wc -l /tmp/reader.out`
	  fi

	  if [ $NUM_DIFF -eq 0 ]; then
	      printf "%-32s\tOK\n" "$f"
	  else
	      printf "%-32s\tERROR\n" "$f"
	      echo "$CMD"
	      cat /tmp/reader.out
	      RC=1
	  fi

	  /bin/rm -f /tmp/reader.out
    done
}

check_results

exit $RC
