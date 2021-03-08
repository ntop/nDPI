#!/bin/sh

cd "$(dirname "${0}")"

GCRYPT_ENABLED=1
GCRYPT_PCAPS="gquic.pcap quic-23.pcap quic-24.pcap quic-27.pcap quic-28.pcap quic-29.pcap quic-mvfst-22.pcap quic-mvfst-27.pcap quic-mvfst-exp.pcap quic_q50.pcap quic_t50.pcap quic_t51.pcap quic_0RTT.pcap quic_interop_V.pcapng quic-33.pcapng doq.pcapng doq_adguard.pcapng dlt_ppp.pcap"
READER="valgrind -q --leak-check=full ../example/ndpiReader -p ../example/protos.txt -c ../example/categories.txt"

RC=0
PCAPS=`cd pcap; /bin/ls *.pcap`

if [ ! -x "../example/ndpiReader" ]; then
  echo "$0: Missing $(realpath ../example/ndpiReader)"
  echo "$0: Run ./configure and make first"
  exit 1
fi

check_results() {
	for f in $PCAPS; do 
	  SKIP_PCAP=0
	  if [ $GCRYPT_ENABLED -eq 0 ]; then
	    for g in $GCRYPT_PCAPS; do
	      if [ $f = $g ]; then
	        SKIP_PCAP=1
	        break
	      fi
	    done
	  fi
	  if [ $SKIP_PCAP -eq 1 ]; then
	    printf "%-32s\tSKIPPED\n" "$f"
	    continue
	  fi

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
