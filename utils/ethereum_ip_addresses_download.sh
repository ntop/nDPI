#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_ethereum_match.c.inc
TMP=/tmp/ethereum
LIST=/tmp/ethereum.list
LIST_MERGED=/tmp/ethereum.list_m
ORIGIN="https://raw.githubusercontent.com/ethereum/go-ethereum/master/params/bootnodes.go"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
grep 'enode' $TMP | grep -v '^/' | grep ':' | cut -d '@' -f 2 | cut -d ':' -f 1 > $LIST #no ipv6 in this list
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"

./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_ETHEREUM > $DEST
rm -f $TMP $LIST $LIST_MERGED
is_file_empty "${DEST}"

echo "(3) Ethereum IPs are available in $DEST"
exit 0
