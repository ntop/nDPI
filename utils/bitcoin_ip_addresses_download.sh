#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_bitcoin_match.c.inc
TMP=/tmp/bitcoin
LIST=/tmp/bitcoin.list
ORIGIN="https://bitnodes.io/api/v1/snapshots/latest/"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.nodes|keys[] as $k | "\($k)"' ${TMP} | grep -v onion | grep -v ']' | cut -d ':' -f 1 > $LIST
is_file_empty "${LIST}"

./ipaddr2list.py $LIST NDPI_PROTOCOL_BITCOIN > $DEST
rm -f $TMP $LIST
is_file_empty "${DEST}"

echo "(3) Bitcoin IPs are available in $DEST"
exit 0
