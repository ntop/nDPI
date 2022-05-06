#!/bin/sh

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_ethereum_match.c.inc
TMP=/tmp/ethereum
LIST=/tmp/ethereum.list
ORIGIN="https://raw.githubusercontent.com/ethereum/go-ethereum/master/params/bootnodes.go"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
grep 'enode' $TMP | grep -v '^/' | grep ':' | cut -d '@' -f 2 | cut -d ':' -f 1 > $LIST

./ipaddr2list.py $LIST NDPI_PROTOCOL_MINING > $DEST
rm -f $TMP $LIST

echo "(3) Ethereum/Mining IPs are available in $DEST"
exit 0
