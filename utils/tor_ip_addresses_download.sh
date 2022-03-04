#!/bin/sh

cd "$(dirname "${0}")"

DEST=../src/lib/ndpi_tor_match.c.inc
LIST=/tmp/tor.list
# There are at least two lists:
#  * https://torstatus.rueckgr.at/ip_list_all.php/Tor_ip_list_ALL.csv
#  * https://check.torproject.org/torbulkexitlist
# The latter seems to be more "stable" (the former changes every few seconds!)
ORIGIN="https://check.torproject.org/torbulkexitlist"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    return 1
fi

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_TOR > $DEST
rm -f $LIST

echo "(3) TOR IPs are available in $DEST"
return 0
