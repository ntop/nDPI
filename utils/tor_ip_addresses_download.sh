#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_tor_match.c.inc
LIST=/tmp/tor.list
# There are at least two lists:
#  * https://torstatus.rueckgr.at/ip_list_all.php/Tor_ip_list_ALL.csv
#  * https://check.torproject.org/torbulkexitlist
# The latter seems to be more "stable" (the former changes every few seconds!)
ORIGIN="https://check.torproject.org/torbulkexitlist"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_TOR > $DEST
rm -f "${LIST}"
is_file_empty "${DEST}"

echo "(3) TOR IPs are available in $DEST"
exit 0
