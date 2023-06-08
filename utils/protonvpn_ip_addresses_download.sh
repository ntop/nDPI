#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_protonvpn_match.c.inc
TMP=/tmp/proton.json
LIST=/tmp/proton.list
LIST_MERGED=/tmp/proton.list.merged
ORIGIN=https://api.protonmail.ch/vpn/logicals


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
#Not sure if we should use EntryIP or ExitIP: use both, for the time being and let see what happens...
jq -r '.LogicalServers[].Servers[].EntryIP' $TMP > $LIST # TODO: ipv6
jq -r '.LogicalServers[].Servers[].ExitIP' $TMP >> $LIST # TODO: ipv6
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_PROTONVPN > $DEST
rm -f $TMP $LIST $LIST_MERGED
is_file_empty "${DEST}"

echo "(3) ProtonVPN IPs are available in $DEST"
exit 0
