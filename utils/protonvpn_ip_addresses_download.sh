#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST_IN=../src/lib/inc_generated/ndpi_protonvpn_in_match.c.inc
DEST_OUT=../src/lib/inc_generated/ndpi_protonvpn_out_match.c.inc
TMP=/tmp/proton.json
LIST=/tmp/proton.list
LIST6=/tmp/proton.list6
LIST_MERGED=/tmp/proton.list.merged
ORIGIN=https://api.protonmail.ch/vpn/logicals


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.LogicalServers[].Servers[].EntryIP' $TMP > $LIST # TODO: ipv6
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
#TODO: no ipv6 yet
touch $LIST6
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_PROTONVPN $LIST6 > $DEST_IN
is_file_empty "${DEST_IN}"

jq -r '.LogicalServers[].Servers[].ExitIP' $TMP > $LIST # TODO: ipv6
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
#TODO: no ipv6 yet
touch $LIST6
./ipaddr2list.py $LIST_MERGED NDPI_ANONYMOUS_SUBSCRIBER $LIST6 "_protonvpn"> $DEST_OUT
is_file_empty "${DEST_OUT}"

rm -f $TMP $LIST $LIST_MERGED $LIST6

echo "(3) ProtonVPN IPs are available in $DEST_IN, $DEST_OUT"
exit 0
