#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_nordvpn_match.c.inc
TMP=/tmp/nordvpn.json
LIST=/tmp/nordvpn.list
LIST_MERGED=/tmp/nordvpn.list_m
ORIGIN=https://api.nordvpn.com/v1/servers?limit=16384
#No ipv6 yet

echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.[] | .ips | .[].ip | select(.version==4) | .ip' $TMP > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_NORDVPN > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST_MERGED}

echo "(3) NordVPN IPs are available in $DEST"
exit 0
