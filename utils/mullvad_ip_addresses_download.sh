#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_mullvad_match.c.inc
TMP=/tmp/mullvad.json
LIST=/tmp/mullvad.list
LIST6=/tmp/mullvad.list6
ORIGIN=https://api-www.mullvad.net/www/relays/all/


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.[].ipv4_addr_in' $TMP > $LIST
is_file_empty "${LIST}"
jq -r '.[].ipv6_addr_in | select( . != null )' $TMP > $LIST6
is_file_empty "${LIST6}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_MULLVAD $LIST6 > $DEST
is_file_empty "${DEST}"

rm -f $TMP $LIST $LIST6

echo "(3) Mullvad IPs are available in $DEST"
exit 0
