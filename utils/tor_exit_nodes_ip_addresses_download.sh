#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_tor_exit_nodes_match.c.inc
LIST=/tmp/tor.list
LIST_MERGED=/tmp/tor.list_m
LIST6_MERGED=/tmp/tor.list_m6
LIST_MERGED_U=/tmp/tor.list_m_u
LIST6_MERGED_U=/tmp/tor.list_m6_u
#Only the exit addresses, since this list is used for NDPI_ANONYMOUS_SUBSCRIBER risk!
ORIGIN="https://raw.githubusercontent.com/alireza-rezaee/tor-nodes/refs/heads/main/latest.exits.csv"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"

echo "(2) Processing IP addresses..."
cat "${LIST}" | cut -d ',' -f 2 | grep '\.' | tr -d '[:blank:]' > "${LIST}.ipv4"
cat "${LIST}" | cut -d ',' -f 2 | grep ':'  | tr -d '[:blank:]' > "${LIST}.ipv6"

./mergeipaddrlist.py ${LIST}.ipv4 > $LIST_MERGED
is_file_empty "${LIST_MERGED}"

./mergeipaddrlist.py ${LIST}.ipv6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"

sort -u $LIST_MERGED  > $LIST_MERGED_U
sort -u $LIST6_MERGED > $LIST6_MERGED_U

./ipaddr2list.py $LIST_MERGED_U NDPI_ANONYMOUS_SUBSCRIBER $LIST6_MERGED_U "_tor_exit_nodes" > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST}.ipv4 ${LIST}.ipv6 ${LIST_MERGED} ${LIST6_MERGED} ${LIST_MERGED_U} ${LIST6_MERGED_U}

echo "(3) TOR exit nodes IPs are available in $DEST"
exit 0
