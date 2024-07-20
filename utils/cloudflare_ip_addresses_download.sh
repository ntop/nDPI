#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_cloudflare_match.c.inc
LIST=/tmp/cloudflare.list
LIST6=/tmp/cloudflare.list6
LIST_MERGED=/tmp/cloudflare.list_m
LIST6_MERGED=/tmp/cloudflare.list6_m
ORIGIN="https://www.cloudflare.com/ips-v4/"
ORIGIN6="https://www.cloudflare.com/ips-v6/"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"
./mergeipaddrlist.py "${LIST}" > "${LIST_MERGED}"
is_file_empty "${LIST_MERGED}"

http_response=$(curl -s -o $LIST6 -w "%{http_code}" ${ORIGIN6})
check_http_response "${http_response}"
is_file_empty "${LIST6}"
./mergeipaddrlist.py "${LIST6}" > "${LIST6_MERGED}"
is_file_empty "${LIST6_MERGED}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_CLOUDFLARE $LIST6_MERGED > $DEST
rm -f $LIST $LIST_MERGED $LIST6_MERGED
is_file_empty "${DEST}"

echo "(3) Cloudflare IPs are available in $DEST"
exit 0
