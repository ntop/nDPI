#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_cloudflare_match.c.inc
LIST=/tmp/cloudflare.list
LIST6=/tmp/cloudflare.list6
ORIGIN="https://www.cloudflare.com/ips-v4"
ORIGIN6="https://www.cloudflare.com/ips-v6"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"

http_response=$(curl -s -o $LIST6 -w "%{http_code}" ${ORIGIN6})
check_http_response "${http_response}"
is_file_empty "${LIST6}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_CLOUDFLARE $LIST6 > $DEST
rm -f $LIST
is_file_empty "${DEST}"

echo "(3) Cloudflare IPs are available in $DEST"
exit 0
