#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_digitalocean_match.c.inc
LIST=/tmp/digitalocean.list
LIST4=/tmp/digitalocean.list_4
LIST6=/tmp/digitalocean.list_6
LIST_MERGED=/tmp/digitalocean.list_m
ORIGIN="https://www.digitalocean.com/geo/google.csv"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"
grep -v ':' "${LIST}" | cut -f 1 -d ',' > ${LIST4}
grep ':' "${LIST}" | cut -f 1 -d ',' > ${LIST6}

is_file_empty "${LIST4}"
is_file_empty "${LIST6}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py ${LIST4} NDPI_PROTOCOL_DIGITALOCEAN ${LIST6} > $DEST
rm -f $LIST4 $LIST6
is_file_empty "${DEST}"

echo "(3) Digitalocean IPs are available in $DEST"
exit 0
