#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_google_match.c.inc
LIST=/tmp/google.list
LIST6=/tmp/google.list6
LIST_MERGED=/tmp/google.list_m
LIST6_MERGED=/tmp/google.list6_m

echo "(1) Downloading file..."
#Nothing to do

echo "(2) Processing IP addresses..."
#https://cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults
python3 google.py > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
python3 google6.py > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_GOOGLE $LIST6_MERGED > $DEST
is_file_empty "${DEST}"

rm -f "$TMP" $LIST $LIST6

echo "(3) Google IPs are available in $DEST"
exit 0
