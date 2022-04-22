#!/bin/sh

set -e

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_google_match.c.inc
LIST=/tmp/google.list

echo "(1) Downloading file..."
#Nothing to do

echo "(2) Processing IP addresses..."
#https://cloud.google.com/vpc/docs/configure-private-google-access#ip-addr-defaults
python3 google.py > $LIST
./ipaddr2list.py $LIST NDPI_PROTOCOL_GOOGLE > $DEST
#rm -f $TMP $LIST

echo "(3) Google IPs are available in $DEST"
exit 0
