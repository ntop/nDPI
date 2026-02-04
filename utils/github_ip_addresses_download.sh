#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_github_match.c.inc
LIST=/tmp/github.list
LIST6=/tmp/github.list6
LIST_MERGED=/tmp/github.list_m
LIST6_MERGED=/tmp/github.list6_m

echo "(1) Downloading file..."
#Nothing to do

echo "(2) Processing IP addresses..."
# https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses
python3 github.py 4 > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
python3 github.py 6 > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_GITHUB $LIST6_MERGED > $DEST
is_file_empty "${DEST}"

rm -f "$TMP" $LIST $LIST6

echo "(3) Github IPs are available in $DEST"
exit 0

done

exit 0
