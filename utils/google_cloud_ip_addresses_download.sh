#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_google_cloud_match.c.inc
TMP=/tmp/google_c.json
LIST=/tmp/google_c.list
LIST6=/tmp/google_c.list6
LIST_MERGED=/tmp/google_c.list_m
LIST6_MERGED=/tmp/google_c.list6_m
ORIGIN="https://www.gstatic.com/ipranges/cloud.json"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
jq -r '.prefixes | .[].ipv6Prefix  | select( . != null )' $TMP > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_GOOGLE_CLOUD $LIST6_MERGED > $DEST

rm -f $TMP $LIST $LIST6 $LIST_MERGED $LIST6_MERGED

echo "(3) Google Cloud IPs are available in $DEST"
exit 0
