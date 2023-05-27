#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_google_cloud_match.c.inc
TMP=/tmp/google_c.json
LIST=/tmp/google_c.list
ORIGIN="https://www.gstatic.com/ipranges/cloud.json"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP > $LIST # TODO: ipv6
./ipaddr2list.py $LIST NDPI_PROTOCOL_GOOGLE_CLOUD > $DEST
rm -f $TMP $LIST

echo "(3) Google Cloud IPs are available in $DEST"
exit 0
