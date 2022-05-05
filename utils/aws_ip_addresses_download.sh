#!/bin/sh

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_amazon_aws_match.c.inc
TMP=/tmp/aws.json
LIST=/tmp/aws.list
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
jq -r '.prefixes | .[].ip_prefix' $TMP > $LIST # TODO: ipv6
./ipaddr2list.py $LIST NDPI_PROTOCOL_AMAZON_AWS > $DEST
rm -f $TMP $LIST

echo "(3) Amazon AWS IPs are available in $DEST"
exit 0
