#!/bin/sh

cd "$(dirname "${0}")"

DEST=../src/lib/ndpi_azure_match.c.inc
TMP=/tmp/azure.json
LIST=/tmp/azure.list
# https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519
ORIGIN="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20220124.json"


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    return
fi

echo "(2) Processing IP addresses..."
# Note: the last "grep -v :" is used to skip IPv6 addresses
tr -d '\r' < $TMP | grep / | tr -d '"' | tr -d " " | tr -d "," | grep -v : > $LIST
./ipaddr2list.py $LIST NDPI_PROTOCOL_MICROSOFT_AZURE > $DEST
rm -f $TMP $LIST

echo "(3) Microsoft Azure IPs are available in $DEST"



