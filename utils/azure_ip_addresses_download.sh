#!/bin/sh

set -e

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_azure_match.c.inc
LINK_TMP=/tmp/azure_link.txt
TMP=/tmp/azure.json
LIST=/tmp/azure.list
# https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519
# Azure links have the format https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_<date>.json
LINK_ORIGIN="https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"

echo "(1) Downloading file... ${LINK_ORIGIN}"
http_response=$(curl -s -o ${LINK_TMP} -w "%{http_code}" ${LINK_ORIGIN})
if [ "${http_response}" != "200" ]; then
    echo "Error $http_response: you probably need to update the link origin url!"
    exit 1
fi

ORIGIN="$(grep -E 'ServiceTags_Public_[[:digit:]]+.json' ${LINK_TMP} | grep -o -E 'href=\"[^"]+' | sed 's/href="//' | uniq)"
rm -f ${LINK_TMP}
if [ -z "${ORIGIN}" ]; then
    echo "Error ${LINK_ORIGIN} does not contain the url format!"
    exit 1
fi

echo "(2) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ "${http_response}" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(3) Processing IP addresses..."
# Note: the last "grep -v :" is used to skip IPv6 addresses
tr -d '\r' < $TMP | grep / | tr -d '"' | tr -d " " | tr -d "," | grep -v : > $LIST
./ipaddr2list.py $LIST NDPI_PROTOCOL_MICROSOFT_AZURE > $DEST
rm -f $TMP $LIST

echo "(4) Microsoft Azure IPs are available in $DEST"
exit 0
