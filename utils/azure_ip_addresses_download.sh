#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_azure_match.c.inc
LINK_TMP=/tmp/azure_link.txt
TMP=/tmp/azure.json
LIST=/tmp/azure.list
LIST6=/tmp/azure.list6
LIST_MERGED=/tmp/azure.list_m
LIST6_MERGED=/tmp/azure.list6_m
# https://www.microsoft.com/en-us/download/details.aspx?id=56519
# Azure links have the format https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_<date>.json
LINK_ORIGIN="https://www.microsoft.com/en-us/download/details.aspx?id=56519"

echo "(1) Downloading file... ${LINK_ORIGIN}"
http_response=$(curl -s -o ${LINK_TMP} -w "%{http_code}" "${LINK_ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${LINK_TMP}"

ORIGIN="$(grep -Eoi '<a [^>]+>' ${LINK_TMP} | grep -Eo 'href="[^\"]+"' | grep "download.microsoft.com/download/" | grep -m 1 -Eo '(http|https)://[^"]+')"
rm -f ${LINK_TMP}
is_str_empty "${ORIGIN}" "${LINK_ORIGIN} does not contain the url format!"

echo "(2) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" "${ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(3) Processing IP addresses..."
tr -d '\r' < $TMP | grep / | tr -d '"' | tr -d " " | tr -d "," | grep -v : > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
tr -d '\r' < $TMP | grep / | tr -d '"' | tr -d " " | tr -d "," | grep : > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_MICROSOFT_AZURE $LIST6_MERGED > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST6} ${LIST_MERGED} ${LIST6_MERGED}

echo "(4) Microsoft Azure IPs are available in $DEST"
exit 0
