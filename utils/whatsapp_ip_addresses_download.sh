#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_whatsapp_match.c.inc
TMP=/tmp/wa.zip
LIST=/tmp/wa.list
LIST_MERGED=/tmp/wa.list_m
IP_LINK_URL='https://developers.facebook.com/docs/whatsapp/guides/network-requirements/'


echo "(1) Scraping Facebook WhatsApp IP Adresses and Ranges..."
ORIGIN="$(curl -s "${IP_LINK_URL}" | sed -ne 's/.*<a href="\([^"]*\)" target="_blank">WhatsApp server IP addresses and ranges (.zip file)<\/a>.*/\1/gp' | sed -e 's/\&amp;/\&/g')"
is_str_empty "${ORIGIN}" "IP webpage list does not contain any addresses. A REGEX update may be required."

echo "(2) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o "${TMP}" -w "%{http_code}" "${ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(3) Processing IP addresses..."
unzip -p /tmp/wa.zip "WhatsApp IPs (IPv4 Only) 2022-07-26 - 2022-07-30.txt" > "${LIST}" #TODO: ipv6
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
./ipaddr2list.py "${LIST_MERGED}" NDPI_PROTOCOL_WHATSAPP > "${DEST}"
rm -f "${TMP}" "${LIST}" "${LIST_MERGED}"
is_file_empty "${DEST}"

echo "(4) WhatsApp IPs are available in $DEST"
exit 0
