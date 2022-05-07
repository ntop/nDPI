#!/bin/sh

set -e

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_whatsapp_match.c.inc
TMP=/tmp/wa.zip
LIST=/tmp/wa.list
IP_LINK_URL='https://developers.facebook.com/docs/whatsapp/guides/network-requirements/'


echo "(1) Scraping Facebook WhatsApp IP Adresses and Ranges..."
ORIGIN="$(curl -s "${IP_LINK_URL}" | sed -ne 's/.*<a href="\([^"]*\)" target="_blank">List of the WhatsApp server IP addresses and ranges (.zip file)<\/a>.*/\1/gp' | sed -e 's/\&amp;/\&/g')"

echo "(2) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(3) Processing IP addresses..."
zcat $TMP > $LIST
./ipaddr2list.py $LIST NDPI_PROTOCOL_WHATSAPP > $DEST
rm -f $TMP $LIST

echo "(4) WhatsApp IPs are available in $DEST"
exit 0
