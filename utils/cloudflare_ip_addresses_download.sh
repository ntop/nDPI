#!/bin/sh

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_cloudflare_match.c.inc
LIST=/tmp/cloudflare.list
# TODO: ipv6 list from https://www.cloudflare.com/ips-v6
ORIGIN="https://www.cloudflare.com/ips-v4"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_CLOUDFLARE > $DEST
rm -f $LIST

echo "(3) Cloudflare IPs are available in $DEST"
exit 0
