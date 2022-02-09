#!/bin/sh

cd "$(dirname "${0}")"

DEST=../src/lib/ndpi_cloudflare_match.c.inc
LIST=/tmp/cloudflare.list
# TODO: ipv6 list from https://www.cloudflare.com/ips-v6
ORIGIN="https://www.cloudflare.com/ips-v4"


echo "(1) Downloading file..."
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    return
fi

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_CLOUDFLARE > $DEST
rm -f $LIST

echo "(3) Cloudflare IPs are available in $DEST"



