#!/bin/sh

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_zoom_match.c.inc
LIST=/tmp/zoom.list
# https://support.zoom.us/hc/en-us/articles/201362683-Zoom-network-firewall-or-proxy-server-settings
# There are few lists in this page, partially overlapping. Pick the generic one
ORIGIN="https://assets.zoom.us/docs/ipranges/Zoom.txt"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST NDPI_PROTOCOL_ZOOM > $DEST
rm -f $LIST

echo "(3) ZOOM IPs are available in $DEST"
exit 0
