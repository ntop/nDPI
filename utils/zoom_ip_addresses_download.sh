#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_zoom_match.c.inc
LIST=/tmp/zoom.list
LIST6=/tmp/zoom.list6
LIST_MERGED=/tmp/zoom.list_m
LIST6_MERGED=/tmp/zoom.list6_m
# https://support.zoom.us/hc/en-us/articles/201362683-Zoom-network-firewall-or-proxy-server-settings
# There are few lists in this page, partially overlapping. Pick the generic one
ORIGIN="https://assets.zoom.us/docs/ipranges/Zoom.txt"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o "${LIST}" -w "%{http_code}" "${ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"

# IPv6: in that page there is a few IPv6 prefixes but these prefixes are not present in
# the "main" list!
# Add them manually: TODO: keep them in sync
echo "2620:123:2000::/40" > $LIST6
echo "2600:9000:2600::/48" >> $LIST6
echo "2407:30C0::/32" >> $LIST6
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}" 

echo "(2) Processing IP addresses..."
./ipaddr2list.py "${LIST_MERGED}" NDPI_PROTOCOL_ZOOM "${LIST6_MERGED}" > "${DEST}"
rm -f "${LIST}" "${LIST6}" "${LIST_MERGED}" "${LIST6_MERGED}"
is_file_empty "${DEST}"

echo "(3) ZOOM IPs are available in ${DEST}"
exit 0
