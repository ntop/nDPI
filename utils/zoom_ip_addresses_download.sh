#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_zoom_match.c.inc
LIST=/tmp/zoom.list
# https://support.zoom.us/hc/en-us/articles/201362683-Zoom-network-firewall-or-proxy-server-settings
# There are few lists in this page, partially overlapping. Pick the generic one
ORIGIN="https://assets.zoom.us/docs/ipranges/Zoom.txt"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o "${LIST}" -w "%{http_code}" "${ORIGIN}")
check_http_response "${http_response}"
is_file_empty "${LIST}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py "${LIST}" NDPI_PROTOCOL_ZOOM > "${DEST}"
rm -f "${LIST}"
is_file_empty "${DEST}"

echo "(3) ZOOM IPs are available in ${DEST}"
exit 0
