#!/bin/sh

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_cachefly_match.c.inc
LIST=/tmp/cachefly.list
ORIGIN='https://cachefly.cachefly.net/ips/cdn.txt'


echo "(1) Downloading file..."
http_response=$(curl -s -o "${LIST}" -w "%{http_code}" "${ORIGIN}")
if [ "${http_response}" != "200" ]; then
    echo "Error ${http_response}: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing IP addresses..."
./ipaddr2list.py "${LIST}" NDPI_PROTOCOL_CACHEFLY > "${DEST}"
rm -f "${LIST}"

echo "(3) Cachefly IPs are available in ${DEST}"
exit 0
