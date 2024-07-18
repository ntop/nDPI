#!/usr/bin/env bash
set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 AS-Number" >&2
    exit 1
fi

LIST=/tmp/asn.json
ORIGIN="https://stat.ripe.net/data/announced-prefixes/data.json?resource=$1"

http_response=$(curl -s -o "${LIST}" -w "%{http_code}" "${ORIGIN}")
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: service temporiarally not available?" >&2
    exit 1
elif [ "$http_response" != "200" ]; then
    echo "Error $http_response: wrong ASN number/format?" >&2
    exit 1
fi

jq -r '.data.prefixes[].prefix' $LIST | grep -v ":"

rm -f $LIST
exit 0
