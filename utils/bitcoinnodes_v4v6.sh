#!/usr/bin/env bash
set -e
#
# List all the current bittorrent nodes
#

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

# NOTE: JQ can be found at https://stedolan.github.io/jq/
CMD=(curl -s -H "Accept: application/json; indent=4" https://bitnodes.io/api/v1/snapshots/latest/)

RESULT_V4="$("${CMD[@]}" | jq -r '.nodes|keys[] as $k | "\($k)"' | grep -v onion | grep -v ']' | cut -d ':' -f 1)"
RESULT_V6="$("${CMD[@]}" | jq -r '.nodes|keys[] as $k | "\($k)"' | grep -v onion | grep ']' | cut -d '[' -f 2 | cut -d ']' -f 1)"

OUT_FILE="../lists/99_bitcoinnodes.ip_list"

rm -f ${OUT_FILE}

strarr=($(echo "$RESULT_V4" | tr " " "\n"))
for i in "${strarr[@]}"; do
    echo "$i/32" >>  "${OUT_FILE}"
done

#########

strarr=($(echo "$RESULT_V6" | tr " " "\n"))
for i in "${strarr[@]}"; do
    echo "$i/128" >>  "${OUT_FILE}"
done
