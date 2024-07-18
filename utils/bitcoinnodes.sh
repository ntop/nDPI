#!/usr/bin/env bash
set -e
#
# List all the current bittorrent nodes
#

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

# NOTE: JQ can be found at https://stedolan.github.io/jq/

RESULT="$(curl -s -H "Accept: application/json; indent=4" https://bitnodes.io/api/v1/snapshots/latest/ | jq -r '.nodes|keys[] as $k | "\($k)"' | grep -v onion | grep -v ']' | cut -d ':' -f 1)"
is_str_empty "${RESULT}" "String empty, please review this script."
