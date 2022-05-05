#!/bin/sh
#
# List all the current bittorrent nodes
#

set -e

# NOTE: JQ can be found at https://stedolan.github.io/jq/

curl -s -H "Accept: application/json; indent=4" https://bitnodes.io/api/v1/snapshots/latest/ | jq -r '.nodes|keys[] as $k | "\($k)"' | grep -v onion | grep -v ']' | cut -d ':' -f 1
