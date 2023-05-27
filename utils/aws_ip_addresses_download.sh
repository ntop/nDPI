#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_amazon_aws_match.c.inc
TMP=/tmp/aws.json
LIST=/tmp/aws.list
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.prefixes | .[].ip_prefix' $TMP > $LIST # TODO: ipv6
is_file_empty "${LIST}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_AMAZON_AWS > $DEST
rm -f $TMP $LIST
is_file_empty "${DEST}"

echo "(3) Amazon AWS IPs are available in $DEST"
exit 0
