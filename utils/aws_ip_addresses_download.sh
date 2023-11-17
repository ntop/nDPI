#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_amazon_aws_match.c.inc
TMP=/tmp/aws.json
LIST=/tmp/aws.list
LIST6=/tmp/aws.list6
LIST_MERGED=/tmp/aws.list_m
LIST6_MERGED=/tmp/aws.list6_m
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json


echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."
jq -r '.prefixes | .[].ip_prefix' $TMP > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
jq -r '.ipv6_prefixes | .[].ipv6_prefix' $TMP > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py $LIST6 > $LIST6_MERGED
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AMAZON_AWS $LIST6_MERGED > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST6} ${LIST_MERGED} ${LIST_MERGED6}

echo "(3) Amazon AWS IPs are available in $DEST"
exit 0
