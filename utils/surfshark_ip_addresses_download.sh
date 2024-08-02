#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_surfshark_match.c.inc
TMP=/tmp/surfshark.json
LIST_DOMAINS=/tmp/surfshark.listd
LIST=/tmp/surfshark.list
LIST_MERGED=/tmp/surfshark.list_m
ORIGIN=https://api.surfshark.com/v4/server/clusters/all
# SurfShark provides a list of DOMAINS, not of IPs!
#TODO: should we convert these domains to ip at runtime?
#No ipv6 support: https://support.surfshark.com/hc/en-us/articles/360011550239-Does-Surfshark-support-IPv6-Do-I-have-it-on-my-network

echo "(1) Downloading file..."
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing domains..."
jq -r '.[] | .connectionName' $TMP > $LIST_DOMAINS
while read -r DOMAIN
do
    dig +short "${DOMAIN}" A >> ${LIST}
#    dig +short "${DOMAIN}" AAAA >> ${LIST6}
done < "${LIST_DOMAINS}"

echo "(3) Processing IP addresses..."
is_file_empty "${LIST}"
./mergeipaddrlist.py $LIST > $LIST_MERGED
is_file_empty "${LIST_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_SURFSHARK > $DEST
is_file_empty "${DEST}"

rm -f ${TMP} ${LIST} ${LIST6} ${LIST_DOMAINS}

echo "(4) SurfShark IPs are available in $DEST"
exit 0
