#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_akamai_match.c.inc
LIST=/tmp/akamai.list
LIST6=/tmp/akamai.list6
LIST_MERGED=/tmp/akamai.list_m
LIST6_MERGED=/tmp/akamai.list6_m
ORIGIN="https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt"
ORIGIN6="https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv6_CIDRs.txt"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $LIST -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${LIST}"
./mergeipaddrlist.py "${LIST}" > "${LIST_MERGED}"
is_file_empty "${LIST_MERGED}"

#
# https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server
#
cat <<EOF >> "${LIST_MERGED}"
23.64.0.0/14
23.72.0.0/13
69.192.0.0/16
72.246.0.0/15
88.221.0.0/16
92.122.0.0/15
96.16.0.0/15
96.6.0.0/15
104.64.0.0/10
118.214.0.0/16
172.224.0.0/12
172.232.0.0/13
172.224.0.0/13
173.222.0.0/15
184.50.0.0/15
184.84.0.0/14
EOF

http_response=$(curl -s -o $LIST6 -w "%{http_code}" ${ORIGIN6})
check_http_response "${http_response}"
is_file_empty "${LIST6}"
./mergeipaddrlist.py "${LIST6}" > "${LIST6_MERGED}"
is_file_empty "${LIST6_MERGED}"

echo "(2) Processing IP addresses..."
./ipaddr2list.py $LIST_MERGED NDPI_PROTOCOL_AKAMAI $LIST6_MERGED > $DEST
rm -f $LIST $LIST_MERGED $LIST6_MERGED
is_file_empty "${DEST}"

echo "(3) Akamai IPs are available in $DEST"
exit 0
