#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST_OUTLOOK=../src/lib/inc_generated/ndpi_ms_outlook_match.c.inc
DEST_SKYPE_MSTEAMS=../src/lib/inc_generated/ndpi_ms_skype_teams_match.c.inc
DEST_ONEDRIVE=../src/lib/inc_generated/ndpi_ms_onedrive_match.c.inc
DEST_OFFICE365=../src/lib/inc_generated/ndpi_ms_office365_match.c.inc
TMP=/tmp/ms.json
LIST=/tmp/ms.list
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
ORIGIN="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."

#OUTLOOK
# Note: the "grep -v :" is used to skip IPv6 addresses
jq -r '.[] | select(.serviceArea=="Exchange") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_MS_OUTLOOK > $DEST_OUTLOOK
is_file_empty "${DEST_OUTLOOK}"

#SKYPE/TEAMS
# Note: the "grep -v :" is used to skip IPv6 addresses
jq -r '.[] | select(.serviceArea=="Skype") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_SKYPE_TEAMS > $DEST_SKYPE_MSTEAMS
is_file_empty "${DEST_SKYPE_MSTEAMS}"

#ONEDRIVE
# Note: the "grep -v :" is used to skip IPv6 addresses
jq -r '.[] | select(.serviceArea=="SharePoint") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_MS_ONE_DRIVE > $DEST_ONEDRIVE
is_file_empty "${DEST_ONEDRIVE}"

#OFFICE
# Note: the "grep -v :" is used to skip IPv6 addresses
jq -r '.[] | select(.serviceArea=="Common") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
#TODO: NDPI_PROTOCOL_MICROSOFT_365 or NDPI_PROTOCOL_MICROSOFT?
./ipaddr2list.py $LIST NDPI_PROTOCOL_MICROSOFT_365 > $DEST_OFFICE365
is_file_empty "${DEST_OFFICE365}"

rm -f "${TMP}" "${LIST}"

echo "(3) Microsoft IPs are available in ${DEST_OUTLOOK}, ${DEST_SKYPE_MSTEAMS}, ${DEST_ONEDRIVE}, ${DEST_OFFICE365}"
exit 0
