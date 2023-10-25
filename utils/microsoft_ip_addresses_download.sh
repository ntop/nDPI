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
LIST6=/tmp/ms.list6
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
ORIGIN="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"


echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."

#OUTLOOK
jq -r '.[] | select(.serviceArea=="Exchange") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
jq -r '.[] | select(.serviceArea=="Exchange") | .ips[]?' < $TMP | grep ':' | sort -u | uniq > $LIST6
is_file_empty "${LIST6}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_MS_OUTLOOK $LIST6 > $DEST_OUTLOOK
is_file_empty "${DEST_OUTLOOK}"

#SKYPE/TEAMS
jq -r '.[] | select(.serviceArea=="Skype") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
jq -r '.[] | select(.serviceArea=="Skype") | .ips[]?' < $TMP | grep ':' | sort -u | uniq > $LIST6
is_file_empty "${LIST6}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_SKYPE_TEAMS $LIST6 > $DEST_SKYPE_MSTEAMS
is_file_empty "${DEST_SKYPE_MSTEAMS}"

#ONEDRIVE
jq -r '.[] | select(.serviceArea=="SharePoint") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
jq -r '.[] | select(.serviceArea=="SharePoint") | .ips[]?' < $TMP | grep ':' | sort -u | uniq > $LIST6
is_file_empty "${LIST6}"
./ipaddr2list.py $LIST NDPI_PROTOCOL_MS_ONE_DRIVE $LIST6 > $DEST_ONEDRIVE
is_file_empty "${DEST_ONEDRIVE}"

#OFFICE
jq -r '.[] | select(.serviceArea=="Common") | .ips[]?' < $TMP | grep -v ':' | sort -u | uniq > $LIST
is_file_empty "${LIST}"
jq -r '.[] | select(.serviceArea=="Common") | .ips[]?' < $TMP | grep ':' | sort -u | uniq > $LIST6
is_file_empty "${LIST6}"
#TODO: NDPI_PROTOCOL_MICROSOFT_365 or NDPI_PROTOCOL_MICROSOFT?
./ipaddr2list.py $LIST NDPI_PROTOCOL_MICROSOFT_365 $LIST6 > $DEST_OFFICE365
is_file_empty "${DEST_OFFICE365}"

rm -f ${TMP} ${LIST} ${LIST6}

echo "(3) Microsoft IPs are available in ${DEST_OUTLOOK}, ${DEST_SKYPE_MSTEAMS}, ${DEST_ONEDRIVE}, ${DEST_OFFICE365}"
exit 0
