#!/bin/sh

set -e

cd "$(dirname "${0}")" || exit 1

DEST_OUTLOOK=../src/lib/inc_generated/ndpi_domains_ms_outlook_match.c.inc
DEST_MSTEAMS=../src/lib/inc_generated/ndpi_domains_ms_teams_match.c.inc
DEST_ONEDRIVE=../src/lib/inc_generated/ndpi_domains_ms_onedrive_match.c.inc
DEST_OFFICE365=../src/lib/inc_generated/ndpi_domains_ms_office365_match.c.inc
DEST_AZURE=../src/lib/inc_generated/ndpi_domains_ms_azure_match.c.inc
TMP=/tmp/ms.json
TMP_AZURE=/tmp/azure.html
LIST=/tmp/ms.list
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
ORIGIN="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
ORIGIN_AZURE="https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading file... ${ORIGIN_AZURE}"
http_response=$(curl -s -o $TMP_AZURE -w "%{http_code}" ${ORIGIN_AZURE})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing domains..."

#OUTLOOK
jq -r '.[] | select(.serviceArea=="Exchange") | .urls[]?' < $TMP | sed 's/^\*\.//' | sort -u | uniq > $LIST
./domains2list.py $LIST "Outlook" NDPI_PROTOCOL_MS_OUTLOOK NDPI_PROTOCOL_CATEGORY_MAIL NDPI_PROTOCOL_ACCEPTABLE > $DEST_OUTLOOK

#SKYPE/TEAMS
jq -r '.[] | select(.serviceArea=="Skype") | .urls[]?' < $TMP | sed 's/^\*\.//' | sort -u | uniq > $LIST
./domains2list.py $LIST "Teams" NDPI_PROTOCOL_MSTEAMS NDPI_PROTOCOL_CATEGORY_COLLABORATIVE NDPI_PROTOCOL_ACCEPTABLE > $DEST_MSTEAMS

#ONEDRIVE
jq -r '.[] | select(.serviceArea=="SharePoint") | .urls[]?' < $TMP | sed 's/^\*\.//' | sort -u | uniq > $LIST
./domains2list.py $LIST "MS_OneDrive" NDPI_PROTOCOL_MS_ONE_DRIVE NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_ONEDRIVE

#OFFICE
# On .id 125 there are mainly some generic domains for certificate management like digicert, verisign. Specific
# microsoft domains are classified via the generic "catch-all" rules in ndpi_content_match.c.in
jq -r '.[] | select(.serviceArea=="Common" and .id != 125) | .urls[]?' < $TMP | sed 's/^\*\.//' | sort -u | uniq > $LIST
#TODO: NDPI_PROTOCOL_MICROSOFT_365 or NDPI_PROTOCOL_MICROSOFT?
./domains2list.py $LIST "Microsoft365" NDPI_PROTOCOL_MICROSOFT_365 NDPI_PROTOCOL_CATEGORY_COLLABORATIVE NDPI_PROTOCOL_ACCEPTABLE > $DEST_OFFICE365

#AZURE
cat $TMP_AZURE | sed -ne 's/<td>\*.\(.*\)<\/td>/\1/gp' | sed 's/\/ /\n/g' | sed 's/^\*\.//' | sort -u | uniq > $LIST
./domains2list.py $LIST "Azure" NDPI_PROTOCOL_MICROSOFT_AZURE NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_AZURE

rm -f $TMP $TMP_AZURE $LIST

echo "(3) Microsoft domains are available in $DEST_OUTLOOK, $DEST_MSTEAMS, $DEST_ONEDRIVE, $DEST_OFFICE365, $DEST_AZURE"
exit 0
