#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1

DEST_OUTLOOK=../src/lib/inc_generated/ndpi_domains_ms_outlook_match.c.inc
DEST_MSTEAMS=../src/lib/inc_generated/ndpi_domains_ms_teams_match.c.inc
DEST_ONEDRIVE=../src/lib/inc_generated/ndpi_domains_ms_onedrive_match.c.inc
DEST_OFFICE365=../src/lib/inc_generated/ndpi_domains_ms_office365_match.c.inc
DEST_AZURE=../src/lib/inc_generated/ndpi_domains_ms_azure_match.c.inc
DEST_GENERIC=../src/lib/inc_generated/ndpi_domains_ms_generic_match.c.inc
TMP=/tmp/ms.json
TMP_AZURE=/tmp/azure.html
LIST2=/tmp/list2
LIST_OUTLOOK=/tmp/ms.outlook.list
LIST_MSTEAMS=/tmp/ms.msteams.list
LIST_ONEDRIVE=/tmp/ms.onedrive.list
LIST_OFFICE365=/tmp/ms.office365.list
LIST_AZURE=/tmp/ms.azure.list
LIST_GENERIC=/tmp/ms.generic.list
# https://docs.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
ORIGIN="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
ORIGIN_AZURE="https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains"

echo "(1) Downloading file... ${ORIGIN}"
http_response=$(curl -L -s -o $TMP -w "%{http_code}" ${ORIGIN})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading file... ${ORIGIN_AZURE}"
http_response=$(curl -L -s -o $TMP_AZURE -w "%{http_code}" ${ORIGIN_AZURE})
if [ $http_response != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(2) Processing domains..."

#OUTLOOK
jq -r '.[] | select(.serviceArea=="Exchange") | .urls[]?' < $TMP | sed 's/^\*\.//' | sed -e 's/[[:space:]]*$//g' | sort -u | uniq > $LIST_OUTLOOK

#SKYPE/TEAMS
jq -r '.[] | select(.serviceArea=="Skype") | .urls[]?' < $TMP | sed 's/^\*\.//' | sed -e 's/[[:space:]]*$//g' | sort -u | uniq > $LIST_MSTEAMS

#ONEDRIVE
jq -r '.[] | select(.serviceArea=="SharePoint") | .urls[]?' < $TMP | sed 's/^\*\.//' | sed -e 's/[[:space:]]*$//g' | sort -u | uniq > $LIST_ONEDRIVE

#OFFICE
# On .id 125 there are mainly some generic domains for certificate management like digicert, verisign. Specific
# microsoft domains are classified via the generic "catch-all" rules in ndpi_content_match.c.in
#
# Skip also the three generic domains (on .id 50 and 78): *.microsoft.com, *.msocdn.com, *.onmicrosoft.com
# As reported in the web page:
#  "Some Office 365 features require endpoints within these domains (including CDNs). Many specific
#   FQDNs within these wildcards have been published recently as we work to either remove or better
#   explain our guidance relating to these wildcards"
#
# We will handle them via the generic "catch-all" rules as well
#
jq -r '.[] | select(.serviceArea=="Common" and .id != 125 and .id != 50 and .id != 78) | .urls[]?' < $TMP | sed -n '/\*\.\.com/!p' | sed 's/^\*\.//' | sed -e 's/[[:space:]]*$//g' | sort -u | uniq > $LIST_OFFICE365

#AZURE
#Skip *.onmicrosoft.com; see above
cat $TMP_AZURE | sed -ne 's/<td>\*.\(.*\)<\/td>/\1/gp' | sed 's/\/ /\n/g' | sed -e '/\*\.onmicrosoft\.com/d' | sed 's/^\*\.//' | sed -e 's/[[:space:]]*$//g' | sort -u | uniq > $LIST_AZURE

#We can have duplicates in these lists!!
#Look for duplicates: remove them from the original lists and put them in the generic one
cat $LIST_OUTLOOK $LIST_MSTEAMS $LIST_ONEDRIVE $LIST_OFFICE365 $LIST_AZURE | sort | uniq -d > $LIST_GENERIC
grep -vwF -f $LIST_GENERIC $LIST_OUTLOOK > $LIST2 && mv $LIST2 $LIST_OUTLOOK
grep -vwF -f $LIST_GENERIC $LIST_MSTEAMS > $LIST2 && mv $LIST2 $LIST_MSTEAMS
grep -vwF -f $LIST_GENERIC $LIST_ONEDRIVE > $LIST2 && mv $LIST2 $LIST_ONEDRIVE
grep -vwF -f $LIST_GENERIC $LIST_OFFICE365 > $LIST2 && mv $LIST2 $LIST_OFFICE365
grep -vwF -f $LIST_GENERIC $LIST_AZURE > $LIST2 && mv $LIST2 $LIST_AZURE

./domains2list.py $LIST_OUTLOOK "Outlook" NDPI_PROTOCOL_MS_OUTLOOK NDPI_PROTOCOL_CATEGORY_MAIL NDPI_PROTOCOL_ACCEPTABLE > $DEST_OUTLOOK
./domains2list.py $LIST_MSTEAMS "Teams" NDPI_PROTOCOL_MSTEAMS NDPI_PROTOCOL_CATEGORY_COLLABORATIVE NDPI_PROTOCOL_ACCEPTABLE > $DEST_MSTEAMS
./domains2list.py $LIST_ONEDRIVE "MS_OneDrive" NDPI_PROTOCOL_MS_ONE_DRIVE NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_ONEDRIVE
./domains2list.py $LIST_OFFICE365 "Microsoft365" NDPI_PROTOCOL_MICROSOFT_365 NDPI_PROTOCOL_CATEGORY_COLLABORATIVE NDPI_PROTOCOL_ACCEPTABLE > $DEST_OFFICE365
./domains2list.py $LIST_AZURE "Azure" NDPI_PROTOCOL_MICROSOFT_AZURE NDPI_PROTOCOL_CATEGORY_CLOUD NDPI_PROTOCOL_ACCEPTABLE > $DEST_AZURE
./domains2list.py $LIST_GENERIC "Microsoft" NDPI_PROTOCOL_MICROSOFT NDPI_PROTOCOL_CATEGORY_WEB NDPI_PROTOCOL_ACCEPTABLE > $DEST_GENERIC

rm -f $TMP $TMP_AZURE $LIST_OUTLOOK $LIST_MSTEAMS $LIST_ONEDRIVE $LIST_OFFICE365 $LIST_AZURE $LIST_GENERIC $LIST2

echo "(3) Microsoft domains are available in $DEST_OUTLOOK, $DEST_MSTEAMS, $DEST_ONEDRIVE, $DEST_OFFICE365, $DEST_AZURE, $DEST_GENERIC"
exit 0
