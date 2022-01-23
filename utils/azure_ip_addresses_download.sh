#!/bin/sh

OUT=../src/lib/ndpi_azure_match.c.inc
TMP=/tmp/azure.json

echo "(1) Downloading file..."
# https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519
curl -s https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20211213.json -o $TMP

echo "(2) Processing IP addresses..."
# Note: the last "grep -v :" is used to skip IPv6 addresses
tr -d '\r' < $TMP | grep / | tr -d '"' | tr -d " " | tr -d "," | grep -v : > $OUT
./ipaddr2list.py $OUT NDPI_PROTOCOL_MICROSOFT_AZURE > $TMP
/bin/mv $TMP $OUT

echo "(3) Microsoft Azure IPs are available in $OUT"



