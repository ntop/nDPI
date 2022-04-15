#!/bin/bash

set -e

function processing_list() {
	local LIST_MERGED="/tmp/list_m"

	echo "(2) Processing IP addresses..."
	./mergeipaddrlist.py "$1" > $LIST_MERGED
	./ipaddr2list.py "$LIST_MERGED" "$2" > "$3"
	rm -f $LIST_MERGED
}

function create_list() {
	LIST=/tmp/list

	for i in "${@:3}"; do
		./get_routes_by_asn.sh "$i" >> $LIST
	done

	processing_list "$LIST" "$1" "$2"
	rm -f $LIST
}

cd "$(dirname "${0}")" || return

echo "(1) Downloading Apple routes..."
DEST="../src/lib/inc_generated/ndpi_asn_apple.c.inc"
create_list NDPI_PROTOCOL_APPLE $DEST "AS714" "AS6185" "AS2709"
echo "(3) Apple IPs are available in $DEST"

echo "(1) Downloading Facebook routes..."
DEST=../src/lib/inc_generated/ndpi_asn_facebook.c.inc
create_list NDPI_PROTOCOL_FACEBOOK $DEST "AS63293" "AS54115" "AS34825" "AS32934"
echo "(3) Facebook IPs are available in $DEST"

echo "(1) Downloading Netflix routes..."
DEST=../src/lib/inc_generated/ndpi_asn_netflix.c.inc
create_list NDPI_PROTOCOL_NETFLIX $DEST "AS55095" "AS40027" "AS394406" "AS2906"
echo "(3) Netflix IPs are available in $DEST"

echo "(1) Downloading Teamviewer routes..."
DEST=../src/lib/inc_generated/ndpi_asn_teamviewer.c.inc
create_list NDPI_PROTOCOL_TEAMVIEWER $DEST "AS43304" "AS212710" "AS208187" "AS208175"
echo "(3) Teamviewer IPs are available in $DEST"

echo "(1) Downloading Telegram routes..."
DEST=../src/lib/inc_generated/ndpi_asn_telegram.c.inc
create_list NDPI_PROTOCOL_TELEGRAM $DEST "AS62041" "AS62014" "AS59930" "AS44907" "AS211157"
echo "(3) Telegram IPs are available in $DEST"

echo "(1) Downloading Twitter routes..."
DEST=../src/lib/inc_generated/ndpi_asn_twitter.c.inc
create_list NDPI_PROTOCOL_TWITTER $DEST "AS63179" "AS54888" "AS35995" "AS13414"
echo "(3) Twitter IPs are available in $DEST"

echo "(1) Downloading Webex routes..."
DEST=../src/lib/inc_generated/ndpi_asn_webex.c.inc
create_list NDPI_PROTOCOL_WEBEX $DEST "AS6577" "AS399937" "AS16472" "AS13445"
echo "(3) Webex IPs are available in $DEST"
