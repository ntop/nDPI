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

echo "(1) Downloading Tencent routes..."
DEST=../src/lib/inc_generated/ndpi_asn_tencent.c.inc
create_list NDPI_PROTOCOL_TENCENT $DEST "AS45090" "AS137876" "AS133478" "AS132591" "AS132203"
echo "(3) Tencent IPs are available in $DEST"

echo "(1) Downloading OpenDNS routes..."
DEST=../src/lib/inc_generated/ndpi_asn_opendns.c.inc
create_list NDPI_PROTOCOL_OPENDNS $DEST "AS36692" "AS30607"
echo "(3) OpenDNS IPs are available in $DEST"

echo "(1) Downloading Dropbox routes..."
DEST=../src/lib/inc_generated/ndpi_asn_dropbox.c.inc
create_list NDPI_PROTOCOL_DROPBOX $DEST "AS62190" "AS54372" "AS393874" "AS203719" "AS200499" "AS19679"
echo "(3) Dropbox IPs are available in $DEST"

echo "(1) Downloading Starcraft routes..." #Starcraft or a more generic Blizzard stuff?
DEST=../src/lib/inc_generated/ndpi_asn_starcraft.c.inc
create_list NDPI_PROTOCOL_STARCRAFT $DEST "AS57976" "AS32163"
echo "(3) Starcraft IPs are available in $DEST"

echo "(1) Downloading UbuntuOne routes..." #Canonical
DEST=../src/lib/inc_generated/ndpi_asn_ubuntuone.c.inc
create_list NDPI_PROTOCOL_UBUNTUONE $DEST "AS41231" "AS11210"
echo "(3) UbuntuOne IPs are available in $DEST"

echo "(1) Downloading Twitch routes..."
DEST=../src/lib/inc_generated/ndpi_asn_twitch.c.inc
create_list NDPI_PROTOCOL_TWITCH $DEST "AS46489" "AS397153"
echo "(3) Twitch IPs are available in $DEST"

echo "(1) Downloading Hotspot Shield routes..." #AnchorFree
DEST=../src/lib/inc_generated/ndpi_asn_hotspotshield.c.inc
create_list NDPI_PROTOCOL_HOTSPOT_SHIELD $DEST "AS26642"
echo "(3) Hotspot Shield IPs are available in $DEST"

echo "(1) Downloading GitHub routes..."
DEST=../src/lib/inc_generated/ndpi_asn_github.c.inc
create_list NDPI_PROTOCOL_GITHUB $DEST "AS36459"
echo "(3) GitHub IPs are available in $DEST"

echo "(1) Downloading Steam routes..." #Valve
DEST=../src/lib/inc_generated/ndpi_asn_steam.c.inc
create_list NDPI_PROTOCOL_STEAM $DEST "AS32590"
echo "(3) Steam IPs are available in $DEST"

echo "(1) Downloading Bloomberg routes..."
DEST=../src/lib/inc_generated/ndpi_asn_bloomberg.c.inc
create_list NDPI_PROTOCOL_BLOOMBERG $DEST "AS8188" "AS58850" "AS33220" "AS33181" "AS199559" "AS17063" "AS13908" "AS10361"
echo "(3) Bloomberg IPs are available in $DEST"

echo "(1) Downloading Citrix routes..." #Citrix or a more generic LogMeIn stuff?
DEST=../src/lib/inc_generated/ndpi_asn_citrix.c.inc
create_list NDPI_PROTOCOL_CITRIX $DEST "AS395424" "AS21866" "AS213380" "AS20104" "AS16815"
echo "(3) Citrix IPs are available in $DEST"
