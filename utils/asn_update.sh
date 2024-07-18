#!/usr/bin/env bash
set -e

FAILED_ASN=0
TOTAL_ASN=0

function processing_list() {
	local LIST_MERGED="/tmp/list_m"
	local LIST6_MERGED="/tmp/list6_m"

	echo "(2) Processing IP addresses..."
	./mergeipaddrlist.py "$1" > $LIST_MERGED
	./mergeipaddrlist.py "$2" > $LIST6_MERGED
	./ipaddr2list.py "$LIST_MERGED" "$3" "$LIST6_MERGED" > "$4"
	rm -f $LIST_MERGED $LIST6_MERGED
}

function create_list() {
	LIST=/tmp/list
	LIST6=/tmp/list6

	for i in "${@:4}"; do
		TOTAL_ASN=$(( TOTAL_ASN + 1 ))
		if ! ./get_routes_by_asn.sh "$i" >> $LIST; then
			echo "Could not fetch route for ${i} (${1})"
			FAILED_ASN=$(( FAILED_ASN + 1 ))
		fi
		if ! ./get_routes6_by_asn.sh "$i" >> $LIST6; then
			echo "Could not fetch route6 for ${i} (${1})"
			FAILED_ASN=$(( FAILED_ASN + 1 ))
		fi
	done

	#TODO: ipv6 addresses
	if [ ! -z "$3" ];  then
	    # Split comma separated list of additional networks to add
	    echo "$3" | tr "," "\n" >> $LIST
	fi

	processing_list "$LIST" "$LIST6" "$1" "$2"
	rm -f $LIST $LIST6
}

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

echo "(1) Downloading Apple routes..."
DEST="../src/lib/inc_generated/ndpi_asn_apple.c.inc"
create_list NDPI_PROTOCOL_APPLE $DEST "" "AS714" "AS6185" "AS2709"
echo "(3) Apple IPs are available in $DEST"

echo "(1) Downloading Facebook routes..."
DEST=../src/lib/inc_generated/ndpi_asn_facebook.c.inc
create_list NDPI_PROTOCOL_FACEBOOK $DEST "" "AS63293" "AS54115" "AS34825" "AS32934"
echo "(3) Facebook IPs are available in $DEST"

echo "(1) Downloading Netflix routes..."
DEST=../src/lib/inc_generated/ndpi_asn_netflix.c.inc
create_list NDPI_PROTOCOL_NETFLIX $DEST "" "AS55095" "AS40027" "AS394406" "AS2906"
echo "(3) Netflix IPs are available in $DEST"

echo "(1) Downloading Teamviewer routes..."
DEST=../src/lib/inc_generated/ndpi_asn_teamviewer.c.inc
create_list NDPI_PROTOCOL_TEAMVIEWER $DEST "" "AS43304" "AS212710" "AS208187" "AS208175"
echo "(3) Teamviewer IPs are available in $DEST"

echo "(1) Downloading Telegram routes..."
DEST=../src/lib/inc_generated/ndpi_asn_telegram.c.inc
create_list NDPI_PROTOCOL_TELEGRAM $DEST "" "AS62041" "AS62014" "AS59930" "AS44907" "AS211157"
echo "(3) Telegram IPs are available in $DEST"

echo "(1) Downloading Twitter routes..."
DEST=../src/lib/inc_generated/ndpi_asn_twitter.c.inc
create_list NDPI_PROTOCOL_TWITTER $DEST "" "AS63179" "AS54888" "AS35995" "AS13414"
echo "(3) Twitter IPs are available in $DEST"

echo "(1) Downloading Webex routes..."
DEST=../src/lib/inc_generated/ndpi_asn_webex.c.inc
create_list NDPI_PROTOCOL_WEBEX $DEST "" "AS6577" "AS399937" "AS16472" "AS13445"
echo "(3) Webex IPs are available in $DEST"

echo "(1) Downloading Tencent routes..."
DEST=../src/lib/inc_generated/ndpi_asn_tencent.c.inc
create_list NDPI_PROTOCOL_TENCENT $DEST "" "AS45090" "AS137876" "AS133478" "AS132591" "AS132203"
echo "(3) Tencent IPs are available in $DEST"

echo "(1) Downloading OpenDNS routes..."
DEST=../src/lib/inc_generated/ndpi_asn_opendns.c.inc
create_list NDPI_PROTOCOL_OPENDNS $DEST "" "AS36692" "AS30607"
echo "(3) OpenDNS IPs are available in $DEST"

echo "(1) Downloading Dropbox routes..."
DEST=../src/lib/inc_generated/ndpi_asn_dropbox.c.inc
create_list NDPI_PROTOCOL_DROPBOX $DEST "" "AS62190" "AS54372" "AS393874" "AS203719" "AS200499" "AS19679"
echo "(3) Dropbox IPs are available in $DEST"

echo "(1) Downloading Starcraft routes..." #Starcraft or a more generic Blizzard stuff?
DEST=../src/lib/inc_generated/ndpi_asn_starcraft.c.inc
create_list NDPI_PROTOCOL_STARCRAFT $DEST "" "AS57976" "AS32163"
echo "(3) Starcraft IPs are available in $DEST"

echo "(1) Downloading UbuntuOne routes..." #Canonical
DEST=../src/lib/inc_generated/ndpi_asn_ubuntuone.c.inc
create_list NDPI_PROTOCOL_UBUNTUONE $DEST "" "AS41231" "AS11210"
echo "(3) UbuntuOne IPs are available in $DEST"

echo "(1) Downloading Twitch routes..."
DEST=../src/lib/inc_generated/ndpi_asn_twitch.c.inc
create_list NDPI_PROTOCOL_TWITCH $DEST "" "AS46489" "AS397153"
echo "(3) Twitch IPs are available in $DEST"

echo "(1) Downloading Hotspot Shield routes..." #AnchorFree
DEST=../src/lib/inc_generated/ndpi_asn_hotspotshield.c.inc
create_list NDPI_PROTOCOL_HOTSPOT_SHIELD $DEST "" "AS26642"
echo "(3) Hotspot Shield IPs are available in $DEST"

echo "(1) Downloading GitHub routes..."
DEST=../src/lib/inc_generated/ndpi_asn_github.c.inc
create_list NDPI_PROTOCOL_GITHUB $DEST "" "AS36459"
echo "(3) GitHub IPs are available in $DEST"

echo "(1) Downloading Steam routes..." #Valve
DEST=../src/lib/inc_generated/ndpi_asn_steam.c.inc
create_list NDPI_PROTOCOL_STEAM $DEST "" "AS32590"
echo "(3) Steam IPs are available in $DEST"

echo "(1) Downloading Bloomberg routes..."
DEST=../src/lib/inc_generated/ndpi_asn_bloomberg.c.inc
create_list NDPI_PROTOCOL_BLOOMBERG $DEST "" "AS8188" "AS58850" "AS33220" "AS33181" "AS199559" "AS17063" "AS13908" "AS10361"
echo "(3) Bloomberg IPs are available in $DEST"

echo "(1) Downloading Edgecast routes..."
DEST=../src/lib/inc_generated/ndpi_asn_edgecast.c.inc
create_list NDPI_PROTOCOL_EDGECAST $DEST "" "AS15133"
echo "(3) Edgecast IPs are available in $DEST"

echo "(1) Downloading LogMeIn/GoTo..."
DEST=../src/lib/inc_generated/ndpi_asn_goto.c.inc
create_list NDPI_PROTOCOL_GOTO $DEST "" "AS395424" "AS21866" "AS213380" "AS20104" "AS16815"
echo "(3) LogMeIn/GoTo IPs are available in $DEST"

echo "(1) Downloading RiotGames..."
DEST=../src/lib/inc_generated/ndpi_asn_riotgames.c.inc
create_list NDPI_PROTOCOL_RIOTGAMES $DEST "" "AS6507"
echo "(3) RiotGames IPs are available in $DEST"

echo "(1) Downloading Threema..."
DEST=../src/lib/inc_generated/ndpi_asn_threema.c.inc
create_list NDPI_PROTOCOL_THREEMA $DEST "" "AS29691"
echo "(3) Threema IPs are available in $DEST"

echo "(1) Downloading AliBaba..."
DEST=../src/lib/inc_generated/ndpi_asn_alibaba.c.inc
create_list NDPI_PROTOCOL_ALIBABA $DEST "" "AS59055" "AS59054" "AS59053" "AS59052" "AS59051" "AS59028" "AS45104" "AS45103" "AS45102" "AS37963" "AS34947" "AS211914" "AS134963"
echo "(3) AliBaba IPs are available in $DEST"

echo "(1) Downloading AVAST..."
DEST=../src/lib/inc_generated/ndpi_asn_avast.c.inc
create_list NDPI_PROTOCOL_AVAST $DEST "" "AS198605"
echo "(3) AVAST IPs are available in $DEST"

echo "(1) Downloading Discord..."
DEST=../src/lib/inc_generated/ndpi_asn_discord.c.inc
create_list NDPI_PROTOCOL_DISCORD $DEST "" "AS49544"
echo "(3) Discord IPs are available in $DEST"

echo "(1) Downloading LINE..."
DEST=../src/lib/inc_generated/ndpi_asn_line.c.inc
create_list NDPI_PROTOCOL_LINE $DEST "125.209.252.0/24" "AS38631"
echo "(3) Line IPs are available in $DEST"

echo "(1) Downloading VK..."
DEST=../src/lib/inc_generated/ndpi_asn_vk.c.inc
create_list NDPI_PROTOCOL_VK $DEST "" "AS47541"
echo "(3) VK IPs are available in $DEST"

echo "(1) Downloading Yandex..."
DEST=../src/lib/inc_generated/ndpi_asn_yandex.c.inc
create_list NDPI_PROTOCOL_YANDEX $DEST "" "AS44534" "AS207207" "AS202611" "AS13238"
echo "(3) Yandex IPs are available in $DEST"

echo "(1) Downloading Yandex Cloud..."
DEST=../src/lib/inc_generated/ndpi_asn_yandex_cloud.c.inc
create_list NDPI_PROTOCOL_YANDEX_CLOUD $DEST "" "AS210656" "AS200350"
echo "(3) Yandex Cloud IPs are available in $DEST"

echo "(1) Downloading Disney+..." #Only "Disney Streaming Services"
DEST=../src/lib/inc_generated/ndpi_asn_disney_plus.c.inc
create_list NDPI_PROTOCOL_DISNEYPLUS $DEST "" "AS400805" "AS398849" "AS22604" "AS11251"
echo "(3) Disney+ IPs are available in $DEST"

echo "(1) Downloading Hulu..."
DEST=../src/lib/inc_generated/ndpi_asn_hulu.c.inc
create_list NDPI_PROTOCOL_HULU $DEST "" "AS23286"
echo "(3) Hulu IPs are available in $DEST"

echo "(1) Downloading EpicGames.."
DEST=../src/lib/inc_generated/ndpi_asn_epicgames.c.inc
create_list NDPI_PROTOCOL_EPICGAMES $DEST "" "AS4356" "AS397645" "AS395701" "AS393326"
echo "(3) EpicGames IPs are available in $DEST"

echo "(1) Downloading Nvidia..."
DEST=../src/lib/inc_generated/ndpi_asn_nvidia.c.inc
create_list NDPI_PROTOCOL_NVIDIA $DEST "" "AS60977" "AS50889" "AS20347" "AS11414"
echo "(3) Nvidia IPs are available in $DEST"

echo "(1) Downloading Roblox..."
DEST=../src/lib/inc_generated/ndpi_asn_roblox.c.inc
create_list NDPI_PROTOCOL_ROBLOX $DEST "" "AS22697"
echo "(3) Roblox IPs are available in $DEST"

if [ ${TOTAL_ASN} -eq 0 ] || [ ${TOTAL_ASN} -eq ${FAILED_ASN} ]; then
	printf '%s: %s\n' "${0}" "All download(s) failed, ./get_routes_by_asn.sh broken?"
	exit 1
else
	exit 0
fi
