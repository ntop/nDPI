#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_crawlers_match.c.inc
TMP1=/tmp/bot_google_c1.json
TMP2=/tmp/bot_google_c2.json
TMP3=/tmp/bot_google_c3.json
TMP_BING=/tmp/bot_bing.json
TMP_FB=/tmp/bot_fb.list
TMP_TW=/tmp/bot_tw.list
LIST=/tmp/bot.list
LIST6=/tmp/bot.list6
LIST_MERGED=/tmp/bot.list_m
LIST6_MERGED=/tmp/bot.list6_m
#Google Common crawlers
ORIGIN1="https://developers.google.com/static/search/apis/ipranges/googlebot.json"
#Google Special-case crawlers
ORIGIN2="https://developers.google.com/static/search/apis/ipranges/special-crawlers.json"
#Google User-triggered fetchers
ORIGIN3="https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json"
#Bing Bot
ORIGIN_BING="https://www.bing.com/toolbox/bingbot.json"
#Facebook Bot: https://developers.facebook.com/docs/sharing/webmasters/crawler/
#TwitterBot
ORIGIN_TW="https://developer.x.com/en/docs/twitter-for-websites/cards/guides/troubleshooting-cards"

echo "(1) Downloading file... ${ORIGIN1}"
http_response=$(curl -s -o $TMP1 -w "%{http_code}" ${ORIGIN1})
check_http_response "${http_response}"
is_file_empty "${TMP1}"

echo "(1) Downloading file... ${ORIGIN2}"
http_response=$(curl -s -o $TMP2 -w "%{http_code}" ${ORIGIN2})
check_http_response "${http_response}"
is_file_empty "${TMP2}"

echo "(1) Downloading file... ${ORIGIN3}"
http_response=$(curl -s -o $TMP3 -w "%{http_code}" ${ORIGIN3})
check_http_response "${http_response}"
is_file_empty "${TMP3}"

echo "(1) Downloading file... ${ORIGIN_BING}"
http_response=$(curl -s -o $TMP_BING -w "%{http_code}" ${ORIGIN_BING})
check_http_response "${http_response}"
is_file_empty "${TMP_BING}"

echo "(1) Downloading FB crawlers routes... "
whois -h whois.radb.net -- '-i origin AS32934' | grep ^route > $TMP_FB
is_file_empty "${TMP_FB}"

echo "(1) Downloading page... ${ORIGIN_TW}"
http_response=$(curl -s -o $TMP_TW -w "%{http_code}" ${ORIGIN_TW})
check_http_response "${http_response}"
is_file_empty "${TMP_TW}"


echo "(2) Processing IP addresses..."
{
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP1
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP2
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP3
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP_BING
    grep -v route6 $TMP_FB | tr -d 'route:^ '
    grep "IP ranges are" $TMP_TW | grep -E -o "[^^][0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}" | tr -d ' ' # TODO: ipv4 only
} > $LIST
is_file_empty "${LIST}"
./mergeipaddrlist.py "${LIST}" > "${LIST_MERGED}"
is_file_empty "${LIST_MERGED}"
{
    jq -r '.prefixes | .[].ipv6Prefix  | select( . != null )' $TMP1
    jq -r '.prefixes | .[].ipv6Prefix  | select( . != null )' $TMP2
    jq -r '.prefixes | .[].ipv6Prefix  | select( . != null )' $TMP3
    jq -r '.prefixes | .[].ipv6Prefix  | select( . != null )' $TMP_BING
    grep route6 $TMP_FB | cut -c9- | tr -d ' '
} > $LIST6
is_file_empty "${LIST6}"
./mergeipaddrlist.py "${LIST6}" > "${LIST6_MERGED}"
is_file_empty "${LIST6_MERGED}"
./ipaddr2list.py $LIST_MERGED NDPI_HTTP_CRAWLER_BOT $LIST6_MERGED > $DEST
is_file_empty "${DEST}"
rm -f $TMP1 $TMP2 $TMP3 $TMP_BING $TMP_FB $TMP_TW $LIST $LIST6 $LIST_MERGED $LIST6_MERGED

echo "(3) Crawlers IPs are available in $DEST"
exit 0
