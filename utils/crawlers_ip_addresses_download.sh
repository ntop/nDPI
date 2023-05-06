#!/bin/sh

set -e

cd "$(dirname "${0}")" || exit 1

DEST=../src/lib/inc_generated/ndpi_crawlers_match.c.inc
TMP1=/tmp/bot_google_c1.json
TMP2=/tmp/bot_google_c2.json
TMP3=/tmp/bot_google_c3.json
TMP_BING=/tmp/bot_bing.json
TMP_FB=/tmp/bot_fb.list
LIST=/tmp/bot.list
#Google Common crawlers
ORIGIN1="https://developers.google.com/static/search/apis/ipranges/googlebot.json"
#Google Special-case crawlers
ORIGIN2="https://developers.google.com/static/search/apis/ipranges/special-crawlers.json"
#Google User-triggered fetchers
ORIGIN3="https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json"
#Bing Bot
ORIGIN_BING="https://www.bing.com/toolbox/bingbot.json"
#Facebook Bot: https://developers.facebook.com/docs/sharing/webmasters/crawler/

echo "(1) Downloading file... ${ORIGIN1}"
http_response=$(curl -s -o $TMP1 -w "%{http_code}" ${ORIGIN1})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading file... ${ORIGIN2}"
http_response=$(curl -s -o $TMP2 -w "%{http_code}" ${ORIGIN2})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading file... ${ORIGIN3}"
http_response=$(curl -s -o $TMP3 -w "%{http_code}" ${ORIGIN3})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading file... ${ORIGIN_BING}"
http_response=$(curl -s -o $TMP_BING -w "%{http_code}" ${ORIGIN_BING})
if [ "$http_response" != "200" ]; then
    echo "Error $http_response: you probably need to update the list url!"
    exit 1
fi

echo "(1) Downloading FB crawlers routes... "
whois -h whois.radb.net -- '-i origin AS32934' | grep ^route > $TMP_FB

echo "(2) Processing IP addresses..."
{
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP1 # TODO: ipv6
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP2 # TODO: ipv6
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP3 # TODO: ipv6
    jq -r '.prefixes | .[].ipv4Prefix  | select( . != null )' $TMP_BING # TODO: ipv6
    grep -v route6 $TMP_FB | tr -d 'route:^ ' # TODO: ipv6
} > $LIST
./ipaddr2list.py $LIST NDPI_HTTP_CRAWLER_BOT > $DEST
rm -f $TMP1 $TMP2 $TMP3 $TMP_BING $TMP_FB $LIST

echo "(3) Crawlers IPs are available in $DEST"
exit 0
