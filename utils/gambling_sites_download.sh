#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_gambling_match.c.inc
LIST=/tmp/gambling.list

printf '(1) %s\n' "Scraping Illegal Gambling Sites (Belgium)"
DOMAINS="$(curl -s 'https://www.gamingcommission.be/en/gaming-commission/illegal-games-of-chance/list-of-illegal-gambling-sites' | sed -n 's/^<td[^>]\+>\(.\+\.[a-zA-Z0-9]\+\)\(\|\/.*[^<]*\)<\/td>/\1/gp' || exit 1)"
is_str_empty "${DOMAINS}" "Please check gambling sites URL and sed REGEX."

printf '(2) %s\n' "Processing IP addresses..."
echo "${DOMAINS}" >${LIST}
./hostname2list.py "${LIST}" "Gambling" NDPI_PROTOCOL_GAMBLING NDPI_PROTOCOL_CATEGORY_WEB NDPI_PROTOCOL_UNSAFE >${DEST}
rm -f "${LIST}"
is_file_empty "${DEST}"

exit 0
