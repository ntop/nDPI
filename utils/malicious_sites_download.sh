#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

# NDPI_PROTOCOL_CATEGORY_MALWARE = 100
LIST=../lists/100_malware.list

TMP=/tmp/mal.json
ORIGIN="https://hole.cert.pl/domains/domains.json"


printf '(1) Downloading file... %s\n' "${ORIGIN}"
http_response=$(curl -s -o ${TMP} -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

printf '%s\n' "(2) Processing Domains..."
jq -r '.[] | select(.DeleteDate="")' < ${TMP} | sed -n 's/^[^"]*"DomainAddress": "\([^"]*\)".*$/\1/gp' >${LIST}

rm -f "${TMP}"
exit 0
