#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

LIST=../lists/public_suffix_list.dat

printf '(1) %s\n' "Getting domain suffix list"
DOMAINS="$(curl -s 'https://publicsuffix.org/list/public_suffix_list.dat')"
is_str_empty "${DOMAINS}" "Please check the URL."

echo "${DOMAINS}" > ${LIST}

printf '(3) %s\n' "List ${LIST} is now ready"
exit 0
