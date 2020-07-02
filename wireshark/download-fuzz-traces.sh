#!/bin/sh

URL_PREFIX='https://www.wireshark.org/download/automated/captures/'
TRACES="$(wget --no-verbose -O - "${URL_PREFIX}" | sed -n 's|^.*<a href="\([^"]\+\).pcap">.*$|\1.pcap|gp')"
CURDIR="$(dirname ${0})/../tests/pcap"

for trace in ${TRACES}; do
    destfile="${CURDIR}/${trace}"
    test -r "${destfile}" || wget --no-verbose "${URL_PREFIX}${trace}" -O "${destfile}"
done
