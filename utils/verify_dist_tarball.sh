#!/usr/bin/env bash

EXCLUDE_PATTERN="(.*\.m4$|Makefile$|Makefile\.in$|utils/verify_dist_tarball\.sh|^packages/debian/.*|^packages/debian|^test-driver|^config\.guess|^config\.sub|^compile|^configure|/|depcomp|.gitattributes|.gitignore|install-sh|ltmain.sh|missing|src/include/ndpi_config\.h\.in|tests/pcap|tests/result)$"

set -x
set -e

cd "$(dirname "${0}")/.."

git ls-tree --full-tree --name-only -r HEAD | grep -vE "${EXCLUDE_PATTERN}" | sort >/tmp/ndpi-dist-verify-git.txt

TARBALL="${1}"
if [ -z "${TARBALL}" ]; then
	if [ ! -r Makefile ]; then
		./autogen.sh
	fi
	make dist
	AC_VERSION="$(sed -n 's/^AC_INIT.*\([[:digit:]]\+\.[[:digit:]]\+\.[[:digit:]]\+\).*$/\1/gp' < configure.ac)"
	TARBALL="./libndpi-${AC_VERSION}.tar.gz"
fi

tar -tzf "${TARBALL}" | sed -n 's|^[^/]*/||gp' | grep -v '^$' | grep -vE "${EXCLUDE_PATTERN}" | sort >/tmp/ndpi-dist-verify-tar.txt

diff -u0 /tmp/ndpi-dist-verify-git.txt /tmp/ndpi-dist-verify-tar.txt

rm -f /tmp/ndpi-dist-verify-git.txt /tmp/ndpi-dist-verify-tar.txt
