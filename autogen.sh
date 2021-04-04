#!/bin/sh

NDPI_MAJOR="4"
NDPI_MINOR="1"
NDPI_PATCH="0"
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

SCRIPT_DIR="$(dirname ${0})"

rm -f configure config.h config.h.in

AUTOCONF=$(command -v autoconf)
AUTOMAKE=$(command -v automake)
LIBTOOL=$(command -v libtool)
LIBTOOLIZE=$(command -v libtoolize)
AUTORECONF=$(command -v autoreconf)
PKG_CONFIG=$(command -v pkg-config)
FUZZY=

if test -z $AUTOCONF; then
    echo "autoconf is missing: please install it and try again"
    exit
else
    V=`autoconf --version | head -1 | cut -d ' ' -f 4`
    if [ "$V" = '2.63' ]; then
        FUZZY="dnl> "
    fi
fi

if test -z $AUTOMAKE; then
    echo "automake is missing: please install it and try again"
    exit
fi

if test -z $LIBTOOL && test -z $LIBTOOLIZE ; then
    echo "libtool and libtoolize is missing: please install it and try again"
    exit
fi

if test -z $AUTORECONF; then
    echo "autoreconf is missing: please install it and try again"
    exit
fi

if test -z $PKG_CONFIG; then
    echo "pkg-config is missing: please install it (apt-get install pkg-config) and try again"
    exit
fi

"${SCRIPT_DIR}/utils/generate_automake_am.sh"

cat "${SCRIPT_DIR}/configure.seed" | sed \
    -e "s/@NDPI_MAJOR@/$NDPI_MAJOR/g" \
    -e "s/@NDPI_MINOR@/$NDPI_MINOR/g" \
    -e "s/@NDPI_PATCH@/$NDPI_PATCH/g" \
    -e "s/@NDPI_VERSION_SHORT@/$NDPI_VERSION_SHORT/g" \
    -e "s/@FUZZY@/$FUZZY/g" \
    > "${SCRIPT_DIR}/configure.ac"

OLDPWD="$(pwd)"
cd "${SCRIPT_DIR}" || exit 1
autoreconf -ivf
cd "${OLDPWD}" || exit 1

cat "${SCRIPT_DIR}/configure" | \
    sed "s/#define PACKAGE/#define NDPI_PACKAGE/g" | \
    sed "s/#define VERSION/#define NDPI_VERSION/g" \
    > "${SCRIPT_DIR}/configure.tmp"
cat "${SCRIPT_DIR}/configure.tmp" > "${SCRIPT_DIR}/configure"

echo "${SCRIPT_DIR}/configure ${*}"
chmod +x "${SCRIPT_DIR}/configure"
${SCRIPT_DIR}/configure ${@}
