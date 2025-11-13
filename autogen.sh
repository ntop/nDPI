#!/usr/bin/env sh

rm -f configure config.h config.h.in

AUTOCONF=$(command -v autoconf)
AUTOMAKE=$(command -v automake)
LIBTOOL=$(command -v libtool)
LIBTOOLIZE=$(command -v libtoolize)
AUTORECONF=$(command -v autoreconf)
PKG_CONFIG=$(command -v pkg-config)
MAKE=$(command -v make)

if test -z "${AUTOCONF}"; then
    echo "ERROR: autoconf is missing" >&2
    echo "Please install autotools package (e.g., apt-get install autoconf)" >&2
    exit 1
fi

if test -z "${AUTOMAKE}"; then
    echo "ERROR: automake is missing" >&2
    echo "Please install automake package (e.g., apt-get install automake)" >&2
    exit 1
fi

if test -z "${LIBTOOL}" && test -z "${LIBTOOLIZE}"; then
    echo "ERROR: libtool and libtoolize are both missing" >&2
    echo "Please install libtool package (e.g., apt-get install libtool)" >&2
    exit 1
fi

if test -z "${AUTORECONF}"; then
    echo "ERROR: autoreconf is missing" >&2
    echo "Please install autoconf package (e.g., apt-get install autoconf)" >&2
    exit 1
fi

if test -z "${PKG_CONFIG}"; then
    echo "ERROR: pkg-config is missing" >&2
    echo "Please install pkg-config package (e.g., apt-get install pkg-config)" >&2
    exit 1
fi

if test -z "${MAKE}"; then
    echo "ERROR: make is missing" >&2
    echo "Please install make package (e.g., apt-get install make)" >&2
    exit 1
fi

echo "Running autoreconf to generate build system..."
autoreconf -ivf || {
    echo "ERROR: autoreconf failed" >&2
    echo "Please check that all autotools are properly installed" >&2
    exit 1
}

echo "Build system generated successfully!"
echo "You can now run: ./configure && make"

#####
# Don't call `configure` here!!!! It breaks out-of-tree builds
#####
