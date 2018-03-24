#!/bin/sh

NDPI_MAJOR="2"
NDPI_MINOR="3"
NDPI_PATCH="0"
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

rm -f configure config.h config.h.in src/lib/Makefile.in

AUTOCONF=$(command -v autoconf)
AUTOMAKE=$(command -v automake)
LIBTOOL=$(command -v libtool)
LIBTOOLIZE=$(command -v libtoolize)
AUTORECONF=$(command -v autoreconf)

if test -z $AUTOCONF; then
    echo "autoconf is missing: please install it and try again"
    exit
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

cat configure.seed | sed \
    -e "s/@NDPI_MAJOR@/$NDPI_MAJOR/g" \
    -e "s/@NDPI_MINOR@/$NDPI_MINOR/g" \
    -e "s/@NDPI_PATCH@/$NDPI_PATCH/g" \
    -e "s/@NDPI_VERSION_SHORT@/$NDPI_VERSION_SHORT/g" \
    > configure.ac

autoreconf -ivf
cat configure | sed "s/#define PACKAGE/#define NDPI_PACKAGE/g" | sed "s/#define VERSION/#define NDPI_VERSION/g"  > configure.tmp
cat configure.tmp > configure

chmod +x configure
./configure $*
