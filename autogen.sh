#!/bin/sh

NDPI_MAJOR="2"
NDPI_MINOR="2"
NDPI_PATCH="0"
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

/bin/rm -f configure config.h config.h.in src/lib/Makefile.in

AUTOCONF=$(which autoconf)
AUTOMAKE=$(which automake)
LIBTOOL=$(which libtool)
LIBTOOLIZE=$(which libtoolize)
AUTORECONF=$(which autoreconf)

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

cat configure.seed | sed "s/@NDPI_MAJOR@/$NDPI_MAJOR/g" | sed "s/@NDPI_MINOR@/$NDPI_MINOR/g" | sed "s/@NDPI_PATCH@/$NDPI_PATCH/g" | sed "s/@NDPI_VERSION_SHORT@/$NDPI_VERSION_SHORT/g" > configure.ac
autoreconf -ivf
./configure $*
