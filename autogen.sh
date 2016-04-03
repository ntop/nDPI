#!/bin/sh


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

autoreconf -ivf
./configure $*
