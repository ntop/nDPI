#!/bin/sh


/bin/rm -f configure config.h config.h.in src/lib/Makefile.in
autoreconf -ivf
./configure
