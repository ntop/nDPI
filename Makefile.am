ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib example tests

if BUILD_FUZZTARGETS
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = autogen.sh
