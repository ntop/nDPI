ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib @EXTRA_TARGETS@

if BUILD_FUZZTARGETS
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = README.md CHANGELOG.md CONTRIBUTING.md README.protocols autogen.sh configure.seed wireshark python windows utils packages doc/nDPI_QuickStartGuide.pages doc/nDPI_QuickStartGuide.pdf example/MacOS example/Win32
