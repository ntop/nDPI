ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src @EXTRA_TARGETS@

if BUILD_FUZZTARGETS
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = \
	README.md CHANGELOG.md CONTRIBUTING.md README.protocols \
	autogen.sh configure.seed \
	wireshark python windows utils packages example/MacOS example/Win32 \
	doc/nDPI_QuickStartGuide.pages doc/nDPI_QuickStartGuide.pdf

changelog:
	git log --since={`curl -s https://github.com/ntop/ndpi/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" | grep  "^ " > CHANGELOG.latest
