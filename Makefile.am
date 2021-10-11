ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib @EXTRA_TARGETS@

if BUILD_FUZZTARGETS
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = README.md CHANGELOG.md CONTRIBUTING.md autogen.sh wireshark python windows utils packages example/MacOS doc/api.rst doc/conf.py doc/flow_risks.rst doc/guide/nDPI_QuickStartGuide.pages doc/guide/nDPI_QuickStartGuide.pdf doc/img/logo.png doc/index.rst doc/Makefile doc/what_is_ndpi.rst

changelog:
	git log --since={`curl -s https://github.com/ntop/ndpi/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" | grep  "^ " > CHANGELOG.latest
