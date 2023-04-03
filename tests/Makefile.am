TESTS = do.sh do-dga.sh

if BUILD_UNITTESTS
TESTS += do-unit.sh
endif

EXTRA_DIST = cfgs/*/pcap cfgs/*/result cfgs/*/*.txt performance \
	unit/unit.c unit/Makefile.in \
	dga/dga_evaluate.c dga/Makefile.in dga/README.md dga/test_dga.csv dga/test_non_dga.csv do-dga.sh \
	do-unit.sh do.sh.in ossfuzz.sh

all:
	@echo -n ""
