ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src/lib @EXTRA_TARGETS@

if BUILD_FUZZTARGETS
SUBDIRS += fuzz
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libndpi.pc

EXTRA_DIST = README.md README.fuzzer.md CHANGELOG.md CONTRIBUTING.md \
	autogen.sh wireshark windows utils packages dga \
	influxdb/Makefile.in influxdb/metric_anomaly.c influxdb/README.txt \
	rrdtool/Makefile.in rrdtool/README.txt rrdtool/rrd_anomaly.c rrdtool/rrd_similarity.c \
	doc/requirements.txt doc/conf.py doc/flow_risks.rst doc/protocols.rst doc/guide/nDPI_QuickStartGuide.pages \
		doc/guide/nDPI_QuickStartGuide.pdf doc/img/logo.png doc/index.rst \
		doc/Makefile doc/what_is_ndpi.rst \
		doc/FAQ.md doc/include_FAQ.rst \
		doc/configuration_parameters.md doc/include_configuration_parameters.rst \
		doc/library_initialization.md doc/include_library_initialization.rst \
		doc/monitoring.md doc/include_monitoring.rst \
		doc/_static/custom.css \
	python/DEV_GUIDE.md python/dev_requirements.txt python/ndpi_example.py python/ndpi/__init__.py \
		python/ndpi/ndpi_build.py python/ndpi/ndpi.py python/README.md \
		python/requirements.txt python/setup.py python/tests.py \
	lists/100_malware.list \
		lists/107_gambling.list \
		lists/107_gambling_custom.list \
		lists/public_suffix_list.dat \
		lists/README.md \
	sonar-project.properties .github .ci-ignore

doc:
	make -C doc html

doc-view:
	python3 -m http.server --bind 127.0.0.1 --directory doc/_build/html 8080

coverage: all
	mkdir -vp coverage_report/ndpi_coverage_report
	lcov --directory . --capture --output-file lcov.info
	genhtml -o coverage_report/ndpi_coverage_report lcov.info

clean-coverage:
	rm -f lcov.info
	find . -type f -name "*.gcda" -exec rm "{}" +
	find . -type f -name "*.gcno" -exec rm "{}" +

pull:
	git pull --rebase
	if test -d ../nDPI-custom; then echo "Pulling ../nDPI-custom"; cd ../nDPI-custom; git pull --rebase; cd ../nDPI; fi

changelog:
	git log --since={`curl -s https://github.com/ntop/ndpi/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" | grep  "^ " > CHANGELOG.latest

.PHONY: doc doc-view coverage clean-coverage changelog
