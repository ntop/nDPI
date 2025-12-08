ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src/lib

if PLUGINS_ENABLED
SUBDIRS += src/lib/plugins
endif

SUBDIRS += @EXTRA_TARGETS@

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
		doc/FAQ.rst \
		doc/configuration_parameters.rst \
		doc/library_initialization.rst \
		doc/monitoring.rst \
	python/DEV_GUIDE.md python/dev_requirements.txt python/ndpi_example.py python/ndpi/__init__.py \
		python/ndpi/ndpi_build.py python/ndpi/ndpi.py python/README.md \
		python/requirements.txt python/setup.py python/tests.py \
	lists/100_malware.list \
		lists/42_mining_domain.list \
		lists/101_ads_tracking.list \
		lists/107_gambling.list \
		lists/107_gambling_custom.list \
		lists/124_bots.list \
		lists/125_scanners.list \
		lists/protocols/266_salesforce.list \
		lists/protocols/42_mining_ip.list \
		lists/public_suffix_list.dat \
		lists/README.md \
		lists/protocols/README.md \
	sonar-project.properties .github .ci-ignore \
	src/lib/plugins/README.md

doc:
	make -C doc html

doc-view:
	python3 -m http.server --bind 127.0.0.1 --directory doc/_build/html 8080

coverage: all
	$(MKDIR_P) coverage_report/ndpi_coverage_report
	lcov --directory . --capture --output-file lcov.info
	genhtml -o coverage_report/ndpi_coverage_report lcov.info

clean-coverage:
	$(RM) lcov.info
	find . -type f -name "*.gcda" -exec rm "{}" +
	find . -type f -name "*.gcno" -exec rm "{}" +

distclean-local:
	$(RM) -r autom4te.cache
	$(RM) libtool config.status config.cache config.log
	$(RM) src/include/stamp-h1

pull:
	cd $(top_srcdir) && git pull --rebase
	if test -d $(top_srcdir)/../nDPI-custom; then echo "Pulling ../nDPI-custom"; cd $(top_srcdir)/../nDPI-custom && git pull --rebase; fi

changelog:
	cd $(top_srcdir) && git log --since={`curl -s https://github.com/ntop/ndpi/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" | grep  "^ " > CHANGELOG.latest

# For out-of-tree builds: copy required configuration files
# ndpiReader has some hard-coded paths in some unit tests: in the out-of-tree builds we need
# some configuration files in the expected path
# Avoid all of that if we are compiling only the library
all-local:
	@if test "$(srcdir)" != . && test -n "@EXTRA_TARGETS@" ; then \
	  echo "Setting up out-of-tree build configuration files..."; \
	  $(MKDIR_P) example lists tests/cfgs; \
	  $(INSTALL_DATA) $(srcdir)/example/*.txt example/; \
	  $(INSTALL_DATA) $(srcdir)/example/*.conf example/; \
	  $(INSTALL_DATA) $(srcdir)/example/*.csv example/; \
	  if test -d $(srcdir)/lists && test -n "$$(ls -A $(srcdir)/lists 2>/dev/null)"; then \
	    cp -R $(srcdir)/lists/* lists/; \
	  fi; \
	  for cfg_dir in $(srcdir)/tests/cfgs/*/ ; do \
	    cfg_name=$$(basename "$$cfg_dir"); \
	    $(MKDIR_P) tests/cfgs/$$cfg_name; \
	    if test -f "$$cfg_dir/config.txt" ; then \
	      cp "$$cfg_dir/config.txt" tests/cfgs/$$cfg_name/config.txt; \
	    fi; \
	  done; \
	fi

clean-local:
	@if test "$(srcdir)" != . && test -n "@EXTRA_TARGETS@" ; then \
	  echo "Cleaning out-of-tree build configuration files..."; \
	  -$(RM) example/*.txt; \
	  -$(RM) example/*.conf; \
	  -$(RM) example/*.csv; \
	  -$(RM) -r lists/*; \
	  -$(RM) tests/cfgs/*/config.txt; \
	fi

.PHONY: doc doc-view coverage clean-coverage changelog

# Prevent parallel execution of clean/distclean to avoid potential race conditions
.NOTPARALLEL: clean distclean
