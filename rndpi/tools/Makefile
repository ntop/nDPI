#
# rndpi - a C library for deep packet inspection on top of nDPI
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Recursively scan subdirectories to build all modules
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#
# Copyright (c) 2015 Rocco Carbone <rocco@tecsiel.it>
#

# The list of directories where to make something
SUBDIRS = live

# Fake targets
.PHONY: all clean distclean ${SUBDIRS}

# The main target is responsible to build all the modules
all:
	@for dir in ${SUBDIRS} ; do \
           if [ -d $$dir ] ; then \
             echo "Making sub-directory $$dir ..." ; \
             (cd $$dir && make -s) ; \
           else \
             echo "Warning: missing sub-directory $$dir" ; \
           fi \
         done

# Cleanup rules
clean distclean:
	@rm -f *~
	@for dir in ${SUBDIRS} ; do \
           if [ -d $$dir ] ; then \
             (cd $$dir && make -s $@) ; \
           fi \
         done
