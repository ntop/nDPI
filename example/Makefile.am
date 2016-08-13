bin_PROGRAMS = ndpiReader

AM_CPPFLAGS = -I$(top_srcdir)/src/include @PCAP_INC@
AM_CFLAGS = @PTHREAD_CFLAGS@

LDADD = $(top_builddir)/src/lib/libndpi.la @JSON_C_LIB@ @PTHREAD_LIBS@ @PCAP_LIB@
AM_LDFLAGS = -static

ndpiReader_SOURCES = ndpiReader.c ndpi_util.c ndpi_util.h

ndpiReader.o: ndpiReader.c

