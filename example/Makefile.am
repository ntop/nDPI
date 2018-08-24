bin_PROGRAMS = ndpiReader

AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/src/lib/third_party/include @PCAP_INC@ @HS_INC@

ndpiReader_SOURCES = ndpiReader.c ndpi_util.c ndpi_util.h uthash.h
ndpiReader_CFLAGS = @PTHREAD_CFLAGS@ # --coverage
ndpiReader_LDFLAGS = -static
ndpiReader_LDADD = $(top_builddir)/src/lib/libndpi.la @JSON_C_LIB@ @PTHREAD_LIBS@ @PCAP_LIB@ @DL_LIB@ @HS_LIB@ -lm
