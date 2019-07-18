bin_PROGRAMS=ndpiReader

ndpiReader_SOURCES=ndpiReader.c reader_util.c
ndpiReader_CFLAGS= $(JSON_C_CFLAGS) $(PCAP_CFLAGS) $(HYPERSCAN_CFLAGS) $(PTHREAD_CFLAGS) $(LIBM) $(DPDK_CFLAGS) $(AM_CFLAGS) 
ndpiReader_LDFLAGS= $(top_builddir)/src/lib/.libs/libndpi.a $(JSON_C_LIBS) $(PCAP_LIBS) $(HYPERSCAN_LIBS) $(LIBM) $(DPDK_LIBS) $(AM_LDFLAGS)
