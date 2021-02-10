bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_with_main

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_CFLAGS =
fuzz_process_packet_LDADD = ../src/lib/libndpi.a
fuzz_process_packet_LDFLAGS = $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_process_packet_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_process_packet_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_process_packet_LDFLAGS) $(LDFLAGS) -o $@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_CFLAGS = -I../example/
fuzz_ndpi_reader_LDADD = ../example/libndpiReader.a ../src/lib/libndpi.a
fuzz_ndpi_reader_LDFLAGS = $(PCAP_LIB) $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_LDFLAGS) $(LDFLAGS) -o $@

fuzz_ndpi_reader_with_main_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_with_main_CFLAGS = -I../example/ -DBUILD_MAIN
fuzz_ndpi_reader_with_main_LDADD = ../src/lib/libndpi.a
fuzz_ndpi_reader_with_main_LDFLAGS = ../example/libndpiReader.a $(PCAP_LIB) $(ADDITIONAL_LIBS) $(LIBS)
# force usage of CXX for linker
fuzz_ndpi_reader_with_main_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_with_main_LDFLAGS) $(LDFLAGS) -o $@

# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard ../tests/pcap/*.pcap)

fuzz_ndpi_reader_seed_corpus.zip: $(testpcaps)
	zip -r fuzz_ndpi_reader_seed_corpus.zip $(testpcaps)
