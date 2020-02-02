bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_LDFLAGS = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
if HAS_FUZZLDFLAGS
    fuzz_process_packet_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_process_packet_SOURCES += onefile.c
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_process_packet_LDFLAGS) $(LDFLAGS) -o $@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c
fuzz_ndpi_reader_CFLAGS = -I../example/
fuzz_ndpi_reader_LDFLAGS = ../example/libndpiReader.a ../src/lib/libndpi.a $(PCAP_LIB) $(ADDITIONAL_LIBS)
if HAS_FUZZLDFLAGS
    fuzz_ndpi_reader_LDFLAGS += $(LIB_FUZZING_ENGINE)
else
    fuzz_ndpi_reader_SOURCES += onefile.c
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_LDFLAGS) $(LDFLAGS) -o $@

EXTRA_fuzz_ndpi_reader_DEPENDENCIES = fuzz_ndpi_reader_seed_corpus.zip

testpcaps := $(wildcard ../tests/pcap/*.pcap)

fuzz_ndpi_reader_seed_corpus.zip: $(testpcaps)
	zip -r fuzz_ndpi_reader_seed_corpus.zip $(testpcaps)
