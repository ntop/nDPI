bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_quic_get_crypto_data

fuzz_process_packet_SOURCES = fuzz_process_packet.c
fuzz_process_packet_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_process_packet_LDADD = ../src/lib/libndpi.a
fuzz_process_packet_LDFLAGS = $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_process_packet_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_process_packet_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_process_packet_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c ../example/reader_util.c
fuzz_ndpi_reader_CFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ndpi_reader_LDADD = ../src/lib/libndpi.a
fuzz_ndpi_reader_LDFLAGS = $(PCAP_LIB) $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_alloc_fail_SOURCES = fuzz_ndpi_reader.c ../example/reader_util.c
fuzz_ndpi_reader_alloc_fail_CFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ndpi_reader_alloc_fail_LDADD = ../src/lib/libndpi.a
fuzz_ndpi_reader_alloc_fail_LDFLAGS = $(PCAP_LIB) $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_alloc_fail_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_alloc_fail_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_alloc_fail_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_alloc_fail_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_quic_get_crypto_data_SOURCES = fuzz_quic_get_crypto_data.c
fuzz_quic_get_crypto_data_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_quic_get_crypto_data_LDADD = ../src/lib/libndpi.a
fuzz_quic_get_crypto_data_LDFLAGS = $(ADDITIONAL_LIBS) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_quic_get_crypto_data_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_quic_get_crypto_data_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_quic_get_crypto_data_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_quic_get_crypto_data_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard ../tests/pcap/*.pcap*)

fuzz_ndpi_reader_seed_corpus.zip: $(testpcaps)
	zip -r fuzz_ndpi_reader_seed_corpus.zip $(testpcaps)

fuzz_ndpi_reader_alloc_fail_seed_corpus.zip: $(testpcaps)
	zip -r fuzz_ndpi_reader_alloc_fail_seed_corpus.zip $(testpcaps)

files_corpus_fuzz_quic_get_crypto_data :=  $(wildcard corpus/fuzz_quic_get_crypto_data/*)

fuzz_quic_get_crypto_data_seed_corpus.zip: $(files_corpus_fuzz_quic_get_crypto_data)
	zip -r fuzz_quic_get_crypto_data_seed_corpus.zip $(files_corpus_fuzz_quic_get_crypto_data)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip

distdir:
	find . -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find . -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.bin' | xargs -I'{}' cp '{}' '$(distdir)/{}'

all: corpus
