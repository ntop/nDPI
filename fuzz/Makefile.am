bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_quic_get_crypto_data fuzz_config
#Alghoritms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des
#Data structures
bin_PROGRAMS += fuzz_ds_patricia fuzz_ds_ahocorasick

fuzz_process_packet_SOURCES = fuzz_process_packet.c fuzz_common_code.c
fuzz_process_packet_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_process_packet_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_process_packet_LDFLAGS = $(LIBS)
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
fuzz_ndpi_reader_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_alloc_fail_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c
fuzz_ndpi_reader_alloc_fail_CFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ndpi_reader_alloc_fail_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_alloc_fail_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_alloc_fail_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_alloc_fail_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_alloc_fail_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_alloc_fail_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_quic_get_crypto_data_SOURCES = fuzz_quic_get_crypto_data.c fuzz_common_code.c
fuzz_quic_get_crypto_data_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_quic_get_crypto_data_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_quic_get_crypto_data_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_quic_get_crypto_data_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_quic_get_crypto_data_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_quic_get_crypto_data_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_quic_get_crypto_data_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_config_SOURCES = fuzz_config.cpp fuzz_common_code.c
fuzz_config_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_config_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_config_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_config_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_config_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_config_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_config_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_config_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_config_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_bins_SOURCES = fuzz_alg_bins.cpp fuzz_common_code.c
fuzz_alg_bins_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_bins_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_bins_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_bins_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_bins_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_bins_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_bins_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_bins_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_bins_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_hll_SOURCES = fuzz_alg_hll.cpp fuzz_common_code.c
fuzz_alg_hll_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_hll_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_hll_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_hll_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_hll_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_hll_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_hll_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_hll_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_hll_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_hw_rsi_outliers_da_SOURCES = fuzz_alg_hw_rsi_outliers_da.cpp fuzz_common_code.c
fuzz_alg_hw_rsi_outliers_da_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_hw_rsi_outliers_da_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_hw_rsi_outliers_da_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_hw_rsi_outliers_da_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_hw_rsi_outliers_da_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_hw_rsi_outliers_da_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_hw_rsi_outliers_da_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_hw_rsi_outliers_da_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_hw_rsi_outliers_da_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_jitter_SOURCES = fuzz_alg_jitter.cpp fuzz_common_code.c
fuzz_alg_jitter_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_jitter_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_jitter_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_jitter_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_jitter_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_jitter_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_jitter_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_jitter_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_jitter_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_ses_des_SOURCES = fuzz_alg_ses_des.cpp fuzz_common_code.c
fuzz_alg_ses_des_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_ses_des_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_alg_ses_des_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_ses_des_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_ses_des_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_ses_des_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_ses_des_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_ses_des_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_ses_des_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_patricia_SOURCES = fuzz_ds_patricia.cpp fuzz_common_code.c
fuzz_ds_patricia_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ds_patricia_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ds_patricia_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_patricia_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_patricia_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_patricia_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_patricia_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_patricia_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_patricia_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_ahocorasick_SOURCES = fuzz_ds_ahocorasick.cpp fuzz_common_code.c
fuzz_ds_ahocorasick_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ds_ahocorasick_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DENABLE_MEM_ALLOC_FAILURES
fuzz_ds_ahocorasick_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_ahocorasick_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_ahocorasick_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_ahocorasick_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_ahocorasick_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_ahocorasick_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_ahocorasick_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@


# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard ../tests/pcap/*.pcap*)

fuzz_ndpi_reader_seed_corpus.zip: $(testpcaps)
	zip -j fuzz_ndpi_reader_seed_corpus.zip $(testpcaps)

fuzz_ndpi_reader_alloc_fail_seed_corpus.zip: $(testpcaps)
	zip -j fuzz_ndpi_reader_alloc_fail_seed_corpus.zip $(testpcaps)

files_corpus_fuzz_quic_get_crypto_data :=  $(wildcard corpus/fuzz_quic_get_crypto_data/*)

fuzz_quic_get_crypto_data_seed_corpus.zip: $(files_corpus_fuzz_quic_get_crypto_data)
	zip -j fuzz_quic_get_crypto_data_seed_corpus.zip $(files_corpus_fuzz_quic_get_crypto_data)

files_corpus_fuzz_ds_patricia :=  $(wildcard corpus/fuzz_ds_patricia/*)

fuzz_ds_patricia_seed_corpus.zip: $(files_corpus_fuzz_ds_patricia)
	zip -j fuzz_ds_patricia_seed_corpus.zip $(files_corpus_fuzz_ds_patricia)

files_corpus_fuzz_ds_ahocorasick :=  $(wildcard corpus/fuzz_ds_ahocorasick/*)

fuzz_ds_ahocorasick_seed_corpus.zip: $(files_corpus_fuzz_ds_ahocorasick)
	zip -j fuzz_ds_ahocorasick_seed_corpus.zip $(files_corpus_fuzz_ds_ahocorasick)

files_corpus_fuzz_alg_ses_des :=  $(wildcard corpus/fuzz_alg_ses_des/*)

fuzz_alg_ses_des_seed_corpus.zip: $(files_corpus_fuzz_alg_ses_des)
	zip -j fuzz_alg_ses_des_seed_corpus.zip $(files_corpus_fuzz_alg_ses_des)

files_corpus_fuzz_alg_hw_rsi_outliers_da :=  $(wildcard corpus/fuzz_alg_hw_rsi_outliers_da/*)

fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip: $(files_corpus_fuzz_alg_hw_rsi_outliers_da)
	zip -j fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip $(files_corpus_fuzz_alg_hw_rsi_outliers_da)

files_corpus_fuzz_alg_bins :=  $(wildcard corpus/fuzz_alg_bins/*)

fuzz_alg_bins_seed_corpus.zip: $(files_corpus_fuzz_alg_bins)
	zip -j fuzz_alg_bins_seed_corpus.zip $(files_corpus_fuzz_alg_bins)

files_corpus_fuzz_alg_hll :=  $(wildcard corpus/fuzz_alg_hll/*)

fuzz_alg_hll_seed_corpus.zip: $(files_corpus_fuzz_alg_hll)
	zip -j fuzz_alg_hll_seed_corpus.zip $(files_corpus_fuzz_alg_hll)

files_corpus_fuzz_alg_jitter :=  $(wildcard corpus/fuzz_alg_jitter/*)

fuzz_alg_jitter_seed_corpus.zip: $(files_corpus_fuzz_alg_jitter)
	zip -j fuzz_alg_jitter_seed_corpus.zip $(files_corpus_fuzz_alg_jitter)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_ds_patricia_seed_corpus.zip fuzz_ds_ahocorasick_seed_corpus.zip fuzz_alg_ses_des_seed_corpus.zip fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip fuzz_alg_bins_seed_corpus.zip fuzz_alg_hll_seed_corpus.zip fuzz_alg_jitter_seed_corpus.zip

distdir:
	find . -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find . -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.h' \
		-o -name '*.cpp' \
		-o -path './corpus/fuzz_quic_get_crypto_data/*' \
		-o -path './corpus/fuzz_alg_ses_des/*' \
		-o -path './corpus/fuzz_alg_bins/*' \
		-o -path './corpus/fuzz_alg_hll/*' \
		-o -path './corpus/fuzz_alg_jitter/*' \
		-o -path './corpus/fuzz_alg_hw_rsi_outliers_da/*' \
		-o -path './corpus/fuzz_ds_ahocorasick/*' \
		-o -path './corpus/fuzz_ds_patricia/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus
