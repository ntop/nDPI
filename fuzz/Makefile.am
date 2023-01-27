bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_quic_get_crypto_data fuzz_config fuzz_community_id fuzz_serialization
#Alghoritms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des
#Data structures
bin_PROGRAMS += fuzz_ds_patricia fuzz_ds_ahocorasick fuzz_ds_libcache fuzz_ds_tree

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
fuzz_config_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_config_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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

fuzz_community_id_SOURCES = fuzz_community_id.cpp fuzz_common_code.c
fuzz_community_id_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_community_id_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_community_id_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_community_id_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_community_id_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_community_id_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_community_id_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_community_id_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_community_id_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_serialization_SOURCES = fuzz_serialization.cpp fuzz_common_code.c
fuzz_serialization_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_serialization_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_serialization_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_serialization_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_serialization_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_serialization_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_serialization_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_serialization_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_serialization_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_bins_SOURCES = fuzz_alg_bins.cpp fuzz_common_code.c
fuzz_alg_bins_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_alg_bins_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_alg_hll_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_alg_hll_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_alg_hw_rsi_outliers_da_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_alg_hw_rsi_outliers_da_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_alg_jitter_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_alg_jitter_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_alg_ses_des_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_alg_ses_des_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_ds_patricia_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_patricia_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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
fuzz_ds_ahocorasick_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_ahocorasick_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
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

fuzz_ds_libcache_SOURCES = fuzz_ds_libcache.cpp fuzz_common_code.c
fuzz_ds_libcache_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_libcache_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_libcache_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_libcache_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_libcache_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_libcache_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_libcache_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_libcache_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_libcache_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_tree_SOURCES = fuzz_ds_tree.cpp fuzz_common_code.c
fuzz_ds_tree_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_tree_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
fuzz_ds_tree_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_tree_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_tree_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_tree_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_tree_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_tree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_tree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@


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

files_corpus_fuzz_config :=  $(wildcard corpus/fuzz_config/*)

fuzz_config_seed_corpus.zip: $(files_corpus_fuzz_config)
	zip -j fuzz_config_seed_corpus.zip $(files_corpus_fuzz_config)

files_corpus_fuzz_serialization :=  $(wildcard corpus/fuzz_serialization/*)

fuzz_serialization_seed_corpus.zip: $(files_corpus_fuzz_serialization)
	zip -j fuzz_serialization_seed_corpus.zip $(files_corpus_fuzz_serialization)

files_corpus_fuzz_community_id :=  $(wildcard corpus/fuzz_community_id/*)

fuzz_community_id_seed_corpus.zip: $(files_corpus_fuzz_community_id)
	zip -j fuzz_community_id_seed_corpus.zip $(files_corpus_fuzz_community_id)

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

files_corpus_fuzz_ds_libcache :=  $(wildcard corpus/fuzz_ds_libcache/*)

fuzz_ds_libcache_seed_corpus.zip: $(files_corpus_fuzz_ds_libcache)
	zip -j fuzz_ds_libcache_seed_corpus.zip $(files_corpus_fuzz_ds_libcache)

files_corpus_fuzz_ds_tree :=  $(wildcard corpus/fuzz_ds_tree/*)

fuzz_ds_tree_seed_corpus.zip: $(files_corpus_fuzz_ds_tree)
	zip -j fuzz_ds_tree_seed_corpus.zip $(files_corpus_fuzz_ds_tree)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_config_seed_corpus.zip fuzz_ds_patricia_seed_corpus.zip fuzz_ds_ahocorasick_seed_corpus.zip fuzz_alg_ses_des_seed_corpus.zip fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip fuzz_alg_bins_seed_corpus.zip fuzz_alg_hll_seed_corpus.zip fuzz_alg_jitter_seed_corpus.zip fuzz_ds_libcache_seed_corpus.zip fuzz_community_id_seed_corpus.zip fuzz_ds_tree_seed_corpus.zip fuzz_serialization_seed_corpus.zip

#Create dictionaries exactly as expected by oss-fuzz.
#This way, if we need to change/update/add something,
#we don't need to update scripts in oss-fuzz repository
dictionaries:
	cp dictionary.dict fuzz_ndpi_reader.dict
	cp dictionary.dict fuzz_ndpi_reader_alloc_fail.dict
	cp dictionary.dict fuzz_process_packet.dict

distdir:
	find . -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find . -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.h' \
		-o -name '*.cpp' \
		-o -name '*.dict' \
		-o -path './corpus/fuzz_quic_get_crypto_data/*' \
		-o -path './corpus/fuzz_config/*' \
		-o -path './corpus/fuzz_serialization/*' \
		-o -path './corpus/fuzz_community_id/*' \
		-o -path './corpus/fuzz_alg_ses_des/*' \
		-o -path './corpus/fuzz_alg_bins/*' \
		-o -path './corpus/fuzz_alg_hll/*' \
		-o -path './corpus/fuzz_alg_jitter/*' \
		-o -path './corpus/fuzz_alg_hw_rsi_outliers_da/*' \
		-o -path './corpus/fuzz_ds_ahocorasick/*' \
		-o -path './corpus/fuzz_ds_libcache/*' \
		-o -path './corpus/fuzz_ds_tree/*' \
		-o -path './corpus/fuzz_ds_patricia/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus dictionaries
