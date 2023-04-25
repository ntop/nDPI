bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_ndpi_reader_payload_analyzer fuzz_quic_get_crypto_data fuzz_config fuzz_community_id fuzz_serialization fuzz_tls_certificate
#Alghoritms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des fuzz_alg_crc32_md5 fuzz_alg_bytestream
#Data structures
bin_PROGRAMS += fuzz_ds_patricia fuzz_ds_ahocorasick fuzz_ds_libcache fuzz_ds_tree fuzz_ds_ptree
#Third party
bin_PROGRAMS += fuzz_libinjection
#Internal crypto
bin_PROGRAMS += fuzz_gcrypt_light

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
fuzz_ndpi_reader_alloc_fail_CFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -DENABLE_MEM_ALLOC_FAILURES -DCRYPT_FORCE_NO_AESNI
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

fuzz_ndpi_reader_payload_analyzer_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c
fuzz_ndpi_reader_payload_analyzer_CFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -DENABLE_MEM_ALLOC_FAILURES -DENABLE_PAYLOAD_ANALYZER
fuzz_ndpi_reader_payload_analyzer_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_payload_analyzer_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_payload_analyzer_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_payload_analyzer_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_payload_analyzer_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_payload_analyzer_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

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
fuzz_config_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_config_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_community_id_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_community_id_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_serialization_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_serialization_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_alg_bins_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_bins_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_alg_hll_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_hll_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_alg_hw_rsi_outliers_da_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_hw_rsi_outliers_da_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_alg_jitter_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_jitter_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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

fuzz_alg_crc32_md5_SOURCES = fuzz_alg_crc32_md5.c
fuzz_alg_crc32_md5_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_crc32_md5_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_crc32_md5_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_crc32_md5_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_crc32_md5_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_crc32_md5_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_crc32_md5_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_bytestream_SOURCES = fuzz_alg_bytestream.c
fuzz_alg_bytestream_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_bytestream_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_bytestream_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_bytestream_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_bytestream_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_bytestream_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_bytestream_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_ses_des_SOURCES = fuzz_alg_ses_des.cpp fuzz_common_code.c
fuzz_alg_ses_des_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_ses_des_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_ds_patricia_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_patricia_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_ds_ahocorasick_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_ahocorasick_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_ds_libcache_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_libcache_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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
fuzz_ds_tree_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_tree_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
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

fuzz_ds_ptree_SOURCES = fuzz_ds_ptree.cpp fuzz_common_code.c
fuzz_ds_ptree_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_ptree_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_ptree_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_ptree_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_ptree_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_ptree_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_ptree_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_ptree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_ptree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_libinjection_SOURCES = fuzz_libinjection.c
fuzz_libinjection_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_libinjection_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_libinjection_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_libinjection_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_libinjection_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_libinjection_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_libinjection_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_tls_certificate_SOURCES = fuzz_tls_certificate.c fuzz_common_code.c
fuzz_tls_certificate_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_tls_certificate_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_tls_certificate_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_tls_certificate_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_tls_certificate_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_tls_certificate_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_tls_certificate_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_light_SOURCES = fuzz_gcrypt_light.cpp fuzz_common_code.c
fuzz_gcrypt_light_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_light_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_light_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_gcrypt_light_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_gcrypt_light_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_light_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_light_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_gcrypt_light_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_light_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard ../tests/cfgs/default/pcap/*.pcap*)

fuzz_ndpi_reader_seed_corpus.zip: $(testpcaps)
	zip -j fuzz_ndpi_reader_seed_corpus.zip $(testpcaps)

fuzz_ndpi_reader_alloc_fail_seed_corpus.zip: $(testpcaps)
	zip -j fuzz_ndpi_reader_alloc_fail_seed_corpus.zip $(testpcaps)

fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip: $(testpcaps)
	zip -j fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip $(testpcaps)

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

files_corpus_fuzz_alg_crc32_md5 :=  $(wildcard corpus/fuzz_alg_crc32_md5/*)

fuzz_alg_crc32_md5_seed_corpus.zip: $(files_corpus_fuzz_alg_crc32_md5)
	zip -j fuzz_alg_crc32_md5_seed_corpus.zip $(files_corpus_fuzz_alg_crc32_md5)

files_corpus_fuzz_ds_libcache :=  $(wildcard corpus/fuzz_ds_libcache/*)

fuzz_ds_libcache_seed_corpus.zip: $(files_corpus_fuzz_ds_libcache)
	zip -j fuzz_ds_libcache_seed_corpus.zip $(files_corpus_fuzz_ds_libcache)

files_corpus_fuzz_ds_tree :=  $(wildcard corpus/fuzz_ds_tree/*)

fuzz_ds_tree_seed_corpus.zip: $(files_corpus_fuzz_ds_tree)
	zip -j fuzz_ds_tree_seed_corpus.zip $(files_corpus_fuzz_ds_tree)

files_corpus_fuzz_ds_ptree :=  $(wildcard corpus/fuzz_ds_ptree/*)

fuzz_ds_ptree_seed_corpus.zip: $(files_corpus_fuzz_ds_ptree)
	zip -j fuzz_ds_ptree_seed_corpus.zip $(files_corpus_fuzz_ds_ptree)

files_corpus_fuzz_alg_bytestream :=  $(wildcard corpus/fuzz_alg_bytestream/*)

fuzz_alg_bytestream_seed_corpus.zip: $(files_corpus_fuzz_alg_bytestream)
	zip -j fuzz_alg_bytestream_seed_corpus.zip $(files_corpus_fuzz_alg_bytestream)

files_corpus_fuzz_libinjection :=  $(wildcard corpus/fuzz_libinjection/*)

fuzz_libinjection_seed_corpus.zip: $(files_corpus_fuzz_libinjection)
	zip -j fuzz_libinjection_seed_corpus.zip $(files_corpus_fuzz_libinjection)

files_corpus_fuzz_tls_certificate :=  $(wildcard corpus/fuzz_tls_certificate/*)

fuzz_tls_certificate_seed_corpus.zip: $(files_corpus_fuzz_tls_certificate)
	zip -j fuzz_tls_certificate_seed_corpus.zip $(files_corpus_fuzz_tls_certificate)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_config_seed_corpus.zip fuzz_ds_patricia_seed_corpus.zip fuzz_ds_ahocorasick_seed_corpus.zip fuzz_alg_ses_des_seed_corpus.zip fuzz_alg_hw_rsi_outliers_da_seed_corpus.zip fuzz_alg_bins_seed_corpus.zip fuzz_alg_hll_seed_corpus.zip fuzz_alg_jitter_seed_corpus.zip fuzz_ds_libcache_seed_corpus.zip fuzz_community_id_seed_corpus.zip fuzz_ds_tree_seed_corpus.zip fuzz_serialization_seed_corpus.zip fuzz_ds_ptree_seed_corpus.zip fuzz_alg_crc32_md5_seed_corpus.zip fuzz_alg_bytestream_seed_corpus.zip fuzz_libinjection_seed_corpus.zip fuzz_tls_certificate_seed_corpus.zip

#Create dictionaries exactly as expected by oss-fuzz.
#This way, if we need to change/update/add something,
#we don't need to update scripts in oss-fuzz repository
dictionaries:
	cp dictionary.dict fuzz_ndpi_reader.dict
	cp dictionary.dict fuzz_ndpi_reader_alloc_fail.dict
	cp dictionary.dict fuzz_ndpi_reader_payload_analyzer.dict
	cp dictionary.dict fuzz_process_packet.dict
	cp dictionary_tls_certificate.dict fuzz_tls_certificate.dict

distdir:
	find . -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find . -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.h' \
		-o -name '*.cpp' \
		-o -name '*.dict' \
		-o -name 'ipv4_addresses.txt' \
		-o -path './corpus/fuzz_quic_get_crypto_data/*' \
		-o -path './corpus/fuzz_config/*' \
		-o -path './corpus/fuzz_serialization/*' \
		-o -path './corpus/fuzz_community_id/*' \
		-o -path './corpus/fuzz_libinjection/*' \
		-o -path './corpus/fuzz_tls_certificate/*' \
		-o -path './corpus/fuzz_alg_ses_des/*' \
		-o -path './corpus/fuzz_alg_bins/*' \
		-o -path './corpus/fuzz_alg_hll/*' \
		-o -path './corpus/fuzz_alg_jitter/*' \
		-o -path './corpus/fuzz_alg_crc32_md5/*' \
		-o -path './corpus/fuzz_alg_hw_rsi_outliers_da/*' \
		-o -path './corpus/fuzz_alg_bytestream/*' \
		-o -path './corpus/fuzz_ds_ahocorasick/*' \
		-o -path './corpus/fuzz_ds_libcache/*' \
		-o -path './corpus/fuzz_ds_tree/*' \
		-o -path './corpus/fuzz_ds_ptree/*' \
		-o -path './corpus/fuzz_ds_patricia/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus dictionaries
