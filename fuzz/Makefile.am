bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_ndpi_reader_payload_analyzer fuzz_quic_get_crypto_data fuzz_config fuzz_community_id fuzz_serialization fuzz_tls_certificate fuzz_dga fuzz_is_stun_udp fuzz_is_stun_tcp
#Alghoritms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des fuzz_alg_crc32_md5 fuzz_alg_bytestream fuzz_alg_shoco fuzz_alg_memmem fuzz_alg_strnstr fuzz_alg_quick_encryption
#Data structures
bin_PROGRAMS += fuzz_ds_patricia fuzz_ds_ahocorasick fuzz_ds_libcache fuzz_ds_tree fuzz_ds_ptree fuzz_ds_hash fuzz_ds_cmsketch fuzz_ds_bitmap64_fuse fuzz_ds_domain_classify fuzz_ds_kdtree fuzz_ds_btree
#Third party
bin_PROGRAMS += fuzz_libinjection fuzz_binaryfusefilter
#Internal crypto
bin_PROGRAMS += fuzz_gcrypt_light fuzz_gcrypt_aes fuzz_gcrypt_gcm fuzz_gcrypt_cipher
#Configuration files
bin_PROGRAMS += fuzz_filecfg_protocols fuzz_filecfg_categories fuzz_filecfg_malicious_sha1 fuzz_filecfg_malicious_ja4 fuzz_filecfg_risk_domains fuzz_filecfg_config fuzz_filecfg_category
#Reader utils
bin_PROGRAMS += fuzz_readerutils_workflow fuzz_readerutils_parseprotolist
#Mutators
bin_PROGRAMS += fuzz_ndpi_reader_pl7m fuzz_ndpi_reader_pl7m_64k fuzz_ndpi_reader_pl7m_simplest fuzz_ndpi_reader_pl7m_internal fuzz_ndpi_reader_pl7m_simplest_internal

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

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c
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
fuzz_quic_get_crypto_data_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
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
fuzz_config_CXXFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_config_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
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
fuzz_alg_crc32_md5_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
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

fuzz_alg_shoco_SOURCES = fuzz_alg_shoco.cpp
fuzz_alg_shoco_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_alg_shoco_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_shoco_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_shoco_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_shoco_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_shoco_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_shoco_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_memmem_SOURCES = fuzz_alg_memmem.cpp
fuzz_alg_memmem_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_memmem_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_memmem_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_memmem_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_memmem_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_memmem_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_memmem_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_strnstr_SOURCES = fuzz_alg_strnstr.cpp
fuzz_alg_strnstr_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_strnstr_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_strnstr_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_strnstr_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_strnstr_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_strnstr_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_strnstr_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_quick_encryption_SOURCES = fuzz_alg_quick_encryption.cpp fuzz_common_code.c
fuzz_alg_quick_encryption_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_quick_encryption_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_alg_quick_encryption_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_alg_quick_encryption_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_alg_quick_encryption_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_quick_encryption_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_alg_quick_encryption_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_alg_quick_encryption_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_quick_encryption_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

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

fuzz_ds_hash_SOURCES = fuzz_ds_hash.cpp fuzz_common_code.c
fuzz_ds_hash_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_hash_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_hash_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_hash_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_hash_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_hash_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_hash_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_hash_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_hash_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_cmsketch_SOURCES = fuzz_ds_cmsketch.cpp fuzz_common_code.c
fuzz_ds_cmsketch_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_cmsketch_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_cmsketch_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_cmsketch_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_cmsketch_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_cmsketch_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_cmsketch_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_cmsketch_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_cmsketch_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_bitmap64_fuse_SOURCES = fuzz_ds_bitmap64_fuse.cpp fuzz_common_code.c
fuzz_ds_bitmap64_fuse_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_bitmap64_fuse_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_ds_bitmap64_fuse_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_bitmap64_fuse_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_bitmap64_fuse_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_bitmap64_fuse_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_bitmap64_fuse_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_bitmap64_fuse_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_bitmap64_fuse_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_domain_classify_SOURCES = fuzz_ds_domain_classify.cpp fuzz_common_code.c
fuzz_ds_domain_classify_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_domain_classify_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_domain_classify_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_domain_classify_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_domain_classify_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_domain_classify_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_domain_classify_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_domain_classify_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_domain_classify_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_kdtree_SOURCES = fuzz_ds_kdtree.cpp fuzz_common_code.c
fuzz_ds_kdtree_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_kdtree_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_kdtree_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_kdtree_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_kdtree_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_kdtree_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_kdtree_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_kdtree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_kdtree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_btree_SOURCES = fuzz_ds_btree.cpp fuzz_common_code.c
fuzz_ds_btree_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_btree_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_btree_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ds_btree_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ds_btree_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_btree_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ds_btree_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ds_btree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_btree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

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

fuzz_binaryfusefilter_SOURCES = fuzz_binaryfusefilter.cpp fuzz_common_code.c
fuzz_binaryfusefilter_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_binaryfusefilter_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_binaryfusefilter_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_binaryfusefilter_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_binaryfusefilter_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_binaryfusefilter_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_binaryfusefilter_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_binaryfusefilter_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_binaryfusefilter_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_tls_certificate_SOURCES = fuzz_tls_certificate.c fuzz_common_code.c
fuzz_tls_certificate_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
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

fuzz_dga_SOURCES = fuzz_dga.c fuzz_common_code.c
fuzz_dga_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_dga_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_dga_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_dga_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_dga_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_dga_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_dga_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_is_stun_udp_SOURCES = fuzz_is_stun.c fuzz_common_code.c
fuzz_is_stun_udp_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_is_stun_udp_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_is_stun_udp_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_is_stun_udp_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_is_stun_udp_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_is_stun_udp_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_is_stun_udp_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_is_stun_tcp_SOURCES = fuzz_is_stun.c fuzz_common_code.c
fuzz_is_stun_tcp_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION -DSTUN_TCP
fuzz_is_stun_tcp_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_is_stun_tcp_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_is_stun_tcp_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_is_stun_tcp_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_is_stun_tcp_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_is_stun_tcp_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

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

fuzz_gcrypt_aes_SOURCES = fuzz_gcrypt_aes.cpp
fuzz_gcrypt_aes_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_aes_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_aes_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_gcrypt_aes_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_gcrypt_aes_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_aes_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_aes_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_gcrypt_aes_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_aes_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_gcm_SOURCES = fuzz_gcrypt_gcm.cpp
fuzz_gcrypt_gcm_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_gcm_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_gcm_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_gcrypt_gcm_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_gcrypt_gcm_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_gcm_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_gcm_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_gcrypt_gcm_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_gcm_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_cipher_SOURCES = fuzz_gcrypt_cipher.cpp
fuzz_gcrypt_cipher_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_cipher_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS) -I ../src/lib/third_party/include/
fuzz_gcrypt_cipher_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_gcrypt_cipher_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_gcrypt_cipher_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_cipher_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_gcrypt_cipher_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_gcrypt_cipher_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_cipher_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_protocols_SOURCES = fuzz_filecfg_protocols.c fuzz_common_code.c
fuzz_filecfg_protocols_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_protocols_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_protocols_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_protocols_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_protocols_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_protocols_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_protocols_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_categories_SOURCES = fuzz_filecfg_categories.c fuzz_common_code.c
fuzz_filecfg_categories_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_categories_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_categories_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_categories_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_categories_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_categories_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_categories_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_malicious_sha1_SOURCES = fuzz_filecfg_malicious_sha1.c fuzz_common_code.c
fuzz_filecfg_malicious_sha1_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_malicious_sha1_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_malicious_sha1_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_malicious_sha1_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_malicious_sha1_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_malicious_sha1_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_malicious_sha1_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_malicious_ja4_SOURCES = fuzz_filecfg_malicious_ja4.c fuzz_common_code.c
fuzz_filecfg_malicious_ja4_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_malicious_ja4_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_malicious_ja4_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_malicious_ja4_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_malicious_ja4_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_malicious_ja4_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_malicious_ja4_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_risk_domains_SOURCES = fuzz_filecfg_risk_domains.c fuzz_common_code.c
fuzz_filecfg_risk_domains_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_risk_domains_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_risk_domains_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_risk_domains_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_risk_domains_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_risk_domains_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_risk_domains_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_config_SOURCES = fuzz_filecfg_config.c fuzz_common_code.c
fuzz_filecfg_config_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_config_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_config_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_config_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_config_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_config_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_config_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_category_SOURCES = fuzz_filecfg_category.c fuzz_common_code.c
fuzz_filecfg_category_CFLAGS = -I../src/lib/ @NDPI_CFLAGS@ $(CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_category_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_filecfg_category_LDFLAGS = $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_filecfg_category_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_filecfg_category_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_filecfg_category_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_category_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_readerutils_workflow_SOURCES = fuzz_readerutils_workflow.cpp fuzz_common_code.c ../example/reader_util.c
fuzz_readerutils_workflow_CXXFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_readerutils_workflow_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_readerutils_workflow_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_readerutils_workflow_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_readerutils_workflow_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_readerutils_workflow_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_readerutils_workflow_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_readerutils_workflow_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_readerutils_workflow_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_readerutils_parseprotolist_SOURCES = fuzz_readerutils_parseprotolist.cpp fuzz_common_code.c ../example/reader_util.c
fuzz_readerutils_parseprotolist_CXXFLAGS = -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_readerutils_parseprotolist_CFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
fuzz_readerutils_parseprotolist_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_readerutils_parseprotolist_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_readerutils_parseprotolist_CXXFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_readerutils_parseprotolist_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_readerutils_parseprotolist_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_readerutils_parseprotolist_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_readerutils_parseprotolist_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_simplest_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_CFLAGS =  -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -I../src/lib/third_party/include/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR
fuzz_ndpi_reader_pl7m_simplest_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_pl7m_simplest_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_pl7m_simplest_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_pl7m_simplest_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_simplest_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_simplest_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_simplest_internal_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_internal_CFLAGS =  -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -I../src/lib/third_party/include/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
fuzz_ndpi_reader_pl7m_simplest_internal_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_pl7m_simplest_internal_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_pl7m_simplest_internal_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_pl7m_simplest_internal_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_simplest_internal_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_simplest_internal_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_CFLAGS =  -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -I../src/lib/third_party/include/ -DENABLE_PCAP_L7_MUTATOR
fuzz_ndpi_reader_pl7m_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_pl7m_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_pl7m_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_pl7m_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_64k_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_64k_CFLAGS =  -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -I../src/lib/third_party/include/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_64K_PACKETS
fuzz_ndpi_reader_pl7m_64k_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_pl7m_64k_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_pl7m_64k_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_pl7m_64k_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_64k_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_64k_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_internal_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_internal_CFLAGS =  -I../example/ @NDPI_CFLAGS@ $(CXXFLAGS) -I../src/lib/third_party/include/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
fuzz_ndpi_reader_pl7m_internal_LDADD = ../src/lib/libndpi.a $(ADDITIONAL_LIBS)
fuzz_ndpi_reader_pl7m_internal_LDFLAGS = $(PCAP_LIB) $(LIBS)
if HAS_FUZZLDFLAGS
fuzz_ndpi_reader_pl7m_internal_CFLAGS += $(LIB_FUZZING_ENGINE)
fuzz_ndpi_reader_pl7m_internal_LDFLAGS += $(LIB_FUZZING_ENGINE)
endif
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_internal_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_internal_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@


# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard ../tests/cfgs/default/pcap/*.pcap*)

testpcaps.zip: $(testpcaps)
	zip -j testpcaps.zip $(testpcaps)

fuzz_ndpi_reader_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_seed_corpus.zip

fuzz_ndpi_reader_alloc_fail_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip

fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip

fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip

fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip

fuzz_ndpi_reader_pl7m_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_seed_corpus.zip

fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip

fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip

files_corpus_fuzz_quic_get_crypto_data :=  $(wildcard corpus/fuzz_quic_get_crypto_data/*)
fuzz_quic_get_crypto_data_seed_corpus.zip: $(files_corpus_fuzz_quic_get_crypto_data)
	zip -j fuzz_quic_get_crypto_data_seed_corpus.zip $(files_corpus_fuzz_quic_get_crypto_data)

files_corpus_fuzz_serialization :=  $(wildcard corpus/fuzz_serialization/*)
fuzz_serialization_seed_corpus.zip: $(files_corpus_fuzz_serialization)
	zip -j fuzz_serialization_seed_corpus.zip $(files_corpus_fuzz_serialization)

files_corpus_fuzz_community_id :=  $(wildcard corpus/fuzz_community_id/*)
fuzz_community_id_seed_corpus.zip: $(files_corpus_fuzz_community_id)
	zip -j fuzz_community_id_seed_corpus.zip $(files_corpus_fuzz_community_id)

files_corpus_fuzz_is_stun_udp :=  $(wildcard corpus/fuzz_is_stun_udp/*)
fuzz_is_stun_udp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_udp)
	zip -j fuzz_is_stun_udp_seed_corpus.zip $(files_corpus_fuzz_is_stun_udp)

files_corpus_fuzz_is_stun_tcp :=  $(wildcard corpus/fuzz_is_stun_tcp/*)
fuzz_is_stun_tcp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_tcp)
	zip -j fuzz_is_stun_tcp_seed_corpus.zip $(files_corpus_fuzz_is_stun_tcp)

files_corpus_fuzz_alg_ses_des :=  $(wildcard corpus/fuzz_alg_ses_des/*)
fuzz_alg_ses_des_seed_corpus.zip: $(files_corpus_fuzz_alg_ses_des)
	zip -j fuzz_alg_ses_des_seed_corpus.zip $(files_corpus_fuzz_alg_ses_des)

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

files_corpus_fuzz_filecfg_protocols :=  $(wildcard corpus/fuzz_filecfg_protocols/*)
fuzz_filecfg_protocols_seed_corpus.zip: $(files_corpus_fuzz_filecfg_protocols)
	zip -j fuzz_filecfg_protocols_seed_corpus.zip $(files_corpus_fuzz_filecfg_protocols)

files_corpus_fuzz_filecfg_categories :=  $(wildcard corpus/fuzz_filecfg_categories/*)
fuzz_filecfg_categories_seed_corpus.zip: $(files_corpus_fuzz_filecfg_categories)
	zip -j fuzz_filecfg_categories_seed_corpus.zip $(files_corpus_fuzz_filecfg_categories)

files_corpus_fuzz_filecfg_malicious_sha1 :=  $(wildcard corpus/fuzz_filecfg_malicious_sha1/*)
fuzz_filecfg_malicious_sha1_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_sha1)
	zip -j fuzz_filecfg_malicious_sha1_seed_corpus.zip $(files_corpus_fuzz_filecfg_malicious_sha1)

files_corpus_fuzz_filecfg_malicious_ja4 :=  $(wildcard corpus/fuzz_filecfg_malicious_ja4/*)
fuzz_filecfg_malicious_ja4_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_ja4)
	zip -j fuzz_filecfg_malicious_ja4_seed_corpus.zip $(files_corpus_fuzz_filecfg_malicious_ja4)

files_corpus_fuzz_filecfg_risk_domains :=  $(wildcard corpus/fuzz_filecfg_risk_domains/*)
fuzz_filecfg_risk_domains_seed_corpus.zip: $(files_corpus_fuzz_filecfg_risk_domains)
	zip -j fuzz_filecfg_risk_domains_seed_corpus.zip $(files_corpus_fuzz_filecfg_risk_domains)

files_corpus_fuzz_filecfg_config :=  $(wildcard corpus/fuzz_filecfg_config/*)
fuzz_filecfg_config_seed_corpus.zip: $(files_corpus_fuzz_filecfg_config)
	zip -j fuzz_filecfg_config_seed_corpus.zip $(files_corpus_fuzz_filecfg_config)

files_corpus_fuzz_filecfg_category :=  $(wildcard corpus/fuzz_filecfg_category/*)
fuzz_filecfg_category_seed_corpus.zip: $(files_corpus_fuzz_filecfg_category)
	zip -j fuzz_filecfg_category_seed_corpus.zip $(files_corpus_fuzz_filecfg_category)

files_corpus_fuzz_readerutils_workflow :=  $(wildcard corpus/fuzz_readerutils_workflow/*)
fuzz_readerutils_workflow_seed_corpus.zip: $(files_corpus_fuzz_readerutils_workflow)
	zip -j fuzz_readerutils_workflow_seed_corpus.zip $(files_corpus_fuzz_readerutils_workflow)

files_corpus_fuzz_readerutils_parseprotolist :=  $(wildcard corpus/fuzz_readerutils_parseprotolist/*)
fuzz_readerutils_parseprotolist_seed_corpus.zip: $(files_corpus_fuzz_readerutils_parseprotolist)
	zip -j fuzz_readerutils_parseprotolist_seed_corpus.zip $(files_corpus_fuzz_readerutils_parseprotolist)

files_corpus_fuzz_ds_bitmap64_fuse :=  $(wildcard corpus/fuzz_ds_bitmap64_fuse/*)
fuzz_ds_bitmap64_fuse_seed_corpus.zip: $(files_corpus_fuzz_ds_bitmap64_fuse)
	zip -j fuzz_ds_bitmap64_fuse_seed_corpus.zip $(files_corpus_fuzz_ds_bitmap64_fuse)

files_corpus_fuzz_ds_domain_classify :=  $(wildcard corpus/fuzz_ds_domain_classify/*)
fuzz_ds_domain_classify_seed_corpus.zip: $(files_corpus_fuzz_ds_domain_classify)
	zip -j fuzz_ds_domain_classify_seed_corpus.zip $(files_corpus_fuzz_ds_domain_classify)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_alg_ses_des_seed_corpus.zip fuzz_alg_bins_seed_corpus.zip fuzz_alg_hll_seed_corpus.zip fuzz_alg_jitter_seed_corpus.zip fuzz_ds_libcache_seed_corpus.zip fuzz_community_id_seed_corpus.zip fuzz_serialization_seed_corpus.zip fuzz_ds_ptree_seed_corpus.zip fuzz_alg_crc32_md5_seed_corpus.zip fuzz_alg_bytestream_seed_corpus.zip fuzz_libinjection_seed_corpus.zip fuzz_tls_certificate_seed_corpus.zip fuzz_filecfg_protocols_seed_corpus.zip fuzz_readerutils_workflow_seed_corpus.zip fuzz_readerutils_parseprotolist_seed_corpus.zip fuzz_ds_bitmap64_fuse_seed_corpus.zip fuzz_ds_domain_classify_seed_corpus.zip fuzz_filecfg_protocols_seed_corpus.zip fuzz_is_stun_udp_seed_corpus.zip fuzz_is_stun_tcp_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip fuzz_ndpi_reader_pl7m_seed_corpus.zip fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip fuzz_filecfg_malicious_ja4_seed_corpus.zip fuzz_filecfg_malicious_sha1_seed_corpus.zip fuzz_filecfg_categories_seed_corpus.zip
	cp corpus/fuzz_*seed_corpus.zip .

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
		-o -name '*.options' \
		-o -name 'ipv4_addresses.txt' \
		-o -name 'ipv6_addresses.txt' \
		-o -name 'bd_param.txt' \
		-o -name 'splt_param.txt' \
		-o -name 'random_list.list' \
		-o -path './dictionary.dict' \
		-o -path './dictionary_tls_certificate.dict' \
		-o -path './corpus/fuzz_*.zip' \
		-o -path './corpus/fuzz_quic_get_crypto_data/*' \
		-o -path './corpus/fuzz_filecfg_protocols/*' \
		-o -path './corpus/fuzz_filecfg_categories/*' \
		-o -path './corpus/fuzz_filecfg_malicious_sha1/*' \
		-o -path './corpus/fuzz_filecfg_malicious_ja4/*' \
		-o -path './corpus/fuzz_filecfg_risk_domains/*' \
		-o -path './corpus/fuzz_filecfg_config/*' \
		-o -path './corpus/fuzz_filecfg_category/*' \
		-o -path './corpus/fuzz_readerutils_workflow/*' \
		-o -path './corpus/fuzz_readerutils_parseprotolist/*' \
		-o -path './corpus/fuzz_is_stun_udp/*' \
		-o -path './corpus/fuzz_is_stun_tcp/*' \
		-o -path './corpus/fuzz_serialization/*' \
		-o -path './corpus/fuzz_community_id/*' \
		-o -path './corpus/fuzz_libinjection/*' \
		-o -path './corpus/fuzz_tls_certificate/*' \
		-o -path './corpus/fuzz_alg_ses_des/*' \
		-o -path './corpus/fuzz_alg_bins/*' \
		-o -path './corpus/fuzz_alg_hll/*' \
		-o -path './corpus/fuzz_alg_jitter/*' \
		-o -path './corpus/fuzz_alg_crc32_md5/*' \
		-o -path './corpus/fuzz_alg_bytestream/*' \
		-o -path './corpus/fuzz_ds_libcache/*' \
		-o -path './corpus/fuzz_ds_bitmap64_fuse/*' \
		-o -path './corpus/fuzz_ds_domain_classify/*' \
		-o -path './corpus/fuzz_ds_ptree/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus dictionaries
