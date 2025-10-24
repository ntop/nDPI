bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_alloc_fail fuzz_ndpi_reader_payload_analyzer fuzz_quic_get_crypto_data fuzz_config fuzz_community_id fuzz_serialization fuzz_tls_certificate fuzz_dga fuzz_is_stun_udp fuzz_is_stun_tcp
#Alghoritms
bin_PROGRAMS += fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des fuzz_alg_crc32_md5 fuzz_alg_bytestream fuzz_alg_shoco fuzz_alg_memmem fuzz_alg_strnstr fuzz_alg_quick_encryption
#Data structures
bin_PROGRAMS += fuzz_ds_patricia fuzz_ds_ahocorasick fuzz_ds_libcache fuzz_ds_tree fuzz_ds_ptree fuzz_ds_hash fuzz_ds_cmsketch fuzz_ds_bitmap64_fuse fuzz_ds_domain_classify fuzz_ds_kdtree fuzz_ds_btree fuzz_ds_address_cache fuzz_ds_bitmap fuzz_ds_filter
#Third party
bin_PROGRAMS += fuzz_libinjection fuzz_binaryfusefilter
#Internal crypto
bin_PROGRAMS += fuzz_gcrypt_light fuzz_gcrypt_aes fuzz_gcrypt_gcm fuzz_gcrypt_cipher
#Configuration files
bin_PROGRAMS += fuzz_filecfg_protocols fuzz_filecfg_categories fuzz_filecfg_malicious_sha1 fuzz_filecfg_malicious_ja4 fuzz_filecfg_risk_domains fuzz_filecfg_config fuzz_filecfg_category
#Reader utils
bin_PROGRAMS += fuzz_readerutils_workflow
#Mutators
bin_PROGRAMS += fuzz_ndpi_reader_pl7m fuzz_ndpi_reader_pl7m_64k fuzz_ndpi_reader_pl7m_simplest fuzz_ndpi_reader_pl7m_internal fuzz_ndpi_reader_pl7m_simplest_internal fuzz_ndpi_reader_pl7m_only_subclassification fuzz_ndpi_reader_pl7m_randomize_ports

#Common flags
AM_CPPFLAGS = -I $(top_srcdir)/src/include -I $(top_srcdir)/src/lib/third_party/include/ @NDPI_CFLAGS@
AM_LDFLAGS = $(LIBS)
AM_CFLAGS = @NDPI_CFLAGS@ $(CFLAGS)
AM_CXXFLAGS = @NDPI_CFLAGS@ $(CXXFLAGS)
LDADD = $(PCAP_LIB) $(top_builddir)/src/lib/libndpi.a $(ADDITIONAL_LIBS)
if HAS_FUZZLDFLAGS
CFLAGS += $(LIB_FUZZING_ENGINE)
LDFLAGS += $(LIB_FUZZING_ENGINE)
CXXFLAGS += $(LIB_FUZZING_ENGINE)
endif
#TODO: find a generic way to always use CXX as linker

fuzz_process_packet_SOURCES = fuzz_process_packet.c fuzz_common_code.c
# force usage of CXX for linker
fuzz_process_packet_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_process_packet_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c ../example/reader_util.c
fuzz_ndpi_reader_CFLAGS = -I$(top_srcdir)/example/
# force usage of CXX for linker
fuzz_ndpi_reader_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_alloc_fail_SOURCES = fuzz_ndpi_reader_alloc_fail.c fuzz_common_code.c ../example/reader_util.c
fuzz_ndpi_reader_alloc_fail_CFLAGS = -I$(top_srcdir)/example/ -DENABLE_MEM_ALLOC_FAILURES -DCRYPT_FORCE_NO_AESNI -DENABLE_FINGERPRINT_FP
# force usage of CXX for linker
fuzz_ndpi_reader_alloc_fail_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_alloc_fail_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_payload_analyzer_SOURCES = fuzz_ndpi_reader_payload_analyzer.c fuzz_common_code.c ../example/reader_util.c
fuzz_ndpi_reader_payload_analyzer_CFLAGS = -I$(top_srcdir)/example/ -DENABLE_MEM_ALLOC_FAILURES -DENABLE_PAYLOAD_ANALYZER
# force usage of CXX for linker
fuzz_ndpi_reader_payload_analyzer_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_payload_analyzer_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_quic_get_crypto_data_SOURCES = fuzz_quic_get_crypto_data.c fuzz_common_code.c
fuzz_quic_get_crypto_data_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_quic_get_crypto_data_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_quic_get_crypto_data_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_config_SOURCES = fuzz_config.cpp fuzz_common_code.c
fuzz_config_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_config_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_config_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_community_id_SOURCES = fuzz_community_id.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_community_id_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_community_id_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_serialization_SOURCES = fuzz_serialization.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_serialization_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_serialization_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_bins_SOURCES = fuzz_alg_bins.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_bins_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_bins_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_hll_SOURCES = fuzz_alg_hll.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_hll_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_hll_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_hw_rsi_outliers_da_SOURCES = fuzz_alg_hw_rsi_outliers_da.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_hw_rsi_outliers_da_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_hw_rsi_outliers_da_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_jitter_SOURCES = fuzz_alg_jitter.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_jitter_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_jitter_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_crc32_md5_SOURCES = fuzz_alg_crc32_md5.c
# force usage of CXX for linker
fuzz_alg_crc32_md5_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_crc32_md5_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_bytestream_SOURCES = fuzz_alg_bytestream.c
# force usage of CXX for linker
fuzz_alg_bytestream_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_bytestream_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_shoco_SOURCES = fuzz_alg_shoco.cpp
# force usage of CXX for linker
fuzz_alg_shoco_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_shoco_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_memmem_SOURCES = fuzz_alg_memmem.cpp
# force usage of CXX for linker
fuzz_alg_memmem_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_memmem_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_strnstr_SOURCES = fuzz_alg_strnstr.cpp
# force usage of CXX for linker
fuzz_alg_strnstr_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_strnstr_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_quick_encryption_SOURCES = fuzz_alg_quick_encryption.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_quick_encryption_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_quick_encryption_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_alg_ses_des_SOURCES = fuzz_alg_ses_des.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_alg_ses_des_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_alg_ses_des_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_patricia_SOURCES = fuzz_ds_patricia.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_patricia_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_patricia_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_ahocorasick_SOURCES = fuzz_ds_ahocorasick.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_ahocorasick_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_ahocorasick_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_libcache_SOURCES = fuzz_ds_libcache.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_libcache_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_libcache_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_tree_SOURCES = fuzz_ds_tree.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_tree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_tree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_ptree_SOURCES = fuzz_ds_ptree.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_ptree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_ptree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_hash_SOURCES = fuzz_ds_hash.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_hash_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_hash_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_cmsketch_SOURCES = fuzz_ds_cmsketch.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_cmsketch_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_cmsketch_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_bitmap64_fuse_SOURCES = fuzz_ds_bitmap64_fuse.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_bitmap64_fuse_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_bitmap64_fuse_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_domain_classify_SOURCES = fuzz_ds_domain_classify.cpp fuzz_common_code.c
fuzz_ds_domain_classify_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_ds_domain_classify_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_domain_classify_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_kdtree_SOURCES = fuzz_ds_kdtree.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_ds_kdtree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_kdtree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_btree_SOURCES = fuzz_ds_btree.cpp fuzz_common_code.c
fuzz_ds_btree_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_ds_btree_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_btree_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_address_cache_SOURCES = fuzz_ds_address_cache.cpp fuzz_common_code.c
fuzz_ds_address_cache_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_ds_address_cache_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_address_cache_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_bitmap_SOURCES = fuzz_ds_bitmap.cpp fuzz_common_code.c
fuzz_ds_bitmap_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_ds_bitmap_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_bitmap_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ds_filter_SOURCES = fuzz_ds_filter.cpp fuzz_common_code.c
fuzz_ds_filter_CXXFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_ds_filter_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ds_filter_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_libinjection_SOURCES = fuzz_libinjection.c
# force usage of CXX for linker
fuzz_libinjection_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_libinjection_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_binaryfusefilter_SOURCES = fuzz_binaryfusefilter.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_binaryfusefilter_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_binaryfusefilter_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_tls_certificate_SOURCES = fuzz_tls_certificate.c fuzz_common_code.c
fuzz_tls_certificate_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_tls_certificate_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_tls_certificate_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_dga_SOURCES = fuzz_dga.c fuzz_common_code.c
# force usage of CXX for linker
fuzz_dga_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_dga_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_is_stun_udp_SOURCES = fuzz_is_stun.c fuzz_common_code.c
fuzz_is_stun_udp_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_is_stun_udp_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_is_stun_udp_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_is_stun_tcp_SOURCES = fuzz_is_stun_tcp.c fuzz_common_code.c
fuzz_is_stun_tcp_CFLAGS = -DNDPI_LIB_COMPILATION -DSTUN_TCP
# force usage of CXX for linker
fuzz_is_stun_tcp_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_is_stun_tcp_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_light_SOURCES = fuzz_gcrypt_light.cpp fuzz_common_code.c
# force usage of CXX for linker
fuzz_gcrypt_light_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_light_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_aes_SOURCES = fuzz_gcrypt_aes.cpp
# force usage of CXX for linker
fuzz_gcrypt_aes_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_aes_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_gcm_SOURCES = fuzz_gcrypt_gcm.cpp
# force usage of CXX for linker
fuzz_gcrypt_gcm_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_gcm_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_gcrypt_cipher_SOURCES = fuzz_gcrypt_cipher.cpp
# force usage of CXX for linker
fuzz_gcrypt_cipher_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_gcrypt_cipher_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_protocols_SOURCES = fuzz_filecfg_protocols.c fuzz_common_code.c
fuzz_filecfg_protocols_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_protocols_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_protocols_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_categories_SOURCES = fuzz_filecfg_categories.c fuzz_common_code.c
fuzz_filecfg_categories_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_categories_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_categories_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_malicious_sha1_SOURCES = fuzz_filecfg_malicious_sha1.c fuzz_common_code.c
fuzz_filecfg_malicious_sha1_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_malicious_sha1_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_malicious_sha1_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_malicious_ja4_SOURCES = fuzz_filecfg_malicious_ja4.c fuzz_common_code.c
fuzz_filecfg_malicious_ja4_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_malicious_ja4_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_malicious_ja4_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_risk_domains_SOURCES = fuzz_filecfg_risk_domains.c fuzz_common_code.c
fuzz_filecfg_risk_domains_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_risk_domains_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_risk_domains_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_config_SOURCES = fuzz_filecfg_config.c fuzz_common_code.c
fuzz_filecfg_config_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_config_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_config_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_filecfg_category_SOURCES = fuzz_filecfg_category.c fuzz_common_code.c
fuzz_filecfg_category_CFLAGS = -DNDPI_LIB_COMPILATION
# force usage of CXX for linker
fuzz_filecfg_category_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_filecfg_category_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_readerutils_workflow_SOURCES = fuzz_readerutils_workflow.cpp fuzz_common_code.c ../example/reader_util.c
fuzz_readerutils_workflow_CXXFLAGS = -I$(top_srcdir)/example/
# force usage of CXX for linker
fuzz_readerutils_workflow_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_readerutils_workflow_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_simplest_SOURCES = fuzz_ndpi_reader_pl7m_simplest.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_simplest_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_simplest_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_simplest_internal_SOURCES = fuzz_ndpi_reader_pl7m_simplest_internal.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_internal_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_simplest_internal_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_simplest_internal_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_SOURCES = fuzz_ndpi_reader_pl7m.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DENABLE_CONFIG2
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_64k_SOURCES = fuzz_ndpi_reader_pl7m_64k.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_64k_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_64K_PACKETS
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_64k_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_64k_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_internal_SOURCES = fuzz_ndpi_reader_pl7m_internal.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_internal_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_internal_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_internal_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_only_subclassification_SOURCES = fuzz_ndpi_reader_pl7m_only_subclassification.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_only_subclassification_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DENABLE_ONLY_SUBCLASSIFICATION
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_only_subclassification_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_only_subclassification_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@

fuzz_ndpi_reader_pl7m_randomize_ports_SOURCES = fuzz_ndpi_reader_pl7m_randomize_ports.c fuzz_common_code.c ../example/reader_util.c ../src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_randomize_ports_CFLAGS =  -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_ENABLE_RANDOMIZE_PORTS
# force usage of CXX for linker
fuzz_ndpi_reader_pl7m_randomize_ports_LINK=$(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) @NDPI_CFLAGS@ $(AM_CXXFLAGS) $(CXXFLAGS) \
    $(fuzz_ndpi_reader_pl7m_randomize_ports_LDFLAGS) @NDPI_LDFLAGS@ $(LDFLAGS) -o $@


# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard $(top_srcdir)/tests/cfgs/default/pcap/*.pcap*)

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

fuzz_ndpi_reader_pl7m_only_subclassification_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_only_subclassification_seed_corpus.zip

fuzz_ndpi_reader_pl7m_randomize_ports_seed_corpus.zip: testpcaps.zip
	cp testpcaps.zip fuzz_ndpi_reader_pl7m_randomize_ports_seed_corpus.zip

files_corpus_fuzz_quic_get_crypto_data :=  $(wildcard $(srcdir)/corpus/fuzz_quic_get_crypto_data/*)
fuzz_quic_get_crypto_data_seed_corpus.zip: $(files_corpus_fuzz_quic_get_crypto_data)
	zip -j fuzz_quic_get_crypto_data_seed_corpus.zip $(files_corpus_fuzz_quic_get_crypto_data)

files_corpus_fuzz_is_stun_udp :=  $(wildcard $(srcdir)/corpus/fuzz_is_stun_udp/*)
fuzz_is_stun_udp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_udp)
	zip -j fuzz_is_stun_udp_seed_corpus.zip $(files_corpus_fuzz_is_stun_udp)

files_corpus_fuzz_is_stun_tcp :=  $(wildcard $(srcdir)/corpus/fuzz_is_stun_tcp/*)
fuzz_is_stun_tcp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_tcp)
	zip -j fuzz_is_stun_tcp_seed_corpus.zip $(files_corpus_fuzz_is_stun_tcp)

files_corpus_fuzz_libinjection :=  $(wildcard $(srcdir)/corpus/fuzz_libinjection/*)
fuzz_libinjection_seed_corpus.zip: $(files_corpus_fuzz_libinjection)
	zip -j fuzz_libinjection_seed_corpus.zip $(files_corpus_fuzz_libinjection)

files_corpus_fuzz_tls_certificate :=  $(wildcard $(srcdir)/corpus/fuzz_tls_certificate/*)
fuzz_tls_certificate_seed_corpus.zip: $(files_corpus_fuzz_tls_certificate)
	zip -j fuzz_tls_certificate_seed_corpus.zip $(files_corpus_fuzz_tls_certificate)

files_corpus_fuzz_filecfg_protocols :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_protocols/*)
fuzz_filecfg_protocols_seed_corpus.zip: $(files_corpus_fuzz_filecfg_protocols)
	zip -j fuzz_filecfg_protocols_seed_corpus.zip $(files_corpus_fuzz_filecfg_protocols)

files_corpus_fuzz_filecfg_categories :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_categories/*)
fuzz_filecfg_categories_seed_corpus.zip: $(files_corpus_fuzz_filecfg_categories)
	zip -j fuzz_filecfg_categories_seed_corpus.zip $(files_corpus_fuzz_filecfg_categories)

files_corpus_fuzz_filecfg_malicious_sha1 :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_malicious_sha1/*)
fuzz_filecfg_malicious_sha1_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_sha1)
	zip -j fuzz_filecfg_malicious_sha1_seed_corpus.zip $(files_corpus_fuzz_filecfg_malicious_sha1)

files_corpus_fuzz_filecfg_malicious_ja4 :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_malicious_ja4/*)
fuzz_filecfg_malicious_ja4_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_ja4)
	zip -j fuzz_filecfg_malicious_ja4_seed_corpus.zip $(files_corpus_fuzz_filecfg_malicious_ja4)

files_corpus_fuzz_filecfg_risk_domains :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_risk_domains/*)
fuzz_filecfg_risk_domains_seed_corpus.zip: $(files_corpus_fuzz_filecfg_risk_domains)
	zip -j fuzz_filecfg_risk_domains_seed_corpus.zip $(files_corpus_fuzz_filecfg_risk_domains)

files_corpus_fuzz_filecfg_config :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_config/*)
fuzz_filecfg_config_seed_corpus.zip: $(files_corpus_fuzz_filecfg_config)
	zip -j fuzz_filecfg_config_seed_corpus.zip $(files_corpus_fuzz_filecfg_config)

files_corpus_fuzz_filecfg_category :=  $(wildcard $(srcdir)/corpus/fuzz_filecfg_category/*)
fuzz_filecfg_category_seed_corpus.zip: $(files_corpus_fuzz_filecfg_category)
	zip -j fuzz_filecfg_category_seed_corpus.zip $(files_corpus_fuzz_filecfg_category)

corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_libinjection_seed_corpus.zip fuzz_tls_certificate_seed_corpus.zip fuzz_filecfg_protocols_seed_corpus.zip fuzz_filecfg_protocols_seed_corpus.zip fuzz_is_stun_udp_seed_corpus.zip fuzz_is_stun_tcp_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip fuzz_ndpi_reader_pl7m_seed_corpus.zip fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip fuzz_ndpi_reader_pl7m_only_subclassification_seed_corpus.zip fuzz_ndpi_reader_pl7m_randomize_ports_seed_corpus.zip fuzz_filecfg_malicious_ja4_seed_corpus.zip fuzz_filecfg_malicious_sha1_seed_corpus.zip fuzz_filecfg_categories_seed_corpus.zip
	cp $(srcdir)/corpus/fuzz_*seed_corpus.zip .

#Create dictionaries exactly as expected by oss-fuzz.
#This way, if we need to change/update/add something,
#we don't need to update scripts in oss-fuzz repository
dictionaries:
	cp $(srcdir)/dictionary.dict fuzz_ndpi_reader.dict
	cp $(srcdir)/dictionary.dict fuzz_ndpi_reader_alloc_fail.dict
	cp $(srcdir)/dictionary.dict fuzz_ndpi_reader_payload_analyzer.dict
	cp $(srcdir)/dictionary.dict fuzz_process_packet.dict
	cp $(srcdir)/dictionary_tls_certificate.dict fuzz_tls_certificate.dict

clean:
	rm -f *.o $(bin_PROGRAMS) ../example/fuzz_*.o ../src/lib/third_party/src/fuzz_*.o ../src/lib/third_party/src/fuzz/fuzz_*.o
	rm -f testpcaps.zip
	rm -f *_seed_corpus.zip
	rm -f fuzz*.dict

distdir:
	find $(srcdir) -type d | xargs -I'{}' mkdir -p '$(distdir)/{}'
	find $(srcdir) -type f -name '*.c' \
		-o -name '*.am' \
		-o -name '*.h' \
		-o -name '*.cpp' \
		-o -name '*.options' \
		-o -name 'ipv4_addresses.txt' \
		-o -name 'ipv6_addresses.txt' \
		-o -name 'bd_param.txt' \
		-o -name 'splt_param.txt' \
		-o -name 'random_list.list' \
		-o -path '$(srcdir)/dictionary.dict' \
		-o -path '$(srcdir)/dictionary_tls_certificate.dict' \
		-o -path '$(srcdir)/corpus/fuzz_*.zip' \
		-o -path '$(srcdir)/corpus/fuzz_quic_get_crypto_data/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_protocols/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_categories/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_malicious_sha1/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_malicious_ja4/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_risk_domains/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_config/*' \
		-o -path '$(srcdir)/corpus/fuzz_filecfg_category/*' \
		-o -path '$(srcdir)/corpus/fuzz_is_stun_udp/*' \
		-o -path '$(srcdir)/corpus/fuzz_is_stun_tcp/*' \
		-o -path '$(srcdir)/corpus/fuzz_libinjection/*' \
		-o -path '$(srcdir)/corpus/fuzz_tls_certificate/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'
	find . -type l -name '*.c' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus dictionaries
