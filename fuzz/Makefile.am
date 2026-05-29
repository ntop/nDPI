bin_PROGRAMS = fuzz_process_packet fuzz_ndpi_reader fuzz_ndpi_reader_nalloc fuzz_ndpi_reader_alloc_fail fuzz_ndpi_reader_payload_analyzer fuzz_quic_get_crypto_data fuzz_config fuzz_community_id fuzz_serialization fuzz_tls_certificate fuzz_dga fuzz_is_stun_udp fuzz_is_stun_tcp fuzz_match_custom_category fuzz_tls_client_server_hello fuzz_dns_parse fuzz_http_parse fuzz_ndpi_decode_tls_blocks
#Alghoritms
bin_PROGRAMS += fuzz_alg_ranking fuzz_alg_bins fuzz_alg_hll fuzz_alg_hw_rsi_outliers_da fuzz_alg_jitter fuzz_alg_ses_des fuzz_alg_crc32_md5 fuzz_alg_shoco fuzz_alg_memmem fuzz_alg_strnstr fuzz_alg_quick_encryption fuzz_alg_isolationforest fuzz_alg_anomalymodel
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
# Use AM_CFLAGS for package flags, never modify or embed user's CFLAGS
AM_CFLAGS = @NDPI_CFLAGS@
AM_CXXFLAGS = @NDPI_CFLAGS@
LDADD = $(top_builddir)/src/lib/libndpi.a $(PCAP_LIB) $(ADDITIONAL_LIBS)
if HAS_FUZZLDFLAGS
AM_CFLAGS += $(LIB_FUZZING_ENGINE)
AM_LDFLAGS += $(LIB_FUZZING_ENGINE)
AM_CXXFLAGS += $(LIB_FUZZING_ENGINE)
endif

# Common linker command template for all fuzz targets
# All fuzz targets need to use CXX as linker (required by libFuzzer)
FUZZ_LINK_COMMAND = $(AM_V_CCLD)$(LIBTOOL) $(AM_V_lt) --silent --tag=CC $(AM_LIBTOOLFLAGS) \
    $(LIBTOOLFLAGS) --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) \
    $($@_LDFLAGS) @NDPI_LDFLAGS@ $(AM_LDFLAGS) $(LDFLAGS) -o $@

# Define sources and flags for each fuzz target
# Note: Fuzz targets with dictionaries should depend on them for proper rebuilds
fuzz_process_packet_SOURCES = fuzz_process_packet.c fuzz_common_code.c
fuzz_process_packet_LINK = $(FUZZ_LINK_COMMAND)
fuzz_process_packet_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary.dict

fuzz_ndpi_reader_SOURCES = fuzz_ndpi_reader.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c
fuzz_ndpi_reader_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/
fuzz_ndpi_reader_LINK = $(FUZZ_LINK_COMMAND)
fuzz_ndpi_reader_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary.dict

fuzz_ndpi_reader_nalloc_SOURCES = fuzz_ndpi_reader_nalloc.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c
fuzz_ndpi_reader_nalloc_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -I $(top_srcdir)/src/lib/third_party/src/fuzz -DENABLE_NALLOC
fuzz_ndpi_reader_nalloc_LINK = $(FUZZ_LINK_COMMAND)
fuzz_ndpi_reader_nalloc_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary.dict

fuzz_ndpi_reader_alloc_fail_SOURCES = fuzz_ndpi_reader_alloc_fail.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c
fuzz_ndpi_reader_alloc_fail_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_MEM_ALLOC_FAILURES -DCRYPT_FORCE_NO_AESNI -DENABLE_FINGERPRINT_FP
fuzz_ndpi_reader_alloc_fail_LINK = $(FUZZ_LINK_COMMAND)
fuzz_ndpi_reader_alloc_fail_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary.dict

fuzz_ndpi_reader_payload_analyzer_SOURCES = fuzz_ndpi_reader_payload_analyzer.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c
fuzz_ndpi_reader_payload_analyzer_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_MEM_ALLOC_FAILURES -DENABLE_PAYLOAD_ANALYZER
fuzz_ndpi_reader_payload_analyzer_LINK = $(FUZZ_LINK_COMMAND)
fuzz_ndpi_reader_payload_analyzer_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary.dict

fuzz_quic_get_crypto_data_SOURCES = fuzz_quic_get_crypto_data.c fuzz_common_code.c
fuzz_quic_get_crypto_data_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_quic_get_crypto_data_LINK = $(FUZZ_LINK_COMMAND)

fuzz_config_SOURCES = fuzz_config.cpp fuzz_common_code.c
fuzz_config_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_config_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_config_LINK = $(FUZZ_LINK_COMMAND)

fuzz_community_id_SOURCES = fuzz_community_id.cpp fuzz_common_code.c
fuzz_community_id_LINK = $(FUZZ_LINK_COMMAND)

fuzz_serialization_SOURCES = fuzz_serialization.cpp fuzz_common_code.c
fuzz_serialization_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_ranking_SOURCES = fuzz_alg_ranking.cpp fuzz_common_code.c
fuzz_alg_ranking_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_bins_SOURCES = fuzz_alg_bins.cpp fuzz_common_code.c
fuzz_alg_bins_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_hll_SOURCES = fuzz_alg_hll.cpp fuzz_common_code.c
fuzz_alg_hll_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_hw_rsi_outliers_da_SOURCES = fuzz_alg_hw_rsi_outliers_da.cpp fuzz_common_code.c
fuzz_alg_hw_rsi_outliers_da_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_isolationforest_SOURCES = fuzz_alg_isolationforest.cpp
fuzz_alg_isolationforest_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_anomalymodel_SOURCES = fuzz_alg_anomalymodel.cpp cpp fuzz_common_code.c
fuzz_alg_anomalymodel_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_jitter_SOURCES = fuzz_alg_jitter.cpp fuzz_common_code.c
fuzz_alg_jitter_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_crc32_md5_SOURCES = fuzz_alg_crc32_md5.c
fuzz_alg_crc32_md5_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_shoco_SOURCES = fuzz_alg_shoco.cpp
fuzz_alg_shoco_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_memmem_SOURCES = fuzz_alg_memmem.cpp
fuzz_alg_memmem_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_strnstr_SOURCES = fuzz_alg_strnstr.cpp
fuzz_alg_strnstr_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_quick_encryption_SOURCES = fuzz_alg_quick_encryption.cpp fuzz_common_code.c
fuzz_alg_quick_encryption_LINK = $(FUZZ_LINK_COMMAND)

fuzz_alg_ses_des_SOURCES = fuzz_alg_ses_des.cpp fuzz_common_code.c
fuzz_alg_ses_des_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_patricia_SOURCES = fuzz_ds_patricia.cpp fuzz_common_code.c
fuzz_ds_patricia_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_ahocorasick_SOURCES = fuzz_ds_ahocorasick.cpp fuzz_common_code.c
fuzz_ds_ahocorasick_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_libcache_SOURCES = fuzz_ds_libcache.cpp fuzz_common_code.c
fuzz_ds_libcache_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_tree_SOURCES = fuzz_ds_tree.cpp fuzz_common_code.c
fuzz_ds_tree_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_ptree_SOURCES = fuzz_ds_ptree.cpp fuzz_common_code.c
fuzz_ds_ptree_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_hash_SOURCES = fuzz_ds_hash.cpp fuzz_common_code.c
fuzz_ds_hash_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_cmsketch_SOURCES = fuzz_ds_cmsketch.cpp fuzz_common_code.c
fuzz_ds_cmsketch_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_bitmap64_fuse_SOURCES = fuzz_ds_bitmap64_fuse.cpp fuzz_common_code.c
fuzz_ds_bitmap64_fuse_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_domain_classify_SOURCES = fuzz_ds_domain_classify.cpp fuzz_common_code.c
fuzz_ds_domain_classify_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_domain_classify_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_kdtree_SOURCES = fuzz_ds_kdtree.cpp fuzz_common_code.c
fuzz_ds_kdtree_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_btree_SOURCES = fuzz_ds_btree.cpp fuzz_common_code.c
fuzz_ds_btree_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_btree_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_btree_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_address_cache_SOURCES = fuzz_ds_address_cache.cpp fuzz_common_code.c
fuzz_ds_address_cache_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_address_cache_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_address_cache_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_bitmap_SOURCES = fuzz_ds_bitmap.cpp fuzz_common_code.c
fuzz_ds_bitmap_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_bitmap_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_bitmap_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ds_filter_SOURCES = fuzz_ds_filter.cpp fuzz_common_code.c
fuzz_ds_filter_CXXFLAGS = $(AM_CXXFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_filter_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_ds_filter_LINK = $(FUZZ_LINK_COMMAND)

fuzz_libinjection_SOURCES = fuzz_libinjection.c
fuzz_libinjection_LINK = $(FUZZ_LINK_COMMAND)

fuzz_binaryfusefilter_SOURCES = fuzz_binaryfusefilter.cpp fuzz_common_code.c
fuzz_binaryfusefilter_LINK = $(FUZZ_LINK_COMMAND)

fuzz_tls_certificate_SOURCES = fuzz_tls_certificate.c fuzz_common_code.c
fuzz_tls_certificate_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_tls_certificate_LINK = $(FUZZ_LINK_COMMAND)
fuzz_tls_certificate_DEPENDENCIES = $(top_builddir)/src/lib/libndpi.a $(srcdir)/dictionary_tls_certificate.dict

fuzz_dga_SOURCES = fuzz_dga.c fuzz_common_code.c
fuzz_dga_LINK = $(FUZZ_LINK_COMMAND)

fuzz_is_stun_udp_SOURCES = fuzz_is_stun.c fuzz_common_code.c
fuzz_is_stun_udp_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_is_stun_udp_LINK = $(FUZZ_LINK_COMMAND)

fuzz_is_stun_tcp_SOURCES = fuzz_is_stun_tcp.c fuzz_common_code.c
fuzz_is_stun_tcp_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION -DSTUN_TCP
fuzz_is_stun_tcp_LINK = $(FUZZ_LINK_COMMAND)

fuzz_match_custom_category_SOURCES = fuzz_match_custom_category.c fuzz_common_code.c
fuzz_match_custom_category_LINK = $(FUZZ_LINK_COMMAND)

fuzz_tls_client_server_hello_SOURCES = fuzz_tls_client_server_hello.c fuzz_common_code.c
fuzz_tls_client_server_hello_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_tls_client_server_hello_LINK = $(FUZZ_LINK_COMMAND)

fuzz_dns_parse_SOURCES = fuzz_dns_parse.c fuzz_common_code.c
fuzz_dns_parse_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_dns_parse_LINK = $(FUZZ_LINK_COMMAND)

fuzz_http_parse_SOURCES = fuzz_http_parse.c fuzz_common_code.c
fuzz_http_parse_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_http_parse_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_decode_tls_blocks_SOURCES = fuzz_ndpi_decode_tls_blocks.c
fuzz_ndpi_decode_tls_blocks_LINK = $(FUZZ_LINK_COMMAND)

fuzz_gcrypt_light_SOURCES = fuzz_gcrypt_light.cpp fuzz_common_code.c
fuzz_gcrypt_light_LINK = $(FUZZ_LINK_COMMAND)

fuzz_gcrypt_aes_SOURCES = fuzz_gcrypt_aes.cpp
fuzz_gcrypt_aes_LINK = $(FUZZ_LINK_COMMAND)

fuzz_gcrypt_gcm_SOURCES = fuzz_gcrypt_gcm.cpp
fuzz_gcrypt_gcm_LINK = $(FUZZ_LINK_COMMAND)

fuzz_gcrypt_cipher_SOURCES = fuzz_gcrypt_cipher.cpp
fuzz_gcrypt_cipher_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_protocols_SOURCES = fuzz_filecfg_protocols.c fuzz_common_code.c
fuzz_filecfg_protocols_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_protocols_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_categories_SOURCES = fuzz_filecfg_categories.c fuzz_common_code.c
fuzz_filecfg_categories_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_categories_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_malicious_sha1_SOURCES = fuzz_filecfg_malicious_sha1.c fuzz_common_code.c
fuzz_filecfg_malicious_sha1_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_malicious_sha1_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_malicious_ja4_SOURCES = fuzz_filecfg_malicious_ja4.c fuzz_common_code.c
fuzz_filecfg_malicious_ja4_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_malicious_ja4_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_risk_domains_SOURCES = fuzz_filecfg_risk_domains.c fuzz_common_code.c
fuzz_filecfg_risk_domains_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_risk_domains_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_config_SOURCES = fuzz_filecfg_config.c fuzz_common_code.c
fuzz_filecfg_config_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_config_LINK = $(FUZZ_LINK_COMMAND)

fuzz_filecfg_category_SOURCES = fuzz_filecfg_category.c fuzz_common_code.c
fuzz_filecfg_category_CFLAGS = $(AM_CFLAGS) -DNDPI_LIB_COMPILATION
fuzz_filecfg_category_LINK = $(FUZZ_LINK_COMMAND)

fuzz_readerutils_workflow_SOURCES = fuzz_readerutils_workflow.cpp fuzz_common_code.c $(top_srcdir)/example/reader_util.c
fuzz_readerutils_workflow_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/example/
fuzz_readerutils_workflow_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/
fuzz_readerutils_workflow_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_simplest_SOURCES = fuzz_ndpi_reader_pl7m_simplest.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR
fuzz_ndpi_reader_pl7m_simplest_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_simplest_internal_SOURCES = fuzz_ndpi_reader_pl7m_simplest_internal.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_simplest_internal_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_SIMPLEST_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
fuzz_ndpi_reader_pl7m_simplest_internal_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_SOURCES = fuzz_ndpi_reader_pl7m.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DENABLE_CONFIG2
fuzz_ndpi_reader_pl7m_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_64k_SOURCES = fuzz_ndpi_reader_pl7m_64k.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_64k_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_64K_PACKETS
fuzz_ndpi_reader_pl7m_64k_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_internal_SOURCES = fuzz_ndpi_reader_pl7m_internal.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_internal_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_USE_INTERNAL_FUZZER_MUTATE
fuzz_ndpi_reader_pl7m_internal_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_only_subclassification_SOURCES = fuzz_ndpi_reader_pl7m_only_subclassification.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_only_subclassification_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DENABLE_ONLY_SUBCLASSIFICATION
fuzz_ndpi_reader_pl7m_only_subclassification_LINK = $(FUZZ_LINK_COMMAND)

fuzz_ndpi_reader_pl7m_randomize_ports_SOURCES = fuzz_ndpi_reader_pl7m_randomize_ports.c fuzz_common_code.c $(top_srcdir)/example/reader_util.c $(top_srcdir)/src/lib/third_party/src/fuzz/pl7m.c
fuzz_ndpi_reader_pl7m_randomize_ports_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/example/ -DENABLE_PCAP_L7_MUTATOR -DPL7M_ENABLE_RANDOMIZE_PORTS
fuzz_ndpi_reader_pl7m_randomize_ports_LINK = $(FUZZ_LINK_COMMAND)


# required for Google oss-fuzz
# see https://github.com/google/oss-fuzz/tree/master/projects/ndpi
testpcaps := $(wildcard $(top_srcdir)/tests/cfgs/default/pcap/*.pcap*)

# Incremental corpus building: only rebuild zip if pcap files changed
testpcaps.zip: $(testpcaps)
	@echo "Building testpcaps.zip from $(words $(testpcaps)) pcap files..."
	@zip -q -j testpcaps.zip $(testpcaps)

# Pattern rule for PCAP-based corpus zips (incremental: only copy if testpcaps.zip is newer)
%_seed_corpus.zip: testpcaps.zip
	@if [ ! -f $@ ] || [ $< -nt $@ ]; then \
		cp testpcaps.zip $@; \
	else \
		echo "$@ is up to date"; \
	fi

# Explicit targets for PCAP-based corpora (uses pattern rule above)
fuzz_ndpi_reader_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_nalloc_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_alloc_fail_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_only_subclassification_seed_corpus.zip: testpcaps.zip
fuzz_ndpi_reader_pl7m_randomize_ports_seed_corpus.zip: testpcaps.zip

# Corpus files from directories (incremental: only rebuild if source files changed)
files_corpus_fuzz_quic_get_crypto_data := $(wildcard $(srcdir)/corpus/fuzz_quic_get_crypto_data/*)
fuzz_quic_get_crypto_data_seed_corpus.zip: $(files_corpus_fuzz_quic_get_crypto_data)
	@zip -q -j $@ $(files_corpus_fuzz_quic_get_crypto_data)

files_corpus_fuzz_is_stun_udp := $(wildcard $(srcdir)/corpus/fuzz_is_stun_udp/*)
fuzz_is_stun_udp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_udp)
	@zip -q -j $@ $(files_corpus_fuzz_is_stun_udp)

files_corpus_fuzz_is_stun_tcp := $(wildcard $(srcdir)/corpus/fuzz_is_stun_tcp/*)
fuzz_is_stun_tcp_seed_corpus.zip: $(files_corpus_fuzz_is_stun_tcp)
	@zip -q -j $@ $(files_corpus_fuzz_is_stun_tcp)

files_corpus_fuzz_libinjection := $(wildcard $(srcdir)/corpus/fuzz_libinjection/*)
fuzz_libinjection_seed_corpus.zip: $(files_corpus_fuzz_libinjection)
	@zip -q -j $@ $(files_corpus_fuzz_libinjection)

files_corpus_fuzz_tls_certificate := $(wildcard $(srcdir)/corpus/fuzz_tls_certificate/*)
fuzz_tls_certificate_seed_corpus.zip: $(files_corpus_fuzz_tls_certificate)
	@zip -q -j $@ $(files_corpus_fuzz_tls_certificate)

files_corpus_fuzz_filecfg_protocols := $(wildcard $(srcdir)/corpus/fuzz_filecfg_protocols/*)
fuzz_filecfg_protocols_seed_corpus.zip: $(files_corpus_fuzz_filecfg_protocols)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_protocols)

files_corpus_fuzz_filecfg_categories := $(wildcard $(srcdir)/corpus/fuzz_filecfg_categories/*)
fuzz_filecfg_categories_seed_corpus.zip: $(files_corpus_fuzz_filecfg_categories)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_categories)

files_corpus_fuzz_filecfg_malicious_sha1 := $(wildcard $(srcdir)/corpus/fuzz_filecfg_malicious_sha1/*)
fuzz_filecfg_malicious_sha1_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_sha1)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_malicious_sha1)

files_corpus_fuzz_filecfg_malicious_ja4 := $(wildcard $(srcdir)/corpus/fuzz_filecfg_malicious_ja4/*)
fuzz_filecfg_malicious_ja4_seed_corpus.zip: $(files_corpus_fuzz_filecfg_malicious_ja4)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_malicious_ja4)

files_corpus_fuzz_filecfg_risk_domains := $(wildcard $(srcdir)/corpus/fuzz_filecfg_risk_domains/*)
fuzz_filecfg_risk_domains_seed_corpus.zip: $(files_corpus_fuzz_filecfg_risk_domains)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_risk_domains)

files_corpus_fuzz_filecfg_config := $(wildcard $(srcdir)/corpus/fuzz_filecfg_config/*)
fuzz_filecfg_config_seed_corpus.zip: $(files_corpus_fuzz_filecfg_config)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_config)

files_corpus_fuzz_filecfg_category := $(wildcard $(srcdir)/corpus/fuzz_filecfg_category/*)
fuzz_filecfg_category_seed_corpus.zip: $(files_corpus_fuzz_filecfg_category)
	@zip -q -j $@ $(files_corpus_fuzz_filecfg_category)

files_corpus_fuzz_http_parse := $(wildcard $(srcdir)/corpus/fuzz_http_parse/*)
fuzz_http_parse_seed_corpus.zip: $(files_corpus_fuzz_http_parse)
	@zip -q -j $@ $(files_corpus_fuzz_http_parse)

files_corpus_fuzz_dns_parse := $(wildcard $(srcdir)/corpus/fuzz_dns_parse/*)
fuzz_dns_parse_seed_corpus.zip: $(files_corpus_fuzz_dns_parse)
	@zip -q -j $@ $(files_corpus_fuzz_dns_parse)

files_corpus_fuzz_tls_client_server_hello := $(wildcard $(srcdir)/corpus/fuzz_tls_client_server_hello/*)
fuzz_tls_client_server_hello_seed_corpus.zip: $(files_corpus_fuzz_tls_client_server_hello)
	@zip -q -j $@ $(files_corpus_fuzz_tls_client_server_hello)

# Phony target to build all corpora (incremental build via dependencies)
.PHONY: corpus
corpus: fuzz_ndpi_reader_seed_corpus.zip fuzz_ndpi_reader_nalloc_seed_corpus.zip fuzz_ndpi_reader_alloc_fail_seed_corpus.zip fuzz_ndpi_reader_payload_analyzer_seed_corpus.zip fuzz_quic_get_crypto_data_seed_corpus.zip fuzz_libinjection_seed_corpus.zip fuzz_tls_certificate_seed_corpus.zip fuzz_filecfg_protocols_seed_corpus.zip fuzz_is_stun_udp_seed_corpus.zip fuzz_is_stun_tcp_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_seed_corpus.zip fuzz_ndpi_reader_pl7m_seed_corpus.zip fuzz_ndpi_reader_pl7m_64k_seed_corpus.zip fuzz_ndpi_reader_pl7m_simplest_internal_seed_corpus.zip fuzz_ndpi_reader_pl7m_internal_seed_corpus.zip fuzz_ndpi_reader_pl7m_only_subclassification_seed_corpus.zip fuzz_ndpi_reader_pl7m_randomize_ports_seed_corpus.zip fuzz_filecfg_malicious_ja4_seed_corpus.zip fuzz_filecfg_malicious_sha1_seed_corpus.zip fuzz_filecfg_categories_seed_corpus.zip fuzz_filecfg_category_seed_corpus.zip fuzz_filecfg_config_seed_corpus.zip fuzz_filecfg_risk_domains_seed_corpus.zip fuzz_http_parse_seed_corpus.zip fuzz_dns_parse_seed_corpus.zip fuzz_tls_client_server_hello_seed_corpus.zip
	@echo "All corpus files are up to date"
	@if [ -d "$(srcdir)/corpus" ] && ls $(srcdir)/corpus/fuzz_*seed_corpus.zip >/dev/null 2>&1; then \
		echo "Copying pre-built corpus files from source directory..."; \
		cp $(srcdir)/corpus/fuzz_*seed_corpus.zip . 2>/dev/null || true; \
	fi

# Create dictionaries exactly as expected by oss-fuzz.
# This way, if we need to change/update/add something,
# we don't need to update scripts in oss-fuzz repository
# Incremental: only copy if source dictionary is newer
.PHONY: dictionaries
dictionaries: fuzz_ndpi_reader.dict fuzz_ndpi_reader_nalloc.dict fuzz_ndpi_reader_alloc_fail.dict fuzz_ndpi_reader_payload_analyzer.dict fuzz_process_packet.dict fuzz_tls_certificate.dict
	@echo "All dictionaries are up to date"

fuzz_ndpi_reader.dict: $(srcdir)/dictionary.dict
	@cp $(srcdir)/dictionary.dict $@

fuzz_ndpi_reader_nalloc.dict: $(srcdir)/dictionary.dict
	@cp $(srcdir)/dictionary.dict $@

fuzz_ndpi_reader_alloc_fail.dict: $(srcdir)/dictionary.dict
	@cp $(srcdir)/dictionary.dict $@

fuzz_ndpi_reader_payload_analyzer.dict: $(srcdir)/dictionary.dict
	@cp $(srcdir)/dictionary.dict $@

fuzz_process_packet.dict: $(srcdir)/dictionary.dict
	@cp $(srcdir)/dictionary.dict $@

fuzz_tls_certificate.dict: $(srcdir)/dictionary_tls_certificate.dict
	@cp $(srcdir)/dictionary_tls_certificate.dict $@

clean-local:
	$(RM) *.o $(bin_PROGRAMS)
	$(RM) $(top_builddir)/example/fuzz_*.o
	$(RM) $(top_builddir)/src/lib/third_party/src/fuzz_*.o
	$(RM) $(top_builddir)/src/lib/third_party/src/fuzz/fuzz_*.o
	$(RM) testpcaps.zip
	$(RM) *_seed_corpus.zip
	$(RM) fuzz*.dict
	$(RM) -r .libs .deps

distclean-local:
	$(RM) Makefile

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
		-o -path '$(srcdir)/corpus/create_corpus_fuzz_match_custom_category.sh' \
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
		-o -path '$(srcdir)/corpus/fuzz_dns_parse/*' \
		-o -path '$(srcdir)/corpus/fuzz_http_parse/*' \
		-o -path '$(srcdir)/corpus/fuzz_tls_client_server_hello/*' \
		-o -path '$(srcdir)/corpus/fuzz_tls_certificate/*' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'
	find . -type l -name '*.c' | xargs -I'{}' cp -r '{}' '$(distdir)/{}'

all: corpus dictionaries
