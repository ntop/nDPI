#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  struct ndpi_detection_module_struct *ndpi_info_mod;
  struct ndpi_flow_struct flow;
  u_int8_t protocol_was_guessed;
  u_int32_t i, num;
  u_int16_t random_proto;
  int random_value;
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_lru_cache_stats lru_stats;
  struct ndpi_patricia_tree_stats patricia_stats;
  struct ndpi_automa_stats automa_stats;

  if(fuzzed_data.remaining_bytes() < 4 + /* ndpi_init_detection_module() */
				     NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS +
				     5 + /* files */
				     ((NDPI_LRUCACHE_MAX + 1) * 5) + /* LRU caches */
				     2 + 1 + 4 + /* ndpi_set_detection_preferences() */
				     7 + /* Opportunistic tls */
				     29 /* Min real data: ip length + udp length + 1 byte */)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_info_mod = ndpi_init_detection_module(fuzzed_data.ConsumeIntegral<u_int32_t>());

  NDPI_BITMASK_RESET(enabled_bitmask);
  for(i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS ; i++) {
    if(fuzzed_data.ConsumeBool())
      NDPI_BITMASK_ADD(enabled_bitmask, i);
  }
  if(ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &enabled_bitmask) == -1) {
    ndpi_exit_detection_module(ndpi_info_mod);
    ndpi_info_mod = NULL;
  }

  if(fuzzed_data.ConsumeBool())
    ndpi_load_protocols_file(ndpi_info_mod, "protos.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_categories_file(ndpi_info_mod, "categories.txt", NULL);
  if(fuzzed_data.ConsumeBool())
    ndpi_load_risk_domain_file(ndpi_info_mod, "risky_domains.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_ja3_file(ndpi_info_mod, "ja3_fingerprints.csv");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_sha1_file(ndpi_info_mod, "sha1_fingerprints.csv");

  for(i = 0; i < NDPI_LRUCACHE_MAX + 1; i++) { /* + 1 to test invalid type */
    ndpi_set_lru_cache_size(ndpi_info_mod, static_cast<lru_cache_type>(i),
			    fuzzed_data.ConsumeIntegralInRange(0, (1 << 16) - 1));
    ndpi_get_lru_cache_size(ndpi_info_mod, static_cast<lru_cache_type>(i), &num);

    ndpi_set_lru_cache_ttl(ndpi_info_mod, static_cast<lru_cache_type>(i),
			   fuzzed_data.ConsumeIntegralInRange(0, (1 << 24) - 1));
    ndpi_get_lru_cache_ttl(ndpi_info_mod, static_cast<lru_cache_type>(i), &num);
  }

  if(fuzzed_data.ConsumeBool())
    ndpi_set_detection_preferences(ndpi_info_mod, ndpi_pref_direction_detect_disable,
                                   fuzzed_data.ConsumeBool());
  if(fuzzed_data.ConsumeBool())
    ndpi_set_detection_preferences(ndpi_info_mod, ndpi_pref_enable_tls_block_dissection,
                                   0 /* unused */);
  if(fuzzed_data.ConsumeBool())
    ndpi_set_detection_preferences(ndpi_info_mod, ndpi_pref_max_packets_to_process,
                                   fuzzed_data.ConsumeIntegralInRange(0, (1 << 16)));

  ndpi_set_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_SMTP, fuzzed_data.ConsumeBool());
  ndpi_get_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_SMTP);
  ndpi_set_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_IMAP, fuzzed_data.ConsumeBool());
  ndpi_get_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_IMAP);
  ndpi_set_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_POP, fuzzed_data.ConsumeBool());
  ndpi_get_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_MAIL_POP);
  ndpi_set_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_FTP_CONTROL, fuzzed_data.ConsumeBool());
  ndpi_get_opportunistic_tls(ndpi_info_mod, NDPI_PROTOCOL_FTP_CONTROL);

  random_proto = fuzzed_data.ConsumeIntegralInRange(0, (1 << 16) - 1);
  random_value = fuzzed_data.ConsumeIntegralInRange(0,2); /* Only 0-1 are valid values */
  ndpi_set_opportunistic_tls(ndpi_info_mod, random_proto, random_value);
  ndpi_get_opportunistic_tls(ndpi_info_mod, random_proto);

  ndpi_finalize_initialization(ndpi_info_mod);


  /* Basic code to try testing this "config" */
  memset(&flow, 0, sizeof(flow));
  std::vector<uint8_t>pkt = fuzzed_data.ConsumeRemainingBytes<uint8_t>();
  assert(pkt.size() >= 29); /* To be sure check on fuzzed_data.remaining_bytes() at the beginning is right */
  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt.data(), pkt.size(), 0, NULL);
  ndpi_detection_giveup(ndpi_info_mod, &flow, 1, &protocol_was_guessed);
  /* ndpi_guess_undetected_protocol() is a "strange" function (since is ipv4 only)
     but it is exported by the library and it is used by ntopng. Try fuzzing it, here */
  if(!flow.is_ipv6)
    ndpi_guess_undetected_protocol(ndpi_info_mod, &flow, flow.l4_proto,
                                   flow.c_address.v4, flow.s_address.v4,
                                   flow.c_port, flow.s_port);
  ndpi_free_flow_data(&flow);

  /* Get some final stats */
  for(i = 0; i < NDPI_LRUCACHE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_lru_cache_stats(ndpi_info_mod, static_cast<lru_cache_type>(i), &lru_stats);
  for(i = 0; i < NDPI_PTREE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_patricia_stats(ndpi_info_mod, static_cast<ptree_type>(i), &patricia_stats);
  for(i = 0; i < NDPI_AUTOMA_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_automa_stats(ndpi_info_mod, static_cast<automa_type>(i), &automa_stats);

  ndpi_exit_detection_module(ndpi_info_mod);

  return 0;
}
