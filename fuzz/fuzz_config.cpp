#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" void ndpi_self_check_host_match(); /* Self check function */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  struct ndpi_detection_module_struct *ndpi_info_mod;
  struct ndpi_flow_struct flow;
  u_int8_t protocol_was_guessed;
  u_int32_t i, num;
  u_int16_t random_proto, bool_value;
  int random_value;
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_lru_cache_stats lru_stats;
  struct ndpi_patricia_tree_stats patricia_stats;
  struct ndpi_automa_stats automa_stats;
  int cat;
  u_int16_t pid;
  char *protoname;
  char catname[] = "name";
  struct ndpi_flow_input_info input_info;
  ndpi_proto p, p2;
  char out[128];


  if(fuzzed_data.remaining_bytes() < 4 + /* ndpi_init_detection_module() */
				     NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS +
				     1 + /* TLS cert expire */
				     6 + /* files */
				     ((NDPI_LRUCACHE_MAX + 1) * 5) + /* LRU caches */
				     2 + 1 + 5 + /* ndpi_set_detection_preferences() */
				     7 + /* Opportunistic tls */
				     2 + /* Pid */
				     2 + /* Category */
				     1 + /* Bool value */
				     2 + /* input_info */
				     21 /* Min real data: ip length + 1 byte of L4 header */)
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

  ndpi_set_tls_cert_expire_days(ndpi_info_mod, fuzzed_data.ConsumeIntegral<u_int8_t>());

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
  /* Note that this function is not used by ndpiReader */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_ipv4_ptree(ndpi_info_mod, "ipv4_addresses.txt", NDPI_PROTOCOL_TLS);

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
                                   fuzzed_data.ConsumeIntegralInRange(0, (1 << 24)));

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

  /* Random protocol configuration */
  pid = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, ndpi_get_num_supported_protocols(ndpi_info_mod) + 1);
  protoname = ndpi_get_proto_by_id(ndpi_info_mod, pid);
  if (protoname) {
    assert(ndpi_get_proto_by_name(ndpi_info_mod, protoname) == pid);
  }
  ndpi_set_proto_breed(ndpi_info_mod, pid, NDPI_PROTOCOL_SAFE);
  ndpi_set_proto_category(ndpi_info_mod, pid, NDPI_PROTOCOL_CATEGORY_MEDIA);
  ndpi_is_subprotocol_informative(ndpi_info_mod, pid);

  /* Custom category configuration */
  cat = fuzzed_data.ConsumeIntegralInRange(static_cast<int>(NDPI_PROTOCOL_CATEGORY_CUSTOM_1),
                                           static_cast<int>(NDPI_PROTOCOL_CATEGORY_CUSTOM_5 + 1)); /* + 1 to trigger invalid cat */
  ndpi_category_set_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat), catname);
  ndpi_is_custom_category(static_cast<ndpi_protocol_category_t>(cat));
  ndpi_category_get_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat));
  ndpi_get_category_id(ndpi_info_mod, catname);

  ndpi_get_num_supported_protocols(ndpi_info_mod);
  ndpi_get_ndpi_num_custom_protocols(ndpi_info_mod);

  ndpi_self_check_host_match();

  /* Basic code to try testing this "config" */
  bool_value = fuzzed_data.ConsumeBool();
  input_info.in_pkt_dir = !!fuzzed_data.ConsumeBool();
  input_info.seen_flow_beginning = !!fuzzed_data.ConsumeBool();
  memset(&flow, 0, sizeof(flow));
  std::vector<uint8_t>pkt = fuzzed_data.ConsumeRemainingBytes<uint8_t>();
  assert(pkt.size() >= 21); /* To be sure check on fuzzed_data.remaining_bytes() at the beginning is right */
  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt.data(), pkt.size(), 0, &input_info);
  p = ndpi_detection_giveup(ndpi_info_mod, &flow, 1, &protocol_was_guessed);
  assert(p.master_protocol == ndpi_get_flow_masterprotocol(ndpi_info_mod, &flow));
  assert(p.app_protocol == ndpi_get_flow_appprotocol(ndpi_info_mod, &flow));
  assert(p.category == ndpi_get_flow_category(ndpi_info_mod, &flow));
  ndpi_get_lower_proto(p);
  ndpi_get_upper_proto(p);
  ndpi_get_flow_error_code(&flow);
  ndpi_get_flow_risk_info(&flow, out, sizeof(out), 1);
  ndpi_get_flow_ndpi_proto(ndpi_info_mod, &flow, &p2);
  ndpi_is_proto(p, NDPI_PROTOCOL_TLS);
  /* ndpi_guess_undetected_protocol() is a "strange" function (since is ipv4 only)
     but it is exported by the library and it is used by ntopng. Try fuzzing it, here */
  if(!ndpi_is_protocol_detected(ndpi_info_mod, p)) {
    if(!flow.is_ipv6) {
      ndpi_guess_undetected_protocol(ndpi_info_mod, bool_value ? &flow : NULL,
                                     flow.l4_proto,
                                     flow.c_address.v4, flow.s_address.v4,
                                     flow.c_port, flow.s_port);
      /* Another "strange" function (ipv4 only): fuzz it here, for lack of a better alternative */
      ndpi_find_ipv4_category_userdata(ndpi_info_mod, flow.c_address.v4);
    }
    /* Another "strange" function: fuzz it here, for lack of a better alternative */
    ndpi_search_tcp_or_udp(ndpi_info_mod, &flow);
  }
  ndpi_free_flow_data(&flow);

  /* Get some final stats */
  for(i = 0; i < NDPI_LRUCACHE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_lru_cache_stats(ndpi_info_mod, static_cast<lru_cache_type>(i), &lru_stats);
  for(i = 0; i < NDPI_PTREE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_patricia_stats(ndpi_info_mod, static_cast<ptree_type>(i), &patricia_stats);
  for(i = 0; i < NDPI_AUTOMA_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_automa_stats(ndpi_info_mod, static_cast<automa_type>(i), &automa_stats);


  ndpi_revision();
  ndpi_get_api_version();
  ndpi_get_gcrypt_version();

  ndpi_exit_detection_module(ndpi_info_mod);

  return 0;
}
