#include "ndpi_api.h"
#include "ndpi_private.h"
#include "ndpi_classify.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  struct ndpi_detection_module_struct *ndpi_info_mod;
  struct ndpi_flow_struct flow;
  u_int8_t protocol_was_guessed, unused;
  u_int32_t i, ret;
  u_int16_t bool_value;
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_lru_cache_stats lru_stats;
  struct ndpi_patricia_tree_stats patricia_stats;
  struct ndpi_automa_stats automa_stats;
  int cat, idx;
  u_int16_t pid, pid2;
  char *protoname, *protoname2;
  char pids_name[32];
  const char *name;
  char catname[] = "name";
  struct ndpi_flow_input_info input_info;
  ndpi_proto p, p2;
  char out[128];
  struct ndpi_global_context *g_ctx;
  char log_ts[32];
  int value;
  char cfg_value[32];
  char cfg_proto[32];
  char cfg_param[32];
  u_int64_t cat_userdata = 0;
  u_int16_t unused1, unused2;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  if(fuzzed_data.ConsumeBool())
    g_ctx = ndpi_global_init();
  else
    g_ctx = NULL;

  ndpi_info_mod = ndpi_init_detection_module(g_ctx);

  set_ndpi_debug_function(ndpi_info_mod, NULL);

  NDPI_BITMASK_SET_ALL(enabled_bitmask);
  if(fuzzed_data.ConsumeBool()) {
    NDPI_BITMASK_RESET(enabled_bitmask);
    for(i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; i++) {
      if(fuzzed_data.ConsumeBool())
        NDPI_BITMASK_ADD(enabled_bitmask, i);
    }
  }
  if(ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &enabled_bitmask) == -1) {
    ndpi_exit_detection_module(ndpi_info_mod);
    ndpi_info_mod = NULL;
  }

  ndpi_set_user_data(ndpi_info_mod, (void *)0xabcdabcd); /* Random pointer */
  ndpi_set_user_data(ndpi_info_mod, (void *)0xabcdabcd); /* Twice to trigger overwriting */
  ndpi_get_user_data(ndpi_info_mod);

  /* ndpi_set_config: try to keep the soame order of the definitions in ndpi_main.c.
     + 1 to trigger unvalid parameter error */

  if(fuzzed_data.ConsumeBool())
    ndpi_load_protocols_file(ndpi_info_mod, "protos.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_protocols_file(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "invalid_filename"); /* Error */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_categories_dir(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : (char *)"./");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_categories_dir(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : (char *)"invalid_dir");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_categories_file(ndpi_info_mod, "categories.txt", &cat_userdata);
  if(fuzzed_data.ConsumeBool())
    ndpi_load_categories_file(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "invalid_filename", &cat_userdata); /* Error */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_risk_domain_file(ndpi_info_mod, "risky_domains.txt");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_risk_domain_file(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "invalid_filename"); /* Error */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_ja3_file(ndpi_info_mod, "ja3_fingerprints.csv");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_ja3_file(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "invalid_filename"); /* Error */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_sha1_file(ndpi_info_mod, "sha1_fingerprints.csv");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_malicious_sha1_file(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "invalid_filename"); /* Error */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_domain_suffixes(ndpi_info_mod, (char *)"public_suffix_list.dat");
  if(fuzzed_data.ConsumeBool())
    ndpi_load_domain_suffixes(ndpi_info_mod, (char *)"public_suffix_list.dat"); /* To trigger reload */
  if(fuzzed_data.ConsumeBool())
    ndpi_load_domain_suffixes(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : (char *)"invalid_filename"); /* Error */
  /* Note that this function is not used by ndpiReader */
  if(fuzzed_data.ConsumeBool()) {
    ndpi_load_ipv4_ptree(ndpi_info_mod, "invalid_filename", NDPI_PROTOCOL_TLS);
    ndpi_load_ipv4_ptree(ndpi_info_mod, "ipv4_addresses.txt", NDPI_PROTOCOL_TLS);
  }

  /* TODO: stub for geo stuff */
  ndpi_load_geoip(ndpi_info_mod, NULL, NULL);

  /* To trigger NDPI_CFG_CONTEXT_ALREADY_INITIALIZED */
  if(fuzzed_data.ConsumeBool()) {
    ret = ndpi_finalize_initialization(ndpi_info_mod);
    if(ret != 0) {
      ndpi_exit_detection_module(ndpi_info_mod);
      ndpi_info_mod = NULL;
    }
  }

  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 365 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "certificate_expiration_threshold", cfg_value);
    ndpi_get_config(ndpi_info_mod, "tls", "certificate_expiration_threshold", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "application_blocks_tracking", cfg_value);
    ndpi_get_config(ndpi_info_mod, "tls", "application_blocks_tracking", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "metadata.sha1_fingerprint", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "metadata.ja3c_fingerprint", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "metadata.ja3s_fingerprint", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "tls", "metadata.ja4c_fingerprint", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "smtp", "tls_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "imap", "tls_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "pop", "tls_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "ftp", "tls_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "stun", "tls_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 255 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "stun", "max_packets_extra_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "stun", "metadata.attribute.response_origin", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "stun", "metadata.attribute.other_address", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "stun", "metadata.attribute.mapped_address", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "dns", "subclassification", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "dns", "process_response", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "http", "process_response", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 0x01 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "ookla", "dpi.aggressiveness", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 255 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "zoom", "max_packets_extra_dissection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 0x01 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "rtp", "search_for_stun", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "any", "log", cfg_value);
    ndpi_get_config(ndpi_info_mod, "any", "log", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    pid = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, NDPI_MAX_SUPPORTED_PROTOCOLS + 1); /* + 1 to trigger invalid pid */
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    snprintf(cfg_proto, sizeof(cfg_proto), "%d", pid);
    /* TODO: we should try to map integer into name */
    ndpi_set_config(ndpi_info_mod, cfg_proto, "log", cfg_value);
    ndpi_get_config(ndpi_info_mod, cfg_proto, "log", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, "any", "ip_list.load", cfg_value);
    ndpi_get_config(ndpi_info_mod, "any", "ip_list.load", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    pid = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, NDPI_MAX_SUPPORTED_PROTOCOLS + 1); /* + 1 to trigger invalid pid */
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    snprintf(cfg_proto, sizeof(cfg_proto), "%d", pid);
    ndpi_set_config(ndpi_info_mod, cfg_proto, "ip_list.load", cfg_value);
    ndpi_get_config(ndpi_info_mod, cfg_proto, "ip_list.load", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 255 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "packets_limit_per_flow", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow.direction_detection", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow.track_payload", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "tcp_ack_payload_heuristic", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "fully_encrypted_heuristic", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "libgcrypt.init", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 0x03 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "dpi.guess_on_giveup", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "fpc", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow_risk_lists.load", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow_risk.anonymous_subscriber.list.icloudprivaterelay.load", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow_risk.anonymous_subscriber.list.protonvpn.load", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "flow_risk.crawler_bot.list.load", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    ndpi_set_config(ndpi_info_mod, NULL, "filename.config", fuzzed_data.ConsumeBool() ? NULL : (char *)"config.txt");
    ndpi_get_config(ndpi_info_mod, NULL, "filename.config", cfg_value, sizeof(cfg_value));
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 3 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "log.level", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.ookla.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.ookla.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.ookla.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.bittorrent.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.bittorrent.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.bittorrent.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.stun.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.stun.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.stun.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.tls_cert.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.tls_cert.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.tls_cert.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.mining.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.mining.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.mining.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.msteams.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.msteams.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.msteams.scope", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.fpc_dns.size", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.fpc_dns.ttl", cfg_value);
  }
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "lru.fpc_dns.scope", cfg_value);
  }
  /* Configure one cache via index */
  if(fuzzed_data.ConsumeBool()) {
    idx = fuzzed_data.ConsumeIntegralInRange(0, static_cast<int>(NDPI_LRUCACHE_MAX));
    name = ndpi_lru_cache_idx_to_name(static_cast<lru_cache_type>(idx));
    if(name) {
      value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 / 2); /* max / 2 instead of max + 1 to avoid oom on oss-fuzzer */
      snprintf(cfg_param, sizeof(cfg_param), "lru.%s.size", name);
      snprintf(cfg_value, sizeof(cfg_value), "%d", value);
      ndpi_set_config(ndpi_info_mod, NULL, cfg_param, cfg_value);
      ndpi_get_config(ndpi_info_mod, NULL, cfg_param, cfg_value, sizeof(cfg_value));
      value = fuzzed_data.ConsumeIntegralInRange(0, 16777215 + 1);
      snprintf(cfg_param, sizeof(cfg_param), "lru.%s.ttl", name);
      snprintf(cfg_value, sizeof(cfg_value), "%d", value);
      ndpi_set_config(ndpi_info_mod, NULL, cfg_param, cfg_value);
      value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
      snprintf(cfg_param, sizeof(cfg_param), "lru.%s.scope", name);
      snprintf(cfg_value, sizeof(cfg_value), "%d", value);
      ndpi_set_config(ndpi_info_mod, NULL, cfg_param, cfg_value);
      ndpi_get_config(ndpi_info_mod, NULL, cfg_param, cfg_value, sizeof(cfg_value));
    }
  }
  /* Invalid parameter */
  if(fuzzed_data.ConsumeBool()) {
    value = fuzzed_data.ConsumeIntegralInRange(0, 1 + 1);
    snprintf(cfg_value, sizeof(cfg_value), "%d", value);
    ndpi_set_config(ndpi_info_mod, NULL, "foo", cfg_value);
    ndpi_get_config(ndpi_info_mod, NULL, "foo", cfg_value, sizeof(cfg_value));
  }
  /* Invalid value */
  if(fuzzed_data.ConsumeBool()) {
    snprintf(cfg_value, sizeof(cfg_value), "%s", "jjj");
    ndpi_set_config(ndpi_info_mod, NULL, "lru.stun.ttl", cfg_value);
    ndpi_get_config(ndpi_info_mod, NULL, "lru.stun.ttl", cfg_value, sizeof(cfg_value));
  }

  ndpi_add_host_risk_mask(ndpi_info_mod,
                          (char *)fuzzed_data.ConsumeBytesAsString(32).c_str(),
                          static_cast<ndpi_risk>(fuzzed_data.ConsumeIntegral<u_int64_t>()));

  ndpi_finalize_initialization(ndpi_info_mod);

  /* Random protocol configuration */
  pid = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1); /* + 1 to trigger invalid pid */
  protoname = ndpi_get_proto_by_id(ndpi_info_mod, pid);
  if (protoname) {
    ndpi_get_proto_by_name(ndpi_info_mod, protoname);

    pid2 = fuzzed_data.ConsumeIntegralInRange<u_int16_t>(0, NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1); /* + 1 to trigger invalid pid */
    protoname2 = ndpi_get_proto_by_id(ndpi_info_mod, pid2);
    if(protoname2) {
      snprintf(pids_name, sizeof(pids_name), "%s.%s", protoname, protoname2);
      pids_name[sizeof(pids_name) - 1] = '\0';
      ndpi_get_protocol_by_name(ndpi_info_mod, pids_name);
    }
  }
  ndpi_map_user_proto_id_to_ndpi_id(ndpi_info_mod, pid);
  ndpi_map_ndpi_id_to_user_proto_id(ndpi_info_mod, pid);
  ndpi_set_proto_breed(ndpi_info_mod, pid, NDPI_PROTOCOL_SAFE);
  ndpi_set_proto_category(ndpi_info_mod, pid, NDPI_PROTOCOL_CATEGORY_MEDIA);
  ndpi_is_subprotocol_informative(pid);
  ndpi_get_proto_breed(ndpi_info_mod, pid);

  ndpi_port_range d_port[MAX_DEFAULT_PORTS] = {};
  ndpi_set_proto_defaults(ndpi_info_mod, 0, 0, NDPI_PROTOCOL_SAFE, pid,
                          protoname, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			  d_port, d_port);

  ndpi_get_proto_by_name(ndpi_info_mod, NULL); /* Error */
  ndpi_get_proto_by_name(ndpi_info_mod, "foo"); /* Invalid protocol */
  ndpi_get_proto_name(ndpi_info_mod, pid);

  struct in_addr pin;
  struct in6_addr pin6;
  u_int16_t suffix_id;
  
  pin.s_addr = fuzzed_data.ConsumeIntegral<u_int32_t>();
  ndpi_network_port_ptree_match(ndpi_info_mod, &pin, fuzzed_data.ConsumeIntegral<u_int16_t>());
  for(i = 0; i < 16; i++)
    pin6.s6_addr[i] = fuzzed_data.ConsumeIntegral<u_int8_t>();
  ndpi_network_port_ptree6_match(ndpi_info_mod, &pin6, fuzzed_data.ConsumeIntegral<u_int16_t>());

  ndpi_get_host_domain_suffix(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "www.bbc.co.uk", &suffix_id);
  ndpi_get_host_domain(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : "www.bbc.co.uk");

  /* Custom category configuration */
  cat = fuzzed_data.ConsumeIntegralInRange(static_cast<int>(NDPI_PROTOCOL_CATEGORY_CUSTOM_1),
                                           static_cast<int>(NDPI_PROTOCOL_NUM_CATEGORIES + 1)); /* + 1 to trigger invalid cat */
  ndpi_category_set_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat), catname);
  ndpi_is_custom_category(static_cast<ndpi_protocol_category_t>(cat));
  ndpi_category_get_name(ndpi_info_mod, static_cast<ndpi_protocol_category_t>(cat));
  ndpi_get_category_id(ndpi_info_mod, catname);

  ndpi_tunnel2str(static_cast<ndpi_packet_tunnel>(fuzzed_data.ConsumeIntegralInRange(static_cast<int>(ndpi_no_tunnel),
                                                                                     static_cast<int>(ndpi_gre_tunnel + 1)))); /* + 1 to trigger invalid value */

  ndpi_get_num_supported_protocols(ndpi_info_mod);
  ndpi_get_proto_defaults(ndpi_info_mod);
  ndpi_get_ndpi_num_custom_protocols(ndpi_info_mod);
  ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);

  ndpi_self_check_host_match(stdout);

  ndpi_dump_protocols(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : stdout);
  ndpi_generate_options(fuzzed_data.ConsumeIntegralInRange(0, 4), fuzzed_data.ConsumeBool() ? NULL : stdout);
  ndpi_dump_risks_score(fuzzed_data.ConsumeBool() ? NULL : stdout);
  ndpi_dump_config(ndpi_info_mod, fuzzed_data.ConsumeBool() ? NULL : stdout);

  char buf[8]; /* Too short in same cases... */
  if(fuzzed_data.ConsumeBool()) {
    ndpi_ssl_version2str(buf, sizeof(buf), fuzzed_data.ConsumeIntegral<u_int16_t>(), &unused);
    ndpi_get_ip_proto_name(fuzzed_data.ConsumeIntegral<u_int8_t>(), buf, sizeof(buf));
  } else {
    ndpi_ssl_version2str(NULL, 0, fuzzed_data.ConsumeIntegral<u_int16_t>(), &unused);
    ndpi_get_ip_proto_name(fuzzed_data.ConsumeIntegral<u_int8_t>(), NULL, 0);
  }
  ndpi_risk2str(static_cast<ndpi_risk_enum>(fuzzed_data.ConsumeIntegral<u_int64_t>()));
  ndpi_risk2code(static_cast<ndpi_risk_enum>(fuzzed_data.ConsumeIntegral<u_int64_t>()));
  ndpi_code2risk(ndpi_risk2code(static_cast<ndpi_risk_enum>(fuzzed_data.ConsumeIntegralInRange(0, NDPI_MAX_RISK + 1))));
  ndpi_severity2str(static_cast<ndpi_risk_severity>(fuzzed_data.ConsumeIntegral<u_int8_t>()));
  ndpi_risk2score(static_cast<ndpi_risk_enum>(fuzzed_data.ConsumeIntegral<u_int64_t>()), &unused1, &unused2);
  ndpi_http_method2str(static_cast<ndpi_http_method>(fuzzed_data.ConsumeIntegral<u_int8_t>()));
  ndpi_confidence_get_name(static_cast<ndpi_confidence_t>(fuzzed_data.ConsumeIntegral<u_int8_t>()));
  ndpi_fpc_confidence_get_name(static_cast<ndpi_fpc_confidence_t>(fuzzed_data.ConsumeIntegral<u_int8_t>()));
  ndpi_get_proto_breed_name(static_cast<ndpi_protocol_breed_t>(fuzzed_data.ConsumeIntegral<u_int8_t>()));
  ndpi_get_l4_proto_name(static_cast<ndpi_l4_proto_info>(fuzzed_data.ConsumeIntegral<u_int8_t>()));

  char buf2[16];
  ndpi_entropy2str(fuzzed_data.ConsumeFloatingPoint<float>(), fuzzed_data.ConsumeBool() ? buf2 : NULL, sizeof(buf2));

  /* Basic code to try testing this "config" */
  bool_value = fuzzed_data.ConsumeBool();
  input_info.in_pkt_dir = fuzzed_data.ConsumeIntegralInRange(0,2);
  input_info.seen_flow_beginning = !!fuzzed_data.ConsumeBool();
  memset(&flow, 0, sizeof(flow));
  std::vector<uint8_t>pkt = fuzzed_data.ConsumeRemainingBytes<uint8_t>();

  const u_int8_t *l4_return;
  u_int16_t l4_len_return;
  u_int8_t l4_protocol_return;
  ndpi_detection_get_l4(pkt.data(), pkt.size(), &l4_return, &l4_len_return, &l4_protocol_return, NDPI_DETECTION_ONLY_IPV6);
  ndpi_detection_get_l4(pkt.data(), pkt.size(), &l4_return, &l4_len_return, &l4_protocol_return, NDPI_DETECTION_ONLY_IPV4);

  ndpi_detection_process_packet(ndpi_info_mod, &flow, pkt.data(), pkt.size(), 0, &input_info);
  p = ndpi_detection_giveup(ndpi_info_mod, &flow, &protocol_was_guessed);

  assert(p.proto.master_protocol == ndpi_get_flow_masterprotocol(&flow));
  assert(p.proto.app_protocol == ndpi_get_flow_appprotocol(&flow));
  assert(p.category == ndpi_get_flow_category(&flow));
  ndpi_get_lower_proto(p);
  ndpi_get_upper_proto(p);
  ndpi_get_flow_error_code(&flow);
  ndpi_get_flow_risk_info(&flow, out, sizeof(out), 1);
  ndpi_get_flow_ndpi_proto(&flow, &p2);
  ndpi_is_proto(p.proto, NDPI_PROTOCOL_TLS);
  ndpi_http_method2str(flow.http.method);
  ndpi_is_subprotocol_informative(p.proto.app_protocol);
  ndpi_get_http_method(bool_value ? &flow : NULL);
  ndpi_get_http_url(&flow);
  ndpi_get_http_content_type(&flow);
  ndpi_get_flow_name(bool_value ? &flow : NULL);
  /* ndpi_guess_undetected_protocol() is a "strange" function. Try fuzzing it, here */
  if(!ndpi_is_protocol_detected(p)) {
    ndpi_guess_undetected_protocol(ndpi_info_mod, bool_value ? &flow : NULL,
                                   flow.l4_proto);
    if(!flow.is_ipv6) {
      /* Another "strange" function (ipv4 only): fuzz it here, for lack of a better alternative */
      ndpi_find_ipv4_category_userdata(ndpi_info_mod, flow.c_address.v4);

      ndpi_search_tcp_or_udp_raw(ndpi_info_mod, NULL, ntohl(flow.c_address.v4), ntohl(flow.s_address.v4));

      ndpi_guess_undetected_protocol_v4(ndpi_info_mod, bool_value ? &flow : NULL,
                                        flow.l4_proto,
                                        flow.c_address.v4, flow.c_port,
                                        flow.s_address.v4, flow.s_port);
    } else {
      ndpi_find_ipv6_category_userdata(ndpi_info_mod, bool_value ? NULL : (struct in6_addr *)flow.c_address.v6);
    }
    /* Another "strange" function: fuzz it here, for lack of a better alternative */
    ndpi_search_tcp_or_udp(ndpi_info_mod, &flow);
  }
  if(!flow.is_ipv6) {
    if(bool_value)
      ndpi_network_risk_ptree_match(ndpi_info_mod, (struct in_addr *)&flow.c_address.v4);

    ndpi_risk_params params[] = { { NDPI_PARAM_HOSTNAME, flow.host_server_name},
                                  { NDPI_PARAM_ISSUER_DN, (void *)("CN=813845657003339838, O=Code42, OU=TEST, ST=MN, C=US") /* from example/protos.txt */},
                                  { NDPI_PARAM_HOST_IPV4, &flow.c_address.v4} };
    ndpi_check_flow_risk_exceptions(ndpi_info_mod, 3, params);

    ndpi_risk_params params2[] = { { NDPI_MAX_RISK_PARAM_ID, &flow.c_address.v4} }; /* Invalid */
    ndpi_check_flow_risk_exceptions(ndpi_info_mod, 1, params2);
  }
  /* TODO: stub for geo stuff */
  ndpi_get_geoip_asn(ndpi_info_mod, NULL, NULL);
  ndpi_get_geoip_country_continent(ndpi_info_mod, NULL, NULL, 0, NULL, 0);

  ndpi_free_flow_data(&flow);

  /* Get some final stats */
  for(i = 0; i < NDPI_LRUCACHE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_lru_cache_stats(g_ctx, ndpi_info_mod, static_cast<lru_cache_type>(i), &lru_stats);
  for(i = 0; i < NDPI_PTREE_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_patricia_stats(ndpi_info_mod, static_cast<ptree_type>(i), &patricia_stats);
  for(i = 0; i < NDPI_AUTOMA_MAX + 1; i++) /* + 1 to test invalid type */
    ndpi_get_automa_stats(ndpi_info_mod, static_cast<automa_type>(i), &automa_stats);


  ndpi_revision();
  ndpi_get_api_version();
  ndpi_get_gcrypt_version();

  ndpi_get_ndpi_detection_module_size();
  ndpi_detection_get_sizeof_ndpi_flow_struct();
  ndpi_detection_get_sizeof_ndpi_flow_tcp_struct();
  ndpi_detection_get_sizeof_ndpi_flow_udp_struct();

  ndpi_get_tot_allocated_memory();
  ndpi_log_timestamp(log_ts, sizeof(log_ts));

  ndpi_free_geoip(ndpi_info_mod);

  ndpi_exit_detection_module(ndpi_info_mod);

  ndpi_global_deinit(g_ctx);

  return 0;
}
