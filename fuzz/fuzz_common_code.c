
#include "fuzz_common_code.h"

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod,
				int enable_log)
{
  ndpi_init_prefs prefs = ndpi_enable_ja3_plus;
  NDPI_PROTOCOL_BITMASK all, debug_bitmask;

  if(*ndpi_info_mod == NULL) {
    *ndpi_info_mod = ndpi_init_detection_module(prefs);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(*ndpi_info_mod, &all);

    if(enable_log) {
      NDPI_BITMASK_SET_ALL(debug_bitmask);
      ndpi_set_log_level(*ndpi_info_mod, 4);
      ndpi_set_debug_bitmask(*ndpi_info_mod, debug_bitmask);
    }

    ndpi_load_protocols_file(*ndpi_info_mod, "protos.txt");
    ndpi_load_categories_file(*ndpi_info_mod, "categories.txt", NULL);
    ndpi_load_risk_domain_file(*ndpi_info_mod, "risky_domains.txt");
    ndpi_load_malicious_ja3_file(*ndpi_info_mod, "ja3_fingerprints.csv");
    ndpi_load_malicious_sha1_file(*ndpi_info_mod, "sha1_fingerprints.csv");

    ndpi_finalize_initialization(*ndpi_info_mod);
  }
}


