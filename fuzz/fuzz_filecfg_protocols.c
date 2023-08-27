#include "ndpi_api.h"
#include "fuzz_common_code.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_detection_module_struct *ndpi_struct;
  FILE *fd;
  /* Try to be fast */
  ndpi_init_prefs prefs = ndpi_dont_load_tor_list |
			  ndpi_dont_load_azure_list |
			  ndpi_dont_load_whatsapp_list |
			  ndpi_dont_load_amazon_aws_list |
			  ndpi_dont_load_ethereum_list |
			  ndpi_dont_load_zoom_list |
			  ndpi_dont_load_cloudflare_list |
			  ndpi_dont_load_microsoft_list |
			  ndpi_dont_load_google_list |
			  ndpi_dont_load_google_cloud_list |
			  ndpi_dont_load_asn_lists |
			  ndpi_dont_init_risk_ptree |
			  ndpi_dont_load_cachefly_list |
			  ndpi_dont_load_protonvpn_list |
			  ndpi_dont_load_mullvad_list;
  NDPI_PROTOCOL_BITMASK all;
  NDPI_PROTOCOL_BITMASK debug_bitmask;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_struct = ndpi_init_detection_module(prefs);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  NDPI_BITMASK_SET_ALL(debug_bitmask);
  ndpi_set_log_level(ndpi_struct, 4);
  ndpi_set_debug_bitmask(ndpi_struct, debug_bitmask);

  fd = buffer_to_file(data, size);
  ndpi_load_protocols_file2(ndpi_struct, fd);
  if(fd)
    fclose(fd);

  /* We don't really need to call ndpi_finalize_initialization */
 
  ndpi_exit_detection_module(ndpi_struct);
  return 0;
}
