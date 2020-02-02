#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
struct ndpi_id_struct *src;
struct ndpi_id_struct *dst;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (ndpi_info_mod == NULL) {
    ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);
    src = ndpi_malloc(SIZEOF_ID_STRUCT);
    dst = ndpi_malloc(SIZEOF_ID_STRUCT);
  }

  struct ndpi_flow_struct *ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
  memset(src, 0, SIZEOF_ID_STRUCT);
  memset(dst, 0, SIZEOF_ID_STRUCT);
  ndpi_detection_process_packet(ndpi_info_mod, ndpi_flow, Data, Size, 0, src, dst);
  ndpi_free_flow(ndpi_flow);

  return 0;
}
