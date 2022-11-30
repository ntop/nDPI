#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static ndpi_serializer json_serializer = {};
static ndpi_serializer csv_serializer = {};

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  uint8_t protocol_was_guessed;

  if (ndpi_info_mod == NULL) {
    ndpi_info_mod = ndpi_init_detection_module(ndpi_enable_ja3_plus);
    NDPI_PROTOCOL_BITMASK all, debug_bitmask;
    NDPI_BITMASK_SET_ALL(all);
    NDPI_BITMASK_SET_ALL(debug_bitmask);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);
    ndpi_set_log_level(ndpi_info_mod, 4);
    ndpi_set_debug_bitmask(ndpi_info_mod, debug_bitmask);
    ndpi_finalize_initialization(ndpi_info_mod);
    ndpi_init_serializer(&json_serializer, ndpi_serialization_format_json);
    ndpi_init_serializer(&csv_serializer, ndpi_serialization_format_csv);
  }

  struct ndpi_flow_struct *ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
  ndpi_protocol detected_protocol =
    ndpi_detection_process_packet(ndpi_info_mod, ndpi_flow, Data, Size, 0, NULL);
  ndpi_protocol guessed_protocol =
    ndpi_detection_giveup(ndpi_info_mod, ndpi_flow, 1, &protocol_was_guessed);

  ndpi_reset_serializer(&json_serializer);
  ndpi_reset_serializer(&csv_serializer);
  if (protocol_was_guessed == 0)
  {
    ndpi_dpi2json(ndpi_info_mod, ndpi_flow, detected_protocol, &json_serializer);
    ndpi_dpi2json(ndpi_info_mod, ndpi_flow, detected_protocol, &csv_serializer);
  } else {
    ndpi_dpi2json(ndpi_info_mod, ndpi_flow, guessed_protocol, &json_serializer);
    ndpi_dpi2json(ndpi_info_mod, ndpi_flow, guessed_protocol, &csv_serializer);
  }
  ndpi_free_flow(ndpi_flow);

  return 0;
}
