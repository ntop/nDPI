#include "ndpi_api.h"
#include "fuzz_common_code.h"
#include "reader_util.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

char *_debug_protocols;
int nDPI_LogLevel = 0;
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
ndpi_init_prefs init_prefs = ndpi_track_flow_payload | ndpi_enable_ja3_plus | ndpi_enable_tcp_ack_payload_heuristic;
int enable_malloc_bins = 0;
int malloc_size_stats = 0;
int max_malloc_bins = 14;
struct ndpi_bin malloc_bins; /* unused */


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  int inverted_logic;
  NDPI_PROTOCOL_BITMASK bitmask;
  char *str;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  inverted_logic = size % 2; /* pseudo-random */
  if(inverted_logic) {
    NDPI_BITMASK_SET_ALL(bitmask);
  } else {
    NDPI_BITMASK_RESET(bitmask);
  }

  str = (char *)ndpi_malloc(size + 1); /* We need a null-terminated string */
  if(str) {
    memcpy(str, data, size);
    str[size] = '\0';

    parse_proto_name_list(str, &bitmask, inverted_logic);

    ndpi_free(str);
  }
  return 0;
}
