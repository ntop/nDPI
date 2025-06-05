#include "ndpi_api.h"
#include "fuzz_common_code.h"
#include "reader_util.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

u_int8_t enable_payload_analyzer = 0;
u_int8_t enable_flow_stats = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
int malloc_size_stats = 0;
FILE *fingerprint_fp = NULL;
bool do_load_lists = false;
char *addr_dump_path = NULL;
int monitoring_enabled = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  int inverted_logic;
  struct ndpi_bitmask bitmask;
  char *str;

  ndpi_bitmask_alloc(&bitmask, ndpi_get_num_internal_protocols()); /* Don't make this call to fail...*/

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  inverted_logic = size % 2; /* pseudo-random */
  if(inverted_logic) {
    ndpi_bitmask_set_all(&bitmask);
  } else {
    ndpi_bitmask_reset(&bitmask);
  }

  str = (char *)ndpi_malloc(size + 1); /* We need a null-terminated string */
  if(str) {
    memcpy(str, data, size);
    str[size] = '\0';

    parse_proto_name_list(str, &bitmask, inverted_logic);

    ndpi_free(str);
  }

  ndpi_bitmask_dealloc(&bitmask);

  return 0;
}
