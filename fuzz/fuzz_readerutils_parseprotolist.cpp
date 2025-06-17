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
  char *str;
  struct ndpi_global_context *g_ctx;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  g_ctx = ndpi_global_init();

  inverted_logic = size % 2; /* pseudo-random */

  str = (char *)ndpi_malloc(size + 1); /* We need a null-terminated string */
  if(str) {
    memcpy(str, data, size);
    str[size] = '\0';

    parse_proto_name_list(g_ctx, str, inverted_logic);

    ndpi_free(str);
  }

  ndpi_global_deinit(g_ctx);

  return 0;
}
