#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  ndpi_ptree_t *t;
  ndpi_ip_addr_t addr, addr2, addr_added;
  u_int8_t bits;
  int rc, is_added = 0;
  u_int64_t user_data;
  char buf_ip[256];

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  t = ndpi_ptree_create();

  /* Random insert */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (fuzzed_data.ConsumeBool()) {
      if(fuzzed_data.remaining_bytes() > 16) {
	memcpy(&addr.ipv6, fuzzed_data.ConsumeBytes<u_int8_t>(16).data(), 16);
        bits = fuzzed_data.ConsumeIntegralInRange(0, 128);
      } else {
        continue;
      }
    } else {
      memset(&addr, '\0', sizeof(addr));
      addr.ipv4 = fuzzed_data.ConsumeIntegral<u_int32_t>();
      bits = fuzzed_data.ConsumeIntegralInRange(0, 32);
    };

    /* Not really ptree stuff, but this seem the right place to fuzz these `ndpi_ip_addr_t` functions */
    ndpi_parse_ip_string(ndpi_get_ip_string(&addr, buf_ip, sizeof(buf_ip)), &addr2);

    rc = ndpi_ptree_insert(t, &addr, bits, 0);
    /* Keep one random node really added */
    if (rc == 0 && is_added == 0 && fuzzed_data.ConsumeBool()) {
      is_added = 1;
      addr_added = addr;
    }
  }

  /* Some higher level functions */
  ndpi_load_ipv4_ptree_file(t, "ipv4_addresses.txt", NDPI_PROTOCOL_TLS);
  ndpi_load_ipv4_ptree_file(t, "invalid_filename", NDPI_PROTOCOL_TLS);
  ndpi_load_ipv6_ptree_file(t, "ipv6_addresses.txt", NDPI_PROTOCOL_TLS);
  ndpi_load_ipv6_ptree_file(t, "invalid_filename", NDPI_PROTOCOL_TLS);

  /* Random search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (fuzzed_data.ConsumeBool()) {
      if(fuzzed_data.remaining_bytes() > 16) {
	memcpy(&addr.ipv6, fuzzed_data.ConsumeBytes<u_int8_t>(16).data(), 16);
      } else {
        continue;
      }
    } else {
      memset(&addr, '\0', sizeof(addr));
      addr.ipv4 = fuzzed_data.ConsumeIntegral<u_int32_t>();
    };

    ndpi_ptree_match_addr(t, &addr, &user_data);
  }
  /* Search of an added node */
  if (is_added)
    ndpi_ptree_match_addr(t, &addr_added, &user_data);

  ndpi_ptree_destroy(t);

  return 0;
}
