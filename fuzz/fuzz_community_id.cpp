#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int8_t is_ipv6, l4_proto, icmp_type, icmp_code;
  u_int16_t src_port, dst_port;
  u_char *hash_buf;
  u_int8_t hash_buf_len;

  /* Just to have some data */

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  is_ipv6 = fuzzed_data.ConsumeBool();
  l4_proto = fuzzed_data.ConsumeIntegral<u_int8_t>();
  src_port = fuzzed_data.ConsumeIntegral<u_int16_t>();
  dst_port = fuzzed_data.ConsumeIntegral<u_int16_t>();
  icmp_type = fuzzed_data.ConsumeIntegral<u_int8_t>();
  icmp_code = fuzzed_data.ConsumeIntegral<u_int8_t>();
  hash_buf_len = fuzzed_data.ConsumeIntegralInRange(0, 64);
  hash_buf = (u_char *)ndpi_malloc(hash_buf_len);
  if (!hash_buf)
    return 0;

  if (!is_ipv6) {
    u_int32_t src_ip, dst_ip;

    src_ip = fuzzed_data.ConsumeIntegral<u_int32_t>();
    dst_ip = fuzzed_data.ConsumeIntegral<u_int32_t>();

    ndpi_flowv4_flow_hash(l4_proto, src_ip, dst_ip, src_port, dst_port,
                          icmp_type, icmp_code, hash_buf, hash_buf_len);
  } else {
    u_char *src_ip, *dst_ip;

    if(fuzzed_data.remaining_bytes() >= 32) {
      std::vector<u_int8_t>data1 = fuzzed_data.ConsumeBytes<u_int8_t>(16);
      src_ip = data1.data();
      std::vector<u_int8_t>data2 = fuzzed_data.ConsumeBytes<u_int8_t>(16);
      dst_ip = data2.data();

      ndpi_flowv6_flow_hash(l4_proto, (struct ndpi_in6_addr *)src_ip,
                            (struct ndpi_in6_addr *)dst_ip, src_port, dst_port,
                            icmp_type, icmp_code, hash_buf, hash_buf_len);
    }
  }

  ndpi_free(hash_buf);

  return 0;
}
