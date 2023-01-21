#include "ndpi_api.h"
#include "../src/lib/third_party/include/libcache.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, rc, num_iteration, data_len, is_added = 0;
  std::vector<u_int8_t>value_added;
  cache_t c;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 2048)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  c = cache_new(fuzzed_data.ConsumeIntegral<u_int8_t>());

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {

    data_len = fuzzed_data.ConsumeIntegralInRange(0, 127);
    std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(data_len);

    rc = cache_add(c, data.data(), data.size());
    /* Keep one random entry really added */
    if (rc == CACHE_NO_ERROR && is_added == 0 && fuzzed_data.ConsumeBool()) {
      value_added = data;
      is_added = 1;
    }
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    data_len = fuzzed_data.ConsumeIntegralInRange(0, 127);
    std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(data_len);

    cache_contains(c, data.data(), data.size());
  }
  /* Search of an added entry */
  if (is_added) {
    cache_contains(c, value_added.data(), value_added.size());
  }

  /* "Random" remove */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    data_len = fuzzed_data.ConsumeIntegralInRange(0, 127);
    std::vector<u_int8_t>data = fuzzed_data.ConsumeBytes<u_int8_t>(data_len);

    cache_remove(c, data.data(), data.size());
  }
  /* Remove of an added entry */
  if (is_added) {
    cache_remove(c, value_added.data(), value_added.size());
  }

  cache_free(c);

  return 0;
}
