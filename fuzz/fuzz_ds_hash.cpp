#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t value16, i, rc, num_iteration, data_len, is_added = 0;
  std::vector<char>value_added;
  ndpi_str_hash *h = NULL;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  if (fuzzed_data.ConsumeBool())
    ndpi_hash_init(&h);
  else
    ndpi_hash_init(NULL);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {

    data_len = fuzzed_data.ConsumeIntegralInRange(0, 127);
    std::vector<char>data = fuzzed_data.ConsumeBytes<char>(data_len);

    rc = ndpi_hash_add_entry(&h, data.data(), data.size(), i);
    /* Keep one random entry really added */
    if (rc == 0 && fuzzed_data.ConsumeBool()) {
      value_added = data;
      is_added = 1;
    }
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    data_len = fuzzed_data.ConsumeIntegralInRange(0, 127);
    std::vector<char>data = fuzzed_data.ConsumeBytes<char>(data_len);

    ndpi_hash_find_entry(h, data.data(), data.size(), &value16);
  }
  /* Search of an added entry */
  if (is_added) {
    ndpi_hash_find_entry(h, value_added.data(), value_added.size(), &value16);
  }

  if (fuzzed_data.ConsumeBool())
    ndpi_hash_free(NULL);

  ndpi_hash_free(&h);

  return 0;
}
