#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  ndpi_filter *f;
  u_int32_t value, value_added;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  f = ndpi_filter_alloc();

  num_iteration = fuzzed_data.ConsumeIntegral<u_int16_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int32_t>();

    ndpi_filter_add(f, value);
    /* Keep one random entry really added */
    if (is_added == 0 && fuzzed_data.ConsumeBool()) {
      value_added = value;
      is_added = 1;
    }

    ndpi_filter_add_string(f, (char *)fuzzed_data.ConsumeRandomLengthString(32).c_str());
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int32_t>();

    ndpi_filter_contains(f, value);
  }
  /* Search of an added entry */
  if (is_added) {
    ndpi_filter_contains(f, value_added);
  }

  ndpi_filter_contains_string(f, (char *)fuzzed_data.ConsumeRandomLengthString(32).c_str());

  ndpi_filter_size(f);
  ndpi_filter_cardinality(f);

  ndpi_filter_free(f);
  return 0;
}
