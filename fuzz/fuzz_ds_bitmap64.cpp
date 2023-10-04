#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  ndpi_bitmap64 *b;
  bool rc;
  u_int64_t value, value_added;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  b = ndpi_bitmap64_alloc();

  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap64_compress(b);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int16_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();

    rc = ndpi_bitmap64_set(b, value);
    /* Keep one random entry really added */
    if (rc == true && is_added == 0 && fuzzed_data.ConsumeBool()) {
      value_added = value;
      is_added = 1;
    }
  }

  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap64_compress(b);

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();

    ndpi_bitmap64_isset(b, value);
  }
  /* Search of an added entry */
  if (is_added) {
    ndpi_bitmap64_isset(b, value_added);
  }

  ndpi_bitmap64_size(b);

  ndpi_bitmap64_free(b);

  return 0;
}
