#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  struct ndpi_cm_sketch *sketch;
  u_int16_t i, num_hashes, num_iteration, num_lookup;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  num_hashes = fuzzed_data.ConsumeIntegralInRange(0, 8192);
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_lookup = fuzzed_data.ConsumeIntegral<u_int8_t>();

  sketch = ndpi_cm_sketch_init(num_hashes);
  if (sketch) {
    for (i = 0; i < num_iteration; i++) { 
      ndpi_cm_sketch_add(sketch, fuzzed_data.ConsumeIntegral<u_int32_t>());
    }
    for (i = 0; i < num_lookup; i++) { 
      ndpi_cm_sketch_count(sketch, fuzzed_data.ConsumeIntegral<u_int32_t>());
    }
    ndpi_cm_sketch_destroy(sketch);
  }

  return 0;
}
