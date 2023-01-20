#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, num_learning_values;
  struct ndpi_jitter_struct s;
  int rc;

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  num_learning_values = fuzzed_data.ConsumeIntegral<u_int16_t>();
  rc = ndpi_jitter_init(&s, num_learning_values);

  if (rc == 0) {
    num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
    for (i = 0; i < num_iteration; i++)
      ndpi_jitter_add_value(&s, fuzzed_data.ConsumeFloatingPoint<float>());

    ndpi_jitter_free(&s);
  }

  return 0;
}
