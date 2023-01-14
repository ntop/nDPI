#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  struct ndpi_hll hll;

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 2048)
    return -1;

  /* We don't really need the detection module, but this way we can enable
     memory allocation failures */
  if (ndpi_info_mod == NULL) {
    fuzz_init_detection_module(&ndpi_info_mod, 0);
  }

  ndpi_hll_init(&hll, fuzzed_data.ConsumeIntegral<u_int16_t>());

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++)
    ndpi_hll_add_number(&hll, fuzzed_data.ConsumeIntegral<u_int32_t>());

  ndpi_hll_count(&hll);

  ndpi_hll_reset(&hll);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    std::vector<int8_t>data = fuzzed_data.ConsumeBytes<int8_t>(fuzzed_data.ConsumeIntegral<u_int8_t>());
    ndpi_hll_add(&hll, (char *)data.data(), data.size());
  }

  ndpi_hll_count(&hll);

  ndpi_hll_destroy(&hll);

  return 0;
}
