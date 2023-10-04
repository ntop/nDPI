#include "fuzz_common_code.h"
#include "../src/lib/third_party/include/binaryfusefilter.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  bool rc;
  u_int64_t *values, value;
  binary_fuse8_t filter8;
  binary_fuse16_t filter16;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  size = fuzzed_data.ConsumeIntegral<u_int16_t>();
  values = (u_int64_t *)ndpi_calloc(size, sizeof(u_int64_t));
  if (!values)
    return 0;
  for (i = 0; i < size; i++) {
    values[i] = fuzzed_data.ConsumeIntegral<u_int64_t>();
  }

  rc = binary_fuse8_allocate(size, &filter8);
  if (rc) {
    rc = binary_fuse8_populate(values, size, &filter8);

    if (rc) {
      /* "Random" search */
      num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
      for (i = 0; i < num_iteration; i++) {
        value = fuzzed_data.ConsumeIntegral<u_int64_t>();
        binary_fuse8_contain(value, &filter8);
      }
      /* Search of an added entry */
      if (size > 0)
        binary_fuse8_contain(values[0], &filter8);
    }
    binary_fuse8_free(&filter8);
  }

  rc = binary_fuse16_allocate(size, &filter16);
  if (rc) {
    rc = binary_fuse16_populate(values, size, &filter16);

    if (rc) {
      /* "Random" search */
      num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
      for (i = 0; i < num_iteration; i++) {
        value = fuzzed_data.ConsumeIntegral<u_int64_t>();
        binary_fuse16_contain(value, &filter16);
      }
      /* Search of an added entry */
      if (size > 0)
        binary_fuse16_contain(values[0], &filter16);
    }
    binary_fuse16_free(&filter16);
  }

  ndpi_free(values);

  return 0;
}
