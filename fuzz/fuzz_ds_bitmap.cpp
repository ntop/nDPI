#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  ndpi_bitmap *a, *a2, *b, *c;
  size_t buf_size;
  char *buf;
  u_int64_t value, value_added;
  ndpi_bitmap_iterator *iter;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  a = ndpi_bitmap_alloc();

  num_iteration = fuzzed_data.ConsumeIntegral<u_int16_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();

    ndpi_bitmap_set(a, value);
    /* Keep one random entry really added */
    if (is_added == 0 && fuzzed_data.ConsumeBool()) {
      value_added = value;
      is_added = 1;
    }
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();

    ndpi_bitmap_isset(a, value);
  }
  /* Search of an added entry */
  if (is_added) {
    ndpi_bitmap_isset(a, value_added);
  }

  a2 = ndpi_bitmap_copy(a);

  /* "Random" unset */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();

    ndpi_bitmap_unset(a, value);
  }
  /* Unset of an added entry */
  if (is_added) {
    ndpi_bitmap_unset(a, value_added);
  }

  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap_optimize(a);

  ndpi_bitmap_is_empty(a);
  ndpi_bitmap_cardinality(a);

  buf_size = ndpi_bitmap_serialize(a, &buf);
  b = ndpi_bitmap_deserialize(buf, buf_size);
  ndpi_bitmap_free(b);
  ndpi_free(buf);

  iter = ndpi_bitmap_iterator_alloc(a);
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeIntegral<u_int64_t>();
    ndpi_bitmap_iterator_next(iter, &value);
  }
  ndpi_bitmap_iterator_free(iter);

  c = ndpi_bitmap_and_alloc(a, a2);
  ndpi_bitmap_free(c);

  c = ndpi_bitmap_or_alloc(a, a2);
  ndpi_bitmap_free(c);

  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap_and(a, a2);
  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap_andnot(a, a2);
  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap_or(a, a2);
  if(fuzzed_data.ConsumeBool())
    ndpi_bitmap_xor(a, a2);

  ndpi_bitmap_free(a);
  ndpi_bitmap_free(a2);

  return 0;
}
