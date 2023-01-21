#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

static int __compare(const void *a, const void *b)
{
  u_int32_t *entry_a, *entry_b;

  entry_a = (u_int32_t *)a;
  entry_b = (u_int32_t *)b;

  return entry_a == entry_b ? 0 : (entry_a < entry_b ? -1 : +1);
}
static void __free(void * const node)
{
  u_int32_t *entry = (u_int32_t *)node;
  ndpi_free(entry);
}
static void __walk(const void *a, ndpi_VISIT which, int depth, void *user_data)
{
  assert(user_data == NULL);
  assert(a);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  void *root = NULL;
  u_int32_t *entry, value_added, e;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    entry = (u_int32_t *)ndpi_malloc(sizeof(u_int32_t));
    if (!entry)
	    continue;
    *entry = fuzzed_data.ConsumeIntegral<u_int32_t>();
    
    if(ndpi_tfind(entry, &root, __compare) == NULL) {
      if(ndpi_tsearch(entry, &root, __compare) == NULL) {
        ndpi_free(entry);
      } else {
        /* Keep one random entry really added */
        if (is_added == 0 && fuzzed_data.ConsumeBool()) {
          value_added = *entry;
          is_added = 1;
        }
      }
    } else {
      ndpi_free(entry);
    }
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    e = fuzzed_data.ConsumeIntegral<u_int32_t>();

    ndpi_tfind(&e, &root, __compare);
  }
  /* Search of an added node */
  if (is_added) {
    ndpi_tfind(&value_added, &root, __compare);
  }

  ndpi_twalk(root, __walk, NULL);

  /* "Random" delete */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    e = fuzzed_data.ConsumeIntegral<u_int32_t>();

    ndpi_tdelete(&e, &root, __compare);
  }
  /* Delete of an added node */
  if (is_added) {
    ndpi_tdelete(&value_added, &root, __compare);
  }

  ndpi_twalk(root, __walk, NULL);

  ndpi_tdestroy(root, __free);

  return 0;
}
