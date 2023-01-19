#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t j, i, num_iteration;
  struct ndpi_bin b, *b_cloned, *bins;
  u_int16_t num_bins, num_cluster_ids, num_element, num_allocated_bins, rc;
  enum ndpi_bin_family family;
  u_int16_t *cluster_ids;
  char buf[128];

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 2048)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  num_bins = fuzzed_data.ConsumeIntegral<u_int16_t>();
  family = fuzzed_data.ConsumeEnum<enum ndpi_bin_family>();

  ndpi_init_bin(&b, family, num_bins);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++)
    ndpi_inc_bin(&b, fuzzed_data.ConsumeIntegral<u_int16_t>(),
                 fuzzed_data.ConsumeIntegral<u_int64_t>());

  b_cloned = ndpi_clone_bin(&b);

  ndpi_bin_similarity(&b, b_cloned, fuzzed_data.ConsumeBool(),
                      fuzzed_data.ConsumeFloatingPointInRange<float>(0, 1));

  for (i = 0; i < num_iteration; i++)
    ndpi_get_bin_value(&b, fuzzed_data.ConsumeIntegral<u_int16_t>());

  ndpi_reset_bin(&b);

  for (i = 0; i < num_iteration; i++)
    ndpi_get_bin_value(&b, fuzzed_data.ConsumeIntegral<u_int16_t>());

  for (i = 0; i < num_iteration; i++)
    ndpi_set_bin(b_cloned, fuzzed_data.ConsumeIntegral<u_int16_t>(),
                 fuzzed_data.ConsumeIntegral<u_int64_t>());

  ndpi_bin_similarity(&b, b_cloned, fuzzed_data.ConsumeBool(),
                      fuzzed_data.ConsumeFloatingPointInRange<float>(0, 1));

  ndpi_normalize_bin(&b);
  ndpi_normalize_bin(b_cloned);

  ndpi_print_bin(&b, fuzzed_data.ConsumeBool(), buf, sizeof(buf));

  ndpi_free_bin(&b);
  ndpi_free_bin(b_cloned);
  ndpi_free(b_cloned);

  /* Cluster */

  num_bins = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_element = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_cluster_ids = fuzzed_data.ConsumeIntegral<u_int16_t>();
  bins = (struct ndpi_bin *)ndpi_malloc(sizeof(struct ndpi_bin) * num_bins);
  cluster_ids = (u_int16_t *)ndpi_malloc(sizeof(u_int16_t) * num_bins);

  num_allocated_bins = 0;
  if (bins && cluster_ids) {
    for (i = 0; i < num_bins; i++) {
      rc = ndpi_init_bin(&bins[num_allocated_bins], ndpi_bin_family64 /* Use 64 bit to avoid overlaps */,
                         num_element);
      if (rc != 0) {
        continue;
      }
      num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
      for (j = 0; j < num_iteration; j++) {
        ndpi_set_bin(&bins[num_allocated_bins],
                     fuzzed_data.ConsumeIntegralInRange(0, num_element + 1),
                     fuzzed_data.ConsumeIntegral<u_int64_t>());
      }
      num_allocated_bins++;
    }
    ndpi_cluster_bins(bins, num_allocated_bins, num_cluster_ids, cluster_ids, NULL);
  }

  ndpi_free(cluster_ids);
  if (bins)
    for (i = 0; i < num_allocated_bins; i++)
      ndpi_free_bin(&bins[i]);
  ndpi_free(bins);

  return 0;
}
