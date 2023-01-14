#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t j, i, num_iteration;
  struct ndpi_bin b, *b_cloned, *bins;
  u_int16_t num_bins, num_cluster_ids, num_element;
  enum ndpi_bin_family family;
  u_int16_t *cluster_ids;

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 2048)
    return -1;

  /* We don't really need the detection module, but this way we can enable
     memory allocation failures */
  if (ndpi_info_mod == NULL) {
    fuzz_init_detection_module(&ndpi_info_mod, 0);
  }

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

  ndpi_free_bin(&b);
  ndpi_free_bin(b_cloned);
  ndpi_free(b_cloned);

  /* Cluster */

  num_bins = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_element = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_cluster_ids = fuzzed_data.ConsumeIntegral<u_int16_t>();
  bins = (struct ndpi_bin *)ndpi_malloc(sizeof(struct ndpi_bin) * num_bins);
  cluster_ids = (u_int16_t *)ndpi_malloc(sizeof(u_int16_t) * num_bins);

  if (bins && cluster_ids) {
    for (i = 0; i < num_bins; i++) {
      ndpi_init_bin(&bins[i], ndpi_bin_family64 /* Use 64 bit to avoid overlaps */,
                    num_element);
      num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
      for (j = 0; j < num_iteration; j++) {
        ndpi_set_bin(&bins[i], fuzzed_data.ConsumeIntegralInRange(0, num_element + 1),
                     fuzzed_data.ConsumeIntegral<u_int64_t>());
      }
    }
    ndpi_cluster_bins(bins, num_bins, num_cluster_ids, cluster_ids, NULL);
  }

  ndpi_free(cluster_ids);
  for (i = 0; i < num_bins; i++)
    ndpi_free_bin(&bins[i]);
  ndpi_free(bins);

  return 0;
}
