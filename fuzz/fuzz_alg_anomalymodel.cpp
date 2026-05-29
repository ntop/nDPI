#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int32_t n_normal, n_attacks, n_features, i, j;
  ndpi_anomaly_model *m;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  n_features = fuzzed_data.ConsumeIntegralInRange<u_int32_t>(1, 8);
  n_normal = fuzzed_data.ConsumeIntegral<u_int8_t>();
  n_attacks = fuzzed_data.ConsumeIntegral<u_int8_t>();
  m = ndpi_alloc_anomaly_model(n_features);

  double *row = (double *)malloc(sizeof(double) * n_features); /* No failure here */

  for(i = 0; i < n_normal; i++) {
    for(j = 0; j < n_features; j++)
      row[j] = fuzzed_data.ConsumeFloatingPoint<double>();

    ndpi_train_anomaly_model(m, row);
  }
  for(i = 0; i < n_attacks; i++) {
    for(j = 0; j < n_features; j++)
      row[j] = fuzzed_data.ConsumeFloatingPoint<double>();

    ndpi_compute_anomaly_score(m, row);
  }

  ndpi_free_anomaly_model(m);
  free(row);

  return 0;
}
