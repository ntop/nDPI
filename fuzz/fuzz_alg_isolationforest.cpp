#include "ndpi_api.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int32_t n_normal, n_attacks, n_features, i, j;
  double **d;
  void *f;

  /* isolationforest code doesn't handle allocation failures */

  /* Data set */
  n_features = fuzzed_data.ConsumeIntegralInRange<u_int32_t>(0, 8);
  n_normal = fuzzed_data.ConsumeIntegral<u_int8_t>();
  n_attacks = fuzzed_data.ConsumeIntegral<u_int8_t>();

  d = (double **)ndpi_malloc(sizeof(double *) * (n_normal + n_attacks));

  for(i = 0; i < n_normal; i++) {
    u_int32_t l = sizeof(double) * n_features;
    double *row = (double *)ndpi_malloc(l);

    d[i] = row;
    for(j = 0; j < n_features; j++)
      row[j] = fuzzed_data.ConsumeFloatingPoint<double>();
  }
  for(i = 0; i < n_attacks; i++) {
    u_int32_t l = sizeof(double) * n_features;
    double *row = (double *)ndpi_malloc(l);

    d[n_normal + i] = row;
    for(j = 0; j < n_features; j++)
      row[j] = fuzzed_data.ConsumeFloatingPoint<double>();
  }

  f = ndpi_alloc_iforest(d, n_normal, n_features);
  for(i = 0; i < n_normal + n_attacks; i++) {
    ndpi_iforest_score(f, d[i]);
  }

  ndpi_free_iforest(f);

  for(i = 0; i < n_normal + n_attacks; i++)
    ndpi_free(d[i]);
  ndpi_free(d);

  return 0;
}
