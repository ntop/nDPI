#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, j, rc, num_iteration, is_added = 0, num_dimensions;
  ndpi_kd_tree *k = NULL;
  double *values, *values_added;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  num_dimensions = fuzzed_data.ConsumeIntegralInRange(1, 8);

  values = (double *)ndpi_malloc(sizeof(double) * num_dimensions);
  values_added = (double *)ndpi_malloc(sizeof(double) * num_dimensions);
  if (!values || !values_added) {
    ndpi_free(values);
    ndpi_free(values_added);
    return 0;
  }

  k = ndpi_kd_create(num_dimensions);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {

    for (j = 0; j < num_dimensions; j++)
      values[j] = fuzzed_data.ConsumeFloatingPoint<double>();

    rc = ndpi_kd_insert(k, values, NULL);

    /* Keep one random entry really added */
    if (rc == 0 && fuzzed_data.ConsumeBool()) {
      for (j = 0; j < num_dimensions; j++)
        values_added[j] = values[j];
      is_added = 1;
    }
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    ndpi_kd_tree_result *res = NULL;
    double *user_data;

    for (j = 0; j < num_dimensions; j++)
      values[j] = fuzzed_data.ConsumeFloatingPoint<double>();

    res = ndpi_kd_nearest(k, values);
    if (res) {
      ndpi_kd_num_results(res);
      ndpi_kd_result_get_item(res, &user_data);
      if(is_added) {
        ndpi_kd_distance(values, values_added, num_dimensions);
      }
      ndpi_kd_result_free(res);
    }

  }
  /* Search of an added entry */
  if (is_added) {
    ndpi_kd_tree_result *res = NULL;
    double *user_data;

    res = ndpi_kd_nearest(k, values_added);
    if (res) {
      ndpi_kd_num_results(res);
      ndpi_kd_result_get_item(res, &user_data);
      ndpi_kd_result_free(res);
    }
  }

  ndpi_free(values);
  ndpi_free(values_added);
  ndpi_kd_clear(k);
  ndpi_kd_free(k);

  return 0;
}
