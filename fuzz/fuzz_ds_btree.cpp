#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, j, num_iteration, num_rows, num_columns, num_q_rows, num_q_columns, num_results;
  ndpi_btree *b;
  double **inputs, **q;

  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

#if 0 /* TODO: ball.c code is not ready to handle memory allocation errors :( */
  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);
#endif

  num_rows = fuzzed_data.ConsumeIntegralInRange(1, 16);
  num_columns = fuzzed_data.ConsumeIntegralInRange(1, 16);

  inputs = (double **)ndpi_malloc(sizeof(double *) * num_rows);
  for (i = 0; i < num_rows; i++) {
    inputs[i] = (double *)ndpi_malloc(sizeof(double) * num_columns);
    for (j = 0; j < num_columns; j++)
      inputs[i][j] = fuzzed_data.ConsumeFloatingPoint<double>();
  }

  num_q_rows = fuzzed_data.ConsumeIntegralInRange(1, 16);
  num_q_columns = fuzzed_data.ConsumeIntegralInRange(1, 16);

  q = (double **)ndpi_malloc(sizeof(double *) * num_q_rows);
  for (i = 0; i < num_q_rows; i++) {
    q[i] = (double *)ndpi_malloc(sizeof(double) * num_q_columns);
    for (j = 0; j < num_q_columns; j++)
      q[i][j] = fuzzed_data.ConsumeFloatingPoint<double>();
  }

  num_results = fuzzed_data.ConsumeIntegralInRange((int)num_q_rows, 16);

  b = ndpi_btree_init(inputs, num_rows, num_columns);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    ndpi_knn result;

    result = ndpi_btree_query(b, q, num_q_rows, num_q_columns, num_results);
    ndpi_free_knn(result);
  }

  for (i = 0; i < num_rows; i++)
    ndpi_free(inputs[i]);
  ndpi_free(inputs);
  for (i = 0; i < num_q_rows; i++)
    ndpi_free(q[i]);
  ndpi_free(q);
  ndpi_free_btree(b);

  return 0;
}
