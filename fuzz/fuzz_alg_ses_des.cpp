#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  struct ndpi_ses_struct s;
  struct ndpi_des_struct d;
  int rc_ses, rc_des;
  double forecast, confidence_band, *values, value;
  float significance, alpha_ses, alpha_des, beta;

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 2048)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  /* Training */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  values = (double *)ndpi_malloc(sizeof(double) * num_iteration);
  if (!values)
    return 0;
  for (i = 0; i < num_iteration; i++)
    values[i] = fuzzed_data.ConsumeFloatingPoint<double>();
  ndpi_ses_fitting(values, num_iteration, &alpha_ses);
  ndpi_des_fitting(values, num_iteration, &alpha_des, &beta);
  ndpi_free(values);

  significance = fuzzed_data.ConsumeFloatingPointInRange<float>(0, 1.1);
  rc_ses = ndpi_ses_init(&s, alpha_ses, significance);
  rc_des = ndpi_des_init(&d, alpha_des, beta, significance);

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeFloatingPoint<double>();
    if (rc_ses == 0)
      ndpi_ses_add_value(&s, value, &forecast, &confidence_band);
    if (rc_des == 0)
      ndpi_des_add_value(&d, value, &forecast, &confidence_band);
  }

  return 0;
}
