#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_values, num_learning_values, max_series_len;
  struct ndpi_hw_struct hw;
  struct ndpi_rsi_struct rsi;
  struct ndpi_analyze_struct *a;
  int rc_hw, rc_rsi;
  u_int16_t num_periods;
  u_int8_t additive_seeasonal;
  double alpha, beta, gamma, forecast, confidence_band;
  float significance;
  u_int32_t *values;
  bool *outliers;

  /* Use the same (integral) dataset to peform: RSI, Data analysis, HW and outliers */

  /* Just to have some data */
  if(fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  /* Data set */
  num_values = fuzzed_data.ConsumeIntegral<u_int8_t>();
  values = (u_int32_t *)ndpi_malloc(sizeof(u_int32_t) * num_values);
  outliers = (bool *)ndpi_malloc(sizeof(bool) * num_values);
  if (!values || !outliers) {
    ndpi_free(values);
    ndpi_free(outliers);
    return -1;
  }
  for (i = 0; i < num_values; i++)
    values[i] = fuzzed_data.ConsumeIntegral<u_int32_t>();
  
  /* Init HW */
  num_periods = fuzzed_data.ConsumeIntegral<u_int8_t>();
  additive_seeasonal = fuzzed_data.ConsumeBool();
  alpha = fuzzed_data.ConsumeFloatingPointInRange<double>(0, 1);
  beta = fuzzed_data.ConsumeFloatingPointInRange<double>(0, 1);
  gamma = fuzzed_data.ConsumeFloatingPointInRange<double>(0, 1);
  significance = fuzzed_data.ConsumeFloatingPointInRange<float>(0, 1.1);
  rc_hw = ndpi_hw_init(&hw, num_periods, additive_seeasonal,
                       alpha, beta, gamma, significance);
  /* Init RSI */
  num_learning_values = fuzzed_data.ConsumeIntegral<u_int8_t>();
  rc_rsi = ndpi_alloc_rsi(&rsi, num_learning_values);

  /* Init Data Analysis */
  max_series_len = fuzzed_data.ConsumeIntegral<u_int16_t>();
  a = ndpi_alloc_data_analysis(max_series_len);

  /* Calculate! */
  for (i = 0; i < num_values; i++) {
    if (rc_hw == 0)
      ndpi_hw_add_value(&hw, values[i], &forecast, &confidence_band);
    if (rc_rsi == 0)
      ndpi_rsi_add_value(&rsi, values[i]);
    ndpi_data_add_value(a, values[i]);
  }
  ndpi_find_outliers(values, outliers, num_values);

  /* Data analysis stuff */
  ndpi_data_average(a);
  ndpi_data_mean(a);
  ndpi_data_variance(a);
  ndpi_data_stddev(a);
  ndpi_data_min(a);
  ndpi_data_max(a);
  ndpi_data_window_average(a);
  ndpi_data_window_variance(a);
  ndpi_data_window_stddev(a);
  ndpi_data_entropy(a);
  ndpi_reset_data_analysis(a);
  ndpi_data_last(a);

  /* Data ratio */
  if (num_values > 1)
    ndpi_data_ratio2str(ndpi_data_ratio(values[0], values[1]));

  /* Done. Free */
  if (rc_hw == 0)
    ndpi_hw_free(&hw);
  if (rc_rsi == 0)
    ndpi_free_rsi(&rsi);
  ndpi_free_data_analysis(a, 1);  
  ndpi_free(values);
  ndpi_free(outliers);

  return 0;
}
