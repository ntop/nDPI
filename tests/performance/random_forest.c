/*
 * Measure the bounded inference cost of the nDPI Random Forest core.
 * This is a throughput benchmark only; it does not claim model accuracy.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "ndpi_random_forest.h"

int main(void)
{
  static const struct ndpi_random_forest_node nodes[] = {
    { 0, 0.5f, 1, 2, 0 },
    { NDPI_RF_LEAF_NODE, 0.0f, -1, -1, 0 },
    { 1, 1.5f, 3, 4, 0 },
    { NDPI_RF_LEAF_NODE, 0.0f, -1, -1, 1 },
    { NDPI_RF_LEAF_NODE, 0.0f, -1, -1, 0 },
  };
  static const int32_t roots[] = { 0, 2, 4 };
  static const struct ndpi_random_forest_model model = {
    nodes, sizeof(nodes) / sizeof(nodes[0]), roots, 3, 2
  };
  const float features[] = { 0.75f, 2.0f };
  float scores[2];
  volatile float sink = 0.0f;
  struct timespec start, end;
  uint32_t i;
  const uint32_t iterations = 1000000;

  clock_gettime(CLOCK_MONOTONIC, &start);
  for(i = 0; i < iterations; i++) {
    if(ndpi_random_forest_predict(&model, features, 2, scores, 2) != 0)
      return 1;
    sink += scores[0] + scores[1];
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  double seconds = (double)(end.tv_sec - start.tv_sec) +
                   (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
  printf("iterations=%u seconds=%.6f predictions_per_second=%.0f checksum=%.1f\n",
         iterations, seconds, iterations / seconds, sink);
  return 0;
}
