#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <unistd.h>
#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, j;
  ndpi_ranking rank, rank2;
  u_int16_t max_num_entries, num_epochs;
  u_int32_t now, prev_epoch;
  ndpi_ranking_epoch_entry *entries;
  ndpi_ranking_change *curr_ranking, *prev_ranking;
  char path[64] = {0};

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  max_num_entries = fuzzed_data.ConsumeIntegral<u_int8_t>();
  num_epochs = fuzzed_data.ConsumeIntegralInRange(1, 255);

  ndpi_init_ranking(&rank, max_num_entries, num_epochs);

  now = 0;

  /* No ndpi_malloc; we don't want failures here */
  entries = (ndpi_ranking_epoch_entry *)malloc(sizeof(ndpi_ranking_epoch_entry) * max_num_entries);
  curr_ranking = (ndpi_ranking_change *)malloc(sizeof(ndpi_ranking_change) * max_num_entries);
  prev_ranking = (ndpi_ranking_change *)malloc(sizeof(ndpi_ranking_change) * max_num_entries);

  for (j = 0; j < max_num_entries; j++) {
    for(i = 0; i < max_num_entries; i++) {
      entries[i].item_unique_id = i;
      entries[i].value = fuzzed_data.ConsumeIntegral<u_int64_t>();
    }

    ndpi_ranking_add_epoch(&rank, now, entries, max_num_entries,
                           curr_ranking, prev_ranking,
                           &prev_epoch);
    now++;
  }

  ndpi_print_ranking(&rank);

  snprintf(path, sizeof(path), "/tmp/ranking.%u.test", (unsigned int)getpid());
  if(ndpi_serialize_ranking(&rank, fuzzed_data.ConsumeBool() ? path : NULL)) {
    if(ndpi_deserialize_ranking(&rank2, fuzzed_data.ConsumeBool() ? path : NULL))
      ndpi_term_ranking(&rank2);
    unlink(path);
  }

  ndpi_term_ranking(&rank);
  /* No ndpi_free! */
  free(entries);
  free(curr_ranking);
  free(prev_ranking);

  return 0;
}
