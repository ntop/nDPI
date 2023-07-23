#include "ndpi_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_char hash[16];
  struct ndpi_popcount popcount;

  /* No memory allocations involved */

  /* Used for crc32, md5 and popcount algs */

  ndpi_crc32(data, size);
  ndpi_md5(data, size, hash);

  ndpi_popcount_init(&popcount);
  ndpi_popcount_count(&popcount, data, size);

  return 0;
}
