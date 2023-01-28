#include "ndpi_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_char hash[16];

  /* No memory allocations involved */

  ndpi_crc32(data, size);
  ndpi_md5(data, size, hash);

  return 0;
}
