#include "ndpi_api.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_int16_t bytes_read;

  /* No memory allocations involved */

  ndpi_bytestream_to_number64(data, size, &bytes_read);
  ndpi_bytestream_dec_or_hex_to_number64(data, size, &bytes_read);
  ntohs_ndpi_bytestream_to_number(data, size, &bytes_read);

  return 0;
}
