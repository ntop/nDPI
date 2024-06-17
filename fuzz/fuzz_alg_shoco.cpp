#include <stdint.h>
#include "shoco.h"
#include "ndpi_api.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  const char *in;
  size_t in_len, out_len;
  char out[8192], orig[8192];
  int higher_level_api;

  /* No memory allocations involved */

  higher_level_api = fuzzed_data.ConsumeBool();

  std::string s = fuzzed_data.ConsumeRemainingBytesAsString().c_str();
  in = s.c_str();
  in_len = strlen(in);

  if(!higher_level_api) {
    out_len = shoco_compress(in, in_len, out, sizeof(out));
    if(out_len <= sizeof(out)) /* No error */
      shoco_decompress(out, out_len, orig, sizeof(orig));
  } else {
    out_len = ndpi_compress_str(in, in_len, out, sizeof(out));
    if(out_len != 0) /* No error */
      ndpi_decompress_str(out, out_len, orig, sizeof(orig));
  }

  return 0;
}
