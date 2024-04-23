#include <stdint.h>
#include "shoco.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  const char *in;
  size_t in_len, out_len;
  char out[4096], orig[4096];

  /* No memory allocations involved */

  std::string s = fuzzed_data.ConsumeRemainingBytesAsString().c_str();
  in = s.c_str();
  in_len = strlen(in);

  out_len = shoco_compress(in, in_len, out, sizeof(out));
  shoco_decompress(out, out_len, orig, sizeof(orig));

  return 0;
}
