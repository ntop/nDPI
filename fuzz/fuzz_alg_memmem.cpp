#include "ndpi_api.h"

#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  char dst[256];
  uint8_t *h;
  int h_len, needle_len = 0, needle_start = 0;

  /* No real memory allocations involved */

  /* 1: needle is a subset of haystack */

  std::vector<uint8_t>haystack = fuzzed_data.ConsumeBytes<uint8_t>(512);
  h = haystack.data();
  h_len = haystack.size();

  if(h_len > 1) {
    needle_start = fuzzed_data.ConsumeIntegralInRange(0, h_len - 1);
    needle_len = fuzzed_data.ConsumeIntegralInRange(0, h_len - needle_start - 1); 
  }
  ndpi_memmem(h, h_len, &h[needle_start], needle_len);

  /* 2: fully random */

  std::vector<uint8_t>needle = fuzzed_data.ConsumeBytes<uint8_t>(512);
  ndpi_memmem(h, h_len, needle.data(), needle.size());


  /* Let use this fuzzer to check also this simple function... */
  ndpi_strlcpy(dst, (const char *)h, sizeof(dst), h_len);

  return 0;
}
