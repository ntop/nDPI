#include "ndpi_api.h"

#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t len;

  /* No real memory allocations involved */

  len = fuzzed_data.ConsumeIntegral<u_int16_t>();
  std::string haystack = fuzzed_data.ConsumeRandomLengthString();
  std::string needle = fuzzed_data.ConsumeRandomLengthString();

  ndpi_strnstr(haystack.c_str(), needle.c_str(), len);

  return 0;
}
