#include "ndpi_api.h"
#include "../src/lib/third_party/include/libinjection.h"
#include "../src/lib/third_party/include/libinjection_xss.h"
#include "../src/lib/third_party/include/libinjection_sqli.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *query;
  char fingerprint[8];

  /* No memory allocations involved */

  /* Libinjection: it wants null-terminated string */

  query = malloc(size + 1);
  memcpy(query, data, size);
  query[size] = '\0';

  libinjection_sqli(query, strlen(query), fingerprint);

  libinjection_xss(query, strlen(query));

  free(query);

  return 0;
}
