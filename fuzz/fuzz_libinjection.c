#include "ndpi_api.h"
#include "../src/lib/third_party/include/libinjection.h"
#include "../src/lib/third_party/include/libinjection_xss.h"
#include "../src/lib/third_party/include/libinjection_sqli.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct libinjection_sqli_state state;

  /* No memory allocations involved */

  libinjection_sqli_init(&state, (char *)data, size, 0); /* Default: FLAG_QUOTE_NONE | FLAG_SQL_ANSI */
  libinjection_is_sqli(&state);
  libinjection_sqli_init(&state, (char *)data, size, FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
  libinjection_is_sqli(&state);
  libinjection_sqli_init(&state, (char *)data, size, FLAG_QUOTE_DOUBLE | FLAG_SQL_ANSI);
  libinjection_is_sqli(&state);
  libinjection_sqli_init(&state, (char *)data, size, FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
  libinjection_is_sqli(&state);
  libinjection_sqli_init(&state, (char *)data, size, FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
  libinjection_is_sqli(&state);
  libinjection_sqli_init(&state, (char *)data, size, FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
  libinjection_is_sqli(&state);

  libinjection_xss((char *)data, size);

  libinjection_version();

  return 0;
}
