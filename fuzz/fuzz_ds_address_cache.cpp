#include "ndpi_api.h"
#include "ndpi_private.h"

#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration;
  int is_added = 0;
  struct ndpi_detection_module_struct ndpi_struct; /*Opaque; we don't really need to initialize it */
  ndpi_ip_addr_t ip_addr, ip_addr_added;
  char *hostname, *hostname2;
  u_int32_t epoch_now;
  u_int32_t ttl;
  bool rc;
  char path[] = "random.dump";


  /* Just to have some data */
  if (fuzzed_data.remaining_bytes() < 1024)
    return -1;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);


  memset(&ndpi_struct, '\0', sizeof(struct ndpi_detection_module_struct));
  ndpi_struct.cfg.address_cache_size = fuzzed_data.ConsumeIntegral<u_int8_t>();

  epoch_now = 1;

  /* Random insert */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (fuzzed_data.ConsumeBool()) {
      if(fuzzed_data.remaining_bytes() > 16) {
        memcpy(&ip_addr.ipv6, fuzzed_data.ConsumeBytes<u_int8_t>(16).data(), 16);
      } else {
        continue;
      }
    } else {
      memset(&ip_addr, '\0', sizeof(ip_addr));
      ip_addr.ipv4 = fuzzed_data.ConsumeIntegral<u_int32_t>();
    }
    hostname = strdup(fuzzed_data.ConsumeRandomLengthString(32).c_str());
    ttl = fuzzed_data.ConsumeIntegral<u_int8_t>();
    epoch_now += fuzzed_data.ConsumeIntegral<u_int8_t>();

    rc = ndpi_cache_address(&ndpi_struct, ip_addr, hostname, epoch_now, ttl);
    if (rc == true) {
      if(is_added == 0 && fuzzed_data.ConsumeBool()) {
        /* Keep one random node really added */
        is_added = 1;
        ip_addr_added = ip_addr;
      } else if(fuzzed_data.ConsumeBool()) {
        /* Add also same ip with different hostname */
        hostname2 = ndpi_strdup(fuzzed_data.ConsumeRandomLengthString(32).c_str());
        ndpi_cache_address(&ndpi_struct, ip_addr, hostname2, epoch_now, ttl);
        ndpi_free(hostname2);
      }
    }
    ndpi_free(hostname);
  }

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    if (fuzzed_data.ConsumeBool()) {
      if(fuzzed_data.remaining_bytes() > 16) {
        memcpy(&ip_addr.ipv6, fuzzed_data.ConsumeBytes<u_int8_t>(16).data(), 16);
      } else {
        continue;
      }
    } else {
      memset(&ip_addr, '\0', sizeof(ip_addr));
      ip_addr.ipv4 = fuzzed_data.ConsumeIntegral<u_int32_t>();
    }

    ndpi_cache_address_find(&ndpi_struct, ip_addr);
  }
  /* Search of an added entry */
  if(is_added)
    ndpi_cache_address_find(&ndpi_struct, ip_addr_added);

  if(fuzzed_data.ConsumeBool()) {
    epoch_now += fuzzed_data.ConsumeIntegral<u_int8_t>();
    ndpi_cache_address_flush_expired(&ndpi_struct, epoch_now);
  }

  epoch_now += fuzzed_data.ConsumeIntegral<u_int8_t>();
  ndpi_cache_address_dump(&ndpi_struct, path, epoch_now);
  epoch_now += fuzzed_data.ConsumeIntegral<u_int8_t>();
  ndpi_cache_address_restore(&ndpi_struct, path, epoch_now);

  ndpi_term_address_cache(ndpi_struct.address_cache);

  return 0;
}
