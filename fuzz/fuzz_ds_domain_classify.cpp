#include "ndpi_api.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  bool rc;
  ndpi_domain_classify *d;
  u_int16_t class_id;
  std::string value, value_added;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL);
  }

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  d = ndpi_domain_classify_alloc();

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeBytesAsString(fuzzed_data.ConsumeIntegral<u_int8_t>());
    class_id = fuzzed_data.ConsumeIntegral<u_int16_t>();
    rc = ndpi_domain_classify_add(ndpi_struct, d, class_id, (char*)value.c_str());
    
    /* Keep one random entry really added */
    if (rc == true && is_added == 0 && fuzzed_data.ConsumeBool()) {
      value_added = value;
      is_added = 1;
    }
  }

  ndpi_domain_classify_add_domains(ndpi_struct, d,
				   fuzzed_data.ConsumeIntegralInRange(0, NDPI_LAST_IMPLEMENTED_PROTOCOL - 1),
				   fuzzed_data.ConsumeBool() ? (char *)"random_list.list" : (char *)"wrong_path");

  /* "Random" search */
  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeBytesAsString(fuzzed_data.ConsumeIntegral<u_int8_t>());
    ndpi_domain_classify_hostname(ndpi_struct, d, &class_id, (char *)value.c_str());
  }
  
  /* Search of an added entry */
  if (is_added) {
    ndpi_domain_classify_hostname(ndpi_struct, d, &class_id, (char *)value_added.c_str());
  }

  ndpi_domain_classify_size(d);
  ndpi_domain_classify_free(d);
  
  return 0;
}
