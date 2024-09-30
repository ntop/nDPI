#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;

extern "C" {

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str, ndpi_log_level_t log_level,
                       const char *file_name, const char *func_name, unsigned int line_number, const char *format, ...);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  u_int16_t i, num_iteration, is_added = 0;
  bool rc;
  ndpi_domain_classify *d;
  u_int16_t class_id;
  std::string value, value_added;

  /* We don't need a complete (and costly to set up) context!
     Setting up manually only what is really needed is complex (and error prone!)
     but allow us to be significant faster and to have better coverage */
  if (ndpi_struct == NULL) {
    ndpi_struct = (struct ndpi_detection_module_struct *)ndpi_calloc(1, sizeof(struct ndpi_detection_module_struct));
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    set_ndpi_debug_function(ndpi_struct, (ndpi_debug_function_ptr)ndpi_debug_printf);
#endif
    if (ndpi_struct) {
      ndpi_struct->cfg.log_level = NDPI_LOG_DEBUG_EXTRA;
      ndpi_load_domain_suffixes(ndpi_struct, (char *)"public_suffix_list.dat");
    }
  }

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  d = ndpi_domain_classify_alloc();

  num_iteration = fuzzed_data.ConsumeIntegral<u_int8_t>();
  
  for (i = 0; i < num_iteration; i++) {
    value = fuzzed_data.ConsumeBytesAsString(fuzzed_data.ConsumeIntegral<u_int8_t>());
    class_id = fuzzed_data.ConsumeIntegral<u_int16_t>();
    rc = ndpi_domain_classify_add(fuzzed_data.ConsumeBool() ? ndpi_struct : NULL,
                                  d, class_id, (char*)value.c_str());
    
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
    ndpi_domain_classify_hostname(fuzzed_data.ConsumeBool() ? ndpi_struct : NULL, d, &class_id, (char *)value.c_str());
  }
  
  /* Search of an added entry */
  if (is_added) {
    ndpi_domain_classify_hostname(ndpi_struct, d, &class_id, (char *)value_added.c_str());
  }

  ndpi_domain_classify_size(d);
  ndpi_domain_classify_free(d);
  
  return 0;
}

}
