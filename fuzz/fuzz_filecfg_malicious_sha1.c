#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str, ndpi_log_level_t log_level,
                       const char *file_name, const char *func_name, unsigned int line_number, const char *format, ...);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_detection_module_struct *ndpi_struct;
  FILE *fd;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  /* We don't need a complete (and costly to set up) context!
     Setting up manually only what is really needed is complex (and error prone!)
     but allow us to be significant faster and to have better coverage */

  /* TODO: if it works, we can extend the same logic to other fuzzers */

  ndpi_struct = ndpi_calloc(1, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  set_ndpi_debug_function(ndpi_struct, (ndpi_debug_function_ptr)ndpi_debug_printf);
#endif
  if(ndpi_struct)
    ndpi_struct->cfg.log_level = NDPI_LOG_DEBUG_EXTRA;

  fd = buffer_to_file(data, size);
  load_malicious_sha1_file_fd(ndpi_struct, fd);
  if(fd)
    fclose(fd);

  /* We also need to manually free anything! */
  if(ndpi_struct && ndpi_struct->malicious_sha1_hashmap)
    ndpi_hash_free(&ndpi_struct->malicious_sha1_hashmap);
  ndpi_free(ndpi_struct);

  return 0;
}
