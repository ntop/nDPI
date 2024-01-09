#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_detection_module_struct *ndpi_struct;
  FILE *fd;
  NDPI_PROTOCOL_BITMASK all;
  NDPI_PROTOCOL_BITMASK debug_bitmask;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  NDPI_BITMASK_SET_ALL(debug_bitmask);
  ndpi_set_log_level(ndpi_struct, 4);
  ndpi_set_debug_bitmask(ndpi_struct, debug_bitmask);

  fd = buffer_to_file(data, size);
  load_categories_file_fd(ndpi_struct, fd, NULL);
  if(fd)
    fclose(fd);

  /* We don't really need to call ndpi_finalize_initialization */

  ndpi_exit_detection_module(ndpi_struct);
  return 0;
}
