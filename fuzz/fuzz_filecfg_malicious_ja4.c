#include "ndpi_api.h"
#include "ndpi_private.h"
#include "fuzz_common_code.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ndpi_detection_module_struct *ndpi_struct;
  FILE *fd;
  NDPI_PROTOCOL_BITMASK all;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_struct = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  ndpi_set_config(ndpi_struct, NULL, "log.level", "3");
  ndpi_set_config(ndpi_struct, "all", "log", "1");

  fd = buffer_to_file(data, size);
  load_malicious_ja4_file_fd(ndpi_struct, fd);
  if(fd)
    fclose(fd);

  ndpi_exit_detection_module(ndpi_struct);
  return 0;
}
