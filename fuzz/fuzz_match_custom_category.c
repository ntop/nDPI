#include "ndpi_api.h"
#include "fuzz_common_code.h"

static char *path = NULL;

static struct ndpi_detection_module_struct *ndpi_struct = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;

  path = dirname(strdup(*argv[0])); /* No errors; no free! */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ndpi_protocol_category_t category;
  ndpi_protocol_breed_t breed;

  if(ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct, NULL, path);
  }

  fuzz_set_alloc_callbacks_and_seed(size);

  ndpi_match_custom_category(ndpi_struct, (char *)data, size,
                             &category, &breed);
  return 0;
}
