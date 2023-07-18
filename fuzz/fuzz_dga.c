#include "ndpi_api.h"
#include "fuzz_common_code.h"

static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static struct ndpi_flow_struct *ndpi_flow = NULL;

static int ndpi_custom_dga_fn(const char* domain, int domain_length)
{
  return ndpi_is_printable_buffer((const u_int8_t *)domain, domain_length);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *name;

  if (ndpi_struct == NULL) {
    fuzz_init_detection_module(&ndpi_struct);
    ndpi_flow = ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
  }

  if (size == 0)
    return 0;

  if (data[0] % 2 == 0)
    ndpi_dga_function = ndpi_custom_dga_fn;
  else
    ndpi_dga_function = NULL;

  name = ndpi_malloc(size + 1);
  if (name) {
    memcpy(name, data, size);
    name[size] = '\0';
    ndpi_check_dga_name(ndpi_struct, ndpi_flow, name, 1, 1);
    ndpi_free(name);
  }

  return 0;
}
