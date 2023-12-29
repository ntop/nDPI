
#include "fuzz_common_code.h"


static int mem_alloc_state = 0;

__attribute__((no_sanitize("integer")))
static int fastrand ()
{
  if(!mem_alloc_state) return 1; /* No failures */
  mem_alloc_state = (214013 * mem_alloc_state + 2531011);
  return (mem_alloc_state >> 16) & 0x7FFF;
}

static void *malloc_wrapper(size_t size) {
  return (fastrand () % 16) ? malloc (size) : NULL;
}
static void free_wrapper(void *freeable) {
  free(freeable);
}

void fuzz_set_alloc_callbacks(void)
{
  set_ndpi_malloc(malloc_wrapper);
  set_ndpi_free(free_wrapper);
}
void fuzz_set_alloc_seed(int seed)
{
  mem_alloc_state = seed;
}
void fuzz_set_alloc_callbacks_and_seed(int seed)
{
  fuzz_set_alloc_callbacks();
  fuzz_set_alloc_seed(seed);
}

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod)
{
  if(*ndpi_info_mod == NULL) {
    *ndpi_info_mod = ndpi_init_detection_module();

    ndpi_set_config(*ndpi_info_mod, NULL, "log.level", "4");
    ndpi_set_config(*ndpi_info_mod, "all", "log.enable", "1");

    ndpi_set_config(*ndpi_info_mod, NULL, "dirname.domains", "./lists/");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.protocols", "protos.txt");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.categories", "categories.txt");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.risky_domains", "risky_domains.txt");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.malicious_ja3", "ja3_fingerprints.csv");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.malicious_sha1", "sha1_fingerprints.csv");
    ndpi_set_config(*ndpi_info_mod, NULL, "filename.config", "config.txt");

    ndpi_finalize_initialization(*ndpi_info_mod);
  }
}

FILE *buffer_to_file(const uint8_t *data, size_t size)
{
  return fmemopen((void *)data, size, "rw");
}
