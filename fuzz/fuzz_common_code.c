
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

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod,
                                struct ndpi_global_context *g_ctx)
{
  NDPI_PROTOCOL_BITMASK all;

  if(*ndpi_info_mod == NULL) {
    *ndpi_info_mod = ndpi_init_detection_module(g_ctx);

    ndpi_set_config_u64(*ndpi_info_mod, NULL, "log.level", 3);
    ndpi_set_config(*ndpi_info_mod, "all", "log", "enable");

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(*ndpi_info_mod, &all);

    ndpi_load_domain_suffixes(*ndpi_info_mod, "public_suffix_list.dat");
    ndpi_load_categories_dir(*ndpi_info_mod, "./lists/");
    ndpi_load_protocols_file(*ndpi_info_mod, "protos.txt");
    ndpi_load_categories_file(*ndpi_info_mod, "categories.txt", NULL);
    ndpi_load_risk_domain_file(*ndpi_info_mod, "risky_domains.txt");
    ndpi_load_malicious_ja4_file(*ndpi_info_mod, "ja4_fingerprints.csv");
    ndpi_load_malicious_sha1_file(*ndpi_info_mod, "sha1_fingerprints.csv");

    ndpi_set_config(*ndpi_info_mod, NULL, "filename.config", "config.txt");

    ndpi_finalize_initialization(*ndpi_info_mod);
  }
}

FILE *buffer_to_file(const uint8_t *data, size_t size)
{
  return fmemopen((void *)data, size, "rw");
}
