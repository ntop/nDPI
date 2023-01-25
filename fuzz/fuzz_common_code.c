
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
  ndpi_init_prefs prefs = ndpi_enable_ja3_plus;
  NDPI_PROTOCOL_BITMASK all;

  if(*ndpi_info_mod == NULL) {
    *ndpi_info_mod = ndpi_init_detection_module(prefs);
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(*ndpi_info_mod, &all);

#if 0
    NDPI_PROTOCOL_BITMASK debug_bitmask;

    NDPI_BITMASK_SET_ALL(debug_bitmask);
    ndpi_set_log_level(*ndpi_info_mod, 4);
    ndpi_set_debug_bitmask(*ndpi_info_mod, debug_bitmask);
#endif

    ndpi_load_protocols_file(*ndpi_info_mod, "protos.txt");
    ndpi_load_categories_file(*ndpi_info_mod, "categories.txt", NULL);
    ndpi_load_risk_domain_file(*ndpi_info_mod, "risky_domains.txt");
    ndpi_load_malicious_ja3_file(*ndpi_info_mod, "ja3_fingerprints.csv");
    ndpi_load_malicious_sha1_file(*ndpi_info_mod, "sha1_fingerprints.csv");

    ndpi_finalize_initialization(*ndpi_info_mod);
  }
}
