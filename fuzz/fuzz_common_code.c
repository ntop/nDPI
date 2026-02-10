
#include "fuzz_common_code.h"

#include <assert.h>


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
static void *calloc_wrapper(size_t nmemb, size_t size) {
  return (fastrand () % 16) ? calloc (nmemb, size) : NULL;
}
static void *realloc_wrapper(void *ptr, size_t size) {
  return (fastrand () % 16) ? realloc (ptr, size) : NULL;
}

void fuzz_set_alloc_callbacks(void)
{
  ndpi_set_memory_alloction_functions(malloc_wrapper,
                                      free_wrapper,
                                      calloc_wrapper,
                                      realloc_wrapper,
                                      /* Aligned allocations are used only by croaring,
                                         but no during fuzzing. So no point to set
                                         these two wrappers here */
                                      NULL, NULL,
                                      malloc_wrapper,
                                      free_wrapper);
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
                                struct ndpi_global_context *g_ctx,
                                const char *path)
{
  char name[256];

  if(*ndpi_info_mod == NULL) {
    *ndpi_info_mod = ndpi_init_detection_module(g_ctx);

    assert(ndpi_set_config_u64(*ndpi_info_mod, NULL, "log.level", 3) == 0);
    assert(ndpi_set_config(*ndpi_info_mod, "all", "log", "enable") == 0);

    sprintf(name, "%s/public_suffix_list.dat", path);
    assert(ndpi_load_domain_suffixes(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/lists/", path);
    assert(ndpi_load_categories_dir(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/lists/protocols/", path);
    assert(ndpi_load_protocols_dir(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/protos.txt", path);
    assert(ndpi_load_protocols_file(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/categories.txt", path);
    assert(ndpi_load_categories_file(*ndpi_info_mod, name, NULL) >= 0);
    sprintf(name, "%s/risky_domains.txt", path);
    assert(ndpi_load_risk_domain_file(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/ja4_fingerprints.csv", path);
    assert(ndpi_load_malicious_ja4_file(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/tcp_fingerprints.csv", path);
    assert(ndpi_load_tcp_fingerprint_file(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/sha1_fingerprints.csv", path);
    assert(ndpi_load_malicious_sha1_file(*ndpi_info_mod, name) >= 0);
    sprintf(name, "%s/config_only_classification.txt", path);
    assert(ndpi_set_config(*ndpi_info_mod, NULL, "filename.config", name) >= 0);

    ndpi_finalize_initialization(*ndpi_info_mod);
  }
}

FILE *buffer_to_file(const uint8_t *data, size_t size)
{
  return fmemopen((void *)data, size, "rw");
}
