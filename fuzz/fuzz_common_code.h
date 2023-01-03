#ifndef __FUZZ_COMMON_CODE_H__
#define __FUZZ_COMMON_CODE_H__

#include "ndpi_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef ENABLE_MEM_ALLOC_FAILURES
void *malloc_wrapper(size_t size);
void free_wrapper(void *freeable);
void set_mem_alloc_state(int value);
#endif

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod,
				int enable_log);

#ifdef __cplusplus
}
#endif

#endif
