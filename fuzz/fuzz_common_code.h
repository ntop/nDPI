#ifndef __FUZZ_COMMON_CODE_H__
#define __FUZZ_COMMON_CODE_H__

#include "ndpi_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod);

/* To allow memory allocation failures */
void fuzz_set_alloc_callbacks(void);
void fuzz_set_alloc_seed(int seed);
void fuzz_set_alloc_callbacks_and_seed(int seed);

#ifdef __cplusplus
}
#endif

#endif
