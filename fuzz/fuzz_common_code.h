#ifndef __FUZZ_COMMON_CODE_H__
#define __FUZZ_COMMON_CODE_H__

#include "ndpi_api.h"

void fuzz_init_detection_module(struct ndpi_detection_module_struct **ndpi_info_mod,
				int enable_log);

#endif
