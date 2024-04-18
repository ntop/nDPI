#pragma once

#include <stddef.h>

#if defined(_MSC_VER)
#define shoco_restrict __restrict
#elif __GNUC__
#define shoco_restrict __restrict__
#else
#define shoco_restrict restrict
#endif

#ifdef __cplusplus
extern "C" {
#endif

size_t shoco_compress(const char * const shoco_restrict in, size_t len, char * const shoco_restrict out, size_t bufsize);
size_t shoco_decompress(const char * const shoco_restrict in, size_t len, char * const shoco_restrict out, size_t bufsize);

#ifdef __cplusplus
}
#endif


