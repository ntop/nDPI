#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_

#include <stdint.h>

uint32_t MurmurHash(const void * key, uint32_t len, uint32_t seed);

#endif
