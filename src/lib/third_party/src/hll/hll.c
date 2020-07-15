/*
  Code taken from https://github.com/avz/hll
  
  Copyright (c) 2015 Artem Zaytsev <arepo@nologin.ru>
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.  
 */

#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <string.h>

#include <stdio.h>

#include "../include/MurmurHash3.h"
#include "../include/hll.h"

u_int32_t _hll_hash(const struct ndpi_hll *hll) {
  return MurmurHash3_x86_32(hll->registers, (u_int32_t)hll->size, 0);
}

static __inline u_int8_t _hll_rank(u_int32_t hash, u_int8_t bits) {
  u_int8_t i;

  for(i = 1; i <= 32 - bits; i++) {
    if(hash & 1)
      break;

    hash >>= 1;
  }

  return i;
}

int hll_init(struct ndpi_hll *hll, u_int8_t bits) {
  if(bits < 4 || bits > 20) {
    errno = ERANGE;
    return -1;
  }

  hll->bits = bits;
  hll->size = (size_t)1 << bits;
  hll->registers = ndpi_calloc(hll->size, 1);

  /* printf("%lu bytes\n", hll->size); */
  return 0;
}

void hll_destroy(struct ndpi_hll *hll) {
  ndpi_free(hll->registers);

  hll->registers = NULL;
}

void hll_reset(struct ndpi_hll *hll) {
  memset(hll->registers, 0, hll->size);
}

static __inline void _hll_add_hash(struct ndpi_hll *hll, u_int32_t hash) {
  u_int32_t index = hash >> (32 - hll->bits);
  u_int8_t rank = _hll_rank(hash, hll->bits);

  if(rank > hll->registers[index]) {
    hll->registers[index] = rank;
  }
}

void hll_add(struct ndpi_hll *hll, const void *buf, size_t size) {
  u_int32_t hash = MurmurHash3_x86_32((const char *)buf, (u_int32_t)size, 0x5f61767a);

  _hll_add_hash(hll, hash);
}

double hll_count(const struct ndpi_hll *hll) {
  double alpha_mm;
  u_int32_t i;

  switch (hll->bits) {
  case 4:
    alpha_mm = 0.673;
    break;
  case 5:
    alpha_mm = 0.697;
    break;
  case 6:
    alpha_mm = 0.709;
    break;
  default:
    alpha_mm = 0.7213 / (1.0 + 1.079 / (double)hll->size);
    break;
  }

  alpha_mm *= ((double)hll->size * (double)hll->size);

  double sum = 0;
  for(i = 0; i < hll->size; i++) {
    sum += 1.0 / (1 << hll->registers[i]);
  }

  double estimate = alpha_mm / sum;

  if (estimate <= 5.0 / 2.0 * (double)hll->size) {
    int zeros = 0;

    for(i = 0; i < hll->size; i++)
      zeros += (hll->registers[i] == 0);

    if(zeros)
      estimate = (double)hll->size * log((double)hll->size / zeros);

  } else if (estimate > (1.0 / 30.0) * 4294967296.0) {
    estimate = -4294967296.0 * log(1.0 - (estimate / 4294967296.0));
  }

  return estimate;
}

