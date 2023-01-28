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

/* Count the number of leading zero's */
static __inline u_int8_t _hll_rank(u_int32_t hash, u_int8_t bits) {
  u_int8_t i;

  for(i = 1; i <= 32 - bits; i++) {
    if(hash & 1)
      break;

    hash >>= 1;
  }

  return i;
}

/*
  IMPORTANT: HyperLogLog Memory and StandardError Notes
  
  StdError = 1.04/sqrt(2^i)

  [i: 4] 16 bytes      [StdError: 26%  ]
  [i: 5] 32 bytes      [StdError: 18.4%]
  [i: 6] 64 bytes      [StdError: 13%  ]
  [i: 7] 128 bytes     [StdError: 9.2% ]
  [i: 8] 256 bytes     [StdError: 6.5% ]
  [i: 9] 512 bytes     [StdError: 4.6% ]
  [i: 10] 1024 bytes   [StdError: 3.25%]
  [i: 11] 2048 bytes   [StdError: 2.3% ]
  [i: 12] 4096 bytes   [StdError: 1.6% ]
  [i: 13] 8192 bytes   [StdError: 1.15%]
  [i: 14] 16384 bytes  [StdError: 0.81%]
  [i: 15] 32768 bytes  [StdError: 0.57%]
  [i: 16] 65536 bytes  [StdError: 0.41%]
  [i: 17] 131072 bytes [StdError: 0.29%]
  [i: 18] 262144 bytes [StdError: 0.2% ]
  [i: 19] 524288 bytes [StdError: 0.14%]
*/
int hll_init(struct ndpi_hll *hll, u_int8_t bits) {
  if(!hll) {
    errno = EINVAL;
    return -1;
  }

  memset(hll, '\0', sizeof(*hll));

  if(bits < 4 || bits > 20) {
    errno = ERANGE;
    return -1;
  }

  hll->bits = bits; /* Number of bits of buckets number */
  hll->size = (size_t)1 << bits; /* Number of buckets 2^bits */
  hll->registers = ndpi_calloc(hll->size, 1); /* Create the bucket register counters */

  /* printf("%lu bytes\n", hll->size); */
  return 0;
}

void hll_destroy(struct ndpi_hll *hll) {
  if(hll->registers) {
    ndpi_free(hll->registers);
    
    hll->registers = NULL;
  }
}

void hll_reset(struct ndpi_hll *hll) {
  if(hll->registers)
    memset(hll->registers, 0, hll->size);
}

/* Return: 0 = nothing changed, 1 = ranking changed */
static __inline int _hll_add_hash(struct ndpi_hll *hll, u_int32_t hash) {
  if(hll->registers) {
    u_int32_t index = hash >> (32 - hll->bits);   /* Use the first 'hll->bits' bits as bucket index */
    u_int8_t rank   = _hll_rank(hash, hll->bits); /* Count the number of leading 0 */
    
    if(rank > hll->registers[index]) {
      hll->registers[index] = rank; /* Store the largest number of lesding zeros for the bucket */
      return(1);
    }
  }
  
  return(0);
}

/* Return: 0 = nothing changed, 1 = ranking changed */
int hll_add(struct ndpi_hll *hll, const void *buf, size_t size) {
  u_int32_t hash = MurmurHash3_x86_32((const char *)buf, (u_int32_t)size, 0x5f61767a);

  return(_hll_add_hash(hll, hash));
}

double hll_count(const struct ndpi_hll *hll) {
  if(hll->registers) {
    double alpha_mm, sum, estimate;
    u_int32_t i;

    switch(hll->bits) {
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

    sum = 0;
    for(i = 0; i < hll->size; i++)
      sum += 1.0 / (1 << hll->registers[i]);    

    estimate = alpha_mm / sum;

    if(estimate <= (5.0 / 2.0 * (double)hll->size)) {
      int zeros = 0;

      for(i = 0; i < hll->size; i++)
	zeros += (hll->registers[i] == 0);

      if(zeros)
	estimate = (double)hll->size * log((double)hll->size / zeros);

    } else if(estimate > ((1.0 / 30.0) * 4294967296.0)) {
      estimate = -4294967296.0 * log(1.0 - (estimate / 4294967296.0));
    }

    return estimate;
  } else
    return(0.);
}

