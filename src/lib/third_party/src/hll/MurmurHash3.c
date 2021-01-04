/*-----------------------------------------------------------------------------
  MurmurHash3 was written by Austin Appleby, and is placed in the public
  domain. The author hereby disclaims copyright to this source code.
*/

#include "MurmurHash3.h"

#define	ROTL32(x, r)	((x) << (r)) | ((x) >> (32 - (r)))

u_int32_t MurmurHash3_x86_32(const void *key, u_int32_t len, u_int32_t seed) {
  const u_int8_t *data = (const u_int8_t *)key;
  const int32_t nblocks = (int32_t)len / 4;

  u_int32_t h1 = seed;
  int i;

  const u_int32_t c1 = 0xcc9e2d51;
  const u_int32_t c2 = 0x1b873593;
  const u_int32_t *blocks = (const u_int32_t *)(data + nblocks * 4);

  for(i = -nblocks; i; i++)
    {
      u_int32_t k1 = blocks[i];

      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;

      h1 ^= k1;
      h1 = ROTL32(h1, 13);
      h1 = h1 * 5 + 0xe6546b64;
    }

  const u_int8_t * tail = (const u_int8_t *)(data + nblocks * 4);

  u_int32_t k1 = 0;

  switch(len & 3)
    {
    case 3:
      k1 ^= (u_int32_t)tail[2] << 16;
      /* fall-through */
    case 2:
      k1 ^= (u_int32_t)tail[1] << 8;
      /* fall-through */
    case 1:
      k1 ^= tail[0];
      k1 *= c1;
      k1 = ROTL32(k1, 15);
      k1 *= c2;
      h1 ^= k1;
    };

  h1 ^= len;

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}
