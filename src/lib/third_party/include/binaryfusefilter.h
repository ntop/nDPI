/* https://github.com/FastFilter/xor_singleheader */
#ifndef BINARYFUSEFILTER_H
#define BINARYFUSEFILTER_H
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef XOR_MAX_ITERATIONS
#define XOR_MAX_ITERATIONS                                                     \
  100 // probability of success should always be > 0.5 so 100 iterations is
      // highly unlikely
#endif

/**
 * We start with a few utilities.
 ***/
static inline uint64_t binary_fuse_murmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}
static inline uint64_t binary_fuse_mix_split(uint64_t key, uint64_t seed) {
  return binary_fuse_murmur64(key + seed);
}
static inline uint64_t binary_fuse_rotl64(uint64_t n, unsigned int c) {
#ifdef _WIN32
    return(_rotr64(n, c));
#else
  return (n << (c & 63)) | (n >> ((-c) & 63));
#endif
}
static inline uint32_t binary_fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}
static inline uint64_t binary_fuse8_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t binary_fuse_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

typedef struct binary_fuse8_s {
  uint64_t Seed;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint8_t *Fingerprints;
} binary_fuse8_t;

// #ifdefs adapted from:
//  https://stackoverflow.com/a/50958815
#ifdef __SIZEOF_INT128__  // compilers supporting __uint128, e.g., gcc, clang
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return ((__uint128_t)a * b) >> 64;
}
#elif defined(_M_X64) || defined(_MARM64)   // MSVC
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return __umulh(a, b);
}
#elif defined(_M_IA64)  // also MSVC
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  unsigned __int64 hi;
  (void) _umul128(a, b, &hi);
  return hi;
}
#else  // portable implementation using uint64_t
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  // Adapted from:
  //  https://stackoverflow.com/a/51587262

  /*
        This is implementing schoolbook multiplication:

                a1 a0
        X       b1 b0
        -------------
                   00  LOW PART
        -------------
                00
             10 10     MIDDLE PART
        +       01
        -------------
             01
        + 11 11        HIGH PART
        -------------
  */

  const uint64_t a0 = (uint32_t) a;
  const uint64_t a1 = a >> 32;
  const uint64_t b0 = (uint32_t) b;
  const uint64_t b1 = b >> 32;
  const uint64_t p11 = a1 * b1;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p00 = a0 * b0;

  // 64-bit product + two 32-bit values
  const uint64_t middle = p10 + (p00 >> 32) + (uint32_t) p01;

  /*
    Proof that 64-bit products can accumulate two more 32-bit values
    without overflowing:

    Max 32-bit value is 2^32 - 1.
    PSum = (2^32-1) * (2^32-1) + (2^32-1) + (2^32-1)
         = 2^64 - 2^32 - 2^32 + 1 + 2^32 - 1 + 2^32 - 1
         = 2^64 - 1
    Therefore the high half below cannot overflow regardless of input.
  */

  // high half
  return p11 + (middle >> 32) + (p01 >> 32);

  // low half (which we don't care about, but here it is)
  // (middle << 32) | (uint32_t) p00;
}
#endif

typedef struct binary_hashes_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
} binary_hashes_t;

static inline binary_hashes_t binary_fuse8_hash_batch(uint64_t hash,
                                        const binary_fuse8_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&filter->SegmentLengthMask;
  return ans;
}

static inline uint32_t binary_fuse8_hash(int index, uint64_t hash,
                                        const binary_fuse8_t *filter) {
    uint64_t h = binary_fuse_mulhi(hash, filter->SegmentCountLength);
    h += (uint64_t)index * filter->SegmentLength;
    // keep the lower 36 bits
    uint64_t hh = hash & ((1ULL << 36) - 1);
    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & filter->SegmentLengthMask);
    return h;
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse8_contain(uint64_t key,
                                        const binary_fuse8_t *filter) {
  uint64_t hash = binary_fuse_mix_split(key, filter->Seed);
  uint8_t f = binary_fuse8_fingerprint(hash);
  binary_hashes_t hashes = binary_fuse8_hash_batch(hash, filter);
  f ^= filter->Fingerprints[hashes.h0] ^ filter->Fingerprints[hashes.h1] ^
       filter->Fingerprints[hashes.h2];
  return f == 0;
}

static inline uint32_t binary_fuse_calculate_segment_length(uint32_t arity,
                                                             uint32_t size) {
  // These parameters are very sensitive. Replacing 'floor' by 'round' can
  // substantially affect the construction time.
  if (arity == 3) {
    return ((uint32_t)1) << (int)(floor(log((double)(size)) / log(3.33) + 2.25));
  } else if (arity == 4) {
    return ((uint32_t)1) << (int)(floor(log((double)(size)) / log(2.91) - 0.5));
  } else {
    return 65536;
  }
}

static inline double binary_fuse_max(double a, double b) {
  if (a < b) {
    return b;
  }
  return a;
}

static inline double binary_fuse_calculate_size_factor(uint32_t arity,
                                                        uint32_t size) {
  if (arity == 3) {
    return binary_fuse_max(1.125, 0.875 + 0.25 * log(1000000.0) / log((double)size));
  } else if (arity == 4) {
    return binary_fuse_max(1.075, 0.77 + 0.305 * log(600000.0) / log((double)size));
  } else {
    return 2.0;
  }
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call binary_fuse8_free(filter)
// size should be at least 2.
static inline bool binary_fuse8_allocate(uint32_t size,
                                         binary_fuse8_t *filter) {
  uint32_t arity = 3;
  filter->SegmentLength = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  double sizeFactor = size <= 1 ? 0 : binary_fuse_calculate_size_factor(arity, size);
  uint32_t capacity = size <= 1 ? 0 : (uint32_t)(round((double)size * sizeFactor));
  uint32_t initSegmentCount =
      (capacity + filter->SegmentLength - 1) / filter->SegmentLength -
      (arity - 1);
  filter->ArrayLength = (initSegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCount =
      (filter->ArrayLength + filter->SegmentLength - 1) / filter->SegmentLength;
  if (filter->SegmentCount <= arity - 1) {
    filter->SegmentCount = 1;
  } else {
    filter->SegmentCount = filter->SegmentCount - (arity - 1);
  }
  filter->ArrayLength =
      (filter->SegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCountLength = filter->SegmentCount * filter->SegmentLength;
  filter->Fingerprints = (uint8_t*)ndpi_malloc(filter->ArrayLength);
  return filter->Fingerprints != NULL;
}

// report memory usage
static inline size_t binary_fuse8_size_in_bytes(const binary_fuse8_t *filter) {
  return filter->ArrayLength * sizeof(uint8_t) + sizeof(binary_fuse8_t);
}

// release memory
static inline void binary_fuse8_free(binary_fuse8_t *filter) {
  ndpi_free(filter->Fingerprints);
  filter->Fingerprints = NULL;
  filter->Seed = 0;
  filter->SegmentLength = 0;
  filter->SegmentLengthMask = 0;
  filter->SegmentCount = 0;
  filter->SegmentCountLength = 0;
  filter->ArrayLength = 0;
}

static inline uint8_t binary_fuse_mod3(uint8_t x) {
    return x > 2 ? x - 3 : x;
}

// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool binary_fuse8_populate(const uint64_t *keys, uint32_t size,
                           binary_fuse8_t *filter) {
  uint64_t rng_counter = 0x726b2b9d438b9d4d;
  filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  uint64_t *reverseOrder = (uint64_t *)ndpi_calloc((size + 1), sizeof(uint64_t));
  uint32_t capacity = filter->ArrayLength;
  uint32_t *alone = (uint32_t *)ndpi_malloc(capacity * sizeof(uint32_t));
  uint8_t *t2count = (uint8_t *)ndpi_calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = (uint8_t *)ndpi_malloc(size * sizeof(uint8_t));
  uint64_t *t2hash = (uint64_t *)ndpi_calloc(capacity, sizeof(uint64_t));

  uint32_t blockBits = 1;
  while (((uint32_t)1 << blockBits) < filter->SegmentCount) {
    blockBits += 1;
  }
  uint32_t block = ((uint32_t)1 << blockBits);
  uint32_t *startPos = (uint32_t *)ndpi_malloc((1 << blockBits) * sizeof(uint32_t));
  uint32_t h012[5];

  if ((alone == NULL) || (t2count == NULL) || (reverseH == NULL) ||
      (t2hash == NULL) || (reverseOrder == NULL) || (startPos == NULL)) {
    ndpi_free(alone);
    ndpi_free(t2count);
    ndpi_free(reverseH);
    ndpi_free(t2hash);
    ndpi_free(reverseOrder);
    ndpi_free(startPos);
    return false;
  }
  reverseOrder[size] = 1;
  int loop;
  for (loop = 0; true; ++loop) {
    if (loop + 1 > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->Fingerprints, ~0, filter->ArrayLength);
      ndpi_free(alone);
      ndpi_free(t2count);
      ndpi_free(reverseH);
      ndpi_free(t2hash);
      ndpi_free(reverseOrder);
      ndpi_free(startPos);
      return true;
    }

    uint32_t i;
    for (i = 0; i < block; i++) {
      // important : i * size would overflow as a 32-bit number in some
      // cases.
      startPos[i] = ((uint64_t)i * size) >> blockBits;
    }

    uint64_t maskblock = block - 1;
    for (i = 0; i < size; i++) {
      uint64_t hash = binary_fuse_murmur64(keys[i] + filter->Seed);
      uint64_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= maskblock;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index]++;
    }
    int error = 0;
    uint32_t duplicates = 0;
    for ( i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      uint32_t h0 = binary_fuse8_hash(0, hash, filter);
      t2count[h0] += 4;
      t2hash[h0] ^= hash;
      uint32_t h1= binary_fuse8_hash(1, hash, filter);
      t2count[h1] += 4;
      t2count[h1] ^= 1;
      t2hash[h1] ^= hash;
      uint32_t h2 = binary_fuse8_hash(2, hash, filter);
      t2count[h2] += 4;
      t2hash[h2] ^= hash;
      t2count[h2] ^= 2;
      if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
        if   (((t2hash[h0] == 0) && (t2count[h0] == 8))
          ||  ((t2hash[h1] == 0) && (t2count[h1] == 8))
          ||  ((t2hash[h2] == 0) && (t2count[h2] == 8))) {
					duplicates += 1;
 					t2count[h0] -= 4;
 					t2hash[h0] ^= hash;
 					t2count[h1] -= 4;
 					t2count[h1] ^= 1;
 					t2hash[h1] ^= hash;
 					t2count[h2] -= 4;
 					t2count[h2] ^= 2;
 					t2hash[h2] ^= hash;
        }
      }
      error = (t2count[h0] < 4) ? 1 : error;
      error = (t2count[h1] < 4) ? 1 : error;
      error = (t2count[h2] < 4) ? 1 : error;
    }
    if(error) {
      memset(reverseOrder, 0, sizeof(uint64_t) * size);
      memset(t2count, 0, sizeof(uint8_t) * capacity);
      memset(t2hash, 0, sizeof(uint64_t) * capacity);
      filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
      continue;
    }

    // End of key addition
    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      Qsize += ((t2count[i] >> 2) == 1) ? 1 : 0;
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2) == 1) {
        uint64_t hash = t2hash[index];

        //h012[0] = binary_fuse8_hash(0, hash, filter);
        h012[1] = binary_fuse8_hash(1, hash, filter);
        h012[2] = binary_fuse8_hash(2, hash, filter);
        h012[3] = binary_fuse8_hash(0, hash, filter); // == h012[0];
        h012[4] = h012[1];
        uint8_t found = t2count[index] & 3;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        Qsize += ((t2count[other_index1] >> 2) == 2 ? 1 : 0);

        t2count[other_index1] -= 4;
        t2count[other_index1] ^= binary_fuse_mod3(found + 1);
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        Qsize += ((t2count[other_index2] >> 2) == 2 ? 1 : 0);
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= binary_fuse_mod3(found + 2);
        t2hash[other_index2] ^= hash;
      }
    }
    if (stacksize + duplicates == size) {
      // success
      size = stacksize;
      break;
    }
    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    memset(t2count, 0, sizeof(uint8_t) * capacity);
    memset(t2hash, 0, sizeof(uint64_t) * capacity);
    filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  }

  uint32_t i;
  for (i = size - 1; i < size; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    uint8_t xor2 = binary_fuse8_fingerprint(hash);
    uint8_t found = reverseH[i];
    h012[0] = binary_fuse8_hash(0, hash, filter);
    h012[1] = binary_fuse8_hash(1, hash, filter);
    h012[2] = binary_fuse8_hash(2, hash, filter);
    h012[3] = h012[0];
    h012[4] = h012[1];
    filter->Fingerprints[h012[found]] = xor2 ^
                                        filter->Fingerprints[h012[found + 1]] ^
                                        filter->Fingerprints[h012[found + 2]];
  }
  ndpi_free(alone);
  ndpi_free(t2count);
  ndpi_free(reverseH);
  ndpi_free(t2hash);
  ndpi_free(reverseOrder);
  ndpi_free(startPos);
  return true;
}

//////////////////
// fuse16
//////////////////

typedef struct binary_fuse16_s {
  uint64_t Seed;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint16_t *Fingerprints;
} binary_fuse16_t;

static inline uint64_t binary_fuse16_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

static inline binary_hashes_t binary_fuse16_hash_batch(uint64_t hash,
                                        const binary_fuse16_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&filter->SegmentLengthMask;
  return ans;
}
static inline uint32_t binary_fuse16_hash(int index, uint64_t hash,
                                        const binary_fuse16_t *filter) {
    uint64_t h = binary_fuse_mulhi(hash, filter->SegmentCountLength);
    h += (uint64_t)index * filter->SegmentLength;
    // keep the lower 36 bits
    uint64_t hh = hash & ((1ULL << 36) - 1);
    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & filter->SegmentLengthMask);
    return h;
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse16_contain(uint64_t key,
                                        const binary_fuse16_t *filter) {
  uint64_t hash = binary_fuse_mix_split(key, filter->Seed);
  uint16_t f = binary_fuse16_fingerprint(hash);
  binary_hashes_t hashes = binary_fuse16_hash_batch(hash, filter);
  f ^= filter->Fingerprints[hashes.h0] ^ filter->Fingerprints[hashes.h1] ^
       filter->Fingerprints[hashes.h2];
  return f == 0;
}


// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call binary_fuse16_free(filter)
// size should be at least 2.
static inline bool binary_fuse16_allocate(uint32_t size,
                                         binary_fuse16_t *filter) {
  uint32_t arity = 3;
  filter->SegmentLength = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  double sizeFactor = size <= 1 ? 0 : binary_fuse_calculate_size_factor(arity, size);
  uint32_t capacity = (uint32_t)(round((double)size * sizeFactor));
  uint32_t initSegmentCount =
      (capacity + filter->SegmentLength - 1) / filter->SegmentLength -
      (arity - 1);
  filter->ArrayLength = (initSegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCount =
      (filter->ArrayLength + filter->SegmentLength - 1) / filter->SegmentLength;
  if (filter->SegmentCount <= arity - 1) {
    filter->SegmentCount = 1;
  } else {
    filter->SegmentCount = filter->SegmentCount - (arity - 1);
  }
  filter->ArrayLength =
      (filter->SegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCountLength = filter->SegmentCount * filter->SegmentLength;
  filter->Fingerprints = (uint16_t*)ndpi_calloc(filter->ArrayLength, sizeof(uint16_t));
  return filter->Fingerprints != NULL;
}

// report memory usage
static inline size_t binary_fuse16_size_in_bytes(const binary_fuse16_t *filter) {
  return filter->ArrayLength * sizeof(uint16_t) + sizeof(binary_fuse16_t);
}

// release memory
static inline void binary_fuse16_free(binary_fuse16_t *filter) {
  ndpi_free(filter->Fingerprints);
  filter->Fingerprints = NULL;
  filter->Seed = 0;
  filter->SegmentLength = 0;
  filter->SegmentLengthMask = 0;
  filter->SegmentCount = 0;
  filter->SegmentCountLength = 0;
  filter->ArrayLength = 0;
}


// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool binary_fuse16_populate(const uint64_t *keys, uint32_t size,
                           binary_fuse16_t *filter) {
  uint64_t rng_counter = 0x726b2b9d438b9d4d;
  filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  uint64_t *reverseOrder = (uint64_t *)ndpi_calloc((size + 1), sizeof(uint64_t));
  uint32_t capacity = filter->ArrayLength;
  uint32_t *alone = (uint32_t *)ndpi_malloc(capacity * sizeof(uint32_t));
  uint8_t *t2count = (uint8_t *)ndpi_calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = (uint8_t *)ndpi_malloc(size * sizeof(uint8_t));
  uint64_t *t2hash = (uint64_t *)ndpi_calloc(capacity, sizeof(uint64_t));

  uint32_t blockBits = 1;
  while (((uint32_t)1 << blockBits) < filter->SegmentCount) {
    blockBits += 1;
  }
  uint32_t block = ((uint32_t)1 << blockBits);
  uint32_t *startPos = (uint32_t *)ndpi_malloc((1 << blockBits) * sizeof(uint32_t));
  uint32_t h012[5];

  if ((alone == NULL) || (t2count == NULL) || (reverseH == NULL) ||
      (t2hash == NULL) || (reverseOrder == NULL) || (startPos == NULL)) {
    ndpi_free(alone);
    ndpi_free(t2count);
    ndpi_free(reverseH);
    ndpi_free(t2hash);
    ndpi_free(reverseOrder);
    ndpi_free(startPos);
    return false;
  }
  reverseOrder[size] = 1;
  int loop;
  for (loop = 0; true; ++loop) {
    if (loop + 1 > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->Fingerprints, ~0, filter->ArrayLength * sizeof(uint16_t));
      ndpi_free(alone);
      ndpi_free(t2count);
      ndpi_free(reverseH);
      ndpi_free(t2hash);
      ndpi_free(reverseOrder);
      ndpi_free(startPos);
      return true;
    }

    uint32_t i;
    for (i = 0; i < block; i++) {
      // important : i * size would overflow as a 32-bit number in some
      // cases.
      startPos[i] = ((uint64_t)i * size) >> blockBits;
    }

    uint64_t maskblock = block - 1;
    for (i = 0; i < size; i++) {
      uint64_t hash = binary_fuse_murmur64(keys[i] + filter->Seed);
      uint64_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= maskblock;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index]++;
    }
    int error = 0;
    uint32_t duplicates = 0;
    for (i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      uint32_t h0 = binary_fuse16_hash(0, hash, filter);
      t2count[h0] += 4;
      t2hash[h0] ^= hash;
      uint32_t h1= binary_fuse16_hash(1, hash, filter);
      t2count[h1] += 4;
      t2count[h1] ^= 1;
      t2hash[h1] ^= hash;
      uint32_t h2 = binary_fuse16_hash(2, hash, filter);
      t2count[h2] += 4;
      t2hash[h2] ^= hash;
      t2count[h2] ^= 2;
      if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
        if   (((t2hash[h0] == 0) && (t2count[h0] == 8))
          ||  ((t2hash[h1] == 0) && (t2count[h1] == 8))
          ||  ((t2hash[h2] == 0) && (t2count[h2] == 8))) {
					duplicates += 1;
 					t2count[h0] -= 4;
 					t2hash[h0] ^= hash;
 					t2count[h1] -= 4;
 					t2count[h1] ^= 1;
 					t2hash[h1] ^= hash;
 					t2count[h2] -= 4;
 					t2count[h2] ^= 2;
 					t2hash[h2] ^= hash;
        }
      }
      error = (t2count[h0] < 4) ? 1 : error;
      error = (t2count[h1] < 4) ? 1 : error;
      error = (t2count[h2] < 4) ? 1 : error;
    }
    if(error) {
      memset(reverseOrder, 0, sizeof(uint64_t) * size);
      memset(t2count, 0, sizeof(uint8_t) * capacity);
      memset(t2hash, 0, sizeof(uint64_t) * capacity);
      filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
      continue;
    }

    // End of key addition
    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      Qsize += ((t2count[i] >> 2) == 1) ? 1 : 0;
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2) == 1) {
        uint64_t hash = t2hash[index];

        //h012[0] = binary_fuse16_hash(0, hash, filter);
        h012[1] = binary_fuse16_hash(1, hash, filter);
        h012[2] = binary_fuse16_hash(2, hash, filter);
        h012[3] = binary_fuse16_hash(0, hash, filter); // == h012[0];
        h012[4] = h012[1];
        uint8_t found = t2count[index] & 3;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        Qsize += ((t2count[other_index1] >> 2) == 2 ? 1 : 0);

        t2count[other_index1] -= 4;
        t2count[other_index1] ^= binary_fuse_mod3(found + 1);
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        Qsize += ((t2count[other_index2] >> 2) == 2 ? 1 : 0);
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= binary_fuse_mod3(found + 2);
        t2hash[other_index2] ^= hash;
      }
    }
    if (stacksize + duplicates == size) {
      // success
      size = stacksize;
      break;
    }
    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    memset(t2count, 0, sizeof(uint8_t) * capacity);
    memset(t2hash, 0, sizeof(uint64_t) * capacity);
    filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  }

  uint32_t i;
  for ( i = size - 1; i < size; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    uint16_t xor2 = binary_fuse16_fingerprint(hash);
    uint8_t found = reverseH[i];
    h012[0] = binary_fuse16_hash(0, hash, filter);
    h012[1] = binary_fuse16_hash(1, hash, filter);
    h012[2] = binary_fuse16_hash(2, hash, filter);
    h012[3] = h012[0];
    h012[4] = h012[1];
    filter->Fingerprints[h012[found]] = xor2 ^
                                        filter->Fingerprints[h012[found + 1]] ^
                                        filter->Fingerprints[h012[found + 2]];
  }
  ndpi_free(alone);
  ndpi_free(t2count);
  ndpi_free(reverseH);
  ndpi_free(t2hash);
  ndpi_free(reverseOrder);
  ndpi_free(startPos);
  return true;
}




#endif
