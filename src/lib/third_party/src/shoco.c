/* https://github.com/Ed-von-Schleck/shoco */

#include <stdint.h>

#if (defined (__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || __BIG_ENDIAN__)
  #define swap(x) (x)
#else
  #if defined(_MSC_VER)
    #include <stdlib.h>
    #define swap(x) _byteswap_ulong(x)
  #elif defined (__GNUC__)
    #if defined(__builtin_bswap32)
      #define swap(x) __builtin_bswap32(x)
    #else
      #define swap(x) ((x<<24) + ((x&0x0000FF00)<<8) + ((x&0x00FF0000)>>8) + (x>>24))
    #endif
  #else
    #include <byteswap.h>
    #define swap(x) bswap_32(x)
  #endif
#endif

#if defined(_MSC_VER)
  #define _ALIGNED __declspec(align(16))
  #define inline __inline
#elif defined(__GNUC__)
  #define _ALIGNED __attribute__ ((aligned(16)))
#else
  #define _ALIGNED
#endif

#if defined(_M_X64) || defined (_M_AMD64) || defined (__x86_64__)
  #include "emmintrin.h"
  #define HAVE_SSE2
#endif

#include "shoco.h"
#define _SHOCO_INTERNAL
#include "shoco_domains_model.h" /* we have built a model trained on domain names */

static inline int decode_header(unsigned char val) {
  int i = -1;
  while ((signed char)val < 0) {
    val <<= 1;
    ++i;
  }
  return i;
}

union Code {
  uint32_t word;
  char bytes[4];
};

#ifdef HAVE_SSE2
static inline int check_indices(const int16_t * shoco_restrict indices, int pack_n) {
  __m128i zero = _mm_setzero_si128();
  __m128i indis = _mm_load_si128 ((__m128i *)indices);
  __m128i masks = _mm_load_si128 ((__m128i *)packs[pack_n].masks);
  __m128i cmp = _mm_cmpgt_epi16 (indis, masks);
  __m128i mmask = _mm_cmpgt_epi16 (masks, zero);
  cmp = _mm_and_si128 (cmp, mmask);
  int result = _mm_movemask_epi8 (cmp);
  return (result == 0);
}
#else
static inline int check_indices(const int16_t * shoco_restrict indices, int pack_n) {
  unsigned int i;
  
  for (i = 0; i < packs[pack_n].bytes_unpacked; ++i)
    if (indices[i] > packs[pack_n].masks[i])
      return 0;
  return 1;
}
#endif

static inline int find_best_encoding(const int16_t * shoco_restrict indices, unsigned int n_consecutive) {
  int p;
  
  for (p = PACK_COUNT - 1; p >= 0; --p)
    if ((n_consecutive >= packs[p].bytes_unpacked) && (check_indices(indices, p)))
      return p;
  return -1;
}

size_t shoco_compress(const char * const shoco_restrict original, size_t strlen, char * const shoco_restrict out, size_t bufsize) {
  char *o = out;
  char * const out_end = out + bufsize;
  const char *in = original;
  int16_t _ALIGNED indices[MAX_SUCCESSOR_N + 1] = { 0 };
  int last_chr_index;
  int current_index;
  int successor_index;
  unsigned int n_consecutive;
  union Code code;
  int pack_n;
  unsigned int rest;
  const char * const in_end = original + strlen;

  while ((*in != '\0')) {
    if (strlen && (in == in_end))
      break;

    // find the longest string of known successors
    indices[0] = chr_ids_by_chr[(unsigned char)in[0]];
    last_chr_index = indices[0];
    if (last_chr_index < 0)
      goto last_resort;

    rest = in_end - in;
    for (n_consecutive = 1; n_consecutive <= MAX_SUCCESSOR_N; ++n_consecutive) {
      if (strlen && (n_consecutive == rest))
        break;

      current_index = chr_ids_by_chr[(unsigned char)in[n_consecutive]];
      if (current_index < 0)  // '\0' is always -1
        break;

      successor_index = successor_ids_by_chr_id_and_chr_id[last_chr_index][current_index];
      if (successor_index < 0)
        break;

      indices[n_consecutive] = (int16_t)successor_index;
      last_chr_index = current_index;
    }
    if (n_consecutive < 2)
      goto last_resort;

    pack_n = find_best_encoding(indices, n_consecutive);
    if (pack_n >= 0) {
      unsigned int i;
      
      if (o + packs[pack_n].bytes_packed > out_end)
        return bufsize + 1;

      code.word = packs[pack_n].word;
      for (i = 0; i < packs[pack_n].bytes_unpacked; ++i)
        code.word |= indices[i] << packs[pack_n].offsets[i];

      // In the little-endian world, we need to swap what's
      // in the register to match the memory representation.
      // On big-endian systems, this is a dummy.
      code.word = swap(code.word);

      // if we'd just copy the word, we might write over the end
      // of the output string
      for (i = 0; i < packs[pack_n].bytes_packed; ++i)
        o[i] = code.bytes[i];

      o += packs[pack_n].bytes_packed;
      in += packs[pack_n].bytes_unpacked;
    } else {
last_resort:
      if (*in & 0x80) {
        // non-ascii case
        if (o + 2 > out_end)
          return bufsize + 1;
        // put in a sentinel byte
        *o++ = 0x00;
      } else {
        // an ascii byte
        if (o + 1 > out_end)
          return bufsize + 1;
      }
      *o++ = *in++;
    }
  }

  return o - out;
}

size_t shoco_decompress(const char * const shoco_restrict original, size_t complen, char * const shoco_restrict out, size_t bufsize) {
  char *o = out;
  char * const out_end = out + bufsize;
  const char *in = original;
  char last_chr;
  union Code code = { 0 };
  int offset;
  int mask;
  int mark;
  const char * const in_end = original + complen;

  while (in < in_end) {
    mark = decode_header(*in);
    if (mark < 0) {
      if (o >= out_end)
        return bufsize + 1;

      // ignore the sentinel value for non-ascii chars
      if (*in == 0x00) {
        if (++in >= in_end)
          return SIZE_MAX;
      }

      *o++ = *in++;
    } else {
      unsigned int i;
      
      if (o + packs[mark].bytes_unpacked > out_end)
        return bufsize + 1;
      else if (in + packs[mark].bytes_packed > in_end)
        return SIZE_MAX;

      // This should be OK as well, but it fails with emscripten.
      // Test this with new versions of emcc.
      //code.word = swap(*(uint32_t *)in);
      for (i = 0; i < packs[mark].bytes_packed; ++i)
        code.bytes[i] = in[i];
      code.word = swap(code.word);

      // unpack the leading char
      offset = packs[mark].offsets[0];
      mask = packs[mark].masks[0];
      last_chr = o[0] = chrs_by_chr_id[(code.word >> offset) & mask];

      // unpack the successor chars
      for (i = 1; i < packs[mark].bytes_unpacked; ++i) {
        offset = packs[mark].offsets[i];
        mask = packs[mark].masks[i];
        last_chr = o[i] = chrs_by_chr_and_successor_id[(unsigned char)last_chr - MIN_CHR][(code.word >> offset) & mask];
      }

      o += packs[mark].bytes_unpacked;
      in += packs[mark].bytes_packed;
    }
  }

  // append a 0-terminator if it fits
  if (o < out_end)
    *o = '\0';

  return o - out;
}
