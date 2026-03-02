#include "ndpi_api.h"
#include "ndpi_md5.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  u_char hash[16];
  ndpi_MD5_CTX ctx;
  struct ndpi_popcount popcount;
  char *str;
  u_int len;
  u_char out[2048], out2[2048];
  int pseudo_bool;
  u_char *enc;
  u_char *dec;
  size_t out_len;

  /* No memory allocations involved */

  /* Used for crc32, md5, hash(es), popcount, hex2bin, hexencode algs */

  pseudo_bool = (size % 2 == 0);

  ndpi_crc16_ccit(data, size);
  ndpi_crc16_ccit_false(data, size);
  ndpi_crc16_xmodem(data, size);
  ndpi_crc16_x25(data, size);
  ndpi_crc32(data, size, 0);

  ndpi_md5(data, size, hash);

  ndpi_MD5Init(&ctx);
  ndpi_MD5Update(&ctx, data, size / 2);
  ndpi_MD5Update(&ctx, data + size / 2, size - size / 2);
  ndpi_MD5Final(hash, &ctx);

  ndpi_murmur_hash((const char *)data, size);
  ndpi_quick_hash(data, size);

  if(size >= 16)
    ndpi_quick_16_byte_hash(data);

  str = ndpi_malloc(size + 1);
  if(str) {
    memcpy(str, data, size);
    str[size] = '\0';

    ndpi_quick_hash64((const char *)str, strlen(str));
    ndpi_hash_string(str);
    ndpi_rev_hash_string(str);
    ndpi_hash_string_len(str, strlen(str));

    ndpi_free(str);
  }
  

  ndpi_popcount_init(pseudo_bool ? &popcount : NULL);
  ndpi_popcount_count(pseudo_bool ? &popcount : NULL, data, size);

  len = ndpi_bin2hex(out, sizeof(out), (u_char *)data, size);
  ndpi_hex2bin(out2, sizeof(out2), out, len);

  enc = ndpi_hex_encode(data, size);
  dec = ndpi_hex_decode(enc, size * 2, &out_len);
  ndpi_free(enc);
  ndpi_free(dec);

  return 0;
}
