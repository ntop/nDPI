#include <stdlib.h>
#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

#define MBEDTLS_CHECK_RETURN_TYPICAL
#include "../src/lib/third_party/include/gcrypt/aes.h"

extern int force_no_aesni;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  mbedtls_aes_context *ctx;
  int key_lens[] = { 128, 192, 256, 512 /* invalid */ };
  unsigned char *input, *output, *key;
  int i, key_len, mode, rc;

  /* No real memory allocations involved */

  if(fuzzed_data.remaining_bytes() < 1 + 1 + 4 + 512 / 8 + 16)
    return -1;

  posix_memalign((void **)&input, 8, 16);
  posix_memalign((void **)&output, 8, 16);
  posix_memalign((void **)&key, 8, 512 / 8);
  ctx = (mbedtls_aes_context *)malloc(sizeof(mbedtls_aes_context));

  force_no_aesni = 0;
  if(fuzzed_data.ConsumeBool())
    force_no_aesni = 1;

  mode = MBEDTLS_AES_ENCRYPT;
  if(fuzzed_data.ConsumeBool())
    mode = MBEDTLS_AES_DECRYPT;

  mbedtls_aes_init(ctx);

  key_len = fuzzed_data.PickValueInArray(key_lens);
  std::vector<unsigned char>k = fuzzed_data.ConsumeBytes<u_int8_t>(key_len / 8);
  std::vector<u_int8_t>in = fuzzed_data.ConsumeBytes<uint8_t>(16);

  for(i = 0; i < 16; i++)
    input[i] = in[i];
  for(i = 0; i < key_len / 8; i++)
    key[i] = k[i];

  if(mode == MBEDTLS_AES_ENCRYPT)
    rc = mbedtls_aes_setkey_enc(ctx, key, key_len);
  else
    rc = mbedtls_aes_setkey_dec(ctx, key, key_len);

  if(rc == 0)
    mbedtls_aes_crypt_ecb(ctx, mode, input, output);

  mbedtls_aes_free(ctx);

  free(ctx);
  free(key);
  free(input);
  free(output);

  return 0;
}
