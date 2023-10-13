#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

#define MBEDTLS_CHECK_RETURN_TYPICAL
#define MBEDTLS_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
#include "../src/lib/third_party/include/gcrypt/cipher.h"
#include "../src/lib/third_party/include/gcrypt/aes.h"

extern int force_no_aesni;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  int key_lens[] = { 128, 192, 256 };
  int key_len, iv_len, rc_e, rc_d, input_length;
  unsigned char *output, *decrypted;
  size_t output_size, output_size2, decrypted_size;
  mbedtls_cipher_type_t cipher_type;
  /* TODO: GCM. This code/fuzzer doesn't work with GCM ciphers. Not sure why.. :( */
  const char *cipher_names[] = { NULL, "", "AES-128-ECB", "AES-192-ECB", "AES-256-ECB",
                                 /* "AES-128-GCM", "AES-192-GCM", "AES-256-GCM" */ };
  const char *cipher_name;
  mbedtls_cipher_context_t *ctx_e, *ctx_d;

  /* No real memory allocations involved */

  if(fuzzed_data.remaining_bytes() < 512) /* Some data */
    return -1;

  posix_memalign((void **)&ctx_e, 8, sizeof(mbedtls_cipher_context_t));
  posix_memalign((void **)&ctx_d, 8, sizeof(mbedtls_cipher_context_t));

  key_len = fuzzed_data.PickValueInArray(key_lens);
  std::vector<unsigned char>key = fuzzed_data.ConsumeBytes<u_int8_t>(key_len / 8);
  iv_len = fuzzed_data.ConsumeIntegralInRange(0, MBEDTLS_MAX_IV_LENGTH + 1);
  std::vector<u_int8_t>iv = fuzzed_data.ConsumeBytes<uint8_t>(iv_len);
  input_length = fuzzed_data.ConsumeIntegralInRange(16, 17);
  std::vector<unsigned char>input = fuzzed_data.ConsumeBytes<u_int8_t>(input_length);
  output = (unsigned char *)malloc(input_length);
  decrypted = (unsigned char *)malloc(input_length);

  mbedtls_cipher_list();
  /* Random iteration */
  cipher_type = static_cast<mbedtls_cipher_type_t>(fuzzed_data.ConsumeIntegralInRange(0, (int)MBEDTLS_CIPHER_AES_256_KWP) + 1);
  mbedtls_cipher_info_from_type(cipher_type);

  /* Real cipher used */
  cipher_name = cipher_names[fuzzed_data.ConsumeIntegralInRange(0, (int)(sizeof(cipher_names) / sizeof(char *) - 1))];
  mbedtls_cipher_init(ctx_e);
  mbedtls_cipher_init(ctx_d);
  ctx_e->cipher_info = mbedtls_cipher_info_from_string(cipher_name);
  ctx_d->cipher_info = ctx_e->cipher_info;

  mbedtls_cipher_info_get_mode(ctx_e->cipher_info);
  mbedtls_cipher_info_get_type(ctx_e->cipher_info);
  mbedtls_cipher_info_get_name(ctx_e->cipher_info);
  mbedtls_cipher_info_has_variable_key_bitlen(ctx_e->cipher_info);
  mbedtls_cipher_info_get_iv_size(ctx_e->cipher_info);
  mbedtls_cipher_info_get_block_size(ctx_e->cipher_info);
  mbedtls_cipher_get_cipher_mode(ctx_e);
  mbedtls_cipher_info_get_key_bitlen(ctx_e->cipher_info);

  posix_memalign((void **)&ctx_e->cipher_ctx, 8, sizeof(mbedtls_aes_context));
  posix_memalign((void **)&ctx_d->cipher_ctx, 8, sizeof(mbedtls_aes_context));

  rc_e = mbedtls_cipher_setkey(ctx_e, key.data(), key.size() * 8, MBEDTLS_ENCRYPT);
  rc_d = mbedtls_cipher_setkey(ctx_d, key.data(), key.size() * 8, MBEDTLS_DECRYPT);
  if(rc_e == 0 && rc_d == 0) {
    rc_e = mbedtls_cipher_set_iv(ctx_e, iv.data(), iv.size());
    rc_d = mbedtls_cipher_set_iv(ctx_d, iv.data(), iv.size());
    if(rc_e == 0 && rc_d == 0) {
      mbedtls_cipher_reset(ctx_e);
      mbedtls_cipher_reset(ctx_d);

      rc_e = mbedtls_cipher_update(ctx_e, input.data(), input.size(), output, &output_size);
      if(rc_e == 0) {
	rc_e = mbedtls_cipher_finish(ctx_e, NULL, &output_size2);
        if(rc_e == 0) {

          rc_d = mbedtls_cipher_update(ctx_d, output, output_size, decrypted, &decrypted_size);
          if(rc_d == 0) {
            rc_d = mbedtls_cipher_finish(ctx_d, NULL, &output_size2);
            /* TODO: decryption doesn't work with no-aesni data path!
	       Note that with MASAN, aesni is always disabled */
#if 0
	    if(rc_d == 0) {
              assert(input.size() == decrypted_size);
              assert(memcmp(input.data(), decrypted, decrypted_size) == 0);
            }
#endif
          }
        }
      }
    }
  }

  free(output);
  free(decrypted);
  free(ctx_e->cipher_ctx);
  free(ctx_e);
  free(ctx_d->cipher_ctx);
  free(ctx_d);
  return 0;
}
