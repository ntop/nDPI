#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

#define MBEDTLS_CHECK_RETURN_TYPICAL
#define MBEDTLS_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
#include "../src/lib/third_party/include/gcrypt/aes.h"
#include "../src/lib/third_party/include/gcrypt/cipher.h"
#include "../src/lib/third_party/include/gcrypt/gcm.h"

extern int force_no_aesni;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  mbedtls_aes_context *aes_e_ctx, *aes_d_ctx;
  mbedtls_gcm_context *gcm_e_ctx, *gcm_d_ctx;
  int key_lens[] = { 128, 192, 256, 512 /* invalid */ };
  unsigned char *output, *decrypted;
  int key_len, rc_e, rc_d;
  mbedtls_cipher_id_t cipher;
  unsigned char *tag;
  int iv_len, tag_len, input_length, force_auth_tag_error;

  /* No real memory allocations involved */

  if(fuzzed_data.remaining_bytes() < 1 + 4 + 512 / 8 +
				     1 + 64 + /* iv */
				     1 + /* tag_len */
				     1 + 64 + /* input */
				     1 + /* force_auth_tag_error */
				     1 /* useless data: to be able to add the check with assert */)
    return -1;

  gcm_e_ctx = (mbedtls_gcm_context *)malloc(sizeof(mbedtls_gcm_context));
  gcm_d_ctx = (mbedtls_gcm_context *)malloc(sizeof(mbedtls_gcm_context));
  aes_e_ctx = (mbedtls_aes_context *)malloc(sizeof(mbedtls_aes_context));
  aes_d_ctx = (mbedtls_aes_context *)malloc(sizeof(mbedtls_aes_context));

  force_no_aesni = 0;
  if(fuzzed_data.ConsumeBool())
    force_no_aesni = 1;

  key_len = fuzzed_data.PickValueInArray(key_lens);
  std::vector<unsigned char>key = fuzzed_data.ConsumeBytes<u_int8_t>(key_len / 8);

  iv_len = fuzzed_data.ConsumeIntegralInRange(0, 64);
  std::vector<u_int8_t>iv = fuzzed_data.ConsumeBytes<uint8_t>(iv_len);

  tag_len = fuzzed_data.ConsumeIntegralInRange(0, 17);
  tag = (unsigned char *)malloc(tag_len);

  input_length = fuzzed_data.ConsumeIntegralInRange(16, 64);
  std::vector<unsigned char>input = fuzzed_data.ConsumeBytes<u_int8_t>(input_length);
  output = (unsigned char *)malloc(input_length);
  decrypted = (unsigned char *)malloc(input_length);

  force_auth_tag_error = fuzzed_data.ConsumeBool();

  cipher = static_cast<mbedtls_cipher_id_t>(fuzzed_data.ConsumeIntegralInRange(0, (int)MBEDTLS_CIPHER_ID_CHACHA20));

  assert(fuzzed_data.remaining_bytes() > 0);

  mbedtls_gcm_init(gcm_e_ctx, aes_e_ctx);
  mbedtls_gcm_init(gcm_d_ctx, aes_d_ctx);

  rc_e = mbedtls_gcm_setkey(gcm_e_ctx, cipher, key.data(), key.size() * 8);
  rc_d = mbedtls_gcm_setkey(gcm_d_ctx, cipher, key.data(), key.size() * 8);

  if (rc_e == 0 && rc_d == 0) {
    rc_e = mbedtls_gcm_crypt_and_tag(gcm_e_ctx, MBEDTLS_GCM_ENCRYPT,
				     input.size(),
				     iv.data(), iv.size(),
				     NULL, 0, /* TODO */
				     input.data(),
				     output,
				     tag_len, tag);
    if(rc_e == 0) {
      if(force_auth_tag_error && tag_len > 0 && tag[0] != 0) {
        tag[0] = 0;
      } else {
        force_auth_tag_error = 0;
      }

      rc_d = mbedtls_gcm_auth_decrypt(gcm_d_ctx,
				      input.size(),
				      iv.data(), iv.size(),
				      NULL, 0, /* TODO */
				      tag, tag_len,
				      output,
				      decrypted);
      if(rc_d == 0)
        assert(memcmp(input.data(), decrypted, input.size()) == 0);
      if(force_auth_tag_error)
        assert(rc_d == MBEDTLS_ERR_GCM_AUTH_FAILED);
    }
  }

  mbedtls_gcm_free(gcm_e_ctx);
  mbedtls_gcm_free(gcm_d_ctx);

  free(tag);
  free(gcm_e_ctx);
  free(gcm_d_ctx);
  free(aes_e_ctx);
  free(aes_d_ctx);
  free(output);
  free(decrypted);

  return 0;
}
