#include "fuzz_common_code.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "fuzzer/FuzzedDataProvider.h"

#ifdef HAVE_LIBGCRYPT
#include "gcrypt.h"
#define HMAC_SHA256_DIGEST_SIZE 32
#else
#include "../src/lib/third_party/include/gcrypt_light.h"
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data(data, size);
  gcry_md_hd_t hh;
  gcry_cipher_hd_t h;
  gcry_error_t rc;
  int algo = 0, flags = 0, mode = 0; /* Invalid values */
  int key_len, iv_len, auth_len;
  u_int8_t out[HMAC_SHA256_DIGEST_SIZE];
  char buf_err[16];
  void *enc_out;

  /* To allow memory allocation failures */
  fuzz_set_alloc_callbacks_and_seed(size);

  gcry_control(fuzzed_data.ConsumeIntegralInRange(0, 2),
               fuzzed_data.ConsumeIntegralInRange(0, 1));

  /* MD */

  if(fuzzed_data.ConsumeBool())
    algo = GCRY_MD_SHA256;
  if(fuzzed_data.ConsumeBool())
    flags = GCRY_MD_FLAG_HMAC;
  key_len = fuzzed_data.ConsumeIntegralInRange(0, 65); /* Max valid key length is 64 */
  std::vector<u_int8_t>key = fuzzed_data.ConsumeBytes<u_int8_t>(key_len);
  std::vector<u_int8_t>src = fuzzed_data.ConsumeBytes<uint8_t>(300);

  gcry_md_get_algo_dlen(algo);
  rc = gcry_md_open(&hh, algo, flags);
  if (rc == 0) {
    gcry_md_reset(hh);
    rc = gcry_md_setkey(hh, key.data(), key.size());
    if (rc == 0) {
      if(fuzzed_data.ConsumeBool()) { /* To trigger MBEDTLS_ERR_MD_REKEY */
        rc = gcry_md_setkey(hh, key.data(), key.size());
      } else {
        rc = gcry_md_write(hh, src.data(), src.size());
        if (rc == 0) {
          memcpy(out, gcry_md_read(hh, 0), gcry_md_get_algo_dlen(algo));
          gcry_md_get_algo(hh);
        }
      }
    }
    gcry_md_close(hh);
  }
  gpg_strerror_r(rc, buf_err, sizeof(buf_err));


  /* Encryption */

  /* ECB */

  if(fuzzed_data.ConsumeBool())
    algo = GCRY_CIPHER_AES128;
  if(fuzzed_data.ConsumeBool())
    flags = 1; /* Invalid value */
  if(fuzzed_data.ConsumeBool())
    mode = GCRY_CIPHER_MODE_ECB;
  key_len = fuzzed_data.ConsumeIntegralInRange(16, 17); /* Only 16 is a valid key length */
  std::vector<u_int8_t>key2 = fuzzed_data.ConsumeBytes<u_int8_t>(key_len);
  enc_out = ndpi_malloc(src.size());
  if (!enc_out)
    return 0;

  h = NULL;
  rc = gcry_cipher_open(&h, algo, mode, flags);
  gpg_strerror_r(rc, buf_err, sizeof(buf_err));
  if(fuzzed_data.ConsumeBool())
    gcry_cipher_setkey(h, key2.data(), key2.size());
  if(fuzzed_data.ConsumeBool()) /* To trigger MBEDTLS_ERR_CIPHER_BAD_KEY */
    gcry_cipher_setkey(h, key2.data(), key2.size());
  rc = gcry_cipher_decrypt(h, enc_out, src.size(), src.data(), src.size());
  gpg_strerror_r(rc, buf_err, sizeof(buf_err));
  rc = gcry_cipher_encrypt(h, enc_out, src.size(), src.data(), src.size());
  gcry_cipher_ctl(h, 0, NULL, 0);
  gcry_cipher_close(h);

  gpg_strerror_r(rc, buf_err, sizeof(buf_err));

  /* GCM */

  if(fuzzed_data.ConsumeBool())
    mode = GCRY_CIPHER_MODE_GCM;
  iv_len = fuzzed_data.ConsumeIntegralInRange(12, 12); /* Only 12 is a valid key length */
  std::vector<u_int8_t>iv = fuzzed_data.ConsumeBytes<u_int8_t>(iv_len);
  auth_len = fuzzed_data.ConsumeIntegralInRange(0, 257); /* 257 is an invalid value */
  std::vector<u_int8_t>auth = fuzzed_data.ConsumeBytes<u_int8_t>(auth_len);

  h = NULL;
  rc = gcry_cipher_open(&h, algo, mode, flags);
  gpg_strerror_r(rc, buf_err, sizeof(buf_err));
  if(fuzzed_data.ConsumeBool()) {
    rc = gcry_cipher_setkey(h, key2.data(), key2.size());
    gpg_strerror_r(rc, buf_err, sizeof(buf_err));
  }
  if(fuzzed_data.ConsumeBool())
    gcry_cipher_reset(h);
  rc = gcry_cipher_setiv(h, iv.data(), iv.size());
  gpg_strerror_r(rc, buf_err, sizeof(buf_err));
  if(fuzzed_data.ConsumeBool()) { /* To trigger MBEDTLS_ERR_CIPHER_BAD_KEY */
    rc = gcry_cipher_setiv(h, iv.data(), iv.size());
  } else {
    rc = gcry_cipher_authenticate(h, auth.data(), auth.size());
    if (rc == 0) {
      rc = gcry_cipher_encrypt(h, enc_out, src.size(), src.data(), src.size());
      gpg_strerror_r(rc, buf_err, sizeof(buf_err));
      rc = gcry_cipher_decrypt(h, enc_out, src.size(), src.data(), src.size());
    }
  }
  gcry_cipher_close(h);

  gpg_strerror_r(rc, buf_err, sizeof(buf_err));

  gpg_strerror_r(static_cast<gcry_error_t>(fuzzed_data.ConsumeIntegral<u_int16_t>()), buf_err, sizeof(buf_err));

  ndpi_free(enc_out);

  return 0;
}
