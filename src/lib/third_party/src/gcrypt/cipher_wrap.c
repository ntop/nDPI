/**
 * \file cipher_wrap.c
 *
 * \brief Generic cipher wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if defined(MBEDTLS_AES_C)

static int aes_crypt_ecb_wrap( void *ctx, mbedtls_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ecb( (mbedtls_aes_context *) ctx, operation, input, output );
}


static int aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_dec( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static int aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_enc( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static void aes_ctx_zero( void *ctx )
{
    mbedtls_aes_init( (mbedtls_aes_context *) ctx );
}

static const mbedtls_cipher_base_t aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    aes_crypt_ecb_wrap,
    aes_setkey_enc_wrap,
    aes_setkey_dec_wrap,
    NULL, // aes_ctx_alloc
    NULL, // aes_ctx_free
    aes_ctx_zero
};

static const mbedtls_cipher_info_t aes_128_ecb_info = {
    MBEDTLS_CIPHER_AES_128_ECB,
    MBEDTLS_MODE_ECB,
    128,
    "AES-128-ECB",
    0,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_ecb_info = {
    MBEDTLS_CIPHER_AES_192_ECB,
    MBEDTLS_MODE_ECB,
    192,
    "AES-192-ECB",
    0,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_ecb_info = {
    MBEDTLS_CIPHER_AES_256_ECB,
    MBEDTLS_MODE_ECB,
    256,
    "AES-256-ECB",
    0,
    0,
    16,
    &aes_info
};

#if defined(MBEDTLS_GCM_C)
static int gcm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_gcm_setkey( (mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                     key, key_bitlen );
}

static const mbedtls_cipher_base_t gcm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
    gcm_aes_setkey_wrap,
    gcm_aes_setkey_wrap,
    NULL, // gcm_ctx_alloc
    NULL, // gcm_ctx_free
    NULL
};

static const mbedtls_cipher_info_t aes_128_gcm_info = {
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_MODE_GCM,
    128,
    "AES-128-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_192_gcm_info = {
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_MODE_GCM,
    192,
    "AES-192-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_256_gcm_info = {
    MBEDTLS_CIPHER_AES_256_GCM,
    MBEDTLS_MODE_GCM,
    256,
    "AES-256-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};
#endif /* MBEDTLS_GCM_C */


#endif /* MBEDTLS_AES_C */






#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
static int null_crypt_stream( void *ctx, size_t length,
                              const unsigned char *input,
                              unsigned char *output )
{
    ((void) ctx);
    memmove( output, input, length );
    return( 0 );
}

static int null_setkey( void *ctx, const unsigned char *key,
                        unsigned int key_bitlen )
{
    ((void) ctx);
    ((void) key);
    ((void) key_bitlen);

    return( 0 );
}

static void * null_ctx_alloc( void )
{
    return( (void *) 1 );
}

static void null_ctx_free( void *ctx )
{
    ((void) ctx);
}

static const mbedtls_cipher_base_t null_base_info = {
    MBEDTLS_CIPHER_ID_NULL,
    NULL,
    null_setkey,
    null_setkey,
    null_ctx_alloc,
    null_ctx_free
};

static const mbedtls_cipher_info_t null_cipher_info = {
    MBEDTLS_CIPHER_NULL,
    MBEDTLS_MODE_STREAM,
    0,
    "NULL",
    0,
    0,
    1,
    &null_base_info
};
#endif /* defined(MBEDTLS_CIPHER_NULL_CIPHER) */


const mbedtls_cipher_definition_t mbedtls_cipher_definitions[] =
{
#if defined(MBEDTLS_AES_C)
    { MBEDTLS_CIPHER_AES_128_ECB,          &aes_128_ecb_info },
    { MBEDTLS_CIPHER_AES_192_ECB,          &aes_192_ecb_info },
    { MBEDTLS_CIPHER_AES_256_ECB,          &aes_256_ecb_info },
#if defined(MBEDTLS_GCM_C)
    { MBEDTLS_CIPHER_AES_128_GCM,          &aes_128_gcm_info },
    { MBEDTLS_CIPHER_AES_192_GCM,          &aes_192_gcm_info },
    { MBEDTLS_CIPHER_AES_256_GCM,          &aes_256_gcm_info },
#endif
#endif /* MBEDTLS_AES_C */







#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
    { MBEDTLS_CIPHER_NULL,                 &null_cipher_info },
#endif /* MBEDTLS_CIPHER_NULL_CIPHER */

    { MBEDTLS_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS ( sizeof(mbedtls_cipher_definitions) /      \
                      sizeof(mbedtls_cipher_definitions[0]) )
int mbedtls_cipher_supported[NUM_CIPHERS];

