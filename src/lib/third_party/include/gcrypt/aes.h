/**
 * \file aes.h
 *
 * \brief   This file contains AES definitions and functions.
 *
 *          The Advanced Encryption Standard (AES) specifies a FIPS-approved
 *          cryptographic algorithm that can be used to protect electronic
 *          data.
 *
 *          The AES algorithm is a symmetric block cipher that can
 *          encrypt and decrypt information. For more information, see
 *          <em>FIPS Publication 197: Advanced Encryption Standard</em> and
 *          <em>ISO/IEC 18033-2:2006: Information technology -- Security
 *          techniques -- Encryption algorithms -- Part 2: Asymmetric
 *          ciphers</em>.
 *
 *          The AES-XTS block mode is standardized by NIST SP 800-38E
 *          <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
 *          and described in detail by IEEE P1619
 *          <https://ieeexplore.ieee.org/servlet/opac?punumber=4375278>.
 */

/*
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

#ifndef MBEDTLS_AES_H
#define MBEDTLS_AES_H



/* padlock.c and aesni.c rely on these values! */
#define MBEDTLS_AES_ENCRYPT     1 /**< AES encryption. */
#define MBEDTLS_AES_DECRYPT     0 /**< AES decryption. */

/* Error codes in range 0x0020-0x0022 */
/** Invalid key length. */
#define MBEDTLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020
/** Invalid data input length. */
#define MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022

/* Error codes in range 0x0021-0x0025 */
/** Invalid input data. */
#define MBEDTLS_ERR_AES_BAD_INPUT_DATA                    -0x0021

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Regular implementation
//

/**
 * \brief The AES context-type definition.
 */
typedef struct mbedtls_aes_context
{
    int nr;                     /*!< The number of rounds. */
    uint32_t *rk;               /*!< AES round keys. */
    uint32_t buf[68];           /*!< Unaligned data buffer. This buffer can
                                     hold 32 extra Bytes, which can be used for
                                     one of the following purposes:
                                     <ul><li>Alignment if VIA padlock is
                                             used.</li>
                                     <li>Simplifying key expansion in the 256-bit
                                         case by generating an extra round key.
                                         </li></ul> */
}
mbedtls_aes_context;



/**
 * \brief          This function initializes the specified AES context.
 *
 *                 It must be the first API called before using
 *                 the context.
 *
 * \param ctx      The AES context to initialize. This must not be \c NULL.
 */
void mbedtls_aes_init( mbedtls_aes_context *ctx );

/**
 * \brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 *                 If this is \c NULL, this function does nothing.
 *                 Otherwise, the context must have been at least initialized.
 */
void mbedtls_aes_free( mbedtls_aes_context *ctx );


/**
 * \brief          This function sets the encryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The encryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 * \param keybits  The size of data passed in bits. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          This function sets the decryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The decryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 * \param keybits  The size of data passed. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>192 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );


/**
 * \brief          This function performs an AES single-block encryption or
 *                 decryption operation.
 *
 *                 It performs the operation defined in the \p mode parameter
 *                 (encrypt or decrypt), on the input data buffer defined in
 *                 the \p input parameter.
 *
 *                 mbedtls_aes_init(), and either mbedtls_aes_setkey_enc() or
 *                 mbedtls_aes_setkey_dec() must be called before the first
 *                 call to this API with the same context.
 *
 * \param ctx      The AES context to use for encryption or decryption.
 *                 It must be initialized and bound to a key.
 * \param mode     The AES operation: #MBEDTLS_AES_ENCRYPT or
 *                 #MBEDTLS_AES_DECRYPT.
 * \param input    The buffer holding the input data.
 *                 It must be readable and at least \c 16 Bytes long.
 * \param output   The buffer where the output data will be written.
 *                 It must be writeable and at least \c 16 Bytes long.

 * \return         \c 0 on success.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief  This function performs an AES-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed. mbedtls_aes_init(), and either
 *         mbedtls_aes_setkey_enc() or mbedtls_aes_setkey_dec() must be called
 *         before the first call to this API with the same context.
 *
 * \note   This function operates on full blocks, that is, the input size
 *         must be a multiple of the AES block size of \c 16 Bytes.
 *
 * \note   Upon exit, the content of the IV is updated so that you can
 *         call the same function again on the next
 *         block(s) of data and get the same result as if it was
 *         encrypted in one call. This allows a "streaming" usage.
 *         If you need to retain the contents of the IV, you should
 *         either save it manually or use the cipher module instead.
 *
 *
 * \param ctx      The AES context to use for encryption or decryption.
 *                 It must be initialized and bound to a key.
 * \param mode     The AES operation: #MBEDTLS_AES_ENCRYPT or
 *                 #MBEDTLS_AES_DECRYPT.
 * \param length   The length of the input data in Bytes. This must be a
 *                 multiple of the block size (\c 16 Bytes).
 * \param iv       Initialization vector (updated after use).
 *                 It must be a readable and writeable buffer of \c 16 Bytes.
 * \param input    The buffer holding the input data.
 *                 It must be readable and of size \p length Bytes.
 * \param output   The buffer holding the output data.
 *                 It must be writeable and of size \p length Bytes.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH
 *                 on failure.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */





/**
 * \brief           Internal AES block encryption function. This is only
 *                  exposed to allow overriding it using
 *                  \c MBEDTLS_AES_ENCRYPT_ALT.
 *
 * \param ctx       The AES context to use for encryption.
 * \param input     The plaintext block.
 * \param output    The output (ciphertext) block.
 *
 * \return          \c 0 on success.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );

/**
 * \brief           Internal AES block decryption function. This is only
 *                  exposed to allow overriding it using see
 *                  \c MBEDTLS_AES_DECRYPT_ALT.
 *
 * \param ctx       The AES context to use for decryption.
 * \param input     The ciphertext block.
 * \param output    The output (plaintext) block.
 *
 * \return          \c 0 on success.
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );


#ifdef __cplusplus
}
#endif

#endif /* aes.h */
