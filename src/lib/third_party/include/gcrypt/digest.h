/*
 * hmac-sha256.c
 * Copyright (C) 2017 Adrian Perez <aperez@igalia.com>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef DIGEST_CRYPT_H
#define DIGEST_CRYPT_H

#define HMAC_SHA256_DIGEST_SIZE 32  /* Same as SHA-256's output size. */
#define SHA256_DIGEST_SIZE 32

typedef struct sha256_t
{
  uint32_t state[8];
  uint64_t count;
  unsigned char buffer[64];
} sha256_t;

void
hmac_sha256 (uint8_t out[HMAC_SHA256_DIGEST_SIZE],
             const uint8_t *data, size_t data_len,
             const uint8_t *key, size_t key_len);

#endif
