/*********************************************************************
 * Filename:   sha256.h
 * Author:     Brad Conte (brad AT bradconte.com)
 * Copyright:
 * Disclaimer: This code is presented "as is" without any guarantees.
 * Details:    Defines the API for the corresponding SHA1 implementation.
 *********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include "ndpi_typedefs.h"

/****************************** MACROS ******************************/

#define NDPI_SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
  u_int8_t data[64];
  u_int32_t datalen;
  unsigned long long bitlen;
  u_int32_t state[8];
} ndpi_SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/

void ndpi_sha256_init(ndpi_SHA256_CTX *ctx);
void ndpi_sha256_update(ndpi_SHA256_CTX *ctx, const u_int8_t data[], size_t len);
void ndpi_sha256_final(ndpi_SHA256_CTX *ctx, u_int8_t hash[]);

#endif   // SHA256_H
