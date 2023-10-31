/*
 *  NIST SP800-38D compliant GCM implementation
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

/*
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * We use the algorithm described as Shoup's method with 4-bit tables in
 * [MGV] 4.1, pp. 12-13, to enhance speed without using too much memory.
 */


/* Parameter validation macros */
#define GCM_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_GCM_BAD_INPUT )
#define GCM_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#ifdef WIN32
#define LBLOCKSIZE 4 
#else
#define LBLOCKSIZE __SIZEOF_LONG__ 
#endif

static void xorbytes( unsigned char *dst, const unsigned char *src, int n) {
    while(n > LBLOCKSIZE) {
	*(unsigned long int *)dst ^= *(const unsigned long int *)src;
	dst += LBLOCKSIZE;
	src += LBLOCKSIZE;
	n -= LBLOCKSIZE;
    }
    while(n) {
	*dst++ ^= *src++;
	n--;
    }
}

static void xorbytes3d( unsigned char *output, unsigned char *buf,
		const unsigned char *ectr, const unsigned char *input, int n) {
    while(n > LBLOCKSIZE) {
	*(unsigned long int *)buf ^= *(const unsigned long int *)input;
	*(unsigned long int *)output = *(const unsigned long int *)input ^ *(const unsigned long int *)ectr;
	buf += LBLOCKSIZE;
	output += LBLOCKSIZE;
	ectr += LBLOCKSIZE;
	input += LBLOCKSIZE;
	n -= LBLOCKSIZE;
    }
    while(n) {
	*buf++ ^= *input;
	*output++ = *input++ ^ *ectr++;
	n--;
    }
}

static void xorbytes3e( unsigned char *output, unsigned char *buf,
		const unsigned char *ectr, const unsigned char *input, int n) {
    while(n > LBLOCKSIZE) {
	unsigned long int t = *(const unsigned long int *)input ^ *(const unsigned long int *)ectr;
	*(unsigned long int *)output = t;
	*(unsigned long int *)buf ^= t;
	buf += LBLOCKSIZE;
	output += LBLOCKSIZE;
	ectr += LBLOCKSIZE;
	input += LBLOCKSIZE;
	n -= LBLOCKSIZE;
    }
    while(n) {
	*output = *input++ ^ *ectr++;
	*buf++ ^= *output++;
	n--;
    }
}



/*
 * Initialize a context
 */
void mbedtls_gcm_init( mbedtls_gcm_context *ctx, void *aes_ctx )
{
    GCM_VALIDATE( ctx != NULL );
    memset( ctx, 0, sizeof( mbedtls_gcm_context ) );
    ctx->cipher_ctx.cipher_ctx = aes_ctx;
}

/*
 * Precompute small multiples of H, that is set
 *      HH[i] || HL[i] = H times i,
 * where i is seen as a field element as in [MGV], ie high-order bits
 * correspond to low powers of P. The result is stored in the same way, that
 * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
 * corresponds to P^127.
 */
static int gcm_gen_table( mbedtls_gcm_context *ctx )
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];
    size_t olen = 0;

    memset( h, 0, 16 );
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, h, 16, h, &olen ) ) != 0 )
        return( ret );

    /* pack h as two 64-bits ints, big-endian */
    hi = MBEDTLS_GET_UINT32_BE( h,  0  );
    lo = MBEDTLS_GET_UINT32_BE( h,  4  );
    vh = (uint64_t) hi << 32 | lo;

    hi = MBEDTLS_GET_UINT32_BE( h,  8  );
    lo = MBEDTLS_GET_UINT32_BE( h,  12 );
    vl = (uint64_t) hi << 32 | lo;

    /* 8 = 1000 corresponds to 1 in GF(2^128) */
    ctx->HL[8] = vl;
    ctx->HH[8] = vh;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    /* With CLMUL support, we need only h, not the rest of the table */
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_CLMUL ) ) {
	aes_aesni_has_support = 1;
        return( 0 );
    }
#endif

    /* 0 corresponds to 0 in GF(2^128) */
    ctx->HH[0] = 0;
    ctx->HL[0] = 0;

    for( i = 4; i > 0; i >>= 1 )
    {
        uint32_t T = ( vl & 1 ) * 0xe1000000U;
        vl  = ( vh << 63 ) | ( vl >> 1 );
        vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);

        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }

    for( i = 2; i <= 8; i *= 2 )
    {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for( j = 1; j < i; j++ )
        {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }

    return( 0 );
}

int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_cipher_info_t *cipher_info;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( key != NULL );
    GCM_VALIDATE_RET( keybits == 128 || keybits == 192 || keybits == 256 );

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits,
                                                   MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    if(ctx->cipher_ctx.cipher_ctx == NULL) return MBEDTLS_ERR_GCM_BAD_INPUT;
    if(!cipher_info->base->ctx_zero_func) return MBEDTLS_ERR_GCM_BAD_INPUT;
    (*cipher_info->base->ctx_zero_func)(ctx->cipher_ctx.cipher_ctx);
    ctx->cipher_ctx.cipher_info = cipher_info;

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = gcm_gen_table( ctx ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint64_t last4[16] =
{
    0x0000ULL << 48, 0x1c20ULL << 48, 0x3840ULL << 48, 0x2460ULL << 48,
    0x7080ULL << 48, 0x6ca0ULL << 48, 0x48c0ULL << 48, 0x54e0ULL << 48,
    0xe100ULL << 48, 0xfd20ULL << 48, 0xd940ULL << 48, 0xc560ULL << 48,
    0x9180ULL << 48, 0x8da0ULL << 48, 0xa9c0ULL << 48, 0xb5e0ULL << 48
};

/*
 * Sets output to x times H using the precomputed tables.
 * x and output are seen as elements of GF(2^128) as in [MGV].
 */
static void gcm_mult( mbedtls_gcm_context *ctx, const unsigned char x[16],
                      unsigned char output[16] )
{
    int i = 0;
    unsigned char lo, hi, rem;
    uint64_t zh, zl;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( aes_aesni_has_support) {
        unsigned char h[16];

        MBEDTLS_PUT_UINT64_BE( ctx->HH[8], h,  0 );
        MBEDTLS_PUT_UINT64_BE( ctx->HL[8], h,  8 );

        mbedtls_aesni_gcm_mult( output, x, h );
        return;
    }
#endif /* MBEDTLS_AESNI_C && MBEDTLS_HAVE_X86_64 */

    lo = x[15] & 0xf;

    zh = ctx->HH[lo];
    zl = ctx->HL[lo];

    for( i = 15; i >= 0; i-- )
    {
        lo = x[i] & 0xf;
        hi = ( x[i] >> 4 ) & 0xf;

        if( i != 15 )
        {
            rem = (unsigned char) zl & 0xf;
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem];
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];

        }

        rem = (unsigned char) zl & 0xf;
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zh ^= (uint64_t) last4[rem];
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
    }
    MBEDTLS_PUT_UINT64_BE( zh, output, 0 );
    MBEDTLS_PUT_UINT64_BE( zl, output, 8 );
}

int mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
                        int mode,
                        const unsigned char *iv, size_t iv_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char work_buf[16];
    const unsigned char *p;
    size_t use_len, olen = 0;
    uint64_t iv_bits;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );

    /* IV is limited to 2^64 bits, so 2^61 bytes */
    /* IV is not allowed to be zero length */
    if( iv_len == 0)
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
#if __SIZE_WIDTH__ == 64
    if( iv_len >= (1ULL << 32 ))
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
#endif

    memset( ctx->y, 0x00, sizeof(ctx->y) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );

    ctx->mode = mode;
    ctx->len = 0;
    ctx->add_len = 0;

    if( iv_len == 12 )
    {
        memcpy( ctx->y, iv, iv_len );
        ctx->y[15] = 1;
    }
    else
    {
        memset( work_buf, 0x00, 16 );
        iv_bits = (uint64_t)iv_len * 8;
        MBEDTLS_PUT_UINT64_BE( iv_bits, work_buf, 8 );

        p = iv;
        while( iv_len > 0 )
        {
            use_len = ( iv_len < 16 ) ? iv_len : 16;

	    xorbytes(ctx->y,p,use_len);

            gcm_mult( ctx, ctx->y, ctx->y );

            iv_len -= use_len;
            p += use_len;
        }

	xorbytes(ctx->y,work_buf,16);

        gcm_mult( ctx, ctx->y, ctx->y );
    }

    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, ctx->y, 16,
                                       ctx->base_ectr, &olen ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/**
 * mbedtls_gcm_context::buf contains the partial state of the computation of
 * the authentication tag.
 * mbedtls_gcm_context::add_len and mbedtls_gcm_context::len indicate
 * different stages of the computation:
 *     * len == 0 && add_len == 0:      initial state
 *     * len == 0 && add_len % 16 != 0: the first `add_len % 16` bytes have
 *                                      a partial block of AD that has been
 *                                      xored in but not yet multiplied in.
 *     * len == 0 && add_len % 16 == 0: the authentication tag is correct if
 *                                      the data ends now.
 *     * len % 16 != 0:                 the first `len % 16` bytes have
 *                                      a partial block of ciphertext that has
 *                                      been xored in but not yet multiplied in.
 *     * len > 0 && len % 16 == 0:      the authentication tag is correct if
 *                                      the data ends now.
 */
int mbedtls_gcm_update_ad( mbedtls_gcm_context *ctx,
                           const unsigned char *add, size_t add_len )
{
    const unsigned char *p;
    size_t use_len, offset;

    GCM_VALIDATE_RET( add_len == 0 || add != NULL );

    /* IV is limited to 2^64 bits, so 2^61 bytes */
    if( (uint64_t) add_len >> 61 != 0 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    offset = ctx->add_len % 16;
    p = add;

    if( offset != 0 )
    {
        use_len = 16 - offset;
        if( use_len > add_len )
            use_len = add_len;

	xorbytes(ctx->buf,p,use_len);

        if( offset + use_len == 16 )
            gcm_mult( ctx, ctx->buf, ctx->buf );

        ctx->add_len += use_len;
        add_len -= use_len;
        p += use_len;
    }

    ctx->add_len += add_len;

    while( add_len >= 16 )
    {
	xorbytes(ctx->buf,p,16);

        gcm_mult( ctx, ctx->buf, ctx->buf );

        add_len -= 16;
        p += 16;
    }

    if( add_len > 0 )
	xorbytes(ctx->buf,p,add_len);

    return( 0 );
}

/* Increment the counter. */
static void gcm_incr( unsigned char y[16] )
{
    size_t i;
    for( i = 16; i > 12; i-- )
        if( ++y[i - 1] != 0 )
            break;
}

/* Calculate and apply the encryption mask. Process use_len bytes of data,
 * starting at position offset in the mask block. */
static int gcm_mask( mbedtls_gcm_context *ctx,
                     unsigned char ectr[16],
                     size_t offset, size_t use_len,
                     const unsigned char *input,
                     unsigned char *output )
{
    size_t olen = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, ctx->y, 16, ectr,
                                       &olen ) ) != 0 )
    {
        mbedtls_platform_zeroize( ectr, 16 );
        return( ret );
    }

    if(ctx->mode == MBEDTLS_GCM_DECRYPT )
	    xorbytes3d(output,&ctx->buf[offset],&ectr[offset],input,use_len);
      else
	    xorbytes3e(output,&ctx->buf[offset],&ectr[offset],input,use_len);

    return( 0 );
}

int mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                        const unsigned char *input, size_t input_length,
                        unsigned char *output, size_t output_size,
                        size_t *output_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = input;
    unsigned char *out_p = output;
    size_t offset;
    unsigned char ectr[16];

    if( output_size < input_length )
        return( MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL );
    GCM_VALIDATE_RET( output_length != NULL );
    *output_length = input_length;

    /* Exit early if input_length==0 so that we don't do any pointer arithmetic
     * on a potentially null pointer.
     * Returning early also means that the last partial block of AD remains
     * untouched for mbedtls_gcm_finish */
    if( input_length == 0 )
        return( 0 );

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( input != NULL );
    GCM_VALIDATE_RET( output != NULL );

    if( output > input && (size_t) ( output - input ) < input_length )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
     * Also check for possible overflow */
    if( ctx->len + input_length < ctx->len ||
        (uint64_t) ctx->len + input_length > 0xFFFFFFFE0ull )
    {
        return( MBEDTLS_ERR_GCM_BAD_INPUT );
    }

    if( ctx->len == 0 && ctx->add_len % 16 != 0 )
    {
        gcm_mult( ctx, ctx->buf, ctx->buf );
    }

    offset = ctx->len % 16;
    if( offset != 0 )
    {
        size_t use_len = 16 - offset;
        if( use_len > input_length )
            use_len = input_length;

        if( ( ret = gcm_mask( ctx, ectr, offset, use_len, p, out_p ) ) != 0 )
            return( ret );

        if( offset + use_len == 16 )
            gcm_mult( ctx, ctx->buf, ctx->buf );

        ctx->len += use_len;
        input_length -= use_len;
        p += use_len;
        out_p += use_len;
    }

    ctx->len += input_length;

    while( input_length >= 16 )
    {
        gcm_incr( ctx->y );
        if( ( ret = gcm_mask( ctx, ectr, 0, 16, p, out_p ) ) != 0 )
            return( ret );

        gcm_mult( ctx, ctx->buf, ctx->buf );

        input_length -= 16;
        p += 16;
        out_p += 16;
    }

    if( input_length > 0 )
    {
        gcm_incr( ctx->y );
        if( ( ret = gcm_mask( ctx, ectr, 0, input_length, p, out_p ) ) != 0 )
            return( ret );
    }

    return( 0 );
}

int mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                        unsigned char *output, size_t output_size,
                        size_t *output_length,
                        unsigned char *tag, size_t tag_len )
{
    unsigned char work_buf[16];
    uint64_t orig_len;
    uint64_t orig_add_len;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    /* We never pass any output in finish(). The output parameter exists only
     * for the sake of alternative implementations. */
    (void) output;
    (void) output_size;
    *output_length = 0;

    orig_len = ctx->len * 8;
    orig_add_len = ctx->add_len * 8;

    if( ctx->len == 0 && ctx->add_len % 16 != 0 )
    {
        gcm_mult( ctx, ctx->buf, ctx->buf );
    }

    if( tag_len > 16 || tag_len < 4 )
        return( MBEDTLS_ERR_GCM_BAD_INPUT );

    if( ctx->len % 16 != 0 )
        gcm_mult( ctx, ctx->buf, ctx->buf );

    memcpy( tag, ctx->base_ectr, tag_len );

    if( orig_len || orig_add_len )
    {
        MBEDTLS_PUT_UINT64_BE( ( orig_add_len ), work_buf, 0  );
        MBEDTLS_PUT_UINT64_BE( ( orig_len ), work_buf, 8  );

	xorbytes(ctx->buf,work_buf,16);

        gcm_mult( ctx, ctx->buf, ctx->buf );

	xorbytes(tag,ctx->buf,tag_len);
    }

    return( 0 );
}

int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );
    GCM_VALIDATE_RET( tag != NULL );

    if( ( ret = mbedtls_gcm_starts( ctx, mode, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_update_ad( ctx, add, add_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_update( ctx, input, length,
                                    output, length, &olen ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_gcm_finish( ctx, NULL, 0, &olen, tag, tag_len ) ) != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char check_tag[16];
    size_t i;
    int diff;

    GCM_VALIDATE_RET( ctx != NULL );
    GCM_VALIDATE_RET( iv != NULL );
    GCM_VALIDATE_RET( add_len == 0 || add != NULL );
    GCM_VALIDATE_RET( tag != NULL );
    GCM_VALIDATE_RET( length == 0 || input != NULL );
    GCM_VALIDATE_RET( length == 0 || output != NULL );

    if( ( ret = mbedtls_gcm_crypt_and_tag( ctx, MBEDTLS_GCM_DECRYPT, length,
                                   iv, iv_len, add, add_len,
                                   input, output, tag_len, check_tag ) ) != 0 )
    {
        return( ret );
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        mbedtls_platform_zeroize( output, length );
        return( MBEDTLS_ERR_GCM_AUTH_FAILED );
    }

    return( 0 );
}

void mbedtls_gcm_free( mbedtls_gcm_context *ctx )
{
    if( ctx == NULL )
        return;
    // mbedtls_cipher_free( &ctx->cipher_ctx );
}

