/*
 *  FIPS-197 compliant AES implementation
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
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */


/* Parameter validation macros based on platform_util.h */
#define AES_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_AES_BAD_INPUT_DATA )
#define AES_VALIDATE( cond )       MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Forward S-box & tables
 */
static unsigned char FSb[256];
static uint32_t FT0[256];
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

/*
 * Reverse S-box & tables
 */
static unsigned char RSb[256];
static uint32_t RT0[256];
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define XTIME(x) ( ( (x) << 1 ) ^ ( ( (x) & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( (x) && (y) ) ? pow[(log[(x)]+log[(y)]) % 255] : 0 )

static int aes_init_done = 0;
int aes_aesni_has_support = 0;

static void aes_gen_tables( void )
{
    int i, x, y, z;
    int pow[256];
    int log[256];

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( mbedtls_aesni_has_support( MBEDTLS_AESNI_AES ) )
        aes_aesni_has_support = 1;
    else
        aes_aesni_has_support = 0;
#endif

    /*
     * compute pow and log tables over GF(2^8)
     */
    for( i = 0, x = 1; i < 256; i++ )
    {
        pow[i] = x;
        log[x] = i;
        x = MBEDTLS_BYTE_0( x ^ XTIME( x ) );
    }

    /*
     * calculate the round constants
     */
    for( i = 0, x = 1; i < 10; i++ )
    {
        RCON[i] = (uint32_t) x;
        x = MBEDTLS_BYTE_0( XTIME( x ) );
    }

    /*
     * generate the forward and reverse S-boxes
     */
    FSb[0x00] = 0x63;
    RSb[0x63] = 0x00;

    for( i = 1; i < 256; i++ )
    {
        x = pow[255 - log[i]];

        y  = x; y = MBEDTLS_BYTE_0( ( y << 1 ) | ( y >> 7 ) );
        x ^= y; y = MBEDTLS_BYTE_0( ( y << 1 ) | ( y >> 7 ) );
        x ^= y; y = MBEDTLS_BYTE_0( ( y << 1 ) | ( y >> 7 ) );
        x ^= y; y = MBEDTLS_BYTE_0( ( y << 1 ) | ( y >> 7 ) );
        x ^= y ^ 0x63;

        FSb[i] = (unsigned char) x;
        RSb[x] = (unsigned char) i;
    }

    /*
     * generate the forward and reverse tables
     */
    for( i = 0; i < 256; i++ )
    {
        x = FSb[i];
        y = MBEDTLS_BYTE_0( XTIME( x ) );
        z = MBEDTLS_BYTE_0( y ^ x );

        FT0[i] = ( (uint32_t) y       ) ^
                 ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^
                 ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
    }
}

#define AES_RT0(idx) RT0[idx]
#define AES_RT1(idx) RT1[idx]
#define AES_RT2(idx) RT2[idx]
#define AES_RT3(idx) RT3[idx]

#define AES_FT0(idx) FT0[idx]
#define AES_FT1(idx) FT1[idx]
#define AES_FT2(idx) FT2[idx]
#define AES_FT3(idx) FT3[idx]

void mbedtls_aes_init( mbedtls_aes_context *ctx )
{
    AES_VALIDATE( ctx != NULL );

    memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
    if( ctx == NULL )
        return;

    // mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aes_context ) );
}


/*
 * AES key schedule (encryption)
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    unsigned int i;
    uint32_t *RK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    switch( keybits )
    {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default : return( MBEDTLS_ERR_AES_INVALID_KEY_LENGTH );
    }

    if( aes_init_done == 0 )
    {
        aes_gen_tables();

        /* Allow to test both aesni and not aesni data path when fuzzing.
           We can call aes_gen_tables() at every iteration without any issues
           (performances asides) */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        aes_init_done = 1;
#endif
    }

    ctx->rk = RK = ctx->buf;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( aes_aesni_has_support )
        return( mbedtls_aesni_setkey_enc( (unsigned char *) ctx->rk, key, keybits ) );
#endif

    for( i = 0; i < ( keybits >> 5 ); i++ )
    {
        RK[i] = MBEDTLS_GET_UINT32_LE( key, i << 2 );
    }

    switch( ctx->nr )
    {
        case 10:

            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_1( RK[3] ) ]       ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_2( RK[3] ) ] <<  8 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_3( RK[3] ) ] << 16 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_0( RK[3] ) ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_1( RK[5] ) ]       ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_2( RK[5] ) ] <<  8 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_3( RK[5] ) ] << 16 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_0( RK[5] ) ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_1( RK[7] ) ]       ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_2( RK[7] ) ] <<  8 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_3( RK[7] ) ] << 16 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_0( RK[7] ) ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_0( RK[11] ) ]       ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_1( RK[11] ) ] <<  8 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_2( RK[11] ) ] << 16 ) ^
                ( (uint32_t) FSb[ MBEDTLS_BYTE_3( RK[11] ) ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;
    }

    return( 0 );
}

/*
 * AES key schedule (decryption)
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    int i, j, ret;
    mbedtls_aes_context cty;
    uint32_t *RK;
    uint32_t *SK;

    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( key != NULL );

    mbedtls_aes_init( &cty );

    ctx->rk = RK = ctx->buf;

    /* Also checks keybits */
    if( ( ret = mbedtls_aes_setkey_enc( &cty, key, keybits ) ) != 0 )
        goto exit;

    ctx->nr = cty.nr;

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( aes_aesni_has_support ) {
        mbedtls_aesni_inverse_key( (unsigned char *) ctx->rk,
                           (const unsigned char *) cty.rk, ctx->nr );
        goto exit;
    }
#endif

    SK = cty.rk + cty.nr * 4;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for( i = ctx->nr - 1, SK -= 8; i > 0; i--, SK -= 8 )
    {
        for( j = 0; j < 4; j++, SK++ )
        {
            *RK++ = AES_RT0( FSb[ MBEDTLS_BYTE_0( *SK ) ] ) ^
                    AES_RT1( FSb[ MBEDTLS_BYTE_1( *SK ) ] ) ^
                    AES_RT2( FSb[ MBEDTLS_BYTE_2( *SK ) ] ) ^
                    AES_RT3( FSb[ MBEDTLS_BYTE_3( *SK ) ] );
        }
    }

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

exit:
    mbedtls_aes_free( &cty );

    return( ret );
}

#define AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
 { uint32_t T; \
    X0 = *RK++; X1 = *RK++; X2 = *RK++; X3 = *RK++; \
    T=Y0; \
    X0 ^= FT0[ ( T ) & 0xFF ]; T >>= 8; \
    X3 ^= FT1[ ( T ) & 0xFF ]; T >>= 8; \
    X2 ^= FT2[ ( T ) & 0xFF ]; T >>= 8; \
    X1 ^= FT3[ ( T ) & 0xFF ]; \
    T=Y1; \
    X1 ^= FT0[ ( T ) & 0xFF ]; T >>= 8; \
    X0 ^= FT1[ ( T ) & 0xFF ]; T >>= 8; \
    X3 ^= FT2[ ( T ) & 0xFF ]; T >>= 8; \
    X2 ^= FT3[ ( T ) & 0xFF ]; \
    T=Y2; \
    X2 ^= FT0[ ( T ) & 0xFF ]; T >>= 8; \
    X1 ^= FT1[ ( T ) & 0xFF ]; T >>= 8; \
    X0 ^= FT2[ ( T ) & 0xFF ]; T >>= 8; \
    X3 ^= FT3[ ( T ) & 0xFF ]; \
    T=Y3; \
    X3 ^= FT0[ ( T ) & 0xFF ]; T >>= 8; \
    X2 ^= FT1[ ( T ) & 0xFF ]; T >>= 8; \
    X1 ^= FT2[ ( T ) & 0xFF ]; T >>= 8; \
    X0 ^= FT3[ ( T ) & 0xFF ]; \
 }

#define AES_RROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{ uint32_t T;                                       \
    X0 = *RK++; X1 = *RK++; X2 = *RK++; X3 = *RK++; \
    T=Y0; \
    X0 ^= RT0[ ( T ) & 0xFF ]; T >>= 8;  \
    X1 ^= RT1[ ( T ) & 0xFF ]; T >>= 8;  \
    X2 ^= RT2[ ( T ) & 0xFF ]; T >>= 8;  \
    X3 ^= RT3[ ( T ) & 0xFF ];  \
    T=Y1; \
    X1 ^= RT0[ ( T ) & 0xFF ]; T >>= 8;  \
    X2 ^= RT1[ ( T ) & 0xFF ]; T >>= 8;  \
    X3 ^= RT2[ ( T ) & 0xFF ]; T >>= 8;  \
    X0 ^= RT3[ ( T ) & 0xFF ];  \
    T=Y2; \
    X2 ^= RT0[ ( T ) & 0xFF ]; T >>= 8;  \
    X3 ^= RT1[ ( T ) & 0xFF ]; T >>= 8;  \
    X0 ^= RT2[ ( T ) & 0xFF ]; T >>= 8;  \
    X2 ^= RT3[ ( T ) & 0xFF ];   \
    T=Y3; \
    X3 ^= RT0[ ( T ) & 0xFF ]; T >>= 8;  \
    X0 ^= RT1[ ( T ) & 0xFF ]; T >>= 8;  \
    X1 ^= RT2[ ( T ) & 0xFF ]; T >>= 8;  \
    X2 ^= RT3[ ( T ) & 0xFF ];   \
}

/*
 * AES-ECB block encryption
 */
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t T0,*RK = ctx->rk;
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    t.X[0] = MBEDTLS_GET_UINT32_LE( input,  0 ); t.X[0] ^= *RK++;
    t.X[1] = MBEDTLS_GET_UINT32_LE( input,  4 ); t.X[1] ^= *RK++;
    t.X[2] = MBEDTLS_GET_UINT32_LE( input,  8 ); t.X[2] ^= *RK++;
    t.X[3] = MBEDTLS_GET_UINT32_LE( input, 12 ); t.X[3] ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_FROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    AES_FROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
#define AES_XROUND(X,Y0,Y1,Y2,Y3) \
    T0  = FSb[ ( Y3 >> 24 ) & 0xFF ]; T0 <<= 8; \
    T0 |= FSb[ ( Y2 >> 16 ) & 0xFF ]; T0 <<= 8; \
    T0 |= FSb[ ( Y1 >>  8 ) & 0xFF ]; T0 <<= 8;\
    T0 |= FSb[ ( Y0       ) & 0xFF ]; \
    X = *RK++ ^ T0

    AES_XROUND(t.X[0],t.Y[0],t.Y[1],t.Y[2],t.Y[3]);
    AES_XROUND(t.X[1],t.Y[1],t.Y[2],t.Y[3],t.Y[0]);
    AES_XROUND(t.X[2],t.Y[2],t.Y[3],t.Y[0],t.Y[1]);
    AES_XROUND(t.X[3],t.Y[3],t.Y[0],t.Y[1],t.Y[2]);
#undef AES_XROUND

    MBEDTLS_PUT_UINT32_LE( t.X[0], output,  0 );
    MBEDTLS_PUT_UINT32_LE( t.X[1], output,  4 );
    MBEDTLS_PUT_UINT32_LE( t.X[2], output,  8 );
    MBEDTLS_PUT_UINT32_LE( t.X[3], output, 12 );

    return( 0 );
}

/*
 * AES-ECB block decryption
 */
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    int i;
    uint32_t T0,*RK = ctx->rk;
    struct
    {
        uint32_t X[4];
        uint32_t Y[4];
    } t;

    t.X[0] = MBEDTLS_GET_UINT32_LE( input,  0 ); t.X[0] ^= *RK++;
    t.X[1] = MBEDTLS_GET_UINT32_LE( input,  4 ); t.X[1] ^= *RK++;
    t.X[2] = MBEDTLS_GET_UINT32_LE( input,  8 ); t.X[2] ^= *RK++;
    t.X[3] = MBEDTLS_GET_UINT32_LE( input, 12 ); t.X[3] ^= *RK++;

    for( i = ( ctx->nr >> 1 ) - 1; i > 0; i-- )
    {
        AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
        AES_RROUND( t.X[0], t.X[1], t.X[2], t.X[3], t.Y[0], t.Y[1], t.Y[2], t.Y[3] );
    }

    AES_RROUND( t.Y[0], t.Y[1], t.Y[2], t.Y[3], t.X[0], t.X[1], t.X[2], t.X[3] );
#define AES_XROUNDD(X,Y0,Y1,Y2,Y3) \
    T0  = RSb[ ( Y3 >> 24 ) & 0xFF ]; T0 <<= 8; \
    T0 |= RSb[ ( Y2 >> 16 ) & 0xFF ]; T0 <<= 8; \
    T0 |= RSb[ ( Y1 >>  8 ) & 0xFF ]; T0 <<= 8;\
    T0 |= RSb[ ( Y0       ) & 0xFF ]; \
    X = *RK++ ^ T0

    AES_XROUNDD(t.X[0],t.Y[0],t.Y[3],t.Y[2],t.Y[1]);
    AES_XROUNDD(t.X[1],t.Y[1],t.Y[0],t.Y[3],t.Y[2]);
    AES_XROUNDD(t.X[2],t.Y[2],t.Y[1],t.Y[0],t.Y[3]);
    AES_XROUNDD(t.X[3],t.Y[3],t.Y[2],t.Y[1],t.Y[0]);

#undef AES_XROUNDD

    MBEDTLS_PUT_UINT32_LE( t.X[0], output,  0 );
    MBEDTLS_PUT_UINT32_LE( t.X[1], output,  4 );
    MBEDTLS_PUT_UINT32_LE( t.X[2], output,  8 );
    MBEDTLS_PUT_UINT32_LE( t.X[3], output, 12 );

    return( 0 );
}

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                           int mode,
                           const unsigned char input[16],
                           unsigned char output[16] )
{
    AES_VALIDATE_RET( ctx != NULL );
    AES_VALIDATE_RET( input != NULL );
    AES_VALIDATE_RET( output != NULL );
    AES_VALIDATE_RET( mode == MBEDTLS_AES_ENCRYPT ||
                      mode == MBEDTLS_AES_DECRYPT );

#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
    if( aes_aesni_has_support )
        return( mbedtls_aesni_crypt_ecb( ctx, mode, input, output ) );
#endif


    if( mode == MBEDTLS_AES_ENCRYPT )
        return( mbedtls_internal_aes_encrypt( ctx, input, output ) );
    else
        return( mbedtls_internal_aes_decrypt( ctx, input, output ) );
}

