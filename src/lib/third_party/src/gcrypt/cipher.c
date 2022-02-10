/**
 * \file cipher.c
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


#define CIPHER_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA )
#define CIPHER_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

static int supported_init = 0;

const int *mbedtls_cipher_list( void )
{
    const mbedtls_cipher_definition_t *def;
    int *type;

    if( ! supported_init )
    {
        def = mbedtls_cipher_definitions;
        type = mbedtls_cipher_supported;

        while( def->type != 0 )
            *type++ = (*def++).type;

        *type = 0;

        supported_init = 1;
    }

    return( mbedtls_cipher_supported );
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_type(
    const mbedtls_cipher_type_t cipher_type )
{
    const mbedtls_cipher_definition_t *def;

    for( def = mbedtls_cipher_definitions; def->info != NULL; def++ )
        if( def->type == cipher_type )
            return( def->info );

    return( NULL );
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_string(
    const char *cipher_name )
{
    const mbedtls_cipher_definition_t *def;

    if( NULL == cipher_name )
        return( NULL );

    for( def = mbedtls_cipher_definitions; def->info != NULL; def++ )
        if( !  strcmp( def->info->name, cipher_name ) )
            return( def->info );

    return( NULL );
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_values(
    const mbedtls_cipher_id_t cipher_id,
    int key_bitlen,
    const mbedtls_cipher_mode_t mode )
{
    const mbedtls_cipher_definition_t *def;

    for( def = mbedtls_cipher_definitions; def->info != NULL; def++ )
        if( def->info->base->cipher == cipher_id &&
            def->info->key_bitlen == (unsigned) key_bitlen &&
            def->info->mode == mode )
            return( def->info );

    return( NULL );
}

void mbedtls_cipher_init( mbedtls_cipher_context_t *ctx )
{
    CIPHER_VALIDATE( ctx != NULL );
    memset( ctx, 0, sizeof( mbedtls_cipher_context_t ) );
}

int mbedtls_cipher_setkey( mbedtls_cipher_context_t *ctx,
                           const unsigned char *key,
                           int key_bitlen,
                           const mbedtls_operation_t operation )
{
    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( key != NULL );
    CIPHER_VALIDATE_RET( operation == MBEDTLS_ENCRYPT ||
                         operation == MBEDTLS_DECRYPT );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


    if( ( ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN ) == 0 &&
        (int) ctx->cipher_info->key_bitlen != key_bitlen )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    /*
     * For OFB, CFB and CTR mode always use the encryption key schedule
     */
    if( MBEDTLS_ENCRYPT == operation ||
        MBEDTLS_MODE_CFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_OFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_CTR == ctx->cipher_info->mode )
    {
        return( ctx->cipher_info->base->setkey_enc_func( ctx->cipher_ctx, key,
                                                         ctx->key_bitlen ) );
    }

    if( MBEDTLS_DECRYPT == operation )
        return( ctx->cipher_info->base->setkey_dec_func( ctx->cipher_ctx, key,
                                                         ctx->key_bitlen ) );

    return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
}

int mbedtls_cipher_set_iv( mbedtls_cipher_context_t *ctx,
                           const unsigned char *iv,
                           size_t iv_len )
{
    size_t actual_iv_size;

    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( iv_len == 0 || iv != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    /* avoid buffer overflow in ctx->iv */
    if( iv_len > MBEDTLS_MAX_IV_LENGTH )
        return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );

    if( ( ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_IV_LEN ) != 0 )
        actual_iv_size = iv_len;
    else
    {
        actual_iv_size = ctx->cipher_info->iv_size;

        /* avoid reading past the end of input buffer */
        if( actual_iv_size > iv_len )
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }


#if defined(MBEDTLS_GCM_C)
    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        return( mbedtls_gcm_starts( (mbedtls_gcm_context *) ctx->cipher_ctx,
                                    ctx->operation,
                                    iv, iv_len ) );
    }
#endif


    if ( actual_iv_size != 0 )
    {
        memcpy( ctx->iv, iv, actual_iv_size );
        ctx->iv_size = actual_iv_size;
    }

    return( 0 );
}

int mbedtls_cipher_reset( mbedtls_cipher_context_t *ctx )
{
    CIPHER_VALIDATE_RET( ctx != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


    ctx->unprocessed_len = 0;

    return( 0 );
}

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
int mbedtls_cipher_update_ad( mbedtls_cipher_context_t *ctx,
                      const unsigned char *ad, size_t ad_len )
{
    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( ad_len == 0 || ad != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


#if defined(MBEDTLS_GCM_C)
    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        return( mbedtls_gcm_update_ad( (mbedtls_gcm_context *) ctx->cipher_ctx,
                                       ad, ad_len ) );
    }
#endif


    return( 0 );
}
#endif /* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

int mbedtls_cipher_update( mbedtls_cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t block_size;

    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( ilen == 0 || input != NULL );
    CIPHER_VALIDATE_RET( output != NULL );
    CIPHER_VALIDATE_RET( olen != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


    *olen = 0;
    block_size = mbedtls_cipher_get_block_size( ctx );
    if ( 0 == block_size )
    {
        return( MBEDTLS_ERR_CIPHER_INVALID_CONTEXT );
    }

    if( ctx->cipher_info->mode == MBEDTLS_MODE_ECB )
    {
        if( ilen != block_size )
            return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        *olen = ilen;

        if( 0 != ( ret = ctx->cipher_info->base->ecb_func( ctx->cipher_ctx,
                    ctx->operation, input, output ) ) )
        {
            return( ret );
        }

        return( 0 );
    }

#if defined(MBEDTLS_GCM_C)
    if( ctx->cipher_info->mode == MBEDTLS_MODE_GCM )
    {
        return( mbedtls_gcm_update( (mbedtls_gcm_context *) ctx->cipher_ctx,
                                    input, ilen,
                                    output, ilen, olen ) );
    }
#endif



    if( input == output &&
       ( ctx->unprocessed_len != 0 || ilen % block_size ) )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( ctx->cipher_info->mode == MBEDTLS_MODE_CBC )
    {
        size_t copy_len = 0;

        /*
         * If there is not enough data for a full block, cache it.
         */
        if( ( ctx->operation == MBEDTLS_DECRYPT && NULL != ctx->add_padding &&
                ilen <= block_size - ctx->unprocessed_len ) ||
            ( ctx->operation == MBEDTLS_DECRYPT && NULL == ctx->add_padding &&
                ilen < block_size - ctx->unprocessed_len ) ||
             ( ctx->operation == MBEDTLS_ENCRYPT &&
                ilen < block_size - ctx->unprocessed_len ) )
        {
            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    ilen );

            ctx->unprocessed_len += ilen;
            return( 0 );
        }

        /*
         * Process cached data first
         */
        if( 0 != ctx->unprocessed_len )
        {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    copy_len );

            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, block_size, ctx->iv,
                    ctx->unprocessed_data, output ) ) )
            {
                return( ret );
            }

            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if( 0 != ilen )
        {
            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = ilen % block_size;
            if( copy_len == 0 &&
                ctx->operation == MBEDTLS_DECRYPT &&
                NULL != ctx->add_padding)
            {
                copy_len = block_size;
            }

            memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    copy_len );

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if( ilen )
        {
            if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                    ctx->operation, ilen, ctx->iv, input, output ) ) )
            {
                return( ret );
            }

            *olen += ilen;
        }

        return( 0 );
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */






    return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}


int mbedtls_cipher_finish( mbedtls_cipher_context_t *ctx,
                   unsigned char *output, size_t *olen )
{
    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( output != NULL );
    CIPHER_VALIDATE_RET( olen != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


    *olen = 0;

    if( MBEDTLS_MODE_CFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_OFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_CTR == ctx->cipher_info->mode ||
        MBEDTLS_MODE_GCM == ctx->cipher_info->mode ||
        MBEDTLS_MODE_CCM_STAR_NO_TAG == ctx->cipher_info->mode ||
        MBEDTLS_MODE_XTS == ctx->cipher_info->mode ||
        MBEDTLS_MODE_STREAM == ctx->cipher_info->mode )
    {
        return( 0 );
    }

    if ( ( MBEDTLS_CIPHER_CHACHA20          == ctx->cipher_info->type ) ||
         ( MBEDTLS_CIPHER_CHACHA20_POLY1305 == ctx->cipher_info->type ) )
    {
        return( 0 );
    }

    if( MBEDTLS_MODE_ECB == ctx->cipher_info->mode )
    {
        if( ctx->unprocessed_len != 0 )
            return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        return( 0 );
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if( MBEDTLS_MODE_CBC == ctx->cipher_info->mode )
    {
        int ret = 0;

        if( MBEDTLS_ENCRYPT == ctx->operation )
        {
            /* check for 'no padding' mode */
            if( NULL == ctx->add_padding )
            {
                if( 0 != ctx->unprocessed_len )
                    return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

                return( 0 );
            }

            ctx->add_padding( ctx->unprocessed_data, mbedtls_cipher_get_iv_size( ctx ),
                    ctx->unprocessed_len );
        }
        else if( mbedtls_cipher_get_block_size( ctx ) != ctx->unprocessed_len )
        {
            /*
             * For decrypt operations, expect a full block,
             * or an empty block if no padding
             */
            if( NULL == ctx->add_padding && 0 == ctx->unprocessed_len )
                return( 0 );

            return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );
        }

        /* cipher block */
        if( 0 != ( ret = ctx->cipher_info->base->cbc_func( ctx->cipher_ctx,
                ctx->operation, mbedtls_cipher_get_block_size( ctx ), ctx->iv,
                ctx->unprocessed_data, output ) ) )
        {
            return( ret );
        }

        /* Set output size for decryption */
        if( MBEDTLS_DECRYPT == ctx->operation )
            return( ctx->get_padding( output, mbedtls_cipher_get_block_size( ctx ),
                                      olen ) );

        /* Set output size for encryption */
        *olen = mbedtls_cipher_get_block_size( ctx );
        return( 0 );
    }
#else
    ((void) output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

    return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}


#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
int mbedtls_cipher_write_tag( mbedtls_cipher_context_t *ctx,
                      unsigned char *tag, size_t tag_len )
{
    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( tag_len == 0 || tag != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( MBEDTLS_ENCRYPT != ctx->operation )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );


#if defined(MBEDTLS_GCM_C)
    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        size_t output_length;
        /* The code here doesn't yet support alternative implementations
         * that can delay up to a block of output. */
        return( mbedtls_gcm_finish( (mbedtls_gcm_context *) ctx->cipher_ctx,
                                    NULL, 0, &output_length,
                                    tag, tag_len ) );
    }
#endif


    return( 0 );
}

int mbedtls_cipher_check_tag( mbedtls_cipher_context_t *ctx,
                      const unsigned char *tag, size_t tag_len )
{
    unsigned char check_tag[16];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( tag_len == 0 || tag != NULL );
    if( ctx->cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( MBEDTLS_DECRYPT != ctx->operation )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }


    /* Status to return on a non-authenticated algorithm. It would make sense
     * to return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT or perhaps
     * MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA, but at the time I write this our
     * unit tests assume 0. */
    ret = 0;

#if defined(MBEDTLS_GCM_C)
    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        size_t output_length;
        /* The code here doesn't yet support alternative implementations
         * that can delay up to a block of output. */

        if( tag_len > sizeof( check_tag ) )
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

        if( 0 != ( ret = mbedtls_gcm_finish(
                       (mbedtls_gcm_context *) ctx->cipher_ctx,
                       NULL, 0, &output_length,
                       check_tag, tag_len ) ) )
        {
            return( ret );
        }

        /* Check the tag in "constant-time" */
        if( mbedtls_ct_memcmp( tag, check_tag, tag_len ) != 0 )
        {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto exit;
        }
    }
#endif /* MBEDTLS_GCM_C */


exit:
    mbedtls_platform_zeroize( check_tag, tag_len );
    return( ret );
}
#endif /* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

/*
 * Packet-oriented wrapper for non-AEAD modes
 */
int mbedtls_cipher_crypt( mbedtls_cipher_context_t *ctx,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *input, size_t ilen,
                  unsigned char *output, size_t *olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t finish_olen;

    CIPHER_VALIDATE_RET( ctx != NULL );
    CIPHER_VALIDATE_RET( iv_len == 0 || iv != NULL );
    CIPHER_VALIDATE_RET( ilen == 0 || input != NULL );
    CIPHER_VALIDATE_RET( output != NULL );
    CIPHER_VALIDATE_RET( olen != NULL );


    if( ( ret = mbedtls_cipher_set_iv( ctx, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_reset( ctx ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_update( ctx, input, ilen,
                                       output, olen ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_finish( ctx, output + *olen,
                                       &finish_olen ) ) != 0 )
        return( ret );

    *olen += finish_olen;

    return( 0 );
}

