
#include <stdint.h>
#if !defined(WIN32) && !defined(_MSC_VER)
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>

#include "ndpi_api.h"

#if defined(__GNUC__) &&  \
        ( defined(__amd64__) || defined(__x86_64__) )   &&  \
    ! defined(MBEDTLS_HAVE_X86_64)
#define MBEDTLS_HAVE_X86_64
#define MBEDTLS_AESNI_C
#endif

/****************************/
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
/****************************/

#define mbedtls_calloc    ndpi_calloc
#define mbedtls_free       ndpi_free

#include "gcrypt_light.h"

#define MBEDTLS_CHECK_RETURN_TYPICAL
#define MBEDTLS_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
#define MBEDTLS_INTERNAL_VALIDATE( cond )           do { } while( 0 )

#define mbedtls_platform_zeroize(a,b) memset(a,0,b)
#define mbedtls_ct_memcmp(s1,s2,n) memcmp(s1,s2,n)

#include "gcrypt/common.h"
#include "gcrypt/error.h"
#include "gcrypt/aes.h"
#if defined(MBEDTLS_AESNI_C)
#include "gcrypt/aesni.h"
#endif
#include "gcrypt/cipher.h"
#include "gcrypt/gcm.h"
#include "gcrypt/digest.h"
#include "gcrypt/cipher_wrap.h"


#include "gcrypt/aes.c"
#if defined(MBEDTLS_AESNI_C) && defined(MBEDTLS_HAVE_X86_64)
#include "gcrypt/aesni.c"
#endif

#include "gcrypt/gcm.c"

#include "gcrypt/cipher.c"
#include "gcrypt/cipher_wrap.c"
#include "gcrypt/digest.c"

#define MBEDTLS_ERR_MD_ALLOC_FAILED 0x50f0
#define MBEDTLS_ERR_MD_NOT_SUPPORT 0x50f1
#define MBEDTLS_ERR_MD_REKEY 0x50f2
#define MBEDTLS_ERR_MD_DATA_TOO_BIG 0x50f3
#define MBEDTLS_ERR_CIPHER_BAD_KEY 0x50f4
#define MBEDTLS_ERR_GCM_ALLOC_FAILED 0x50f5
#define MBEDTLS_ERR_GCM_NOT_SUPPORT 0x50f6
#define MBEDTLS_ERR_GCM_MISSING_KEY 0x50f7
#define MBEDTLS_ERR_AES_MISSING_KEY 0x50f8
#define MBEDTLS_ERR_NOT_SUPPORT 0x50f9

const char *gcry_errstr(gcry_error_t err) {
    switch(err) {
        case MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED: return "Corruption detected";
        case MBEDTLS_ERR_MD_ALLOC_FAILED: return "MD:Alloc failed";
        case MBEDTLS_ERR_MD_NOT_SUPPORT: return "MD:Not supported";
        case MBEDTLS_ERR_MD_REKEY: return "MD:Key already set";
        case MBEDTLS_ERR_MD_DATA_TOO_BIG: return "MD:Data is too long";
        case MBEDTLS_ERR_AES_BAD_INPUT_DATA: return "AES:Bad input data";
        case MBEDTLS_ERR_AES_MISSING_KEY: return "AES:No key";
        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH: return "AES:Invalid key length";
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH: return "AES:Invalid input length";
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA: return "CIPHER:Bad input data";
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED: return "CIPHER:Alloc failed";
        case MBEDTLS_ERR_CIPHER_BAD_KEY: return "CIPHER:Wrong key/iv";
        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE: return "CIPHER:Feature unavailable";
        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT: return "CIPHER:Invalid context";
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED: return "CIPHER:Full block expected";
        case MBEDTLS_ERR_CIPHER_AUTH_FAILED: return "CIPHER:Auth failed";
        case MBEDTLS_ERR_GCM_AUTH_FAILED: return "GCM:Auth failed";
        case MBEDTLS_ERR_GCM_BAD_INPUT: return "GCM:Bad input";
        case MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL: return "GCM:Buffer too small";
        case MBEDTLS_ERR_GCM_ALLOC_FAILED: return "GCM:Alloc failed";
        case MBEDTLS_ERR_GCM_NOT_SUPPORT: return "GCM:Not supported";
        case MBEDTLS_ERR_GCM_MISSING_KEY: return "GCM:No key/siv/auth";
        case MBEDTLS_ERR_NOT_SUPPORT: return "Not supported";
    }
    return "Unknown error code";
}

char *gpg_strerror_r(gcry_error_t err,char *buf, size_t buflen) {
    const char *err_txt = gcry_errstr(err);
    strncpy(buf,err_txt,buflen-1);
    return buf;
}

int gcry_control (int ctl,int val) {
    if(ctl == GCRYCTL_INITIALIZATION_FINISHED ||
       (ctl == 1 && val == 0) /* GCRYCTL_INITIALIZATION_FINISHED_P */)
        return GPG_ERR_NO_ERROR;
    return MBEDTLS_ERR_NOT_SUPPORT;
}

const char *gcry_check_version(void *unused) {
    return "1.8.6internal";
}

gcry_error_t gcry_md_open(gcry_md_hd_t *h,int algo,int flags) {
    gcry_md_hd_t ctx;
    if(!(algo == GCRY_MD_SHA256 && flags == GCRY_MD_FLAG_HMAC)) return MBEDTLS_ERR_MD_NOT_SUPPORT;
    ctx = ndpi_calloc(1,sizeof(struct gcry_md_hd));
    if(!ctx) return MBEDTLS_ERR_MD_ALLOC_FAILED;
    *h = ctx;
    return GPG_ERR_NO_ERROR;
}

void gcry_md_close(gcry_md_hd_t h) {
    if(h) ndpi_free(h);
}

void gcry_md_reset(gcry_md_hd_t h) {
    memset((char *)h, 0, sizeof(*h));
}

gcry_error_t gcry_md_setkey(gcry_md_hd_t h,const uint8_t *key,size_t key_len) {
    if(h->key_len) return MBEDTLS_ERR_MD_REKEY;
    h->key_len = key_len <= sizeof(h->key) ? key_len : sizeof(h->key);
    memcpy(h->key,key,h->key_len);
    return GPG_ERR_NO_ERROR;
}

gcry_error_t gcry_md_write(gcry_md_hd_t h,const uint8_t *data,size_t data_len) {
    if(h->data_len + data_len > GCRY_MD_BUFF_SIZE) return  MBEDTLS_ERR_MD_DATA_TOO_BIG;
    memcpy(&h->data_buf[h->data_len],data,data_len);
    h->data_len += data_len;
    return GPG_ERR_NO_ERROR;
}

size_t gcry_md_get_algo_dlen(int algo) {
    return algo == GCRY_MD_SHA256 ? HMAC_SHA256_DIGEST_SIZE:0;
}

int gcry_md_get_algo(gcry_md_hd_t h) {
    return GCRY_MD_SHA256;
}

uint8_t *gcry_md_read(gcry_md_hd_t h, int flag) {
    hmac_sha256(h->out,h->data_buf,h->data_len,h->key,h->key_len);
    return h->out;
}

/**********************************************************/

static int check_valid_algo_mode(gcry_cipher_hd_t h) {
    if(!h) return 1;
    if(h->algo == GCRY_CIPHER_AES128 &&
       (h->mode == GCRY_CIPHER_MODE_ECB || h->mode == GCRY_CIPHER_MODE_GCM)) return 0;
    return 1;
}

#define ROUND_SIZE8(a) (((a)+7UL) & ~7UL)

gcry_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
                  int algo, int mode, unsigned int flags) {

struct gcry_cipher_hd *r = 0;
size_t s_len = ROUND_SIZE8(sizeof(struct gcry_cipher_hd));;

    if(flags || algo != GCRY_CIPHER_AES128 || !( mode == GCRY_CIPHER_MODE_ECB || mode == GCRY_CIPHER_MODE_GCM)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

    switch(mode) {
        case GCRY_CIPHER_MODE_ECB:
            r = ndpi_calloc(1,s_len + sizeof(mbedtls_aes_context));
            if(!r) return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
            r->ctx.ecb = (mbedtls_aes_context *)(r+1);
            mbedtls_aes_init(r->ctx.ecb);
            break;
        case GCRY_CIPHER_MODE_GCM:
            {
            size_t aes_ctx_size = ROUND_SIZE8(sizeof( mbedtls_aes_context ));
            size_t gcm_ctx_size = ROUND_SIZE8(sizeof( mbedtls_gcm_context ));

            r = ndpi_calloc(1,s_len + gcm_ctx_size + aes_ctx_size);
            if(!r) return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
            r->ctx.gcm = (mbedtls_gcm_context *)(r+1);
            mbedtls_gcm_init(r->ctx.gcm,(void *)(((char *)(r+1)) + gcm_ctx_size));
            }
            break;
        default:
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    r->algo = algo;
    r->mode = mode;
    *handle = r;
    return GPG_ERR_NO_ERROR;
}

void gcry_cipher_close (gcry_cipher_hd_t h) {
    if(h && !check_valid_algo_mode(h)) {
        switch(h->mode) {
            case GCRY_CIPHER_MODE_ECB:
            mbedtls_aes_free(h->ctx.ecb);
            break;
        case GCRY_CIPHER_MODE_GCM:
            mbedtls_gcm_free(h->ctx.gcm);
            break;
        }
        ndpi_free(h);
    }
}

gcry_error_t gcry_cipher_ctl (gcry_cipher_hd_t h, int cmd, void *data, size_t len) {
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

gcry_error_t gcry_cipher_reset (gcry_cipher_hd_t h) {

    gcry_error_t err = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    if(check_valid_algo_mode(h)) return err;
    h->authlen = 0; h->taglen = 0; h->ivlen = 0;
    h->s_auth = 0;  h->s_iv = 0;   h->s_crypt_ok = 0;
    memset((char *)h->iv,0,sizeof(h->iv));
    memset((char *)h->auth,0,sizeof(h->auth));
    memset((char *)h->tag,0,sizeof(h->tag));
    switch(h->mode) {
        case GCRY_CIPHER_MODE_ECB:
            break;
        case GCRY_CIPHER_MODE_GCM:
            mbedtls_cipher_reset(&h->ctx.gcm->cipher_ctx);
            break;
        default:
            return err;
    }
    return 0;
}


gcry_error_t gcry_cipher_setkey (gcry_cipher_hd_t h, const void *key, size_t keylen) {
    gcry_error_t r = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    if(check_valid_algo_mode(h)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    if( h->s_key ) return MBEDTLS_ERR_CIPHER_BAD_KEY;
    if( keylen != gcry_cipher_get_algo_keylen(h->algo)) return MBEDTLS_ERR_CIPHER_BAD_KEY;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_ECB:
            r = mbedtls_aes_setkey_enc( h->ctx.ecb,  key, keylen*8 );
            break;
        case GCRY_CIPHER_MODE_GCM:
            r = mbedtls_gcm_setkey( h->ctx.gcm, MBEDTLS_CIPHER_ID_AES, key, keylen*8 );
            break;
    }
    if(!r) {
        h->s_key = 1;
        h->keylen = keylen;
    }
    return r;
}

gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t h, const void *iv, size_t ivlen) {
    if(check_valid_algo_mode(h)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    if(h->s_iv) return MBEDTLS_ERR_CIPHER_BAD_KEY;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if(ivlen != 12) return MBEDTLS_ERR_CIPHER_BAD_KEY;
            h->s_iv = 1;
            h->ivlen = ivlen;
            memcpy( h->iv, iv, ivlen );
            return 0;
    }
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t h, const void *abuf, size_t abuflen) {
    if(check_valid_algo_mode(h)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    if(h->s_auth) return MBEDTLS_ERR_CIPHER_BAD_KEY;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if(abuflen > sizeof(h->auth)) return MBEDTLS_ERR_CIPHER_BAD_KEY;
            h->s_auth = 1;
            h->authlen = abuflen;
            memcpy(h->auth,abuf,abuflen);
            return 0;
    }
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t h, const void *intag, size_t taglen) {
    if(check_valid_algo_mode(h)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if(h->s_crypt_ok && h->taglen == taglen) {
                size_t i;
                int diff;
                const uint8_t *ctag = intag;
                for( diff = 0, i = 0; i < taglen; i++ )
                    diff |= ctag[i] ^ h->tag[i];
                if(!diff) return 0;
            }
            return MBEDTLS_ERR_GCM_AUTH_FAILED;
    }
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

size_t gcry_cipher_get_algo_keylen (int algo) {
    switch(algo) {
        case GCRY_CIPHER_AES128: return 16;
        default: return 0;
    }
    return 0;
}

static gcry_error_t _gcry_cipher_crypt (gcry_cipher_hd_t h,
                     void *out, size_t outsize,
                     const void *in, size_t inlen,int encrypt) {
  uint8_t *src = NULL;
  size_t srclen = 0;
  gcry_error_t rv = MBEDTLS_ERR_GCM_BAD_INPUT;

    if(check_valid_algo_mode(h)) return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    if(!inlen && !outsize) return MBEDTLS_ERR_GCM_BAD_INPUT;
    if(!in && !inlen) {
        src = ndpi_malloc(outsize);
        if(!src) return MBEDTLS_ERR_GCM_ALLOC_FAILED;
        srclen = outsize;
        memcpy(src,out,outsize);
    } else {
        if(inlen != outsize) return MBEDTLS_ERR_GCM_BAD_INPUT;
    }
    switch(h->mode) {
        case GCRY_CIPHER_MODE_ECB:
            if(!encrypt) return MBEDTLS_ERR_GCM_NOT_SUPPORT;
            if(!( h->s_key && !h->s_crypt_ok)) return MBEDTLS_ERR_AES_MISSING_KEY;
            rv = mbedtls_aes_crypt_ecb(h->ctx.ecb, MBEDTLS_AES_ENCRYPT,
                        src ? src:in, out);
            break;
        case GCRY_CIPHER_MODE_GCM:
            if(encrypt) return MBEDTLS_ERR_GCM_NOT_SUPPORT;
            if(!( h->s_key && h->s_auth && h->s_iv && !h->s_crypt_ok)) return MBEDTLS_ERR_GCM_MISSING_KEY;
            h->taglen = 16;
            rv = mbedtls_gcm_crypt_and_tag(h->ctx.gcm,
                        MBEDTLS_GCM_DECRYPT,
                        src ? srclen:outsize,
                        h->iv,h->ivlen,
                        h->auth,h->authlen,
                        src ? src:in,out,
                        h->taglen, h->tag);
            break;
    }
    if(!rv) h->s_crypt_ok = 1;
   
    if(src) ndpi_free(src);
    return rv;
}


gcry_error_t gcry_cipher_encrypt (gcry_cipher_hd_t h,
                     void *out, size_t outsize,
                     const void *in, size_t inlen) {
    return _gcry_cipher_crypt(h,out,outsize,in,inlen,1);
}

gcry_error_t gcry_cipher_decrypt (gcry_cipher_hd_t h,
                     void *out, size_t outsize,
                     const void *in, size_t inlen) {
    return _gcry_cipher_crypt(h,out,outsize,in,inlen,0);
}

/* vim: set ts=4 sw=4 et: */
