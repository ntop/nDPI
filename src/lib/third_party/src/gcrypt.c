
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "ndpi_api.h"

#if !defined(HAVE_LIBGCRYPT)

#ifdef _MSC_VER

  #include <stdlib.h>
  #define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

  // Mac OS X / Darwin features
  #include <libkern/OSByteOrder.h>
  #define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

  #include <sys/byteorder.h>
  #define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

  #include <sys/endian.h>
  #define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

  #include <sys/types.h>
  #define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

  #include <sys/types.h>
  #include <machine/bswap.h>
  #if defined(__BSWAP_RENAME) && !defined(__bswap_32)
  #define bswap_64(x) bswap64(x)
  #endif
#elif defined(__MINGW32__) || defined(__MINGW64__)
  #define bswap_64(x) ((uint64_t)htonl((x) >> 32) | ((uint64_t)htonl((x) & 0xfffffffful) << 32))
  #warning use MINGW
#endif

/****************************/
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#undef MBEDTLS_SELF_TEST
/****************************/


#if defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN)

#define GET_UINT32_LE(n,b,i)  (n) = *(uint32_t *) (&(b)[(i)]);
#define PUT_UINT32_LE(n,b,i)  *(uint32_t *) (&(b)[(i)]) = (n);

#define GET_UINT32_BE(n,b,i)  (n) = htonl(*(uint32_t *) (&(b)[(i)]));
#define PUT_UINT32_BE(n,b,i)  *(uint32_t *) (&(b)[(i)]) = htonl(n);
#define PUT_UINT64_BE(n,b,i)  *(uint64_t *) (&(b)[(i)]) = bswap_64(n);

#elif defined(__BIG_ENDIAN__) || defined(__BIG_ENDIAN) 

#define GET_UINT32_LE(n,b,i)  (n) = htonl(*(uint32_t *) (&(b)[(i)]));
#define PUT_UINT32_LE(n,b,i)  *(uint32_t *) (&(b)[(i)]) = htonl(n);

#define GET_UINT32_BE(n,b,i)  (n) = *(uint32_t *) (&(b)[(i)]);
#define PUT_UINT32_BE(n,b,i)  *(uint32_t *) (&(b)[(i)]) = (n);
#define PUT_UINT64_BE(n,b,i)  *(uint64_t *) (&(b)[(i)]) = (n);

#else
#error "__BYTE_ORDER MUST BE DEFINED !"
#endif


#include "gcrypt_light.h"

#include "gcrypt/aes.c"
#include "gcrypt/gcm.c"

#include "gcrypt/cipher.c"
#include "gcrypt/cipher_wrap.c"
#include "gcrypt/digest.c"

int gcry_control (int ctl,int val) {
    return 0;
}

const char *gcry_check_version(void *unused) {
    return "1.8.6";
}

gcry_error_t gcry_md_open(gcry_md_hd_t *h,int algo,int flags) {
    gcry_md_hd_t ctx;
    if(!(algo == GCRY_MD_SHA256 && flags == GCRY_MD_FLAG_HMAC)) return GPG_ERR_ANY;
    ctx = ndpi_calloc(1,sizeof(struct gcry_md_hd));
    if(!ctx) return GPG_ERR_ANY;
    *h = ctx;
    return GPG_ERR_NO_ERROR;
}

void gcry_md_close(gcry_md_hd_t h) {
    ndpi_free(h);
}

void gcry_md_reset(gcry_md_hd_t h) {
    memset((char *)h, 0, sizeof(*h));
}

gcry_error_t gcry_md_setkey(gcry_md_hd_t h,const uint8_t *key,size_t key_len) {
    if(h->key_len) return GPG_ERR_KEY;
    h->key_len = key_len <= sizeof(h->key) ? key_len : sizeof(h->key);
    memcpy(h->key,key,h->key_len);
    return GPG_ERR_NO_ERROR;
}

gcry_error_t gcry_md_write(gcry_md_hd_t h,const uint8_t *data,size_t data_len) {
    if(h->data_len + data_len > GCRY_MD_BUFF_SIZE) return  GPG_ERR_ANY;
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

#define ROUND16(a) (((a)+7UL) & ~7UL)

gcry_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
                  int algo, int mode, unsigned int flags) {

struct gcry_cipher_hd *r = 0;
size_t s_len = ROUND16(sizeof(struct gcry_cipher_hd));;

    if(flags || algo != GCRY_CIPHER_AES128 || !( mode == GCRY_CIPHER_MODE_ECB || mode == GCRY_CIPHER_MODE_GCM)) return 1;

    switch(mode) {
        case GCRY_CIPHER_MODE_ECB:
            r = ndpi_calloc(1,s_len + sizeof(mbedtls_aes_context));
            if(!r) return 1;
            r->ctx.ecb = (mbedtls_aes_context *)((char *)r + s_len);
            mbedtls_aes_init(r->ctx.ecb);
            break;
        case GCRY_CIPHER_MODE_GCM:
            r = ndpi_calloc(1,s_len + sizeof(mbedtls_gcm_context));
            if(!r) return 1;
            r->ctx.gcm = (mbedtls_gcm_context *)((char *)r + s_len);
            mbedtls_gcm_init(r->ctx.gcm);
            break;
        default:
            return 1;
    }
    r->algo = algo;
    r->mode = mode;
    *handle = r;
    return 0;
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
    if(check_valid_algo_mode(h)) return 1;
    return 1;
}

gcry_error_t gcry_cipher_reset (gcry_cipher_hd_t h) {

    if(check_valid_algo_mode(h)) return 1;
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
            return 1;
    }
    return 0;
}


gcry_error_t gcry_cipher_setkey (gcry_cipher_hd_t h, const void *key, size_t keylen) {
    gcry_error_t r = 1;
    if(check_valid_algo_mode(h)) return 1;
    if( h->s_key ) return 1;
    if( keylen != gcry_cipher_get_algo_keylen(h->algo)) return 1;
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
    if(check_valid_algo_mode(h)) return 1;
    if(h->s_iv) return 1;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if(ivlen != 12 || ivlen > sizeof(h->iv)) return 1;
            h->s_iv = 1;
            h->ivlen = ivlen;
            memcpy( h->iv, iv, ivlen );
            return 0;
    }
    return 1;
}

gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t h, const void *abuf, size_t abuflen) {
    if(check_valid_algo_mode(h)) return 1;
    if(h->s_auth) return 1;
    switch(h->mode) {
        case GCRY_CIPHER_MODE_GCM:
            if(abuflen > sizeof(h->auth)) return 1;
            h->s_auth = 1;
            h->authlen = abuflen;
            memcpy(h->auth,abuf,abuflen);
            return 0;
    }
    return 1;
}

gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t h, const void *intag, size_t taglen) {
    if(check_valid_algo_mode(h)) return 1;
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
            return 1;
    }
    return 1;
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
  gcry_error_t rv = 1;

    if(check_valid_algo_mode(h)) return 1;
    if(!inlen && !outsize) return 1;
    if(!in && !inlen) {
        src = ndpi_malloc(outsize);
        if(!src) return 1;
        srclen = outsize;
        memcpy(src,out,outsize);
    } else {
        if(inlen != outsize) return 1;
    }
    switch(h->mode) {
        case GCRY_CIPHER_MODE_ECB:
            if(!encrypt) return 1;
            if(!( h->s_key && !h->s_crypt_ok)) return 1;
            rv = mbedtls_aes_crypt_ecb(h->ctx.ecb,
                        encrypt ? MBEDTLS_AES_ENCRYPT:MBEDTLS_AES_DECRYPT,
                        src ? src:in, out);
            break;
        case GCRY_CIPHER_MODE_GCM:
            if(encrypt) return 1;
            if(!( h->s_key && h->s_auth && h->s_iv && !h->s_crypt_ok)) return 1;
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

#endif /* HAVE_LIBGCRYPT */

/* vim: set ts=4 sw=4 et: */
