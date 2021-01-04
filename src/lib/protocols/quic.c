/*
 * quic.c
 *
 * Copyright (C) 2012-21 - ntop.org
 *
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "ndpi_protocol_ids.h"
#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_QUIC
#include "ndpi_api.h"

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

// #define DEBUG_CRYPT
// #define QUIC_DEBUG

/* This dissector handles GQUIC and IETF-QUIC both.
   Main references:
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/wVHBir-uRU0?pli=1
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/jCbjP0AVAAAJ
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/-NYxlh88AgAJ
   * https://docs.google.com/document/d/1FcpCJGTDEMblAs-Bm5TYuqhHyUqeWpqrItw2vkMFsdY/edit
   * https://tools.ietf.org/html/draft-ietf-quic-tls-29
   * https://tools.ietf.org/html/draft-ietf-quic-transport-29
   */

extern int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
                                    struct ndpi_flow_struct *flow, uint32_t quic_version);
extern int http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow,
                                   const u_int8_t *ua_ptr, u_int16_t ua_ptr_len);

/* Versions */
#define V_1		0x00000001
#define V_Q024		0x51303234
#define V_Q025		0x51303235
#define V_Q030		0x51303330
#define V_Q033		0x51303333
#define V_Q034		0x51303334
#define V_Q035		0x51303335
#define V_Q037		0x51303337
#define V_Q039		0x51303339
#define V_Q043		0x51303433
#define V_Q046		0x51303436
#define V_Q050		0x51303530
#define V_T050		0x54303530
#define V_T051		0x54303531
#define V_MVFST_22	0xfaceb001
#define V_MVFST_27	0xfaceb002
#define V_MVFST_EXP	0xfaceb00e

#define QUIC_MAX_CID_LENGTH  20

static int is_version_gquic(uint32_t version)
{
  return ((version & 0xFFFFFF00) == 0x54303500) /* T05X */ ||
    ((version & 0xFFFFFF00) == 0x51303500) /* Q05X */ ||
    ((version & 0xFFFFFF00) == 0x51303400) /* Q04X */ ||
    ((version & 0xFFFFFF00) == 0x51303300) /* Q03X */ ||
    ((version & 0xFFFFFF00) == 0x51303200) /* Q02X */;
}
static int is_version_quic(uint32_t version)
{
  return version == V_1 ||
    ((version & 0xFFFFFF00) == 0xFF000000) /* IETF Drafts*/ ||
    ((version & 0xFFFFF000) == 0xfaceb000) /* Facebook */ ||
    ((version & 0x0F0F0F0F) == 0x0a0a0a0a) /* Forcing Version Negotiation */;
}
static int is_version_valid(uint32_t version)
{
  return is_version_gquic(version) || is_version_quic(version);
}
static uint8_t get_u8_quic_ver(uint32_t version)
{
  /* IETF Draft versions */
  if((version >> 8) == 0xff0000)
    return (uint8_t)version;
  /* QUIC (final?) constants for v1 are defined in draft-33 */
  if (version == 0x00000001) {
    return 33;
  }

  if (version == V_MVFST_22)
    return 22;
  if (version == V_MVFST_27 || version == V_MVFST_EXP)
    return 27;

  /* "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
     forcing version negotiation to be exercised".
     It is tricky to return a correct draft version: such number is primarly
     used to select a proper salt (which depends on the version itself), but
     we don't have a real version here! Let's hope that we need to handle
     only latest drafts... */
  if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
    return 29;
  return 0;
}
#ifdef HAVE_LIBGCRYPT
static int is_quic_ver_less_than(uint32_t version, uint8_t max_version)
{
  uint8_t u8_ver = get_u8_quic_ver(version);
  return u8_ver && u8_ver <= max_version;
}
#endif
static int is_quic_ver_greater_than(uint32_t version, uint8_t min_version)
{
  return get_u8_quic_ver(version) >= min_version;
}
static uint8_t get_u8_gquic_ver(uint32_t version)
{
  if(is_version_gquic(version)) {
    version = ntohl(((uint16_t)version) << 16);
    return atoi((char *)&version);
  }
  return 0;
}
static int is_gquic_ver_less_than(uint32_t version, uint8_t max_version)
{
  uint8_t u8_ver = get_u8_gquic_ver(version);
  return u8_ver && u8_ver <= max_version;
}
static int is_version_supported(uint32_t version)
{
  return (version == V_Q024 ||
          version == V_Q025 ||
          version == V_Q030 ||
          version == V_Q033 ||
          version == V_Q034 ||
          version == V_Q035 ||
          version == V_Q037 ||
          version == V_Q039 ||
          version == V_Q043 ||
          version == V_Q046 ||
          version == V_Q050 ||
          version == V_T050 ||
          version == V_T051 ||
	  version == V_MVFST_22 ||
	  version == V_MVFST_27 ||
	  version == V_MVFST_EXP ||
          is_quic_ver_greater_than(version, 23));
}
static int is_version_with_encrypted_header(uint32_t version)
{
  return is_version_quic(version) ||
    ((version & 0xFFFFFF00) == 0x51303500) /* Q05X */ ||
    ((version & 0xFFFFFF00) == 0x54303500) /* T05X */;
}
static int is_version_with_tls(uint32_t version)
{
  return is_version_quic(version) ||
    ((version & 0xFFFFFF00) == 0x54303500) /* T05X */;
}
int is_version_with_var_int_transport_params(uint32_t version)
{
  return (is_version_quic(version) && is_quic_ver_greater_than(version, 27)) ||
    (version == V_T051);
}
int is_version_with_ietf_long_header(uint32_t version)
{
  /* At least draft-ietf-quic-invariants-06, or newer*/
  return is_version_quic(version) ||
    ((version & 0xFFFFFF00) == 0x51303500) /* Q05X */ ||
    ((version & 0xFFFFFF00) == 0x54303500) /* T05X */;
}

int quic_len(const uint8_t *buf, uint64_t *value)
{
  *value = buf[0];
  switch((*value) >> 6) {
  case 0:
    (*value) &= 0x3F;
    return 1;
  case 1:
    *value = ntohs(*(uint16_t *)buf) & 0x3FFF;
    return 2;
  case 2:
    *value = ntohl(*(uint32_t *)buf) & 0x3FFFFFFF;
    return 4;
  case 3:
    *value = ndpi_ntohll(*(uint64_t *)buf) & 0x3FFFFFFFFFFFFFFF;
    return 8;
  default: /* No Possible */
    return 0;
  }
}
int quic_len_buffer_still_required(uint8_t value)
{
  switch(value >> 6) {
  case 0:
    return 0;
  case 1:
    return 1;
  case 2:
    return 3;
  case 3:
    return 7;
  default: /* No Possible */
    return 0;
  }
}


static uint16_t gquic_get_u16(const uint8_t *buf, uint32_t version)
{
  if(version >= V_Q039)
    return ntohs(*(uint16_t *)buf);
  return (*(uint16_t *)buf);
}


#ifdef HAVE_LIBGCRYPT

#ifdef DEBUG_CRYPT
char *__gcry_err(gpg_error_t err, char *buf, size_t buflen)
{
#ifdef HAVE_LIBGPG_ERROR
  gpg_strerror_r(err, buf, buflen);
  /* I am not sure if the string will be always null-terminated...
     Better safe than sorry */
  if(buflen > 0)
    buf[buflen - 1] = '\0';
#else
  if(buflen > 0)
    buf[0] = '\0';
#endif
  return buf;
}
#endif /* DEBUG_CRYPT */

static uint64_t pntoh64(const void *p)
{
  return (uint64_t)*((const uint8_t *)(p)+0)<<56|
    (uint64_t)*((const uint8_t *)(p)+1)<<48|
    (uint64_t)*((const uint8_t *)(p)+2)<<40|
    (uint64_t)*((const uint8_t *)(p)+3)<<32|
    (uint64_t)*((const uint8_t *)(p)+4)<<24|
    (uint64_t)*((const uint8_t *)(p)+5)<<16|
    (uint64_t)*((const uint8_t *)(p)+6)<<8|
    (uint64_t)*((const uint8_t *)(p)+7)<<0;
}
static void phton64(uint8_t *p, uint64_t v)
{
  p[0] = (uint8_t)(v >> 56);
  p[1] = (uint8_t)(v >> 48);
  p[2] = (uint8_t)(v >> 40);
  p[3] = (uint8_t)(v >> 32);
  p[4] = (uint8_t)(v >> 24);
  p[5] = (uint8_t)(v >> 16);
  p[6] = (uint8_t)(v >> 8);
  p[7] = (uint8_t)(v >> 0);
}

static void *memdup(const uint8_t *orig, size_t len)
{
  void *dest = ndpi_malloc(len);
  if(dest)
    memcpy(dest, orig, len);
  return dest;
}


/*
 * Generic Wireshark definitions
 */

#define HASH_SHA2_256_LENGTH		32
#define TLS13_AEAD_NONCE_LENGTH		12

typedef struct _StringInfo {
  unsigned char *data;		/* Backing storage which may be larger than data_len */
  unsigned int data_len;	/* Length of the meaningful part of data */
} StringInfo;

/* QUIC decryption context. */

typedef struct quic_hp_cipher {
  gcry_cipher_hd_t hp_cipher;  /* Header protection cipher. */
} quic_hp_cipher;
typedef struct quic_pp_cipher {
  gcry_cipher_hd_t pp_cipher;  /* Packet protection cipher. */
  uint8_t pp_iv[TLS13_AEAD_NONCE_LENGTH];
} quic_pp_cipher;
typedef struct quic_ciphers {
  quic_hp_cipher hp_cipher;
  quic_pp_cipher pp_cipher;
} quic_ciphers;

typedef struct quic_decrypt_result {
  uint8_t *data; /* Decrypted result on success (file-scoped). */
  uint32_t data_len;   /* Size of decrypted data. */
} quic_decrypt_result_t;


/*
 * From wsutil/wsgcrypt.{c,h}
 */

static gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer,
				   size_t length, const void *key, size_t keylen)
{
  gcry_md_hd_t hmac_handle;
  gcry_error_t result = gcry_md_open(&hmac_handle, algo, GCRY_MD_FLAG_HMAC);
  if(result) {
    return result;
  }
  result = gcry_md_setkey(hmac_handle, key, keylen);
  if(result) {
    gcry_md_close(hmac_handle);
    return result;
  }
  gcry_md_write(hmac_handle, buffer, length);
  memcpy(digest, gcry_md_read(hmac_handle, 0), gcry_md_get_algo_dlen(algo));
  gcry_md_close(hmac_handle);
  return GPG_ERR_NO_ERROR;
}
static gcry_error_t hkdf_expand(int hashalgo, const uint8_t *prk, uint32_t prk_len,
				const uint8_t *info, uint32_t info_len,
				uint8_t *out, uint32_t out_len)
{
  /* Current maximum hash output size: 48 bytes for SHA-384. */
  uint8_t lastoutput[48];
  gcry_md_hd_t h;
  gcry_error_t err;
  const unsigned int hash_len = gcry_md_get_algo_dlen(hashalgo);

  /* Some sanity checks */
  if(!(out_len > 0 && out_len <= 255 * hash_len) ||
     !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
    return GPG_ERR_INV_ARG;
  }

  err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
  if(err) {
    return err;
  }

  for(uint32_t offset = 0; offset < out_len; offset += hash_len) {
    gcry_md_reset(h);
    gcry_md_setkey(h, prk, prk_len); /* Set PRK */
    if(offset > 0) {
      gcry_md_write(h, lastoutput, hash_len); /* T(1..N) */
    }
    gcry_md_write(h, info, info_len);                   /* info */

    uint8_t c = offset / hash_len + 1;
    gcry_md_write(h, &c, sizeof(c));                    /* constant 0x01..N */

    memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
    memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
  }

  gcry_md_close(h);
  return 0;
}
/*
 * Calculate HKDF-Extract(salt, IKM) -> PRK according to RFC 5869.
 * Caller MUST ensure that 'prk' is large enough to store the digest from hash
 * algorithm 'hashalgo' (e.g. 32 bytes for SHA-256).
 */
static gcry_error_t hkdf_extract(int hashalgo, const uint8_t *salt, size_t salt_len,
				 const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
  /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
  return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}


/*
 * From epan/dissectors/packet-tls-utils.c
 */

/*
 * Computes HKDF-Expand-Label(Secret, Label, Hash(context_value), Length) with a
 * custom label prefix. If "context_hash" is NULL, then an empty context is
 * used. Otherwise it must have the same length as the hash algorithm output.
 */
static int tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
					   const char *label_prefix, const char *label,
					   const uint8_t *context_hash, uint8_t context_length,
					   uint16_t out_len, uint8_t **out)
{
  /* RFC 8446 Section 7.1:
   * HKDF-Expand-Label(Secret, Label, Context, Length) =
   *      HKDF-Expand(Secret, HkdfLabel, Length)
   * struct {
   *     uint16 length = Length;
   *     opaque label<7..255> = "tls13 " + Label; // "tls13 " is label prefix.
   *     opaque context<0..255> = Context;
   * } HkdfLabel;
   *
   * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
   * HKDF-Expand(PRK, info, L) -> OKM
   */
  gcry_error_t err;
  const unsigned int label_prefix_length = (unsigned int)strlen(label_prefix);
  const unsigned label_length = (unsigned int)strlen(label);
#ifdef DEBUG_CRYPT
  char buferr[128];
#endif

  /* Some sanity checks */
  if(!(label_length > 0 && label_prefix_length + label_length <= 255)) {
#ifdef DEBUG_CRYPT
    printf("Failed sanity checks\n");
#endif
    return 0;
  }

  /* info = HkdfLabel { length, label, context } */
  /* Keep original Wireshark code as reference */
#if 0
  GByteArray *info = g_byte_array_new();
  const uint16_t length = htons(out_len);
  g_byte_array_append(info, (const guint8 *)&length, sizeof(length));

  const uint8_t label_vector_length = label_prefix_length + label_length;
  g_byte_array_append(info, &label_vector_length, 1);
  g_byte_array_append(info, (const uint8_t *)label_prefix, label_prefix_length);
  g_byte_array_append(info, (const uint8_t *)label, label_length);

  g_byte_array_append(info, &context_length, 1);
  if (context_length) {
    g_byte_array_append(info, context_hash, context_length);
  }
#else
  uint32_t info_len = 0;
  uint8_t *info_data = (uint8_t *)ndpi_malloc(1024);
  if(!info_data)
    return 0;
  const uint16_t length = htons(out_len);
  memcpy(&info_data[info_len], &length, sizeof(length));
  info_len += sizeof(length);

  const uint8_t label_vector_length = label_prefix_length + label_length;
  memcpy(&info_data[info_len], &label_vector_length, 1);
  info_len += 1;
  memcpy(&info_data[info_len], (const uint8_t *)label_prefix, label_prefix_length);
  info_len += label_prefix_length;
  memcpy(&info_data[info_len], (const uint8_t *)label, label_length);
  info_len += label_length;

  memcpy(&info_data[info_len], &context_length, 1);
  info_len += 1;
  if(context_length) {
    memcpy(&info_data[info_len], context_hash, context_length);
    info_len += context_length;
  }
#endif

  *out = (uint8_t *)ndpi_malloc(out_len);
  if(!*out)
    return 0;
  err = hkdf_expand(md, secret->data, secret->data_len, info_data, info_len, *out, out_len);
  ndpi_free(info_data);

  if(err) {
#ifdef DEBUG_CRYPT
    printf("Failed hkdf_expand: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    ndpi_free(*out);
    *out = NULL;
    return 0;
  }

  return 1;
}
static int tls13_hkdf_expand_label(int md, const StringInfo *secret,
				   const char *label_prefix, const char *label,
				   uint16_t out_len, unsigned char **out)
{
  return tls13_hkdf_expand_label_context(md, secret, label_prefix, label, NULL, 0, out_len, out);
}


/*
 * From epan/dissectors/packet-quic.c
 */

static int quic_hkdf_expand_label(int hash_algo, uint8_t *secret, uint32_t secret_len,
				  const char *label, uint8_t *out, uint32_t out_len)
{
  const StringInfo secret_si = { secret, secret_len };
  uint8_t *out_mem = NULL;
  if(tls13_hkdf_expand_label(hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
    memcpy(out, out_mem, out_len);
    ndpi_free(out_mem);
    return 1;
  }
  return 0;
}
static void quic_hp_cipher_reset(quic_hp_cipher *hp_cipher)
{
  gcry_cipher_close(hp_cipher->hp_cipher);
#if 0
  memset(hp_cipher, 0, sizeof(*hp_cipher));
#endif
}
static void quic_pp_cipher_reset(quic_pp_cipher *pp_cipher)
{
  gcry_cipher_close(pp_cipher->pp_cipher);
#if 0
  memset(pp_cipher, 0, sizeof(*pp_cipher));
#endif
}
static void quic_ciphers_reset(quic_ciphers *ciphers)
{
  quic_hp_cipher_reset(&ciphers->hp_cipher);
  quic_pp_cipher_reset(&ciphers->pp_cipher);
}
/**
 * Expands the secret (length MUST be the same as the "hash_algo" digest size)
 * and initialize cipher with the new key.
 */
static int quic_hp_cipher_init(quic_hp_cipher *hp_cipher, int hash_algo,
			       uint8_t key_length, uint8_t *secret)
{
  uint8_t hp_key[256/8]; /* Maximum key size is for AES256 cipher. */
  uint32_t hash_len = gcry_md_get_algo_dlen(hash_algo);

  if(!quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic hp", hp_key, key_length)) {
    return 0;
  }

  return gcry_cipher_setkey(hp_cipher->hp_cipher, hp_key, key_length) == 0;
}
static int quic_pp_cipher_init(quic_pp_cipher *pp_cipher, int hash_algo,
			       uint8_t key_length, uint8_t *secret)
{
  uint8_t write_key[256/8]; /* Maximum key size is for AES256 cipher. */
  uint32_t hash_len = gcry_md_get_algo_dlen(hash_algo);

  if(key_length > sizeof(write_key)) {
    return 0;
  }

  if(!quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic key", write_key, key_length) ||
     !quic_hkdf_expand_label(hash_algo, secret, hash_len, "quic iv", pp_cipher->pp_iv, sizeof(pp_cipher->pp_iv))) {
    return 0;
  }

  return gcry_cipher_setkey(pp_cipher->pp_cipher, write_key, key_length) == 0;
}
/**
 * Maps a Packet Protection cipher to the Packet Number protection cipher.
 * See https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.3
 */
static int quic_get_pn_cipher_algo(int cipher_algo, int *hp_cipher_mode)
{
  switch (cipher_algo) {
  case GCRY_CIPHER_AES128:
  case GCRY_CIPHER_AES256:
    *hp_cipher_mode = GCRY_CIPHER_MODE_ECB;
    return 1;
  default:
    return 0;
  }
}
/*
 * (Re)initialize the PNE/PP ciphers using the given cipher algorithm.
 * If the optional base secret is given, then its length MUST match the hash
 * algorithm output.
 */
static int quic_hp_cipher_prepare(quic_hp_cipher *hp_cipher, int hash_algo, int cipher_algo, uint8_t *secret)
{
#if 0
  /* Clear previous state (if any). */
  quic_hp_cipher_reset(hp_cipher);
#endif

  int hp_cipher_mode;
  if(!quic_get_pn_cipher_algo(cipher_algo, &hp_cipher_mode)) {
#ifdef DEBUG_CRYPT
    printf("Unsupported cipher algorithm\n");
#endif
    return 0;
  }

  if(gcry_cipher_open(&hp_cipher->hp_cipher, cipher_algo, hp_cipher_mode, 0)) {
    quic_hp_cipher_reset(hp_cipher);
#ifdef DEBUG_CRYPT
    printf("Failed to create HP cipher\n");
#endif
    return 0;
  }

  if(secret) {
    uint32_t cipher_keylen = (uint8_t)gcry_cipher_get_algo_keylen(cipher_algo);
    if(!quic_hp_cipher_init(hp_cipher, hash_algo, cipher_keylen, secret)) {
      quic_hp_cipher_reset(hp_cipher);
#ifdef DEBUG_CRYPT
      printf("Failed to derive key material for HP cipher\n");
#endif
      return 0;
    }
  }

  return 1;
}
static int quic_pp_cipher_prepare(quic_pp_cipher *pp_cipher, int hash_algo, int cipher_algo, int cipher_mode, uint8_t *secret)
{
#if 0
  /* Clear previous state (if any). */
  quic_pp_cipher_reset(pp_cipher);
#endif

  if(gcry_cipher_open(&pp_cipher->pp_cipher, cipher_algo, cipher_mode, 0)) {
    quic_pp_cipher_reset(pp_cipher);
#ifdef DEBUG_CRYPT
    printf("Failed to create PP cipher\n");
#endif
    return 0;
  }

  if(secret) {
    uint32_t cipher_keylen = (uint8_t)gcry_cipher_get_algo_keylen(cipher_algo);
    if(!quic_pp_cipher_init(pp_cipher, hash_algo, cipher_keylen, secret)) {
      quic_pp_cipher_reset(pp_cipher);
#ifdef DEBUG_CRYPT
      printf("Failed to derive key material for PP cipher\n");
#endif
      return 0;
    }
  }

  return 1;
}
static int quic_ciphers_prepare(quic_ciphers *ciphers, int hash_algo, int cipher_algo, int cipher_mode, uint8_t *secret)
{
  return quic_hp_cipher_prepare(&ciphers->hp_cipher, hash_algo, cipher_algo, secret) &&
         quic_pp_cipher_prepare(&ciphers->pp_cipher, hash_algo, cipher_algo, cipher_mode, secret);
}
/**
 * Given a header protection cipher, a buffer and the packet number offset,
 * return the unmasked first byte and packet number.
 * If the loss bits feature is enabled, the protected bits in the first byte
 * are fewer than usual: 3 instead of 5 (on short headers only)
 */
static int quic_decrypt_header(const uint8_t *packet_payload,
			       uint32_t pn_offset, quic_hp_cipher *hp_cipher,
			       int hp_cipher_algo, uint8_t *first_byte, uint32_t *pn,
			       int loss_bits_negotiated)
{
  if(!hp_cipher->hp_cipher) {
    /* Need to know the cipher */
    return 0;
  }
  gcry_cipher_hd_t h = hp_cipher->hp_cipher;

  /* Sample is always 16 bytes and starts after PKN (assuming length 4).
     https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.2 */
  uint8_t sample[16];
  memcpy(sample, packet_payload + pn_offset + 4, 16);

  uint8_t mask[5] = { 0 };
  switch (hp_cipher_algo) {
  case GCRY_CIPHER_AES128:
  case GCRY_CIPHER_AES256:
    /* Encrypt in-place with AES-ECB and extract the mask. */
    if(gcry_cipher_encrypt(h, sample, sizeof(sample), NULL, 0)) {
      return 0;
    }
    memcpy(mask, sample, sizeof(mask));
    break;
  default:
    return 0;
  }

  /* https://tools.ietf.org/html/draft-ietf-quic-tls-22#section-5.4.1 */
  uint8_t packet0 = packet_payload[0];
  if((packet0 & 0x80) == 0x80) {
    /* Long header: 4 bits masked */
    packet0 ^= mask[0] & 0x0f;
  } else {
    /* Short header */
    if(loss_bits_negotiated == 0) {
      /* Standard mask: 5 bits masked */
      packet0 ^= mask[0] & 0x1F;
    } else {
      /* https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-lossbits-03#section-5.3 */
      packet0 ^= mask[0] & 0x07;
    }
  }
  uint32_t pkn_len = (packet0 & 0x03) + 1;
  /* printf("packet0 0x%x pkn_len %d\n", packet0, pkn_len); */

  uint8_t pkn_bytes[4];
  memcpy(pkn_bytes, packet_payload + pn_offset, pkn_len);
  uint32_t pkt_pkn = 0;
  for(uint32_t i = 0; i < pkn_len; i++) {
    pkt_pkn |= (uint32_t)(pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
  }
  *first_byte = packet0;
  *pn = pkt_pkn;
  return 1;
}
/**
 * Given a QUIC message (header + non-empty payload), the actual packet number,
 * try to decrypt it using the cipher.
 * As the header points to the original buffer with an encrypted packet number,
 * the (encrypted) packet number length is also included.
 *
 * The actual packet number must be constructed according to
 * https://tools.ietf.org/html/draft-ietf-quic-transport-22#section-12.3
 */
static void quic_decrypt_message(quic_pp_cipher *pp_cipher, const uint8_t *packet_payload, uint32_t packet_payload_len,
				 uint32_t header_length, uint8_t first_byte, uint32_t pkn_len,
				 uint64_t packet_number, quic_decrypt_result_t *result)
{
  gcry_error_t err;
  uint8_t *header;
  uint8_t nonce[TLS13_AEAD_NONCE_LENGTH];
  uint8_t *buffer;
  uint8_t atag[16];
  uint32_t buffer_length;
#ifdef DEBUG_CRYPT
  char buferr[128];
#endif

  if(!(pp_cipher != NULL) ||
     !(pp_cipher->pp_cipher != NULL) ||
     !(pkn_len < header_length) ||
     !(1 <= pkn_len && pkn_len <= 4)) {
#ifdef DEBUG_CRYPT
    printf("Failed sanity checks\n");
#endif
    return;
  }
  /* Copy header, but replace encrypted first byte and PKN by plaintext. */
  header = (uint8_t *)memdup(packet_payload, header_length);
  if(!header)
    return;
  header[0] = first_byte;
  for(uint32_t i = 0; i < pkn_len; i++) {
    header[header_length - 1 - i] = (uint8_t)(packet_number >> (8 * i));
  }

  /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
  buffer_length = packet_payload_len - (header_length + 16);
  if(buffer_length == 0) {
#ifdef DEBUG_CRYPT
    printf("Decryption not possible, ciphertext is too short\n");
#endif
    ndpi_free(header);
    return;
  }
  buffer = (uint8_t *)memdup(packet_payload + header_length, buffer_length);
  if(!buffer) {
    ndpi_free(header);
    return;
  }
  memcpy(atag, packet_payload + header_length + buffer_length, 16);

  memcpy(nonce, pp_cipher->pp_iv, TLS13_AEAD_NONCE_LENGTH);
  /* Packet number is left-padded with zeroes and XORed with write_iv */
  phton64(nonce + sizeof(nonce) - 8, pntoh64(nonce + sizeof(nonce) - 8) ^ packet_number);

  gcry_cipher_reset(pp_cipher->pp_cipher);
  err = gcry_cipher_setiv(pp_cipher->pp_cipher, nonce, TLS13_AEAD_NONCE_LENGTH);
  if(err) {
#ifdef DEBUG_CRYPT
    printf("Decryption (setiv) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    ndpi_free(header);
    ndpi_free(buffer);
    return;
  }

  /* associated data (A) is the contents of QUIC header */
  err = gcry_cipher_authenticate(pp_cipher->pp_cipher, header, header_length);
  if(err) {
#ifdef DEBUG_CRYPT
    printf("Decryption (authenticate) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    ndpi_free(header);
    ndpi_free(buffer);
    return;
  }

  ndpi_free(header);

  /* Output ciphertext (C) */
  err = gcry_cipher_decrypt(pp_cipher->pp_cipher, buffer, buffer_length, NULL, 0);
  if(err) {
#ifdef DEBUG_CRYPT
    printf("Decryption (decrypt) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    ndpi_free(buffer);
    return;
  }

  err = gcry_cipher_checktag(pp_cipher->pp_cipher, atag, 16);
  if(err) {
#ifdef DEBUG_CRYPT
    printf("Decryption (checktag) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    ndpi_free(buffer);
    return;
  }

  result->data = buffer;
  result->data_len = buffer_length;
}
/**
 * Compute the client and server initial secrets given Connection ID "cid".
 */
static int quic_derive_initial_secrets(uint32_t version,
				       const uint8_t *cid, uint8_t cid_len,
				       uint8_t client_initial_secret[HASH_SHA2_256_LENGTH])
{
  /*
   * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
   *
   * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
   *
   * client_initial_secret = HKDF-Expand-Label(initial_secret,
   *                                           "client in", "", Hash.length)
   *
   * Hash for handshake packets is SHA-256 (output size 32).
   */
  static const uint8_t handshake_salt_draft_22[20] = {
						      0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
						      0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
  };
  static const uint8_t handshake_salt_draft_23[20] = {
						      0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
						      0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
  };
  static const uint8_t handshake_salt_draft_29[20] = {
						      0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
						      0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
  };
  static const uint8_t hanshake_salt_draft_q50[20] = {
						      0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
						      0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45
  };
  static const uint8_t hanshake_salt_draft_t50[20] = {
						      0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
						      0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10
  };
  static const uint8_t hanshake_salt_draft_t51[20] = {
						      0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
						      0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d
  };
  static const uint8_t handshake_salt_v1[20] = {
						0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
						0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
  };
  gcry_error_t err;
  uint8_t secret[HASH_SHA2_256_LENGTH];
#ifdef DEBUG_CRYPT
  char buferr[128];
#endif

  if(version == V_Q050) {
    err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_q50,
		       sizeof(hanshake_salt_draft_q50),
                       cid, cid_len, secret);
  } else if(version == V_T050) {
    err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_t50,
		       sizeof(hanshake_salt_draft_t50),
                       cid, cid_len, secret);
  } else if(version == V_T051) {
    err = hkdf_extract(GCRY_MD_SHA256, hanshake_salt_draft_t51,
		       sizeof(hanshake_salt_draft_t51),
                       cid, cid_len, secret);
  } else if(is_quic_ver_less_than(version, 22)) {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_22,
		       sizeof(handshake_salt_draft_22),
                       cid, cid_len, secret);
  } else if(is_quic_ver_less_than(version, 28)) {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_23,
		       sizeof(handshake_salt_draft_23),
                       cid, cid_len, secret);
  } else if(is_quic_ver_less_than(version, 32)) {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_draft_29,
		       sizeof(handshake_salt_draft_29),
                       cid, cid_len, secret);
  } else {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v1,
		       sizeof(handshake_salt_v1),
                       cid, cid_len, secret);
  }
  if(err) {
#ifdef DEBUG_CRYPT
    printf("Failed to extract secrets: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    return -1;
  }

  if(!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, sizeof(secret), "client in",
			     client_initial_secret, HASH_SHA2_256_LENGTH)) {
#ifdef DEBUG_CRYPT
    printf("Key expansion (client) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
#endif
    return -1;
  }

  return 0;
}

/*
 * End Wireshark code
 */


static uint8_t *decrypt_initial_packet(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow,
				       const uint8_t *dest_conn_id, uint8_t dest_conn_id_len,
				       uint8_t source_conn_id_len, uint32_t version,
				       uint32_t *clear_payload_len)
{
  uint64_t token_length, payload_length, packet_number;
  struct ndpi_packet_struct *packet = &flow->packet;
  uint8_t first_byte;
  uint32_t pkn32, pn_offset, pkn_len, offset;
  quic_ciphers ciphers; /* Client initial ciphers */
  quic_decrypt_result_t decryption = {0};
  uint8_t client_secret[HASH_SHA2_256_LENGTH];

  memset(&ciphers, '\0', sizeof(ciphers));
  if(quic_derive_initial_secrets(version, dest_conn_id, dest_conn_id_len,
				 client_secret) != 0) {
    NDPI_LOG_DBG(ndpi_struct, "Error quic_derive_initial_secrets\n");
    return NULL;
  }

  /* Packet numbers are protected with AES128-CTR,
     Initial packets are protected with AEAD_AES_128_GCM. */
  if(!quic_ciphers_prepare(&ciphers, GCRY_MD_SHA256,
                           GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                           client_secret)) {
    NDPI_LOG_DBG(ndpi_struct, "Error quic_cipher_prepare\n");
    return NULL;
  }

  /* Type(1) + version(4) + DCIL + DCID + SCIL + SCID */
  pn_offset = 1 + 4 + 1 + dest_conn_id_len + 1 + source_conn_id_len;
  pn_offset += quic_len(&packet->payload[pn_offset], &token_length);
  pn_offset += token_length;
  /* Checks: quic_len reads 8 bytes, at most; quic_decrypt_header reads other 20 bytes */
  if(pn_offset + 8 + (4 + 16) >= packet->payload_packet_len) {
    quic_ciphers_reset(&ciphers);
    return NULL;
  }
  pn_offset += quic_len(&packet->payload[pn_offset], &payload_length);

  NDPI_LOG_DBG2(ndpi_struct, "pn_offset %d token_length %d payload_length %d\n",
		pn_offset, token_length, payload_length);

  if (pn_offset + payload_length > packet->payload_packet_len) {
    NDPI_LOG_DBG(ndpi_struct, "Too short %d %d\n", pn_offset + payload_length,
                 packet->payload_packet_len);
    quic_ciphers_reset(&ciphers);
    return NULL;
  }

  if(!quic_decrypt_header(&packet->payload[0], pn_offset, &ciphers.hp_cipher,
			  GCRY_CIPHER_AES128, &first_byte, &pkn32, 0)) {
    quic_ciphers_reset(&ciphers);
    return NULL;
  }
  NDPI_LOG_DBG2(ndpi_struct, "first_byte 0x%x pkn32 0x%x\n", first_byte, pkn32);

  pkn_len = (first_byte & 3) + 1;
  /* TODO: is it always true in Initial Packets? */
  packet_number = pkn32;

  offset = pn_offset + pkn_len;
  if (!(pn_offset + payload_length >= offset + 16)) {
    NDPI_LOG_DBG(ndpi_struct, "No room for Auth Tag %d %d",
                 pn_offset + payload_length, offset);
    quic_ciphers_reset(&ciphers);
    return NULL;
  }
  quic_decrypt_message(&ciphers.pp_cipher, &packet->payload[0], pn_offset + payload_length,
		       offset, first_byte, pkn_len, packet_number, &decryption);

  quic_ciphers_reset(&ciphers);

  if(decryption.data_len) {
    *clear_payload_len = decryption.data_len;
    return decryption.data;
  }
  return NULL;
}

#endif /* HAVE_LIBGCRYPT */


static const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow,
				      uint32_t version,
				      u_int8_t *clear_payload, uint32_t clear_payload_len,
				      uint64_t *crypto_data_len)
{
  const u_int8_t *crypto_data;
  uint32_t counter;
  uint8_t first_nonzero_payload_byte, offset_len;
  uint64_t unused, offset;

  counter = 0;
  while(counter < clear_payload_len && clear_payload[counter] == 0)
    counter += 1;
  if(counter >= clear_payload_len)
    return NULL;
  first_nonzero_payload_byte = clear_payload[counter];
  NDPI_LOG_DBG2(ndpi_struct, "first_nonzero_payload_byte 0x%x\n", first_nonzero_payload_byte);
  if(is_gquic_ver_less_than(version, 46)) {
    if(first_nonzero_payload_byte == 0x40 ||
       first_nonzero_payload_byte == 0x60) {
      /* Probably an ACK/NACK frame: this CHLO is not the first one but try
         decoding it nonetheless */
      counter += (first_nonzero_payload_byte == 0x40) ? 6 : 9;
      if(counter >= clear_payload_len)
        return NULL;
      first_nonzero_payload_byte = clear_payload[counter];
    }
    if((first_nonzero_payload_byte != 0xA0) &&
       (first_nonzero_payload_byte != 0xA4)) {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected frame 0x%x version 0x%x\n",\
		   first_nonzero_payload_byte, version);
      return NULL;
    }
    offset_len = (first_nonzero_payload_byte & 0x1C) >> 2;
    if(offset_len > 0)
      offset_len += 1;
    if(counter + 2 + offset_len + 2 /*gquic_get_u16 reads 2 bytes */  > clear_payload_len)
      return NULL;
    if(clear_payload[counter + 1] != 0x01) {
#ifdef QUIC_DEBUG
      NDPI_LOG_ERR(ndpi_struct, "Unexpected stream ID version 0x%x\n", version);
#endif
      return NULL;
    }
    counter += 2 + offset_len;
    *crypto_data_len = gquic_get_u16(&clear_payload[counter], version);
    counter += 2;
    crypto_data = &clear_payload[counter];

  } else if(version == V_Q050 || version == V_T050 || version == V_T051) {
    if(first_nonzero_payload_byte == 0x40 ||
       first_nonzero_payload_byte == 0x60) {
      /* Probably an ACK/NACK frame: this CHLO is not the first one but try
         decoding it nonetheless */
      counter += (first_nonzero_payload_byte == 0x40) ? 6 : 9;
      if(counter >= clear_payload_len)
        return NULL;
      first_nonzero_payload_byte = clear_payload[counter];
    }
    if(first_nonzero_payload_byte != 0x08) {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected frame 0x%x\n", first_nonzero_payload_byte);
      return NULL;
    }
    counter += 1;
    if(counter + 8 + 8 >= clear_payload_len) /* quic_len reads 8 bytes, at most */
      return NULL;
    counter += quic_len(&clear_payload[counter], &unused);
    counter += quic_len(&clear_payload[counter], crypto_data_len);
    crypto_data = &clear_payload[counter];

  } else {  /* All other versions */
    if(first_nonzero_payload_byte != 0x06) {
      if(first_nonzero_payload_byte != 0x02 &&
         first_nonzero_payload_byte != 0x1C) {
#ifdef QUIC_DEBUG
        NDPI_LOG_ERR(ndpi_struct, "Unexpected frame 0x%x\n", first_nonzero_payload_byte);
#endif
      } else {
        NDPI_LOG_DBG(ndpi_struct, "Unexpected ACK/CC frame\n");
      }
      return NULL;
    }
    counter += 1;
    if(counter + 8 + 8 >= clear_payload_len) /* quic_len reads 8 bytes, at most */
      return NULL;
    counter += quic_len(&clear_payload[counter], &offset);
    if(offset != 0) {
#ifdef QUIC_DEBUG
      NDPI_LOG_ERR(ndpi_struct, "Unexpected crypto stream offset 0x%x\n",
		   offset);
#endif
      return NULL;
    }
    counter += quic_len(&clear_payload[counter], crypto_data_len);
    crypto_data = &clear_payload[counter];
  }

  if(*crypto_data_len + counter > clear_payload_len) {
#ifdef QUIC_DEBUG
    NDPI_LOG_ERR(ndpi_struct, "Invalid length %lu + %d > %d version 0x%x\n",
		 (unsigned long)*crypto_data_len, counter, clear_payload_len, version);
#endif
    return NULL;
  }
  return crypto_data;
}

static uint8_t *get_clear_payload(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  uint32_t version, uint32_t *clear_payload_len)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t *clear_payload;
  u_int8_t dest_conn_id_len;
#ifdef HAVE_LIBGCRYPT
  u_int8_t source_conn_id_len;
#endif

  if(is_gquic_ver_less_than(version, 43)) {
    clear_payload = (uint8_t *)&packet->payload[26];
    *clear_payload_len = packet->payload_packet_len - 26;
    /* Skip Private-flag field for version for < Q34 */
    if(is_gquic_ver_less_than(version, 33)) {
      clear_payload += 1;
      (*clear_payload_len) -= 1;
    }
  } else if(version == V_Q046) {
    if(packet->payload[5] != 0x50) {
      NDPI_LOG_DBG(ndpi_struct, "Q46 invalid conn id len 0x%x\n",
		   packet->payload[5]);
      return NULL;
    }
    clear_payload = (uint8_t *)&packet->payload[30];
    *clear_payload_len = packet->payload_packet_len - 30;
  } else {
    /* Upper limit of CIDs length has been already validated. If dest_conn_id_len is 0,
       this is probably the Initial Packet from the server */
    dest_conn_id_len = packet->payload[5];
    if(dest_conn_id_len == 0) {
      NDPI_LOG_DBG(ndpi_struct, "Packet 0x%x with dest_conn_id_len %d\n",
		   version, dest_conn_id_len);
      return NULL;
    }
#ifdef HAVE_LIBGCRYPT
    source_conn_id_len = packet->payload[6 + dest_conn_id_len];
    const u_int8_t *dest_conn_id = &packet->payload[6];
    clear_payload = decrypt_initial_packet(ndpi_struct, flow,
					   dest_conn_id, dest_conn_id_len,
					   source_conn_id_len, version,
					   clear_payload_len);
#else
    clear_payload = NULL;
#endif
  }

  return clear_payload;
}
static void process_tls(struct ndpi_detection_module_struct *ndpi_struct,
			struct ndpi_flow_struct *flow,
			const u_int8_t *crypto_data, uint32_t crypto_data_len,
			uint32_t version)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* Overwriting packet payload */
  u_int16_t p_len;
  const u_int8_t *p;
  p = packet->payload;
  p_len = packet->payload_packet_len;
  packet->payload = crypto_data;
  packet->payload_packet_len = crypto_data_len;

  processClientServerHello(ndpi_struct, flow, version);
  flow->l4.tcp.tls.hello_processed = 1; /* Allow matching of custom categories */

  /* Restore */
  packet->payload = p;
  packet->payload_packet_len = p_len;

  /* ServerHello is not needed to sub-classified QUIC, so we ignore it:
     this way we lose JA3S and negotiated ciphers...
     Negotiated version is only present in the ServerHello message too, but
     fortunately, QUIC always uses TLS version 1.3 */
  flow->protos.tls_quic_stun.tls_quic.ssl_version = 0x0304;

  /* DNS-over-QUIC: ALPN is "doq" or "doq-XXX" (for drafts versions) */
  if(flow->protos.tls_quic_stun.tls_quic.alpn &&
     strncmp(flow->protos.tls_quic_stun.tls_quic.alpn, "doq", 3) == 0) {
    NDPI_LOG_DBG(ndpi_struct, "Found DOQ (ALPN: [%s])\n", flow->protos.tls_quic_stun.tls_quic.alpn);
    ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DOH_DOT, NDPI_PROTOCOL_QUIC);
  }
}
static void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow,
			 const u_int8_t *crypto_data, uint32_t crypto_data_len)
{
  const uint8_t *tag;
  uint32_t i;
  uint16_t num_tags;
  uint32_t prev_offset;
  uint32_t tag_offset_start, offset, len, sni_len;
  ndpi_protocol_match_result ret_match;
  int sni_found = 0, ua_found = 0;

  if(crypto_data_len < 6)
    return;
  if(memcmp(crypto_data, "CHLO", 4) != 0) {
#ifdef QUIC_DEBUG
    NDPI_LOG_ERR(ndpi_struct, "Unexpected handshake message");
#endif
    return;
  }
  num_tags = (*(uint16_t *)&crypto_data[4]);

  tag_offset_start = 8 + 8 * num_tags;
  prev_offset = 0;
  for(i = 0; i < num_tags; i++) {
    if(8 + 8 * i + 8 >= crypto_data_len)
      break;
    tag = &crypto_data[8 + 8 * i];
    offset = *((u_int32_t *)&crypto_data[8 + 8 * i + 4]);
    if(prev_offset > offset)
      break;
    len = offset - prev_offset;
    if(tag_offset_start + prev_offset + len > crypto_data_len)
      break;
#if 0
    printf("crypto_data_len %u prev_offset %u offset %u len %d\n",
	   crypto_data_len, prev_offset, offset, len);
#endif
    if((memcmp(tag, "SNI\0", 4) == 0) &&
       (tag_offset_start + prev_offset + len < crypto_data_len)) {
      sni_len = MIN(len, sizeof(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name) - 1);
      memcpy(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name,
             &crypto_data[tag_offset_start + prev_offset], sni_len);
      flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[sni_len] = '\0';

      NDPI_LOG_DBG2(ndpi_struct, "SNI: [%s]\n",
                    flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);

      ndpi_match_host_subprotocol(ndpi_struct, flow,
                                  (char *)flow->protos.tls_quic_stun.tls_quic.client_requested_server_name,
                                  strlen((const char*)flow->protos.tls_quic_stun.tls_quic.client_requested_server_name),
                                  &ret_match, NDPI_PROTOCOL_QUIC);
      flow->l4.tcp.tls.hello_processed = 1; /* Allow matching of custom categories */

      ndpi_check_dga_name(ndpi_struct, flow,
                          flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, 1);

      sni_found = 1;
      if (ua_found)
        return;
    }

    if(memcmp(tag, "UAID", 4) == 0) {
      u_int uaid_offset = tag_offset_start + prev_offset;
            
      if((uaid_offset + len) < crypto_data_len) {      
	NDPI_LOG_DBG2(ndpi_struct, "UA: [%.*s]\n", len, &crypto_data[uaid_offset]);
	
	http_process_user_agent(ndpi_struct, flow, &crypto_data[uaid_offset], len); /* http.c */
	ua_found = 1;
	
	if (sni_found)
	  return;
      }
    }

    prev_offset = offset;
  }
  if(i != num_tags)
    NDPI_LOG_DBG(ndpi_struct, "Something went wrong in tags iteration\n");

  /* Add check for missing SNI */
  if(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == '\0') {
    /* This is a bit suspicious */
    ndpi_set_risk(flow, NDPI_TLS_MISSING_SNI);
  }
}


static int may_be_initial_pkt(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      uint32_t *version)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t first_byte;
  u_int8_t pub_bit1, pub_bit2, pub_bit3, pub_bit4, pub_bit5, pub_bit7, pub_bit8;
  u_int8_t dest_conn_id_len, source_conn_id_len;

  /* According to draft-ietf-quic-transport-29: "Clients MUST ensure that UDP
     datagrams containing Initial packets have UDP payloads of at least 1200
     bytes". Similar limit exists for previous versions */
  if(packet->payload_packet_len < 1200) {
    return 0;
  }

  first_byte = packet->payload[0];
  pub_bit1 = ((first_byte & 0x80) != 0);
  pub_bit2 = ((first_byte & 0x40) != 0);
  pub_bit3 = ((first_byte & 0x20) != 0);
  pub_bit4 = ((first_byte & 0x10) != 0);
  pub_bit5 = ((first_byte & 0x08) != 0);
  pub_bit7 = ((first_byte & 0x02) != 0);
  pub_bit8 = ((first_byte & 0x01) != 0);

  *version = 0;
  if(pub_bit1) {
    *version = ntohl(*((u_int32_t *)&packet->payload[1]));
  } else if(pub_bit5 && !pub_bit2) {
    if(!pub_bit8) {
      NDPI_LOG_DBG2(ndpi_struct, "Packet without version\n")
	} else {
      *version = ntohl(*((u_int32_t *)&packet->payload[9]));
    }
  }
  if(!is_version_valid(*version)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid version 0x%x\n", *version);
    return 0;
  }

  if(is_gquic_ver_less_than(*version, 43) &&
     (!pub_bit5 || pub_bit3 != 0 || pub_bit4 != 0)) {
#ifdef QUIC_DEBUG
    NDPI_LOG_ERR(ndpi_struct, "Version 0x%x invalid flags 0x%x\n", *version, first_byte);
#endif
    return 0;
  }
  if((*version == V_Q046) &&
     (pub_bit7 != 1 || pub_bit8 != 1)) {
#ifdef QUIC_DEBUG
    NDPI_LOG_ERR(ndpi_struct, "Q46 invalid flag 0x%x\n", first_byte);
#endif
    return 0;
  }
  if((is_version_quic(*version) || (*version == V_Q046) || (*version == V_Q050)) &&
     (pub_bit3 != 0 || pub_bit4 != 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x not Initial Packet\n", *version);
    return 0;
  }

  /* Forcing Version Negotiation packets are QUIC Initial Packets (i.e.
     Long Header). It should also be quite rare that a client sends this kind
     of traffic with the QUIC bit greased i.e. having a server token.
     Accordind to https://tools.ietf.org/html/draft-thomson-quic-bit-grease-00#section-3.1
     "A client MAY also clear the QUIC Bit in Initial packets that are sent
      to establish a new connection.  A client can only clear the QUIC Bit
      if the packet includes a token provided by the server in a NEW_TOKEN
      frame on a connection where the server also included the
      grease_quic_bit transport parameter." */
  if((*version & 0x0F0F0F0F) == 0x0a0a0a0a &&
     !(pub_bit1 == 1 && pub_bit2 == 1)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x with first byte 0x%x\n", first_byte);
    return 0;
  }

  /* Check that CIDs lengths are valid: QUIC limits the CID length to 20 */
  if(is_version_with_ietf_long_header(*version)) {
    dest_conn_id_len = packet->payload[5];
    source_conn_id_len = packet->payload[5 + 1 + dest_conn_id_len];
    if (dest_conn_id_len > QUIC_MAX_CID_LENGTH ||
        source_conn_id_len > QUIC_MAX_CID_LENGTH) {
      NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x invalid CIDs length %u %u",
		     *version, dest_conn_id_len, source_conn_id_len);
      return 0;
    }
  }

  /* TODO: add some other checks to avoid false positives */

  return 1;
}

/* ***************************************************************** */

static int eval_extra_processing(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow, u_int32_t version)
{
  /* For the time being we need extra processing only to detect Snapchat calls,
     i.e. RTP/RTCP multiplxed with QUIC.
     We noticed that Snapchat uses Q046, without any SNI */

  if(version == V_Q046 &&
     flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == '\0') {
    NDPI_LOG_DBG2(ndpi_struct, "We have further work to do\n");
    return 1;
  }
  return 0;
}

static int is_valid_rtp_payload_type(uint8_t type)
{
  /* https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml */
  return type <= 34 || (type >= 96 && type <= 127);
}

static int ndpi_search_quic_extra(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  /* We are elaborating a packet following the initial CHLO/ClientHello.
     Mutiplexing QUIC with RTP/RTCP should be quite generic, but
     for the time being, we known only NDPI_PROTOCOL_SNAPCHAT_CALL having such behaviour */

  NDPI_LOG_DBG(ndpi_struct, "search QUIC extra func\n");

  /* If this packet is still a Q046 one we need to keep going */
  if(packet->payload[0] & 0x40) {
    NDPI_LOG_DBG(ndpi_struct, "Still QUIC\n");
    return 1; /* Keep going */
  }

  NDPI_LOG_DBG2(ndpi_struct, "No more QUIC: nothing to do on QUIC side\n");
  flow->extra_packets_func = NULL;

  /* This might be a RTP/RTCP stream: let's check it */
  /* TODO: the cleanest solution should be triggering the rtp/rtcp dissector, but
     I have not been able to that that so I reimplemented a basic RTP/RTCP detection.*/
  if((packet->payload[0] >> 6) == 2 && /* Version 2 */
     packet->payload_packet_len > 1 &&
     (packet->payload[1] == 201 || /* RTCP, Receiver Report */
      packet->payload[1] == 200 || /* RTCP, Sender Report */
      is_valid_rtp_payload_type(packet->payload[1] & 0x7F)) /* RTP */) {
    NDPI_LOG_DBG(ndpi_struct, "Found RTP/RTCP over QUIC\n");
    ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SNAPCHAT_CALL, NDPI_PROTOCOL_QUIC);
  } else {
    /* Unexpected traffic pattern: we should investigate it... */
    NDPI_LOG_INFO(ndpi_struct, "To investigate...\n");
  }

  return 0;
}

void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  u_int32_t version;
  u_int8_t *clear_payload;
  uint32_t clear_payload_len;
  const u_int8_t *crypto_data;
  uint64_t crypto_data_len;
  int is_quic;

  NDPI_LOG_DBG2(ndpi_struct, "search QUIC\n");

  /* Buffers: packet->payload ---> clear_payload ---> crypto_data */

  /*
   * 1) (Very) basic heuristic to check if it is a QUIC packet.
   *    The first packet of each QUIC session should contain a valid
   *    CHLO/ClientHello message and we need (only) it to sub-classify
   *    the flow.
   *    Detecting QUIC sessions where the first captured packet is not a
   *    CHLO/CH is VERY hard. Let's try avoiding it and let's see if
   *    anyone complains...
   */

  is_quic = may_be_initial_pkt(ndpi_struct, flow, &version);
  if(!is_quic) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 2) Ok, this packet seems to be QUIC
   */

  NDPI_LOG_INFO(ndpi_struct, "found QUIC\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN);

  /*
   * 3) Skip not supported versions
   */

  if(!is_version_supported(version)) {
#ifdef QUIC_DEBUG
    NDPI_LOG_ERR(ndpi_struct, "Unsupported version 0x%x\n", version);
#endif
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 4) Extract the Payload from Initial Packets
   */
  clear_payload = get_clear_payload(ndpi_struct, flow, version, &clear_payload_len);
  if(!clear_payload) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 5) Extract Crypto Data from the Payload
   */
  crypto_data = get_crypto_data(ndpi_struct, flow, version,
				clear_payload, clear_payload_len,
				&crypto_data_len);
  if(!crypto_data) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    if(is_version_with_encrypted_header(version)) {
      ndpi_free(clear_payload);
    }
    return;
  }

  /*
   * 6) Process ClientHello/CHLO from the Crypto Data
   */
  if(!is_version_with_tls(version)) {
    process_chlo(ndpi_struct, flow, crypto_data, crypto_data_len);
  } else {
    process_tls(ndpi_struct, flow, crypto_data, crypto_data_len, version);
  }
  if(is_version_with_encrypted_header(version)) {
    ndpi_free(clear_payload);
  }

  /*
   * 7) We need to process other packets than ClientHello/CHLO?
   */
  if(eval_extra_processing(ndpi_struct, flow, version)) {
    flow->check_extra_packets = 1;
    flow->max_extra_packets_to_check = 24; /* TODO */
    flow->extra_packets_func = ndpi_search_quic_extra;
  }
}

/* ***************************************************************** */

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_QUIC, ndpi_search_quic,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
