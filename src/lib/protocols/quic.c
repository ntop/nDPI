/*
 * quic.c
 *
 * Copyright (C) 2012-22 - ntop.org
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
#include "ndpi_private.h"


#ifdef USE_HOST_LIBGCRYPT
#include <gcrypt.h>
#else
#include <gcrypt_light.h>
#endif

/* This dissector handles GQUIC and IETF-QUIC both.
   Main references:
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/wVHBir-uRU0?pli=1
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/jCbjP0AVAAAJ
   * https://groups.google.com/a/chromium.org/g/proto-quic/c/OAVgFqw2fko/m/-NYxlh88AgAJ
   * https://docs.google.com/document/d/1FcpCJGTDEMblAs-Bm5TYuqhHyUqeWpqrItw2vkMFsdY/edit
   * https://www.rfc-editor.org/rfc/rfc9001.txt [Using TLS over QUIC]
   * https://www.rfc-editor.org/rfc/rfc9000.txt [v1]
   * https://www.rfc-editor.org/rfc/rfc9369.txt [v2]
   */

/* Versions */
#define V_2		0x6b3343cf
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

static int is_version_forcing_vn(uint32_t version)
{
  return (version & 0x0F0F0F0F) == 0x0a0a0a0a; /* Forcing Version Negotiation */
}
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
    is_version_forcing_vn(version) ||
    (version == V_2);
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
  /* QUIC (final?) constants for v1 are defined in draft-33, but latest
     draft version is -34 */
  if (version == 0x00000001) {
    return 34;
  }

  if (version == V_MVFST_22)
    return 22;
  if (version == V_MVFST_27 || version == V_MVFST_EXP)
    return 27;

  /* "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
     forcing version negotiation to be exercised".
     We can't return a correct draft version because we don't have a real
     version here! That means that we can't decode any data and we can dissect
     only the cleartext header.
     Let's return v1 (any other numbers should be fine, anyway) to only allow
     the dissection of the (expected) long header */
  if(is_version_forcing_vn(version))
    return 34;

  /* QUIC Version 2 */
  if (version == V_2)
    return 100;

  return 0;
}

static int is_quic_ver_less_than(uint32_t version, uint8_t max_version)
{
  uint8_t u8_ver = get_u8_quic_ver(version);
  return u8_ver && u8_ver <= max_version;
}
int is_quic_ver_greater_than(uint32_t version, uint8_t min_version)
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
int is_version_with_tls(uint32_t version)
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
static int is_version_with_v1_labels(uint32_t version)
{
  if(((version & 0xFFFFFF00) == 0x51303500)  /* Q05X */ ||
     ((version & 0xFFFFFF00) == 0x54303500)) /* T05X */
    return 1;
  return is_quic_ver_less_than(version, 34);
}
static int is_version_quic_v2(uint32_t version)
{
  return version == V_2;
}

char *ndpi_quic_version2str(char *buf, int buf_len, u_int32_t version) {

  if(buf == NULL || buf_len <= 1)
    return NULL;

  switch(version) {
  case V_2: strncpy(buf, "V-2", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_1: strncpy(buf, "V-1", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q024: strncpy(buf, "Q024", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q025: strncpy(buf, "Q025", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q030: strncpy(buf, "Q030", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q033: strncpy(buf, "Q033", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q034: strncpy(buf, "Q034", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q035: strncpy(buf, "Q035", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q037: strncpy(buf, "Q037", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q039: strncpy(buf, "Q039", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q043: strncpy(buf, "Q043", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q046: strncpy(buf, "Q046", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_Q050: strncpy(buf, "Q050", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_T050: strncpy(buf, "T050", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_T051: strncpy(buf, "T051", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_MVFST_22: strncpy(buf, "MVFST-22", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_MVFST_27: strncpy(buf, "MVFST-27", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case V_MVFST_EXP: strncpy(buf, "MVFST-EXP", buf_len); buf[buf_len - 1] = '\0'; return buf;
  }

  if(is_version_forcing_vn(version)) {
    strncpy(buf, "Ver-Negotiation", buf_len);
    buf[buf_len - 1] = '\0';
    return buf;
  }
  if(((version & 0xFFFFFF00) == 0xFF000000)) {
    snprintf(buf, buf_len, "Draft-%d", version & 0x000000FF);
    buf[buf_len - 1] = '\0';
    return buf;
  }

  ndpi_snprintf(buf, buf_len, "Unknown (%04X)", version);
  return buf;
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
    *value = ndpi_ntohll(get_u_int64_t(buf, 0)) & 0x3FFFFFFFFFFFFFFF;
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
  return le16toh(*(uint16_t *)buf);
}


#ifdef NDPI_ENABLE_DEBUG_MESSAGES
static char *__gcry_err(gpg_error_t err, char *buf, size_t buflen)
{
  gpg_strerror_r(err, buf, buflen);
  /* I am not sure if the string will be always null-terminated...
     Better safe than sorry */
  if(buflen > 0)
    buf[buflen - 1] = '\0';
  return buf;
}
#endif

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
  uint32_t offset;

  /* Some sanity checks */
  if(!(out_len > 0 && out_len <= 255 * hash_len) ||
     !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
    return GPG_ERR_INV_ARG;
  }

  err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
  if(err) {
    return err;
  }

  for(offset = 0; offset < out_len; offset += hash_len) {
    gcry_md_reset(h);
    gcry_md_setkey(h, prk, prk_len); /* Set PRK */
    if(offset > 0) {
      gcry_md_write(h, lastoutput, hash_len); /* T(1..N) */
    }
    gcry_md_write(h, info, info_len);                   /* info */

    uint8_t c = offset / hash_len + 1;
    gcry_md_write(h, &c, sizeof(c));                    /* constant 0x01..N */

    memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
    memcpy(out + offset, lastoutput, ndpi_min(hash_len, out_len - offset));
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
static int tls13_hkdf_expand_label_context(struct ndpi_detection_module_struct *ndpi_struct,
					   int md, const StringInfo *secret,
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
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  char buferr[128];
#endif

  /* Some sanity checks */
  if(!(label_length > 0 && label_prefix_length + label_length <= 255)) {
    NDPI_LOG_DBG(ndpi_struct, "Failed sanity checks\n");
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
  if(context_length && context_hash != NULL) {
    memcpy(&info_data[info_len], context_hash, context_length);
    info_len += context_length;
  }
#endif

  *out = (uint8_t *)ndpi_malloc(out_len);
  if(!*out) {
    ndpi_free(info_data);
    return 0;
  }
  err = hkdf_expand(md, secret->data, secret->data_len, info_data, info_len, *out, out_len);
  ndpi_free(info_data);

  if(err) {
    NDPI_LOG_DBG(ndpi_struct, "Failed hkdf_expand: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    ndpi_free(*out);
    *out = NULL;
    return 0;
  }

  return 1;
}
static int tls13_hkdf_expand_label(struct ndpi_detection_module_struct *ndpi_struct,
				   int md, const StringInfo *secret,
				   const char *label_prefix, const char *label,
				   uint16_t out_len, unsigned char **out)
{
  return tls13_hkdf_expand_label_context(ndpi_struct, md, secret, label_prefix, label, NULL, 0, out_len, out);
}


/*
 * From epan/dissectors/packet-quic.c
 */

static int quic_hkdf_expand_label(struct ndpi_detection_module_struct *ndpi_struct,
				  int hash_algo, uint8_t *secret, uint32_t secret_len,
				  const char *label, uint8_t *out, uint32_t out_len)
{
  const StringInfo secret_si = { secret, secret_len };
  uint8_t *out_mem = NULL;
  if(tls13_hkdf_expand_label(ndpi_struct, hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
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
static int quic_hp_cipher_init(struct ndpi_detection_module_struct *ndpi_struct,
			       quic_hp_cipher *hp_cipher, int hash_algo,
			       uint8_t key_length, uint8_t *secret,
			       uint32_t version)
{
  uint8_t hp_key[256/8]; /* Maximum key size is for AES256 cipher. */
  uint32_t hash_len = gcry_md_get_algo_dlen(hash_algo);
  char const * const label = is_version_with_v1_labels(version) ? "quic hp" : "quicv2 hp";

  if(!quic_hkdf_expand_label(ndpi_struct, hash_algo, secret, hash_len, label, hp_key, key_length)) {
    return 0;
  }

  return gcry_cipher_setkey(hp_cipher->hp_cipher, hp_key, key_length) == 0;
}
static int quic_pp_cipher_init(struct ndpi_detection_module_struct *ndpi_struct,
			       quic_pp_cipher *pp_cipher, int hash_algo,
			       uint8_t key_length, uint8_t *secret,
			       uint32_t version)
{
  uint8_t write_key[256/8]; /* Maximum key size is for AES256 cipher. */
  uint32_t hash_len = gcry_md_get_algo_dlen(hash_algo);
  char const * const key_label = is_version_with_v1_labels(version) ? "quic key" : "quicv2 key";
  char const * const iv_label = is_version_with_v1_labels(version) ? "quic iv" : "quicv2 iv";

  if(key_length > sizeof(write_key)) {
    return 0;
  }

  if(!quic_hkdf_expand_label(ndpi_struct, hash_algo, secret, hash_len, key_label, write_key, key_length) ||
     !quic_hkdf_expand_label(ndpi_struct, hash_algo, secret, hash_len, iv_label, pp_cipher->pp_iv, sizeof(pp_cipher->pp_iv))) {
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
static int quic_hp_cipher_prepare(struct ndpi_detection_module_struct *ndpi_struct,
                                  quic_hp_cipher *hp_cipher, int hash_algo, int cipher_algo,
                                  uint8_t *secret, u_int32_t version)
{
#if 0
  /* Clear previous state (if any). */
  quic_hp_cipher_reset(hp_cipher);
#endif

  int hp_cipher_mode;
  if(!quic_get_pn_cipher_algo(cipher_algo, &hp_cipher_mode)) {
    NDPI_LOG_DBG(ndpi_struct, "Unsupported cipher algorithm\n");
    return 0;
  }

  if(gcry_cipher_open(&hp_cipher->hp_cipher, cipher_algo, hp_cipher_mode, 0)) {
    quic_hp_cipher_reset(hp_cipher);
    NDPI_LOG_DBG(ndpi_struct, "Failed to create HP cipher\n");
    return 0;
  }

  if(secret) {
    uint32_t cipher_keylen = (uint8_t)gcry_cipher_get_algo_keylen(cipher_algo);
    if(!quic_hp_cipher_init(ndpi_struct, hp_cipher, hash_algo, cipher_keylen, secret, version)) {
      quic_hp_cipher_reset(hp_cipher);
      NDPI_LOG_DBG(ndpi_struct, "Failed to derive key material for HP cipher\n");
      return 0;
    }
  }

  return 1;
}
static int quic_pp_cipher_prepare(struct ndpi_detection_module_struct *ndpi_struct,
                                  quic_pp_cipher *pp_cipher, int hash_algo, int cipher_algo,
                                  int cipher_mode, uint8_t *secret, u_int32_t version)
{
#if 0
  /* Clear previous state (if any). */
  quic_pp_cipher_reset(pp_cipher);
#endif

  if(gcry_cipher_open(&pp_cipher->pp_cipher, cipher_algo, cipher_mode, 0)) {
    quic_pp_cipher_reset(pp_cipher);
    NDPI_LOG_DBG(ndpi_struct, "Failed to create PP cipher\n");
    return 0;
  }

  if(secret) {
    uint32_t cipher_keylen = (uint8_t)gcry_cipher_get_algo_keylen(cipher_algo);
    if(!quic_pp_cipher_init(ndpi_struct, pp_cipher, hash_algo, cipher_keylen, secret, version)) {
      quic_pp_cipher_reset(pp_cipher);
      NDPI_LOG_DBG(ndpi_struct, "Failed to derive key material for PP cipher\n");
      return 0;
    }
  }

  return 1;
}
static int quic_ciphers_prepare(struct ndpi_detection_module_struct *ndpi_struct,
                                quic_ciphers *ciphers, int hash_algo, int cipher_algo,
                                int cipher_mode, uint8_t *secret, u_int32_t version)
{
  int ret;

  ret = quic_hp_cipher_prepare(ndpi_struct, &ciphers->hp_cipher, hash_algo, cipher_algo, secret, version);
  if(ret != 1)
    return ret;
  ret = quic_pp_cipher_prepare(ndpi_struct, &ciphers->pp_cipher, hash_algo, cipher_algo, cipher_mode, secret, version);
  if(ret != 1)
    quic_hp_cipher_reset(&ciphers->hp_cipher);
  return ret;
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
  uint32_t pkt_pkn = 0, i;
  for(i = 0; i < pkn_len; i++) {
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
static void quic_decrypt_message(struct ndpi_detection_module_struct *ndpi_struct,
				 quic_pp_cipher *pp_cipher, const uint8_t *packet_payload, uint32_t packet_payload_len,
				 uint32_t header_length, uint8_t first_byte, uint32_t pkn_len,
				 uint64_t packet_number, quic_decrypt_result_t *result)
{
  gcry_error_t err;
  uint8_t *header;
  uint8_t nonce[TLS13_AEAD_NONCE_LENGTH];
  uint8_t *buffer;
  uint8_t atag[16];
  uint32_t buffer_length, i;
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  char buferr[128];
#endif

  if(!(pp_cipher != NULL) ||
     !(pp_cipher->pp_cipher != NULL) ||
     !(pkn_len < header_length) ||
     !(1 <= pkn_len && pkn_len <= 4)) {
    NDPI_LOG_DBG(ndpi_struct, "Failed sanity checks\n");
    return;
  }
  /* Copy header, but replace encrypted first byte and PKN by plaintext. */
  header = (uint8_t *)memdup(packet_payload, header_length);
  if(!header)
    return;
  header[0] = first_byte;
  for( i = 0; i < pkn_len; i++) {
    header[header_length - 1 - i] = (uint8_t)(packet_number >> (8 * i));
  }

  /* Input is "header || ciphertext (buffer) || auth tag (16 bytes)" */
  buffer_length = packet_payload_len - (header_length + 16);
  if(buffer_length == 0) {
    NDPI_LOG_DBG(ndpi_struct, "Decryption not possible, ciphertext is too short\n");
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
    NDPI_LOG_DBG(ndpi_struct, "Decryption (setiv) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    ndpi_free(header);
    ndpi_free(buffer);
    return;
  }

  /* associated data (A) is the contents of QUIC header */
  err = gcry_cipher_authenticate(pp_cipher->pp_cipher, header, header_length);
  if(err) {
    NDPI_LOG_DBG(ndpi_struct, "Decryption (authenticate) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    ndpi_free(header);
    ndpi_free(buffer);
    return;
  }

  ndpi_free(header);

  /* Output ciphertext (C) */
  err = gcry_cipher_decrypt(pp_cipher->pp_cipher, buffer, buffer_length, NULL, 0);
  if(err) {
    NDPI_LOG_DBG(ndpi_struct, "Decryption (decrypt) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    ndpi_free(buffer);
    return;
  }

  err = gcry_cipher_checktag(pp_cipher->pp_cipher, atag, 16);
  if(err) {
    NDPI_LOG_DBG(ndpi_struct, "Decryption (checktag) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    ndpi_free(buffer);
    return;
  }

  result->data = buffer;
  result->data_len = buffer_length;
}
/**
 * Compute the client and server initial secrets given Connection ID "cid".
 */
static int quic_derive_initial_secrets(struct ndpi_detection_module_struct *ndpi_struct,
				       uint32_t version,
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
  static const uint8_t handshake_salt_v2_draft_00[20] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
  };
  gcry_error_t err;
  uint8_t secret[HASH_SHA2_256_LENGTH];
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
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
  } else if (is_quic_ver_less_than(version, 34)) {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v1,
		       sizeof(handshake_salt_v1),
                       cid, cid_len, secret);
  } else {
    err = hkdf_extract(GCRY_MD_SHA256, handshake_salt_v2_draft_00,
		       sizeof(handshake_salt_v2_draft_00),
                       cid, cid_len, secret);
  }
  if(err) {
    NDPI_LOG_DBG(ndpi_struct, "Failed to extract secrets: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    return -1;
  }

  if(!quic_hkdf_expand_label(ndpi_struct, GCRY_MD_SHA256, secret, sizeof(secret), "client in",
			     client_initial_secret, HASH_SHA2_256_LENGTH)) {
    NDPI_LOG_DBG(ndpi_struct, "Key expansion (client) failed: %s\n", __gcry_err(err, buferr, sizeof(buferr)));
    return -1;
  }

  return 0;
}

/*
 * End Wireshark code
 */


static uint8_t *decrypt_initial_packet(struct ndpi_detection_module_struct *ndpi_struct,
				       const uint8_t *orig_dest_conn_id, uint8_t orig_dest_conn_id_len,
				       uint8_t dest_conn_id_len,
				       uint8_t source_conn_id_len, uint32_t version,
				       uint32_t *clear_payload_len)
{
  uint64_t token_length, payload_length, packet_number;
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  uint8_t first_byte;
  uint32_t pkn32, pn_offset, pkn_len, offset;
  quic_ciphers ciphers; /* Client initial ciphers */
  quic_decrypt_result_t decryption = { 0, 0};
  uint8_t client_secret[HASH_SHA2_256_LENGTH];

  memset(&ciphers, '\0', sizeof(ciphers));
  if(quic_derive_initial_secrets(ndpi_struct, version, orig_dest_conn_id, orig_dest_conn_id_len,
				 client_secret) != 0) {
    NDPI_LOG_DBG(ndpi_struct, "Error quic_derive_initial_secrets\n");
    return NULL;
  }

  /* Packet numbers are protected with AES128-CTR,
     Initial packets are protected with AEAD_AES_128_GCM. */
  if(!quic_ciphers_prepare(ndpi_struct, &ciphers, GCRY_MD_SHA256,
                           GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM,
                           client_secret, version)) {
    NDPI_LOG_DBG(ndpi_struct, "Error quic_cipher_prepare\n");
    return NULL;
  }

  /* Type(1) + version(4) + DCIL + DCID + SCIL + SCID */
  pn_offset = 1 + 4 + 1 + dest_conn_id_len + 1 + source_conn_id_len;
  pn_offset += quic_len(&packet->payload[pn_offset], &token_length);
  pn_offset += token_length;
  /* Checks: quic_len reads 8 bytes, at most; quic_decrypt_header reads other 20 bytes.
     Promote to uint64_t to avoid unsigned wrapping */
  if((uint64_t)pn_offset + 8 + (4 + 16) >= (uint64_t)packet->payload_packet_len) {
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
  quic_decrypt_message(ndpi_struct, &ciphers.pp_cipher, &packet->payload[0], pn_offset + payload_length,
		       offset, first_byte, pkn_len, packet_number, &decryption);

  quic_ciphers_reset(&ciphers);

  if(decryption.data_len) {
    *clear_payload_len = decryption.data_len;
    return decryption.data;
  }
  return NULL;
}

static void update_reasm_buf_bitmap(u_int8_t *buffer_bitmap,
				    const u_int32_t buffer_bitmap_size,
				    const u_int32_t recv_pos,
				    const u_int32_t recv_len)
{
  if (!recv_len || !buffer_bitmap_size || !buffer_bitmap || recv_pos + recv_len > buffer_bitmap_size * 8)
    return;
  const u_int32_t start_byte = recv_pos / 8;
  const u_int32_t end_byte = (recv_pos + recv_len - 1) / 8;
  const u_int32_t start_bit = recv_pos % 8;
  const u_int32_t end_bit = (start_bit + recv_len - 1) % 8;
  if (start_byte == end_byte)
    buffer_bitmap[start_byte] |= (((1U << recv_len) - 1U) << start_bit); // fill from bit 'start_bit' until bit 'end_bit', both inclusive
  else{
    u_int32_t i;

    for (i = start_byte + 1; i <= end_byte - 1; i++)
      buffer_bitmap[i] = 0xff; // completely received byte
    buffer_bitmap[start_byte] |= ~((1U << start_bit) - 1U); // fill from bit 'start_bit' until bit 7, both inclusive
    buffer_bitmap[end_byte] |= (1U << (end_bit + 1U)) - 1U; // fill from bit 0 until bit 'end_bit', both inclusive
  }
}

static int is_reasm_buf_complete(const u_int8_t *buffer_bitmap,
                                 const u_int32_t buffer_len)
{
  const u_int32_t complete_bytes = buffer_len / 8;
  const u_int32_t remaining_bits = buffer_len % 8;
  u_int32_t i;

  if (!buffer_bitmap)
    return 0;

  for(i = 0; i < complete_bytes; i++)
    if (buffer_bitmap[i] != 0xff)
      return 0;

  if (remaining_bits && buffer_bitmap[complete_bytes] != (1U << (remaining_bits)) - 1) 
    return 0;
    
  return 1;
}

static int __reassemble(struct ndpi_flow_struct *flow, const u_int8_t *frag,
                        uint64_t frag_len, uint64_t frag_offset,
                        const u_int8_t **buf, u_int64_t *buf_len)
{
  const uint64_t max_quic_reasm_buffer_len = 4096; /* Let's say a couple of full-MTU packets... Must be multiple of 8*/
  const uint64_t quic_reasm_buffer_bitmap_len = max_quic_reasm_buffer_len / 8;
  const uint64_t last_pos = frag_offset + frag_len;

  if(!flow->l4.udp.quic_reasm_buf) {
    flow->l4.udp.quic_reasm_buf = (uint8_t *)ndpi_malloc(max_quic_reasm_buffer_len);
    if(!flow->l4.udp.quic_reasm_buf_bitmap)
      flow->l4.udp.quic_reasm_buf_bitmap = (uint8_t *)ndpi_calloc(quic_reasm_buffer_bitmap_len, sizeof(uint8_t));
    if(!flow->l4.udp.quic_reasm_buf || !flow->l4.udp.quic_reasm_buf_bitmap)
      return -1; /* Memory error */
    flow->l4.udp.quic_reasm_buf_last_pos = 0;
  }
  if(last_pos > max_quic_reasm_buffer_len)
    return -3; /* Buffer too small */

  memcpy(&flow->l4.udp.quic_reasm_buf[frag_offset], frag, frag_len);
  flow->l4.udp.quic_reasm_buf_last_pos = last_pos > flow->l4.udp.quic_reasm_buf_last_pos ? last_pos : flow->l4.udp.quic_reasm_buf_last_pos;
  update_reasm_buf_bitmap(flow->l4.udp.quic_reasm_buf_bitmap, quic_reasm_buffer_bitmap_len, frag_offset, frag_len); 

  *buf = flow->l4.udp.quic_reasm_buf;
  *buf_len = flow->l4.udp.quic_reasm_buf_last_pos;
  return 0;
}
static int is_ch_complete(const u_int8_t *buf, uint64_t buf_len)
{
  uint32_t msg_len;

  if(buf_len >= 4) {
    msg_len = (buf[1] << 16) + (buf[2] << 8) + buf[3];
    if (4 + msg_len == buf_len) {
      return 1;
    }
  }
  return 0;
}
static int is_ch_reassembler_pending(struct ndpi_flow_struct *flow)
{
  return flow->l4.udp.quic_reasm_buf != NULL &&
    !(is_reasm_buf_complete(flow->l4.udp.quic_reasm_buf_bitmap, flow->l4.udp.quic_reasm_buf_last_pos)
      && is_ch_complete(flow->l4.udp.quic_reasm_buf, flow->l4.udp.quic_reasm_buf_last_pos));
}
static const uint8_t *get_reassembled_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
						  struct ndpi_flow_struct *flow,
						  const u_int8_t *frag,
						  uint64_t frag_offset, uint64_t frag_len,
						  uint64_t *crypto_data_len)
{
  const u_int8_t *crypto_data;
  int rc;

  NDPI_LOG_DBG2(ndpi_struct, "frag %d/%d\n", frag_offset, frag_len);

  /* Fast path: no need of reassembler stuff */
  if(frag_offset == 0 &&
     is_ch_complete(frag, frag_len)) {
    NDPI_LOG_DBG2(ndpi_struct, "Complete CH (fast path)\n");
    *crypto_data_len = frag_len;
    return frag;
  }

  rc = __reassemble(flow, frag, frag_len, frag_offset,
                    &crypto_data, crypto_data_len);
  if(rc == 0) {
    if(is_reasm_buf_complete(flow->l4.udp.quic_reasm_buf_bitmap, *crypto_data_len) &&
       is_ch_complete(crypto_data, *crypto_data_len)) {
      NDPI_LOG_DBG2(ndpi_struct, "Reassembler completed!\n");
      return crypto_data;
    }
    NDPI_LOG_DBG2(ndpi_struct, "CH not yet completed\n");
  } else {
    NDPI_LOG_DBG(ndpi_struct, "Reassembler error: %d\n", rc);
  }
  return NULL;
}

const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
			       struct ndpi_flow_struct *flow,
			       u_int8_t *clear_payload, uint32_t clear_payload_len,
			       uint64_t *crypto_data_len)
{
  const u_int8_t *crypto_data = NULL;
  uint32_t counter;
  uint8_t first_nonzero_payload_byte, offset_len;
  uint64_t unused, frag_offset, frag_len;
  u_int32_t version = flow->protos.tls_quic.quic_version;

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
      NDPI_LOG_DBG(ndpi_struct, "Unexpected stream ID version 0x%x\n", version);
      return NULL;
    }
    counter += 2 + offset_len;
    *crypto_data_len = gquic_get_u16(&clear_payload[counter], version);
    counter += 2;
    if(*crypto_data_len + counter > clear_payload_len) {
      NDPI_LOG_DBG(ndpi_struct, "Invalid length %lu + %d > %d version 0x%x\n",
		   (unsigned long)*crypto_data_len, counter, clear_payload_len, version);
      return NULL;
    }
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
    if(*crypto_data_len + counter > clear_payload_len) {
      NDPI_LOG_DBG(ndpi_struct, "Invalid length %lu + %d > %d version 0x%x\n",
		   (unsigned long)*crypto_data_len, counter, clear_payload_len, version);
      return NULL;
    }
    crypto_data = &clear_payload[counter];

  } else {  /* All other versions */
    while(counter < clear_payload_len) {
      uint8_t frame_type = clear_payload[counter];
      switch(frame_type) {
      case 0x00:
        NDPI_LOG_DBG2(ndpi_struct, "PADDING frame\n");
        while(counter < clear_payload_len &&
              clear_payload[counter] == 0)
          counter += 1;
        break;
      case 0x01:
        NDPI_LOG_DBG2(ndpi_struct, "PING frame\n");
        counter += 1;
        break;
      case 0x06:
        NDPI_LOG_DBG2(ndpi_struct, "CRYPTO frame\n");
        counter += 1;
        if(counter >= clear_payload_len ||
           counter + quic_len_buffer_still_required(clear_payload[counter]) >= clear_payload_len)
          return NULL;
        counter += quic_len(&clear_payload[counter], &frag_offset);
        if(counter >= clear_payload_len ||
           counter + quic_len_buffer_still_required(clear_payload[counter]) >= clear_payload_len)
          return NULL;
        counter += quic_len(&clear_payload[counter], &frag_len);
        if(frag_len + counter > clear_payload_len) {
          NDPI_LOG_DBG(ndpi_struct, "Invalid crypto frag length %lu + %d > %d version 0x%x\n",
                       (unsigned long)frag_len, counter, clear_payload_len, version);
          return NULL;
        }
        crypto_data = get_reassembled_crypto_data(ndpi_struct, flow,
                                                  &clear_payload[counter],
                                                  frag_offset, frag_len,
                                                  crypto_data_len);
        if(crypto_data) {
          return crypto_data;
	}
        NDPI_LOG_DBG(ndpi_struct, "Crypto reassembler pending\n");
        counter += frag_len;
        break;
      case 0x1C: /* CC */
      case 0x02: /* ACK */
        NDPI_LOG_DBG2(ndpi_struct, "Unexpected CC/ACK frame\n");
        return NULL;
      default:
        NDPI_LOG_DBG(ndpi_struct, "Unexpected frame 0x%x\n", frame_type);
	return NULL;
      }
    }
    if(counter > clear_payload_len) {
      NDPI_LOG_DBG(ndpi_struct, "Error parsing frames %d %d\n", counter, clear_payload_len);
      return NULL;
    }
  }
  return crypto_data;
}

static uint8_t *get_clear_payload(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  uint32_t version, uint32_t *clear_payload_len)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t *clear_payload;
  u_int8_t dest_conn_id_len;
  u_int8_t source_conn_id_len;

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

    source_conn_id_len = packet->payload[6 + dest_conn_id_len];
    const u_int8_t *dest_conn_id = &packet->payload[6];

    /* For initializing the ciphers we need the DCID of the very first Initial
       sent by the client. This is quite important when CH is fragmented into multiple
       packets and these packets have different DCID */
    if(flow->l4.udp.quic_orig_dest_conn_id_len == 0) {
      memcpy(flow->l4.udp.quic_orig_dest_conn_id,
             dest_conn_id, dest_conn_id_len);
      flow->l4.udp.quic_orig_dest_conn_id_len = dest_conn_id_len;
    }

    clear_payload = decrypt_initial_packet(ndpi_struct,
					   flow->l4.udp.quic_orig_dest_conn_id,
					   flow->l4.udp.quic_orig_dest_conn_id_len,
					   dest_conn_id_len,
					   source_conn_id_len, version,
					   clear_payload_len);
  }

  return clear_payload;
}

void process_tls(struct ndpi_detection_module_struct *ndpi_struct,
		 struct ndpi_flow_struct *flow,
		 const u_int8_t *crypto_data, uint32_t crypto_data_len)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* Overwriting packet payload */
  u_int16_t p_len;
  const u_int8_t *p;
  p = packet->payload;
  p_len = packet->payload_packet_len;
  packet->payload = crypto_data;
  packet->payload_packet_len = crypto_data_len;

  processClientServerHello(ndpi_struct, flow, flow->protos.tls_quic.quic_version);
  flow->protos.tls_quic.client_hello_processed = 1; /* Allow matching of custom categories */

  /* Restore */
  packet->payload = p;
  packet->payload_packet_len = p_len;

  /* ServerHello is not needed to sub-classified QUIC, so we ignore it:
     this way we lose JA3S and negotiated ciphers...
     Negotiated version is only present in the ServerHello message too, but
     fortunately, QUIC always uses TLS version 1.3 */
  flow->protos.tls_quic.ssl_version = 0x0304;

  /* DNS-over-QUIC: ALPN is "doq" or "doq-XXX" (for drafts versions) */
  if(flow->protos.tls_quic.advertised_alpns &&
     strncmp(flow->protos.tls_quic.advertised_alpns, "doq", 3) == 0) {
    NDPI_LOG_DBG(ndpi_struct, "Found DOQ (ALPN: [%s])\n", flow->protos.tls_quic.advertised_alpns);
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_DOH_DOT, NDPI_PROTOCOL_QUIC, NDPI_CONFIDENCE_DPI);
  }
}
void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow,
		  const u_int8_t *crypto_data, uint32_t crypto_data_len)
{
  const uint8_t *tag;
  uint32_t i;
  uint16_t num_tags;
  uint32_t prev_offset;
  uint32_t tag_offset_start, offset, len;
  ndpi_protocol_match_result ret_match;
  int sni_found = 0, icsl_found = 0;

  if(crypto_data_len < 6)
    return;
  if(memcmp(crypto_data, "CHLO", 4) != 0) {
    NDPI_LOG_DBG(ndpi_struct, "Unexpected handshake message");
    return;
  }
  num_tags = le16toh(*(uint16_t *)&crypto_data[4]);

  tag_offset_start = 8 + 8 * num_tags;
  prev_offset = 0;
  for(i = 0; i < num_tags; i++) {
    if(8 + 8 * i + 8 >= crypto_data_len)
      break;
    tag = &crypto_data[8 + 8 * i];
    offset = le32toh(*((u_int32_t *)&crypto_data[8 + 8 * i + 4]));
    if(prev_offset > offset)
      break;
    len = offset - prev_offset;
    /* Promote to uint64_t to avoid unsigned wrapping */
    if((uint64_t)tag_offset_start + prev_offset + len > (uint64_t)crypto_data_len)
      break;
#if 0
    printf("crypto_data_len %u tag_offset_start %u prev_offset %u offset %u len %u\n",
	   crypto_data_len, tag_offset_start, prev_offset, offset, len);
#endif
    if(memcmp(tag, "SNI\0", 4) == 0) {

      ndpi_hostname_sni_set(flow, &crypto_data[tag_offset_start + prev_offset], len, NDPI_HOSTNAME_NORM_ALL);

      NDPI_LOG_DBG2(ndpi_struct, "SNI: [%s]\n",
                    flow->host_server_name);

      ndpi_match_host_subprotocol(ndpi_struct, flow,
                                  flow->host_server_name,
                                  strlen(flow->host_server_name),
                                  &ret_match, NDPI_PROTOCOL_QUIC);
      flow->protos.tls_quic.client_hello_processed = 1; /* Allow matching of custom categories */

      ndpi_check_dga_name(ndpi_struct, flow,
                          flow->host_server_name, 1, 0);

      if(ndpi_is_valid_hostname((char *)&crypto_data[tag_offset_start + prev_offset],
				len) == 0) {
	char str[128];

	snprintf(str, sizeof(str), "Invalid host %s", flow->host_server_name);
	ndpi_set_risk(ndpi_struct, flow, NDPI_INVALID_CHARACTERS, str);
	
	/* This looks like an attack */
	ndpi_set_risk(ndpi_struct, flow, NDPI_POSSIBLE_EXPLOIT, "Suspicious hostname: attack ?");
      }
      
      sni_found = 1;
      if(icsl_found)
        return;
    }

    if(memcmp(tag, "ICSL", 4) == 0 && len >= 4) {
      u_int icsl_offset = tag_offset_start + prev_offset;

      flow->protos.tls_quic.quic_idle_timeout_sec = le32toh((*(uint32_t *)&crypto_data[icsl_offset]));
      NDPI_LOG_DBG2(ndpi_struct, "ICSL: %d\n", flow->protos.tls_quic.quic_idle_timeout_sec);
      icsl_found = 1;

      if(sni_found)
        return;
    }

    prev_offset = offset;
  }
  if(i != num_tags)
    NDPI_LOG_DBG(ndpi_struct, "Something went wrong in tags iteration\n");

  /* Add check for missing SNI */
  if(flow->host_server_name[0] == '\0') {
    /* This is a bit suspicious */
    ndpi_set_risk(ndpi_struct, flow, NDPI_TLS_MISSING_SNI, "SNI should be present all time: attack ?");
  }
}

static int may_be_gquic_rej(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  void *ptr;

  /* Common case: msg from server default port */
  if(packet->udp->source != ntohs(443))
    return 0;
  /* GQUIC. Common case: cid length 8, no version, packet number length 1 */
  if(packet->payload[0] != 0x08)
    return 0;
  if(packet->payload_packet_len < 1 + 8 + 1 + 12 /* Message auth hash */ + 16 /* Arbitrary length */)
    return 0;
  /* Search for "REJ" tag in the first 16 bytes after the hash */
  ptr = memchr(&packet->payload[1 + 8 + 1 + 12], 'R', 16 - 3);
  if(ptr && memcmp(ptr, "REJ", 3) == 0)
    return 1;
  return 0;
}

static int may_be_sh(struct ndpi_detection_module_struct *ndpi_struct,
		     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t last_byte;

  if((packet->payload[0] & 0x40) == 0)
    return 0;
  if(packet->udp->dest != ntohs(443)) {
    if(packet->udp->source ==  ntohs(443)) {
      return -1; /* Keep looking for packets sent by the client */
    }
    return 0;
  }

  /* SH packet sent by the client */

  /* QUIC never retransmits packet, but we should also somehow check that
   * these 3 packets from the client are really different from each other
   * to avoid matching retransmissions on some other protocols.
   * To avoid saving too much state, simply check the last byte of each packet
   * (the idea is that being QUIC fully encrypted, the bytes are somehow always
   * different; a weak assumption, but it allow us to save only 1 byte in
   * flow structure and it seems to work)
   * TODO: do we need something better?
   */

  if(packet->payload_packet_len < 1 + QUIC_SERVER_CID_HEURISTIC_LENGTH)
    return 0;
  last_byte = packet->payload[packet->payload_packet_len - 1];
  if(flow->l4.udp.quic_server_cid_stage > 0) {
    if(memcmp(flow->l4.udp.quic_server_cid, &packet->payload[1],
              QUIC_SERVER_CID_HEURISTIC_LENGTH) != 0 ||
       flow->l4.udp.quic_client_last_byte == last_byte)
      return 0;
    flow->l4.udp.quic_server_cid_stage++;
    if(flow->l4.udp.quic_server_cid_stage == 3) {
      /* Found QUIC via 3 SHs by client */
      return 1;
    }
  } else {
    memcpy(flow->l4.udp.quic_server_cid, &packet->payload[1], QUIC_SERVER_CID_HEURISTIC_LENGTH);
    flow->l4.udp.quic_server_cid_stage = 1;
  }
  flow->l4.udp.quic_client_last_byte = last_byte;
  return -1; /* Keep looking for other packets sent by client */
}

static int may_be_0rtt(struct ndpi_detection_module_struct *ndpi_struct,
		       uint32_t *version)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int8_t first_byte;
  u_int8_t pub_bit1, pub_bit2, pub_bit3, pub_bit4;
  u_int8_t dest_conn_id_len, source_conn_id_len;

  /* First byte + version + dest_conn_id_len */
  if(packet->payload_packet_len < 5 + 1) {
    NDPI_LOG_DBG2(ndpi_struct, "Pkt too short\n");
    return 0;
  }

  first_byte = packet->payload[0];
  pub_bit1 = ((first_byte & 0x80) != 0);
  pub_bit2 = ((first_byte & 0x40) != 0);
  pub_bit3 = ((first_byte & 0x20) != 0);
  pub_bit4 = ((first_byte & 0x10) != 0);

  *version = ntohl(*((u_int32_t *)&packet->payload[1]));

  /* IETF versions, Long header, fixed bit (ignore QUIC-bit-greased case), 0RTT */

  if(!(is_version_quic(*version) &&
       pub_bit1 && pub_bit2)) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid header or version\n");
    return 0;
  }
  if(!is_version_quic_v2(*version) &&
     (pub_bit3 != 0 || pub_bit4 != 1)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x not 0-RTT Packet\n", *version);
    return 0;
  }
  if(is_version_quic_v2(*version) &&
     (pub_bit3 != 1 || pub_bit4 != 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x not 0-RTT Packet\n", *version);
    return 0;
  }

  /* Check that CIDs lengths are valid */
  dest_conn_id_len = packet->payload[5];
  if(packet->payload_packet_len <= 5 + 1 + dest_conn_id_len) {
    NDPI_LOG_DBG2(ndpi_struct, "Dcid too short\n");
    return 0;
  }
  source_conn_id_len = packet->payload[5 + 1 + dest_conn_id_len];
  if(packet->payload_packet_len <= 5 + 1 + dest_conn_id_len + 1 + source_conn_id_len) {
    NDPI_LOG_DBG2(ndpi_struct, "Scid too short\n");
    return 0;
  }
  if(dest_conn_id_len > QUIC_MAX_CID_LENGTH ||
     source_conn_id_len > QUIC_MAX_CID_LENGTH) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x invalid CIDs length %u %u\n",
                  *version, dest_conn_id_len, source_conn_id_len);
    return 0;
  }

  return 1;
}

static int may_be_initial_pkt(struct ndpi_detection_module_struct *ndpi_struct,
			      uint32_t *version)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
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
    NDPI_LOG_DBG(ndpi_struct, "Version 0x%x invalid flags 0x%x\n", *version, first_byte);
    return 0;
  }
  if((*version == V_Q046) &&
     (pub_bit7 != 1 || pub_bit8 != 1)) {
    NDPI_LOG_DBG(ndpi_struct, "Q46 invalid flag 0x%x\n", first_byte);
    return 0;
  }
  if(((is_version_quic(*version) && !is_version_quic_v2(*version)) ||
      (*version == V_Q046) || (*version == V_Q050)) &&
     (pub_bit3 != 0 || pub_bit4 != 0)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x not Initial Packet\n", *version);
    return 0;
  }
  if(is_version_quic_v2(*version) &&
     (pub_bit3 != 0 || pub_bit4 != 1)) {
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
  if(is_version_forcing_vn(*version) &&
     !(pub_bit1 == 1 && pub_bit2 == 1)) {
    NDPI_LOG_DBG2(ndpi_struct, "Version 0x%x with first byte 0x%x\n", *version, first_byte);
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
                                 struct ndpi_flow_struct *flow)
{
  u_int32_t version = flow->protos.tls_quic.quic_version;

  /* For the time being we need extra processing in two cases only:
     1) to detect Snapchat calls, i.e. RTP/RTCP multiplxed with QUIC.
        Two cases:
        a) [old] Q046, without any SNI
        b) v1 with SNI *.addlive.io
     2) to reassemble CH fragments on multiple UDP packets.
     These two cases are mutually exclusive
  */

  if(version == V_Q046 && flow->host_server_name[0] == '\0') {
    NDPI_LOG_DBG2(ndpi_struct, "We have further work to do (old snapchat call?)\n");
    return 1;
  }

  if(version == V_1 &&
     flow->detected_protocol_stack[0] == NDPI_PROTOCOL_SNAPCHAT) {
    size_t sni_len = strlen(flow->host_server_name);
    if(sni_len > 11 &&
       strcmp(flow->host_server_name + sni_len - 11, ".addlive.io") == 0) {
      NDPI_LOG_DBG2(ndpi_struct, "We have further work to do (new snapchat call?)\n");
      return 1;
    }
  }

  if(is_ch_reassembler_pending(flow)) {
    NDPI_LOG_DBG2(ndpi_struct, "We have further work to do (reasm)\n");
    return 1;
  }

  return 0;
}

static void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow);
static int ndpi_search_quic_extra(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* We are elaborating a packet following the initial CHLO/ClientHello.
     Two cases:
     1) Mutiplexing QUIC with RTP/RTCP. It should be quite generic, but
     for the time being, we known only NDPI_PROTOCOL_SNAPCHAT_CALL having
     such behaviour
     2) CH reasssembling is going on */
  /* TODO: could we unify ndpi_search_quic() and ndpi_search_quic_extra() somehow? */

  NDPI_LOG_DBG(ndpi_struct, "search QUIC extra func\n");

  if(packet->payload_packet_len == 0)
    return 1;

  if (is_ch_reassembler_pending(flow)) {
    ndpi_search_quic(ndpi_struct, flow);
    if(is_ch_reassembler_pending(flow))
      return 1;
    flow->extra_packets_func = NULL;
    return 0;
  }

  /* RTP/RTCP stuff */

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
    ndpi_protocol proto;

    NDPI_LOG_DBG(ndpi_struct, "Found RTP/RTCP over QUIC\n");
    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SNAPCHAT_CALL, NDPI_PROTOCOL_QUIC, NDPI_CONFIDENCE_DPI);
    /* In "extra_eval" data path, if we change the classification, we need to update the category, too */
    proto.proto.master_protocol = NDPI_PROTOCOL_QUIC;
    proto.proto.app_protocol = NDPI_PROTOCOL_SNAPCHAT_CALL;
    proto.category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;
    ndpi_fill_protocol_category(ndpi_struct, flow, &proto);
  } else {
    /* Unexpected traffic pattern: we should investigate it... */
    NDPI_LOG_INFO(ndpi_struct, "To investigate...\n");
  }

  return 0;
}

static int is_vn(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t version;
  u_int8_t first_byte;
  u_int8_t pub_bit1;
  u_int8_t dest_conn_id_len, source_conn_id_len;

  /* RFC 8999 6 */

  /* First byte + version (4) + 2 CID lengths (set to 0) + at least one supported version */
  if(packet->payload_packet_len < 11) {
    return 0;
  }

  first_byte = packet->payload[0];
  pub_bit1 = ((first_byte & 0x80) != 0);
  if(!pub_bit1) {
    NDPI_LOG_DBG2(ndpi_struct, "Not a long header\n");
    return 0;
  }

  version = ntohl(*((u_int32_t *)&packet->payload[1]));
  if(version != 0) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid version 0x%x\n", version);
    return 0;
  }

  /* Check that CIDs lengths are valid: QUIC limits the CID length to 20 */
  dest_conn_id_len = packet->payload[5];
  if(5 + 1 + dest_conn_id_len >= packet->payload_packet_len) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid Length %d\n", packet->payload_packet_len);
    return 0;
  }
  source_conn_id_len = packet->payload[5 + 1 + dest_conn_id_len];
  if (dest_conn_id_len > QUIC_MAX_CID_LENGTH ||
      source_conn_id_len > QUIC_MAX_CID_LENGTH) {
    NDPI_LOG_DBG2(ndpi_struct, "Invalid CIDs length %u %u",
		  dest_conn_id_len, source_conn_id_len);
    return 0;
  }

  return 1;
}

static int ndpi_search_quic_extra_vn(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* We are elaborating a packet following the Forcing VN, i.e. we are expecting:
     1) first a VN packet (from the server)
     2) then a "standard" Initial from the client */
  /* TODO: could we unify ndpi_search_quic() and ndpi_search_quic_extra_vn() somehow? */

  NDPI_LOG_DBG(ndpi_struct, "search QUIC extra func VN\n");

  if(packet->payload_packet_len == 0)
    return 1; /* Keep going */

  if(flow->l4.udp.quic_vn_pair == 0) {
    if(is_vn(ndpi_struct)) {
      NDPI_LOG_DBG(ndpi_struct, "Valid VN\n");
      flow->l4.udp.quic_vn_pair = 1;
      return 1;
    } else {
      NDPI_LOG_DBG(ndpi_struct, "Invalid reply to a Force VN. Stop\n");
      flow->extra_packets_func = NULL;
      return 0; /* Stop */
    }
  } else {
    flow->extra_packets_func = NULL;
    ndpi_search_quic(ndpi_struct, flow);
    return 0;
  }
}

static void ndpi_search_quic(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow)
{
  u_int32_t version;
  u_int8_t *clear_payload;
  uint32_t clear_payload_len = 0;
  const u_int8_t *crypto_data;
  uint64_t crypto_data_len;
  int is_initial_quic, ret;

  NDPI_LOG_DBG2(ndpi_struct, "search QUIC\n");

  /* Buffers: packet->payload ---> clear_payload ---> crypto_data */

  /*
   * 1) (Very) basic heuristic to check if it is a QUIC packet.
   *    The first packet of each QUIC session should contain a valid
   *    CHLO/ClientHello message and we need (only) it to sub-classify
   *    the flow.
   *    Detecting QUIC sessions where the first captured packet is not a
   *    CHLO/CH is VERY hard. Let try only some easy cases:
   *    * out-of-order 0-RTT, i.e 0-RTT packets received before the Initial;
   *      in that case, keep looking for the Initial
   *    * if we have only SH pkts, focus on standard case where server
   *      port is 443 and default length of Server CID is >=8 (as it happens
   *      with most common broswer and apps). Look for 3 consecutive SH
   *      pkts send by the client and check their CIDs (note that
   *      some QUIC implementations have Client CID length set to 0, so
   *      checking pkts sent by server is useless). Since we don't know the
   *      real CID length, use the min value 8, i.e. QUIC_SERVER_CID_HEURISTIC_LENGTH
   *    * with only GQUIC packets from server (usefull with unidirectional
   *      captures) look for Rejection packet
   *    Avoid the generic cases and let's see if anyone complains...
   */

  is_initial_quic = may_be_initial_pkt(ndpi_struct, &version);
  if(!is_initial_quic) {
    if(!is_ch_reassembler_pending(flow)) { /* Better safe than sorry */
      ret = may_be_0rtt(ndpi_struct, &version);
      if(ret == 1) {
        NDPI_LOG_DBG(ndpi_struct, "Found 0-RTT, keep looking for Initial\n");
        flow->l4.udp.quic_0rtt_found = 1;
        if(flow->packet_counter >= 3) {
          /* We haven't still found an Initial.. give up */
          NDPI_LOG_INFO(ndpi_struct, "QUIC 0RTT\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
          flow->protos.tls_quic.quic_version = version;
        }
        return;
      } else if(flow->l4.udp.quic_0rtt_found == 1) {
        /* Unknown packet (probably an Handshake one) after a 0-RTT */
        NDPI_LOG_INFO(ndpi_struct, "QUIC 0RTT (without Initial)\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        flow->protos.tls_quic.quic_version = 0; /* unknown */
        return;
      }
      ret = may_be_sh(ndpi_struct, flow);
      if(ret == 1) {
        NDPI_LOG_INFO(ndpi_struct, "SH Quic\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        flow->protos.tls_quic.quic_version = 0; /* unknown */
	return;
      }
      if(ret == -1) {
        NDPI_LOG_DBG2(ndpi_struct, "Keep looking for SH by client\n");
        if(flow->packet_counter > 10 /* TODO */)
          NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	return;
      }
      ret = may_be_gquic_rej(ndpi_struct);
      if(ret == 1) {
        NDPI_LOG_INFO(ndpi_struct, "GQUIC REJ\n");
        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
        flow->protos.tls_quic.quic_version = 0; /* unknown */
	return;
      }
    }
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 2) Ok, this packet seems to be QUIC
   */

  NDPI_LOG_INFO(ndpi_struct, "found QUIC\n");
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
  flow->protos.tls_quic.quic_version = version;

  /*
   * 3) Skip not supported versions
   */

  if(!is_version_supported(version)) {
    NDPI_LOG_DBG(ndpi_struct, "Unsupported version 0x%x\n", version);
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  /*
   * 3a) Forcing VN. There is no payload to analyze yet.
   * Expecteed flow:
   *  *) C->S: Forcing VN
   *  *) S->C: VN
   *  *) C->S: "Standard" Initial with crypto data
   */
  if(is_version_forcing_vn(version)) {
    NDPI_LOG_DBG(ndpi_struct, "Forcing VN\n");
    flow->max_extra_packets_to_check = 4; /* TODO */
    flow->extra_packets_func = ndpi_search_quic_extra_vn;
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
  crypto_data = get_crypto_data(ndpi_struct, flow,
				clear_payload, clear_payload_len,
				&crypto_data_len);

  /*
   * 6) Process ClientHello/CHLO from the Crypto Data (if any)
   */
  if(crypto_data) {
    if(!is_version_with_tls(version)) {
      process_chlo(ndpi_struct, flow, crypto_data, crypto_data_len);
    } else {
      process_tls(ndpi_struct, flow, crypto_data, crypto_data_len);
    }
  }
  if(is_version_with_encrypted_header(version)) {
    ndpi_free(clear_payload);
  }

  /*
   * 7) We need to process other packets than (the first) ClientHello/CHLO?
   */
  if(eval_extra_processing(ndpi_struct, flow)) {
    flow->max_extra_packets_to_check = 24; /* TODO */
    flow->extra_packets_func = ndpi_search_quic_extra;
  } else if(!crypto_data) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}

/* ***************************************************************** */

void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id)
{
  ndpi_set_bitmask_protocol_detection("QUIC", ndpi_struct, *id,
				      NDPI_PROTOCOL_QUIC, ndpi_search_quic,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
