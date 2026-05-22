/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-26 - ntop.org and contributors
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>
#include <time.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_encryption.h"
#include "ndpi_private.h"

#include "ahocorasick.h"
#include "libcache.h"
#include "shoco.h"

#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "third_party/include/ndpi_patricia.h"
#include "third_party/include/libinjection.h"
#include "third_party/include/libinjection_sqli.h"
#include "third_party/include/libinjection_xss.h"
#include "third_party/include/uthash.h"
#include "third_party/include/rce_injection.h"

#include "ndpi_replace_printf.h"
#include "ndpi_sha256.h"

#define NDPI_CONST_GENERIC_PROTOCOL_NAME  "GenericProtocol"

// #define MATCH_DEBUG 1

// #define DEBUG_REASSEMBLY

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

struct pcre2_struct {
  pcre2_code *compiled;
};
#endif

typedef struct {
  char *key;
  u_int64_t value64;
  ndpi_list value_list;
  UT_hash_handle hh;
} ndpi_str_hash_priv;

typedef struct {
  uint32_t seconds;
  uint32_t fraction;
} ntp_t;

#define NTP_DELTA 2208988800UL

/* ****************************************** */

// https://tickelton.gitlab.io/articles/ntp-timestamps/
void ntp_ts_to_string(uint64_t timestamp, char *buffer, size_t buffer_size) {

  if (timestamp == 0) {
    buffer[0] = '\0';
    return;
  }

  ntp_t ntp;

  memcpy(&ntp, &timestamp, sizeof(uint64_t));

  time_t sec = ntohl(ntp.seconds) - NTP_DELTA;
  uint32_t usec = (uint32_t)((double)ntohl(ntp.fraction) * 1.0e9 / (double)(1LL << 32));

  struct tm tm;

  (void)ndpi_gmtime_r(&sec, &tm);
  size_t offset = strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", &tm);
  snprintf(buffer + offset, buffer_size - offset, ".%d", usec);
}


/* implementation of the punycode check function */
int ndpi_check_punycode_string(char * buffer , int len) {
  int i = 0;

  while(i < len - 3) {
    if((buffer[i] == 'x')
       && (buffer[i+1] == 'n')
       && (buffer[i+2] == '-')
       && (buffer[i+3] == '-'))
      // is a punycode string
      return(1);
    i++;
  }

  // not a punycode string
  return 0;
}

/* ****************************************** */

/* ftp://ftp.cc.uoc.gr/mirrors/OpenBSD/src/lib/libc/stdlib/tsearch.c */
/* find or insert datum into search tree */
void * ndpi_tsearch(const void *vkey, void **vrootp,
		    int (*compar)(const void *, const void *))
{
  ndpi_node *q;
  char *key = (char *)vkey;
  ndpi_node **rootp = (ndpi_node **)vrootp;

  if(rootp == (ndpi_node **)0)
    return ((void *)0);
  while (*rootp != (ndpi_node *)0) {	/* Knuth's T1: */
    int r;

    if((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */
      return ((*rootp)->key);	/* we found it! */
    rootp = (r < 0) ?
      &(*rootp)->left :		/* T3: follow left branch */
      &(*rootp)->right;		/* T4: follow right branch */
  }
  q = (ndpi_node *) ndpi_malloc(sizeof(ndpi_node));	/* T5: key not found */
  if(q != (ndpi_node *)0) {	/* make new node */
    *rootp = q;			/* link new node to old */
    q->key = key;		/* initialize new node */
    q->left = q->right = (ndpi_node *)0;
    return ((void *)q->key);
  }
  return ((void *)0);
}

/* ****************************************** */

/* delete node with given key */
void * ndpi_tdelete(const void *vkey, void **vrootp,
		    int (*compar)(const void *, const void *))
{
  ndpi_node **rootp = (ndpi_node **)vrootp;
  char *key = (char *)vkey;
  ndpi_node *q;
  ndpi_node *r;
  int cmp;

  if(rootp == (ndpi_node **)0 || *rootp == (ndpi_node *)0)
    return((void *)0);
  while ((cmp = (*compar)(key, (*rootp)->key)) != 0) {
    rootp = (cmp < 0) ?
      &(*rootp)->left :		/* follow left branch */
      &(*rootp)->right;		/* follow right branch */
    if(*rootp == (ndpi_node *)0)
      return ((void *)0);		/* key not found */
  }
  r = (*rootp)->right;			/* D1: */
  if((q = (*rootp)->left) == (ndpi_node *)0)	/* Left (ndpi_node *)0? */
    q = r;
  else if(r != (ndpi_node *)0) {		/* Right link is null? */
    if(r->left == (ndpi_node *)0) {	/* D2: Find successor */
      r->left = q;
      q = r;
    } else {			/* D3: Find (ndpi_node *)0 link */
      for(q = r->left; q->left != (ndpi_node *)0; q = r->left)
	r = q;
      r->left = q->right;
      q->left = (*rootp)->left;
      q->right = (*rootp)->right;
    }
  }
  key = (*rootp)->key;
  ndpi_free((ndpi_node *) *rootp);	/* D4: Free node */
  *rootp = q;				/* link parent to new node */

  /* Return the key to give the caller a chance to free custom data */
  return(key);
}

/* ****************************************** */

/* Walk the nodes of a tree */
static void ndpi_trecurse(ndpi_node *root, void (*action)(const void *, ndpi_VISIT, int, void*), int level, void *user_data)
{
  if(root->left == (ndpi_node *)0 && root->right == (ndpi_node *)0)
    (*action)(root, ndpi_leaf, level, user_data);
  else {
    (*action)(root, ndpi_preorder, level, user_data);
    if(root->left != (ndpi_node *)0)
      ndpi_trecurse(root->left, action, level + 1, user_data);
    (*action)(root, ndpi_postorder, level, user_data);
    if(root->right != (ndpi_node *)0)
      ndpi_trecurse(root->right, action, level + 1, user_data);
    (*action)(root, ndpi_endorder, level, user_data);
  }
}

/* ****************************************** */

/* Walk the nodes of a tree */
void ndpi_twalk(const void *vroot, void (*action)(const void *, ndpi_VISIT, int, void *), void *user_data)
{
  ndpi_node *root = (ndpi_node *)vroot;

  if(root != (ndpi_node *)0 && action != (void (*)(const void *, ndpi_VISIT, int, void*))0)
    ndpi_trecurse(root, action, 0, user_data);
}

/* ****************************************** */

/* find a node, or return 0 */
void * ndpi_tfind(const void *vkey, void *vrootp,
		  int (*compar)(const void *, const void *))
{
  char *key = (char *)vkey;
  ndpi_node **rootp = (ndpi_node **)vrootp;

  if(rootp == (ndpi_node **)0)
    return ((ndpi_node *)0);
  while (*rootp != (ndpi_node *)0) {	/* T1: */
    int r;
    if((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */
      return (*rootp);		/* key found */
    rootp = (r < 0) ?
      &(*rootp)->left :		/* T3: follow left branch */
      &(*rootp)->right;		/* T4: follow right branch */
  }
  return (ndpi_node *)0;
}

/* ****************************************** */

/* Walk the nodes of a tree */
static void ndpi_tdestroy_recurse(ndpi_node* root, void (*free_action)(void *))
{
  if(root->left != NULL)
    ndpi_tdestroy_recurse(root->left, free_action);
  if(root->right != NULL)
    ndpi_tdestroy_recurse(root->right, free_action);

  (*free_action) ((void *) root->key);
  ndpi_free(root);
}

void ndpi_tdestroy(void *vrootp, void (*freefct)(void *))
{
  ndpi_node *root = (ndpi_node *) vrootp;

  if(root != NULL)
    ndpi_tdestroy_recurse(root, freefct);
}

/* ****************************************** */

u_int8_t ndpi_net_match(u_int32_t ip_to_check,
			u_int32_t net,
			u_int32_t num_bits) {
  u_int32_t mask = 0;

  num_bits &= 0x1F; /* Avoid overflows */

  mask = ~(~mask >> num_bits);

  return(((ip_to_check & mask) == (net & mask)) ? 1 : 0);
}

u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
			u_int32_t net, u_int32_t num_bits) {
  return(ndpi_net_match(src, net, num_bits) || ndpi_net_match(dst, net, num_bits));
}

/* **************************************** */

u_int8_t ndpi_is_safe_ssl_cipher(u_int32_t cipher) {
  /* https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites */

  switch(cipher) {
    /* INSECURE */
  case TLS_ECDHE_RSA_WITH_RC4_128_SHA: return(NDPI_CIPHER_INSECURE);
  case TLS_RSA_WITH_RC4_128_SHA: return(NDPI_CIPHER_INSECURE);
  case TLS_RSA_WITH_RC4_128_MD5: return(NDPI_CIPHER_INSECURE);

    /* WEAK */
  case TLS_RSA_WITH_AES_256_GCM_SHA384: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_AES_256_CBC_SHA256: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_AES_256_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_AES_128_GCM_SHA256: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_AES_128_CBC_SHA256: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_AES_128_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_3DES_EDE_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_SEED_CBC_SHA: return(NDPI_CIPHER_WEAK);
  case TLS_RSA_WITH_IDEA_CBC_SHA: return(NDPI_CIPHER_WEAK);

  default:
    return(NDPI_CIPHER_SAFE);
  }
}

/* ***************************************************** */

const char* ndpi_cipher2str(u_int32_t cipher, char unknown_cipher[8]) {
  switch(cipher) {
  case TLS_NULL_WITH_NULL_NULL:	return("TLS_NULL_WITH_NULL_NULL");
  case TLS_RSA_EXPORT_WITH_RC4_40_MD5:	return("TLS_RSA_EXPORT_WITH_RC4_40_MD5");
  case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:	return("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5");
  case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_RSA_WITH_NULL_MD5:	return("TLS_RSA_WITH_NULL_MD5");
  case TLS_RSA_WITH_NULL_SHA:	return("TLS_RSA_WITH_NULL_SHA");
  case TLS_RSA_WITH_NULL_SHA256:	return("TLS_RSA_WITH_NULL_SHA256");
  case TLS_RSA_WITH_RC4_128_MD5:	return("TLS_RSA_WITH_RC4_128_MD5");
  case TLS_RSA_WITH_RC4_128_SHA:	return("TLS_RSA_WITH_RC4_128_SHA");
  case TLS_RSA_WITH_IDEA_CBC_SHA:	return("TLS_RSA_WITH_IDEA_CBC_SHA");
  case TLS_RSA_WITH_DES_CBC_SHA:	return("TLS_RSA_WITH_DES_CBC_SHA");
  case TLS_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_RSA_WITH_AES_128_CBC_SHA:	return("TLS_RSA_WITH_AES_128_CBC_SHA");
  case TLS_RSA_WITH_AES_256_CBC_SHA:	return("TLS_RSA_WITH_AES_256_CBC_SHA");
  case TLS_RSA_WITH_AES_128_CBC_SHA256:	return("TLS_RSA_WITH_AES_128_CBC_SHA256");
  case TLS_RSA_WITH_AES_256_CBC_SHA256:	return("TLS_RSA_WITH_AES_256_CBC_SHA256");
  case TLS_RSA_WITH_AES_128_GCM_SHA256:	return("TLS_RSA_WITH_AES_128_GCM_SHA256");
  case TLS_RSA_WITH_AES_256_GCM_SHA384:	return("TLS_RSA_WITH_AES_256_GCM_SHA384");
  case TLS_RSA_WITH_AES_128_CCM:	return("TLS_RSA_WITH_AES_128_CCM");
  case TLS_RSA_WITH_AES_256_CCM:	return("TLS_RSA_WITH_AES_256_CCM");
  case TLS_RSA_WITH_AES_128_CCM_8:	return("TLS_RSA_WITH_AES_128_CCM_8");
  case TLS_RSA_WITH_AES_256_CCM_8:	return("TLS_RSA_WITH_AES_256_CCM_8");
  case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_RSA_WITH_SEED_CBC_SHA:	return("TLS_RSA_WITH_SEED_CBC_SHA");
  case TLS_RSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_RSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_RSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_RSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_RSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_RSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_RSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_RSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_DH_RSA_WITH_DES_CBC_SHA:	return("TLS_DH_RSA_WITH_DES_CBC_SHA");
  case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_DH_RSA_WITH_AES_128_CBC_SHA:	return("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
  case TLS_DH_RSA_WITH_AES_256_CBC_SHA:	return("TLS_DH_RSA_WITH_AES_256_CBC_SHA");
  case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:	return("TLS_DH_RSA_WITH_AES_128_CBC_SHA256");
  case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:	return("TLS_DH_RSA_WITH_AES_256_CBC_SHA256");
  case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:	return("TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
  case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:	return("TLS_DH_RSA_WITH_AES_256_GCM_SHA384");
  case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DH_RSA_WITH_SEED_CBC_SHA:	return("TLS_DH_RSA_WITH_SEED_CBC_SHA");
  case TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_DHE_RSA_WITH_DES_CBC_SHA:	return("TLS_DHE_RSA_WITH_DES_CBC_SHA");
  case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:	return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
  case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:	return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
  case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:	return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
  case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:	return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
  case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:	return("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
  case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:	return("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
  case TLS_DHE_RSA_WITH_AES_128_CCM:	return("TLS_DHE_RSA_WITH_AES_128_CCM");
  case TLS_DHE_RSA_WITH_AES_256_CCM:	return("TLS_DHE_RSA_WITH_AES_256_CCM");
  case TLS_DHE_RSA_WITH_AES_128_CCM_8:	return("TLS_DHE_RSA_WITH_AES_128_CCM_8");
  case TLS_DHE_RSA_WITH_AES_256_CCM_8:	return("TLS_DHE_RSA_WITH_AES_256_CCM_8");
  case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DHE_RSA_WITH_SEED_CBC_SHA:	return("TLS_DHE_RSA_WITH_SEED_CBC_SHA");
  case TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_DH_DSS_WITH_DES_CBC_SHA:	return("TLS_DH_DSS_WITH_DES_CBC_SHA");
  case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:	return("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA");
  case TLS_DH_DSS_WITH_AES_128_CBC_SHA:	return("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
  case TLS_DH_DSS_WITH_AES_256_CBC_SHA:	return("TLS_DH_DSS_WITH_AES_256_CBC_SHA");
  case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:	return("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
  case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:	return("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
  case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:	return("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
  case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:	return("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
  case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DH_DSS_WITH_SEED_CBC_SHA:	return("TLS_DH_DSS_WITH_SEED_CBC_SHA");
  case TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256:	return("TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256");
  case TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384:	return("TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384");
  case TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256:	return("TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256");
  case TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384:	return("TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384");
  case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_DHE_DSS_WITH_DES_CBC_SHA:	return("TLS_DHE_DSS_WITH_DES_CBC_SHA");
  case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:	return("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA");
  case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:	return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
  case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:	return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
  case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:	return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
  case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:	return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
  case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:	return("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
  case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:	return("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
  case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DHE_DSS_WITH_SEED_CBC_SHA:	return("TLS_DHE_DSS_WITH_SEED_CBC_SHA");
  case TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256:	return("TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256");
  case TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384:	return("TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384");
  case TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:	return("TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256");
  case TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:	return("TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384");
  case TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5:	return("TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5");
  case TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA:	return("TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA");
  case TLS_DH_ANON_WITH_RC4_128_MD5:	return("TLS_DH_ANON_WITH_RC4_128_MD5");
  case TLS_DH_ANON_WITH_DES_CBC_SHA:	return("TLS_DH_ANON_WITH_DES_CBC_SHA");
  case TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA:	return("TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA");
  case TLS_DH_ANON_WITH_AES_128_CBC_SHA:	return("TLS_DH_ANON_WITH_AES_128_CBC_SHA");
  case TLS_DH_ANON_WITH_AES_256_CBC_SHA:	return("TLS_DH_ANON_WITH_AES_256_CBC_SHA");
  case TLS_DH_ANON_WITH_AES_128_CBC_SHA256:	return("TLS_DH_ANON_WITH_AES_128_CBC_SHA256");
  case TLS_DH_ANON_WITH_AES_256_CBC_SHA256:	return("TLS_DH_ANON_WITH_AES_256_CBC_SHA256");
  case TLS_DH_ANON_WITH_AES_128_GCM_SHA256:	return("TLS_DH_ANON_WITH_AES_128_GCM_SHA256");
  case TLS_DH_ANON_WITH_AES_256_GCM_SHA384:	return("TLS_DH_ANON_WITH_AES_256_GCM_SHA384");
  case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA:	return("TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA");
  case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA:	return("TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA");
  case TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256:	return("TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256");
  case TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DH_ANON_WITH_SEED_CBC_SHA:	return("TLS_DH_ANON_WITH_SEED_CBC_SHA");
  case TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256:	return("TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256");
  case TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384:	return("TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384");
  case TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256:	return("TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256");
  case TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384:	return("TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384");
  case TLS_ECDH_RSA_WITH_NULL_SHA:	return("TLS_ECDH_RSA_WITH_NULL_SHA");
  case TLS_ECDH_RSA_WITH_RC4_128_SHA:	return("TLS_ECDH_RSA_WITH_RC4_128_SHA");
  case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:	return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
  case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:	return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
  case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:	return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
  case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:	return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
  case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:	return("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
  case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:	return("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
  case TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_ECDHE_RSA_WITH_NULL_SHA:	return("TLS_ECDHE_RSA_WITH_NULL_SHA");
  case TLS_ECDHE_RSA_WITH_RC4_128_SHA:	return("TLS_ECDHE_RSA_WITH_RC4_128_SHA");
  case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:	return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
  case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:	return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
  case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:	return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
  case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:	return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
  case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:	return("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:	return("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
  case TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_ECDH_ECDSA_WITH_NULL_SHA:	return("TLS_ECDH_ECDSA_WITH_NULL_SHA");
  case TLS_ECDH_ECDSA_WITH_RC4_128_SHA:	return("TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
  case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:	return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:	return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:	return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
  case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:	return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
  case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:	return("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
  case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:	return("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
  case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_ECDHE_ECDSA_WITH_NULL_SHA:	return("TLS_ECDHE_ECDSA_WITH_NULL_SHA");
  case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:	return("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
  case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:	return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
  case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:	return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
  case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:	return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
  case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:	return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
  case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:	return("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:	return("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:	return("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
  case TLS_ECDHE_ECDSA_WITH_AES_256_CCM:	return("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
  case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:	return("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
  case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:	return("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
  case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256:	return("TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256");
  case TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384:	return("TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384");
  case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:	return("TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
  case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:	return("TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
  case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_ECDH_ANON_WITH_NULL_SHA:	return("TLS_ECDH_ANON_WITH_NULL_SHA");
  case TLS_ECDH_ANON_WITH_RC4_128_SHA:	return("TLS_ECDH_ANON_WITH_RC4_128_SHA");
  case TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDH_ANON_WITH_AES_128_CBC_SHA:	return("TLS_ECDH_ANON_WITH_AES_128_CBC_SHA");
  case TLS_ECDH_ANON_WITH_AES_256_CBC_SHA:	return("TLS_ECDH_ANON_WITH_AES_256_CBC_SHA");
  case TLS_PSK_WITH_NULL_SHA:	return("TLS_PSK_WITH_NULL_SHA");
  case TLS_PSK_WITH_NULL_SHA256:	return("TLS_PSK_WITH_NULL_SHA256");
  case TLS_PSK_WITH_NULL_SHA384:	return("TLS_PSK_WITH_NULL_SHA384");
  case TLS_PSK_WITH_RC4_128_SHA:	return("TLS_PSK_WITH_RC4_128_SHA");
  case TLS_PSK_WITH_3DES_EDE_CBC_SHA:	return("TLS_PSK_WITH_3DES_EDE_CBC_SHA");
  case TLS_PSK_WITH_AES_128_CBC_SHA:	return("TLS_PSK_WITH_AES_128_CBC_SHA");
  case TLS_PSK_WITH_AES_256_CBC_SHA:	return("TLS_PSK_WITH_AES_256_CBC_SHA");
  case TLS_PSK_WITH_AES_128_CBC_SHA256:	return("TLS_PSK_WITH_AES_128_CBC_SHA256");
  case TLS_PSK_WITH_AES_256_CBC_SHA384:	return("TLS_PSK_WITH_AES_256_CBC_SHA384");
  case TLS_PSK_WITH_AES_128_GCM_SHA256:	return("TLS_PSK_WITH_AES_128_GCM_SHA256");
  case TLS_PSK_WITH_AES_256_GCM_SHA384:	return("TLS_PSK_WITH_AES_256_GCM_SHA384");
  case TLS_PSK_WITH_AES_128_CCM:	return("TLS_PSK_WITH_AES_128_CCM");
  case TLS_PSK_WITH_AES_256_CCM:	return("TLS_PSK_WITH_AES_256_CCM");
  case TLS_PSK_WITH_AES_128_CCM_8:	return("TLS_PSK_WITH_AES_128_CCM_8");
  case TLS_PSK_WITH_AES_256_CCM_8:	return("TLS_PSK_WITH_AES_256_CCM_8");
  case TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_PSK_WITH_ARIA_128_CBC_SHA256:	return("TLS_PSK_WITH_ARIA_128_CBC_SHA256");
  case TLS_PSK_WITH_ARIA_256_CBC_SHA384:	return("TLS_PSK_WITH_ARIA_256_CBC_SHA384");
  case TLS_PSK_WITH_ARIA_128_GCM_SHA256:	return("TLS_PSK_WITH_ARIA_128_GCM_SHA256");
  case TLS_PSK_WITH_ARIA_256_GCM_SHA384:	return("TLS_PSK_WITH_ARIA_256_GCM_SHA384");
  case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_RSA_PSK_WITH_NULL_SHA:	return("TLS_RSA_PSK_WITH_NULL_SHA");
  case TLS_RSA_PSK_WITH_NULL_SHA256:	return("TLS_RSA_PSK_WITH_NULL_SHA256");
  case TLS_RSA_PSK_WITH_NULL_SHA384:	return("TLS_RSA_PSK_WITH_NULL_SHA384");
  case TLS_RSA_PSK_WITH_RC4_128_SHA:	return("TLS_RSA_PSK_WITH_RC4_128_SHA");
  case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:	return("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA");
  case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:	return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA");
  case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:	return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA");
  case TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:	return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");
  case TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:	return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384");
  case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:	return("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256");
  case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:	return("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384");
  case TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256:	return("TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256");
  case TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384:	return("TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384");
  case TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256:	return("TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256");
  case TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384:	return("TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384");
  case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_DHE_PSK_WITH_NULL_SHA:	return("TLS_DHE_PSK_WITH_NULL_SHA");
  case TLS_DHE_PSK_WITH_NULL_SHA256:	return("TLS_DHE_PSK_WITH_NULL_SHA256");
  case TLS_DHE_PSK_WITH_NULL_SHA384:	return("TLS_DHE_PSK_WITH_NULL_SHA384");
  case TLS_DHE_PSK_WITH_RC4_128_SHA:	return("TLS_DHE_PSK_WITH_RC4_128_SHA");
  case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:	return("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:	return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
  case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:	return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
  case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:	return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256");
  case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:	return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384");
  case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:	return("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256");
  case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:	return("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384");
  case TLS_DHE_PSK_WITH_AES_128_CCM:	return("TLS_DHE_PSK_WITH_AES_128_CCM");
  case TLS_DHE_PSK_WITH_AES_256_CCM:	return("TLS_DHE_PSK_WITH_AES_256_CCM");
  case TLS_DHE_PSK_WITH_AES_128_CCM_8:	return("TLS_DHE_PSK_WITH_AES_128_CCM_8");
  case TLS_DHE_PSK_WITH_AES_256_CCM_8:	return("TLS_DHE_PSK_WITH_AES_256_CCM_8");
  case TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:	return("TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:	return("TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256:	return("TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256");
  case TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384:	return("TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384");
  case TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256:	return("TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256");
  case TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384:	return("TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384");
  case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_ECDHE_PSK_WITH_NULL_SHA:	return("TLS_ECDHE_PSK_WITH_NULL_SHA");
  case TLS_ECDHE_PSK_WITH_NULL_SHA256:	return("TLS_ECDHE_PSK_WITH_NULL_SHA256");
  case TLS_ECDHE_PSK_WITH_NULL_SHA384:	return("TLS_ECDHE_PSK_WITH_NULL_SHA384");
  case TLS_ECDHE_PSK_WITH_RC4_128_SHA:	return("TLS_ECDHE_PSK_WITH_RC4_128_SHA");
  case TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:	return("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:	return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
  case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:	return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
  case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:	return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
  case TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:	return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
  case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:	return("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256");
  case TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:	return("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384");
  case TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:	return("TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256");
  case TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:	return("TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256");
  case TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:	return("TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:	return("TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256:	return("TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256");
  case TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384:	return("TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384");
  case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:	return("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case TLS_KRB5_EXPORT_WITH_RC4_40_MD5:	return("TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
  case TLS_KRB5_EXPORT_WITH_RC4_40_SHA:	return("TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
  case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5:	return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
  case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA:	return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
  case TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5:	return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5");
  case TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA:	return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA");
  case TLS_KRB5_WITH_RC4_128_MD5:	return("TLS_KRB5_WITH_RC4_128_MD5");
  case TLS_KRB5_WITH_RC4_128_SHA:	return("TLS_KRB5_WITH_RC4_128_SHA");
  case TLS_KRB5_WITH_IDEA_CBC_MD5:	return("TLS_KRB5_WITH_IDEA_CBC_MD5");
  case TLS_KRB5_WITH_IDEA_CBC_SHA:	return("TLS_KRB5_WITH_IDEA_CBC_SHA");
  case TLS_KRB5_WITH_DES_CBC_MD5:	return("TLS_KRB5_WITH_DES_CBC_MD5");
  case TLS_KRB5_WITH_DES_CBC_SHA:	return("TLS_KRB5_WITH_DES_CBC_SHA");
  case TLS_KRB5_WITH_3DES_EDE_CBC_MD5:	return("TLS_KRB5_WITH_3DES_EDE_CBC_MD5");
  case TLS_KRB5_WITH_3DES_EDE_CBC_SHA:	return("TLS_KRB5_WITH_3DES_EDE_CBC_SHA");
  case TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:	return("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA");
  case TLS_SRP_SHA_WITH_AES_128_CBC_SHA:	return("TLS_SRP_SHA_WITH_AES_128_CBC_SHA");
  case TLS_SRP_SHA_WITH_AES_256_CBC_SHA:	return("TLS_SRP_SHA_WITH_AES_256_CBC_SHA");
  case TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:	return("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
  case TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:	return("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
  case TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:	return("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
  case TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:	return("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
  case TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:	return("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
  case TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:	return("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
  case TLS_ECCPWD_WITH_AES_128_GCM_SHA256:	return("TLS_ECCPWD_WITH_AES_128_GCM_SHA256");
  case TLS_ECCPWD_WITH_AES_256_GCM_SHA384:	return("TLS_ECCPWD_WITH_AES_256_GCM_SHA384");
  case TLS_ECCPWD_WITH_AES_128_CCM_SHA256:	return("TLS_ECCPWD_WITH_AES_128_CCM_SHA256");
  case TLS_ECCPWD_WITH_AES_256_CCM_SHA384:	return("TLS_ECCPWD_WITH_AES_256_CCM_SHA384");
  case TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC:	return("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC");
  case TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC:	return("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC");
  case TLS_GOSTR341112_256_WITH_28147_CNT_IMIT:	return("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT");
  case TLS_AES_128_GCM_SHA256:	return("TLS_AES_128_GCM_SHA256");
  case TLS_AES_256_GCM_SHA384:	return("TLS_AES_256_GCM_SHA384");
  case TLS_AES_128_CCM_SHA256:	return("TLS_AES_128_CCM_SHA256");
  case TLS_AES_128_CCM_8_SHA256:	return("TLS_AES_128_CCM_8_SHA256");
  case TLS_CHACHA20_POLY1305_SHA256:	return("TLS_CHACHA20_POLY1305_SHA256");
  case TLS_SM4_GCM_SM3:	return("TLS_SM4_GCM_SM3");
  case TLS_SM4_CCM_SM3:	return("TLS_SM4_CCM_SM3");
  case TLS_SHA256_SHA256:	return("TLS_SHA256_SHA256");
  case TLS_SHA384_SHA384:	return("TLS_SHA384_SHA384");
  case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:	return("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
  case TLS_FALLBACK_SCSV:	return("TLS_FALLBACK_SCSV");
  case TLS_CIPHER_GREASE_RESERVED_0:	return("TLS_CIPHER_GREASE_RESERVED_0");
  case TLS_CIPHER_GREASE_RESERVED_1:	return("TLS_CIPHER_GREASE_RESERVED_1");
  case TLS_CIPHER_GREASE_RESERVED_2:	return("TLS_CIPHER_GREASE_RESERVED_2");
  case TLS_CIPHER_GREASE_RESERVED_3:	return("TLS_CIPHER_GREASE_RESERVED_3");
  case TLS_CIPHER_GREASE_RESERVED_4:	return("TLS_CIPHER_GREASE_RESERVED_4");
  case TLS_CIPHER_GREASE_RESERVED_5:	return("TLS_CIPHER_GREASE_RESERVED_5");
  case TLS_CIPHER_GREASE_RESERVED_6:	return("TLS_CIPHER_GREASE_RESERVED_6");
  case TLS_CIPHER_GREASE_RESERVED_7:	return("TLS_CIPHER_GREASE_RESERVED_7");
  case TLS_CIPHER_GREASE_RESERVED_8:	return("TLS_CIPHER_GREASE_RESERVED_8");
  case TLS_CIPHER_GREASE_RESERVED_9:	return("TLS_CIPHER_GREASE_RESERVED_9");
  case TLS_CIPHER_GREASE_RESERVED_A:	return("TLS_CIPHER_GREASE_RESERVED_A");
  case TLS_CIPHER_GREASE_RESERVED_B:	return("TLS_CIPHER_GREASE_RESERVED_B");
  case TLS_CIPHER_GREASE_RESERVED_C:	return("TLS_CIPHER_GREASE_RESERVED_C");
  case TLS_CIPHER_GREASE_RESERVED_D:	return("TLS_CIPHER_GREASE_RESERVED_D");
  case TLS_CIPHER_GREASE_RESERVED_E:	return("TLS_CIPHER_GREASE_RESERVED_E");
  case TLS_CIPHER_GREASE_RESERVED_F:	return("TLS_CIPHER_GREASE_RESERVED_F");

  default:
    {
      ndpi_snprintf(unknown_cipher, 8, "0X%04X", cipher);
      return(unknown_cipher);
    }
  }
}

/* ******************************************************************** */

static inline int ndpi_is_other_char(char c) {
  return((c == '.')
	 || (c == ' ')
	 || (c == '@')
	 || (c == '/')
	 );
}

/* ******************************************************************** */

static int _ndpi_is_valid_char(char c) {
  if(ndpi_ispunct(c) && (!ndpi_is_other_char(c)))
    return(0);
  else
    return(ndpi_isdigit(c)
	   || ndpi_isalpha(c)
	   || ndpi_is_other_char(c));
}
static char ndpi_is_valid_char_tbl[256],ndpi_is_valid_char_tbl_init=0;

static void _ndpi_is_valid_char_init(void) {
  int c;
  for(c=0; c < 256; c++) ndpi_is_valid_char_tbl[c] = _ndpi_is_valid_char(c);
  ndpi_is_valid_char_tbl_init = 1;
}
static inline int ndpi_is_valid_char(char c) {
	if(!ndpi_is_valid_char_tbl_init)
		_ndpi_is_valid_char_init();
	return ndpi_is_valid_char_tbl[(unsigned char)c];
}

/* ******************************************************************** */

static int ndpi_find_non_eng_bigrams(char *str) {
  char s[3];

  if((ndpi_isdigit(str[0]) && ndpi_isdigit(str[1]))
     || ndpi_is_other_char(str[0])
     || ndpi_is_other_char(str[1])
     )
    return(1);

  s[0] = tolower(str[0]), s[1] = tolower(str[1]), s[2] = '\0';

  return(ndpi_match_bigram(s));
}

/* ******************************************************************** */

/* #define PRINT_STRINGS 1 */

int ndpi_has_human_readable_string(char *buffer, u_int buffer_size,
				    u_int8_t min_string_match_len,
				    char *outbuf, u_int outbuf_len) {
  u_int ret = 0, i, do_cr = 0, len = 0, o_idx = 0, being_o_idx = 0;

  if(buffer_size <= 0)
    return(0);

  outbuf_len--;
  outbuf[outbuf_len] = '\0';

  for(i=0; i<buffer_size-2; i++) {
    if(ndpi_is_valid_char(buffer[i])
       && ndpi_is_valid_char(buffer[i+1])
       && ndpi_find_non_eng_bigrams(&buffer[i])) {
#ifdef PRINT_STRINGS
      printf("%c%c", buffer[i], buffer[i+1]);
#endif
      if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i];
      if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i+1];
      do_cr = 1, i += 1, len += 2;
    } else {
      if(ndpi_is_valid_char(buffer[i]) && do_cr) {
#ifdef PRINT_STRINGS
	printf("%c", buffer[i]);
#endif
	if(o_idx < outbuf_len) outbuf[o_idx++] = buffer[i];
	len += 1;
      }

      // printf("->> %c%c\n", ndpi_isprint(buffer[i]) ? buffer[i] : '.', ndpi_isprint(buffer[i+1]) ? buffer[i+1] : '.');
      if(do_cr) {
	if(len > min_string_match_len)
	  ret = 1;
	else {
	  o_idx = being_o_idx;
	  being_o_idx = o_idx;
	  outbuf[o_idx] = '\0';
	}

#ifdef PRINT_STRINGS
	printf(" [len: %u]%s\n", len, ret ? "<-- HIT" : "");
#endif

	if(ret)
	  break;

	do_cr = 0, len = 0;
      }
    }
  }

#ifdef PRINT_STRINGS
  printf("=======>> Found string: %u\n", ret);
#endif

  return(ret);
}

/* ********************************** */

static const char* ndpi_get_flow_info_by_proto_id(struct ndpi_flow_struct const * const flow,
                                                  u_int16_t proto_id) {
  switch (proto_id) {
    case NDPI_PROTOCOL_WHOIS_DAS:
    case NDPI_PROTOCOL_MAIL_SMTP:
    case NDPI_PROTOCOL_NETBIOS:
    case NDPI_PROTOCOL_SSDP:
    case NDPI_PROTOCOL_MDNS:
    case NDPI_PROTOCOL_STUN:
    case NDPI_PROTOCOL_DNS:
    case NDPI_PROTOCOL_DHCP:
    case NDPI_PROTOCOL_XIAOMI:
    case NDPI_PROTOCOL_SD_RTN:
    case NDPI_PROTOCOL_COLLECTD:
    case NDPI_PROTOCOL_HTTP:
    case NDPI_PROTOCOL_HTTP_CONNECT:
    case NDPI_PROTOCOL_HTTP_PROXY:
      return flow->host_server_name;

    case NDPI_PROTOCOL_QUIC:
    case NDPI_PROTOCOL_TLS:
      if(flow->protos.tls_quic.client_hello_processed != 0)
        return flow->host_server_name;
      break;
  }

  return NULL;
}

/* ********************************** */

const char* ndpi_get_flow_info(struct ndpi_flow_struct const * const flow,
                               ndpi_protocol const * const l7_protocol) {
  char const * const app_protocol_info = ndpi_get_flow_info_by_proto_id(flow, l7_protocol->proto.app_protocol);

  if(app_protocol_info != NULL)
    return app_protocol_info;

  return ndpi_get_flow_info_by_proto_id(flow, l7_protocol->proto.master_protocol);
}

/* ********************************** */

char *ndpi_multimedia_flowtype2str(char *buf, int buf_len, u_int8_t m_types)
{
  int rc, len = 0;

  if(buf == NULL || buf_len <= 1)
    return NULL;

  buf[0] = '\0';

  if(m_types == ndpi_multimedia_unknown_flow) {
    rc = ndpi_snprintf(buf + len, buf_len - len, "Unknown", len > 0 ? ", " : "");
    if(rc > 0 && len + rc < buf_len) len += rc; else return NULL;
  }

  if(m_types & ndpi_multimedia_audio_flow) {
    rc = ndpi_snprintf(buf + len, buf_len - len, "%sAudio", len > 0 ? ", " : "");
    if(rc > 0 && len + rc < buf_len) len += rc; else return NULL;
  }
  if(m_types & ndpi_multimedia_video_flow) {
    rc = ndpi_snprintf(buf + len, buf_len - len, "%sVideo", len > 0 ? ", " : "");
    if(rc > 0 && len + rc < buf_len) len += rc; else return NULL;
  }
  if(m_types & ndpi_multimedia_screen_sharing_flow) {
    rc = ndpi_snprintf(buf + len, buf_len - len, "%sScreen Sharing", len > 0 ? ", " : "");
    if(rc > 0 && len + rc < buf_len) len += rc; else return NULL;
  }

  return buf;
}

/* ********************************** */

char* ndpi_ssl_version2str(char *buf, int buf_len,
                           u_int16_t version, u_int8_t *unknown_tls_version) {
  if(unknown_tls_version)
    *unknown_tls_version = 0;

  if(buf == NULL || buf_len <= 1)
    return NULL;

  switch(version) {
  case 0x0300: strncpy(buf, "SSLv3", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0x0301: strncpy(buf, "TLSv1", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0x0302: strncpy(buf, "TLSv1.1", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0x0303: strncpy(buf, "TLSv1.2", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0x0304: strncpy(buf, "TLSv1.3", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0XFB1A: strncpy(buf, "TLSv1.3 (Fizz)", buf_len); buf[buf_len - 1] = '\0'; return buf; /* https://engineering.fb.com/security/fizz/ */
  case 0XFEFF: strncpy(buf, "DTLSv1.0", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0XFEFD: strncpy(buf, "DTLSv1.2", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0XFEFC: strncpy(buf, "DTLSv1.3", buf_len); buf[buf_len - 1] = '\0'; return buf;
  case 0x0A0A:
  case 0x1A1A:
  case 0x2A2A:
  case 0x3A3A:
  case 0x4A4A:
  case 0x5A5A:
  case 0x6A6A:
  case 0x7A7A:
  case 0x8A8A:
  case 0x9A9A:
  case 0xAAAA:
  case 0xBABA:
  case 0xCACA:
  case 0xDADA:
  case 0xEAEA:
  case 0xFAFA: strncpy(buf, "GREASE", buf_len);  buf[buf_len - 1] = '\0'; return buf;
  }

  if((version >= 0x7f00) && (version <= 0x7fff)) {
    strncpy(buf, "TLSv1.3 (draft)", buf_len);
    buf[buf_len - 1] = '\0';
    return buf;
  }

  if(unknown_tls_version)
    *unknown_tls_version = 1;

  ndpi_snprintf(buf, buf_len, "TLS (%04X)", version);

  return buf;
}

/* ***************************************************** */

void ndpi_patchIPv6Address(char *str) {
  int i = 0, j = 0;

  if (strstr(str, "::"))
   return;

  while(str[i] != '\0') {
    if((str[i] == ':')
       && (str[i+1] == '0')
       && (str[i+2] == ':')) {
      str[j++] = ':';
      str[j++] = ':';
      i += 3;
    } else
      str[j++] = str[i++];
  }

  if(str[j] != '\0') str[j] = '\0';
}

/* ********************************** */

void ndpi_user_pwd_payload_copy(u_int8_t *dest, u_int dest_len,
				u_int offset,
				const u_int8_t *src, u_int src_len) {
  u_int i, j=0, k = dest_len-1;

  for(i=offset; (i<src_len) && (j<=k); i++) {
    if((j == k) || (src[i] < ' '))
      break;

    dest[j++] = src[i];
  }

  dest[j <=k ? j : k] = '\0';
}

/* ********************************** */
/* ********************************** */

/* http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c */

static const unsigned char base64_table[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable (NULL character at the end is ignored)
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 * The returned buffer is always NULL terminated
 */
u_char* ndpi_base64_decode(const u_char *src, size_t len, size_t *out_len) {
  u_char dtable[256], *out, *pos, block[4], tmp;
  size_t i, count, olen;
  int pad = 0;

  memset(dtable, 0x80, 256);
  for(i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (u_char) i;
  dtable['='] = 0;

  count = 0;
  for(i = 0; i < len; i++) {
    if(dtable[src[i]] != 0x80)
      count++;
  }

  if(count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3 + 1; /* out is always NULL terminated */
  pos = out = ndpi_calloc(1, olen);
  if(out == NULL)
    return NULL;

  count = 0;
  for(i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if(tmp == 0x80)
      continue;

    if(src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if(count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if(pad) {
	if(pad == 1)
	  pos--;
	else if(pad == 2)
	  pos -= 2;
	else {
	  /* Invalid padding */
	  ndpi_free(out);
	  return NULL;
	}
	break;
      }
    }
  }

  *out_len = pos - out;

  return out;
}

/* ********************************** */

/* NOTE: caller MUST free returned pointer */
char* ndpi_base64_encode(unsigned char const* bytes_to_encode, size_t in_len) {
  size_t len = 0, ret_size;
  char *ret;
  int j, i = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  ret_size = ((in_len+2)/3)*4;

  if((ret = (char*)ndpi_malloc(ret_size+1)) == NULL)
    return NULL;

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if(i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; i < 4; i++)
        ret[len++] = base64_table[char_array_4[i]];
      i = 0;
    }
  }

  if(i) {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for(j = 0; (j < i + 1); j++)
      ret[len++] = base64_table[char_array_4[j]];

    while((i++ < 3))
      ret[len++] = '=';
  }

  ret[len++] = '\0';

  return ret;
}

/* ********************************** */

/* NOTE: caller MUST free returned pointer */
u_char* ndpi_hex_encode(unsigned char const* bytes_to_encode, size_t in_len) {
  size_t double_len = in_len * 2;
  u_char *ret = (u_char*)ndpi_malloc(double_len+1);

  if(ret != NULL) {
    u_int i, ret_idx = 0;

    for(i=0; i<in_len; i++) {
      sprintf((char*)&ret[ret_idx], "%02x", bytes_to_encode[i]);
      ret_idx += 2;
    }

    ret[ret_idx] = '\0';
  }

  return(ret);
}

/* ********************************** */

static int ndpi_hex2nibble(u_char c) {
  if(c >= '0' && c <= '9')
    return(c - '0');
  if(c >= 'a' && c <= 'f')
    return(10 + (c - 'a'));
  if(c >= 'A' && c <= 'F')
    return(10 + (c - 'A'));

  return(-1);
}

/* ********************************** */

u_char* ndpi_hex_decode(const u_char *src, size_t len, size_t *out_len) {
  size_t i, decoded_len;
  u_char *ret;

  if(out_len == NULL)
    return(NULL);

  *out_len = 0;

  if((src == NULL) && (len != 0))
    return(NULL);

  if((len & 0x1) != 0)
    return(NULL);

  decoded_len = len / 2;
  ret = (u_char*)ndpi_malloc(decoded_len + 1);

  if(ret != NULL) {
    for(i = 0; i < decoded_len; i++) {
      int hi = ndpi_hex2nibble(src[2 * i]);
      int lo = ndpi_hex2nibble(src[(2 * i) + 1]);

      if((hi < 0) || (lo < 0)) {
        ndpi_free(ret);
        return(NULL);
      }

      ret[i] = (u_char)((hi << 4) | lo);
    }

    ret[decoded_len] = '\0';
    *out_len = decoded_len;
  }

  return(ret);
}

/* ********************************** */

void ndpi_serialize_risk(ndpi_serializer *serializer,
                         ndpi_risk risk) {
  u_int32_t i;

  if(risk == 0) {
    return;
  }

  ndpi_serialize_start_of_block(serializer, "flow_risk");
  for(i = 0; i < NDPI_MAX_RISK; i++) {
    ndpi_risk_enum r = (ndpi_risk_enum)i;

    if(NDPI_ISSET_BIT(risk, r)) {
      ndpi_risk_info const * const risk_info = ndpi_risk2severity(r);
      if(risk_info == NULL)
        continue;

      ndpi_serialize_start_of_block_uint32(serializer, i);
      ndpi_serialize_string_string(serializer, "risk", ndpi_risk2str(risk_info->risk));
      ndpi_serialize_string_string(serializer, "severity", ndpi_severity2str(risk_info->severity));
      ndpi_serialize_risk_score(serializer, r);
      ndpi_serialize_end_of_block(serializer);
    }
  }

  ndpi_serialize_end_of_block(serializer);
}

/* ********************************** */

void ndpi_serialize_risk_score(ndpi_serializer *serializer,
                               ndpi_risk_enum risk) {
  u_int16_t rs, rs_client = 0, rs_server = 0;

  if(risk == NDPI_NO_RISK) {
    return;
  }

  ndpi_serialize_start_of_block(serializer, "risk_score");
  rs = ndpi_risk2score(risk, &rs_client, &rs_server);
  ndpi_serialize_string_uint32(serializer, "total", rs);
  ndpi_serialize_string_uint32(serializer, "client", rs_client);
  ndpi_serialize_string_uint32(serializer, "server", rs_server);
  ndpi_serialize_end_of_block(serializer);
}

/* ********************************** */

void ndpi_serialize_confidence(ndpi_serializer *serializer,
                               ndpi_confidence_t confidence)
{
  if(confidence == NDPI_CONFIDENCE_UNKNOWN) {
    return;
  }

  ndpi_serialize_start_of_block(serializer, "confidence");
  ndpi_serialize_uint32_string(serializer, (u_int32_t)confidence, ndpi_confidence_get_name(confidence));
  ndpi_serialize_end_of_block(serializer);
}

/* ********************************** */

void ndpi_serialize_proto(struct ndpi_detection_module_struct *ndpi_struct,
                          ndpi_serializer *serializer,
                          ndpi_risk risk,
                          ndpi_confidence_t confidence,
                          ndpi_protocol l7_protocol)
{
  char buf[64];

  ndpi_serialize_risk(serializer, risk);
  ndpi_serialize_confidence(serializer, confidence);
  ndpi_serialize_string_string(serializer, "proto", ndpi_protocol2name(ndpi_struct, l7_protocol.proto, buf, sizeof(buf)));
  ndpi_serialize_string_string(serializer, "proto_id", ndpi_protocol2id(l7_protocol.proto, buf, sizeof(buf)));
  ndpi_serialize_string_string(serializer, "proto_by_ip", ndpi_get_proto_name(ndpi_struct,
                                                                              l7_protocol.protocol_by_ip));
  if(l7_protocol.protocol_by_ip) ndpi_serialize_string_uint32(serializer, "proto_by_ip_id", l7_protocol.protocol_by_ip);
  ndpi_serialize_string_uint32(serializer, "encrypted", ndpi_is_encrypted_proto(ndpi_struct, l7_protocol.proto));
  ndpi_serialize_string_string(serializer, "breed", ndpi_get_proto_breed_name(l7_protocol.breed));
  ndpi_serialize_string_uint32(serializer, "category_id", l7_protocol.category);
  ndpi_serialize_string_string(serializer, "category", ndpi_category_get_name(ndpi_struct, l7_protocol.category));
}

/* ********************************** */

void ndpi_serialize_tls_blocks(struct ndpi_detection_module_struct *ndpi_struct,
			       ndpi_serializer *serializer,
			       struct ndpi_flow_struct *flow) {
  bool is_tls_proto = (ndpi_get_master_proto(ndpi_struct, flow) == NDPI_PROTOCOL_TLS) ? true : false;

  if(is_tls_proto
     && (ndpi_struct->cfg.tls_max_num_blocks_to_analyze > 0)
     && (flow->l4.tcp.tls.tls_blocks != NULL)
     && (flow->l4.tcp.tls.num_tls_blocks > 0)) {
    u_int16_t i, idx = 0;
    int ret;
    char buf[256];

    ndpi_serialize_start_of_list(serializer, "tls_blocks");

    for(i=0; i< flow->l4.tcp.tls.num_tls_blocks; i++) {
      if(!flow->l4.tcp.tls.tls_blocks[i].same_pkt) {
	if(idx > 0) {
	  ndpi_serialize_string_string(serializer, "", buf);
	  idx = 0;
	}
      }

      if(ndpi_struct->cfg.tls_blocks_show_timing)
	ret = snprintf(&buf[idx], sizeof(buf)-idx-1, "%s%s=%d@%u",
		       (idx > 0) ? "," : "",
		       ndpi_print_encoded_tls_block_type(flow->l4.tcp.tls.tls_blocks[i].block_type, true),
		       flow->l4.tcp.tls.tls_blocks[i].len,
		       flow->l4.tcp.tls.tls_blocks[i].msec_delta);
      else
	ret = snprintf(&buf[idx], sizeof(buf)-idx-1, "%s%s=%d",
		       (idx > 0) ? "," : "",
		       ndpi_print_encoded_tls_block_type(flow->l4.tcp.tls.tls_blocks[i].block_type, true),
		       flow->l4.tcp.tls.tls_blocks[i].len);

      if(ret > 0) idx += ret; else break;
    } /* for */

    if(idx > 0)
      ndpi_serialize_string_string(serializer, "", buf);

    ndpi_serialize_end_of_list(serializer);
  }

#ifdef TLS_HANDLE_SIGNATURE_ALGORITMS
  ndpi_serialize_string_uint32(serializer, "sig_algs", flow->protos.tls_quic.num_tls_signature_algorithms);
#endif

  if(flow->protos.tls_quic.ja_client != NULL) {
    ndpi_tls_client_info *c = flow->protos.tls_quic.ja_client;
    u_int16_t i;
    char unknown_cipher[8];

    ndpi_serialize_start_of_block(serializer, "client_data");

    if(c->num_ciphers > 0) {
      ndpi_serialize_start_of_list(serializer, "ciphers");

      for(i=0; i<c->num_ciphers; i++)
	ndpi_serialize_string_string(serializer, "", ndpi_cipher2str(c->cipher[i], unknown_cipher));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_tls_extensions > 0) {
      char unknown_extn[8];

      ndpi_serialize_start_of_list(serializer, "tls_extensions");

      for(i=0; i<c->num_tls_extensions; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_extension2str(c->tls_extension[i], unknown_extn));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_elliptic_curve_groups > 0) {
      char unknown_group[8];

      ndpi_serialize_start_of_list(serializer, "elliptic_curve_groups");

      for(i=0; i<c->num_elliptic_curve_groups; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_elliptic_curve_groups2str(c->elliptic_curve_group[i], unknown_group));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_elliptic_curve_point_format > 0) {
      char unknown_curve[8];

      ndpi_serialize_start_of_list(serializer, "elliptic_curve_point_format");

      for(i=0; i<c->num_elliptic_curve_point_format; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_elliptic_curve2str(c->elliptic_curve_point_format[i], unknown_curve));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_signature_algorithms > 0) {
      char unknown_algo[8];

      ndpi_serialize_start_of_list(serializer, "signature_algorithms");

      for(i=0; i<c->num_signature_algorithms; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_signature_algo2str(c->signature_algorithm[i], unknown_algo));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_key_share_groups > 0) {
      char unknown_group[8];

      ndpi_serialize_start_of_list(serializer, "key_share_groups");

      for(i=0; i<c->num_key_share_groups; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_key_share_group2str(c->key_share_group[i], unknown_group));

      ndpi_serialize_end_of_list(serializer);
    }

    if(c->num_supported_versions > 0) {
      char unknown_version[8];

      ndpi_serialize_start_of_list(serializer, "supported_versions");

      for(i=0; i<c->num_supported_versions; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_supported_version2str(c->supported_version[i], unknown_version));

      ndpi_serialize_end_of_list(serializer);
    }

    ndpi_serialize_end_of_block(serializer);
  }

  if(flow->protos.tls_quic.ja_server != NULL) {
    ndpi_tls_server_info *s = flow->protos.tls_quic.ja_server;
    u_int16_t i;
    char unknown_cipher[8];

    ndpi_serialize_start_of_block(serializer, "server_data");

    if(s->num_ciphers > 0) {
      ndpi_serialize_start_of_list(serializer, "ciphers");

      for(i=0; i<s->num_ciphers; i++)
	ndpi_serialize_string_string(serializer, "", ndpi_cipher2str(s->cipher[i], unknown_cipher));

      ndpi_serialize_end_of_list(serializer);
    }

    if(s->num_tls_extensions > 0) {
      char unknown_extn[8];

      ndpi_serialize_start_of_list(serializer, "tls_extensions");

      for(i=0; i<s->num_tls_extensions; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_extension2str(s->tls_extension[i], unknown_extn));

      ndpi_serialize_end_of_list(serializer);
    }

    if(s->num_elliptic_curve_point_format > 0) {
      char unknown_curve[8];

      ndpi_serialize_start_of_list(serializer, "elliptic_curve_point_format");

      for(i=0; i<s->num_elliptic_curve_point_format; i++)
	ndpi_serialize_string_string(serializer, "",
				     ndpi_tls_elliptic_curve2str(s->elliptic_curve_point_format[i], unknown_curve));

      ndpi_serialize_end_of_list(serializer);
    }

    ndpi_serialize_end_of_block(serializer);
  }
}

/* ********************************** */

static void ndpi_tls2json(struct ndpi_detection_module_struct *ndpi_struct, ndpi_serializer *serializer,
			  struct ndpi_flow_struct *flow) {
  if(flow->protos.tls_quic.ssl_version) {
    char buf[64];
    char notBefore[32], notAfter[32];
    struct tm a, b, *before = NULL, *after = NULL;
    u_int i, off;
    u_int8_t unknown_tls_version;
    char version[16], unknown_cipher[8];

    ndpi_ssl_version2str(version, sizeof(version), flow->protos.tls_quic.ssl_version, &unknown_tls_version);

    if(flow->protos.tls_quic.notBefore)
      before = ndpi_gmtime_r((const time_t *)&flow->protos.tls_quic.notBefore, &a);

    if(flow->protos.tls_quic.notAfter)
      after = ndpi_gmtime_r((const time_t *)&flow->protos.tls_quic.notAfter, &b);

    if(!unknown_tls_version) {
      ndpi_serialize_start_of_block(serializer, "tls");
      ndpi_serialize_string_string(serializer, "version", version);

      if(flow->protos.tls_quic.server_names) {
        ndpi_serialize_string_string(serializer, "server_names",
                                     flow->protos.tls_quic.server_names);
      }

      if(before) {
        strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
        ndpi_serialize_string_string(serializer, "notbefore", notBefore);
      }

      if(after) {
        strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
        ndpi_serialize_string_string(serializer, "notafter", notAfter);
      }

      ndpi_serialize_string_string(serializer, "ja3s", flow->protos.tls_quic.ja3_server);
      ndpi_serialize_string_string(serializer, "ja4", flow->protos.tls_quic.ja4_client);
      ndpi_serialize_string_uint32(serializer, "unsafe_cipher", flow->protos.tls_quic.server_unsafe_cipher);
      if(flow->protos.tls_quic.server_cipher != TLS_NULL_WITH_NULL_NULL)
        ndpi_serialize_string_string(serializer, "cipher",
                                     ndpi_cipher2str(flow->protos.tls_quic.server_cipher, unknown_cipher));

      if(flow->protos.tls_quic.issuerDN)
        ndpi_serialize_string_string(serializer, "issuerDN", flow->protos.tls_quic.issuerDN);

      if(flow->protos.tls_quic.subjectDN)
        ndpi_serialize_string_string(serializer, "subjectDN", flow->protos.tls_quic.subjectDN);

      if(flow->protos.tls_quic.advertised_alpns)
        ndpi_serialize_string_string(serializer, "advertised_alpns", flow->protos.tls_quic.advertised_alpns);

      if(flow->protos.tls_quic.negotiated_alpn)
        ndpi_serialize_string_string(serializer, "negotiated_alpn", flow->protos.tls_quic.negotiated_alpn);

      if(flow->protos.tls_quic.tls_supported_versions)
        ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic.tls_supported_versions);

      if(flow->protos.tls_quic.sha1_certificate_fingerprint[0] != '\0') {
        for(i=0, off=0; i<20; i++) {
          int rc = ndpi_snprintf(&buf[off], sizeof(buf)-off-1,"%s%02X", (i > 0) ? ":" : "",
				 flow->protos.tls_quic.sha1_certificate_fingerprint[i] & 0xFF);

          if(rc <= 0) break; else off += rc;
        }

        ndpi_serialize_string_string(serializer, "fingerprint", buf);
      }

      ndpi_serialize_tls_blocks(ndpi_struct, serializer, flow);

      ndpi_serialize_end_of_block(serializer);
    }
  }
}

/* ********************************** */

char* print_ndpi_address_port(ndpi_address_port *ap, char *buf, u_int buf_len) {
  char ipbuf[INET6_ADDRSTRLEN];

  if(ap->is_ipv6) {
    inet_ntop(AF_INET6, &ap->address, ipbuf, sizeof(ipbuf));
  } else {
    inet_ntop(AF_INET, &ap->address, ipbuf, sizeof(ipbuf));
  }

  snprintf(buf, buf_len, "%s:%u", ipbuf, ap->port);

  return(buf);
}

/* ********************************** */

void ndpi_ssh_serialize_csv(ndpi_serializer *serializer,
			    const char *csv_string,
			    const char* label) {
  u_int offset=0;

  if(!csv_string) return;

  ndpi_serialize_start_of_list(serializer, label);

  while(csv_string[offset] != '\0') {
    u_int len = 0, new_offset = offset;
    /*
      ext-info-c is a special keyword used in the Secure Shell (SSH)
      protocol's initial key exchange (KEXINIT) to signal that the
      client supports the SSH Extension Negotiation mechanism (RFC 8308),
      allowing it to send additional information (like
      supported algorithms) to the server via SSH_MSG_EXT_INFO
      messages after the KEX starts.
    */
    const char *toskip = "ext-info-";

    while((csv_string[new_offset] != ',')
	  && (csv_string[new_offset] != '\0'))
      new_offset++, len++;

    if(ndpi_strnstr(&csv_string[offset], toskip, len) == NULL)
      ndpi_serialize_string_string_len(serializer, "",
				       &csv_string[offset], len);

    offset += len;

    if(csv_string[offset] == ',')
      offset++;
    else
      break;
  }

  ndpi_serialize_end_of_list(serializer);
}

/* ********************************** */

/* NOTE: serializer must have been already initialized */
int ndpi_dpi2json(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow,
		  ndpi_protocol l7_protocol,
		  ndpi_serializer *serializer) {
  char buf[64];
  char const *host_server_name;
  char quic_version[16];
  char content[64] = {0};
  u_int i;

  if(flow == NULL) return(-1);

  ndpi_serialize_start_of_block(serializer, "ndpi");
  ndpi_serialize_proto(ndpi_struct, serializer, flow->risk, flow->confidence, l7_protocol);

  host_server_name = ndpi_get_flow_info(flow, &l7_protocol);

  if (host_server_name != NULL) {
    ndpi_serialize_string_string(serializer, "hostname", host_server_name);
    ndpi_serialize_string_string(serializer, "domainame", ndpi_get_host_domain(ndpi_struct, host_server_name));
  }

  if(flow->flow_multimedia_types != ndpi_multimedia_unknown_flow) {
    ndpi_serialize_string_string(serializer, "stream_content", ndpi_multimedia_flowtype2str(content, sizeof(content), flow->flow_multimedia_types));
  }

  switch(l7_protocol.proto.master_protocol ? l7_protocol.proto.master_protocol : l7_protocol.proto.app_protocol) {
  case NDPI_PROTOCOL_IP_ICMP:
    if(flow->entropy > 0.0f) {
      ndpi_serialize_string_float(serializer, "entropy", flow->entropy, "%.6f");
    }
    break;

  case NDPI_PROTOCOL_DHCP:
    ndpi_serialize_start_of_block(serializer, "dhcp");
    ndpi_serialize_string_string(serializer, "fingerprint", flow->protos.dhcp.fingerprint);
    ndpi_serialize_string_string(serializer, "class_ident", flow->protos.dhcp.class_ident);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_BITTORRENT:
    {
      u_int i, j, n = 0;
      char bittorent_hash[sizeof(flow->protos.bittorrent.hash)*2+1];

      for(i=0, j = 0; j < sizeof(bittorent_hash)-1; i++) {
	snprintf(&bittorent_hash[j],
		 sizeof(bittorent_hash) - j,
		 "%02x",
		 flow->protos.bittorrent.hash[i]);

	j += 2, n += flow->protos.bittorrent.hash[i];
      }

      if(n == 0) bittorent_hash[0] = '\0';

      ndpi_serialize_start_of_block(serializer, "bittorrent");
      ndpi_serialize_string_string(serializer, "hash", bittorent_hash);
      ndpi_serialize_end_of_block(serializer);
    }
    break;

  case NDPI_PROTOCOL_COLLECTD:
    ndpi_serialize_start_of_block(serializer, "collectd");
    ndpi_serialize_string_string(serializer, "client_username", flow->protos.collectd.client_username);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_DNS:
    ndpi_serialize_start_of_block(serializer, "dns");
    ndpi_serialize_string_uint32(serializer, "num_queries", flow->protos.dns.num_queries);
    ndpi_serialize_string_uint32(serializer, "num_answers", flow->protos.dns.num_answers);
    ndpi_serialize_string_uint32(serializer, "reply_code",  flow->protos.dns.reply_code);
    ndpi_serialize_string_uint32(serializer, "query_type",  flow->protos.dns.query_type);
    ndpi_serialize_string_uint32(serializer, "rsp_type",    flow->protos.dns.rsp_type);

    ndpi_serialize_start_of_list(serializer, "rsp_addr");

    for(i=0; i<flow->protos.dns.num_rsp_addr; i++) {
      char buf[64];
      u_int len;

      if(flow->protos.dns.is_rsp_addr_ipv6[i] == 0) {
	inet_ntop(AF_INET, &flow->protos.dns.rsp_addr[i].ipv4, buf, sizeof(buf));
      } else {
	inet_ntop(AF_INET6, &flow->protos.dns.rsp_addr[i].ipv6, buf, sizeof(buf));
      }

      len = strlen(buf);
      snprintf(&buf[len], sizeof(buf)-len, ",ttl=%u", flow->protos.dns.rsp_addr_ttl[i]);
      ndpi_serialize_string_string(serializer, "addr", buf);
    }

    ndpi_serialize_end_of_list(serializer);

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_NTP:
    ndpi_serialize_start_of_block(serializer, "ntp");
    for (i = 0; i < 2; i++) {
      ndpi_serialize_start_of_block_uint32(serializer,i);
      ndpi_serialize_string_uint32(serializer, "leap_indicator", flow->protos.ntp[i].leap_indicator);
      ndpi_serialize_string_uint32(serializer, "version", flow->protos.ntp[i].version);
      ndpi_serialize_string_uint32(serializer, "mode", flow->protos.ntp[i].mode);
      ndpi_serialize_string_uint32(serializer, "stratum", flow->protos.ntp[i].stratum);
      ndpi_serialize_string_int32(serializer, "ppol", flow->protos.ntp[i].ppol);
      ndpi_serialize_string_int32(serializer, "precision", flow->protos.ntp[i].precision);
      ndpi_serialize_string_float(serializer, "root_delay", flow->protos.ntp[i].root_delay, "%f");
      ndpi_serialize_string_float(serializer, "root_dispersion", flow->protos.ntp[i].root_dispersion, "%f");
      ndpi_serialize_string_string(serializer, "ref_id", flow->protos.ntp[i].ref_id);


      char timestamp[64];
      ntp_ts_to_string(flow->protos.ntp[i].ref_time, timestamp, sizeof timestamp);
      ndpi_serialize_string_string(serializer, "ref_time", timestamp);
      ntp_ts_to_string(flow->protos.ntp[i].org_time, timestamp, sizeof timestamp);
      ndpi_serialize_string_string(serializer, "org_time", timestamp);
      ntp_ts_to_string(flow->protos.ntp[i].rec_time, timestamp, sizeof timestamp);
      ndpi_serialize_string_string(serializer, "rec_time", timestamp);
      ntp_ts_to_string(flow->protos.ntp[i].trans_time, timestamp, sizeof timestamp);
      ndpi_serialize_string_string(serializer, "trans_time", timestamp);
      ndpi_serialize_end_of_block(serializer);
    }
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MDNS:
    ndpi_serialize_start_of_block(serializer, "mdns");
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_UBNTAC2:
    ndpi_serialize_start_of_block(serializer, "ubntac2");
    ndpi_serialize_string_string(serializer, "version", flow->protos.ubntac2.version);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_KERBEROS:
    ndpi_serialize_start_of_block(serializer, "kerberos");
    ndpi_serialize_string_string(serializer, "hostname", flow->protos.kerberos.hostname);
    ndpi_serialize_string_string(serializer, "domain", flow->protos.kerberos.domain);
    ndpi_serialize_string_string(serializer, "username", flow->protos.kerberos.username);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_SOFTETHER:
    ndpi_serialize_start_of_block(serializer, "softether");
    ndpi_serialize_string_string(serializer, "client_ip", flow->protos.softether.ip);
    ndpi_serialize_string_string(serializer, "client_port", flow->protos.softether.port);
    ndpi_serialize_string_string(serializer, "hostname", flow->protos.softether.hostname);
    ndpi_serialize_string_string(serializer, "fqdn", flow->protos.softether.fqdn);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_NATPMP:
    ndpi_serialize_start_of_block(serializer, "natpmp");
    ndpi_serialize_string_uint32(serializer, "result", flow->protos.natpmp.result_code);
    ndpi_serialize_string_uint32(serializer, "internal_port", flow->protos.natpmp.internal_port);
    ndpi_serialize_string_uint32(serializer, "external_port", flow->protos.natpmp.external_port);
    inet_ntop(AF_INET, &flow->protos.natpmp.external_address.ipv4, buf, sizeof(buf));
    ndpi_serialize_string_string(serializer, "external_address", buf);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_RSH:
    ndpi_serialize_start_of_block(serializer, "rsh");
    ndpi_serialize_string_string(serializer, "client_username", flow->protos.rsh.client_username);
    ndpi_serialize_string_string(serializer, "server_username", flow->protos.rsh.server_username);
    ndpi_serialize_string_string(serializer, "command", flow->protos.rsh.command);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_SNMP:
    ndpi_serialize_start_of_block(serializer, "snmp");
    ndpi_serialize_string_uint32(serializer, "version", flow->protos.snmp.version);
    ndpi_serialize_string_uint32(serializer, "primitive", flow->protos.snmp.primitive);
    ndpi_serialize_string_uint32(serializer, "error_status", flow->protos.snmp.error_status);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_TELNET:
    ndpi_serialize_start_of_block(serializer, "telnet");
    ndpi_serialize_string_string(serializer, "username", flow->protos.telnet.username);
    ndpi_serialize_string_string(serializer, "password", flow->protos.telnet.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_TFTP:
    ndpi_serialize_start_of_block(serializer, "tftp");
    ndpi_serialize_string_string(serializer, "filename", flow->protos.tftp.filename);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_TIVOCONNECT:
    ndpi_serialize_start_of_block(serializer, "tivoconnect");
    ndpi_serialize_string_string(serializer, "identity_uuid", flow->protos.tivoconnect.identity_uuid);
    ndpi_serialize_string_string(serializer, "machine", flow->protos.tivoconnect.machine);
    ndpi_serialize_string_string(serializer, "platform", flow->protos.tivoconnect.platform);
    ndpi_serialize_string_string(serializer, "services", flow->protos.tivoconnect.services);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_HTTP:
  case NDPI_PROTOCOL_HTTP_CONNECT:
  case NDPI_PROTOCOL_HTTP_PROXY:
    ndpi_serialize_start_of_block(serializer, "http");

    if(flow->http.url != NULL) {
      ndpi_serialize_string_string(serializer, "url", flow->http.url);
      ndpi_serialize_string_uint32(serializer, "code", flow->http.response_status_code);
      ndpi_serialize_string_string(serializer, "content_type", flow->http.content_type);
      ndpi_serialize_string_string(serializer, "user_agent", flow->http.user_agent);
    }

    if (flow->http.request_content_type != NULL)
      ndpi_serialize_string_string(serializer, "request_content_type",
                                   flow->http.request_content_type);

    if (flow->http.detected_os != NULL)
      ndpi_serialize_string_string(serializer, "detected_os",
                                   flow->http.detected_os);

    if (flow->http.nat_ip != NULL)
      ndpi_serialize_string_string(serializer, "nat_ip",
                                   flow->http.nat_ip);

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_QUIC:
    ndpi_serialize_start_of_block(serializer, "quic");

    ndpi_quic_version2str(quic_version, sizeof(quic_version),
                          flow->protos.tls_quic.quic_version);
    ndpi_serialize_string_string(serializer, "quic_version", quic_version);

    ndpi_tls2json(ndpi_struct, serializer, flow);

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_IMAP:
    ndpi_serialize_start_of_block(serializer, "imap");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer, "auth_failed",
                                 flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_POP:
    ndpi_serialize_start_of_block(serializer, "pop");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer, "auth_failed",
                                 flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_SMTP:
    ndpi_serialize_start_of_block(serializer, "smtp");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer, "auth_failed",
                                 flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_FTP_CONTROL:
    ndpi_serialize_start_of_block(serializer, "ftp");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer,  "auth_failed", flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MIKROTIK:
    {
      char buf[32];

      ndpi_serialize_start_of_block(serializer, "mikrotik");

      snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
	       flow->protos.mikrotik.mac_addr[0] & 0xFF,
	       flow->protos.mikrotik.mac_addr[1] & 0xFF,
	       flow->protos.mikrotik.mac_addr[2] & 0xFF,
	       flow->protos.mikrotik.mac_addr[3] & 0xFF,
	       flow->protos.mikrotik.mac_addr[4] & 0xFF,
	       flow->protos.mikrotik.mac_addr[5] & 0xFF);

      ndpi_serialize_string_string(serializer, "mac_address", buf);

      if(flow->protos.mikrotik.identity[0] != '\0')
	ndpi_serialize_string_string(serializer, "identity", flow->protos.mikrotik.identity);

      if(flow->protos.mikrotik.version[0] != '\0')
	ndpi_serialize_string_string(serializer, "version", flow->protos.mikrotik.version);

      if(flow->protos.mikrotik.sw_id[0] != '\0')
	ndpi_serialize_string_string(serializer, "software_id", flow->protos.mikrotik.sw_id);

      if(flow->protos.mikrotik.board[0] != '\0')
	ndpi_serialize_string_string(serializer, "board", flow->protos.mikrotik.board);

      if(flow->protos.mikrotik.iface_name[0] != '\0')
	ndpi_serialize_string_string(serializer, "iface_name", flow->protos.mikrotik.iface_name);

      if(flow->protos.mikrotik.ipv4_addr != 0)
	ndpi_serialize_string_string(serializer, "ipv4_addr",
				     ndpi_intoav4(flow->protos.mikrotik.ipv4_addr, buf, sizeof(buf)));

      if(flow->protos.mikrotik.ipv6_addr.u6_addr.u6_addr64[0] != 0)
	ndpi_serialize_string_string(serializer, "ipv6_addr",
				     ndpi_intoav6(&flow->protos.mikrotik.ipv6_addr, buf, sizeof(buf)));

      if(flow->protos.mikrotik.uptime != 0)
	ndpi_serialize_string_uint32(serializer, "uptime", flow->protos.mikrotik.uptime);

      ndpi_serialize_end_of_block(serializer);
    }
    break;

  case NDPI_PROTOCOL_SSDP:
    ndpi_serialize_start_of_block(serializer, "ssdp");

    if (flow->protos.ssdp.method) {
      ndpi_serialize_string_string(serializer, "METHOD", flow->protos.ssdp.method);
    }

    if (flow->protos.ssdp.cache_controle) {
      ndpi_serialize_string_string(serializer, "CACHE-CONTROL", flow->protos.ssdp.cache_controle);
    }

    if (flow->protos.ssdp.location) {
      ndpi_serialize_string_string(serializer, "LOCATION", flow->protos.ssdp.location);
    }

    if (flow->protos.ssdp.nt) {
      ndpi_serialize_string_string(serializer, "NT", flow->protos.ssdp.nt);
    }

    if (flow->protos.ssdp.nts) {
      ndpi_serialize_string_string(serializer, "NTS", flow->protos.ssdp.nts);
    }

    if (flow->protos.ssdp.server) {
      ndpi_serialize_string_string(serializer, "SERVER", flow->protos.ssdp.server);
    }

    if (flow->protos.ssdp.usn) {
      ndpi_serialize_string_string(serializer, "USN", flow->protos.ssdp.usn);
    }

    if (flow->protos.ssdp.securelocation_upnp) {
      ndpi_serialize_string_string(serializer, "SECURELOCATION.UPNP.ORG", flow->protos.ssdp.securelocation_upnp);
    }

    if (flow->protos.ssdp.man) {
      ndpi_serialize_string_string(serializer, "MAN", flow->protos.ssdp.man);
    }

    if (flow->protos.ssdp.mx) {
      ndpi_serialize_string_string(serializer, "MX", flow->protos.ssdp.mx);
    }

    if (flow->protos.ssdp.st) {
      ndpi_serialize_string_string(serializer, "ST", flow->protos.ssdp.st);
    }

    if (flow->protos.ssdp.user_agent) {
      ndpi_serialize_string_string(serializer, "USER_AGENT", flow->protos.ssdp.user_agent);
    }

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_DISCORD:
    if (l7_protocol.proto.master_protocol != NDPI_PROTOCOL_TLS) {
      ndpi_serialize_start_of_block(serializer, "discord");
      ndpi_serialize_string_string(serializer, "client_ip", flow->protos.discord.client_ip);
      ndpi_serialize_end_of_block(serializer);
    }
    break;

  case NDPI_PROTOCOL_SSH:
    ndpi_serialize_start_of_block(serializer, "ssh");
    ndpi_serialize_string_string(serializer,  "client_signature", flow->protos.ssh.client_signature);
    ndpi_serialize_string_string(serializer,  "server_signature", flow->protos.ssh.server_signature);

    if(ndpi_struct->cfg.ssh_hassh_fingerprint_enabled) {
      ndpi_serialize_string_string(serializer,  "hassh_client", flow->protos.ssh.hassh_client);
      ndpi_serialize_string_string(serializer,  "hassh_server", flow->protos.ssh.hassh_server);
    }

    if(flow->protos.ssh.key_exchange_method)
      ndpi_serialize_string_string(serializer, "kex_alg",
                                   flow->protos.ssh.key_exchange_method);
    if(flow->protos.ssh.negotiated_hostkey_alg)
      ndpi_serialize_string_string(serializer, "hostkey_alg",
                                   flow->protos.ssh.negotiated_hostkey_alg);
    if(flow->protos.ssh.negotiated_cipher_c2s)
      ndpi_serialize_string_string(serializer, "cipher_c2s",
                                   flow->protos.ssh.negotiated_cipher_c2s);
    if(flow->protos.ssh.negotiated_cipher_s2c)
      ndpi_serialize_string_string(serializer, "cipher_s2c",
                                   flow->protos.ssh.negotiated_cipher_s2c);
    if(flow->protos.ssh.negotiated_mac_c2s)
      ndpi_serialize_string_string(serializer, "mac_c2s",
                                   flow->protos.ssh.negotiated_mac_c2s);
    if(flow->protos.ssh.negotiated_mac_s2c)
      ndpi_serialize_string_string(serializer, "mac_s2c",
                                   flow->protos.ssh.negotiated_mac_s2c);

    if(ndpi_struct->cfg.ssh_hassh_data_enabled) {
      ndpi_serialize_start_of_block(serializer, "key_exchange_algorithms");

      if(flow->protos.ssh.client_key_exchange_algorithms)
	ndpi_ssh_serialize_csv(serializer, flow->protos.ssh.client_key_exchange_algorithms, "client");

      if(flow->protos.ssh.server_key_exchange_algorithms)
	ndpi_ssh_serialize_csv(serializer, flow->protos.ssh.server_key_exchange_algorithms, "server");

      ndpi_serialize_end_of_block(serializer);
    }

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_STUN:
    ndpi_serialize_start_of_block(serializer, "stun");

    if(flow->stun.mapped_address.port)
      ndpi_serialize_string_string(serializer,  "mapped_address", print_ndpi_address_port(&flow->stun.mapped_address, buf, sizeof(buf)));

    if(flow->stun.peer_address.port)
      ndpi_serialize_string_string(serializer,  "peer_address", print_ndpi_address_port(&flow->stun.peer_address, buf, sizeof(buf)));

    if(flow->stun.relayed_address.port)
      ndpi_serialize_string_string(serializer,  "relayed_address", print_ndpi_address_port(&flow->stun.relayed_address, buf, sizeof(buf)));

    if(flow->stun.response_origin.port)
      ndpi_serialize_string_string(serializer,  "response_origin", print_ndpi_address_port(&flow->stun.response_origin, buf, sizeof(buf)));

    if(flow->stun.other_address.port)
      ndpi_serialize_string_string(serializer,  "other_address", print_ndpi_address_port(&flow->stun.other_address, buf, sizeof(buf)));

    ndpi_serialize_string_string(serializer,  "multimedia_flow_types",
				 ndpi_multimedia_flowtype2str(content, sizeof(content), flow->flow_multimedia_types));

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/ndpi_utils_dpi2json_stun.c"
#endif

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_SIP:
    ndpi_serialize_start_of_block(serializer, "sip");

    if(flow->protos.sip.from)
      ndpi_serialize_string_string(serializer, "from", flow->protos.sip.from);

    if(flow->protos.sip.from_imsi[0] != '\0')
      ndpi_serialize_string_string(serializer, "from_imsi", flow->protos.sip.from_imsi);

    if(flow->protos.sip.to)
      ndpi_serialize_string_string(serializer, "to", flow->protos.sip.to);

    if(flow->protos.sip.to_imsi[0] != '\0')
      ndpi_serialize_string_string(serializer, "to_imsi", flow->protos.sip.to_imsi);

    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_TLS:
    ndpi_tls2json(ndpi_struct, serializer, flow);
    break;

  case NDPI_PROTOCOL_DTLS:
    ndpi_tls2json(ndpi_struct, serializer, flow);
#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/ndpi_utils_dpi2json_dtls.c"
#endif
    break;

  case NDPI_PROTOCOL_IPSEC:
    {
      u_int32_t buffer_len;
      char *buffer, version[8];

      ndpi_serialize_start_of_block(serializer, "ipsec");

      snprintf(version, sizeof(version), "%u.%u",
	       (flow->protos.ipsec.version & 0xF0) >> 4,
	       (flow->protos.ipsec.version & 0x0F));
      ndpi_serialize_string_string(serializer, "ike_version", version);

      if(flow->protos.ipsec.proposal[NDPI_IKEV2_REQUEST_PROPOSAL].proto_id
	 || flow->protos.ipsec.proposal[NDPI_IKEV2_RESPONSE_PROPOSAL].proto_id) {
	u_int8_t i;
	ndpi_serializer sub_serializer;
	
	if(ndpi_init_serializer(&sub_serializer, ndpi_serialization_format_json) == -1)
	  ;
	else {
	  ndpi_serializer *ser;

	  ser = &sub_serializer;

	  for(i=0; i<2; i++) {
	    struct ndpi_ipsec_proposal *p = &flow->protos.ipsec.proposal[i];

	    ndpi_serialize_string_string(ser, "type", (i == NDPI_IKEV2_REQUEST_PROPOSAL) ? "request" : "response");
	    ndpi_serialize_string_uint32(ser, "protocol_id", p->proto_id);
	    ndpi_serialize_string_uint32(ser, "num_transforms", p->num_transforms);
	    ndpi_serialize_string_string(ser, "encryption_algorithm", ndpi_ikev2_encr_name(p->encr_alg));
	    ndpi_serialize_string_uint32(ser, "encryption_key_bits", p->encr_key_bits);
	    ndpi_serialize_string_string(ser, "pseudo_random_algorithm", ndpi_ikev2_prf_name(p->prf_alg));
	    ndpi_serialize_string_string(ser, "integrity_algorithm", ndpi_ikev2_integ_name(p->integ_alg));
	    ndpi_serialize_string_string(ser, "diffie_hellman_group", ndpi_ikev2_dh_name(p->dh_group));
	    ndpi_serialize_string_uint32(ser, "extended_sequence_numbers", p->esn);
	    ndpi_serialize_end_of_record(ser);
	  }

	  buffer = ndpi_serializer_get_buffer(ser, &buffer_len);
	  if(buffer && (buffer_len > 0))
	    ndpi_serialize_string_raw(serializer, "proposals", buffer, buffer_len);

	  ndpi_term_serializer(ser);
	}
      }

      ndpi_serialize_end_of_block(serializer);
    }
    break;

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/ndpi_utils_dpi2json_protos.c"
#endif
  } /* switch */

  if((flow->custom.plugin != NULL)
     && (flow->custom.plugin->jsonExportFctn != NULL))
    flow->custom.plugin->jsonExportFctn(ndpi_struct, flow, serializer);

  ndpi_serialize_end_of_block(serializer); // "ndpi"

  return(0);
}

/* ********************************** */

char *ndpi_get_ip_proto_name(u_int16_t ip_proto, char *name, unsigned int name_len) {
  if(name == NULL || name_len == 0)
    return name;

  switch (ip_proto) {
  case IPPROTO_TCP:
    snprintf(name, name_len, "TCP");
    break;

  case IPPROTO_UDP:
    snprintf(name, name_len, "UDP");
    break;

  case NDPI_IPSEC_PROTOCOL_ESP:
    snprintf(name, name_len, "ESP");
    break;

  case NDPI_IPSEC_PROTOCOL_AH:
    snprintf(name, name_len, "AH");
    break;

  case NDPI_GRE_PROTOCOL_TYPE:
    snprintf(name, name_len, "GRE");
    break;

  case NDPI_ICMP_PROTOCOL_TYPE:
    snprintf(name, name_len, "ICMP");
    break;

  case NDPI_IGMP_PROTOCOL_TYPE:
    snprintf(name, name_len, "IGMP");
    break;

  case NDPI_EGP_PROTOCOL_TYPE:
    snprintf(name, name_len, "EGP");
    break;

  case NDPI_SCTP_PROTOCOL_TYPE:
    snprintf(name, name_len, "SCTP");
    break;

  case NDPI_PGM_PROTOCOL_TYPE:
    snprintf(name, name_len, "PGM");
    break;

  case NDPI_OSPF_PROTOCOL_TYPE:
    snprintf(name, name_len, "OSPF");
    break;

  case NDPI_IPIP_PROTOCOL_TYPE:
    snprintf(name, name_len, "IPIP");
    break;

  case NDPI_ICMPV6_PROTOCOL_TYPE:
    snprintf(name, name_len, "ICMPV6");
    break;

  case NDPI_PIM_PROTOCOL_TYPE:
    snprintf(name, name_len, "PIM");
    break;

  case NDPI_VRRP_PROTOCOL_TYPE:
    snprintf(name, name_len, "VRRP");
    break;

  default:
    snprintf(name, name_len, "%d", ip_proto);
    break;
  }

  name[name_len - 1] = '\0';
  return name;
}

/* ********************************** */

/* NOTE: serializer is initialized by the function */
int ndpi_flow2json(struct ndpi_detection_module_struct *ndpi_struct,
		   struct ndpi_flow_struct *flow,
		   u_int8_t ip_version,
		   u_int8_t l4_protocol,
		   u_int16_t vlan_id,
		   u_int32_t src_v4, u_int32_t dst_v4,
		   struct ndpi_in6_addr *src_v6, struct ndpi_in6_addr *dst_v6,
		   u_int16_t src_port, u_int16_t dst_port,
		   ndpi_protocol l7_protocol,
		   ndpi_serializer *serializer) {
  char src_name[INET6_ADDRSTRLEN] = {'\0'}, dst_name[INET6_ADDRSTRLEN] = {'\0'};
  char l4_proto_name[32];

  if(ip_version == 4) {
    inet_ntop(AF_INET, &src_v4, src_name, sizeof(src_name));
    inet_ntop(AF_INET, &dst_v4, dst_name, sizeof(dst_name));
  } else {
    inet_ntop(AF_INET6, src_v6, src_name, sizeof(src_name));
    inet_ntop(AF_INET6, dst_v6, dst_name, sizeof(dst_name));
    /* For consistency across platforms replace :0: with :: */
    ndpi_patchIPv6Address(src_name), ndpi_patchIPv6Address(dst_name);
  }

  if(vlan_id != 0) ndpi_serialize_string_uint32(serializer, "vlan_id", vlan_id);
  ndpi_serialize_string_string(serializer, "src_ip", src_name);
  ndpi_serialize_string_string(serializer, "dest_ip", dst_name);
  if(src_port) ndpi_serialize_string_uint32(serializer, "src_port", ntohs(src_port));
  if(dst_port) ndpi_serialize_string_uint32(serializer, "dst_port", ntohs(dst_port));

  ndpi_serialize_string_uint32(serializer, "ip", ip_version);

  if(flow->tcp.fingerprint)
    ndpi_serialize_string_string(serializer, "tcp_fingerprint", flow->tcp.fingerprint);

  if(flow->tcp.fingerprint_raw)
    ndpi_serialize_string_string(serializer, "tcp_fingerprint_raw", flow->tcp.fingerprint_raw);

  if(flow->ndpi.client_fingerprint || flow->ndpi.server_fingerprint) {
    ndpi_serialize_start_of_block(serializer, "ndpi_fingerprint");

    if(flow->ndpi.client_fingerprint)
      ndpi_serialize_string_string(serializer, "client", flow->ndpi.client_fingerprint);

    if(flow->ndpi.server_fingerprint)
      ndpi_serialize_string_string(serializer, "server", flow->ndpi.server_fingerprint);

    ndpi_serialize_end_of_block(serializer);
  }

  ndpi_serialize_string_string(serializer, "proto",
			       ndpi_get_ip_proto_name(l4_protocol,
						      l4_proto_name, sizeof(l4_proto_name)));

  return(ndpi_dpi2json(ndpi_struct, flow, l7_protocol, serializer));
}

/* ********************************** */

const char* ndpi_tunnel2str(ndpi_packet_tunnel tt) {
  switch(tt) {
  case ndpi_no_tunnel:
    return("No-Tunnel");

  case ndpi_gtp_tunnel:
    return("GTP");

  case ndpi_capwap_tunnel:
    return("CAPWAP");

  case ndpi_tzsp_tunnel:
    return("TZSP");

  case ndpi_l2tp_tunnel:
    return("L2TP");

  case ndpi_vxlan_tunnel:
    return("VXLAN");

  case ndpi_gre_tunnel:
    return("GRE");
  }

  return("");
}

/* ********************************** */

/*
  /dv/vulnerabilities/xss_r/?name=%3Cscript%3Econsole.log%28%27JUL2D3WXHEGWRAFJE2PI7OS71Z4Z8RFUHXGNFLUFYVP6M3OL55%27%29%3Bconsole.log%28document.cookie%29%3B%3C%2Fscript%3E
  /dv/vulnerabilities/sqli/?id=1%27+and+1%3D1+union+select+null%2C+table_name+from+information_schema.tables%23&Submit=Submit
*/

/* https://www.rosettacode.org/wiki/URL_decoding#C */
static int ishex(int x) {
  return(x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F');
}

/* ********************************** */

static int ndpi_url_decode(const char *s, char *out) {
  char *o;
  const char *end = s + strlen(s);
  int c;

  for(o = out; s <= end; o++) {
    c = *s++;
    if(c == '+') c = ' ';
    else if(c == '%' && (!ishex(*s++)||
			 !ishex(*s++)||
			 (sscanf(s - 2, "%2x", (unsigned int*)&c) != 1)))
      return(-1);

    if(out) *o = c;
  }

  return(o - out);
}

/* ********************************** */

static int ndpi_is_sql_injection(char* query) {
  struct libinjection_sqli_state state;

  size_t qlen = strlen(query);
  libinjection_sqli_init(&state, query, qlen, FLAG_NONE);

  return libinjection_is_sqli(&state);
}

/* ********************************** */

static int ndpi_is_xss_injection(char* query) {
  size_t qlen = strlen(query);
  return libinjection_xss(query, qlen);
}

/* ********************************** */

#ifdef HAVE_PCRE2

static void ndpi_compile_rce_regex() {
  PCRE2_UCHAR pcreErrorStr[128];
  PCRE2_SIZE pcreErrorOffset;
  int i, pcreErrorCode = 0;

  for(i = 0; i < N_RCE_REGEX; i++) {
    comp_rx[i] = (struct pcre2_struct*)ndpi_malloc(sizeof(struct pcre2_struct));

    comp_rx[i]->compiled = pcre2_compile((PCRE2_SPTR)rce_regex[i], PCRE2_ZERO_TERMINATED, 0, &pcreErrorCode,
                                        &pcreErrorOffset, NULL);
    pcre2_get_error_message(pcreErrorCode, pcreErrorStr, 128);
    if(comp_rx[i]->compiled == NULL) {
#ifdef DEBUG
      NDPI_LOG_ERR(ndpi_str, "ERROR: Could not compile '%s': %s\n", rce_regex[i],
                   pcreErrorStr);
#endif

      continue;
    }

    pcreErrorCode = pcre2_jit_compile(comp_rx[i]->compiled, PCRE2_JIT_COMPLETE);

#ifdef DEBUG
    if(pcreErrorCode < 0) {
      pcre2_get_error_message(pcreErrorCode, pcreErrorStr, 128);
      NDPI_LOG_ERR(ndpi_str, "ERROR: Could not jit compile '%s': %s\n", rce_regex[i],
                   pcreErrorStr);
    }
#endif
  }
}

/* ********************************** */

static int ndpi_is_rce_injection(char* query) {
  if(!initialized_comp_rx) {
    ndpi_compile_rce_regex();
    initialized_comp_rx = 1;
  }

  pcre2_match_data *pcreMatchData;
  int i, pcreExecRet;
  unsigned long j;

  for(i = 0; i < N_RCE_REGEX; i++) {
    unsigned int length = strlen(query);

    pcreMatchData = pcre2_match_data_create_from_pattern(comp_rx[i]->compiled, NULL);
    pcreExecRet = pcre2_match(comp_rx[i]->compiled,
                            (PCRE2_SPTR)query, length, 0, 0, pcreMatchData, NULL);
    pcre2_match_data_free(pcreMatchData);
    if(pcreExecRet > 0) {
      return 1;
    }
#ifdef DEBUG
    else {
      switch(pcreExecRet) {
      case PCRE_ERROR_NOMATCH:
	NDPI_LOG_ERR(ndpi_str, "ERROR: String did not match the pattern\n");
	break;
      case PCRE_ERROR_NULL:
	NDPI_LOG_ERR(ndpi_str, "ERROR: Something was null\n");
	break;
      case PCRE_ERROR_BADOPTION:
	NDPI_LOG_ERR(ndpi_str, "ERROR: A bad option was passed\n");
	break;
      case PCRE_ERROR_BADMAGIC:
	NDPI_LOG_ERR(ndpi_str, "ERROR: Magic number bad (compiled re corrupt?)\n");
	break;
      case PCRE_ERROR_UNKNOWN_NODE:
	NDPI_LOG_ERR(ndpi_str, "ERROR: Something kooky in the compiled re\n");
	break;
      case PCRE_ERROR_NOMEMORY:
	NDPI_LOG_ERR(ndpi_str, "ERROR: Ran out of memory\n");
	break;
      default:
	NDPI_LOG_ERR(ndpi_str, "ERROR: Unknown error\n");
	break;
      }
    }
#endif
  }

  size_t ushlen = sizeof(ush_commands) / sizeof(ush_commands[0]);

  for(j = 0; j < ushlen; j++) {
    if(strstr(query, ush_commands[j]) != NULL) {
      return 1;
    }
  }

  size_t pwshlen = sizeof(pwsh_commands) / sizeof(pwsh_commands[0]);

  for(j = 0; j < pwshlen; j++) {
    if(strstr(query, pwsh_commands[j]) != NULL) {
      return 1;
    }
  }

  return 0;
}

#endif

/* ********************************** */

ndpi_risk_enum ndpi_validate_url(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow,
				 char *url) {
  char *orig_str = NULL, *str = NULL, *question_mark = strchr(url, '?');
  ndpi_risk_enum rc = NDPI_NO_RISK;

  if(question_mark) {
    char *tmp;

    orig_str = str = ndpi_strdup(&question_mark[1]); /* Skip ? */

    if(!str) goto validate_rc;

    str = strtok_r(str, "&", &tmp);

    while(str != NULL) {
      char *value = strchr(str, '=');
      char *decoded;

      if(!value)
	break;
      else
	value = &value[1];

      if(value[0] != '\0') {
	if(!(decoded = (char*)ndpi_malloc(strlen(value)+1)))
	  break;

	if(ndpi_url_decode(value, decoded) < 0) {
	  /* Invalid string */
	} else if(decoded[0] != '\0') {
	  /* Valid string */

	  if(ndpi_is_xss_injection(decoded))
	    rc = NDPI_URL_POSSIBLE_XSS;
	  else if(ndpi_is_sql_injection(decoded))
	    rc = NDPI_URL_POSSIBLE_SQL_INJECTION;
#ifdef HAVE_PCRE2
	  else if(ndpi_is_rce_injection(decoded))
	    rc = NDPI_URL_POSSIBLE_RCE_INJECTION;
#endif

#ifdef URL_CHECK_DEBUG
	  printf("=>> [rc: %u] %s\n", rc, decoded);
#endif
	}

	ndpi_free(decoded);

	if(rc != NDPI_NO_RISK) {
	  if(flow != NULL) {
	    char msg[128];

	    snprintf(msg, sizeof(msg), "Suspicious URL [%s]", url);
	    ndpi_set_risk(ndpi_str, flow, rc, msg);
	  }
	  break;
	}
      }

      str = strtok_r(NULL, "&", &tmp);
    }
  }

 validate_rc:
  if(orig_str) ndpi_free(orig_str);

  if(rc == NDPI_NO_RISK) {
    /* Let's do an extra check */
    if(strstr(url, "..")) {
      /* 127.0.0.1/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe */
      rc = NDPI_HTTP_SUSPICIOUS_URL;
    }
  }

  return(rc);
}

/* ******************************************************************** */

u_int8_t ndpi_is_protocol_detected(ndpi_protocol proto) {
  if((proto.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (proto.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (proto.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED))
    return(1);
  else
    return(0);
}

/* ******************************************************************** */

const char* ndpi_risk2str(ndpi_risk_enum risk) {
  static char buf[16];

  switch(risk) {
  case NDPI_URL_POSSIBLE_XSS:
    return("XSS Attack");

  case NDPI_URL_POSSIBLE_SQL_INJECTION:
    return("SQL Injection");

  case NDPI_URL_POSSIBLE_RCE_INJECTION:
    return("RCE Injection");

  case NDPI_BINARY_APPLICATION_TRANSFER:
    return("Binary App Transfer");

  case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
    return("Known Proto on Non Std Port");

  case NDPI_TLS_SELFSIGNED_CERTIFICATE:
    return("Self-signed Cert");

  case NDPI_TLS_OBSOLETE_VERSION:
    return("Obsolete TLS (v1.1 or older)");

  case NDPI_TLS_WEAK_CIPHER:
    return("Weak TLS Cipher");

  case NDPI_TLS_CERTIFICATE_EXPIRED:
    return("TLS Cert Expired");

  case NDPI_TLS_CERTIFICATE_MISMATCH:
    return("TLS Cert Mismatch");

  case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
    return("HTTP Susp User-Agent");

  case NDPI_NUMERIC_IP_HOST:
    return("HTTP/TLS/QUIC Numeric Hostname/SNI");

  case NDPI_HTTP_SUSPICIOUS_URL:
    return("HTTP Susp URL");

  case NDPI_HTTP_SUSPICIOUS_HEADER:
    return("HTTP Susp Header");

  case NDPI_TLS_NOT_CARRYING_HTTPS:
    return("TLS (probably) Not Carrying HTTPS");

  case NDPI_SUSPICIOUS_DGA_DOMAIN:
    return("Susp DGA Domain name");

  case NDPI_MALFORMED_PACKET:
    return("Malformed Packet");

  case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
    return("SSH Obsolete Cli Vers/Cipher");

  case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
    return("SSH Obsolete Ser Vers/Cipher");

  case NDPI_SMB_INSECURE_VERSION:
    return("SMB Insecure Vers");

  case NDPI_MISMATCHING_PROTOCOL_WITH_IP:
    return("Mismatching Protocol with server IP address");

  case NDPI_UNSAFE_PROTOCOL:
    return("Unsafe Protocol");

  case NDPI_DNS_SUSPICIOUS_TRAFFIC:
    return("Susp DNS Traffic"); /* Exfiltration ? */

  case NDPI_TLS_MISSING_SNI:
    return("Missing SNI TLS Extn");

  case NDPI_HTTP_SUSPICIOUS_CONTENT:
    return("HTTP Susp Content");

  case NDPI_RISKY_ASN:
    return("Risky ASN");

  case NDPI_RISKY_DOMAIN:
    return("Risky Domain Name");

  case NDPI_MALICIOUS_FINGERPRINT:
    return("Malicious Fingerprint");

  case NDPI_MALICIOUS_SHA1_CERTIFICATE:
    return("Malicious SSL Cert/SHA1 Fingerp.");

  case NDPI_DESKTOP_OR_FILE_SHARING_SESSION:
    return("Desktop/File Sharing");

  case NDPI_TLS_UNCOMMON_ALPN:
    return("Uncommon TLS ALPN");

  case NDPI_TLS_CERT_VALIDITY_TOO_LONG:
    return("TLS Cert Validity Too Long");

  case NDPI_TLS_SUSPICIOUS_EXTENSION:
    return("TLS Susp Extn");

  case NDPI_TLS_FATAL_ALERT:
    return("TLS Fatal Alert");

  case NDPI_SUSPICIOUS_ENTROPY:
    return("Susp Entropy");

  case NDPI_CLEAR_TEXT_CREDENTIALS:
    return("Clear-Text Credentials");

  case NDPI_DNS_LARGE_PACKET:
    return("Large DNS Packet (512+ bytes)");

  case NDPI_DNS_FRAGMENTED:
    return("Fragmented DNS Message");

  case NDPI_INVALID_CHARACTERS:
    return("Non-Printable/Invalid Chars Detected");

  case NDPI_POSSIBLE_EXPLOIT:
    return("Possible Exploit Attempt");

  case NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE:
    return("TLS Cert About To Expire");

  case NDPI_PUNYCODE_IDN:
    return("IDN Domain Name");

  case NDPI_ERROR_CODE_DETECTED:
    return("Error Code");

  case NDPI_HTTP_CRAWLER_BOT:
    return("Crawler/Bot");

  case NDPI_ANONYMOUS_SUBSCRIBER:
    return("Anonymous Subscriber");

  case NDPI_UNIDIRECTIONAL_TRAFFIC:
    return("Unidirectional Traffic");

  case NDPI_HTTP_OBSOLETE_SERVER:
    return("HTTP Obsolete Server");

  case NDPI_PERIODIC_FLOW:
    return("Periodic Flow");

  case NDPI_MINOR_ISSUES:
    return("Minor Issues");

  case NDPI_TCP_ISSUES:
    return("TCP Connection Issues");

  case NDPI_UNRESOLVED_HOSTNAME:
    return("Unresolved hostname");

  case NDPI_TLS_ALPN_SNI_MISMATCH:
    return("ALPN/SNI Mismatch");

  case NDPI_MALWARE_HOST_CONTACTED:
    return("Client Contacted A Malware Host");

  case NDPI_BINARY_DATA_TRANSFER:
    return("Binary File/Data Transfer (Attempt)");

  case NDPI_PROBING_ATTEMPT:
    return("Probing Attempt");

  case NDPI_OBFUSCATED_TRAFFIC:
    return("Obfuscated Traffic");

  case NDPI_SLOW_DOS:
    return("(Possible) Slow DoS");

  case NDPI_NON_PQC:
    return("Non PQC Compliant Flow");

  default:
    ndpi_snprintf(buf, sizeof(buf), "%d", (int)risk);
    return(buf);
  }
}

/* ******************************************************************** */

#define STRINGIFY(x) #x

const char* ndpi_risk2code(ndpi_risk_enum risk) {
  switch(risk) {
  case NDPI_NO_RISK:
    return STRINGIFY(NDPI_NO_RISK);
  case NDPI_URL_POSSIBLE_XSS:
    return STRINGIFY(NDPI_URL_POSSIBLE_XSS);
  case NDPI_URL_POSSIBLE_SQL_INJECTION:
    return STRINGIFY(NDPI_URL_POSSIBLE_SQL_INJECTION);
  case NDPI_URL_POSSIBLE_RCE_INJECTION:
    return STRINGIFY(NDPI_URL_POSSIBLE_RCE_INJECTION);
  case NDPI_BINARY_APPLICATION_TRANSFER:
    return STRINGIFY(NDPI_BINARY_APPLICATION_TRANSFER);
  case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
    return STRINGIFY(NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);
  case NDPI_TLS_SELFSIGNED_CERTIFICATE:
    return STRINGIFY(NDPI_TLS_SELFSIGNED_CERTIFICATE);
  case NDPI_TLS_OBSOLETE_VERSION:
    return STRINGIFY(NDPI_TLS_OBSOLETE_VERSION);
  case NDPI_TLS_WEAK_CIPHER:
    return STRINGIFY(NDPI_TLS_WEAK_CIPHER);
  case NDPI_TLS_CERTIFICATE_EXPIRED:
    return STRINGIFY(NDPI_TLS_CERTIFICATE_EXPIRED);
  case NDPI_TLS_CERTIFICATE_MISMATCH:
    return STRINGIFY(NDPI_TLS_CERTIFICATE_MISMATCH);
  case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
    return STRINGIFY(NDPI_HTTP_SUSPICIOUS_USER_AGENT);
  case NDPI_NUMERIC_IP_HOST:
    return STRINGIFY(NDPI_NUMERIC_IP_HOST);
  case NDPI_HTTP_SUSPICIOUS_URL:
    return STRINGIFY(NDPI_HTTP_SUSPICIOUS_URL);
  case NDPI_HTTP_SUSPICIOUS_HEADER:
    return STRINGIFY(NDPI_HTTP_SUSPICIOUS_HEADER);
  case NDPI_TLS_NOT_CARRYING_HTTPS:
    return STRINGIFY(NDPI_TLS_NOT_CARRYING_HTTPS);
  case NDPI_SUSPICIOUS_DGA_DOMAIN:
    return STRINGIFY(NDPI_SUSPICIOUS_DGA_DOMAIN);
  case NDPI_MALFORMED_PACKET:
    return STRINGIFY(NDPI_MALFORMED_PACKET);
  case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
    return STRINGIFY(NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER);
  case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
    return STRINGIFY(NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER);
  case NDPI_SMB_INSECURE_VERSION:
    return STRINGIFY(NDPI_SMB_INSECURE_VERSION);
  case NDPI_MISMATCHING_PROTOCOL_WITH_IP:
    return STRINGIFY(NDPI_MISMATCHING_PROTOCOL_WITH_IP);
  case NDPI_UNSAFE_PROTOCOL:
    return STRINGIFY(NDPI_TLS_SUSPICIOUS_ESNI_USAGE);
  case NDPI_DNS_SUSPICIOUS_TRAFFIC:
    return STRINGIFY(NDPI_DNS_SUSPICIOUS_TRAFFIC);
  case NDPI_TLS_MISSING_SNI:
    return STRINGIFY(NDPI_TLS_MISSING_SNI);
  case NDPI_HTTP_SUSPICIOUS_CONTENT:
    return STRINGIFY(NDPI_HTTP_SUSPICIOUS_CONTENT);
  case NDPI_RISKY_ASN:
    return STRINGIFY(NDPI_RISKY_ASN);
  case NDPI_RISKY_DOMAIN:
    return STRINGIFY(NDPI_RISKY_DOMAIN);
  case NDPI_MALICIOUS_FINGERPRINT:
    return STRINGIFY(NDPI_MALICIOUS_FINGERPRINT);
  case NDPI_MALICIOUS_SHA1_CERTIFICATE:
    return STRINGIFY(NDPI_MALICIOUS_SHA1_CERTIFICATE);
  case NDPI_DESKTOP_OR_FILE_SHARING_SESSION:
    return STRINGIFY(NDPI_DESKTOP_OR_FILE_SHARING_SESSION);
  case NDPI_TLS_UNCOMMON_ALPN:
    return STRINGIFY(NDPI_TLS_UNCOMMON_ALPN);
  case NDPI_TLS_CERT_VALIDITY_TOO_LONG:
    return STRINGIFY(NDPI_TLS_CERT_VALIDITY_TOO_LONG);
  case NDPI_TLS_SUSPICIOUS_EXTENSION:
    return STRINGIFY(NDPI_TLS_SUSPICIOUS_EXTENSION);
  case NDPI_TLS_FATAL_ALERT:
    return STRINGIFY(NDPI_TLS_FATAL_ALERT);
  case NDPI_SUSPICIOUS_ENTROPY:
    return STRINGIFY(NDPI_SUSPICIOUS_ENTROPY);
  case NDPI_CLEAR_TEXT_CREDENTIALS:
    return STRINGIFY(NDPI_CLEAR_TEXT_CREDENTIALS);
  case NDPI_DNS_LARGE_PACKET:
    return STRINGIFY(NDPI_DNS_LARGE_PACKET);
  case NDPI_DNS_FRAGMENTED:
    return STRINGIFY(NDPI_DNS_FRAGMENTED);
  case NDPI_INVALID_CHARACTERS:
    return STRINGIFY(NDPI_INVALID_CHARACTERS);
  case NDPI_POSSIBLE_EXPLOIT:
    return STRINGIFY(NDPI_POSSIBLE_EXPLOIT);
  case NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE:
    return STRINGIFY(NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE);
  case NDPI_PUNYCODE_IDN:
    return STRINGIFY(NDPI_PUNYCODE_IDN);
  case NDPI_ERROR_CODE_DETECTED:
    return STRINGIFY(NDPI_ERROR_CODE_DETECTED);
  case NDPI_HTTP_CRAWLER_BOT:
    return STRINGIFY(NDPI_HTTP_CRAWLER_BOT);
  case NDPI_ANONYMOUS_SUBSCRIBER:
    return STRINGIFY(NDPI_ANONYMOUS_SUBSCRIBER);
  case NDPI_UNIDIRECTIONAL_TRAFFIC:
    return STRINGIFY(NDPI_UNIDIRECTIONAL_TRAFFIC);
  case NDPI_HTTP_OBSOLETE_SERVER:
    return STRINGIFY(NDPI_HTTP_OBSOLETE_SERVER);
  case NDPI_PERIODIC_FLOW:
    return STRINGIFY(NDPI_PERIODIC_FLOW);
  case NDPI_MINOR_ISSUES:
    return STRINGIFY(NDPI_MINOR_ISSUES);
  case NDPI_TCP_ISSUES:
    return STRINGIFY(NDPI_MINOR_ISSUES);
  case NDPI_UNRESOLVED_HOSTNAME:
    return STRINGIFY(NDPI_UNRESOLVED_HOSTNAME);
  case NDPI_TLS_ALPN_SNI_MISMATCH:
    return STRINGIFY(NDPI_TLS_ALPN_SNI_MISMATCH);
  case NDPI_MALWARE_HOST_CONTACTED:
    return STRINGIFY(NDPI_MALWARE_HOST_CONTACTED);
  case NDPI_BINARY_DATA_TRANSFER:
    return STRINGIFY(NDPI_BINARY_DATA_TRANSFER);
  case NDPI_PROBING_ATTEMPT:
    return STRINGIFY(NDPI_PROBING_ATTEMPT);
  case NDPI_OBFUSCATED_TRAFFIC:
    return STRINGIFY(NDPI_OBFUSCATED_TRAFFIC);
  case NDPI_SLOW_DOS:
    return STRINGIFY(NDPI_SLOW_DOS);
  case NDPI_NON_PQC:
    return STRINGIFY(NDPI_NON_PQC);

  default:
    return("Unknown risk");
  }
}

/* ******************************************************************** */

ndpi_risk_enum ndpi_code2risk(const char* risk) {
  if(strcmp(STRINGIFY(NDPI_NO_RISK), risk) == 0)
    return(NDPI_NO_RISK);
  else if(strcmp(STRINGIFY(NDPI_URL_POSSIBLE_XSS), risk) == 0)
    return(NDPI_URL_POSSIBLE_XSS);
  else if(strcmp(STRINGIFY(NDPI_URL_POSSIBLE_SQL_INJECTION), risk) == 0)
    return(NDPI_URL_POSSIBLE_SQL_INJECTION);
  else if(strcmp(STRINGIFY(NDPI_URL_POSSIBLE_RCE_INJECTION), risk) == 0)
    return(NDPI_URL_POSSIBLE_RCE_INJECTION);
  else if(strcmp(STRINGIFY(NDPI_BINARY_APPLICATION_TRANSFER), risk) == 0)
    return(NDPI_BINARY_APPLICATION_TRANSFER);
  else if(strcmp(STRINGIFY(NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT), risk) == 0)
    return(NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);
  else if(strcmp(STRINGIFY(NDPI_TLS_SELFSIGNED_CERTIFICATE), risk) == 0)
    return(NDPI_TLS_SELFSIGNED_CERTIFICATE);
  else if(strcmp(STRINGIFY(NDPI_TLS_OBSOLETE_VERSION), risk) == 0)
    return(NDPI_TLS_OBSOLETE_VERSION);
  else if(strcmp(STRINGIFY(NDPI_TLS_WEAK_CIPHER), risk) == 0)
    return(NDPI_TLS_WEAK_CIPHER);
  else if(strcmp(STRINGIFY(NDPI_TLS_CERTIFICATE_EXPIRED), risk) == 0)
    return(NDPI_TLS_CERTIFICATE_EXPIRED);
  else if(strcmp(STRINGIFY(NDPI_TLS_CERTIFICATE_MISMATCH), risk) == 0)
    return(NDPI_TLS_CERTIFICATE_MISMATCH);
  else if(strcmp(STRINGIFY(NDPI_HTTP_SUSPICIOUS_USER_AGENT), risk) == 0)
    return(NDPI_HTTP_SUSPICIOUS_USER_AGENT);
  else if(strcmp(STRINGIFY(NDPI_NUMERIC_IP_HOST), risk) == 0)
    return(NDPI_NUMERIC_IP_HOST);
  else if(strcmp(STRINGIFY(NDPI_HTTP_SUSPICIOUS_URL), risk) == 0)
    return(NDPI_HTTP_SUSPICIOUS_URL);
  else if(strcmp(STRINGIFY(NDPI_HTTP_SUSPICIOUS_HEADER), risk) == 0)
    return(NDPI_HTTP_SUSPICIOUS_HEADER);
  else if(strcmp(STRINGIFY(NDPI_TLS_NOT_CARRYING_HTTPS), risk) == 0)
    return(NDPI_TLS_NOT_CARRYING_HTTPS);
  else if(strcmp(STRINGIFY(NDPI_SUSPICIOUS_DGA_DOMAIN), risk) == 0)
    return(NDPI_SUSPICIOUS_DGA_DOMAIN);
  else if(strcmp(STRINGIFY(NDPI_MALFORMED_PACKET), risk) == 0)
    return(NDPI_MALFORMED_PACKET);
  else if(strcmp(STRINGIFY(NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER), risk) == 0)
    return(NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER);
  else if(strcmp(STRINGIFY(NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER), risk) == 0)
    return(NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER);
  else if(strcmp(STRINGIFY(NDPI_SMB_INSECURE_VERSION), risk) == 0)
    return(NDPI_SMB_INSECURE_VERSION);
  else if(strcmp(STRINGIFY(NDPI_MISMATCHING_PROTOCOL_WITH_IP), risk) == 0)
    return(NDPI_MISMATCHING_PROTOCOL_WITH_IP);
  else if(strcmp(STRINGIFY(NDPI_UNSAFE_PROTOCOL), risk) == 0)
    return(NDPI_UNSAFE_PROTOCOL);
  else if(strcmp(STRINGIFY(NDPI_DNS_SUSPICIOUS_TRAFFIC), risk) == 0)
    return(NDPI_DNS_SUSPICIOUS_TRAFFIC);
  else if(strcmp(STRINGIFY(NDPI_TLS_MISSING_SNI), risk) == 0)
    return(NDPI_TLS_MISSING_SNI);
  else if(strcmp(STRINGIFY(NDPI_HTTP_SUSPICIOUS_CONTENT), risk) == 0)
    return(NDPI_HTTP_SUSPICIOUS_CONTENT);
  else if(strcmp(STRINGIFY(NDPI_RISKY_ASN), risk) == 0)
    return(NDPI_RISKY_ASN);
  else if(strcmp(STRINGIFY(NDPI_RISKY_DOMAIN), risk) == 0)
    return(NDPI_RISKY_DOMAIN);
  else if(strcmp(STRINGIFY(NDPI_MALICIOUS_FINGERPRINT), risk) == 0)
    return(NDPI_MALICIOUS_FINGERPRINT);
  else if(strcmp(STRINGIFY(NDPI_MALICIOUS_SHA1_CERTIFICATE), risk) == 0)
    return(NDPI_MALICIOUS_SHA1_CERTIFICATE);
  else if(strcmp(STRINGIFY(NDPI_DESKTOP_OR_FILE_SHARING_SESSION), risk) == 0)
    return(NDPI_DESKTOP_OR_FILE_SHARING_SESSION);
  else if(strcmp(STRINGIFY(NDPI_TLS_UNCOMMON_ALPN), risk) == 0)
    return(NDPI_TLS_UNCOMMON_ALPN);
  else if(strcmp(STRINGIFY(NDPI_TLS_CERT_VALIDITY_TOO_LONG), risk) == 0)
    return(NDPI_TLS_CERT_VALIDITY_TOO_LONG);
  else if(strcmp(STRINGIFY(NDPI_TLS_SUSPICIOUS_EXTENSION), risk) == 0)
    return(NDPI_TLS_SUSPICIOUS_EXTENSION);
  else if(strcmp(STRINGIFY(NDPI_TLS_FATAL_ALERT), risk) == 0)
    return(NDPI_TLS_FATAL_ALERT);
  else if(strcmp(STRINGIFY(NDPI_SUSPICIOUS_ENTROPY), risk) == 0)
    return(NDPI_SUSPICIOUS_ENTROPY);
  else if(strcmp(STRINGIFY(NDPI_CLEAR_TEXT_CREDENTIALS), risk) == 0)
    return(NDPI_CLEAR_TEXT_CREDENTIALS);
  else if(strcmp(STRINGIFY(NDPI_DNS_LARGE_PACKET), risk) == 0)
    return(NDPI_DNS_LARGE_PACKET);
  else if(strcmp(STRINGIFY(NDPI_DNS_FRAGMENTED), risk) == 0)
    return(NDPI_DNS_FRAGMENTED);
  else if(strcmp(STRINGIFY(NDPI_INVALID_CHARACTERS), risk) == 0)
    return(NDPI_INVALID_CHARACTERS);
  else if(strcmp(STRINGIFY(NDPI_POSSIBLE_EXPLOIT), risk) == 0)
    return(NDPI_POSSIBLE_EXPLOIT);
  else if(strcmp(STRINGIFY(NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE), risk) == 0)
    return(NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE);
  else if(strcmp(STRINGIFY(NDPI_PUNYCODE_IDN), risk) == 0)
    return(NDPI_PUNYCODE_IDN);
  else if(strcmp(STRINGIFY(NDPI_ERROR_CODE_DETECTED), risk) == 0)
    return(NDPI_ERROR_CODE_DETECTED);
  else if(strcmp(STRINGIFY(NDPI_HTTP_CRAWLER_BOT), risk) == 0)
    return(NDPI_HTTP_CRAWLER_BOT);
  else if(strcmp(STRINGIFY(NDPI_ANONYMOUS_SUBSCRIBER), risk) == 0)
    return(NDPI_ANONYMOUS_SUBSCRIBER);
  else if(strcmp(STRINGIFY(NDPI_UNIDIRECTIONAL_TRAFFIC), risk) == 0)
    return(NDPI_UNIDIRECTIONAL_TRAFFIC);
  else if(strcmp(STRINGIFY(NDPI_HTTP_OBSOLETE_SERVER), risk) == 0)
    return(NDPI_HTTP_OBSOLETE_SERVER);
  else if(strcmp(STRINGIFY(NDPI_PERIODIC_FLOW), risk) == 0)
    return(NDPI_PERIODIC_FLOW);
  else if(strcmp(STRINGIFY(NDPI_MINOR_ISSUES), risk) == 0)
    return(NDPI_MINOR_ISSUES);
  else if(strcmp(STRINGIFY(NDPI_TCP_ISSUES), risk) == 0)
    return(NDPI_MINOR_ISSUES);
  else if(strcmp(STRINGIFY(NDPI_UNRESOLVED_HOSTNAME), risk) == 0)
    return(NDPI_UNRESOLVED_HOSTNAME);
  else if(strcmp(STRINGIFY(NDPI_TLS_ALPN_SNI_MISMATCH), risk) == 0)
    return(NDPI_TLS_ALPN_SNI_MISMATCH);
  else if(strcmp(STRINGIFY(NDPI_MALWARE_HOST_CONTACTED), risk) == 0)
    return(NDPI_MALWARE_HOST_CONTACTED);
  else if(strcmp(STRINGIFY(NDPI_BINARY_DATA_TRANSFER), risk) == 0)
    return(NDPI_BINARY_DATA_TRANSFER);
  else if(strcmp(STRINGIFY(NDPI_PROBING_ATTEMPT), risk) == 0)
    return(NDPI_PROBING_ATTEMPT);
  else if(strcmp(STRINGIFY(NDPI_OBFUSCATED_TRAFFIC), risk) == 0)
    return(NDPI_OBFUSCATED_TRAFFIC);
  else if(strcmp(STRINGIFY(NDPI_SLOW_DOS), risk) == 0)
    return(NDPI_SLOW_DOS);
  else if(strcmp(STRINGIFY(NDPI_NON_PQC), risk) == 0)
    return(NDPI_NON_PQC);
  else
    return(NDPI_MAX_RISK);
}

/* ******************************************************************** */

const char* ndpi_severity2str(ndpi_risk_severity s) {
  switch(s) {
  case NDPI_RISK_LOW:
    return("Low");

  case NDPI_RISK_MEDIUM:
    return("Medium");

  case NDPI_RISK_HIGH:
    return("High");

  case NDPI_RISK_SEVERE:
    return("Severe");

  case NDPI_RISK_CRITICAL:
    return("Critical");

  case NDPI_RISK_EMERGENCY:
    return("Emergency");
  }

  return("");
}

/* ******************************************************************** */

u_int16_t ndpi_risk2score(ndpi_risk risk,
			  u_int16_t *client_score,
			  u_int16_t *server_score) {
  u_int16_t score = 0;
  u_int32_t i;

  *client_score = *server_score = 0; /* Reset values */

  if(risk == 0) return(0);

  for(i = 0; i < NDPI_MAX_RISK; i++) {
    ndpi_risk_enum r = (ndpi_risk_enum)i;

    if(NDPI_ISSET_BIT(risk, r)) {
      ndpi_risk_info *info = ndpi_risk2severity(r);
      u_int16_t val = 0, client_score_val;

      switch(info->severity) {
      case NDPI_RISK_LOW:
	val = NDPI_SCORE_RISK_LOW;
	break;

      case NDPI_RISK_MEDIUM:
	val = NDPI_SCORE_RISK_MEDIUM;
	break;

      case NDPI_RISK_HIGH:
	val = NDPI_SCORE_RISK_HIGH;
	break;

      case NDPI_RISK_SEVERE:
	val = NDPI_SCORE_RISK_SEVERE;
	break;

      case NDPI_RISK_CRITICAL:
	val = NDPI_SCORE_RISK_CRITICAL;
	break;

      case NDPI_RISK_EMERGENCY:
	val = NDPI_SCORE_RISK_EMERGENCY;
	break;
      }

      score += val;
      client_score_val = (val * info->default_client_risk_pctg) / 100;

      *client_score += client_score_val, *server_score += (val - client_score_val);
    }
  }

  return(score);
}

const char *ndpi_risk_shortnames[NDPI_MAX_RISK] = {
  "unknown",                    /* NDPI_NO_RISK */
  "xss",
  "sql",
  "rce",
  "binary_transfer",
  "non_standard_port",
  "tls_selfsigned_cert",
  "tls_obsolete_ver",
  "tls_weak_cipher",
  "tls_cert_expired",
  "tls_cert_mismatch",          /* NDPI_TLS_CERTIFICATE_MISMATCH */
  "http_susp_ua",
  "numeric_ip_host",
  "http_susp_url",
  "http_susp_header",
  "tls_not_https",
  "dga",
  "malformed_pkt",
  "ssh_obsolete_client",
  "ssh_obsolete_server",
  "smb_insecure_ver",           /* NDPI_SMB_INSECURE_VERSION */
  "mismatching_hostname_with_ip",
  "unsafe_proto",
  "dns_susp",
  "tls_no_sni",
  "http_susp_content",
  "risky_asn",
  "risky_domain",
  "malicious_fingerprint",
  "malicious_cert",
  "desktop_sharing",            /* NDPI_DESKTOP_OR_FILE_SHARING_SESSION */
  "uls_uncommon_alpn",
  "tls_cert_too_long",
  "tls_susp_ext",
  "tls_fatal_err",
  "susp_entropy",
  "clear_credential",
  "dns_large_pkt",
  "dns_fragmented",
  "invalid_characters",
  "exploit",                    /* NDPI_POSSIBLE_EXPLOIT */
  "tls_cert_about_to_expire",
  "punycode",
  "error_code",
  "crawler_bot",
  "anonymous_subscriber",
  "unidirectional",
  "http_obsolete_server",
  "periodic_flow",
  "minor_issues",
  "tcp_issues",                 /* NDPI_TCP_ISSUES */
  "unresolved_hostname",
  "tls_alpn_mismatch",
  "malware_host",
  "binary_data_transfer",
  "probing",
  "obfuscated",
  "slow_DoS",
  "non_PQC"
};

/* ******************************************************************** */

const char* ndpi_http_method2str(ndpi_http_method m) {
  switch(m) {
  case NDPI_HTTP_METHOD_UNKNOWN:      break;
  case NDPI_HTTP_METHOD_OPTIONS:      return("OPTIONS");
  case NDPI_HTTP_METHOD_GET:          return("GET");
  case NDPI_HTTP_METHOD_HEAD:         return("HEAD");
  case NDPI_HTTP_METHOD_PATCH:        return("PATCH");
  case NDPI_HTTP_METHOD_POST:         return("POST");
  case NDPI_HTTP_METHOD_PUT:          return("PUT");
  case NDPI_HTTP_METHOD_DELETE:       return("DELETE");
  case NDPI_HTTP_METHOD_TRACE:        return("TRACE");
  case NDPI_HTTP_METHOD_CONNECT:      return("CONNECT");
  case NDPI_HTTP_METHOD_RPC_CONNECT:  return("RPC_CONNECT");
  case NDPI_HTTP_METHOD_RPC_IN_DATA:  return("RPC_IN_DATA");
  case NDPI_HTTP_METHOD_RPC_OUT_DATA: return("RPC_OUT_DATA");
  case NDPI_HTTP_METHOD_MKCOL:        return("MKCOL");
  case NDPI_HTTP_METHOD_MOVE:         return("MOVE");
  case NDPI_HTTP_METHOD_COPY:         return("COPY");
  case NDPI_HTTP_METHOD_LOCK:         return("LOCK");
  case NDPI_HTTP_METHOD_UNLOCK:       return("UNLOCK");
  case NDPI_HTTP_METHOD_PROPFIND:     return("PROPFIND");
  case NDPI_HTTP_METHOD_PROPPATCH:    return("PROPPATCH");
  }

  return("Unknown HTTP method");
}

/* ******************************************************************** */

ndpi_http_method ndpi_http_str2method(const char* method, u_int16_t method_len) {
  if(!method || method_len < 3)
    return(NDPI_HTTP_METHOD_UNKNOWN);

  switch(method[0]) {
  case 'O': return(NDPI_HTTP_METHOD_OPTIONS);
  case 'G': return(NDPI_HTTP_METHOD_GET);
  case 'H': return(NDPI_HTTP_METHOD_HEAD);
  case 'L': return(NDPI_HTTP_METHOD_LOCK);

  case 'M':
    if (method[1] == 'O')
      return(NDPI_HTTP_METHOD_MOVE);
    else
      return(NDPI_HTTP_METHOD_MKCOL);

  case 'P':
    switch(method[1]) {
    case 'A':return(NDPI_HTTP_METHOD_PATCH);
    case 'O':return(NDPI_HTTP_METHOD_POST);
    case 'U':return(NDPI_HTTP_METHOD_PUT);
    case 'R':
      if (method_len >= 5) {
        if (strncmp(method, "PROPF", 5) == 0)
          return(NDPI_HTTP_METHOD_PROPFIND);
        else if (strncmp(method, "PROPP", 5) == 0)
          return NDPI_HTTP_METHOD_PROPPATCH;
      }
    }
    break;

  case 'D':  return(NDPI_HTTP_METHOD_DELETE);
  case 'T':  return(NDPI_HTTP_METHOD_TRACE);
  case 'C':
    if (method_len == 4)
      return(NDPI_HTTP_METHOD_COPY);
    else
      return(NDPI_HTTP_METHOD_CONNECT);

  case 'R':
    if(method_len >= 11) {
      if(strncmp(method, "RPC_CONNECT", 11) == 0) {
        return(NDPI_HTTP_METHOD_RPC_CONNECT);
      } else if(strncmp(method, "RPC_IN_DATA", 11) == 0) {
        return(NDPI_HTTP_METHOD_RPC_IN_DATA);
      } else if(strncmp(method, "RPC_OUT_DATA", 12) == 0) {
        return(NDPI_HTTP_METHOD_RPC_OUT_DATA);
      }
    }
    break;

  case 'U': return(NDPI_HTTP_METHOD_UNLOCK);
  }

  return(NDPI_HTTP_METHOD_UNKNOWN);
}

/* ******************************************************************** */

int ndpi_hash_init(ndpi_str_hash **h) {
  if (h == NULL)
    return 1;

  *h = ndpi_calloc(1, sizeof(**h));
  if(!*h)
    return 1;
  return 0;
}

/* ******************************************************************** */

void ndpi_hash_free(ndpi_str_hash **h) {
  if(h && *h) {
    ndpi_str_hash_priv *h_priv = (ndpi_str_hash_priv *)((*h)->priv);
    ndpi_str_hash_priv *current, *tmp;

    HASH_ITER(hh, h_priv, current, tmp) {
      HASH_DEL(h_priv, current);
      ndpi_free(current->key);
      ndpi_free(current);
    }

    ndpi_free(*h);
    *h = NULL;
  }
}

/* ******************************************************************** */

int ndpi_hash_find_entry_extra(ndpi_str_hash *h, const char *key, u_int key_len,
			       u_int64_t *value /* out */,
			       ndpi_list **extra_data /* out */) {
  ndpi_str_hash_priv *h_priv;
  ndpi_str_hash_priv *item;

  if(!h || !key || key_len == 0)
    return(2);

  h_priv = (ndpi_str_hash_priv *)((h)->priv);

  h->stats.n_search++;
  HASH_FIND(hh, h_priv, key, key_len, item);

  if (item != NULL) {
    if(value != NULL)
      *value = item->value64;

    if(extra_data != NULL)
      *extra_data = &item->value_list;

    h->stats.n_found++;
    return 0;
  } else
    return 1;
}

/* ******************************************************************** */

int ndpi_hash_find_entry(ndpi_str_hash *h, const char *key,
			 u_int key_len, u_int64_t *value /* out */) {
  return(ndpi_hash_find_entry_extra(h, key, key_len, value, NULL));
}

/* ******************************************************************** */

int ndpi_hash_add_entry(ndpi_str_hash **h, char *key, u_int8_t key_len,
			u_int64_t value, char *extra_data /* Allocated by caller */) {
  ndpi_str_hash_priv *h_priv;
  ndpi_str_hash_priv *item, *ret_found;

  if(!h || !*h || !key || key_len == 0)
    return(3);

  h_priv = (ndpi_str_hash_priv *)((*h)->priv);

  HASH_FIND(hh, h_priv, key, key_len, item);

  if(item != NULL) {
    if(extra_data != NULL) {
      /*
	If there are extra blocks to handle value64
	(the protocol) is not overwritten (***)
      */
      ndpi_list_append(&item->value_list, extra_data);
    } else
      item->value64 = value;

    return(1); /* Entry already present */
  }

  item = ndpi_calloc(1, sizeof(ndpi_str_hash_priv));
  if(item == NULL)
    return(2);

  ndpi_list_init(&item->value_list);
  item->key = ndpi_malloc(key_len+1);

  if(item->key == NULL) {
    ndpi_free(item);
    return(1);
  } else {
    memcpy(item->key, key, key_len);
    item->key[key_len] = '\0';
  }

  if(extra_data != NULL) /* Same as (***) above */
    ndpi_list_append(&item->value_list, extra_data);
  else
    item->value64 = value;

  HASH_ADD(hh, *(ndpi_str_hash_priv **)&((*h)->priv), key[0], key_len, item);

  HASH_FIND(hh, *(ndpi_str_hash_priv **)&((*h)->priv), key, key_len, ret_found);
  if(ret_found == NULL) {
    /* The insertion failed (because of a memory allocation error) */
    ndpi_free(item->key);
    ndpi_free(item);
    return 4;
  }

  return 0;
}

/* ******************************************************************** */

void ndpi_hash_get_stats(ndpi_str_hash *h, struct ndpi_str_hash_stats *stats) {
  if(h) {
    stats->n_search = h->stats.n_search;
    stats->n_found = h->stats.n_found;
  } else {
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

/* ******************************************************************** */

void ndpi_hash_walk(ndpi_str_hash **h, ndpi_hash_walk_iter cb, void *data) {
  if(h && *h) {
    ndpi_str_hash_priv *h_priv = (ndpi_str_hash_priv *)((*h)->priv);
    ndpi_str_hash_priv *current, *tmp;

    HASH_ITER(hh, h_priv, current, tmp) {
      cb(current->key, current->value64, data);
    }
  }
}

/* ******************************************************************** */

int ndpi_get_hash_stats(struct ndpi_detection_module_struct *ndpi_struct,
                        str_hash_type hash_type,
                        struct ndpi_str_hash_stats *stats)
{
  if(!ndpi_struct || !stats)
    return -1;

  switch(hash_type) {
  case NDPI_STR_HASH_MALICIOUS_JA4:
    ndpi_hash_get_stats(ndpi_struct->malicious_ja4_hashmap, stats);
    return 0;

  case NDPI_STR_HASH_MALICIOUS_SHA1:
    ndpi_hash_get_stats(ndpi_struct->malicious_sha1_hashmap, stats);
    return 0;

  case NDPI_STR_HASH_TCP_FINGERPRINTS:
    ndpi_hash_get_stats(ndpi_struct->tcp_fingerprint_hashmap, stats);
    return 0;

  case NDPI_STR_HASH_PUBLIC_DOMAIN_SUFFIX:
    ndpi_hash_get_stats(ndpi_struct->public_domain_suffixes, stats);
    return 0;

  case NDPI_STR_HASH_JA4_CUSTOM_PROTOS:
    ndpi_hash_get_stats(ndpi_struct->ja4_custom_protos, stats);
    return 0;

  case NDPI_STR_HASH_FP_CUSTOM_PROTOS:
    ndpi_hash_get_stats(ndpi_struct->ndpifp_custom_protos, stats);
    return 0;

  case NDPI_STR_HASH_HTTP_URL:
    ndpi_hash_get_stats(ndpi_struct->http_url_hashmap, stats);
    return 0;

  default:
    return -1;
  }
}

/* ********************************************************************************* */

static u_int64_t ndpi_host_ip_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					       struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str->ip_risk_mask)
    return((u_int64_t)-1);

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32,
		      ((ndpi_patricia_tree_t *) ndpi_str->ip_risk_mask->v4)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_mask->v4, &prefix);

  if(node)
    return(node->value.u.uv64);
  else
    return((u_int64_t)-1);
}

/* ********************************************************************************* */

static u_int64_t ndpi_host_ip_risk_ptree_match6(struct ndpi_detection_module_struct *ndpi_str,
					        struct in6_addr *pin6) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str->ip_risk_mask)
    return((u_int64_t)-1);

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v6(&prefix, pin6, 128,
		      ((ndpi_patricia_tree_t *) ndpi_str->ip_risk_mask->v6)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_mask->v6, &prefix);

  if(node)
    return(node->value.u.uv64);
  else
    return((u_int64_t)-1);
}

/* ********************************************************************************* */

/* Check isuerDN exception */
u_int8_t ndpi_check_issuerdn_risk_exception(struct ndpi_detection_module_struct *ndpi_str,
					    char *issuerDN) {
  if(issuerDN != NULL) {
    ndpi_list *head = ndpi_str->trusted_issuer_dn;

    while(head != NULL) {
      if(strcmp(issuerDN, head->value) == 0)
	return(1); /* This is a trusted DN */
      else
	head = head->next;
    }
  }

  return(0 /* no exception */);
}

/* ********************************************************************************* */

/* Check host exception */
static u_int8_t ndpi_check_hostname_risk_exception(struct ndpi_detection_module_struct *ndpi_str,
						   struct ndpi_flow_struct *flow,
						   char *hostname) {
  if(hostname == NULL)
    return(0);
  else {
    ndpi_automa *automa = &ndpi_str->host_risk_mask_automa;
    u_int8_t ret = 0;

    if(automa && automa->ac_automa) {
      AC_TEXT_t ac_input_text;
      AC_REP_t match;

      memset(&match, 0, sizeof(match));
      ac_input_text.astring = hostname, ac_input_text.length = strlen(hostname);
      ac_input_text.option = 0;

      if(ac_automata_search(automa->ac_automa, &ac_input_text, &match) > 0) {
	if(flow) flow->risk_mask &= match.number64;
	ret = 1;
      }
    }

    return(ret);
  }
}

/* ********************************************************************************* */

/* Check host exception */
static u_int8_t ndpi_check_ipv4_exception(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  u_int32_t addr) {
  struct in_addr pin;
  u_int64_t r;

  pin.s_addr = addr;
  r = ndpi_host_ip_risk_ptree_match(ndpi_str, &pin);

  if(flow) flow->risk_mask &= r;

  return((r != (u_int64_t)-1) ? 1 : 0);
}

/* ********************************************************************************* */

static u_int8_t ndpi_check_ipv6_exception(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  struct in6_addr *addr) {
  u_int64_t r;

  r = ndpi_host_ip_risk_ptree_match6(ndpi_str, addr);

  if(flow) flow->risk_mask &= r;

  return((r != (u_int64_t)-1) ? 1 : 0);
}

/* ********************************************************************************* */

int is_flowrisk_enabled(struct ndpi_detection_module_struct *ndpi_str, ndpi_risk_enum flowrisk_id)
{
  if(ndpi_bitmask_is_set(&ndpi_str->cfg.flowrisk_bitmask, flowrisk_id) == 0)
    return 0;
  return 1;
}

/* ********************************************************************************* */

int is_flowrisk_info_enabled(struct ndpi_detection_module_struct *ndpi_str, ndpi_risk_enum flowrisk_id)
{
  if(ndpi_bitmask_is_set(&ndpi_str->cfg.flowrisk_info_bitmask, flowrisk_id) == 0)
    return 0;
  return 1;
}

/* ********************************************************************************* */

void ndpi_handle_risk_exceptions(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow) {
  if(flow->risk == 0) return; /* Nothing to do */

  if((!flow->host_risk_mask_evaluated) && (!flow->ip_risk_mask_evaluated))
    flow->risk_mask = (u_int64_t)-1; /* No mask */

  if(!flow->host_risk_mask_evaluated) {
    char *host = ndpi_get_flow_name(flow);

    if(host && (host[0] != '\0')) {
      /* Check host exception */
      ndpi_check_hostname_risk_exception(ndpi_str, flow, host);

      if(flow->risk_mask == 0) {
	u_int i;

	/*
	  Might be that the exception applied when some risks
	  were already triggered: we need to clean them up
	*/
	for(i=0; i<flow->num_risk_infos; i++) {
	  if(flow->risk_infos[i].info != NULL) {
	    ndpi_free(flow->risk_infos[i].info);
	    flow->risk_infos[i].info = NULL;
	  }

	  flow->risk_infos[i].id = NDPI_NO_RISK;
	}

	flow->num_risk_infos = 0;
      }

      /* Used to avoid double checks (e.g. in DNS req/rsp) */
      flow->host_risk_mask_evaluated = 1;
    }
  }

  if(!flow->ip_risk_mask_evaluated) {
    if(flow->is_ipv6 == 0) {
      ndpi_check_ipv4_exception(ndpi_str, flow, flow->c_address.v4 /* Client */);
      ndpi_check_ipv4_exception(ndpi_str, flow, flow->s_address.v4 /* Server */);
    } else {
      ndpi_check_ipv6_exception(ndpi_str, flow, (struct in6_addr *)&flow->c_address.v6 /* Client */);
      ndpi_check_ipv6_exception(ndpi_str, flow, (struct in6_addr *)&flow->s_address.v6 /* Server */);
    }

    flow->ip_risk_mask_evaluated = 1;
  }

  flow->risk &= flow->risk_mask;
}

/* ******************************************************************** */

void ndpi_set_risk(struct ndpi_detection_module_struct *ndpi_str,
		   struct ndpi_flow_struct *flow,
                   ndpi_risk_enum r, char *risk_message) {
  if(!flow) return;

  if(!is_flowrisk_enabled(ndpi_str, r))
    return;

  /* Check if the risk is not yet set */
  if(!ndpi_isset_risk(flow, r)) {
    ndpi_risk v = 1ull << r;

    /* In case there is an exception set, take it into account */
    if(flow->host_risk_mask_evaluated)
      v &= flow->risk_mask;

    // NDPI_SET_BIT(flow->risk, (u_int32_t)r);
    flow->risk |= v;

    /* Will be handled by ndpi_reconcile_protocols() */
    // ndpi_handle_risk_exceptions(ndpi_str, flow);

    if(flow->risk != 0 /* check if it has been masked */) {
      if(is_flowrisk_info_enabled(ndpi_str, r) &&
         risk_message != NULL) {
	if(flow->num_risk_infos < MAX_NUM_RISK_INFOS) {
	  char *s = ndpi_strdup(risk_message);

	  if(s != NULL) {
	    flow->risk_infos[flow->num_risk_infos].id = r;
	    flow->risk_infos[flow->num_risk_infos].info = s;
	    flow->num_risk_infos++;
	  }
	}
      }
    }
  } else if(is_flowrisk_info_enabled(ndpi_str, r) && risk_message) {
    u_int8_t i;

    for(i = 0; i < flow->num_risk_infos; i++)
      if(flow->risk_infos[i].id == r) {
	if((flow->risk_infos[i].info != NULL)
	   && (r != NDPI_SUSPICIOUS_ENTROPY /* Entropy changes when recomputed, so let's keep only one message */)
	   /* Messages are different */
	   && strcmp(flow->risk_infos[i].info, risk_message)
	   && (strstr(flow->risk_infos[i].info, risk_message) == NULL)
	   ) {
	  char buf[1024];

	  /* Concatenate risks info */
	  snprintf(buf, sizeof(buf), "%s;%s",
		   flow->risk_infos[i].info, risk_message);

	  ndpi_free(flow->risk_infos[i].info);
	  flow->risk_infos[i].info = ndpi_strdup(buf);
	}

        return;
      }

    /* Risk already set without any details, but now we have a specific risk_message
       that we want to save.
       This might happen with NDPI_HTTP_CRAWLER_BOT which might have been set early via
       IP matching (no details) and now via UA matching (with message). */
    if(flow->num_risk_infos < MAX_NUM_RISK_INFOS) {
      char *s = ndpi_strdup(risk_message);

      if(s != NULL) {
        flow->risk_infos[flow->num_risk_infos].id = r;
        flow->risk_infos[flow->num_risk_infos].info = s;
        flow->num_risk_infos++;
      }
    }
  }
}

/* ******************************************************************** */

void ndpi_unset_risk(struct ndpi_detection_module_struct *ndpi_str,
                     struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  if(ndpi_isset_risk(flow, r)) {
    u_int8_t i, j;
    ndpi_risk v = 1ull << r;

    flow->risk &= ~v;

    if(!is_flowrisk_info_enabled(ndpi_str, r))
      return;

    for(i = 0; i < flow->num_risk_infos; i++) {
      if(flow->risk_infos[i].id == r) {
        flow->risk_infos[i].id = 0;
        if(flow->risk_infos[i].info) {
          ndpi_free(flow->risk_infos[i].info);
          flow->risk_infos[i].info = NULL;
        }
        for(j = i + 1; j < flow->num_risk_infos; j++) {
          flow->risk_infos[j - 1].id = flow->risk_infos[j].id;
          flow->risk_infos[j - 1].info = flow->risk_infos[j].info;
        }
        flow->num_risk_infos--;
      }
    }
  }
}

/* ******************************************************************** */

int ndpi_isset_risk(struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  ndpi_risk v = 1ull << r;

  return(((flow->risk & v) == v) ?  1 : 0);
}

/* ******************************************************************** */

int ndpi_is_printable_buffer(u_int8_t const * const buf, size_t len) {
  int retval = 1;
  size_t i;

  for(i = 0; i < len; ++i) {
    if(ndpi_isprint(buf[i]) == 0) {
      retval = 0;
    }
  }

  return retval;
}

/* ******************************************************************** */

int ndpi_normalize_printable_string(char * const str, size_t len) {
  int retval = 1;
  size_t i;

  for(i = 0; i < len; ++i) {
    if(ndpi_isprint(str[i]) == 0) {
      str[i] = '?';
      retval = 0;
    }
  }

  return retval;
}

/* ******************************************************************** */

/*
  This function checks if a symbolic hostname is valid or not.

  Validation Rules Implemented:
  - Hostname must not be NULL or empty
  - Total length must be b$ 253 characters
  - Each label (part between dots) must be 1-63 characters
  - Can only contain alphanumeric characters and hyphens
  - Each label must start and end with a letter or digit
  - Must not start or end with a dot
  - Must contain at least one label
*/
bool ndpi_is_valid_hostname(char * const hostname, size_t len) {
  const char *p;
  size_t label_len = 0, idx = 0;
  bool has_valid_label = false;

  if(!hostname || len == 0 || *hostname == '\0')
    return(false); /* Empty string or NULL pointer */

  if(len > 253) /* Maximum length of a full hostname */
    return(false);

  /* Check each label (part between dots) */
  p = hostname;

  while ((idx < len) && *p) {
    if(*p == '.') {
      /* Check previous label */
      if(label_len == 0 || (label_len > 63))
	return(false); /* Empty label or too long */

      label_len = 0;
      idx++;
      p++;
      has_valid_label = true;
      continue;
    }

    if(!(isalnum((unsigned char)*p) || *p == '-'))
      return(false); /* Invalid character */

    /* Check first and last character of label */
    if(label_len == 0) {
      if(!isalnum((unsigned char)*p))
	return(false); /* Label must start with letter or digit */
    }

    label_len++;
    if(label_len > 63)
      return(false); /* Label too long */

    idx++;
    p++;
  }

  /* Check last label */
  if(label_len == 0)
    return(false); /* Ends with a dot */

  if(!isalnum(hostname[idx-1]))
    return(false); /* Label must end with letter or digit */

  return(has_valid_label || len > 0); /* At least one label exists */
}

/* ******************************************************************** */

float ndpi_entropy(u_int8_t const * const buf, size_t len) {
  float entropy = 0.0f;
  u_int32_t byte_counters[256];
  size_t i;

  memset(byte_counters, 0, sizeof(byte_counters));

  for(i = 0; i < len; ++i) {
    byte_counters[buf[i]]++;
  }

  for(i = 0; i < sizeof(byte_counters) / sizeof(byte_counters[0]); ++i) {
    if(byte_counters[i] == 0) {
      continue;
    }

    float const p = (float)byte_counters[i] / len;
    entropy += p * log2f(1 / p);
  }

  return entropy;
}

/* ******************************************************************** */

/* Losely implemented by: https://redirect.cs.umbc.edu/courses/graduate/CMSC691am/student%20talks/CMSC%20691%20Malware%20-%20Entropy%20Analysis%20Presentation.pdf */
char *ndpi_entropy2str(float entropy, char *buf, size_t len) {
  if (buf == NULL) {
    return NULL;
  }

  static const char entropy_fmtstr[] = "Entropy: %.3f (%s?)";
  if (NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(entropy)) {
    snprintf(buf, len, entropy_fmtstr, entropy, "Encrypted or Random");
  } else if (NDPI_ENTROPY_EXECUTABLE_ENCRYPTED(entropy)) {
    snprintf(buf, len, entropy_fmtstr, entropy, "Encrypted Executable");
  } else if (NDPI_ENTROPY_EXECUTABLE_PACKED(entropy)) {
    snprintf(buf, len, entropy_fmtstr, entropy, "Compressed Executable");
  } else if (NDPI_ENTROPY_EXECUTABLE(entropy)) {
    snprintf(buf, len, entropy_fmtstr, entropy, "Executable");
  } else {
    snprintf(buf, len, entropy_fmtstr, entropy, "Unknown");
  }

  return buf;
}

/* ******************************************************************** */

void ndpi_entropy2risk(struct ndpi_detection_module_struct *ndpi_struct,
                       struct ndpi_flow_struct *flow) {
  char str[64];

  if (NDPI_ENTROPY_PLAINTEXT(flow->entropy))
    goto reset_risk;

  if (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TLS ||
      flow->detected_protocol_stack[1] == NDPI_PROTOCOL_TLS ||
      flow->detected_protocol_stack[0] == NDPI_PROTOCOL_QUIC ||
      flow->detected_protocol_stack[1] == NDPI_PROTOCOL_QUIC ||
      flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DTLS ||
      flow->detected_protocol_stack[1] == NDPI_PROTOCOL_DTLS) {
    flow->skip_entropy_check = 1;
    goto reset_risk;
  }

  if (flow->confidence != NDPI_CONFIDENCE_DPI &&
      flow->confidence != NDPI_CONFIDENCE_DPI_CACHE) {
    ndpi_set_risk(ndpi_struct, flow, NDPI_SUSPICIOUS_ENTROPY,
                  ndpi_entropy2str(flow->entropy, str, sizeof(str)));
    return;
  }

  if (ndpi_isset_risk(flow, NDPI_MALWARE_HOST_CONTACTED) ||
      ndpi_isset_risk(flow, NDPI_BINARY_DATA_TRANSFER) ||
      ndpi_isset_risk(flow, NDPI_BINARY_APPLICATION_TRANSFER) ||
      ndpi_isset_risk(flow, NDPI_POSSIBLE_EXPLOIT) ||
      ndpi_isset_risk(flow, NDPI_HTTP_SUSPICIOUS_CONTENT) ||
      ndpi_isset_risk(flow, NDPI_DNS_SUSPICIOUS_TRAFFIC) ||
      ndpi_isset_risk(flow, NDPI_MALFORMED_PACKET) ||
      (flow->category == NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT &&
       (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
        flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP)) ||
      flow->category == NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER ||
      flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED ||
      flow->category == NDPI_PROTOCOL_CATEGORY_WEB)
  {
    ndpi_set_risk(ndpi_struct, flow, NDPI_SUSPICIOUS_ENTROPY,
                  ndpi_entropy2str(flow->entropy, str, sizeof(str)));
    return;
  }

reset_risk:
  ndpi_unset_risk(ndpi_struct, flow, NDPI_SUSPICIOUS_ENTROPY);
}

/* ******************************************************************** */

static inline u_int16_t get_n16bit(u_int8_t const * cbuf) {
  u_int16_t r = ((u_int16_t)cbuf[0]) | (((u_int16_t)cbuf[1]) << 8);
  return r;
}

u_int16_t icmp4_checksum(const u_int8_t * buf, size_t len) {
  u_int32_t checksum = 0;

  /*
   * The first two bytes of the icmp header are required.
   * The next two bytes is the checksum, which we want to ignore.
   */

  for(; len > 1; len -= 2) {
    checksum += get_n16bit(buf);
    buf += 2;
  }

  if(len == 1) {
    checksum += *buf;
  }

  checksum = (checksum >> 16) + (checksum & 0xFFFF);
  checksum += (checksum >> 16);

  return ~checksum;
}

/* ******************************************* */

char* ndpi_get_flow_name(struct ndpi_flow_struct *flow) {
  if(!flow) goto no_flow_info;

  if(flow->host_server_name[0] != '\0')
    return((char*)flow->host_server_name);

 no_flow_info:
  return((char*)"");
}

/* ******************************************* */

void load_common_alpns(struct ndpi_detection_module_struct *ndpi_str) {
  /* see: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
  const char* const common_alpns[] = {
    "http/0.9", "http/1.0", "http/1.1",
    "spdy/1", "spdy/2", "spdy/3", "spdy/3.1",
    "stun.turn", "stun.nat-discovery",
    "h2", "h2c", "h2-16", "h2-15", "h2-14", "h2-fb",
    "webrtc", "c-webrtc",
    "ftp", "imap", "pop3", "managesieve", "coap",
    "xmpp-client", "xmpp-server",
    "acme-tls/1",
    "mqtt", "dot", "ntske/1", "sunrpc",
    "h3",
    "smb",
    "irc",

    /* QUIC ALPNs */
    "h3-T051", "h3-T050",
    "h3-34", "h3-33", "h3-32", "h3-31", "h3-30", "h3-29", "h3-28", "h3-27", "h3-24", "h3-22",
    "hq-34", "hq-33", "hq-32", "hq-31", "hq-30", "hq-29", "hq-28", "hq-27", "hq-interop",
    "h3-fb-05", "h1q-fb",
    "doq-i00",

    /* ApplePush */
    "apns-security-v3", "apns-pack-v1",

    /* LIBP2P */
    "/yamux/1.0.0", "libp2p",

    NULL /* end */
  };
  u_int i;

  for(i=0; common_alpns[i] != NULL; i++) {
    AC_PATTERN_t ac_pattern;

    memset(&ac_pattern, 0, sizeof(ac_pattern));
    ac_pattern.astring      = ndpi_strdup((char*)common_alpns[i]);
    if(!ac_pattern.astring) {
      NDPI_LOG_ERR(ndpi_str, "Unable to add %s [mem alloc error]\n", common_alpns[i]);
      continue;
    }
    ac_pattern.length       = strlen(common_alpns[i]);

    if(ac_automata_add(ndpi_str->common_alpns_automa.ac_automa, &ac_pattern) != ACERR_SUCCESS) {
      ndpi_free(ac_pattern.astring);
      NDPI_LOG_ERR(ndpi_str, "Unable to add %s\n", common_alpns[i]);
    }
  }
}

/* ******************************************* */

u_int8_t is_a_common_alpn(struct ndpi_detection_module_struct *ndpi_str,
			  const char *alpn_to_check, u_int alpn_to_check_len) {
  ndpi_automa *automa = &ndpi_str->common_alpns_automa;

  if(automa->ac_automa) {
    AC_TEXT_t ac_input_text;
    AC_REP_t match;

    memset(&match, 0, sizeof(match));
    ac_input_text.astring = (char*)alpn_to_check, ac_input_text.length = alpn_to_check_len;
    ac_input_text.option = 0;

    if(ac_automata_search(automa->ac_automa, &ac_input_text, &match) > 0)
      return(1);
  }

  return(0);
}

/* ******************************************* */

u_int8_t ndpi_is_valid_protoId(const struct ndpi_detection_module_struct *ndpi_str, u_int16_t protoId) {
  if(!ndpi_str)
    return 0;
  return(protoId >= ndpi_str->num_supported_protocols ? 0 : 1);
}

/* ******************************************* */

u_int8_t ndpi_is_encrypted_proto(struct ndpi_detection_module_struct *ndpi_str,
                                 ndpi_master_app_protocol proto) {
  if(proto.master_protocol == NDPI_PROTOCOL_UNKNOWN && ndpi_is_valid_protoId(ndpi_str, proto.app_protocol)) {
    return(!ndpi_str->proto_defaults[proto.app_protocol].isClearTextProto);
  } else if(ndpi_is_valid_protoId(ndpi_str, proto.master_protocol) && ndpi_is_valid_protoId(ndpi_str, proto.app_protocol)) {
    if(ndpi_str->proto_defaults[proto.master_protocol].isClearTextProto
       && (!ndpi_str->proto_defaults[proto.app_protocol].isClearTextProto))
      return(0);
    else
      return((ndpi_str->proto_defaults[proto.master_protocol].isClearTextProto
	      && ndpi_str->proto_defaults[proto.app_protocol].isClearTextProto) ? 0 : 1);
  } else
    return(0);
}

/* ******************************************* */

u_int32_t ndpi_get_flow_error_code(struct ndpi_flow_struct *flow) {
  switch(flow->detected_protocol_stack[0] /* proto.app_protocol */) {
  case NDPI_PROTOCOL_DNS:
    return(flow->protos.dns.reply_code);

  case NDPI_PROTOCOL_HTTP:
    return(flow->http.response_status_code);

  case NDPI_PROTOCOL_SNMP:
    return(flow->protos.snmp.error_status);
 }

  return(0);
}

/* ******************************************* */

int ndpi_vsnprintf(char * str, size_t size, char const * format, va_list va_args)
{
#ifdef WIN32
  if((str == NULL) || (size == 0) || (format == NULL)) {
    return -1;
  }

  int ret = vsnprintf_s(str, size, _TRUNCATE, format, va_args);

  if(ret < 0) {
    return size;
  } else {
    return ret;
  }
#else
  return vsnprintf(str, size, format, va_args);
#endif
}

/* ******************************************* */

struct tm *ndpi_gmtime_r(const time_t *timep,
                         struct tm *result)
{
#if defined(WIN32)
  gmtime_s(result, timep);
  return result;
#else
  return gmtime_r(timep, result);
#endif
}

/* ******************************************* */

int ndpi_snprintf(char * str, size_t size, char const * format, ...) {
  va_list va_args;

  va_start(va_args, format);
  int rc = ndpi_vsnprintf(str, size, format, va_args);
  va_end(va_args);

  /*
    ndpi_snprintf wraps standard snprintf, which returns the number of characters that would
    have been written (not the number actually written) when the output is truncated.
    So if rc >= size, only size - 1 characters were actually written, but tls_s_len is
    advanced by rc. This has two consequences:
  */

  if(rc >= (int)size)
    rc = size - 1;

  return(rc);
}

/* ******************************************* */

static int risk_infos_pair_cmp (const void *_a, const void *_b)
{
  struct ndpi_risk_information *a = (struct ndpi_risk_information *)_a;
  struct ndpi_risk_information *b = (struct ndpi_risk_information *)_b;

  return b->id - a->id;
}

/* ******************************************* */

char* ndpi_get_flow_risk_info(struct ndpi_flow_struct *flow,
			      char *out, u_int out_len,
			      u_int8_t use_json) {
  u_int i, offset = 0;
  struct ndpi_risk_information *ordered_risk_infos;

  if((out == NULL)
     || (flow == NULL)
     || (flow->num_risk_infos == 0))
    return(NULL);

  /* Ordered list of flow risk infos */
  ordered_risk_infos = ndpi_malloc(sizeof(flow->risk_infos));
  if(!ordered_risk_infos)
    return(NULL);

  memcpy(ordered_risk_infos, flow->risk_infos, sizeof(flow->risk_infos));
  qsort(ordered_risk_infos, flow->num_risk_infos,
	sizeof(struct ndpi_risk_information), risk_infos_pair_cmp);

  if(use_json) {
    ndpi_serializer serializer;
    u_int32_t buffer_len;
    char *buffer;

    if(ndpi_init_serializer(&serializer, ndpi_serialization_format_json) == -1) {
      ndpi_free(ordered_risk_infos);
      return(NULL);
    }

    for(i=0; i<flow->num_risk_infos; i++)
      ndpi_serialize_uint32_string(&serializer,
                                   ordered_risk_infos[i].id,
                                   ordered_risk_infos[i].info);

    buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

    if(buffer && (buffer_len > 0)) {
      u_int l = ndpi_min(out_len-1, buffer_len);

      strncpy(out, buffer, l);
      out[l] = '\0';
    }

    ndpi_term_serializer(&serializer);

    ndpi_free(ordered_risk_infos);
    return(out);
  } else {
    out[0] = '\0', out_len--;

    for(i=0; (i<flow->num_risk_infos) && (out_len > offset); i++) {
      int rc = snprintf(&out[offset], out_len-offset, "%s%s",
			(i == 0) ? "" : ";",
			ordered_risk_infos[i].info);

      if(rc <= 0)
	break;
      else
	offset += rc;
    }

    if(offset > out_len) offset = out_len;

    out[offset] = '\0';

    ndpi_free(ordered_risk_infos);
    return(out[0] == '\0' ? NULL : out);
  }
}

/* ******************************************* */
/*
  This function checks if a flow having the specified risk
  parameters is an exception (i.e. the flow risk should not
  be triggered) or not.

  You can use this function to check if a flow that
  as a flow risk will match an exception or not.
*/
u_int8_t ndpi_check_flow_risk_exceptions(struct ndpi_detection_module_struct *ndpi_str,
					 u_int num_params,
					 ndpi_risk_params params[]) {
  u_int i;

  if(!ndpi_str)
    return(0);

  for(i=0; i<num_params; i++) {
    switch(params[i].id) {
    case NDPI_PARAM_HOSTNAME:
      if(ndpi_check_hostname_risk_exception(ndpi_str, NULL, (char*)params[i].value))
	return(1);
      break;

    case NDPI_PARAM_ISSUER_DN:
      if(ndpi_check_issuerdn_risk_exception(ndpi_str, (char*)params[i].value))
	return(1);
      break;

    case NDPI_PARAM_HOST_IPV4:
      if(ndpi_check_ipv4_exception(ndpi_str, NULL, *((u_int32_t*)params[i].value)))
	return(1);
      break;

    default:
      NDPI_LOG_ERR(ndpi_str, "Ignored risk parameter id %u\n", params[i].id);
      break;
    }
  }

  return(0);
}

/* ******************************************* */

int64_t asn1_ber_decode_length(const unsigned char *payload, int payload_len, u_int16_t *value_len) {
  unsigned int value, i;

  if(payload_len <= 0)
    return -1;

  /* Malformed */
  if(payload[0] == 0xFF)
    return -1;

  /* Definite, short */
  if(payload[0] <= 0x80) {
    *value_len = 1;
    return payload[0];
  }
  /* Indefinite, unsupported */
  if((payload[0] & 0x7F) == 0)
    return -1;

  *value_len = payload[0] & 0x7F;
  /* We support only 4 additional length octets */
  if(*value_len > 4 ||
     payload_len <= *value_len + 1)
    return -1;

  value = 0;
  for (i = 1; i <= *value_len; i++) {
    value |= (unsigned int)payload[i] << ((*value_len) - i) * 8;
  }

  (*value_len) += 1;
  return value;
}

/* ******************************************* */

char* ndpi_intoav4(unsigned int addr, char* buf, u_int16_t bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return(cp);
}

/* ****************************************************** */

char* ndpi_intoav6(struct ndpi_in6_addr *addr, char* buf, u_int16_t bufLen) {
  char *ret;
  const u_int8_t use_brackets = 0;

  if(use_brackets == 0) {
    ret = (char*)inet_ntop(AF_INET6, (struct in6_addr *)addr, buf, bufLen);

    if(ret == NULL) {
      /* Internal error (buffer too short */
      buf[0] = '\0';
    }
  } else {
    ret = (char*)inet_ntop(AF_INET6, (struct in6_addr *)addr, &buf[1], bufLen-1);

    if(ret == NULL) {
      /* Internal error (buffer too short) */
      buf[0] = '\0';
    } else {
      int len = strlen(ret);

      buf[0] = '[';
      buf[len+1] = ']';
      buf[len+2] = '\0';
    }
  }

  return(buf);
}

/* ******************************************* */

/* Find the nearest (>=) value of x */
u_int32_t ndpi_nearest_power_of_two(u_int32_t x) {
  x--;

  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;

  x++;
  return(x);
}

/* ******************************************* */

int tpkt_verify_hdr(const struct ndpi_packet_struct * const packet) {
  return ((packet->tcp != NULL) && (packet->payload_packet_len > 4) &&
          (packet->payload[0] == 3) && (packet->payload[1] == 0) &&
          (get_u_int16_t(packet->payload,2) == htons(packet->payload_packet_len)));
}

/* ******************************************* */

int64_t ndpi_strtonum(const char *numstr, int64_t minval,
		      int64_t maxval, const char **errstrp, int base) {
  int64_t val = 0;
  char* endptr;

  if (minval > maxval) {
    *errstrp = "minval > maxval";
    return 0;
  }

  errno = 0;    /* To distinguish success/failure after call */
  val = (int64_t)strtoll(numstr, &endptr, base);

  if((val == LLONG_MIN && errno == ERANGE) || (val < minval)) {
    *errstrp = "value too small";
    return 0;
  }

  if((val == LLONG_MAX && errno == ERANGE) || (val > maxval )) {
    *errstrp = "value too large";
    return 0;
  }

  if(errno != 0 && val == 0) {
    *errstrp = "generic error";
    return 0;
  }

  if(endptr == numstr) {
    *errstrp = "No digits were found";
    return 0;
  }
  /* Like the original strtonum, we allow further characters after the number */

  *errstrp = NULL;
  return val;
}

/* ****************************************************** */

char* ndpi_strrstr(const char *haystack, const char *needle) {
  if (!haystack || !needle) {
    return NULL;
  }

  if (*needle == '\0') {
    return (char*) haystack + strlen(haystack);
  }

  const char *last_occurrence = NULL;

  while (true) {
    const char *current_pos = strstr(haystack, needle);

    if (!current_pos) {
      break;
    }

    last_occurrence = current_pos;
    haystack = current_pos + 1;
  }

  return (char*) last_occurrence;
}

/* ************************************************************** */

void *ndpi_memrchr(const void *m, int c, size_t n) {
  const unsigned char *s = m;

  c = (unsigned char)c;
  while(n--)
    if(s[n]==c)
      return (void *)(s+n);

  return 0;
}


/* ************************************************************** */

int ndpi_str_endswith(const char *s, const char *suffix) {
  size_t slen = strlen(s);
  size_t suffixlen = strlen(suffix);

  return((slen >= suffixlen) && (!memcmp(&s[slen - suffixlen], suffix, suffixlen)));
}

/* ******************************************* */

const char *ndpi_lru_cache_idx_to_name(lru_cache_type idx)
{
  const char *names[NDPI_LRUCACHE_MAX] = { "ookla", "bittorrent", "stun",
                                           "tls_cert", "mining", "msteams",
                                           "fpc_dns", "signal" };

  if(idx < 0 || idx >= NDPI_LRUCACHE_MAX)
    return "unknown";
  return names[idx];
}

/* ******************************************* */

size_t ndpi_compress_str(const char * in, size_t len, char * out, size_t bufsize) {
  size_t ret = shoco_compress(in, len, out, bufsize);

  if(ret > bufsize)
    return(0); /* Better not to compress data (it is longer than the uncompressed data) */

  return(ret);
}

/* ******************************************* */

size_t ndpi_decompress_str(const char * in, size_t len, char * out, size_t bufsize) {
  return(shoco_decompress(in, len, out, bufsize));
}

/* ******************************************* */

static u_char ndpi_domain_mapper[256];
static bool ndpi_domain_mapper_initialized = false;

#define IGNORE_CHAR           0xFF
#define NUM_BITS_NIBBLE       6 /* each 'nibble' is encoded with 6 bits */
#define NIBBLE_ELEM_OFFSET    24

/* Used fo encoding domain names 8 bits -> 6 bits */
static void ndpi_domain_mapper_init() {
  u_int i;
  u_char idx = 1 /* start from 1 to make sure 0 is no ambiguous */;

  memset(ndpi_domain_mapper, IGNORE_CHAR, 256);

  for(i='a'; i<= 'z'; i++)
    ndpi_domain_mapper[i] = idx++;

  for(i='0'; i<= '9'; i++)
    ndpi_domain_mapper[i] = idx++;

  ndpi_domain_mapper['-'] = idx++;
  ndpi_domain_mapper['_'] = idx++;
  ndpi_domain_mapper['.'] = idx++;
}

/* ************************************************ */

u_int ndpi_encode_domain(struct ndpi_detection_module_struct *ndpi_str,
			 const char *domain, char *out, u_int out_len) {
  u_int out_idx = 0, i, buf_shift = 0, domain_buf_len, compressed_len, suffix_len, domain_len;
  u_int32_t value = 0;
  u_char domain_buf[256], compressed[128];
  u_int64_t domain_id = 0;
  const char *suffix;

  if(!ndpi_domain_mapper_initialized) {
    ndpi_domain_mapper_init();
    ndpi_domain_mapper_initialized = true;
  }

  domain_len = strlen(domain);

  if(domain_len >= (out_len-3))
    return(0);

  if(domain_len <= 4)
    return((u_int)snprintf(out, out_len, "%s", domain));  /* Too short */

  /* [1] Encode the domain in 6 bits */
  suffix = ndpi_get_host_domain_suffix(ndpi_str, domain, &domain_id);

  if(suffix == NULL)
    return((u_int)snprintf(out, out_len, "%s", domain));  /* Unknown suffix */

  snprintf((char*)domain_buf, sizeof(domain_buf), "%s", domain);
  domain_buf_len = strlen((char*)domain_buf), suffix_len = strlen(suffix);

  if(domain_buf_len > suffix_len) {
    snprintf((char*)domain_buf, sizeof(domain_buf), "%s", domain);
    domain_buf_len = domain_buf_len-suffix_len-1;
    domain_buf[domain_buf_len] = '\0';

    for(i=0; domain_buf[i] != '\0'; i++) {
      u_int32_t mapped_idx = ndpi_domain_mapper[domain_buf[i]];

      if(mapped_idx != IGNORE_CHAR) {
	mapped_idx <<= buf_shift;
	value |= mapped_idx, buf_shift += NUM_BITS_NIBBLE;

	if(buf_shift == NIBBLE_ELEM_OFFSET) {
	  out[out_idx++] = value & 0xFF;
	  out[out_idx++] = (value >> 8) & 0xFF;
	  out[out_idx++] = (value >> 16) & 0xFF;
	  buf_shift = 0; /* Move to the next buffer */
	  value = 0;
	}
      }
    }

    if(buf_shift != 0) {
      u_int j, bytes = buf_shift / NUM_BITS_NIBBLE;

      for(j = 0; j < bytes; j++)
        out[out_idx++] = (value >> (j * 8)) & 0xFF;
    }
  }

  /* [2] Check if compressing the string is more efficient */
  compressed_len = ndpi_compress_str((char*)domain_buf, domain_buf_len,
				     (char*)compressed, sizeof(compressed));

  if((compressed_len > 0) && ((out_idx == 0) || (compressed_len < out_idx))) {
    if(compressed_len >= domain_len) {
      /* Compression creates a longer buffer */
      return((u_int)snprintf(out, out_len, "%s", domain));
    } else {
      compressed_len = ndpi_min(ndpi_min(compressed_len, sizeof(compressed)), out_len-3);
      memcpy(out, compressed, compressed_len);
      out_idx = compressed_len;
    }
  }

  /* Add trailer domainId value */
  out[out_idx++] = (domain_id >> 8) & 0xFF;
  out[out_idx++] = domain_id & 0xFF;

#ifdef DEBUG
  {
    u_int i;

    fprintf(stdout, "%s [len: %u][", domain, out_idx);
    for(i=0; i<out_idx; i++) fprintf(stdout, "%02X", out[i] & 0xFF);
    fprintf(stdout, "]\n");
  }
#endif

  return(out_idx);
}

/* ****************************************************** */

static u_int8_t is_ndpi_proto(struct ndpi_flow_struct *flow, u_int16_t id) {
  if((flow->detected_protocol_stack[0] == id)
     || (flow->detected_protocol_stack[1] == id))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

bool ndpi_serialize_flow_fingerprint(struct ndpi_detection_module_struct *ndpi_str,
				     struct ndpi_flow_struct *flow, ndpi_serializer *serializer) {
  if(is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) || is_ndpi_proto(flow, NDPI_PROTOCOL_QUIC)) {
    if((flow->protos.tls_quic.ja4_client_raw != NULL)
       || (flow->protos.tls_quic.ja4_client[0] != '\0')) {

      if(flow->protos.tls_quic.ja4_client_raw != NULL)
	ndpi_serialize_string_string(serializer, "JA4r", flow->protos.tls_quic.ja4_client_raw);

      ndpi_serialize_string_string(serializer, "JA4", flow->protos.tls_quic.ja4_client);

      if(flow->host_server_name[0] != '\0') {
	ndpi_serialize_string_string(serializer, "sni", flow->host_server_name);

	ndpi_serialize_string_string(serializer, "sni_domain",
				     ndpi_get_host_domain(ndpi_str,
							  flow->host_server_name));
      }

      return(true);
    }
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_DHCP)
	    && (flow->protos.dhcp.fingerprint[0] != '\0')) {
    ndpi_serialize_string_string(serializer, "options", flow->protos.dhcp.options);
    ndpi_serialize_string_string(serializer, "fingerprint", flow->protos.dhcp.fingerprint);

    if(flow->protos.dhcp.class_ident[0] != '\0')
      ndpi_serialize_string_string(serializer, "class_identifier", flow->protos.dhcp.class_ident);

    return(true);
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)
	    && (flow->protos.ssh.hassh_client[0] != '\0')) {

    ndpi_serialize_string_string(serializer, "hassh_client", flow->protos.ssh.hassh_client);
    ndpi_serialize_string_string(serializer, "client_signature", flow->protos.ssh.client_signature);
    ndpi_serialize_string_string(serializer, "hassh_server", flow->protos.ssh.hassh_server);
    ndpi_serialize_string_string(serializer, "server_signature", flow->protos.ssh.server_signature);

    return(true);
  }

  return(false);
}

/* ****************************************************** */

u_int ndpi_hex2bin(u_char *out, u_int out_len, u_char* in, u_int in_len) {
  u_int i, j;

  if(((in_len+1) / 2) > out_len)
    return(0);

  for(i=0, j=0; i<in_len; i += 2, j++) {
    char buf[3];

    buf[0] = in[i], buf[1] = in[i+1], buf[2] = '\0';
    out[j] = strtol(buf, NULL, 16);
  }

  return(j);
}

/* ****************************************************** */

u_int ndpi_bin2hex(u_char *out, u_int out_len, u_char* in, u_int in_len) {
  u_int i, j;

  if (out_len < (in_len*2)) {
    out[0] = '\0';
    return(0);
  }

  for(i=0, j=0; i<in_len; i++) {
    snprintf((char*)&out[j], out_len-j, "%02X", in[i]);
    j += 2;
  }

  return(j);
}

/* ****************************************************** */
/* ****************************************************** */

#include "third_party/include/aes.h"

/*
  IMPORTANT: the returned string (if not NULL) must be freed
*/
char* ndpi_quick_encrypt(const char *cleartext_msg,
			 u_int16_t cleartext_msg_len,
			 u_int16_t *encrypted_msg_len,
			 u_char encrypt_key[64]) {
  char *encoded = NULL, *encoded_buf;
  struct AES_ctx ctx;
  int encoded_len, i, n_padding;
  u_char nonce[24] = { 0x0 };
  u_char binary_encrypt_key[32];

  /* AES, as a block cipher, does not change the size. The input size is always the output size.
   * But AES, being a block cipher, requires the input to be multiple of block size (16 bytes). */
  encoded_len = cleartext_msg_len + 16 - (cleartext_msg_len % 16);

  *encrypted_msg_len = 0;
  encoded_buf = (char *)ndpi_calloc(encoded_len, 1);

  if (encoded_buf == NULL) {
    /* Allocation failure */
    return(NULL);
  }

  ndpi_hex2bin(binary_encrypt_key, sizeof(binary_encrypt_key), (u_char*)encrypt_key, 64);

  memcpy(encoded_buf, cleartext_msg, cleartext_msg_len);

  /* PKCS5 Padding (https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html) */
  n_padding = encoded_len - cleartext_msg_len;

  for(i = encoded_len - n_padding; i < encoded_len; i++)
    encoded_buf[i] = n_padding;

  AES_init_ctx_iv(&ctx, binary_encrypt_key, nonce);
  AES_CBC_encrypt_buffer(&ctx, (u_int8_t*)encoded_buf, encoded_len);

  encoded = ndpi_base64_encode((const unsigned char *)encoded_buf, encoded_len);
  ndpi_free(encoded_buf);

  if(encoded)
    *encrypted_msg_len = strlen(encoded);

  return(encoded);
}

/* ************************************************************** */

char* ndpi_quick_decrypt(const char *encrypted_msg,
			 u_int16_t encrypted_msg_len,
			 u_int16_t *decrypted_msg_len,
			 u_char decrypt_key[64]) {
  u_char nonce[24] = { 0x0 };
  u_char binary_decrypt_key[32];
  u_char *content;
  size_t content_len, allocated_decoded_string = encrypted_msg_len + 8 /* padding */;
  char *decoded_string = (char*)ndpi_calloc(sizeof(u_char), allocated_decoded_string);
  u_int n_padding;
  struct AES_ctx ctx;

  *decrypted_msg_len = 0;

  if(decoded_string == NULL) {
    /* Allocation failure */
    return(NULL);
  }

  ndpi_hex2bin(binary_decrypt_key, sizeof(binary_decrypt_key), (u_char*)decrypt_key, 64);

  content = ndpi_base64_decode((const u_char*)encrypted_msg, encrypted_msg_len, &content_len);

  if((content == NULL) || (content_len == 0)) {
    /* Base64 decoding error */
    ndpi_free(decoded_string);
    ndpi_free(content);
    return(NULL);
  }

  if(allocated_decoded_string < (content_len+1)) {
    /* Buffer size failure */
    ndpi_free(decoded_string);
    ndpi_free(content);
    return(NULL);
  }

  /* AES - https://github.com/kokke/tiny-AES-c */
  AES_init_ctx_iv(&ctx, binary_decrypt_key, nonce);
  memcpy(decoded_string, content, content_len);
  AES_CBC_decrypt_buffer(&ctx, (u_int8_t*)decoded_string, content_len);

  /* Remove PKCS5 padding */
  n_padding = decoded_string[content_len-1];

  if(content_len > n_padding) {
    content_len = content_len - n_padding;
    decoded_string[content_len] = 0;
  }

  *decrypted_msg_len = content_len;

  ndpi_free(content);

  return(decoded_string);
}

/* ************************************************************** */

void ndpi_fill_randombytes(unsigned char *buf, unsigned int buf_len) {
  unsigned int i;

  for(i=0; i<buf_len; i++)
    buf[i] = (unsigned char)rand();
}

/* ************************************************************** */

const char* ndpi_print_os_hint(ndpi_os os_hint) {
  switch(os_hint) {
  case ndpi_os_windows:          return("Windows");
  case ndpi_os_macos:            return("macOS");
  case ndpi_os_ios_ipad_os:      return("iOS/iPad");
  case ndpi_os_android:          return("Android");
  case ndpi_os_linux:            return("Linux");
  case ndpi_os_freebsd:          return("FreeBSD");
  default:
    break;
  }

  return("Unknown");
}

/* ************************************************************** */

char* ndpi_strndup(const char *s, size_t size) {
  char *ret = (char*)ndpi_malloc(size+1);

  if(ret == NULL) return(NULL);

  memcpy(ret, s, size);
  ret[size] = '\0';

  return(ret);
}

/* ************************************************************** */

char *ndpi_strip_leading_trailing_spaces(char *ptr, int *ptr_len) {

  /* Stripping leading spaces */
  while(*ptr_len > 0 && ptr[0] == ' ') {
    (*ptr_len)--;
    ptr++;
  }
  if(*ptr_len == 0)
    return NULL;

  /* Stripping trailing spaces */
  while(*ptr_len > 0 && ptr[*ptr_len - 1] == ' ') {
    (*ptr_len)--;
  }
  if(*ptr_len == 0)
    return NULL;

  return ptr;
}

/* ************************************************************** */

ndpi_protocol_qoe_category_t ndpi_find_protocol_qoe(struct ndpi_detection_module_struct *ndpi_str,
						    u_int16_t protoId) {
  if(!ndpi_is_valid_protoId(ndpi_str, protoId))
    return(NDPI_PROTOCOL_QOE_CATEGORY_UNSPECIFIED);
  else
    return(ndpi_str->proto_defaults[protoId].qoeCategory);
}

/* ************************************************************** */

/* https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-rtp.c */
const char* ndpi_rtp_payload_type2str(u_int8_t payload_type, u_int32_t evs_payload_type) {
  switch(payload_type) {
  case 0:   return("ITU-T G.711 PCMU");
  case 1:   return("USA Federal Standard FS-1016");
  case 2:   return("ITU-T G.721");
  case 3:   return("GSM 06.10");
  case 4:   return("ITU-T G.723");
  case 5:   return("DVI4 8000 samples/s");
  case 6:   return("DVI4 16000 samples/s");
  case 8:   return("ITU-T G.711 PCMA");
  case 9:   return("ITU-T G.722");
  case 10:  return("16-bit uncompressed audio, stereo");
  case 11:  return("16-bit uncompressed audio, monaural");
  case 12:  return("Qualcomm Code Excited Linear Predictive coding");
  case 13:  return("Comfort noise");
  case 14:  return("MPEG-I/II Audio");
  case 15:  return("ITU-T G.728");
  case 16:  return("DVI4 11025 samples/s");
  case 17:  return("DVI4 22050 samples/s");
  case 18:  return("ITU-T G.729");
  case 19:  return("Comfort noise (old)");
  case 25:  return("Sun CellB video encoding");
  case 26:  return("JPEG-compressed video");
  case 28:  return("'nv' program");
  case 31:  return("ITU-T H.261");
  case 32:  return("MPEG-I/II Video");
  case 33:  return("MPEG-II transport streams");
  case 34:  return("ITU-T H.263");
  case 98:  return("AMR-WB");
  case 118: return("AMR"); /* Adptive Multirate */
  case 126: /* Enhanced Voice Services */
  case 127: /* Enhanced Voice Services */
    {
      switch(evs_payload_type) {
	/* https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-evs.c */

      case 0x0: return("AMR-WB IO 6.6 kbps");
      case 0x1: return("AMR-WB IO 8.85 kbps");
      case 0x2: return("AMR-WB IO 12.65 kbps");
      case 0x3: return("AMR-WB IO 14.24 kbps");
      case 0x4: return("AMR-WB IO 15.85 kbps");
      case 0x5: return("AMR-WB IO 18.25 kbps");
      case 0x6: return("AMR-WB IO 19.85 kbps");
      case 0x7: return("AMR-WB IO 23.05 kbps");
      case 0x8: return("AMR-WB IO 23.85 kbps");
      case 0x9: return("AMR-WB IO 2.0 kbps SID");

	/* ** */
	/* Dummy SWB 30 offset */
      case 0x3+30: return("SWB 9.6 kbps");
      case 0x4+30: return("SWB 13.2 kbps");
      case 0x5+30: return("SWB 16.4 kbps");
      case 0x6+30: return("SWB 24.4 kbps");
      case 0x7+30: return("SWB 32 kbps");
      case 0x8+30: return("SWB 48 kbps");
      case 0x9+30: return("SWB 64 kbps");
      case 0xa+30: return("SWB 96 kbps");
      case 0xb+30: return("SWB 128 kbps");


      case    48: return("EVS Primary SID 2.4");
      case   136: return("EVS AMR-WB IO 6.6");
      case   144: return("EVS Primary 7.2");
      case   160: return("EVS Primary 8.0");
      case   184: return("EVS AMR-WB IO 8.85");
      case   192: return("EVS Primary 9.6");
      case   256: return("EVS AMR-WB IO 12.65");
      case   264: return("EVS Primary 13.2");
      case   288: return("EVS AMR-WB IO 14.25");
      case   320: return("EVS AMR-WB IO 15.85");
      case   328: return("EVS Primary 16.4");
      case   368: return("EVS AMR-WB IO 18.25");
      case   400: return("EVS AMR-WB IO 19.85");
      case   464: return("EVS AMR-WB IO 23.05");
      case   480: return("EVS AMR-WB IO 23.85");
      case   488: return("EVS Primary 24.4");
      case   640: return("EVS Primary 32.0");
      case   960: return("EVS Primary 48.0");
      case  1280: return("EVS Primary 64.0");
      case  1920: return("EVS Primary 96.0");
      case  2560: return("EVS Primary 128.0");
      default:    return("EVS 13.2");
      }
    }
    break;
  default:  return("Unknown");
  }
}

/* ************************************************************** */

u_char* ndpi_str_to_utf8(u_char *in, u_int in_len, u_char *out, u_int out_len) {
  if(out_len < ((in_len*2)+1)) {
    out[0] = '\0';
  } else {
    u_int i = 0, j = 0;

    while((i < in_len) && (in[i] != '\0')) {
      if(in[i] < 0x80) {
	out[j] = in[i];
	i++, j++;
      } else {
	out[j] = 0xC0 +(in[i] >> 6);
	j++;
	out[j] = 0x80 | (in[i] & 0x3F);
	i++, j++;
      }
    }

    out[j] = '\0';
  }

  return(out);
}

/* ************************************************************** */

/*
    The function below checks whether the specified protocol is a
      "real" master protocol or not, meaning that the protocol cannot
        be encapsulated on another nDPI protocol.
*/
bool ndpi_is_master_only_protocol(struct ndpi_detection_module_struct *ndpi_str,
				  u_int16_t proto_id) {
  if(!ndpi_is_valid_protoId(ndpi_str, proto_id))
    return(false);
  else
    return(ndpi_str->proto_defaults[proto_id].isAppProtocol ? false : true);
}

/* ************************************************************** */

bool ndpi_normalize_protocol(struct ndpi_detection_module_struct *ndpi_str,
			     ndpi_master_app_protocol *proto) {
  /* Move app to master when not an application protocol */
  if((proto->master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (proto->app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
    if(ndpi_is_master_only_protocol(ndpi_str, proto->app_protocol)) {
      proto->master_protocol = proto->app_protocol;
      proto->app_protocol = NDPI_PROTOCOL_UNKNOWN;
      return(true);
    } else {
      #ifdef DEBUG
      NDPI_LOG_ERR(ndpi_str, "INTERNAL ERROR: unexpected protocol combination %u.%u/%s",
		   proto->master_protocol, proto->app_protocol,
		   ndpi_get_proto_name(ndpi_str, proto));
      #endif
    }
  }

  /* Remove duplicate protocols */
  if((proto->master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto->master_protocol == proto->app_protocol)) {
    if(ndpi_is_master_only_protocol(ndpi_str, proto->app_protocol)) {
      proto->master_protocol = proto->app_protocol;
      proto->app_protocol = NDPI_PROTOCOL_UNKNOWN;
      return(true);
    } else {
      proto->master_protocol = NDPI_PROTOCOL_UNKNOWN;
      return(true);
    }
  }

  return(false);
}



int ndpi_bitmask_alloc(struct ndpi_bitmask *b, u_int16_t max_bits)
{
  if(!b)
    return -1;
  b->fds = ndpi_calloc(howmanybits(max_bits, sizeof(ndpi_ndpi_mask)), sizeof(ndpi_ndpi_mask));
  if(!b->fds)
    return -1;
  b->max_bits = max_bits;
  b->num_fds = howmanybits(max_bits, sizeof(ndpi_ndpi_mask));
  return 0;
}

void ndpi_bitmask_free(struct ndpi_bitmask *b)
{
  if(b) {
    ndpi_free(b->fds);
    b->num_fds = 0;
  }
}

void ndpi_bitmask_set(struct ndpi_bitmask *b, u_int16_t bit)
{
  if(b && b->fds && bit < b->max_bits)
    b->fds[bit / 32] |= (1ul << (bit % 32));
}

void ndpi_bitmask_clear(struct ndpi_bitmask *b, u_int16_t bit)
{
  if(b && b->fds && bit < b->max_bits)
    b->fds[bit / 32] &= ~(1ul << (bit % 32));
}

int ndpi_bitmask_is_set(const struct ndpi_bitmask *b, u_int16_t bit)
{
  if(b && b->fds && bit < b->max_bits)
    return b->fds[bit / 32] & (1ul << (bit % 32));
  return -1;
}

void ndpi_bitmask_set_all(struct ndpi_bitmask *b)
{
  if(b && b->fds)
    memset(b->fds, 0xFF, b->num_fds * sizeof(ndpi_ndpi_mask));
}

void ndpi_bitmask_reset(struct ndpi_bitmask *b)
{
  if(b && b->fds)
    memset(b->fds, 0x00, b->num_fds * sizeof(ndpi_ndpi_mask));
}

/* **************************************** */

bool ndpi_check_is_numeric_ip(char *host) {
  unsigned char buf[sizeof(struct in6_addr)];

  if(inet_pton(AF_INET, host, buf) == 1)
    return true;
  else if(inet_pton(AF_INET6, host, buf) == 1)
    return true;
  else
    return false;
}

/* **************************************** */

static u_int16_t ndpi_tls_refine_master_protocol(struct ndpi_detection_module_struct *ndpi_struct,
						 struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int32_t protocol;

  if(packet->tcp != NULL) {
    /*
      In case of TLS there are probably sub-protocols
      such as IMAPS that can be otherwise detected
    */
    u_int16_t sport = ntohs(packet->tcp->source);
    u_int16_t dport = ntohs(packet->tcp->dest);

    if(flow->stun.maybe_dtls)
      protocol = NDPI_PROTOCOL_DTLS;
    else if((sport == 465) || (dport == 465) || (sport == 587) || (dport == 587))
      protocol = NDPI_PROTOCOL_MAIL_SMTPS;
    else if((sport == 993) || (dport == 993) || (flow->l4.tcp.mail_imap_starttls))
      protocol = NDPI_PROTOCOL_MAIL_IMAPS;
    else if((sport == 995) || (dport == 995))
      protocol = NDPI_PROTOCOL_MAIL_POPS;
    else
      protocol = NDPI_PROTOCOL_TLS;
  } else {
      protocol = NDPI_PROTOCOL_DTLS;
  }

  return protocol;
}

/* **************************************** */

u_int16_t ndpi_get_master_proto(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow) {
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[1];
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[0];

  return ndpi_tls_refine_master_protocol(ndpi_struct, flow);
}

/* ****************************************** */

void* ndpi_memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
  if (!haystack || !needle || haystack_len < needle_len) {
    return NULL;
  }

  if (needle_len == 0) {
    return (void *)haystack;
  }

  if (needle_len == 1) {
    return (void *)memchr(haystack, *(const u_int8_t *)needle, haystack_len);
  }

  const u_int8_t *const end_of_search = (const u_int8_t *)haystack + haystack_len - needle_len + 1;

  const u_int8_t *current = (const u_int8_t *)haystack;

  while (1) {
    /* Find the first occurrence of the first character from the needle */
    current = (const u_int8_t *)memchr(current, *(const u_int8_t *)needle, end_of_search - current);

    if (!current) {
      return NULL;
    }

    /* Check the rest of the needle for a match */
    if (memcmp(current, needle, needle_len) == 0) {
      return (void *)current;
    }

    /* Shift one character to the right for the next search */
    current++;
  }

  return NULL;
}

/* ****************************************** */

size_t ndpi_strlcpy(char *dst, const char* src, size_t dst_len, size_t src_len) {
  if (!dst || !src || dst_len == 0) {
    return 0;
  }

  size_t copy_len = ndpi_min(src_len, dst_len - 1);
  memmove(dst, src, copy_len);
  dst[copy_len] = '\0';

  return src_len;
}

/* ****************************************** */

int ndpi_memcasecmp(const void *s1, const void *s2, size_t n) {
  if (s1 == NULL && s2 == NULL) {
    return 0;
  }

  if (s1 == NULL) {
    return -1;
  }

  if (s2 == NULL) {
    return 1;
  }

  if (n == 0) {
    return 0;
  }

  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;

  if (n == 1) {
    return tolower(*p1) - tolower(*p2);
  }

  /* Early exit optimization - check first and last bytes */

  int first_cmp = tolower(p1[0]) - tolower(p2[0]);
  if (first_cmp != 0) {
    return first_cmp;
  }

  int last_cmp = tolower(p1[n-1]) - tolower(p2[n-1]);
  if (last_cmp != 0) {
    return last_cmp;
  }

  size_t i;
  for (i = 1; i < n-1; i++) {
    int cmp = tolower(p1[i]) - tolower(p2[i]);
    if (cmp != 0) {
      return cmp;
    }
  }

  return 0;
}

/* ****************************************** */

char *ndpi_stack2str(struct ndpi_detection_module_struct *ndpi_str,
                     struct ndpi_proto_stack *stack, char *buf, u_int buf_len) {
  int ret, used = 0, i = 0;

  if(!ndpi_str || buf == NULL || buf_len == 0)
    return NULL;

  buf[0] = '\0';

  if(stack->protos_num == 0) {
    ndpi_snprintf(buf, buf_len, "Unknown");
    return buf;
  }

  while((int64_t)buf_len - used > 0 && i < stack->protos_num) {
    ret = ndpi_snprintf(buf + used, buf_len - used, "%s%s",
                       i != 0 ? "." : "",
                      ndpi_get_proto_name(ndpi_str, stack->protos[i]));
    if(ret <= 0)
      break;
    used += ret;
    i++;
  }

  return buf;
}

/* ****************************************** */

ndpi_tls_block_type ndpi_encode_tls_block_type(u_int8_t block_type, u_int8_t handshake_type) {
  switch(block_type) {
  case 20: /* Change Cipher */
    return(tls_change_cipher);
  case 21: /* Alert */
    return(tls_alert);
  case 22: /* Handshake */
    switch(handshake_type) {
    case 0: /* Encrypted Handshake Message */
      return(tls_handshake_encrypted_message);
    case 1: /* Client Hello */
      return(tls_handshake_client_hello);
    case 2: /* Server Hello */
      return(tls_handshake_server_hello);
    case 4: /* New Session Ticket */
      return(tls_handshake_new_session_ticket);
    case 8: /* Encrypted Extn (1.3 only) */
      return(tls_handshake_encrypted_extn);
    case 11: /* Certificate */
      return(tls_handshake_certificate);
    case 12: /* Server Key Exchange */
      return(tls_handshake_server_key_exchange);
    case 13: /* Certificate Request */
      return(tls_handshake_certificate_request);
    case 14: /* Server Hello Done */
      return(tls_handshake_server_hello_done);
    case 15: /* Certificate Verify */
      return(tls_handshake_certificate_verify);
    case 16: /* Client Key Exchange */
      return(tls_handshake_client_key_exchange);
    case 20: /* Finished */
      return(tls_handshake_finished);
    }
    break;
  case 23: /* Application Data */
    return(tls_application_data);
  case 24: /* Heartbeat */
    return(tls_heartbeat);
  }

  return(tls_unknown);
}

/* ****************************************** */

const char* ndpi_print_encoded_tls_block_type(ndpi_tls_block_type block_type, bool numeric_mode) {
  switch(block_type) {
  case tls_change_cipher:                 return(numeric_mode ? "20"    : "ChangeCipher");
  case tls_alert:                         return(numeric_mode ? "21"    : "Alert");
  case tls_handshake_encrypted_message:   return(numeric_mode ? "22:0"  : "Handshake:EncHandshakeMsg");
  case tls_handshake_client_hello:        return(numeric_mode ? "22:1"  : "Handshake:ClientHello");
  case tls_handshake_server_hello:        return(numeric_mode ? "22:2"  : "Handshake:ServerHello");
  case tls_handshake_new_session_ticket:  return(numeric_mode ? "22:4"  : "Handshake:NewSessTicket");
  case tls_handshake_encrypted_extn:      return(numeric_mode ? "22:8"  : "Handshake:EncryptedExtn");
  case tls_handshake_certificate:         return(numeric_mode ? "22:11" : "Handshake:Certificate");
  case tls_handshake_server_key_exchange: return(numeric_mode ? "22:12" : "Handshake:ServerKeyExch");
  case tls_handshake_certificate_request: return(numeric_mode ? "22:13" : "Handshake:CertRequest");
  case tls_handshake_server_hello_done:   return(numeric_mode ? "22:14" : "Handshake:ServerHelloDone");
  case tls_handshake_certificate_verify:  return(numeric_mode ? "22:15" : "Handshake:CertVerify");
  case tls_handshake_client_key_exchange: return(numeric_mode ? "22:16" : "Handshake:ClientKeyExch");
  case tls_handshake_finished:            return(numeric_mode ? "22:20" : "Handshake:Finished");
  case tls_application_data:              return(numeric_mode ? "23"    : "AppData");
  case tls_heartbeat:                     return(numeric_mode ? "24"    : "Heartbeat");
  default:                                return(numeric_mode ? "0"     : "Unknown");
  }
}

/* ****************************************** */

/* NOTE: caller MUST free the returned pointer */
u_char* ndpi_encode_tls_blocks(struct ndpi_tls_block *tls_blocks,
			       u_int8_t num_tls_blocks) {
  u_char buf[512];
  u_int8_t i, offset=0, block_len = 3 /* block_type(1) + len(2) */;
  u_int expected_len = num_tls_blocks * block_len;

  if(sizeof(buf) < expected_len) return(0); /* Buffer too short */

  for(i=0; i<num_tls_blocks; i++) {
    buf[offset++] = (tls_blocks[i].block_type & 0x7F) + (tls_blocks[i].same_pkt << 7);
    buf[offset++] = tls_blocks[i].len >> 8;
    buf[offset++] = tls_blocks[i].len & 0xFF;
  }

  return(ndpi_hex_encode(buf, expected_len));
}

/* ****************************************** */

/* NOTE: caller MUST free the returned pointer */
struct ndpi_tls_block* ndpi_decode_tls_blocks(const u_char *encoded_blocks,
					      u_int encoded_blocks_len,
					      u_int8_t *num_tls_blocks) {
  size_t out_len;
  u_char *buf;
  u_int8_t i, offset, block_len = 3; /* block_type(1) + len(2) */
  struct ndpi_tls_block *tls_blocks;

  if(num_tls_blocks == NULL)
    return(NULL);

  *num_tls_blocks = 0;

  buf = ndpi_hex_decode(encoded_blocks, encoded_blocks_len, &out_len);
  if(buf == NULL)
    return(NULL);
  if((out_len == 0) || ((out_len % block_len) != 0)
     || ((out_len / block_len) > 0xFF)) {
    ndpi_free(buf);
    return(NULL);
  }

  *num_tls_blocks = out_len / block_len;

  tls_blocks = (struct ndpi_tls_block*)ndpi_calloc(*num_tls_blocks,
						   sizeof(struct ndpi_tls_block));
  if(tls_blocks == NULL) { ndpi_free(buf); return(NULL); }

  for(i=0, offset=0; i<*num_tls_blocks; i++) {
    tls_blocks[i].block_type = buf[offset] & 0x7F;
    tls_blocks[i].same_pkt   = (buf[offset] & 0x80) ? 1 : 0;
    tls_blocks[i].len = (buf[offset+1] << 8) + buf[offset+2];
    offset += 3;
  }

  ndpi_free(buf);

  return(tls_blocks);
}

/* ****************************************** */

const char* ndpi_tls_extension2str(u_int16_t extension_id,
				   char unknown_extn[8]) {
  switch(extension_id) {
    /* RFC 6066 - TLS Extensions Definitions */
  case 0: return "server_name";
  case 1: return "max_fragment_length";
  case 2: return "client_certificate_url";
  case 3: return "trusted_ca_keys";
  case 4: return "truncated_hmac";
  case 5: return "status_request";

    /* RFC 4366 - Transport Layer Security (TLS) Extensions */
  case 6: return "user_mapping";
  case 7: return "client_authz";
  case 8: return "server_authz";

    /* RFC 4492 - Elliptic Curve Cryptography (ECC) Cipher Suites */
  case 10: return "supported_groups";  /* Formerly "elliptic_curves" */
  case 11: return "ec_point_formats";

    /* RFC 4681 - TLS User Mapping Extension */
  case 12: return "srp";
  case 13: return "signature_algorithms";
  case 14: return "use_srtp";
  case 15: return "heartbeat";

    /* RFC 7301 - Application-Layer Protocol Negotiation (ALPN) */
  case 16: return "application_layer_protocol_negotiation";

    /* RFC 7685 - A TLS Extension for Certificate Status Request */
  case 17: return "status_request_v2";
  case 18: return "signed_certificate_timestamp";
  case 19: return "client_certificate_type";
  case 20: return "server_certificate_type";

    /* RFC 8879 - TLS Certificate Compression */
  case 22: return "compress_certificate";

    /* RFC 8449 - Record Size Limit Extension */
  case 28: return "record_size_limit";

    /* RFC 5746 - Transport Layer Security (TLS) Renegotiation Indication */
  case 65281: return "renegotiation_info";

    /* TLS 1.3 Extensions (RFC 8446) */
  case 21: return "padding";
  case 23: return "session_ticket";
  case 24: return "pre_shared_key";
  case 25: return "early_data";
  case 26: return "supported_versions";
  case 27: return "cookie";
  case 29: return "preshared_key";  /* Alternate spelling */
  case 30: return "psk_key_exchange_modes";
  case 31: return "ticket_early_data_info";
  case 32: return "certificate_authorities";
  case 33: return "oid_filters";
  case 34: return "post_handshake_auth";
  case 35: return "signature_algorithms_cert";
  case 36: return "key_share";
  case 37: return "transparency_info";
  case 38: return "connection_id";
  case 39: return "external_id_hash";
  case 40: return "external_session_id";
  case 41: return "quic_transport_parameters";
  case 42: return "ticket_request";
  case 43: return "dnssec_chain";

    /* RFC 7627 - Extended Master Secret Extension */
  case 44: return "extended_master_secret";

    /* RFC 8446 - Other TLS 1.3 extensions */
  case 45: return "token_binding";
  case 46: return "cached_info";
  case 47: return "tls_lts";

    /* Drafts and other extensions */
  case 48: return "compress_certificate_algorithms";
  case 49: return "record_size_limit";
  case 50: return "pwd_protect";
  case 51: return "pwd_clear";
  case 52: return "password_salt";
  case 53: return "ticket_pinning";
  case 54: return "tls_cert_with_extern_psk";
  case 55: return "delegated_credential";
  case 56: return "session_ticket_tls";
  case 57: return "TLD";
  case 58: return "external_id_hash";
  case 59: return "external_session_id";
  case 60: return "quic_transport_parameters";
  case 61: return "ticket_request";
  case 62: return "dnssec_chain";
  case 63: return "sequence_number_encryption_algorithms";

    /* GREASE values (RFC 8701) */
  case 0x0A0A: return "(GREASE)";
  case 0x1A1A: return "(GREASE)";
  case 0x2A2A: return "(GREASE)";
  case 0x3A3A: return "(GREASE)";
  case 0x4A4A: return "(GREASE)";
  case 0x5A5A: return "(GREASE)";
  case 0x6A6A: return "(GREASE)";
  case 0x7A7A: return "(GREASE)";
  case 0x8A8A: return "(GREASE)";
  case 0x9A9A: return "(GREASE)";
  case 0xAAAA: return "(GREASE)";
  case 0xBABA: return "(GREASE)";
  case 0xCACA: return "(GREASE)";
  case 0xDADA: return "(GREASE)";
  case 0xEAEA: return "(GREASE)";
  case 0xFAFA: return "(GREASE)";

  case 0x44CD: return "application_settings";

    /* Custom/Private extensions (experimental range) */
  case 65037: return "next_protocol_negotiation";  /*  Google NPN */
  case 65280: return "extended_random";  /* Used in some implementations */
  case 65282: return "token_binding";  /* Alternate value */

  default:
    ndpi_snprintf(unknown_extn, 8, "0X%04X", extension_id);
    return(unknown_extn);
  }
}

/* ****************************************** */

const char* ndpi_tls_elliptic_curve2str(u_int16_t curve_id, char unknown_curve[8]) {
  if((curve_id >= 0x002B) && (curve_id <= 0x003F))
    return "(Reserved)";

  switch (curve_id) {
    /* RFC 4492 / 8422 - Standard Curves */
  case 0x0001: return "sect163k1";           // deprecated
  case 0x0002: return "sect163r1";           // deprecated
  case 0x0003: return "sect163r2";           // deprecated
  case 0x0004: return "sect193r1";           // deprecated
  case 0x0005: return "sect193r2";           // deprecated
  case 0x0006: return "sect233k1";           // deprecated
  case 0x0007: return "sect233r1";           // deprecated
  case 0x0008: return "sect239k1";           // deprecated
  case 0x0009: return "sect283k1";           // deprecated
  case 0x000A: return "sect283r1";           // deprecated
  case 0x000B: return "sect409k1";           // deprecated
  case 0x000C: return "sect409r1";           // deprecated
  case 0x000D: return "sect571k1";           // deprecated
  case 0x000E: return "sect571r1";           // deprecated
  case 0x000F: return "secp160k1";           // deprecated
  case 0x0010: return "secp160r1";           // deprecated
  case 0x0011: return "secp160r2";           // deprecated
  case 0x0012: return "secp192k1";           // deprecated
  case 0x0013: return "secp192r1";           // P-192, deprecated
  case 0x0014: return "secp224k1";           // deprecated
  case 0x0015: return "secp224r1";           // P-224
  case 0x0016: return "secp256k1";           // deprecated
  case 0x0017: return "secp256r1";           // P-256
  case 0x0018: return "secp384r1";           // P-384
  case 0x0019: return "secp521r1";           // P-521

    /* RFC 7027 - Brainpool Curves */
  case 0x001A: return "brainpoolP256r1";
  case 0x001B: return "brainpoolP384r1";
  case 0x001C: return "brainpoolP512r1";

    /* RFC 8422 - TLS 1.3 Recommended Curves */
  case 0x001D: return "x25519";              // Curve25519
  case 0x001E: return "x448";                // Curve448

    /* RFC 8998 - Hybrid Key Exchange in TLS 1.3 */
  case 0x001F: return "brainpoolP256r1tls13"; // Reserved, not used
  case 0x0020: return "brainpoolP384r1tls13"; // Reserved, not used
  case 0x0021: return "brainpoolP512r1tls13"; // Reserved, not used

    /* RFC 9189 - Post-Quantum Hybrid Key Exchange */
  case 0x0022: return "x25519kyber768";
  case 0x0023: return "secp256r1kyber768";
  case 0x0024: return "x25519kyber1024";
  case 0x0025: return "secp256r1kyber1024";
  case 0x0026: return "secp384r1kyber768";
  case 0x0027: return "secp384r1kyber1024";
  case 0x0028: return "secp521r1kyber1024";
  case 0x0029: return "x448kyber768";
  case 0x002A: return "x448kyber1024";

    /* Arbitrary Prime and Characteristic-2 Curves */
  case 0xFF01: return "arbitrary_explicit_prime_curves";
  case 0xFF02: return "arbitrary_explicit_char2_curves";

    /* GREASE values for Elliptic Curves (RFC 8701) */
  case 0x0A0A: return "(GREASE)";
  case 0x1A1A: return "(GREASE)";
  case 0x2A2A: return "(GREASE)";
  case 0x3A3A: return "(GREASE)";
  case 0x4A4A: return "(GREASE)";
  case 0x5A5A: return "(GREASE)";
  case 0x6A6A: return "(GREASE)";
  case 0x7A7A: return "(GREASE)";
  case 0x8A8A: return "(GREASE)";
  case 0x9A9A: return "(GREASE)";
  case 0xAAAA: return "(GREASE)";
  case 0xBABA: return "(GREASE)";
  case 0xCACA: return "(GREASE)";
  case 0xDADA: return "(GREASE)";
  case 0xEAEA: return "(GREASE)";
  case 0xFAFA: return "(GREASE)";

   default:
    ndpi_snprintf(unknown_curve, 8, "0X%04X", curve_id);
    return(unknown_curve);
  }
}

/* ****************************************** */

const char* ndpi_tls_signature_algo2str(u_int16_t algo_id, char unknown_algo[8]) {
  if (algo_id >= 0xFE00 && algo_id <= 0xFEFF) {
    return("(Experimental/Private Use)");
  }

  switch (algo_id) {
    // Legacy RSA PKCS#1 schemes (deprecated in TLS 1.3)
  case 0x0201: return "rsa_pkcs1_sha1";          // Deprecated
  case 0x0401: return "rsa_pkcs1_sha256";
  case 0x0501: return "rsa_pkcs1_sha384";
  case 0x0601: return "rsa_pkcs1_sha512";

    // Legacy DSA schemes (deprecated)
  case 0x0202: return "dsa_sha1";                // Deprecated
  case 0x0402: return "dsa_sha256";              // Deprecated
  case 0x0502: return "dsa_sha384";              // Deprecated
  case 0x0602: return "dsa_sha512";              // Deprecated

    // Legacy ECDSA schemes (deprecated format)
  case 0x0203: return "ecdsa_sha1";              // Deprecated
  case 0x0403: return "ecdsa_sha256";
  case 0x0503: return "ecdsa_sha384";
  case 0x0603: return "ecdsa_sha512";

    // Legacy RSASSA-PSS without MGF1 (deprecated)
  case 0x0804: return "rsa_pss_sha256";          // Old format
  case 0x0805: return "rsa_pss_sha384";          // Old format
  case 0x0806: return "rsa_pss_sha512";          // Old format

    // EdDSA schemes (RFC 8422, RFC 8446)
  case 0x0807: return "ed25519";
  case 0x0808: return "ed448";

    // RSASSA-PSS with MGF1 (TLS 1.3, RFC 8446)
  case 0x0809: return "rsa_pss_rsae_sha256";
  case 0x080A: return "rsa_pss_rsae_sha384";
  case 0x080B: return "rsa_pss_rsae_sha512";

    // RSASSA-PSS with PSS padding only (RFC 8446)
  case 0x080C: return "rsa_pss_pss_sha256";
  case 0x080D: return "rsa_pss_pss_sha384";
  case 0x080E: return "rsa_pss_pss_sha512";

    // ECDSA_branchy (historical, not in standards)
  case 0x080F: return "ecdsa_branchy";

    // GOST R 34.10 schemes (RFC 9189)
  case 0xEE01: return "gostr34102012_256";
  case 0xEE02: return "gostr34102012_512";

    // SM2 signature scheme (Chinese standard)
  case 0xEE03: return "sm2sig_sm3";

    // Anonymous schemes (deprecated and insecure)
  case 0x0200: return "anonymous_sha1";          // Deprecated
  case 0x0300: return "anonymous_sha224";        // Deprecated
  case 0x0400: return "anonymous_sha256";        // Deprecated
  case 0x0500: return "anonymous_sha384";        // Deprecated
  case 0x0600: return "anonymous_sha512";        // Deprecated

    // GREASE values for signature algorithms (RFC 8701)
  case 0x0A0A: return "(GREASE)";
  case 0x1A1A: return "(GREASE)";
  case 0x2A2A: return "(GREASE)";
  case 0x3A3A: return "(GREASE)";
  case 0x4A4A: return "(GREASE)";
  case 0x5A5A: return "(GREASE)";
  case 0x6A6A: return "(GREASE)";
  case 0x7A7A: return "(GREASE)";
  case 0x8A8A: return "(GREASE)";
  case 0x9A9A: return "(GREASE)";
  case 0xAAAA: return "(GREASE)";
  case 0xBABA: return "(GREASE)";
  case 0xCACA: return "(GREASE)";
  case 0xDADA: return "(GREASE)";
  case 0xEAEA: return "(GREASE)";
  case 0xFAFA: return "(GREASE)";

  default:
    ndpi_snprintf(unknown_algo, 8, "0X%04X", algo_id);
    return(unknown_algo);
  }
}

/* ****************************************** */

typedef struct {
  unsigned short id;
  const char* name;
  const char* type;
  int bits;
  int deprecated;
  int tls13_supported;
} tls_named_group_info;

static const tls_named_group_info named_groups[] = {
  // ========== Elliptic Curve Groups (ECDHE) ==========
  // Deprecated binary/sect curves (RFC 4492)
  {0x0001, "sect163k1", "EC", 163, 1, 0},
  {0x0002, "sect163r1", "EC", 163, 1, 0},
  {0x0003, "sect163r2", "EC", 163, 1, 0},
  {0x0004, "sect193r1", "EC", 193, 1, 0},
  {0x0005, "sect193r2", "EC", 193, 1, 0},
  {0x0006, "sect233k1", "EC", 233, 1, 0},
  {0x0007, "sect233r1", "EC", 233, 1, 0},
  {0x0008, "sect239k1", "EC", 239, 1, 0},
  {0x0009, "sect283k1", "EC", 283, 1, 0},
  {0x000A, "sect283r1", "EC", 283, 1, 0},
  {0x000B, "sect409k1", "EC", 409, 1, 0},
  {0x000C, "sect409r1", "EC", 409, 1, 0},
  {0x000D, "sect571k1", "EC", 571, 1, 0},
  {0x000E, "sect571r1", "EC", 571, 1, 0},

  // Prime curves (secp*)
  {0x000F, "secp160k1", "EC", 160, 1, 0},
  {0x0010, "secp160r1", "EC", 160, 1, 0},
  {0x0011, "secp160r2", "EC", 160, 1, 0},
  {0x0012, "secp192k1", "EC", 192, 1, 0},
  {0x0013, "secp192r1", "EC", 192, 1, 0},  // P-192, deprecated
  {0x0014, "secp224k1", "EC", 224, 1, 0},
  {0x0015, "secp224r1", "EC", 224, 0, 1},  // P-224
  {0x0016, "secp256k1", "EC", 256, 1, 0},  // Bitcoin curve
  {0x0017, "secp256r1", "EC", 256, 0, 1},  // P-256 (NIST), widely used
  {0x0018, "secp384r1", "EC", 384, 0, 1},  // P-384
  {0x0019, "secp521r1", "EC", 521, 0, 1},  // P-521

  // Brainpool curves (RFC 7027)
  {0x001A, "brainpoolP256r1", "EC", 256, 1, 0},
  {0x001B, "brainpoolP384r1", "EC", 384, 1, 0},
  {0x001C, "brainpoolP512r1", "EC", 512, 1, 0},

  // Montgomery curves (RFC 7748, RFC 8446)
  {0x001D, "x25519", "EC", 255, 0, 1},     // Curve25519, recommended
  {0x001E, "x448", "EC", 448, 0, 1},       // Curve448

  // Reserved for brainpool in TLS 1.3 (not used)
  {0x001F, "brainpoolP256r1tls13", "EC", 256, 1, 0},
  {0x0020, "brainpoolP384r1tls13", "EC", 384, 1, 0},
  {0x0021, "brainpoolP512r1tls13", "EC", 512, 1, 0},

  // Hybrid post-quantum key exchange (RFC 9189)
  {0x0022, "x25519kyber768", "PQ", 255, 0, 1},
  {0x0023, "secp256r1kyber768", "PQ", 256, 0, 1},
  {0x0024, "x25519kyber1024", "PQ", 255, 0, 1},
  {0x0025, "secp256r1kyber1024", "PQ", 256, 0, 1},
  {0x0026, "secp384r1kyber768", "PQ", 384, 0, 1},
  {0x0027, "secp384r1kyber1024", "PQ", 384, 0, 1},
  {0x0028, "secp521r1kyber1024", "PQ", 521, 0, 1},
  {0x0029, "x448kyber768", "PQ", 448, 0, 1},
  {0x002A, "x448kyber1024", "PQ", 448, 0, 1},

  // ========== Finite Field Groups (FFDHE) ==========
  {0x0100, "ffdhe2048", "DH", 2048, 0, 1},
  {0x0101, "ffdhe3072", "DH", 3072, 0, 1},
  {0x0102, "ffdhe4096", "DH", 4096, 0, 1},
  {0x0103, "ffdhe6144", "DH", 6144, 0, 1},
  {0x0104, "ffdhe8192", "DH", 8192, 0, 1},

  // ========== Special Values ==========
  {0xFF01, "arbitrary_explicit_prime_curves", "SPEC", 0, 1, 0},
  {0xFF02, "arbitrary_explicit_char2_curves", "SPEC", 0, 1, 0},

  // Terminator
  {0xFFFF, NULL, NULL, 0, 0, 0}
};

/* ****************************************** */

const char* ndpi_tls_elliptic_curve_groups2str(u_int16_t group_id, char unknown_group[8]) {
  u_int16_t i;

  if(((group_id) & 0x0F0F) == 0x0A0A)
    return("(GREASE)");

  // Check for reserved ranges
  if ((group_id >= 0x002B && group_id <= 0x003F) ||  // Reserved ECDHE
      (group_id >= 0x0105 && group_id <= 0x01FF)) {  // Reserved FFDHE
    return("(Reserved)");
  }

  // Check for experimental/private use
  if (group_id >= 0xFE00 && group_id <= 0xFEFF) {
    return("(Experimental/Private Use)");
  }

  // Search in the table
  for (i = 0; named_groups[i].name != NULL; i++) {
    if (named_groups[i].id == group_id) {
      return(named_groups[i].name);
    }
  }

  ndpi_snprintf(unknown_group, 8, "0X%04X", group_id);
  return(unknown_group);
}

/* ****************************************** */

typedef struct {
  u_int16_t id;
  const char* name;
  const char* type;
  int public_key_size;     // Typical public key size in bytes
  int shared_secret_size;  // Typical shared secret size in bytes
  int tls13_supported;
  int requires_key_share;
  const char* security_level;
  const char* rfc;
  int draft_version;
} key_share_group_info;

// TLS 1.3 KeyShare groups - Complete and up-to-date
static const key_share_group_info key_share_groups[] = {
  // ========== Traditional Elliptic Curve Groups (ECDHE) ==========
  {0x0017, "secp256r1", "ECDHE", 65, 32, 1, 1, "128-bit", "RFC 8446", 0},
  {0x0018, "secp384r1", "ECDHE", 97, 48, 1, 1, "192-bit", "RFC 8446", 0},
  {0x0019, "secp521r1", "ECDHE", 133, 66, 1, 1, "256-bit", "RFC 8446", 0},

  // Montgomery curves (RFC 7748, RFC 8446)
  {0x001D, "x25519", "ECDHE", 32, 32, 1, 1, "128-bit", "RFC 8446", 0},
  {0x001E, "x448", "ECDHE", 56, 56, 1, 1, "224-bit", "RFC 8446", 0},

  // ========== Finite Field Groups (FFDHE) ==========
  {0x0100, "ffdhe2048", "FFDHE", 256, 256, 1, 0, "112-bit", "RFC 7919", 0},
  {0x0101, "ffdhe3072", "FFDHE", 384, 384, 1, 0, "128-bit", "RFC 7919", 0},
  {0x0102, "ffdhe4096", "FFDHE", 512, 512, 1, 0, "152-bit", "RFC 7919", 0},
  {0x0103, "ffdhe6144", "FFDHE", 768, 768, 1, 0, "176-bit", "RFC 7919", 0},
  {0x0104, "ffdhe8192", "FFDHE", 1024, 1024, 1, 0, "192-bit", "RFC 7919", 0},

  // ========== Kyber-based Hybrid Groups (RFC 9189) ==========
  {0x0022, "x25519kyber768", "PQ_HYBRID", 32+1184, 32+32, 1, 1, "128-bit + L3", "RFC 9189", 0},
  {0x0023, "secp256r1kyber768", "PQ_HYBRID", 65+1184, 32+32, 1, 1, "128-bit + L3", "RFC 9189", 0},
  {0x0024, "x25519kyber1024", "PQ_HYBRID", 32+1568, 32+32, 1, 1, "128-bit + L5", "RFC 9189", 0},
  {0x0025, "secp256r1kyber1024", "PQ_HYBRID", 65+1568, 32+32, 1, 1, "128-bit + L5", "RFC 9189", 0},
  {0x0026, "secp384r1kyber768", "PQ_HYBRID", 97+1184, 48+32, 1, 1, "192-bit + L3", "RFC 9189", 0},
  {0x0027, "secp384r1kyber1024", "PQ_HYBRID", 97+1568, 48+32, 1, 1, "192-bit + L5", "RFC 9189", 0},
  {0x0028, "secp521r1kyber1024", "PQ_HYBRID", 133+1568, 66+32, 1, 1, "256-bit + L5", "RFC 9189", 0},
  {0x0029, "x448kyber768", "PQ_HYBRID", 56+1184, 56+32, 1, 1, "224-bit + L3", "RFC 9189", 0},
  {0x002A, "x448kyber1024", "PQ_HYBRID", 56+1568, 56+32, 1, 1, "224-bit + L5", "RFC 9189", 0},

  // ========== ML-KEM (FIPS 203, formerly Kyber) Hybrid Groups ==========
  // IANA: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
  {0x11EC, "X25519MLKEM768", "PQ_HYBRID", 32+1184, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11ED, "P256MLKEM768", "PQ_HYBRID", 65+1184, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11EE, "X25519MLKEM1024", "PQ_HYBRID", 32+1568, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x11EF, "P256MLKEM1024", "PQ_HYBRID", 65+1568, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x11F0, "X448MLKEM768", "PQ_HYBRID", 56+1184, 56+32, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11F1, "P384MLKEM768", "PQ_HYBRID", 97+1184, 48+32, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11F2, "X448MLKEM1024", "PQ_HYBRID", 56+1568, 56+32, 1, 1, "224-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x11F3, "P384MLKEM1024", "PQ_HYBRID", 97+1568, 48+32, 1, 1, "192-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x11F4, "P521MLKEM1024", "PQ_HYBRID", 133+1568, 66+32, 1, 1, "256-bit + L5", "draft-ietf-tls-hybrid-design", 10},

  // ========== ML-KEM Only (non-hybrid) ==========
  {0x11F5, "MLKEM512", "PQ_ONLY", 800, 32, 1, 1, "L1", "draft-ietf-tls-hybrid-design", 10},
  {0x11F6, "MLKEM768", "PQ_ONLY", 1184, 32, 1, 1, "L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11F7, "MLKEM1024", "PQ_ONLY", 1568, 32, 1, 1, "L5", "draft-ietf-tls-hybrid-design", 10},

  // ========== NTRU Hybrid Groups ==========
  {0x11F8, "X25519NTRUHPS2048509", "PQ_HYBRID", 32+699, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x11F9, "P256NTRUHPS2048509", "PQ_HYBRID", 65+699, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x11FA, "X25519NTRUHPS2048677", "PQ_HYBRID", 32+930, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11FB, "P256NTRUHPS2048677", "PQ_HYBRID", 65+930, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11FC, "X448NTRUHPS2048677", "PQ_HYBRID", 56+930, 56+32, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x11FD, "P384NTRUHPS2048677", "PQ_HYBRID", 97+930, 48+32, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},

  // ========== NTRU Prime Hybrid Groups ==========
  {0x11FE, "X25519NTRULPR653", "PQ_HYBRID", 32+897, 32+32, 1, 1, "128-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x11FF, "P256NTRULPR653", "PQ_HYBRID", 65+897, 32+32, 1, 1, "128-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x1200, "X25519NTRULPR761", "PQ_HYBRID", 32+1039, 32+32, 1, 1, "128-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x1201, "P256NTRULPR761", "PQ_HYBRID", 65+1039, 32+32, 1, 1, "128-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x1202, "X448NTRULPR761", "PQ_HYBRID", 56+1039, 56+32, 1, 1, "224-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x1203, "P384NTRULPR761", "PQ_HYBRID", 97+1039, 48+32, 1, 1, "192-bit", "draft-ietf-tls-hybrid-design", 10},
  {0x1204, "P521NTRULPR761", "PQ_HYBRID", 133+1039, 66+32, 1, 1, "256-bit", "draft-ietf-tls-hybrid-design", 10},

  // ========== Saber (LightSaber) Hybrid Groups ==========
  {0x1205, "X25519LightSaber", "PQ_HYBRID", 32+672, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x1206, "P256LightSaber", "PQ_HYBRID", 65+672, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x1207, "X25519Saber", "PQ_HYBRID", 32+992, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1208, "P256Saber", "PQ_HYBRID", 65+992, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1209, "X448Saber", "PQ_HYBRID", 56+992, 56+32, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x120A, "P384Saber", "PQ_HYBRID", 97+992, 48+32, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},

  // ========== FrodoKEM Hybrid Groups ==========
  {0x120B, "X25519Frodo640SHAKE", "PQ_HYBRID", 32+9616, 32+16, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x120C, "P256Frodo640SHAKE", "PQ_HYBRID", 65+9616, 32+16, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x120D, "X25519Frodo976SHAKE", "PQ_HYBRID", 32+15632, 32+24, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x120E, "P256Frodo976SHAKE", "PQ_HYBRID", 65+15632, 32+24, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x120F, "X448Frodo976SHAKE", "PQ_HYBRID", 56+15632, 56+24, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1210, "P384Frodo976SHAKE", "PQ_HYBRID", 97+15632, 48+24, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1211, "X25519Frodo1344SHAKE", "PQ_HYBRID", 32+21520, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1212, "P256Frodo1344SHAKE", "PQ_HYBRID", 65+21520, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1213, "P384Frodo1344SHAKE", "PQ_HYBRID", 97+21520, 48+32, 1, 1, "192-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1214, "P521Frodo1344SHAKE", "PQ_HYBRID", 133+21520, 66+32, 1, 1, "256-bit + L5", "draft-ietf-tls-hybrid-design", 10},

  // ========== BIKE Hybrid Groups ==========
  {0x1215, "X25519BIKE1L1", "PQ_HYBRID", 32+1541, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x1216, "P256BIKE1L1", "PQ_HYBRID", 65+1541, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x1217, "X25519BIKE1L3", "PQ_HYBRID", 32+3083, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1218, "P256BIKE1L3", "PQ_HYBRID", 65+3083, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1219, "X448BIKE1L3", "PQ_HYBRID", 56+3083, 56+32, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x121A, "P384BIKE1L3", "PQ_HYBRID", 97+3083, 48+32, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},

  // ========== HQC Hybrid Groups ==========
  {0x121B, "X25519HQCL1", "PQ_HYBRID", 32+2249, 32+64, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x121C, "P256HQCL1", "PQ_HYBRID", 65+2249, 32+64, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x121D, "X25519HQCL3", "PQ_HYBRID", 32+4522, 32+64, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x121E, "P256HQCL3", "PQ_HYBRID", 65+4522, 32+64, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x121F, "X448HQCL3", "PQ_HYBRID", 56+4522, 56+64, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1220, "P384HQCL3", "PQ_HYBRID", 97+4522, 48+64, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},

  // ========== SIKE Hybrid Groups (NOTE: Broken in 2022, included for completeness) ==========
  {0x1221, "X25519SIKEp434", "PQ_HYBRID_BROKEN", 32+330, 32+16, 0, 0, "128-bit + L1", "draft-ietf-tls-hybrid-design", 0},
  {0x1222, "P256SIKEp434", "PQ_HYBRID_BROKEN", 65+330, 32+16, 0, 0, "128-bit + L1", "draft-ietf-tls-hybrid-design", 0},
  {0x1223, "X25519SIKEp503", "PQ_HYBRID_BROKEN", 32+378, 32+24, 0, 0, "128-bit + L2", "draft-ietf-tls-hybrid-design", 0},
  {0x1224, "P256SIKEp503", "PQ_HYBRID_BROKEN", 65+378, 32+24, 0, 0, "128-bit + L2", "draft-ietf-tls-hybrid-design", 0},
  {0x1225, "X25519SIKEp610", "PQ_HYBRID_BROKEN", 32+462, 32+24, 0, 0, "128-bit + L3", "draft-ietf-tls-hybrid-design", 0},
  {0x1226, "P256SIKEp610", "PQ_HYBRID_BROKEN", 65+462, 32+24, 0, 0, "128-bit + L3", "draft-ietf-tls-hybrid-design", 0},
  {0x1227, "X448SIKEp610", "PQ_HYBRID_BROKEN", 56+462, 56+24, 0, 0, "224-bit + L3", "draft-ietf-tls-hybrid-design", 0},
  {0x1228, "P384SIKEp610", "PQ_HYBRID_BROKEN", 97+462, 48+24, 0, 0, "192-bit + L3", "draft-ietf-tls-hybrid-design", 0},
  {0x1229, "X25519SIKEp751", "PQ_HYBRID_BROKEN", 32+564, 32+32, 0, 0, "128-bit + L5", "draft-ietf-tls-hybrid-design", 0},
  {0x122A, "P256SIKEp751", "PQ_HYBRID_BROKEN", 65+564, 32+32, 0, 0, "128-bit + L5", "draft-ietf-tls-hybrid-design", 0},
  {0x122B, "P384SIKEp751", "PQ_HYBRID_BROKEN", 97+564, 48+32, 0, 0, "192-bit + L5", "draft-ietf-tls-hybrid-design", 0},
  {0x122C, "P521SIKEp751", "PQ_HYBRID_BROKEN", 133+564, 66+32, 0, 0, "256-bit + L5", "draft-ietf-tls-hybrid-design", 0},

  // ========== Classic McEliece Hybrid Groups ==========
  {0x122D, "X25519ClassicMcEliece348864", "PQ_HYBRID", 32+261120, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x122E, "P256ClassicMcEliece348864", "PQ_HYBRID", 65+261120, 32+32, 1, 1, "128-bit + L1", "draft-ietf-tls-hybrid-design", 10},
  {0x122F, "X25519ClassicMcEliece460896", "PQ_HYBRID", 32+524160, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1230, "P256ClassicMcEliece460896", "PQ_HYBRID", 65+524160, 32+32, 1, 1, "128-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1231, "X448ClassicMcEliece460896", "PQ_HYBRID", 56+524160, 56+32, 1, 1, "224-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1232, "P384ClassicMcEliece460896", "PQ_HYBRID", 97+524160, 48+32, 1, 1, "192-bit + L3", "draft-ietf-tls-hybrid-design", 10},
  {0x1233, "X25519ClassicMcEliece6688128", "PQ_HYBRID", 32+1044992, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1234, "P256ClassicMcEliece6688128", "PQ_HYBRID", 65+1044992, 32+32, 1, 1, "128-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1235, "P384ClassicMcEliece6688128", "PQ_HYBRID", 97+1044992, 48+32, 1, 1, "192-bit + L5", "draft-ietf-tls-hybrid-design", 10},
  {0x1236, "P521ClassicMcEliece6688128", "PQ_HYBRID", 133+1044992, 66+32, 1, 1, "256-bit + L5", "draft-ietf-tls-hybrid-design", 10},

  // ========== Other/Experimental Groups ==========
  // Brainpool curves (not typically used in TLS 1.3)
  {0x001A, "brainpoolP256r1", "ECDHE", 65, 32, 0, 0, "128-bit", "RFC 7027", 0},
  {0x001B, "brainpoolP384r1", "ECDHE", 97, 48, 0, 0, "192-bit", "RFC 7027", 0},
  {0x001C, "brainpoolP512r1", "ECDHE", 133, 64, 0, 0, "256-bit", "RFC 7027", 0},

  // Terminator
  {0x0000, NULL, NULL, 0, 0, 0, 0, NULL, NULL, 0}
};


const char* ndpi_tls_key_share_group2str(u_int16_t group_id, char unknown_group[8]) {
  u_int16_t i;

  if(((group_id) & 0x0F0F) == 0x0A0A)
    return("(GREASE)");

  if ((group_id >= 0x002B && group_id <= 0x003F) ||  // Reserved ECDHE
      (group_id >= 0x0105 && group_id <= 0x01FF)) {  // Reserved FFDHE
    return("(Reserved)");
  }

  if (group_id >= 0xFE00 && group_id <= 0xFEFF) {
    return("(Experimental/Private Use)");
  }

  for (i = 0; key_share_groups[i].name != NULL; i++) {
    if (key_share_groups[i].id == group_id) {
      return(key_share_groups[i].name);
    }
  }

  ndpi_snprintf(unknown_group, 8, "0X%04X", group_id);
  return(unknown_group);
}

/* ****************************************** */

typedef struct {
  u_int16_t version;
  const char* name;
  const char* rfc;
  int is_draft;
  int deprecated;
  int recommended;
  const char* security_status;
} tls_version_info;

// TLS versions table (RFC 5246, RFC 8446, and drafts)
static const tls_version_info tls_versions[] = {
  // ========== SSL/TLS Legacy Versions ==========
  {0x0200, "SSL 2.0", "Historical", 0, 1, 0, "INSECURE - MUST NOT USE"},
  {0x0300, "SSL 3.0", "Historical", 0, 1, 0, "INSECURE - MUST NOT USE"},

  // ========== TLS 1.x Series ==========
  {0x0301, "TLS 1.0", "RFC 2246", 0, 1, 0, "INSECURE - MUST NOT USE"},
  {0x0302, "TLS 1.1", "RFC 4346", 0, 1, 0, "WEAK - Should not use"},
  {0x0303, "TLS 1.2", "RFC 5246", 0, 0, 1, "SECURE - Widely supported"},
  {0x0304, "TLS 1.3", "RFC 8446", 0, 0, 1, "SECURE - Recommended"},

  // ========== TLS 1.4 Drafts ==========
  {0x7F00, "TLS 1.4 (draft-00)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F01, "TLS 1.4 (draft-01)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F02, "TLS 1.4 (draft-02)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F03, "TLS 1.4 (draft-03)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F04, "TLS 1.4 (draft-04)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F05, "TLS 1.4 (draft-05)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F06, "TLS 1.4 (draft-06)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F07, "TLS 1.4 (draft-07)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F08, "TLS 1.4 (draft-08)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F09, "TLS 1.4 (draft-09)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0A, "TLS 1.4 (draft-10)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0B, "TLS 1.4 (draft-11)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0C, "TLS 1.4 (draft-12)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0D, "TLS 1.4 (draft-13)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0E, "TLS 1.4 (draft-14)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F0F, "TLS 1.4 (draft-15)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F10, "TLS 1.4 (draft-16)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F11, "TLS 1.4 (draft-17)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F12, "TLS 1.4 (draft-18)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F13, "TLS 1.4 (draft-19)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F14, "TLS 1.4 (draft-20)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F15, "TLS 1.4 (draft-21)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F16, "TLS 1.4 (draft-22)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F17, "TLS 1.4 (draft-23)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F18, "TLS 1.4 (draft-24)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F19, "TLS 1.4 (draft-25)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F1A, "TLS 1.4 (draft-26)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F1B, "TLS 1.4 (draft-27)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F1C, "TLS 1.4 (draft-28)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F1D, "TLS 1.4 (draft-29)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},
  {0x7F1E, "TLS 1.4 (draft-30)", "draft-ietf-tls-tls13", 1, 0, 0, "EXPERIMENTAL"},

  // ========== DTLS Versions ==========
  {0xFEFF, "DTLS 1.0", "RFC 4347", 0, 1, 0, "WEAK"},
  {0xFEFD, "DTLS 1.2", "RFC 6347", 0, 0, 1, "SECURE"},
  {0xFEFC, "DTLS 1.3", "RFC 9147", 0, 0, 1, "SECURE - Recommended"},

  // ========== Experimental/Private Use ==========
  {0x0A0A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x1A1A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x2A2A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x3A3A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x4A4A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x5A5A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x6A6A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x7A7A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x8A8A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0x9A9A, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xAAAA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xBABA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xCACA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xDADA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xEAEA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},
  {0xFAFA, "(GREASE)", "RFC 8701", 0, 0, 0, "TESTING"},


  // ========== QUIC Versions (used in TLS over QUIC) ==========
  {0x00000001, "QUIC v1", "RFC 9000", 0, 0, 1, "TRANSPORT"},

  // Terminator
  {0x0000, NULL, NULL, 0, 0, 0, NULL}
};

const char* ndpi_tls_supported_version2str(u_int16_t version_id, char unknown_version[8]) {
  u_int16_t i;

  if(((version_id) & 0x0F0F) == 0x0A0A)
    return("(GREASE)");

  for (i = 0; tls_versions[i].name != NULL; i++) {
    if (tls_versions[i].version == version_id) {
      return(tls_versions[i].name);
    }
  }

  ndpi_snprintf(unknown_version, 8, "0X%04X", version_id);
  return(unknown_version);
}

/* ****************************************** */

/*
  Compares two TLS blocks of the same lenght and
  returns a distance values: 0 = vectors are identical,
  otherwise a value is returned. The higger is the value
  the more different are the vectors.

 */
float ndpi_tls_blocks_len_compare(struct ndpi_tls_block *a,
				  struct ndpi_tls_block *b,
				  u_int8_t num_tls_blocks) {
  float total = 0;
  u_int8_t n;

  for(n=0; n<num_tls_blocks; n++) {
    if(a[n].block_type != b[n].block_type)
      return(999999.);
    else {
      int diff = a[n].len - b[n].len;

      if((diff != 0) && (n < 2 /* C/S Hello */))
	return(999999.);

      total += diff * diff;

#if 0
      fprintf(stderr, "[%d] diff=%u [%d, %d], %.2f\n",
	      n, diff, a[n].len, b[n].len, total);
#endif
    }
  }

  return(total);
}

/* ****************************************** */

void ndpi_list_init(ndpi_list *l) {
  l->value = NULL, l->next = NULL;
}

/* ****************************************** */

void ndpi_list_free(ndpi_list *l) {
  while(l != NULL) {
    ndpi_list *next = l->next;

    if(l->value != NULL) ndpi_free(l->value);
    ndpi_free(l);
    l = next;
  }
}

/* ****************************************** */

/*
  NOTE:
  *value must be allocated by the caller and
  it will be freed by ndpi_list_free()
*/
bool ndpi_list_append(ndpi_list *l, void *value) {
  if(l->value == NULL) {
    /* Empty list: let's use the first entry */
    l->value = value;
  } else {
    ndpi_list *new_tail = (ndpi_list*)ndpi_malloc(sizeof(ndpi_list));

    if(new_tail == NULL) return(false);
    new_tail->value = value, new_tail->next = NULL;

    /* Move to the end */
    while(l->next != NULL) l = l->next;

    if(l != NULL)
      l->next = new_tail;
    else
      ndpi_free(new_tail); /* Something went wrong */
  }

  return(true); /* All good */
}

/* ****************************************** */

const char *ndpi_ikev2_encr_name(u_int16_t id) {
  switch (id) {
    case 1:  return "DES_IV64";
    case 2:  return "DES";
    case 3:  return "3DES";
    case 4:  return "RC5";
    case 5:  return "IDEA";
    case 6:  return "CAST";
    case 7:  return "BLOWFISH";
    case 8:  return "3IDEA";
    case 9:  return "DES_IV32";
    case 11: return "NULL";
    case 12: return "AES_CBC";
    case 13: return "AES_CTR";
    case 14: return "AES_CCM_8";
    case 15: return "AES_CCM_12";
    case 16: return "AES_CCM_16";
    case 18: return "AES_GCM_8";
    case 19: return "AES_GCM_12";
    case 20: return "AES_GCM_16";
    case 23: return "CAMELLIA_CBC";
    case 28: return "CHACHA20_POLY1305";
    default: return "UNKNOWN";
  }
}

/* ****************************************** */

const char *ndpi_ikev2_prf_name(u_int16_t id) {
  switch (id) {
    case 1: return "HMAC_MD5";
    case 2: return "HMAC_SHA1";
    case 3: return "HMAC_TIGER";
    case 4: return "AES128_XCBC";
    case 5: return "HMAC_SHA2_256";
    case 6: return "HMAC_SHA2_384";
    case 7: return "HMAC_SHA2_512";
    case 8: return "AES128_CMAC";
    default: return "UNKNOWN";
  }
}

/* ****************************************** */

const char *ndpi_ikev2_integ_name(u_int16_t id) {
  switch (id) {
    case 0:  return "NONE";
    case 1:  return "HMAC_MD5_96";
    case 2:  return "HMAC_SHA1_96";
    case 3:  return "DES_MAC";
    case 4:  return "KPDK_MD5";
    case 5:  return "AES_XCBC_96";
    case 6:  return "HMAC_MD5_128";
    case 7:  return "HMAC_SHA1_160";
    case 8:  return "AES_CMAC_96";
    case 9:  return "AES_128_GMAC";
    case 10: return "AES_192_GMAC";
    case 11: return "AES_256_GMAC";
    case 12: return "HMAC_SHA2_256_128";
    case 13: return "HMAC_SHA2_384_192";
    case 14: return "HMAC_SHA2_512_256";
    default: return "UNKNOWN";
  }
}

/* ****************************************** */

const char *ndpi_ikev2_dh_name(u_int16_t id) {
  switch (id) {
    case 0:  return "NONE";
    case 1:  return "MODP_768";
    case 2:  return "MODP_1024";
    case 5:  return "MODP_1536";
    case 14: return "MODP_2048";
    case 15: return "MODP_3072";
    case 16: return "MODP_4096";
    case 17: return "MODP_6144";
    case 18: return "MODP_8192";
    case 19: return "ECP_256";
    case 20: return "ECP_384";
    case 21: return "ECP_521";
    case 22: return "MODP_1024_160";
    case 23: return "MODP_2048_224";
    case 24: return "MODP_2048_256";
    case 25: return "ECP_192";
    case 26: return "ECP_224";
    case 28: return "BRAINPOOL_P256";
    case 29: return "BRAINPOOL_P384";
    case 30: return "BRAINPOOL_P512";
    case 31: return "CURVE25519";
    case 32: return "CURVE448";
    default: return "UNKNOWN";
  }
}
