/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-23 - ntop.org and contributors
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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


#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_encryption.h"

#include "ahocorasick.h"
#include "libcache.h"

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

#define NDPI_CONST_GENERIC_PROTOCOL_NAME  "GenericProtocol"

// #define MATCH_DEBUG 1

// #define DEBUG_REASSEMBLY

#ifdef HAVE_PCRE
#include <pcre.h>

struct pcre_struct {
  pcre *compiled;
  pcre_extra *optimized;
};
#endif

/*
 * Please keep this strcture in sync with
 * `struct ndpi_str_hash` in src/include/ndpi_typedefs.h
 */

typedef struct ndpi_str_hash_private {
  unsigned int hash;
  void *value;
  // u_int8_t private_data[1]; /* Avoid error C2466 and do not initiate private data with 0  */
  UT_hash_handle hh;
} ndpi_str_hash_private;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ndpi_str_hash) == sizeof(struct ndpi_str_hash_private) - sizeof(UT_hash_handle),
               "Please keep `struct ndpi_str_hash` and `struct ndpi_str_hash_private` syncd.");
#endif

/* ****************************************** */

/* implementation of the punycode check function */
int ndpi_check_punycode_string(char * buffer , int len) {
  int i = 0;

  while(i++ < len - 3) {
    if((buffer[i] == 'x')
       && (buffer[i+1] == 'n')
       && (buffer[i+2] == '-')
       && (buffer[i+3] == '-'))
      // is a punycode string
      return(1);
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
			u_int32_t net, u_int32_t num_bits)
{
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
  if(ispunct(c) && (!ndpi_is_other_char(c)))
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

static int ndpi_find_non_eng_bigrams(struct ndpi_detection_module_struct *ndpi_struct,
				     char *str) {
  char s[3];

  if((isdigit((int)str[0]) && isdigit((int)str[1]))
     || ndpi_is_other_char(str[0])
     || ndpi_is_other_char(str[1])
     )
    return(1);

  s[0] = tolower(str[0]), s[1] = tolower(str[1]), s[2] = '\0';

  return(ndpi_match_bigram(s));
}

/* ******************************************************************** */

/* #define PRINT_STRINGS 1 */

int ndpi_has_human_readeable_string(struct ndpi_detection_module_struct *ndpi_struct,
				    char *buffer, u_int buffer_size,
				    u_int8_t min_string_match_len,
				    char *outbuf, u_int outbuf_len) {
  u_int ret = 0, i = 0, do_cr = 0, len = 0, o_idx = 0, being_o_idx = 0;

  if(buffer_size <= 0)
    return(0);

  outbuf_len--;
  outbuf[outbuf_len] = '\0';

  for(i=0; i<buffer_size-2; i++) {
    if(ndpi_is_valid_char(buffer[i])
       && ndpi_is_valid_char(buffer[i+1])
       && ndpi_find_non_eng_bigrams(ndpi_struct, &buffer[i])) {
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

      // printf("->> %c%c\n", isprint(buffer[i]) ? buffer[i] : '.', isprint(buffer[i+1]) ? buffer[i+1] : '.');
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
      if(flow->protos.tls_quic.hello_processed != 0)
        return flow->host_server_name;
      break;
  }
  
  return NULL;
}

/* ********************************** */

const char* ndpi_get_flow_info(struct ndpi_flow_struct const * const flow,
                               ndpi_protocol const * const l7_protocol) {
  char const * const app_protocol_info = ndpi_get_flow_info_by_proto_id(flow, l7_protocol->app_protocol);

  if(app_protocol_info != NULL)  
    return app_protocol_info;  

  return ndpi_get_flow_info_by_proto_id(flow, l7_protocol->master_protocol);
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
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
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

  olen = count / 4 * 3;
  pos = out = ndpi_malloc(olen);
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
  ndpi_serialize_string_string(serializer, "proto", ndpi_protocol2name(ndpi_struct, l7_protocol, buf, sizeof(buf)));
  ndpi_serialize_string_string(serializer, "proto_id", ndpi_protocol2id(ndpi_struct, l7_protocol, buf, sizeof(buf)));
  ndpi_serialize_string_string(serializer, "proto_by_ip", ndpi_get_proto_name(ndpi_struct,
                                                                              l7_protocol.protocol_by_ip));
  ndpi_serialize_string_uint32(serializer, "proto_by_ip_id", l7_protocol.protocol_by_ip);
  ndpi_serialize_string_uint32(serializer, "encrypted", ndpi_is_encrypted_proto(ndpi_struct, l7_protocol));
  ndpi_protocol_breed_t breed =
    ndpi_get_proto_breed(ndpi_struct,
                         (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  ndpi_serialize_string_string(serializer, "breed", ndpi_get_proto_breed_name(ndpi_struct, breed));
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
  {
    ndpi_serialize_string_uint32(serializer, "category_id", l7_protocol.category);
    ndpi_serialize_string_string(serializer, "category", ndpi_category_get_name(ndpi_struct, l7_protocol.category));
  }
}

/* ********************************** */

static void ndpi_tls2json(ndpi_serializer *serializer, struct ndpi_flow_struct *flow)
{
  if(flow->protos.tls_quic.ssl_version)
  {
    char buf[64];
    char notBefore[32], notAfter[32];
    struct tm a, b, *before = NULL, *after = NULL;
    u_int i, off;
    u_int8_t unknown_tls_version;
    char version[16], unknown_cipher[8];

    ndpi_ssl_version2str(version, sizeof(version), flow->protos.tls_quic.ssl_version, &unknown_tls_version);

    if(flow->protos.tls_quic.notBefore)
    {
      before = ndpi_gmtime_r((const time_t *)&flow->protos.tls_quic.notBefore, &a);
    }
    if(flow->protos.tls_quic.notAfter)
    {
      after = ndpi_gmtime_r((const time_t *)&flow->protos.tls_quic.notAfter, &b);
    }

    if(!unknown_tls_version)
    {
      ndpi_serialize_start_of_block(serializer, "tls");
      ndpi_serialize_string_string(serializer, "version", version);

      if(flow->protos.tls_quic.server_names)
      {
        ndpi_serialize_string_string(serializer, "server_names",
                                     flow->protos.tls_quic.server_names);
      }

      if(before)
      {
        strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
        ndpi_serialize_string_string(serializer, "notbefore", notBefore);
      }

      if(after)
      {
        strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
        ndpi_serialize_string_string(serializer, "notafter", notAfter);
      }

      ndpi_serialize_string_string(serializer, "ja3", flow->protos.tls_quic.ja3_client);
      ndpi_serialize_string_string(serializer, "ja3s", flow->protos.tls_quic.ja3_server);
      ndpi_serialize_string_uint32(serializer, "unsafe_cipher", flow->protos.tls_quic.server_unsafe_cipher);
      ndpi_serialize_string_string(serializer, "cipher",
                                   ndpi_cipher2str(flow->protos.tls_quic.server_cipher, unknown_cipher));

      if(flow->protos.tls_quic.issuerDN)
      {
        ndpi_serialize_string_string(serializer, "issuerDN", flow->protos.tls_quic.issuerDN);
      }
      if(flow->protos.tls_quic.subjectDN)
      {
        ndpi_serialize_string_string(serializer, "subjectDN", flow->protos.tls_quic.subjectDN);
      }
      if(flow->protos.tls_quic.advertised_alpns)
      {
        ndpi_serialize_string_string(serializer, "advertised_alpns", flow->protos.tls_quic.advertised_alpns);
      }
      if(flow->protos.tls_quic.negotiated_alpn)
      {
        ndpi_serialize_string_string(serializer, "negotiated_alpn", flow->protos.tls_quic.negotiated_alpn);
      }
      if(flow->protos.tls_quic.tls_supported_versions)
      {
        ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic.tls_supported_versions);
      }

      if(flow->protos.tls_quic.sha1_certificate_fingerprint[0] != '\0')
      {
        for(i=0, off=0; i<20; i++)
        {
          int rc = ndpi_snprintf(&buf[off], sizeof(buf)-off,"%s%02X", (i > 0) ? ":" : "",
                               flow->protos.tls_quic.sha1_certificate_fingerprint[i] & 0xFF);

          if(rc <= 0) break; else off += rc;
        }

        ndpi_serialize_string_string(serializer, "fingerprint", buf);
      }

      ndpi_serialize_end_of_block(serializer);
    }
  }
}

/* NOTE: serializer must have been already initialized */
int ndpi_dpi2json(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow,
		  ndpi_protocol l7_protocol,
		  ndpi_serializer *serializer) {
  char buf[64];
  char const *host_server_name;

  if(flow == NULL) return(-1);

  ndpi_serialize_start_of_block(serializer, "ndpi");
  ndpi_serialize_proto(ndpi_struct, serializer, flow->risk, flow->confidence, l7_protocol);

  host_server_name = ndpi_get_flow_info(flow, &l7_protocol);
  if (host_server_name != NULL)
  {
    ndpi_serialize_string_string(serializer, "hostname", host_server_name);
  }

  switch(l7_protocol.master_protocol ? l7_protocol.master_protocol : l7_protocol.app_protocol) {
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
	sprintf(&bittorent_hash[j], "%02x",
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

    inet_ntop(AF_INET, &flow->protos.dns.rsp_addr, buf, sizeof(buf));
    ndpi_serialize_string_string(serializer, "rsp_addr",    buf);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_NTP:
    ndpi_serialize_start_of_block(serializer, "ntp");
    ndpi_serialize_string_uint32(serializer, "request_code", flow->protos.ntp.request_code);
    ndpi_serialize_string_uint32(serializer, "version", flow->protos.ntp.request_code);
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

  case NDPI_PROTOCOL_STUN:
    ndpi_serialize_start_of_block(serializer, "stun");
    ndpi_serialize_string_uint32(serializer, "num_pkts", flow->stun.num_pkts);
    ndpi_serialize_string_uint32(serializer, "num_binding_requests",
                                 flow->stun.num_binding_requests);
    ndpi_serialize_string_uint32(serializer, "num_processed_pkts",
                                 flow->stun.num_processed_pkts);
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
      ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);
      if (risk != NDPI_NO_RISK)
      {
        NDPI_SET_BIT(flow->risk, risk);
      }
      ndpi_serialize_string_string(serializer, "url", flow->http.url);
      ndpi_serialize_string_uint32(serializer, "code", flow->http.response_status_code);
      ndpi_serialize_string_string(serializer, "content_type", flow->http.content_type);
      ndpi_serialize_string_string(serializer, "user_agent", flow->http.user_agent);
    }
    if (flow->http.request_content_type != NULL)
    {
      ndpi_serialize_string_string(serializer, "request_content_type",
                                   flow->http.request_content_type);
    }
    if (flow->http.detected_os != NULL)
    {
      ndpi_serialize_string_string(serializer, "detected_os",
                                   flow->http.detected_os);
    }
    if (flow->http.nat_ip != NULL)
    {
      ndpi_serialize_string_string(serializer, "nat_ip",
                                   flow->http.nat_ip);
    }
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_QUIC:
    ndpi_serialize_start_of_block(serializer, "quic");
    if(flow->http.user_agent)
      ndpi_serialize_string_string(serializer, "user_agent", flow->http.user_agent);

    ndpi_tls2json(serializer, flow);

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

  case NDPI_PROTOCOL_DISCORD:
    if (l7_protocol.master_protocol != NDPI_PROTOCOL_TLS) {
      ndpi_serialize_start_of_block(serializer, "discord");
      ndpi_serialize_string_string(serializer, "client_ip", flow->protos.discord.client_ip);
      ndpi_serialize_end_of_block(serializer);
    }
    break;

  case NDPI_PROTOCOL_SSH:
    ndpi_serialize_start_of_block(serializer, "ssh");
    ndpi_serialize_string_string(serializer,  "client_signature", flow->protos.ssh.client_signature);
    ndpi_serialize_string_string(serializer,  "server_signature", flow->protos.ssh.server_signature);
    ndpi_serialize_string_string(serializer,  "hassh_client", flow->protos.ssh.hassh_client);
    ndpi_serialize_string_string(serializer,  "hassh_server", flow->protos.ssh.hassh_server);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_TLS:
  case NDPI_PROTOCOL_DTLS:
    ndpi_tls2json(serializer, flow);
    break;
  } /* switch */

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

  case 112:
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

  ndpi_serialize_string_string(serializer, "src_ip", src_name);
  ndpi_serialize_string_string(serializer, "dest_ip", dst_name);
  if(src_port) ndpi_serialize_string_uint32(serializer, "src_port", ntohs(src_port));
  if(dst_port) ndpi_serialize_string_uint32(serializer, "dst_port", ntohs(dst_port));

  ndpi_serialize_string_uint32(serializer, "ip", ip_version);

  ndpi_serialize_string_string(serializer, "proto", ndpi_get_ip_proto_name(l4_protocol, l4_proto_name, sizeof(l4_proto_name)));

  return(ndpi_dpi2json(ndpi_struct, flow, l7_protocol, serializer));
}

/* ********************************** */

const char* ndpi_tunnel2str(ndpi_packet_tunnel tt) {
  switch(tt) {
  case ndpi_no_tunnel:
    return("No-Tunnel");
    break;

  case ndpi_gtp_tunnel:
    return("GTP");
    break;

  case ndpi_capwap_tunnel:
    return("CAPWAP");
    break;

  case ndpi_tzsp_tunnel:
    return("TZSP");
    break;

  case ndpi_l2tp_tunnel:
    return("L2TP");
    break;

  case ndpi_vxlan_tunnel:
    return("VXLAN");
    break;

  case ndpi_gre_tunnel:
    return("GRE");
    break;
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
			 !sscanf(s - 2, "%2x", (unsigned int*)&c)))
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

#ifdef HAVE_PCRE

static void ndpi_compile_rce_regex() {
  const char *pcreErrorStr = NULL;
  int pcreErrorOffset;

  for(int i = 0; i < N_RCE_REGEX; i++) {
    comp_rx[i] = (struct pcre_struct*)ndpi_malloc(sizeof(struct pcre_struct));

    comp_rx[i]->compiled = pcre_compile(rce_regex[i], 0, &pcreErrorStr,
                                        &pcreErrorOffset, NULL);

    if(comp_rx[i]->compiled == NULL) {
#ifdef DEBUG
      NDPI_LOG_ERR(ndpi_str, "ERROR: Could not compile '%s': %s\n", rce_regex[i],
                   pcreErrorStr);
#endif

      continue;
    }

    comp_rx[i]->optimized = pcre_study(comp_rx[i]->compiled, 0, &pcreErrorStr);

#ifdef DEBUG
    if(pcreErrorStr != NULL) {
      NDPI_LOG_ERR(ndpi_str, "ERROR: Could not study '%s': %s\n", rce_regex[i],
                   pcreErrorStr);
    }
#endif
  }

  ndpi_free((void *)pcreErrorStr);
}

static int ndpi_is_rce_injection(char* query) {
  if(!initialized_comp_rx) {
    ndpi_compile_rce_regex();
    initialized_comp_rx = 1;
  }

  int pcreExecRet;
  int subStrVec[30];

  for(int i = 0; i < N_RCE_REGEX; i++) {
    unsigned int length = strlen(query);

    pcreExecRet = pcre_exec(comp_rx[i]->compiled,
                            comp_rx[i]->optimized,
                            query, length, 0, 0, subStrVec, 30);

    if(pcreExecRet >= 0) {
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

  for(unsigned long i = 0; i < ushlen; i++) {
    if(strstr(query, ush_commands[i]) != NULL) {
      return 1;
    }
  }

  size_t pwshlen = sizeof(pwsh_commands) / sizeof(pwsh_commands[0]);

  for(unsigned long i = 0; i < pwshlen; i++) {
    if(strstr(query, pwsh_commands[i]) != NULL) {
      return 1;
    }
  }

  return 0;
}

#endif

/* ********************************** */

ndpi_risk_enum ndpi_validate_url(char *url) {
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
#ifdef HAVE_PCRE
	  else if(ndpi_is_rce_injection(decoded))
	    rc = NDPI_URL_POSSIBLE_RCE_INJECTION;
#endif

#ifdef URL_CHECK_DEBUG
	  printf("=>> [rc: %u] %s\n", rc, decoded);
#endif
	}

	ndpi_free(decoded);

	if(rc != NDPI_NO_RISK)
	  break;
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

u_int8_t ndpi_is_protocol_detected(struct ndpi_detection_module_struct *ndpi_str,
				   ndpi_protocol proto) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
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

  case NDPI_TLS_SUSPICIOUS_ESNI_USAGE:
    return("TLS Susp ESNI Usage");

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

  case NDPI_MALICIOUS_JA3:
    return("Malicious JA3 Fingerp.");

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
    return("Text With Non-Printable Chars");

  case NDPI_POSSIBLE_EXPLOIT:
    return("Possible Exploit");

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

  default:
    ndpi_snprintf(buf, sizeof(buf), "%d", (int)risk);
    return(buf);
  }
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
  case NDPI_HTTP_METHOD_RPC_IN_DATA:  return("RPC_IN_DATA");
  case NDPI_HTTP_METHOD_RPC_OUT_DATA: return("RPC_OUT_DATA");
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

  case 'P':
    switch(method[1]) {
    case 'A':return(NDPI_HTTP_METHOD_PATCH);
    case 'O':return(NDPI_HTTP_METHOD_POST);
    case 'U':return(NDPI_HTTP_METHOD_PUT);
    }
    break;

  case 'D':  return(NDPI_HTTP_METHOD_DELETE);
  case 'T':  return(NDPI_HTTP_METHOD_TRACE);
  case 'C':  return(NDPI_HTTP_METHOD_CONNECT);
  case 'R':
    if(method_len >= 11) {
      if(strncmp(method, "RPC_IN_DATA", 11) == 0)
	return(NDPI_HTTP_METHOD_RPC_IN_DATA);
      else if(strncmp(method, "RPC_OUT_DATA", 11) == 0)
	return(NDPI_HTTP_METHOD_RPC_OUT_DATA);
    }
    break;
  }

  return(NDPI_HTTP_METHOD_UNKNOWN);
}

/* ******************************************************************** */

#define ROR64(x,r) (((x)>>(r))|((x)<<(64-(r))))

/*
  'in_16_bytes_long` points to some 16 byte memory data to be hashed;
  two independent 64-bit linear congruential generators are applied
  results are mixed, scrambled and cast to 32-bit
*/
u_int32_t ndpi_quick_16_byte_hash(u_int8_t *in_16_bytes_long) {
  u_int64_t a = *(u_int64_t*)(in_16_bytes_long + 0);
  u_int64_t c = *(u_int64_t*)(in_16_bytes_long + 8);

  // multipliers are taken from sprng.org, addends are prime
  a = a * 0x2c6fe96ee78b6955 + 0x9af64480a3486659;
  c = c * 0x369dea0f31a53f85 + 0xd0c6225445b76b5b;

  // mix results
  a += c;

  // final scramble
  a ^= ROR64(a, 13) ^ ROR64(a, 7);

  // down-casting, also taking advantage of upper half
  a ^= a >> 32;

  return((u_int32_t)a);
}

/* ******************************************************************** */

int ndpi_hash_init(ndpi_str_hash **h)
{
  if (h == NULL)
  {
    return 1;
  }

  *h = NULL;
  return 0;
}

/* ******************************************************************** */

void ndpi_hash_free(ndpi_str_hash **h, void (*cleanup_func)(ndpi_str_hash *h))
{
  struct ndpi_str_hash_private *h_priv;
  struct ndpi_str_hash_private *current, *tmp;

  if (h == NULL)
  {
    return;
  }
  h_priv = *(struct ndpi_str_hash_private **)h;

  HASH_ITER(hh, h_priv, current, tmp) {
    HASH_DEL(h_priv, current);
    if (cleanup_func != NULL)
    {
      cleanup_func((ndpi_str_hash *)current);
    }
    ndpi_free(current);
  }

  *h = NULL;
}

/* ******************************************************************** */

int ndpi_hash_find_entry(ndpi_str_hash *h, char *key, u_int key_len, void **value)
{
  struct ndpi_str_hash_private *h_priv = (struct ndpi_str_hash_private *)h;
  struct ndpi_str_hash_private *found;
  unsigned int hash_value;

  HASH_VALUE(key, key_len, hash_value);
  HASH_FIND_INT(h_priv, &hash_value, found);
  if (found != NULL)
  {
    if (value != NULL)
    {
      *value = found->value;
    }
    return 0;
  } else {
    return 1;
  }
}

/* ******************************************************************** */

int ndpi_hash_add_entry(ndpi_str_hash **h, char *key, u_int8_t key_len, void *value)
{
  struct ndpi_str_hash_private **h_priv = (struct ndpi_str_hash_private **)h;
  struct ndpi_str_hash_private *new = ndpi_calloc(1, sizeof(*new));
  unsigned int hash_value;

  if (new == NULL)
  {
    return 1;
  }

  HASH_VALUE(key, key_len, hash_value);
  new->hash = hash_value;
  new->value = value;
  HASH_ADD_INT(*h_priv, hash, new);
  return 0;
}

/* ********************************************************************************* */

static u_int64_t ndpi_host_ip_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					       struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str->protocols_ptree)
    return((u_int64_t)-1);

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_mask_ptree, &prefix);

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

static void ndpi_handle_risk_exceptions(struct ndpi_detection_module_struct *ndpi_str,
					struct ndpi_flow_struct *flow) {
  char *host;

  if(flow->risk == 0) return; /* Nothing to do */

  host = ndpi_get_flow_name(flow);

  if((!flow->host_risk_mask_evaluated) && (!flow->ip_risk_mask_evaluated)) {
    flow->risk_mask = (u_int64_t)-1; /* No mask */
  }

  if(!flow->host_risk_mask_evaluated) {
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
	}
	
	flow->num_risk_infos = 0;
      }
      
      /* Used to avoid double checks (e.g. in DNS req/rsp) */
      flow->host_risk_mask_evaluated = 1;
    }
  }

  /* TODO: add IPv6 support */
  if(!flow->ip_risk_mask_evaluated) {
    if(flow->is_ipv6 == 0) {
      ndpi_check_ipv4_exception(ndpi_str, flow, flow->c_address.v4 /* Client */);
      ndpi_check_ipv4_exception(ndpi_str, flow, flow->s_address.v4 /* Server */);
    }

    flow->ip_risk_mask_evaluated = 1;
  }

  flow->risk &= flow->risk_mask;
}

/* ******************************************************************** */

void ndpi_set_risk(struct ndpi_detection_module_struct *ndpi_str,
		   struct ndpi_flow_struct *flow, ndpi_risk_enum r,
		   char *risk_message) {
  /* Check if the risk is not yet set */
  if(!ndpi_isset_risk(ndpi_str, flow, r)) {
    ndpi_risk v = 1ull << r;
    
    // NDPI_SET_BIT(flow->risk, (u_int32_t)r);
    flow->risk |= v;
    
    ndpi_handle_risk_exceptions(ndpi_str, flow);

    if(flow->risk != 0 /* check if it has been masked */) {
      if(risk_message != NULL) {
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
  } else if(risk_message) {
    u_int8_t i;

    for(i = 0; i < flow->num_risk_infos; i++)
      if(flow->risk_infos[i].id == r)
        return;

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
  if(ndpi_isset_risk(ndpi_str, flow, r)) {
    u_int8_t i, j;
    ndpi_risk v = 1ull << r;

    flow->risk &= ~v;

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

int ndpi_isset_risk(struct ndpi_detection_module_struct *ndpi_str,
		     struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  ndpi_risk v = 1ull << r;

  return(((flow->risk & v) == v) ?  1 : 0);
}

/* ******************************************************************** */

int ndpi_is_printable_buffer(uint8_t const * const buf, size_t len) {
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

int ndpi_is_valid_hostname(char * const str, size_t len) {
  size_t i;

  for(i = 0; i < len; ++i) {
    if((str[i] == '.')
       || (str[i] == '-')
       || (str[i] == '_')
       || (str[i] == ':')
       )
      continue; /* Used in hostnames */    
    else if((ndpi_isprint(str[i]) == 0)       
	    || ndpi_isspace(str[i])
	    || ndpi_ispunct(str[i])
	    ) {
      return(0);
    }
  }
  
  return(1);
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
static inline uint16_t get_n16bit(uint8_t const * cbuf) {
  uint16_t r = ((uint16_t)cbuf[0]) | (((uint16_t)cbuf[1]) << 8);
  return r;
}

u_int16_t ndpi_calculate_icmp4_checksum(const u_int8_t * buf, size_t len) {
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

u_int8_t ndpi_is_valid_protoId(u_int16_t protoId) {
  return((protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS) ? 0 : 1);
}

/* ******************************************* */

u_int8_t ndpi_is_encrypted_proto(struct ndpi_detection_module_struct *ndpi_str,
				 ndpi_protocol proto) {
  if(proto.master_protocol == NDPI_PROTOCOL_UNKNOWN && ndpi_is_valid_protoId(proto.app_protocol)) {
    return(!ndpi_str->proto_defaults[proto.app_protocol].isClearTextProto);
  } else if(ndpi_is_valid_protoId(proto.master_protocol) && ndpi_is_valid_protoId(proto.app_protocol)) {
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

void ndpi_set_tls_cert_expire_days(struct ndpi_detection_module_struct *ndpi_str,
				   u_int8_t num_days) {
  if(ndpi_str)
    ndpi_str->tls_certificate_expire_in_x_days = num_days;
}

/* ******************************************* */

u_int32_t ndpi_get_flow_error_code(struct ndpi_flow_struct *flow) {
  switch(flow->detected_protocol_stack[0] /* app_protocol */) {
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
#ifdef WIN32
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
  int ret = ndpi_vsnprintf(str, size, format, va_args);
  va_end(va_args);

  return ret;
}

/* ******************************************* */

char* ndpi_get_flow_risk_info(struct ndpi_flow_struct *flow,
			      char *out, u_int out_len,
			      u_int8_t use_json) {
  u_int i, offset = 0;
  
  if((out == NULL)
     || (flow == NULL)
     || (flow->num_risk_infos == 0))
    return(NULL);

  if(use_json) {
    ndpi_serializer serializer;
    u_int32_t buffer_len;
    char *buffer;
    
    if(ndpi_init_serializer(&serializer, ndpi_serialization_format_json) == -1)
      return(NULL);

    for(i=0; i<flow->num_risk_infos; i++)
      ndpi_serialize_uint32_string(&serializer,
				   flow->risk_infos[i].id, 
				   flow->risk_infos[i].info);  
    
    buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

    if(buffer && (buffer_len > 0)) {
      u_int l = ndpi_min(out_len-1, buffer_len);

      strncpy(out, buffer, l);
      out[l] = '\0';
    }
    
    ndpi_term_serializer(&serializer);

    return(out);
  } else {
    out[0] = '\0', out_len--;
    
    for(i=0; (i<flow->num_risk_infos) && (out_len > offset); i++) {
      int rc = snprintf(&out[offset], out_len-offset, "%s%s",
			(i == 0) ? "" : " / ",
			flow->risk_infos[i].info);
      
      if(rc <= 0)
	break;
      else
	offset += rc;
    }
    
    if(offset > out_len) offset = out_len;
    
    out[offset] = '\0';
  
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

    case NDPI_MAX_RISK_PARAM_ID:
      /* Nothing to do, just avoid warnings */
      break;

    default:
      printf("nDPI [%s:%u] Ignored risk parameter id %u\n",
	     __FILE__, __LINE__, params[i].id);
      break;
    }
  }
  
  return(0);
}

/* ******************************************* */

int64_t ndpi_asn1_ber_decode_length(const unsigned char *payload, int payload_len, u_int16_t *value_len)
{
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
