/*
 * ndpi_utils.cc
 *
 * Copyright (C) 2011-19 - ntop.org
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

#ifdef HAVE_CONFIG_H
#include "ndpi_config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include "ahocorasick.h"
#include "libcache.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_api.h"
#include "ndpi_config.h"

#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "third_party/include/ndpi_patricia.h"
#include "third_party/include/ht_hash.h"

#define NDPI_CONST_GENERIC_PROTOCOL_NAME  "GenericProtocol"

// #define MATCH_DEBUG 1

/* implementation of the punycode check function */
int ndpi_check_punycode_string(char * buffer , int len) {
  int i = 0;

  while(i++ < len) {
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
      return ((void *)*rootp);	/* we found it! */
    rootp = (r < 0) ?
      &(*rootp)->left :		/* T3: follow left branch */
      &(*rootp)->right;		/* T4: follow right branch */
  }
  q = (ndpi_node *) ndpi_malloc(sizeof(ndpi_node));	/* T5: key not found */
  if(q != (ndpi_node *)0) {	/* make new node */
    *rootp = q;			/* link new node to old */
    q->key = key;		/* initialize new node */
    q->left = q->right = (ndpi_node *)0;
  }
  return ((void *)q);
}

/* delete node with given key */
void * ndpi_tdelete(const void *vkey, void **vrootp,
		    int (*compar)(const void *, const void *))
{
  ndpi_node **rootp = (ndpi_node **)vrootp;
  char *key = (char *)vkey;
  ndpi_node *p = (ndpi_node *)1;
  ndpi_node *q;
  ndpi_node *r;
  int cmp;

  if(rootp == (ndpi_node **)0 || *rootp == (ndpi_node *)0)
    return ((ndpi_node *)0);
  while ((cmp = (*compar)(key, (*rootp)->key)) != 0) {
    p = *rootp;
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
  ndpi_free((ndpi_node *) *rootp);	/* D4: Free node */
  *rootp = q;				/* link parent to new node */
  return(p);
}

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

/* Walk the nodes of a tree */
void ndpi_twalk(const void *vroot, void (*action)(const void *, ndpi_VISIT, int, void *), void *user_data)
{
  ndpi_node *root = (ndpi_node *)vroot;

  if(root != (ndpi_node *)0 && action != (void (*)(const void *, ndpi_VISIT, int, void*))0)
    ndpi_trecurse(root, action, 0, user_data);
}

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
			u_int32_t num_bits)
{
  u_int32_t mask = 0;

  mask = ~(~mask >> num_bits);

  return(((ip_to_check & mask) == (net & mask)) ? 1 : 0);
}

u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
			u_int32_t net, u_int32_t num_bits)
{
  return(ndpi_net_match(src, net, num_bits) || ndpi_net_match(dst, net, num_bits));
}

/* ****************************************** */

#ifdef WIN32
/* http://opensource.apple.com/source/Libc/Libc-186/string.subproj/strcasecmp.c */

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static const u_char charmap[] = {
				 '\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
				 '\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
				 '\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
				 '\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
				 '\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
				 '\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
				 '\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
				 '\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
				 '\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
				 '\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
				 '\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
				 '\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
				 '\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
				 '\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
				 '\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
				 '\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
				 '\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
				 '\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
				 '\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
				 '\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
				 '\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
				 '\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
				 '\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
				 '\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
				 '\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
				 '\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
				 '\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
				 '\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
				 '\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
				 '\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
				 '\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
				 '\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
};

int strcasecmp(const char *s1, const char *s2) {
  register const u_char *cm = charmap,
    *us1 = (const u_char *)s1,
    *us2 = (const u_char *)s2;

  while (cm[*us1] == cm[*us2++])
    if(*us1++ == '\0')
      return (0);
  return (cm[*us1] - cm[*--us2]);
}

/* ****************************************** */

int strncasecmp(const char *s1, const char *s2, size_t n) {
  if(n != 0) {
    register const u_char *cm = charmap,
      *us1 = (const u_char *)s1,
      *us2 = (const u_char *)s2;

    do {
      if(cm[*us1] != cm[*us2++])
	return (cm[*us1] - cm[*--us2]);
      if(*us1++ == '\0')
	break;
    } while (--n != 0);
  }
  return (0);
}

#endif

/* **************************************** */

u_int8_t ndpi_is_safe_ssl_cipher(u_int32_t cipher) {
  /* https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites */
  /* INSECURE */
  switch(cipher) {
  case 0xc011: return(NDPI_CIPHER_INSECURE); /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
  case 0x0005: return(NDPI_CIPHER_INSECURE); /* TLS_RSA_WITH_RC4_128_SHA */
  case 0x0004: return(NDPI_CIPHER_INSECURE); /* TLS_RSA_WITH_RC4_128_MD5 */
    /* WEAK */
  case 0x009d: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
  case 0x003d: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
  case 0x0035: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_256_CBC_SHA */
  case 0x0084: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
  case 0x009c: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
  case 0x003c: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
  case 0x002f: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_AES_128_CBC_SHA */
  case 0x0041: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
  case 0xc012: return(NDPI_CIPHER_WEAK); /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
  case 0x0016: return(NDPI_CIPHER_WEAK); /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
  case 0x000a: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
  case 0x0096: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_SEED_CBC_SHA */
  case 0x0007: return(NDPI_CIPHER_WEAK); /* TLS_RSA_WITH_IDEA_CBC_SHA */
  default:     return(NDPI_CIPHER_SAFE);
  }
}

/* ***************************************************** */

const char* ndpi_cipher2str(u_int32_t cipher) {
  switch(cipher) {
  case 0x000000: return("TLS_NULL_WITH_NULL_NULL");
  case 0x000001: return("TLS_RSA_WITH_NULL_MD5");
  case 0x000002: return("TLS_RSA_WITH_NULL_SHA");
  case 0x000003: return("TLS_RSA_EXPORT_WITH_RC4_40_MD5");
  case 0x000004: return("TLS_RSA_WITH_RC4_128_MD5");
  case 0x000005: return("TLS_RSA_WITH_RC4_128_SHA");
  case 0x000006: return("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5");
  case 0x000007: return("TLS_RSA_WITH_IDEA_CBC_SHA");
  case 0x000008: return("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000009: return("TLS_RSA_WITH_DES_CBC_SHA");
  case 0x00000a: return("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00000b: return("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00000c: return("TLS_DH_DSS_WITH_DES_CBC_SHA");
  case 0x00000d: return("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x00000e: return("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00000f: return("TLS_DH_RSA_WITH_DES_CBC_SHA");
  case 0x000010: return("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x000011: return("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000012: return("TLS_DHE_DSS_WITH_DES_CBC_SHA");
  case 0x000013: return("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x000014: return("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA");
  case 0x000015: return("TLS_DHE_RSA_WITH_DES_CBC_SHA");
  case 0x000016: return("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x000017: return("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5");
  case 0x000018: return("TLS_DH_anon_WITH_RC4_128_MD5");
  case 0x000019: return("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA");
  case 0x00001a: return("TLS_DH_anon_WITH_DES_CBC_SHA");
  case 0x00001b: return("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA");
  case 0x00001c: return("SSL_FORTEZZA_KEA_WITH_NULL_SHA");
  case 0x00001d: return("SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA");
    /* case 0x00001e: return("SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"); */
  case 0x00001E: return("TLS_KRB5_WITH_DES_CBC_SHA");
  case 0x00001F: return("TLS_KRB5_WITH_3DES_EDE_CBC_SHA");
  case 0x000020: return("TLS_KRB5_WITH_RC4_128_SHA");
  case 0x000021: return("TLS_KRB5_WITH_IDEA_CBC_SHA");
  case 0x000022: return("TLS_KRB5_WITH_DES_CBC_MD5");
  case 0x000023: return("TLS_KRB5_WITH_3DES_EDE_CBC_MD5");
  case 0x000024: return("TLS_KRB5_WITH_RC4_128_MD5");
  case 0x000025: return("TLS_KRB5_WITH_IDEA_CBC_MD5");
  case 0x000026: return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA");
  case 0x000027: return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA");
  case 0x000028: return("TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
  case 0x000029: return("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5");
  case 0x00002A: return("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5");
  case 0x00002B: return("TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
  case 0x00002C: return("TLS_PSK_WITH_NULL_SHA");
  case 0x00002D: return("TLS_DHE_PSK_WITH_NULL_SHA");
  case 0x00002E: return("TLS_RSA_PSK_WITH_NULL_SHA");
  case 0x00002f: return("TLS_RSA_WITH_AES_128_CBC_SHA");
  case 0x000030: return("TLS_DH_DSS_WITH_AES_128_CBC_SHA");
  case 0x000031: return("TLS_DH_RSA_WITH_AES_128_CBC_SHA");
  case 0x000032: return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");
  case 0x000033: return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
  case 0x000034: return("TLS_DH_anon_WITH_AES_128_CBC_SHA");
  case 0x000035: return("TLS_RSA_WITH_AES_256_CBC_SHA");
  case 0x000036: return("TLS_DH_DSS_WITH_AES_256_CBC_SHA");
  case 0x000037: return("TLS_DH_RSA_WITH_AES_256_CBC_SHA");
  case 0x000038: return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");
  case 0x000039: return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
  case 0x00003A: return("TLS_DH_anon_WITH_AES_256_CBC_SHA");
  case 0x00003B: return("TLS_RSA_WITH_NULL_SHA256");
  case 0x00003C: return("TLS_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00003D: return("TLS_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00003E: return("TLS_DH_DSS_WITH_AES_128_CBC_SHA256");
  case 0x00003F: return("TLS_DH_RSA_WITH_AES_128_CBC_SHA256");
  case 0x000040: return("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");
  case 0x000041: return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000042: return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000043: return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000044: return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000045: return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000046: return("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA");
  case 0x000047: return("TLS_ECDH_ECDSA_WITH_NULL_SHA");
  case 0x000048: return("TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
  case 0x000049: return("TLS_ECDH_ECDSA_WITH_DES_CBC_SHA");
  case 0x00004A: return("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00004B: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00004C: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x000060: return("TLS_RSA_EXPORT1024_WITH_RC4_56_MD5");
  case 0x000061: return("TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5");
  case 0x000062: return("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA");
  case 0x000063: return("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA");
  case 0x000064: return("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA");
  case 0x000065: return("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA");
  case 0x000066: return("TLS_DHE_DSS_WITH_RC4_128_SHA");
  case 0x000067: return("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
  case 0x000068: return("TLS_DH_DSS_WITH_AES_256_CBC_SHA256");
  case 0x000069: return("TLS_DH_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00006A: return("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");
  case 0x00006B: return("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
  case 0x00006C: return("TLS_DH_anon_WITH_AES_128_CBC_SHA256");
  case 0x00006D: return("TLS_DH_anon_WITH_AES_256_CBC_SHA256");
  case 0x000084: return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000085: return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000086: return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000087: return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000088: return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA");
  case 0x000089: return("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA");
  case 0x00008A: return("TLS_PSK_WITH_RC4_128_SHA");
  case 0x00008B: return("TLS_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x00008C: return("TLS_PSK_WITH_AES_128_CBC_SHA");
  case 0x00008D: return("TLS_PSK_WITH_AES_256_CBC_SHA");
  case 0x00008E: return("TLS_DHE_PSK_WITH_RC4_128_SHA");
  case 0x00008F: return("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x000090: return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA");
  case 0x000091: return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA");
  case 0x000092: return("TLS_RSA_PSK_WITH_RC4_128_SHA");
  case 0x000093: return("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x000094: return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA");
  case 0x000095: return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA");
  case 0x000096: return("TLS_RSA_WITH_SEED_CBC_SHA");
  case 0x000097: return("TLS_DH_DSS_WITH_SEED_CBC_SHA");
  case 0x000098: return("TLS_DH_RSA_WITH_SEED_CBC_SHA");
  case 0x000099: return("TLS_DHE_DSS_WITH_SEED_CBC_SHA");
  case 0x00009A: return("TLS_DHE_RSA_WITH_SEED_CBC_SHA");
  case 0x00009B: return("TLS_DH_anon_WITH_SEED_CBC_SHA");
  case 0x00009C: return("TLS_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00009D: return("TLS_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00009E: return("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00009F: return("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
  case 0x0000A0: return("TLS_DH_RSA_WITH_AES_128_GCM_SHA256");
  case 0x0000A1: return("TLS_DH_RSA_WITH_AES_256_GCM_SHA384");
  case 0x0000A2: return("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");
  case 0x0000A3: return("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");
  case 0x0000A4: return("TLS_DH_DSS_WITH_AES_128_GCM_SHA256");
  case 0x0000A5: return("TLS_DH_DSS_WITH_AES_256_GCM_SHA384");
  case 0x0000A6: return("TLS_DH_anon_WITH_AES_128_GCM_SHA256");
  case 0x0000A7: return("TLS_DH_anon_WITH_AES_256_GCM_SHA384");
  case 0x0000A8: return("TLS_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000A9: return("TLS_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AA: return("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000AB: return("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AC: return("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256");
  case 0x0000AD: return("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384");
  case 0x0000AE: return("TLS_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000AF: return("TLS_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B0: return("TLS_PSK_WITH_NULL_SHA256");
  case 0x0000B1: return("TLS_PSK_WITH_NULL_SHA384");
  case 0x0000B2: return("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000B3: return("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B4: return("TLS_DHE_PSK_WITH_NULL_SHA256");
  case 0x0000B5: return("TLS_DHE_PSK_WITH_NULL_SHA384");
  case 0x0000B6: return("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256");
  case 0x0000B7: return("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384");
  case 0x0000B8: return("TLS_RSA_PSK_WITH_NULL_SHA256");
  case 0x0000B9: return("TLS_RSA_PSK_WITH_NULL_SHA384");
  case 0x0000BA: return("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BB: return("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BC: return("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BD: return("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BE: return("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000BF: return("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256");
  case 0x0000C0: return("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C1: return("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C2: return("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C3: return("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C4: return("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000C5: return("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256");
  case 0x0000FF: return("TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
  case 0x00c001: return("TLS_ECDH_ECDSA_WITH_NULL_SHA");
  case 0x00c002: return("TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
  case 0x00c003: return("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c004: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00c005: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x00c006: return("TLS_ECDHE_ECDSA_WITH_NULL_SHA");
  case 0x00c007: return("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
  case 0x00c008: return("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c009: return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
  case 0x00c00a: return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
  case 0x00c00b: return("TLS_ECDH_RSA_WITH_NULL_SHA");
  case 0x00c00c: return("TLS_ECDH_RSA_WITH_RC4_128_SHA");
  case 0x00c00d: return("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c00e: return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA");
  case 0x00c00f: return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA");
  case 0x00c010: return("TLS_ECDHE_RSA_WITH_NULL_SHA");
  case 0x00c011: return("TLS_ECDHE_RSA_WITH_RC4_128_SHA");
  case 0x00c012: return("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00c013: return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
  case 0x00c014: return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
  case 0x00c015: return("TLS_ECDH_anon_WITH_NULL_SHA");
  case 0x00c016: return("TLS_ECDH_anon_WITH_RC4_128_SHA");
  case 0x00c017: return("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA");
  case 0x00c018: return("TLS_ECDH_anon_WITH_AES_128_CBC_SHA");
  case 0x00c019: return("TLS_ECDH_anon_WITH_AES_256_CBC_SHA");
  case 0x00C01A: return("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01B: return("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01C: return("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA");
  case 0x00C01D: return("TLS_SRP_SHA_WITH_AES_128_CBC_SHA");
  case 0x00C01E: return("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA");
  case 0x00C01F: return("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA");
  case 0x00C020: return("TLS_SRP_SHA_WITH_AES_256_CBC_SHA");
  case 0x00C021: return("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA");
  case 0x00C022: return("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA");
  case 0x00C023: return("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
  case 0x00C024: return("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
  case 0x00C025: return("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256");
  case 0x00C026: return("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384");
  case 0x00C027: return("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00C028: return("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
  case 0x00C029: return("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256");
  case 0x00C02A: return("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384");
  case 0x00C02B: return("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  case 0x00C02C: return("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  case 0x00C02D: return("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
  case 0x00C02E: return("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384");
  case 0x00C02F: return("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00C030: return("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00C031: return("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256");
  case 0x00C032: return("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384");
  case 0x00C033: return("TLS_ECDHE_PSK_WITH_RC4_128_SHA");
  case 0x00C034: return("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA");
  case 0x00C035: return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA");
  case 0x00C036: return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA");
  case 0x00C037: return("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256");
  case 0x00C038: return("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384");
  case 0x00C039: return("TLS_ECDHE_PSK_WITH_NULL_SHA");
  case 0x00C03A: return("TLS_ECDHE_PSK_WITH_NULL_SHA256");
  case 0x00C03B: return("TLS_ECDHE_PSK_WITH_NULL_SHA384");
  case 0x00CC13: return("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CC14: return("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CC15: return("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCA8: return("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCA9: return("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAA: return("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAB: return("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAC: return("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAD: return("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00CCAE: return("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256");
  case 0x00E410: return("TLS_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E411: return("TLS_RSA_WITH_SALSA20_SHA1");
  case 0x00E412: return("TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E413: return("TLS_ECDHE_RSA_WITH_SALSA20_SHA1");
  case 0x00E414: return("TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E415: return("TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1");
  case 0x00E416: return("TLS_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E417: return("TLS_PSK_WITH_SALSA20_SHA1");
  case 0x00E418: return("TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E419: return("TLS_ECDHE_PSK_WITH_SALSA20_SHA1");
  case 0x00E41A: return("TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41B: return("TLS_RSA_PSK_WITH_SALSA20_SHA1");
  case 0x00E41C: return("TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41D: return("TLS_DHE_PSK_WITH_SALSA20_SHA1");
  case 0x00E41E: return("TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1");
  case 0x00E41F: return("TLS_DHE_RSA_WITH_SALSA20_SHA1");
  case 0x00fefe: return("SSL_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x00feff: return("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe0: return("SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe1: return("SSL_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x010080: return("SSL2_RC4_128_WITH_MD5");
  case 0x020080: return("SSL2_RC4_128_EXPORT40_WITH_MD5");
  case 0x030080: return("SSL2_RC2_128_CBC_WITH_MD5");
  case 0x040080: return("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5");
  case 0x050080: return("SSL2_IDEA_128_CBC_WITH_MD5");
  case 0x060040: return("SSL2_DES_64_CBC_WITH_MD5");
  case 0x0700c0: return("SSL2_DES_192_EDE3_CBC_WITH_MD5");
  case 0x080080: return("SSL2_RC4_64_WITH_MD5");
  case 0x001301: return("TLS_AES_128_GCM_SHA256");
  case 0x001302: return("TLS_AES_256_GCM_SHA384");
  case 0x001303: return("TLS_CHACHA20_POLY1305_SHA256");
  case 0x001304: return("TLS_AES_128_CCM_SHA256");
  case 0x001305: return("TLS_AES_128_CCM_8_SHA256");

  default:
    {
      static char buf[8];

      snprintf(buf, sizeof(buf), "0X%04X", cipher);
      return(buf);
    }
  }
}

/* ******************************************************************** */

static int ndpi_is_other_char(char c) {
  return((c == '.')
	 || (c == ' ')
	 || (c == '@')
	 || (c == '/')
	 );
}

/* ******************************************************************** */

static int ndpi_is_valid_char(char c) {
  if(ispunct(c) && (!ndpi_is_other_char(c)))
    return(0);
  else
    return(isdigit(c)
	   || isalpha(c)
	   || ndpi_is_other_char(c));
}

/* ******************************************************************** */


static int ndpi_find_non_eng_bigrams(struct ndpi_detection_module_struct *ndpi_struct,
				     char *str) {
  char s[3];

  if((isdigit(str[0]) && isdigit(str[1]))
     || ndpi_is_other_char(str[0])
     || ndpi_is_other_char(str[1])
     )
    return(1);

  s[0] = tolower(str[0]), s[1] = tolower(str[1]), s[2] = '\0';

  return(ndpi_match_bigram(ndpi_struct, &ndpi_struct->bigrams_automa, s));
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

char* ndpi_ssl_version2str(u_int16_t version) {
  static char v[8];

  switch(version) {
  case 0x300: return("SSLv3");
  case 0x301: return("TLSv1");
  case 0x302: return("TLSv1.1");
  case 0x303: return("TLSv1.2");
  case 0x304: return("TLSv1.3");
  }

  if((version >= 0x7f00) && (version <= 0x7fff))
    return("TLSv1.3 (draft)");

  snprintf(v, sizeof(v), "%04X", version);
  return(v);
}

/* ********************************** */
/* ********************************** */

static u_int64_t ndpi_htonll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.lv[0] = htonl(v >> 32);
  u.lv[1] = htonl(v & 0xFFFFFFFFULL);
  return u.llv;
}

/* ********************************** */

static u_int64_t ndpi_ntohll(u_int64_t v) {
  union { u_int32_t lv[2]; u_int64_t llv; } u;
  u.llv = v;
  return ((u_int64_t)ntohl(u.lv[0]) << 32) | (u_int64_t)ntohl(u.lv[1]);
}

/* ********************************** */

/*
 * Escapes a string to be suitable for a JSON value, adding double quotes, and terminating the string with a null byte.
 * It is recommended to provide a destination buffer (dst) which is as large as double the source buffer (src) at least.
 * Upon successful return, these functions return the number of characters printed (excluding the null byte used to terminate the string).
 */
static int ndpi_json_string_escape(const char *src, int src_len, char *dst, int dst_max_len) {
  char c = 0;
  int i, j = 0;

  dst[j++] = '"';

  for (i = 0; i < src_len && j < dst_max_len; i++) {

    c = src[i];

    switch (c) {
      case '\\':
      case '"':
      case '/':
        dst[j++] = '\\';
        dst[j++] = c;
      break;
      case '\b':
        dst[j++] = '\\';
        dst[j++] = 'b';
      break;
      case '\t':
        dst[j++] = '\\';
        dst[j++] = 't';
      break;
      case '\n':
        dst[j++] = '\\';
        dst[j++] = 'n';
      break;
      case '\f':
        dst[j++] = '\\';
        dst[j++] = 'f';
      break;
      case '\r':
        dst[j++] = '\\';
        dst[j++] = 'r';
      break;
      default:
        if(c < ' ')
          ; /* non printable */
        else
          dst[j++] = c;
    }
  }

  dst[j++] = '"';
  dst[j+1] = '\0';

  return j;
}

/* ********************************** */

void ndpi_reset_serializer(ndpi_serializer *serializer) {
  if(serializer->fmt == ndpi_serialization_format_json) {
    u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
    /* Note: please keep a space at the beginning as it is used for arrays when an end-of-record is used */
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, " {}");
  } else if(serializer->fmt == ndpi_serialization_format_csv)
    serializer->size_used = 0;
  else
    serializer->size_used = 2 * sizeof(u_int8_t);      
}

/* ********************************** */

int ndpi_init_serializer(ndpi_serializer *serializer,
			 ndpi_serialization_format fmt) {
  serializer->buffer_size = 8192;
  serializer->buffer      = (u_int8_t *) malloc(serializer->buffer_size * sizeof(u_int8_t));

  if(serializer->buffer == NULL)
    return(-1);

  serializer->fmt         = fmt;

  serializer->buffer[0]   = 1; /* version */
  serializer->buffer[1]   = (u_int8_t) fmt;

  serializer->csv_separator[0] = ',';
  serializer->csv_separator[1] = '\0';

  ndpi_reset_serializer(serializer);

  if(fmt == ndpi_serialization_format_json)
    serializer->json_buffer = (char *) &serializer->buffer[2];

  return(1);
}

/* ********************************** */

void ndpi_serializer_set_csv_separator(ndpi_serializer *serializer, char separator) {
  serializer->csv_separator[0] = separator;
}

/* ********************************** */

void ndpi_term_serializer(ndpi_serializer *serializer) {
  if(serializer->buffer) {
    free(serializer->buffer);
    serializer->buffer_size = 0;
    serializer->buffer = NULL;
  }
}

/* ********************************** */

static int ndpi_extend_serializer_buffer(ndpi_serializer *serializer, u_int32_t min_len) {
  u_int32_t new_size;
  void *r;

  if(min_len < 1024)
    min_len = 1024;

  new_size = serializer->buffer_size + min_len;

  r = realloc((void *) serializer->buffer, new_size);

  if(r == NULL)
    return(-1);

  serializer->buffer = r;
  serializer->buffer_size = new_size;

  return(0);
}

/* ********************************** */

static void ndpi_serialize_single_uint32(ndpi_serializer *serializer,
					 u_int32_t s) {

  u_int32_t v = htonl(s);

  memcpy(&serializer->buffer[serializer->size_used], &v, sizeof(u_int32_t));
  serializer->size_used += sizeof(u_int32_t);
}

/* ********************************** */

static void ndpi_serialize_single_uint64(ndpi_serializer *serializer,
					 u_int64_t s) {

  u_int64_t v = ndpi_htonll(s);

  memcpy(&serializer->buffer[serializer->size_used], &v, sizeof(u_int64_t));
  serializer->size_used += sizeof(u_int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static void ndpi_serialize_single_float(ndpi_serializer *serializer, float s) {

  memcpy(&serializer->buffer[serializer->size_used], &s, sizeof(s));
  serializer->size_used += sizeof(float);
}

/* ********************************** */

static void ndpi_serialize_single_string(ndpi_serializer *serializer,
					 const char *s, u_int16_t slen) {
  u_int16_t l = htons(slen);

  memcpy(&serializer->buffer[serializer->size_used], &l, sizeof(u_int16_t));
  serializer->size_used += sizeof(u_int16_t);

  if(slen > 0)
    memcpy(&serializer->buffer[serializer->size_used], s, slen);

  serializer->size_used += slen;
}

/* ********************************** */

static void ndpi_deserialize_single_uint32(ndpi_serializer *deserializer,
					   u_int32_t *s) {
  *s = ntohl(*((u_int32_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(u_int32_t);
}

/* ********************************** */

static void ndpi_deserialize_single_int32(ndpi_serializer *deserializer,
					  int32_t *s) {
  *s = ntohl(*((int32_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(int32_t);
}

/* ********************************** */

static void ndpi_deserialize_single_uint64(ndpi_serializer *deserializer,
					   u_int64_t *s) {
  *s = ndpi_ntohll(*(u_int64_t*)&deserializer->buffer[deserializer->size_used]);
  deserializer->size_used += sizeof(u_int64_t);
}

/* ********************************** */

static void ndpi_deserialize_single_int64(ndpi_serializer *deserializer,
					  int64_t *s) {
  *s = ndpi_ntohll(*(int64_t*)&deserializer->buffer[deserializer->size_used]);
  deserializer->size_used += sizeof(int64_t);
}

/* ********************************** */

/* TODO: fix portability across platforms */
static void ndpi_deserialize_single_float(ndpi_serializer *deserializer,
					  float *s) {
  *s = *(float*)&deserializer->buffer[deserializer->size_used];
  deserializer->size_used += sizeof(float);
}

/* ********************************** */

static void ndpi_deserialize_single_string(ndpi_serializer *deserializer,
					   ndpi_string *v) {
  v->str_len = ntohs(*((u_int16_t *) &deserializer->buffer[deserializer->size_used]));
  deserializer->size_used += sizeof(u_int16_t);

  v->str = (char *) &deserializer->buffer[deserializer->size_used];
  deserializer->size_used += v->str_len;
}

/* ********************************** */

int ndpi_serialize_end_of_record(ndpi_serializer *serializer) {
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 1;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    if(!(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)) {
      serializer->json_buffer[0] = '[';
      serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, "]");
    }
    serializer->status |= NDPI_SERIALIZER_STATUS_ARRAY | NDPI_SERIALIZER_STATUS_EOR;
    serializer->status &= ~NDPI_SERIALIZER_STATUS_COMMA;
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_end_of_record;
  }

  return(0);
}

/* ********************************** */

static void ndpi_serialize_json_pre(ndpi_serializer *serializer) {
  if(serializer->status & NDPI_SERIALIZER_STATUS_EOR) {
    serializer->size_used--; /* Remove ']' */
    serializer->status &= ~NDPI_SERIALIZER_STATUS_EOR;
    serializer->buffer[serializer->size_used++] = ',';
    serializer->buffer[serializer->size_used++] = '{';
  } else {
    if(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)
      serializer->size_used--; /* Remove ']'*/
    serializer->size_used--; /* Remove '}'*/
  }
  if(serializer->status & NDPI_SERIALIZER_STATUS_COMMA)
    serializer->buffer[serializer->size_used++] = ',';
}

/* ********************************** */

static void ndpi_serialize_json_post(ndpi_serializer *serializer) {
  serializer->buffer[serializer->size_used++] = '}';
  if(serializer->status & NDPI_SERIALIZER_STATUS_ARRAY)
    serializer->buffer[serializer->size_used++] = ']';

  serializer->status |= NDPI_SERIALIZER_STATUS_COMMA;
}

/* ********************************** */

int ndpi_serialize_uint32_uint32(ndpi_serializer *serializer,
				 u_int32_t key, u_int32_t value) {
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":%u", key, value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%u", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_uint32;

    ndpi_serialize_single_uint32(serializer, key);
    ndpi_serialize_single_uint32(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_uint64(ndpi_serializer *serializer,
				 u_int32_t key, u_int64_t value) {
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int16_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":%llu", key, (unsigned long long)value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%llu",
				      (serializer->size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);

  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_uint64;

    ndpi_serialize_single_uint32(serializer, key);
    ndpi_serialize_single_uint64(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_uint32_string(ndpi_serializer *serializer,
				 u_int32_t key, const char *value) {
  u_int16_t slen = strlen(value);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int32_t) /* key */ +
    sizeof(u_int16_t) /* len */ +
    slen;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 24 + slen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "\"%u\":", key);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += ndpi_json_string_escape(value, slen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%s", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_uint32_string;

    ndpi_serialize_single_uint32(serializer, key);
    ndpi_serialize_single_string(serializer, value, slen);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int32(ndpi_serializer *serializer,
				const char *key, int32_t value) {
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%d", value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%d", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_int32;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_uint32(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_int64(ndpi_serializer *serializer,
				const char *key, int64_t value) {
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%lld", value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%lld", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_int64;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_uint32(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint32(ndpi_serializer *serializer,
				 const char *key, u_int32_t value) {
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int32_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%u", value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%u", (serializer->size_used > 0) ? serializer->csv_separator : "", value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_uint32;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_uint32(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_uint32_format(ndpi_serializer *serializer,
					const char *key, u_int32_t value,
					const char *format) {
  if(serializer->fmt == ndpi_serialization_format_json) {
    /*
      JSON supports base 10 numbers only
      http://cjihrig.com/blog/json-overview/
    */

    return(ndpi_serialize_string_uint32(serializer, key, value));
  } else
    return(ndpi_serialize_string_uint32_format(serializer, key, value, format));
}

/* ********************************** */

int ndpi_serialize_string_uint64(ndpi_serializer *serializer,
				 const char *key, u_int64_t value) {
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(u_int64_t);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      ":%llu", (unsigned long long)value);
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%llu", (serializer->size_used > 0) ? serializer->csv_separator : "",
				      (unsigned long long)value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_uint64;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_uint64(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_float(ndpi_serializer *serializer,
				const char *key, float value,
				const char *format /* e.f. "%.2f" */) {
  u_int16_t klen = strlen(key);
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen /* key */ +
    sizeof(float);

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 32 + klen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;

    serializer->buffer[serializer->size_used] = ':';
    serializer->size_used++;

    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, format, value);

    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    if(serializer->size_used > 0)
      serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, "%s", serializer->csv_separator);

    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, format, value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_float;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_float(serializer, value);
  }

  return(0);
}

/* ********************************** */

int ndpi_serialize_string_string(ndpi_serializer *serializer,
				 const char *key, const char *value) {
  u_int16_t klen = strlen(key), vlen = strlen(value);
  u_int32_t needed =
    sizeof(u_int8_t) /* type */ +
    sizeof(u_int16_t) /* key len */ +
    klen +
    sizeof(u_int16_t) /* len */ +
    vlen;
  u_int32_t buff_diff = serializer->buffer_size - serializer->size_used;

  if(serializer->fmt == ndpi_serialization_format_json)
    needed += 16 + klen + vlen;

  if(buff_diff < needed) {
    if(ndpi_extend_serializer_buffer(serializer, needed - buff_diff) < 0)
      return(-1);
    buff_diff = serializer->buffer_size - serializer->size_used;
  }

  if(serializer->fmt == ndpi_serialization_format_json) {
    ndpi_serialize_json_pre(serializer);
    serializer->size_used += ndpi_json_string_escape(key, klen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff, ":");
    buff_diff = serializer->buffer_size - serializer->size_used;
    serializer->size_used += ndpi_json_string_escape(value, vlen,
						     (char *) &serializer->buffer[serializer->size_used], buff_diff);
    buff_diff = serializer->buffer_size - serializer->size_used;
    ndpi_serialize_json_post(serializer);
  } else if(serializer->fmt == ndpi_serialization_format_csv) {
    serializer->size_used += snprintf((char *) &serializer->buffer[serializer->size_used], buff_diff,
				      "%s%s", (serializer->size_used > 0) ? serializer->csv_separator : "",
				      value);
  } else {
    serializer->buffer[serializer->size_used++] = ndpi_serialization_string_string;

    ndpi_serialize_single_string(serializer, key, klen);
    ndpi_serialize_single_string(serializer, value, vlen);
  }

  return(0);
}

/* ********************************** */
/* ********************************** */

int ndpi_init_deserializer_buf(ndpi_deserializer *deserializer,
			       u_int8_t *serialized_buffer,
			       u_int32_t serialized_buffer_len) {
  if(serialized_buffer_len < (2 * sizeof(u_int8_t)))
    return(-1);

  deserializer->buffer      = serialized_buffer;

  if(deserializer->buffer[0] != 1)
    return(-2); /* Invalid version */

  deserializer->buffer_size = serialized_buffer_len;
  deserializer->fmt         = deserializer->buffer[1];
  ndpi_reset_serializer(deserializer);

  return(0);
}

/* ********************************** */

int ndpi_init_deserializer(ndpi_deserializer *deserializer,
			   ndpi_serializer *serializer) {
  return(ndpi_init_deserializer_buf(deserializer,
				    serializer->buffer,
				    serializer->size_used));
}

/* ********************************** */

ndpi_serialization_element_type ndpi_deserialize_get_nextitem_type(ndpi_deserializer *deserializer) {
  ndpi_serialization_element_type et;

  if(deserializer->size_used >= deserializer->buffer_size)
    return(ndpi_serialization_unknown);

  et = (ndpi_serialization_element_type) deserializer->buffer[deserializer->size_used];

  return et;
}

/* ********************************** */

int ndpi_deserialize_end_of_record(ndpi_deserializer *deserializer) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_end_of_record) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_uint32(ndpi_deserializer *deserializer,
				   u_int32_t *key, u_int32_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_uint32_uint32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(deserializer, key);
    ndpi_deserialize_single_uint32(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_uint64(ndpi_deserializer *deserializer,
				   u_int32_t *key, u_int64_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_uint32_uint64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int16_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(deserializer, key);
    ndpi_deserialize_single_uint64(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_uint32_string(ndpi_deserializer *deserializer,
				   u_int32_t *key, ndpi_string *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_uint32_string) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int32_t) /* key */ +
      sizeof(u_int16_t) /* len */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_uint32(deserializer, key);
    ndpi_deserialize_single_string(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_int32(ndpi_deserializer *deserializer,
				  ndpi_string *key, int32_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_int32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_int32(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_int64(ndpi_deserializer *deserializer,
				  ndpi_string *key, int64_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_int64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_int64(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_uint32(ndpi_deserializer *deserializer,
				   ndpi_string *key, u_int32_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_uint32) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int32_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_uint32(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_uint64(ndpi_deserializer *deserializer,
				   ndpi_string *key, u_int64_t *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_uint64) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int64_t);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_uint64(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_float(ndpi_deserializer *deserializer,
				  ndpi_string *key, float *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_float) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(float);

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_float(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */

int ndpi_deserialize_string_string(ndpi_deserializer *deserializer,
				   ndpi_string *key, ndpi_string *value) {
  if(ndpi_deserialize_get_nextitem_type(deserializer) == ndpi_serialization_string_string) {
    u_int32_t buff_diff = deserializer->buffer_size - deserializer->size_used;
    u_int32_t expected =
      sizeof(u_int8_t) /* type */ +
      sizeof(u_int16_t) /* key len */ +
      sizeof(u_int16_t) /* len */;

    if(buff_diff < expected) return(-2);

    deserializer->size_used++; /* Skip element type */
    ndpi_deserialize_single_string(deserializer, key);
    ndpi_deserialize_single_string(deserializer, value);

    return(0);
  } else
    return(-1);
}

/* ********************************** */
