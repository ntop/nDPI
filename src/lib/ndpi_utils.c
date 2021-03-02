/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-21 - ntop.org
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
#include <sys/types.h>


#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"

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
#include "third_party/include/ht_hash.h"

#include "third_party/include/libinjection.h"
#include "third_party/include/libinjection_sqli.h"
#include "third_party/include/libinjection_xss.h"
#include "third_party/include/rce_injection.h"

#define NDPI_CONST_GENERIC_PROTOCOL_NAME  "GenericProtocol"

// #define MATCH_DEBUG 1

// #define DEBUG_REASSEMBLY

/* ****************************************** */

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
  }
  return ((void *)q->key);
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

/* ****************************************** */

#if defined(WIN32) && !defined(__MINGW32__)
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

/*
  Some values coming from packet-tls-utils.c (wireshark)
*/
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
  case 0x00001c: return("TLS_FORTEZZA_KEA_WITH_NULL_SHA");
  case 0x00001d: return("TLS_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA");
    /* case 0x00001e: return("TLS_FORTEZZA_KEA_WITH_RC4_128_SHA"); */
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
    /* RFC 8701 */
  case 0x0A0A: return("Reserved (GREASE)");
    /* RFC 8446 */
  case 0x1301: return("TLS_AES_128_GCM_SHA256");
  case 0x1302: return("TLS_AES_256_GCM_SHA384");
  case 0x1303: return("TLS_CHACHA20_POLY1305_SHA256");
  case 0x1304: return("TLS_AES_128_CCM_SHA256");
  case 0x1305: return("TLS_AES_128_CCM_8_SHA256");
    /* RFC 8701 */
  case 0x1A1A: return("Reserved (GREASE)");
  case 0x2A2A: return("Reserved (GREASE)");
  case 0x3A3A: return("Reserved (GREASE)");
  case 0x4A4A: return("Reserved (GREASE)");
    /* From RFC 7507 */
  case 0x5600: return("TLS_FALLBACK_SCSV");
    /* RFC 8701 */
  case 0x5A5A: return("Reserved (GREASE)");
  case 0x6A6A: return("Reserved (GREASE)");
  case 0x7A7A: return("Reserved (GREASE)");
  case 0x8A8A: return("Reserved (GREASE)");
  case 0x9A9A: return("Reserved (GREASE)");
  case 0xAAAA: return("Reserved (GREASE)");
  case 0xBABA: return("Reserved (GREASE)");

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
    /* RFC 6209 */
  case 0xC03C: return("TLS_RSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC03D: return("TLS_RSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC03E: return("TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256");
  case 0xC03F: return("TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384");
  case 0xC040: return("TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC041: return("TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC042: return("TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256");
  case 0xC043: return("TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384");
  case 0xC044: return("TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC045: return("TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC046: return("TLS_DH_anon_WITH_ARIA_128_CBC_SHA256");
  case 0xC047: return("TLS_DH_anon_WITH_ARIA_256_CBC_SHA384");
  case 0xC048: return("TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC049: return("TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC04A: return("TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC04B: return("TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC04C: return("TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC04D: return("TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC04E: return("TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256");
  case 0xC04F: return("TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384");
  case 0xC050: return("TLS_RSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC051: return("TLS_RSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC052: return("TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC053: return("TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC054: return("TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC055: return("TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC056: return("TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256");
  case 0xC057: return("TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384");
  case 0xC058: return("TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256");
  case 0xC059: return("TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384");
  case 0xC05A: return("TLS_DH_anon_WITH_ARIA_128_GCM_SHA256");
  case 0xC05B: return("TLS_DH_anon_WITH_ARIA_256_GCM_SHA384");
  case 0xC05C: return("TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC05D: return("TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC05E: return("TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC05F: return("TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC060: return("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC061: return("TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC062: return("TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256");
  case 0xC063: return("TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384");
  case 0xC064: return("TLS_PSK_WITH_ARIA_128_CBC_SHA256");
  case 0xC065: return("TLS_PSK_WITH_ARIA_256_CBC_SHA384");
  case 0xC066: return("TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256");
  case 0xC067: return("TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384");
  case 0xC068: return("TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256");
  case 0xC069: return("TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384");
  case 0xC06A: return("TLS_PSK_WITH_ARIA_128_GCM_SHA256");
  case 0xC06B: return("TLS_PSK_WITH_ARIA_256_GCM_SHA384");
  case 0xC06C: return("TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256");
  case 0xC06D: return("TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384");
  case 0xC06E: return("TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256");
  case 0xC06F: return("TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384");
  case 0xC070: return("TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256");
  case 0xC071: return("TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384");
    /* RFC 6367 */
  case 0xC072: return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC073: return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC074: return("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC075: return("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC076: return("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC077: return("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC078: return("TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC079: return("TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC07A: return("TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC07B: return("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC07C: return("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC07D: return("TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC07E: return("TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC07F: return("TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC080: return("TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC081: return("TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC082: return("TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC083: return("TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC084: return("TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC085: return("TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC086: return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC087: return("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC088: return("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC089: return("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC08A: return("TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC08B: return("TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC08C: return("TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC08D: return("TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC08E: return("TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC08F: return("TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC090: return("TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC091: return("TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC092: return("TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256");
  case 0xC093: return("TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384");
  case 0xC094: return("TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC095: return("TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC096: return("TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC097: return("TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC098: return("TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC099: return("TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384");
  case 0xC09A: return("TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256");
  case 0xC09B: return("TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384");
    /* RFC 6655 */
  case 0xC09C: return("TLS_RSA_WITH_AES_128_CCM");
  case 0xC09D: return("TLS_RSA_WITH_AES_256_CCM");
  case 0xC09E: return("TLS_DHE_RSA_WITH_AES_128_CCM");
  case 0xC09F: return("TLS_DHE_RSA_WITH_AES_256_CCM");
  case 0xC0A0: return("TLS_RSA_WITH_AES_128_CCM_8");
  case 0xC0A1: return("TLS_RSA_WITH_AES_256_CCM_8");
  case 0xC0A2: return("TLS_DHE_RSA_WITH_AES_128_CCM_8");
  case 0xC0A3: return("TLS_DHE_RSA_WITH_AES_256_CCM_8");
  case 0xC0A4: return("TLS_PSK_WITH_AES_128_CCM");
  case 0xC0A5: return("TLS_PSK_WITH_AES_256_CCM");
  case 0xC0A6: return("TLS_DHE_PSK_WITH_AES_128_CCM");
  case 0xC0A7: return("TLS_DHE_PSK_WITH_AES_256_CCM");
  case 0xC0A8: return("TLS_PSK_WITH_AES_128_CCM_8");
  case 0xC0A9: return("TLS_PSK_WITH_AES_256_CCM_8");
  case 0xC0AA: return("TLS_PSK_DHE_WITH_AES_128_CCM_8");
  case 0xC0AB: return("TLS_PSK_DHE_WITH_AES_256_CCM_8");
    /* RFC 7251 */
  case 0xC0AC: return("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
  case 0xC0AD: return("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
  case 0xC0AE: return("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
  case 0xC0AF: return("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
    /* RFC 8492 */
  case 0xC0B0: return("TLS_ECCPWD_WITH_AES_128_GCM_SHA256");
  case 0xC0B1: return("TLS_ECCPWD_WITH_AES_256_GCM_SHA384");
  case 0xC0B2: return("TLS_ECCPWD_WITH_AES_128_CCM_SHA256");
  case 0xC0B3: return("TLS_ECCPWD_WITH_AES_256_CCM_SHA384");
    /* draft-camwinget-tls-ts13-macciphersuites */
  case 0xC0B4: return("TLS_SHA256_SHA256");
  case 0xC0B5: return("TLS_SHA384_SHA384");
    /* https://www.ietf.org/archive/id/draft-cragie-tls-ecjpake-01.txt */
  case 0xC0FF: return("TLS_ECJPAKE_WITH_AES_128_CCM_8");
    /* draft-smyshlyaev-tls12-gost-suites */
  case 0xC100: return("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC");
  case 0xC101: return("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC");
  case 0xC102: return("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT");
    /* draft-smyshlyaev-tls13-gost-suites */
  case 0xC103: return("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L");
  case 0xC104: return("TLS_GOSTR341112_256_WITH_MAGMA_MGM_L");
  case 0xC105: return("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S");
  case 0xC106: return("TLS_GOSTR341112_256_WITH_MAGMA_MGM_S");
    /* RFC 8701 */
  case 0xCACA: return("Reserved (GREASE)");

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
  case 0x00fefe: return("TLS_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x00feff: return("TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe0: return("TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA");
  case 0x00ffe1: return("TLS_RSA_FIPS_WITH_DES_CBC_SHA");
  case 0x010080: return("SSL2_RC4_128_WITH_MD5");
  case 0x020080: return("SSL2_RC4_128_EXPORT40_WITH_MD5");
  case 0x030080: return("SSL2_RC2_128_CBC_WITH_MD5");
  case 0x040080: return("SSL2_RC2_128_CBC_EXPORT40_WITH_MD5");
  case 0x050080: return("SSL2_IDEA_128_CBC_WITH_MD5");
  case 0x060040: return("SSL2_DES_64_CBC_WITH_MD5");
  case 0x0700c0: return("SSL2_DES_192_EDE3_CBC_WITH_MD5");
  case 0x080080: return("SSL2_RC4_64_WITH_MD5");

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

char* ndpi_ssl_version2str(struct ndpi_flow_struct *flow,
                           u_int16_t version, u_int8_t *unknown_tls_version) {

  if(unknown_tls_version)
    *unknown_tls_version = 0;

  switch(version) {
  case 0x0300: return("SSLv3");
  case 0x0301: return("TLSv1");
  case 0x0302: return("TLSv1.1");
  case 0x0303: return("TLSv1.2");
  case 0x0304: return("TLSv1.3");
  case 0XFB1A: return("TLSv1.3 (Fizz)"); /* https://engineering.fb.com/security/fizz/ */
  case 0XFEFF: return("DTLSv1.0");
  case 0XFEFD: return("DTLSv1.2");
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
  case 0xFAFA: return("GREASE");
  }

  if((version >= 0x7f00) && (version <= 0x7fff))
    return("TLSv1.3 (draft)");

  if(unknown_tls_version)
    *unknown_tls_version = 1;

  if(flow != NULL) {
    snprintf(flow->protos.tls_quic_stun.tls_quic.ssl_version_str,
	     sizeof(flow->protos.tls_quic_stun.tls_quic.ssl_version_str), "TLS (%04X)", version);
    
    return(flow->protos.tls_quic_stun.tls_quic.ssl_version_str);
  } else
    return("");
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
  int i = 0;
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
    for(int j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for(int j = 0; (j < i + 1); j++)
      ret[len++] = base64_table[char_array_4[j]];

    while((i++ < 3))
      ret[len++] = '=';
  }

  ret[len++] = '\0';

  return ret;
}

/* ********************************** */

void ndpi_serialize_risk(ndpi_serializer *serializer,
			 struct ndpi_flow_struct *flow) {
  if(flow->risk != 0) {
    u_int32_t i;

    ndpi_serialize_start_of_block(serializer, "flow_risk");
    
    for(i = 0; i < NDPI_MAX_RISK; i++) {
      ndpi_risk_enum r = (ndpi_risk_enum)i;
      
      if(NDPI_ISSET_BIT(flow->risk, r))
	ndpi_serialize_uint32_string(serializer, i, ndpi_risk2str(r));
    }
    
    ndpi_serialize_end_of_block(serializer);
  }
}

/* ********************************** */
/* ********************************** */

/* NOTE: serializer must have been already initialized */
int ndpi_dpi2json(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow,
		  ndpi_protocol l7_protocol,
		  ndpi_serializer *serializer) {
  char buf[64];

  if(flow == NULL) return(-1);
  
  ndpi_serialize_start_of_block(serializer, "ndpi");
  ndpi_serialize_risk(serializer, flow);
  ndpi_serialize_string_string(serializer, "proto", ndpi_protocol2name(ndpi_struct, l7_protocol, buf, sizeof(buf)));
  ndpi_protocol_breed_t breed =
      ndpi_get_proto_breed(ndpi_struct,
                           (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  ndpi_serialize_string_string(serializer, "breed", ndpi_get_proto_breed_name(ndpi_struct, breed));
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    ndpi_serialize_string_string(serializer, "category", ndpi_category_get_name(ndpi_struct, l7_protocol.category));
  ndpi_serialize_end_of_block(serializer);

  switch(l7_protocol.master_protocol ? l7_protocol.master_protocol : l7_protocol.app_protocol) {
  case NDPI_PROTOCOL_DHCP:
    ndpi_serialize_start_of_block(serializer, "dhcp");
    ndpi_serialize_string_string(serializer, "fingerprint", flow->protos.dhcp.fingerprint);
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

  case NDPI_PROTOCOL_DNS:
    ndpi_serialize_start_of_block(serializer, "dns");
    if(flow->host_server_name[0] != '\0')
      ndpi_serialize_string_string(serializer, "query", (const char*)flow->host_server_name);
    ndpi_serialize_string_uint32(serializer, "num_queries", flow->protos.dns.num_queries);
    ndpi_serialize_string_uint32(serializer, "num_answers", flow->protos.dns.num_answers);
    ndpi_serialize_string_uint32(serializer, "reply_code",  flow->protos.dns.reply_code);
    ndpi_serialize_string_uint32(serializer, "query_type",  flow->protos.dns.query_type);
    ndpi_serialize_string_uint32(serializer, "rsp_type",    flow->protos.dns.rsp_type);

    inet_ntop(AF_INET, &flow->protos.dns.rsp_addr, buf, sizeof(buf));
    ndpi_serialize_string_string(serializer, "rsp_addr",    buf);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MDNS:
    ndpi_serialize_start_of_block(serializer, "mdns");
    ndpi_serialize_string_string(serializer, "answer", (const char*)flow->host_server_name);
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

  case NDPI_PROTOCOL_TELNET:
    ndpi_serialize_start_of_block(serializer, "telnet");
    ndpi_serialize_string_string(serializer, "username", flow->protos.telnet.username);
    ndpi_serialize_string_string(serializer, "password", flow->protos.telnet.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_HTTP:
    ndpi_serialize_start_of_block(serializer, "http");
    if(flow->host_server_name[0] != '\0')
      ndpi_serialize_string_string(serializer, "hostname", (const char*)flow->host_server_name);
    if(flow->http.url != NULL){
      ndpi_serialize_string_string(serializer,   "url", flow->http.url);
      ndpi_serialize_string_uint32(serializer,   "code", flow->http.response_status_code);
      ndpi_serialize_string_string(serializer,   "content_type", flow->http.content_type);
      ndpi_serialize_string_string(serializer,   "user_agent", flow->http.user_agent);
    }
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_QUIC:
    ndpi_serialize_start_of_block(serializer, "quic");
    if(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] != '\0')
      ndpi_serialize_string_string(serializer, "client_requested_server_name",
                                   flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);
    if(flow->http.user_agent)
      ndpi_serialize_string_string(serializer, "user_agent", flow->http.user_agent);
    if(flow->protos.tls_quic_stun.tls_quic.ssl_version) {
      u_int8_t unknown_tls_version;
      char *version = ndpi_ssl_version2str(flow, flow->protos.tls_quic_stun.tls_quic.ssl_version, &unknown_tls_version);

      if(!unknown_tls_version)
	ndpi_serialize_string_string(serializer, "version", version);
      if(flow->protos.tls_quic_stun.tls_quic.alpn)
        ndpi_serialize_string_string(serializer, "alpn", flow->protos.tls_quic_stun.tls_quic.alpn);
      ndpi_serialize_string_string(serializer, "ja3", flow->protos.tls_quic_stun.tls_quic.ja3_client);
      if(flow->protos.tls_quic_stun.tls_quic.tls_supported_versions)
        ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic_stun.tls_quic.tls_supported_versions);
    }
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_IMAP:
    ndpi_serialize_start_of_block(serializer, "imap");
    ndpi_serialize_string_string(serializer,  "user", flow->protos.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->protos.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_POP:
    ndpi_serialize_start_of_block(serializer, "pop");
    ndpi_serialize_string_string(serializer,  "user", flow->protos.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->protos.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_SMTP:
    ndpi_serialize_start_of_block(serializer, "smtp");
    ndpi_serialize_string_string(serializer,  "user", flow->protos.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->protos.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_FTP_CONTROL:
    ndpi_serialize_start_of_block(serializer, "ftp");
    ndpi_serialize_string_string(serializer,  "user", flow->protos.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->protos.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer,  "auth_failed", flow->protos.ftp_imap_pop_smtp.auth_failed);
    ndpi_serialize_end_of_block(serializer);
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
    if(flow->protos.tls_quic_stun.tls_quic.ssl_version) {
      char notBefore[32], notAfter[32];
      struct tm a, b, *before = NULL, *after = NULL;
      u_int i, off;
      u_int8_t unknown_tls_version;
      char *version = ndpi_ssl_version2str(flow, flow->protos.tls_quic_stun.tls_quic.ssl_version, &unknown_tls_version);

      if(flow->protos.tls_quic_stun.tls_quic.notBefore)
        before = gmtime_r((const time_t *)&flow->protos.tls_quic_stun.tls_quic.notBefore, &a);
      if(flow->protos.tls_quic_stun.tls_quic.notAfter)
        after  = gmtime_r((const time_t *)&flow->protos.tls_quic_stun.tls_quic.notAfter, &b);

      if(!unknown_tls_version) {
	ndpi_serialize_start_of_block(serializer, "tls");
	ndpi_serialize_string_string(serializer, "version", version);
	ndpi_serialize_string_string(serializer, "client_requested_server_name",
				     flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);
	if(flow->protos.tls_quic_stun.tls_quic.server_names)
	  ndpi_serialize_string_string(serializer, "server_names", flow->protos.tls_quic_stun.tls_quic.server_names);

	if(before) {
          strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
          ndpi_serialize_string_string(serializer, "notbefore", notBefore);
        }

	if(after) {
	  strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
          ndpi_serialize_string_string(serializer, "notafter", notAfter);
        }
	ndpi_serialize_string_string(serializer, "ja3", flow->protos.tls_quic_stun.tls_quic.ja3_client);
	ndpi_serialize_string_string(serializer, "ja3s", flow->protos.tls_quic_stun.tls_quic.ja3_server);
	ndpi_serialize_string_uint32(serializer, "unsafe_cipher", flow->protos.tls_quic_stun.tls_quic.server_unsafe_cipher);
	ndpi_serialize_string_string(serializer, "cipher", ndpi_cipher2str(flow->protos.tls_quic_stun.tls_quic.server_cipher));

	if(flow->protos.tls_quic_stun.tls_quic.issuerDN)
	  ndpi_serialize_string_string(serializer, "issuerDN", flow->protos.tls_quic_stun.tls_quic.issuerDN);
	
	if(flow->protos.tls_quic_stun.tls_quic.subjectDN)
	  ndpi_serialize_string_string(serializer, "issuerDN", flow->protos.tls_quic_stun.tls_quic.subjectDN);

	if(flow->protos.tls_quic_stun.tls_quic.alpn)
	  ndpi_serialize_string_string(serializer, "alpn", flow->protos.tls_quic_stun.tls_quic.alpn);
	
	if(flow->protos.tls_quic_stun.tls_quic.tls_supported_versions)
	  ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic_stun.tls_quic.tls_supported_versions);	
	
	if(flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint[0] != '\0') {
	  for(i=0, off=0; i<20; i++) {
	    int rc = snprintf(&buf[off], sizeof(buf)-off,"%s%02X", (i > 0) ? ":" : "",
			      flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint[i] & 0xFF);
	    
	    if(rc <= 0) break; else off += rc;
	  }

	  ndpi_serialize_string_string(serializer, "fingerprint", buf);
	}

	ndpi_serialize_end_of_block(serializer);
      }
    }
    break;
  } /* switch */

  return(0);
}

/* ********************************** */

/* NOTE: serializer is initialized by the function */
int ndpi_flow2json(struct ndpi_detection_module_struct *ndpi_struct,
		   struct ndpi_flow_struct *flow,
		   u_int8_t ip_version,
		   u_int8_t l4_protocol, u_int16_t vlan_id,
		   u_int32_t src_v4, u_int32_t dst_v4,
		   struct ndpi_in6_addr *src_v6, struct ndpi_in6_addr *dst_v6,
		   u_int16_t src_port, u_int16_t dst_port,
		   ndpi_protocol l7_protocol,
		   ndpi_serializer *serializer) {
  char src_name[32], dst_name[32];

  if(ndpi_init_serializer(serializer, ndpi_serialization_format_json) == -1)
    return(-1);

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
  if(src_port) ndpi_serialize_string_uint32(serializer, "src_port", src_port);
  if(dst_port) ndpi_serialize_string_uint32(serializer, "dst_port", dst_port);

  switch(l4_protocol) {
  case IPPROTO_TCP:
    ndpi_serialize_string_string(serializer, "proto", "TCP");
    break;

  case IPPROTO_UDP:
    ndpi_serialize_string_string(serializer, "proto", "UDP");
    break;

  case IPPROTO_ICMP:
    ndpi_serialize_string_string(serializer, "proto", "ICMP");
    break;

  default:
    ndpi_serialize_string_uint32(serializer, "proto", l4_protocol);
    break;
  }

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
  const char *pcreErrorStr;
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

  free((void *)pcreErrorStr);
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

  for(int i = 0; i < ushlen; i++) {
    if(strstr(query, ush_commands[i]) != NULL) {
      return 1;
    }
  }

  size_t pwshlen = sizeof(pwsh_commands) / sizeof(pwsh_commands[0]);

  for(int i = 0; i < pwshlen; i++) {
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
    return("XSS attack");

  case NDPI_URL_POSSIBLE_SQL_INJECTION:
    return("SQL injection");

  case NDPI_URL_POSSIBLE_RCE_INJECTION:
    return("RCE injection");

  case NDPI_BINARY_APPLICATION_TRANSFER:
    return("Binary application transfer");

  case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
    return("Known protocol on non standard port");

  case NDPI_TLS_SELFSIGNED_CERTIFICATE:
    return("Self-signed Certificate");

  case NDPI_TLS_OBSOLETE_VERSION:
    return("Obsolete TLS version (< 1.1)");

  case NDPI_TLS_WEAK_CIPHER:
    return("Weak TLS cipher");

  case NDPI_TLS_CERTIFICATE_EXPIRED:
    return("TLS Expired Certificate");
    
  case NDPI_TLS_CERTIFICATE_MISMATCH:
    return("TLS Certificate Mismatch");

  case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
    return("HTTP Suspicious User-Agent");

  case NDPI_HTTP_NUMERIC_IP_HOST:
    return("HTTP Numeric IP Address");

  case NDPI_HTTP_SUSPICIOUS_URL:
    return("HTTP Suspicious URL");

  case NDPI_HTTP_SUSPICIOUS_HEADER:
    return("HTTP Suspicious Header");
    
  case NDPI_TLS_NOT_CARRYING_HTTPS:
    return("TLS (probably) not carrying HTTPS");

  case NDPI_SUSPICIOUS_DGA_DOMAIN:
    return("Suspicious DGA domain name");

  case NDPI_MALFORMED_PACKET:
    return("Malformed packet");

  case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
    return("SSH Obsolete Client Version/Cipher");

  case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
    return("SSH Obsolete Server Version/Cipher");
    
  case NDPI_SMB_INSECURE_VERSION:
    return("SMB Insecure Version");

  case NDPI_TLS_SUSPICIOUS_ESNI_USAGE:
    return("TLS Suspicious ESNI Usage");

  case NDPI_UNSAFE_PROTOCOL:
    return("Unsafe Protocol");

  case NDPI_DNS_SUSPICIOUS_TRAFFIC:
    return("Suspicious DNS traffic"); /* Exfiltration ? */
    
  case NDPI_TLS_MISSING_SNI:
    return("SNI TLS extension was missing");
    
  case NDPI_HTTP_SUSPICIOUS_CONTENT:
    return("HTTP suspicious content");
    
  case NDPI_RISKY_ASN:
    return("Risky ASN");
    
  case NDPI_RISKY_DOMAIN:
    return("Risky domain name");

  case NDPI_MALICIOUS_JA3:
    return("Possibly Malicious JA3 Fingerprint");

  case NDPI_MALICIOUS_SHA1:
    return("Possibly Malicious SSL Certificate SHA1 Fingerprint");

  default:
    snprintf(buf, sizeof(buf), "%d", (int)risk);
    return(buf);
  }
}

/* ******************************************************************** */

const char* ndpi_http_method2str(ndpi_http_method m) {
  switch(m) {
  case NDPI_HTTP_METHOD_UNKNOWN: break;
  case NDPI_HTTP_METHOD_OPTIONS: return("OPTIONS");
  case NDPI_HTTP_METHOD_GET:     return("GET");
  case NDPI_HTTP_METHOD_HEAD:    return("HEAD");
  case NDPI_HTTP_METHOD_PATCH:   return("PATCH");
  case NDPI_HTTP_METHOD_POST:    return("POST");
  case NDPI_HTTP_METHOD_PUT:     return("PUT");
  case NDPI_HTTP_METHOD_DELETE:  return("DELETE");
  case NDPI_HTTP_METHOD_TRACE:   return("TRACE");
  case NDPI_HTTP_METHOD_CONNECT: return("CONNECT");
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
  }

  return(NDPI_HTTP_METHOD_UNKNOWN);
}

#ifdef FRAG_MAN
#define ARRAYSZ_255 255
void printRawData(const uint8_t *ptr, size_t len) {		
  uint8_t *p=(uint8_t*)ptr;
  DBGINFO("ptr=%p, len=%llu", ptr, (unsigned long long)len)
    if(p && len > 0) {
      size_t ctLines=0,i,j;
      char line1[ARRAYSZ_255]={0}, line2[ARRAYSZ_255]={0}, temp[ARRAYSZ_255];
      snprintf(line1,sizeof(line1),"\t%05X",(unsigned int)(16*ctLines));
      for(i=0; i<len; i++) {
			
	if(i > 0 && i%16==0) {		        
	  printf("%s\t%s\n", line1,line2);
	  ctLines++;
	  snprintf(line1,ARRAYSZ_255,"\t%05X",(unsigned int)(16*ctLines));
	  snprintf(line2,ARRAYSZ_255,"%s","");
	}      
	snprintf(temp,ARRAYSZ_255," %02X", (uint8_t)*p);
	strncat(line1, temp, 3);
	snprintf(temp,ARRAYSZ_255,"%c", (isprint(*p)? *(p):'.'));
	strncat(line2, temp, 1);
	p++;
      }
      uint8_t exv= i%16;
      for(j=exv;exv > 0 && j<16;j++) {
	strncat(line1, "   ", 3);
      }
      printf("%s\t%s\n", line1,line2);
    }
  return;	
}
/* ******************************************************************** */

// the struct is defined in ndpi_utils.h

void ins_sort_array(sorter_index_item_t arr[], int len) {
  DBGINFO("sorting  no. %u items", (unsigned)len)
    for(int i=1; i<len; i++) {
      for(int j=i; j > 0 && arr[j].sort_value<arr[j-1].sort_value; j--) {
	sorter_index_item_t temp = arr[j];
	arr[j] = arr[j-1];
	arr[j-1] = temp;
      }
    }
}

void shell_sort_array(sorter_index_item_t arr[], int n) {
  // Rearrange elements at each n/2, n/4, n/8, ... intervals
  DBGINFO("sorting  no. %u items", (unsigned)n)
    for(int interval = n / 2; interval > 0; interval /= 2) {
      for(int i = interval; i < n; i += 1) {
	sorter_index_item_t temp = arr[i];
	int j;
	for(j = i; j >= interval && arr[j - interval].sort_value > temp.sort_value; j -= interval) {
	  arr[j] = arr[j - interval];
	  DBGTRACER("exchanged item no. %d (%d) with: %d (%d)", j, arr[j].sort_value, j-interval, temp.sort_value);
	}

	DBGTRACER("item no. %d value: %d", j, temp.sort_value);
	arr[j] = temp;
      }
    }
}

/* ******************************************************************** */

void free_fragment(fragments_wrapper_t *frag) {
  /*
   *  
   typedef struct fragment_wrapper {
   uint16_t id;
   uint8_t l4_protocol;
   uint8_t ct_frag;
   char   *flow_label;    // IP6
   fragment_t **fragments_list;
   } fragments_wrapper_t; 
   *
   * */
  if(frag) {
    DBGTRACER("(frag:%p) freeing fragments list -> %p",frag, frag->fragments_list);
    if(frag->fragments_list) {
      DBGTRACER("fragments are %u.",frag->ct_frag);
	
      for(int y=0;y<frag->ct_frag;y++) {
	if(frag->fragments_list[y]) {
	  if(frag->fragments_list[y]->data) {
	    DBGPOINTER("freeing fragment item %d -> %p",y, frag->fragments_list[y]);
	    ndpi_free(frag->fragments_list[y]->data);
	  }

	  ndpi_free(frag->fragments_list[y]);
	}
      }        
      DBGPOINTER("freeing fragments list -> %p",frag->fragments_list)
	ndpi_free(frag->fragments_list);
      frag->fragments_list= NULL;
    }
    //reset counter and initial offset
    frag->ct_frag=0;
    frag->initial_offset=0;
  }
}

/* ******************************************************************** */

uint8_t add_segment_to_buffer(struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph, uint32_t new_expected_seq) {
  DBGINFO("[flow:%p], dir: %d, seq:%u, ack:%u, len: %ubytes",
          flow, flow->packet.packet_direction, ntohl(tcph->seq), ntohl(tcph->ack_seq), flow->packet.payload_packet_len)

    if(flow->tcp_segments_management) {
      fragments_wrapper_t *fragW= &flow->tcp_segments_list[flow->packet.packet_direction];
      DBGTRACER("tcp segments management enabled (list container: %p)", fragW);

      if(fragW->ct_frag == 0) {
	if(fragW->fragments_list)
	  free_fragment(fragW);

	// initialize the offset with the first fragment seq number
	fragW->initial_offset = new_expected_seq;
	DBGTRACER("initialized initial_offset: %u)",fragW->initial_offset);
      }
    
      if(flow->packet.payload_packet_len > 0) {
	uint32_t seq;

	// allocate memory for pointer
	size_t new_len= (1+fragW->ct_frag) * sizeof(fragment_t*);
	DBGTRACER("actual fragment list ct=%d, new size: %llu", fragW->ct_frag, (unsigned long long)new_len);

	fragW->fragments_list = ndpi_realloc(fragW->fragments_list,(fragW->ct_frag * sizeof(fragment_t*)),new_len);
	if(fragW->fragments_list == NULL) {
	  flow->tcp_segments_management= 0; 
	  // fprintf(stderr, "[%8u] Not enough memory for new fragment \n", flow->packet_counter);
	  return 0;
	}

	DBGPOINTER("fragments_list initialized for item no. %u, list->%p i-esimo->%p",
		   fragW->ct_frag, fragW->fragments_list, fragW->fragments_list[fragW->ct_frag]);

	// allocate memory for item
	fragment_t *new_frag = (fragment_t*)ndpi_calloc(1, sizeof(fragment_t));
	if(new_frag == NULL) {
	  flow->tcp_segments_management= 0; 
	  free_fragment(fragW);
	  // fprintf(stderr, "[%8u] Not enough memory for new fragment \n", flow->packet_counter);
	  return 0;
	}       

	DBGPOINTER("new_frag=> %p",new_frag);

	// fill item with offsetm len and data fragment/segment
	seq = (0xffffffff & ntohl(tcph->seq));
	if(seq >= fragW->initial_offset /* safety check */) {
	  new_frag->offset = seq - fragW->initial_offset;
	} else {
	  /* CHECK THIS CASE
	     fprintf(stderr, "[%8u] Bad seq or initial offset (seq = %u, initial offset = %u)\n",
	     flow->packet_counter, seq, fragW->initial_offset);
	  */
	  flow->tcp_segments_management= 0;
	  ndpi_free(new_frag);
	  free_fragment(fragW);
	  return 0;
	}

	DBGTRACER("offset calculation: seq %u, init: %u, offset result: %u", ntohl(tcph->seq),
		  fragW->initial_offset, new_frag->offset);
	new_frag->len = flow->packet.payload_packet_len;      
       
	new_frag->data = (void*)ndpi_calloc(new_frag->len, sizeof(char));
	DBGPOINTER("new_frag->data=> %p",new_frag->data)
	  if(new_frag->data) {
	    memcpy(new_frag->data,flow->packet.payload,new_frag->len);

#ifdef DEBUG_REASSEMBLY
	    printf("[%s:%u] ==>> %s() [%p][offset: %u]\n",
		   __FILE__, __LINE__, __FUNCTION__, new_frag, new_frag->offset);
#endif

	    fragW->fragments_list[fragW->ct_frag++]= new_frag; /* Add it to the list */
	  } else {
	    flow->tcp_segments_management= 0; 
	    ndpi_free(new_frag);
	    free_fragment(fragW);
	    // fprintf(stderr, "[%8u] Not enough memory for new fragment data \n", flow->packet_counter);
	    return 0;
	  }

	DBGINFO("item no. %u: %p->%p [off:%u, len:%u, data:%p]",
		fragW->ct_frag, fragW->fragments_list, *fragW->fragments_list, 
		(unsigned int) new_frag->offset, (unsigned int)new_frag->len, new_frag->data);

	return fragW->ct_frag;
      }
    }
  
  return 0;
}

//TODO: manage partial retrasmission

/* ******************************************************************** */

uint32_t reassembly_fragment(struct ndpi_flow_struct *const flow,
			     struct ndpi_tcphdr const * tcph,
			     uint8_t **ret_buffer, size_t *len_buffer) {
  uint32_t ret_value = 0;
  uint16_t last_item = 0;
  size_t length = 0, tot_length = 0;
  sorter_index_item_t *sorted_indexes;
  fragments_wrapper_t *fragW;
  uint8_t *buffer;

#ifdef DEBUG_REASSEMBLY
  printf("[%s:%u] ==>> %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif
  
  fragW = &flow->tcp_segments_list[flow->packet.packet_direction];

  DBGTRACER("tcph:%p, ret_buffer:%p, len_buffer:%u", tcph, ret_buffer, len_buffer);

  // phase 1: calculate the size and fill the indexes array
  DBGINFO("phase 1: init sorter, calculate the size of buffer to reassemble: %u items", fragW->ct_frag);

  sorted_indexes = (sorter_index_item_t*)ndpi_calloc(fragW->ct_frag, sizeof(sorter_index_item_t));

  if(sorted_indexes == NULL) {
    //fprintf(stderr, "[%8u] Not enough memory to sort the %u segments \n", flow->packet_counter, fragW->ct_frag); 
    free_fragment(fragW);
    return 0;
  }

  DBGPOINTER("sorted_indexes=> %p", sorted_indexes);
  
  for(int i=0; i<fragW->ct_frag; i++) {
    fragment_t *item = (fragment_t*)fragW->fragments_list[i];
    
    sorted_indexes[i].sort_value = item->offset;
    sorted_indexes[i].item_index = i;        
    tot_length += item->len;
    
    DBGTRACER("segment (%d): len:%lu, offset: %u => partial buffer len: %lu",
	      i, (long unsigned int)item->len, (unsigned int)item->offset, (long unsigned int)tot_length);
  }

  // phase 2: sorts fragments and check fragments and sequences
  DBGINFO(" phase 2 sorting %d segments and checking",fragW->ct_frag);

  if(fragW->ct_frag>1) shell_sort_array(sorted_indexes, fragW->ct_frag);

  // checks
  for(uint i=0; i<fragW->ct_frag; i++) {
    fragment_t *item = (fragment_t*)fragW->fragments_list[ sorted_indexes[i].item_index ];

    // 1: no segment offset can be > tot_length
    DBGTRACER("checking %d/%d element: offset=%lu vs t_length=%lu",
              i, sorted_indexes[i].item_index, (unsigned long)item->offset, (unsigned long)tot_length);

    if((item->offset+item->len) > (uint32_t)tot_length) {
      // update the last index of elements to elaborate
      DBGINFO("stop processing at %d/%d element: len= %u; offset= %u",
              i, sorted_indexes[i].item_index, (unsigned)length, (unsigned)item->offset)

	// tot_length = length; /* CHECK THIS CASE */
#ifdef DEBUG_REASSEMBLY
	printf("[%s:%u] ==>> Too long [last_item: %u][offset: %u/len: %u][%p]\n", __FILE__, __LINE__,
	       last_item, item->offset, item->len, item);
#endif

      tot_length = item->offset+item->len; /* CHECK THIS CASE */
      
      // set the first offset to wait for the next segment
      ret_value = fragW->initial_offset + item->offset;
      break;
      // 2: for every len(buffer) must exists a offset fragment
    } else if(item->offset != (uint32_t)length) {
      // update the last index of elements to elaborate
      DBGINFO("checking %d/%d element: stop processing! len: %u; n_offset: %u",
              i, sorted_indexes[i].item_index, (unsigned)length, (unsigned)item->offset);

      // tot_length = length; /* CHECK THIS CASE */

      // set the first offset to wait for the next segment
      ret_value = fragW->initial_offset + item->offset;
      break;
    } else {
      // continue to sum length data bytes
      length += item->len;
      last_item = i;
    }
  }
  last_item++;  // index to number aligment

  // phase 3: allocate memory and fill the buffer
  DBGINFO("phase 3: allocate memory for %u items and fill the buffer tot: %lu", last_item, (unsigned long int)tot_length);

#ifdef DEBUG_REASSEMBLY
  printf("[%s:%u] ==>> [tot_length: %u][length: %u]\n",
	 __FILE__, __LINE__, (u_int32_t)tot_length, (u_int32_t)length);
#endif
  
  buffer = ndpi_calloc(tot_length, sizeof(uint8_t));

  if(buffer == NULL) {
    // fprintf(stderr, "[%8u] Not enough memory for buffer for %u segments \n", flow->packet_counter,last_item);
    free_fragment(fragW);
    ndpi_free(sorted_indexes);
    return 0;
  }  

  DBGPOINTER("buffer (len:%lu)=> %p", (unsigned long)tot_length, buffer);

  for(uint i=0; i<last_item; i++) {
    fragment_t *item = (fragment_t*) fragW->fragments_list[sorted_indexes[i].item_index];

    DBGINFO("copying data item no:%u of len: %lu to buffer: %p (offset:%lu)",
            sorted_indexes[i].item_index, (unsigned long int)item->len, buffer,
            (unsigned long int)item->offset);

    if((item->offset+item->len) > tot_length) {      
      //#ifdef DEBUG_REASSEMBLY
      printf("[%s:%u] ==>> Out of boundary [%u vs %u][offset: %u][len: %u][item: %u/%u]\n", __FILE__, __LINE__,
	     (u_int32_t)(item->offset+item->len), (u_int32_t)tot_length,
	     (u_int32_t)item->offset, (u_int32_t)item->len, i, last_item);
      //#endif
      continue;
    } else {
#ifdef DEBUG_REASSEMBLY
      printf("[%s:%u] ==>> memcpy OK [%u vs %u][offset: %u][item: %u/%u]\n",
	     __FILE__, __LINE__,
	     (u_int32_t)(item->offset+item->len), (u_int32_t)tot_length,
	     item->offset, i, last_item);
#endif
    }
    
    memcpy((void*)(buffer + item->offset), item->data, item->len);

    // free memory item
    ndpi_free(item->data);
    item->data=NULL;
    ndpi_free(item);
    fragW->fragments_list[sorted_indexes[i].item_index]=NULL;
  }

  if(last_item == fragW->ct_frag) {
    DBGTRACER("all processed: free all memory!");
    free_fragment(fragW);
  } else {
    // phase 4: re-organize the other segments, updating the list    
    fragment_t **fragW_old_list = fragW->fragments_list;
    fragW->fragments_list = ndpi_calloc((fragW->ct_frag-last_item), sizeof(struct fragment_t*));

    DBGPOINTER("old segments list: %p, new segments list: %p.",
               fragW_old_list, fragW->fragments_list);

    if(!fragW->fragments_list) {
      // fprintf(stderr, "[%8u] Not enough memory for new segments list \n", flow->packet_counter);
      free_fragment(fragW);
      ndpi_free(buffer);
      ndpi_free(sorted_indexes);
      return 0;
    }    

    // re-fill the new segments list, updating the offsets
    for(uint i = last_item; i < fragW->ct_frag; i++) {
      fragment_t *item = (fragment_t*)fragW_old_list[sorted_indexes[i].item_index];
      fragW->fragments_list[i-last_item] = item;
      if(item->offset >= tot_length /* safety check */) {
        item->offset -= tot_length;
      }
      /* CHECK THIS CASE
	 else {
	 fprintf(stderr, "[%8u] Bad offset update (item->offset = %u, tot_length = %lu)\n",
	 flow->packet_counter, item->offset, tot_length);
	 }
      */

      DBGTRACER("moving the item (%p), index %u - to position %u of new segments list; new offset: %u.",
                item, sorted_indexes[i].item_index, i-last_item, item->offset );
    }

    // update the fragments countes
    fragW->ct_frag -= last_item;
    fragW->initial_offset += tot_length;

    DBGINFO("updated counter: %d and i_offset: %u.",
            (unsigned)fragW->ct_frag, (unsigned)fragW->initial_offset);
    
    DBGPOINTER("freeing old segments list: %p ", fragW_old_list)
      ndpi_free(fragW_old_list);
  }

  if(sorted_indexes) {
    DBGPOINTER("freeing sorter indexes: %p ", sorted_indexes);
    ndpi_free(sorted_indexes);
  }

  if(len_buffer != NULL) {
    *len_buffer = tot_length;
  }

  if(ret_buffer != NULL) {
    *ret_buffer = (u_int8_t *) buffer;
    flow->must_free[flow->packet.packet_direction] = 1;

    DBGINFO("retrieved the buffer of segments (len:%lu) %p",
            *len_buffer, *ret_buffer);
  } else {
    DBGPOINTER("freeing buffer=> %p", buffer);
    ndpi_free(buffer);
  }

  DBGINFO("returning: %d", ret_value);
  return(ret_value);
}

/* ******************************************************************** */

uint8_t check_for_sequence(struct ndpi_flow_struct *flow, struct ndpi_tcphdr const * tcph) {
  uint8_t *ret_buffer=NULL;
  size_t len_buffer=0;

  DBGINFO("## sorted flags: %d/%d ",flow->not_sorted[0],flow->not_sorted[1]);

  if(flow->next_tcp_seq_nr[flow->packet.packet_direction]) {
    uint32_t *trigger, expected;
    uint8_t *not_sorted;

    // use pointers to allow the modification
    not_sorted = &flow->not_sorted[flow->packet.packet_direction];
    trigger = &flow->trigger[flow->packet.packet_direction];

    DBGTRACER("dir:%d, trg:%u, next:%u", flow->packet.packet_direction,*trigger,
	      flow->next_tcp_seq_nr[flow->packet.packet_direction]);

    expected = (*not_sorted && *trigger) ? ndpi_min(*trigger, flow->next_tcp_seq_nr[flow->packet.packet_direction]) : flow->next_tcp_seq_nr[flow->packet.packet_direction];

    if(expected < (0xffffffff & ntohl(tcph->seq))) {
      // segment not in order... almost 1 has been skipped! add this fragment to buffer
      DBGINFO("received a segment (seq:%u) over the expected (next:%u)", (0xffffffff & ntohl(tcph->seq)), expected);
      
      if(add_segment_to_buffer(flow, tcph, expected)) {
	DBGTRACER("segment (seq:%u) bufferized, waiting for(next:%u)", (0xffffffff & ntohl(tcph->seq)), expected);

	// set flag a save the expected sequence number
	*not_sorted=1;
	*trigger= *trigger ? ndpi_min(flow->next_tcp_seq_nr[flow->packet.packet_direction],*trigger):flow->next_tcp_seq_nr[flow->packet.packet_direction];
	DBGINFO("set flag and trigger[%d]: %u",flow->packet.packet_direction,*trigger);
      }
      return 1;

    } else if(expected>(0xffffffff & ntohl(tcph->seq))) {
      DBGINFO("received a segment (seq:%u) minus than the expected (next:%u): retransmission!!", (0xffffffff & ntohl(tcph->seq)), flow->next_tcp_seq_nr[flow->packet.packet_direction]);

      flow->packet.tcp_retransmission = 1;

      /* CHECK IF PARTIAL RETRY IS HAPPENING */
      if((flow->next_tcp_seq_nr[flow->packet.packet_direction] - ntohl(tcph->seq) <
	  flow->packet.payload_packet_len)) {
	/* num_retried_bytes actual_payload_len hold info about the partial retry
	   analyzer which require this info can make use of this info
	   Other analyzer can use packet->payload_packet_len */
	flow->packet.num_retried_bytes = (u_int16_t)(flow->next_tcp_seq_nr[flow->packet.packet_direction] - ntohl(tcph->seq));
	flow->packet.actual_payload_len = flow->packet.payload_packet_len - flow->packet.num_retried_bytes;
	flow->next_tcp_seq_nr[flow->packet.packet_direction] = ntohl(tcph->seq) + flow->packet.payload_packet_len;
	DBGINFO("partial_bytes:%u",flow->packet.num_retried_bytes);

	//TODO: manage this!!
      }

    } else {
      DBGTRACER("seq (%u) and expected (%u) matched! sorted flag: %d",
		(0xffffffff & ntohl(tcph->seq)),
		flow->next_tcp_seq_nr[flow->packet.packet_direction],
		*not_sorted);

      if(*not_sorted) {
	if(add_segment_to_buffer(flow, tcph, 0)) {
	  *trigger= reassembly_fragment(flow,tcph,&ret_buffer,&len_buffer);
	  *not_sorted=(*trigger > 0);

	  if(len_buffer > 0) {
	    // the previous pointers must not be free, because managed in other part
	    flow->packet.payload_packet_len= len_buffer;
	    flow->packet.payload= ret_buffer;
	  }
	}
      }
    }
  }

  return 0;
}
#endif // FRAG_MAN

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

ndpi_str_hash* ndpi_hash_alloc(u_int32_t max_num_entries) {
  ndpi_str_hash *h = (ndpi_str_hash*)malloc(sizeof(ndpi_str_hash));

  if(!h) return(NULL);
  if(max_num_entries < 1024) max_num_entries = 1024;
  if(max_num_entries > 10000000) max_num_entries = 10000000;
  
  h->max_num_entries = max_num_entries, h->num_buckets = max_num_entries/2;
  h->buckets = (struct ndpi_str_hash_info**)calloc(sizeof(struct ndpi_str_hash_info*), h->num_buckets);

  if(h->buckets == NULL) {
    free(h);
    return(NULL);
  } else
    return(h);
}

/* ******************************************************************** */

void ndpi_hash_free(ndpi_str_hash *h) {
  u_int32_t i;
  
  for(i=0; i<h->num_buckets; i++) {
    struct ndpi_str_hash_info *head = h->buckets[i];

    while(head != NULL) {
      struct ndpi_str_hash_info *next = head->next;

      free(head->key);
      free(head);
      head = next;
    }
  }

  free(h->buckets);
  free(h);
}

/* ******************************************************************** */

static u_int32_t _ndpi_hash_function(ndpi_str_hash *h, char *key, u_int8_t key_len) {
  u_int32_t hv = 0;
  u_int8_t i;

  for(i=0; i<key_len; i++)
    hv += key[i]*(i+1);

  return(hv % h->num_buckets);
}

/* ******************************************************************** */

static int _ndpi_hash_find_entry(ndpi_str_hash *h, u_int32_t hashval, char *key, u_int key_len, u_int8_t *value) {
  struct ndpi_str_hash_info *head = h->buckets[hashval];
  
  while(head != NULL) {
    if((head->key_len == key_len) && (memcmp(head->key, key, key_len) == 0)) {
      *value = head->value;
      return(0); /* Found */
    }
    
    head = head-> next;
  }

  return(-1); /* Not found */
}

/* ******************************************************************** */

int ndpi_hash_find_entry(ndpi_str_hash *h, char *key, u_int key_len, u_int8_t *value) {
  u_int32_t hv = _ndpi_hash_function(h, key, key_len);

  return(_ndpi_hash_find_entry(h, hv, key, key_len, value));
}

/* ******************************************************************** */

int ndpi_hash_add_entry(ndpi_str_hash *h, char *key, u_int8_t key_len, u_int8_t value) {
  u_int32_t hv = _ndpi_hash_function(h, key, key_len);
  u_int8_t ret_value;
  int rc = _ndpi_hash_find_entry(h, hv, key, key_len, &ret_value);

  if(rc == -1) {
    /* Not found */
    struct ndpi_str_hash_info *e = (struct ndpi_str_hash_info*)malloc(sizeof(struct ndpi_str_hash_info));

    if(e == NULL)
      return(-2);
    
    if((e->key = (char*)malloc(key_len)) == NULL)
      return(-3);

    memcpy(e->key, key, key_len);
    e->key_len = key_len, e->value = value;
    e->next = h->buckets[hv];
    h->buckets[hv] = e;

    return(0);
  } else
    return(0);
}

/* ******************************************************************** */

void ndpi_set_risk(struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  u_int32_t v = 1 << r;
  
  // NDPI_SET_BIT(flow->risk, (u_int32_t)r);
  flow->risk |= v;

}
