/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-20 - ntop.org
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

char* ndpi_ssl_version2str(u_int16_t version, u_int8_t *unknown_tls_version) {
  static char v[12];

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
  }

  if((version >= 0x7f00) && (version <= 0x7fff))
    return("TLSv1.3 (draft)");

  *unknown_tls_version = 1;
  snprintf(v, sizeof(v), "TLS (%04X)", version);

  return(v);
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
  for (i = 0; i < sizeof(base64_table) - 1; i++)
    dtable[base64_table[i]] = (u_char) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < len; i++) {
    if (dtable[src[i]] != 0x80)
      count++;
  }

  if (count == 0 || count % 4)
    return NULL;

  olen = count / 4 * 3;
  pos = out = ndpi_malloc(olen);
  if (out == NULL)
    return NULL;

  count = 0;
  for (i = 0; i < len; i++) {
    tmp = dtable[src[i]];
    if (tmp == 0x80)
      continue;

    if (src[i] == '=')
      pad++;
    block[count] = tmp;
    count++;
    if (count == 4) {
      *pos++ = (block[0] << 2) | (block[1] >> 4);
      *pos++ = (block[1] << 4) | (block[2] >> 2);
      *pos++ = (block[2] << 6) | block[3];
      count = 0;
      if (pad) {
	if (pad == 1)
	  pos--;
	else if (pad == 2)
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

char* ndpi_base64_encode(unsigned char const* bytes_to_encode, ssize_t in_len) {
  ssize_t len = 0, ret_size;
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
/* ********************************** */

int ndpi_flow2json(struct ndpi_detection_module_struct *ndpi_struct,
		   struct ndpi_flow_struct *flow,
		   u_int8_t ip_version,
		   u_int8_t l4_protocol, u_int16_t vlan_id,
		   u_int32_t src_v4, u_int32_t dst_v4,
		   struct ndpi_in6_addr *src_v6, struct ndpi_in6_addr *dst_v6,
		   u_int16_t src_port, u_int16_t dst_port,
		   ndpi_protocol l7_protocol,
		   ndpi_serializer *serializer) {
  char buf[64], src_name[32], dst_name[32];

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

  ndpi_serialize_start_of_block(serializer, "ndpi");
  ndpi_serialize_string_string(serializer, "proto", ndpi_protocol2name(ndpi_struct, l7_protocol, buf, sizeof(buf)));
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    ndpi_serialize_string_string(serializer, "category", ndpi_category_get_name(ndpi_struct, l7_protocol.category));
  ndpi_serialize_end_of_block(serializer);

  if(flow == NULL) return(0);

  switch(l7_protocol.master_protocol ? l7_protocol.master_protocol : l7_protocol.app_protocol) {
  case NDPI_PROTOCOL_DHCP:
    ndpi_serialize_start_of_block(serializer, "dhcp");
    ndpi_serialize_string_string(serializer, "fingerprint", flow->protos.dhcp.fingerprint);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_BITTORRENT:
    {
      u_int i, j, n = 0;
      char bittorent_hash[32];

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
    ndpi_serialize_string_string(serializer, "answer", flow->protos.mdns.answer);
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
    ndpi_serialize_string_string(serializer,   "url", flow->http.url);
    ndpi_serialize_string_uint32(serializer,   "code", flow->http.response_status_code);
    ndpi_serialize_string_string(serializer,   "content_type", flow->http.content_type);
    ndpi_serialize_string_string(serializer,   "user_agent", flow->http.user_agent);
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
    if(flow->protos.stun_ssl.ssl.ssl_version) {
      char notBefore[32], notAfter[32];
      struct tm a, b, *before = NULL, *after = NULL;
      u_int i, off;
      u_int8_t unknown_tls_version;
      char *version = ndpi_ssl_version2str(flow->protos.stun_ssl.ssl.ssl_version, &unknown_tls_version);

      if(flow->protos.stun_ssl.ssl.notBefore)
        before = gmtime_r((const time_t *)&flow->protos.stun_ssl.ssl.notBefore, &a);
      if(flow->protos.stun_ssl.ssl.notAfter)
        after  = gmtime_r((const time_t *)&flow->protos.stun_ssl.ssl.notAfter, &b);

      if(!unknown_tls_version) {
	ndpi_serialize_start_of_block(serializer, "tls");
	ndpi_serialize_string_string(serializer, "version", version);
	ndpi_serialize_string_string(serializer, "client_requested_server_name",
				     flow->protos.stun_ssl.ssl.client_requested_server_name);
	if(flow->protos.stun_ssl.ssl.server_names)
	  ndpi_serialize_string_string(serializer, "server_names", flow->protos.stun_ssl.ssl.server_names);
	ndpi_serialize_string_string(serializer, "issuer", flow->protos.stun_ssl.ssl.server_organization);

	if(before) {
          strftime(notBefore, sizeof(notBefore), "%F %T", before);
          ndpi_serialize_string_string(serializer, "notbefore", notBefore);
        }

	if(after) {
	  strftime(notAfter, sizeof(notAfter), "%F %T", after);
          ndpi_serialize_string_string(serializer, "notafter", notAfter);
        }
	ndpi_serialize_string_string(serializer, "ja3", flow->protos.stun_ssl.ssl.ja3_client);
	ndpi_serialize_string_string(serializer, "ja3s", flow->protos.stun_ssl.ssl.ja3_server);
	ndpi_serialize_string_uint32(serializer, "unsafe_cipher", flow->protos.stun_ssl.ssl.server_unsafe_cipher);
	ndpi_serialize_string_string(serializer, "cipher", ndpi_cipher2str(flow->protos.stun_ssl.ssl.server_cipher));

	if(flow->l4.tcp.tls.sha1_certificate_fingerprint[0] != '\0') {
	  for(i=0, off=0; i<20; i++) {
	    int rc = snprintf(&buf[off], sizeof(buf)-off,"%s%02X", (i > 0) ? ":" : "",
			      flow->l4.tcp.tls.sha1_certificate_fingerprint[i] & 0xFF);
	    
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
  if (!initialized_comp_rx) {
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

    if (pcreExecRet >= 0) {
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

ndpi_url_risk ndpi_validate_url(char *url) {
  char *orig_str = NULL, *str = NULL, *question_mark = strchr(url, '?');
  ndpi_url_risk rc = ndpi_url_no_problem;

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
	    rc = ndpi_url_possible_xss;
	  else if(ndpi_is_sql_injection(decoded))
	    rc = ndpi_url_possible_sql_injection;
#ifdef HAVE_PCRE
	  else if(ndpi_is_rce_injection(decoded))
	    rc = ndpi_url_possible_rce_injection;
#endif

#ifdef URL_CHECK_DEBUG
	  printf("=>> [rc: %u] %s\n", rc, decoded);
#endif
	}

	ndpi_free(decoded);

	if(rc != ndpi_url_no_problem)
	  break;
      }
      
      str = strtok_r(NULL, "&", &tmp);
    }
  }

 validate_rc:
  if(orig_str) ndpi_free(orig_str);
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
