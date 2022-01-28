/*
 * ndpi_utils.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

const char* ndpi_cipher2str(u_int32_t cipher) {
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
      static char buf[8];

      snprintf(buf, sizeof(buf), "0X%04X", cipher);
      return(buf);
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
    return(isdigit(c)
	   || isalpha(c)
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

  if((isdigit(str[0]) && isdigit(str[1]))
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
                                                  u_int16_t proto_id)
{
  switch (proto_id)
  {
    case NDPI_PROTOCOL_DNS:
    case NDPI_PROTOCOL_HTTP:
        return flow->host_server_name;
    case NDPI_PROTOCOL_QUIC:
    case NDPI_PROTOCOL_TLS:
        if (flow->protos.tls_quic.hello_processed != 0)
        {
          return flow->host_server_name;
        }
        break;
  }

  return NULL;
}

const char* ndpi_get_flow_info(struct ndpi_flow_struct const * const flow,
                               ndpi_protocol const * const l7_protocol)
{
  char const * const app_protocol_info = ndpi_get_flow_info_by_proto_id(flow, l7_protocol->app_protocol);

  if (app_protocol_info != NULL)
  {
    return app_protocol_info;
  }

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

  snprintf(buf, buf_len, "TLS (%04X)", version);

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
                         ndpi_risk_enum risk)
{
  u_int32_t i;

  if (risk == NDPI_NO_RISK) {
    return;
  }

  ndpi_serialize_start_of_block(serializer, "flow_risk");
  for(i = 0; i < NDPI_MAX_RISK; i++) {
    ndpi_risk_enum r = (ndpi_risk_enum)i;

    if(NDPI_ISSET_BIT(risk, r))
      ndpi_serialize_uint32_string(serializer, i, ndpi_risk2str(r));
  }

  ndpi_serialize_end_of_block(serializer);
}

 /* ********************************** */

void ndpi_serialize_proto(struct ndpi_detection_module_struct *ndpi_struct,
                          ndpi_serializer *serializer,
                          ndpi_risk_enum risk,
                          ndpi_protocol l7_protocol)
{
  char buf[64];

  ndpi_serialize_start_of_block(serializer, "ndpi");
  ndpi_serialize_risk(serializer, risk);
  ndpi_serialize_string_string(serializer, "proto", ndpi_protocol2name(ndpi_struct, l7_protocol, buf, sizeof(buf)));
  ndpi_protocol_breed_t breed =
    ndpi_get_proto_breed(ndpi_struct,
                         (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  ndpi_serialize_string_string(serializer, "breed", ndpi_get_proto_breed_name(ndpi_struct, breed));
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    ndpi_serialize_string_string(serializer, "category", ndpi_category_get_name(ndpi_struct, l7_protocol.category));
  ndpi_serialize_end_of_block(serializer);
}

/* ********************************** */

/* NOTE: serializer must have been already initialized */
int ndpi_dpi2json(struct ndpi_detection_module_struct *ndpi_struct,
		  struct ndpi_flow_struct *flow,
		  ndpi_protocol l7_protocol,
		  ndpi_serializer *serializer) {
  char buf[64];

  if(flow == NULL) return(-1);

  ndpi_serialize_proto(ndpi_struct, serializer, flow->risk, l7_protocol);

  switch(l7_protocol.master_protocol ? l7_protocol.master_protocol : l7_protocol.app_protocol) {
  case NDPI_PROTOCOL_IP_ICMP:
    if (flow->entropy > 0.0f) {
      ndpi_serialize_string_float(serializer, "entropy", flow->entropy, "%.6f");
    }
    break;

  case NDPI_PROTOCOL_DHCP:
    ndpi_serialize_start_of_block(serializer, "dhcp");
    ndpi_serialize_string_string(serializer, "hostname", flow->host_server_name);
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

  case NDPI_PROTOCOL_DNS:
    ndpi_serialize_start_of_block(serializer, "dns");
    if(flow->host_server_name[0] != '\0')
      ndpi_serialize_string_string(serializer, "query", flow->host_server_name);
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
    ndpi_serialize_string_string(serializer, "answer", flow->host_server_name);
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
      ndpi_serialize_string_string(serializer, "hostname", flow->host_server_name);
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
    if(flow->host_server_name[0] != '\0')
      ndpi_serialize_string_string(serializer, "client_requested_server_name",
                                   flow->host_server_name);
    if(flow->protos.tls_quic.server_names)
      ndpi_serialize_string_string(serializer, "server_names", flow->protos.tls_quic.server_names);
    if(flow->http.user_agent)
      ndpi_serialize_string_string(serializer, "user_agent", flow->http.user_agent);
    if(flow->protos.tls_quic.ssl_version) {
      u_int8_t unknown_tls_version;
      char version[16];

      ndpi_ssl_version2str(version, sizeof(version), flow->protos.tls_quic.ssl_version, &unknown_tls_version);

      if(!unknown_tls_version)
	ndpi_serialize_string_string(serializer, "version", version);
      if(flow->protos.tls_quic.alpn)
        ndpi_serialize_string_string(serializer, "alpn", flow->protos.tls_quic.alpn);
      ndpi_serialize_string_string(serializer, "ja3", flow->protos.tls_quic.ja3_client);
      if(flow->protos.tls_quic.tls_supported_versions)
        ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic.tls_supported_versions);
    }
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_IMAP:
    ndpi_serialize_start_of_block(serializer, "imap");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_POP:
    ndpi_serialize_start_of_block(serializer, "pop");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_MAIL_SMTP:
    ndpi_serialize_start_of_block(serializer, "smtp");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_end_of_block(serializer);
    break;

  case NDPI_PROTOCOL_FTP_CONTROL:
    ndpi_serialize_start_of_block(serializer, "ftp");
    ndpi_serialize_string_string(serializer,  "user", flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_serialize_string_string(serializer,  "password", flow->l4.tcp.ftp_imap_pop_smtp.password);
    ndpi_serialize_string_uint32(serializer,  "auth_failed", flow->l4.tcp.ftp_imap_pop_smtp.auth_failed);
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
    if(flow->protos.tls_quic.ssl_version) {
      char notBefore[32], notAfter[32];
      struct tm a, b, *before = NULL, *after = NULL;
      u_int i, off;
      u_int8_t unknown_tls_version;
      char version[16];

      ndpi_ssl_version2str(version, sizeof(version), flow->protos.tls_quic.ssl_version, &unknown_tls_version);

      if(flow->protos.tls_quic.notBefore)
        before = gmtime_r((const time_t *)&flow->protos.tls_quic.notBefore, &a);
      if(flow->protos.tls_quic.notAfter)
        after  = gmtime_r((const time_t *)&flow->protos.tls_quic.notAfter, &b);

      if(!unknown_tls_version) {
	ndpi_serialize_start_of_block(serializer, "tls");
	ndpi_serialize_string_string(serializer, "version", version);
	ndpi_serialize_string_string(serializer, "client_requested_server_name",
				     flow->host_server_name);
	if(flow->protos.tls_quic.server_names)
	  ndpi_serialize_string_string(serializer, "server_names", flow->protos.tls_quic.server_names);

	if(before) {
          strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
          ndpi_serialize_string_string(serializer, "notbefore", notBefore);
        }

	if(after) {
	  strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);
          ndpi_serialize_string_string(serializer, "notafter", notAfter);
        }
	ndpi_serialize_string_string(serializer, "ja3", flow->protos.tls_quic.ja3_client);
	ndpi_serialize_string_string(serializer, "ja3s", flow->protos.tls_quic.ja3_server);
	ndpi_serialize_string_uint32(serializer, "unsafe_cipher", flow->protos.tls_quic.server_unsafe_cipher);
	ndpi_serialize_string_string(serializer, "cipher", ndpi_cipher2str(flow->protos.tls_quic.server_cipher));

	if(flow->protos.tls_quic.issuerDN)
	  ndpi_serialize_string_string(serializer, "issuerDN", flow->protos.tls_quic.issuerDN);

	if(flow->protos.tls_quic.subjectDN)
	  ndpi_serialize_string_string(serializer, "subjectDN", flow->protos.tls_quic.subjectDN);

	if(flow->protos.tls_quic.alpn)
	  ndpi_serialize_string_string(serializer, "alpn", flow->protos.tls_quic.alpn);

	if(flow->protos.tls_quic.tls_supported_versions)
	  ndpi_serialize_string_string(serializer, "tls_supported_versions", flow->protos.tls_quic.tls_supported_versions);

	if(flow->protos.tls_quic.sha1_certificate_fingerprint[0] != '\0') {
	  for(i=0, off=0; i<20; i++) {
	    int rc = snprintf(&buf[off], sizeof(buf)-off,"%s%02X", (i > 0) ? ":" : "",
			      flow->protos.tls_quic.sha1_certificate_fingerprint[i] & 0xFF);

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
		   u_int8_t l4_protocol,
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

  case ndpi_vxlan_tunnel:
    return("VXLAN");
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
    return("Binary Application Transfer");

  case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
    return("Known Protocol on Non Standard Port");

  case NDPI_TLS_SELFSIGNED_CERTIFICATE:
    return("Self-signed Certificate");

  case NDPI_TLS_OBSOLETE_VERSION:
    return("Obsolete TLS Version (1.1 or older)");

  case NDPI_TLS_WEAK_CIPHER:
    return("Weak TLS Cipher");

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
    return("TLS (probably) Not Carrying HTTPS");

  case NDPI_SUSPICIOUS_DGA_DOMAIN:
    return("Suspicious DGA Domain name");

  case NDPI_MALFORMED_PACKET:
    return("Malformed Packet");

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
    return("Suspicious DNS Traffic"); /* Exfiltration ? */

  case NDPI_TLS_MISSING_SNI:
    return("Missing SNI TLS Extension");

  case NDPI_HTTP_SUSPICIOUS_CONTENT:
    return("HTTP Suspicious Content");

  case NDPI_RISKY_ASN:
    return("Risky ASN");

  case NDPI_RISKY_DOMAIN:
    return("Risky Domain Name");

  case NDPI_MALICIOUS_JA3:
    return("Possibly Malicious JA3 Fingerprint");

  case NDPI_MALICIOUS_SHA1_CERTIFICATE:
    return("Possibly Malicious SSL Cert. SHA1 Fingerprint");

  case NDPI_DESKTOP_OR_FILE_SHARING_SESSION:
    return("Desktop/File Sharing Session");

  case NDPI_TLS_UNCOMMON_ALPN:
    return("Uncommon TLS ALPN");

  case NDPI_TLS_CERT_VALIDITY_TOO_LONG:
    return("TLS Certificate Validity Too Long");

  case NDPI_TLS_SUSPICIOUS_EXTENSION:
    return("TLS Suspicious Extension");

  case NDPI_TLS_FATAL_ALERT:
    return("TLS Fatal Alert");

  case NDPI_SUSPICIOUS_ENTROPY:
    return("Suspicious Entropy");
      
  case NDPI_CLEAR_TEXT_CREDENTIALS:
    return("Clear-Text Credentials");
    
  case NDPI_DNS_LARGE_PACKET:
    return("DNS Packet Larger Than 512 bytes");
    
  case NDPI_DNS_FRAGMENTED:
    return("Fragmented DNS Message");

  case NDPI_INVALID_CHARACTERS:
    return("Text Contains Non-Printable Characters");

  case NDPI_POSSIBLE_EXPLOIT:
    return("Possible Exploit Detected");
    break;
    
  case NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE:
    return("TLS Certificate About To Expire");
    break;
    
  default:
    snprintf(buf, sizeof(buf), "%d", (int)risk);
    return(buf);
  }
}

/* ******************************************************************** */

const char* ndpi_severity2str(ndpi_risk_severity s) {
  switch(s) {
  case NDPI_RISK_LOW:
    return("Low");
    break;

  case NDPI_RISK_MEDIUM:
    return("Medium");
    break;

  case NDPI_RISK_HIGH:
    return("High");
    break;

  case NDPI_RISK_SEVERE:
    return("Severe");
    break;
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
  ndpi_str_hash *h = (ndpi_str_hash*)ndpi_malloc(sizeof(ndpi_str_hash));

  if(!h) return(NULL);
  if(max_num_entries < 1024) max_num_entries = 1024;
  if(max_num_entries > 10000000) max_num_entries = 10000000;

  h->max_num_entries = max_num_entries, h->num_buckets = max_num_entries/2;
  h->buckets = (struct ndpi_str_hash_info**)ndpi_calloc(sizeof(struct ndpi_str_hash_info*), h->num_buckets);

  if(h->buckets == NULL) {
    ndpi_free(h);
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

      ndpi_free(head->key);
      ndpi_free(head);
      head = next;
    }
  }

  ndpi_free(h->buckets);
  ndpi_free(h);
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
    struct ndpi_str_hash_info *e = (struct ndpi_str_hash_info*)ndpi_malloc(sizeof(struct ndpi_str_hash_info));

    if(e == NULL)
      return(-2);

    if((e->key = (char*)ndpi_malloc(key_len)) == NULL)
      return(-3);

    memcpy(e->key, key, key_len);
    e->key_len = key_len, e->value = value;
    e->next = h->buckets[hv];
    h->buckets[hv] = e;

    return(0);
  } else
    return(0);
}

/* ********************************************************************************* */

static u_int64_t ndpi_host_ip_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					       struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_mask_ptree, &prefix);

  if(node)
    return(node->value.u.uv64);
  else
    return((u_int64_t)-1);
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
      ndpi_automa *automa = &ndpi_str->host_risk_mask_automa;

      if(automa->ac_automa) {
	AC_TEXT_t ac_input_text;
	AC_REP_t match;

	ac_input_text.astring = host, ac_input_text.length = strlen(host);
	ac_input_text.option = 0;

	if(ac_automata_search(automa->ac_automa, &ac_input_text, &match) > 0)
	   flow->risk_mask &= match.number64;
      }

      /* Used to avoid double checks (e.g. in DNS req/rsp) */
      flow->host_risk_mask_evaluated = 1;
    }
  }

  /* TODO: add IPv6 support */
  if(!flow->ip_risk_mask_evaluated) {
    if(flow->is_ipv6 == 0) {
      struct in_addr pin;

      pin.s_addr = flow->saddr;
      flow->risk_mask &= ndpi_host_ip_risk_ptree_match(ndpi_str, &pin);

      pin.s_addr = flow->daddr;
      flow->risk_mask &= ndpi_host_ip_risk_ptree_match(ndpi_str, &pin);
    }

    flow->ip_risk_mask_evaluated = 1;
  }

  flow->risk &= flow->risk_mask;
}

/* ******************************************************************** */

void ndpi_set_risk(struct ndpi_detection_module_struct *ndpi_str,
		   struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  ndpi_risk v = 1ull << r;

  // NDPI_SET_BIT(flow->risk, (u_int32_t)r);
  flow->risk |= v;
  ndpi_handle_risk_exceptions(ndpi_str, flow);
}

/* ******************************************************************** */

int ndpi_isset_risk(struct ndpi_detection_module_struct *ndpi_str,
		     struct ndpi_flow_struct *flow, ndpi_risk_enum r) {
  ndpi_risk v = 1ull << r;

  return(((flow->risk & v) == v) ?  1 : 0);
}

/* ******************************************************************** */

int ndpi_is_printable_string(char * const str, size_t len) {
  int retval = 1;

  for (size_t i = 0; i < len; ++i) {
    if (ndpi_isprint(str[i]) == 0) {
      str[i] = '?';
      retval = 0;
    }
  }

  return retval;
}

/* ******************************************************************** */

float ndpi_entropy(u_int8_t const * const buf, size_t len) {
  float entropy = 0.0f;
  u_int32_t byte_counters[256];

  memset(byte_counters, 0, sizeof(byte_counters));

  for (size_t i = 0; i < len; ++i) {
    byte_counters[buf[i]]++;
  }

  for (size_t i = 0; i < sizeof(byte_counters) / sizeof(byte_counters[0]); ++i) {
    if (byte_counters[i] == 0) {
      continue;
    }

    float const p = (float)byte_counters[i] / len;
    entropy += p * log2f(1 / p);
  }

  return entropy;
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
    "h3-32", "h3-30", "h3-29", "h3-28", "h3-27", "h3-24", "h3-22",
    "hq-30", "hq-29", "hq-28", "hq-27",
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
    ac_pattern.length       = strlen(common_alpns[i]);

    if(ac_automata_add(ndpi_str->common_alpns_automa.ac_automa, &ac_pattern) != ACERR_SUCCESS)
      printf("%s(): unable to add %s\n", __FUNCTION__, common_alpns[i]);
  }
}

/* ******************************************* */

u_int8_t is_a_common_alpn(struct ndpi_detection_module_struct *ndpi_str,
			  const char *alpn_to_check, u_int alpn_to_check_len) {
  ndpi_automa *automa = &ndpi_str->common_alpns_automa;
  
  if(automa->ac_automa) {
    AC_TEXT_t ac_input_text;
    AC_REP_t match;
    
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
  ndpi_str->tls_certificate_expire_in_x_days = num_days;
}
