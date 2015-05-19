/*
 * ndpi_main.c
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-11 - ipoque GmbH
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


#ifndef __KERNEL__
#include <stdlib.h>
#include <errno.h>
#endif

#include "ahocorasick.h"
#include "ndpi_api.h"


#ifndef __KERNEL__
#include "../../config.h"
#endif

// #define DEBUG

#ifdef __KERNEL__
#include <linux/version.h>
#define printf printk
#else
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif
#endif

#include "ndpi_content_match.c.inc"
#include "third_party/include/ndpi_patricia.h"
#include "third_party/src/ndpi_patricia.c"

#ifdef WIN32
/* http://social.msdn.microsoft.com/Forums/uk/vcgeneral/thread/963aac07-da1a-4612-be4a-faac3f1d65ca */
#ifndef strtok_r
#define strtok_r(a,b,c) strtok(a,b)
#endif
#endif

#ifdef __KERNEL__
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static inline char _tolower(const char c)
{
  return c | 0x20;
}

static int _kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
  unsigned long long acc;
  int ok;

  if(base == 0) {
    if(s[0] == '0') {
      if(_tolower(s[1]) == 'x' && isxdigit(s[2]))
	base = 16;
      else
	base = 8;
    } else
      base = 10;
  }
  if(base == 16 && s[0] == '0' && _tolower(s[1]) == 'x')
    s += 2;

  acc = 0;
  ok = 0;
  while (*s) {
    unsigned int val;

    if('0' <= *s && *s <= '9')
      val = *s - '0';
    else if('a' <= _tolower(*s) && _tolower(*s) <= 'f')
      val = _tolower(*s) - 'a' + 10;
    else if(*s == '\n') {
      if(*(s + 1) == '\0')
	break;
      else
	return -EINVAL;
    } else
      return -EINVAL;

    if(val >= base)
      return -EINVAL;
    if(acc > div_u64(ULLONG_MAX - val, base))
      return -ERANGE;
    acc = acc * base + val;
    ok = 1;

    s++;
  }
  if(!ok)
    return -EINVAL;
  *res = acc;
  return 0;
}

int kstrtoull(const char *s, unsigned int base, unsigned long long *res)
{
  if(s[0] == '+')
    s++;
  return _kstrtoull(s, base, res);
}
int kstrtoll(const char *s, unsigned int base, long long *res)
{
  unsigned long long tmp;
  int rv;

  if(s[0] == '-') {
    rv = _kstrtoull(s + 1, base, &tmp);
    if(rv < 0)
      return rv;
    if((long long)(-tmp) >= 0)
      return -ERANGE;
    *res = -tmp;
  } else {
    rv = kstrtoull(s, base, &tmp);
    if(rv < 0)
      return rv;
    if((long long)tmp < 0)
      return -ERANGE;
    *res = tmp;
  }
  return 0;
}
int kstrtoint(const char *s, unsigned int base, int *res)
{
  long long tmp;
  int rv;

  rv = kstrtoll(s, base, &tmp);
  if(rv < 0)
    return rv;
  if(tmp != (long long)(int)tmp)
    return -ERANGE;
  *res = tmp;
  return 0;
}
#endif

int atoi(const char *str) {
  int rc;

  if(kstrtoint(str, 0, &rc) == 0 /* Success */)
    return(rc);
  else
    return(0);
}
#endif

/* ftp://ftp.cc.uoc.gr/mirrors/OpenBSD/src/lib/libc/stdlib/tsearch.c */
/* find or insert datum into search tree */
void *
ndpi_tsearch(const void *vkey, void **vrootp,
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
void *
ndpi_tdelete(const void *vkey, void **vrootp,
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
      for (q = r->left; q->left != (ndpi_node *)0; q = r->left)
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
static void
ndpi_trecurse(ndpi_node *root, void (*action)(const void *, ndpi_VISIT, int, void*), int level, void *user_data)
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
void
ndpi_twalk(const void *vroot, void (*action)(const void *, ndpi_VISIT, int, void *), void *user_data)
{
  ndpi_node *root = (ndpi_node *)vroot;

  if(root != (ndpi_node *)0 && action != (void (*)(const void *, ndpi_VISIT, int, void*))0)
    ndpi_trecurse(root, action, 0, user_data);
}

/* find a node, or return 0 */
void* ndpi_tfind(const void *vkey, void *vrootp,
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
static void ndpi_tdestroy_recurse(ndpi_node* root, void (*free_action)(void *)) {
  if(root->left != NULL)
    ndpi_tdestroy_recurse(root->left, free_action);
  if(root->right != NULL)
    ndpi_tdestroy_recurse(root->right, free_action);

  (*free_action) ((void *) root->key);
  ndpi_free(root);
}

void ndpi_tdestroy(void *vrootp, void (*freefct)(void *)) {
  ndpi_node *root = (ndpi_node *) vrootp;

  if(root != NULL)
    ndpi_tdestroy_recurse(root, freefct);
}

/* ****************************************** */

u_int8_t ndpi_net_match(u_int32_t ip_to_check,
			u_int32_t net,
			u_int32_t num_bits) {
  u_int32_t mask = 0;

  mask = ~(~mask >> num_bits);

  return(((ip_to_check & mask) == (net & mask)) ? 1 : 0);
}

u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
			u_int32_t net, u_int32_t num_bits) {
  return(ndpi_net_match(src, net, num_bits) || ndpi_net_match(dst, net, num_bits));
}

/* ****************************************** */

static void *(*_ndpi_malloc)(unsigned long size);
static void  (*_ndpi_free)(void *ptr);

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

int
strcasecmp(s1, s2)
     const char *s1, *s2;
{
  register const u_char *cm = charmap,
    *us1 = (const u_char *)s1,
    *us2 = (const u_char *)s2;

  while (cm[*us1] == cm[*us2++])
    if(*us1++ == '\0')
      return (0);
  return (cm[*us1] - cm[*--us2]);
}

int
strncasecmp(s1, s2, n)
     const char *s1, *s2;
     register size_t n;
{
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

/* ****************************************** */

/* Forward */
static void addDefaultPort(ndpi_port_range *range,
			   ndpi_proto_defaults_t *def, ndpi_default_ports_tree_node_t **root);
static int removeDefaultPort(ndpi_port_range *range,
			     ndpi_proto_defaults_t *def, ndpi_default_ports_tree_node_t **root);

/* ****************************************** */

void* ndpi_malloc(unsigned long size) { return(_ndpi_malloc(size)); }

/* ****************************************** */

void* ndpi_calloc(unsigned long count, unsigned long size) {
  unsigned long len = count*size;
  void *p = ndpi_malloc(len);

  if(p)
    memset(p, 0, len);

  return(p);
}

/* ****************************************** */

void  ndpi_free(void *ptr)            { _ndpi_free(ptr); }

/* ****************************************** */

void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size) {
  void *ret = ndpi_malloc(new_size);

  if(!ret)
    return(ret);
  else {
    memcpy(ret, ptr, old_size);
    ndpi_free(ptr);
    return(ret);
  }
}
/* ****************************************** */

char *ndpi_strdup(const char *s) {
  int len = strlen(s);
  char *m = ndpi_malloc(len+1);

  if(m) {
    memcpy(m, s, len);
    m[len] = '\0';
  }

  return(m);
}

/* ****************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void)
{
  return sizeof(struct ndpi_flow_struct);
}

/* ****************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void)
{
  return sizeof(struct ndpi_id_struct);
}

/* ******************************************************************** */

char* ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_mod, u_int id) {
  return((id >= ndpi_mod->ndpi_num_supported_protocols) ? NULL : ndpi_mod->proto_defaults[id].protoName);
}

/* ******************************************************************** */

ndpi_port_range* ndpi_build_default_ports_range(ndpi_port_range *ports,
						u_int16_t portA_low, u_int16_t portA_high,
						u_int16_t portB_low, u_int16_t portB_high,
						u_int16_t portC_low, u_int16_t portC_high,
						u_int16_t portD_low, u_int16_t portD_high,
						u_int16_t portE_low, u_int16_t portE_high) {
  int i = 0;

  ports[i].port_low = portA_low, ports[i].port_high = portA_high; i++;
  ports[i].port_low = portB_low, ports[i].port_high = portB_high; i++;
  ports[i].port_low = portC_low, ports[i].port_high = portC_high; i++;
  ports[i].port_low = portD_low, ports[i].port_high = portD_high; i++;
  ports[i].port_low = portE_low, ports[i].port_high = portE_high; i++;

  return(ports);
}

/* ******************************************************************** */

ndpi_port_range* ndpi_build_default_ports(ndpi_port_range *ports,
					  u_int16_t portA,
					  u_int16_t portB,
					  u_int16_t portC,
					  u_int16_t portD,
					  u_int16_t portE) {
  int i = 0;

  ports[i].port_low = portA, ports[i].port_high = portA; i++;
  ports[i].port_low = portB, ports[i].port_high = portB; i++;
  ports[i].port_low = portC, ports[i].port_high = portC; i++;
  ports[i].port_low = portD, ports[i].port_high = portD; i++;
  ports[i].port_low = portE, ports[i].port_high = portE; i++;

  return(ports);
}

/* ******************************************************************** */

void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_mod,
			     ndpi_protocol_breed_t breed, u_int16_t protoId,
			     u_int16_t tcp_master_protoId[2], u_int16_t udp_master_protoId[2],
			     char *protoName,
			     ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts) {
  char *name = ndpi_strdup(protoName);
  int j;

  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS) {
    printf("[NDPI] %s(protoId=%d): INTERNAL ERROR\n", __FUNCTION__, protoId);
    ndpi_free(name);
    return;
  }

  ndpi_mod->proto_defaults[protoId].protoName = name,
    ndpi_mod->proto_defaults[protoId].protoId = protoId,
    ndpi_mod->proto_defaults[protoId].protoBreed = breed;

  memcpy(&ndpi_mod->proto_defaults[protoId].master_tcp_protoId, tcp_master_protoId, 2*sizeof(u_int16_t));
  memcpy(&ndpi_mod->proto_defaults[protoId].master_udp_protoId, udp_master_protoId, 2*sizeof(u_int16_t));

  for(j=0; j<MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0) addDefaultPort(&udpDefPorts[j], &ndpi_mod->proto_defaults[protoId], &ndpi_mod->udpRoot);
    if(tcpDefPorts[j].port_low != 0) addDefaultPort(&tcpDefPorts[j], &ndpi_mod->proto_defaults[protoId], &ndpi_mod->tcpRoot);
  }

#if 0
  printf("%s(%d, %s, %p) [%s]\n",
	 __FUNCTION__,
	 protoId,
	 ndpi_mod->proto_defaults[protoId].protoName,
	 ndpi_mod,
	 ndpi_mod->proto_defaults[1].protoName);
#endif
}

/* ******************************************************************** */

static int ndpi_default_ports_tree_node_t_cmp(const void *a, const void *b) {
  ndpi_default_ports_tree_node_t *fa = (ndpi_default_ports_tree_node_t*)a;
  ndpi_default_ports_tree_node_t *fb = (ndpi_default_ports_tree_node_t*)b;

  //printf("[NDPI] %s(%d, %d)\n", __FUNCTION__, fa->default_port, fb->default_port);

  return((fa->default_port == fb->default_port) ? 0 : ((fa->default_port < fb->default_port) ? -1 : 1));
}

/* ******************************************************************** */

void ndpi_default_ports_tree_node_t_walker(const void *node, const ndpi_VISIT which, const int depth) {
  ndpi_default_ports_tree_node_t *f = *(ndpi_default_ports_tree_node_t **)node;


  printf("<%d>Walk on node %s (%u)\n",
	 depth,
	 which == ndpi_preorder?"ndpi_preorder":
	 which == ndpi_postorder?"ndpi_postorder":
	 which == ndpi_endorder?"ndpi_endorder":
	 which == ndpi_leaf?"ndpi_leaf": "unknown",
	 f->default_port);
}

/* ******************************************************************** */

static void addDefaultPort(ndpi_port_range *range,
			   ndpi_proto_defaults_t *def, ndpi_default_ports_tree_node_t **root) {
  ndpi_default_ports_tree_node_t *ret;
  u_int16_t port;

  // printf("[NDPI] %s(%d)\n", __FUNCTION__, port);

  for(port=range->port_low; port<=range->port_high; port++) {
    ndpi_default_ports_tree_node_t *node = (ndpi_default_ports_tree_node_t*)ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));

    if(!node) {
      printf("[NDPI] %s(): not enough memory\n", __FUNCTION__);
      break;
    }

    node->proto = def, node->default_port = port;
    ret = *(ndpi_default_ports_tree_node_t**)ndpi_tsearch(node, (void*)root, ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != node) {
      printf("[NDPI] %s(): found duplicate for port %u: overwriting it with new value\n", __FUNCTION__, port);

      ret->proto = def;
      ndpi_free(node);
    }
  }
}

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastrutures while using them
*/
static int removeDefaultPort(ndpi_port_range *range,
			     ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root) {
  ndpi_default_ports_tree_node_t node;
  ndpi_default_ports_tree_node_t *ret;
  u_int16_t port;

  for(port=range->port_low; port<=range->port_high; port++) {
    node.proto = def, node.default_port = port;
    ret = *(ndpi_default_ports_tree_node_t**)ndpi_tdelete(&node, (void*)root,
							  ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != NULL) {
      ndpi_free((ndpi_default_ports_tree_node_t*)ret);
      return(0);
    }
  }

  return(-1);
}

/* ****************************************************** */

static int ndpi_string_to_automa(struct ndpi_detection_module_struct *ndpi_struct,
				 ndpi_automa *automa,
				 char *value, int protocol_id,
				 ndpi_protocol_breed_t breed) {
  AC_PATTERN_t ac_pattern;

  if(protocol_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)) {
    printf("[NDPI] %s(protoId=%d): INTERNAL ERROR\n", __FUNCTION__, protocol_id);
    return(-1);
  }

  if(automa->ac_automa == NULL) return(-2);
  ac_pattern.astring = value;
  ac_pattern.rep.number = protocol_id;
  ac_pattern.length = strlen(ac_pattern.astring);
  ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern);

  return(0);
}

/* ****************************************************** */

static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					 char *value, int protocol_id,
					 ndpi_protocol_breed_t breed) {
  return(ndpi_string_to_automa(ndpi_struct, &ndpi_struct->host_automa,
			       value, protocol_id, breed));
}

/* ****************************************************** */

int ndpi_add_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				 char *value, int protocol_id,
				 ndpi_protocol_breed_t breed) {
  return(ndpi_string_to_automa(ndpi_struct, &ndpi_struct->content_automa, value, protocol_id, breed));
}

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastrutures while using them
*/
static int ndpi_remove_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					    char *value, int protocol_id) {

  printf("[NDPI] Missing implementation of %s()\n", __FUNCTION__);
  return(-1);
}

/* ******************************************************************** */

static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_mod) {
  int i;

  for(i=0; host_match[i].string_to_match != NULL; i++) {
    ndpi_add_host_url_subprotocol(ndpi_mod, host_match[i].string_to_match,
				  host_match[i].protocol_id, host_match[i].protocol_breed);

    if(ndpi_mod->proto_defaults[host_match[i].protocol_id].protoName == NULL) {
      ndpi_mod->proto_defaults[host_match[i].protocol_id].protoName = ndpi_strdup(host_match[i].proto_name);
      ndpi_mod->proto_defaults[host_match[i].protocol_id].protoId = host_match[i].protocol_id;
      ndpi_mod->proto_defaults[host_match[i].protocol_id].protoBreed = host_match[i].protocol_breed;
    }
  }

  for(i=0; content_match[i].string_to_match != NULL; i++)
    ndpi_add_content_subprotocol(ndpi_mod, content_match[i].string_to_match,
				 content_match[i].protocol_id,
				 content_match[i].protocol_breed);

  for(i=0; ndpi_en_bigrams[i] != NULL; i++)
    ndpi_string_to_automa(ndpi_mod, &ndpi_mod->bigrams_automa,
			  (char*)ndpi_en_bigrams[i],
			  1, NDPI_PROTOCOL_UNRATED);

  for(i=0; ndpi_en_impossible_bigrams[i] != NULL; i++)
    ndpi_string_to_automa(ndpi_mod, &ndpi_mod->impossible_bigrams_automa,
			  (char*)ndpi_en_impossible_bigrams[i],
			  1, NDPI_PROTOCOL_UNRATED);
}

/* ******************************************************************** */

/* This function is used to map protocol name and default ports and it MUST
   be updated whenever a new protocol is added to NDPI.

   Do NOT add web services (NDPI_SERVICE_xxx) here.
*/
static void ndpi_init_protocol_defaults(struct ndpi_detection_module_struct *ndpi_mod) {
  int i;
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
  u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO },
    custom_master[2], custom_master1[2];

    /* Reset all settings */
    memset(ndpi_mod->proto_defaults, 0, sizeof(ndpi_mod->proto_defaults));

    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			    no_master,
			    no_master, "Unknown",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_CONTROL,
			    no_master,
			    no_master, "FTP_CONTROL",
			    ndpi_build_default_ports(ports_a, 21, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_DATA,
			    no_master,
			    no_master, "FTP_DATA",
			    ndpi_build_default_ports(ports_a, 20, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_POP,
			    no_master,
			    no_master, "POP3",
			    ndpi_build_default_ports(ports_a, 110, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_POPS,
			    no_master,
			    no_master, "POPS",
			    ndpi_build_default_ports(ports_a, 995, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_SMTP,
			    no_master,
			    no_master, "SMTP",
			    ndpi_build_default_ports(ports_a, 25, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_SMTPS,
			    no_master,
			    no_master, "SMTPS",
			    ndpi_build_default_ports(ports_a, 465, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_IMAP,
			    no_master,
			    no_master, "IMAP",
			    ndpi_build_default_ports(ports_a, 143, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_IMAPS,
			    no_master,
			    no_master, "IMAPS",
			    ndpi_build_default_ports(ports_a, 993, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNS,
			    no_master,
			    no_master, "DNS",
			    ndpi_build_default_ports(ports_a, 53, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 53, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IPP,
			    no_master,
			    no_master, "IPP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			    no_master,
			    no_master, "HTTP",
			    ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MDNS,
			    no_master,
			    no_master, "MDNS",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5353, 5354, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NTP,
			    no_master,
			    no_master, "NTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 123, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETBIOS,
			    no_master,
			    no_master, "NetBIOS",
			    ndpi_build_default_ports(ports_a, 139, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 137, 138, 139, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NFS,
			    no_master,
			    no_master, "NFS",
			    ndpi_build_default_ports(ports_a, 2049, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2049, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSDP,
			    no_master,
			    no_master, "SSDP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BGP,
			    no_master,
			    no_master, "BGP",
			    ndpi_build_default_ports(ports_a, 2605, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNMP,
			    no_master,
			    no_master, "SNMP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 161, 162, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XDMCP,
			    no_master,
			    no_master, "XDMCP",
			    ndpi_build_default_ports(ports_a, 177, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 177, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMB,
			    no_master,
			    no_master, "SMB",
			    ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SYSLOG,
			    no_master,
			    no_master, "Syslog",
			    ndpi_build_default_ports(ports_a, 514, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 514, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCP,
			    no_master,
			    no_master, "DHCP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 67, 68, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_POSTGRES,
			    no_master,
			    no_master, "PostgreSQL",
			    ndpi_build_default_ports(ports_a, 5432, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MYSQL,
			    no_master,
			    no_master, "MySQL",
			    ndpi_build_default_ports(ports_a, 3306, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_TDS,
			    no_master,
			    no_master, "TDS",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,
			    no_master,
			    no_master, "Direct_Download_Link",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_APPLEJUICE,
			    no_master,
			    no_master, "AppleJuice",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECTCONNECT,
			    no_master,
			    no_master, "DirectConnect",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_SOCRATES,
			    no_master,
			    no_master, "Socrates",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_WINMX,
			    no_master,
			    no_master, "WinMX",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VMWARE,
			    no_master,
			    no_master, "VMware",
			    ndpi_build_default_ports(ports_a, 903, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 902, 903, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FILETOPIA,
			    no_master,
			    no_master, "Filetopia",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_IMESH,
			    no_master,
			    no_master, "iMESH",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_KONTIKI,
			    no_master,
			    no_master, "Kontiki",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_OPENFT,
			    no_master,
			    no_master, "OpenFT",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FASTTRACK,
			    no_master,
			    no_master, "FastTrack",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_GNUTELLA,
			    no_master,
			    no_master, "Gnutella",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_EDONKEY,
			    no_master,
			    no_master, "eDonkey",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BITTORRENT,
			    no_master,
			    no_master, "BitTorrent",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6771, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EPP,
			    no_master,
			    no_master, "EPP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_AVI,
			    no_master,
			    no_master, "AVI",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_FLASH,
			    no_master,
			    no_master, "Flash",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_OGG,
			    no_master,
			    no_master, "OggVorbis",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_MPEG,
			    no_master,
			    no_master, "MPEG",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_QUICKTIME,
			    no_master,
			    no_master, "QuickTime",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_REALMEDIA,
			    no_master,
			    no_master, "RealMedia",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_WINDOWSMEDIA,
			    no_master,
			    no_master, "WindowsMedia",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_MMS,
			    no_master,
			    no_master, "MMS",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_XBOX,
			    no_master,
			    no_master, "Xbox",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQ,
			    no_master,
			    no_master, "QQ",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MOVE,
			    no_master,
			    no_master, "Move",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RTSP,
			    no_master,
			    no_master, "RTSP",
			    ndpi_build_default_ports(ports_a, 554, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 554, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ICECAST,
			    no_master,
			    no_master, "IceCast",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPLIVE,
			    no_master,
			    no_master, "PPLive",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			    no_master,
			    no_master, "PPStream",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ZATTOO,
			    no_master,
			    no_master, "Zattoo",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SHOUTCAST,
			    no_master,
			    no_master, "ShoutCast",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOPCAST,
			    no_master,
			    no_master, "Sopcast",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVANTS,
			    no_master,
			    no_master, "Tvants",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVUPLAYER,
			    no_master,
			    no_master, "TVUplayer",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV,
			    no_master,
			    no_master, "HTTP_APPLICATION_VEOHTV",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQLIVE,
			    no_master,
			    no_master, "QQLive",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_THUNDER,
			    no_master,
			    no_master, "Thunder",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOULSEEK,
			    no_master,
			    no_master, "Soulseek",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SSL, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSL_NO_CERT,
			    custom_master, no_master, "SSL_No_Cert",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IRC,
			    no_master,
			    no_master, "IRC",
			    ndpi_build_default_ports(ports_a, 194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AYIYA,
			    no_master,
			    no_master, "Ayiya",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5072, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UNENCRYPED_JABBER,
			    no_master,
			    no_master, "Unencryped_Jabber",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSN,
			    no_master,
			    no_master, "MSN",
			    ndpi_build_default_ports(ports_a, 1863, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OSCAR,
			    no_master,
			    no_master, "Oscar",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_YAHOO,
			    no_master,
			    no_master, "Yahoo",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_BATTLEFIELD,
			    no_master,
			    no_master, "BattleField",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QUAKE,
			    no_master,
			    no_master, "Quake",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_VRRP,
			    no_master,
			    no_master, "VRRP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STEAM,
			    no_master,
			    no_master, "Steam",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HALFLIFE2,
			    no_master,
			    no_master, "HalfLife2",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			    no_master,
			    no_master, "WorldOfWarcraft",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_TELNET,
			    no_master,
			    no_master, "Telnet",
			    ndpi_build_default_ports(ports_a, 23, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SIP, custom_master[1] = NDPI_PROTOCOL_H323;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_STUN,
			    no_master, custom_master, "STUN",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_IP_IPSEC,
			    no_master,
			    no_master, "IPsec",
			    ndpi_build_default_ports(ports_a, 500, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 500, 4500, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_GRE,
			    no_master,
			    no_master, "GRE",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMP,
			    no_master,
			    no_master, "ICMP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IGMP,
			    no_master,
			    no_master, "IGMP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_EGP,
			    no_master,
			    no_master, "EGP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_SCTP,
			    no_master,
			    no_master, "SCTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_OSPF,
			    no_master,
			    no_master, "OSPF",
			    ndpi_build_default_ports(ports_a, 2604, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IP_IN_IP,
			    no_master,
			    no_master, "IP_in_IP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTP,
			    no_master,
			    no_master, "RTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RDP,
			    no_master,
			    no_master, "RDP",
			    ndpi_build_default_ports(ports_a, 3389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VNC,
			    no_master,
			    no_master, "VNC",
			    ndpi_build_default_ports(ports_a, 5900, 5901, 5800, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PCANYWHERE,
			    no_master,
			    no_master, "PcAnywhere",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SSL_NO_CERT, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_SSL,
			    no_master, custom_master, "SSL",
			    ndpi_build_default_ports(ports_a, 443, 3001 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSH,
			    no_master,
			    no_master, "SSH",
			    ndpi_build_default_ports(ports_a, 22, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_USENET,
			    no_master,
			    no_master, "Usenet",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MGCP,
			    no_master,
			    no_master, "MGCP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IAX,
			    no_master,
			    no_master, "IAX",
			    ndpi_build_default_ports(ports_a, 4569, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 4569, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TFTP,
			    no_master,
			    no_master, "TFTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AFP,
			    no_master,
			    no_master, "AFP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_STEALTHNET,
			    no_master,
			    no_master, "Stealthnet",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AIMINI,
			    no_master,
			    no_master, "Aimini",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIP,
			    no_master,
			    no_master,
			    "SIP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5060, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TRUPHONE,
			    no_master,
			    no_master, "TruPhone",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMPV6,
			    no_master,
			    no_master, "ICMPV6",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCPV6,
			    no_master,
			    no_master, "DHCPV6",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ARMAGETRON,
			    no_master,
			    no_master, "Armagetron",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CROSSFIRE,
			    no_master,
			    no_master, "Crossfire",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DOFUS,
			    no_master,
			    no_master, "Dofus",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_FIESTA,
			    no_master,
			    no_master, "Fiesta",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FLORENSIA,
			    no_master,
			    no_master, "Florensia",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GUILDWARS,
			    no_master,
			    no_master, "Guildwars",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC,
			    no_master,
			    no_master, "HTTP_Application_ActiveSync",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KERBEROS,
			    no_master,
			    no_master, "Kerberos",
			    ndpi_build_default_ports(ports_a, 88, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 88, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LDAP,
			    no_master,
			    no_master, "LDAP",
			    ndpi_build_default_ports(ports_a, 389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 389, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MAPLESTORY,
			    no_master,
			    no_master, "MapleStory",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSSQL,
			    no_master,
			    no_master, "MsSQL",
			    ndpi_build_default_ports(ports_a, 1433, 1434, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PPTP,
			    no_master,
			    no_master, "PPTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WARCRAFT3,
			    no_master,
			    no_master, "Warcraft3",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
			    no_master,
			    no_master, "WorldOfKungFu",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEEBO,
			    no_master,
			    no_master, "Meebo", /* Remove */
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DROPBOX,
			    no_master,
			    no_master, "DropBox",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 17500, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE,
			    no_master,
			    no_master, "Skype",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DCERPC,
			    no_master,
			    no_master, "DCE_RPC",
			    ndpi_build_default_ports(ports_a, 135, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETFLOW,
			    no_master,
			    no_master, "NetFlow",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2055, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SFLOW,
			    no_master,
			    no_master, "sFlow",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6343, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_CONNECT,
			    no_master,
			    no_master, "HTTP_Connect",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_PROXY,
			    no_master,
			    no_master, "HTTP_Proxy",
			    ndpi_build_default_ports(ports_a, 8080, 3128, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX,
			    no_master,
			    no_master, "Citrix",
			    ndpi_build_default_ports(ports_a, 1494, 2598, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_PREPAID,
			    no_master,
			    no_master, "SkyFile_PrePaid",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_RUDICS,
			    no_master,
			    no_master, "SkyFile_Rudics",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_POSTPAID,
			    no_master,
			    no_master, "SkyFile_PostPaid",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX_ONLINE,
			    no_master,
			    no_master, "Citrix_Online",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBEX,
			    no_master,
			    no_master, "Webex",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RADIUS,
			    no_master,
			    no_master, "Radius",
			    ndpi_build_default_ports(ports_a, 1812, 1813, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1812, 1813, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WINDOWS_UPDATE,
			    no_master,
			    no_master, "WindowsUpdate",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMVIEWER,
			    no_master,
			    no_master, "TeamViewer",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LOTUS_NOTES,
			    no_master,
			    no_master, "LotusNotes",
			    ndpi_build_default_ports(ports_a, 1352, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SAP,
			    no_master,
			    no_master, "SAP",
			    ndpi_build_default_ports(ports_a, 3201, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP,
			    no_master,
			    no_master, "GTP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2152, 2123, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UPNP,
			    no_master,
			    no_master, "UPnP",
			    ndpi_build_default_ports(ports_a, 1780, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1900, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TELEGRAM,
			    no_master,
			    no_master, "Telegram",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_HTTP, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    custom_master1[0] = NDPI_PROTOCOL_DNS, custom_master1[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE,
			    NDPI_SERVICE_GOOGLE,
			    custom_master, custom_master1,
			    "Google",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_HTTP, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    custom_master1[0] = NDPI_PROTOCOL_DNS, custom_master1[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE,
			    NDPI_SERVICE_APPLE,
			    custom_master, custom_master1,
			    "Apple",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_HTTP, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    custom_master1[0] = NDPI_PROTOCOL_DNS, custom_master1[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE,
			    NDPI_SERVICE_APPLE_ICLOUD,
			    custom_master, custom_master1,
			    "AppleiCloud",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_HTTP, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    custom_master1[0] = NDPI_PROTOCOL_DNS, custom_master1[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN,
			    NDPI_SERVICE_APPLE_ITUNES,
			    custom_master, custom_master1,
			    "AppleiTunes",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    /* http://en.wikipedia.org/wiki/Link-local_Multicast_Name_Resolution */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LLMNR,
			    no_master,
			    no_master, "LLMNR",
			    ndpi_build_default_ports(ports_a, 5355, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5355, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_REMOTE_SCAN,
			    no_master,
			    no_master, "RemoteScan",
			    ndpi_build_default_ports(ports_a, 6077, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6078, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */

    custom_master[0] = NDPI_PROTOCOL_HTTP, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SPOTIFY,
			    custom_master, no_master, "Spotify",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 57621, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_WEBM,
			    no_master,
			    no_master, "WebM", /* Courtesy of Shreeram Ramamoorthy Swaminathan <shreeram <shreeram1985@yahoo.co.in> */
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_H323,
			    no_master,
			    no_master,
			    "H323",
			    ndpi_build_default_ports(ports_a, 1719, 1720, 3478, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1719, 1720, 3478, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OPENVPN,
			    no_master,
			    no_master, "OpenVPN",
			    ndpi_build_default_ports(ports_a, 1194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NOE,
			    no_master,
			    no_master, "NOE",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_CISCOVPN,
			    no_master,
			    no_master, "CiscoVPN",
			    ndpi_build_default_ports(ports_a, 10000, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 10000, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMSPEAK,
			    no_master,
			    no_master, "TeamSpeak",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_TOR,
			    no_master,
			    no_master, "TOR",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKINNY,
			    no_master,
			    no_master, "CiscoSkinny",
			    ndpi_build_default_ports(ports_a, 2000, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTCP,
			    no_master,
			    no_master, "RTCP",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RSYNC,
			    no_master,
			    no_master, "RSYNC",
			    ndpi_build_default_ports(ports_a, 873, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ORACLE,
			    no_master,
			    no_master, "Oracle",
			    ndpi_build_default_ports(ports_a, 1521, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CORBA,
			    no_master,
			    no_master, "Corba",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UBUNTUONE,
			    no_master,
			    no_master, "UbuntuONE",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHOIS_DAS,
			    no_master,
			    no_master, "Whois-DAS",
			    ndpi_build_default_ports(ports_a, 43, 4343, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_COLLECTD,
			    no_master,
			    no_master, "Collectd",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 25826, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS5,
			    no_master,
			    no_master, "SOCKS5",
			    ndpi_build_default_ports(ports_a, 1080, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1080, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS4,
			    no_master,
			    no_master, "SOCKS4",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTMP,
			    no_master,
			    no_master, "RTMP",
			    ndpi_build_default_ports(ports_a, 1935, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PANDO,
			    no_master,
			    no_master, "Pando_Media_Booster",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VIBER,
			    no_master,
			    no_master, "Viber",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEGACO,
			    no_master,
			    no_master, "Megaco",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2944 , 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_REDIS,
			    no_master,
			    no_master, "Redis",
			    ndpi_build_default_ports(ports_a, 6379, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZMQ,
			    no_master,
			    no_master, "ZeroMQ",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_SERVICE_TWITTER,
			    no_master,
			    no_master, "Twitter",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VHUA,
			    no_master,
			    no_master, "VHUA",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 58267, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_SERVICE_FACEBOOK,
			    no_master,
			    no_master, "Facebook",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_SERVICE_PANDORA,
			    no_master,
			    no_master, "Pandora",
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    init_string_based_protocols(ndpi_mod);

    for(i=0; i<(int)ndpi_mod->ndpi_num_supported_protocols; i++) {
      if(ndpi_mod->proto_defaults[i].protoName == NULL) {
	printf("[NDPI] %s(missing protoId=%d) INTERNAL ERROR: not all protocols have been initialized\n", __FUNCTION__, i);
      }
    }
}

/* ****************************************************** */

static int ac_match_handler(AC_MATCH_t *m, void *param) {
  int *matching_protocol_id = (int*)param;

  /* Stopping to the first match. We might consider searching
   * for the more specific match, paying more cpu cycles. */
  *matching_protocol_id = m->patterns[0].rep.number;

  return 1; /* 0 to continue searching, !0 to stop */
}

/* ******************************************************************** */

#ifdef NDPI_PROTOCOL_TOR

static int fill_prefix_v4(prefix_t *p, struct in_addr *a, int b, int mb) {
  do {
    if(b < 0 || b > mb)
      return(-1);

    memset(p, 0, sizeof(prefix_t));
    memcpy(&p->add.sin, a, (mb+7)/8);
    p->family = AF_INET;
    p->bitlen = b;
    p->ref_count = 0;
  } while (0);

  return(0);
}

/* ******************************************* */

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  prefix_t prefix;
  patricia_node_t *node;

  pin->s_addr = ntohl(pin->s_addr); /* Make sure all in network byte order otherwise compares wont work */
  fill_prefix_v4(&prefix, pin, 32, ((patricia_tree_t*)ndpi_struct->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_struct->protocols_ptree, &prefix);

  return(node ? node->value.user_value : NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************* */

u_int16_t ndpi_host_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t host) {
  struct in_addr pin;

  pin.s_addr = host;

  return(ndpi_network_ptree_match(ndpi_struct, &pin));
}

/* ******************************************* */

static u_int8_t tor_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_struct, pin) == NDPI_PROTOCOL_TOR) ? 1 : 0);
}

/* ******************************************* */

u_int8_t ndpi_is_tor_flow(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->tcp != NULL) {
    if(flow->packet.iph) {
      if(tor_ptree_match(ndpi_struct, (struct in_addr *)&packet->iph->saddr)
         || tor_ptree_match(ndpi_struct, (struct in_addr *)&packet->iph->daddr)) {
	return(1);
      }
    }
  }

  return(0);
}

/* ******************************************* */

static patricia_node_t* add_to_ptree(patricia_tree_t *tree, int family,
				     void *addr, int bits) {
  prefix_t prefix;
  patricia_node_t *node;

  fill_prefix_v4(&prefix, (struct in_addr*)addr, bits, tree->maxbits);

  node = ndpi_patricia_lookup(tree, &prefix);

  return(node);
}
/* ******************************************* */

static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str,
				 void *ptree, ndpi_network host_list[]) {
  int i;

  for(i=0; host_list[i].network != 0x0; i++) {
    struct in_addr pin;
    patricia_node_t *node;

    pin.s_addr = ntohl(host_list[i].network);
    if((node = add_to_ptree(ptree, AF_INET, &pin, host_list[i].cidr /* bits */)) != NULL)
      node->value.user_value = host_list[i].value;
  }
}
#endif

/* ******************************************************************** */

struct ndpi_detection_module_struct *ndpi_init_detection_module(u_int32_t ticks_per_second,
								void* (*__ndpi_malloc)(unsigned long size),
								void  (*__ndpi_free)(void *ptr),
								ndpi_debug_function_ptr ndpi_debug_printf)
{
  struct ndpi_detection_module_struct *ndpi_str;

  _ndpi_malloc = __ndpi_malloc;
  _ndpi_free = __ndpi_free;

  ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));

  if(ndpi_str == NULL) {
    ndpi_debug_printf(0, NULL, NDPI_LOG_DEBUG, "ndpi_init_detection_module initial malloc failed\n");
    return NULL;
  }
  memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

  if((ndpi_str->protocols_ptree = ndpi_New_Patricia(32 /* IPv4 */)) != NULL)
    ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, host_protocol_list);

  NDPI_BITMASK_RESET(ndpi_str->detection_bitmask);
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_str->ndpi_debug_printf = ndpi_debug_printf;
  ndpi_str->user_data = NULL;
#endif

  ndpi_str->match_dns_host_names = 1; /*
					Set it to 0 to increase library speed avoid
					matching host names
				      */
  ndpi_str->ticks_per_second = ticks_per_second;
  ndpi_str->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
  ndpi_str->directconnect_connection_ip_tick_timeout =
    NDPI_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT * ticks_per_second;

  ndpi_str->rtsp_connection_timeout = NDPI_RTSP_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_str->tvants_connection_timeout = NDPI_TVANTS_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_str->irc_timeout = NDPI_IRC_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_str->gnutella_timeout = NDPI_GNUTELLA_CONNECTION_TIMEOUT * ticks_per_second;

  ndpi_str->battlefield_timeout = NDPI_BATTLEFIELD_CONNECTION_TIMEOUT * ticks_per_second;

  ndpi_str->thunder_timeout = NDPI_THUNDER_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_str->yahoo_detect_http_connections = NDPI_YAHOO_DETECT_HTTP_CONNECTIONS;

  ndpi_str->yahoo_lan_video_timeout = NDPI_YAHOO_LAN_VIDEO_TIMEOUT * ticks_per_second;
  ndpi_str->zattoo_connection_timeout = NDPI_ZATTOO_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_str->jabber_stun_timeout = NDPI_JABBER_STUN_TIMEOUT * ticks_per_second;
  ndpi_str->jabber_file_transfer_timeout = NDPI_JABBER_FT_TIMEOUT * ticks_per_second;
  ndpi_str->soulseek_connection_ip_tick_timeout = NDPI_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT * ticks_per_second;

  ndpi_str->ndpi_num_supported_protocols = NDPI_MAX_SUPPORTED_PROTOCOLS;
  ndpi_str->ndpi_num_custom_protocols = 0;

  ndpi_str->host_automa.ac_automa = ac_automata_init(ac_match_handler);
  ndpi_str->content_automa.ac_automa = ac_automata_init(ac_match_handler);
  ndpi_str->bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);
  ndpi_str->impossible_bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);

  ndpi_init_protocol_defaults(ndpi_str);
  return ndpi_str;
}

/* *********************************************** */

static void free_ptree_data(void *data) { ; }

/* ****************************************************** */

void ndpi_exit_detection_module(struct ndpi_detection_module_struct
				*ndpi_struct, void (*ndpi_free) (void *ptr)) {
  if(ndpi_struct != NULL) {
    int i;

    for(i=0; i<(int)ndpi_struct->ndpi_num_supported_protocols; i++) {
      if(ndpi_struct->proto_defaults[i].protoName)
	ndpi_free(ndpi_struct->proto_defaults[i].protoName);
    }

    if(ndpi_struct->protocols_ptree)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_struct->protocols_ptree, free_ptree_data);

    ndpi_tdestroy(ndpi_struct->udpRoot, ndpi_free);
    ndpi_tdestroy(ndpi_struct->tcpRoot, ndpi_free);

    if(ndpi_struct->host_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_struct->host_automa.ac_automa);

    if(ndpi_struct->content_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_struct->content_automa.ac_automa);

    if(ndpi_struct->bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_struct->bigrams_automa.ac_automa);

    if(ndpi_struct->impossible_bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_struct->impossible_bigrams_automa.ac_automa);

    ndpi_free(ndpi_struct);
  }
}

/* ****************************************************** */

int ndpi_get_protocol_id_master_proto(struct ndpi_detection_module_struct *ndpi_struct,
				      u_int16_t protocol_id,
				      u_int16_t** tcp_master_proto,
				      u_int16_t** udp_master_proto) {
  if(protocol_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)) {
    *tcp_master_proto = *udp_master_proto = NDPI_PROTOCOL_UNKNOWN;
    return(-1);
  }

  *tcp_master_proto = ndpi_struct->proto_defaults[protocol_id].master_tcp_protoId,
    *udp_master_proto = ndpi_struct->proto_defaults[protocol_id].master_udp_protoId;

  return(0);
}

/* ****************************************************** */

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
				 u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  const void *ret;
  ndpi_default_ports_tree_node_t node;

  if(sport && dport) {
    node.default_port = sport;
    ret = ndpi_tfind(&node,
		     (proto == IPPROTO_TCP) ? (void*)&ndpi_struct->tcpRoot : (void*)&ndpi_struct->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = dport;
      ret = ndpi_tfind(&node,
		       (proto == IPPROTO_TCP) ? (void*)&ndpi_struct->tcpRoot : (void*)&ndpi_struct->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret != NULL) {
      ndpi_default_ports_tree_node_t *found = *(ndpi_default_ports_tree_node_t**)ret;

      return(found->proto->protoId);
    }
  } else {
    /* No TCP/UDP */

    switch(proto) {
    case NDPI_IPSEC_PROTOCOL_ESP:
    case NDPI_IPSEC_PROTOCOL_AH:
      return(NDPI_PROTOCOL_IP_IPSEC);
      break;
    case NDPI_GRE_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_GRE);
      break;
    case NDPI_ICMP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_ICMP);
      break;
    case NDPI_IGMP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IGMP);
      break;
    case NDPI_EGP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_EGP);
      break;
    case NDPI_SCTP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_SCTP);
      break;
    case NDPI_OSPF_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_OSPF);
      break;
    case NDPI_IPIP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IP_IN_IP);
      break;
    case NDPI_ICMPV6_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_ICMPV6);
      break;
    case 112:
      return(NDPI_PROTOCOL_IP_VRRP);
      break;
    }
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************************************** */

#if 0
#ifndef __KERNEL__
static int add_proto_default_port(u_int16_t **ports, u_int16_t new_port,
				  ndpi_proto_defaults_t *def,
				  ndpi_default_ports_tree_node_t *root) {
  u_int num_ports, i;

  if(*ports == NULL) {
    ndpi_port_range range = { new_port, new_port };

    addDefaultPort(&range, def, &root);
    return(0);
  }

  for(num_ports=0; (*ports)[num_ports] != 0; num_ports++)
    ;

  if(num_ports >= MAX_DEFAULT_PORTS) {
    printf("Too many ports defined: ignored port %d\n", new_port);
    return(-1);
  } else {
    u_int16_t *new_ports = (u_int16_t*)ndpi_malloc(num_ports+1);
    ndpi_port_range range;

    if(new_ports == NULL) {
      printf("Not enough memory\n");
      return(-2);
    }

    for(i=0; i<num_ports; i++)
      new_ports[i] = (*ports)[i];

    new_ports[i++] = new_port;
    new_ports[i++] = 0;

    ndpi_free(*ports);
    *ports = new_ports;

    range.port_low = range.port_high = new_port;
    addDefaultPort(&range, def, &root);
    return(0);
  }
}
#endif
#endif

/* ******************************************************************** */

u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_mod) {
  return(ndpi_mod->ndpi_num_supported_protocols);
}

/* ******************************************************************** */

int ndpi_handle_rule(struct ndpi_detection_module_struct *ndpi_mod, char* rule, u_int8_t do_add) {
  char *at, *proto, *elem;
  ndpi_proto_defaults_t *def;
  int subprotocol_id, i;

  at = strrchr(rule, '@');
  if(at == NULL) {
    printf("Invalid rule '%s'\n", rule);
    return(-1);
  } else
    at[0] = 0, proto = &at[1];

  for(i=0, def = NULL; i<(int)ndpi_mod->ndpi_num_supported_protocols; i++) {
    if(strcasecmp(ndpi_mod->proto_defaults[i].protoName, proto) == 0) {
      def = &ndpi_mod->proto_defaults[i];
      subprotocol_id = i;
      break;
    }
  }

  if(def == NULL) {
    if(!do_add) {
      /* We need to remove a rule */
      printf("Unable to find protocol '%s': skipping rule '%s'\n", proto, rule);
      return(-3);
    } else {
      ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
      u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO };

      if(ndpi_mod->ndpi_num_custom_protocols >= (NDPI_MAX_NUM_CUSTOM_PROTOCOLS-1)) {
	printf("Too many protocols defined (%u): skipping protocol %s\n",
	       ndpi_mod->ndpi_num_custom_protocols, proto);
	return(-2);
      }

      ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE,
			      ndpi_mod->ndpi_num_supported_protocols,
			      no_master,
			      no_master,
			      ndpi_strdup(proto),
			      ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			      ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
      def = &ndpi_mod->proto_defaults[ndpi_mod->ndpi_num_supported_protocols];
      subprotocol_id = ndpi_mod->ndpi_num_supported_protocols;
      ndpi_mod->ndpi_num_supported_protocols++, ndpi_mod->ndpi_num_custom_protocols++;
    }
  }

  while((elem = strsep(&rule, ",")) != NULL) {
    char *attr = elem, *value = NULL;
    ndpi_port_range range;
    int is_tcp = 0, is_udp = 0;

    if(strncmp(attr, "tcp:", 4) == 0)
      is_tcp = 1, value = &attr[4];
    else if(strncmp(attr, "udp:", 4) == 0)
      is_udp = 1, value = &attr[4];
    else if(strncmp(attr, "host:", 5) == 0) {
      /* host:"<value>",host:"<value>",.....@<subproto> */
      value = &attr[5];
      if(value[0] == '"') value++; /* remove leading " */
      if(value[strlen(value)-1] == '"') value[strlen(value)-1] = '\0'; /* remove trailing " */
    }

    if(is_tcp || is_udp) {
      if(sscanf(value, "%u-%u", (unsigned int *)&range.port_low, (unsigned int *)&range.port_high) != 2)
	range.port_low = range.port_high = atoi(&elem[4]);
      if(do_add)
	addDefaultPort(&range, def, is_tcp ? &ndpi_mod->tcpRoot : &ndpi_mod->udpRoot);
      else
	removeDefaultPort(&range, def, is_tcp ? &ndpi_mod->tcpRoot : &ndpi_mod->udpRoot);
    } else {
      if(do_add)
	ndpi_add_host_url_subprotocol(ndpi_mod, value, subprotocol_id, NDPI_PROTOCOL_ACCEPTABLE);
      else
	ndpi_remove_host_url_subprotocol(ndpi_mod, value, subprotocol_id);
    }
  }

  return(0);
}

/* ******************************************************************** */

/*
  Format:
  <tcp|udp>:<port>,<tcp|udp>:<port>,.....@<proto>

  Example:
  tcp:80,tcp:3128@HTTP
  udp:139@NETBIOS

*/
int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_mod, char* path) {
#ifdef __KERNEL__
  return(0);
#else
  FILE *fd = fopen(path, "r");
  int i;

  if(fd == NULL) {
    printf("Unable to open file %s [%s]", path, strerror(errno));
    return(-1);
  }

  while(fd) {
    char buffer[512], *line;

    if(!(line = fgets(buffer, sizeof(buffer), fd)))
      break;

    if(((i = strlen(line)) <= 1) || (line[0] == '#'))
      continue;
    else
      line[i-1] = '\0';

    ndpi_handle_rule(ndpi_mod, line, 1);
  }

  fclose(fd);

#if 0
  printf("\nTCP:\n");
  ndpi_twalk(ndpi_mod->tcpRoot, ndpi_default_ports_tree_node_t_walker, NULL);
  printf("\nUDP:\n");
  ndpi_twalk(ndpi_mod->udpRoot, ndpi_default_ports_tree_node_t_walker, NULL);
#endif
#endif

  return(0);
}

/* ntop */
void ndpi_set_bitmask_protocol_detection( char * label,
					  struct ndpi_detection_module_struct *ndpi_struct,
					  const NDPI_PROTOCOL_BITMASK * detection_bitmask,
					  const u_int32_t idx,
					  u_int16_t ndpi_protocol_id,
					  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow),
					  const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
					  u_int8_t b_save_bitmask_unknow,
					  u_int8_t b_add_detection_bitmask)
{
  /*
    Compare specify protocol bitmask with main detection bitmask
  */
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(*detection_bitmask, ndpi_protocol_id) != 0) {
    // #ifdef DEBUG
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,"[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] protocol_id=%u\n", label, idx, ndpi_protocol_id);
    // #endif
    /*
      Set funcition and index protocol within proto_default strcuture for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
    ndpi_struct->proto_defaults[ndpi_protocol_id].protoIdx = idx;

    ndpi_struct->proto_defaults[ndpi_protocol_id].func =
      ndpi_struct->callback_buffer[idx].func = func;
    /*
      Set ndpi_selection_bitmask for protocol
    */
    ndpi_struct->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

    /*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
    if (b_save_bitmask_unknow) NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
    if (b_add_detection_bitmask) NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_struct->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

    NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[idx].excluded_protocol_bitmask, ndpi_protocol_id);
  }
}

/* ******************************************************************** */

void ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_struct,
					  const NDPI_PROTOCOL_BITMASK * dbm)
{
  NDPI_PROTOCOL_BITMASK detection_bitmask_local;
  NDPI_PROTOCOL_BITMASK *detection_bitmask = &detection_bitmask_local;
  u_int32_t a = 0;

  NDPI_BITMASK_SET(detection_bitmask_local, *dbm);
  NDPI_BITMASK_SET(ndpi_struct->detection_bitmask, *dbm);

  /* set this here to zero to be interrupt safe */
  ndpi_struct->callback_buffer_size = 0;


#ifdef NDPI_PROTOCOL_HTTP
  ndpi_set_bitmask_protocol_detection("HTTP",ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_HTTP,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("HTTP_PROXY", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_HTTP_PROXY,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

#ifdef NDPI_CONTENT_MPEG
  ndpi_set_bitmask_protocol_detection("MPEG", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_MPEG,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_FLASH
  ndpi_set_bitmask_protocol_detection("FLASH", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_FLASH,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_QUICKTIME
  ndpi_set_bitmask_protocol_detection("QUICKTIME", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_QUICKTIME,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_REALMEDIA
  ndpi_set_bitmask_protocol_detection("REALMEDIA", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_REALMEDIA,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_WINDOWSMEDIA
  ndpi_set_bitmask_protocol_detection("WINDOWSMEDIA", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_WINDOWSMEDIA,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_MMS
  ndpi_set_bitmask_protocol_detection("MMS", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_MMS,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_XBOX
  ndpi_set_bitmask_protocol_detection("XBOX", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_XBOX,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_WINDOWS_UPDATE
  ndpi_set_bitmask_protocol_detection("WINDOWS_UPDATE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_WINDOWS_UPDATE,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_QQ
  ndpi_set_bitmask_protocol_detection("QQ", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_QQ,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_AVI
  ndpi_set_bitmask_protocol_detection("AVI", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_AVI,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_OGG
  ndpi_set_bitmask_protocol_detection("OGG", ndpi_struct, detection_bitmask, a++,
				      NDPI_CONTENT_OGG,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MOVE
  ndpi_set_bitmask_protocol_detection("MOVE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MOVE,
				      ndpi_search_http_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
  /*Update excluded protocol bitmask*/
  NDPI_BITMASK_SET(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
		   ndpi_struct->callback_buffer[a].detection_bitmask);

  /*Delete protocol from exluded protocol bitmask*/
  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
				 NDPI_PROTOCOL_UNKNOWN);

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
				 NDPI_PROTOCOL_QQ);

#ifdef NDPI_CONTENT_FLASH
  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
				 NDPI_CONTENT_FLASH);
#endif

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
				 NDPI_CONTENT_MMS);
  // #ifdef NDPI_PROTOCOL_RTSP
  //   NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
  // 				 NDPI_PROTOCOL_RTSP);
  // #endif
  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask,
				 NDPI_PROTOCOL_XBOX);

  NDPI_BITMASK_SET(ndpi_struct->generic_http_packet_bitmask,
		   ndpi_struct->callback_buffer[a].detection_bitmask);

  NDPI_DEL_PROTOCOL_FROM_BITMASK(ndpi_struct->generic_http_packet_bitmask, NDPI_PROTOCOL_UNKNOWN);

  /* Update callback_buffer index */
  a++;
#endif


#ifdef NDPI_PROTOCOL_SSL
  ndpi_set_bitmask_protocol_detection("SSL", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_SSL,
				      ndpi_search_ssl_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif


#ifdef NDPI_PROTOCOL_STUN
  ndpi_set_bitmask_protocol_detection("STUN", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_STUN,
				      ndpi_search_stun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RTP
  ndpi_set_bitmask_protocol_detection("RTP", ndpi_struct, detection_bitmask,a,
				      NDPI_PROTOCOL_RTP,
				      ndpi_search_rtp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  /* consider also real protocol for detection select in main loop */
  ndpi_struct->callback_buffer[a].detection_feature = NDPI_SELECT_DETECTION_WITH_REAL_PROTOCOL;
  /* Update callback_buffer index */
  a++;
#endif

#ifdef NDPI_PROTOCOL_RTSP
  ndpi_set_bitmask_protocol_detection("RTSP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RTSP,
				      ndpi_search_rtsp_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RDP
  ndpi_set_bitmask_protocol_detection("RDP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RDP,
				      ndpi_search_rdp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SIP
  ndpi_set_bitmask_protocol_detection("SIP", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_SIP,
				      ndpi_search_sip,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,/* Fix courtesy of Miguel Quesada <mquesadab@gmail.com> */
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_BITTORRENT
  ndpi_set_bitmask_protocol_detection("BITTORRENT", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_BITTORRENT,
				      ndpi_search_bittorrent,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_EDONKEY
  ndpi_set_bitmask_protocol_detection("EDONKEY", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_EDONKEY,
				      ndpi_search_edonkey,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_FASTTRACK
  ndpi_set_bitmask_protocol_detection("FASTTRACK", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_FASTTRACK,
				      ndpi_search_fasttrack_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  ndpi_set_bitmask_protocol_detection("GNUTELLA", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_GNUTELLA,
				      ndpi_search_gnutella,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_WINMX
  ndpi_set_bitmask_protocol_detection("WINMX", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_WINMX,
				      ndpi_search_winmx_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DIRECTCONNECT
  ndpi_set_bitmask_protocol_detection("DIRECTCONNECT", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_DIRECTCONNECT,
				      ndpi_search_directconnect,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MSN

  NDPI_BITMASK_RESET(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask);

  ndpi_set_bitmask_protocol_detection("MSN", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_MSN,
				      ndpi_search_msn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_YAHOO
  ndpi_set_bitmask_protocol_detection("YAHOO", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_YAHOO,
				      ndpi_search_yahoo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_OSCAR
  ndpi_set_bitmask_protocol_detection("OSCAR", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_OSCAR,
				      ndpi_search_oscar,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_APPLEJUICE
  ndpi_set_bitmask_protocol_detection("APPLEJUICE", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_APPLEJUICE,
				      ndpi_search_applejuice_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SOULSEEK
  ndpi_set_bitmask_protocol_detection("SOULSEEK", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_SOULSEEK,
				      ndpi_search_soulseek_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_IRC
  ndpi_set_bitmask_protocol_detection("IRC", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_IRC,
				      ndpi_search_irc_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
  ndpi_set_bitmask_protocol_detection("UNENCRYPED_JABBER", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_UNENCRYPED_JABBER,
				      ndpi_search_jabber_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MAIL_POP
  ndpi_set_bitmask_protocol_detection("MAIL_POP", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_MAIL_POP,
				      ndpi_search_mail_pop_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MAIL_IMAP
  ndpi_set_bitmask_protocol_detection("MAIL_IMAP", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_MAIL_IMAP,
				      ndpi_search_mail_imap_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MAIL_SMTP
  ndpi_set_bitmask_protocol_detection("MAIL_SMTP", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_MAIL_SMTP,
				      ndpi_search_mail_smtp_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_USENET
  ndpi_set_bitmask_protocol_detection("USENET", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_USENET,
				      ndpi_search_usenet_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DNS
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_FILETOPIA
  ndpi_set_bitmask_protocol_detection("FILETOPIA", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_FILETOPIA,
				      ndpi_search_filetopia_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_VMWARE
  ndpi_set_bitmask_protocol_detection("VMWARE", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_VMWARE,
				      ndpi_search_vmware,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_IMESH
  ndpi_set_bitmask_protocol_detection("IMESH", ndpi_struct, detection_bitmask,a++,
				      NDPI_PROTOCOL_IMESH,
				      ndpi_search_imesh_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_CONTENT_MMS
  ndpi_set_bitmask_protocol_detection("NDPI_CONTENT_MMS", ndpi_struct, detection_bitmask,a++,
				      NDPI_CONTENT_MMS,
				      ndpi_search_mms_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#if defined(NDPI_PROTOCOL_IP_IPSEC) || defined(NDPI_PROTOCOL_IP_GRE) || defined(NDPI_PROTOCOL_IP_ICMP) || defined(NDPI_PROTOCOL_IP_IGMP) || defined(NDPI_PROTOCOL_IP_EGP) || defined(NDPI_PROTOCOL_IP_SCTP) || defined(NDPI_PROTOCOL_IP_OSPF) || defined(NDPI_PROTOCOL_IP_IP_IN_IP) || defined(NDPI_PROTOCOL_IP_ICMPV6)

  /* always add non tcp/udp if one protocol is compiled in */
  NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[a].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);

  ndpi_set_bitmask_protocol_detection("IP_IPSEC", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_IPSEC,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_GRE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_GRE,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_ICMP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_ICMP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_IGMP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_IGMP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_EGP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_EGP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_SCTP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_SCTP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_OSPF", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_OSPF,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_IP_IN_IP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_IP_IN_IP,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  ndpi_set_bitmask_protocol_detection("IP_ICMPV6", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IP_ICMPV6,
				      ndpi_search_in_non_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6,
				      NO_SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  // NDPI_BITMASK_RESET(ndpi_struct->callback_buffer[a].excluded_protocol_bitmask);
#endif


#ifdef NDPI_PROTOCOL_TVANTS
  ndpi_set_bitmask_protocol_detection("TVANTS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TVANTS,
				      ndpi_search_tvants_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SOPCAST
  ndpi_set_bitmask_protocol_detection("SOPCAST", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SOPCAST,
				      ndpi_search_sopcast,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_TVUPLAYER
  ndpi_set_bitmask_protocol_detection("TVUPLAYER", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TVUPLAYER,
				      ndpi_search_tvuplayer,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_PPSTREAM
  ndpi_set_bitmask_protocol_detection("PPSTREAM", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_PPSTREAM,
				      ndpi_search_ppstream,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  ndpi_set_bitmask_protocol_detection("PPLIVE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_PPLIVE,
				      ndpi_search_pplive,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_IAX
  ndpi_set_bitmask_protocol_detection("IAX", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IAX,
				      ndpi_search_iax,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MGCP
  ndpi_set_bitmask_protocol_detection("MGCP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MGCP,
				      ndpi_search_mgcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_ZATTOO
  ndpi_set_bitmask_protocol_detection("ZATTOO", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_ZATTOO,
				      ndpi_search_zattoo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_QQ
  ndpi_set_bitmask_protocol_detection("QQ", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_QQ,
				      ndpi_search_qq,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_SSH
  ndpi_set_bitmask_protocol_detection("SSH", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SSH,
				      ndpi_search_ssh_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_AYIYA
  ndpi_set_bitmask_protocol_detection("AYIYA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_AYIYA,
				      ndpi_search_ayiya,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_THUNDER
  ndpi_set_bitmask_protocol_detection("THUNDER", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_THUNDER,
				      ndpi_search_thunder,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_VNC
  ndpi_set_bitmask_protocol_detection("VNC", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_VNC,
				      ndpi_search_vnc_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TEAMVIEWER
  ndpi_set_bitmask_protocol_detection("TEAMVIEWER", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TEAMVIEWER,
				      ndpi_search_teamview,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DHCP
  ndpi_set_bitmask_protocol_detection("DHCP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DHCP,
				      ndpi_search_dhcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_SOCRATES
  ndpi_set_bitmask_protocol_detection("SOCRATES", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SOCRATES,
				      ndpi_search_socrates,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_STEAM
  ndpi_set_bitmask_protocol_detection("STEAM", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_STEAM,
				      ndpi_search_steam,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_HALFLIFE2
  ndpi_set_bitmask_protocol_detection("HALFLIFE2", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_HALFLIFE2,
				      ndpi_search_halflife2,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_XBOX
  ndpi_set_bitmask_protocol_detection("XBOX", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_XBOX,
				      ndpi_search_xbox,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC
  ndpi_set_bitmask_protocol_detection("HTTP_APPLICATION_ACTIVESYNC", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC,
				      ndpi_search_activesync,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_SMB
  ndpi_set_bitmask_protocol_detection("SMB", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SMB,
				      ndpi_search_smb_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TELNET
  ndpi_set_bitmask_protocol_detection("TELNET", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TELNET,
				      ndpi_search_telnet_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_NTP
  ndpi_set_bitmask_protocol_detection("NTP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_NTP,
				      ndpi_search_ntp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_NFS
  ndpi_set_bitmask_protocol_detection("NFS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_NFS,
				      ndpi_search_nfs,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SSDP
  ndpi_set_bitmask_protocol_detection("SSDP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SSDP,
				      ndpi_search_ssdp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_WORLDOFWARCRAFT
  ndpi_set_bitmask_protocol_detection("WORLDOFWARCRAFT", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_WORLDOFWARCRAFT,
				      ndpi_search_worldofwarcraft,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_POSTGRES
  ndpi_set_bitmask_protocol_detection("POSTGRES", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_POSTGRES,
				      ndpi_search_postgres_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MYSQL
  ndpi_set_bitmask_protocol_detection("MYSQL", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MYSQL,
				      ndpi_search_mysql_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_BGP
  ndpi_set_bitmask_protocol_detection("BGP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_BGP,
				      ndpi_search_bgp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_QUAKE
  ndpi_set_bitmask_protocol_detection("QUAKE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_QUAKE,
				      ndpi_search_quake,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_BATTLEFIELD
  ndpi_set_bitmask_protocol_detection("BATTLEFIELD", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_BATTLEFIELD,
				      ndpi_search_battlefield,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_PCANYWHERE
  ndpi_set_bitmask_protocol_detection("PCANYWHERE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_PCANYWHERE,
				      ndpi_search_pcanywhere,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_SNMP
  ndpi_set_bitmask_protocol_detection("SNMP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SNMP,
				      ndpi_search_snmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_KONTIKI
  ndpi_set_bitmask_protocol_detection("KONTIKI", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_KONTIKI,
				      ndpi_search_kontiki,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_ICECAST
  ndpi_set_bitmask_protocol_detection("ICECAST", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_ICECAST,
				      ndpi_search_icecast_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SHOUTCAST
  ndpi_set_bitmask_protocol_detection("SHOUTCAST", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SHOUTCAST,
				      ndpi_search_shoutcast_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV
  ndpi_set_bitmask_protocol_detection("HTTP_APPLICATION_VEOHTV", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV,
				      ndpi_search_veohtv_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_KERBEROS
  ndpi_set_bitmask_protocol_detection("KERBEROS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_KERBEROS,
				      ndpi_search_kerberos,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_OPENFT
  ndpi_set_bitmask_protocol_detection("OPENFT", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_OPENFT,
				      ndpi_search_openft_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_SYSLOG
  ndpi_set_bitmask_protocol_detection("SYSLOG", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SYSLOG,
				      ndpi_search_syslog,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TDS
  ndpi_set_bitmask_protocol_detection("TDS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TDS,
				      ndpi_search_tds_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK
  ndpi_set_bitmask_protocol_detection("DIRECT_DOWNLOAD_LINK", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,
				      ndpi_search_direct_download_link_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_NETBIOS
  ndpi_set_bitmask_protocol_detection("NETBIOS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_NETBIOS,
				      ndpi_search_netbios,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MDNS
  ndpi_set_bitmask_protocol_detection("MDNS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MDNS,
				      ndpi_search_mdns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_IPP
  ndpi_set_bitmask_protocol_detection("IPP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_IPP,
				      ndpi_search_ipp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_LDAP
  ndpi_set_bitmask_protocol_detection("LDAP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_LDAP,
				      ndpi_search_ldap,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_WARCRAFT3
  ndpi_set_bitmask_protocol_detection("WARCRAFT3", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_WARCRAFT3,
				      ndpi_search_warcraft3,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_XDMCP
  ndpi_set_bitmask_protocol_detection("XDMCP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_XDMCP,
				      ndpi_search_xdmcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TFTP
  ndpi_set_bitmask_protocol_detection("TFTP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TFTP,
				      ndpi_search_tftp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MSSQL
  ndpi_set_bitmask_protocol_detection("MSSQL", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MSSQL,
				      ndpi_search_mssql,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_PPTP
  ndpi_set_bitmask_protocol_detection("PPTP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_PPTP,
				      ndpi_search_pptp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_STEALTHNET
  ndpi_set_bitmask_protocol_detection("STEALTHNET", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_STEALTHNET,
				      ndpi_search_stealthnet,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_DHCPV6
  ndpi_set_bitmask_protocol_detection("DHCPV6", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DHCPV6,
				      ndpi_search_dhcpv6_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MEEBO
  ndpi_set_bitmask_protocol_detection("Meebo", ndpi_struct, detection_bitmask, a,
				      NDPI_PROTOCOL_MEEBO,
				      ndpi_search_meebo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  /* Add protocol bitmask dependencies to detected bitmask*/
#ifdef NDPI_CONTENT_FLASH
  NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_struct->callback_buffer[a].detection_bitmask, NDPI_CONTENT_FLASH);
#endif
  a++;
#endif

#ifdef NDPI_PROTOCOL_AFP
  ndpi_set_bitmask_protocol_detection("AFP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_AFP,
				      ndpi_search_afp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_AIMINI
  ndpi_set_bitmask_protocol_detection("AIMINI", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_AIMINI,
				      ndpi_search_aimini,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_FLORENSIA
  ndpi_set_bitmask_protocol_detection("FLORENSIA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_FLORENSIA,
				      ndpi_search_florensia,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_MAPLESTORY
  ndpi_set_bitmask_protocol_detection("MAPLESTORY", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MAPLESTORY,
				      ndpi_search_maplestory,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_DOFUS
  ndpi_set_bitmask_protocol_detection("DOFUS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DOFUS,
				      ndpi_search_dofus,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_WORLD_OF_KUNG_FU
  ndpi_set_bitmask_protocol_detection("WORLD_OF_KUNG_FU", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
				      ndpi_search_world_of_kung_fu,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_FIESTA
  ndpi_set_bitmask_protocol_detection("FIESTA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_FIESTA,
				      ndpi_search_fiesta,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_CROSSFIRE
  ndpi_set_bitmask_protocol_detection("CROSSFIRE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_CROSSFIRE,
				      ndpi_search_crossfire_tcp_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_GUILDWARS
  ndpi_set_bitmask_protocol_detection("GUILDWARS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_GUILDWARS,
				      ndpi_search_guildwars_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif
#ifdef NDPI_PROTOCOL_ARMAGETRON
  ndpi_set_bitmask_protocol_detection("ARMAGETRON", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_ARMAGETRON,
				      ndpi_search_armagetron_udp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DROPBOX
  ndpi_set_bitmask_protocol_detection("DROPBOX", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DROPBOX,
				      ndpi_search_dropbox,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SPOTIFY
  ndpi_set_bitmask_protocol_detection("SPOTIFY", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SPOTIFY,
				      ndpi_search_spotify,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SKYPE
  ndpi_set_bitmask_protocol_detection("SKYPE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SKYPE,
				      ndpi_search_skype,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RADIUS
  ndpi_set_bitmask_protocol_detection("RADIUS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RADIUS,
				      ndpi_search_radius,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_CITRIX
  ndpi_set_bitmask_protocol_detection("CITRIX", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_CITRIX,
				      ndpi_search_citrix,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_LOTUS_NOTES
  ndpi_set_bitmask_protocol_detection("LOTUS_NOTES", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_LOTUS_NOTES,
				      ndpi_search_lotus_notes,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_GTP
  ndpi_set_bitmask_protocol_detection("GTP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_GTP,
				      ndpi_search_gtp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_DCERPC
  ndpi_set_bitmask_protocol_detection("DCERPC", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_DCERPC,
				      ndpi_search_dcerpc,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_NETFLOW
  ndpi_set_bitmask_protocol_detection("NETFLOW", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_NETFLOW,
				      ndpi_search_netflow,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SFLOW
  ndpi_set_bitmask_protocol_detection("SFLOW", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SFLOW,
				      ndpi_search_sflow,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_H323
  ndpi_set_bitmask_protocol_detection("H323", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_H323,
				      ndpi_search_h323,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_OPENVPN
  ndpi_set_bitmask_protocol_detection("OPENVPN", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_OPENVPN,
				      ndpi_search_openvpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_NOE
  ndpi_set_bitmask_protocol_detection("NOE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_NOE,
				      ndpi_search_noe,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_CISCOVPN
  ndpi_set_bitmask_protocol_detection("CISCOVPN", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_CISCOVPN,
				      ndpi_search_ciscovpn,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TEAMSPEAK
  ndpi_set_bitmask_protocol_detection("TEAMSPEAK", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TEAMSPEAK,
				      ndpi_search_teamspeak,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_VIBER
  ndpi_set_bitmask_protocol_detection("VIBER", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_VIBER,
				      ndpi_search_viber,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TOR
  ndpi_set_bitmask_protocol_detection("TOR", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TOR,
				      ndpi_search_tor,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_SKINNY
  ndpi_set_bitmask_protocol_detection("SKINNY", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_SKINNY,
				      ndpi_search_skinny,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RTCP
  ndpi_set_bitmask_protocol_detection("RTCP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RTCP,
				      ndpi_search_rtcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RSYNC
  ndpi_set_bitmask_protocol_detection("RSYNC", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RSYNC,
				      ndpi_search_rsync,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_WHOIS_DAS
  ndpi_set_bitmask_protocol_detection("WHOIS_DAS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_WHOIS_DAS,
				      ndpi_search_whois_das,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_ORACLE
  ndpi_set_bitmask_protocol_detection("ORACLE", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_ORACLE,
				      ndpi_search_oracle,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_CORBA
  ndpi_set_bitmask_protocol_detection("CORBA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_CORBA,
				      ndpi_search_corba,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_RTMP
  ndpi_set_bitmask_protocol_detection("RTMP", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_RTMP,
				      ndpi_search_rtmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_FTP_CONTROL
  ndpi_set_bitmask_protocol_detection("FTP_CONTROL", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_FTP_CONTROL,
				      ndpi_search_ftp_control,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_FTP_DATA
  ndpi_set_bitmask_protocol_detection("FTP_DATA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_FTP_DATA,
				      ndpi_search_ftp_data,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_PANDO
  ndpi_set_bitmask_protocol_detection("PANDO", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_PANDO,
				      ndpi_search_pando,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_MEGACO
  ndpi_set_bitmask_protocol_detection("MEGACO", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_MEGACO,
				      ndpi_search_megaco,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_REDIS
  ndpi_set_bitmask_protocol_detection("REDIS", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_REDIS,
				      ndpi_search_redis,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_VHUA
  ndpi_set_bitmask_protocol_detection("VHUA", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_VHUA,
				      ndpi_search_vhua,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_ZMQ
  ndpi_set_bitmask_protocol_detection("ZMQ", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_ZMQ,
				      ndpi_search_zmq, /* TODO: add UDP support */
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif


#ifdef NDPI_SERVICE_TWITTER
  ndpi_set_bitmask_protocol_detection("TWITTER", ndpi_struct, detection_bitmask, a++,
				      NDPI_SERVICE_TWITTER,
				      ndpi_search_twitter,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

#ifdef NDPI_PROTOCOL_TELEGRAM
  ndpi_set_bitmask_protocol_detection("TELEGRAM", ndpi_struct, detection_bitmask, a++,
				      NDPI_PROTOCOL_TELEGRAM,
				      ndpi_search_telegram,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
#endif

  ndpi_struct->callback_buffer_size = a;

  NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	   "callback_buffer_size is %u\n", ndpi_struct->callback_buffer_size);

  /* now build the specific buffer for tcp, udp and non_tcp_udp */
  ndpi_struct->callback_buffer_size_tcp_payload = 0;
  ndpi_struct->callback_buffer_size_tcp_no_payload = 0;
  for (a = 0; a < ndpi_struct->callback_buffer_size; a++) {
    if((ndpi_struct->callback_buffer[a].ndpi_selection_bitmask
	& (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	   NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
	   NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0) {
      NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	       "callback_buffer_tcp_payload, adding buffer %u as entry %u\n", a,
	       ndpi_struct->callback_buffer_size_tcp_payload);

      memcpy(&ndpi_struct->callback_buffer_tcp_payload[ndpi_struct->callback_buffer_size_tcp_payload],
	     &ndpi_struct->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_struct->callback_buffer_size_tcp_payload++;

      if((ndpi_struct->
	  callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
		 "\tcallback_buffer_tcp_no_payload, additional adding buffer %u to no_payload process\n", a);

	memcpy(&ndpi_struct->callback_buffer_tcp_no_payload
	       [ndpi_struct->callback_buffer_size_tcp_no_payload], &ndpi_struct->callback_buffer[a],
	       sizeof(struct ndpi_call_function_struct));
	ndpi_struct->callback_buffer_size_tcp_no_payload++;
      }
    }
  }

  ndpi_struct->callback_buffer_size_udp = 0;
  for (a = 0; a < ndpi_struct->callback_buffer_size; a++) {
    if((ndpi_struct->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC))
       != 0) {
      NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	       "callback_buffer_size_udp: adding buffer : %u as entry %u\n", a, ndpi_struct->callback_buffer_size_udp);

      memcpy(&ndpi_struct->callback_buffer_udp[ndpi_struct->callback_buffer_size_udp],
	     &ndpi_struct->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_struct->callback_buffer_size_udp++;
    }
  }

  ndpi_struct->callback_buffer_size_non_tcp_udp = 0;
  for (a = 0; a < ndpi_struct->callback_buffer_size; a++) {
    if((ndpi_struct->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP))
       == 0
       || (ndpi_struct->
	   callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC) != 0) {
      NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	       "callback_buffer_non_tcp_udp: adding buffer : %u as entry %u\n", a, ndpi_struct->callback_buffer_size_non_tcp_udp);

      memcpy(&ndpi_struct->callback_buffer_non_tcp_udp[ndpi_struct->callback_buffer_size_non_tcp_udp],
	     &ndpi_struct->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_struct->callback_buffer_size_non_tcp_udp++;
    }
  }
}

#ifdef NDPI_DETECTION_SUPPORT_IPV6
/* handle extension headers in IPv6 packets
 * arguments:
 * 	l4ptr: pointer to the byte following the initial IPv6 header
 * 	l4len: the length of the IPv6 packet excluding the IPv6 header
 * 	nxt_hdr: next header value from the IPv6 header
 * result:
 * 	l4ptr: pointer to the start of the actual packet payload
 * 	l4len: length of the actual payload
 * 	nxt_hdr: protocol of the actual payload
 * returns 0 upon success and 1 upon failure
 */
static int ndpi_handle_ipv6_extension_headers(struct ndpi_detection_module_struct *ndpi_struct,
					      const u_int8_t ** l4ptr, u_int16_t * l4len, u_int8_t * nxt_hdr)
{
  while ((*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len;

    // no next header
    if(*nxt_hdr == 59) {
      return 1;
    }
    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return 1;
      }
      *nxt_hdr = (*l4ptr)[0];
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }
    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(*l4len < ehdr_len) {
      return 1;
    }
    *nxt_hdr = (*l4ptr)[0];
    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }
  return 0;
}
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */


static u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize)
{
  //#ifdef REQUIRE_FULL_PACKETS
  if(ipsize < iph->ihl * 4 ||
     ipsize < ntohs(iph->tot_len) || ntohs(iph->tot_len) < iph->ihl * 4 || (iph->frag_off & htons(0x1FFF)) != 0) {
    return 0;
  }
  //#endif

  return 1;
}

static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_struct,
					       const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
					       u_int8_t * l4_protocol_return, u_int32_t flags)
{
  const struct ndpi_iphdr *iph = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iph_v6 = NULL;
#endif
  u_int16_t l4len = 0;
  const u_int8_t *l4ptr = NULL;
  u_int8_t l4protocol = 0;

  if(l3 == NULL || l3_len < sizeof(struct ndpi_iphdr))
    return 1;

  iph = (const struct ndpi_iphdr *) l3;

  if(iph->version == 4 && iph->ihl >= 5) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr)) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header\n");
    iph_v6 = (const struct ndpi_ipv6hdr *) iph;
    iph = NULL;
  }
#endif
  else {
    return 1;
  }

  if((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header found but excluded by flag\n");
    return 1;
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header found but excluded by flag\n");
    return 1;
  }
#endif

  if(iph != NULL && ndpi_iph_is_valid_and_not_fragmented(iph, l3_len)) {
    u_int16_t len  = ntohs(iph->tot_len);
    u_int16_t hlen = (iph->ihl * 4);

    l4ptr = (((const u_int8_t *) iph) + iph->ihl * 4);

    if(len == 0) len = l3_len;

    l4len = (len > hlen) ? (len - hlen) : 0;
    l4protocol = iph->protocol;
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->payload_len)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->payload_len);
    l4protocol = iph_v6->nexthdr;

    // we need to handle IPv6 extension headers if present
    if(ndpi_handle_ipv6_extension_headers(ndpi_struct, &l4ptr, &l4len, &l4protocol) != 0) {
      return 1;
    }

  }
#endif
  else {
    return 1;
  }

  if(l4_return != NULL) {
    *l4_return = l4ptr;
  }

  if(l4_len_return != NULL) {
    *l4_len_return = l4len;
  }

  if(l4_protocol_return != NULL) {
    *l4_protocol_return = l4protocol;
  }

  return 0;
}

#if !defined(WIN32)
#define ATTRIBUTE_ALWAYS_INLINE static inline
#else
__forceinline static
#endif
void ndpi_apply_flow_protocol_to_packet(struct ndpi_flow_struct *flow,
					struct ndpi_packet_struct *packet)
{
  memcpy(&packet->detected_protocol_stack[0],
	 &flow->detected_protocol_stack[0], sizeof(packet->detected_protocol_stack));
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  memcpy(&packet->protocol_stack_info, &flow->protocol_stack_info, sizeof(packet->protocol_stack_info));
#endif
}

static int ndpi_init_packet_header(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   unsigned short packetlen)
{
  const struct ndpi_iphdr *decaps_iph = NULL;
  u_int16_t l3len;
  u_int16_t l4len;
  const u_int8_t *l4ptr;
  u_int8_t l4protocol;
  u_int8_t l4_result;

  /* reset payload_packet_len, will be set if ipv4 tcp or udp */
  flow->packet.payload_packet_len = 0;
  flow->packet.l4_packet_len = 0;
  flow->packet.l3_packet_len = packetlen;

  flow->packet.tcp = NULL;
  flow->packet.udp = NULL;
  flow->packet.generic_l4_ptr = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  flow->packet.iphv6 = NULL;
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if(flow) {
    ndpi_apply_flow_protocol_to_packet(flow, &flow->packet);
  } else {
    ndpi_int_reset_packet_protocol(&flow->packet);
  }

  l3len = flow->packet.l3_packet_len;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iph != NULL) {
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

    decaps_iph =flow->packet.iph;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  }
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if(decaps_iph->version == 4 && decaps_iph->ihl >= 5) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
	  (ndpi_struct->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header\n");
    flow->packet.iphv6 = (struct ndpi_ipv6hdr *)flow->packet.iph;
    flow->packet.iph = NULL;
  }
#endif
  else {
    flow->packet.iph = NULL;
    return 1;
  }


  /* needed:
   *  - unfragmented packets
   *  - ip header <= packet len
   *  - ip total length >= packet len
   */


  l4ptr = NULL;
  l4len = 0;
  l4protocol = 0;

  l4_result =
    ndpi_detection_get_l4_internal(ndpi_struct, (const u_int8_t *) decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

  if(l4_result != 0) {
    return 1;
  }

  flow->packet.l4_protocol = l4protocol;
  flow->packet.l4_packet_len = l4len;

  /* tcp / udp detection */
  if(l4protocol == 6 /* TCP */  &&flow->packet.l4_packet_len >= 20 /* min size of tcp */ ) {
    /* tcp */
    flow->packet.tcp = (struct ndpi_tcphdr *) l4ptr;

    if(flow->packet.l4_packet_len >=flow->packet.tcp->doff * 4) {
      flow->packet.payload_packet_len =
	flow->packet.l4_packet_len -flow->packet.tcp->doff * 4;
      flow->packet.actual_payload_len =flow->packet.payload_packet_len;
      flow->packet.payload = ((u_int8_t *)flow->packet.tcp) + (flow->packet.tcp->doff * 4);

      /* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
      if(flow && flow->packet.tcp->syn != 0
	 && flow->packet.tcp->ack == 0
	 && flow->init_finished != 0
	 && flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {

	memset(flow, 0, sizeof(*(flow)));


	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct,
		 NDPI_LOG_DEBUG,
		 "%s:%u: tcp syn packet for unknown protocol, reset detection state\n", __FUNCTION__, __LINE__);

      }
    } else {
      /* tcp header not complete */
      flow->packet.tcp = NULL;
    }
  } else if(l4protocol == 17 /* udp */  &&flow->packet.l4_packet_len >= 8 /* size of udp */ ) {
    flow->packet.udp = (struct ndpi_udphdr *) l4ptr;
    flow->packet.payload_packet_len =flow->packet.l4_packet_len - 8;
    flow->packet.payload = ((u_int8_t *)flow->packet.udp) + 8;
  } else {
    flow->packet.generic_l4_ptr = l4ptr;
  }
  return 0;
}


#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow)
{
  /* const for gcc code optimisation and cleaner code */
  struct ndpi_packet_struct *packet = &flow->packet;
  const struct ndpi_iphdr *iph = packet->iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
#endif
  const struct ndpi_tcphdr *tcph = packet->tcp;
  const struct ndpi_udphdr *udph = flow->packet.udp;

  //struct ndpi_unique_flow_struct      unique_flow;
  //uint8_t                               new_connection;

  u_int8_t proxy_enabled = 0;

  packet->tcp_retransmission = 0, packet->packet_direction = 0;

  if(ndpi_struct->direction_detect_disable) {
    packet->packet_direction = flow->packet_direction;
  } else {
    if(iph != NULL && iph->saddr < iph->daddr)
      packet->packet_direction = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if(iphv6 != NULL && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->saddr, &iphv6->daddr) != 0)
      packet->packet_direction = 1;
#endif
  }

  packet->packet_lines_parsed_complete = 0;
  if(flow == NULL)
    return;

  if(flow->init_finished == 0) {
    flow->init_finished = 1;
    flow->setup_packet_direction = packet->packet_direction;
  }

  if(tcph != NULL) {
    /* reset retried bytes here before setting it */
    packet->num_retried_bytes = 0;

    if(!ndpi_struct->direction_detect_disable)
      packet->packet_direction = (tcph->source < tcph->dest) ? 1 : 0;

    if(tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0 && flow->l4.tcp.seen_syn_ack == 0
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_syn = 1;
    }
    if(tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 0
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_syn_ack = 1;
    }
    if(tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_ack = 1;
    }
    if((flow->next_tcp_seq_nr[0] == 0 && flow->next_tcp_seq_nr[1] == 0)
       || (proxy_enabled && (flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0))) {
      /* initalize tcp sequence counters */
      /* the ack flag needs to be set to get valid sequence numbers from the other
       * direction. Usually it will catch the second packet syn+ack but it works
       * also for asymmetric traffic where it will use the first data packet
       *
       * if the syn flag is set add one to the sequence number,
       * otherwise use the payload length.
       */
      if(tcph->ack != 0) {
	flow->next_tcp_seq_nr[flow->packet.packet_direction] =
	  ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);
	if(!proxy_enabled) {
	  flow->next_tcp_seq_nr[1 -flow->packet.packet_direction] = ntohl(tcph->ack_seq);
	}
      }
    } else if(packet->payload_packet_len > 0) {
      /* check tcp sequence counters */
      if(((u_int32_t)
	  (ntohl(tcph->seq) -
	   flow->next_tcp_seq_nr[packet->packet_direction])) >
	 ndpi_struct->tcp_max_retransmission_window_size) {

	packet->tcp_retransmission = 1;


	/*CHECK IF PARTIAL RETRY IS HAPPENENING */
	if((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) < packet->payload_packet_len)) {
	  /* num_retried_bytes actual_payload_len hold info about the partial retry
	     analyzer which require this info can make use of this info
	     Other analyzer can use packet->payload_packet_len */
	  packet->num_retried_bytes = (u_int16_t)(flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq));
	  packet->actual_payload_len = packet->payload_packet_len - packet->num_retried_bytes;
	  flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	}
      }
      /*normal path
	actual_payload_len is initialized to payload_packet_len during tcp header parsing itself.
	It will be changed only in case of retransmission */
      else {


	packet->num_retried_bytes = 0;
	flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
      }


    }

    if(tcph->rst) {
      flow->next_tcp_seq_nr[0] = 0;
      flow->next_tcp_seq_nr[1] = 0;
    }
  } else if(udph != NULL) {
    if(!ndpi_struct->direction_detect_disable)
      packet->packet_direction = (udph->source < udph->dest) ? 1 : 0;
  }

  if(flow->packet_counter < MAX_PACKET_COUNTER && packet->payload_packet_len) {
    flow->packet_counter++;
  }

  if(flow->packet_direction_counter[packet->packet_direction] < MAX_PACKET_COUNTER && packet->payload_packet_len) {
    flow->packet_direction_counter[packet->packet_direction]++;
  }

  if(flow->byte_counter[packet->packet_direction] + packet->payload_packet_len >
     flow->byte_counter[packet->packet_direction]) {
    flow->byte_counter[packet->packet_direction] += packet->payload_packet_len;
  }
}

void check_ndpi_other_flow_func(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN)
     && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			     ndpi_struct->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
     && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer[proto_index].detection_bitmask,
			     detection_bitmask) != 0
     && (ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask
	 & *ndpi_selection_packet) == ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask) {
    if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
       && (ndpi_struct->proto_defaults[flow->guessed_protocol_id].func != NULL))
      ndpi_struct->proto_defaults[flow->guessed_protocol_id].func(ndpi_struct, flow),
	func = ndpi_struct->proto_defaults[flow->guessed_protocol_id].func;
  }

  for (a = 0; a < ndpi_struct->callback_buffer_size_non_tcp_udp; a++) {
    if((func != ndpi_struct->callback_buffer_non_tcp_udp[a].func)
       && (ndpi_struct->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
       ndpi_struct->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask
       && (flow == NULL
	   ||
	   NDPI_BITMASK_COMPARE
	   (flow->excluded_protocol_bitmask,
	    ndpi_struct->callback_buffer_non_tcp_udp[a].excluded_protocol_bitmask) == 0)
       && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer_non_tcp_udp[a].detection_bitmask,
			       detection_bitmask) != 0) {

      if(ndpi_struct->callback_buffer_non_tcp_udp[a].func != NULL)
	ndpi_struct->callback_buffer_non_tcp_udp[a].func(ndpi_struct, flow);

      if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	break; /* Stop after detecting the first protocol */
    }
  }
}


void check_ndpi_udp_flow_func(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN)
     && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			     ndpi_struct->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
     && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer[proto_index].detection_bitmask,
			     detection_bitmask) != 0
     && (ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask
	 & *ndpi_selection_packet) == ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask) {
    if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
       && (ndpi_struct->proto_defaults[flow->guessed_protocol_id].func != NULL))
      ndpi_struct->proto_defaults[flow->guessed_protocol_id].func(ndpi_struct, flow),
	func = ndpi_struct->proto_defaults[flow->guessed_protocol_id].func;
  }

  for (a = 0; a < ndpi_struct->callback_buffer_size_udp; a++) {
    if((func != ndpi_struct->callback_buffer_tcp_payload[a].func)
       && (ndpi_struct->callback_buffer_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
       ndpi_struct->callback_buffer_udp[a].ndpi_selection_bitmask
       && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			       ndpi_struct->callback_buffer_udp[a].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer_udp[a].detection_bitmask,
			       detection_bitmask) != 0) {
      ndpi_struct->callback_buffer_udp[a].func(ndpi_struct, flow);
      // NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "[UDP,CALL] dissector of protocol as callback_buffer idx =  %d\n",a);
      if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	break; /* Stop after detecting the first protocol */
    } else
      NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	       "[UDP,SKIP] dissector of protocol as callback_buffer idx =  %d\n",a);
  }
}


void check_ndpi_tcp_flow_func(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_struct->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if(flow->packet.payload_packet_len != 0) {
    if((proto_id != NDPI_PROTOCOL_UNKNOWN)
       && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			       ndpi_struct->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer[proto_index].detection_bitmask,
			       detection_bitmask) != 0
       && (ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask
	   & *ndpi_selection_packet) == ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask) {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_struct->proto_defaults[flow->guessed_protocol_id].func != NULL))
	ndpi_struct->proto_defaults[flow->guessed_protocol_id].func(ndpi_struct, flow),
	  func = ndpi_struct->proto_defaults[flow->guessed_protocol_id].func;
    }

    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      for (a = 0; a < ndpi_struct->callback_buffer_size_tcp_payload; a++) {
        if((func != ndpi_struct->callback_buffer_tcp_payload[a].func)
	   && (ndpi_struct->callback_buffer_tcp_payload[a].ndpi_selection_bitmask
	       & *ndpi_selection_packet) == ndpi_struct->callback_buffer_tcp_payload[a].ndpi_selection_bitmask
	   && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				   ndpi_struct->callback_buffer_tcp_payload[a].excluded_protocol_bitmask) == 0
	   && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer_tcp_payload[a].detection_bitmask,
				   detection_bitmask) != 0) {
	  ndpi_struct->callback_buffer_tcp_payload[a].func(ndpi_struct, flow);

	  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	    break; /* Stop after detecting the first protocol */
	}
      }
    }
  } else {
    /* no payload */
    if((proto_id != NDPI_PROTOCOL_UNKNOWN)
       && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			       ndpi_struct->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer[proto_index].detection_bitmask,
			       detection_bitmask) != 0
       && (ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask
	   & *ndpi_selection_packet) == ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask) {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_struct->proto_defaults[flow->guessed_protocol_id].func != NULL)
	 && ((ndpi_struct->callback_buffer[flow->guessed_protocol_id].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0))
	ndpi_struct->proto_defaults[flow->guessed_protocol_id].func(ndpi_struct, flow),
	  func = ndpi_struct->proto_defaults[flow->guessed_protocol_id].func;
    }

    for (a = 0; a < ndpi_struct->callback_buffer_size_tcp_no_payload; a++) {
      if((func != ndpi_struct->callback_buffer_tcp_payload[a].func)
	 && (ndpi_struct->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
	 ndpi_struct->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask
	 && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				 ndpi_struct->
				 callback_buffer_tcp_no_payload[a].excluded_protocol_bitmask) == 0
	 && NDPI_BITMASK_COMPARE(ndpi_struct->callback_buffer_tcp_no_payload[a].detection_bitmask,
				 detection_bitmask) != 0) {
	ndpi_struct->callback_buffer_tcp_no_payload[a].func(ndpi_struct, flow);

	if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	  break; /* Stop after detecting the first protocol */
      }
    }
  }
}

void check_ndpi_flow_func(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow,
			  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  if(flow->packet.tcp != NULL)
    check_ndpi_tcp_flow_func(ndpi_struct, flow, ndpi_selection_packet);
  else if(flow->packet.udp != NULL)
    check_ndpi_udp_flow_func(ndpi_struct, flow, ndpi_selection_packet);
  else
    check_ndpi_other_flow_func(ndpi_struct, flow, ndpi_selection_packet);
}

unsigned int ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   const unsigned char *packet,
					   const unsigned short packetlen,
					   const u_int64_t current_tick_l,
					   struct ndpi_id_struct *src,
					   struct ndpi_id_struct *dst)
{
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t a;

  if(flow == NULL)
    return NDPI_PROTOCOL_UNKNOWN;

  if(flow->server_id == NULL) flow->server_id = dst; /* Default */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN && !flow->no_cache_protocol)
    return(flow->detected_protocol_stack[0]); /* Stop after detecting the first protocol */

  /* need at least 20 bytes for ip header */
  if(packetlen < 20) {
    /* reset protocol which is normally done in init_packet_header */
    ndpi_int_reset_packet_protocol(&flow->packet);

    return NDPI_PROTOCOL_UNKNOWN;
  }

  flow->packet.tick_timestamp_l = current_tick_l;
#ifdef __KERNEL__
  {
    u_int64_t d = current_tick_l;
    do_div(d,1000);
    flow->packet.tick_timestamp = d;
  }
#else
  flow->packet.tick_timestamp = (u_int32_t)current_tick_l/1000;
#endif

  /* parse packet */
  flow->packet.iph = (struct ndpi_iphdr *) packet;
  /* we are interested in ipv4 packet */

  if(ndpi_init_packet_header(ndpi_struct, flow, packetlen) != 0)
    return NDPI_PROTOCOL_UNKNOWN;

  /* detect traffic for tcp or udp only */

  flow->src = src, flow->dst = dst;

  ndpi_connection_tracking(ndpi_struct, flow);

  /* build ndpi_selction packet bitmask */
  ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
  if(flow->packet.iph != NULL) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
  }
  if(flow->packet.tcp != NULL) {
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);
  }
  if(flow->packet.udp != NULL) {
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);
  }
  if(flow->packet.payload_packet_len != 0) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
  }

  if(flow->packet.tcp_retransmission == 0) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iphv6 != NULL) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
  }
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if((!flow->protocol_id_already_guessed)
     && (
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	 flow->packet.iphv6 ||
#endif
	 flow->packet.iph)) {
    u_int16_t sport, dport;
    u_int8_t protocol;
    u_int32_t saddr, daddr;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if(flow->packet.iphv6 != NULL) {
      protocol = flow->packet.iphv6->nexthdr, saddr = 0, daddr = 0;
    } else
#endif
      {
	protocol = flow->packet.iph->protocol;
	saddr = ntohl(flow->packet.iph->saddr);
	daddr = ntohl(flow->packet.iph->daddr);
      }

    if(flow->packet.udp) sport = ntohs(flow->packet.udp->source), dport = ntohs(flow->packet.udp->dest);
    else if(flow->packet.tcp) sport = ntohs(flow->packet.tcp->source), dport = ntohs(flow->packet.tcp->dest);
    else sport = dport = 0;

    flow->guessed_protocol_id = (int16_t)ndpi_guess_protocol_id(ndpi_struct, protocol,
								sport, dport);
    flow->protocol_id_already_guessed = 1;
  }

  a = flow->detected_protocol_stack[0];
  if(a != NDPI_PROTOCOL_UNKNOWN && flow->no_cache_protocol) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_TRACE, "PROCESS KNOWN PROTOCOL\n");
    ndpi_struct->proto_defaults[a].func(ndpi_struct, flow);
    return a;
  }

  check_ndpi_flow_func(ndpi_struct, flow, &ndpi_selection_packet);

  a = flow->packet.detected_protocol_stack[0];
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_struct->detection_bitmask, a) == 0)
    a = NDPI_PROTOCOL_UNKNOWN;

  if(a != NDPI_PROTOCOL_UNKNOWN) {
    int i;

    for(i=0; (i<sizeof(flow->host_server_name)) && (flow->host_server_name[i] != '\0'); i++)
      flow->host_server_name[i] = tolower(flow->host_server_name[i]);

    flow->host_server_name[i] ='\0';
  }

  return a;
}


u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int32_t val;
  val = 0;
  // cancel if eof, ' ' or line end chars are reached
  while (*str >= '0' && *str <= '9' && max_chars_to_read > 0) {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }
  return (val);
}

u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int32_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;
    while (max_chars_to_read > 0) {

      if(*str >= '0' && *str <= '9') {
	val *= 16;
	val += *str - '0';
      } else if(*str >= 'a' && *str <= 'f') {
	val *= 16;
	val += *str + 10 - 'a';
      } else if(*str >= 'A' && *str <= 'F') {
	val *= 16;
	val += *str + 10 - 'A';
      } else {
	break;
      }
      str++;
      max_chars_to_read = max_chars_to_read - 1;
      *bytes_read = *bytes_read + 1;
    }
  }
  return (val);
}


u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int64_t val;
  val = 0;
  // cancel if eof, ' ' or line end chars are reached
  while (max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }
  return (val);
}

u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int64_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return ndpi_bytestream_to_number64(str, max_chars_to_read, bytes_read);
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;
    while (max_chars_to_read > 0) {

      if(*str >= '0' && *str <= '9') {
	val *= 16;
	val += *str - '0';
      } else if(*str >= 'a' && *str <= 'f') {
	val *= 16;
	val += *str + 10 - 'a';
      } else if(*str >= 'A' && *str <= 'F') {
	val *= 16;
	val += *str + 10 - 'A';
      } else {
	break;
      }
      str++;
      max_chars_to_read = max_chars_to_read - 1;
      *bytes_read = *bytes_read + 1;
    }
  }
  return (val);
}


u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int32_t val;
  u_int16_t read = 0;
  u_int16_t oldread;
  u_int32_t c;
  /* ip address must be X.X.X.X with each X between 0 and 255 */
  oldread = read;
  c = ndpi_bytestream_to_number(str, max_chars_to_read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return 0;
  read++;
  val = c << 24;
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return 0;
  read++;
  val = val + (c << 16);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return 0;
  read++;
  val = val + (c << 8);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read)
    return 0;
  val = val + c;

  *bytes_read = *bytes_read + read;

  return htonl(val);
}

/* internal function for every detection to parse one packet and to increase the info buffer */
void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow)
{
  u_int32_t a;
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t end = packet->payload_packet_len - 1;
  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  packet->parsed_lines = 0;

  packet->empty_line_position_set = 0;

  packet->host_line.ptr = NULL;
  packet->host_line.len = 0;
  packet->referer_line.ptr = NULL;
  packet->referer_line.len = 0;
  packet->content_line.ptr = NULL;
  packet->content_line.len = 0;
  packet->accept_line.ptr = NULL;
  packet->accept_line.len = 0;
  packet->user_agent_line.ptr = NULL;
  packet->user_agent_line.len = 0;
  packet->http_url_name.ptr = NULL;
  packet->http_url_name.len = 0;
  packet->http_encoding.ptr = NULL;
  packet->http_encoding.len = 0;
  packet->http_transfer_encoding.ptr = NULL;
  packet->http_transfer_encoding.len = 0;
  packet->http_contentlen.ptr = NULL;
  packet->http_contentlen.len = 0;
  packet->http_cookie.ptr = NULL;
  packet->http_cookie.len = 0;
  packet->http_origin.len = 0;
  packet->http_origin.ptr = NULL;
  packet->http_x_session_type.ptr = NULL;
  packet->http_x_session_type.len = 0;
  packet->server_line.ptr = NULL;
  packet->server_line.len = 0;
  packet->http_method.ptr = NULL;
  packet->http_method.len = 0;
  packet->http_response.ptr = NULL;
  packet->http_response.len = 0;

  if((packet->payload_packet_len == 0)
     || (packet->payload == NULL))
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for (a = 0; a < end; a++) {
    if(get_u_int16_t(packet->payload, a) == ntohs(0x0d0a)) {
      packet->line[packet->parsed_lines].len = (u_int16_t)(((unsigned long) &packet->payload[a]) - ((unsigned long) packet->line[packet->parsed_lines].ptr));

      if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.1 200 ") &&
	 memcmp(packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] > '0' &&
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] < '6') {
	packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
	packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
	NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
		 "ndpi_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
		 packet->http_response.len, packet->http_response.ptr);
      }
      if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
	// some stupid clients omit a space and place the servername directly after the colon
	if(packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")] == ' ') {
	  packet->server_line.ptr =
	    &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:") + 1];
	  packet->server_line.len =
	    packet->line[packet->parsed_lines].len - (NDPI_STATICSTRING_LEN("Server:") + 1);
	} else {
	  packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")];
	  packet->server_line.len = packet->line[packet->parsed_lines].len - NDPI_STATICSTRING_LEN("Server:");
	}
      }

      if(packet->line[packet->parsed_lines].len > 6
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Host:", 5) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
	  packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
	  packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
	} else {
	  packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
	  packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
	}
      }

      if(packet->line[packet->parsed_lines].len > 17
	 && memcmp(packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
	} else {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
	}
      }

      if(packet->line[packet->parsed_lines].len > 14
	 &&
	 (memcmp
	  (packet->line[packet->parsed_lines].ptr, "Content-Type: ",
	   14) == 0 || memcmp(packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
	packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
	packet->content_line.len = packet->line[packet->parsed_lines].len - 14;
      }

      if(packet->line[packet->parsed_lines].len > 13
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0) {
	packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
	packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
      }

      if(packet->line[packet->parsed_lines].len > 8
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
	packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
	packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
      }

      if(packet->line[packet->parsed_lines].len > 9
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
	packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
	packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
      }

      if(packet->line[packet->parsed_lines].len > 12
	 && (memcmp(packet->line[packet->parsed_lines].ptr, "User-Agent: ", 12) == 0 ||
	     memcmp(packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0)) {
	packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
	packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
      }

      if(packet->line[packet->parsed_lines].len > 18
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
	packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
	packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
      }

      if(packet->line[packet->parsed_lines].len > 19
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
	packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
	packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
      }
      if(packet->line[packet->parsed_lines].len > 16
	 && ((memcmp(packet->line[packet->parsed_lines].ptr, "Content-Length: ", 16) == 0)
	     || (memcmp(packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0))) {
	packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
	packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
      }
      if(packet->line[packet->parsed_lines].len > 8
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
	packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
	packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
      }
      if(packet->line[packet->parsed_lines].len > 8
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Origin: ", 8) == 0) {
	packet->http_origin.ptr = &packet->line[packet->parsed_lines].ptr[8];
	packet->http_origin.len = packet->line[packet->parsed_lines].len - 8;
      }
      if(packet->line[packet->parsed_lines].len > 16
	 && memcmp(packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
	packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
	packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
      }


      if(packet->line[packet->parsed_lines].len == 0) {
	packet->empty_line_position = a;
	packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1)) {
	return;
      }

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 2) >= packet->payload_packet_len) {

	return;
      }
      a++;
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len
      = (u_int16_t)(((unsigned long) &packet->payload[packet->payload_packet_len]) -
		    ((unsigned long) packet->line[packet->parsed_lines].ptr));
    packet->parsed_lines++;
  }
}

void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t a;
  u_int16_t end = packet->payload_packet_len;
  if(packet->packet_lines_parsed_complete != 0)
    return;



  packet->packet_lines_parsed_complete = 1;
  packet->parsed_lines = 0;

  if(packet->payload_packet_len == 0)
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for (a = 0; a < end; a++) {
    if(packet->payload[a] == 0x0a) {
      packet->line[packet->parsed_lines].len = (u_int16_t)(
							   ((unsigned long) &packet->payload[a]) -
							   ((unsigned long) packet->line[packet->parsed_lines].ptr));
      if(a > 0 && packet->payload[a-1] == 0x0d)
	packet->line[packet->parsed_lines].len--;

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1)) {
	break;
      }

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 1];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 1) >= packet->payload_packet_len) {
	break;
      }
      //a++;
    }
  }
}


u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow, u_int16_t counter)
{

  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "called ndpi_check_for_email_address\n");

  if(packet->payload_packet_len > counter && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
					      || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
					      || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
					      || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
    NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "first letter\n");
    counter++;
    while (packet->payload_packet_len > counter
	   && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
	       || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
	       || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
	       || packet->payload[counter] == '-' || packet->payload[counter] == '_'
	       || packet->payload[counter] == '.')) {
      NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "further letter\n");
      counter++;
      if(packet->payload_packet_len > counter && packet->payload[counter] == '@') {
	NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "@\n");
	counter++;
	while (packet->payload_packet_len > counter
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
		   || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
		   || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
	  NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "letter\n");
	  counter++;
	  if(packet->payload_packet_len > counter && packet->payload[counter] == '.') {
	    NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, ".\n");
	    counter++;
	    if(packet->payload_packet_len > counter + 1
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   && (packet->payload[counter + 1] >= 'a' && packet->payload[counter + 1] <= 'z'))) {
	      NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "two letters\n");
	      counter += 2;
	      if(packet->payload_packet_len > counter
		 && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "whitespace1\n");
		return counter;
	      } else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			&& packet->payload[counter] <= 'z') {
		NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "one letter\n");
		counter++;
		if(packet->payload_packet_len > counter
		   && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		  NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "whitespace2\n");
		  return counter;
		} else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			  && packet->payload[counter] <= 'z') {
		  counter++;
		  if(packet->payload_packet_len > counter
		     && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		    NDPI_LOG(NDPI_PROTOCOL_MSN, ndpi_struct, NDPI_LOG_DEBUG, "whitespace3\n");
		    return counter;
		  } else {
		    return 0;
		  }
		} else {
		  return 0;
		}
	      } else {
		return 0;
	      }
	    } else {
	      return 0;
	    }
	  }
	}
	return 0;
      }
    }
  }
  return 0;
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void ndpi_debug_get_last_log_function_line(struct ndpi_detection_module_struct
					   *ndpi_struct, const char **file, const char **func, u_int32_t * line)
{
  *file = "";
  *func = "";

  if(ndpi_struct->ndpi_debug_print_file != NULL)
    *file = ndpi_struct->ndpi_debug_print_file;

  if(ndpi_struct->ndpi_debug_print_function != NULL)
    *func = ndpi_struct->ndpi_debug_print_function;

  *line = ndpi_struct->ndpi_debug_print_line;
}
#endif
u_int8_t ndpi_detection_get_l4(const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
			       u_int8_t * l4_protocol_return, u_int32_t flags)
{
  return ndpi_detection_get_l4_internal(NULL, l3, l3_len, l4_return, l4_len_return, l4_protocol_return, flags);
}

void ndpi_int_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow,
			     u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type)
{
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_int_change_protocol(ndpi_struct, flow, detected_protocol, protocol_type);

  if(src != NULL) {
    NDPI_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, detected_protocol);
  }
  if(dst != NULL) {
    NDPI_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, detected_protocol);
  }
}

void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type)
{
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  u_int8_t a;
  u_int8_t stack_size;
  u_int8_t new_is_real = 0;
  u_int16_t preserve_bitmask;
#endif

  if(!flow)
    return;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  stack_size = flow->protocol_stack_info.current_stack_size_minus_one + 1;

  /* here are the rules for stack manipulations:
   * 1.if the new protocol is a real protocol, insert it at the position
   *   of the top-most real protocol or below the last non-unknown correlated
   *   protocol.
   * 2.if the new protocol is not real, put it on top of stack but if there is
   *   a real protocol in the stack, make sure at least one real protocol remains
   *   in the stack
   */

  if(protocol_type == NDPI_CORRELATED_PROTOCOL) {
    u_int16_t saved_real_protocol = NDPI_PROTOCOL_UNKNOWN;

    if(stack_size == NDPI_PROTOCOL_HISTORY_SIZE) {
      /* check whether we will lost real protocol information due to shifting */
      u_int16_t real_protocol = flow->protocol_stack_info.entry_is_real_protocol;

      for (a = 0; a < stack_size; a++) {
	if(real_protocol & 1)
	  break;
	real_protocol >>= 1;
      }

      if(a == (stack_size - 1)) {
	/* oh, only one real protocol at the end, store it and insert it later */
	saved_real_protocol = flow->detected_protocol_stack[stack_size - 1];
      }
    } else {
      flow->protocol_stack_info.current_stack_size_minus_one++;
      stack_size++;
    }

    /* now shift and insert */
    for (a = stack_size - 1; a > 0; a--) {
      flow->detected_protocol_stack[a] = flow->detected_protocol_stack[a - 1];
    }

    flow->protocol_stack_info.entry_is_real_protocol <<= 1;

    /* now set the new protocol */

    flow->detected_protocol_stack[0] = detected_protocol;

    /* restore real protocol */
    if(saved_real_protocol != NDPI_PROTOCOL_UNKNOWN) {
      flow->detected_protocol_stack[stack_size - 1] = saved_real_protocol;
      flow->protocol_stack_info.entry_is_real_protocol |= 1 << (stack_size - 1);
    }
    /* done */
  } else {
    u_int8_t insert_at = 0;

    if(!(flow->protocol_stack_info.entry_is_real_protocol & 1)) {
      u_int16_t real_protocol = flow->protocol_stack_info.entry_is_real_protocol;

      for (a = 0; a < stack_size; a++) {
	if(real_protocol & 1)
	  break;
	real_protocol >>= 1;
      }

      insert_at = a;
    }

    if(insert_at >= stack_size) {
      /* no real protocol found, insert it at the bottom */

      insert_at = stack_size - 1;
    }

    if(stack_size < NDPI_PROTOCOL_HISTORY_SIZE) {
      flow->protocol_stack_info.current_stack_size_minus_one++;
      stack_size++;
    }

    /* first shift all stacks */
    for (a = stack_size - 1; a > insert_at; a--) {
      flow->detected_protocol_stack[a] = flow->detected_protocol_stack[a - 1];
    }

    preserve_bitmask = (1 << insert_at) - 1;

    new_is_real = (flow->protocol_stack_info.entry_is_real_protocol & (~preserve_bitmask)) << 1;
    new_is_real |= flow->protocol_stack_info.entry_is_real_protocol & preserve_bitmask;

    flow->protocol_stack_info.entry_is_real_protocol = new_is_real;

    /* now set the new protocol */

    flow->detected_protocol_stack[insert_at] = detected_protocol;

    /* and finally update the additional stack information */

    flow->protocol_stack_info.entry_is_real_protocol |= 1 << insert_at;
  }
#else
  flow->detected_protocol_stack[0] = detected_protocol;
  flow->detected_subprotocol_stack[0] = detected_subprotocol;
#endif
}

void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  /* NOTE: everything below is identically to change_flow_protocol
   *        except flow->packet If you want to change something here,
   *        don't! Change it for the flow function and apply it here
   *        as well */
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  u_int8_t a;
  u_int8_t stack_size;
  u_int16_t new_is_real = 0;
  u_int16_t preserve_bitmask;
#endif

  if(!packet)
    return;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  stack_size = packet->protocol_stack_info.current_stack_size_minus_one + 1;

  /* here are the rules for stack manipulations:
   * 1.if the new protocol is a real protocol, insert it at the position
   *   of the top-most real protocol or below the last non-unknown correlated
   *   protocol.
   * 2.if the new protocol is not real, put it on top of stack but if there is
   *   a real protocol in the stack, make sure at least one real protocol remains
   *   in the stack
   */

  if(protocol_type == NDPI_CORRELATED_PROTOCOL) {
    u_int16_t saved_real_protocol = NDPI_PROTOCOL_UNKNOWN;

    if(stack_size == NDPI_PROTOCOL_HISTORY_SIZE) {
      /* check whether we will lost real protocol information due to shifting */
      u_int16_t real_protocol = packet->protocol_stack_info.entry_is_real_protocol;

      for (a = 0; a < stack_size; a++) {
	if(real_protocol & 1)
	  break;
	real_protocol >>= 1;
      }

      if(a == (stack_size - 1)) {
	/* oh, only one real protocol at the end, store it and insert it later */
	saved_real_protocol = packet->detected_protocol_stack[stack_size - 1];
      }
    } else {
      packet->protocol_stack_info.current_stack_size_minus_one++;
      stack_size++;
    }

    /* now shift and insert */
    for (a = stack_size - 1; a > 0; a--) {
      packet->detected_protocol_stack[a] = packet->detected_protocol_stack[a - 1];
    }

    packet->protocol_stack_info.entry_is_real_protocol <<= 1;

    /* now set the new protocol */

    packet->detected_protocol_stack[0] = detected_protocol;

    /* restore real protocol */
    if(saved_real_protocol != NDPI_PROTOCOL_UNKNOWN) {
      packet->detected_protocol_stack[stack_size - 1] = saved_real_protocol;
      packet->protocol_stack_info.entry_is_real_protocol |= 1 << (stack_size - 1);
    }
    /* done */
  } else {
    u_int8_t insert_at = 0;

    if(!(packet->protocol_stack_info.entry_is_real_protocol & 1)) {
      u_int16_t real_protocol = packet->protocol_stack_info.entry_is_real_protocol;

      for (a = 0; a < stack_size; a++) {
	if(real_protocol & 1)
	  break;
	real_protocol >>= 1;
      }

      insert_at = a;
    }

    if(insert_at >= stack_size) {
      /* no real protocol found, insert it at the first unknown protocol */

      insert_at = stack_size - 1;
    }

    if(stack_size < NDPI_PROTOCOL_HISTORY_SIZE) {
      packet->protocol_stack_info.current_stack_size_minus_one++;
      stack_size++;
    }

    /* first shift all stacks */
    for (a = stack_size - 1; a > insert_at; a--) {
      packet->detected_protocol_stack[a] = packet->detected_protocol_stack[a - 1];
    }

    preserve_bitmask = (1 << insert_at) - 1;

    new_is_real = (packet->protocol_stack_info.entry_is_real_protocol & (~preserve_bitmask)) << 1;
    new_is_real |= packet->protocol_stack_info.entry_is_real_protocol & preserve_bitmask;

    packet->protocol_stack_info.entry_is_real_protocol = (u_int8_t)new_is_real;

    /* now set the new protocol */

    packet->detected_protocol_stack[insert_at] = detected_protocol;

    /* and finally update the additional stack information */

    packet->protocol_stack_info.entry_is_real_protocol |= 1 << insert_at;
  }
#else
  packet->detected_protocol_stack[0] = detected_protocol;
  packet->detected_subprotocol_stack[0] = detected_subprotocol;
#endif
}


/*
 * this function returns the real protocol of the flow. Actually it
 * accesses the packet stack since this is what leaves the library but
 * it could also use the flow stack.
 */
u_int16_t ndpi_detection_get_real_protocol_of_flow(struct ndpi_detection_module_struct * ndpi_struct,
						   struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  u_int8_t a;
  u_int8_t stack_size;
  u_int16_t real_protocol;
#endif

  if(!packet)
    return NDPI_PROTOCOL_UNKNOWN;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  stack_size = packet->protocol_stack_info.current_stack_size_minus_one + 1;
  real_protocol = packet->protocol_stack_info.entry_is_real_protocol;

  for (a = 0; a < stack_size; a++) {
    if(real_protocol & 1)
      return packet->detected_protocol_stack[a];
    real_protocol >>= 1;
  }

  return NDPI_PROTOCOL_UNKNOWN;
#else
  return packet->detected_protocol_stack[0];
#endif
}

/*
 * this function checks whether a protocol can be found in the
 * history. Actually it accesses the packet stack since this is what
 * leaves the library but it could also use the flow stack.
 */
u_int8_t ndpi_detection_flow_protocol_history_contains_protocol(struct ndpi_detection_module_struct * ndpi_struct,
								struct ndpi_flow_struct *flow,
								u_int16_t protocol_id)
{
  u_int8_t a;
  u_int8_t stack_size;
  struct ndpi_packet_struct *packet = &flow->packet;

  if(!packet)
    return 0;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  stack_size = packet->protocol_stack_info.current_stack_size_minus_one + 1;
#else
  stack_size = 1;
#endif

  for (a = 0; a < stack_size; a++) {
    if(packet->detected_protocol_stack[a] == protocol_id)
      return 1;
  }

  return 0;
}

/* generic function for setting a protocol for a flow
 *
 * what it does is:
 * 1.call ndpi_int_change_protocol
 * 2.set protocol in detected bitmask for src and dst
 */
void ndpi_int_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
			     struct ndpi_flow_struct *flow,
			     u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the flow protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 */
void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the packetprotocol
 *
 * what it does is:
 * 1.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      u_int16_t detected_protocol,
			      ndpi_protocol_type_t protocol_type)
{
  ndpi_int_change_flow_protocol(ndpi_struct, flow, detected_protocol, protocol_type);
  ndpi_int_change_packet_protocol(ndpi_struct, flow, detected_protocol, protocol_type);
}


/* turns a packet back to unknown */
void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet) {
  packet->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
  packet->protocol_stack_info.current_stack_size_minus_one = 0;
  packet->protocol_stack_info.entry_is_real_protocol = 0;
#endif
}

void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow)
{
  if(flow) {
    flow->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
    flow->protocol_stack_info.current_stack_size_minus_one = 0;
    flow->protocol_stack_info.entry_is_real_protocol = 0;
#endif
  }
}

void NDPI_PROTOCOL_IP_clear(ndpi_ip_addr_t * ip)
{
  memset(ip, 0, sizeof(ndpi_ip_addr_t));
}

/* NTOP */
int NDPI_PROTOCOL_IP_is_set(const ndpi_ip_addr_t * ip)
{
  return memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(ndpi_ip_addr_t)) != 0;
}

/* check if the source ip address in packet and ip are equal */
/* NTOP */
int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip)
{
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->saddr.ndpi_v6_u.u6_addr64[0] == ip->ipv6.ndpi_v6_u.u6_addr64[0] &&
       packet->iphv6->saddr.ndpi_v6_u.u6_addr64[1] == ip->ipv6.ndpi_v6_u.u6_addr64[1]) {

      return 1;
    } else {
      return 0;
    }
  }
#endif
  if(packet->iph->saddr == ip->ipv4) {
    return 1;
  }
  return 0;
}

/* check if the destination ip address in packet and ip are equal */
int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip)
{
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->daddr.ndpi_v6_u.u6_addr64[0] == ip->ipv6.ndpi_v6_u.u6_addr64[0] &&
       packet->iphv6->daddr.ndpi_v6_u.u6_addr64[1] == ip->ipv6.ndpi_v6_u.u6_addr64[1]) {
      return 1;
    } else {
      return 0;
    }
  }
#endif
  if(packet->iph->daddr == ip->ipv4) {
    return 1;
  }
  return 0;
}

/* get the source ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    ip->ipv6.ndpi_v6_u.u6_addr64[0] = packet->iphv6->saddr.ndpi_v6_u.u6_addr64[0];
    ip->ipv6.ndpi_v6_u.u6_addr64[1] = packet->iphv6->saddr.ndpi_v6_u.u6_addr64[1];
  } else
#endif
    ip->ipv4 = packet->iph->saddr;
}

/* get the destination ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    ip->ipv6.ndpi_v6_u.u6_addr64[0] = packet->iphv6->daddr.ndpi_v6_u.u6_addr64[0];
    ip->ipv6.ndpi_v6_u.u6_addr64[1] = packet->iphv6->daddr.ndpi_v6_u.u6_addr64[1];
  } else
#endif
    ip->ipv4 = packet->iph->daddr;
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
/* get the string representation of ip
 * returns a pointer to a static string
 * only valid until the next call of this function */
char *ndpi_get_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
			 const ndpi_ip_addr_t * ip)
{
  const u_int8_t *a = (const u_int8_t *) &ip->ipv4;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(ip->ipv6.ndpi_v6_u.u6_addr32[1] != 0 || ip->ipv6.ndpi_v6_u.u6_addr64[1] != 0) {
    const u_int16_t *b = ip->ipv6.ndpi_v6_u.u6_addr16;
    snprintf(ndpi_struct->ip_string, 32, "%x:%x:%x:%x:%x:%x:%x:%x",
	     ntohs(b[0]), ntohs(b[1]), ntohs(b[2]), ntohs(b[3]),
	     ntohs(b[4]), ntohs(b[5]), ntohs(b[6]), ntohs(b[7]));
    return ndpi_struct->ip_string;
  }
#endif
  snprintf(ndpi_struct->ip_string, 32, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return ndpi_struct->ip_string;

}


/* get the string representation of the source ip address from packet */
char *ndpi_get_packet_src_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
				    const struct ndpi_packet_struct *packet)
{
  ndpi_ip_addr_t ip;
  ndpi_packet_src_ip_get(packet, &ip);
  return ndpi_get_ip_string(ndpi_struct, &ip);
}

/* get the string representation of the destination ip address from packet */
char *ndpi_get_packet_dst_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
				    const struct ndpi_packet_struct *packet)
{
  ndpi_ip_addr_t ip;
  ndpi_packet_dst_ip_get(packet, &ip);
  return ndpi_get_ip_string(ndpi_struct, &ip);
}
#endif							/* NDPI_ENABLE_DEBUG_MESSAGES */

/* ****************************************************** */

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return ntohs(val);
}

/* ****************************************************** */

#if 0
#ifndef __KERNEL__
static u_int is_port(u_int16_t sport, u_int16_t dport, u_int16_t match_port) {
  return(((match_port == sport) || (match_port == dport)) ? 1 : 0);
}
#endif
#endif

/* ****************************************************** */

unsigned int ndpi_find_port_based_protocol(struct ndpi_detection_module_struct *ndpi_struct /* NOTUSED */,
					   u_int8_t proto,
					   u_int32_t shost, u_int16_t sport,
					   u_int32_t dhost, u_int16_t dport) {
  /* Skyfile (host 193.252.234.246 or host 10.10.102.80) */
  if((shost == 0xC1FCEAF6) || (dhost == 0xC1FCEAF6)
     || (shost == 0x0A0A6650) || (dhost == 0x0A0A6650)) {
    if((sport == 4708) || (dport == 4708)) return(NDPI_PROTOCOL_SKYFILE_PREPAID);
    else if((sport == 4709) || (dport == 4709)) return(NDPI_PROTOCOL_SKYFILE_RUDICS);
    else if((sport == 4710) || (dport == 4710)) return(NDPI_PROTOCOL_SKYFILE_POSTPAID);
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */

unsigned int ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					    u_int8_t proto,
					    u_int32_t shost /* host byte order */, u_int16_t sport,
					    u_int32_t dhost /* host byte order */, u_int16_t dport) {
  unsigned int rc;
  struct in_addr addr;

  if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
    rc = ndpi_search_tcp_or_udp_raw(ndpi_struct, proto, shost, dhost, sport, dport);
    if(rc != NDPI_PROTOCOL_UNKNOWN) return(rc);

    rc = ndpi_guess_protocol_id(ndpi_struct, proto, sport, dport);
    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      if(rc == NDPI_PROTOCOL_SSL)
	goto check_guessed_skype;
      else
	return(rc);
    }

    rc = ndpi_find_port_based_protocol(ndpi_struct, proto, shost, sport, dhost, dport);
    if(rc != NDPI_PROTOCOL_UNKNOWN) return(rc);

  check_guessed_skype:
    addr.s_addr = shost;
    if(ndpi_network_ptree_match(ndpi_struct, &addr) == NDPI_PROTOCOL_SKYPE) return(NDPI_PROTOCOL_SKYPE);

    addr.s_addr = dhost;
    if(ndpi_network_ptree_match(ndpi_struct, &addr) == NDPI_PROTOCOL_SKYPE) return(NDPI_PROTOCOL_SKYPE);

    return(rc);
  } else {
    return(ndpi_guess_protocol_id(ndpi_struct, proto, sport, dport));
  }
}

/* ****************************************************** */

char* ndpi_get_proto_name(struct ndpi_detection_module_struct *ndpi_mod, u_int16_t proto_id) {
  if((proto_id >= ndpi_mod->ndpi_num_supported_protocols)
     || ((proto_id < (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
	 && (ndpi_mod->proto_defaults[proto_id].protoName == NULL)))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_mod->proto_defaults[proto_id].protoName);
}

/* ****************************************************** */

ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_mod,
					   u_int16_t proto_id) {
  if((proto_id >= ndpi_mod->ndpi_num_supported_protocols)
     || ((proto_id < (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
	 && (ndpi_mod->proto_defaults[proto_id].protoName == NULL)))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_mod->proto_defaults[proto_id].protoBreed);
}

/* ****************************************************** */

char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_mod,
				ndpi_protocol_breed_t breed_id) {
  switch(breed_id) {
  case NDPI_PROTOCOL_SAFE:
    return("Safe");
    break;
  case NDPI_PROTOCOL_ACCEPTABLE:
    return("Acceptable");
    break;
  case NDPI_PROTOCOL_FUN:
    return("Fun");
    break;
  case NDPI_PROTOCOL_UNSAFE:
    return("Unsafe");
    break;
  case NDPI_PROTOCOL_POTENTIALLY_DANGEROUS:
    return("Dangerous");
    break;

  case NDPI_PROTOCOL_UNRATED:
  default:
    return("Unrated");
    break;
  }
}

/* ****************************************************** */

int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_mod, char *proto) {
  int i;

  for(i=0; i<(int)ndpi_mod->ndpi_num_supported_protocols; i++)
    if(strcasecmp(proto, ndpi_mod->proto_defaults[i].protoName) == 0)
      return(i);

  return(-1);
}

/* ****************************************************** */

void ndpi_dump_protocols(struct ndpi_detection_module_struct *ndpi_mod) {
  int i;

  for(i=0; i<(int)ndpi_mod->ndpi_num_supported_protocols; i++)
    printf("[%3d] %s\n", i, ndpi_mod->proto_defaults[i].protoName);
}

/* ****************************************************** */

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char* ndpi_strnstr(const char *s, const char *find, size_t slen) {
  char c, sc;
  size_t len;

  if((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
	if(slen-- < 1 || (sc = *s++) == '\0')
	  return (NULL);
      } while (sc != c);
      if(len > slen)
	return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

/* ****************************************************** */

static int ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
						ndpi_automa *automa,
						struct ndpi_flow_struct *flow,
						char *string_to_match, u_int string_to_match_len) {
  int matching_protocol_id;
  struct ndpi_packet_struct *packet = &flow->packet;
  AC_TEXT_t ac_input_text;

  if((automa->ac_automa == NULL) || (string_to_match_len== 0)) return(NDPI_PROTOCOL_UNKNOWN);

  if(!automa->ac_automa_finalized) {
    ac_automata_finalize((AC_AUTOMATA_t*)automa->ac_automa);
    automa->ac_automa_finalized = 1;
  }

  matching_protocol_id = NDPI_PROTOCOL_UNKNOWN;

  ac_input_text.astring = string_to_match, ac_input_text.length = string_to_match_len;
  ac_automata_search (((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, (void*)&matching_protocol_id);

  ac_automata_reset(((AC_AUTOMATA_t*)automa->ac_automa));

#ifdef DEBUG
  {
    char m[256];
    int len = ndpi_min(sizeof(m), string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    printf("[NDPI] ndpi_match_string_subprotocol(%s): %s\n", m, ndpi_struct->proto_defaults[matching_protocol_id].protoName);
  }
#endif

  if(matching_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
    packet->detected_protocol_stack[0] = matching_protocol_id;

    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
      flow->detected_protocol_stack[0] = packet->detected_protocol_stack[0];

    return(packet->detected_protocol_stack[0]);
  }

#ifdef DEBUG
  string_to_match[string_to_match_len] = '\0';
  printf("[NTOP] Unable to find a match for '%s'\n", string_to_match);
#endif

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  char *string_to_match, u_int string_to_match_len) {
  return(ndpi_automa_match_string_subprotocol(ndpi_struct, &ndpi_struct->host_automa,
					      flow, string_to_match, string_to_match_len));
}

/* ****************************************************** */

int ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   char *string_to_match, u_int string_to_match_len) {
  return(ndpi_automa_match_string_subprotocol(ndpi_struct, &ndpi_struct->content_automa,
					      flow, string_to_match, string_to_match_len));
}

/* ****************************************************** */

int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_struct,
		      ndpi_automa *automa, char *bigram_to_match) {
  AC_TEXT_t ac_input_text;
  int ret = 0;

  if((automa->ac_automa == NULL) || (bigram_to_match == NULL))
    return(ret);

  if(!automa->ac_automa_finalized) {
    ac_automata_finalize((AC_AUTOMATA_t*)automa->ac_automa);
    automa->ac_automa_finalized = 1;
  }

  ac_input_text.astring = bigram_to_match, ac_input_text.length = 2;
  ac_automata_search(((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, (void*)&ret);
  ac_automata_reset(((AC_AUTOMATA_t*)automa->ac_automa));

  return(ret);
}

/* ****************************************************** */

void ndpi_free_flow(struct ndpi_flow_struct *flow) {
  if(flow) {
    if(flow->http.url)          ndpi_free(flow->http.url);
    if(flow->http.content_type) ndpi_free(flow->http.content_type);
    ndpi_free(flow);
  }
}

/* ****************************************************** */

#ifndef __KERNEL__
char* ndpi_revision() {
  return(NDPI_GIT_RELEASE);
}
#endif

/* ****************************************************** */

#ifdef WIN32

/*
  int pthread_mutex_init(pthread_mutex_t *mutex, void *unused) {
  unused = NULL;
  *mutex = CreateMutex(NULL, FALSE, NULL);
  return *mutex == NULL ? -1 : 0;
  }

  int pthread_mutex_destroy(pthread_mutex_t *mutex) {
  return CloseHandle(*mutex) == 0 ? -1 : 0;
  }

  int pthread_mutex_lock(pthread_mutex_t *mutex) {
  return WaitForSingleObject(*mutex, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
  }

  int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  return ReleaseMutex(*mutex) == 0 ? -1 : 0;
  }
*/
/*  http://git.postgresql.org/gitweb/?p=postgresql.git;a=blob;f=src/port/gettimeofday.c;h=75a91993b74414c0a1c13a2a09ce739cb8aa8a08;hb=HEAD */
int gettimeofday(struct timeval * tp, struct timezone * tzp) {
  /* FILETIME of Jan 1 1970 00:00:00. */
  const unsigned __int64 epoch = (__int64)(116444736000000000);

  FILETIME    file_time;
  SYSTEMTIME  system_time;
  ULARGE_INTEGER ularge;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);
  ularge.LowPart = file_time.dwLowDateTime;
  ularge.HighPart = file_time.dwHighDateTime;

  tp->tv_sec = (long) ((ularge.QuadPart - epoch) / 10000000L);
  tp->tv_usec = (long) (system_time.wMilliseconds * 1000);

  return 0;
}
#endif

int NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK a, NDPI_PROTOCOL_BITMASK b) {
  int i;

  for(i=0; i<NDPI_NUM_FDS_BITS; i++) {
    if(a.fds_bits[i] & b.fds_bits[i])
      return(1);
  }

  return(0);
}

int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a) {
  int i;

  for(i=0; i<NDPI_NUM_FDS_BITS; i++)
    if(a.fds_bits[i] != 0)
      return(0);

  return(1);
}

void NDPI_DUMP_BITMASK(NDPI_PROTOCOL_BITMASK a) {
  int i;

  for(i=0; i<NDPI_NUM_FDS_BITS; i++)
    printf("[%d=%u]", i, a.fds_bits[i]);

  printf("\n");
}


#ifdef WIN32
/* http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/bsd/libkern/strsep.c */

/*
 * Get next token from string *stringp, where tokens are possibly-empty
 * strings separated by characters from delim.
 *
 * Writes NULs into the string at *stringp to end tokens.
 * delim need not remain constant from call to call.
 * On return, *stringp points past the last NUL written (if there might
 * be further tokens), or is NULL (if there are definitely no more tokens).
 *
 * If *stringp is NULL, strsep returns NULL.
 */
char* strsep(char **stringp, const char *delim) {
  char *s;
  const char *spanp;
  int c, sc;
  char *tok;

  if((s = *stringp) == NULL)
    return (NULL);
  for (tok = s;;) {
    c = *s++;
    spanp = delim;
    do {
      if((sc = *spanp++) == c) {
	if(c == 0)
	  s = NULL;
	else
	  s[-1] = 0;
	*stringp = s;
	return (tok);
      }
    } while (sc != 0);
  }
  /* NOTREACHED */
}
#endif


