/*
 * ndpi_main.c
 *
 * Copyright (C) 2011-16 - ntop.org
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
#include "ahocorasick.h"
#include "ndpi_api.h"
#include "../../config.h"

#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "ndpi_content_match.c.inc"
#include "third_party/include/ndpi_patricia.h"
#include "third_party/src/ndpi_patricia.c"


/* implementation of the punycode check function */
int check_punycode_string(char * buffer , int len)
{
  int i = 0;
  
  while(i++ < len)
  {
    if( buffer[i] == 'x' &&
	buffer[i+1] == 'n' &&
	buffer[i+2] == '-' &&
	buffer[i+3] == '-' )
      // is a punycode string
      return 1;
  }
  // not a punycode string
  return 0;
}

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

static void *(*_ndpi_malloc)(size_t size);
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
			   ndpi_proto_defaults_t *def,
			   u_int8_t customUserProto,
			   ndpi_default_ports_tree_node_t **root);

static int removeDefaultPort(ndpi_port_range *range,
			     ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root);

/* ****************************************** */

void* ndpi_malloc(size_t size) { return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size)); }

/* ****************************************** */

void* ndpi_calloc(unsigned long count, size_t size) {
  size_t len = count*size;
  void *p = ndpi_malloc(len);

  if(p)
    memset(p, 0, len);

  return(p);
}

/* ****************************************** */

void ndpi_free(void *ptr)  { if(_ndpi_free) _ndpi_free(ptr); else free(ptr); }

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

/* ****************************************************** */

u_int16_t ndpi_get_proto_by_name(struct ndpi_detection_module_struct *ndpi_mod, const char *name) {
  u_int16_t i, num = ndpi_get_num_supported_protocols(ndpi_mod);

  for(i = 0; i < num; i++)
    if(strcasecmp(ndpi_get_proto_by_id(ndpi_mod, i), name) == 0)
      return(i);
  
  return(NDPI_PROTOCOL_UNKNOWN);
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
			     char *protoName, ndpi_protocol_category_t protoCategory,
			     ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts) {
  char *name;
  int j;

  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS) {
#ifdef DEBUG
    printf("[NDPI] %s(%s/protoId=%d): INTERNAL ERROR\n", __FUNCTION__, protoName, protoId);
#endif
    return;
  }

  if(ndpi_mod->proto_defaults[protoId].protoName != NULL) {
#ifdef DEBUG
    printf("[NDPI] %s(%s/protoId=%d): already initialized. Ignoring it\n", __FUNCTION__, protoName, protoId);
#endif
    return;
  }

  name = ndpi_strdup(protoName);

  ndpi_mod->proto_defaults[protoId].protoName = name,
    ndpi_mod->proto_defaults[protoId].protoCategory = protoCategory,
    ndpi_mod->proto_defaults[protoId].protoId = protoId,
    ndpi_mod->proto_defaults[protoId].protoBreed = breed;

  memcpy(&ndpi_mod->proto_defaults[protoId].master_tcp_protoId, tcp_master_protoId, 2*sizeof(u_int16_t));
  memcpy(&ndpi_mod->proto_defaults[protoId].master_udp_protoId, udp_master_protoId, 2*sizeof(u_int16_t));

  for(j=0; j<MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0) addDefaultPort(&udpDefPorts[j], &ndpi_mod->proto_defaults[protoId], 0, &ndpi_mod->udpRoot);
    if(tcpDefPorts[j].port_low != 0) addDefaultPort(&tcpDefPorts[j], &ndpi_mod->proto_defaults[protoId], 0, &ndpi_mod->tcpRoot);
  }
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
			   ndpi_proto_defaults_t *def,
			   u_int8_t customUserProto,
			   ndpi_default_ports_tree_node_t **root) {
  ndpi_default_ports_tree_node_t *ret;
  u_int16_t port;

  for(port=range->port_low; port<=range->port_high; port++) {
    ndpi_default_ports_tree_node_t *node = (ndpi_default_ports_tree_node_t*)ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));

    if(!node) {
      printf("[NDPI] %s(): not enough memory\n", __FUNCTION__);
      break;
    }

    node->proto = def, node->default_port = port, node->customUserProto = customUserProto;
    ret = *(ndpi_default_ports_tree_node_t**)ndpi_tsearch(node, (void*)root, ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != node) {
      /* printf("[NDPI] %s(): found duplicate for port %u: overwriting it with new value\n", __FUNCTION__, port); */

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
  if(value == NULL)
    ac_pattern.length = 0;
  else
    ac_pattern.length = strlen(ac_pattern.astring);

  ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern);

  return(0);
}

/* ****************************************************** */

static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					 char *value, int protocol_id,
					 ndpi_protocol_breed_t breed) {
#ifdef DEBUG
  printf("[NDPI] Adding [%s][%d]\n", value, protocol_id);
#endif

  return(ndpi_string_to_automa(ndpi_struct, &ndpi_struct->host_automa,
			       value, protocol_id, breed));
}

/* ****************************************************** */

int ndpi_add_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				 char *value, int protocol_id,
				 ndpi_protocol_breed_t breed) {
  return(ndpi_string_to_automa(ndpi_struct, &ndpi_struct->content_automa,
			       value, protocol_id, breed));
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

void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_mod,
			      ndpi_protocol_match *match) {
  u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO };
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  ndpi_add_host_url_subprotocol(ndpi_mod, match->string_to_match,
				match->protocol_id, match->protocol_breed);

  if(ndpi_mod->proto_defaults[match->protocol_id].protoName == NULL) {
    ndpi_mod->proto_defaults[match->protocol_id].protoName  = ndpi_strdup(match->proto_name);
    ndpi_mod->proto_defaults[match->protocol_id].protoCategory = match->proto_category;
    ndpi_mod->proto_defaults[match->protocol_id].protoId    = match->protocol_id;
    ndpi_mod->proto_defaults[match->protocol_id].protoBreed = match->protocol_breed;
  }

  ndpi_set_proto_defaults(ndpi_mod,
			  ndpi_mod->proto_defaults[match->protocol_id].protoBreed,
			  ndpi_mod->proto_defaults[match->protocol_id].protoId,
			  no_master, no_master,
			  ndpi_mod->proto_defaults[match->protocol_id].protoName,
			  ndpi_mod->proto_defaults[match->protocol_id].protoCategory,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
}

/* ******************************************************************** */

static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_mod) {
  int i;

  for(i=0; host_match[i].string_to_match != NULL; i++)
    ndpi_init_protocol_match(ndpi_mod, &host_match[i]);

#ifdef DEBUG
  ac_automata_display(ndpi_mod->host_automa.ac_automa, 'n');
#endif

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
    custom_master[2];

    /* Reset all settings */
    memset(ndpi_mod->proto_defaults, 0, sizeof(ndpi_mod->proto_defaults));

    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			    no_master,
			    no_master, "Unknown", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_CONTROL,
			    no_master,
			    no_master, "FTP_CONTROL", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
			    ndpi_build_default_ports(ports_a, 21, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_DATA,
			    no_master,
			    no_master, "FTP_DATA", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
			    ndpi_build_default_ports(ports_a, 20, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_POP,
			    no_master,
			    no_master, "POP3", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 110, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_POPS,
			    no_master,
			    no_master, "POPS", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 995, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_SMTP,
			    no_master,
			    no_master, "SMTP", NDPI_PROTOCOL_CATEGORY_MAIL_SEND,
			    ndpi_build_default_ports(ports_a, 25, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_SMTPS,
			    no_master,
			    no_master, "SMTPS", NDPI_PROTOCOL_CATEGORY_MAIL_SEND,
			    ndpi_build_default_ports(ports_a, 465, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_IMAP,
			    no_master,
			    no_master, "IMAP", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 143, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_IMAPS,
			    no_master,
			    no_master, "IMAPS", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 993, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNS,
    			    no_master,
    			    no_master, "DNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 53, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 53, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IPP,
			    no_master,
			    no_master, "IPP", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HEP,
			    no_master,
			    no_master, "HEP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 9064, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 9063, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			    no_master,
			    no_master, "HTTP", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MDNS,
			    no_master,
			    no_master, "MDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5353, 5354, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NTP,
			    no_master,
			    no_master, "NTP", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 123, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETBIOS,
			    no_master,
			    no_master, "NetBIOS", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 139, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 137, 138, 139, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NFS,
			    no_master,
			    no_master, "NFS", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
			    ndpi_build_default_ports(ports_a, 2049, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2049, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSDP,
			    no_master,
			    no_master, "SSDP", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BGP,
    			    no_master,
    			    no_master, "BGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 2605, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNMP,
			    no_master,
			    no_master, "SNMP", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 161, 162, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XDMCP,
			    no_master,
			    no_master, "XDMCP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 177, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 177, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMB,
			    no_master,
			    no_master, "SMB", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SYSLOG,
			    no_master,
			    no_master, "Syslog", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 514, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 514, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCP,
    			    no_master,
    			    no_master, "DHCP", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 67, 68, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_POSTGRES,
			    no_master,
			    no_master, "PostgreSQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 5432, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MYSQL,
			    no_master,
			    no_master, "MySQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 3306, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,
			    no_master,
			    no_master, "Direct_Download_Link", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_APPLEJUICE,
    			    no_master,
    			    no_master, "AppleJuice", NDPI_PROTOCOL_CATEGORY_P2P,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECTCONNECT,
			    no_master,
			    no_master, "DirectConnect", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_SOCRATES,
			    no_master,
			    no_master, "Socrates", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VMWARE,
			    no_master,
			    no_master, "VMware", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 903, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 902, 903, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FILETOPIA,
    			    no_master,
    			    no_master, "Filetopia", NDPI_PROTOCOL_CATEGORY_P2P,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_KONTIKI,
			    no_master,
			    no_master, "Kontiki", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_OPENFT,
			    no_master,
			    no_master, "OpenFT", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FASTTRACK,
			    no_master,
			    no_master, "FastTrack", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_GNUTELLA,
			    no_master,
			    no_master, "Gnutella", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_EDONKEY,
			    no_master,
			    no_master, "eDonkey", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BITTORRENT,
    			    no_master,
    			    no_master, "BitTorrent", NDPI_PROTOCOL_CATEGORY_P2P,
    			    ndpi_build_default_ports(ports_a, 51413, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 6771, 51413, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEREDO,
    			    no_master,
    			    no_master, "Teredo", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 3544, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EPP,
			    no_master,
			    no_master, "EPP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_AVI,
			    no_master,
			    no_master, "AVI", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_FLASH,
			    no_master,
			    no_master, "Flash", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_OGG,
			    no_master,
			    no_master, "OggVorbis", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_MPEG,
    			    no_master,
    			    no_master, "MPEG", NDPI_PROTOCOL_CATEGORY_MEDIA,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_QUICKTIME,
			    no_master,
			    no_master, "QuickTime", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_REALMEDIA,
    			    no_master,
    			    no_master, "RealMedia", NDPI_PROTOCOL_CATEGORY_MEDIA,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_CONTENT_WINDOWSMEDIA,
			    no_master,
			    no_master, "WindowsMedia", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_MMS,
    			    no_master,
    			    no_master, "MMS", NDPI_PROTOCOL_CATEGORY_MEDIA,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_XBOX,
			    no_master,
			    no_master, "Xbox", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQ,
    			    no_master,
    			    no_master, "QQ", NDPI_PROTOCOL_CATEGORY_CHAT,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MOVE,
			    no_master,
			    no_master, "Move", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RTSP,
			    no_master,
			    no_master, "RTSP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 554, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 554, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ICECAST,
			    no_master,
			    no_master, "IceCast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPLIVE,
			    no_master,
			    no_master, "PPLive", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			    no_master,
			    no_master, "PPStream", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ZATTOO,
			    no_master,
			    no_master, "Zattoo", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SHOUTCAST,
			    no_master,
			    no_master, "ShoutCast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOPCAST,
			    no_master,
			    no_master, "Sopcast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVANTS,
			    no_master,
			    no_master, "Tvants", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVUPLAYER,
			    no_master,
			    no_master, "TVUplayer", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HTTP_DOWNLOAD,
			    no_master,
			    no_master, "HTTPDownload", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQLIVE,
			    no_master,
			    no_master, "QQLive", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_THUNDER,
			    no_master,
			    no_master, "Thunder", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOULSEEK,
			    no_master,
			    no_master, "Soulseek", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SSL, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSL_NO_CERT,
			    custom_master,
			    no_master, "SSL_No_Cert", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IRC,
			    no_master,
			    no_master, "IRC", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AYIYA,
			    no_master,
			    no_master, "Ayiya", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5072, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UNENCRYPED_JABBER,
    			    no_master,
    			    no_master, "Unencryped_Jabber", NDPI_PROTOCOL_CATEGORY_WEB,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OSCAR,
    			    no_master,
    			    no_master, "Oscar", NDPI_PROTOCOL_CATEGORY_CHAT,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_BATTLEFIELD,
    			    no_master,
    			    no_master, "BattleField", NDPI_PROTOCOL_CATEGORY_GAME,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QUAKE,
			    no_master,
			    no_master, "Quake", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_VRRP,
			    no_master,
			    no_master, "VRRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STEAM,
			    no_master,
			    no_master, "Steam", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HALFLIFE2,
			    no_master,
			    no_master, "HalfLife2", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			    no_master,
			    no_master, "WorldOfWarcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_SERVICE_HOTSPOT_SHIELD,
			    no_master,
			    no_master, "HotspotShield", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_TELNET,
			    no_master,
			    no_master, "Telnet", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 23, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SIP, custom_master[1] = NDPI_PROTOCOL_H323;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_STUN,
    			    no_master,
    			    custom_master, "STUN", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 3478, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_IP_IPSEC,
			    no_master,
			    no_master, "IPsec", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 500, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 500, 4500, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_GRE,
			    no_master,
			    no_master, "GRE", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMP,
			    no_master,
			    no_master, "ICMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IGMP,
			    no_master,
			    no_master, "IGMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_EGP,
			    no_master,
			    no_master, "EGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_SCTP,
			    no_master,
			    no_master, "SCTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_OSPF,
			    no_master,
			    no_master, "OSPF", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 2604, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IP_IN_IP,
			    no_master,
			    no_master, "IP_in_IP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTP,
    			    no_master,
    			    no_master, "RTP", NDPI_PROTOCOL_CATEGORY_VOIP,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RDP,
			    no_master,
			    no_master, "RDP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 3389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VNC,
			    no_master,
			    no_master, "VNC", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 5900, 5901, 5800, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PCANYWHERE,
			    no_master,
			    no_master, "PcAnywhere", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_VOICE,
    			    no_master,
    			    no_master, "WhatsAppVoice", NDPI_PROTOCOL_CATEGORY_VOIP,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SSL_NO_CERT, custom_master[1] = NDPI_PROTOCOL_UNKNOWN;
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_SSL,
			    no_master,
			    custom_master, "SSL", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 443, 3001 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSH,
			    no_master,
			    no_master, "SSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 22, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_USENET,
			    no_master,
			    no_master, "Usenet", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MGCP,
			    no_master,
			    no_master, "MGCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IAX,
    			    no_master,
    			    no_master, "IAX", NDPI_PROTOCOL_CATEGORY_VOIP,
    			    ndpi_build_default_ports(ports_a, 4569, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 4569, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AFP,
    			    no_master,
    			    no_master, "AFP", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_STEALTHNET,
			    no_master,
			    no_master, "Stealthnet", NDPI_PROTOCOL_CATEGORY_P2P,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AIMINI,
    			    no_master,
    			    no_master, "Aimini", NDPI_PROTOCOL_CATEGORY_P2P,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIP,
			    no_master,
			    no_master, "SIP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 5060, 5061, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5060, 5061, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TRUPHONE,
			    no_master,
			    no_master, "TruPhone", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMPV6,
			    no_master,
			    no_master, "ICMPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCPV6,
			    no_master,
			    no_master, "DHCPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ARMAGETRON,
    			    no_master,
    			    no_master, "Armagetron", NDPI_PROTOCOL_CATEGORY_GAME,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CROSSFIRE,
			    no_master,
			    no_master, "Crossfire", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DOFUS,
    			    no_master,
    			    no_master, "Dofus", NDPI_PROTOCOL_CATEGORY_GAME,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_FIESTA,
			    no_master,
			    no_master, "Fiesta", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FLORENSIA,
    			    no_master,
    			    no_master, "Florensia", NDPI_PROTOCOL_CATEGORY_GAME,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GUILDWARS,
			    no_master,
			    no_master, "Guildwars", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC,
			    no_master,
			    no_master, "HTTP_Application_ActiveSync", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KERBEROS,
			    no_master,
			    no_master, "Kerberos", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 88, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 88, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LDAP,
			    no_master,
			    no_master, "LDAP", NDPI_PROTOCOL_CATEGORY_SYSTEM,
			    ndpi_build_default_ports(ports_a, 389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 389, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MAPLESTORY,
			    no_master,
			    no_master, "MapleStory", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSSQL_TDS,
			    no_master,
			    no_master, "MsSQL-TDS", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 1433, 1434, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PPTP,
			    no_master,
			    no_master, "PPTP", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WARCRAFT3,
			    no_master,
			    no_master, "Warcraft3", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
			    no_master,
			    no_master, "WorldOfKungFu", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DCERPC,
    			    no_master,
    			    no_master, "DCE_RPC", NDPI_PROTOCOL_CATEGORY_RPC,
    			    ndpi_build_default_ports(ports_a, 135, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETFLOW,
			    no_master,
			    no_master, "NetFlow", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2055, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SFLOW,
			    no_master,
			    no_master, "sFlow", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6343, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_CONNECT,
			    no_master,
			    no_master, "HTTP_Connect", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_PROXY,
			    no_master,
			    no_master, "HTTP_Proxy", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 8080, 3128, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX,
    			    no_master,
    			    no_master, "Citrix", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 1494, 2598, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_PREPAID,
			    no_master,
			    no_master, "SkyFile_PrePaid", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_RUDICS,
			    no_master,
			    no_master, "SkyFile_Rudics", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYFILE_POSTPAID,
			    no_master,
			    no_master, "SkyFile_PostPaid", NDPI_PROTOCOL_CATEGORY_MAIL_SYNC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX_ONLINE,
			    no_master,
			    no_master, "Citrix_Online", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBEX,
			    no_master,
			    no_master, "Webex", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RADIUS,
			    no_master,
			    no_master, "Radius", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 1812, 1813, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1812, 1813, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMVIEWER,
    			    no_master,
    			    no_master, "TeamViewer", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LOTUS_NOTES,
    			    no_master,
    			    no_master, "LotusNotes", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
    			    ndpi_build_default_ports(ports_a, 1352, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SAP,
			    no_master,
			    no_master, "SAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 3201, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP,
    			    no_master,
    			    no_master, "GTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 2152, 2123, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UPNP,
			    no_master,
			    no_master, "UPnP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 1780, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1900, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TELEGRAM,
			    no_master,
			    no_master, "Telegram", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_QUIC,
			    no_master,
			    no_master, "QUIC", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 443, 80, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DROPBOX,
			    no_master,
			    no_master, "Dropbox", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 17500, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EAQ,
			    no_master,
			    no_master, "EAQ", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6000, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_SERVICE_KAKAOTALK_VOICE,
    			    no_master,
    			    no_master, "KakaoTalk_Voice", NDPI_PROTOCOL_CATEGORY_VOIP,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGTS,
			    no_master,
			    no_master, "MPEG_TS", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    /* http://en.wikipedia.org/wiki/Link-local_Multicast_Name_Resolution */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LLMNR,
			    no_master,
			    no_master, "LLMNR", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 5355, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5355, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_REMOTE_SCAN,
			    no_master,
			    no_master, "RemoteScan", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 6077, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6078, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_CONTENT_WEBM,
			    no_master,
			    no_master, "WebM", NDPI_PROTOCOL_CATEGORY_MEDIA, /* Courtesy of Shreeram Ramamoorthy Swaminathan <shreeram <shreeram1985@yahoo.co.in> */
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_H323,
			    no_master,
			    no_master,"H323", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 1719, 1720, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1719, 1720, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OPENVPN,
			    no_master,
			    no_master, "OpenVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 1194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NOE,
			    no_master,
			    no_master, "NOE", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_CISCOVPN,
    			    no_master,
    			    no_master, "CiscoVPN", NDPI_PROTOCOL_CATEGORY_VPN,
    			    ndpi_build_default_ports(ports_a, 10000, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 10000, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMSPEAK,
			    no_master,
			    no_master, "TeamSpeak", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKINNY,
			    no_master,
			    no_master, "CiscoSkinny", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 2000, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTCP,
			    no_master,
			    no_master, "RTCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RSYNC,
			    no_master,
			    no_master, "RSYNC", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
			    ndpi_build_default_ports(ports_a, 873, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ORACLE,
			    no_master,
			    no_master, "Oracle", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 1521, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CORBA,
    			    no_master,
    			    no_master, "Corba", NDPI_PROTOCOL_CATEGORY_RPC,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
    			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UBUNTUONE,
			    no_master,
			    no_master, "UbuntuONE", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHOIS_DAS,
			    no_master,
			    no_master, "Whois-DAS", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 43, 4343, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));         /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_COLLECTD,
    			    no_master,
    			    no_master, "Collectd", NDPI_PROTOCOL_CATEGORY_SYSTEM,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
    			    ndpi_build_default_ports(ports_b, 25826, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS,
			    no_master,
			    no_master, "SOCKS", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 1080, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 1080, 0, 0, 0, 0));     /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TFTP,
    			    no_master,
    			    no_master, "TFTP", NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER,
    			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
    			    ndpi_build_default_ports(ports_b, 69, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTMP,
			    no_master,
			    no_master, "RTMP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 1935, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));        /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PANDO,
			    no_master,
			    no_master, "Pando_Media_Booster", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));        /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEGACO,
			    no_master,
			    no_master, "Megaco", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 2944 , 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_REDIS,
			    no_master,
			    no_master, "Redis", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 6379, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZMQ,
			    no_master,
			    no_master, "ZeroMQ", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) );      /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VHUA,
			    no_master,
			    no_master, "VHUA", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 58267, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STARCRAFT,
			    no_master,
			    no_master, "Starcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 1119, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 1119, 0, 0, 0, 0));     /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_UBNTAC2,
			    no_master,
			    no_master, "UBNTAC2", NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),	      /* TCP */
			    ndpi_build_default_ports(ports_b, 10001, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MS_LYNC,
			    no_master,
			    no_master, "Lync", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),	      /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));	      /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VIBER,
			    no_master,
			    no_master, "Viber", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),	      /* TCP */
			    ndpi_build_default_ports(ports_b, 7985, 7987, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_COAP,
			    no_master,
			    no_master, "COAP", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 5683, 5684, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MQTT,
			    no_master,
			    no_master, "MQTT", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 1883, 8883, 0, 0, 0),  /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RX,
			    no_master,
			    no_master, "RX", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),        /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GIT,
			    no_master,
			    no_master, "Git", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			    ndpi_build_default_ports(ports_a, 9418, 0, 0, 0, 0),    /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DRDA,
			    no_master,
			    no_master, "DRDA", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),       /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_SERVICE_HANGOUT,
			    no_master,
			    no_master, "GoogleHangout", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_mod, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BJNP,
			    no_master,
			    no_master, "BJNP", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    

    /* calling function for host and content matched protocols */
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

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin /* network byte order */) {
  prefix_t prefix;
  patricia_node_t *node;

  /* Make sure all in network byte order otherwise compares wont work */
  fill_prefix_v4(&prefix, pin, 32, ((patricia_tree_t*)ndpi_struct->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_struct->protocols_ptree, &prefix);

  return(node ? node->value.user_value : NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************* */

/* u_int16_t ndpi_host_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t host /\* network byte order *\/) { */
/*   struct in_addr pin; */

/*   pin.s_addr = host; */

/*   return(ndpi_network_ptree_match(ndpi_struct, &pin)); */
/* } */

/* ******************************************* */

static u_int8_t tor_ptree_match(struct ndpi_detection_module_struct *ndpi_struct, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_struct, pin) == NDPI_PROTOCOL_TOR) ? 1 : 0);
}

/* ******************************************* */

u_int8_t ndpi_is_tor_flow(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->tcp != NULL) {
    if(packet->iph) {
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

    pin.s_addr = htonl(host_list[i].network);
    if((node = add_to_ptree(ptree, AF_INET, &pin, host_list[i].cidr /* bits */)) != NULL)
      node->value.user_value = host_list[i].value;
  }
}

/* ******************************************* */

static int ndpi_add_host_ip_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
					char *value, int protocol_id) {

  patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr = strrchr(value, '/');

  if (ptr)
  {
    ptr[0] = '\0';
    ptr++;
    if (atoi(ptr)>=0 && atoi(ptr)<=32)
      bits = atoi(ptr);
  }

  inet_pton(AF_INET, value, &pin);

  if((node = add_to_ptree(ndpi_struct->protocols_ptree, AF_INET, &pin, bits)) != NULL)
    node->value.user_value = protocol_id;

  return 0;
}

#endif

void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size)) { _ndpi_malloc = __ndpi_malloc; }

void set_ndpi_free(void  (*__ndpi_free)(void *ptr))       { _ndpi_free = __ndpi_free; }

void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str, ndpi_log_level_t log_level, const char * format, ...)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  va_list args;
  #define MAX_STR_LEN 120 
  char str[MAX_STR_LEN];
  va_start(args, format);
  vsprintf(str, format, args);
  va_end(args);
  
  if (ndpi_str != NULL) {
    char proto_name[64];
	snprintf(proto_name, sizeof(proto_name), "%s", ndpi_get_proto_name(ndpi_str, proto));
	printf("%s:%s:%u - Proto: %s, %s\n", ndpi_str->ndpi_debug_print_file, ndpi_str->ndpi_debug_print_function, ndpi_str->ndpi_debug_print_line, proto_name, str);
  } else {
    printf("Proto: %u, %s\n", proto, str);
  }
#endif
}

void set_ndpi_debug_function(struct ndpi_detection_module_struct *ndpi_str, ndpi_debug_function_ptr ndpi_debug_printf) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    ndpi_str->ndpi_debug_printf = ndpi_debug_printf;
#endif
}

/* ******************************************************************** */

struct ndpi_detection_module_struct *ndpi_init_detection_module(void) {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));

  if(ndpi_str == NULL) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    NDPI_LOG(0, ndpi_str, NDPI_LOG_DEBUG, "ndpi_init_detection_module initial malloc failed for ndpi_str\n");
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */
    return NULL;
  }
  memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr)ndpi_debug_printf);
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */

  if((ndpi_str->protocols_ptree = ndpi_New_Patricia(32 /* IPv4 */)) != NULL)
    ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, host_protocol_list);

  NDPI_BITMASK_RESET(ndpi_str->detection_bitmask);
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_str->user_data = NULL;
#endif

  ndpi_str->ticks_per_second = 1000; /* ndpi_str->ticks_per_second */
  ndpi_str->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
  ndpi_str->directconnect_connection_ip_tick_timeout =
    NDPI_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT * ndpi_str->ticks_per_second;

  ndpi_str->rtsp_connection_timeout = NDPI_RTSP_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->tvants_connection_timeout = NDPI_TVANTS_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->irc_timeout = NDPI_IRC_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->gnutella_timeout = NDPI_GNUTELLA_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;

  ndpi_str->battlefield_timeout = NDPI_BATTLEFIELD_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;

  ndpi_str->thunder_timeout = NDPI_THUNDER_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->yahoo_detect_http_connections = NDPI_YAHOO_DETECT_HTTP_CONNECTIONS;

  ndpi_str->yahoo_lan_video_timeout = NDPI_YAHOO_LAN_VIDEO_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->zattoo_connection_timeout = NDPI_ZATTOO_CONNECTION_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->jabber_stun_timeout = NDPI_JABBER_STUN_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->jabber_file_transfer_timeout = NDPI_JABBER_FT_TIMEOUT * ndpi_str->ticks_per_second;
  ndpi_str->soulseek_connection_ip_tick_timeout = NDPI_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT * ndpi_str->ticks_per_second;

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

/* Wrappers */
void* ndpi_init_automa(void) {
  return(ac_automata_init(ac_match_handler));
}

int ndpi_add_string_to_automa(void *_automa, char *str) { 
  AC_PATTERN_t ac_pattern;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;

  if(automa == NULL) return(-1);

  ac_pattern.astring = str;
  ac_pattern.rep.number = 1; /* Dummy */
  ac_pattern.length = strlen(ac_pattern.astring);
  return(ac_automata_add(automa, &ac_pattern) == ACERR_SUCCESS ? 0 : -1);
}

void ndpi_free_automa(void *_automa)     { ac_automata_release((AC_AUTOMATA_t*)_automa);  }
void ndpi_finalize_automa(void *_automa) { ac_automata_finalize((AC_AUTOMATA_t*)_automa); }

/* ****************************************************** */

int ndpi_match_string(void *_automa, char *string_to_match) {
  int matching_protocol_id = NDPI_PROTOCOL_UNKNOWN;
  AC_TEXT_t ac_input_text;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;
  
  if((automa == NULL) 
     || (string_to_match == NULL)
     || (string_to_match[0] == '\0'))
    return(-2);

  ac_input_text.astring = string_to_match, ac_input_text.length = strlen(string_to_match);
  ac_automata_search(automa, &ac_input_text, (void*)&matching_protocol_id);
  ac_automata_reset(automa);

  return(matching_protocol_id > 0 ? 0 : -1);
}

/* *********************************************** */

static void free_ptree_data(void *data) { ; }

/* ****************************************************** */

void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_struct) {
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

static ndpi_default_ports_tree_node_t* ndpi_get_guessed_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
								    u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  const void *ret;
  ndpi_default_ports_tree_node_t node;
  
  if(sport && dport) {
    int low  = ndpi_min(sport, dport);
    int high = ndpi_max(sport, dport);

    node.default_port = low; /* Check server port first */
    ret = ndpi_tfind(&node,
		     (proto == IPPROTO_TCP) ? (void*)&ndpi_struct->tcpRoot : (void*)&ndpi_struct->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = high;
      ret = ndpi_tfind(&node,
		       (proto == IPPROTO_TCP) ? (void*)&ndpi_struct->tcpRoot : (void*)&ndpi_struct->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret) return(*(ndpi_default_ports_tree_node_t**)ret);
  }

  return(NULL);
}

/* ****************************************************** */

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_struct,
				 u_int8_t proto, u_int16_t sport, u_int16_t dport,
				 u_int8_t *user_defined_proto) {

  *user_defined_proto = 0; /* Default */
  if(sport && dport) {
    ndpi_default_ports_tree_node_t *found = ndpi_get_guessed_protocol_id(ndpi_struct, proto, sport, dport);

    if(found != NULL) {
      *user_defined_proto = found->customUserProto;
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

u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_mod) {
  return(ndpi_mod->ndpi_num_supported_protocols);
}

/* ******************************************************************** */

#ifdef WIN32
char * strsep(char **sp, char *sep)
{
  char *p, *s;
  if (sp == NULL || *sp == NULL || **sp == '\0') return(NULL);
  s = *sp;
  p = s + strcspn(s, sep);
  if (*p != '\0') *p++ = '\0';
  *sp = p;
  return(s);
}
#endif

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

  for(i=0; proto[i] != '\0'; i++) {
    switch(proto[i]) {
    case '/':
    case '&':
    case '^':
    case ':':
    case ';':
    case '\'':
    case '"':
    case ' ':
      proto[i] = '_';
      break;
    }
  }

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
			      NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, /* TODO add protocol category support in rules */
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
    int is_tcp = 0, is_udp = 0, is_ip = 0;

    if(strncmp(attr, "tcp:", 4) == 0)
      is_tcp = 1, value = &attr[4];
    else if(strncmp(attr, "udp:", 4) == 0)
      is_udp = 1, value = &attr[4];
    else if(strncmp(attr, "ip:", 3) == 0)
      is_ip = 1, value = &attr[3];
    else if(strncmp(attr, "host:", 5) == 0) {
      /* host:"<value>",host:"<value>",.....@<subproto> */
      value = &attr[5];
      if(value[0] == '"') value++; /* remove leading " */
      if(value[strlen(value)-1] == '"') value[strlen(value)-1] = '\0'; /* remove trailing " */
    }

    if(is_tcp || is_udp) {
      if(sscanf(value, "%u-%u", (u_int32_t *)&range.port_low, (u_int32_t *)&range.port_high) != 2)
        range.port_low = range.port_high = atoi(&elem[4]);
      if(do_add)
        addDefaultPort(&range, def, 1 /* Custom user proto */, is_tcp ? &ndpi_mod->tcpRoot : &ndpi_mod->udpRoot);
      else
        removeDefaultPort(&range, def, is_tcp ? &ndpi_mod->tcpRoot : &ndpi_mod->udpRoot);
    } else if(is_ip) {
#ifdef NDPI_PROTOCOL_TOR
        ndpi_add_host_ip_subprotocol(ndpi_mod, value, subprotocol_id);
#endif
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
#ifdef DEBUG
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,"[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] protocol_id=%u\n", label, idx, ndpi_protocol_id);
#endif

    if(ndpi_struct->proto_defaults[ndpi_protocol_id].protoIdx != 0)
      printf("[NDPI] Internal error: protocol %s/%u has been already registered\n", label, ndpi_protocol_id);
    else {
#ifdef DEBUG
      printf("[NDPI] Adding %s with protocol id %d\n", label, ndpi_protocol_id);
#endif
    }

    /*
      Set function and index protocol within proto_default strcuture for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
    ndpi_struct->proto_defaults[ndpi_protocol_id].protoIdx = idx;
    ndpi_struct->proto_defaults[ndpi_protocol_id].func = ndpi_struct->callback_buffer[idx].func = func;

    /*
      Set ndpi_selection_bitmask for protocol
    */
    ndpi_struct->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

    /*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
    if(b_save_bitmask_unknow) NDPI_SAVE_AS_BITMASK(ndpi_struct->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
    if(b_add_detection_bitmask) NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_struct->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

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

  /* HTTP */
  init_http_dissector(ndpi_struct, &a, detection_bitmask);

  /* STARCRAFT */
  init_starcraft_dissector(ndpi_struct, &a, detection_bitmask);

  /* SSL */
  init_ssl_dissector(ndpi_struct, &a, detection_bitmask);

  /* STUN */
  init_stun_dissector(ndpi_struct, &a, detection_bitmask);

  /* RTP */
  init_rtp_dissector(ndpi_struct, &a, detection_bitmask);

  /* RTSP */
  init_rtsp_dissector(ndpi_struct, &a, detection_bitmask);

  /* RDP */
  init_rdp_dissector(ndpi_struct, &a, detection_bitmask);

  /* SIP */
  init_sip_dissector(ndpi_struct, &a, detection_bitmask);

  /* HEP */
  init_hep_dissector(ndpi_struct, &a, detection_bitmask);

  /* Teredo */
  init_teredo_dissector(ndpi_struct, &a, detection_bitmask);

  /* EDONKEY */
  init_edonkey_dissector(ndpi_struct, &a, detection_bitmask);

  /* FASTTRACK */
  init_fasttrack_dissector(ndpi_struct, &a, detection_bitmask);

  /* GNUTELLA */
  init_gnutella_dissector(ndpi_struct, &a, detection_bitmask);

  /* DIRECTCONNECT */
  init_directconnect_dissector(ndpi_struct, &a, detection_bitmask);

  /* MSN */
  init_msn_dissector(ndpi_struct, &a, detection_bitmask);

  /* YAHOO */
  init_yahoo_dissector(ndpi_struct, &a, detection_bitmask);

  /* OSCAR */
  init_oscar_dissector(ndpi_struct, &a, detection_bitmask);

  /* APPLEJUICE */
  init_applejuice_dissector(ndpi_struct, &a, detection_bitmask);

  /* SOULSEEK */
  init_soulseek_dissector(ndpi_struct, &a, detection_bitmask);

  /* SOCKS */
  init_socks_dissector(ndpi_struct, &a, detection_bitmask);

  /* IRC */
  init_irc_dissector(ndpi_struct, &a, detection_bitmask);

  /* JABBER */
  init_jabber_dissector(ndpi_struct, &a, detection_bitmask);

  /* MAIL_POP */
  init_mail_pop_dissector(ndpi_struct, &a, detection_bitmask);

  /* MAIL_IMAP */
  init_mail_imap_dissector(ndpi_struct, &a, detection_bitmask);

  /* MAIL_SMTP */
  init_mail_smtp_dissector(ndpi_struct, &a, detection_bitmask);

  /* USENET */
  init_usenet_dissector(ndpi_struct, &a, detection_bitmask);

  /* DNS */
  init_dns_dissector(ndpi_struct, &a, detection_bitmask);

  /* FILETOPIA */
  init_filetopia_dissector(ndpi_struct, &a, detection_bitmask);

  /* VMWARE */
  init_vmware_dissector(ndpi_struct, &a, detection_bitmask);

  /* MMS */
  init_mms_dissector(ndpi_struct, &a, detection_bitmask);

  /* NON_TCP_UDP */
  init_non_tcp_udp_dissector(ndpi_struct, &a, detection_bitmask);

  /* TVANTS */
  init_tvants_dissector(ndpi_struct, &a, detection_bitmask);

  /* SOPCAST */
  init_sopcast_dissector(ndpi_struct, &a, detection_bitmask);

  /* TVUPLAYER */
  init_tvuplayer_dissector(ndpi_struct, &a, detection_bitmask);

  /* PPSTREAM */
  init_ppstream_dissector(ndpi_struct, &a, detection_bitmask);

  /* PPLIVE */
  init_pplive_dissector(ndpi_struct, &a, detection_bitmask);

  /* IAX */
  init_iax_dissector(ndpi_struct, &a, detection_bitmask);

  /* MGPC */
  init_mgpc_dissector(ndpi_struct, &a, detection_bitmask);

  /* ZATTOO */
  init_zattoo_dissector(ndpi_struct, &a, detection_bitmask);

  /* QQ */
  init_qq_dissector(ndpi_struct, &a, detection_bitmask);

  /* SSH */
  init_ssh_dissector(ndpi_struct, &a, detection_bitmask);

  /* AYIYA */
  init_ayiya_dissector(ndpi_struct, &a, detection_bitmask);

  /* THUNDER */
  init_thunder_dissector(ndpi_struct, &a, detection_bitmask);

  /* VNC */
  init_vnc_dissector(ndpi_struct, &a, detection_bitmask);

  /* TEAMVIEWER */
  init_teamviewer_dissector(ndpi_struct, &a, detection_bitmask);

  /* DHCP */
  init_dhcp_dissector(ndpi_struct, &a, detection_bitmask);

  /* SOCRATES */
  init_socrates_dissector(ndpi_struct, &a, detection_bitmask);

  /* STEAM */
  init_steam_dissector(ndpi_struct, &a, detection_bitmask);

  /* HALFLIFE2 */
  init_halflife2_dissector(ndpi_struct, &a, detection_bitmask);

  /* XBOX */
  init_xbox_dissector(ndpi_struct, &a, detection_bitmask);

  /* HTTP_APPLICATION_ACTIVESYNC */
  init_http_activesync_dissector(ndpi_struct, &a, detection_bitmask);

  /* SMB */
  init_smb_dissector(ndpi_struct, &a, detection_bitmask);

  /* TELNET */
  init_telnet_dissector(ndpi_struct, &a, detection_bitmask);

  /* NTP */
  init_ntp_dissector(ndpi_struct, &a, detection_bitmask);

  /* NFS */
  init_nfs_dissector(ndpi_struct, &a, detection_bitmask);

  /* SSDP */
  init_ssdp_dissector(ndpi_struct, &a, detection_bitmask);

  /* WORLD_OF_WARCRAFT */
  init_world_of_warcraft_dissector(ndpi_struct, &a, detection_bitmask);

  /* POSTGRES */
  init_postgres_dissector(ndpi_struct, &a, detection_bitmask);

  /* MYSQL */
  init_mysql_dissector(ndpi_struct, &a, detection_bitmask);

  /* BGP */
  init_bgp_dissector(ndpi_struct, &a, detection_bitmask);

  /* QUAKE */
  init_quake_dissector(ndpi_struct, &a, detection_bitmask);

  /* BATTLEFIELD */
  init_battlefield_dissector(ndpi_struct, &a, detection_bitmask);

  /* PCANYWHERE */
  init_pcanywhere_dissector(ndpi_struct, &a, detection_bitmask);

  /* SNMP */
  init_snmp_dissector(ndpi_struct, &a, detection_bitmask);

  /* KONTIKI */
  init_kontiki_dissector(ndpi_struct, &a, detection_bitmask);

  /* ICECAST */
  init_icecast_dissector(ndpi_struct, &a, detection_bitmask);

  /* SHOUTCAST */
  init_shoutcast_dissector(ndpi_struct, &a, detection_bitmask);

  /* KERBEROS */
  init_kerberos_dissector(ndpi_struct, &a, detection_bitmask);

  /* OPENFT */
  init_openft_dissector(ndpi_struct, &a, detection_bitmask);

  /* SYSLOG */
  init_syslog_dissector(ndpi_struct, &a, detection_bitmask);

  /* DIRECT_DOWNLOAD_LINK */
  init_directdownloadlink_dissector(ndpi_struct, &a, detection_bitmask);

  /* NETBIOS */
  init_netbios_dissector(ndpi_struct, &a, detection_bitmask);

  /* MDNS */
  init_mdns_dissector(ndpi_struct, &a, detection_bitmask);

  /* IPP */
  init_ipp_dissector(ndpi_struct, &a, detection_bitmask);

  /* LDAP */
  init_ldap_dissector(ndpi_struct, &a, detection_bitmask);

  /* WARCRAFT3 */
  init_warcraft3_dissector(ndpi_struct, &a, detection_bitmask);

  /* XDMCP */
  init_xdmcp_dissector(ndpi_struct, &a, detection_bitmask);

  /* TFTP */
  init_tftp_dissector(ndpi_struct, &a, detection_bitmask);

  /* MSSQL_TDS */
  init_mssql_tds_dissector(ndpi_struct, &a, detection_bitmask);

  /* PPTP */
  init_pptp_dissector(ndpi_struct, &a, detection_bitmask);

  /* STEALTHNET */
  init_stealthnet_dissector(ndpi_struct, &a, detection_bitmask);

  /* DHCPV6 */
  init_dhcpv6_dissector(ndpi_struct, &a, detection_bitmask);

  /* AFP */
  init_afp_dissector(ndpi_struct, &a, detection_bitmask);

  /* AIMINI */
  init_aimini_dissector(ndpi_struct, &a, detection_bitmask);

  /* FLORENSIA */
  init_florensia_dissector(ndpi_struct, &a, detection_bitmask);

  /* MAPLESTORY */
  init_maplestory_dissector(ndpi_struct, &a, detection_bitmask);

  /* DOFUS */
  init_dofus_dissector(ndpi_struct, &a, detection_bitmask);

  /* WORLD_OF_KUNG_FU */
  init_world_of_kung_fu_dissector(ndpi_struct, &a, detection_bitmask);

  /* FIESTA */
  init_fiesta_dissector(ndpi_struct, &a, detection_bitmask);

  /* CROSSIFIRE */
  init_crossfire_dissector(ndpi_struct, &a, detection_bitmask);

  /* GUILDWARS */
  init_guildwars_dissector(ndpi_struct, &a, detection_bitmask);

  /* ARMAGETRON */
  init_armagetron_dissector(ndpi_struct, &a, detection_bitmask);

  /* DROPBOX */
  init_dropbox_dissector(ndpi_struct, &a, detection_bitmask);

  /* SPOTIFY */
  init_spotify_dissector(ndpi_struct, &a, detection_bitmask);

  /* RADIUS */
  init_radius_dissector(ndpi_struct, &a, detection_bitmask);

  /* CITRIX */
  init_citrix_dissector(ndpi_struct, &a, detection_bitmask);

  /* LOTUS_NOTES */
  init_lotus_notes_dissector(ndpi_struct, &a, detection_bitmask);

  /* GTP */
  init_gtp_dissector(ndpi_struct, &a, detection_bitmask);

  /* DCERPC */
  init_dcerpc_dissector(ndpi_struct, &a, detection_bitmask);

  /* NETFLOW */
  init_netflow_dissector(ndpi_struct, &a, detection_bitmask);

  /* SFLOW */
  init_sflow_dissector(ndpi_struct, &a, detection_bitmask);

  /* H323 */
  init_h323_dissector(ndpi_struct, &a, detection_bitmask);

  /* OPENVPN */
  init_openvpn_dissector(ndpi_struct, &a, detection_bitmask);

  /* NOE */
  init_noe_dissector(ndpi_struct, &a, detection_bitmask);

  /* CISCOVPN */
  init_ciscovpn_dissector(ndpi_struct, &a, detection_bitmask);

  /* TEAMSPEAK */
  init_teamspeak_dissector(ndpi_struct, &a, detection_bitmask);

  /* VIBER */
  init_viber_dissector(ndpi_struct, &a, detection_bitmask);

  /* TOR */
  init_tor_dissector(ndpi_struct, &a, detection_bitmask);

  /* SKINNY */
  init_skinny_dissector(ndpi_struct, &a, detection_bitmask);

  /* RTCP */
  init_rtcp_dissector(ndpi_struct, &a, detection_bitmask);

  /* RSYNC */
  init_rsync_dissector(ndpi_struct, &a, detection_bitmask);

  /* WHOIS_DAS */
  init_whois_das_dissector(ndpi_struct, &a, detection_bitmask);

  /* ORACLE */
  init_oracle_dissector(ndpi_struct, &a, detection_bitmask);

  /* CORBA */
  init_corba_dissector(ndpi_struct, &a, detection_bitmask);

  /* RTMP */
  init_rtmp_dissector(ndpi_struct, &a, detection_bitmask);

  /* FTP_CONTROL */
  init_ftp_control_dissector(ndpi_struct, &a, detection_bitmask);

  /* FTP_DATA */
  init_ftp_data_dissector(ndpi_struct, &a, detection_bitmask);

  /* PANDO */
  init_pando_dissector(ndpi_struct, &a, detection_bitmask);

  /* MEGACO */
  init_megaco_dissector(ndpi_struct, &a, detection_bitmask);

  /* REDIS */
  init_redis_dissector(ndpi_struct, &a, detection_bitmask);

  /* VHUA */
  init_vhua_dissector(ndpi_struct, &a, detection_bitmask);

  /* ZMQ */
  init_zmq_dissector(ndpi_struct, &a, detection_bitmask);

  /* TELEGRAM */
  init_telegram_dissector(ndpi_struct, &a, detection_bitmask);

  /* QUIC */
  init_quic_dissector(ndpi_struct, &a, detection_bitmask);

  /* EAQ */
  init_eaq_dissector(ndpi_struct, &a, detection_bitmask);

  /* KAKAOTALK_VOICE */
  init_kakaotalk_voice_dissector(ndpi_struct, &a, detection_bitmask);

  /* MPEGTS */
  init_mpegts_dissector(ndpi_struct, &a, detection_bitmask);

  /* UBNTAC2 */
  init_ubntac2_dissector(ndpi_struct, &a, detection_bitmask);

  /* COAP */
  init_coap_dissector(ndpi_struct, &a, detection_bitmask);

  /* MQTT */
  init_mqtt_dissector(ndpi_struct, &a, detection_bitmask);

  /* RX */
  init_rx_dissector(ndpi_struct, &a, detection_bitmask);

  /* GIT */
  init_git_dissector(ndpi_struct, &a, detection_bitmask);

  /* HANGOUT */
  init_hangout_dissector(ndpi_struct, &a, detection_bitmask);

  /* DRDA */
  init_drda_dissector(ndpi_struct, &a, detection_bitmask);
  
  /*** Put false-positive sensitive protocols at the end ***/

  /* SKYPE */
  init_skype_dissector(ndpi_struct, &a, detection_bitmask);

  /* BITTORRENT */
  init_bittorrent_dissector(ndpi_struct, &a, detection_bitmask);

  /* BJNP */
  init_bjnp_dissector(ndpi_struct, &a, detection_bitmask);

  /* ----------------------------------------------------------------- */


  ndpi_struct->callback_buffer_size = a;

  NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG,
	   "callback_buffer_size is %u\n", ndpi_struct->callback_buffer_size);

  /* now build the specific buffer for tcp, udp and non_tcp_udp */
  ndpi_struct->callback_buffer_size_tcp_payload = 0;
  ndpi_struct->callback_buffer_size_tcp_no_payload = 0;
  for(a = 0; a < ndpi_struct->callback_buffer_size; a++) {
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
  for(a = 0; a < ndpi_struct->callback_buffer_size; a++) {
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
  for(a = 0; a < ndpi_struct->callback_buffer_size; a++) {
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
static int ndpi_handle_ipv6_extension_headers(struct ndpi_detection_module_struct *ndpi_struct, const u_int8_t ** l4ptr, u_int16_t * l4len, u_int8_t * nxt_hdr)
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
					       const u_int8_t * l3, u_int16_t l3_len,
					       const u_int8_t ** l4_return, u_int16_t * l4_len_return,
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
  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->ip6_ctlun.ip6_un1.ip6_un1_plen)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->ip6_ctlun.ip6_un1.ip6_un1_plen);
    l4protocol = iph_v6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

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

void ndpi_apply_flow_protocol_to_packet(struct ndpi_flow_struct *flow,
					struct ndpi_packet_struct *packet)
{
  memcpy(&packet->detected_protocol_stack, &flow->detected_protocol_stack, sizeof(packet->detected_protocol_stack));
  memcpy(&packet->protocol_stack_info, &flow->protocol_stack_info, sizeof(packet->protocol_stack_info));
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

  if(decaps_iph && decaps_iph->version == 4 && decaps_iph->ihl >= 5) {
    NDPI_LOG(NDPI_PROTOCOL_UNKNOWN, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(decaps_iph && decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
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

  u_int8_t proxy_enabled = 0;

  packet->tcp_retransmission = 0, packet->packet_direction = 0;

  if(ndpi_struct->direction_detect_disable) {
    packet->packet_direction = flow->packet_direction;
  } else {
    if(iph != NULL && iph->saddr < iph->daddr)
      packet->packet_direction = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if(iphv6 != NULL && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->ip6_src, &iphv6->ip6_dst) != 0)
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
      if(((u_int32_t)(ntohl(tcph->seq) - flow->next_tcp_seq_nr[packet->packet_direction])) >
	 ndpi_struct->tcp_max_retransmission_window_size) {

	packet->tcp_retransmission = 1;

	/* CHECK IF PARTIAL RETRY IS HAPPENING */
	if((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) < packet->payload_packet_len)) {
	  /* num_retried_bytes actual_payload_len hold info about the partial retry
	     analyzer which require this info can make use of this info
	     Other analyzer can use packet->payload_packet_len */
	  packet->num_retried_bytes = (u_int16_t)(flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq));
	  packet->actual_payload_len = packet->payload_packet_len - packet->num_retried_bytes;
	  flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	}
      }

      /* normal path
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

  for(a = 0; a < ndpi_struct->callback_buffer_size_non_tcp_udp; a++) {
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

  for(a = 0; a < ndpi_struct->callback_buffer_size_udp; a++) {
    if((func != ndpi_struct->callback_buffer_udp[a].func)
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
       && (ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_struct->callback_buffer[proto_index].ndpi_selection_bitmask) {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_struct->proto_defaults[flow->guessed_protocol_id].func != NULL))
	ndpi_struct->proto_defaults[flow->guessed_protocol_id].func(ndpi_struct, flow),
	  func = ndpi_struct->proto_defaults[flow->guessed_protocol_id].func;
    }

    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      for(a = 0; a < ndpi_struct->callback_buffer_size_tcp_payload; a++) {
        if((func != ndpi_struct->callback_buffer_tcp_payload[a].func)
	   && (ndpi_struct->callback_buffer_tcp_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_struct->callback_buffer_tcp_payload[a].ndpi_selection_bitmask
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

    for(a = 0; a < ndpi_struct->callback_buffer_size_tcp_no_payload; a++) {
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

/* ********************************************************************************* */

ndpi_protocol ndpi_l4_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
					       struct ndpi_flow_struct *flow,
					       const struct ndpi_iphdr *iph,
					       struct ndpi_ipv6hdr *iph6,
					       struct ndpi_tcphdr *tcp,
					       struct ndpi_udphdr *udp,
					       u_int8_t src_to_dst_direction,
					       u_int8_t l4_proto,
					       struct ndpi_id_struct *src,
					       u_int16_t sport,
				       struct ndpi_id_struct *dst,
					       u_int16_t dport,
					       const u_int64_t current_tick_l,
					       u_int8_t *payload, u_int16_t payload_len) {
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t a;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if(flow == NULL)
    return(ret);

  if(payload_len == 0) return(ret);

  flow->packet.tcp = tcp, flow->packet.udp = udp;
  flow->packet.payload = payload, flow->packet.payload_packet_len = payload_len;

  flow->packet.tick_timestamp_l = current_tick_l;
  flow->packet.tick_timestamp = (u_int32_t)current_tick_l/1000;

  if(flow) {
    ndpi_apply_flow_protocol_to_packet(flow, &flow->packet);
  } else {
    ndpi_int_reset_packet_protocol(&flow->packet);
  }

  if(flow->server_id == NULL) flow->server_id = dst; /* Default */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    goto ret_protocols;

  if(src_to_dst_direction)
    flow->src = src, flow->dst = dst;
  else
    flow->src = dst, flow->dst = src;

  ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
  if((flow->packet.iph = iph) != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if((flow->packet.iphv6 = iph6) != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  ndpi_connection_tracking(ndpi_struct, flow);

  if(flow->packet.tcp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(flow->packet.udp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(flow->packet.payload_packet_len != 0) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
  }

  if(flow->packet.tcp_retransmission == 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;

  flow->packet.l4_protocol = l4_proto, flow->packet.packet_direction = src_to_dst_direction;

  if((!flow->protocol_id_already_guessed)
     && (
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	 flow->packet.iphv6 ||
#endif
	 flow->packet.iph)) {
    u_int8_t user_defined_proto;
    
    flow->protocol_id_already_guessed = 1,
      flow->guessed_protocol_id = (int16_t)ndpi_guess_protocol_id(ndpi_struct, l4_proto, sport, dport, &user_defined_proto);

    if(user_defined_proto && (flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)) {
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN, ret.protocol = flow->guessed_protocol_id;
      return(ret);
    }
      
    if(flow->packet.iph) {
      if((flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_struct, (struct in_addr *)&flow->packet.iph->saddr)) == NDPI_PROTOCOL_UNKNOWN)
        flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_struct, (struct in_addr *)&flow->packet.iph->daddr);
    }
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

 ret_protocols:
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
    ret.master_protocol = flow->detected_protocol_stack[1], ret.protocol = flow->detected_protocol_stack[0];

    if(ret.protocol == ret.master_protocol)
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  } else
    ret.protocol = flow->detected_protocol_stack[0];

  return(ret);
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow) {
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if(flow == NULL) return(ret);

  /* TODO: add the remaining stage_XXXX protocols */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    if(flow->http_detected)
      ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_HTTP, NDPI_PROTOCOL_UNKNOWN);
    else if((flow->packet.l4_protocol == IPPROTO_TCP) && (flow->l4.tcp.ssl_stage > 1)) {
      if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	ndpi_int_change_protocol(ndpi_struct, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_SSL);
      else
	ndpi_int_change_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SSL, NDPI_PROTOCOL_UNKNOWN);
    } else {
      flow->detected_protocol_stack[1] = flow->guessed_protocol_id, flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;

      if(flow->detected_protocol_stack[1] == flow->detected_protocol_stack[0])
	flow->detected_protocol_stack[1] = NDPI_PROTOCOL_UNKNOWN;
    }
  }

  ret.master_protocol = flow->detected_protocol_stack[1], ret.protocol = flow->detected_protocol_stack[0];
  return(ret);
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    const unsigned char *packet,
					    const unsigned short packetlen,
					    const u_int64_t current_tick_l,
					    struct ndpi_id_struct *src,
					    struct ndpi_id_struct *dst)
{
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t a;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if(flow == NULL)
    return(ret);

  if(flow->server_id == NULL) flow->server_id = dst; /* Default */
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    goto ret_protocols;

  /* need at least 20 bytes for ip header */
  if(packetlen < 20) {
    /* reset protocol which is normally done in init_packet_header */
    ndpi_int_reset_packet_protocol(&flow->packet);
    return(ret);
  }

  flow->packet.tick_timestamp_l = current_tick_l;
  flow->packet.tick_timestamp = (u_int32_t)current_tick_l/1000;

  /* parse packet */
  flow->packet.iph = (struct ndpi_iphdr *)packet;
  /* we are interested in ipv4 packet */

  if(ndpi_init_packet_header(ndpi_struct, flow, packetlen) != 0)
    return(ret);

  /* detect traffic for tcp or udp only */

  flow->src = src, flow->dst = dst;

  ndpi_connection_tracking(ndpi_struct, flow);

  /* build ndpi_selection packet bitmask */
  ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
  if(flow->packet.iph != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

  if(flow->packet.tcp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(flow->packet.udp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(flow->packet.payload_packet_len != 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;

  if(flow->packet.tcp_retransmission == 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iphv6 != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if((!flow->protocol_id_already_guessed)
     && (
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	 flow->packet.iphv6 ||
#endif
	 flow->packet.iph)) {
    u_int16_t sport, dport;
    u_int8_t protocol;
    u_int8_t user_defined_proto;

    flow->protocol_id_already_guessed = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if(flow->packet.iphv6 != NULL) {
      protocol = flow->packet.iphv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    } else
#endif
      {
	protocol = flow->packet.iph->protocol;
      }

    if(flow->packet.udp) sport = ntohs(flow->packet.udp->source), dport = ntohs(flow->packet.udp->dest);
    else if(flow->packet.tcp) sport = ntohs(flow->packet.tcp->source), dport = ntohs(flow->packet.tcp->dest);
    else sport = dport = 0;

    flow->guessed_protocol_id = (int16_t)ndpi_guess_protocol_id(ndpi_struct, protocol, sport, dport, &user_defined_proto);

    if(user_defined_proto && (flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)) {
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN, ret.protocol = flow->guessed_protocol_id;
      return(ret);
    }

    if(flow->packet.iph) {
      if((flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_struct, (struct in_addr *)&flow->packet.iph->saddr)) == NDPI_PROTOCOL_UNKNOWN)
	flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_struct, (struct in_addr *)&flow->packet.iph->daddr);
    }
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

 ret_protocols:
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
    ret.master_protocol = flow->detected_protocol_stack[1], ret.protocol = flow->detected_protocol_stack[0];

    if(ret.protocol == ret.master_protocol)
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  } else
    ret.protocol = flow->detected_protocol_stack[0];

  return(ret);
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
     || (packet->payload == NULL)
     || (end == 0)
     )
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; a < end-1 /* This because get_u_int16_t(packet->payload, a) reads 2 bytes */; a++) {
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
	 && (memcmp(packet->line[packet->parsed_lines].ptr, "Content-Type: ", 14) == 0
	     || memcmp(packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
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

  for(a = 0; a < end; a++) {
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

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t upper_detected_protocol,
				u_int16_t lower_detected_protocol)
{
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  ndpi_int_change_protocol(ndpi_struct, flow, upper_detected_protocol, lower_detected_protocol);

  if(src != NULL) {
    NDPI_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, upper_detected_protocol);

    if(lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN)
      NDPI_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, lower_detected_protocol);
  }

 if(dst != NULL) {
    NDPI_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, upper_detected_protocol);

    if(lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN)
      NDPI_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, lower_detected_protocol);
  }
}

u_int16_t ndpi_get_flow_masterprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow) {
  return(flow->detected_protocol_stack[1]);
}

void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   u_int16_t upper_detected_protocol,
				   u_int16_t lower_detected_protocol) {
  if(!flow) return;

  flow->detected_protocol_stack[0] = upper_detected_protocol, flow->detected_protocol_stack[1] = lower_detected_protocol;
}

void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t upper_detected_protocol,
				     u_int16_t lower_detected_protocol) {
  struct ndpi_packet_struct *packet = &flow->packet;
  /* NOTE: everything below is identically to change_flow_protocol
   *        except flow->packet If you want to change something here,
   *        don't! Change it for the flow function and apply it here
   *        as well */

  if(!packet)
    return;

  packet->detected_protocol_stack[0] = upper_detected_protocol, packet->detected_protocol_stack[1] = lower_detected_protocol;
}

/* /\* */
/*  * this function checks whether a protocol can be found in the */
/*  * history. Actually it accesses the packet stack since this is what */
/*  * leaves the library but it could also use the flow stack. */
/*  *\/ */
/* u_int8_t ndpi_detection_flow_protocol_history_contains_protocol(struct ndpi_detection_module_struct * ndpi_struct, */
/* 								struct ndpi_flow_struct *flow, */
/* 								u_int16_t protocol_id) { */
/*   u_int8_t a; */
/*   struct ndpi_packet_struct *packet = &flow->packet; */

/*   if(!packet) */
/*     return 0; */

/*   for(a = 0; a < NDPI_PROTOCOL_HISTORY_SIZE; a++) { */
/*     if(packet->detected_protocol_stack[a] == protocol_id) */
/*       return 1; */
/*   } */

/*   return 0; */
/* } */

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow,
			      u_int16_t upper_detected_protocol,
			      u_int16_t lower_detected_protocol) {
  if(upper_detected_protocol == lower_detected_protocol)
    lower_detected_protocol = NDPI_PROTOCOL_UNKNOWN;

  ndpi_int_change_flow_protocol(ndpi_struct, flow, upper_detected_protocol, lower_detected_protocol);
  ndpi_int_change_packet_protocol(ndpi_struct, flow, upper_detected_protocol, lower_detected_protocol);
}


/* turns a packet back to unknown */
void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet) {
  int a;

  for(a = 0; a < NDPI_PROTOCOL_HISTORY_SIZE; a++)
    packet->detected_protocol_stack[a] = NDPI_PROTOCOL_UNKNOWN;
}

void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow) {
  if(flow) {
    int a;

    for(a = 0; a < NDPI_PROTOCOL_HISTORY_SIZE; a++) {
      flow->detected_protocol_stack[a] = NDPI_PROTOCOL_UNKNOWN;
    }
  }
}

 void NDPI_PROTOCOL_IP_clear(ndpi_ip_addr_t * ip) {
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

  /* IPv6 */
  if(packet->iphv6 != NULL) {

    if(packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ip->ipv6.u6_addr.u6_addr32[0] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[1] == ip->ipv6.u6_addr.u6_addr32[1] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[2] == ip->ipv6.u6_addr.u6_addr32[2] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[3] == ip->ipv6.u6_addr.u6_addr32[3])
      return 1;
    //else
    return 0;
  }
#endif

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return 1;
  return 0;
}

/* check if the destination ip address in packet and ip are equal */
int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip)
{

#ifdef NDPI_DETECTION_SUPPORT_IPV6

  /* IPv6 */
  if(packet->iphv6 != NULL) {

    if(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ip->ipv6.u6_addr.u6_addr32[0] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] == ip->ipv6.u6_addr.u6_addr32[1] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[2] == ip->ipv6.u6_addr.u6_addr32[2] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[3] == ip->ipv6.u6_addr.u6_addr32[3])
      return 1;
    //else
    return 0;
  }
#endif

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return 1;
  return 0;
}

/* get the source ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);

#ifdef NDPI_DETECTION_SUPPORT_IPV6

  /* IPv6 */
  if(packet->iphv6 != NULL) {

    ip->ipv6.u6_addr.u6_addr32[0] = packet->iphv6->ip6_src.u6_addr.u6_addr32[0];
    ip->ipv6.u6_addr.u6_addr32[1] = packet->iphv6->ip6_src.u6_addr.u6_addr32[1];
    ip->ipv6.u6_addr.u6_addr32[2] = packet->iphv6->ip6_src.u6_addr.u6_addr32[2];
    ip->ipv6.u6_addr.u6_addr32[3] = packet->iphv6->ip6_src.u6_addr.u6_addr32[3];

  } else
#endif

    /* IPv4 */
    ip->ipv4 = packet->iph->saddr;
}

/* get the destination ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);

#ifdef NDPI_DETECTION_SUPPORT_IPV6

  if(packet->iphv6 != NULL) {

    ip->ipv6.u6_addr.u6_addr32[0] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[0];
    ip->ipv6.u6_addr.u6_addr32[1] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[1];
    ip->ipv6.u6_addr.u6_addr32[2] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[2];
    ip->ipv6.u6_addr.u6_addr32[3] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[3];

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
  if(ip->ipv6.u6_addr.u6_addr32[0] != 0 ||
     ip->ipv6.u6_addr.u6_addr32[1] != 0 ||
     ip->ipv6.u6_addr.u6_addr32[1] != 0 ||
     ip->ipv6.u6_addr.u6_addr32[1] != 0) {

    const u_int16_t *b = ip->ipv6.u6_addr.u6_addr16;
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

ndpi_protocol ndpi_find_port_based_protocol(struct ndpi_detection_module_struct *ndpi_struct /* NOTUSED */,
					    /* u_int8_t proto, */
					    u_int32_t shost, u_int16_t sport,
					    u_int32_t dhost, u_int16_t dport) {
  ndpi_protocol p = NDPI_PROTOCOL_NULL;

  /* Skyfile (host 193.252.234.246 or host 10.10.102.80) */
  if((shost == 0xC1FCEAF6) || (dhost == 0xC1FCEAF6)
     || (shost == 0x0A0A6650) || (dhost == 0x0A0A6650)) {
    if((sport == 4708) || (dport == 4708)) p.protocol = NDPI_PROTOCOL_SKYFILE_PREPAID;
    else if((sport == 4709) || (dport == 4709)) p.protocol = NDPI_PROTOCOL_SKYFILE_RUDICS;
    else if((sport == 4710) || (dport == 4710)) p.protocol = NDPI_PROTOCOL_SKYFILE_POSTPAID;
  }

  return(p);
}

/* ****************************************************** */

u_int8_t ndpi_is_proto(ndpi_protocol p, u_int16_t proto) {
  return(((p.protocol == proto) || (p.master_protocol == proto)) ? 1 : 0);
}

/* ****************************************************** */

u_int16_t ndpi_get_lower_proto(ndpi_protocol p) {
  return((p.master_protocol != NDPI_PROTOCOL_UNKNOWN) ? p.master_protocol : p.protocol);
}

/* ****************************************************** */

ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					     u_int8_t proto,
					     u_int32_t shost /* host byte order */, u_int16_t sport,
					     u_int32_t dhost /* host byte order */, u_int16_t dport) {
  u_int32_t rc;
  struct in_addr addr;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };
  u_int8_t user_defined_proto;

  if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
    rc = ndpi_search_tcp_or_udp_raw(ndpi_struct, proto, shost, dhost, sport, dport);

    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      ret.protocol = rc,
	ret.master_protocol = ndpi_guess_protocol_id(ndpi_struct, proto, sport, dport, &user_defined_proto);

      if(ret.protocol == ret.master_protocol)
	ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;

      return(ret);
    }

    rc = ndpi_guess_protocol_id(ndpi_struct, proto, sport, dport, &user_defined_proto);
    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      ret.protocol = rc;

      if(rc == NDPI_PROTOCOL_SSL)
	goto check_guessed_skype;
      else
	return(ret);
    }

    ret = ndpi_find_port_based_protocol(ndpi_struct/* , proto */, shost, sport, dhost, dport);
    if(ret.protocol != NDPI_PROTOCOL_UNKNOWN)
      return(ret);

  check_guessed_skype:
    addr.s_addr = htonl(shost);
    if(ndpi_network_ptree_match(ndpi_struct, &addr) == NDPI_PROTOCOL_SKYPE) {
      ret.protocol = NDPI_PROTOCOL_SKYPE;
    } else {
      addr.s_addr = htonl(dhost);
      if(ndpi_network_ptree_match(ndpi_struct, &addr) == NDPI_PROTOCOL_SKYPE)
	ret.protocol = NDPI_PROTOCOL_SKYPE;
    }
  } else
    ret.protocol = ndpi_guess_protocol_id(ndpi_struct, proto, sport, dport, &user_defined_proto);

  return(ret);
}

/* ****************************************************** */

char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_mod,
			 ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.master_protocol != proto.protocol)) {
    snprintf(buf, buf_len, "%s.%s",
	     ndpi_get_proto_name(ndpi_mod, proto.master_protocol),
	     ndpi_get_proto_name(ndpi_mod, proto.protocol));
  } else
    snprintf(buf, buf_len, "%s",
	     ndpi_get_proto_name(ndpi_mod, proto.protocol));

  return(buf);
}

/* ****************************************************** */

const char* ndpi_category_str(ndpi_protocol_category_t category) {
  switch(category) {
  case NDPI_PROTOCOL_CATEGORY_MEDIA:
    return("Media");
	break;
  case NDPI_PROTOCOL_CATEGORY_VPN:
    return("VPN");
	break;
  case NDPI_PROTOCOL_CATEGORY_MAIL_SEND:
    return("EmailSend");
	break;
  case NDPI_PROTOCOL_CATEGORY_MAIL_SYNC:
    return("EmailSync");
	break;
  case NDPI_PROTOCOL_CATEGORY_FILE_TRANSFER:
    return("FileTransfer");
	break;
  case NDPI_PROTOCOL_CATEGORY_WEB:
    return("Web");
	break;
  case NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK:
    return("SocialNetwork");
	break;
  case NDPI_PROTOCOL_CATEGORY_P2P:
    return("P2P");
	break;
  case NDPI_PROTOCOL_CATEGORY_GAME:
    return("Game");
	break;
  case NDPI_PROTOCOL_CATEGORY_CHAT:
    return("Chat");
	break;
  case NDPI_PROTOCOL_CATEGORY_VOIP:
    return("VoIP");
	break;
  case NDPI_PROTOCOL_CATEGORY_DATABASE:
    return("Database");
	break;
  case NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS:
    return("RemoteAccess");
	break;
  case NDPI_PROTOCOL_CATEGORY_CLOUD:
    return("Cloud");
	break;
  case NDPI_PROTOCOL_CATEGORY_NETWORK:
    return("Network");
	break;
  case NDPI_PROTOCOL_CATEGORY_COLLABORATIVE:
    return("Collaborative");
	break;
  case NDPI_PROTOCOL_CATEGORY_RPC:
    return("RPC");
	break;
  case NDPI_PROTOCOL_CATEGORY_NETWORK_TOOL:
    return("NetworkTool");
	break;
  case NDPI_PROTOCOL_CATEGORY_SYSTEM:
    return("System");
	break;
  case NDPI_PROTOCOL_CATEGORY_UNSPECIFIED:
    return("Unspecified");
	break;
  }

  return("Unspecified");
}

/* ****************************************************** */

ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_mod,
			 ndpi_protocol proto) {
  /* simple rule: sub protocol first, master after */
  if ((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) ||
      (ndpi_mod->proto_defaults[proto.protocol].protoCategory != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED))
    return ndpi_mod->proto_defaults[proto.protocol].protoCategory;
  else
    return ndpi_mod->proto_defaults[proto.master_protocol].protoCategory;
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

int ndpi_match_prefix(const u_int8_t *payload, size_t payload_len,
    const char *str, size_t str_len)
{
  return str_len <= payload_len
          ? memcmp(payload, str, str_len) == 0
          : 0;
}

/* ****************************************************** */

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				  char *string_to_match, u_int string_to_match_len,
				  u_int8_t is_host_match) {
  int matching_protocol_id = NDPI_PROTOCOL_UNKNOWN;
  AC_TEXT_t ac_input_text;
  ndpi_automa *automa = is_host_match ? &ndpi_struct->host_automa : &ndpi_struct->content_automa;

  if((automa->ac_automa == NULL) || (string_to_match_len == 0)) return(NDPI_PROTOCOL_UNKNOWN);

  if(!automa->ac_automa_finalized) {
    ac_automata_finalize((AC_AUTOMATA_t*)automa->ac_automa);
    automa->ac_automa_finalized = 1;
  }

  ac_input_text.astring = string_to_match, ac_input_text.length = string_to_match_len;
  ac_automata_search(((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, (void*)&matching_protocol_id);
  ac_automata_reset(((AC_AUTOMATA_t*)automa->ac_automa));

  return(matching_protocol_id);
}

/* ****************************************************** */

static int ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
						struct ndpi_flow_struct *flow,
						char *string_to_match, u_int string_to_match_len,
						u_int16_t master_protocol_id,
						u_int8_t is_host_match) {
  int matching_protocol_id = ndpi_match_string_subprotocol(ndpi_struct, string_to_match, string_to_match_len, is_host_match);
  struct ndpi_packet_struct *packet = &flow->packet;

#ifdef DEBUG
  {
    char m[256];
    int len = ndpi_min(sizeof(m), string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    printf("[NDPI] ndpi_match_host_subprotocol(%s): %s\n",
	   m, ndpi_struct->proto_defaults[matching_protocol_id].protoName);
  }
#endif

  if(matching_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
    /* Move the protocol on slot 0 down one position */
    packet->detected_protocol_stack[1] = master_protocol_id,
      packet->detected_protocol_stack[0] = matching_protocol_id;

    flow->detected_protocol_stack[0] = packet->detected_protocol_stack[0],
      flow->detected_protocol_stack[1] = packet->detected_protocol_stack[1];

    return(packet->detected_protocol_stack[0]);
  }

#ifdef DEBUG
  string_to_match[string_to_match_len] = '\0';
  printf("[NTOP] Unable to find a match for '%s'\n", string_to_match);
#endif

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */

int ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				char *string_to_match, u_int string_to_match_len,
				u_int16_t master_protocol_id) {
  return(ndpi_automa_match_string_subprotocol(ndpi_struct,
					      flow, string_to_match, string_to_match_len,
					      master_protocol_id, 1));
}

/* ****************************************************** */

int ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   char *string_to_match, u_int string_to_match_len,
				   u_int16_t master_protocol_id) {
  return(ndpi_automa_match_string_subprotocol(ndpi_struct, flow,
					      string_to_match, string_to_match_len,
					      master_protocol_id, 0));
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

char* ndpi_revision() { return(NDPI_GIT_RELEASE); }

/* ****************************************************** */

#ifdef WIN32

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

