/*
 * ndpi_main.c
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

#include "ndpi_content_match.c.inc"
#include "third_party/include/ndpi_patricia.h"
#include "third_party/include/ht_hash.h"
#include "third_party/include/ndpi_md5.h"

/* stun.c */
extern u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev);

static int _ndpi_debug_callbacks = 0;

/* #define MATCH_DEBUG 1 */

/* ****************************************** */

static void *(*_ndpi_flow_malloc)(size_t size);
static void  (*_ndpi_flow_free)(void *ptr);

static void *(*_ndpi_malloc)(size_t size);
static void  (*_ndpi_free)(void *ptr);

/* ****************************************** */

/* Forward */
static void addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
			   ndpi_port_range *range,
			   ndpi_proto_defaults_t *def,
			   u_int8_t customUserProto,
			   ndpi_default_ports_tree_node_t **root,
			   const char *_func, int _line);

static int removeDefaultPort(ndpi_port_range *range,
			     ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root);

/* ****************************************** */

static inline uint8_t flow_is_proto(struct ndpi_flow_struct *flow, u_int16_t p) {
  return((flow->detected_protocol_stack[0] == p) || (flow->detected_protocol_stack[1] == p));
}

/* ****************************************** */

void* ndpi_malloc(size_t size) { return(_ndpi_malloc ? _ndpi_malloc(size) : malloc(size)); }
void* ndpi_flow_malloc(size_t size) { return(_ndpi_flow_malloc ? _ndpi_flow_malloc(size) : ndpi_malloc(size)); }

/* ****************************************** */

void * ndpi_calloc(unsigned long count, size_t size)
{
  size_t len = count*size;
  void *p = ndpi_malloc(len);

  if(p)
    memset(p, 0, len);

  return(p);
}

/* ****************************************** */

void ndpi_free(void *ptr) {
  if(_ndpi_free)
    _ndpi_free(ptr);
  else
    free(ptr);
}

/* ****************************************** */

void ndpi_flow_free(void *ptr) {
  if(_ndpi_flow_free)
    _ndpi_flow_free(ptr);
  else
    ndpi_free_flow((struct ndpi_flow_struct *) ptr);
}

/* ****************************************** */

void * ndpi_realloc(void *ptr, size_t old_size,
		    size_t new_size) {
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

char * ndpi_strdup(const char *s)
{
  int len = strlen(s);
  char *m = ndpi_malloc(len+1);

  if(m) {
    memcpy(m, s, len);
    m[len] = '\0';
  }

  return(m);
}

/* *********************************************************************************** */

/* Opaque structure defined here */
struct ndpi_ptree {
  patricia_tree_t *v4;
  patricia_tree_t *v6;
};

/* *********************************************************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void) { return(sizeof(struct ndpi_flow_struct)); }

/* *********************************************************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void) { return(sizeof(struct ndpi_id_struct)); }

/* *********************************************************************************** */

char * ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_str, u_int id) {
  return((id >= ndpi_str->ndpi_num_supported_protocols) ? NULL : ndpi_str->proto_defaults[id].protoName);
}

/* *********************************************************************************** */

u_int16_t ndpi_get_proto_by_name(struct ndpi_detection_module_struct *ndpi_str, const char *name) {
  u_int16_t i, num = ndpi_get_num_supported_protocols(ndpi_str);

  for(i = 0; i < num; i++)
    if(strcasecmp(ndpi_get_proto_by_id(ndpi_str, i), name) == 0)
      return(i);

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ************************************************************************************* */

#ifdef CODE_UNUSED
ndpi_port_range * ndpi_build_default_ports_range(ndpi_port_range *ports,
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
  ports[i].port_low = portE_low, ports[i].port_high = portE_high;

  return(ports);
}
#endif

/* *********************************************************************************** */

ndpi_port_range * ndpi_build_default_ports(ndpi_port_range *ports,
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
  ports[i].port_low = portE, ports[i].port_high = portE;

  return(ports);
}

/* ********************************************************************************** */

void ndpi_set_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
			  u_int16_t protoId, ndpi_protocol_breed_t breed) {
  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)
    return;
  else
    ndpi_str->proto_defaults[protoId].protoBreed = breed;
}

/* ********************************************************************************** */

void ndpi_set_proto_category(struct ndpi_detection_module_struct *ndpi_str,
			     u_int16_t protoId, ndpi_protocol_category_t protoCategory) {
  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)
    return;
  else
    ndpi_str->proto_defaults[protoId].protoCategory = protoCategory;
}

/* ********************************************************************************** */

/*
  There are some (master) protocols that are informative, meaning that it shows
  what is the subprotocol about, but also that the subprotocol isn't a real protocol.

  Example:
  - DNS is informative as if we see a DNS request for www.facebook.com, the
  returned protocol is DNS.Facebook, but Facebook isn't a real subprotocol but
  rather it indicates a query for Facebook and not Facebook traffic.
  - HTTP/SSL are NOT informative as SSL.Facebook (likely) means that this is
  SSL (HTTPS) traffic containg Facebook traffic.
*/
u_int8_t ndpi_is_subprotocol_informative(struct ndpi_detection_module_struct *ndpi_str,
					 u_int16_t protoId) {
  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)
    return(0);

  switch(protoId) {
    /* All dissectors that have calls to ndpi_match_host_subprotocol() */
  case NDPI_PROTOCOL_DNS:
    return(1);
    break;

  default:
    return(0);
  }
}
/* ********************************************************************************** */

void ndpi_exclude_protocol(struct ndpi_detection_module_struct *ndpi_str,
			   struct ndpi_flow_struct *flow,
			   u_int16_t protocol_id,
			   const char *_file, const char *_func,int _line) {
  if(protocol_id < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    if( ndpi_str &&
	ndpi_str->ndpi_log_level >= NDPI_LOG_DEBUG &&
	ndpi_str->ndpi_debug_printf != NULL) {

      (*(ndpi_str->ndpi_debug_printf))(protocol_id, ndpi_str, NDPI_LOG_DEBUG,
					  _file, _func, _line, "exclude %s\n",ndpi_get_proto_name(ndpi_str, protocol_id));
    }
#endif
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, protocol_id);
  }
}

/* ********************************************************************************** */

void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_str,
			     ndpi_protocol_breed_t breed, u_int16_t protoId,
			     u_int8_t can_have_a_subprotocol,
			     u_int16_t tcp_master_protoId[2], u_int16_t udp_master_protoId[2],
			     char *protoName, ndpi_protocol_category_t protoCategory,
			     ndpi_port_range *tcpDefPorts, ndpi_port_range *udpDefPorts) {
  char *name;
  int j;

  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: INTERNAL ERROR\n", protoName, protoId);
#endif
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName != NULL) {
#ifdef DEBUG
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: already initialized. Ignoring it\n", protoName, protoId);
#endif
    return;
  }

  name = ndpi_strdup(protoName);

  if(ndpi_str->proto_defaults[protoId].protoName)
    ndpi_free(ndpi_str->proto_defaults[protoId].protoName);

  ndpi_str->proto_defaults[protoId].protoName = name,
    ndpi_str->proto_defaults[protoId].protoCategory = protoCategory,
    ndpi_str->proto_defaults[protoId].protoId = protoId,
    ndpi_str->proto_defaults[protoId].protoBreed = breed;
  ndpi_str->proto_defaults[protoId].can_have_a_subprotocol = can_have_a_subprotocol;

  memcpy(&ndpi_str->proto_defaults[protoId].master_tcp_protoId, tcp_master_protoId, 2*sizeof(u_int16_t));
  memcpy(&ndpi_str->proto_defaults[protoId].master_udp_protoId, udp_master_protoId, 2*sizeof(u_int16_t));

  for(j=0; j<MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &udpDefPorts[j],
		     &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->udpRoot, __FUNCTION__,__LINE__);

    if(tcpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &tcpDefPorts[j],
		     &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->tcpRoot, __FUNCTION__,__LINE__);
  }
}

/* ******************************************************************** */

static int ndpi_default_ports_tree_node_t_cmp(const void *a, const void *b)
{
  ndpi_default_ports_tree_node_t *fa = (ndpi_default_ports_tree_node_t*)a;
  ndpi_default_ports_tree_node_t *fb = (ndpi_default_ports_tree_node_t*)b;

  //printf("[NDPI] %s(%d, %d)\n", __FUNCTION__, fa->default_port, fb->default_port);

  return((fa->default_port == fb->default_port) ? 0 : ((fa->default_port < fb->default_port) ? -1 : 1));
}

/* ******************************************************************** */

void ndpi_default_ports_tree_node_t_walker(const void *node, const ndpi_VISIT which, const int depth)
{
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

static void addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
			   ndpi_port_range *range,
			   ndpi_proto_defaults_t *def,
			   u_int8_t customUserProto,
			   ndpi_default_ports_tree_node_t **root,
			   const char *_func, int _line) {
  u_int16_t port;

  for(port=range->port_low; port<=range->port_high; port++) {
    ndpi_default_ports_tree_node_t *node = (ndpi_default_ports_tree_node_t*)ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));
    ndpi_default_ports_tree_node_t *ret;

    if(!node) {
      NDPI_LOG_ERR(ndpi_str, "%s:%d not enough memory\n", _func, _line);
      break;
    }

    node->proto = def, node->default_port = port, node->customUserProto = customUserProto;
    ret = (ndpi_default_ports_tree_node_t*)ndpi_tsearch(node, (void*)root, ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != node) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d found duplicate for port %u: overwriting it with new value\n",
		   _func, _line, port);

      ret->proto = def;
      ndpi_free(node);
    }
  }
}

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastructures while using them
*/
static int removeDefaultPort(ndpi_port_range *range,
			     ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root)
{
  ndpi_default_ports_tree_node_t node;
  u_int16_t port;

  for(port=range->port_low; port<=range->port_high; port++) {
    ndpi_default_ports_tree_node_t *ret;

    node.proto = def, node.default_port = port;
    ret = (ndpi_default_ports_tree_node_t*)ndpi_tdelete(&node, (void*)root,
							  ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != NULL) {
      ndpi_free((ndpi_default_ports_tree_node_t*)ret);
      return(0);
    }
  }

  return(-1);
}

/* ****************************************************** */

static int ndpi_string_to_automa(struct ndpi_detection_module_struct *ndpi_str,
				 ndpi_automa *automa,
				 char *value, u_int16_t protocol_id,
				 ndpi_protocol_category_t category,
				 ndpi_protocol_breed_t breed) {
  AC_PATTERN_t ac_pattern;

  if((value == NULL)
     || (protocol_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] protoId=%d: INTERNAL ERROR\n", protocol_id);
    return(-1);
  }

  if(automa->ac_automa == NULL) return(-2);
  ac_pattern.astring = value,
    ac_pattern.rep.number = protocol_id,
    ac_pattern.rep.category = (u_int16_t)category,
    ac_pattern.rep.breed = (u_int16_t)breed;

#ifdef MATCH_DEBUG
  printf("Adding to automa [%s][protocol_id: %u][category: %u][breed: %u]\n",
	 value, protocol_id, category, breed);
#endif

  if(value == NULL)
    ac_pattern.length = 0;
  else
    ac_pattern.length = strlen(ac_pattern.astring);

  if(ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern) != ACERR_SUCCESS)
    return(-2);

  return(0);
}

/* ****************************************************** */

static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					 char *_value, int protocol_id,
					 ndpi_protocol_category_t category,
					 ndpi_protocol_breed_t breed) {
  int rv;
  char *value = ndpi_strdup(_value);

  if(!value) return(-1);

#ifdef DEBUG
  NDPI_LOG_DEBUG2(ndpi_str, "[NDPI] Adding [%s][%d]\n", value, protocol_id);
#endif

  rv = ndpi_string_to_automa(ndpi_str,
			       &ndpi_str->host_automa,
			       value,
			       protocol_id,
			       category, breed);

  if(rv != 0) ndpi_free(value);

  return(rv);
}

/* ****************************************************** */

#ifdef CODE_UNUSED
int ndpi_add_content_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
				 char *value, int protocol_id,
				 ndpi_protocol_category_t category,
				 ndpi_protocol_breed_t breed) {
  return(ndpi_string_to_automa(ndpi_str, &ndpi_str->content_automa,
			       value, protocol_id, category, breed));
}
#endif

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastructures while using them
*/
static int ndpi_remove_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					    char *value, int protocol_id)
{
  NDPI_LOG_ERR(ndpi_str, "[NDPI] Missing implementation for proto %s/%d\n",value,protocol_id);
  return(-1);
}

/* ******************************************************************** */

void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_str,
			      ndpi_protocol_match *match) {
  u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO };
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  if(ndpi_str->proto_defaults[match->protocol_id].protoName == NULL) {
    ndpi_str->proto_defaults[match->protocol_id].protoName    = ndpi_strdup(match->proto_name);

    ndpi_str->proto_defaults[match->protocol_id].protoId       = match->protocol_id;
    ndpi_str->proto_defaults[match->protocol_id].protoCategory = match->protocol_category;
    ndpi_str->proto_defaults[match->protocol_id].protoBreed    = match->protocol_breed;

    ndpi_set_proto_defaults(ndpi_str,
			    ndpi_str->proto_defaults[match->protocol_id].protoBreed,
			    ndpi_str->proto_defaults[match->protocol_id].protoId,
			    0 /* can_have_a_subprotocol */,
			    no_master, no_master,
			    ndpi_str->proto_defaults[match->protocol_id].protoName,
			    ndpi_str->proto_defaults[match->protocol_id].protoCategory,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  }

  ndpi_add_host_url_subprotocol(ndpi_str,
				match->string_to_match,
				match->protocol_id,
				match->protocol_category,
				match->protocol_breed);
}

/* ******************************************************************** */

#ifdef HAVE_HYPERSCAN

static int hyperscan_load_patterns(struct hs *hs, u_int num_patterns,
				   const char **expressions, unsigned int *ids) {
  hs_compile_error_t *compile_err;

  if(hs_compile_multi(expressions, NULL, ids,
		      num_patterns, HS_MODE_BLOCK, NULL,
		      &hs->database, &compile_err) != HS_SUCCESS) {
    NDPI_LOG_ERR(ndpi_str, "Unable to initialize hyperscan database\n");
    hs_free_compile_error(compile_err);
    return(-1);
  }

  hs->scratch = NULL;
  if(hs_alloc_scratch(hs->database, &hs->scratch) != HS_SUCCESS) {
    NDPI_LOG_ERR(ndpi_str, "Unable to allocate hyperscan scratch space\n");
    hs_free_database(hs->database);
    return(-1);
  }

  return(0);
}

/* ******************************************************************** */

static char* string2hex(const char *pat) {
  u_int patlen, i;
  char *hexbuf, *buf;

  patlen = strlen(pat);
  hexbuf = (char*)ndpi_calloc(sizeof(char), patlen * 4 + 1);
  if(!hexbuf) return(NULL);

  for (i = 0, buf = hexbuf; i < patlen; i++, buf += 4) {
    snprintf(buf, 5, "\\x%02x", (unsigned char)pat[i]);
  }
  *buf = '\0';

  return(hexbuf);
}

/* ******************************************************************** */

static int init_hyperscan(struct ndpi_detection_module_struct *ndpi_str) {
  u_int num_patterns = 0, i, j;
  char **expressions;
  unsigned int *ids;
  unsigned char *need_to_be_free;
  struct hs *hs;
  int rc;

  ndpi_str->hyperscan = (void*)ndpi_malloc(sizeof(struct hs));
  if(!ndpi_str->hyperscan) return(-1);
  hs = (struct hs*)ndpi_str->hyperscan;

  for(i = 0; (host_match[i].string_to_match != NULL)
	|| (host_match[i].pattern_to_match != NULL); i++)
    num_patterns++;

  expressions = (char**)ndpi_calloc(sizeof(char*), num_patterns + 1);
  if(!expressions) return(-1);

  ids = (unsigned int*)ndpi_calloc(sizeof(unsigned int), num_patterns + 1);
  if(!ids) {
    ndpi_free(expressions);
    return(-1);
  }

  need_to_be_free = (unsigned char*)ndpi_calloc(sizeof(unsigned char), num_patterns + 1);
  if(!need_to_be_free) {
    ndpi_free(expressions);
    ndpi_free(ids);
    return(-1);
  }

  for(i = 0, j = 0; host_match[i].string_to_match != NULL || host_match[i].pattern_to_match != NULL; i++) {
    if(host_match[i].pattern_to_match) {
      expressions[j] = host_match[i].pattern_to_match;
      ids[j] = host_match[i].protocol_id;
      need_to_be_free[j] = 0;
      ++j;
    } else {
      expressions[j] = string2hex(host_match[i].string_to_match);
      if(expressions[j] != NULL) {
        ids[j] = host_match[i].protocol_id;
        need_to_be_free[j] = 1;
        ++j;
      } else {
#ifdef DEBUG
        printf("Fail to calloc memory for %s\n", host_match[i].string_to_match);
#endif
      }
    }
    /*printf("[DEBUG] %s\n", j ? expressions[j - 1] : "No Expression");*/
  }

  rc = hyperscan_load_patterns(hs, j, (const char**)expressions, ids);

  for(i = 0; i < j; ++i)
    if(need_to_be_free[i])
      ndpi_free(expressions[i]);

  ndpi_free(expressions), ndpi_free(ids);
  ndpi_free(need_to_be_free);

  return(rc);
}

/* ******************************************************************** */

static void free_hyperscan_memory(struct hs *h) {
  if(h) {
    hs_free_scratch(h->scratch);
    hs_free_database(h->database);
    ndpi_free(h);
  }
}

/* ******************************************************************** */

static void destroy_hyperscan(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str->hyperscan)
    free_hyperscan_memory((struct hs*)ndpi_str->hyperscan);
}

#endif

/* ******************************************************************** */

static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

#ifdef HAVE_HYPERSCAN
  // TODO check return value
  init_hyperscan(ndpi_str);
#endif

  for(i=0; host_match[i].string_to_match != NULL; i++)
    ndpi_init_protocol_match(ndpi_str, &host_match[i]);

  ndpi_enable_loaded_categories(ndpi_str);

#ifdef MATCH_DEBUG
  // ac_automata_display(ndpi_str->host_automa.ac_automa, 'n');
#endif

  for(i=0; ndpi_en_bigrams[i] != NULL; i++)
    ndpi_string_to_automa(ndpi_str, &ndpi_str->bigrams_automa,
			  (char*)ndpi_en_bigrams[i],
			  1, 1, 1);

  for(i=0; ndpi_en_impossible_bigrams[i] != NULL; i++)
    ndpi_string_to_automa(ndpi_str, &ndpi_str->impossible_bigrams_automa,
			  (char*)ndpi_en_impossible_bigrams[i],
			  1, 1, 1);
}

/* ******************************************************************** */

int ndpi_set_detection_preferences(struct ndpi_detection_module_struct *ndpi_str,
				   ndpi_detection_preference pref,
				   int value) {
  switch(pref) {
  case ndpi_pref_direction_detect_disable:
    ndpi_str->direction_detect_disable = (u_int8_t)value;
    break;

  default:
    return(-1);
  }

  return(0);
}

/* ******************************************************************** */

static void ndpi_validate_protocol_initialization(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  for(i=0; i<(int)ndpi_str->ndpi_num_supported_protocols; i++) {
    if(ndpi_str->proto_defaults[i].protoName == NULL) {
      NDPI_LOG_ERR(ndpi_str, "[NDPI] INTERNAL ERROR missing protoName initialization for [protoId=%d]: recovering\n",  i);
    } else {
      if((i != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_str->proto_defaults[i].protoCategory == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
	NDPI_LOG_ERR(ndpi_str, "[NDPI] INTERNAL ERROR missing category [protoId=%d/%s] initialization: recovering\n",
		     i, ndpi_str->proto_defaults[i].protoName ? ndpi_str->proto_defaults[i].protoName : "???");
      }
    }
  }
}

/* ******************************************************************** */

/* This function is used to map protocol name and default ports and it MUST
   be updated whenever a new protocol is added to NDPI.

   Do NOT add web services (NDPI_SERVICE_xxx) here.
*/
static void ndpi_init_protocol_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
  u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO },
    custom_master[2];

    /* Reset all settings */
    memset(ndpi_str->proto_defaults, 0, sizeof(ndpi_str->proto_defaults));

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Unknown", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_CONTROL,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FTP_CONTROL", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 21, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_FTP_DATA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FTP_DATA", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 20, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_POP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "POP3", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 110, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_POPS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "POPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 995, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MAIL_SMTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SMTP", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 25, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_SMTPS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SMTPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 465, 587, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_IMAP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IMAP", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 143, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_IMAPS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IMAPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			    ndpi_build_default_ports(ports_a, 993, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNS,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "DNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 53, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 53, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IPP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IPP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IMO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IMO", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MDNS,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "MDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5353, 5354, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NTP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 123, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETBIOS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NetBIOS", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 139, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 137, 138, 139, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NFS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NFS", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			    ndpi_build_default_ports(ports_a, 2049, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2049, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSDP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SSDP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BGP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "BGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 179, 2605, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNMP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SNMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 161, 162, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XDMCP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "XDMCP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 177, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 177, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_DANGEROUS, NDPI_PROTOCOL_SMBV1,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SMBv1", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SYSLOG,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Syslog", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 514, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 514, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DHCP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 67, 68, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_POSTGRES,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PostgreSQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 5432, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MYSQL,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MySQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 3306, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Direct_Download_Link", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_APPLEJUICE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "AppleJuice", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_DIRECTCONNECT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DirectConnect", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_NTOP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ntop", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VMWARE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "VMware", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 903, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 902, 903, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FBZERO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FacebookZero", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			    ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_KONTIKI,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Kontiki", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_OPENFT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "OpenFT", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_FASTTRACK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FastTrack", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_GNUTELLA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Gnutella", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_EDONKEY,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "eDonkey", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_BITTORRENT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "BitTorrent", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 51413, 53646, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6771, 51413, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Skype", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE_CALL,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SkypeCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TIKTOK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TikTok", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEREDO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Teredo", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 3544, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WECHAT,
			    0 /* can_have_a_subprotocol */, no_master, /* wechat.com */
			    no_master, "WeChat", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEMCACHED,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Memcached", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 11211, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 11211, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMBV23,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SMBv23", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MINING,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Mining", CUSTOM_CATEGORY_MINING,
			    ndpi_build_default_ports(ports_a, 8333, 30303, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NEST_LOG_SINK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NestLogSink", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 11095, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MODBUS,
			    1 /* no subprotocol */, no_master,
			    no_master, "Modbus", NDPI_PROTOCOL_CATEGORY_NETWORK, /* Perhaps IoT in the future */
			    ndpi_build_default_ports(ports_a, 502, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0,   0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_CALL,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsAppCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DATASAVER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DataSaver", NDPI_PROTOCOL_CATEGORY_WEB /* dummy */,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SIGNAL,
			    0 /* can_have_a_subprotocol */, no_master, /* https://signal.org */
			    no_master, "Signal", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DOH_DOT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DoH_DoT", NDPI_PROTOCOL_CATEGORY_NETWORK /* dummy */,
			    ndpi_build_default_ports(ports_a, 853, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FREE_205,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FREE_205", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WIREGUARD,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WireGuard", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 51820, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PPStream", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_XBOX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Xbox", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 3074, 3076, 0, 0, 0)         /* TCP */,
			    ndpi_build_default_ports(ports_b, 3074, 3076, 500, 3544, 4500) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PLAYSTATION,
                            0 /* can_have_a_subprotocol */, no_master,
                            no_master, "Playstation", NDPI_PROTOCOL_CATEGORY_GAME,
                            ndpi_build_default_ports(ports_a, 1935, 3478, 3479, 3480, 0) /* TCP */,
                            ndpi_build_default_ports(ports_b, 3478, 3479, 0, 0, 0)       /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQ,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "QQ", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RTSP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RTSP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 554, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 554, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ICECAST,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IceCast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPLIVE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PPLive", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PPStream", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ZATTOO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Zattoo", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SHOUTCAST,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ShoutCast", NDPI_PROTOCOL_CATEGORY_MUSIC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOPCAST,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Sopcast", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVANTS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Tvants", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVUPLAYER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TVUplayer", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_DOWNLOAD,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP_Download", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQLIVE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "QQLive", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_THUNDER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Thunder", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOULSEEK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Soulseek", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PS_VUE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PS_VUE", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_IRC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IRC", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AYIYA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Ayiya", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5072, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UNENCRYPTED_JABBER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Unencrypted_Jabber", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OSCAR,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Oscar", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_BATTLEFIELD,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "BattleField", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_VRRP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "VRRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STEAM,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Steam", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HALFLIFE2,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "HalfLife2", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WorldOfWarcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_HOTSPOT_SHIELD,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "HotspotShield", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_TELNET,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Telnet", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 23, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    custom_master[0] = NDPI_PROTOCOL_SIP, custom_master[1] = NDPI_PROTOCOL_H323;
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_STUN,
			    0 /* can_have_a_subprotocol */, no_master,
			    custom_master, "STUN", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 3478, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_IP_IPSEC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IPsec", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 500, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 500, 4500, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_GRE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "GRE", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ICMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IGMP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IGMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_EGP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "EGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_SCTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SCTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_OSPF,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "OSPF", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 2604, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IP_IN_IP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IP_in_IP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RTP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RDP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RDP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 3389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 3389, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VNC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "VNC", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 5900, 5901, 5800, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PCANYWHERE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PcAnywhere", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZOOM,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Zoom", NDPI_PROTOCOL_CATEGORY_VIDEO,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_FILES,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsAppFiles", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WhatsApp", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_TLS,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "TLS", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSH,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 22, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_USENET,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Usenet", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MGCP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MGCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IAX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "IAX", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 4569, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 4569, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AFP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "AFP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			    ndpi_build_default_ports(ports_a, 548, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 548, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HULU,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Hulu", NDPI_PROTOCOL_CATEGORY_STREAMING,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CHECKMK,
                            0 /* can_have_a_subprotocol */, no_master,
                            no_master, "CHECKMK", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
                            ndpi_build_default_ports(ports_a, 6556, 0, 0, 0, 0) /* TCP */,
                            ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_STEALTHNET,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Stealthnet", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AIMINI,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Aimini", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SIP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 5060, 5061, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5060, 5061, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TRUPHONE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TruPhone", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMPV6,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ICMPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCPV6,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DHCPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ARMAGETRON,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Armagetron", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CROSSFIRE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Crossfire", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DOFUS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Dofus", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FIESTA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Fiesta", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_FLORENSIA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Florensia", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GUILDWARS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Guildwars", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_ACTIVESYNC,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP_ActiveSync", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KERBEROS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Kerberos", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 88, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 88, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LDAP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "LDAP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 389, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 389, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MAPLESTORY,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MapleStory", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSSQL_TDS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MsSQL-TDS", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 1433, 1434, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PPTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "PPTP", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WARCRAFT3,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Warcraft3", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "WorldOfKungFu", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DCERPC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DCE_RPC", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 135, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETFLOW,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NetFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2055, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SFLOW,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "sFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6343, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_CONNECT,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP_Connect", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_PROXY,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "HTTP_Proxy", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 8080, 3128, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Citrix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 1494, 2598, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBEX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Webex", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RADIUS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Radius", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 1812, 1813, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1812, 1813, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMVIEWER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TeamViewer", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			    ndpi_build_default_ports(ports_a, 5938, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5938, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LOTUS_NOTES,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "LotusNotes", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			    ndpi_build_default_ports(ports_a, 1352, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SAP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 3201, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "GTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 2152, 2123, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UPNP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "UPnP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 1780, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1900, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TELEGRAM,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Telegram", NDPI_PROTOCOL_CATEGORY_CHAT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_QUIC,
			    1 /* can_have_a_subprotocol */, no_master,
			    no_master, "QUIC", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 443, 80, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DIAMETER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Diameter", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 3868, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APPLE_PUSH,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ApplePush", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 1, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DROPBOX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Dropbox", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 17500, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SPOTIFY,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Spotify", NDPI_PROTOCOL_CATEGORY_MUSIC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MESSENGER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Messenger", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LISP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "LISP", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 4342, 4341, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EAQ,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "EAQ", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6000, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KAKAOTALK_VOICE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "KakaoTalk_Voice", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGTS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MPEG_TS", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    /* http://en.wikipedia.org/wiki/Link-local_Multicast_Name_Resolution */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LLMNR,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "LLMNR", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 5355, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5355, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_REMOTE_SCAN,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RemoteScan", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 6077, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 6078, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */

    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_H323,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master,"H323", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 1719, 1720, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1719, 1720, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OPENVPN,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "OpenVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 1194, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 1194, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NOE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "NOE", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CISCOVPN,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "CiscoVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 10000, 8008, 8009, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 10000, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMSPEAK,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TeamSpeak", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKINNY,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "CiscoSkinny", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 2000, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTCP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RTCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RSYNC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RSYNC", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			    ndpi_build_default_ports(ports_a, 873, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ORACLE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Oracle", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 1521, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CORBA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Corba", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UBUNTUONE,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "UbuntuONE", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHOIS_DAS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Whois-DAS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 43, 4343, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));         /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_COLLECTD,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Collectd", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 25826, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SOCKS", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 1080, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 1080, 0, 0, 0, 0));     /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TFTP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TFTP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 69, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTMP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RTMP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			    ndpi_build_default_ports(ports_a, 1935, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));        /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PANDO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Pando_Media_Booster", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));        /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEGACO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Megaco", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 2944 , 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_REDIS,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Redis", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 6379, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZMQ,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "ZeroMQ", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 0 , 0, 0, 0, 0) );      /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VHUA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "VHUA", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 58267, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STARCRAFT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Starcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 1119, 0, 0, 0, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 1119, 0, 0, 0, 0));     /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_UBNTAC2,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "UBNTAC2", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),	      /* TCP */
			    ndpi_build_default_ports(ports_b, 10001, 0, 0, 0, 0));    /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VIBER,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Viber", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 7985, 5242, 5243, 4244, 0),      /* TCP */
			    ndpi_build_default_ports(ports_b, 7985, 7987, 5242, 5243, 4244));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_COAP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "COAP", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),         /* TCP */
			    ndpi_build_default_ports(ports_b, 5683, 5684, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MQTT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "MQTT", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 1883, 8883, 0, 0, 0),  /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOMEIP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SOMEIP", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 30491, 30501, 0, 0, 0),  /* TCP */
			    ndpi_build_default_ports(ports_b, 30491, 30501, 30490, 0, 0)); /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "RX", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),        /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));       /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_GIT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Git", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			    ndpi_build_default_ports(ports_a, 9418, 0, 0, 0, 0),    /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DRDA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DRDA", NDPI_PROTOCOL_CATEGORY_DATABASE,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),       /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HANGOUT_DUO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "GoogleHangoutDuo", NDPI_PROTOCOL_CATEGORY_VOIP,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BJNP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "BJNP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 8612, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMPP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "SMPP", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OOKLA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Ookla", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMQP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "AMQP", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DNSCRYPT,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "DNScrypt", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));  /* UDP */
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TINC,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "TINC", NDPI_PROTOCOL_CATEGORY_VPN,
			    ndpi_build_default_ports(ports_a, 655, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 655, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FIX,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "FIX", NDPI_PROTOCOL_CATEGORY_RPC,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_NINTENDO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Nintendo", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CSGO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "CSGO", NDPI_PROTOCOL_CATEGORY_GAME,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AJP,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "AJP", NDPI_PROTOCOL_CATEGORY_WEB,
			    ndpi_build_default_ports(ports_a, 8009, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TARGUS_GETDATA,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "Targus Dataspeed", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 5001, 5201, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5001, 5201, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMAZON_VIDEO,
			    0 /* can_have_a_subprotocol */, no_master,
			    no_master, "AmazonVideo", NDPI_PROTOCOL_CATEGORY_CLOUD,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNP3,
			    1 /* no subprotocol */, no_master,
			    no_master, "DNP3", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 20000, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0,   0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IEC60870,
			    1 /* no subprotocol */, no_master,
			    no_master, "IEC60870", NDPI_PROTOCOL_CATEGORY_NETWORK, /* Perhaps IoT in the future */
			    ndpi_build_default_ports(ports_a, 2404, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0,   0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BLOOMBERG,
			    1 /* no subprotocol */, no_master,
			    no_master, "Bloomberg", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0,   0, 0, 0, 0) /* UDP */);
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CAPWAP,
			    1 /* no subprotocol */, no_master,
			    no_master, "CAPWAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 5246, 5247, 0, 0, 0) /* UDP */
			    );
    ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZABBIX,
			    1 /* no subprotocol */, no_master,
			    no_master, "Zabbix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			    ndpi_build_default_ports(ports_a, 10050, 0, 0, 0, 0) /* TCP */,
			    ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */
			    );

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main.c"
#endif

    /* calling function for host and content matched protocols */
    init_string_based_protocols(ndpi_str);

    ndpi_validate_protocol_initialization(ndpi_str);
}

/* ****************************************************** */

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_protocols.c"
#endif

/* ****************************************************** */

static int ac_match_handler(AC_MATCH_t *m, AC_TEXT_t *txt, AC_REP_t *match) {
  int min_len = (txt->length < m->patterns->length) ? txt->length : m->patterns->length;
  char buf[64] = { '\0' }, *whatfound;
  int min_buf_len = (txt->length > 63 /* sizeof(buf)-1 */) ? 63 : txt->length;
  u_int buf_len = strlen(buf);

  strncpy(buf, txt->astring, min_buf_len);
  buf[min_buf_len] = '\0';

#ifdef MATCH_DEBUG
  printf("Searching [to search: %s/%u][pattern: %s/%u] [len: %d][match_num: %u][%s]\n",
	 buf, (unigned int)txt->length, m->patterns->astring, (unigned int)m->patterns->length,
	 min_len, m->match_num, m->patterns->astring);
#endif

  whatfound = strstr(buf, m->patterns->astring);

#ifdef MATCH_DEBUG
  printf("[NDPI] %s() [searching=%s][pattern=%s][%s][%c]\n",
	 __FUNCTION__, buf,  m->patterns->astring,
	 whatfound ? whatfound : "<NULL>",
	 whatfound[-1]);
#endif

  if(whatfound) {
    /*
      The patch below allows in case of pattern ws.amazon.com
      to avoid matching aws.amazon.com whereas a.ws.amazon.com
      has to match
    */
    if((whatfound != buf)
       && (m->patterns->astring[0] != '.')  /* The searched pattern does not start with . */
       && strchr(m->patterns->astring, '.') /* The matched pattern has a . (e.g. numeric or sym IPs) */) {
      int len = strlen(m->patterns->astring);
		       
      if((whatfound[-1] != '.')
	 || ((m->patterns->astring[len-1] != '.') && (whatfound[len] != '\0') /* endsWith does not hold here */)
	 ) {
	return(0);
      } else {
	memcpy(match, &m->patterns[0].rep, sizeof(AC_REP_t)); /* Partial match? */
	return(0); /* Keep searching as probably there is a better match */
      }
    }
  }

  /*
    Return 1 for stopping to the first match.
    We might consider searching for the more
    specific match, paying more cpu cycles.
  */
  memcpy(match, &m->patterns[0].rep, sizeof(AC_REP_t));

  if(((buf_len >= min_len) && (strncmp(&buf[buf_len-min_len], m->patterns->astring, min_len) == 0))
     || (strncmp(buf, m->patterns->astring, min_len) == 0) /* begins with */
     ) {
#ifdef MATCH_DEBUG
    printf("Found match [%s][%s] [len: %d]"
	   // "[proto_id: %u]"
	   "\n",
	   buf, m->patterns->astring, min_len /* , *matching_protocol_id */);
#endif
    return(1); /* If the pattern found matches the string at the beginning we stop here */
  } else {
#ifdef MATCH_DEBUG
    printf("NO match found: continue\n");
#endif
    return(0); /* 0 to continue searching, !0 to stop */
  }
}

/* ******************************************************************** */

static int fill_prefix_v4(prefix_t *p, const struct in_addr *a, int b, int mb) {
  do {
    if(b < 0 || b > mb)
      return(-1);

    memset(p, 0, sizeof(prefix_t));
    memcpy(&p->add.sin, a, (mb+7)/8);
    p->family = AF_INET;
    p->bitlen = b;
    p->ref_count = 0;
  } while(0);

  return(0);
}

/* ******************************************* */

static int fill_prefix_v6(prefix_t *prefix, const struct in6_addr *addr, int bits, int maxbits) {
#ifdef PATRICIA_IPV6
    if(bits < 0 || bits > maxbits)
    return -1;

  memcpy(&prefix->add.sin6, addr, (maxbits + 7) / 8);
  prefix->family = AF_INET6, prefix->bitlen = bits, prefix->ref_count = 0;

  return 0;
#else
    return(-1);
#endif
}

/* ******************************************* */

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
				   struct in_addr *pin /* network byte order */) {
  prefix_t prefix;
  patricia_node_t *node;

  /* Make sure all in network byte order otherwise compares wont work */
  fill_prefix_v4(&prefix, pin, 32, ((patricia_tree_t*)ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

  return(node ? node->value.user_value : NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************* */

#if 0
static u_int8_t tor_ptree_match(struct ndpi_detection_module_struct *ndpi_str, struct in_addr *pin) {
  return((ndpi_network_ptree_match(ndpi_str, pin) == NDPI_PROTOCOL_TOR) ? 1 : 0);
}
#endif

/* ******************************************* */

u_int8_t ndpi_is_tor_flow(struct ndpi_detection_module_struct *ndpi_str,
			  struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->tcp != NULL) {
    if(packet->iph) {
      if(flow->guessed_host_protocol_id == NDPI_PROTOCOL_TOR)
	return(1);
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

/*
  Load a file containing IPv4 addresses in CIDR format as 'protocol_id'

  Return: the number of entries loaded or -1 in case of error
*/
int ndpi_load_ipv4_ptree(struct ndpi_detection_module_struct *ndpi_str,
			 const char *path, u_int16_t protocol_id) {
  char buffer[128], *line, *addr, *cidr, *saveptr;
  FILE *fd;
  int len;
  u_int num_loaded = 0;

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len-1] = '\0';
    addr = strtok_r(line, "/", &saveptr);

    if(addr) {
      struct in_addr pin;
      patricia_node_t *node;

      cidr = strtok_r(NULL, "\n", &saveptr);

      pin.s_addr = inet_addr(addr);
      if((node = add_to_ptree(ndpi_str->protocols_ptree, AF_INET,
			      &pin, cidr ? atoi(cidr) : 32 /* bits */)) != NULL)
	node->value.user_value = protocol_id, num_loaded++;
    }
  }

  fclose(fd);
  return(num_loaded);
}


/* ******************************************* */

static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str,
				 void *ptree, ndpi_network host_list[],
				 u_int8_t skip_tor_hosts) {
  int i;

  for(i=0; host_list[i].network != 0x0; i++) {
    struct in_addr pin;
    patricia_node_t *node;

    if(skip_tor_hosts && (host_list[i].value == NDPI_PROTOCOL_TOR))
      continue;

    pin.s_addr = htonl(host_list[i].network);
    if((node = add_to_ptree(ptree, AF_INET,
			    &pin, host_list[i].cidr /* bits */)) != NULL)
      node->value.user_value = host_list[i].value;
  }
}

/* ******************************************* */

static int ndpi_add_host_ip_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					char *value, int protocol_id) {

  patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr = strrchr(value, '/');

  if(ptr) {
    ptr[0] = '\0';
    ptr++;
    if(atoi(ptr)>=0 && atoi(ptr)<=32)
      bits = atoi(ptr);
  }

  inet_pton(AF_INET, value, &pin);

  if((node = add_to_ptree(ndpi_str->protocols_ptree, AF_INET, &pin, bits)) != NULL)
    node->value.user_value = protocol_id;

  return(0);
}

void set_ndpi_malloc(void* (*__ndpi_malloc)(size_t size)) { _ndpi_malloc = __ndpi_malloc; }
void set_ndpi_flow_malloc(void* (*__ndpi_flow_malloc)(size_t size)) { _ndpi_flow_malloc = __ndpi_flow_malloc; }

void set_ndpi_free(void  (*__ndpi_free)(void *ptr))       { _ndpi_free = __ndpi_free; }
void set_ndpi_flow_free(void  (*__ndpi_flow_free)(void *ptr))       { _ndpi_flow_free = __ndpi_flow_free; }

void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str,
		       ndpi_log_level_t log_level, const char *file_name, const char *func_name, int line_number,
		       const char * format, ...)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  va_list args;
#define MAX_STR_LEN 250
  char str[MAX_STR_LEN];
  if(ndpi_str != NULL && log_level > NDPI_LOG_ERROR  &&
     proto > 0 && proto < NDPI_MAX_SUPPORTED_PROTOCOLS &&
     !NDPI_ISSET(&ndpi_str->debug_bitmask,proto)) return;
  va_start(args, format);
  vsnprintf(str,sizeof(str)-1, format, args);
  va_end(args);

  if(ndpi_str != NULL) {
    printf("%s:%s:%-3d - [%s]: %s",
	   file_name, func_name, line_number, ndpi_get_proto_name(ndpi_str, proto), str);
  } else {
    printf("Proto: %u, %s", proto, str);
  }
#endif
}

void set_ndpi_debug_function(struct ndpi_detection_module_struct *ndpi_str, ndpi_debug_function_ptr ndpi_debug_printf) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_str->ndpi_debug_printf = ndpi_debug_printf;
#endif
}

/* ****************************************** */

/* Keep it in order and in sync with ndpi_protocol_category_t in ndpi_typedefs.h */
static const char* categories[] = {
  "Unspecified",
  "Media",
  "VPN",
  "Email",
  "DataTransfer",
  "Web",
  "SocialNetwork",
  "Download-FileTransfer-FileSharing",
  "Game",
  "Chat",
  "VoIP",
  "Database",
  "RemoteAccess",
  "Cloud",
  "Network",
  "Collaborative",
  "RPC",
  "Streaming",
  "System",
  "SoftwareUpdate",
  "",
  "",
  "",
  "",
  "",
  "Music",
  "Video",
  "Shopping",
  "Productivity",
  "FileSharing",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "Mining", /* 99 */
  "Malware",
  "Advertisement",
  "Banned_Site",
  "Site_Unavailable",
  "Allowed_Site",
  "Antimalware",
};

/* ******************************************************************** */

struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs) {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));
  int i;

  if(ndpi_str == NULL) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    NDPI_LOG_ERR(ndpi_str, "ndpi_init_detection_module initial malloc failed for ndpi_str\n");
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */
    return(NULL);
  }

  memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr)ndpi_debug_printf);
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */

  if((ndpi_str->protocols_ptree = ndpi_New_Patricia(32 /* IPv4 */)) != NULL)
    ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree,
			 host_protocol_list,
			 prefs & ndpi_dont_load_tor_hosts);

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

  ndpi_str->host_automa.ac_automa               = ac_automata_init(ac_match_handler);
  ndpi_str->content_automa.ac_automa            = ac_automata_init(ac_match_handler);
  ndpi_str->bigrams_automa.ac_automa            = ac_automata_init(ac_match_handler);
  ndpi_str->impossible_bigrams_automa.ac_automa = ac_automata_init(ac_match_handler);

  if((sizeof(categories)/sizeof(char*)) != NDPI_PROTOCOL_NUM_CATEGORIES) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] invalid categories length: expected %u, got %u\n",
		 NDPI_PROTOCOL_NUM_CATEGORIES, (unsigned int)(sizeof(categories)/sizeof(char*)));
    return(NULL);
  }

#ifdef HAVE_HYPERSCAN
  ndpi_str->custom_categories.num_to_load = 0, ndpi_str->custom_categories.to_load = NULL;
  ndpi_str->custom_categories.hostnames = NULL;
#else
  ndpi_str->custom_categories.hostnames.ac_automa        = ac_automata_init(ac_match_handler);
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_match_handler);
#endif

  ndpi_str->custom_categories.ipAddresses                = ndpi_New_Patricia(32 /* IPv4 */);
  ndpi_str->custom_categories.ipAddresses_shadow         = ndpi_New_Patricia(32 /* IPv4 */);

  if((ndpi_str->custom_categories.ipAddresses == NULL)
     || (ndpi_str->custom_categories.ipAddresses_shadow == NULL))
    return(NULL);

  ndpi_init_protocol_defaults(ndpi_str);

  for(i=0; i<NUM_CUSTOM_CATEGORIES; i++)
    snprintf(ndpi_str->custom_category_labels[i],
	     CUSTOM_CATEGORY_LABEL_LEN, "User custom category %u", (unsigned int)(i+1));

  return(ndpi_str);
}

/* *********************************************** */

void ndpi_finalize_initalization(struct ndpi_detection_module_struct *ndpi_str) {
  u_int i;

  for(i=0; i<4; i++) {
    ndpi_automa *automa;

    switch(i) {
    case 0:
      automa = &ndpi_str->host_automa;
      break;

    case 1:
      automa = &ndpi_str->content_automa;
      break;

    case 2:
      automa = &ndpi_str->bigrams_automa;
      break;

    case 3:
      automa = &ndpi_str->impossible_bigrams_automa;
      break;

    default:
        automa = NULL;
        break;
    }

    if (automa) {
        ac_automata_finalize((AC_AUTOMATA_t*)automa->ac_automa);
        automa->ac_automa_finalized = 1;
    }
  }
}

/* *********************************************** */

/* Wrappers */
void* ndpi_init_automa(void) {
  return(ac_automata_init(ac_match_handler));
}

int ndpi_add_string_value_to_automa(void *_automa, char *str, unsigned long num) {
  AC_PATTERN_t ac_pattern;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;

  if(automa == NULL) return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));
  ac_pattern.astring = str;
  ac_pattern.rep.number = num;
  ac_pattern.length = strlen(ac_pattern.astring);
  return(ac_automata_add(automa, &ac_pattern) == ACERR_SUCCESS ? 0 : -1);
}

int ndpi_add_string_to_automa(void *_automa, char *str) {
  return(ndpi_add_string_value_to_automa(_automa, str, 1));
}

void ndpi_free_automa(void *_automa)     { ac_automata_release((AC_AUTOMATA_t*)_automa, 0);  }
void ndpi_finalize_automa(void *_automa) { ac_automata_finalize((AC_AUTOMATA_t*)_automa); }

/* ****************************************************** */

int ndpi_match_string(void *_automa, char *string_to_match) {
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  AC_TEXT_t ac_input_text;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;
  int rc;

  if((automa == NULL)
     || (string_to_match == NULL)
     || (string_to_match[0] == '\0'))
    return(-2);

  ac_input_text.astring = string_to_match, ac_input_text.length = strlen(string_to_match);
  rc = ac_automata_search(automa, &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  return(rc ? match.number : 0);
}

/* ****************************************************** */

int ndpi_match_string_id(void *_automa, char *string_to_match, u_int match_len, unsigned long *id) {
  AC_TEXT_t ac_input_text;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t*)_automa;
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int rc;

  *id = -1;
  if((automa == NULL)
     || (string_to_match == NULL)
     || (string_to_match[0] == '\0'))
    return(-2);

  ac_input_text.astring = string_to_match, ac_input_text.length = match_len;
  rc = ac_automata_search(automa, &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  *id = rc ? match.number : NDPI_PROTOCOL_UNKNOWN;

  return(*id != NDPI_PROTOCOL_UNKNOWN ? 0 : -1);
}

/* *********************************************** */

#ifdef HAVE_HYPERSCAN

static int hyperscanCustomEventHandler(unsigned int id,
				       unsigned long long from,
				       unsigned long long to,
				       unsigned int flags, void *ctx) {
  *((unsigned long  *)ctx) = (unsigned long)id;

#ifdef DEBUG
  printf("[HS] Found category %u\n", id);
#endif

  return(HS_SCAN_TERMINATED);
}
#endif

/* *********************************************** */

int ndpi_match_custom_category(struct ndpi_detection_module_struct *ndpi_str,
			       char *name, u_int name_len, unsigned long *id) {
#ifdef HAVE_HYPERSCAN
  if(ndpi_str->custom_categories.hostnames == NULL)
    return(-1);
  else {
    hs_error_t rc;
    
    *id = (unsigned long)-1;
    
    rc = hs_scan(ndpi_str->custom_categories.hostnames->database,
		 name, name_len, 0,
		 ndpi_str->custom_categories.hostnames->scratch,
		 hyperscanCustomEventHandler, id);
    
    if(rc == HS_SCAN_TERMINATED) {
#ifdef DEBUG
      printf("[HS] Found category %lu for %s\n", *id, name);
#endif
      return(0);
    } else
      return(-1);
  }
#else
  return(ndpi_match_string_id(ndpi_str->custom_categories.hostnames.ac_automa, name, name_len, id));
#endif
}

/* *********************************************** */

int ndpi_get_custom_category_match(struct ndpi_detection_module_struct *ndpi_str,
				   char *name_or_ip, u_int name_len, unsigned long *id) {
  char ipbuf[64], *ptr;
  struct in_addr pin;
  u_int cp_len = ndpi_min(sizeof(ipbuf)-1, name_len);

  if(!ndpi_str->custom_categories.categories_loaded)
    return(-1);

  if(cp_len > 0) {
    memcpy(ipbuf, name_or_ip, cp_len);
    ipbuf[cp_len] = '\0';
  } else
    ipbuf[0] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr)
    ptr[0] = '\0';

  if(inet_pton(AF_INET, ipbuf, &pin) == 1) {
    /* Search IP */
    prefix_t prefix;
    patricia_node_t *node;

    /* Make sure all in network byte order otherwise compares wont work */
    fill_prefix_v4(&prefix, &pin, 32, ((patricia_tree_t*)ndpi_str->protocols_ptree)->maxbits);
    node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);

    if(node) {
      *id = node->value.user_value;
      return(0);
    }

    return(-1);
  } else
    /* Search Host */
    return(ndpi_match_custom_category(ndpi_str, name_or_ip, name_len, id));
}

/* *********************************************** */

static void free_ptree_data(void *data) { ; }

/* ****************************************************** */

void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str != NULL) {
    int i;

    for(i=0; i<(NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS); i++) {
      if(ndpi_str->proto_defaults[i].protoName)
	ndpi_free(ndpi_str->proto_defaults[i].protoName);
    }

    /* NDPI_PROTOCOL_TINC */
    if(ndpi_str->tinc_cache)
      cache_free((cache_t)(ndpi_str->tinc_cache));

    if(ndpi_str->ookla_cache)
      ndpi_lru_free_cache(ndpi_str->ookla_cache);

    if(ndpi_str->stun_cache)
      ndpi_lru_free_cache(ndpi_str->stun_cache);

    if(ndpi_str->protocols_ptree)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->protocols_ptree, free_ptree_data);

    if(ndpi_str->udpRoot != NULL)
      ndpi_tdestroy(ndpi_str->udpRoot, ndpi_free);
    if(ndpi_str->tcpRoot != NULL)
      ndpi_tdestroy(ndpi_str->tcpRoot, ndpi_free);

    if(ndpi_str->host_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->host_automa.ac_automa, 1 /* free patterns strings memory */);

    if(ndpi_str->content_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->content_automa.ac_automa, 0);

    if(ndpi_str->bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->bigrams_automa.ac_automa, 0);

    if(ndpi_str->impossible_bigrams_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->impossible_bigrams_automa.ac_automa, 0);

#ifdef HAVE_HYPERSCAN
    destroy_hyperscan(ndpi_str);

    while(ndpi_str->custom_categories.to_load != NULL) {
      struct hs_list *next = ndpi_str->custom_categories.to_load->next;

      ndpi_free(ndpi_str->custom_categories.to_load->expression);
      ndpi_free(ndpi_str->custom_categories.to_load);
      ndpi_str->custom_categories.to_load = next;
    }

    free_hyperscan_memory(ndpi_str->custom_categories.hostnames);
#else
    if(ndpi_str->custom_categories.hostnames.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames.ac_automa, 1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.hostnames_shadow.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames_shadow.ac_automa, 1 /* free patterns strings memory */);
#endif

    if(ndpi_str->custom_categories.ipAddresses != NULL)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->custom_categories.ipAddresses, free_ptree_data);

    if(ndpi_str->custom_categories.ipAddresses_shadow != NULL)
      ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->custom_categories.ipAddresses_shadow, free_ptree_data);

    ndpi_free(ndpi_str);
  }
}

/* ****************************************************** */

int ndpi_get_protocol_id_master_proto(struct ndpi_detection_module_struct *ndpi_str,
				      u_int16_t protocol_id,
				      u_int16_t** tcp_master_proto,
				      u_int16_t** udp_master_proto) {
  if(protocol_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS)) {
    *tcp_master_proto = ndpi_str->proto_defaults[NDPI_PROTOCOL_UNKNOWN].master_tcp_protoId,
      *udp_master_proto = ndpi_str->proto_defaults[NDPI_PROTOCOL_UNKNOWN].master_udp_protoId;
    return(-1);
  }

  *tcp_master_proto = ndpi_str->proto_defaults[protocol_id].master_tcp_protoId,
    *udp_master_proto = ndpi_str->proto_defaults[protocol_id].master_udp_protoId;

  return(0);
}

/* ****************************************************** */

static ndpi_default_ports_tree_node_t* ndpi_get_guessed_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
								    u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  ndpi_default_ports_tree_node_t node;

  if(sport && dport) {
    int low  = ndpi_min(sport, dport);
    int high = ndpi_max(sport, dport);
    const void *ret;

    node.default_port = low; /* Check server port first */
    ret = ndpi_tfind(&node,
		     (proto == IPPROTO_TCP) ? (void*)&ndpi_str->tcpRoot : (void*)&ndpi_str->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = high;
      ret = ndpi_tfind(&node,
		       (proto == IPPROTO_TCP) ? (void*)&ndpi_str->tcpRoot : (void*)&ndpi_str->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret) return(*(ndpi_default_ports_tree_node_t**)ret);
  }

  return(NULL);
}

/* ****************************************************** */

/*
  These are UDP protocols that must fit a single packet
  and thus that if have NOT been detected they cannot be guessed
  as they have been excluded
*/
u_int8_t is_udp_guessable_protocol(u_int16_t l7_guessed_proto) {
  switch(l7_guessed_proto) {
  case NDPI_PROTOCOL_QUIC:
  case NDPI_PROTOCOL_SNMP:
  case NDPI_PROTOCOL_NETFLOW:
    /* TODO: add more protocols (if any missing) */
    return(1);
  }

  return(0);
}

/* ****************************************************** */

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow,
				 u_int8_t proto, u_int16_t sport, u_int16_t dport,
				 u_int8_t *user_defined_proto) {
  *user_defined_proto = 0; /* Default */

  if(sport && dport) {
    ndpi_default_ports_tree_node_t *found = ndpi_get_guessed_protocol_id(ndpi_str, proto, sport, dport);

    if(found != NULL) {
      u_int16_t guessed_proto = found->proto->protoId;

      /* We need to check if the guessed protocol isn't excluded by nDPI */
      if(flow
	 && (proto == IPPROTO_UDP)
	 && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, guessed_proto)
	 && is_udp_guessable_protocol(guessed_proto)
	 )
	return(NDPI_PROTOCOL_UNKNOWN);
      else {
	*user_defined_proto = found->customUserProto;
	return(guessed_proto);
      }
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

u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str->ndpi_num_supported_protocols);
}

/* ******************************************************************** */

#ifdef WIN32
char * strsep(char **sp, char *sep)
{
  char *p, *s;
  if(sp == NULL || *sp == NULL || **sp == '\0') return(NULL);
  s = *sp;
  p = s + strcspn(s, sep);
  if(*p != '\0') *p++ = '\0';
  *sp = p;
  return(s);
}
#endif

/* ******************************************************************** */

int ndpi_handle_rule(struct ndpi_detection_module_struct *ndpi_str,
		     char* rule, u_int8_t do_add) {
  char *at, *proto, *elem;
  ndpi_proto_defaults_t *def;
  int subprotocol_id, i;

  at = strrchr(rule, '@');
  if(at == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Invalid rule '%s'\n", rule);
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

  for(i=0, def = NULL; i<(int)ndpi_str->ndpi_num_supported_protocols; i++) {
    if(ndpi_str->proto_defaults[i].protoName && strcasecmp(ndpi_str->proto_defaults[i].protoName, proto) == 0) {
      def = &ndpi_str->proto_defaults[i];
      subprotocol_id = i;
      break;
    }
  }

  if(def == NULL) {
    if(!do_add) {
      /* We need to remove a rule */
      NDPI_LOG_ERR(ndpi_str, "Unable to find protocol '%s': skipping rule '%s'\n", proto, rule);
      return(-3);
    } else {
      ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
      u_int16_t no_master[2] = { NDPI_PROTOCOL_NO_MASTER_PROTO, NDPI_PROTOCOL_NO_MASTER_PROTO };

      if(ndpi_str->ndpi_num_custom_protocols >= (NDPI_MAX_NUM_CUSTOM_PROTOCOLS-1)) {
	NDPI_LOG_ERR(ndpi_str, "Too many protocols defined (%u): skipping protocol %s\n",
		     ndpi_str->ndpi_num_custom_protocols, proto);
	return(-2);
      }

      ndpi_set_proto_defaults(ndpi_str, NDPI_PROTOCOL_ACCEPTABLE,
			      ndpi_str->ndpi_num_supported_protocols,
			      0 /* can_have_a_subprotocol */, no_master,
			      no_master,
			      proto,
			      NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, /* TODO add protocol category support in rules */
			      ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			      ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
      def = &ndpi_str->proto_defaults[ndpi_str->ndpi_num_supported_protocols];
      subprotocol_id = ndpi_str->ndpi_num_supported_protocols;
      ndpi_str->ndpi_num_supported_protocols++, ndpi_str->ndpi_num_custom_protocols++;
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
      u_int p_low, p_high;

      if(sscanf(value, "%u-%u", &p_low, &p_high) == 2)
	range.port_low = p_low, range.port_high = p_high;
      else
	range.port_low = range.port_high = atoi(&elem[4]);

      if(do_add)
	addDefaultPort(ndpi_str, &range, def, 1 /* Custom user proto */,
		       is_tcp ? &ndpi_str->tcpRoot : &ndpi_str->udpRoot, __FUNCTION__,__LINE__);
      else
	removeDefaultPort(&range, def, is_tcp ? &ndpi_str->tcpRoot : &ndpi_str->udpRoot);
    } else if(is_ip) {
      /* NDPI_PROTOCOL_TOR */
      ndpi_add_host_ip_subprotocol(ndpi_str, value, subprotocol_id);
    } else {
      if(do_add)
	ndpi_add_host_url_subprotocol(ndpi_str, value, subprotocol_id,
				      NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
				      NDPI_PROTOCOL_ACCEPTABLE);
      else
	ndpi_remove_host_url_subprotocol(ndpi_str, value, subprotocol_id);
    }
  }

  return(0);
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <host|ip>	<category_id>
 *
 * Notes:
 *  - host and category are separated by a single TAB
 *  - empty lines or lines starting with # are ignored
 */
int ndpi_load_categories_file(struct ndpi_detection_module_struct *ndpi_str, const char* path) {
  char buffer[512], *line, *name, *category, *saveptr;
  FILE *fd;
  int len, num = 0;

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len-1] = '\0';
    name = strtok_r(line, "\t", &saveptr);

    if(name) {
      category = strtok_r(NULL, "\t", &saveptr);

      if(category) {
        int rc = ndpi_load_category(ndpi_str, name, (ndpi_protocol_category_t) atoi(category));

	if(rc >= 0)
	  num++;
      }
    }
  }

  fclose(fd);
  ndpi_enable_loaded_categories(ndpi_str);

  return(num);
}

/* ******************************************************************** */

/*
  Format:
  <tcp|udp>:<port>,<tcp|udp>:<port>,.....@<proto>

  Subprotocols Format:
  host:"<value>",host:"<value>",.....@<subproto>

  IP based Subprotocols Format (<value> is IP or CIDR):
  ip:<value>,ip:<value>,.....@<subproto>

  Example:
  tcp:80,tcp:3128@HTTP
  udp:139@NETBIOS

*/
int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_str, const char* path) {
  FILE *fd;
  char *buffer, *old_buffer;
  int chunk_len = 512, buffer_len = chunk_len, old_buffer_len;
  int i, rc = -1;

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    goto error;
  }

  buffer = ndpi_malloc(buffer_len);

  if(buffer == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Memory allocation failure\n");
    goto close_fd;
  }

  while(1) {
    char *line = buffer;
    int line_len = buffer_len;

    while((line = fgets(line, line_len, fd)) != NULL && line[strlen(line)-1] != '\n') {
      i = strlen(line);
      old_buffer = buffer;
      old_buffer_len = buffer_len;
      buffer_len += chunk_len;

      buffer = ndpi_realloc(old_buffer, old_buffer_len, buffer_len);

      if(buffer == NULL) {
        NDPI_LOG_ERR(ndpi_str, "Memory allocation failure\n");
        ndpi_free(old_buffer);
        goto close_fd;
      }

      line = &buffer[i];
      line_len = chunk_len;
    }

    if(!line) /* safety check */
      break;

    i = strlen(buffer);
    if((i <= 1) || (buffer[0] == '#'))
      continue;
    else
      buffer[i-1] = '\0';

    ndpi_handle_rule(ndpi_str, buffer, 1);
  }

  rc = 0;

  ndpi_free(buffer);

 close_fd:
  fclose(fd);

 error:
  return(rc);
}

/* ******************************************************************** */

/* ntop */
void ndpi_set_bitmask_protocol_detection(char * label,
					 struct ndpi_detection_module_struct *ndpi_str,
					 const NDPI_PROTOCOL_BITMASK * detection_bitmask,
					 const u_int32_t idx,
					 u_int16_t ndpi_protocol_id,
					 void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow),
					 const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
					 u_int8_t b_save_bitmask_unknow,
					 u_int8_t b_add_detection_bitmask) {
  /*
    Compare specify protocol bitmask with main detection bitmask
  */
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(*detection_bitmask, ndpi_protocol_id) != 0) {
#ifdef DEBUG
    NDPI_LOG_DBG2(ndpi_str
		  "[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] protocol_id=%u\n",
		  label, idx, ndpi_protocol_id);
#endif

    if(ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx != 0) {
      NDPI_LOG_DBG2(ndpi_str,
		    "[NDPI] Internal error: protocol %s/%u has been already registered\n", label, ndpi_protocol_id);
#ifdef DEBUG
    } else {
      NDPI_LOG_DBG2(ndpi_str,
		    "[NDPI] Adding %s with protocol id %d\n", label, ndpi_protocol_id);
#endif
    }

    /*
      Set function and index protocol within proto_default structure for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
    ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx = idx;
    ndpi_str->proto_defaults[ndpi_protocol_id].func = ndpi_str->callback_buffer[idx].func = func;

    /*
      Set ndpi_selection_bitmask for protocol
    */
    ndpi_str->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

    /*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
    if(b_save_bitmask_unknow) NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
    if(b_add_detection_bitmask) NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

    NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].excluded_protocol_bitmask, ndpi_protocol_id);
  }
}

/* ******************************************************************** */

void ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_str,
					  const NDPI_PROTOCOL_BITMASK * dbm) {
  NDPI_PROTOCOL_BITMASK detection_bitmask_local;
  NDPI_PROTOCOL_BITMASK *detection_bitmask = &detection_bitmask_local;
  u_int32_t a = 0;

  NDPI_BITMASK_SET(detection_bitmask_local, *dbm);
  NDPI_BITMASK_SET(ndpi_str->detection_bitmask, *dbm);

  /* set this here to zero to be interrupt safe */
  ndpi_str->callback_buffer_size = 0;

  /* HTTP */
  init_http_dissector(ndpi_str, &a, detection_bitmask);

  /* STARCRAFT */
  init_starcraft_dissector(ndpi_str, &a, detection_bitmask);

  /* TLS */
  init_tls_dissector(ndpi_str, &a, detection_bitmask);

  /* STUN */
  init_stun_dissector(ndpi_str, &a, detection_bitmask);

  /* RTP */
  init_rtp_dissector(ndpi_str, &a, detection_bitmask);

  /* RTSP */
  init_rtsp_dissector(ndpi_str, &a, detection_bitmask);

  /* RDP */
  init_rdp_dissector(ndpi_str, &a, detection_bitmask);

  /* SIP */
  init_sip_dissector(ndpi_str, &a, detection_bitmask);

  /* IMO */
  init_imo_dissector(ndpi_str, &a, detection_bitmask);

  /* Teredo */
  init_teredo_dissector(ndpi_str, &a, detection_bitmask);

  /* EDONKEY */
  init_edonkey_dissector(ndpi_str, &a, detection_bitmask);

  /* FASTTRACK */
  init_fasttrack_dissector(ndpi_str, &a, detection_bitmask);

  /* GNUTELLA */
  init_gnutella_dissector(ndpi_str, &a, detection_bitmask);

  /* DIRECTCONNECT */
  init_directconnect_dissector(ndpi_str, &a, detection_bitmask);

  /* MSN */
  init_msn_dissector(ndpi_str, &a, detection_bitmask);

  /* YAHOO */
  init_yahoo_dissector(ndpi_str, &a, detection_bitmask);

  /* OSCAR */
  init_oscar_dissector(ndpi_str, &a, detection_bitmask);

  /* APPLEJUICE */
  init_applejuice_dissector(ndpi_str, &a, detection_bitmask);

  /* SOULSEEK */
  init_soulseek_dissector(ndpi_str, &a, detection_bitmask);

  /* SOCKS */
  init_socks_dissector(ndpi_str, &a, detection_bitmask);

  /* IRC */
  init_irc_dissector(ndpi_str, &a, detection_bitmask);

  /* JABBER */
  init_jabber_dissector(ndpi_str, &a, detection_bitmask);

  /* MAIL_POP */
  init_mail_pop_dissector(ndpi_str, &a, detection_bitmask);

  /* MAIL_IMAP */
  init_mail_imap_dissector(ndpi_str, &a, detection_bitmask);

  /* MAIL_SMTP */
  init_mail_smtp_dissector(ndpi_str, &a, detection_bitmask);

  /* USENET */
  init_usenet_dissector(ndpi_str, &a, detection_bitmask);

  /* DNS */
  init_dns_dissector(ndpi_str, &a, detection_bitmask);

  /* FILETOPIA */
  init_fbzero_dissector(ndpi_str, &a, detection_bitmask);

  /* VMWARE */
  init_vmware_dissector(ndpi_str, &a, detection_bitmask);

  /* NON_TCP_UDP */
  init_non_tcp_udp_dissector(ndpi_str, &a, detection_bitmask);

  /* TVANTS */
  init_tvants_dissector(ndpi_str, &a, detection_bitmask);

  /* SOPCAST */
  init_sopcast_dissector(ndpi_str, &a, detection_bitmask);

  /* TVUPLAYER */
  init_tvuplayer_dissector(ndpi_str, &a, detection_bitmask);

  /* PPSTREAM */
  init_ppstream_dissector(ndpi_str, &a, detection_bitmask);

  /* PPLIVE */
  init_pplive_dissector(ndpi_str, &a, detection_bitmask);

  /* IAX */
  init_iax_dissector(ndpi_str, &a, detection_bitmask);

  /* MGPC */
  init_mgpc_dissector(ndpi_str, &a, detection_bitmask);

  /* ZATTOO */
  init_zattoo_dissector(ndpi_str, &a, detection_bitmask);

  /* QQ */
  init_qq_dissector(ndpi_str, &a, detection_bitmask);

  /* SSH */
  init_ssh_dissector(ndpi_str, &a, detection_bitmask);

  /* AYIYA */
  init_ayiya_dissector(ndpi_str, &a, detection_bitmask);

  /* THUNDER */
  init_thunder_dissector(ndpi_str, &a, detection_bitmask);

  /* VNC */
  init_vnc_dissector(ndpi_str, &a, detection_bitmask);

  /* TEAMVIEWER */
  init_teamviewer_dissector(ndpi_str, &a, detection_bitmask);

  /* DHCP */
  init_dhcp_dissector(ndpi_str, &a, detection_bitmask);

  /* STEAM */
  init_steam_dissector(ndpi_str, &a, detection_bitmask);

  /* HALFLIFE2 */
  init_halflife2_dissector(ndpi_str, &a, detection_bitmask);

  /* XBOX */
  init_xbox_dissector(ndpi_str, &a, detection_bitmask);

  /* HTTP_APPLICATION_ACTIVESYNC */
  init_http_activesync_dissector(ndpi_str, &a, detection_bitmask);

  /* SMB */
  init_smb_dissector(ndpi_str, &a, detection_bitmask);

  /* MINING */
  init_mining_dissector(ndpi_str, &a, detection_bitmask);

  /* TELNET */
  init_telnet_dissector(ndpi_str, &a, detection_bitmask);

  /* NTP */
  init_ntp_dissector(ndpi_str, &a, detection_bitmask);

  /* NFS */
  init_nfs_dissector(ndpi_str, &a, detection_bitmask);

  /* SSDP */
  init_ssdp_dissector(ndpi_str, &a, detection_bitmask);

  /* WORLD_OF_WARCRAFT */
  init_world_of_warcraft_dissector(ndpi_str, &a, detection_bitmask);

  /* POSTGRES */
  init_postgres_dissector(ndpi_str, &a, detection_bitmask);

  /* MYSQL */
  init_mysql_dissector(ndpi_str, &a, detection_bitmask);

  /* BGP */
  init_bgp_dissector(ndpi_str, &a, detection_bitmask);

  /* BATTLEFIELD */
  init_battlefield_dissector(ndpi_str, &a, detection_bitmask);

  /* PCANYWHERE */
  init_pcanywhere_dissector(ndpi_str, &a, detection_bitmask);

  /* SNMP */
  init_snmp_dissector(ndpi_str, &a, detection_bitmask);

  /* KONTIKI */
  init_kontiki_dissector(ndpi_str, &a, detection_bitmask);

  /* ICECAST */
  init_icecast_dissector(ndpi_str, &a, detection_bitmask);

  /* SHOUTCAST */
  init_shoutcast_dissector(ndpi_str, &a, detection_bitmask);

  /* KERBEROS */
  init_kerberos_dissector(ndpi_str, &a, detection_bitmask);

  /* OPENFT */
  init_openft_dissector(ndpi_str, &a, detection_bitmask);

  /* SYSLOG */
  init_syslog_dissector(ndpi_str, &a, detection_bitmask);

  /* DIRECT_DOWNLOAD_LINK */
  init_directdownloadlink_dissector(ndpi_str, &a, detection_bitmask);

  /* NETBIOS */
  init_netbios_dissector(ndpi_str, &a, detection_bitmask);

  /* MDNS */
  init_mdns_dissector(ndpi_str, &a, detection_bitmask);

  /* IPP */
  init_ipp_dissector(ndpi_str, &a, detection_bitmask);

  /* LDAP */
  init_ldap_dissector(ndpi_str, &a, detection_bitmask);

  /* WARCRAFT3 */
  init_warcraft3_dissector(ndpi_str, &a, detection_bitmask);

  /* XDMCP */
  init_xdmcp_dissector(ndpi_str, &a, detection_bitmask);

  /* TFTP */
  init_tftp_dissector(ndpi_str, &a, detection_bitmask);

  /* MSSQL_TDS */
  init_mssql_tds_dissector(ndpi_str, &a, detection_bitmask);

  /* PPTP */
  init_pptp_dissector(ndpi_str, &a, detection_bitmask);

  /* STEALTHNET */
  init_stealthnet_dissector(ndpi_str, &a, detection_bitmask);

  /* DHCPV6 */
  init_dhcpv6_dissector(ndpi_str, &a, detection_bitmask);

  /* AFP */
  init_afp_dissector(ndpi_str, &a, detection_bitmask);

  /* check_mk */
  init_checkmk_dissector(ndpi_str, &a, detection_bitmask);

  /* AIMINI */
  init_aimini_dissector(ndpi_str, &a, detection_bitmask);

  /* FLORENSIA */
  init_florensia_dissector(ndpi_str, &a, detection_bitmask);

  /* MAPLESTORY */
  init_maplestory_dissector(ndpi_str, &a, detection_bitmask);

  /* DOFUS */
  init_dofus_dissector(ndpi_str, &a, detection_bitmask);

  /* WORLD_OF_KUNG_FU */
  init_world_of_kung_fu_dissector(ndpi_str, &a, detection_bitmask);

  /* FIESTA */
  init_fiesta_dissector(ndpi_str, &a, detection_bitmask);

  /* CROSSIFIRE */
  init_crossfire_dissector(ndpi_str, &a, detection_bitmask);

  /* GUILDWARS */
  init_guildwars_dissector(ndpi_str, &a, detection_bitmask);

  /* ARMAGETRON */
  init_armagetron_dissector(ndpi_str, &a, detection_bitmask);

  /* DROPBOX */
  init_dropbox_dissector(ndpi_str, &a, detection_bitmask);

  /* SPOTIFY */
  init_spotify_dissector(ndpi_str, &a, detection_bitmask);

  /* RADIUS */
  init_radius_dissector(ndpi_str, &a, detection_bitmask);

  /* CITRIX */
  init_citrix_dissector(ndpi_str, &a, detection_bitmask);

  /* LOTUS_NOTES */
  init_lotus_notes_dissector(ndpi_str, &a, detection_bitmask);

  /* GTP */
  init_gtp_dissector(ndpi_str, &a, detection_bitmask);

  /* DCERPC */
  init_dcerpc_dissector(ndpi_str, &a, detection_bitmask);

  /* NETFLOW */
  init_netflow_dissector(ndpi_str, &a, detection_bitmask);

  /* SFLOW */
  init_sflow_dissector(ndpi_str, &a, detection_bitmask);

  /* H323 */
  init_h323_dissector(ndpi_str, &a, detection_bitmask);

  /* OPENVPN */
  init_openvpn_dissector(ndpi_str, &a, detection_bitmask);

  /* NOE */
  init_noe_dissector(ndpi_str, &a, detection_bitmask);

  /* CISCOVPN */
  init_ciscovpn_dissector(ndpi_str, &a, detection_bitmask);

  /* TEAMSPEAK */
  init_teamspeak_dissector(ndpi_str, &a, detection_bitmask);

  /* TOR */
  init_tor_dissector(ndpi_str, &a, detection_bitmask);

  /* SKINNY */
  init_skinny_dissector(ndpi_str, &a, detection_bitmask);

  /* RTCP */
  init_rtcp_dissector(ndpi_str, &a, detection_bitmask);

  /* RSYNC */
  init_rsync_dissector(ndpi_str, &a, detection_bitmask);

  /* WHOIS_DAS */
  init_whois_das_dissector(ndpi_str, &a, detection_bitmask);

  /* ORACLE */
  init_oracle_dissector(ndpi_str, &a, detection_bitmask);

  /* CORBA */
  init_corba_dissector(ndpi_str, &a, detection_bitmask);

  /* RTMP */
  init_rtmp_dissector(ndpi_str, &a, detection_bitmask);

  /* FTP_CONTROL */
  init_ftp_control_dissector(ndpi_str, &a, detection_bitmask);

  /* FTP_DATA */
  init_ftp_data_dissector(ndpi_str, &a, detection_bitmask);

  /* PANDO */
  init_pando_dissector(ndpi_str, &a, detection_bitmask);

  /* MEGACO */
  init_megaco_dissector(ndpi_str, &a, detection_bitmask);

  /* REDIS */
  init_redis_dissector(ndpi_str, &a, detection_bitmask);

  /* UPnP */
  init_upnp_dissector(ndpi_str, &a, detection_bitmask);

  /* VHUA */
  init_vhua_dissector(ndpi_str, &a, detection_bitmask);

  /* ZMQ */
  init_zmq_dissector(ndpi_str, &a, detection_bitmask);

  /* TELEGRAM */
  init_telegram_dissector(ndpi_str, &a, detection_bitmask);

  /* QUIC */
  init_quic_dissector(ndpi_str, &a, detection_bitmask);

  /* DIAMETER */
  init_diameter_dissector(ndpi_str, &a, detection_bitmask);

  /* APPLE_PUSH */
  init_apple_push_dissector(ndpi_str, &a, detection_bitmask);

  /* EAQ */
  init_eaq_dissector(ndpi_str, &a, detection_bitmask);

  /* KAKAOTALK_VOICE */
  init_kakaotalk_voice_dissector(ndpi_str, &a, detection_bitmask);

  /* MPEGTS */
  init_mpegts_dissector(ndpi_str, &a, detection_bitmask);

  /* UBNTAC2 */
  init_ubntac2_dissector(ndpi_str, &a, detection_bitmask);

  /* COAP */
  init_coap_dissector(ndpi_str, &a, detection_bitmask);

  /* MQTT */
  init_mqtt_dissector(ndpi_str, &a, detection_bitmask);

  /* SOME/IP */
  init_someip_dissector(ndpi_str, &a, detection_bitmask);

  /* RX */
  init_rx_dissector(ndpi_str, &a, detection_bitmask);

  /* GIT */
  init_git_dissector(ndpi_str, &a, detection_bitmask);

  /* HANGOUT */
  init_hangout_dissector(ndpi_str, &a, detection_bitmask);

  /* DRDA */
  init_drda_dissector(ndpi_str, &a, detection_bitmask);

  /* BJNP */
  init_bjnp_dissector(ndpi_str, &a, detection_bitmask);

  /* SMPP */
  init_smpp_dissector(ndpi_str, &a, detection_bitmask);

  /* TINC */
  init_tinc_dissector(ndpi_str, &a, detection_bitmask);

  /* FIX */
  init_fix_dissector(ndpi_str, &a, detection_bitmask);

  /* NINTENDO */
  init_nintendo_dissector(ndpi_str, &a, detection_bitmask);

  /* MODBUS */
  init_modbus_dissector(ndpi_str, &a, detection_bitmask);

  /* CAPWAP */
  init_capwap_dissector(ndpi_str, &a, detection_bitmask);

  /* ZABBIX */
  init_zabbix_dissector(ndpi_str, &a, detection_bitmask);

  /*** Put false-positive sensitive protocols at the end ***/

  /* VIBER */
  init_viber_dissector(ndpi_str, &a, detection_bitmask);

  /* SKYPE */
  init_skype_dissector(ndpi_str, &a, detection_bitmask);

  /* BITTORRENT */
  init_bittorrent_dissector(ndpi_str, &a, detection_bitmask);

  /* WHATSAPP */
  init_whatsapp_dissector(ndpi_str, &a, detection_bitmask);

  /* OOKLA */
  init_ookla_dissector(ndpi_str, &a, detection_bitmask);

  /* AMQP */
  init_amqp_dissector(ndpi_str, &a, detection_bitmask);

  /* CSGO */
  init_csgo_dissector(ndpi_str, &a, detection_bitmask);

  /* LISP */
  init_lisp_dissector(ndpi_str, &a, detection_bitmask);

  /* AJP */
  init_ajp_dissector(ndpi_str, &a, detection_bitmask);

  /* Memcached */
  init_memcached_dissector(ndpi_str, &a, detection_bitmask);

  /* Nest Log Sink */
  init_nest_log_sink_dissector(ndpi_str, &a, detection_bitmask);

  /* WireGuard VPN */
  init_wireguard_dissector(ndpi_str, &a, detection_bitmask);

  /* Amazon_Video */
  init_amazon_video_dissector(ndpi_str, &a, detection_bitmask);

  /* Targus Getdata */
  init_targus_getdata_dissector(ndpi_str, &a, detection_bitmask);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main_init.c"
#endif

  /* ----------------------------------------------------------------- */

  ndpi_str->callback_buffer_size = a;

  NDPI_LOG_DBG2(ndpi_str,
		"callback_buffer_size is %u\n", ndpi_str->callback_buffer_size);

  /* now build the specific buffer for tcp, udp and non_tcp_udp */
  ndpi_str->callback_buffer_size_tcp_payload = 0;
  ndpi_str->callback_buffer_size_tcp_no_payload = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if((ndpi_str->callback_buffer[a].ndpi_selection_bitmask
	& (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	   NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
	   NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0) {
      if(_ndpi_debug_callbacks) NDPI_LOG_DBG2(ndpi_str,
					      "callback_buffer_tcp_payload, adding buffer %u as entry %u\n", a,
					      ndpi_str->callback_buffer_size_tcp_payload);

      memcpy(&ndpi_str->callback_buffer_tcp_payload[ndpi_str->callback_buffer_size_tcp_payload],
	     &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_str->callback_buffer_size_tcp_payload++;

      if((ndpi_str->
	  callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0) {
	if(_ndpi_debug_callbacks) NDPI_LOG_DBG2(ndpi_str,
						"\tcallback_buffer_tcp_no_payload, additional adding buffer %u to no_payload process\n", a);

	memcpy(&ndpi_str->callback_buffer_tcp_no_payload
	       [ndpi_str->callback_buffer_size_tcp_no_payload], &ndpi_str->callback_buffer[a],
	       sizeof(struct ndpi_call_function_struct));
	ndpi_str->callback_buffer_size_tcp_no_payload++;
      }
    }
  }

  ndpi_str->callback_buffer_size_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC))
       != 0) {
      if(_ndpi_debug_callbacks) NDPI_LOG_DBG2(ndpi_str,
					      "callback_buffer_size_udp: adding buffer : %u as entry %u\n", a, ndpi_str->callback_buffer_size_udp);

      memcpy(&ndpi_str->callback_buffer_udp[ndpi_str->callback_buffer_size_udp],
	     &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_str->callback_buffer_size_udp++;
    }
  }

  ndpi_str->callback_buffer_size_non_tcp_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if((ndpi_str->callback_buffer[a].ndpi_selection_bitmask & (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
								  NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)) == 0
       || (ndpi_str->
	   callback_buffer[a].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC) != 0) {
      if(_ndpi_debug_callbacks) NDPI_LOG_DBG2(ndpi_str,
					      "callback_buffer_non_tcp_udp: adding buffer : %u as entry %u\n", a, ndpi_str->callback_buffer_size_non_tcp_udp);

      memcpy(&ndpi_str->callback_buffer_non_tcp_udp[ndpi_str->callback_buffer_size_non_tcp_udp],
	     &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
      ndpi_str->callback_buffer_size_non_tcp_udp++;
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
static int ndpi_handle_ipv6_extension_headers(struct ndpi_detection_module_struct *ndpi_str, const u_int8_t ** l4ptr, u_int16_t * l4len, u_int8_t * nxt_hdr)
{
  while((*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len;

    // no next header
    if(*nxt_hdr == 59) {
      return(1);
    }
    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return(1);
      }
      *nxt_hdr = (*l4ptr)[0];
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }
    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    if (*l4len < 2) {
      return(1);
    }
    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(*l4len < ehdr_len) {
      return(1);
    }
    *nxt_hdr = (*l4ptr)[0];
    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }
  return(0);
}
#endif /* NDPI_DETECTION_SUPPORT_IPV6 */


static u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize)
{
  //#ifdef REQUIRE_FULL_PACKETS
  if(ipsize < iph->ihl * 4 ||
     ipsize < ntohs(iph->tot_len) || ntohs(iph->tot_len) < iph->ihl * 4 || (iph->frag_off & htons(0x1FFF)) != 0) {
    return(0);
  }
  //#endif

  return(1);
}

static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_str,
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
    return(1);

  if((iph = (const struct ndpi_iphdr *) l3) == NULL)
    return(1);

  if(iph->version == IPVERSION && iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr)) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    iph_v6 = (const struct ndpi_ipv6hdr *) l3;
    iph = NULL;
  }
#endif
  else {
    return(1);
  }

  if((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header found but excluded by flag\n");
    return(1);
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header found but excluded by flag\n");
    return(1);
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
  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->ip6_hdr.ip6_un1_plen)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->ip6_hdr.ip6_un1_plen);
    l4protocol = iph_v6->ip6_hdr.ip6_un1_nxt;

    // we need to handle IPv6 extension headers if present
    if(ndpi_handle_ipv6_extension_headers(ndpi_str, &l4ptr, &l4len, &l4protocol) != 0) {
      return(1);
    }

  }
#endif
  else {
    return(1);
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

  return(0);
}

void ndpi_apply_flow_protocol_to_packet(struct ndpi_flow_struct *flow,
					struct ndpi_packet_struct *packet)
{
  memcpy(&packet->detected_protocol_stack, &flow->detected_protocol_stack, sizeof(packet->detected_protocol_stack));
  memcpy(&packet->protocol_stack_info, &flow->protocol_stack_info, sizeof(packet->protocol_stack_info));
}

static int ndpi_init_packet_header(struct ndpi_detection_module_struct *ndpi_str,
				   struct ndpi_flow_struct *flow,
				   unsigned short packetlen) {
  const struct ndpi_iphdr *decaps_iph = NULL;
  u_int16_t l3len;
  u_int16_t l4len;
  const u_int8_t *l4ptr;
  u_int8_t l4protocol;
  u_int8_t l4_result;

  if (!flow)
    return(1);

  /* reset payload_packet_len, will be set if ipv4 tcp or udp */
  flow->packet.payload_packet_len = 0;
  flow->packet.l4_packet_len = 0;
  flow->packet.l3_packet_len = packetlen;

  flow->packet.tcp = NULL, flow->packet.udp = NULL;
  flow->packet.generic_l4_ptr = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  flow->packet.iphv6 = NULL;
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  ndpi_apply_flow_protocol_to_packet(flow, &flow->packet);

  l3len = flow->packet.l3_packet_len;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iph != NULL) {
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

    decaps_iph = flow->packet.iph;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  }
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if(decaps_iph && decaps_iph->version == IPVERSION && decaps_iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(decaps_iph && decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
	  (ndpi_str->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    flow->packet.iphv6 = (struct ndpi_ipv6hdr *)flow->packet.iph;
    flow->packet.iph = NULL;
  }
#endif
  else {
    flow->packet.iph = NULL;
    return(1);
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
    ndpi_detection_get_l4_internal(ndpi_str, (const u_int8_t *) decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

  if(l4_result != 0) {
    return(1);
  }

  flow->packet.l4_protocol = l4protocol;
  flow->packet.l4_packet_len = l4len;
  flow->l4_proto = l4protocol;

  /* tcp / udp detection */
  if(l4protocol == IPPROTO_TCP && flow->packet.l4_packet_len >= 20 /* min size of tcp */ ) {
    /* tcp */
    flow->packet.tcp = (struct ndpi_tcphdr *) l4ptr;
    if(flow->packet.l4_packet_len >=flow->packet.tcp->doff * 4) {
      flow->packet.payload_packet_len =
	flow->packet.l4_packet_len -flow->packet.tcp->doff * 4;
      flow->packet.actual_payload_len = flow->packet.payload_packet_len;
      flow->packet.payload = ((u_int8_t *)flow->packet.tcp) + (flow->packet.tcp->doff * 4);

      /* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
      if(flow->packet.tcp->syn != 0
	 && flow->packet.tcp->ack == 0
	 && flow->init_finished != 0
	 && flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	u_int8_t backup;
	u_int16_t backup1, backup2;

	if(flow->http.url)                  { ndpi_free(flow->http.url); flow->http.url = NULL; }
	if(flow->http.content_type)         { ndpi_free(flow->http.content_type); flow->http.content_type = NULL; }
	if(flow->http.user_agent)           { ndpi_free(flow->http.user_agent); flow->http.user_agent = NULL; }
	if(flow->kerberos_buf.pktbuf) {
		ndpi_free(flow->kerberos_buf.pktbuf);
		flow->kerberos_buf.pktbuf = NULL;
	}
	if(flow->l4.tcp.tls.message.buffer) {
	    ndpi_free(flow->l4.tcp.tls.message.buffer);
	    flow->l4.tcp.tls.message.buffer = NULL;
	    flow->l4.tcp.tls.message.buffer_len = flow->l4.tcp.tls.message.buffer_used = 0;
	}

	backup  = flow->num_processed_pkts;
	backup1 = flow->guessed_protocol_id;
	backup2 = flow->guessed_host_protocol_id;
	memset(flow, 0, sizeof(*(flow)));
	flow->num_processed_pkts = backup;
	flow->guessed_protocol_id      = backup1;
	flow->guessed_host_protocol_id = backup2;

	NDPI_LOG_DBG(ndpi_str,
		     "tcp syn packet for unknown protocol, reset detection state\n");
      }
    } else {
      /* tcp header not complete */
      flow->packet.tcp = NULL;
    }
  } else if(l4protocol == IPPROTO_UDP && flow->packet.l4_packet_len >= 8 /* size of udp */ ) {
    flow->packet.udp = (struct ndpi_udphdr *) l4ptr;
    flow->packet.payload_packet_len =flow->packet.l4_packet_len - 8;
    flow->packet.payload = ((u_int8_t *)flow->packet.udp) + 8;
  } else {
    flow->packet.generic_l4_ptr = l4ptr;
  }

  return(0);
}

void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow) {
  if(!flow) {
    return;
  } else {
    /* const for gcc code optimization and cleaner code */
    struct ndpi_packet_struct *packet = &flow->packet;
    const struct ndpi_iphdr *iph = packet->iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
    const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
#endif
    const struct ndpi_tcphdr *tcph = packet->tcp;
    const struct ndpi_udphdr *udph = flow->packet.udp;

    packet->tcp_retransmission = 0, packet->packet_direction = 0;

    if(ndpi_str->direction_detect_disable) {
      packet->packet_direction = flow->packet_direction;
    } else {
      if(iph != NULL && ntohl(iph->saddr) < ntohl(iph->daddr))
	packet->packet_direction = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
      if(iphv6 != NULL && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->ip6_src,
							    &iphv6->ip6_dst) != 0)
	packet->packet_direction = 1;
#endif
    }

    packet->packet_lines_parsed_complete = 0;

    if(flow->init_finished == 0) {
      flow->init_finished = 1;
      flow->setup_packet_direction = packet->packet_direction;
    }

    if(tcph != NULL) {
      /* reset retried bytes here before setting it */
      packet->num_retried_bytes = 0;

      if(!ndpi_str->direction_detect_disable)
	packet->packet_direction = (ntohs(tcph->source) < ntohs(tcph->dest)) ? 1 : 0;

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
	 || (flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0)) {
	/* initialize tcp sequence counters */
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

	  flow->next_tcp_seq_nr[1 -flow->packet.packet_direction] = ntohl(tcph->ack_seq);
	}
      } else if(packet->payload_packet_len > 0) {
	/* check tcp sequence counters */
	if(((u_int32_t)(ntohl(tcph->seq) - flow->next_tcp_seq_nr[packet->packet_direction])) >
	   ndpi_str->tcp_max_retransmission_window_size) {

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
      if(!ndpi_str->direction_detect_disable)
	packet->packet_direction = (htons(udph->source) < htons(udph->dest)) ? 1 : 0;
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
}

void check_ndpi_other_flow_func(struct ndpi_detection_module_struct *ndpi_str,
				struct ndpi_flow_struct *flow,
				NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {

  if (!flow) {
    return;
  }

  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN)
     && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			     ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
     && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask,
			     detection_bitmask) != 0
     && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask
	 & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask) {
    if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
       && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
      ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
	func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
  }

  for(a = 0; a < ndpi_str->callback_buffer_size_non_tcp_udp; a++) {
    if((func != ndpi_str->callback_buffer_non_tcp_udp[a].func)
       && (ndpi_str->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
       ndpi_str->callback_buffer_non_tcp_udp[a].ndpi_selection_bitmask
       &&
	   NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				ndpi_str->callback_buffer_non_tcp_udp[a].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_non_tcp_udp[a].detection_bitmask,
			       detection_bitmask) != 0) {

      if(ndpi_str->callback_buffer_non_tcp_udp[a].func != NULL)
	ndpi_str->callback_buffer_non_tcp_udp[a].func(ndpi_str, flow);

      if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	break; /* Stop after detecting the first protocol */
    }
  }
}


void check_ndpi_udp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow,
			      NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN)
     && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			     ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
     && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask,
			     detection_bitmask) != 0
     && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask
	 & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask) {
    if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
       && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
      ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
	func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
  }

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    for(a = 0; a < ndpi_str->callback_buffer_size_udp; a++) {
      if((func != ndpi_str->callback_buffer_udp[a].func)
	 && (ndpi_str->callback_buffer_udp[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
	 ndpi_str->callback_buffer_udp[a].ndpi_selection_bitmask
	 && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				 ndpi_str->callback_buffer_udp[a].excluded_protocol_bitmask) == 0
	 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_udp[a].detection_bitmask,
				 detection_bitmask) != 0) {
	ndpi_str->callback_buffer_udp[a].func(ndpi_str, flow);

	// NDPI_LOG_DBG(ndpi_str, "[UDP,CALL] dissector of protocol as callback_buffer idx =  %d\n",a);
	if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	  break; /* Stop after detecting the first protocol */
      } else
	if(_ndpi_debug_callbacks) NDPI_LOG_DBG2(ndpi_str,
						"[UDP,SKIP] dissector of protocol as callback_buffer idx =  %d\n",a);
    }
  }
}


void check_ndpi_tcp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow,
			      NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  void *func = NULL;
  u_int32_t a;
  u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
  int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->packet.detected_protocol_stack[0]);

  if(flow->packet.payload_packet_len != 0) {
    if((proto_id != NDPI_PROTOCOL_UNKNOWN)
       && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			       ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0
       && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask) {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL))
	ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
	  func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
    }

    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
      for(a = 0; a < ndpi_str->callback_buffer_size_tcp_payload; a++) {
	if((func != ndpi_str->callback_buffer_tcp_payload[a].func)
	   && (ndpi_str->callback_buffer_tcp_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) == ndpi_str->callback_buffer_tcp_payload[a].ndpi_selection_bitmask
	   && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				   ndpi_str->callback_buffer_tcp_payload[a].excluded_protocol_bitmask) == 0
	   && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_tcp_payload[a].detection_bitmask,
				   detection_bitmask) != 0) {
	  ndpi_str->callback_buffer_tcp_payload[a].func(ndpi_str, flow);

	  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	    break; /* Stop after detecting the first protocol */
	}
      }
    }
  } else {
    /* no payload */
    if((proto_id != NDPI_PROTOCOL_UNKNOWN)
       && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			       ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0
       && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask,
			       detection_bitmask) != 0
       && (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask
	   & *ndpi_selection_packet) == ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask) {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL)
	 && ((ndpi_str->callback_buffer[flow->guessed_protocol_id].ndpi_selection_bitmask & NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0))
	ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow),
	  func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
    }

    for(a = 0; a < ndpi_str->callback_buffer_size_tcp_no_payload; a++) {
      if((func != ndpi_str->callback_buffer_tcp_payload[a].func)
	 && (ndpi_str->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask & *ndpi_selection_packet) ==
	 ndpi_str->callback_buffer_tcp_no_payload[a].ndpi_selection_bitmask
	 && NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
				 ndpi_str->callback_buffer_tcp_no_payload[a].excluded_protocol_bitmask) == 0
	 && NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer_tcp_no_payload[a].detection_bitmask,
				 detection_bitmask) != 0) {
	ndpi_str->callback_buffer_tcp_no_payload[a].func(ndpi_str, flow);

	if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	  break; /* Stop after detecting the first protocol */
      }
    }
  }
}

/* ********************************************************************************* */

void ndpi_check_flow_func(struct ndpi_detection_module_struct *ndpi_str,
			  struct ndpi_flow_struct *flow,
			  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  if(flow->packet.tcp != NULL)
    check_ndpi_tcp_flow_func(ndpi_str, flow, ndpi_selection_packet);
  else if(flow->packet.udp != NULL)
    check_ndpi_udp_flow_func(ndpi_str, flow, ndpi_selection_packet);
  else
    check_ndpi_other_flow_func(ndpi_str, flow, ndpi_selection_packet);
}

/* ********************************************************************************* */

u_int16_t ndpi_guess_host_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow) {
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;

  if(flow->packet.iph) {
    struct in_addr addr;

    addr.s_addr = flow->packet.iph->saddr;

    /* guess host protocol */
    ret = ndpi_network_ptree_match(ndpi_str, &addr);

    if(ret == NDPI_PROTOCOL_UNKNOWN) {
      addr.s_addr = flow->packet.iph->daddr;
      ret = ndpi_network_ptree_match(ndpi_str, &addr);
    }
  }

  return(ret);
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_str,
				    struct ndpi_flow_struct *flow,
				    u_int8_t enable_guess,
				    u_int8_t *protocol_was_guessed) {
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };

  *protocol_was_guessed = 0;

  if(flow == NULL)
    return(ret);

  /* Init defaults */
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
  ret.category = flow->category;

  /* Ensure that we don't change our mind if detection is already complete */
  if((ret.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    return(ret);

  /* TODO: add the remaining stage_XXXX protocols */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
    u_int16_t guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN,
      guessed_host_protocol_id = NDPI_PROTOCOL_UNKNOWN;

    if(flow->guessed_protocol_id == NDPI_PROTOCOL_STUN)
      goto check_stun_export;
    else if((flow->guessed_protocol_id == NDPI_PROTOCOL_HANGOUT_DUO)
	    || (flow->guessed_protocol_id == NDPI_PROTOCOL_MESSENGER)
	    || (flow->guessed_protocol_id == NDPI_PROTOCOL_WHATSAPP_CALL))
      ndpi_set_detected_protocol(ndpi_str, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_UNKNOWN);
    else if((flow->l4.tcp.tls.hello_processed == 1)
	    && (flow->protos.stun_ssl.ssl.client_requested_server_name[0] != '\0')) {
      ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_TLS, NDPI_PROTOCOL_UNKNOWN);
    } else if(enable_guess) {
      if((flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
	 && (flow->packet.l4_protocol == IPPROTO_TCP)
	 && flow->l4.tcp.tls.hello_processed)
	flow->guessed_protocol_id = NDPI_PROTOCOL_TLS;

      guessed_protocol_id = flow->guessed_protocol_id, guessed_host_protocol_id = flow->guessed_host_protocol_id;

      if((guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 && ((flow->packet.l4_protocol == IPPROTO_UDP)
	     && NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_host_protocol_id)
	     && is_udp_guessable_protocol(guessed_host_protocol_id)
	     ))
	flow->guessed_host_protocol_id = guessed_host_protocol_id = NDPI_PROTOCOL_UNKNOWN;

      /* Ignore guessed protocol if they have been discarded */
      if((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 // && (guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)
	 && (flow->packet.l4_protocol == IPPROTO_UDP)
	 && NDPI_ISSET(&flow->excluded_protocol_bitmask, guessed_protocol_id)
	 && is_udp_guessable_protocol(guessed_protocol_id))
	flow->guessed_protocol_id = guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN;

      if((guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
	 || (guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)) {
	if((guessed_protocol_id == 0)
	   && (flow->protos.stun_ssl.stun.num_binding_requests > 0)
	   && (flow->protos.stun_ssl.stun.num_processed_pkts > 0))
	  guessed_protocol_id = NDPI_PROTOCOL_STUN;

	if(flow->host_server_name[0] != '\0') {
	  ndpi_protocol_match_result ret_match;

	  memset(&ret_match, 0, sizeof(ret_match));

	  ndpi_match_host_subprotocol(ndpi_str, flow,
				      (char *)flow->host_server_name,
				      strlen((const char*)flow->host_server_name),
				      &ret_match,
				      NDPI_PROTOCOL_DNS);

	  if(ret_match.protocol_id != NDPI_PROTOCOL_UNKNOWN)
	    guessed_host_protocol_id = ret_match.protocol_id;
	}

	ndpi_int_change_protocol(ndpi_str, flow,
				 guessed_host_protocol_id,
				 guessed_protocol_id);
      }
    }
  } else if(enable_guess) {
    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN)
      flow->detected_protocol_stack[1] = flow->guessed_protocol_id;

    if(flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)
      flow->detected_protocol_stack[0] = flow->guessed_host_protocol_id;

    if(flow->detected_protocol_stack[1] == flow->detected_protocol_stack[0])
      flow->detected_protocol_stack[1] = flow->guessed_host_protocol_id;
  }

  if((flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
     && (flow->guessed_protocol_id == NDPI_PROTOCOL_STUN)) {
  check_stun_export:
    if(flow->protos.stun_ssl.stun.num_processed_pkts || flow->protos.stun_ssl.stun.num_udp_pkts) {
      // if(/* (flow->protos.stun_ssl.stun.num_processed_pkts >= NDPI_MIN_NUM_STUN_DETECTION) */
      ndpi_set_detected_protocol(ndpi_str, flow,
				 flow->guessed_host_protocol_id,
				 NDPI_PROTOCOL_STUN);
    }
  }

  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

  if(ret.master_protocol == NDPI_PROTOCOL_STUN) {
    if(ret.app_protocol == NDPI_PROTOCOL_FACEBOOK)
      ret.app_protocol = NDPI_PROTOCOL_MESSENGER;
    else if(ret.app_protocol == NDPI_PROTOCOL_GOOGLE) {
      /*
	As Google has recently introduced Duo,
	we need to distinguish between it and hangout
	thing that should be handled by the STUN dissector
      */
      ret.app_protocol = NDPI_PROTOCOL_HANGOUT_DUO;
    }
  }

  if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);

  return(ret);
}

/* ********************************************************************************* */

void ndpi_process_extra_packet(struct ndpi_detection_module_struct *ndpi_str,
			       struct ndpi_flow_struct *flow,
			       const unsigned char *packet,
			       const unsigned short packetlen,
			       const u_int64_t current_tick_l,
			       struct ndpi_id_struct *src,
			       struct ndpi_id_struct *dst) {
  if(flow == NULL)
    return;

  if(flow->server_id == NULL) flow->server_id = dst; /* Default */

  /* need at least 20 bytes for ip header */
  if(packetlen < 20) {
    return;
  }

  flow->packet.tick_timestamp_l = current_tick_l;
  flow->packet.tick_timestamp = (u_int32_t)(current_tick_l/ndpi_str->ticks_per_second);

  /* parse packet */
  flow->packet.iph = (struct ndpi_iphdr *)packet;
  /* we are interested in ipv4 packet */

  /* set up the packet headers for the extra packet function to use if it wants */
  if(ndpi_init_packet_header(ndpi_str, flow, packetlen) != 0)
    return;

  /* detect traffic for tcp or udp only */
  flow->src = src, flow->dst = dst;
  ndpi_connection_tracking(ndpi_str, flow);

  /* call the extra packet function (which may add more data/info to flow) */
  if(flow->extra_packets_func) {
    if((flow->extra_packets_func(ndpi_str, flow)) == 0)
      flow->check_extra_packets = 0;

    if(++flow->num_extra_packets_checked == flow->max_extra_packets_to_check)
      flow->extra_packets_func = NULL; /* Enough packets detected */    
  }
}

/* ********************************************************************************* */

int ndpi_load_ip_category(struct ndpi_detection_module_struct *ndpi_str,
			   const char *ip_address_and_mask, ndpi_protocol_category_t category) {
  patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr;
  char ipbuf[64];

  strncpy(ipbuf, ip_address_and_mask, sizeof(ipbuf));
  ipbuf[sizeof(ipbuf) - 1] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr) {
    *(ptr++) = '\0';
    if(atoi(ptr)>=0 && atoi(ptr)<=32)
      bits = atoi(ptr);
  }

  if(inet_pton(AF_INET, ipbuf, &pin) != 1) {
    NDPI_LOG_DBG2(ndpi_str, "Invalid ip/ip+netmask: %s\n", ip_address_and_mask);
    return(-1);
  }

  if((node = add_to_ptree(ndpi_str->custom_categories.ipAddresses_shadow,
			  AF_INET, &pin, bits)) != NULL)
    node->value.user_value = (int)category;
  return(0);
}

/* ********************************************************************************* */

int ndpi_load_hostname_category(struct ndpi_detection_module_struct *ndpi_str,
				const char *name_to_add, ndpi_protocol_category_t category) {
  char *name;

  if(name_to_add == NULL)
    return(-1);

  name = ndpi_strdup(name_to_add);

  if(name == NULL)
    return(-1);

#if 0
  printf("===> %s() Loading %s as %u\n", __FUNCTION__, name, category);
#endif

#ifdef HAVE_HYPERSCAN
    {
      struct hs_list *h = (struct hs_list*)ndpi_malloc(sizeof(struct hs_list));

      if(h) {
	h->expression = name, h->id = (unsigned int)category;
	h->next = ndpi_str->custom_categories.to_load;
	ndpi_str->custom_categories.to_load = h;
	ndpi_str->custom_categories.num_to_load++;
      } else {
        free(name);
        return(-1);
      }
    }
#else
    AC_PATTERN_t ac_pattern;

    memset(&ac_pattern, 0, sizeof(ac_pattern));

    if(ndpi_str->custom_categories.hostnames_shadow.ac_automa == NULL) {
      free(name);
      return(-1);
    }

    ac_pattern.astring = name, ac_pattern.length = strlen(ac_pattern.astring);
    ac_pattern.rep.number = (int)category;

    if(ac_automata_add(ndpi_str->custom_categories.hostnames_shadow.ac_automa, &ac_pattern) != ACERR_SUCCESS) {
      free(name);
      return(-1);
    }
#endif

  return(0);
}

/* ********************************************************************************* */

/* Loads an IP or name category */
int ndpi_load_category(struct ndpi_detection_module_struct *ndpi_struct,
				 const char *ip_or_name, ndpi_protocol_category_t category) {
  int rv;

  /* Try to load as IP address first */
  rv = ndpi_load_ip_category(ndpi_struct, ip_or_name, category);

  if(rv < 0) {
    /* IP load failed, load as hostname */
    rv = ndpi_load_hostname_category(ndpi_struct, ip_or_name, category);
  }

  return(rv);
}

/* ********************************************************************************* */

int ndpi_enable_loaded_categories(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  /* First add the nDPI known categories matches */
  for(i=0; category_match[i].string_to_match != NULL; i++)
    ndpi_load_category(ndpi_str, category_match[i].string_to_match, category_match[i].protocol_category);

#ifdef HAVE_HYPERSCAN
  if(ndpi_str->custom_categories.num_to_load > 0) {
    const char **expressions;
    unsigned int *ids;
    int rc;
    struct hs_list *head = ndpi_str->custom_categories.to_load;

    expressions = (const char**)ndpi_calloc(sizeof(char*),
					    ndpi_str->custom_categories.num_to_load+1);
    if(!expressions) return(-1);

    ids = (unsigned int*)ndpi_calloc(sizeof(unsigned int),
				     ndpi_str->custom_categories.num_to_load+1);
    if(!ids) {
      ndpi_free(expressions);
      return(-1);
    }

    for(i=0; head != NULL; i++) {
#ifdef DEBUG
      printf("[HS] Loading category %u for %s\n", head->id, head->expression);
#endif
      expressions[i] = head->expression, ids[i] = head->id;
      head = head->next;
    }

    if(i != ndpi_str->custom_categories.num_to_load){
      ndpi_free(expressions);
      return(-1);
    }

    free_hyperscan_memory(ndpi_str->custom_categories.hostnames);
    ndpi_str->custom_categories.hostnames = (struct hs*)ndpi_malloc(sizeof(struct hs));

    if(ndpi_str->custom_categories.hostnames == NULL) {
      ndpi_free(expressions);
      ndpi_free(ids);
      return(-1); /* Failed */
    }

    rc = hyperscan_load_patterns(ndpi_str->custom_categories.hostnames,
				 ndpi_str->custom_categories.num_to_load,
				 expressions, ids);
    ndpi_free(expressions), ndpi_free(ids);

    head = ndpi_str->custom_categories.to_load;
    while(head != NULL) {
      struct hs_list *next = head->next;

      ndpi_free(head->expression);
      ndpi_free(head);

      head = next;
    }

    ndpi_str->custom_categories.to_load = NULL;
    ndpi_str->custom_categories.num_to_load = 0;

    if(rc < 0) {
      ndpi_free(ndpi_str->custom_categories.hostnames);
      ndpi_str->custom_categories.hostnames = NULL;
    }
  }
#else
  /* Free */
  ac_automata_release((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames.ac_automa, 1 /* free patterns strings memory */);

  /* Finalize */
  ac_automata_finalize((AC_AUTOMATA_t*)ndpi_str->custom_categories.hostnames_shadow.ac_automa);

  /* Swap */
  ndpi_str->custom_categories.hostnames.ac_automa = ndpi_str->custom_categories.hostnames_shadow.ac_automa;

  /* Realloc */
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_match_handler);
#endif

  if(ndpi_str->custom_categories.ipAddresses != NULL)
    ndpi_Destroy_Patricia((patricia_tree_t*)ndpi_str->custom_categories.ipAddresses,
			  free_ptree_data);

  ndpi_str->custom_categories.ipAddresses = ndpi_str->custom_categories.ipAddresses_shadow;
  ndpi_str->custom_categories.ipAddresses_shadow = ndpi_New_Patricia(32 /* IPv4 */);

  ndpi_str->custom_categories.categories_loaded = 1;

  return(0);
}

/* ********************************************************************************* */

int ndpi_fill_ip_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
				   u_int32_t saddr,
				   u_int32_t daddr,
				   ndpi_protocol *ret) {
  if(ndpi_str->custom_categories.categories_loaded) {
    prefix_t prefix;
    patricia_node_t *node;

    if(saddr == 0)
      node = NULL;
    else {
      /* Make sure all in network byte order otherwise compares wont work */
      fill_prefix_v4(&prefix, (struct in_addr *)&saddr,
		     32, ((patricia_tree_t*)ndpi_str->protocols_ptree)->maxbits);
      node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
    }

    if(!node) {
      if(daddr != 0) {
	fill_prefix_v4(&prefix, (struct in_addr *)&daddr,
		       32, ((patricia_tree_t*)ndpi_str->protocols_ptree)->maxbits);
	node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
      }
    }

    if(node) {
      ret->category = (ndpi_protocol_category_t)node->value.user_value;
      return(1);
    }
  }

  ret->category = ndpi_get_proto_category(ndpi_str, *ret);

  return(0);
}

/* ********************************************************************************* */

void ndpi_fill_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow,
				 ndpi_protocol *ret) {
  if(ndpi_str->custom_categories.categories_loaded) {
    if(flow->guessed_header_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) {
      flow->category = ret->category = flow->guessed_header_category;
      return;
    }

    if(flow->host_server_name[0] != '\0') {
      unsigned long id;
      int rc = ndpi_match_custom_category(ndpi_str, (char *)flow->host_server_name,
					  strlen((char *)flow->host_server_name), &id);

      if(rc == 0) {
	flow->category = ret->category = (ndpi_protocol_category_t)id;
	return;
      }
    }

    if(flow->protos.stun_ssl.ssl.client_requested_server_name[0] != '\0') {
      unsigned long id;
      int rc = ndpi_match_custom_category(ndpi_str,
					  (char *)flow->protos.stun_ssl.ssl.client_requested_server_name,
					  strlen(flow->protos.stun_ssl.ssl.client_requested_server_name),
					  &id);

      if(rc == 0) {
	flow->category = ret->category = (ndpi_protocol_category_t)id;
	return;
      }
    }
  }

  flow->category = ret->category = ndpi_get_proto_category(ndpi_str, *ret);
}

/* ********************************************************************************* */

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet) {
  packet->parsed_lines = 0,
  packet->empty_line_position_set = 0,
  packet->host_line.ptr = NULL,
  packet->host_line.len = 0,
  packet->referer_line.ptr = NULL,
  packet->referer_line.len = 0,
  packet->content_line.ptr = NULL,
  packet->content_line.len = 0,
  packet->accept_line.ptr = NULL,
  packet->accept_line.len = 0,
  packet->user_agent_line.ptr = NULL,
  packet->user_agent_line.len = 0,
  packet->http_url_name.ptr = NULL,
  packet->http_url_name.len = 0,
  packet->http_encoding.ptr = NULL,
  packet->http_encoding.len = 0,
  packet->http_transfer_encoding.ptr = NULL,
  packet->http_transfer_encoding.len = 0,
  packet->http_contentlen.ptr = NULL,
  packet->http_contentlen.len = 0,
  packet->http_cookie.ptr = NULL,
  packet->http_cookie.len = 0,
  packet->http_origin.len = 0,
  packet->http_origin.ptr = NULL,
  packet->http_x_session_type.ptr = NULL,
  packet->http_x_session_type.len = 0,
  packet->server_line.ptr = NULL,
  packet->server_line.len = 0,
  packet->http_method.ptr = NULL,
  packet->http_method.len = 0,
  packet->http_response.ptr = NULL,
  packet->http_response.len = 0,
  packet->http_num_headers = 0;
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
					    struct ndpi_flow_struct *flow,
					    const unsigned char *packet,
					    const unsigned short packetlen,
					    const u_int64_t current_tick_l,
					    struct ndpi_id_struct *src,
					    struct ndpi_id_struct *dst) {
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t a;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };

  if(ndpi_str->ndpi_log_level >= NDPI_LOG_TRACE)
    NDPI_LOG(flow ? flow->detected_protocol_stack[0]:NDPI_PROTOCOL_UNKNOWN,
	     ndpi_str, NDPI_LOG_TRACE, "START packet processing\n");

  if(flow == NULL)
    return(ret);
  else
    ret.category = flow->category;

  flow->num_processed_pkts++;

  /* Init default */
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

  if(flow->server_id == NULL) flow->server_id = dst; /* Default */

  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    if(flow->check_extra_packets) {
      ndpi_process_extra_packet(ndpi_str, flow, packet, packetlen, current_tick_l, src, dst);
      /* Update in case of new match */
      ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0], ret.category = flow->category;
      goto invalidate_ptr;
    } else
      goto ret_protocols;
  }

  /* need at least 20 bytes for ip header */
  if(packetlen < 20) {
    /* reset protocol which is normally done in init_packet_header */
    ndpi_int_reset_packet_protocol(&flow->packet);
    goto invalidate_ptr;
  }

  flow->packet.tick_timestamp_l = current_tick_l;
  flow->packet.tick_timestamp = (u_int32_t)(current_tick_l/ndpi_str->ticks_per_second);

  /* parse packet */
  flow->packet.iph = (struct ndpi_iphdr *)packet;
  /* we are interested in ipv4 packet */

  if(ndpi_init_packet_header(ndpi_str, flow, packetlen) != 0)
    goto invalidate_ptr;

  /* detect traffic for tcp or udp only */
  flow->src = src, flow->dst = dst;

  ndpi_connection_tracking(ndpi_str, flow);

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
      protocol = flow->packet.iphv6->ip6_hdr.ip6_un1_nxt;
    } else
#endif
      {
	protocol = flow->packet.iph->protocol;
      }

    if(flow->packet.udp) sport = ntohs(flow->packet.udp->source), dport = ntohs(flow->packet.udp->dest);
    else if(flow->packet.tcp) sport = ntohs(flow->packet.tcp->source), dport = ntohs(flow->packet.tcp->dest);
    else sport = dport = 0;

    /* guess protocol */
    flow->guessed_protocol_id = (int16_t)ndpi_guess_protocol_id(ndpi_str, flow, protocol, sport, dport, &user_defined_proto);
    flow->guessed_host_protocol_id = ndpi_guess_host_protocol_id(ndpi_str, flow);

    if(ndpi_str->custom_categories.categories_loaded && flow->packet.iph) {
      ndpi_fill_ip_protocol_category(ndpi_str, flow->packet.iph->saddr, flow->packet.iph->daddr, &ret);
      flow->guessed_header_category = ret.category;
    } else
      flow->guessed_header_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

    if(flow->guessed_protocol_id >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
      /* This is a custom protocol and it has priority over everything else */
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN,
	ret.app_protocol = flow->guessed_protocol_id ? flow->guessed_protocol_id : flow->guessed_host_protocol_id;
      ndpi_fill_protocol_category(ndpi_str, flow, &ret);
      goto invalidate_ptr;
    }

    if(user_defined_proto && flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      if(flow->packet.iph) {
	if(flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
	  u_int8_t protocol_was_guessed;

	  /* ret.master_protocol = flow->guessed_protocol_id , ret.app_protocol = flow->guessed_host_protocol_id; /\* ****** *\/ */
	  ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
	}

	ndpi_fill_protocol_category(ndpi_str, flow, &ret);
	goto invalidate_ptr;
      }
    } else {
      /* guess host protocol */
      if(flow->packet.iph) {
	struct in_addr addr;

	addr.s_addr = flow->packet.iph->saddr;
	flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_str, &addr);

	if(flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN) {
	  addr.s_addr = flow->packet.iph->daddr;
	  flow->guessed_host_protocol_id = ndpi_network_ptree_match(ndpi_str, &addr);
	}

	/*
	  We could implement a shortcut here skipping dissectors for
	  protocols we have identified by other means such as with the IP

	  However we do NOT stop here and skip invoking the dissectors
	  because we want to dissect the flow (e.g. dissect the TLS)
	  and extract metadata.
	 */
#if SKIP_INVOKING_THE_DISSECTORS
	if(flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
	  /*
	    We have identified a protocol using the IP address so
	    it is not worth to dissect the traffic as we already have
	    the solution
	  */
	  ret.master_protocol = flow->guessed_protocol_id,
	    ret.app_protocol = flow->guessed_host_protocol_id;
	}
#endif
      }
    }
  }

  if(flow->guessed_host_protocol_id >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
    /* This is a custom protocol and it has priority over everything else */
    ret.master_protocol = flow->guessed_protocol_id, ret.app_protocol = flow->guessed_host_protocol_id;

    ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
    goto invalidate_ptr;
  }

  ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

  a = flow->packet.detected_protocol_stack[0];
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_str->detection_bitmask, a) == 0)
    a = NDPI_PROTOCOL_UNKNOWN;

  if(a != NDPI_PROTOCOL_UNKNOWN) {
    int i;

    for(i=0; i<sizeof(flow->host_server_name); i++) {
      if(flow->host_server_name[i] != '\0')
	flow->host_server_name[i] = tolower(flow->host_server_name[i]);
      else {
	flow->host_server_name[i] ='\0';
	break;
      }
    }
  }

 ret_protocols:
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
    ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

    if(ret.app_protocol == ret.master_protocol)
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  } else
    ret.app_protocol = flow->detected_protocol_stack[0];

  /* Don't overwrite the category if already set */
  if((flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
     && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
  else
    ret.category = flow->category;

  if((flow->num_processed_pkts == 1)
     && (ret.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (ret.app_protocol == NDPI_PROTOCOL_UNKNOWN)
     && flow->packet.tcp
     && (flow->packet.tcp->syn == 0)
     && (flow->guessed_protocol_id == 0)
     ) {
    u_int8_t protocol_was_guessed;

    /*
      This is a TCP flow
      - whose first packet is NOT a SYN
      - no protocol has been detected

      We don't see how future packets can match anything
      hence we giveup here
    */
    ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
  }

  if((ret.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)) {
    ret.master_protocol = ret.app_protocol;
    ret.app_protocol = flow->guessed_host_protocol_id;
  }

 invalidate_ptr:
  /*
     Invalidate packet memory to avoid accessing the pointers below
     when the packet is no longer accessible
  */
  flow->packet.iph = NULL, flow->packet.tcp = NULL, flow->packet.udp = NULL, flow->packet.payload = NULL;
  ndpi_reset_packet_line_info(&flow->packet);

  return(ret);
}

/* ********************************************************************************* */

u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int32_t val;
  val = 0;

  // cancel if eof, ' ' or line end chars are reached
  while(*str >= '0' && *str <= '9' && max_chars_to_read > 0) {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }

  return(val);
}

/* ********************************************************************************* */

#ifdef CODE_UNUSED
u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str, u_int16_t max_chars_to_read,
					       u_int16_t * bytes_read) {
  u_int32_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return(ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read));
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;

    while(max_chars_to_read > 0) {
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

  return(val);
}

#endif

/* ********************************************************************************* */

u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read,
				      u_int16_t * bytes_read) {
  u_int64_t val;
  val = 0;
  // cancel if eof, ' ' or line end chars are reached
  while(max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }
  return(val);
}

/* ********************************************************************************* */

u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int64_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return(ndpi_bytestream_to_number64(str, max_chars_to_read, bytes_read));
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;
    while(max_chars_to_read > 0) {

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
  return(val);
}

/* ********************************************************************************* */

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
    return(0);
  read++;
  val = c << 24;
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = val + (c << 16);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = val + (c << 8);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read)
    return(0);
  val = val + c;

  *bytes_read = *bytes_read + read;

  return(htonl(val));
}

/* ********************************************************************************* */

/* internal function for every detection to parse one packet and to increase the info buffer */
void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow)
{
  u_int32_t a;
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  ndpi_reset_packet_line_info(packet);

  if((packet->payload_packet_len < 3)
     || (packet->payload == NULL))
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; (a < packet->payload_packet_len)
	&& (packet->parsed_lines < NDPI_MAX_PARSE_LINES_PER_PACKET); a++) {
    if((a + 1) >= packet->payload_packet_len)
      return; /* Return if only one byte remains (prevent invalid reads past end-of-buffer) */

    if(get_u_int16_t(packet->payload, a) == ntohs(0x0d0a)) { /* If end of line char sequence CR+NL "\r\n", process line */
      packet->line[packet->parsed_lines].len = (u_int16_t)(((unsigned long) &packet->payload[a]) - ((unsigned long) packet->line[packet->parsed_lines].ptr));

      /* First line of a HTTP response parsing. Expected a "HTTP/1.? ???" */
      if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.X 200 ") &&
	 strncasecmp((const char *)packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] > '0' && /* response code between 000 and 699 */
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] < '6') {
	packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
	packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
	packet->http_num_headers++;

	/* Set server HTTP response code */
	if(packet->payload_packet_len >= 12) {
	  char buf[4];

	  /* Set server HTTP response code */
	  strncpy(buf, (char*)&packet->payload[9], 3);
	  buf[3] = '\0';

	  flow->http.response_status_code = atoi(buf);
	  /* https://en.wikipedia.org/wiki/List_of_HTTP_status_codes */
	  if((flow->http.response_status_code < 100) || (flow->http.response_status_code > 509))
	    flow->http.response_status_code = 0; /* Out of range */
	}
      }

      /* "Server:" header line in HTTP response */
      if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
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
        packet->http_num_headers++;
      }
      /* "Host:" header line in HTTP request */
      if(packet->line[packet->parsed_lines].len > 6
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr,
			"Host:", 5) == 0) {
        // some stupid clients omit a space and place the hostname directly after the colon
        if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
          packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
          packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
        } else {
          packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
          packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
        }
        packet->http_num_headers++;
      }
      /* "X-Forwarded-For:" header line in HTTP request. Commonly used for HTTP proxies. */
      if(packet->line[packet->parsed_lines].len > 17
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
        // some stupid clients omit a space and place the hostname directly after the colon
        if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
          packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
          packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
        } else {
          packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
          packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
        }
        packet->http_num_headers++;
      }
      /* "Content-Type:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 14
	 && (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Type: ", 14) == 0
	     || strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
        packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
        packet->content_line.len = packet->line[packet->parsed_lines].len - 14;

	while((packet->content_line.len > 0) && (packet->content_line.ptr[0] == ' '))
	  packet->content_line.len--, packet->content_line.ptr++;

        packet->http_num_headers++;
      }
      /* "Content-Type:" header line in HTTP AGAIN. Probably a bogus response without space after ":" */
      if((packet->content_line.len == 0)
	 && (packet->line[packet->parsed_lines].len > 13)
	 && (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0)) {
        packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
        packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
        packet->http_num_headers++;
      }

      if(packet->content_line.len > 0) {
	/* application/json; charset=utf-8 */
	char separator[] = { ';', '\r', '\0' };
	int i;

	for(i=0; separator[i] != '\0'; i++) {
	  char *c = memchr((char*)packet->content_line.ptr, separator[i], packet->content_line.len);

	  if(c != NULL)
	    packet->content_line.len = c - (char*)packet->content_line.ptr;
	}
      }

      /* "Accept:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 8
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
        packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "Referer:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 9
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
        packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
        packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
        packet->http_num_headers++;
      }
      /* "User-Agent:" header line in HTTP request. */
      if(packet->line[packet->parsed_lines].len > 12
	 && (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "User-Agent: ", 12) == 0
	     || strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0)) {
        packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
        packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
        packet->http_num_headers++;
      }
      /* "Content-Encoding:" header line in HTTP response (and request?). */
      if(packet->line[packet->parsed_lines].len > 18
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
        packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
        packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
        packet->http_num_headers++;
      }
      /* "Transfer-Encoding:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 19
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
        packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
        packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
        packet->http_num_headers++;
      }
      /* "Content-Length:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 16
	 && ((strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Content-Length: ", 16) == 0)
	     || (strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0))) {
        packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
        packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
        packet->http_num_headers++;
      }
      /* "Cookie:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 8
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
        packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "Origin:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 8
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Origin: ", 8) == 0) {
        packet->http_origin.ptr = &packet->line[packet->parsed_lines].ptr[8];
        packet->http_origin.len = packet->line[packet->parsed_lines].len - 8;
        packet->http_num_headers++;
      }
      /* "X-Session-Type:" header line in HTTP. */
      if(packet->line[packet->parsed_lines].len > 16
	 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
        packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
        packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
        packet->http_num_headers++;
      }
      /* Identification and counting of other HTTP headers.
       * We consider the most common headers, but there are many others,
       * which can be seen at references below:
       * - https://tools.ietf.org/html/rfc7230
       * - https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
       */
      if((packet->line[packet->parsed_lines].len >  6 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Date: ", 6) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Vary: ", 6) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "ETag: ", 6) == 0 )) ||
         (packet->line[packet->parsed_lines].len >  8 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Pragma: ", 8) == 0) ||
         (packet->line[packet->parsed_lines].len >  9 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Expires: ", 9) == 0) ||
         (packet->line[packet->parsed_lines].len > 12 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Set-Cookie: ", 12) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Keep-Alive: ", 12) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Connection: ", 12) == 0)) ||
         (packet->line[packet->parsed_lines].len > 15 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Last-Modified: ", 15) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Ranges: ", 15) == 0)) ||
         (packet->line[packet->parsed_lines].len > 17 && ( strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Language: ", 17) == 0 ||
                                                           strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Accept-Encoding: ", 17) == 0)) ||
         (packet->line[packet->parsed_lines].len > 27 && strncasecmp((const char *)packet->line[packet->parsed_lines].ptr, "Upgrade-Insecure-Requests: ", 27) == 0)) {
        /* Just count. In the future, if needed, this if can be splited to parse these headers */
        packet->http_num_headers++;
      }


      if(packet->line[packet->parsed_lines].len == 0) {
        packet->empty_line_position = a;
        packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
        return;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      a++; /* next char in the payload */
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len
      = (u_int16_t)(((unsigned long) &packet->payload[packet->payload_packet_len]) -
		    ((unsigned long) packet->line[packet->parsed_lines].ptr));
    packet->parsed_lines++;
  }
}

/* ********************************************************************************* */

void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_str,
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

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
        break;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 1];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 1) >= packet->payload_packet_len)
        break;

      //a++;
    }
  }
}

/* ********************************************************************************* */

u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_str,
				       struct ndpi_flow_struct *flow, u_int16_t counter)
{

  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG2(ndpi_str, "called ndpi_check_for_email_address\n");

  if(packet->payload_packet_len > counter && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
					      || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
					      || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
					      || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
    NDPI_LOG_DBG2(ndpi_str, "first letter\n");
    counter++;
    while(packet->payload_packet_len > counter
	   && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
	       || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
	       || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
	       || packet->payload[counter] == '-' || packet->payload[counter] == '_'
	       || packet->payload[counter] == '.')) {
      NDPI_LOG_DBG2(ndpi_str, "further letter\n");
      counter++;
      if(packet->payload_packet_len > counter && packet->payload[counter] == '@') {
	NDPI_LOG_DBG2(ndpi_str, "@\n");
	counter++;
	while(packet->payload_packet_len > counter
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
		   || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
		   || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
	  NDPI_LOG_DBG2(ndpi_str, "letter\n");
	  counter++;
	  if(packet->payload_packet_len > counter && packet->payload[counter] == '.') {
	    NDPI_LOG_DBG2(ndpi_str, ".\n");
	    counter++;
	    if(packet->payload_packet_len > counter + 1
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   && (packet->payload[counter + 1] >= 'a' && packet->payload[counter + 1] <= 'z'))) {
	      NDPI_LOG_DBG2(ndpi_str, "two letters\n");
	      counter += 2;
	      if(packet->payload_packet_len > counter
		 && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		NDPI_LOG_DBG2(ndpi_str, "whitespace1\n");
		return(counter);
	      } else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			&& packet->payload[counter] <= 'z') {
		NDPI_LOG_DBG2(ndpi_str, "one letter\n");
		counter++;
		if(packet->payload_packet_len > counter
		   && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		  NDPI_LOG_DBG2(ndpi_str, "whitespace2\n");
		  return(counter);
		} else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			  && packet->payload[counter] <= 'z') {
		  counter++;
		  if(packet->payload_packet_len > counter
		     && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		    NDPI_LOG_DBG2(ndpi_str, "whitespace3\n");
		    return(counter);
		  } else {
		    return(0);
		  }
		} else {
		  return(0);
		}
	      } else {
		return(0);
	      }
	    } else {
	      return(0);
	    }
	  }
	}
	return(0);
      }
    }
  }
  return(0);
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
/* ********************************************************************************* */

void ndpi_debug_get_last_log_function_line(struct ndpi_detection_module_struct
					   *ndpi_str, const char **file, const char **func, u_int32_t * line)
{
  *file = "";
  *func = "";

  if(ndpi_str->ndpi_debug_print_file != NULL)
    *file = ndpi_str->ndpi_debug_print_file;

  if(ndpi_str->ndpi_debug_print_function != NULL)
    *func = ndpi_str->ndpi_debug_print_function;

  *line = ndpi_str->ndpi_debug_print_line;
}
#endif

/* ********************************************************************************* */

u_int8_t ndpi_detection_get_l4(const u_int8_t * l3, u_int16_t l3_len,
			       const u_int8_t ** l4_return, u_int16_t * l4_len_return,
			       u_int8_t * l4_protocol_return, u_int32_t flags) {
  return(ndpi_detection_get_l4_internal(NULL, l3, l3_len,
					l4_return, l4_len_return, l4_protocol_return, flags));
}

/* ********************************************************************************* */

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_str,
				struct ndpi_flow_struct *flow,
				u_int16_t upper_detected_protocol,
				u_int16_t lower_detected_protocol) {
  struct ndpi_id_struct *src = flow->src, *dst = flow->dst;

  ndpi_int_change_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol);

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

/* ********************************************************************************* */

u_int16_t ndpi_get_flow_masterprotocol(struct ndpi_detection_module_struct *ndpi_str,
				       struct ndpi_flow_struct *flow) {
  return(flow->detected_protocol_stack[1]);
}

/* ********************************************************************************* */

void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_str,
				   struct ndpi_flow_struct *flow,
				   u_int16_t upper_detected_protocol,
				   u_int16_t lower_detected_protocol) {
  if(!flow) return;

  flow->detected_protocol_stack[0] = upper_detected_protocol,
    flow->detected_protocol_stack[1] = lower_detected_protocol;
}

/* ********************************************************************************* */

void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_str,
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

  packet->detected_protocol_stack[0] = upper_detected_protocol,
    packet->detected_protocol_stack[1] = lower_detected_protocol;
}

/* ********************************************************************************* */

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow,
			      u_int16_t upper_detected_protocol,
			      u_int16_t lower_detected_protocol) {
  if((upper_detected_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN))
    upper_detected_protocol = lower_detected_protocol;

  if(upper_detected_protocol == lower_detected_protocol)
    lower_detected_protocol = NDPI_PROTOCOL_UNKNOWN;

  if((upper_detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (lower_detected_protocol == NDPI_PROTOCOL_UNKNOWN)) {
    if((flow->guessed_host_protocol_id != NDPI_PROTOCOL_UNKNOWN)
       && (upper_detected_protocol != flow->guessed_host_protocol_id)) {
      if(ndpi_str->proto_defaults[upper_detected_protocol].can_have_a_subprotocol) {
	lower_detected_protocol = upper_detected_protocol;
	upper_detected_protocol = flow->guessed_host_protocol_id;
      }
    }
  }

  ndpi_int_change_flow_protocol(ndpi_str, flow,
				upper_detected_protocol, lower_detected_protocol);
  ndpi_int_change_packet_protocol(ndpi_str, flow,
				  upper_detected_protocol, lower_detected_protocol);
}

/* ********************************************************************************* */

void ndpi_int_change_category(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow,
			      ndpi_protocol_category_t protocol_category) {
  flow->category = protocol_category;
}

/* ********************************************************************************* */

/* turns a packet back to unknown */
void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet) {
  int a;

  for(a = 0; a < NDPI_PROTOCOL_SIZE; a++)
    packet->detected_protocol_stack[a] = NDPI_PROTOCOL_UNKNOWN;
}

/* ********************************************************************************* */

void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow) {
  if(flow) {
    int a;

    for(a = 0; a < NDPI_PROTOCOL_SIZE; a++)
      flow->detected_protocol_stack[a] = NDPI_PROTOCOL_UNKNOWN;
  }
}

/* ********************************************************************************* */

void NDPI_PROTOCOL_IP_clear(ndpi_ip_addr_t * ip) {
  memset(ip, 0, sizeof(ndpi_ip_addr_t));
}

/* ********************************************************************************* */

#ifdef CODE_UNUSED
/* NTOP */
int NDPI_PROTOCOL_IP_is_set(const ndpi_ip_addr_t * ip)
{
  return(memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(ndpi_ip_addr_t)) != 0);
}
#endif

/* ********************************************************************************* */

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
      return(1);
    //else
    return(0);
  }
#endif

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return(1);
  return(0);
}

/* ********************************************************************************* */

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
      return(1);
    //else
    return(0);
  }
#endif

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return(1);

  return(0);
}

/* ********************************************************************************* */

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

/* ********************************************************************************* */

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

/* ********************************************************************************* */

u_int8_t ndpi_is_ipv6(const ndpi_ip_addr_t *ip) {
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  return(ip->ipv6.u6_addr.u6_addr32[1] != 0 ||
         ip->ipv6.u6_addr.u6_addr32[2] != 0 ||
         ip->ipv6.u6_addr.u6_addr32[3] != 0);
#else
  return(0);
#endif
}

/* ********************************************************************************* */

char *ndpi_get_ip_string(const ndpi_ip_addr_t * ip, char *buf, u_int buf_len) {
  const u_int8_t *a = (const u_int8_t *) &ip->ipv4;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(ndpi_is_ipv6(ip)) {
    if(inet_ntop(AF_INET6, &ip->ipv6.u6_addr, buf, buf_len) == NULL)
      buf[0] = '\0';

    return(buf);
  }
#endif

  snprintf(buf, buf_len, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

  return(buf);

}

/* ****************************************************** */

/* Returns -1 on failutre, otherwise fills parsed_ip and returns the IP version */
int ndpi_parse_ip_string(const char *ip_str, ndpi_ip_addr_t *parsed_ip) {
  int rv = -1;
  memset(parsed_ip, 0, sizeof(*parsed_ip));

  if(strchr(ip_str, '.')) {
    if(inet_pton(AF_INET, ip_str, &parsed_ip->ipv4) > 0)
      rv = 4;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  } else {
    if(inet_pton(AF_INET6, ip_str, &parsed_ip->ipv6) > 0)
      rv = 6;
#endif
  }

  return(rv);
}

/* ****************************************************** */

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str,
					  u_int16_t max_chars_to_read,
					  u_int16_t * bytes_read) {
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return(ntohs(val));
}

/* ****************************************************** */

u_int8_t ndpi_is_proto(ndpi_protocol proto, u_int16_t p) {
  return(((proto.app_protocol == p) || (proto.master_protocol == p)) ? 1 : 0);
}

/* ****************************************************** */

u_int16_t ndpi_get_lower_proto(ndpi_protocol proto) {
  return((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) ? proto.master_protocol : proto.app_protocol);
}

/* ****************************************************** */

ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_str,
					     struct ndpi_flow_struct *flow,
					     u_int8_t proto,
					     u_int32_t shost /* host byte order */, u_int16_t sport,
					     u_int32_t dhost /* host byte order */, u_int16_t dport) {
  u_int32_t rc;
  struct in_addr addr;
  ndpi_protocol ret = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };
  u_int8_t user_defined_proto;

  if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
    rc = ndpi_search_tcp_or_udp_raw(ndpi_str, flow, proto, shost, dhost, sport, dport);

    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      if(flow && (proto == IPPROTO_UDP)
	 && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, rc)
	 && is_udp_guessable_protocol(rc))
	;
      else {
	ret.app_protocol = rc,
	  ret.master_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport,
						       dport, &user_defined_proto);

	if(ret.app_protocol == ret.master_protocol)
	  ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;

	ret.category = ndpi_get_proto_category(ndpi_str, ret);
	return(ret);
      }
    }

    rc = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto);
    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      if(flow && (proto == IPPROTO_UDP)
	 && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, rc)
	 && is_udp_guessable_protocol(rc))
	;
      else {
	ret.app_protocol = rc;

	if(rc == NDPI_PROTOCOL_TLS)
	  goto check_guessed_skype;
	else {
	  ret.category = ndpi_get_proto_category(ndpi_str, ret);
	  return(ret);
	}
      }
    }

  check_guessed_skype:
    addr.s_addr = htonl(shost);
    if(ndpi_network_ptree_match(ndpi_str, &addr) == NDPI_PROTOCOL_SKYPE) {
      ret.app_protocol = NDPI_PROTOCOL_SKYPE;
    } else {
      addr.s_addr = htonl(dhost);
      if(ndpi_network_ptree_match(ndpi_str, &addr) == NDPI_PROTOCOL_SKYPE)
	ret.app_protocol = NDPI_PROTOCOL_SKYPE;
    }
  } else
    ret.app_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport,
					      dport, &user_defined_proto);

  ret.category = ndpi_get_proto_category(ndpi_str, ret);
  return(ret);
}

/* ****************************************************** */

char* ndpi_protocol2id(struct ndpi_detection_module_struct *ndpi_str,
		       ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      snprintf(buf, buf_len, "%u.%u",
	       proto.master_protocol, proto.app_protocol);
    else
      snprintf(buf, buf_len, "%u", proto.master_protocol);
  } else
    snprintf(buf, buf_len, "%u", proto.app_protocol);

  return(buf);
}

/* ****************************************************** */

char* ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_str,
			 ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      snprintf(buf, buf_len, "%s.%s",
	       ndpi_get_proto_name(ndpi_str, proto.master_protocol),
	       ndpi_get_proto_name(ndpi_str, proto.app_protocol));
    else
      snprintf(buf, buf_len, "%s",
	       ndpi_get_proto_name(ndpi_str, proto.master_protocol));
  } else
    snprintf(buf, buf_len, "%s",
	     ndpi_get_proto_name(ndpi_str, proto.app_protocol));

  return(buf);
}

/* ****************************************************** */

int ndpi_is_custom_category(ndpi_protocol_category_t category) {
  switch(category) {
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
    return(1);
    break;

  default:
    return(0);
    break;
  }
}

/* ****************************************************** */

void ndpi_category_set_name(struct ndpi_detection_module_struct *ndpi_str,
			    ndpi_protocol_category_t category, char *name) {

  if(!name) return;

  switch(category) {
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
    snprintf(ndpi_str->custom_category_labels[0], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
    snprintf(ndpi_str->custom_category_labels[1], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
    snprintf(ndpi_str->custom_category_labels[2], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
    snprintf(ndpi_str->custom_category_labels[3], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
    snprintf(ndpi_str->custom_category_labels[4], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  default:
    break;
  }
}

/* ****************************************************** */

const char* ndpi_category_get_name(struct ndpi_detection_module_struct *ndpi_str,
				   ndpi_protocol_category_t category) {
  if((!ndpi_str) || (category >= NDPI_PROTOCOL_NUM_CATEGORIES)) {
    static char b[24];

    if(!ndpi_str)
      snprintf(b, sizeof(b), "NULL nDPI");
    else
      snprintf(b, sizeof(b), "Invalid category %d", (int)category);
    return(b);
  }

  if((category >= NDPI_PROTOCOL_CATEGORY_CUSTOM_1) && (category <= NDPI_PROTOCOL_CATEGORY_CUSTOM_5)) {
    switch(category) {
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
      return(ndpi_str->custom_category_labels[0]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
      return(ndpi_str->custom_category_labels[1]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
      return(ndpi_str->custom_category_labels[2]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
      return(ndpi_str->custom_category_labels[3]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
      return(ndpi_str->custom_category_labels[4]);
    case NDPI_PROTOCOL_NUM_CATEGORIES:
      return("Code should not use this internal constant");
    default:
      return("Unspecified");
    }
  } else
    return(categories[category]);
}

/* ****************************************************** */

ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_str,
						 ndpi_protocol proto) {
  if(proto.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    return(proto.category);

  /* simple rule: sub protocol first, master after */
  else if((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
	  || (ndpi_str->proto_defaults[proto.app_protocol].protoCategory != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
    if(proto.app_protocol < (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
      return(ndpi_str->proto_defaults[proto.app_protocol].protoCategory);
  } else if(proto.master_protocol < (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
    return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);
  
  return(NDPI_PROTOCOL_CATEGORY_UNSPECIFIED);
}

/* ****************************************************** */

char* ndpi_get_proto_name(struct ndpi_detection_module_struct *ndpi_str, u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (proto_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoName);
}

/* ****************************************************** */

ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
					   u_int16_t proto_id) {
  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (proto_id >= (NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoBreed);
}

/* ****************************************************** */

char* ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_str,
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
    return("Potentially Dangerous");
    break;
  case NDPI_PROTOCOL_DANGEROUS:
    return("Dangerous");
    break;
  case NDPI_PROTOCOL_UNRATED:
  default:
    return("Unrated");
    break;
  }
}

/* ****************************************************** */

int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_str, char *proto) {
  int i;

  for(i=0; i<(int)ndpi_str->ndpi_num_supported_protocols; i++)
    if(strcasecmp(proto, ndpi_str->proto_defaults[i].protoName) == 0)
      return(i);

  return(-1);
}

/* ****************************************************** */

int ndpi_get_category_id(struct ndpi_detection_module_struct *ndpi_str, char *cat) {
  int i;

  for(i = 0; i < NDPI_PROTOCOL_NUM_CATEGORIES; i++) {
    const char *name = ndpi_category_get_name(ndpi_str, i);

    if(strcasecmp(cat, name) == 0)
      return(i);
  }

  return(-1);
}

/* ****************************************************** */

void ndpi_dump_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  for(i=0; i<(int)ndpi_str->ndpi_num_supported_protocols; i++)
    printf("%3d %-22s %-8s %-12s %s\n", i,
	   ndpi_str->proto_defaults[i].protoName,
	   ndpi_get_l4_proto_name(ndpi_get_l4_proto_info(ndpi_str, i)),
	   ndpi_get_proto_breed_name(ndpi_str, ndpi_str->proto_defaults[i].protoBreed),
	   ndpi_category_get_name(ndpi_str, ndpi_str->proto_defaults[i].protoCategory)
	   );
}

/* ****************************************************** */

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char* ndpi_strnstr(const char *s, const char *find, size_t slen) {
  char c;
  size_t len;

  if((c = *find++) != '\0') {
    len = strnlen(find, slen);
    do {
      char sc;

      do {
	if(slen-- < 1 || (sc = *s++) == '\0')
	  return(NULL);
      } while(sc != c);
      if(len > slen)
	return(NULL);
    } while(strncmp(s, find, len) != 0);
    s--;
  }

  return((char *)s);
}

/* ****************************************************** */

/*
 * Same as ndpi_strnstr but case-insensitive
 */
char* ndpi_strncasestr(const char *s, const char *find, size_t slen) {
  char c;
  size_t len;

  if((c = *find++) != '\0') {
    len = strlen(find);
    do {
      char sc;

      do {
	if(slen-- < 1 || (sc = *s++) == '\0')
	  return(NULL);
      } while(sc != c);

      if(len > slen)
	return(NULL);
    } while(strncasecmp(s, find, len) != 0);

    s--;
  }
  return((char *)s);
}

/* ****************************************************** */

int ndpi_match_prefix(const u_int8_t *payload, size_t payload_len,
		      const char *str, size_t str_len) {
  int rc = str_len <= payload_len ? memcmp(payload, str, str_len) == 0 : 0;

  return(rc);
}

/* ****************************************************** */

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
				  char *string_to_match, u_int string_to_match_len,
				  ndpi_protocol_match_result *ret_match,
				  u_int8_t is_host_match) {
  AC_TEXT_t ac_input_text;
  ndpi_automa *automa = is_host_match ? &ndpi_str->host_automa : &ndpi_str->content_automa;
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int rc;
  
  if((automa->ac_automa == NULL) || (string_to_match_len == 0))
    return(NDPI_PROTOCOL_UNKNOWN);

  if(!automa->ac_automa_finalized) {
    printf("[%s:%d] [NDPI] Internal error: please call ndpi_finalize_initalization()\n", __FILE__, __LINE__);
    return(0); /* No matches */
  }

  ac_input_text.astring = string_to_match, ac_input_text.length = string_to_match_len;
  rc = ac_automata_search(((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;
  
  /* We need to take into account also rc == 0 that is used for partial matches */
  ret_match->protocol_id = match.number,
    ret_match->protocol_category = match.category,
    ret_match->protocol_breed = match.breed;
  
  return(rc ? match.number : 0);
}

#ifdef HAVE_HYPERSCAN

/* ******************************************************************** */

static int hyperscanEventHandler(unsigned int id, unsigned long long from,
				 unsigned long long to, unsigned int flags, void *ctx) {
  *((int *)ctx) = (int)id;

  NDPI_LOG_DBG2(ndpi_str, "[NDPI] Match with: %d [from: %llu][to: %llu]\n", id, from, to);

  /* return HS_SCAN_TERMINATED; */
  return(0); /* keep searching */
}

#endif

/* **************************************** */

static u_int8_t ndpi_is_more_generic_protocol(u_int16_t previous_proto, u_int16_t new_proto) {
  /* Sometimes certificates are more generic than previously identified protocols */

  if((previous_proto == NDPI_PROTOCOL_UNKNOWN)
     || (previous_proto == new_proto))
    return(0);

  switch(previous_proto) {
  case NDPI_PROTOCOL_WHATSAPP_CALL:
  case NDPI_PROTOCOL_WHATSAPP_FILES:
    if(new_proto == NDPI_PROTOCOL_WHATSAPP)
      return(1);
  }

  return(0);
}

/* ****************************************************** */

static u_int16_t ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
						      struct ndpi_flow_struct *flow,
						      char *string_to_match, u_int string_to_match_len,
						      u_int16_t master_protocol_id,
						      ndpi_protocol_match_result *ret_match,
						      u_int8_t is_host_match) {
  int matching_protocol_id;
  struct ndpi_packet_struct *packet = &flow->packet;

#ifndef HAVE_HYPERSCAN
  matching_protocol_id = ndpi_match_string_subprotocol(ndpi_str, string_to_match,
						       string_to_match_len, ret_match,
						       is_host_match);
#else
  struct hs *hs = (struct hs*)ndpi_str->hyperscan;
  hs_error_t status;

  matching_protocol_id = NDPI_PROTOCOL_UNKNOWN;
  /*
    TODO HYPERSCAN
    In case of match fill up ret_match and set flow protocol + category
  */
  status = hs_scan(hs->database, string_to_match,
		   string_to_match_len, 0, hs->scratch,
		   hyperscanEventHandler, &matching_protocol_id);

  if(status == HS_SUCCESS) {
    NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan engine completed normally. Result: %s [%d][%s]\n",
		  ndpi_get_proto_name(ndpi_str, matching_protocol_id), matching_protocol_id, string_to_match);
  } else if(status == HS_SCAN_TERMINATED) {
    NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan engine was terminated by callback. Result: %s [%d][%s]\n",
		  ndpi_get_proto_name(ndpi_str, matching_protocol_id), matching_protocol_id, string_to_match);
  } else {
    NDPI_LOG_DBG2(ndpi_str, "[NDPI] Hyperscan returned with error.\n");
  }

  ret_match->protocol_id = matching_protocol_id,
    ret_match->protocol_category = ndpi_str->proto_defaults[matching_protocol_id].protoCategory,
    ret_match->protocol_breed = ndpi_str->proto_defaults[matching_protocol_id].protoBreed;
#endif

#ifdef DEBUG
  {
    char m[256];
    int len = ndpi_min(sizeof(m), string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    NDPI_LOG_DBG2(ndpi_str, "[NDPI] ndpi_match_host_subprotocol(%s): %s\n",
		  m, ndpi_str->proto_defaults[matching_protocol_id].protoName);
  }
#endif

  if((matching_protocol_id != NDPI_PROTOCOL_UNKNOWN)
     && (!ndpi_is_more_generic_protocol(packet->detected_protocol_stack[0], matching_protocol_id))) {
    /* Move the protocol on slot 0 down one position */
    packet->detected_protocol_stack[1] = master_protocol_id,
      packet->detected_protocol_stack[0] = matching_protocol_id;

    flow->detected_protocol_stack[0] = packet->detected_protocol_stack[0],
      flow->detected_protocol_stack[1] = packet->detected_protocol_stack[1];

    if(flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
      flow->category = ret_match->protocol_category;

    return(packet->detected_protocol_stack[0]);
  }

#ifdef DEBUG
  string_to_match[string_to_match_len] = '\0';
  NDPI_LOG_DBG2(ndpi_str, "[NTOP] Unable to find a match for '%s'\n", string_to_match);
#endif

  ret_match->protocol_id = NDPI_PROTOCOL_UNKNOWN,
    ret_match->protocol_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
    ret_match->protocol_breed = NDPI_PROTOCOL_UNRATED;

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */

u_int16_t ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow,
				      char *string_to_match, u_int string_to_match_len,
				      ndpi_protocol_match_result *ret_match,
				      u_int16_t master_protocol_id) {
  u_int16_t rc = ndpi_automa_match_string_subprotocol(ndpi_str,
						      flow, string_to_match, string_to_match_len,
						      master_protocol_id, ret_match, 1);
  unsigned long id = ret_match->protocol_category;

  if(ndpi_get_custom_category_match(ndpi_str, string_to_match, string_to_match_len, &id) != -1) {
    if(id != -1) {
      flow->category = ret_match->protocol_category = id;
      rc = master_protocol_id;
    }
  }

  return(rc);
}

/* **************************************** */

int ndpi_match_hostname_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int16_t master_protocol,				 
				 char *name, u_int name_len) {
  ndpi_protocol_match_result ret_match;
  u_int16_t subproto, what_len;
  char *what;
  
  if((name_len > 2) && (name[0] == '*') && (name[1] == '.'))
    what = &name[1], what_len = name_len - 1;
  else
    what = name, what_len = name_len;
  
  subproto = ndpi_match_host_subprotocol(ndpi_struct, flow,
					 what, what_len,
					 &ret_match, master_protocol);
  
  if(subproto != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, subproto, master_protocol);
    ndpi_int_change_category(ndpi_struct, flow, ret_match.protocol_category);
    return(1);
  } else
    return(0);
}

/* ****************************************************** */

u_int16_t ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					 struct ndpi_flow_struct *flow,
					 char *string_to_match, u_int string_to_match_len,
					 ndpi_protocol_match_result *ret_match,
					 u_int16_t master_protocol_id) {
  return(ndpi_automa_match_string_subprotocol(ndpi_str, flow,
					      string_to_match, string_to_match_len,
					      master_protocol_id, ret_match, 0));
}

/* ****************************************************** */

int ndpi_match_bigram(struct ndpi_detection_module_struct *ndpi_str,
		      ndpi_automa *automa, char *bigram_to_match) {
  AC_TEXT_t ac_input_text;
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int rc;

  if((automa->ac_automa == NULL) || (bigram_to_match == NULL))
    return(-1);

  if(!automa->ac_automa_finalized) {
    printf("[%s:%d] [NDPI] Internal error: please call ndpi_finalize_initalization()\n", __FILE__, __LINE__);
    return(0); /* No matches */
  }

  ac_input_text.astring = bigram_to_match, ac_input_text.length = 2;
  rc = ac_automata_search(((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, &match);

  /*
    As ac_automata_search can detect partial matches and continue the search process
    in case rc == 0 (i.e. no match), we need to check if there is a partial match
    and in this case return it
  */
  if((rc == 0) && (match.number != 0)) rc = 1;

  return(rc ? match.number : 0);
}

/* ****************************************************** */

void ndpi_free_flow(struct ndpi_flow_struct *flow) {
  if(flow) {
    if(flow->http.url)            ndpi_free(flow->http.url);
    if(flow->http.content_type)   ndpi_free(flow->http.content_type);
    if(flow->http.user_agent)     ndpi_free(flow->http.user_agent);
    if(flow->kerberos_buf.pktbuf) ndpi_free(flow->kerberos_buf.pktbuf);

    if(flow_is_proto(flow, NDPI_PROTOCOL_TLS)) {
      if(flow->protos.stun_ssl.ssl.server_names)
	ndpi_free(flow->protos.stun_ssl.ssl.server_names);

      if(flow->protos.stun_ssl.ssl.alpn)
	ndpi_free(flow->protos.stun_ssl.ssl.alpn);

      if(flow->protos.stun_ssl.ssl.tls_supported_versions)
	ndpi_free(flow->protos.stun_ssl.ssl.tls_supported_versions);

      if(flow->l4.tcp.tls.srv_cert_fingerprint_ctx)
	ndpi_free(flow->l4.tcp.tls.srv_cert_fingerprint_ctx);
    }

    if(flow->l4_proto == IPPROTO_TCP) {
      if(flow->l4.tcp.tls.message.buffer)
	ndpi_free(flow->l4.tcp.tls.message.buffer);
    }

    ndpi_free(flow);
  }
}

/* ****************************************************** */

char* ndpi_revision() { return(NDPI_GIT_RELEASE); }

/* ****************************************************** */

#ifdef WIN32

/* https://stackoverflow.com/questions/10905892/equivalent-of-gettimeday-for-windows */
int gettimeofday(struct timeval * tp, struct timezone * tzp) {
  // Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
  // This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
  // until 00:00:00 January 1, 1970
  static const uint64_t EPOCH = ((uint64_t) 116444736000000000ULL);

  SYSTEMTIME  system_time;
  FILETIME    file_time;
  uint64_t    time;

  GetSystemTime( &system_time );
  SystemTimeToFileTime( &system_time, &file_time );
  time =  ((uint64_t)file_time.dwLowDateTime )      ;
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec  = (long) ((time - EPOCH) / 10000000L);
  tp->tv_usec = (long) (system_time.wMilliseconds * 1000);
  return(0);
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

#ifdef CODE_UNUSED
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
#endif

u_int8_t ndpi_get_api_version() {
  return(NDPI_API_VERSION);
}

ndpi_proto_defaults_t* ndpi_get_proto_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str->proto_defaults);
}

u_int ndpi_get_ndpi_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str->ndpi_num_supported_protocols);
}

u_int ndpi_get_ndpi_num_custom_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str->ndpi_num_custom_protocols);
}

u_int ndpi_get_ndpi_detection_module_size() {
  return(sizeof(struct ndpi_detection_module_struct));
}

void ndpi_set_log_level(struct ndpi_detection_module_struct *ndpi_str, u_int l) {
  ndpi_str->ndpi_log_level = l;
}

/* ******************************************************************** */

/* LRU cache */
struct ndpi_lru_cache* ndpi_lru_cache_init(u_int32_t num_entries) {
  struct ndpi_lru_cache *c = (struct ndpi_lru_cache*)ndpi_malloc(sizeof(struct ndpi_lru_cache));

  if(!c) return(NULL);

  c->entries = (struct ndpi_lru_cache_entry*)ndpi_calloc(num_entries,
							 sizeof(struct ndpi_lru_cache_entry));

  if(!c->entries) {
    ndpi_free(c);
    return(NULL);
  } else
    c->num_entries = num_entries;

  return(c);
}

void ndpi_lru_free_cache(struct ndpi_lru_cache *c) {
  ndpi_free(c->entries);
  ndpi_free(c);
}

u_int8_t ndpi_lru_find_cache(struct ndpi_lru_cache *c, u_int32_t key, u_int16_t *value, u_int8_t clean_key_when_found) {
  u_int32_t slot = key % c->num_entries;

  if(c->entries[slot].is_full) {
    *value = c->entries[slot].value;
    if(clean_key_when_found) c->entries[slot].is_full = 0;
    return(1);
  } else
    return(0);
}

void ndpi_lru_add_to_cache(struct ndpi_lru_cache *c, u_int32_t key, u_int16_t value) {
  u_int32_t slot = key % c->num_entries;

  c->entries[slot].is_full = 1,
    c->entries[slot].key = key,
    c->entries[slot].value = value;
}

/* ******************************************************************** */

/*
   This function tells if it's possible to further dissect a given flow
   0 - All possible dissection has been completed
   1 - Additional dissection is possible
*/
u_int8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_str,
					struct ndpi_flow_struct *flow) {
  u_int16_t proto = flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

#if 0
  printf("[DEBUG] %s(%u.%u): %u\n", __FUNCTION__,
	 flow->detected_protocol_stack[0],
	 flow->detected_protocol_stack[1],
   proto);
#endif

  switch(proto) {
  case NDPI_PROTOCOL_TLS:
    if(!flow->l4.tcp.tls.certificate_processed)
      return(1); /* TODO: add check for TLS 1.3 */
    break;

  case NDPI_PROTOCOL_HTTP:
    if((flow->host_server_name[0] == '\0') || (flow->http.response_status_code == 0))
      return(1);
    break;

  case NDPI_PROTOCOL_DNS:
    if(flow->protos.dns.num_answers == 0)
      return(1);
    break;

  case NDPI_PROTOCOL_FTP_CONTROL:
  case NDPI_PROTOCOL_MAIL_POP:
  case NDPI_PROTOCOL_MAIL_IMAP:
  case NDPI_PROTOCOL_MAIL_SMTP:
    if(flow->protos.ftp_imap_pop_smtp.password[0] == '\0')
      return(1);
    break;

  case NDPI_PROTOCOL_SSH:
    if((flow->protos.ssh.hassh_client[0] == '\0')
       || (flow->protos.ssh.hassh_server[0] == '\0'))
      return(1);
    break;

  case NDPI_PROTOCOL_TELNET:
    if(!flow->protos.telnet.password_detected)
      return(1);
    break;
  }

  return(0);
}

/* ******************************************************************** */

const char* ndpi_get_l4_proto_name(ndpi_l4_proto_info proto) {
  switch(proto) {
  case ndpi_l4_proto_unknown:
    return("");
    break;

  case ndpi_l4_proto_tcp_only:
    return("TCP");
    break;

  case ndpi_l4_proto_udp_only:
    return("UDP");
    break;

  case ndpi_l4_proto_tcp_and_udp:
    return("TCP/UDP");
    break;
  }

  return("");
}

/* ******************************************************************** */

ndpi_l4_proto_info ndpi_get_l4_proto_info(struct ndpi_detection_module_struct *ndpi_struct,
					  u_int16_t ndpi_proto_id) {
  if(ndpi_proto_id < ndpi_struct->ndpi_num_supported_protocols) {
    u_int16_t idx = ndpi_struct->proto_defaults[ndpi_proto_id].protoIdx;
    NDPI_SELECTION_BITMASK_PROTOCOL_SIZE bm = ndpi_struct->callback_buffer[idx].ndpi_selection_bitmask;

    if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP)             return(ndpi_l4_proto_tcp_only);
    else if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP)        return(ndpi_l4_proto_udp_only);
    else if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP) return(ndpi_l4_proto_tcp_and_udp);
  }

  return(ndpi_l4_proto_unknown); /* default */
}

/* ******************************************************************** */

ndpi_ptree_t* ndpi_ptree_create(void) {
  ndpi_ptree_t *tree = (ndpi_ptree_t*) ndpi_malloc(sizeof(ndpi_ptree_t));

  if(tree) {
    tree->v4 = ndpi_New_Patricia(32);
    tree->v6 = ndpi_New_Patricia(128);

    if((!tree->v4) || (!tree->v6)) {
      ndpi_ptree_destroy(tree);
      return(NULL);
    }
  }

  return(tree);
}

/* ******************************************************************** */

void ndpi_ptree_destroy(ndpi_ptree_t *tree) {
  if(tree) {
    if(tree->v4) ndpi_Destroy_Patricia(tree->v4, free_ptree_data);
    if(tree->v6) ndpi_Destroy_Patricia(tree->v6, free_ptree_data);

    ndpi_free(tree);
  }
}

/* ******************************************************************** */

int ndpi_ptree_insert(ndpi_ptree_t *tree, const ndpi_ip_addr_t *addr, u_int8_t bits, uint user_data) {
  u_int8_t is_v6 = ndpi_is_ipv6(addr);
  patricia_tree_t *ptree = is_v6 ? tree->v6 : tree->v4;
  prefix_t prefix;
  patricia_node_t *node;

  if(bits > ptree->maxbits)
    return(-1);

  if(is_v6)
    fill_prefix_v6(&prefix, (const struct in6_addr*)&addr->ipv6, bits, ptree->maxbits);
  else
    fill_prefix_v4(&prefix, (const struct in_addr*)&addr->ipv4, bits, ptree->maxbits);

  /* Verify that the node does not already exist */
  node = ndpi_patricia_search_best(ptree, &prefix);

  if(node && (node->prefix->bitlen == bits))
    return(-2);

  node = ndpi_patricia_lookup(ptree, &prefix);

  if(node != NULL) {
    node->value.user_value = user_data;
    return(0);
  }

  return(-3);
}

/* ******************************************************************** */

int ndpi_ptree_match_addr(ndpi_ptree_t *tree, const ndpi_ip_addr_t *addr, uint *user_data) {
  u_int8_t is_v6 = ndpi_is_ipv6(addr);
  patricia_tree_t *ptree = is_v6 ? tree->v6 : tree->v4;
  prefix_t prefix;
  patricia_node_t *node;
  int bits = ptree->maxbits;

  if(is_v6)
    fill_prefix_v6(&prefix, (const struct in6_addr*)&addr->ipv6, bits, ptree->maxbits);
  else
    fill_prefix_v4(&prefix, (const struct in_addr*)&addr->ipv4, bits, ptree->maxbits);

  node = ndpi_patricia_search_best(ptree, &prefix);

  if(node) {
    *user_data = node->value.user_value;
    return(0);
  }

  return(-1);
}

/* ******************************************************************** */

void ndpi_md5(const u_char *data, size_t data_len, u_char hash[16]) {
  ndpi_MD5_CTX ctx;

  ndpi_MD5Init(&ctx);
  ndpi_MD5Update(&ctx, data, data_len);
  ndpi_MD5Final(hash, &ctx);
}
