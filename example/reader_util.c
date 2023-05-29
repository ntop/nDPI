/*
 * reader_util.c
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

#include "ndpi_config.h"
#include "ndpi_api.h"

#include <stdlib.h>
#include <math.h>
#include <float.h>

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#ifndef DISABLE_NPCAP
#include <ip6_misc.h>
#endif
#else
#include <unistd.h>
#include <netinet/in.h>
#endif

#include "reader_util.h"

#define SNAP                   0XAA
#define BSTP                   0x42     /* Bridge Spanning Tree Protocol */

/* Keep last 32 packets */
#define DATA_ANALUYSIS_SLIDING_WINDOW    32

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#define GTP_U_V1_PORT                  2152
#define NDPI_CAPWAP_DATA_PORT          5247
#define TZSP_PORT                      37008

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif

#include "ndpi_main.h"
#include "reader_util.h"
#include "ndpi_classify.h"

extern u_int8_t enable_protocol_guess, enable_flow_stats, enable_payload_analyzer;
extern u_int8_t verbose, human_readeable_string_len;
extern u_int8_t max_num_udp_dissected_pkts /* 24 */, max_num_tcp_dissected_pkts /* 80 */;
static u_int32_t flow_id = 0;

u_int8_t enable_doh_dot_detection = 0;
extern ndpi_init_prefs init_prefs;

extern int malloc_size_stats;
extern struct ndpi_bin malloc_bins;
extern int max_malloc_bins;
extern int enable_malloc_bins;

/* ****************************************************** */

struct flow_id_stats {
  u_int32_t flow_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct packet_id_stats {
  u_int32_t packet_id;
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct payload_stats {
  u_int8_t *pattern;
  u_int8_t pattern_len;
  u_int16_t num_occurrencies;
  struct flow_id_stats *flows;
  struct packet_id_stats *packets;
  UT_hash_handle hh;   /* makes this structure hashable */
};


struct payload_stats *pstats = NULL;
u_int32_t max_num_packets_per_flow      = 10; /* ETTA requires min 10 pkts for record. */
u_int32_t max_packet_payload_dissection = 128;
u_int32_t max_num_reported_top_payloads = 25;
u_int16_t min_pattern_len = 4;
u_int16_t max_pattern_len = 8;

/* *********************************************************** */

void ndpi_analyze_payload(struct ndpi_flow_info *flow,
			  u_int8_t src_to_dst_direction,
			  u_int8_t *payload,
			  u_int16_t payload_len,
			  u_int32_t packet_id) {
  struct payload_stats *ret;
  struct flow_id_stats *f;
  struct packet_id_stats *p;

#ifdef DEBUG_PAYLOAD
  u_int16_t i;
  for(i=0; i<payload_len; i++)
    printf("%c", isprint(payload[i]) ? payload[i] : '.');
  printf("\n");
#endif

  HASH_FIND(hh, pstats, payload, payload_len, ret);
  if(ret == NULL) {
    if((ret = (struct payload_stats*)ndpi_calloc(1, sizeof(struct payload_stats))) == NULL)
      return; /* OOM */

    if((ret->pattern = (u_int8_t*)ndpi_malloc(payload_len)) == NULL) {
      ndpi_free(ret);
      return;
    }

    memcpy(ret->pattern, payload, payload_len);
    ret->pattern_len = payload_len;
    ret->num_occurrencies = 1;

    HASH_ADD(hh, pstats, pattern[0], payload_len, ret);

#ifdef DEBUG_PAYLOAD
    printf("Added element [total: %u]\n", HASH_COUNT(pstats));
#endif
  } else {
    ret->num_occurrencies++;
    // printf("==> %u\n", ret->num_occurrencies);
  }

  HASH_FIND_INT(ret->flows, &flow->flow_id, f);
  if(f == NULL) {
    if((f = (struct flow_id_stats*)ndpi_calloc(1, sizeof(struct flow_id_stats))) == NULL)
      return; /* OOM */

    f->flow_id = flow->flow_id;
    HASH_ADD_INT(ret->flows, flow_id, f);
  }

  HASH_FIND_INT(ret->packets, &packet_id, p);
  if(p == NULL) {
    if((p = (struct packet_id_stats*)ndpi_calloc(1, sizeof(struct packet_id_stats))) == NULL)
      return; /* OOM */
    p->packet_id = packet_id;

    HASH_ADD_INT(ret->packets, packet_id, p);
  }
}

/* *********************************************************** */

void ndpi_payload_analyzer(struct ndpi_flow_info *flow,
			   u_int8_t src_to_dst_direction,
			   u_int8_t *payload, u_int16_t payload_len,
			   u_int32_t packet_id) {
  u_int16_t i, j;
  u_int16_t scan_len = ndpi_min(max_packet_payload_dissection, payload_len);

  if((flow->src2dst_packets+flow->dst2src_packets) <= max_num_packets_per_flow) {
#ifdef DEBUG_PAYLOAD
    printf("[hashval: %u][proto: %u][vlan: %u][%s:%u <-> %s:%u][direction: %s][payload_len: %u]\n",
	   flow->hashval, flow->protocol, flow->vlan_id,
	   flow->src_name, flow->src_port,
	   flow->dst_name, flow->dst_port,
	   src_to_dst_direction ? "s2d" : "d2s",
	   payload_len);
#endif
  } else
    return;

  for(i=0; i<scan_len; i++) {
    for(j=min_pattern_len; j <= max_pattern_len; j++) {
      if((i+j) < payload_len) {
	ndpi_analyze_payload(flow, src_to_dst_direction, &payload[i], j, packet_id);
      }
    }
  }
}

/* ***************************************************** */

static int payload_stats_sort_asc(void *_a, void *_b) {
  struct payload_stats *a = (struct payload_stats *)_a;
  struct payload_stats *b = (struct payload_stats *)_b;

  //return(a->num_occurrencies - b->num_occurrencies);
  return(b->num_occurrencies - a->num_occurrencies);
}

/* ***************************************************** */

static void print_payload_stat(struct payload_stats *p, FILE *out) {
  u_int i;
  struct flow_id_stats *s, *tmp;
  struct packet_id_stats *s1, *tmp1;

  fprintf(out, "\t[");

  for(i=0; i<p->pattern_len; i++) {
    fprintf(out, "%c", isprint(p->pattern[i]) ? p->pattern[i] : '.');
  }

  fprintf(out, "]");
  for(; i<16; i++) fprintf(out, " ");
  fprintf(out, "[");

  for(i=0; i<p->pattern_len; i++) {
    fprintf(out, "%s%02X", (i > 0) ? " " : "", isprint(p->pattern[i]) ? p->pattern[i] : '.');
  }

  fprintf(out, "]");

  for(; i<16; i++) fprintf(out, "  ");
  for(i=p->pattern_len; i<max_pattern_len; i++) fprintf(out, " ");

  fprintf(out, "[len: %u][num_occurrencies: %u][flowId: ",
	  p->pattern_len, p->num_occurrencies);

  i = 0;
  HASH_ITER(hh, p->flows, s, tmp) {
    fprintf(out, "%s%u", (i > 0) ? " " : "", s->flow_id);
    i++;
  }

  fprintf(out, "][packetIds: ");

  /* ******************************** */

  i = 0;
  HASH_ITER(hh, p->packets, s1, tmp1) {
    fprintf(out, "%s%u", (i > 0) ? " " : "", s1->packet_id);
    i++;
  }

  fprintf(out, "]\n");


}

/* ***************************************************** */

void ndpi_report_payload_stats(FILE *out) {
  struct payload_stats *p, *tmp;
  u_int num = 0;

  if(out)
    fprintf(out, "\n\nPayload Analysis\n");

  HASH_SORT(pstats, payload_stats_sort_asc);

  HASH_ITER(hh, pstats, p, tmp) {
    if(out && num <= max_num_reported_top_payloads)
      print_payload_stat(p, out);

    ndpi_free(p->pattern);

    {
      struct flow_id_stats *p1, *tmp1;

      HASH_ITER(hh, p->flows, p1, tmp1) {
	HASH_DEL(p->flows, p1);
	ndpi_free(p1);
      }
    }

    {
      struct packet_id_stats *p1, *tmp1;

      HASH_ITER(hh, p->packets, p1, tmp1) {
	HASH_DEL(p->packets, p1);
	ndpi_free(p1);
      }
    }

    HASH_DEL(pstats, p);
    ndpi_free(p);
    num++;
  }
}

/* ***************************************************** */

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow) {
  if(flow->ndpi_flow) { ndpi_flow_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
}

/* ***************************************************** */

extern u_int32_t current_ndpi_memory, max_ndpi_memory;

static u_int32_t __slot_malloc_bins(u_int64_t v)
{
  int i;

  /* 0-2,3-4,5-8,9-16,17-32,33-64,65-128,129-256,257-512,513-1024,1025-2048,2049-4096,4097-8192,8193- */
  for(i=0; i < max_malloc_bins - 1; i++)
    if((1ULL << (i + 1)) >= v)
      return i;
  return i;
}

/**
 * @brief ndpi_malloc wrapper function
 */
static void *ndpi_malloc_wrapper(size_t size) {
  current_ndpi_memory += size;

  if(current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  if(enable_malloc_bins && malloc_size_stats)
    ndpi_inc_bin(&malloc_bins, __slot_malloc_bins(size), 1);

  return(malloc(size)); /* Don't change to ndpi_malloc !!!!! */
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void free_wrapper(void *freeable) {
  free(freeable); /* Don't change to ndpi_free !!!!! */
}

/* ***************************************************** */

static uint16_t ndpi_get_proto_id(struct ndpi_detection_module_struct *ndpi_mod, const char *name) {
  uint16_t proto_id;
  char *e;
  unsigned long p = strtol(name,&e,0);
  ndpi_proto_defaults_t *proto_defaults = ndpi_get_proto_defaults(ndpi_mod);

  if(e && !*e) {
    if(p < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS &&
       proto_defaults[p].protoName) return (uint16_t)p;
    return NDPI_PROTOCOL_UNKNOWN;
  }

  for(proto_id=NDPI_PROTOCOL_UNKNOWN; proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS; proto_id++) {
    if(proto_defaults[proto_id].protoName &&
       !strcasecmp(proto_defaults[proto_id].protoName,name))
      return proto_id;
  }
  return NDPI_PROTOCOL_UNKNOWN;
}

/* ***************************************************** */

static char _proto_delim[] = " \t,:;";
int parse_proto_name_list(char *str, NDPI_PROTOCOL_BITMASK *bitmask, int inverted_logic) {
  char *n;
  uint16_t proto;
  char op;
  struct ndpi_detection_module_struct *module;
  NDPI_PROTOCOL_BITMASK all;

  if(!inverted_logic)
   op = 1; /* Default action: add to the bitmask */
  else
   op = 0; /* Default action: remove from the bitmask */
  /* Use a temporary module with all protocols enabled */
  module = ndpi_init_detection_module(0);
  if(!module)
    return 1;
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(module, &all);
  ndpi_finalize_initialization(module);

  for(n = strtok(str,_proto_delim); n && *n; n = strtok(NULL,_proto_delim)) {
    if(*n == '-') {
      op = !inverted_logic ? 0 : 1;
      n++;
    } else if(*n == '+') {
      op = !inverted_logic ? 1 : 0;
      n++;
    }
    if(!strcmp(n,"all")) {
      if(op)
	NDPI_BITMASK_SET_ALL(*bitmask);
      else
	NDPI_BITMASK_RESET(*bitmask);
      continue;
    }
    proto = ndpi_get_proto_id(module, n);
    if(proto == NDPI_PROTOCOL_UNKNOWN && strcmp(n,"unknown") && strcmp(n,"0")) {
      fprintf(stderr,"Invalid protocol %s\n",n);
      ndpi_exit_detection_module(module);
      return 1;
    }
    if(op)
      NDPI_BITMASK_ADD(*bitmask,proto);
    else
      NDPI_BITMASK_DEL(*bitmask,proto);
  }
  ndpi_exit_detection_module(module);
  return 0;
}

/* ***************************************************** */

extern char *_debug_protocols;

struct ndpi_workflow* ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs,
					 pcap_t * pcap_handle, int do_init_flows_root,
					 ndpi_serialization_format serialization_format) {
  struct ndpi_detection_module_struct * module;
  struct ndpi_workflow * workflow;
  static NDPI_PROTOCOL_BITMASK debug_bitmask;
  static int _debug_protocols_ok = 0;

  set_ndpi_malloc(ndpi_malloc_wrapper), set_ndpi_free(free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

  /* TODO: just needed here to init ndpi ndpi_malloc wrapper */
  module = ndpi_init_detection_module(init_prefs);

  if(module == NULL) {
    LOG(NDPI_LOG_ERROR, "global structure initialization failed\n");
    exit(-1);
  }

  workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));
  if(workflow == NULL) {
    LOG(NDPI_LOG_ERROR, "global structure initialization failed\n");
    ndpi_free(module);
    exit(-1);
  }

  workflow->pcap_handle = pcap_handle;
  workflow->prefs       = *prefs;
  workflow->ndpi_struct = module;

  ndpi_set_log_level(module, nDPI_LogLevel);

  if(_debug_protocols != NULL && ! _debug_protocols_ok) {
    NDPI_BITMASK_RESET(debug_bitmask);
    if(parse_proto_name_list(_debug_protocols, &debug_bitmask, 0))
      exit(-1);
    _debug_protocols_ok = 1;
  }
  if(_debug_protocols_ok)
    ndpi_set_debug_bitmask(module, debug_bitmask);

  if(do_init_flows_root)
    workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

  workflow->ndpi_serialization_format = serialization_format;

  return workflow;
}

/* ***************************************************** */

void ndpi_flow_info_freer(void *node) {
  struct ndpi_flow_info *flow = (struct ndpi_flow_info*)node;

  ndpi_flow_info_free_data(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

static void ndpi_free_flow_tls_data(struct ndpi_flow_info *flow) {

  if(flow->dhcp_fingerprint) {
    ndpi_free(flow->dhcp_fingerprint);
    flow->dhcp_fingerprint = NULL;
  }
  if(flow->dhcp_class_ident) {
    ndpi_free(flow->dhcp_class_ident);
    flow->dhcp_class_ident = NULL;
  }

  if(flow->bittorent_hash) {
    ndpi_free(flow->bittorent_hash);
    flow->bittorent_hash = NULL;
  }

  if(flow->telnet.username) {
    ndpi_free(flow->telnet.username);
    flow->telnet.username = NULL;
  }
  if(flow->telnet.password) {
    ndpi_free(flow->telnet.password);
    flow->telnet.password = NULL;
  }

  if(flow->ssh_tls.server_names) {
    ndpi_free(flow->ssh_tls.server_names);
    flow->ssh_tls.server_names = NULL;
  }

  if(flow->ssh_tls.advertised_alpns) {
    ndpi_free(flow->ssh_tls.advertised_alpns);
    flow->ssh_tls.advertised_alpns = NULL;
  }

  if(flow->ssh_tls.negotiated_alpn) {
    ndpi_free(flow->ssh_tls.negotiated_alpn);
    flow->ssh_tls.negotiated_alpn = NULL;
  }

  if(flow->ssh_tls.tls_supported_versions) {
    ndpi_free(flow->ssh_tls.tls_supported_versions);
    flow->ssh_tls.tls_supported_versions = NULL;
  }

  if(flow->ssh_tls.tls_issuerDN) {
    ndpi_free(flow->ssh_tls.tls_issuerDN);
    flow->ssh_tls.tls_issuerDN = NULL;
  }

  if(flow->ssh_tls.tls_subjectDN) {
    ndpi_free(flow->ssh_tls.tls_subjectDN);
    flow->ssh_tls.tls_subjectDN = NULL;
  }

  if(flow->ssh_tls.encrypted_sni.esni) {
    ndpi_free(flow->ssh_tls.encrypted_sni.esni);
    flow->ssh_tls.encrypted_sni.esni = NULL;
  }
}

/* ***************************************************** */

static void ndpi_free_flow_data_analysis(struct ndpi_flow_info *flow) {
  if(flow->iat_c_to_s) ndpi_free_data_analysis(flow->iat_c_to_s, 1);
  if(flow->iat_s_to_c) ndpi_free_data_analysis(flow->iat_s_to_c, 1);

  if(flow->pktlen_c_to_s) ndpi_free_data_analysis(flow->pktlen_c_to_s, 1);
  if(flow->pktlen_s_to_c) ndpi_free_data_analysis(flow->pktlen_s_to_c, 1);

  if(flow->iat_flow) ndpi_free_data_analysis(flow->iat_flow, 1);

  if(flow->entropy) ndpi_free(flow->entropy);
  if(flow->last_entropy) ndpi_free(flow->last_entropy);
}

/* ***************************************************** */

void ndpi_flow_info_free_data(struct ndpi_flow_info *flow) {

  ndpi_free_flow_info_half(flow);
  ndpi_term_serializer(&flow->ndpi_flow_serializer);
  ndpi_free_flow_data_analysis(flow);
  ndpi_free_flow_tls_data(flow);

#ifdef DIRECTION_BINS
  ndpi_free_bin(&flow->payload_len_bin_src2dst);
  ndpi_free_bin(&flow->payload_len_bin_dst2src);
#else
  ndpi_free_bin(&flow->payload_len_bin);
#endif

  if(flow->risk_str)     ndpi_free(flow->risk_str);
  if(flow->flow_payload) ndpi_free(flow->flow_payload);
}

/* ***************************************************** */

void ndpi_workflow_free(struct ndpi_workflow * workflow) {
  u_int i;

  for(i=0; i<workflow->prefs.num_roots; i++)
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);

  ndpi_exit_detection_module(workflow->ndpi_struct);
  ndpi_free(workflow->ndpi_flows_root);
  ndpi_free(workflow);
}

static inline int cmp_n32(uint32_t a,uint32_t b) {
	return a == b ? 0 : ntohl(a) < ntohl(b) ? -1:1;
}
static inline int cmp_n16(uint16_t a,uint16_t b) {
	return a == b ? 0 : ntohs(a) < ntohs(b) ? -1:1;
}

/* ***************************************************** */

int ndpi_workflow_node_cmp(const void *a, const void *b) {
  const struct ndpi_flow_info *fa = (const struct ndpi_flow_info*)a;
  const struct ndpi_flow_info *fb = (const struct ndpi_flow_info*)b;

  if(fa->hashval < fb->hashval) return(-1); else if(fa->hashval > fb->hashval) return(1);

  /* Flows have the same hash */

  if(fa->vlan_id   < fb->vlan_id   ) return(-1); else { if(fa->vlan_id    > fb->vlan_id   ) return(1); }
  if(fa->protocol  < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  int r;
  r = cmp_n32(fa->src_ip, fb->src_ip); if(r) return r;
  r = cmp_n16(fa->src_port, fb->src_port) ; if(r) return r;
  r = cmp_n32(fa->dst_ip, fb->dst_ip); if(r) return r;
  r = cmp_n16(fa->dst_port, fb->dst_port);

  return(r);
}

/* ***************************************************** */

/**
 * \brief Update the byte count for the flow record.
 * \param f Flow data
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
static void
ndpi_flow_update_byte_count(struct ndpi_flow_info *flow, const void *x,
                            unsigned int len, u_int8_t src_to_dst_direction) {
  /*
   * implementation note: The spec says that 4000 octets is enough of a
   * sample size to accurately reflect the byte distribution. Also, to avoid
   * wrapping of the byte count at the 16-bit boundry, we stop counting once
   * the 4000th octet has been seen for a flow.
   */

  if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
    /* octet count was already incremented before processing this payload */
    u_int32_t current_count;

    if(src_to_dst_direction) {
      current_count = flow->entropy->src2dst_l4_bytes - len;
    } else {
      current_count = flow->entropy->dst2src_l4_bytes - len;
    }

    if(current_count < ETTA_MIN_OCTETS) {
      u_int32_t i;
      const unsigned char *data = x;

      for(i=0; i<len; i++) {
        if(src_to_dst_direction) {
          flow->entropy->src2dst_byte_count[data[i]]++;
        } else {
          flow->entropy->dst2src_byte_count[data[i]]++;
        }
        current_count++;
        if(current_count >= ETTA_MIN_OCTETS) {
          break;
        }
      }
    }
  }
}

/* ***************************************************** */

/**
 * \brief Update the byte distribution mean for the flow record.
 * \param f Flow record
 * \param x Data to use for update
 * \param len Length of the data (in bytes)
 * \return none
 */
static void
ndpi_flow_update_byte_dist_mean_var(ndpi_flow_info_t *flow, const void *x,
                                    unsigned int len, u_int8_t src_to_dst_direction) {
  const unsigned char *data = x;

  if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
    unsigned int i;

    for(i=0; i<len; i++) {
      double delta;

      if(src_to_dst_direction) {
        flow->entropy->src2dst_num_bytes += 1;
        delta = ((double)data[i] - flow->entropy->src2dst_bd_mean);
        flow->entropy->src2dst_bd_mean += delta/((double)flow->entropy->src2dst_num_bytes);
        flow->entropy->src2dst_bd_variance += delta*((double)data[i] - flow->entropy->src2dst_bd_mean);
      } else {
        flow->entropy->dst2src_num_bytes += 1;
        delta = ((double)data[i] - flow->entropy->dst2src_bd_mean);
        flow->entropy->dst2src_bd_mean += delta/((double)flow->entropy->dst2src_num_bytes);
        flow->entropy->dst2src_bd_variance += delta*((double)data[i] - flow->entropy->dst2src_bd_mean);
      }
    }
  }
}

/* ***************************************************** */

double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256],
				       unsigned int num_bytes)
{
  int i;
  double sum = 0.0;

  for(i=0; i<256; i++) {
    double tmp = (double) byte_count[i] / (double) num_bytes;

    if(tmp > FLT_EPSILON) {
      sum -= tmp * logf(tmp);
    }
  }
  return(sum / log(2.0));
}

/* ***************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow * workflow,
						 const u_int8_t version,
						 u_int16_t vlan_id,
						 ndpi_packet_tunnel tunnel_type,
						 const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 u_int16_t l4_offset,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction,
                                                 pkt_timeval when) {
  u_int32_t idx, hashval;
  struct ndpi_flow_info flow;
  void *ret;
  const u_int8_t *l3, *l4;
  u_int32_t l4_data_len = 0XFEEDFACE;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == IPVERSION) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       /* || (iph->frag_off & htons(0x1FFF)) != 0 */)
      return NULL;

    l3 = (const u_int8_t*)iph;
  } else {
    if(l4_offset > ipsize)
      return NULL;

    l3 = (const u_int8_t*)iph6;
  }
  if(ipsize < l4_offset + l4_packet_len)
    return NULL;

  *proto = iph->protocol;

  if(l4_packet_len < 64)
    workflow->stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    workflow->stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    workflow->stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    workflow->stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    workflow->stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    workflow->stats.packet_len[5]++;

  if(l4_packet_len > workflow->stats.max_packet_len)
    workflow->stats.max_packet_len = l4_packet_len;

  l4 =& ((const u_int8_t *) l3)[l4_offset];

  if(*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr)) {
    u_int tcp_len;

    // TCP
    workflow->stats.tcp_count++;
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = (u_int8_t*)&l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
    l4_data_len = l4_packet_len - sizeof(struct ndpi_tcphdr);
  } else if(*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr)) {
    // UDP
    workflow->stats.udp_count++;
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_udphdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len-sizeof(struct ndpi_udphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_udphdr);
  } else if(*proto == IPPROTO_ICMP) {
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmphdr )];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len-sizeof(struct ndpi_icmphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_icmphdr);
    *sport = *dport = 0;
  } else if(*proto == IPPROTO_ICMPV6) {
    *payload = (u_int8_t*)&l4[sizeof(struct ndpi_icmp6hdr)];
    *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len-sizeof(struct ndpi_icmp6hdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct ndpi_icmp6hdr);
    *sport = *dport = 0;
  } else {
    // non tcp/udp protocols
    *sport = *dport = 0;
    l4_data_len = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.src_ip = iph->saddr, flow.dst_ip = iph->daddr;
  flow.src_port = htons(*sport), flow.dst_port = htons(*dport);
  flow.hashval = hashval = flow.protocol + ntohl(flow.src_ip) + ntohl(flow.dst_ip) 
	  + ntohs(flow.src_port) + ntohs(flow.dst_port);

#if 0
  {
  char ip1[48],ip2[48];
       inet_ntop(AF_INET, &flow.src_ip, ip1, sizeof(ip1));
       inet_ntop(AF_INET, &flow.dst_ip, ip2, sizeof(ip2));
  printf("hashval=%u [%u][%u][%s:%u][%s:%u]\n", hashval, flow.protocol, flow.vlan_id,
        ip1, ntohs(flow.src_port),  ip2, ntohs(flow.dst_port));
  }
#endif

  idx = hashval % workflow->prefs.num_roots;
  ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);

  /* to avoid two nodes in one binary tree for a flow */
  int is_changed = 0;
  if(ret == NULL) {
    u_int32_t orig_src_ip = flow.src_ip;
    u_int16_t orig_src_port = flow.src_port;
    u_int32_t orig_dst_ip = flow.dst_ip;
    u_int16_t orig_dst_port = flow.dst_port;

    flow.src_ip = orig_dst_ip;
    flow.src_port = orig_dst_port;
    flow.dst_ip = orig_src_ip;
    flow.dst_port = orig_src_port;

    is_changed = 1;

    ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);
  }

  if(ret == NULL) {
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      LOG(NDPI_LOG_ERROR,
	       "maximum flow count (%u) has been exceeded\n",
	       workflow->prefs.max_ndpi_flows);
      return NULL;
    } else {
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)ndpi_malloc(sizeof(struct ndpi_flow_info));

      if(newflow == NULL) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* Avoid too much logging while fuzzing */
	LOG(NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
#endif
	return(NULL);
      } else
        workflow->num_allocated_flows++;

      memset(newflow, 0, sizeof(struct ndpi_flow_info));
      newflow->flow_id = flow_id++;
      newflow->hashval = hashval;
      newflow->tunnel_type = tunnel_type;
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->src_ip = iph->saddr, newflow->dst_ip = iph->daddr;
      newflow->src_port = htons(*sport), newflow->dst_port = htons(*dport);
      newflow->ip_version = version;
      newflow->iat_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->iat_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);
      newflow->pktlen_c_to_s = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->pktlen_s_to_c =  ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW),
	newflow->iat_flow = ndpi_alloc_data_analysis(DATA_ANALUYSIS_SLIDING_WINDOW);

#ifdef DIRECTION_BINS
      ndpi_init_bin(&newflow->payload_len_bin_src2dst, ndpi_bin_family8, PLEN_NUM_BINS);
      ndpi_init_bin(&newflow->payload_len_bin_dst2src, ndpi_bin_family8, PLEN_NUM_BINS);
#else
      ndpi_init_bin(&newflow->payload_len_bin, ndpi_bin_family8, PLEN_NUM_BINS);
#endif

      if(version == IPVERSION) {
	inet_ntop(AF_INET, &newflow->src_ip, newflow->src_name, sizeof(newflow->src_name));
	inet_ntop(AF_INET, &newflow->dst_ip, newflow->dst_name, sizeof(newflow->dst_name));
      } else {
        newflow->src_ip6 = *(struct ndpi_in6_addr *)&iph6->ip6_src;
        inet_ntop(AF_INET6, &newflow->src_ip6,
                  newflow->src_name, sizeof(newflow->src_name));
        newflow->dst_ip6 = *(struct ndpi_in6_addr *)&iph6->ip6_dst;
        inet_ntop(AF_INET6, &newflow->dst_ip6,
                  newflow->dst_name, sizeof(newflow->dst_name));
        /* For consistency across platforms replace :0: with :: */
        ndpi_patchIPv6Address(newflow->src_name), ndpi_patchIPv6Address(newflow->dst_name);
      }

      if((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* Avoid too much logging while fuzzing */
	LOG(NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
#endif
	ndpi_flow_info_free_data(newflow);
	ndpi_free(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    if (workflow->ndpi_serialization_format != ndpi_serialization_format_unknown)
    {
      if (ndpi_init_serializer(&newflow->ndpi_flow_serializer,
                               workflow->ndpi_serialization_format) != 0)
      {
        LOG(NDPI_LOG_ERROR, "ndpi serializer init failed\n");
        ndpi_flow_info_free_data(newflow);
        ndpi_free(newflow);
        return(NULL);
      }
    }

      if(ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp) == NULL) { /* Add */
        ndpi_flow_info_free_data(newflow);
        ndpi_free(newflow);
        return(NULL);
      }
      workflow->stats.ndpi_flow_count++;
      if(*proto == IPPROTO_TCP)
        workflow->stats.flow_count[0]++;
      else if(*proto == IPPROTO_UDP)
        workflow->stats.flow_count[1]++;
      else
        workflow->stats.flow_count[2]++;

      if(enable_flow_stats) {
        newflow->entropy = ndpi_calloc(1, sizeof(struct ndpi_entropy));
        newflow->last_entropy = ndpi_calloc(1, sizeof(struct ndpi_entropy));
        newflow->entropy->src2dst_pkt_len[newflow->entropy->src2dst_pkt_count] = l4_data_len;
        newflow->entropy->src2dst_pkt_time[newflow->entropy->src2dst_pkt_count] = when;
        if(newflow->entropy->src2dst_pkt_count == 0) {
          newflow->entropy->src2dst_start = when;
        }
        newflow->entropy->src2dst_pkt_count++;
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          newflow->entropy->src2dst_opackets++;
          newflow->entropy->src2dst_l4_bytes += l4_data_len;
        }
      }
      return newflow;
    }
  } else {
    struct ndpi_flow_info *rflow = *(struct ndpi_flow_info**)ret;

    if(is_changed) {
	*src_to_dst_direction = 0, rflow->bidirectional |= 1;
    }
    else {
	*src_to_dst_direction = 1;
    }
    if(enable_flow_stats) {
      if(*src_to_dst_direction) {
        if(rflow->entropy->src2dst_pkt_count < max_num_packets_per_flow) {
          rflow->entropy->src2dst_pkt_len[rflow->entropy->src2dst_pkt_count] = l4_data_len;
          rflow->entropy->src2dst_pkt_time[rflow->entropy->src2dst_pkt_count] = when;
          rflow->entropy->src2dst_l4_bytes += l4_data_len;
          rflow->entropy->src2dst_pkt_count++;
        }
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          rflow->entropy->src2dst_opackets++;
        }
      } else {
        if(rflow->entropy->dst2src_pkt_count < max_num_packets_per_flow) {
          rflow->entropy->dst2src_pkt_len[rflow->entropy->dst2src_pkt_count] = l4_data_len;
          rflow->entropy->dst2src_pkt_time[rflow->entropy->dst2src_pkt_count] = when;
          if(rflow->entropy->dst2src_pkt_count == 0) {
            rflow->entropy->dst2src_start = when;
          }
          rflow->entropy->dst2src_l4_bytes += l4_data_len;
          rflow->entropy->dst2src_pkt_count++;
        }
        // Non zero app data.
        if(l4_data_len != 0XFEEDFACE && l4_data_len != 0) {
          rflow->entropy->dst2src_opackets++;
        }
      }
    }

    return(rflow);
  }
}

/* ****************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow * workflow,
						  u_int16_t vlan_id,
						  ndpi_packet_tunnel tunnel_type,
						  const struct ndpi_ipv6hdr *iph6,
						  u_int16_t ip_offset,
						  u_int16_t ipsize,
						  struct ndpi_tcphdr **tcph,
						  struct ndpi_udphdr **udph,
						  u_int16_t *sport, u_int16_t *dport,
						  u_int8_t *proto,
						  u_int8_t **payload,
						  u_int16_t *payload_len,
						  u_int8_t *src_to_dst_direction,
                                                  pkt_timeval when) {
  struct ndpi_iphdr iph;

  if(ipsize < 40)
    return(NULL);
  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  u_int8_t l4proto = iph6->ip6_hdr.ip6_un1_nxt;
  u_int16_t ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
  const u_int8_t *l4ptr = (((const u_int8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
  if(ipsize < sizeof(struct ndpi_ipv6hdr) + ip_len)
    return(NULL);
  if(ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &l4proto) != 0) {
    return(NULL);
  }
  iph.protocol = l4proto;

  return(get_ndpi_flow_info(workflow, 6, vlan_id, tunnel_type,
			    &iph, iph6, ip_offset, ipsize,
			    ip_len, l4ptr - (const u_int8_t *)iph6,
			    tcph, udph, sport, dport,
			    proto, payload,
			    payload_len, src_to_dst_direction, when));
}

/* ****************************************************** */

static u_int8_t is_ndpi_proto(struct ndpi_flow_info *flow, u_int16_t id) {
  if((flow->detected_protocol.master_protocol == id)
     || (flow->detected_protocol.app_protocol == id))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

void correct_csv_data_field(char* data) {
  /* Replace , with ; to avoid issues with CSVs */
  u_int i;
  for(i=0; data[i] != '\0'; i++) if(data[i] == ',') data[i] = ';';
}

/* ****************************************************** */

u_int8_t plen2slot(u_int16_t plen) {
  /*
     Slots [32 bytes lenght]
     0..31, 32..63 ...
  */

  if(plen > PLEN_MAX)
    return(PLEN_NUM_BINS-1);
  else
    return(plen/PLEN_BIN_LEN);
}

/* ****************************************************** */

void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow) {
  u_int i, is_quic = 0;
  char out[128], *s;
  
  if(!flow->ndpi_flow) return;

  flow->info_type = INFO_INVALID;

  s = ndpi_get_flow_risk_info(flow->ndpi_flow, out, sizeof(out), 0 /* text */);

  if(s != NULL)
    flow->risk_str = ndpi_strdup(s);  
  
  flow->confidence = flow->ndpi_flow->confidence;
  flow->num_dissector_calls = flow->ndpi_flow->num_dissector_calls;

  ndpi_snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
	   flow->ndpi_flow->host_server_name);

  ndpi_snprintf(flow->flow_extra_info, sizeof(flow->flow_extra_info), "%s",
	   flow->ndpi_flow->flow_extra_info);

  flow->risk = flow->ndpi_flow->risk;

  if(is_ndpi_proto(flow, NDPI_PROTOCOL_DHCP)) {
    if(flow->ndpi_flow->protos.dhcp.fingerprint[0] != '\0')
      flow->dhcp_fingerprint = ndpi_strdup(flow->ndpi_flow->protos.dhcp.fingerprint);
    if(flow->ndpi_flow->protos.dhcp.class_ident[0] != '\0')
      flow->dhcp_class_ident = ndpi_strdup(flow->ndpi_flow->protos.dhcp.class_ident);
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_BITTORRENT) &&
            !is_ndpi_proto(flow, NDPI_PROTOCOL_DNS) &&
            !is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)) {
    u_int j;

    if(flow->ndpi_flow->protos.bittorrent.hash[0] != '\0') {
      flow->bittorent_hash = ndpi_malloc(sizeof(flow->ndpi_flow->protos.bittorrent.hash) * 2 + 1);
      if(flow->bittorent_hash) {
        for(i=0, j = 0; i < sizeof(flow->ndpi_flow->protos.bittorrent.hash); i++) {
          sprintf(&flow->bittorent_hash[j], "%02x",
	          flow->ndpi_flow->protos.bittorrent.hash[i]);

          j += 2;
        }
        flow->bittorent_hash[j] = '\0';
      }
    }
  }
  /* TIVOCONNECT */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TIVOCONNECT)) {
    flow->info_type = INFO_TIVOCONNECT;
    ndpi_snprintf(flow->tivoconnect.identity_uuid, sizeof(flow->tivoconnect.identity_uuid),
                  "%s", flow->ndpi_flow->protos.tivoconnect.identity_uuid);
    ndpi_snprintf(flow->tivoconnect.machine, sizeof(flow->tivoconnect.machine),
                  "%s", flow->ndpi_flow->protos.tivoconnect.machine);
    ndpi_snprintf(flow->tivoconnect.platform, sizeof(flow->tivoconnect.platform),
                  "%s", flow->ndpi_flow->protos.tivoconnect.platform);
    ndpi_snprintf(flow->tivoconnect.services, sizeof(flow->tivoconnect.services),
                  "%s", flow->ndpi_flow->protos.tivoconnect.services);
  }
  /* SOFTETHER */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_SOFTETHER) && !is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP)) {
    flow->info_type = INFO_SOFTETHER;
    ndpi_snprintf(flow->softether.ip, sizeof(flow->softether.ip), "%s",
                  flow->ndpi_flow->protos.softether.ip);
    ndpi_snprintf(flow->softether.port, sizeof(flow->softether.port), "%s",
                  flow->ndpi_flow->protos.softether.port);
    ndpi_snprintf(flow->softether.hostname, sizeof(flow->softether.hostname), "%s",
                  flow->ndpi_flow->protos.softether.hostname);
    ndpi_snprintf(flow->softether.fqdn, sizeof(flow->softether.fqdn), "%s",
                  flow->ndpi_flow->protos.softether.fqdn);
  }
  /* NATPMP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_NATPMP)) {
    flow->info_type = INFO_NATPMP;
    flow->natpmp.result_code = flow->ndpi_flow->protos.natpmp.result_code;
    flow->natpmp.internal_port = flow->ndpi_flow->protos.natpmp.internal_port;
    flow->natpmp.external_port = flow->ndpi_flow->protos.natpmp.external_port;
    inet_ntop(AF_INET, &flow->ndpi_flow->protos.natpmp.external_address.ipv4, &flow->natpmp.ip[0], sizeof(flow->natpmp.ip));
  }
  /* DISCORD */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_DISCORD) &&
          !is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) &&
          !is_ndpi_proto(flow, NDPI_PROTOCOL_DTLS) &&
          flow->ndpi_flow->protos.discord.client_ip[0] != '\0') {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "Client IP: %s",
                  flow->ndpi_flow->protos.discord.client_ip);
  }
  /* DNS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_DNS)) {
    if(flow->ndpi_flow->protos.dns.rsp_type == 0x1)
    {
      flow->info_type = INFO_GENERIC;
      inet_ntop(AF_INET, &flow->ndpi_flow->protos.dns.rsp_addr.ipv4, flow->info, sizeof(flow->info));
    } else {
      flow->info_type = INFO_GENERIC;
      inet_ntop(AF_INET6, &flow->ndpi_flow->protos.dns.rsp_addr.ipv6, flow->info, sizeof(flow->info));

      /* For consistency across platforms replace :0: with :: */
      ndpi_patchIPv6Address(flow->info);
    }
  }
  /* MDNS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_MDNS)) {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->host_server_name);
  }
  /* UBNTAC2 */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_UBNTAC2)) {
    flow->info_type = INFO_GENERIC;
    ndpi_snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
  }
  /* FTP */
  else if((is_ndpi_proto(flow, NDPI_PROTOCOL_FTP_CONTROL))
	  || /* IMAP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAP)
	  || /* POP */  is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POP)
	  || /* SMTP */ is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTP)) {
    flow->info_type = INFO_FTP_IMAP_POP_SMTP;
    ndpi_snprintf(flow->ftp_imap_pop_smtp.username,
                  sizeof(flow->ftp_imap_pop_smtp.username),
                  "%s", flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.username);
    ndpi_snprintf(flow->ftp_imap_pop_smtp.password,
                  sizeof(flow->ftp_imap_pop_smtp.password),
                  "%s", flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.password);
    flow->ftp_imap_pop_smtp.auth_failed =
      flow->ndpi_flow->l4.tcp.ftp_imap_pop_smtp.auth_failed;
  }
  /* TFTP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TFTP)) {
    flow->info_type = INFO_GENERIC;
    if(flow->ndpi_flow->protos.tftp.filename[0] != '\0')
      ndpi_snprintf(flow->info, sizeof(flow->info), "Filename: %s",
                    flow->ndpi_flow->protos.tftp.filename);
  }
  /* KERBEROS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_KERBEROS)) {
    flow->info_type = INFO_KERBEROS;
    ndpi_snprintf(flow->kerberos.domain,
                  sizeof(flow->kerberos.domain),
                  "%s", flow->ndpi_flow->protos.kerberos.domain);
    ndpi_snprintf(flow->kerberos.hostname,
                  sizeof(flow->kerberos.hostname),
                  "%s", flow->ndpi_flow->protos.kerberos.hostname);
    ndpi_snprintf(flow->kerberos.username,
                  sizeof(flow->kerberos.username),
                  "%s", flow->ndpi_flow->protos.kerberos.username);
  }
  /* RTP */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_RTP)) {
    flow->info_type = INFO_RTP;
    flow->rtp.stream_type = flow->ndpi_flow->protos.rtp.stream_type;
  /* COLLECTD */
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_COLLECTD)) {
    flow->info_type = INFO_GENERIC;
    if(flow->ndpi_flow->protos.collectd.client_username[0] != '\0')
      ndpi_snprintf(flow->info, sizeof(flow->info), "Username: %s",
                    flow->ndpi_flow->protos.collectd.client_username);
  }
  /* TELNET */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TELNET)) {
    if(flow->ndpi_flow->protos.telnet.username[0] != '\0')
      flow->telnet.username = ndpi_strdup(flow->ndpi_flow->protos.telnet.username);
    if(flow->ndpi_flow->protos.telnet.password[0] != '\0')
      flow->telnet.password = ndpi_strdup(flow->ndpi_flow->protos.telnet.password);
  } else if(is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)) {
    ndpi_snprintf(flow->host_server_name,
	     sizeof(flow->host_server_name), "%s",
	     flow->ndpi_flow->protos.ssh.client_signature);
    ndpi_snprintf(flow->ssh_tls.server_info, sizeof(flow->ssh_tls.server_info), "%s",
	     flow->ndpi_flow->protos.ssh.server_signature);
    ndpi_snprintf(flow->ssh_tls.client_hassh, sizeof(flow->ssh_tls.client_hassh), "%s",
	     flow->ndpi_flow->protos.ssh.hassh_client);
    ndpi_snprintf(flow->ssh_tls.server_hassh, sizeof(flow->ssh_tls.server_hassh), "%s",
	     flow->ndpi_flow->protos.ssh.hassh_server);
  }
  /* TLS */
  else if(is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_DTLS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POPS)
          || is_ndpi_proto(flow, NDPI_PROTOCOL_FTPS)
	  || ((is_quic = is_ndpi_proto(flow, NDPI_PROTOCOL_QUIC)))
	  ) {
    flow->ssh_tls.ssl_version = flow->ndpi_flow->protos.tls_quic.ssl_version;

    if(flow->ndpi_flow->protos.tls_quic.server_names_len > 0 && flow->ndpi_flow->protos.tls_quic.server_names)
      flow->ssh_tls.server_names = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.server_names);

    flow->ssh_tls.notBefore = flow->ndpi_flow->protos.tls_quic.notBefore;
    flow->ssh_tls.notAfter = flow->ndpi_flow->protos.tls_quic.notAfter;
    ndpi_snprintf(flow->ssh_tls.ja3_client, sizeof(flow->ssh_tls.ja3_client), "%s",
	     flow->ndpi_flow->protos.tls_quic.ja3_client);
    ndpi_snprintf(flow->ssh_tls.ja3_server, sizeof(flow->ssh_tls.ja3_server), "%s",
	     flow->ndpi_flow->protos.tls_quic.ja3_server);
    flow->ssh_tls.server_unsafe_cipher = flow->ndpi_flow->protos.tls_quic.server_unsafe_cipher;
    flow->ssh_tls.server_cipher = flow->ndpi_flow->protos.tls_quic.server_cipher;

    if(flow->ndpi_flow->protos.tls_quic.fingerprint_set) {
      memcpy(flow->ssh_tls.sha1_cert_fingerprint,
	     flow->ndpi_flow->protos.tls_quic.sha1_certificate_fingerprint, 20);
      flow->ssh_tls.sha1_cert_fingerprint_set = 1;
    }

    flow->ssh_tls.browser_heuristics = flow->ndpi_flow->protos.tls_quic.browser_heuristics;

    if(flow->ndpi_flow->protos.tls_quic.issuerDN)
      flow->ssh_tls.tls_issuerDN = strdup(flow->ndpi_flow->protos.tls_quic.issuerDN);

    if(flow->ndpi_flow->protos.tls_quic.subjectDN)
      flow->ssh_tls.tls_subjectDN = strdup(flow->ndpi_flow->protos.tls_quic.subjectDN);

    if(flow->ndpi_flow->protos.tls_quic.encrypted_sni.esni) {
      flow->ssh_tls.encrypted_sni.esni = strdup(flow->ndpi_flow->protos.tls_quic.encrypted_sni.esni);
      flow->ssh_tls.encrypted_sni.cipher_suite = flow->ndpi_flow->protos.tls_quic.encrypted_sni.cipher_suite;
    }

    if(flow->ndpi_flow->protos.tls_quic.tls_supported_versions) {
      if((flow->ssh_tls.tls_supported_versions = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.tls_supported_versions)) != NULL)
	correct_csv_data_field(flow->ssh_tls.tls_supported_versions);
    }

    if(flow->ndpi_flow->protos.tls_quic.advertised_alpns) {
      if((flow->ssh_tls.advertised_alpns = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.advertised_alpns)) != NULL)
	correct_csv_data_field(flow->ssh_tls.advertised_alpns);
    }

    if(flow->ndpi_flow->protos.tls_quic.negotiated_alpn) {
      if((flow->ssh_tls.negotiated_alpn = ndpi_strdup(flow->ndpi_flow->protos.tls_quic.negotiated_alpn)) != NULL)
	correct_csv_data_field(flow->ssh_tls.negotiated_alpn);
    }

    if(enable_doh_dot_detection) {
      /* For TLS we use TLS block lenght instead of payload lenght */
      ndpi_reset_bin(&flow->payload_len_bin);

      for(i=0; i<flow->ndpi_flow->l4.tcp.tls.num_tls_blocks; i++) {
	u_int16_t len = abs(flow->ndpi_flow->l4.tcp.tls.tls_application_blocks_len[i]);

	/* printf("[TLS_LEN] %u\n", len); */
	ndpi_inc_bin(&flow->payload_len_bin, plen2slot(len), 1);
      }
    }
  }

  /* HTTP metadata are "global" not in `flow->ndpi_flow->protos` union; for example, we can have
     HTTP/BitTorrent and in that case we want to export also HTTP attributes */
  if(is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP)
	  || is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP_PROXY)
	  || is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP_CONNECT)) {
    if(flow->ndpi_flow->http.url != NULL) {
      ndpi_snprintf(flow->http.url, sizeof(flow->http.url), "%s", flow->ndpi_flow->http.url);
    }
    flow->http.response_status_code = flow->ndpi_flow->http.response_status_code;
    ndpi_snprintf(flow->http.content_type, sizeof(flow->http.content_type), "%s", flow->ndpi_flow->http.content_type ? flow->ndpi_flow->http.content_type : "");
    ndpi_snprintf(flow->http.server, sizeof(flow->http.server), "%s", flow->ndpi_flow->http.server ? flow->ndpi_flow->http.server : "");
    ndpi_snprintf(flow->http.request_content_type, sizeof(flow->http.request_content_type), "%s", flow->ndpi_flow->http.request_content_type ? flow->ndpi_flow->http.request_content_type : "");
    ndpi_snprintf(flow->http.nat_ip, sizeof(flow->http.nat_ip), "%s", flow->ndpi_flow->http.nat_ip ? flow->ndpi_flow->http.nat_ip : "");
  }

  ndpi_snprintf(flow->http.user_agent,
                sizeof(flow->http.user_agent),
                "%s", (flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : ""));

  if (workflow->ndpi_serialization_format != ndpi_serialization_format_unknown)
  {
    if (ndpi_flow2json(workflow->ndpi_struct, flow->ndpi_flow,
                       flow->ip_version, flow->protocol,
                       flow->src_ip, flow->dst_ip,
                       &flow->src_ip6, &flow->dst_ip6,
                       flow->src_port, flow->dst_port,
                       flow->detected_protocol,
                       &flow->ndpi_flow_serializer) != 0)
    {
      LOG(NDPI_LOG_ERROR, "flow2json failed\n");
      exit(-1);
    }
    ndpi_serialize_string_uint32(&flow->ndpi_flow_serializer, "detection_completed", flow->detection_completed);
    ndpi_serialize_string_uint32(&flow->ndpi_flow_serializer, "check_extra_packets", flow->check_extra_packets);
  }

  if(flow->detection_completed && (!flow->check_extra_packets)) {
   
    flow->flow_payload = flow->ndpi_flow->flow_payload, flow->flow_payload_len = flow->ndpi_flow->flow_payload_len;
    flow->ndpi_flow->flow_payload = NULL; /* We'll free the memory */

    ndpi_free_flow_info_half(flow);
  }
}

/* ****************************************************** */

/**
 * @brief Clear entropy stats if it meets prereq.
 */
static void
ndpi_clear_entropy_stats(struct ndpi_flow_info *flow) {
  if(enable_flow_stats) {
    if(flow->entropy->src2dst_pkt_count + flow->entropy->dst2src_pkt_count == max_num_packets_per_flow) {
      memcpy(flow->last_entropy, flow->entropy,  sizeof(struct ndpi_entropy));
      memset(flow->entropy, 0x00, sizeof(struct ndpi_entropy));
    }
  }
}

void update_tcp_flags_count(struct ndpi_flow_info* flow, struct ndpi_tcphdr* tcp, u_int8_t src_to_dst_direction){
  if(tcp->cwr){
    flow->cwr_count++;
    src_to_dst_direction ? flow->src2dst_cwr_count++ : flow->dst2src_cwr_count++;
  }
  if(tcp->ece){
    flow->ece_count++;
    src_to_dst_direction ? flow->src2dst_ece_count++ : flow->dst2src_ece_count++;
  }
  if(tcp->rst){
    flow->rst_count++;
    src_to_dst_direction ? flow->src2dst_rst_count++ : flow->dst2src_rst_count++;
  }
  if(tcp->ack){
    flow->ack_count++;
    src_to_dst_direction ? flow->src2dst_ack_count++ : flow->dst2src_ack_count++;
  }
  if(tcp->fin){
    flow->fin_count++;
    src_to_dst_direction ? flow->src2dst_fin_count++ : flow->dst2src_fin_count++;
  }
  if(tcp->syn){
    flow->syn_count++;
    src_to_dst_direction ? flow->src2dst_syn_count++ : flow->dst2src_syn_count++;
  }
  if(tcp->psh){
    flow->psh_count++;
    src_to_dst_direction ? flow->src2dst_psh_count++ : flow->dst2src_psh_count++;
  }
  if(tcp->urg){
    flow->urg_count++;
    src_to_dst_direction ? flow->src2dst_urg_count++ : flow->dst2src_urg_count++;
  }
}

/* ****************************************************** */

/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
static struct ndpi_proto packet_processing(struct ndpi_workflow * workflow,
					   const u_int64_t time_ms,
					   u_int16_t vlan_id,
					   ndpi_packet_tunnel tunnel_type,
					   const struct ndpi_iphdr *iph,
					   struct ndpi_ipv6hdr *iph6,
					   u_int16_t ip_offset,
					   u_int16_t ipsize, u_int16_t rawsize,
					   const struct pcap_pkthdr *header,
					   const u_char *packet,
					   pkt_timeval when,
					   ndpi_risk *flow_risk) {
  struct ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len = 0;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  u_int8_t begin_or_end_tcp = 0;
  struct ndpi_proto nproto = NDPI_PROTOCOL_NULL;

  if(workflow->prefs.ignore_vlanid)
    vlan_id = 0;

  if(iph)
    flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id,
			      tunnel_type, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) ? (ntohs(iph->tot_len) - (iph->ihl * 4)) : ipsize - (iph->ihl * 4) /* TSO */,
			      iph->ihl * 4,
			      &tcph, &udph, &sport, &dport,
			      &proto,
			      &payload, &payload_len, &src_to_dst_direction, when);
  else
    flow = get_ndpi_flow_info6(workflow, vlan_id,
			       tunnel_type, iph6, ip_offset, ipsize,
			       &tcph, &udph, &sport, &dport,
			       &proto,
			       &payload, &payload_len, &src_to_dst_direction, when);

  if(flow != NULL) {
    pkt_timeval tdiff;

    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
      workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;

    if(tcph != NULL){
      update_tcp_flags_count(flow, tcph, src_to_dst_direction);
      if(tcph->syn && !flow->src2dst_bytes){
	flow->c_to_s_init_win = rawsize;
      }else if(tcph->syn && tcph->ack && flow->src2dst_bytes == flow->c_to_s_init_win){
	flow->s_to_c_init_win = rawsize;
      }
    }

    if((tcph != NULL) && (tcph->fin || tcph->rst || tcph->syn))
      begin_or_end_tcp = 1;

    if(flow->flow_last_pkt_time.tv_sec) {
      ndpi_timer_sub(&when, &flow->flow_last_pkt_time, &tdiff);

      if(flow->iat_flow
	 && (tdiff.tv_sec >= 0) /* Discard backward time */
	 ) {
	u_int64_t ms = ndpi_timeval_to_milliseconds(tdiff);

	if(ms > 0)
	  ndpi_data_add_value(flow->iat_flow, ms);
      }
    }

    memcpy(&flow->flow_last_pkt_time, &when, sizeof(when));

    if(src_to_dst_direction) {
      if(flow->src2dst_last_pkt_time.tv_sec) {
	ndpi_timer_sub(&when, &flow->src2dst_last_pkt_time, &tdiff);

	if(flow->iat_c_to_s
	   && (tdiff.tv_sec >= 0) /* Discard backward time */
	   ) {
	  u_int64_t ms = ndpi_timeval_to_milliseconds(tdiff);

	  ndpi_data_add_value(flow->iat_c_to_s, ms);
	}
      }

      ndpi_data_add_value(flow->pktlen_c_to_s, rawsize);
      flow->src2dst_packets++, flow->src2dst_bytes += rawsize, flow->src2dst_goodput_bytes += payload_len;
      memcpy(&flow->src2dst_last_pkt_time, &when, sizeof(when));

#ifdef DIRECTION_BINS
      if(payload_len && (flow->src2dst_packets < MAX_NUM_BIN_PKTS))
	ndpi_inc_bin(&flow->payload_len_bin_src2dst, plen2slot(payload_len));
#endif
    } else {
      if(flow->dst2src_last_pkt_time.tv_sec && (!begin_or_end_tcp)) {
	ndpi_timer_sub(&when, &flow->dst2src_last_pkt_time, &tdiff);

	if(flow->iat_s_to_c) {
	  u_int64_t ms = ndpi_timeval_to_milliseconds(tdiff);

	  ndpi_data_add_value(flow->iat_s_to_c, ms);
	}
      }
      ndpi_data_add_value(flow->pktlen_s_to_c, rawsize);
      flow->dst2src_packets++, flow->dst2src_bytes += rawsize, flow->dst2src_goodput_bytes += payload_len;
      flow->risk &= ~(1ULL << NDPI_UNIDIRECTIONAL_TRAFFIC); /* Clear bit */
      memcpy(&flow->dst2src_last_pkt_time, &when, sizeof(when));

#ifdef DIRECTION_BINS
      if(payload_len && (flow->dst2src_packets < MAX_NUM_BIN_PKTS))
	ndpi_inc_bin(&flow->payload_len_bin_dst2src, plen2slot(payload_len));
#endif
    }

#ifndef DIRECTION_BINS
    if(payload_len && ((flow->src2dst_packets+flow->dst2src_packets) < MAX_NUM_BIN_PKTS)) {
#if 0
      /* Discard packets until the protocol is detected */
      if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
#endif
	ndpi_inc_bin(&flow->payload_len_bin, plen2slot(payload_len), 1);
    }
#endif

    if(enable_payload_analyzer && (payload_len > 0))
      ndpi_payload_analyzer(flow, src_to_dst_direction,
			    payload, payload_len,
			    workflow->stats.ip_packet_count);

    if(enable_flow_stats) {
      /* Update BD, distribution and mean. */
      ndpi_flow_update_byte_count(flow, payload, payload_len, src_to_dst_direction);
      ndpi_flow_update_byte_dist_mean_var(flow, payload, payload_len, src_to_dst_direction);
      /* Update SPLT scores for first 32 packets. */
      if((flow->entropy->src2dst_pkt_count+flow->entropy->dst2src_pkt_count) <= max_num_packets_per_flow) {
        if(flow->bidirectional)
          flow->entropy->score = ndpi_classify(flow->entropy->src2dst_pkt_len, flow->entropy->src2dst_pkt_time,
					      flow->entropy->dst2src_pkt_len, flow->entropy->dst2src_pkt_time,
					      flow->entropy->src2dst_start, flow->entropy->dst2src_start,
					      max_num_packets_per_flow, ntohs(flow->src_port), ntohs(flow->dst_port),
					      flow->src2dst_packets, flow->dst2src_packets,
					      flow->entropy->src2dst_opackets, flow->entropy->dst2src_opackets,
					      flow->entropy->src2dst_l4_bytes, flow->entropy->dst2src_l4_bytes, 1,
					      flow->entropy->src2dst_byte_count, flow->entropy->dst2src_byte_count);
	else
	  flow->entropy->score = ndpi_classify(flow->entropy->src2dst_pkt_len, flow->entropy->src2dst_pkt_time,
					      NULL, NULL, flow->entropy->src2dst_start, flow->entropy->src2dst_start,
					      max_num_packets_per_flow, ntohs(flow->src_port), ntohs(flow->dst_port),
					      flow->src2dst_packets, 0,
					      flow->entropy->src2dst_opackets, 0,
					      flow->entropy->src2dst_l4_bytes, 0, 1,
					      flow->entropy->src2dst_byte_count, NULL);
      }
    }

    if(flow->first_seen_ms == 0)
      flow->first_seen_ms = time_ms;

    flow->last_seen_ms = time_ms;

    /* Copy packets entropy if num packets count == 10 */
    ndpi_clear_entropy_stats(flow);
    /* Reset IAT reeference times (see https://github.com/ntop/nDPI/pull/1316) */
    if(((flow->src2dst_packets + flow->dst2src_packets) % max_num_packets_per_flow) == 0) {
      memset(&flow->src2dst_last_pkt_time, '\0', sizeof(flow->src2dst_last_pkt_time));
      memset(&flow->dst2src_last_pkt_time, '\0', sizeof(flow->dst2src_last_pkt_time));
      memset(&flow->flow_last_pkt_time, '\0', sizeof(flow->flow_last_pkt_time));
    }

    if((human_readeable_string_len != 0) && (!flow->has_human_readeable_strings)) {
      u_int8_t skip = 0;

      if((proto == IPPROTO_TCP)
	 && (
	     is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
	     || is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH))
	 ) {
	if((flow->src2dst_packets+flow->dst2src_packets) < 10 /* MIN_NUM_ENCRYPT_SKIP_PACKETS */)
	  skip = 1; /* Skip initial negotiation packets */
      }

      if((!skip) && ((flow->src2dst_packets+flow->dst2src_packets) < 100)) {
	if(ndpi_has_human_readeable_string(workflow->ndpi_struct, (char*)packet, header->caplen,
					   human_readeable_string_len,
					   flow->human_readeable_string_buffer,
					   sizeof(flow->human_readeable_string_buffer)) == 1)
	  flow->has_human_readeable_strings = 1;
      }
    } else {
      if((proto == IPPROTO_TCP)
	 && (
	     is_ndpi_proto(flow, NDPI_PROTOCOL_TLS)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
	     || is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)
	     || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSH))
	 )
	flow->has_human_readeable_strings = 0;
    }
  } else { // flow is NULL
    workflow->stats.total_discarded_bytes += header->len;
    return(nproto);
  }

  if(!flow->detection_completed) {
    struct ndpi_flow_input_info input_info;

    u_int enough_packets =
      (((proto == IPPROTO_UDP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_udp_dissected_pkts))
       || ((proto == IPPROTO_TCP) && ((flow->src2dst_packets + flow->dst2src_packets) > max_num_tcp_dissected_pkts))) ? 1 : 0;

#if 0
    printf("%s()\n", __FUNCTION__);
#endif

    if(proto == IPPROTO_TCP)
      workflow->stats.dpi_packet_count[0]++;
    else if(proto == IPPROTO_UDP)
      workflow->stats.dpi_packet_count[1]++;
    else
      workflow->stats.dpi_packet_count[2]++;
    flow->dpi_packets++;

    memset(&input_info, '\0', sizeof(input_info)); /* To be sure to set to "unknown" any fields */
    /* Set here any information (easily) available; in this trivial example we don't have any */
    input_info.in_pkt_dir = NDPI_IN_PKT_DIR_UNKNOWN;
    input_info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
    malloc_size_stats = 1;
    flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, time_ms, &input_info);

    enough_packets |= ndpi_flow->fail_with_unknown;
    if(enough_packets || (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
      if((!enough_packets)
	 && ndpi_extra_dissection_possible(workflow->ndpi_struct, ndpi_flow))
	; /* Wait for certificate fingerprint */
      else {
	/* New protocol detected or give up */
	flow->detection_completed = 1;

#if 0
	/* Check if we should keep checking extra packets */
	if(ndpi_flow && ndpi_flow->check_extra_packets)
	  flow->check_extra_packets = 1;
#endif

	if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
	  u_int8_t proto_guessed;

	  flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow,
							  enable_protocol_guess, &proto_guessed);
	  if(enable_protocol_guess) workflow->stats.guessed_flow_protocols++;
	}

	process_ndpi_collected_info(workflow, flow);
      }
    }
    malloc_size_stats = 0;
  }
  
#if 0
  if(flow->risk != 0) {
    FILE *r = fopen("/tmp/e", "a");

    if(r) {
      fprintf(r, "->>> %u [%08X]\n", flow->risk, flow->risk);
      fclose(r);
    }
  }
#endif

  *flow_risk = flow->risk;

  return(flow->detected_protocol);
}

/* ****************************************************** */

int ndpi_is_datalink_supported(int datalink_type) {
  /* Keep in sync with the similar switch in ndpi_workflow_process_packet */
  switch(datalink_type) {
  case DLT_NULL:
  case DLT_PPP_SERIAL:
  case DLT_C_HDLC:
  case DLT_PPP:
#ifdef DLT_IPV4
  case DLT_IPV4:
#endif
#ifdef DLT_IPV6
  case DLT_IPV6:
#endif
  case DLT_EN10MB:
  case DLT_LINUX_SLL:
  case DLT_IEEE802_11_RADIO:
  case DLT_RAW:
  case DLT_PPI:
  case LINKTYPE_LINUX_SLL2:
    return 1;
  default:
    return 0;
  }
}

static bool ndpi_is_valid_vxlan(const struct pcap_pkthdr *header, const u_char *packet, u_int16_t ip_offset, u_int16_t ip_len){
  if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr) + sizeof(struct ndpi_vxlanhdr)) {
    return false;
  }
  u_int32_t vxlan_dst_port  = ntohs(4789);
  struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
  u_int offset = ip_offset + ip_len + sizeof(struct ndpi_udphdr);
  /**
   * rfc-7348 
   *    VXLAN Header:  This is an 8-byte field that has:

    - Flags (8 bits): where the I flag MUST be set to 1 for a valid
      VXLAN Network ID (VNI).  The other 7 bits (designated "R") are
      reserved fields and MUST be set to zero on transmission and
      ignored on receipt.

    - VXLAN Segment ID/VXLAN Network Identifier (VNI): this is a
      24-bit value used to designate the individual VXLAN overlay
      network on which the communicating VMs are situated.  VMs in
      different VXLAN overlay networks cannot communicate with each
      other.

    - Reserved fields (24 bits and 8 bits): MUST be set to zero on
      transmission and ignored on receipt.
         VXLAN Header:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |R|R|R|R|I|R|R|R|            Reserved                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                VXLAN Network Identifier (VNI) |   Reserved    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  if((udp->dest == vxlan_dst_port || udp->source == vxlan_dst_port) &&
    (packet[offset] == 0x8) &&
    (packet[offset + 1] == 0x0) &&
    (packet[offset + 2] == 0x0) &&
    (packet[offset + 3] == 0x0) &&
    (packet[offset + 7] ==  0x0)) {
    return true;
    }
  return false;
}

static inline u_int ndpi_skip_vxlan(u_int16_t ip_offset, u_int16_t ip_len){
  return ip_offset + ip_len + sizeof(struct ndpi_udphdr) + sizeof(struct ndpi_vxlanhdr);
}

static uint32_t ndpi_is_valid_gre_tunnel(const struct pcap_pkthdr *header, 
                const u_char *packet, const u_int16_t ip_offset, 
                const u_int16_t ip_len) {
  if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_gre_basehdr))
    return 0; /* Too short for GRE header*/
  uint32_t offset = ip_offset + ip_len;
  struct ndpi_gre_basehdr *grehdr = (struct ndpi_gre_basehdr*)&packet[offset];
  offset += sizeof(struct ndpi_gre_basehdr);
  /*
    rfc-1701
    The GRE flags are encoded in the first two octets.  Bit 0 is the
    most significant bit, bit 15 is the least significant bit.  Bits
    13 through 15 are reserved for the Version field.  Bits 5 through
    12 are reserved for future use and MUST be transmitted as zero.
  */
  if(NDPI_GRE_IS_FLAGS(grehdr->flags))
    return 0;
  if(NDPI_GRE_IS_REC(grehdr->flags))
    return 0;
  /*GRE rfc 2890 that update 1701*/
  if(NDPI_GRE_IS_VERSION_0(grehdr->flags)) {
    if(NDPI_GRE_IS_CSUM(grehdr->flags)) {
      if(header->caplen < offset + 4)
        return 0;
      /*checksum field and offset field*/
      offset += 4;
    }
    if(NDPI_GRE_IS_KEY(grehdr->flags)) {
      if(header->caplen < offset + 4)
        return 0;
      offset += 4;
    }
    if(NDPI_GRE_IS_SEQ(grehdr->flags)) {
      if(header->caplen < offset + 4)
        return 0;
      offset += 4;
    }
  } else if(NDPI_GRE_IS_VERSION_1(grehdr->flags)) { /*rfc-2637 section 4.1 enhanced gre*/
    if(NDPI_GRE_IS_CSUM(grehdr->flags))
      return 0;
    if(NDPI_GRE_IS_ROUTING(grehdr->flags))
      return 0;
    if(!NDPI_GRE_IS_KEY(grehdr->flags))
      return 0;
    if(NDPI_GRE_IS_STRICT(grehdr->flags))
      return 0;
    if(grehdr->protocol != NDPI_GRE_PROTO_PPP) 
      return 0;
    /*key field*/
    if(header->caplen < offset + 4)
      return 0;
    offset += 4;
    if(NDPI_GRE_IS_SEQ(grehdr->flags)) {
      if(header->caplen < offset + 4)
        return 0;
      offset += 4;
    }
    if(NDPI_GRE_IS_ACK(grehdr->flags)) {
      if(header->caplen < offset + 4)
        return 0;
      offset += 4;
    }
  } else { /*support only ver 0, 1*/
    return 0;
  }
  return offset;
}

/* ****************************************************** */

struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow * workflow,
					       const struct pcap_pkthdr *header,
					       const u_char *packet,
					       ndpi_risk *flow_risk) {
  /*
   * Declare pointers to packet headers
   */
  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- LLC header --- */
  const struct ndpi_llc_header_snap *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  union mpls {
    uint32_t u32;
    struct ndpi_mpls_header mpls;
  } mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  struct ndpi_proto nproto = NDPI_PROTOCOL_NULL;
  ndpi_packet_tunnel tunnel_type = ndpi_no_tunnel;

  /* lengths and offsets */
  u_int32_t eth_offset = 0, dlt;
  u_int16_t radio_len, header_length;
  u_int16_t fc;
  u_int16_t type = 0;
  int wifi_len = 0;
  int pyld_eth_len = 0;
  int check;
  u_int64_t time_ms;
  u_int16_t ip_offset = 0, ip_len;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0, recheck_type;
  /*u_int32_t label;*/

  /* counters */
  u_int8_t vlan_packet = 0;

  *flow_risk = 0 /* NDPI_NO_RISK */;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;

  /* setting time */
  time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

  /* safety check */
  if(workflow->last_time > time_ms) {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time_ms = workflow->last_time;
  }
  /* update last time value */
  workflow->last_time = time_ms;

  /*** check Data Link type ***/
  int datalink_type;

#ifdef USE_DPDK
  datalink_type = DLT_EN10MB;
#else
  datalink_type = (int)pcap_datalink(workflow->pcap_handle);
#endif

 datalink_check:
  // 20 for min iph and 8 for min UDP
  if(header->caplen < eth_offset + 28)
    return(nproto); /* Too short */

  /* Keep in sync with ndpi_is_datalink_supported() */
  switch(datalink_type) {
  case DLT_NULL:
    if(ntohl(*((u_int32_t*)&packet[eth_offset])) == 2)
      type = ETH_P_IP;
    else
      type = ETH_P_IPV6;

    ip_offset = 4 + eth_offset;
    break;

    /* Cisco PPP in HDLC-like framing - 50 */
  case DLT_PPP_SERIAL:
    chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
    ip_offset = eth_offset + sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* Cisco PPP - 9 or 104 */
  case DLT_C_HDLC:
  case DLT_PPP:
    if(packet[0] == 0x0f || packet[0] == 0x8f) {
      chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
      ip_offset = eth_offset + sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
      type = ntohs(chdlc->proto_code);
    } else {
      ip_offset = eth_offset + 2;
      type = ntohs(*((u_int16_t*)&packet[eth_offset]));
    }
    break;

#ifdef DLT_IPV4
  case DLT_IPV4:
    type = ETH_P_IP;
    ip_offset = eth_offset;
    break;
#endif

#ifdef DLT_IPV6
  case DLT_IPV6:
    type = ETH_P_IPV6;
    ip_offset = eth_offset;
    break;
#endif

    /* IEEE 802.3 Ethernet - 1 */
  case DLT_EN10MB:
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    check = ntohs(ethernet->h_proto);

    if(check <= 1500)
      pyld_eth_len = check;
    else if(check >= 1536)
      type = check;

    if(pyld_eth_len != 0) {
      llc = (struct ndpi_llc_header_snap *)(&packet[ip_offset]);
      /* check for LLC layer with SNAP extension */
      if(llc->dsap == SNAP || llc->ssap == SNAP) {
	type = llc->snap.proto_ID;
	ip_offset += + 8;
      }
      /* No SNAP extension - Spanning Tree pkt must be discarted */
      else if(llc->dsap == BSTP || llc->ssap == BSTP) {
	goto v4_warning;
      }
    }
    break;

    /* Linux Cooked Capture - 113 */
  case DLT_LINUX_SLL:
    type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
    ip_offset = 16 + eth_offset;
    break;

    /* Linux Cooked Capture v2 - 276 */
  case LINKTYPE_LINUX_SLL2:
    type = (packet[eth_offset+10] << 8) + packet[eth_offset+11];
    ip_offset = 20 + eth_offset;
    break;

    /* Radiotap link-layer - 127 */
  case DLT_IEEE802_11_RADIO:
    radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
    radio_len = radiotap->len;

    /* Check Bad FCS presence */
    if((radiotap->flags & BAD_FCS) == BAD_FCS) {
      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }

    if(header->caplen < (eth_offset + radio_len + sizeof(struct ndpi_wifi_header)))
      return(nproto);

    /* Calculate 802.11 header length (variable) */
    wifi = (struct ndpi_wifi_header*)( packet + eth_offset + radio_len);
    fc = wifi->fc;

    /* check wifi data presence */
    if(FCF_TYPE(fc) == WIFI_DATA) {
      if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	 (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	wifi_len = 26; /* + 4 byte fcs */
    } else   /* no data frames */
      return(nproto);

    /* Check ether_type from LLC */
    if(header->caplen < (eth_offset + wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap)))
      return(nproto);
    llc = (struct ndpi_llc_header_snap*)(packet + eth_offset + wifi_len + radio_len);
    if(llc->dsap == SNAP)
      type = ntohs(llc->snap.proto_ID);

    /* Set IP header offset */
    ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header_snap) + eth_offset;
    break;

  case DLT_RAW:
    ip_offset = eth_offset;
    break;

  case DLT_PPI:
    header_length = le16toh(*(u_int16_t *)&packet[eth_offset + 2]);
    dlt = le32toh(*(u_int32_t *)&packet[eth_offset + 4]);
    if(dlt != DLT_EN10MB) /* Handle only standard ethernet, for the time being */
      return(nproto);
    datalink_type = DLT_EN10MB;
    eth_offset += header_length;
    goto datalink_check;

  default:
    /*
     * We shoudn't be here, because we already checked that this datalink is supported.
     * Should ndpi_is_datalink_supported() be updated?
     */
    printf("Unknown datalink %d\n", datalink_type);
    return(nproto);
  }

 ether_type_check:
  recheck_type = 0;

  /* check ether type */
  switch(type) {
  case ETH_P_VLAN:
    if(ip_offset+4 >= (int)header->caplen)
      return(nproto);
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;
    vlan_packet = 1;

    // double tagging for 802.1Q
    while((type == 0x8100) && (((bpf_u_int32)ip_offset+4) < header->caplen)) {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case ETH_P_MPLS_UNI:
  case ETH_P_MPLS_MULTI:
    if(ip_offset+4 >= (int)header->caplen)
      return(nproto);
    mpls.u32 = *((uint32_t *) &packet[ip_offset]);
    mpls.u32 = ntohl(mpls.u32);
    workflow->stats.mpls_count++;
    type = ETH_P_IP, ip_offset += 4;

    while(!mpls.mpls.s && (((bpf_u_int32)ip_offset) + 4 < header->caplen)) {
      mpls.u32 = *((uint32_t *) &packet[ip_offset]);
      mpls.u32 = ntohl(mpls.u32);
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case ETH_P_PPPoE:
    workflow->stats.pppoe_count++;
    type = ETH_P_IP;
    ip_offset += 8;
    recheck_type = 1;
    break;

  default:
    break;
  }

  if(recheck_type)
    goto ether_type_check;

  workflow->stats.vlan_count += vlan_packet;

 iph_check:
  /* Check and set IP header size and total packet length */
  if(header->caplen < ip_offset + sizeof(struct ndpi_iphdr))
    return(nproto); /* Too short for next IP header*/

  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  LOG(NDPI_LOG_DEBUG,
		   "\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == IPVERSION) {
    ip_len = ((u_int16_t)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == IPPROTO_IPV6
       || iph->protocol == NDPI_IPIP_PROTOCOL_TYPE
       ) {
      ip_offset += ip_len;
      if(ip_len > 0)
        goto iph_check;
    }

    if((frag_off & 0x1FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;
      workflow->stats.fragmented_count++;

      if(ipv4_frags_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  LOG(NDPI_LOG_DEBUG, "\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      workflow->stats.total_discarded_bytes +=  header->len;
      return(nproto);
    }
  } else if(iph->version == 6) {
    if(header->caplen < ip_offset + sizeof(struct ndpi_ipv6hdr))
      return(nproto); /* Too short for IPv6 header*/

    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);

    if(header->caplen < (ip_offset + sizeof(struct ndpi_ipv6hdr) + ntohs(iph6->ip6_hdr.ip6_un1_plen)))
      return(nproto); /* Too short for IPv6 payload*/

    const u_int8_t *l4ptr = (((const u_int8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
    u_int16_t ipsize = header->caplen - ip_offset;

    if(ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &proto) != 0) {
      return(nproto);
    }

    if(proto == IPPROTO_IPV6
       || proto == NDPI_IPIP_PROTOCOL_TYPE
       ) {
      if(l4ptr > packet) { /* Better safe than sorry */
        ip_offset = (l4ptr - packet);
        goto iph_check;
      }
    }

    iph = NULL;
  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if(!workflow->prefs.quiet_mode)
        LOG(NDPI_LOG_DEBUG,
		 "\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }

    workflow->stats.total_discarded_bytes +=  header->len;
    return(nproto);
  }

  if(workflow->prefs.decode_tunnels && (proto == IPPROTO_UDP)) {
    if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr))
      return(nproto); /* Too short for UDP header*/
    else {
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
      u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if(((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) &&
         (ip_offset + ip_len + sizeof(struct ndpi_udphdr) + 8 /* Minimum GTPv1 header len */ < header->caplen)) {
	/* Check if it's GTPv1 */
	u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t flags = packet[offset];
	u_int8_t message_type = packet[offset+1];
	u_int8_t exts_parsing_error = 0;

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	   (message_type == 0xFF /* T-PDU */)) {

	  offset += 8; /* GTPv1 header len */
	  if(flags & 0x07)
	    offset += 4; /* sequence_number + pdu_number + next_ext_header fields */
	  /* Extensions parsing */
	  if(flags & 0x04) {
	    unsigned int ext_length = 0;

	    while(offset < header->caplen) {
	      ext_length = packet[offset] << 2;
	      offset += ext_length;
	      if(offset >= header->caplen || ext_length == 0) {
	        exts_parsing_error = 1;
	        break;
	      }
	      if(packet[offset - 1] == 0)
	        break;
	    }
	  }

	  if(offset < header->caplen && !exts_parsing_error) {
	    /* Ok, valid GTP-U */
	    tunnel_type = ndpi_gtp_tunnel;
	    ip_offset = offset;
	    iph = (struct ndpi_iphdr *)&packet[ip_offset];
	    if(iph->version == 6) {
	      iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
	      iph = NULL;
              if(header->caplen < ip_offset + sizeof(struct ndpi_ipv6hdr))
	        return(nproto);
	    } else if(iph->version != IPVERSION) {
	      // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)workflow->stats.raw_packet_count);
	      goto v4_warning;
	    } else {
              if(header->caplen < ip_offset + sizeof(struct ndpi_iphdr))
	        return(nproto);
	    }
	  }
	}
      } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
	/* https://en.wikipedia.org/wiki/TZSP */
	if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr) + 4)
	  return(nproto); /* Too short for TZSP*/

	u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t version       = packet[offset];
	u_int8_t ts_type       = packet[offset+1];
	u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

	tunnel_type = ndpi_tzsp_tunnel;

	if((version == 1) && (ts_type == 0) && (encapsulates == 1)) {
	  u_int8_t stop = 0;

	  offset += 4;

	  while((!stop) && (offset < header->caplen)) {
	    u_int8_t tag_type = packet[offset];
	    u_int8_t tag_len;

	    switch(tag_type) {
	    case 0: /* PADDING Tag */
	      tag_len = 1;
	      break;
	    case 1: /* END Tag */
	      tag_len = 1, stop = 1;
	      break;
	    default:
	      if(offset + 1 >= header->caplen)
	        return(nproto); /* Invalid packet */
	      tag_len = packet[offset+1];
	      break;
	    }

	    offset += tag_len;

	    if(offset >= header->caplen)
	      return(nproto); /* Invalid packet */
	    else {
	      eth_offset = offset;
	      goto datalink_check;
	    }
	  }
	}
      } else if((sport == NDPI_CAPWAP_DATA_PORT) || (dport == NDPI_CAPWAP_DATA_PORT)) {
	/* We dissect ONLY CAPWAP traffic */
	u_int offset           = ip_offset+ip_len+sizeof(struct ndpi_udphdr);

	if((offset+1) < header->caplen) {
	  uint8_t preamble = packet[offset];

	  if((preamble & 0x0F) == 0) { /* CAPWAP header */
	    u_int16_t msg_len = (packet[offset+1] & 0xF8) >> 1;

	    offset += msg_len;

	    if((offset + 32 < header->caplen) &&
	       (packet[offset + 1] == 0x08)) {
	      /* IEEE 802.11 Data */
	      offset += 24;
	      /* LLC header is 8 bytes */
	      type = ntohs((u_int16_t)*((u_int16_t*)&packet[offset+6]));

	      ip_offset = offset + 8;

	      tunnel_type = ndpi_capwap_tunnel;
	      goto iph_check;
	    }
	  }
	}
      }else if(ndpi_is_valid_vxlan(header, packet, ip_offset, ip_len)){
	      tunnel_type = ndpi_vxlan_tunnel;
        eth_offset = ndpi_skip_vxlan(ip_offset, ip_len);
	      goto datalink_check;
      }
    }
  } else if(workflow->prefs.decode_tunnels && (proto == IPPROTO_GRE)) {
    if(header->caplen < ip_offset + ip_len + sizeof(struct ndpi_gre_basehdr))
      return(nproto); /* Too short for GRE header*/
    u_int32_t offset = 0;
    if((offset = ndpi_is_valid_gre_tunnel(header, packet, ip_offset, ip_len))) {
      tunnel_type = ndpi_gre_tunnel;
      struct ndpi_gre_basehdr *grehdr = (struct ndpi_gre_basehdr*)&packet[ip_offset + ip_len];
      if(grehdr->protocol == ntohs(ETH_P_IP) || grehdr->protocol == ntohs(ETH_P_IPV6)) { 
        ip_offset = offset;
        goto iph_check; 
      } else if(grehdr->protocol ==  NDPI_GRE_PROTO_PPP) {  // ppp protocol
        ip_offset = offset + NDPI_PPP_HDRLEN; 
        goto iph_check;
      } else {
        eth_offset = offset;
        goto datalink_check;
      }
    } else {
      return(nproto);
    }
  }

  /* process the packet */
  return(packet_processing(workflow, time_ms, vlan_id, tunnel_type, iph, iph6,
			   ip_offset, header->caplen - ip_offset,
			   header->caplen, header, packet, header->ts,
			   flow_risk));
}

/* *********************************************** */

#ifdef USE_DPDK

#include <rte_version.h>
#include <rte_ether.h>

static const struct rte_eth_conf port_conf_default = {
#if(RTE_VERSION < RTE_VERSION_NUM(19, 8, 0, 0))
						      .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
#else
						      .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
#endif
};

/* ************************************ */

int dpdk_port_init(int port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = port_conf_default;
  const u_int16_t rx_rings = 1, tx_rings = 1;
  int retval;
  u_int16_t q;

  /* 1 RX queue */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);

  if(retval != 0)
    return retval;

  for(q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if(retval < 0)
      return retval;
  }

  for(q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
    if(retval < 0)
      return retval;
  }

  retval = rte_eth_dev_start(port);

  if(retval < 0)
    return retval;

  rte_eth_promiscuous_enable(port);

  return 0;
}

int dpdk_port_deinit(int port) {
  rte_eth_dev_stop(port);
  rte_eth_dev_close(port);
  return 0;
}

#endif
