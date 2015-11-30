/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2014 - Matteo Bogo <matteo.bogo@gmail.com> (JSON support)
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

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>

#include "../config.h"
#include "ndpi_api.h"

#ifdef HAVE_JSON_C
#include <json.h>
#endif

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024
#define NUM_ROOTS                 512
#define GTP_U_V1_PORT            2152
#define TZSP_PORT               37008
#define MAX_NDPI_FLOWS      200000000

#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif

#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif

#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */

#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

/**
 * @brief Set main components necessary to the detection
 * @details TODO
 */
static void setupDetection(u_int16_t thread_id);

/**
 * Client parameters
 */
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interafaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file = NULL;
static char *results_path = NULL;
static char *_bpf_filter      = NULL; /**< bpf filter  */
static char *_protoFilePath   = NULL; /**< Protocol file path  */
#ifdef HAVE_JSON_C
static char *_jsonFilePath    = NULL; /**< JSON file path  */
#endif
#ifdef HAVE_JSON_C
static json_object *jArray_known_flows, *jArray_unknown_flows;
#endif
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
/**
 * User preferences
 */
static u_int8_t enable_protocol_guess = 1, verbose = 0, nDPI_traceLevel = 0, json_flag = 0;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif

static struct timeval pcap_start, pcap_end;

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_for = 0;
static time_t capture_until = 0;

static u_int32_t num_flows;

struct thread_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
};

struct reader_thread {
  struct ndpi_detection_module_struct *ndpi_struct;
  void *ndpi_flows_root[NUM_ROOTS];
  char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *_pcap_handle;
  u_int64_t last_time;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  pthread_t pthread;
  int _pcap_datalink_type;

  /* TODO Add barrier */
  struct thread_stats stats;

  struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
  u_int8_t ip[4];				// Ip address
  struct ndpi_id_struct *ndpi_id;		// nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;		// ID tracking structure size

// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[48], upper_name[48];
  u_int8_t ip_version;
  u_int64_t last_seen;
  u_int64_t bytes;
  u_int32_t packets;

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char host_server_name[256];

  struct {
    char client_certificate[48], server_certificate[48];
  } ssl;

  void *src_id, *dst_id;
} ndpi_flow_t;


static u_int32_t size_flow_struct = 0;

static void help(u_int long_help) {
  printf("ndpiReader -i <file|device> [-f <filter>][-s <duration>]\n"
	 "          [-p <protos>][-l <loops> [-q][-d][-h][-t][-v <level>]\n"
	 "          [-n <threads>] [-w <file>] [-j <file>]\n\n"
	 "Usage:\n"
	 "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a device for live capture (comma-separated list)\n"
	 "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
	 "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
	 "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
	 "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -n <num threads>          | Number of threads. Default: number of interfaces in -i. Ignored with pcap files.\n"
	 "  -j <file.json>            | Specify a file to write the content of packets in .json format\n"
#ifdef linux
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
	 "  -d                        | Disable protocol guess and use only DPI\n"
	 "  -q                        | Quiet mode\n"
	 "  -t                        | Dissect GTP/TZSP tunnels\n"
	 "  -r                        | Print nDPI version and git revision\n"
	 "  -w <path>                 | Write test output on the specified file. This is useful for\n"
	 "                            | testing purposes in order to compare results across runs\n"
	 "  -h                        | This help\n"
	 "  -v <1|2>                  | Verbose 'unknown protocol' packet print. 1=verbose, 2=very verbose\n");

  if(long_help) {
    printf("\n\nSupported protocols:\n");
    num_threads = 1;
    setupDetection(0);
    ndpi_dump_protocols(ndpi_thread_info[0].ndpi_struct);
  }

  exit(!long_help);
}

/* ***************************************************** */

static void parseOptions(int argc, char **argv) {
  char *__pcap_file = NULL, *bind_mask = NULL;
  int thread_id, opt;
#ifdef linux
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif

  while ((opt = getopt(argc, argv, "df:g:i:hp:l:s:tv:V:n:j:rp:w:q")) != EOF) {
    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'i':
      _pcap_file[0] = optarg;
      break;

    case 'f':
      _bpf_filter = optarg;
      break;

    case 'g':
      bind_mask = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'r':
      printf("ndpiReader - nDPI (%s)\n", ndpi_revision());
      exit(0);

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      printf("%d\n",atoi(optarg) );
      nDPI_traceLevel  = atoi(optarg);
      break;

    case 'h':
      help(1);
      break;

    case 'j':
#ifndef HAVE_JSON_C
      printf("WARNING: this copy of ndpiReader has been compiled without JSON-C: json export disabled\n");
#else
      _jsonFilePath = optarg;
      json_flag = 1;
#endif
      break;

    case 'w':
      results_path = strdup(optarg);
      if((results_file = fopen(results_path, "w")) == NULL) {
	printf("Unable to write in file %s: quitting\n", results_path);
	return;
      }
      break;

    case 'q':
      quiet_mode = 1;
      break;

    default:
      help(0);
      break;
    }
  }

  // check parameters
  if(_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0) {
    help(0);
  }

  if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
    num_threads = 0; /* setting number of threads = number of interfaces */
    __pcap_file = strtok(_pcap_file[0], ",");
    while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
      _pcap_file[num_threads++] = __pcap_file;
      __pcap_file = strtok(NULL, ",");
    }
  } else {
    if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
    for(thread_id = 1; thread_id < num_threads; thread_id++)
      _pcap_file[thread_id] = _pcap_file[0];
  }

#ifdef linux
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1;

  if(num_cores > 1 && bind_mask != NULL) {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;
    while (core_id != NULL && thread_id < num_threads) {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
#endif
}

/* ***************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_traceLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}

/* ***************************************************** */

static void *malloc_wrapper(unsigned long size) {
  current_ndpi_memory += size;

  if(current_ndpi_memory > max_ndpi_memory)
    max_ndpi_memory = current_ndpi_memory;

  return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
  free(freeable);
}

/* ***************************************************** */

static char* ipProto2Name(u_short proto_id) {
  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case IPPROTO_ICMPV6:
    return("ICMPV6");
    break;
  case 112:
    return("VRRP");
    break;
  case IPPROTO_IGMP:
    return("IGMP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

/* ***************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ***************************************************** */

static void printFlow(u_int16_t thread_id, struct ndpi_flow *flow) {
#ifdef HAVE_JSON_C
  json_object *jObj;
#endif
  FILE *out = results_file ? results_file : stdout;

  if(!json_flag) {
    fprintf(out, "\t%u", ++num_flows);

    fprintf(out, "\t%s %s%s%s:%u <-> %s%s%s:%u ",
	    ipProto2Name(flow->protocol),
	    (flow->ip_version == 6) ? "[" : "",
	    flow->lower_name, 
	    (flow->ip_version == 6) ? "]" : "",
	    ntohs(flow->lower_port),
	    (flow->ip_version == 6) ? "[" : "",
	    flow->upper_name, 
	    (flow->ip_version == 6) ? "]" : "",
	    ntohs(flow->upper_port));

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

    if(flow->detected_protocol.master_protocol) {
      char buf[64];

      fprintf(out, "[proto: %u.%u/%s]",
	      flow->detected_protocol.master_protocol, flow->detected_protocol.protocol,
	      ndpi_protocol2name(ndpi_thread_info[thread_id].ndpi_struct,
				 flow->detected_protocol, buf, sizeof(buf)));
    } else
      fprintf(out, "[proto: %u/%s]",
	      flow->detected_protocol.protocol,
	      ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.protocol));

    fprintf(out, "[%u pkts/%llu bytes]",
	    flow->packets, (long long unsigned int)flow->bytes);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
    if(flow->ssl.client_certificate[0] != '\0') fprintf(out, "[SSL client: %s]", flow->ssl.client_certificate);
    if(flow->ssl.server_certificate[0] != '\0') fprintf(out, "[SSL server: %s]", flow->ssl.server_certificate);

    fprintf(out, "\n");
  } else {
#ifdef HAVE_JSON_C
    jObj = json_object_new_object();

    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"host_a.name",json_object_new_string(flow->lower_name));
    json_object_object_add(jObj,"host_a.port",json_object_new_int(ntohs(flow->lower_port)));
    json_object_object_add(jObj,"host_b.name",json_object_new_string(flow->upper_name));
    json_object_object_add(jObj,"host_n.port",json_object_new_int(ntohs(flow->upper_port)));

    if(flow->detected_protocol.master_protocol)
      json_object_object_add(jObj,"detected.masterprotocol",json_object_new_int(flow->detected_protocol.master_protocol));

    json_object_object_add(jObj,"detected.protocol",json_object_new_int(flow->detected_protocol.protocol));

    if(flow->detected_protocol.master_protocol) {
      char tmp[256];

      snprintf(tmp, sizeof(tmp), "%s.%s",
	       ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.master_protocol),
	       ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.protocol));

      json_object_object_add(jObj,"detected.protocol.name",
			     json_object_new_string(tmp));
    } else
      json_object_object_add(jObj,"detected.protocol.name",
			     json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,
									flow->detected_protocol.protocol)));

    json_object_object_add(jObj,"packets",json_object_new_int(flow->packets));
    json_object_object_add(jObj,"bytes",json_object_new_int(flow->bytes));

    if(flow->host_server_name[0] != '\0')
      json_object_object_add(jObj,"host.server.name",json_object_new_string(flow->host_server_name));

    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
      json_object *sjObj = json_object_new_object();

      if(flow->ssl.client_certificate[0] != '\0')
	json_object_object_add(sjObj, "client", json_object_new_string(flow->ssl.client_certificate));

      if(flow->ssl.server_certificate[0] != '\0')
	json_object_object_add(sjObj, "server", json_object_new_string(flow->ssl.server_certificate));

      json_object_object_add(jObj, "ssl", sjObj);
    }

    //flow->protos.ssl.client_certificate, flow->protos.ssl.server_certificate);
    if(json_flag == 1)
      json_object_array_add(jArray_known_flows,jObj);
    else if(json_flag == 2)
      json_object_array_add(jArray_unknown_flows,jObj);
#endif
  }
}

/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }

}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
  struct ndpi_flow *flow = (struct ndpi_flow*)node;

  free_ndpi_flow(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(thread_id, flow);
}

/* ***************************************************** */

static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(thread_id, flow);
}

/* ***************************************************** */

static u_int16_t node_guess_undetected_protocol(u_int16_t thread_id, struct ndpi_flow *flow) {
  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));
  // printf("Guess state: %u\n", flow->detected_protocol);
  if(flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN)
    ndpi_thread_info[thread_id].stats.guessed_flow_protocols++;

  return(flow->detected_protocol.protocol);
}

/* ***************************************************** */

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(enable_protocol_guess) {
      if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
	node_guess_undetected_protocol(thread_id, flow);
	// printFlow(thread_id, flow);
      }
    }

    ndpi_thread_info[thread_id].stats.protocol_counter[flow->detected_protocol.protocol]       += flow->packets;
    ndpi_thread_info[thread_id].stats.protocol_counter_bytes[flow->detected_protocol.protocol] += flow->bytes;
    ndpi_thread_info[thread_id].stats.protocol_flows[flow->detected_protocol.protocol]++;
  }
}

/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);

      if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      free_ndpi_flow(flow);
      ndpi_thread_info[thread_id].stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(u_int16_t thread_id,
				       const u_int8_t version,
				       u_int16_t vlan_id,
				       const struct ndpi_iphdr *iph,
				       const struct ndpi_ipv6hdr *iph6,
				       u_int16_t ip_offset,
				       u_int16_t ipsize,
				       u_int16_t l4_packet_len,
				       struct ndpi_tcphdr **tcph,
				       struct ndpi_udphdr **udph,
				       u_int16_t *sport, u_int16_t *dport,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto,
				       u_int8_t **payload,
				       u_int16_t *payload_len,
				       u_int8_t *src_to_dst_direction) {
  u_int32_t idx, l4_offset;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;
  u_int8_t *l3, *l4;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ipv6hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(l4_packet_len < 64)
    ndpi_thread_info[thread_id].stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    ndpi_thread_info[thread_id].stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    ndpi_thread_info[thread_id].stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    ndpi_thread_info[thread_id].stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    ndpi_thread_info[thread_id].stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    ndpi_thread_info[thread_id].stats.packet_len[5]++;

  if(l4_packet_len > ndpi_thread_info[thread_id].stats.max_packet_len)
    ndpi_thread_info[thread_id].stats.max_packet_len = l4_packet_len;

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4 = ((u_int8_t *) l3 + l4_offset);

  if(iph->protocol == 6 && l4_packet_len >= 20) {
    u_int tcp_len;

    ndpi_thread_info[thread_id].stats.tcp_count++;

    // tcp
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
    
    if(iph->saddr < iph->daddr) {
      lower_port = (*tcph)->source, upper_port = (*tcph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*tcph)->dest;
      upper_port = (*tcph)->source;

      *src_to_dst_direction = 0;
      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }
    
    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = &l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    ndpi_thread_info[thread_id].stats.udp_count++;

    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);    
    *payload = &l4[sizeof(struct ndpi_udphdr)];
    *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));

    if(iph->saddr < iph->daddr) {
      lower_port = (*udph)->source, upper_port = (*udph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*udph)->dest, upper_port = (*udph)->source;

      *src_to_dst_direction = 0;

      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;
	  
	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    *sport = ntohs(lower_port), *dport = ntohs(upper_port);
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  if(0)
    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);

  if(ret == NULL) {
    if(ndpi_thread_info[thread_id].stats.ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->ip_version = version;

      if(version == 4) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

      if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
	printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, size_flow_struct);

      if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
	printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->src_id, 0, size_id_struct);

      if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
	printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->dst_id, 0, size_id_struct);

      ndpi_tsearch(newflow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp); /* Add */
      ndpi_thread_info[thread_id].stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      // printFlow(thread_id, newflow);
      return newflow;
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow6(u_int16_t thread_id,
					u_int16_t vlan_id,
					const struct ndpi_ipv6hdr *iph6,
					u_int16_t ip_offset,
					struct ndpi_tcphdr **tcph,
					struct ndpi_udphdr **udph,
					u_int16_t *sport, u_int16_t *dport,
					struct ndpi_id_struct **src,
					struct ndpi_id_struct **dst,
					u_int8_t *proto,
					u_int8_t **payload,
					u_int16_t *payload_len,
					u_int8_t *src_to_dst_direction) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

  if(iph.protocol == 0x3C /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow(thread_id, 6, vlan_id, &iph, iph6, ip_offset,
		       sizeof(struct ndpi_ipv6hdr),
		       ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
		       tcph, udph, sport, dport,
		       src, dst, proto, payload, payload_len, src_to_dst_direction));
}

/* ***************************************************** */

static void setupDetection(u_int16_t thread_id) {
  NDPI_PROTOCOL_BITMASK all;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));

  // init global detection structure
  ndpi_thread_info[thread_id].ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
								       malloc_wrapper, free_wrapper, debug_printf);
  if(ndpi_thread_info[thread_id].ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }

  /* ndpi_thread_info[thread_id].ndpi_struct->http_dont_dissect_response = 1; */

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].ndpi_struct, &all);

  // allocate memory for id and flow tracking
  size_id_struct = sizeof(struct ndpi_id_struct);
  size_flow_struct = sizeof(struct ndpi_flow_struct);

  // clear memory for results
  memset(ndpi_thread_info[thread_id].stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].ndpi_struct, _protoFilePath);
}

/* ***************************************************** */

static void terminateDetection(u_int16_t thread_id) {
  int i;

  for(i=0; i<NUM_ROOTS; i++) {
    ndpi_tdestroy(ndpi_thread_info[thread_id].ndpi_flows_root[i], ndpi_flow_freer);
    ndpi_thread_info[thread_id].ndpi_flows_root[i] = NULL;
  }

  ndpi_exit_detection_module(ndpi_thread_info[thread_id].ndpi_struct, free_wrapper);
}

/* ***************************************************** */

// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(u_int16_t thread_id,
				      const u_int64_t time,
				      u_int16_t vlan_id,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ipv6hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction= 1;
  
  if(iph)
    flow = get_ndpi_flow(thread_id, 4, vlan_id, iph, NULL,
			 ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &tcph, &udph, &sport, &dport,			
			 &src, &dst, &proto,
			 &payload, &payload_len, &src_to_dst_direction);
  else
    flow = get_ndpi_flow6(thread_id, vlan_id, iph6, ip_offset,
			  &tcph, &udph, &sport, &dport,			
			  &src, &dst, &proto,
			  &payload, &payload_len, &src_to_dst_direction);

  if(flow != NULL) {
    ndpi_thread_info[thread_id].stats.ip_packet_count++;
    ndpi_thread_info[thread_id].stats.total_wire_bytes += rawsize + 24 /* CRC etc */, ndpi_thread_info[thread_id].stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
  } else {
    return(0);
  }

  if(flow->detection_completed) return(0);

  flow->detected_protocol = ndpi_detection_process_packet(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow,
							  iph ? (uint8_t *)iph : (uint8_t *)iph6,
							  ipsize, time, src, dst);
  
  if((flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

    if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0))
      ndpi_set_detected_protocol(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

    if((proto == IPPROTO_TCP) && (flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS)) {
      snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
    }

    free_ndpi_flow(flow);

    if(verbose > 1) {
      if(enable_protocol_guess) {
	if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
	  flow->detected_protocol.protocol = node_guess_undetected_protocol(thread_id, flow),
	    flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
	}
      }

      printFlow(thread_id, flow);
    }
  }

  if(live_capture) {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].last_time) {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while (ndpi_thread_info[thread_id].num_idle_flows > 0)
	ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
		     &ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_cmp);

      if(++ndpi_thread_info[thread_id].idle_scan_idx == NUM_ROOTS) ndpi_thread_info[thread_id].idle_scan_idx = 0;
      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].last_time;
    }
  }

  return 0;
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ***************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* ***************************************************** */

#ifdef HAVE_JSON_C
static void json_init() {
  jArray_known_flows = json_object_new_array();
  jArray_unknown_flows = json_object_new_array();
}
#endif

/* ***************************************************** */

char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
  char unit = 'B';

  if(howMuch < 1024) {
    snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  } else if(howMuch < 1048576) {
    snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
  } else {
    float tmpGB = ((float)howMuch)/1048576;

    if(tmpGB < 1024) {
      snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    } else {
      tmpGB /= 1024;

      snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
    }
  }

  return(buf);
}

/* ***************************************************** */

static void printResults(u_int64_t tot_usec) {
  u_int32_t i;
  u_int64_t total_flow_bytes = 0;
  u_int avg_pkt_size = 0;
  struct thread_stats cumulative_stats;
  int thread_id;
  char buf[32];
#ifdef HAVE_JSON_C
  FILE *json_fp = NULL;
  json_object *jObj_main, *jObj_trafficStats, *jArray_detProto, *jObj;
#endif
  long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].stats.total_wire_bytes == 0) continue;

    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_proto_guess_walker, &thread_id);

    /* Stats aggregation */
    cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].stats.raw_packet_count;
    cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].stats.total_wire_bytes;
    cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].stats.total_discarded_bytes;

    for(i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
      cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].stats.protocol_counter[i];
      cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].stats.protocol_counter_bytes[i];
      cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].stats.protocol_flows[i];
    }

    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].stats.ndpi_flow_count;
    cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].stats.tcp_count;
    cumulative_stats.udp_count   += ndpi_thread_info[thread_id].stats.udp_count;
    cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].stats.pppoe_count;
    cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].stats.fragmented_count;
    for(i = 0; i < 6; i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].stats.packet_len[i];
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].stats.max_packet_len;
  }

  if(!quiet_mode) {
    printf("\nnDPI Memory statistics:\n");
    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(sizeof(struct ndpi_detection_module_struct), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(size_flow_struct, buf, sizeof(buf)));
    printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));

    if(!json_flag) {
      printf("\nTraffic statistics:\n");
      printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
	     (long long unsigned int)cumulative_stats.total_wire_bytes);
      printf("\tDiscarded bytes:       %-13llu\n",
	     (long long unsigned int)cumulative_stats.total_discarded_bytes);
      printf("\tIP packets:            %-13llu of %llu packets total\n",
	     (long long unsigned int)cumulative_stats.ip_packet_count,
	     (long long unsigned int)cumulative_stats.raw_packet_count);
      /* In order to prevent Floating point exception in case of no traffic*/
      if(cumulative_stats.total_ip_bytes && cumulative_stats.raw_packet_count)
	avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
      printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
	     (long long unsigned int)cumulative_stats.total_ip_bytes,avg_pkt_size);
      printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);

      printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
      printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
      printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
      printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
      printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
      printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
      printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
      printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
      printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
      printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
      printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
      printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
      printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

      if(tot_usec > 0) {
	char buf[32], buf1[32];
	float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)tot_usec;
	float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)tot_usec;
	float traffic_duration;
	if (live_capture) traffic_duration = tot_usec;
	else traffic_duration = (pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - (pcap_start.tv_sec*1000000 + pcap_start.tv_usec);
	printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
	t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
	b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
	printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
	printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
      }

      if(enable_protocol_guess)
	printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);
    }
  }

  if(json_flag) {
#ifdef HAVE_JSON_C
    if((json_fp = fopen(_jsonFilePath,"w")) == NULL) {
      printf("Error createing .json file %s\n", _jsonFilePath);
      json_flag = 0;
    } else {
      jObj_main = json_object_new_object();
      jObj_trafficStats = json_object_new_object();
      jArray_detProto = json_object_new_array();

      json_object_object_add(jObj_trafficStats,"ethernet.bytes",json_object_new_int64(cumulative_stats.total_wire_bytes));
      json_object_object_add(jObj_trafficStats,"discarded.bytes",json_object_new_int64(cumulative_stats.total_discarded_bytes));
      json_object_object_add(jObj_trafficStats,"ip.packets",json_object_new_int64(cumulative_stats.ip_packet_count));
      json_object_object_add(jObj_trafficStats,"total.packets",json_object_new_int64(cumulative_stats.raw_packet_count));
      json_object_object_add(jObj_trafficStats,"ip.bytes",json_object_new_int64(cumulative_stats.total_ip_bytes));
      json_object_object_add(jObj_trafficStats,"avg.pkt.size",json_object_new_int(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count));
      json_object_object_add(jObj_trafficStats,"unique.flows",json_object_new_int(cumulative_stats.ndpi_flow_count));
      json_object_object_add(jObj_trafficStats,"tcp.pkts",json_object_new_int64(cumulative_stats.tcp_count));
      json_object_object_add(jObj_trafficStats,"udp.pkts",json_object_new_int64(cumulative_stats.udp_count));
      json_object_object_add(jObj_trafficStats,"vlan.pkts",json_object_new_int64(cumulative_stats.vlan_count));
      json_object_object_add(jObj_trafficStats,"mpls.pkts",json_object_new_int64(cumulative_stats.mpls_count));
      json_object_object_add(jObj_trafficStats,"pppoe.pkts",json_object_new_int64(cumulative_stats.pppoe_count));
      json_object_object_add(jObj_trafficStats,"fragmented.pkts",json_object_new_int64(cumulative_stats.fragmented_count));
      json_object_object_add(jObj_trafficStats,"max.pkt.size",json_object_new_int(cumulative_stats.max_packet_len));
      json_object_object_add(jObj_trafficStats,"pkt.len_min64",json_object_new_int64(cumulative_stats.packet_len[0]));
      json_object_object_add(jObj_trafficStats,"pkt.len_64_128",json_object_new_int64(cumulative_stats.packet_len[1]));
      json_object_object_add(jObj_trafficStats,"pkt.len_128_256",json_object_new_int64(cumulative_stats.packet_len[2]));
      json_object_object_add(jObj_trafficStats,"pkt.len_256_1024",json_object_new_int64(cumulative_stats.packet_len[3]));
      json_object_object_add(jObj_trafficStats,"pkt.len_1024_1500",json_object_new_int64(cumulative_stats.packet_len[4]));
      json_object_object_add(jObj_trafficStats,"pkt.len_grt1500",json_object_new_int64(cumulative_stats.packet_len[5]));
      json_object_object_add(jObj_trafficStats,"guessed.flow.protos",json_object_new_int(cumulative_stats.guessed_flow_protocols));

      json_object_object_add(jObj_main,"traffic.statistics",jObj_trafficStats);
    }
#endif
  }

  if((!json_flag) && (!quiet_mode)) printf("\n\nDetected protocols:\n");
  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
    ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].ndpi_struct, i);

    if(cumulative_stats.protocol_counter[i] > 0) {
      breed_stats[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];

      if(results_file)
	fprintf(results_file, "%s\t%llu\t%llu\t%u\n",
		ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, i),
		(long long unsigned int)cumulative_stats.protocol_counter[i],
		(long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
		cumulative_stats.protocol_flows[i]);

      if((!json_flag) && (!quiet_mode)) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u\n",
	       ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, i),
	       (long long unsigned int)cumulative_stats.protocol_counter[i],
	       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	       cumulative_stats.protocol_flows[i]);
      } else {
#ifdef HAVE_JSON_C
	if(json_fp) {
	  jObj = json_object_new_object();

	  json_object_object_add(jObj,"name",json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, i)));
	  json_object_object_add(jObj,"breed",json_object_new_string(ndpi_get_proto_breed_name(ndpi_thread_info[0].ndpi_struct, breed)));
	  json_object_object_add(jObj,"packets",json_object_new_int64(cumulative_stats.protocol_counter[i]));
	  json_object_object_add(jObj,"bytes",json_object_new_int64(cumulative_stats.protocol_counter_bytes[i]));
	  json_object_object_add(jObj,"flows",json_object_new_int(cumulative_stats.protocol_flows[i]));

	  json_object_array_add(jArray_detProto,jObj);
	}
#endif
      }

      total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
    }
  }

  if((!json_flag) && (!quiet_mode)) {
    printf("\n\nProtocol statistics:\n");

    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats[i] > 0) {
	printf("\t%-20s %13llu bytes\n",
	       ndpi_get_proto_breed_name(ndpi_thread_info[0].ndpi_struct, i),
	       breed_stats[i]);
      }
    }
  }

  // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

  if(verbose) {
    FILE *out = results_file ? results_file : stdout;

    if(!json_flag) fprintf(out, "\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_known_proto_walker, &thread_id);
    }

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
        if(!json_flag) {
	  FILE *out = results_file ? results_file : stdout;

          fprintf(out, "\n\nUndetected flows:%s\n", undetected_flows_deleted ? " (expired flows are not listed below)" : "");
        }

	if(json_flag)
	  json_flag = 2;
        break;
      }
    }

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].stats.protocol_counter[0] > 0) {
        for(i=0; i<NUM_ROOTS; i++)
	  ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_unknown_proto_walker, &thread_id);
      }
    }
  }

  if(json_flag != 0) {
#ifdef HAVE_JSON_C
    json_object_object_add(jObj_main,"detected.protos",jArray_detProto);
    json_object_object_add(jObj_main,"known.flows",jArray_known_flows);

    if(json_object_array_length(jArray_unknown_flows) != 0)
      json_object_object_add(jObj_main,"unknown.flows",jArray_unknown_flows);

    fprintf(json_fp,"%s\n",json_object_to_json_string(jObj_main));
    fclose(json_fp);
#endif
  }
}

/* ***************************************************** */

static void closePcapFile(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_close(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

static void breakPcapLoop(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

// executed for each packet in the pcap file
void sigproc(int sig) {
  static int called = 0;
  int thread_id;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}

/* ***************************************************** */

static int getNextPcapFileFromPlaylist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {

  if(playlist_fp[thread_id] == NULL) {
    if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
      return -1;
  }

 next_line:
  if(fgets(filename, filename_len, playlist_fp[thread_id])) {
    int l = strlen(filename);
    if(filename[0] == '\0' || filename[0] == '#') goto next_line;
    if(filename[l-1] == '\n') filename[l-1] = '\0';
    return 0;
  } else {
    fclose(playlist_fp[thread_id]);
    playlist_fp[thread_id] = NULL;
    return -1;
  }
}

/* ***************************************************** */

static void configurePcapHandle(u_int16_t thread_id) {
  ndpi_thread_info[thread_id]._pcap_datalink_type = pcap_datalink(ndpi_thread_info[thread_id]._pcap_handle);

  if(_bpf_filter != NULL) {
    struct bpf_program fcode;

    if(pcap_compile(ndpi_thread_info[thread_id]._pcap_handle, &fcode, _bpf_filter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
    } else {
      if(pcap_setfilter(ndpi_thread_info[thread_id]._pcap_handle, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
      } else
	printf("Successfully set BPF filter to '%s'\n", _bpf_filter);
    }
  }
}

/* ***************************************************** */

static void openPcapFileOrDevice(u_int16_t thread_id) {
  u_int snaplen = 1536;
  int promisc = 1;
  char errbuf[PCAP_ERRBUF_SIZE];

  /* trying to open a live interface */
  if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_live(_pcap_file[thread_id], snaplen, promisc, 500, errbuf)) == NULL) {
    capture_for = capture_until = 0;

    live_capture = 0;
    num_threads = 1; /* Open pcap files in single threads mode */

    /* trying to open a pcap file */
    if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(_pcap_file[thread_id], ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {
      char filename[256];

      /* trying to open a pcap playlist */
      if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0 ||
	 (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {

        printf("ERROR: could not open pcap file or playlist: %s\n", ndpi_thread_info[thread_id]._pcap_error_buffer);
        exit(-1);
      } else {
        if((!json_flag) && (!quiet_mode)) printf("Reading packets from playlist %s...\n", _pcap_file[thread_id]);
      }
    } else {
      if((!json_flag) && (!quiet_mode)) printf("Reading packets from pcap file %s...\n", _pcap_file[thread_id]);
    }
  } else {
    live_capture = 1;

    if((!json_flag) && (!quiet_mode)) printf("Capturing live traffic from device %s...\n", _pcap_file[thread_id]);
  }

  configurePcapHandle(thread_id);

  if(capture_for > 0) {
    if((!json_flag) && (!quiet_mode)) printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
    alarm(capture_for);
    signal(SIGALRM, sigproc);
#endif
  }
}

/* ***************************************************** */

static void pcap_packet_callback(u_char *args,
				 const struct pcap_pkthdr *header,
				 const u_char *packet) {

  /*
   * Declare pointers to packet headers
   */
  
  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- Ethernet II header --- */
  const struct ndpi_ethhdr *ethernet_2;
  /* --- LLC header --- */
  const struct ndpi_llc_header *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;
  /* --- SLARP frame --- */
  struct ndpi_slarp *slarp;
  /* --- CDP --- */
  struct ndpi_cdp *cdp;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  struct ndpi_mpls_header *mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  /* lengths and offsets */
  u_int16_t eth_offset = 0;
  u_int16_t radio_len;
  u_int16_t fc;
  u_int16_t type;
  int wifi_len;
  int llc_off;
  int pyld_eth_len = 0;
  int check;
  u_int32_t fcs;

  u_int64_t time;
  u_int16_t ip_offset, ip_len, ip6_offset;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0;
  u_int32_t label;

  u_int16_t thread_id = *((u_int16_t*)args);

  /* counters */
  u_int8_t malformed_pkts = 0, vlan_packet = 0;
  u_int8_t slarp_pkts = 0, cdp_pkts = 0;

  /* Increment raw packet counter */
  ndpi_thread_info[thread_id].stats.raw_packet_count++;

  if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
    if(ndpi_thread_info[thread_id]._pcap_handle != NULL)
      pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);
    return;
  }

  /* Check if capture is live or not */
  if (!live_capture) {
    if (!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
    pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;
  }

  /* setting time */
  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);

  /* safety check */
  if(ndpi_thread_info[thread_id].last_time > time) {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time = ndpi_thread_info[thread_id].last_time;
  }
  /* update last time value */
  ndpi_thread_info[thread_id].last_time = time;

  /*** check Data Link type ***/
  int datalink_type = ndpi_thread_info[thread_id]._pcap_datalink_type;

 datalink_check:
  switch(datalink_type) {

    case DLT_NULL :
      if(ntohl(*((u_int32_t*)&packet[eth_offset])) == 2)
	type = ETH_P_IP;
      else
	type = ETH_P_IPV6;

      ip_offset = 4 + eth_offset;

      /* Cisco PPP in HDLC-like framing - 50 */
    case DLT_PPP_SERIAL:
      chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
      ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
      type = ntohs(chdlc->proto_code);
      break;

      /* Cisco PPP with HDLC framing - 104 */
    case DLT_C_HDLC:
      chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
      ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
      type = ntohs(chdlc->proto_code);
      break;
      
      /* IEEE 802.3 Ethernet - 1 */
    case DLT_EN10MB :
      ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
      ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
      check = ntohs(ethernet->h_proto);

      if(check <= 1500)
	pyld_eth_len = check;
      else if (check >= 1536)
	type = check;

      if(pyld_eth_len != 0) {
      /* check for LLC layer with SNAP extension */
	if(packet[ip_offset] == SNAP) {
	  llc = (struct ndpi_llc_header *)(&packet[ip_offset]);
	  type = llc->snap.proto_ID;
	  ip_offset += + 8;
	}
      }
      break;

      /* Linux Cooked Capture - 113 */
    case DLT_LINUX_SLL :
      type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
      ip_offset = 16 + eth_offset;
      break;

      /* Radiotap link-layer - 127 */
    case DLT_IEEE802_11_RADIO :
      radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
      radio_len = radiotap->len;

      /* Check Bad FCS presence */
      if((radiotap->flags & BAD_FCS) == BAD_FCS) {
	malformed_pkts += 1;
	ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
	return;
      }

      fcs = header->len - 4;

      /* Calculate 802.11 header length (variable) */
      wifi = (struct ndpi_wifi_header*)( packet + eth_offset + radio_len);
      fc = wifi->fc;

      /* check wifi data presence */
      if(FCF_TYPE(fc) == WIFI_DATA) {
	if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	   (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	  wifi_len = 26; /* + 4 byte fcs */
      } else   /* no data frames */
	break;

      /* Check ether_type from LLC */
      llc = (struct ndpi_llc_header*)(packet + eth_offset + wifi_len + radio_len);
      if(llc->dsap == SNAP)
	type = ntohs(llc->snap.proto_ID);

      /* Set IP header offset */
      ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header) + eth_offset;
      break;

    default:
      return;
    }

  /* check ether type */
  if(type == VLAN) {
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;
    vlan_packet = 1;
  }
  else if(type == MPLS_UNI || type == MPLS_MULTI) {
    
    mpls = (struct ndpi_mpls_header *) &packet[ip_offset];
    label = ntohl(mpls->label);
    /* label = ntohl(*((u_int32_t*)&packet[ip_offset])); */
    ndpi_thread_info[thread_id].stats.mpls_count++;
    type = ETH_P_IP, ip_offset += 4;
    
    while((label & 0x100) != 0x100) {
      ip_offset += 4;
      label = ntohl(mpls->label);
    }
  }
  else if(type == SLARP) {
    slarp = (struct ndpi_slarp *) &packet[ip_offset];
    if(slarp->slarp_type == 0x02 || slarp->slarp_type == 0x00 || slarp->slarp_type == 0x01) {
      /* TODO if info are needed */
    }
    slarp_pkts++;
  }
  else if(type == CISCO_D_PROTO) {
    cdp = (struct ndpi_cdp *) &packet[ip_offset];
    cdp_pkts++;
  }    
  else if(type == PPPoE) {
    ndpi_thread_info[thread_id].stats.pppoe_count++;
    type = ETH_P_IP;
    ip_offset += 8;
  }
  
  ndpi_thread_info[thread_id].stats.vlan_count += vlan_packet;

 iph_check:
  /* Check and set IP header size and total packet length */
  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	if((!json_flag) && (!quiet_mode)) printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == 4) {
    ip_len = ((u_short)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == 41) {
      ip_offset += ip_len;
      goto iph_check;
    }

    if((frag_off & 0x3FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;
      ndpi_thread_info[thread_id].stats.fragmented_count++;

      if(ipv4_frags_warning_used == 0) {
	if((!json_flag) && (!quiet_mode)) printf("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
      return;
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ipv6hdr);

    if(proto == 0x3C /* IPv6 destination option */) {

      u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];
      proto = options[0];
      ip_len += 8 * (options[1] + 1);
    }
    iph = NULL;

  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if((!json_flag) && (!quiet_mode))
	printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }
    ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
    return;
  }

  if(decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	 (message_type == 0xFF /* T-PDU */)) {

	ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8; /* GTPv1 header len */
	if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	iph = (struct ndpi_iphdr *) &packet[ip_offset];

	if(iph->version != 4) {
	  // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)ndpi_thread_info[thread_id].stats.raw_packet_count);
	  goto v4_warning;
	}
      }
    } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
      /* https://en.wikipedia.org/wiki/TZSP */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t version = packet[offset];
      u_int8_t type    = packet[offset+1];
      u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

      if((version == 1) && (type == 0) && (encapsulates == 1)) {
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
	    tag_len = packet[offset+1];
	    break;
	  }

	  offset += tag_len;

	  if(offset >= header->caplen)
	    return; /* Invalid packet */
	  else {
	    eth_offset = offset;
	    goto datalink_check;
	  }
	}
      }
    }
  }

  /* process the packet */
  packet_processing(thread_id, time, vlan_id, iph, iph6,
		    ip_offset, header->len - ip_offset, header->len);
}

/* ******************************************************************** */

static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id]._pcap_handle != NULL))
    pcap_loop(ndpi_thread_info[thread_id]._pcap_handle, -1, &pcap_packet_callback, (u_char*)&thread_id);
}

/* ******************************************************************** */

void *processing_thread(void *_thread_id) {
  long thread_id = (long) _thread_id;

#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
  if(core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else {
      if((!json_flag) && (!quiet_mode)) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  } else
#endif
    if((!json_flag) && (!quiet_mode)) printf("Running thread %ld...\n", thread_id);

 pcap_loop:
  runPcapLoop(thread_id);

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) != NULL) {
      configurePcapHandle(thread_id);
      goto pcap_loop;
    }
  }

  return NULL;
}

/* ******************************************************************** */

void test_lib() {
  struct timeval begin, end;
  u_int64_t tot_usec;
  long thread_id;

#ifdef HAVE_JSON_C
  json_init();
#endif

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    setupDetection(thread_id);
    openPcapFileOrDevice(thread_id);
  }

  gettimeofday(&begin, NULL);

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);

  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    pthread_join(ndpi_thread_info[thread_id].pthread, NULL);

  gettimeofday(&end, NULL);
  tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

  /* Printing cumulative results */
  printResults(tot_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    closePcapFile(thread_id);
    terminateDetection(thread_id);
  }
}

/* ***************************************************** */

int main(int argc, char **argv) {
  int i;

  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
  memset(&pcap_start, 0, sizeof(pcap_start));
  memset(&pcap_end, 0, sizeof(pcap_end));

  parseOptions(argc, argv);

  if((!json_flag) && (!quiet_mode)) {
    printf("\n-----------------------------------------------------------\n"
	   "* NOTE: This is demo app to show *some* nDPI features.\n"
	   "* In this demo we have implemented only some basic features\n"
	   "* just to show you what you can do with the library. Feel \n"
	   "* free to extend it and send us the patches for inclusion\n"
	   "------------------------------------------------------------\n\n");

    printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);
  }

  signal(SIGINT, sigproc);

  for(i=0; i<num_loops; i++)
    test_lib();

  if(results_path) free(results_path);
  if(results_file) fclose(results_file);

  return 0;
}

/* ****************************************************** */

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};

/* ***************************************************** */

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  FILETIME        ft;
  LARGE_INTEGER   li;
  __int64         t;
  static int      tzflag;

  if(tv) {
    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    t  = li.QuadPart;       /* In 100-nanosecond intervals */
    t -= EPOCHFILETIME;     /* Offset to the Epoch time */
    t /= 10;                /* In microseconds */
    tv->tv_sec  = (long)(t / 1000000);
    tv->tv_usec = (long)(t % 1000000);
  }

  if(tz) {
    if(!tzflag) {
      _tzset();
      tzflag++;
    }

    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }

  return 0;
}
#endif /* WIN32 */
