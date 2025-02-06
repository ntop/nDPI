/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-24 - ntop.org
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

#ifdef __linux__
#include <sched.h>
#endif

#include "ndpi_api.h"
#include "../src/lib/third_party/include/uthash.h"
#include "../src/lib/third_party/include/ahocorasick.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <float.h> /* FLT_EPSILON */
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _MSC_BUILD
#include <libgen.h>
#endif
#include <errno.h>

#include "reader_util.h"

#define ntohl64(x) ( ( (uint64_t)(ntohl( (uint32_t)((x << 32) >> 32) )) << 32) | ntohl( ((uint32_t)(x >> 32)) ) )
#define htonl64(x) ntohl64(x)

#define HEURISTICS_CODE 1

/** Client parameters **/

static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
#ifndef USE_DPDK
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
#endif
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static char *_maliciousJA4Path      = NULL; /**< Malicious JA4 signatures */
static char *_maliciousSHA1Path     = NULL; /**< Malicious SSL certificate SHA1 fingerprints */
static char *_riskyDomainFilePath   = NULL; /**< Risky domain files */
static char *_domain_suffixes       = NULL; /**< Domain suffixes file */
static char *_categoriesDirPath     = NULL; /**< Directory containing domain files */
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
static FILE *csv_fp                 = NULL; /**< for CSV export */
static FILE *serialization_fp       = NULL; /**< for TLV,CSV,JSON export */
static ndpi_serialization_format serialization_format = ndpi_serialization_format_unknown;
static char* domain_to_check = NULL;
static char* ip_port_to_check = NULL;
static u_int8_t ignore_vlanid = 0;
FILE *fingerprint_fp         = NULL; /**< for flow fingerprint export */
#ifdef __linux__
static char *bind_mask = NULL;
#endif
#define MAX_FARGS 64
static char* fargv[MAX_FARGS];
static int fargc = 0;
static int dump_fpc_stats = 0;

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../nDPI-custom/ndpiReader_defs.c"
#endif

/** User preferences **/
char *addr_dump_path = NULL;
u_int8_t enable_realtime_output = 0, enable_payload_analyzer = 0, num_bin_clusters = 0, extcap_exit = 0;
u_int8_t verbose = 0, enable_flow_stats = 0;
bool do_load_lists = false;

struct cfg {
  char *proto;
  char *param;
  char *value;
};
#define MAX_NUM_CFGS 32
static struct cfg cfgs[MAX_NUM_CFGS];
static int num_cfgs = 0;

int reader_log_level = 0;
char *_disabled_protocols = NULL;
static u_int8_t stats_flag = 0;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 24 /* 8 is enough for most protocols, Signal and SnapchatCall require more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int32_t risk_stats[NDPI_MAX_RISK] = { 0 }, risks_found = 0, flows_with_risks = 0;
static struct ndpi_stats cumulative_stats;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval startup_time, begin, end;
#ifdef __linux__
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
static struct timeval pcap_start = { 0, 0}, pcap_end = { 0, 0 };
#ifndef USE_DPDK
static struct bpf_program bpf_code;
#endif
static struct bpf_program *bpf_cfilter = NULL;
/** Detection parameters **/
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int32_t num_flows;

extern u_int8_t enable_doh_dot_detection;
extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;
u_int8_t dump_internal_stats;

static struct ndpi_bin malloc_bins;
static int enable_malloc_bins = 0;
static int max_malloc_bins = 14;
int malloc_size_stats = 0;

int monitoring_enabled;

struct flow_info {
  struct ndpi_flow_info *flow;
  u_int16_t thread_id;
};

static struct flow_info *all_flows;

struct info_pair {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
};

typedef struct node_a {
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
  struct node_a *left, *right;
}addr_node;

// struct to add more statitcs in function printFlowStats
typedef struct hash_stats{
  char* domain_name;
  int occurency;       /* how many time domain name occury in the flow */
  UT_hash_handle hh;   /* hashtable to collect the stats */
}hash_stats;


struct port_stats {
  u_int32_t port; /* we'll use this field as the key */
  u_int32_t num_pkts, num_bytes;
  u_int32_t num_flows;
  u_int32_t num_addr; /*number of distinct IP addresses */
  u_int32_t cumulative_addr; /*cumulative some of IP addresses */
  addr_node *addr_tree; /* tree of distinct IP addresses */
  struct info_pair top_ip_addrs[MAX_NUM_IP_ADDRESS];
  u_int8_t hasTopHost; /* as boolean flag */
  u_int32_t top_host;  /* host that is contributed to > 95% of traffic */
  u_int8_t version;    /* top host's ip version */
  char proto[16];      /* application level protocol of top host */
  UT_hash_handle hh;   /* makes this structure hashable */
};

struct port_stats *srcStats = NULL, *dstStats = NULL;

// struct to hold count of flows received by destination ports
struct port_flow_info {
  u_int32_t port; /* key */
  u_int32_t num_flows;
  UT_hash_handle hh;
};

// struct to hold single packet tcp flows sent by source ip address
struct single_flow_info {
  u_int32_t saddr; /* key */
  u_int8_t version; /* IP version */
  struct port_flow_info *ports;
  u_int32_t tot_flows;
  UT_hash_handle hh;
};

struct single_flow_info *scannerHosts = NULL;

// struct to hold top receiver hosts
struct receiver {
  u_int32_t addr; /* key */
  u_int8_t version; /* IP version */
  u_int32_t num_pkts;
  UT_hash_handle hh;
};

struct receiver *receivers = NULL, *topReceivers = NULL;

#define WIRESHARK_NTOP_MAGIC 0x19680924
#define WIRESHARK_METADATA_SIZE		192
#define WIRESHARK_FLOW_RISK_INFO_SIZE	128

#define WIRESHARK_METADATA_SERVERNAME	0x01
#define WIRESHARK_METADATA_JA4C		0x02
#define WIRESHARK_METADATA_TLS_HEURISTICS_MATCHING_FINGERPRINT	0x03

struct ndpi_packet_tlv {
  u_int16_t type;
  u_int16_t length;
  unsigned char data[];
};

PACK_ON
struct ndpi_packet_trailer {
  u_int32_t magic; /* WIRESHARK_NTOP_MAGIC */
  ndpi_master_app_protocol proto;
  char name[16];
  u_int8_t flags;
  ndpi_risk flow_risk;
  u_int16_t flow_score;
  u_int16_t flow_risk_info_len;
  char flow_risk_info[WIRESHARK_FLOW_RISK_INFO_SIZE];
  /* TLV of attributes. Having a max and fixed size for all the metadata
     is not efficient but greatly improves detection of the trailer by Wireshark */
  u_int16_t metadata_len;
  unsigned char metadata[WIRESHARK_METADATA_SIZE];
} PACK_OFF;

static pcap_dumper_t *extcap_dumper = NULL;
static pcap_t *extcap_fifo_h = NULL;
static char extcap_buf[65536 + sizeof(struct ndpi_packet_trailer)];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;
static int do_extcap_capture = 0;
static int extcap_add_crc = 0;

// struct associated to a workflow for a thread
struct reader_thread {
  struct ndpi_workflow *workflow;
  pthread_t pthread;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

// array for every thread created for a flow
static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

// ID tracking
typedef struct ndpi_id {
  u_int8_t ip[4];                   // Ip address
  struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

void test_lib(); /* Forward */

extern void ndpi_report_payload_stats(FILE *out);
extern int parse_proto_name_list(char *str, NDPI_PROTOCOL_BITMASK *bitmask,
				 int inverted_logic);
extern u_int8_t is_ndpi_proto(struct ndpi_flow_info *flow, u_int16_t id);

/* ********************************** */

// #define DEBUG_TRACE

#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

/* ***************************************************** */

static u_int32_t reader_slot_malloc_bins(u_int64_t v)
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
    ndpi_inc_bin(&malloc_bins, reader_slot_malloc_bins(size), 1);

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


#define NUM_DOH_BINS 2

static struct ndpi_bin doh_ndpi_bins[NUM_DOH_BINS];

static u_int8_t doh_centroids[NUM_DOH_BINS][PLEN_NUM_BINS] = {
  { 23,25,3,0,26,0,0,0,0,0,0,0,0,0,2,0,0,15,3,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 },
  { 35,30,21,0,0,0,2,4,0,0,5,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }
};

static float doh_max_distance = 35.5;

static void init_doh_bins() {
  u_int i;

  for(i=0; i<NUM_DOH_BINS; i++) {
    ndpi_init_bin(&doh_ndpi_bins[i], ndpi_bin_family8, PLEN_NUM_BINS);
    ndpi_free_bin(&doh_ndpi_bins[i]); /* Hack: we use static bins (see below), so we need to free the dynamic ones just allocated */
    doh_ndpi_bins[i].u.bins8 = doh_centroids[i];
  }
}

/* *********************************************** */

static u_int check_bin_doh_similarity(struct ndpi_bin *bin, float *similarity) {
  u_int i;
  float lowest_similarity = 9999999999.0f;

  for(i=0; i<NUM_DOH_BINS; i++) {
    *similarity = ndpi_bin_similarity(&doh_ndpi_bins[i], bin, 0, 0);

    if(*similarity < 0) /* Error */
      return(0);

    if(*similarity <= doh_max_distance)
      return(1);

    if(*similarity < lowest_similarity) lowest_similarity = *similarity;
  }

  *similarity = lowest_similarity;

  return(0);
}

/* *********************************************** */

void ndpiCheckHostStringMatch(char *testChar) {
  ndpi_protocol_match_result match = { NDPI_PROTOCOL_UNKNOWN,
				       NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED };
  int  testRes;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  struct ndpi_detection_module_struct *ndpi_str;
  NDPI_PROTOCOL_BITMASK all;

  if(!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_finalize_initialization(ndpi_str);

  testRes =  ndpi_match_string_subprotocol(ndpi_str,
                                           testChar, strlen(testChar), &match);

  if(testRes) {
    memset(&detected_protocol, 0, sizeof(ndpi_protocol) );

    detected_protocol.proto.app_protocol    = match.protocol_id;
    detected_protocol.proto.master_protocol = 0;
    detected_protocol.category        = match.protocol_category;

    ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr,
		       sizeof(appBufStr));

    printf("Match Found for string [%s] -> P(%d) B(%d) C(%d) => %s %s %s\n",
	   testChar, match.protocol_id, match.protocol_breed,
	   match.protocol_category,
	   appBufStr,
	   ndpi_get_proto_breed_name(match.protocol_breed ),
	   ndpi_category_get_name(ndpi_str, match.protocol_category));
  } else
    printf("Match NOT Found for string: %s\n\n", testChar );

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static char const *
ndpi_cfg_error2string(ndpi_cfg_error const err)
{
  switch (err)
    {
    case NDPI_CFG_INVALID_CONTEXT:
      return "Invalid context";
    case NDPI_CFG_NOT_FOUND:
      return "Configuration not found";
    case NDPI_CFG_INVALID_PARAM:
      return "Invalid configuration parameter";
    case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
      return "Configuration context already initialized";
    case NDPI_CFG_CALLBACK_ERROR:
      return "Configuration callback error";
    case NDPI_CFG_OK:
      return "Success";
    }

  return "Unknown";
}

static void ndpiCheckIPMatch(char *testChar) {
  struct ndpi_detection_module_struct *ndpi_str;
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;
  u_int16_t port = 0;
  char *saveptr, *ip_str, *port_str;
  struct in_addr addr;
  char appBufStr[64];
  ndpi_protocol detected_protocol;
  int i;
  ndpi_cfg_error rc;
  NDPI_PROTOCOL_BITMASK all;

  if(!testChar)
    return;

  ndpi_str = ndpi_init_detection_module(NULL);
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_str, _protoFilePath);

  for(i = 0; i < num_cfgs; i++) {
    rc = ndpi_set_config(ndpi_str, cfgs[i].proto, cfgs[i].param, cfgs[i].value);

    if (rc != NDPI_CFG_OK) {
      fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
	      (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
	      cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
      exit(-1);
    }
  }

  ndpi_finalize_initialization(ndpi_str);

  ip_str = strtok_r(testChar, ":", &saveptr);
  if(!ip_str)
    return;

  addr.s_addr = inet_addr(ip_str);
  port_str = strtok_r(NULL, "\n", &saveptr);
  if(port_str)
    port = atoi(port_str);
  ret = ndpi_network_port_ptree_match(ndpi_str, &addr, htons(port));

  if(ret != NDPI_PROTOCOL_UNKNOWN) {
    memset(&detected_protocol, 0, sizeof(ndpi_protocol));
    detected_protocol.proto.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, ret);

    ndpi_protocol2name(ndpi_str, detected_protocol, appBufStr,
                       sizeof(appBufStr));

    printf("Match Found for IP %s, port %d -> %s (%d)\n",
	   ip_str, port, appBufStr, detected_protocol.proto.app_protocol);
  } else {
    printf("Match NOT Found for IP: %s\n", testChar);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/********************** FUNCTIONS ********************* */

static double ndpi_flow_get_byte_count_entropy(const uint32_t byte_count[256],
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

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle,
                           struct ndpi_global_context *g_ctx);

/**
 * @brief Get flow byte distribution mean and variance
 */
static void
flowGetBDMeanandVariance(struct ndpi_flow_info* flow) {
  FILE *out = results_file ? results_file : stdout;
  const uint32_t *array = NULL;
  uint32_t tmp[256], i;
  unsigned int num_bytes;
  double mean = 0.0, variance = 0.0;
  struct ndpi_entropy *last_entropy = flow->last_entropy;

  fflush(out);

  if(!last_entropy)
    return;

  /*
   * Sum up the byte_count array for outbound and inbound flows,
   * if this flow is bidirectional
   */
  /* TODO: we could probably use ndpi_data_* generic functions to simplify the code and
     to get rid of `ndpi_flow_get_byte_count_entropy()` */
  if (!flow->bidirectional) {
    array = last_entropy->src2dst_byte_count;
    num_bytes = last_entropy->src2dst_l4_bytes;
    for(i=0; i<256; i++) {
      tmp[i] = last_entropy->src2dst_byte_count[i];
    }

    if (last_entropy->src2dst_num_bytes != 0) {
      mean = last_entropy->src2dst_bd_mean;
      variance = last_entropy->src2dst_bd_variance/(last_entropy->src2dst_num_bytes - 1);
      variance = sqrt(variance);

      if (last_entropy->src2dst_num_bytes == 1) {
        variance = 0.0;
      }
    }
  } else {
    for(i=0; i<256; i++) {
      tmp[i] = last_entropy->src2dst_byte_count[i] + last_entropy->dst2src_byte_count[i];
    }
    array = tmp;
    num_bytes = last_entropy->src2dst_l4_bytes + last_entropy->dst2src_l4_bytes;

    if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes != 0) {
      mean = ((double)last_entropy->src2dst_num_bytes)/((double)(last_entropy->src2dst_num_bytes+last_entropy->dst2src_num_bytes))*last_entropy->src2dst_bd_mean +
	((double)last_entropy->dst2src_num_bytes)/((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes))*last_entropy->dst2src_bd_mean;

      variance = ((double)last_entropy->src2dst_num_bytes)/((double)(last_entropy->src2dst_num_bytes+last_entropy->dst2src_num_bytes))*last_entropy->src2dst_bd_variance +
	((double)last_entropy->dst2src_num_bytes)/((double)(last_entropy->dst2src_num_bytes+last_entropy->src2dst_num_bytes))*last_entropy->dst2src_bd_variance;

      variance = variance/((double)(last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes - 1));
      variance = sqrt(variance);
      if (last_entropy->src2dst_num_bytes + last_entropy->dst2src_num_bytes == 1) {
        variance = 0.0;
      }
    }
  }

  if(enable_flow_stats) {
    /* Output the mean */
    if(num_bytes != 0) {
      double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

      if(csv_fp) {
        fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", mean, variance, entropy, entropy * num_bytes);
      } else {
        fprintf(out, "[byte_dist_mean: %.3f", mean);
        fprintf(out, "][byte_dist_std: %.3f]", variance);
        fprintf(out, "[entropy: %.3f]", entropy);
        fprintf(out, "[total_entropy: %.3f]", entropy * num_bytes);
      }
    } else {
      if(csv_fp)
        fprintf(csv_fp, "|%.3f|%.3f|%.3f|%.3f", 0.0, 0.0, 0.0, 0.0);
    }
  }
}

/**
 * @brief Print help instructions
 */
static void help(u_int long_help) {
  printf("Welcome to nDPI %s\n\n", ndpi_revision());

  printf("ndpiReader "
#ifndef USE_DPDK
         "-i <file|device> "
#endif
         "[-f <filter>][-s <duration>][-m <duration>][-b <num bin clusters>]\n"
         "          [-p <protos>][-l <loops> [-q][-d][-h][-H][-D][-e <len>][-E <path>][-t][-v <level>]\n"
         "          [-n <threads>][-N <path>][-w <file>][-c <file>][-C <file>][-j <file>][-x <file>]\n"
         "          [-r <file>][-R][-j <file>][-S <file>][-T <num>][-U <num>] [-x <domain>]\n"
         "          [-a <mode>][-B proto_list][-L <domain suffixes>]\n\n"
         "Usage:\n"
         "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
         "                            | device for live capture (comma-separated list)\n"
         "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
         "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
         "  -m <duration>             | Split analysis duration in <duration> max seconds\n"
         "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
         "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -L <domain suffixes>      | Domain suffixes (e.g. ../lists/public_suffix_list.dat)\n"
         "  -n <num threads>          | Number of threads. Default: number of interfaces in -i.\n"
         "                            | Ignored with pcap files.\n"
	 "  -N <path>                 | Address cache dump/restore pathxo.\n"
         "  -b <num bin clusters>     | Number of bin clusters\n"
         "  -k <file>                 | Specify a file to write serialized detection results\n"
         "  -K <format>               | Specify the serialization format for `-k'\n"
         "                            | Valid formats are tlv, csv or json (default)\n"
#ifdef __linux__
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
         "  -a <mode>                 | Generates option values for GUIs\n"
         "                            | 0 - List known protocols\n"
         "                            | 1 - List known categories\n"
         "                            | 2 - List known risks\n"
         "  -d                        | Disable protocol guess (by ip and by port) and use only DPI.\n"
	 "                            | It is a shortcut to --cfg=dpi.guess_on_giveup,0\n"
         "  -e <len>                  | Min human readeable string match len. Default %u\n"
         "  -q                        | Quiet mode\n"
         "  -F                        | Enable flow stats\n"
         "  -t                        | Dissect GTP/TZSP tunnels\n"
         "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
         "                            | <a> = min pattern len to search\n"
         "                            | <b> = max pattern len to search\n"
         "                            | <c> = max num packets per flow\n"
         "                            | <d> = max packet payload dissection\n"
         "                            | <d> = max num reported payloads\n"
         "                            | Default: %u:%u:%u:%u:%u\n"
         "  -c <path>                 | Load custom categories from the specified file\n"
         "  -C <path>                 | Write output in CSV format on the specified file\n"
	 "  -E <path>                 | Write flow fingerprints on the specified file\n"
         "  -r <path>                 | Load risky domain file\n"
         "  -R                        | Print detected realtime protocols\n"
         "  -j <path>                 | Load malicious JA4 fingeprints\n"
         "  -S <path>                 | Load malicious SSL certificate SHA1 fingerprints\n"
	 "  -G <dir>                  | Bind domain names to categories loading files from <dir>\n"
         "  -w <path>                 | Write test output on the specified file. This is useful for\n"
         "                            | testing purposes in order to compare results across runs\n"
         "  -h                        | This help\n"
         "  -H                        | This help plus some information about supported protocols/risks\n"
         "  -v <1|2|3|4>              | Verbose 'unknown protocol' packet print.\n"
         "                            | 1 = verbose\n"
         "                            | 2 = very verbose\n"
         "                            | 3 = port stats\n"
         "                            | 4 = hash stats\n"
         "  -V <0-4>                  | nDPI logging level\n"
         "                            | 0 - error, 1 - trace, 2 - debug, 3 - extra debug\n"
         "                            | >3 - extra debug + log enabled for all protocols (i.e. '-u all')\n"
         "  -u all|proto|num[,...]    | Enable logging only for such protocol(s)\n"
         "                            | If this flag is present multiple times (directly, or via '-V'),\n"
         "                            | only the last instance will be considered\n"
         "  -B all|proto|num[,...]    | Disable such protocol(s). By defaul all protocols are enabled\n"
         "  -T <num>                  | Max number of TCP processed packets before giving up [default: %u]\n"
         "  -U <num>                  | Max number of UDP processed packets before giving up [default: %u]\n"
         "  -D                        | Enable DoH traffic analysis based on content (no DPI)\n"
         "  -x <domain>               | Check domain name [Test only]\n"
         "  -I                        | Ignore VLAN id for flow hash calculation\n"
         "  -A                        | Dump internal statistics (LRU caches / Patricia trees / Ahocarasick automas / ...\n"
         "  -M                        | Memory allocation stats on data-path (only by the library).\n"
	 "                            | It works only on single-thread configuration\n"
         "  --openvp_heuristics       | Enable OpenVPN heuristics.\n"
         "                            | It is a shortcut to --cfg=openvpn,dpi.heuristics,0x01\n"
         "  --tls_heuristics          | Enable TLS heuristics.\n"
         "                            | It is a shortcut to --cfg=tls,dpi.heuristics,0x07\n"
         "  --cfg=proto,param,value   | Configure the specific attribute of this protocol\n"
         "  --dump-fpc-stats          | Print FPC statistics\n"
         ,
         human_readeable_string_len,
         min_pattern_len, max_pattern_len, max_num_packets_per_flow, max_packet_payload_dissection,
         max_num_reported_top_payloads, max_num_tcp_dissected_pkts, max_num_udp_dissected_pkts);

  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_str, _protoFilePath);

  ndpi_finalize_initialization(ndpi_str);

  printf("\nProtocols configuration parameters:\n");
  ndpi_dump_config(ndpi_str, stdout);

#ifndef WIN32
  printf("\nExcap (wireshark) options:\n"
         "  --extcap-interfaces\n"
         "  --extcap-version\n"
         "  --extcap-dlts\n"
         "  --extcap-interface <name>\n"
         "  --extcap-config\n"
         "  --capture\n"
         "  --extcap-capture-filter <filter>\n"
         "  --fifo <path to file or pipe>\n"
         "  --ndpi-proto-filter <protocol>\n"
	 );
#endif

  if(long_help) {
    printf("\n\n"
	   "Size of nDPI Flow structure:      %u\n"
           "Size of nDPI Flow protocol union: %zu\n",
           ndpi_detection_get_sizeof_ndpi_flow_struct(),
           sizeof(((struct ndpi_flow_struct *)0)->protos));

    printf("\n\nnDPI supported protocols:\n");
    printf("%3s %8s %-22s %-10s %-8s %-12s %-18s %-31s %-31s \n",
	   "Id", "Userd-id", "Protocol", "Layer_4", "Nw_Proto", "Breed", "Category","Def UDP Port/s","Def TCP Port/s");
    num_threads = 1;

    ndpi_dump_protocols(ndpi_str, stdout);

    printf("\n\nnDPI supported risks:\n");
    ndpi_dump_risks_score(stdout);
  }

  ndpi_exit_detection_module(ndpi_str);

  exit(!long_help);
}


#define OPTLONG_VALUE_CFG		3000
#define OPTLONG_VALUE_OPENVPN_HEURISTICS	3001
#define OPTLONG_VALUE_TLS_HEURISTICS		3002
#define OPTLONG_VALUE_CONF                      3003
#define OPTLONG_VALUE_FPC_STATS                 3004

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces", no_argument, NULL, '0'},
  { "extcap-version", optional_argument, NULL, '1'},
  { "extcap-dlts", no_argument, NULL, '2'},
  { "extcap-interface", required_argument, NULL, '3'},
  { "extcap-config", no_argument, NULL, '4'},
  { "capture", no_argument, NULL, '5'},
  { "extcap-capture-filter", required_argument, NULL, '6'},
  { "fifo", required_argument, NULL, '7'},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", required_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "flow-stats", required_argument, NULL, 'F'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "load-categories", required_argument, NULL, 'G'},
  { "loops", required_argument, NULL, 'l'},
  { "domain-suffixes", required_argument, NULL, 'L'},
  { "num-threads", required_argument, NULL, 'n'},
  { "address-cache-dump", required_argument, NULL, 'N'},
  { "ignore-vlanid", no_argument, NULL, 'I'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", required_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'r'},
  { "ndpi-log-level", required_argument, NULL, 'V'},
  { "dbg-proto", required_argument, NULL, 'u'},
  { "help", no_argument, NULL, 'h'},
  { "long-help", no_argument, NULL, 'H'},
  { "serialization-outfile", required_argument, NULL, 'k'},
  { "serialization-format", required_argument, NULL, 'K'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  { "cfg", required_argument, NULL, OPTLONG_VALUE_CFG},
  { "openvpn_heuristics", no_argument, NULL, OPTLONG_VALUE_OPENVPN_HEURISTICS},
  { "tls_heuristics", no_argument, NULL, OPTLONG_VALUE_TLS_HEURISTICS},
  { "conf", required_argument, NULL, OPTLONG_VALUE_CONF},
  { "dump-fpc-stats", no_argument, NULL, OPTLONG_VALUE_FPC_STATS},

  {0, 0, 0, 0}
};

static const char* longopts_short = "a:Ab:B:e:E:c:C:dDFf:g:G:i:Ij:k:K:S:hHp:pP:l:L:r:Rs:tu:v:V:n:rp:x:X:w:q0123:456:7:89:m:MN:T:U:";

/* ********************************** */

void extcap_interfaces() {
  printf("extcap {version=%s}{help=https://github.com/ntop/nDPI/tree/dev/wireshark}\n", ndpi_revision());
  printf("interface {value=ndpi}{display=nDPI interface}\n");

  extcap_exit = 1;
}

/* ********************************** */

void extcap_dlts() {
  u_int dlts_number = DLT_EN10MB;

  printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
  extcap_exit = 1;
}

/* ********************************** */

struct ndpi_proto_sorter {
  int id;
  char name[32];
};

/* ********************************** */

int cmpProto(const void *_a, const void *_b) {
  struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter*)_a;
  struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter*)_b;

  return(strcmp(a->name, b->name));
}

/* ********************************** */

int cmpFlows(const void *_a, const void *_b) {
  struct ndpi_flow_info *fa = ((struct flow_info*)_a)->flow;
  struct ndpi_flow_info *fb = ((struct flow_info*)_b)->flow;
  uint64_t a_size = fa->src2dst_bytes + fa->dst2src_bytes;
  uint64_t b_size = fb->src2dst_bytes + fb->dst2src_bytes;
  if(a_size != b_size)
    return a_size < b_size ? 1 : -1;

  // copy from ndpi_workflow_node_cmp();

  if(fa->ip_version < fb->ip_version ) return(-1); else { if(fa->ip_version > fb->ip_version ) return(1); }
  if(fa->protocol   < fb->protocol   ) return(-1); else { if(fa->protocol   > fb->protocol   ) return(1); }
  if(htonl(fa->src_ip)   < htonl(fb->src_ip)  ) return(-1); else { if(htonl(fa->src_ip)   > htonl(fb->src_ip)  ) return(1); }
  if(htons(fa->src_port) < htons(fb->src_port)) return(-1); else { if(htons(fa->src_port) > htons(fb->src_port)) return(1); }
  if(htonl(fa->dst_ip)   < htonl(fb->dst_ip)  ) return(-1); else { if(htonl(fa->dst_ip)   > htonl(fb->dst_ip)  ) return(1); }
  if(htons(fa->dst_port) < htons(fb->dst_port)) return(-1); else { if(htons(fa->dst_port) > htons(fb->dst_port)) return(1); }
  if(fa->vlan_id < fb->vlan_id) return(-1); else { if(fa->vlan_id > fb->vlan_id) return(1); }
  return(0);
}

/* ********************************** */

void extcap_config() {
  int argidx = 0;

  struct ndpi_proto_sorter *protos;
  u_int ndpi_num_supported_protocols;
  int i;
  ndpi_proto_defaults_t *proto_defaults;
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  if(!ndpi_str) exit(0);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  ndpi_finalize_initialization(ndpi_str);

  ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_str);
  proto_defaults = ndpi_get_proto_defaults(ndpi_str);

  /* -i <interface> */
  printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}{group=Live Capture}"
         "{tooltip=The interface name}\n", argidx++);

  printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}{mustexist=true}{group=Pcap}"
         "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);


  protos = (struct ndpi_proto_sorter*)ndpi_malloc(sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
  if(!protos) exit(0);

  printf("arg {number=%d}{call=--ndpi-proto-filter}{display=nDPI Protocol Filter}{type=selector}{group=Options}"
         "{tooltip=nDPI Protocol to be filtered}\n", argidx);

  printf("value {arg=%d}{value=%d}{display=%s}{default=true}\n", argidx, (u_int32_t)-1, "No nDPI filtering");

  for(i=0; i<(int) ndpi_num_supported_protocols; i++) {
    protos[i].id = i;
    ndpi_snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
  }

  qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

  for(i=0; i<(int)ndpi_num_supported_protocols; i++)
    printf("value {arg=%d}{value=%d}{display=%s (%d)}{default=false}{enabled=true}\n", argidx, protos[i].id,
           protos[i].name, protos[i].id);

  ndpi_free(protos);
  argidx++;

  printf("arg {number=%d}{call=--openvpn_heuristics}{display=Enable Obfuscated OpenVPN heuristics}"
	 "{tooltip=Enable Obfuscated OpenVPN heuristics}{type=boolflag}{group=Options}\n", argidx++);
  printf("arg {number=%d}{call=--tls_heuristics}{display=Enable Obfuscated TLS heuristics}"
	 "{tooltip=Enable Obfuscated TLS heuristics}{type=boolflag}{group=Options}\n", argidx++);

  ndpi_exit_detection_module(ndpi_str);

  extcap_exit = 1;
}

/* ********************************** */

void extcap_capture(int datalink_type) {
#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

  if((extcap_fifo_h = pcap_open_dead(datalink_type, 16384 /* MTU */)) == NULL) {
    fprintf(stderr, "Error pcap_open_dead");

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Error pcap_open_dead\n");
#endif
    return;
  }

  if((extcap_dumper = pcap_dump_open(extcap_fifo_h,
                                     extcap_capture_fifo)) == NULL) {
    fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Unable to open the pcap dumper on %s\n",
                      extcap_capture_fifo);
#endif
    return;
  }

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Starting packet capture [%p]\n", extcap_dumper);
#endif
}

/* ********************************** */

void printCSVHeader() {
  if(!csv_fp) return;

  fprintf(csv_fp, "#flow_id|protocol|first_seen|last_seen|duration|src_ip|src_port|dst_ip|dst_port|ndpi_proto_num|ndpi_proto|proto_by_ip|server_name_sni|");
  fprintf(csv_fp, "c_to_s_pkts|c_to_s_bytes|c_to_s_goodput_bytes|s_to_c_pkts|s_to_c_bytes|s_to_c_goodput_bytes|");
  fprintf(csv_fp, "data_ratio|str_data_ratio|c_to_s_goodput_ratio|s_to_c_goodput_ratio|");

  /* IAT (Inter Arrival Time) */
  fprintf(csv_fp, "iat_flow_min|iat_flow_avg|iat_flow_max|iat_flow_stddev|");
  fprintf(csv_fp, "iat_c_to_s_min|iat_c_to_s_avg|iat_c_to_s_max|iat_c_to_s_stddev|");
  fprintf(csv_fp, "iat_s_to_c_min|iat_s_to_c_avg|iat_s_to_c_max|iat_s_to_c_stddev|");

  /* Packet Length */
  fprintf(csv_fp, "pktlen_c_to_s_min|pktlen_c_to_s_avg|pktlen_c_to_s_max|pktlen_c_to_s_stddev|");
  fprintf(csv_fp, "pktlen_s_to_c_min|pktlen_s_to_c_avg|pktlen_s_to_c_max|pktlen_s_to_c_stddev|");

  /* TCP flags */
  fprintf(csv_fp, "cwr|ece|urg|ack|psh|rst|syn|fin|");

  fprintf(csv_fp, "c_to_s_cwr|c_to_s_ece|c_to_s_urg|c_to_s_ack|c_to_s_psh|c_to_s_rst|c_to_s_syn|c_to_s_fin|");

  fprintf(csv_fp, "s_to_c_cwr|s_to_c_ece|s_to_c_urg|s_to_c_ack|s_to_c_psh|s_to_c_rst|s_to_c_syn|s_to_c_fin|");

  /* TCP window */
  fprintf(csv_fp, "c_to_s_init_win|s_to_c_init_win|");

  /* Flow info */
  fprintf(csv_fp, "server_info|");
  fprintf(csv_fp, "tls_version|quic_version|");
  fprintf(csv_fp, "ja3s|");
  fprintf(csv_fp, "advertised_alpns|negotiated_alpn|tls_supported_versions|");
#if 0
  fprintf(csv_fp, "tls_issuerDN|tls_subjectDN|");
#endif
  fprintf(csv_fp, "ssh_client_hassh|ssh_server_hassh|flow_info|plen_bins|http_user_agent");

  if(enable_flow_stats) {
    fprintf(csv_fp, "|byte_dist_mean|byte_dist_std|entropy|total_entropy");
  }

  fprintf(csv_fp, "\n");
}

static int parse_three_strings(char *param, char **s1, char **s2, char **s3)
{
  char *saveptr, *tmp_str, *s1_str, *s2_str = NULL, *s3_str;
  int num_commas;
  unsigned int i;

  tmp_str = ndpi_strdup(param);
  if(tmp_str) {

    /* First parameter might be missing */
    num_commas = 0;
    for(i = 0; i < strlen(tmp_str); i++) {
      if(tmp_str[i] == ',')
        num_commas++;
    }

    if(num_commas == 1) {
      s1_str = NULL;
      s2_str = strtok_r(tmp_str, ",", &saveptr);
    } else if(num_commas == 2) {
      s1_str = strtok_r(tmp_str, ",", &saveptr);
      if(s1_str) {
        s2_str = strtok_r(NULL, ",", &saveptr);
      }
    } else {
      ndpi_free(tmp_str);
      return -1;
    }

    if(s2_str) {
      s3_str = strtok_r(NULL, ",", &saveptr);
      if(s3_str) {
        *s1 = ndpi_strdup(s1_str);
        *s2 = ndpi_strdup(s2_str);
        *s3 = ndpi_strdup(s3_str);
        ndpi_free(tmp_str);
        if(!s1 || !s2 || !s3) {
          ndpi_free(s1);
          ndpi_free(s2);
          ndpi_free(s3);
          return -1;
        }
        return 0;
      }
    }
  }
  ndpi_free(tmp_str);
  return -1;
}

int reader_add_cfg(char *proto, char *param, char *value, int dup)
{
  if(num_cfgs >= MAX_NUM_CFGS) {
    printf("Too many parameter! [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
    return -1;
  }
  cfgs[num_cfgs].proto = dup ? ndpi_strdup(proto) : proto;
  cfgs[num_cfgs].param = dup ? ndpi_strdup(param) : param;
  cfgs[num_cfgs].value = dup ? ndpi_strdup(value) : value;
  num_cfgs++;
  return 0;
}

/* ********************************** */


static void parse_parameters(int argc, char **argv)
{
  int option_idx = 0;
  int opt;
  char *s1, *s2, *s3;

  while((opt = getopt_long(argc, argv, longopts_short, longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### Handling option -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

    switch (opt) {
    case 'a':
      ndpi_generate_options(atoi(optarg), stdout);
      exit(0);

    case 'A':
      dump_internal_stats = 1;
      break;

    case 'b':
      if((num_bin_clusters = atoi(optarg)) > 32)
        num_bin_clusters = 32;
      break;

    case 'd':
      if(reader_add_cfg(NULL, "dpi.guess_on_giveup", "0", 1) == 1) {
        printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case 'D':
      enable_doh_dot_detection = 1;
      break;

    case 'e':
      human_readeable_string_len = atoi(optarg);
      break;

    case 'E':
      errno = 0;
      if((fingerprint_fp = fopen(optarg, "w")) == NULL) {
        printf("Unable to write on fingerprint file %s: %s\n", optarg, strerror(errno));
        exit(1);
      }

      if(reader_add_cfg("tls", "metadata.ja4r_fingerprint", "1", 1) == -1) {
        printf("Unable to enable JA4r fingerprints\n");
        exit(1);
      }

      do_load_lists = true;
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'I':
      ignore_vlanid = 1;
      break;

    case 'j':
      _maliciousJA4Path = optarg;
      break;

    case 'S':
      _maliciousSHA1Path = optarg;
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'f':
    case '6':
      bpfFilter = optarg;
      break;

#ifndef USE_DPDK
#ifdef __linux__
    case 'g':
      bind_mask = optarg;
      break;
#endif
#endif

    case 'G':
      _categoriesDirPath = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'L':
      _domain_suffixes = optarg;
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'N':
      addr_dump_path = optarg;
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 'c':
      _customCategoryFilePath = optarg;
      break;

    case 'C':
      errno = 0;
      if((csv_fp = fopen(optarg, "w")) == NULL)
        {
          printf("Unable to write on CSV file %s: %s\n", optarg, strerror(errno));
          exit(1);
        }
      break;

    case 'r':
      _riskyDomainFilePath = optarg;
      break;

    case 'R':
      enable_realtime_output =1;
      break;

    case 's':
      capture_for = atoi(optarg);
      capture_until = capture_for + time(NULL);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      {
        char buf[12];
        int log_level;
        const char *errstrp;

        /* (Internals) log levels are 0-3, but ndpiReader allows 0-4, where with 4
           we also enable all protocols */
        log_level = ndpi_strtonum(optarg, NDPI_LOG_ERROR, NDPI_LOG_DEBUG_EXTRA + 1, &errstrp, 10);
        if(errstrp != NULL) {
          printf("Invalid log level %s: %s\n", optarg, errstrp);
          exit(1);
        }
        if(log_level > NDPI_LOG_DEBUG_EXTRA) {
          log_level = NDPI_LOG_DEBUG_EXTRA;
          if(reader_add_cfg("all", "log", "enable", 1) == 1) {
            printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
            exit(1);
          }
        }
        snprintf(buf, sizeof(buf), "%d", log_level);
        if(reader_add_cfg(NULL, "log.level", buf, 1) == 1) {
          printf("Invalid log level [%s] [num:%d/%d]\n", buf, num_cfgs, MAX_NUM_CFGS);
          exit(1);
        }
        reader_log_level = log_level;
        break;
      }

    case 'u':
      {
        char *n;
        char *str = ndpi_strdup(optarg);
        int inverted_logic;

        /* Reset any previous call to this knob */
        if(reader_add_cfg("all", "log", "disable", 1) == 1) {
          printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
          exit(1);
        }

        for(n = strtok(str, ","); n && *n; n = strtok(NULL, ",")) {
          inverted_logic = 0;
          if(*n == '-') {
            inverted_logic = 1;
            n++;
          }
          if(reader_add_cfg(n, "log", inverted_logic ? "disable" : "enable", 1) == 1) {
            printf("Invalid parameter [%s] [num:%d/%d]\n", n, num_cfgs, MAX_NUM_CFGS);
            exit(1);
          }
        }
        ndpi_free(str);
        break;
      }

    case 'B':
      ndpi_free(_disabled_protocols);
      _disabled_protocols = ndpi_strdup(optarg);
      break;

    case 'h':
      help(0);
      break;

    case 'H':
      help(1);
      break;

    case 'F':
      enable_flow_stats = 1;
      break;

    case 'P':
      {
        int _min_pattern_len, _max_pattern_len,
          _max_num_packets_per_flow, _max_packet_payload_dissection,
          _max_num_reported_top_payloads;

        enable_payload_analyzer = 1;
        if(sscanf(optarg, "%d:%d:%d:%d:%d", &_min_pattern_len, &_max_pattern_len,
                  &_max_num_packets_per_flow,
                  &_max_packet_payload_dissection,
                  &_max_num_reported_top_payloads) == 5) {
          min_pattern_len = _min_pattern_len, max_pattern_len = _max_pattern_len;
          max_num_packets_per_flow = _max_num_packets_per_flow, max_packet_payload_dissection = _max_packet_payload_dissection;
          max_num_reported_top_payloads = _max_num_reported_top_payloads;
          if(min_pattern_len > max_pattern_len) min_pattern_len = max_pattern_len;
          if(min_pattern_len < 2)               min_pattern_len = 2;
          if(max_pattern_len > 16)              max_pattern_len = 16;
          if(max_num_packets_per_flow == 0)     max_num_packets_per_flow = 1;
          if(max_packet_payload_dissection < 4) max_packet_payload_dissection = 4;
          if(max_num_reported_top_payloads == 0) max_num_reported_top_payloads = 1;
        } else {
          printf("Invalid -P format. Ignored\n");
          help(0);
        }
      }
      break;

    case 'M':
      enable_malloc_bins = 1;
      ndpi_init_bin(&malloc_bins, ndpi_bin_family64, max_malloc_bins);
      break;

    case 'k':
      errno = 0;
      if((serialization_fp = fopen(optarg, "w")) == NULL)
        {
          printf("Unable to write on serialization file %s: %s\n", optarg, strerror(errno));
          exit(1);
        }
      break;

    case 'K':
      if (strcasecmp(optarg, "tlv") == 0 && strlen(optarg) == 3)
        {
          serialization_format = ndpi_serialization_format_tlv;
        } else if (strcasecmp(optarg, "csv") == 0 && strlen(optarg) == 3)
        {
          serialization_format = ndpi_serialization_format_csv;
        } else if (strcasecmp(optarg, "json") == 0 && strlen(optarg) == 4)
        {
          serialization_format = ndpi_serialization_format_json;
        } else {
        printf("Unknown serialization format. Valid values are: tlv,csv,json\n");
        exit(1);
      }
      break;

    case 'w':
      results_path = ndpi_strdup(optarg);
      if((results_file = fopen(results_path, "w")) == NULL) {
        printf("Unable to write in file %s: quitting\n", results_path);
        exit(1);
      }
      break;

    case 'q':
      quiet_mode = 1;
      if(reader_add_cfg(NULL, "log.level", "0", 1) == 1) {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      reader_log_level = 0;
      break;

    case OPTLONG_VALUE_OPENVPN_HEURISTICS:
      if(reader_add_cfg("openvpn", "dpi.heuristics", "0x01", 1) == 1) {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case OPTLONG_VALUE_TLS_HEURISTICS:
      if(reader_add_cfg("tls", "dpi.heuristics", "0x07", 1) == 1) {
        printf("Invalid cfg [num:%d/%d]\n", num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    case OPTLONG_VALUE_FPC_STATS:
      dump_fpc_stats = 1;
      break;

    case OPTLONG_VALUE_CONF:
      {
        FILE *fd;
        char buffer[512], *line, *saveptr;
        int len, saved_optind, initial_fargc;

        fd = fopen(optarg, "r");
        if(fd == NULL) {
          printf("Error opening: %s\n", optarg);
          exit(1);
        }

        if(fargc == 0) {
          fargv[0] = ndpi_strdup(argv[0]);
          fargc = 1;
        }
        initial_fargc = fargc;

        while(1) {
          line = fgets(buffer, sizeof(buffer), fd);

          if(line == NULL)
            break;

          len = strlen(line);

          if((len <= 1) || (line[0] == '#'))
            continue;

          line[len - 1] = '\0';

          fargv[fargc] = ndpi_strdup(strtok_r(line, " \t", &saveptr));
          while(fargc < MAX_FARGS && fargv[fargc] != NULL) {
            fargc++;
            fargv[fargc] = ndpi_strdup(strtok_r(NULL, " \t", &saveptr));
          }
          if(fargc == MAX_FARGS) {
            printf("Too many arguments\n");
            exit(1);
          }
        }

        /* Recursive call to getopt_long() */
        saved_optind = optind;
        optind = initial_fargc;
        parse_parameters(fargc, fargv);
        optind = saved_optind;

        fclose(fd);
      }
      break;

      /* Extcap */
    case '0':
      extcap_interfaces();
      break;

    case '1':
      printf("extcap {version=%s}\n", ndpi_revision());
      break;

    case '2':
      extcap_dlts();
      break;

    case '4':
      extcap_config();
      break;

#ifndef USE_DPDK
    case '5':
      do_extcap_capture = 1;
      break;
#endif

    case '7':
      extcap_capture_fifo = ndpi_strdup(optarg);
      break;

    case '9':
      {
        struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
        NDPI_PROTOCOL_BITMASK all;

        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
        ndpi_finalize_initialization(ndpi_str);

        extcap_packet_filter = ndpi_get_proto_by_name(ndpi_str, optarg);
        if(extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);

        ndpi_exit_detection_module(ndpi_str);
        break;
      }

    case 'T':
      max_num_tcp_dissected_pkts = atoi(optarg);
      /* If we enable that, allow at least 3WHS + 1 "real" packet */
      if(max_num_tcp_dissected_pkts != 0 && max_num_tcp_dissected_pkts < 4) max_num_tcp_dissected_pkts = 4;
      break;

    case 'x':
      domain_to_check = optarg;
      break;

    case 'X':
      ip_port_to_check = optarg;
      break;

    case 'U':
      max_num_udp_dissected_pkts = atoi(optarg);
      break;

    case OPTLONG_VALUE_CFG:
      if(parse_three_strings(optarg, &s1, &s2, &s3) == -1 ||
         reader_add_cfg(s1, s2, s3, 0) == -1) {
        printf("Invalid parameter [%s] [num:%d/%d]\n", optarg, num_cfgs, MAX_NUM_CFGS);
        exit(1);
      }
      break;

    default:
#ifdef DEBUG_TRACE
      if(trace) fprintf(trace, " #### Unknown option -%c: skipping it #### \n", opt);
#endif

      help(0);
      break;
    }
  }
}

/**
 * @brief Option parser
 */
static void parseOptions(int argc, char **argv) {
#ifndef USE_DPDK
  char *__pcap_file = NULL;
  int thread_id;
#ifdef __linux__
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif
#endif

#ifdef USE_DPDK
  {
    int ret = rte_eal_init(argc, argv);

    if(ret < 0)
      rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret, argv += ret;
  }
#endif

  parse_parameters(argc, argv);

  if (serialization_fp == NULL && serialization_format != ndpi_serialization_format_unknown)
    {
      printf("Serializing detection results to a file requires command line arguments `-k'\n");
      exit(1);
    }
  if (serialization_fp != NULL && serialization_format == ndpi_serialization_format_unknown)
    {
      serialization_format = ndpi_serialization_format_json;
    }

  if(extcap_exit)
    exit(0);

  printCSVHeader();

#ifndef USE_DPDK
  if(do_extcap_capture) {
    quiet_mode = 1;
  }

  if(!domain_to_check && !ip_port_to_check) {
    if(_pcap_file[0] == NULL)
      help(0);

    if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
      num_threads = 0;               /* setting number of threads = number of interfaces */
      __pcap_file = strtok(_pcap_file[0], ",");
      while(__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
        _pcap_file[num_threads++] = __pcap_file;
        __pcap_file = strtok(NULL, ",");
      }
    } else {
      if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
      for(thread_id = 1; thread_id < num_threads; thread_id++)
        _pcap_file[thread_id] = _pcap_file[0];
    }

    if(num_threads > 1 && enable_malloc_bins == 1)
      {
	printf("Memory profiling ('-M') is incompatible with multi-thread enviroment");
	exit(1);
      }
  }

#ifdef __linux__
#ifndef USE_DPDK
  for(thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1;

  if(num_cores > 1 && bind_mask != NULL) {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;

    while(core_id != NULL && thread_id < num_threads) {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
#endif
#endif
#endif
}

/* ********************************** */

static char* print_cipher(ndpi_cipher_weakness c) {
  switch(c) {
  case ndpi_cipher_insecure:
    return(" (INSECURE)");
    break;

  case ndpi_cipher_weak:
    return(" (WEAK)");
    break;

  default:
    return("");
  }
}

/* ********************************** */

void print_bin(FILE *fout, const char *label, struct ndpi_bin *b) {
  u_int16_t i;
  const char *sep = label ? "," : ";";

  ndpi_normalize_bin(b);

  if(label) fprintf(fout, "[%s: ", label);

  for(i=0; i<b->num_bins; i++) {
    switch(b->family) {
    case ndpi_bin_family8:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins8[i]);
      break;
    case ndpi_bin_family16:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins16[i]);
      break;
    case ndpi_bin_family32:
      fprintf(fout, "%s%u", (i > 0) ? sep : "", b->u.bins32[i]);
      break;
    case ndpi_bin_family64:
      fprintf(fout, "%s%llu", (i > 0) ? sep : "", (unsigned long long)b->u.bins64[i]);
      break;
    }
  }

  if(label) fprintf(fout, "]");
}

/* ********************************** */

static void print_ndpi_address_port_list_file(FILE *out, const char *label, ndpi_address_port_list *list) {
  unsigned int i;
  ndpi_address_port *ap;

  if(list->num_aps == 0)
    return;
  fprintf(out, "[%s: ", label);
  for(i = 0; i < list->num_aps; i++) {
    ap = &list->aps[i];
    if(ap->port != 0) {
      char buf[INET6_ADDRSTRLEN];

      if(ap->is_ipv6) {
        inet_ntop(AF_INET6, &ap->address, buf, sizeof(buf));
        fprintf(out, "[%s]:%u", buf, ap->port);
      } else {
        inet_ntop(AF_INET, &ap->address, buf, sizeof(buf));
        fprintf(out, "%s:%u", buf, ap->port);
      }
      if(i != list->num_aps - 1)
	fprintf(out, ", ");
    }
  }
  fprintf(out, "]");
}

/* ********************************** */

/**
 * @brief Print the flow
 */
static void printFlow(u_int32_t id, struct ndpi_flow_info *flow, u_int16_t thread_id) {
  FILE *out = results_file ? results_file : stdout;
  u_int8_t known_tls;
  char buf[32], buf1[64];
  char buf_ver[16];
  char buf2_ver[16];
  char l4_proto_name[32];
  u_int i;

  if(csv_fp != NULL) {
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;

    fprintf(csv_fp, "%u|%u|%.3f|%.3f|%.3f|%s|%u|%s|%u|",
            flow->flow_id,
            flow->protocol,
            f/1000.0, l/1000.0,
            (l-f)/1000.0,
            flow->src_name, ntohs(flow->src_port),
            flow->dst_name, ntohs(flow->dst_port)
            );

    fprintf(csv_fp, "%s|",
            ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)));

    fprintf(csv_fp, "%s|%s|%s|",
            ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                               flow->detected_protocol, buf, sizeof(buf)),
            ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                flow->detected_protocol.protocol_by_ip),
            flow->host_server_name);

    fprintf(csv_fp, "%u|%llu|%llu|", flow->src2dst_packets,
            (long long unsigned int) flow->src2dst_bytes, (long long unsigned int) flow->src2dst_goodput_bytes);
    fprintf(csv_fp, "%u|%llu|%llu|", flow->dst2src_packets,
            (long long unsigned int) flow->dst2src_bytes, (long long unsigned int) flow->dst2src_goodput_bytes);
    fprintf(csv_fp, "%.3f|%s|", data_ratio, ndpi_data_ratio2str(data_ratio));
    fprintf(csv_fp, "%.1f|%.1f|", 100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
            100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|",
            (unsigned long long int)ndpi_data_min(flow->iat_flow), ndpi_data_average(flow->iat_flow),
            (unsigned long long int)ndpi_data_max(flow->iat_flow), ndpi_data_stddev(flow->iat_flow));

    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
	    (unsigned long long int)ndpi_data_min(flow->iat_c_to_s), ndpi_data_average(flow->iat_c_to_s),
	    (unsigned long long int)ndpi_data_max(flow->iat_c_to_s), ndpi_data_stddev(flow->iat_c_to_s),
	    (unsigned long long int)ndpi_data_min(flow->iat_s_to_c), ndpi_data_average(flow->iat_s_to_c),
	    (unsigned long long int)ndpi_data_max(flow->iat_s_to_c), ndpi_data_stddev(flow->iat_s_to_c));

    /* Packet Length */
    fprintf(csv_fp, "%llu|%.1f|%llu|%.1f|%llu|%.1f|%llu|%.1f|",
	    (unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_c_to_s),
	    (unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_c_to_s),
	    (unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c), ndpi_data_average(flow->pktlen_s_to_c),
	    (unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c), ndpi_data_stddev(flow->pktlen_s_to_c));

    /* TCP flags */
    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->cwr_count, flow->ece_count, flow->urg_count, flow->ack_count, flow->psh_count, flow->rst_count, flow->syn_count, flow->fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->src2dst_cwr_count, flow->src2dst_ece_count, flow->src2dst_urg_count, flow->src2dst_ack_count,
	    flow->src2dst_psh_count, flow->src2dst_rst_count, flow->src2dst_syn_count, flow->src2dst_fin_count);

    fprintf(csv_fp, "%d|%d|%d|%d|%d|%d|%d|%d|", flow->dst2src_cwr_count, flow->dst2src_ece_count, flow->dst2src_urg_count, flow->dst2src_ack_count,
	    flow->dst2src_psh_count, flow->dst2src_rst_count, flow->dst2src_syn_count, flow->dst2src_fin_count);

    /* TCP window */
    fprintf(csv_fp, "%u|%u|", flow->c_to_s_init_win, flow->s_to_c_init_win);

    fprintf(csv_fp, "%s|",
            (flow->ssh_tls.server_info[0] != '\0')  ? flow->ssh_tls.server_info : "");

    fprintf(csv_fp, "%s|%s|%s|",
            (flow->ssh_tls.ssl_version != 0)        ? ndpi_ssl_version2str(buf_ver, sizeof(buf_ver), flow->ssh_tls.ssl_version, &known_tls) : "0",
            (flow->ssh_tls.quic_version != 0)       ? ndpi_quic_version2str(buf2_ver, sizeof(buf2_ver), flow->ssh_tls.quic_version) : "0",
            (flow->ssh_tls.ja3_server[0] != '\0')   ? flow->ssh_tls.ja3_server : "");

    fprintf(csv_fp, "%s|%s|%s|",
            flow->ssh_tls.advertised_alpns          ? flow->ssh_tls.advertised_alpns : "",
            flow->ssh_tls.negotiated_alpn           ? flow->ssh_tls.negotiated_alpn : "",
            flow->ssh_tls.tls_supported_versions    ? flow->ssh_tls.tls_supported_versions : ""
            );

#if 0
    fprintf(csv_fp, "%s|%s|",
            flow->ssh_tls.tls_issuerDN              ? flow->ssh_tls.tls_issuerDN : "",
            flow->ssh_tls.tls_subjectDN             ? flow->ssh_tls.tls_subjectDN : ""
            );
#endif

    fprintf(csv_fp, "%s|%s",
            (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh : "",
            (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh : ""
            );

    fprintf(csv_fp, "|%s|", flow->info);

#ifndef DIRECTION_BINS
    print_bin(csv_fp, NULL, &flow->payload_len_bin);
#endif

    fprintf(csv_fp, "|%s", flow->http.user_agent);

    if((verbose != 1) && (verbose != 2)) {
      if(csv_fp && enable_flow_stats) {
	flowGetBDMeanandVariance(flow);
      }

      if(csv_fp)
	fprintf(csv_fp, "\n");
      //  return;
    }
  }

  if(csv_fp || (verbose > 1)) {
#if 1
    fprintf(out, "\t%u", id);
#else
    fprintf(out, "\t%u(%u)", id, flow->flow_id);
#endif

    fprintf(out, "\t%s ", ndpi_get_ip_proto_name(flow->protocol, l4_proto_name, sizeof(l4_proto_name)));

    fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
	    flow->bidirectional ? "<->" : "->",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
	    );

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);
    if(enable_payload_analyzer) fprintf(out, "[flowId: %u]", flow->flow_id);

    if(enable_flow_stats) {
      /* Print entropy values for monitored flows. */
      flowGetBDMeanandVariance(flow);
      fflush(out);
      fprintf(out, "[score: %.4f]", flow->entropy->score);
    }

    //if(csv_fp) fprintf(csv_fp, "\n");

    fprintf(out, "[proto: ");
    if(flow->tunnel_type != ndpi_no_tunnel)
      fprintf(out, "%s:", ndpi_tunnel2str(flow->tunnel_type));

    fprintf(out, "%s/%s][IP: %u/%s]",
	    ndpi_protocol2id(flow->detected_protocol, buf, sizeof(buf)),
	    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			       flow->detected_protocol, buf1, sizeof(buf1)),
	    flow->detected_protocol.protocol_by_ip,
	    ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				flow->detected_protocol.protocol_by_ip));

    if(flow->multimedia_flow_types != ndpi_multimedia_unknown_flow) {
      char content[64] = {0};

      fprintf(out, "[Stream Content: %s]", ndpi_multimedia_flowtype2str(content, sizeof(content), flow->multimedia_flow_types));
    }

    fprintf(out, "[%s]",
	    ndpi_is_encrypted_proto(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				    flow->detected_protocol) ? "Encrypted" : "ClearText");

    fprintf(out, "[Confidence: %s]", ndpi_confidence_get_name(flow->confidence));

    if(flow->fpc.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
      fprintf(out, "[FPC: %u/%s, ",
              flow->fpc.proto.app_protocol,
              ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				  flow->fpc.proto.app_protocol));
    } else {
      fprintf(out, "[FPC: %u.%u/%s.%s, ",
              flow->fpc.proto.master_protocol,
              flow->fpc.proto.app_protocol,
              ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				  flow->fpc.proto.master_protocol),
              ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				  flow->fpc.proto.app_protocol));
    }
    fprintf(out, "Confidence: %s]",
	    ndpi_fpc_confidence_get_name(flow->fpc.confidence));

    /* If someone wants to have the num_dissector_calls variable per flow, he can print it here.
       Disabled by default to avoid too many diffs in the unit tests...
    */
#if 0
    fprintf(out, "[Num calls: %d]", flow->num_dissector_calls);
#endif
    fprintf(out, "[DPI packets: %d]", flow->dpi_packets);

    if(flow->num_packets_before_monitoring > 0)
      fprintf(out, "[DPI packets before monitoring: %d]", flow->num_packets_before_monitoring);

    if(flow->detected_protocol.category != 0)
      fprintf(out, "[cat: %s/%u]",
	      ndpi_category_get_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				     flow->detected_protocol.category),
	      (unsigned int)flow->detected_protocol.category);

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
	    (flow->dst2src_packets > 0) ? "<->" : "->",
	    flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    fprintf(out, "[Goodput ratio: %.0f/%.0f]",
	    100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
	    100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

    if(flow->last_seen_ms > flow->first_seen_ms)
      fprintf(out, "[%.2f sec]", ((float)(flow->last_seen_ms - flow->first_seen_ms))/(float)1000);
    else
      fprintf(out, "[< 1 sec]");

    if(flow->telnet.username)  fprintf(out, "[Username: %s]", flow->telnet.username);
    if(flow->telnet.password)  fprintf(out, "[Password: %s]", flow->telnet.password);

    if(flow->http.username[0])  fprintf(out, "[Username: %s]", flow->http.username);
    if(flow->http.password[0])  fprintf(out, "[Password: %s]", flow->http.password);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Hostname/SNI: %s]", flow->host_server_name);

    switch (flow->info_type)
      {
      case INFO_INVALID:
        break;

      case INFO_GENERIC:
        if (flow->info[0] != '\0')
	  {
	    fprintf(out, "[%s]", flow->info);
	  }
        break;

      case INFO_KERBEROS:
        if (flow->kerberos.domain[0] != '\0' ||
            flow->kerberos.hostname[0] != '\0' ||
            flow->kerberos.username[0] != '\0')
	  {
	    fprintf(out, "[%s%s%s%s]",
		    flow->kerberos.domain,
		    (flow->kerberos.hostname[0] != '\0' ||
		     flow->kerberos.username[0] != '\0' ? "\\" : ""),
		    flow->kerberos.hostname,
		    flow->kerberos.username);
	  }
        break;

      case INFO_SOFTETHER:
        if (flow->softether.ip[0] != '\0')
	  {
	    fprintf(out, "[Client IP: %s]", flow->softether.ip);
	  }
        if (flow->softether.port[0] != '\0')
	  {
	    fprintf(out, "[Client Port: %s]", flow->softether.port);
	  }
        if (flow->softether.hostname[0] != '\0')
	  {
	    fprintf(out, "[Hostname: %s]", flow->softether.hostname);
	  }
        if (flow->softether.fqdn[0] != '\0')
	  {
	    fprintf(out, "[FQDN: %s]", flow->softether.fqdn);
	  }
        break;

      case INFO_TIVOCONNECT:
        if (flow->tivoconnect.identity_uuid[0] != '\0')
	  {
	    fprintf(out, "[UUID: %s]", flow->tivoconnect.identity_uuid);
	  }
        if (flow->tivoconnect.machine[0] != '\0')
	  {
	    fprintf(out, "[Machine: %s]", flow->tivoconnect.machine);
	  }
        if (flow->tivoconnect.platform[0] != '\0')
	  {
	    fprintf(out, "[Platform: %s]", flow->tivoconnect.platform);
	  }
        if (flow->tivoconnect.services[0] != '\0')
	  {
	    fprintf(out, "[Services: %s]", flow->tivoconnect.services);
	  }
        break;

      case INFO_SIP:
        if (flow->sip.from[0] != '\0')
          {
            fprintf(out, "[SIP From: %s]", flow->sip.from);
          }
        if (flow->sip.from_imsi[0] != '\0')
          {
            fprintf(out, "[SIP From IMSI: %s]", flow->sip.from_imsi);
          }
        if (flow->sip.to[0] != '\0')
          {
            fprintf(out, "[SIP To: %s]", flow->sip.to);
          }
        if (flow->sip.to_imsi[0] != '\0')
          {
            fprintf(out, "[SIP To IMSI: %s]", flow->sip.to_imsi);
          }
        break;

      case INFO_NATPMP:
        if (flow->natpmp.internal_port != 0 && flow->natpmp.ip[0] != '\0')
	  {
            fprintf(out, "[Result: %u][Internal Port: %u][External Port: %u][External Address: %s]",
                    flow->natpmp.result_code, flow->natpmp.internal_port, flow->natpmp.external_port,
                    flow->natpmp.ip);
	  }
        break;

      case INFO_FTP_IMAP_POP_SMTP:
        if (flow->ftp_imap_pop_smtp.username[0] != '\0')
	  {
	    fprintf(out, "[User: %s][Pwd: %s]",
		    flow->ftp_imap_pop_smtp.username,
		    flow->ftp_imap_pop_smtp.password);
	    if (flow->ftp_imap_pop_smtp.auth_failed != 0)
	      {
		fprintf(out, "[%s]", "Auth Failed");
	      }
	  }
        break;
      }

    if(flow->ssh_tls.advertised_alpns)
      fprintf(out, "[(Advertised) ALPNs: %s]", flow->ssh_tls.advertised_alpns);

    if(flow->ssh_tls.negotiated_alpn)
      fprintf(out, "[(Negotiated) ALPN: %s]", flow->ssh_tls.negotiated_alpn);

    if(flow->ssh_tls.tls_supported_versions)
      fprintf(out, "[TLS Supported Versions: %s]", flow->ssh_tls.tls_supported_versions);

    if(flow->mining.currency[0] != '\0') fprintf(out, "[currency: %s]", flow->mining.currency);

    if(flow->dns.geolocation_iata_code[0] != '\0') fprintf(out, "[GeoLocation: %s]", flow->dns.geolocation_iata_code);

    if((flow->src2dst_packets+flow->dst2src_packets) > 5) {
      if(flow->iat_c_to_s && flow->iat_s_to_c) {
	float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

	fprintf(out, "[bytes ratio: %.3f (%s)]", data_ratio, ndpi_data_ratio2str(data_ratio));

	/* IAT (Inter Arrival Time) */
	fprintf(out, "[IAT c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
		(unsigned long long int)ndpi_data_min(flow->iat_c_to_s),
		(unsigned long long int)ndpi_data_min(flow->iat_s_to_c),
		(float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
		(unsigned long long int)ndpi_data_max(flow->iat_c_to_s),
		(unsigned long long int)ndpi_data_max(flow->iat_s_to_c),
		(float)ndpi_data_stddev(flow->iat_c_to_s),  (float)ndpi_data_stddev(flow->iat_s_to_c));

	/* Packet Length */
	fprintf(out, "[Pkt Len c2s/s2c min/avg/max/stddev: %llu/%llu %.0f/%.0f %llu/%llu %.0f/%.0f]",
		(unsigned long long int)ndpi_data_min(flow->pktlen_c_to_s),
		(unsigned long long int)ndpi_data_min(flow->pktlen_s_to_c),
		ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
		(unsigned long long int)ndpi_data_max(flow->pktlen_c_to_s),
		(unsigned long long int)ndpi_data_max(flow->pktlen_s_to_c),
		ndpi_data_stddev(flow->pktlen_c_to_s),  ndpi_data_stddev(flow->pktlen_s_to_c));
      }
    }

    print_ndpi_address_port_list_file(out, "Mapped IP/Port", &flow->stun.mapped_address);
    print_ndpi_address_port_list_file(out, "Peer IP/Port", &flow->stun.peer_address);
    print_ndpi_address_port_list_file(out, "Relayed IP/Port", &flow->stun.relayed_address);
    print_ndpi_address_port_list_file(out, "Rsp Origin IP/Port", &flow->stun.response_origin);
    print_ndpi_address_port_list_file(out, "Other IP/Port", &flow->stun.other_address);

    /* These counters make sense only if the flow entered the monitor state */
    if(flow->num_packets_before_monitoring > 0)
      fprintf(out, "[RTP packets: %d/%d]", flow->stun.rtp_counters[0], flow->stun.rtp_counters[1]);

    if(flow->http.url[0] != '\0') {
      ndpi_risk_enum risk = ndpi_validate_url(flow->http.url);

      if(risk != NDPI_NO_RISK)
	NDPI_SET_BIT(flow->risk, risk);

      fprintf(out, "[URL: %s]", flow->http.url);
    }

    if(flow->http.response_status_code)
      fprintf(out, "[StatusCode: %u]", flow->http.response_status_code);

    if(flow->http.request_content_type[0] != '\0')
      fprintf(out, "[Req Content-Type: %s]", flow->http.request_content_type);

    if(flow->http.content_type[0] != '\0')
      fprintf(out, "[Content-Type: %s]", flow->http.content_type);

    if(flow->http.nat_ip[0] != '\0')
      fprintf(out, "[Nat-IP: %s]", flow->http.nat_ip);

    if(flow->http.server[0] != '\0')
      fprintf(out, "[Server: %s]", flow->http.server);

    if(flow->http.user_agent[0] != '\0')
      fprintf(out, "[User-Agent: %s]", flow->http.user_agent);

    if(flow->http.filename[0] != '\0')
      fprintf(out, "[Filename: %s]", flow->http.filename);

    if(flow->risk) {
      u_int i;
      u_int16_t cli_score, srv_score;
      fprintf(out, "[Risk: ");

      for(i=0; i<NDPI_MAX_RISK; i++)
	if(NDPI_ISSET_BIT(flow->risk, i))
	  fprintf(out, "** %s **", ndpi_risk2str(i));

      fprintf(out, "]");

      fprintf(out, "[Risk Score: %u]", ndpi_risk2score(flow->risk, &cli_score, &srv_score));

      if(flow->risk_str)
	fprintf(out, "[Risk Info: %s]", flow->risk_str);
    }

    if(flow->tcp_fingerprint)
      fprintf(out, "[TCP Fingerprint: %s]", flow->tcp_fingerprint);

    if(flow->ssh_tls.ssl_version != 0) fprintf(out, "[%s]", ndpi_ssl_version2str(buf_ver, sizeof(buf_ver),
										 flow->ssh_tls.ssl_version, &known_tls));

    if(flow->ssh_tls.quic_version != 0) fprintf(out, "[QUIC ver: %s]", ndpi_quic_version2str(buf_ver, sizeof(buf_ver),
											     flow->ssh_tls.quic_version));

    if(flow->ssh_tls.client_hassh[0] != '\0') fprintf(out, "[HASSH-C: %s]", flow->ssh_tls.client_hassh);

    if(flow->ssh_tls.ja4_client[0] != '\0') fprintf(out, "[JA4: %s%s]", flow->ssh_tls.ja4_client,
						    print_cipher(flow->ssh_tls.client_unsafe_cipher));

    if(flow->ssh_tls.ja4_client_raw != NULL) fprintf(out, "[JA4_r: %s]", flow->ssh_tls.ja4_client_raw);

    if(flow->ssh_tls.server_info[0] != '\0') fprintf(out, "[Server: %s]", flow->ssh_tls.server_info);

    if(flow->ssh_tls.server_names) fprintf(out, "[ServerNames: %s]", flow->ssh_tls.server_names);
    if(flow->ssh_tls.server_hassh[0] != '\0') fprintf(out, "[HASSH-S: %s]", flow->ssh_tls.server_hassh);

    if(flow->ssh_tls.ja3_server[0] != '\0') fprintf(out, "[JA3S: %s]", flow->ssh_tls.ja3_server);

    if(flow->ssh_tls.tls_issuerDN)  fprintf(out, "[Issuer: %s]", flow->ssh_tls.tls_issuerDN);
    if(flow->ssh_tls.tls_subjectDN) fprintf(out, "[Subject: %s]", flow->ssh_tls.tls_subjectDN);

    if(flow->ssh_tls.encrypted_ch.version != 0) {
      fprintf(out, "[ECH: version 0x%x]", flow->ssh_tls.encrypted_ch.version);
    }

    if(flow->ssh_tls.sha1_cert_fingerprint_set) {
      fprintf(out, "[Certificate SHA-1: ");
      for(i=0; i<20; i++)
        fprintf(out, "%s%02X", (i > 0) ? ":" : "",
                flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
      fprintf(out, "]");
    }

  if(flow->idle_timeout_sec) fprintf(out, "[Idle Timeout: %d]", flow->idle_timeout_sec);

#ifdef HEURISTICS_CODE
    if(flow->ssh_tls.browser_heuristics.is_safari_tls)  fprintf(out, "[Safari]");
    if(flow->ssh_tls.browser_heuristics.is_firefox_tls) fprintf(out, "[Firefox]");
    if(flow->ssh_tls.browser_heuristics.is_chrome_tls)  fprintf(out, "[Chrome]");
#endif

    if(flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
      char notBefore[32], notAfter[32];
      struct tm a, b;
      struct tm *before = ndpi_gmtime_r(&flow->ssh_tls.notBefore, &a);
      struct tm *after  = ndpi_gmtime_r(&flow->ssh_tls.notAfter, &b);

      strftime(notBefore, sizeof(notBefore), "%Y-%m-%d %H:%M:%S", before);
      strftime(notAfter, sizeof(notAfter), "%Y-%m-%d %H:%M:%S", after);

      fprintf(out, "[Validity: %s - %s]", notBefore, notAfter);
    }

    char unknown_cipher[8];
    if(flow->ssh_tls.server_cipher != '\0')
      {
	fprintf(out, "[Cipher: %s]", ndpi_cipher2str(flow->ssh_tls.server_cipher, unknown_cipher));
      }
    if(flow->bittorent_hash != NULL) fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);
    if(flow->dhcp_fingerprint != NULL) fprintf(out, "[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);
    if(flow->dhcp_class_ident) fprintf(out, "[DHCP Class Ident: %s]",
				       flow->dhcp_class_ident);

    if(flow->has_human_readeable_strings) fprintf(out, "[PLAIN TEXT (%s)]",
						  flow->human_readeable_string_buffer);

#ifdef DIRECTION_BINS
    print_bin(out, "Plen c2s", &flow->payload_len_bin_src2dst);
    print_bin(out, "Plen s2c", &flow->payload_len_bin_dst2src);
#else
    print_bin(out, "Plen Bins", &flow->payload_len_bin);
#endif

    if(flow->flow_payload && (flow->flow_payload_len > 0)) {
      u_int i;

      fprintf(out, "[Payload: ");

      for(i=0; i<flow->flow_payload_len; i++)
	fprintf(out, "%c", ndpi_isspace(flow->flow_payload[i]) ? '.' : flow->flow_payload[i]);

      fprintf(out, "]");
    }

    fprintf(out, "\n");
  }
}

static void printFlowSerialized(struct ndpi_flow_info *flow)
{
  char *json_str = NULL;
  u_int32_t json_str_len = 0;
  ndpi_serializer * const serializer = &flow->ndpi_flow_serializer;
  //float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
  double f = (double)flow->first_seen_ms, l = (double)flow->last_seen_ms;
  float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

  ndpi_serialize_string_uint32(serializer, "flow_id", flow->flow_id);
  ndpi_serialize_string_double(serializer, "first_seen", f / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "last_seen", l / 1000., "%.3f");
  ndpi_serialize_string_double(serializer, "duration", (l-f)/1000.0, "%.3f");
  ndpi_serialize_string_uint32(serializer, "vlan_id", flow->vlan_id);
  ndpi_serialize_string_uint32(serializer, "bidirectional", flow->bidirectional);

  /* XFER Packets/Bytes */
  ndpi_serialize_start_of_block(serializer, "xfer");
  ndpi_serialize_string_float(serializer, "data_ratio", data_ratio, "%.3f");
  ndpi_serialize_string_string(serializer, "data_ratio_str", ndpi_data_ratio2str(data_ratio));
  ndpi_serialize_string_uint32(serializer, "src2dst_packets", flow->src2dst_packets);
  ndpi_serialize_string_uint64(serializer, "src2dst_bytes",
                               (u_int64_t)flow->src2dst_bytes);
  ndpi_serialize_string_uint64(serializer, "src2dst_goodput_bytes",
                               (u_int64_t)flow->src2dst_goodput_bytes);
  ndpi_serialize_string_uint32(serializer, "dst2src_packets", flow->dst2src_packets);
  ndpi_serialize_string_uint64(serializer, "dst2src_bytes",
                               (u_int64_t)flow->dst2src_bytes);
  ndpi_serialize_string_uint64(serializer, "dst2src_goodput_bytes",
                               (u_int64_t)flow->dst2src_goodput_bytes);
  ndpi_serialize_end_of_block(serializer);

  /* IAT (Inter Arrival Time) */
  ndpi_serialize_start_of_block(serializer, "iat");
  ndpi_serialize_string_uint32(serializer, "flow_min", ndpi_data_min(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_avg",
                              ndpi_data_average(flow->iat_flow), "%.1f");
  ndpi_serialize_string_uint32(serializer, "flow_max", ndpi_data_max(flow->iat_flow));
  ndpi_serialize_string_float(serializer, "flow_stddev",
                              ndpi_data_stddev(flow->iat_flow), "%.1f");

  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->iat_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->iat_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->iat_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->iat_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->iat_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* Packet Length */
  ndpi_serialize_start_of_block(serializer, "pktlen");
  ndpi_serialize_string_uint32(serializer, "c_to_s_min",
                               ndpi_data_min(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_avg",
                              ndpi_data_average(flow->pktlen_c_to_s), "%.1f");
  ndpi_serialize_string_uint32(serializer, "c_to_s_max",
                               ndpi_data_max(flow->pktlen_c_to_s));
  ndpi_serialize_string_float(serializer, "c_to_s_stddev",
                              ndpi_data_stddev(flow->pktlen_c_to_s), "%.1f");

  ndpi_serialize_string_uint32(serializer, "s_to_c_min",
                               ndpi_data_min(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_avg",
                              ndpi_data_average(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_string_uint32(serializer, "s_to_c_max",
                               ndpi_data_max(flow->pktlen_s_to_c));
  ndpi_serialize_string_float(serializer, "s_to_c_stddev",
                              ndpi_data_stddev(flow->pktlen_s_to_c), "%.1f");
  ndpi_serialize_end_of_block(serializer);

  /* TCP flags */
  ndpi_serialize_start_of_block(serializer, "tcp_flags");
  ndpi_serialize_string_int32(serializer, "cwr_count", flow->cwr_count);
  ndpi_serialize_string_int32(serializer, "ece_count", flow->ece_count);
  ndpi_serialize_string_int32(serializer, "urg_count", flow->urg_count);
  ndpi_serialize_string_int32(serializer, "ack_count", flow->ack_count);
  ndpi_serialize_string_int32(serializer, "psh_count", flow->psh_count);
  ndpi_serialize_string_int32(serializer, "rst_count", flow->rst_count);
  ndpi_serialize_string_int32(serializer, "syn_count", flow->syn_count);
  ndpi_serialize_string_int32(serializer, "fin_count", flow->fin_count);

  ndpi_serialize_string_int32(serializer, "src2dst_cwr_count", flow->src2dst_cwr_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ece_count", flow->src2dst_ece_count);
  ndpi_serialize_string_int32(serializer, "src2dst_urg_count", flow->src2dst_urg_count);
  ndpi_serialize_string_int32(serializer, "src2dst_ack_count", flow->src2dst_ack_count);
  ndpi_serialize_string_int32(serializer, "src2dst_psh_count", flow->src2dst_psh_count);
  ndpi_serialize_string_int32(serializer, "src2dst_rst_count", flow->src2dst_rst_count);
  ndpi_serialize_string_int32(serializer, "src2dst_syn_count", flow->src2dst_syn_count);
  ndpi_serialize_string_int32(serializer, "src2dst_fin_count", flow->src2dst_fin_count);

  ndpi_serialize_string_int32(serializer, "dst2src_cwr_count", flow->dst2src_cwr_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ece_count", flow->dst2src_ece_count);
  ndpi_serialize_string_int32(serializer, "dst2src_urg_count", flow->dst2src_urg_count);
  ndpi_serialize_string_int32(serializer, "dst2src_ack_count", flow->dst2src_ack_count);
  ndpi_serialize_string_int32(serializer, "dst2src_psh_count", flow->dst2src_psh_count);
  ndpi_serialize_string_int32(serializer, "dst2src_rst_count", flow->dst2src_rst_count);
  ndpi_serialize_string_int32(serializer, "dst2src_syn_count", flow->dst2src_syn_count);
  ndpi_serialize_string_int32(serializer, "dst2src_fin_count", flow->dst2src_fin_count);
  ndpi_serialize_end_of_block(serializer);

  /* TCP window */
  ndpi_serialize_string_uint32(serializer, "c_to_s_init_win", flow->c_to_s_init_win);
  ndpi_serialize_string_uint32(serializer, "s_to_c_init_win", flow->s_to_c_init_win);

  json_str = ndpi_serializer_get_buffer(serializer, &json_str_len);
  if (json_str == NULL || json_str_len == 0)
    {
      printf("ERROR: nDPI serialization failed\n");
      exit(-1);
    }

  fprintf(serialization_fp, "%.*s\n", (int)json_str_len, json_str);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../nDPI-custom/ndpiReader_flow_serialize.c"
#endif
}

/* ********************************** */

/**
 * @brief Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node,
                                            ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  (void)depth;

  if((flow->detected_protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (flow->detected_protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

/* ********************************** */

/**
 * @brief Known Proto Walker
 */
static void node_print_known_proto_walker(const void *node,
                                          ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  (void)depth;

  if((flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN))
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
    /* Avoid walking the same node multiple times */
    all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
    num_flows++;
  }
}

/* ********************************** */

/**
 * @brief Proto Guess Walker
 */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data), proto, fpc_proto;

  (void)depth;

  if(flow == NULL) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow) {
      u_int8_t proto_guessed;

      malloc_size_stats = 1;
      flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
                                                      flow->ndpi_flow, &proto_guessed);
      malloc_size_stats = 0;

      if(proto_guessed) ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;
    }

    process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

    proto = flow->detected_protocol.proto.app_protocol ? flow->detected_protocol.proto.app_protocol : flow->detected_protocol.proto.master_protocol;
    proto = ndpi_map_user_proto_id_to_ndpi_id(ndpi_thread_info[thread_id].workflow->ndpi_struct, proto);

    fpc_proto = flow->fpc.proto.app_protocol ? flow->fpc.proto.app_protocol : flow->fpc.proto.master_protocol;
    fpc_proto = ndpi_map_user_proto_id_to_ndpi_id(ndpi_thread_info[thread_id].workflow->ndpi_struct, fpc_proto);

    ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
    ndpi_thread_info[thread_id].workflow->stats.flow_confidence[flow->confidence]++;
    ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls += flow->num_dissector_calls;
    ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[fpc_proto]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter_bytes[fpc_proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_flows[fpc_proto]++;
    ndpi_thread_info[thread_id].workflow->stats.fpc_flow_confidence[flow->fpc.confidence]++;
  }
}

/* *********************************************** */

void updateScanners(struct single_flow_info **scanners, u_int32_t saddr,
                    u_int8_t version, u_int32_t dport) {
  struct single_flow_info *f;
  struct port_flow_info *p;

  HASH_FIND_INT(*scanners, (int *)&saddr, f);

  if(f == NULL) {
    f = (struct single_flow_info*)ndpi_malloc(sizeof(struct single_flow_info));
    if(!f) return;
    f->saddr = saddr;
    f->version = version;
    f->tot_flows = 1;
    f->ports = NULL;

    p = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));

    if(!p) {
      ndpi_free(f);
      return;
    } else
      p->port = dport, p->num_flows = 1;

    HASH_ADD_INT(f->ports, port, p);
    HASH_ADD_INT(*scanners, saddr, f);
  } else{
    struct port_flow_info *pp;
    f->tot_flows++;

    HASH_FIND_INT(f->ports, (int *)&dport, pp);

    if(pp == NULL) {
      pp = (struct port_flow_info*)ndpi_malloc(sizeof(struct port_flow_info));
      if(!pp) return;
      pp->port = dport, pp->num_flows = 1;

      HASH_ADD_INT(f->ports, port, pp);
    } else
      pp->num_flows++;
  }
}

/* *********************************************** */

int updateIpTree(u_int32_t key, u_int8_t version,
                 addr_node **vrootp, const char *proto) {
  addr_node *q;
  addr_node **rootp = vrootp;

  if(rootp == (addr_node **)0)
    return 0;

  while(*rootp != (addr_node *)0) {
    /* Knuth's T1: */
    if((version == (*rootp)->version) && (key == (*rootp)->addr)) {
      /* T2: */
      return ++((*rootp)->count);
    }

    rootp = (key < (*rootp)->addr) ?
      &(*rootp)->left :                /* T3: follow left branch */
      &(*rootp)->right;                /* T4: follow right branch */
  }

  q = (addr_node *) ndpi_malloc(sizeof(addr_node));        /* T5: key not found */
  if(q != (addr_node *)0) {                        /* make new node */
    *rootp = q;                                        /* link new node to old */

    q->addr = key;
    q->version = version;
    strncpy(q->proto, proto, sizeof(q->proto) - 1);
    q->proto[sizeof(q->proto) - 1] = '\0';
    q->count = UPDATED_TREE;
    q->left = q->right = (addr_node *)0;

    return q->count;
  }

  return(0);
}
/* *********************************************** */

void freeIpTree(addr_node *root) {
  if(root == NULL)
    return;

  freeIpTree(root->left);
  freeIpTree(root->right);
  ndpi_free(root);
}

/* *********************************************** */

void updateTopIpAddress(u_int32_t addr, u_int8_t version, const char *proto,
                        int count, struct info_pair top[], int size) {
  struct info_pair pair;
  int min = count;
  int update = 0;
  int min_i = 0;
  int i;

  if(count == 0) return;

  pair.addr = addr;
  pair.version = version;
  pair.count = count;
  strncpy(pair.proto, proto, sizeof(pair.proto) - 1);
  pair.proto[sizeof(pair.proto) - 1] = '\0';

  for(i=0; i<size; i++) {
    /* if the same ip with a bigger
       count just update it     */
    if(top[i].addr == addr) {
      top[i].count = count;
      return;
    }
    /* if array is not full yet
       add it to the first empty place */
    if(top[i].count == 0) {
      top[i] = pair;
      return;
    }
  }

  /* if bigger than the smallest one, replace it */
  for(i=0; i<size; i++) {
    if(top[i].count < count && top[i].count < min) {
      min = top[i].count;
      min_i = i;
      update = 1;
    }
  }

  if(update)
    top[min_i] = pair;
}

/* *********************************************** */

static void updatePortStats(struct port_stats **stats, u_int32_t port,
                            u_int32_t addr, u_int8_t version,
                            u_int32_t num_pkts, u_int32_t num_bytes,
                            const char *proto) {

  struct port_stats *s = NULL;
  int count = 0;

  HASH_FIND_INT(*stats, &port, s);
  if(s == NULL) {
    s = (struct port_stats*)ndpi_calloc(1, sizeof(struct port_stats));
    if(!s) return;

    s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
    s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

    updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

    s->addr_tree = (addr_node *) ndpi_malloc(sizeof(addr_node));
    if(!s->addr_tree) {
      ndpi_free(s);
      return;
    }

    s->addr_tree->addr = addr;
    s->addr_tree->version = version;
    strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto) - 1);
    s->addr_tree->proto[sizeof(s->addr_tree->proto) - 1] = '\0';
    s->addr_tree->count = 1;
    s->addr_tree->left = NULL;
    s->addr_tree->right = NULL;

    HASH_ADD_INT(*stats, port, s);
  }
  else{
    count = updateIpTree(addr, version, &(*s).addr_tree, proto);

    if(count == UPDATED_TREE) s->num_addr++;

    if(count) {
      s->cumulative_addr++;
      updateTopIpAddress(addr, version, proto, count, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);
    }

    s->num_pkts += num_pkts, s->num_bytes += num_bytes, s->num_flows++;
  }
}

/* *********************************************** */

/* @brief heuristic choice for receiver stats */
static int acceptable(u_int32_t num_pkts) {
  return num_pkts > 5;
}

/* *********************************************** */

static int receivers_sort_asc(void *_a, void *_b) {
  struct receiver *a = (struct receiver *)_a;
  struct receiver *b = (struct receiver *)_b;

  return(a->num_pkts - b->num_pkts);
}

/* ***************************************************** */
/*@brief removes first (size - max) elements from hash table.
 * hash table is ordered in ascending order.
 */
static struct receiver *cutBackTo(struct receiver **rcvrs, u_int32_t size, u_int32_t max) {
  struct receiver *r, *tmp;
  int i=0;
  int count;

  if(size < max) //return the original table
    return *rcvrs;

  count = size - max;

  HASH_ITER(hh, *rcvrs, r, tmp) {
    if(i++ == count)
      return r;
    HASH_DEL(*rcvrs, r);
    ndpi_free(r);
  }

  return(NULL);

}

/* *********************************************** */
/*@brief merge first table to the second table.
 * if element already in the second table
 *  then updates its value
 * else adds it to the second table
 */
static void mergeTables(struct receiver **primary, struct receiver **secondary) {
  struct receiver *r, *s, *tmp;

  HASH_ITER(hh, *primary, r, tmp) {
    HASH_FIND_INT(*secondary, (int *)&(r->addr), s);
    if(s == NULL) {
      s = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if(!s) return;

      s->addr = r->addr;
      s->version = r->version;
      s->num_pkts = r->num_pkts;

      HASH_ADD_INT(*secondary, addr, s);
    }
    else
      s->num_pkts += r->num_pkts;

    HASH_DEL(*primary, r);
    ndpi_free(r);
  }
}
/* *********************************************** */

static void deleteReceivers(struct receiver *rcvrs) {
  struct receiver *current, *tmp;

  HASH_ITER(hh, rcvrs, current, tmp) {
    HASH_DEL(rcvrs, current);
    ndpi_free(current);
  }
}

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if(table1.size < max1 || acceptable) {
 *    create new element and add to the table1
 *    if(table1.size > max2) {
 *      cut table1 back to max1
 *      merge table 1 to table2
 *      if(table2.size > max1)
 *        cut table2 back to max1
 *    }
 * }
 * else
 *   update table1
 */
static void updateReceivers(struct receiver **rcvrs, u_int32_t dst_addr,
                            u_int8_t version, u_int32_t num_pkts,
                            struct receiver **topRcvrs) {
  struct receiver *r;
  u_int32_t size;
  int a;

  HASH_FIND_INT(*rcvrs, (int *)&dst_addr, r);
  if(r == NULL) {
    if(((size = HASH_COUNT(*rcvrs)) < MAX_TABLE_SIZE_1)
       || ((a = acceptable(num_pkts)) != 0)) {
      r = (struct receiver *)ndpi_malloc(sizeof(struct receiver));
      if(!r) return;

      r->addr = dst_addr;
      r->version = version;
      r->num_pkts = num_pkts;

      HASH_ADD_INT(*rcvrs, addr, r);

      if((size = HASH_COUNT(*rcvrs)) > MAX_TABLE_SIZE_2) {

        HASH_SORT(*rcvrs, receivers_sort_asc);
        *rcvrs = cutBackTo(rcvrs, size, MAX_TABLE_SIZE_1);
        mergeTables(rcvrs, topRcvrs);

        if((size = HASH_COUNT(*topRcvrs)) > MAX_TABLE_SIZE_1) {
          HASH_SORT(*topRcvrs, receivers_sort_asc);
          *topRcvrs = cutBackTo(topRcvrs, size, MAX_TABLE_SIZE_1);
        }

        *rcvrs = NULL;
      }
    }
  }
  else
    r->num_pkts += num_pkts;
}

/* *********************************************** */

static void deleteScanners(struct single_flow_info *scanners) {
  struct single_flow_info *s, *tmp;
  struct port_flow_info *p, *tmp2;

  HASH_ITER(hh, scanners, s, tmp) {
    HASH_ITER(hh, s->ports, p, tmp2) {
      if(s->ports) HASH_DEL(s->ports, p);
      ndpi_free(p);
    }
    HASH_DEL(scanners, s);
    ndpi_free(s);
  }
}

/* *********************************************** */

static void deletePortsStats(struct port_stats *stats) {
  struct port_stats *current_port, *tmp;

  HASH_ITER(hh, stats, current_port, tmp) {
    HASH_DEL(stats, current_port);
    freeIpTree(current_port->addr_tree);
    ndpi_free(current_port);
  }
}

/* *********************************************** */

/**
 * @brief Ports stats
 */
static void port_stats_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
    u_int16_t thread_id = *(int *)user_data;
    u_int16_t sport, dport;
    char proto[16];

    (void)depth;

    sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

    /* get app level protocol */
    if(flow->detected_protocol.proto.master_protocol) {
      ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                         flow->detected_protocol, proto, sizeof(proto));
    } else {
      strncpy(proto, ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                                         flow->detected_protocol.proto.app_protocol),sizeof(proto) - 1);
      proto[sizeof(proto) - 1] = '\0';
    }

    if(flow->protocol == IPPROTO_TCP
       && (flow->src2dst_packets == 1) && (flow->dst2src_packets == 0)) {
      updateScanners(&scannerHosts, flow->src_ip, flow->ip_version, dport);
    }

    updateReceivers(&receivers, flow->dst_ip, flow->ip_version,
                    flow->src2dst_packets, &topReceivers);

    updatePortStats(&srcStats, sport, flow->src_ip, flow->ip_version,
                    flow->src2dst_packets, flow->src2dst_bytes, proto);

    updatePortStats(&dstStats, dport, flow->dst_ip, flow->ip_version,
                    flow->dst2src_packets, flow->dst2src_bytes, proto);
  }
}

/* *********************************************** */

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen_ms + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);
      if(verbose == 3)
        port_stats_walker(node, which, depth, user_data);

      if((flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      ndpi_flow_info_free_data(flow);

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* *********************************************** */

static int is_realtime_protocol(ndpi_protocol proto)
{
  static u_int16_t const realtime_protos[] = {
    NDPI_PROTOCOL_YOUTUBE,
    NDPI_PROTOCOL_YOUTUBE_UPLOAD,
    NDPI_PROTOCOL_TIKTOK,
    NDPI_PROTOCOL_GOOGLE,
    NDPI_PROTOCOL_GOOGLE_CLASSROOM,
    NDPI_PROTOCOL_GOOGLE_CLOUD,
    NDPI_PROTOCOL_GOOGLE_DOCS,
    NDPI_PROTOCOL_GOOGLE_DRIVE,
    NDPI_PROTOCOL_GOOGLE_MAPS,
    NDPI_PROTOCOL_GOOGLE_SERVICES
  };
  u_int16_t i;

  for (i = 0; i < NDPI_ARRAY_LENGTH(realtime_protos); i++) {
    if (proto.proto.app_protocol == realtime_protos[i]
        || proto.proto.master_protocol == realtime_protos[i])
      {
	return 1;
      }
  }

  return 0;
}

static void dump_realtime_protocol(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow)
{
  FILE *out = results_file ? results_file : stdout;
  char srcip[70], dstip[70];
  char ip_proto[64], app_name[64];
  char date[64];
  int ret = is_realtime_protocol(flow->detected_protocol);
  time_t firsttime = flow->first_seen_ms;
  struct tm result;

  if (ndpi_gmtime_r(&firsttime, &result) != NULL)
    {
      strftime(date, sizeof(date), "%d.%m.%y %H:%M:%S", &result);
    } else {
    snprintf(date, sizeof(date), "%s", "Unknown");
  }

  if (flow->ip_version==4) {
    inet_ntop(AF_INET, &flow->src_ip, srcip, sizeof(srcip));
    inet_ntop(AF_INET, &flow->dst_ip, dstip, sizeof(dstip));
  } else {
    snprintf(srcip, sizeof(srcip), "[%s]", flow->src_name);
    snprintf(dstip, sizeof(dstip), "[%s]", flow->dst_name);
  }

  ndpi_protocol2name(workflow->ndpi_struct, flow->detected_protocol, app_name, sizeof(app_name));

  if (ret == 1) {
    fprintf(out, "Detected Realtime protocol %s --> [%s] %s:%d <--> %s:%d app=%s <%s>\n",
            date, ndpi_get_ip_proto_name(flow->protocol, ip_proto, sizeof(ip_proto)),
            srcip, ntohs(flow->src_port), dstip, ntohs(flow->dst_port),
            app_name, flow->human_readeable_string_buffer);
  }
}

static void on_protocol_discovered(struct ndpi_workflow * workflow,
                                   struct ndpi_flow_info * flow,
                                   void * userdata)
{
  (void)userdata;
  if (enable_realtime_output != 0)
    dump_realtime_protocol(workflow, flow);
}

/* *********************************************** */

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle,
                           struct ndpi_global_context *g_ctx) {
  NDPI_PROTOCOL_BITMASK enabled_bitmask;
  struct ndpi_workflow_prefs prefs;
  int i, ret;
  ndpi_cfg_error rc;

  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = decode_tunnels;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = quiet_mode;
  prefs.ignore_vlanid = ignore_vlanid;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
  ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle, 1,
                                                            serialization_format, g_ctx);

  /* Protocols to enable/disable. Default: everything is enabled */
  NDPI_BITMASK_SET_ALL(enabled_bitmask);
  if(_disabled_protocols != NULL) {
    if(parse_proto_name_list(_disabled_protocols, &enabled_bitmask, 1))
      exit(-1);
  }

  if(_categoriesDirPath) {
    int failed_files = ndpi_load_categories_dir(ndpi_thread_info[thread_id].workflow->ndpi_struct, _categoriesDirPath);
    if (failed_files < 0) {
      fprintf(stderr, "Failed to parse all *.list files in: %s\n", _categoriesDirPath);
      exit(-1);
    }
  }

  if(_domain_suffixes)
    ndpi_load_domain_suffixes(ndpi_thread_info[thread_id].workflow->ndpi_struct, _domain_suffixes);
  
  if(_riskyDomainFilePath)
    ndpi_load_risk_domain_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _riskyDomainFilePath);

  if(_maliciousJA4Path)
    ndpi_load_malicious_ja4_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousJA4Path);

  if(_maliciousSHA1Path)
    ndpi_load_malicious_sha1_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _maliciousSHA1Path);

  if(_customCategoryFilePath) {
    char *label = strrchr(_customCategoryFilePath, '/');

    if(label != NULL)
      label = &label[1];
    else
      label = _customCategoryFilePath;

    int failed_lines = ndpi_load_categories_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _customCategoryFilePath, label);
    if (failed_lines < 0) {
      fprintf(stderr, "Failed to parse custom categories file: %s\n", _customCategoryFilePath);
      exit(-1);
    }
  }

  ndpi_thread_info[thread_id].workflow->g_ctx = g_ctx;

  ndpi_workflow_set_flow_callback(ndpi_thread_info[thread_id].workflow,
                                  on_protocol_discovered, NULL);

  /* Make sure to load lists before finalizing the initialization */
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &enabled_bitmask);

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

  ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, NULL, "tcp_ack_payload_heuristic", "enable");

  for(i = 0; i < num_cfgs; i++) {
    rc = ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct,
                         cfgs[i].proto, cfgs[i].param, cfgs[i].value);
    if (rc != NDPI_CFG_OK) {
      fprintf(stderr, "Error setting config [%s][%s][%s]: %s (%d)\n",
	      (cfgs[i].proto != NULL ? cfgs[i].proto : ""),
	      cfgs[i].param, cfgs[i].value, ndpi_cfg_error2string(rc), rc);
      exit(-1);
    }
  }

  if(enable_doh_dot_detection)
    ndpi_set_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, "tls", "application_blocks_tracking", "enable");

  if(addr_dump_path != NULL)
    ndpi_cache_address_restore(ndpi_thread_info[thread_id].workflow->ndpi_struct, addr_dump_path, 0);

  ret = ndpi_finalize_initialization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
  if(ret != 0) {
    fprintf(stderr, "Error ndpi_finalize_initialization: %d\n", ret);
    exit(-1);
  }

  char buf[16];
  if(ndpi_get_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, "stun", "monitoring", buf, sizeof(buf)) != NULL) {
    if(atoi(buf))
      monitoring_enabled = 1;
  }
}

/* *********************************************** */

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
  ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
  ndpi_thread_info[thread_id].workflow = NULL;
}

/* *********************************************** */

/**
 * @brief Traffic stats format
 */
char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    ndpi_snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < (1024*1024)) {
    ndpi_snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/(1024*1024);

    if(tmpMBits < 1024) {
      ndpi_snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
        ndpi_snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
        ndpi_snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* *********************************************** */

/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

  if(numPkts < 1000) {
    ndpi_snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < (1000*1000)) {
    ndpi_snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= (1000*1000);
    ndpi_snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* *********************************************** */

/**
 * @brief Bytes stats format
 */
char* formatBytes(u_int32_t howMuch, char *buf, u_int buf_len) {
  char unit = 'B';

  if(howMuch < 1024) {
    ndpi_snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  } else if(howMuch < (1024*1024)) {
    ndpi_snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
  } else {
    float tmpGB = ((float)howMuch)/(1024*1024);

    if(tmpGB < 1024) {
      ndpi_snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    } else {
      tmpGB /= 1024;

      ndpi_snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
    }
  }

  return(buf);
}

/* *********************************************** */

static int port_stats_sort(void *_a, void *_b) {
  struct port_stats *a = (struct port_stats*)_a;
  struct port_stats *b = (struct port_stats*)_b;

  if(b->num_pkts == 0 && a->num_pkts == 0)
    return(b->num_flows - a->num_flows);

  return(b->num_pkts - a->num_pkts);
}

/* *********************************************** */

static int info_pair_cmp (const void *_a, const void *_b)
{
  struct info_pair *a = (struct info_pair *)_a;
  struct info_pair *b = (struct info_pair *)_b;

  return b->count - a->count;
}

/* *********************************************** */

void printPortStats(struct port_stats *stats) {
  struct port_stats *s, *tmp;
  char addr_name[48];
  int i = 0, j = 0;

  HASH_ITER(hh, stats, s, tmp) {
    i++;
    printf("\t%2d\tPort %5u\t[%u IP address(es)/%u flows/%u pkts/%u bytes]\n\t\tTop IP Stats:\n",
           i, s->port, s->num_addr, s->num_flows, s->num_pkts, s->num_bytes);

    qsort(&s->top_ip_addrs[0], MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);

    for(j=0; j<MAX_NUM_IP_ADDRESS; j++) {
      if(s->top_ip_addrs[j].count != 0) {
        if(s->top_ip_addrs[j].version == IPVERSION) {
          inet_ntop(AF_INET, &(s->top_ip_addrs[j].addr), addr_name, sizeof(addr_name));
        } else {
          inet_ntop(AF_INET6, &(s->top_ip_addrs[j].addr),  addr_name, sizeof(addr_name));
        }

        printf("\t\t%-36s ~ %.2f%%\n", addr_name,
               ((s->top_ip_addrs[j].count) * 100.0) / s->cumulative_addr);
      }
    }

    printf("\n");
    if(i >= 10) break;
  }
}

/* *********************************************** */

static void node_flow_risk_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *f = *(struct ndpi_flow_info**)node;

  (void)depth;
  (void)user_data;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(f->risk) {
      u_int j;

      flows_with_risks++;

      for(j = 0; j < NDPI_MAX_RISK; j++) {
        ndpi_risk_enum r = (ndpi_risk_enum)j;

        if(NDPI_ISSET_BIT(f->risk, r))
          risks_found++, risk_stats[r]++;
      }
    }
  }
}

/* *********************************************** */

static void printRiskStats() {
  if(!quiet_mode) {
    u_int thread_id, i;

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		   node_flow_risk_walker, &thread_id);
    }

    if(risks_found) {
      printf("\nRisk stats [found %u (%.1f %%) flows with risks]:\n",
             flows_with_risks,
             (100.*flows_with_risks)/(float)cumulative_stats.ndpi_flow_count);

      for(i = 0; i < NDPI_MAX_RISK; i++) {
        ndpi_risk_enum r = (ndpi_risk_enum)i;

        if(risk_stats[r] != 0)
          printf("\t%-40s %5u [%4.01f %%]\n", ndpi_risk2str(r), risk_stats[r],
                 (float)(risk_stats[r]*100)/(float)risks_found);
      }

      printf("\n\tNOTE: as one flow can have multiple risks set, the sum of the\n"
             "\t      last column can exceed the number of flows with risks.\n");
      printf("\n\n");
    }
  }
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to order in creasing order to delete host with the leatest occurency*/
static int hash_stats_sort_to_order(void *_a, void *_b) {
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (a->occurency - b->occurency);
}

/* *********************************************** */

/*function to use in HASH_SORT function in verbose == 4 to print in decreasing order*/
static int hash_stats_sort_to_print(void *_a, void *_b) {
  struct hash_stats *a = (struct hash_stats*)_a;
  struct hash_stats *b = (struct hash_stats*)_b;

  return (b->occurency - a->occurency);
}

/* *********************************************** */

static void printFlowsStats() {
  int thread_id;
  u_int32_t total_flows = 0;
  FILE *out = results_file ? results_file : stdout;

  if(enable_payload_analyzer)
    ndpi_report_payload_stats(out);

  for(thread_id = 0; thread_id < num_threads; thread_id++)
    total_flows += ndpi_thread_info[thread_id].workflow->num_allocated_flows;

  if((all_flows = (struct flow_info*)ndpi_malloc(sizeof(struct flow_info)*total_flows)) == NULL) {
    fprintf(out, "Fatal error: not enough memory\n");
    exit(-1);
  }

  if(verbose) {
    ndpi_host_ja_fingerprints *jaByHostsHashT = NULL; // outer hash table
    ndpi_ja_fingerprints_host *hostByJA4C_ht = NULL;   // for client
    ndpi_ja_fingerprints_host *hostByJA3S_ht = NULL;   // for server
    unsigned int i;
    ndpi_host_ja_fingerprints *jaByHost_element = NULL;
    ndpi_ja_info *info_of_element = NULL;
    ndpi_host_ja_fingerprints *tmp = NULL;
    ndpi_ja_info *tmp2 = NULL;
    unsigned int num_ja4_client;
    unsigned int num_ja3_server;

    fprintf(out, "\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_known_proto_walker, &thread_id);
    }

    if((verbose == 2) || (verbose == 3)) {

      /* We are going to print JA4C and JA3S stats */

      for(i = 0; i < num_flows; i++) {
        ndpi_host_ja_fingerprints *jaByHostFound = NULL;
        ndpi_ja_fingerprints_host *hostByJAFound = NULL;

        //check if this is a ssh-ssl flow
        if(all_flows[i].flow->ssh_tls.ja4_client[0] != '\0') {
          //looking if the host is already in the hash table
          HASH_FIND_INT(jaByHostsHashT, &(all_flows[i].flow->src_ip), jaByHostFound);

          //host ip -> ja4c
          if(jaByHostFound == NULL) {
            //adding the new host
            ndpi_host_ja_fingerprints *newHost = ndpi_malloc(sizeof(ndpi_host_ja_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->ip = all_flows[i].flow->src_ip;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja_info *newJA = ndpi_malloc(sizeof(ndpi_ja_info));
            newJA->ja = all_flows[i].flow->ssh_tls.ja4_client;
            newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            //adding the new ja4c fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
                            newJA->ja, strlen(newJA->ja), newJA);
            //adding the new host
            HASH_ADD_INT(jaByHostsHashT, ip, newHost);
          } else {
            //host already in the hash table
            ndpi_ja_info *infoFound = NULL;

            HASH_FIND_STR(jaByHostFound->host_client_info_hasht,
                          all_flows[i].flow->ssh_tls.ja4_client, infoFound);

            if(infoFound == NULL) {
              ndpi_ja_info *newJA = ndpi_malloc(sizeof(ndpi_ja_info));
              newJA->ja = all_flows[i].flow->ssh_tls.ja4_client;
              newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, jaByHostFound->host_client_info_hasht,
                              newJA->ja, strlen(newJA->ja), newJA);
            }
          }

          //ja4c -> host ip
          HASH_FIND_STR(hostByJA4C_ht, all_flows[i].flow->ssh_tls.ja4_client, hostByJAFound);
          if(hostByJAFound == NULL) {
            ndpi_ip_dns *newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->src_ip;
            newHost->ip_string = all_flows[i].flow->src_name;
            newHost->dns_name = all_flows[i].flow->host_server_name;

            ndpi_ja_fingerprints_host *newElement = ndpi_malloc(sizeof(ndpi_ja_fingerprints_host));
            newElement->ja = all_flows[i].flow->ssh_tls.ja4_client;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA4C_ht, newElement->ja, strlen(newElement->ja),
                            newElement);
          } else {
            ndpi_ip_dns *innerElement = NULL;
            HASH_FIND_INT(hostByJAFound->ipToDNS_ht, &(all_flows[i].flow->src_ip), innerElement);
            if(innerElement == NULL) {
              ndpi_ip_dns *newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->src_ip;
              newInnerElement->ip_string = all_flows[i].flow->src_name;
              newInnerElement->dns_name = all_flows[i].flow->host_server_name;
              HASH_ADD_INT(hostByJAFound->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }

        if(all_flows[i].flow->ssh_tls.ja3_server[0] != '\0') {
          //looking if the host is already in the hash table
          HASH_FIND_INT(jaByHostsHashT, &(all_flows[i].flow->dst_ip), jaByHostFound);
          if(jaByHostFound == NULL) {
            //adding the new host in the hash table
            ndpi_host_ja_fingerprints *newHost = ndpi_malloc(sizeof(ndpi_host_ja_fingerprints));
            newHost->host_client_info_hasht = NULL;
            newHost->host_server_info_hasht = NULL;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;

            ndpi_ja_info *newJA = ndpi_malloc(sizeof(ndpi_ja_info));
            newJA->ja = all_flows[i].flow->ssh_tls.ja3_server;
            newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            //adding the new ja3s fingerprint
            HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht, newJA->ja,
                            strlen(newJA->ja), newJA);
            //adding the new host
            HASH_ADD_INT(jaByHostsHashT, ip, newHost);
          } else {
            //host already in the hashtable
            ndpi_ja_info *infoFound = NULL;
            HASH_FIND_STR(jaByHostFound->host_server_info_hasht,
                          all_flows[i].flow->ssh_tls.ja3_server, infoFound);
            if(infoFound == NULL) {
              ndpi_ja_info *newJA = ndpi_malloc(sizeof(ndpi_ja_info));
              newJA->ja = all_flows[i].flow->ssh_tls.ja3_server;
              newJA->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
              HASH_ADD_KEYPTR(hh, jaByHostFound->host_server_info_hasht,
                              newJA->ja, strlen(newJA->ja), newJA);
            }
          }

          HASH_FIND_STR(hostByJA3S_ht, all_flows[i].flow->ssh_tls.ja3_server, hostByJAFound);
          if(hostByJAFound == NULL) {
            ndpi_ip_dns *newHost = ndpi_malloc(sizeof(ndpi_ip_dns));

            newHost->ip = all_flows[i].flow->dst_ip;
            newHost->ip_string = all_flows[i].flow->dst_name;
            newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;;

            ndpi_ja_fingerprints_host *newElement = ndpi_malloc(sizeof(ndpi_ja_fingerprints_host));
            newElement->ja = all_flows[i].flow->ssh_tls.ja3_server;
            newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
            newElement->ipToDNS_ht = NULL;

            HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
            HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja, strlen(newElement->ja),
                            newElement);
          } else {
            ndpi_ip_dns *innerElement = NULL;

            HASH_FIND_INT(hostByJAFound->ipToDNS_ht, &(all_flows[i].flow->dst_ip), innerElement);
            if(innerElement == NULL) {
              ndpi_ip_dns *newInnerElement = ndpi_malloc(sizeof(ndpi_ip_dns));
              newInnerElement->ip = all_flows[i].flow->dst_ip;
              newInnerElement->ip_string = all_flows[i].flow->dst_name;
              newInnerElement->dns_name = all_flows[i].flow->ssh_tls.server_info;
              HASH_ADD_INT(hostByJAFound->ipToDNS_ht, ip, newInnerElement);
            }
          }
        }
      }

      if(jaByHostsHashT) {
        ndpi_ja_fingerprints_host *hostByJAElement = NULL;
        ndpi_ja_fingerprints_host *tmp3 = NULL;
        ndpi_ip_dns *innerHashEl = NULL;
        ndpi_ip_dns *tmp4 = NULL;

        if(verbose == 2) {
          /* for each host the number of flow with a ja4c fingerprint is printed */
          i = 1;

          fprintf(out, "JA Host Stats: \n");
          fprintf(out, "\t\t IP %-24s \t %-10s \n", "Address", "# JA4C");

          for(jaByHost_element = jaByHostsHashT; jaByHost_element != NULL;
              jaByHost_element = jaByHost_element->hh.next) {
            num_ja4_client = HASH_COUNT(jaByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(jaByHost_element->host_server_info_hasht);

            if(num_ja4_client > 0) {
              fprintf(out, "\t%d\t %-24s \t %-7u\n",
                      i,
                      jaByHost_element->ip_string,
                      num_ja4_client
                      );
              i++;
            }

          }
        } else if(verbose == 3) {
          int i = 1;
          int againstRepeat;
          ndpi_ja_fingerprints_host *hostByJAElement = NULL;
          ndpi_ja_fingerprints_host *tmp3 = NULL;
          ndpi_ip_dns *innerHashEl = NULL;
          ndpi_ip_dns *tmp4 = NULL;

          //for each host it is printted the JA4C and JA3S, along the server name (if any)
          //and the security status

          fprintf(out, "JA4C/JA3S Host Stats: \n");
          fprintf(out, "\t%-7s %-24s %-44s %s\n", "", "IP", "JA4C", "JA3S");

          //reminder
          //jaByHostsHashT: hash table <ip, (ja, ht_client, ht_server)>
          //jaByHost_element: element of jaByHostsHashT
          //info_of_element: element of the inner hash table of jaByHost_element
          HASH_ITER(hh, jaByHostsHashT, jaByHost_element, tmp) {
            num_ja4_client = HASH_COUNT(jaByHost_element->host_client_info_hasht);
            num_ja3_server = HASH_COUNT(jaByHost_element->host_server_info_hasht);
            againstRepeat = 0;
            if(num_ja4_client > 0) {
              HASH_ITER(hh, jaByHost_element->host_client_info_hasht, info_of_element, tmp2) {
                fprintf(out, "\t%-7d %-24s %s %s\n",
                        i,
                        jaByHost_element->ip_string,
                        info_of_element->ja,
                        print_cipher(info_of_element->unsafe_cipher)
                        );
                againstRepeat = 1;
                i++;
              }
            }

            if(num_ja3_server > 0) {
              HASH_ITER(hh, jaByHost_element->host_server_info_hasht, info_of_element, tmp2) {
                fprintf(out, "\t%-7d %-24s %-44s %s %s %s%s%s\n",
                        i,
                        jaByHost_element->ip_string,
                        "",
                        info_of_element->ja,
                        print_cipher(info_of_element->unsafe_cipher),
                        jaByHost_element->dns_name[0] ? "[" : "",
                        jaByHost_element->dns_name,
                        jaByHost_element->dns_name[0] ? "]" : ""
                        );
                i++;
              }
            }
          }

          i = 1;

          fprintf(out, "\nIP/JA Distribution:\n");
          fprintf(out, "%-15s %-43s %-26s\n", "", "JA", "IP");
          HASH_ITER(hh, hostByJA4C_ht, hostByJAElement, tmp3) {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJAElement->ipToDNS_ht, innerHashEl, tmp4) {
              if(againstRepeat == 0) {
                fprintf(out, "\t%-7d JA4C %s",
                        i,
                        hostByJAElement->ja
                        );
                fprintf(out, "   %-20s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher)
                        );
                againstRepeat = 1;
                i++;
              } else {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher)
                        );
              }
            }
          }
          HASH_ITER(hh, hostByJA3S_ht, hostByJAElement, tmp3) {
            againstRepeat = 0;
            HASH_ITER(hh, hostByJAElement->ipToDNS_ht, innerHashEl, tmp4) {
              if(againstRepeat == 0) {
                fprintf(out, "\t%-7d JA3S %s",
                        i,
                        hostByJAElement->ja
                        );
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
                againstRepeat = 1;
                i++;
              } else {
                fprintf(out, "\t%45s", "");
                fprintf(out, "   %-15s %-10s %s%s%s\n",
                        innerHashEl->ip_string,
                        print_cipher(hostByJAElement->unsafe_cipher),
                        innerHashEl->dns_name[0] ? "[" : "",
                        innerHashEl->dns_name,
                        innerHashEl->dns_name[0] ? "]" : ""
                        );
              }
            }
          }
        }
        fprintf(out, "\n\n");

        //freeing the hash table
        HASH_ITER(hh, jaByHostsHashT, jaByHost_element, tmp) {
          HASH_ITER(hh, jaByHost_element->host_client_info_hasht, info_of_element, tmp2) {
            if(jaByHost_element->host_client_info_hasht)
              HASH_DEL(jaByHost_element->host_client_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_ITER(hh, jaByHost_element->host_server_info_hasht, info_of_element, tmp2) {
            if(jaByHost_element->host_server_info_hasht)
              HASH_DEL(jaByHost_element->host_server_info_hasht, info_of_element);
            ndpi_free(info_of_element);
          }
          HASH_DEL(jaByHostsHashT, jaByHost_element);
          ndpi_free(jaByHost_element);
        }

        HASH_ITER(hh, hostByJA4C_ht, hostByJAElement, tmp3) {
          HASH_ITER(hh, hostByJA4C_ht->ipToDNS_ht, innerHashEl, tmp4) {
            if(hostByJAElement->ipToDNS_ht)
              HASH_DEL(hostByJAElement->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA4C_ht, hostByJAElement);
          ndpi_free(hostByJAElement);
        }

        hostByJAElement = NULL;
        HASH_ITER(hh, hostByJA3S_ht, hostByJAElement, tmp3) {
          HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4) {
            if(hostByJAElement->ipToDNS_ht)
              HASH_DEL(hostByJAElement->ipToDNS_ht, innerHashEl);
            ndpi_free(innerHashEl);
          }
          HASH_DEL(hostByJA3S_ht, hostByJAElement);
          ndpi_free(hostByJAElement);
        }
      }
    }

    if (verbose == 4) {
      //how long the table could be
      unsigned int len_table_max = 1000;
      //number of element to delete when the table is full
      int toDelete = 10;
      struct hash_stats *hostsHashT = NULL;
      struct hash_stats *host_iter = NULL;
      struct hash_stats *tmp = NULL;
      int len_max = 0;

      for (i = 0; i<num_flows; i++) {

	if(all_flows[i].flow->host_server_name[0] != '\0') {

	  int len = strlen(all_flows[i].flow->host_server_name);
	  len_max = ndpi_max(len,len_max);

	  struct hash_stats *hostFound;
	  HASH_FIND_STR(hostsHashT, all_flows[i].flow->host_server_name, hostFound);

	  if(hostFound == NULL) {
	    struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));
	    newHost->domain_name = all_flows[i].flow->host_server_name;
	    newHost->occurency = 1;
	    if (HASH_COUNT(hostsHashT) == len_table_max) {
	      int i=0;
	      while (i<=toDelete) {

		HASH_ITER(hh, hostsHashT, host_iter, tmp) {
		  HASH_DEL(hostsHashT,host_iter);
		  free(host_iter);
		  i++;
		}
	      }

	    }
	    HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
	  } else
	    hostFound->occurency++;
	}

	if(all_flows[i].flow->ssh_tls.server_info[0] != '\0') {
	  int len = strlen(all_flows[i].flow->host_server_name);
	  len_max = ndpi_max(len,len_max);

	  struct hash_stats *hostFound;
	  HASH_FIND_STR(hostsHashT, all_flows[i].flow->ssh_tls.server_info, hostFound);

	  if(hostFound == NULL) {
	    struct hash_stats *newHost = (struct hash_stats*)ndpi_malloc(sizeof(hash_stats));

	    newHost->domain_name = all_flows[i].flow->ssh_tls.server_info;
	    newHost->occurency = 1;

	    if ((HASH_COUNT(hostsHashT)) == len_table_max) {
	      int i=0;
	      while (i<toDelete) {

		HASH_ITER(hh, hostsHashT, host_iter, tmp) {
		  HASH_DEL(hostsHashT,host_iter);
		  ndpi_free(host_iter);
		  i++;
		}
	      }
	    }
	    HASH_ADD_KEYPTR(hh, hostsHashT, newHost->domain_name, strlen(newHost->domain_name), newHost);
	  } else
	    hostFound->occurency++;
	}

	//sort the table by the least occurency
	HASH_SORT(hostsHashT, hash_stats_sort_to_order);
      }

      //sort the table in decreasing order to print
      HASH_SORT(hostsHashT, hash_stats_sort_to_print);

      //print the element of the hash table
      int j;
      HASH_ITER(hh, hostsHashT, host_iter, tmp) {

	printf("\t%s", host_iter->domain_name);
	//to print the occurency in aligned column
	int diff = len_max-strlen(host_iter->domain_name);
	for (j = 0; j <= diff+5;j++)
	  printf (" ");
	printf("%d\n",host_iter->occurency);
      }
      printf("%s", "\n\n");

      //freeing the hash table
      HASH_ITER(hh, hostsHashT, host_iter, tmp) {
	HASH_DEL(hostsHashT, host_iter);
	ndpi_free(host_iter);
      }

    }

    /* Print all flows stats */

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    if(verbose > 1) {
#ifndef DIRECTION_BINS
      struct ndpi_bin *bins   = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_flows);
      u_int16_t *cluster_ids  = (u_int16_t*)ndpi_malloc(sizeof(u_int16_t)*num_flows);
      u_int32_t num_flow_bins = 0;
#endif

      for(i=0; i<num_flows; i++) {
#ifndef DIRECTION_BINS
        if(enable_doh_dot_detection) {
          /* Discard flows with few packets per direction */
          if((all_flows[i].flow->src2dst_packets < 10)
             || (all_flows[i].flow->dst2src_packets < 10)
             /* Ignore flows for which we have not seen the beginning */
             )
            goto print_flow;

          if(all_flows[i].flow->protocol == 6 /* TCP */) {
            /* Discard flows with no SYN as we need to check ALPN */
            if((all_flows[i].flow->src2dst_syn_count == 0) || (all_flows[i].flow->dst2src_syn_count == 0))
              goto print_flow;

            if(all_flows[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS) {
              if((all_flows[i].flow->src2dst_packets+all_flows[i].flow->dst2src_packets) < 40)
                goto print_flow; /* Too few packets for TLS negotiation etc */
            }
          }
        }

        if(bins && cluster_ids) {
          u_int j;
          u_int8_t not_empty;

          if(enable_doh_dot_detection) {
            not_empty = 0;

            /* Check if bins are empty (and in this case discard it) */
            for(j=0; j<all_flows[i].flow->payload_len_bin.num_bins; j++)
              if(all_flows[i].flow->payload_len_bin.u.bins8[j] != 0) {
                not_empty = 1;
                break;
              }
          } else
            not_empty = 1;

          if(not_empty) {
            memcpy(&bins[num_flow_bins], &all_flows[i].flow->payload_len_bin, sizeof(struct ndpi_bin));
            ndpi_normalize_bin(&bins[num_flow_bins]);
            num_flow_bins++;
          }
        }
#endif

      print_flow:
        printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
      }

#ifndef DIRECTION_BINS
      if(bins && cluster_ids && (num_bin_clusters > 0) && (num_flow_bins > 0)) {
        char buf[64];
        u_int j;
        struct ndpi_bin *centroids;

        if((centroids = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bin_clusters)) != NULL) {
          for(i=0; i<num_bin_clusters; i++)
            ndpi_init_bin(&centroids[i], ndpi_bin_family32 /* Use 32 bit to avoid overlaps */,
                          bins[0].num_bins);

          ndpi_cluster_bins(bins, num_flow_bins, num_bin_clusters, cluster_ids, centroids);

          fprintf(out, "\n"
		  "\tBin clusters\n"
		  "\t------------\n");

          for(j=0; j<num_bin_clusters; j++) {
            u_int16_t num_printed = 0;
            float max_similarity = 0;

            for(i=0; i<num_flow_bins; i++) {
              float similarity, s;

              if(cluster_ids[i] != j) continue;

              if(num_printed == 0) {
                fprintf(out, "\tCluster %u [", j);
                print_bin(out, NULL, &centroids[j]);
                fprintf(out, "]\n");
              }

              fprintf(out, "\t%u\t%-10s\t%s:%u <-> %s:%u\t[",
                      i,
                      ndpi_protocol2name(ndpi_thread_info[0].workflow->ndpi_struct,
                                         all_flows[i].flow->detected_protocol, buf, sizeof(buf)),
                      all_flows[i].flow->src_name,
                      ntohs(all_flows[i].flow->src_port),
                      all_flows[i].flow->dst_name,
                      ntohs(all_flows[i].flow->dst_port));

              print_bin(out, NULL, &bins[i]);
              fprintf(out, "][similarity: %f]",
                      (similarity = ndpi_bin_similarity(&centroids[j], &bins[i], 0, 0)));

              if(all_flows[i].flow->host_server_name[0] != '\0')
                fprintf(out, "[%s]", all_flows[i].flow->host_server_name);

              if(enable_doh_dot_detection) {
                if(((all_flows[i].flow->detected_protocol.proto.master_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_TLS)
                    || (all_flows[i].flow->detected_protocol.proto.app_protocol == NDPI_PROTOCOL_DOH_DOT)
                    )
                   && all_flows[i].flow->ssh_tls.advertised_alpns /* ALPN */
                   ) {
                  if(check_bin_doh_similarity(&bins[i], &s))
                    fprintf(out, "[DoH (%f distance)]", s);
                  else
                    fprintf(out, "[NO DoH (%f distance)]", s);
                } else {
                  if(all_flows[i].flow->ssh_tls.advertised_alpns == NULL)
                    fprintf(out, "[NO DoH check: missing ALPN]");
                }
              }

              fprintf(out, "\n");
              num_printed++;
              if(similarity > max_similarity) max_similarity = similarity;
            }

            if(num_printed) {
              fprintf(out, "\tMax similarity: %f\n", max_similarity);
              fprintf(out, "\n");
            }
          }

          for(i=0; i<num_bin_clusters; i++)
            ndpi_free_bin(&centroids[i]);

          ndpi_free(centroids);
        }
      }
      if(bins)
        ndpi_free(bins);
      if(cluster_ids)
        ndpi_free(cluster_ids);
#endif
    }

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
        fprintf(out, "\n\nUndetected flows:%s\n",
                undetected_flows_deleted ? " (expired flows are not listed below)" : "");
        break;
      }
    }

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0 ||
         (dump_fpc_stats && ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[0] > 0)) {
        for(i=0; i<NUM_ROOTS; i++)
          ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                     node_print_unknown_proto_walker, &thread_id);
      }
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
  } else if(csv_fp != NULL) {
    unsigned int i;

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                   node_print_known_proto_walker, &thread_id);
    }

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
  }

  if (serialization_fp != NULL &&
      serialization_format != ndpi_serialization_format_unknown)
    {
      unsigned int i;

      num_flows = 0;
      for(thread_id = 0; thread_id < num_threads; thread_id++) {
	for(i = 0; i < NUM_ROOTS; i++) {
	  ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		     node_print_known_proto_walker, &thread_id);
	  ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		     node_print_unknown_proto_walker, &thread_id);
	}
      }

      for(i=0; i<num_flows; i++)	
	printFlowSerialized(all_flows[i].flow);	
    }

  ndpi_free(all_flows);
}

/* *********************************************** */

/**
 * @brief Print result
 */
static void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec) {
  u_int32_t i;
  u_int32_t avg_pkt_size = 0;
  int thread_id;
  char buf[32];
  long long unsigned int breed_stats_pkts[NUM_BREEDS] = { 0 };
  long long unsigned int breed_stats_bytes[NUM_BREEDS] = { 0 };
  long long unsigned int breed_stats_flows[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
       && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
      continue;

    for(i=0; i<NUM_ROOTS; i++) {
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
                 node_proto_guess_walker, &thread_id);
      if(verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
						port_stats_walker, &thread_id);
    }

    /* Stats aggregation */
    cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].workflow->stats.raw_packet_count;
    cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].workflow->stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes;
    cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].workflow->stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].workflow->stats.total_discarded_bytes;

    for(i = 0; i < ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
      cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter[i];
      cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[i];
      cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.protocol_flows[i];

      cumulative_stats.fpc_protocol_counter[i] += ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter[i];
      cumulative_stats.fpc_protocol_counter_bytes[i] += ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_counter_bytes[i];
      cumulative_stats.fpc_protocol_flows[i] += ndpi_thread_info[thread_id].workflow->stats.fpc_protocol_flows[i];
    }

    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
    cumulative_stats.flow_count[0] += ndpi_thread_info[thread_id].workflow->stats.flow_count[0];
    cumulative_stats.flow_count[1] += ndpi_thread_info[thread_id].workflow->stats.flow_count[1];
    cumulative_stats.flow_count[2] += ndpi_thread_info[thread_id].workflow->stats.flow_count[2];
    cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
    cumulative_stats.udp_count   += ndpi_thread_info[thread_id].workflow->stats.udp_count;
    cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
    cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
    for(i = 0; i < sizeof(cumulative_stats.packet_len)/sizeof(cumulative_stats.packet_len[0]); i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;

    cumulative_stats.dpi_packet_count[0] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[0];
    cumulative_stats.dpi_packet_count[1] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[1];
    cumulative_stats.dpi_packet_count[2] += ndpi_thread_info[thread_id].workflow->stats.dpi_packet_count[2];

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++)
      cumulative_stats.flow_confidence[i] += ndpi_thread_info[thread_id].workflow->stats.flow_confidence[i];

    for(i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence)/sizeof(cumulative_stats.fpc_flow_confidence[0]); i++)
      cumulative_stats.fpc_flow_confidence[i] += ndpi_thread_info[thread_id].workflow->stats.fpc_flow_confidence[i];

    cumulative_stats.num_dissector_calls += ndpi_thread_info[thread_id].workflow->stats.num_dissector_calls;

    /* LRU caches */
    for(i = 0; i < NDPI_LRUCACHE_MAX; i++) {
      struct ndpi_lru_cache_stats s;
      int scope;
      char param[64];

      snprintf(param, sizeof(param), "lru.%s.scope", ndpi_lru_cache_idx_to_name(i));
      if(ndpi_get_config(ndpi_thread_info[thread_id].workflow->ndpi_struct, NULL, param, buf, sizeof(buf)) != NULL) {
        scope = atoi(buf);
	if(scope == NDPI_LRUCACHE_SCOPE_LOCAL ||
           (scope == NDPI_LRUCACHE_SCOPE_GLOBAL && thread_id == 0)) {
          ndpi_get_lru_cache_stats(ndpi_thread_info[thread_id].workflow->g_ctx,
                                   ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
          cumulative_stats.lru_stats[i].n_insert += s.n_insert;
          cumulative_stats.lru_stats[i].n_search += s.n_search;
          cumulative_stats.lru_stats[i].n_found += s.n_found;
	}
      }
    }

    /* Automas */
    for(i = 0; i < NDPI_AUTOMA_MAX; i++) {
      struct ndpi_automa_stats s;
      ndpi_get_automa_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
      cumulative_stats.automa_stats[i].n_search += s.n_search;
      cumulative_stats.automa_stats[i].n_found += s.n_found;
    }

    /* Patricia trees */
    for(i = 0; i < NDPI_PTREE_MAX; i++) {
      struct ndpi_patricia_tree_stats s;
      ndpi_get_patricia_stats(ndpi_thread_info[thread_id].workflow->ndpi_struct, i, &s);
      cumulative_stats.patricia_stats[i].n_search += s.n_search;
      cumulative_stats.patricia_stats[i].n_found += s.n_found;
    }
  }

  if(cumulative_stats.total_wire_bytes == 0)
    goto free_stats;

  if(!quiet_mode) {
    printf("\nnDPI Memory statistics:\n");
    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(ndpi_get_ndpi_detection_module_size(), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(ndpi_detection_get_sizeof_ndpi_flow_struct(), buf, sizeof(buf)));
    printf("\tActual Memory:           %-13s\n", formatBytes(current_ndpi_memory, buf, sizeof(buf)));
    printf("\tPeak Memory:             %-13s\n", formatBytes(max_ndpi_memory, buf, sizeof(buf)));
    printf("\tSetup Time:              %lu msec\n", (unsigned long)(setup_time_usec/1000));
    printf("\tPacket Processing Time:  %lu msec\n", (unsigned long)(processing_time_usec/1000));

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
      {
	avg_pkt_size = (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count);
      }
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

    if(processing_time_usec > 0) {
      char buf[32], buf1[32], when[64];
      float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)processing_time_usec;
      float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)processing_time_usec;
      float traffic_duration;
      struct tm result;

      if(live_capture) traffic_duration = processing_time_usec;
      else traffic_duration = ((u_int64_t)pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - ((u_int64_t)pcap_start.tv_sec*1000000 + pcap_start.tv_usec);

      printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      if(traffic_duration != 0) {
	t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
	b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;
      } else {
	t = 0;
	b = 0;
      }
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
      time_t tv_sec = pcap_start.tv_sec;
      struct tm * tm_ptr = localtime(&tv_sec);
      result = *tm_ptr;
#else
      localtime_r(&pcap_start.tv_sec, &result);
#endif
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis begin:        %s\n", when);
#ifdef WIN32
      /* localtime() on Windows is thread-safe */
      tv_sec = pcap_end.tv_sec;
      tm_ptr = localtime(&tv_sec);
      result = *tm_ptr;
#else
      localtime_r(&pcap_end.tv_sec, &result);
#endif
      strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", &result);
      printf("\tAnalysis end:          %s\n", when);
      printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
    }

    if(cumulative_stats.guessed_flow_protocols)
      printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);

    if(cumulative_stats.flow_count[0])
      printf("\tDPI Packets (TCP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[0],
	     cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    if(cumulative_stats.flow_count[1])
      printf("\tDPI Packets (UDP):     %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[1],
	     cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    if(cumulative_stats.flow_count[2])
      printf("\tDPI Packets (other):   %-13llu (%.2f pkts/flow)\n",
	     (long long unsigned int)cumulative_stats.dpi_packet_count[2],
	     cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++) {
      if(cumulative_stats.flow_confidence[i] != 0)
	printf("\tConfidence: %-10s %-13llu (flows)\n", ndpi_confidence_get_name(i),
	       (long long unsigned int)cumulative_stats.flow_confidence[i]);
    }

    if(dump_fpc_stats) {
      for(i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence)/sizeof(cumulative_stats.fpc_flow_confidence[0]); i++) {
        if(cumulative_stats.fpc_flow_confidence[i] != 0)
          printf("\tFPC Confidence: %-10s %-13llu (flows)\n", ndpi_fpc_confidence_get_name(i),
                 (long long unsigned int)cumulative_stats.fpc_flow_confidence[i]);
      }
    }

    if(dump_internal_stats) {
      char buf[1024];

      if(cumulative_stats.ndpi_flow_count)
	printf("\tNum dissector calls:   %-13llu (%.2f diss/flow)\n",
	       (long long unsigned int)cumulative_stats.num_dissector_calls,
	       cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);

      printf("\tLRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      printf("\tLRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      printf("\tLRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      printf("\tLRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      printf("\tLRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      printf("\tLRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      printf("\tLRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
	     (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

      printf("\tAutoma host:          %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      printf("\tAutoma domain:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      printf("\tAutoma tls cert:      %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      printf("\tAutoma risk mask:     %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      printf("\tAutoma common alpns:  %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
	     (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      printf("\tPatricia risk mask:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      printf("\tPatricia risk mask IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      printf("\tPatricia risk:        %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      printf("\tPatricia risk IPv6:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      printf("\tPatricia protocols:   %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      printf("\tPatricia protocols IPv6: %llu/%llu (search/found)\n",
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
	     (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      if(enable_malloc_bins)
	printf("\tData-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
    }
  }

  if(results_file) {
    if(cumulative_stats.guessed_flow_protocols)
      fprintf(results_file, "Guessed flow protos:\t%u\n\n", cumulative_stats.guessed_flow_protocols);

    if(cumulative_stats.flow_count[0])
      fprintf(results_file, "DPI Packets (TCP):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[0],
	      cumulative_stats.dpi_packet_count[0] / (float)cumulative_stats.flow_count[0]);
    if(cumulative_stats.flow_count[1])
      fprintf(results_file, "DPI Packets (UDP):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[1],
	      cumulative_stats.dpi_packet_count[1] / (float)cumulative_stats.flow_count[1]);
    if(cumulative_stats.flow_count[2])
      fprintf(results_file, "DPI Packets (other):\t%llu\t(%.2f pkts/flow)\n",
	      (long long unsigned int)cumulative_stats.dpi_packet_count[2],
	      cumulative_stats.dpi_packet_count[2] / (float)cumulative_stats.flow_count[2]);

    for(i = 0; i < sizeof(cumulative_stats.flow_confidence)/sizeof(cumulative_stats.flow_confidence[0]); i++) {
      if(cumulative_stats.flow_confidence[i] != 0)
	fprintf(results_file, "Confidence %-17s: %llu (flows)\n",
		ndpi_confidence_get_name(i),
		(long long unsigned int)cumulative_stats.flow_confidence[i]);
    }

    if(dump_fpc_stats) {
      for(i = 0; i < sizeof(cumulative_stats.fpc_flow_confidence)/sizeof(cumulative_stats.fpc_flow_confidence[0]); i++) {
        if(cumulative_stats.fpc_flow_confidence[i] != 0)
          fprintf(results_file, "FPC Confidence %-17s: %llu (flows)\n",
                  ndpi_fpc_confidence_get_name(i),
                  (long long unsigned int)cumulative_stats.fpc_flow_confidence[i]);
      }
    }

    if(dump_internal_stats) {
      char buf[1024];

      if(cumulative_stats.ndpi_flow_count)
	fprintf(results_file, "Num dissector calls: %llu (%.2f diss/flow)\n",
		(long long unsigned int)cumulative_stats.num_dissector_calls,
		cumulative_stats.num_dissector_calls / (float)cumulative_stats.ndpi_flow_count);

      fprintf(results_file, "LRU cache ookla:      %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_OOKLA].n_found);
      fprintf(results_file, "LRU cache bittorrent: %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_BITTORRENT].n_found);
      fprintf(results_file, "LRU cache stun:       %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_STUN].n_found);
      fprintf(results_file, "LRU cache tls_cert:   %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_TLS_CERT].n_found);
      fprintf(results_file, "LRU cache mining:     %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MINING].n_found);
      fprintf(results_file, "LRU cache msteams:    %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_MSTEAMS].n_found);
      fprintf(results_file, "LRU cache fpc_dns:    %llu/%llu/%llu (insert/search/found)\n",
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_insert,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_search,
	      (long long unsigned int)cumulative_stats.lru_stats[NDPI_LRUCACHE_FPC_DNS].n_found);

      fprintf(results_file, "Automa host:          %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_HOST].n_found);
      fprintf(results_file, "Automa domain:        %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_DOMAIN].n_found);
      fprintf(results_file, "Automa tls cert:      %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_TLS_CERT].n_found);
      fprintf(results_file, "Automa risk mask:     %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_RISK_MASK].n_found);
      fprintf(results_file, "Automa common alpns:  %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_search,
	      (long long unsigned int)cumulative_stats.automa_stats[NDPI_AUTOMA_COMMON_ALPNS].n_found);

      fprintf(results_file, "Patricia risk mask:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK].n_found);
      fprintf(results_file, "Patricia risk mask IPv6: %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK_MASK6].n_found);
      fprintf(results_file, "Patricia risk:        %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK].n_found);
      fprintf(results_file, "Patricia risk IPv6:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_RISK6].n_found);
      fprintf(results_file, "Patricia protocols:   %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS].n_found);
      fprintf(results_file, "Patricia protocols IPv6: %llu/%llu (search/found)\n",
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_search,
	      (long long unsigned int)cumulative_stats.patricia_stats[NDPI_PTREE_PROTOCOLS6].n_found);

      if(enable_malloc_bins)
        fprintf(results_file, "Data-path malloc histogram: %s\n", ndpi_print_bin(&malloc_bins, 0, buf, sizeof(buf)));
    }

    fprintf(results_file, "\n");
  }

  if(!quiet_mode) printf("\n\nDetected protocols:\n");
  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
    ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct,
                                                       ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i));

    if(cumulative_stats.protocol_counter[i] > 0 ||
       (dump_fpc_stats && cumulative_stats.fpc_protocol_counter[i] > 0)) {
      breed_stats_bytes[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];
      breed_stats_pkts[breed] += (long long unsigned int)cumulative_stats.protocol_counter[i];
      breed_stats_flows[breed] += (long long unsigned int)cumulative_stats.protocol_flows[i];

      if(results_file) {
	fprintf(results_file, "%s\t%llu\t%llu\t%u",
		ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct,
				    ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i)),
		(long long unsigned int)cumulative_stats.protocol_counter[i],
		(long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
		cumulative_stats.protocol_flows[i]);
	if(dump_fpc_stats) {
	  fprintf(results_file, "\t%llu\t%llu\t%u",
                  (long long unsigned int)cumulative_stats.fpc_protocol_counter[i],
                  (long long unsigned int)cumulative_stats.fpc_protocol_counter_bytes[i],
	          cumulative_stats.fpc_protocol_flows[i]);
	  if(cumulative_stats.protocol_counter[i] != cumulative_stats.fpc_protocol_counter[i] ||
	     cumulative_stats.protocol_counter_bytes[i] != cumulative_stats.fpc_protocol_counter_bytes[i] ||
	     cumulative_stats.protocol_flows[i] != cumulative_stats.fpc_protocol_flows[i])
	    fprintf(results_file, "\t(*)");
	}
	fprintf(results_file, "\n");
      }

      if(!quiet_mode) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u",
	       ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct,
				   ndpi_map_ndpi_id_to_user_proto_id(ndpi_thread_info[0].workflow->ndpi_struct, i)),
	       (long long unsigned int)cumulative_stats.protocol_counter[i],
	       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	       cumulative_stats.protocol_flows[i]);
	if(dump_fpc_stats) {
	  printf(" FPC packets: %-13llu FPC bytes: %-13llu "
	         "FPC flows: %-13u",
	         (long long unsigned int)cumulative_stats.fpc_protocol_counter[i],
	         (long long unsigned int)cumulative_stats.fpc_protocol_counter_bytes[i],
	         cumulative_stats.fpc_protocol_flows[i]);
	  if(cumulative_stats.protocol_counter[i] != cumulative_stats.fpc_protocol_counter[i] ||
	     cumulative_stats.protocol_counter_bytes[i] != cumulative_stats.fpc_protocol_counter_bytes[i] ||
	     cumulative_stats.protocol_flows[i] != cumulative_stats.fpc_protocol_flows[i])
	    printf("(*)");
	}
	printf("\n");
      }
    }
  }
  if(!quiet_mode && dump_fpc_stats) {
    printf("\n\tNOTE: protocols with different standard and FPC statistics are marked\n");
  }

  if(!quiet_mode) {
    printf("\n\nProtocol statistics:\n");

    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats_pkts[i] > 0) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13llu\n",
	       ndpi_get_proto_breed_name(i),
	       breed_stats_pkts[i], breed_stats_bytes[i], breed_stats_flows[i]);
      }
    }
  }
  if(results_file) {
    fprintf(results_file, "\n");
    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats_pkts[i] > 0) {
	fprintf(results_file, "%-20s %13llu %-13llu %-13llu\n",
	        ndpi_get_proto_breed_name(i),
	        breed_stats_pkts[i], breed_stats_bytes[i], breed_stats_flows[i]);
      }
    }
  }

  printRiskStats();
  printFlowsStats();

  if(stats_flag || verbose == 3) {
    HASH_SORT(srcStats, port_stats_sort);
    HASH_SORT(dstStats, port_stats_sort);
  }

  if(verbose == 3) {
    printf("\n\nSource Ports Stats:\n");
    printPortStats(srcStats);

    printf("\nDestination Ports Stats:\n");
    printPortStats(dstStats);
  }

 free_stats:
  if(scannerHosts) {
    deleteScanners(scannerHosts);
    scannerHosts = NULL;
  }

  if(receivers) {
    deleteReceivers(receivers);
    receivers = NULL;
  }

  if(topReceivers) {
    deleteReceivers(topReceivers);
    topReceivers = NULL;
  }

  if(srcStats) {
    deletePortsStats(srcStats);
    srcStats = NULL;
  }

  if(dstStats) {
    deletePortsStats(dstStats);
    dstStats = NULL;
  }
}

/**
 * @brief Force a pcap_dispatch() or pcap_loop() call to return
 */
static void breakPcapLoop(u_int16_t thread_id) {
#ifdef USE_DPDK
  dpdk_run_capture = 0;
#else
  if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
  }
#endif
}

/**
 * @brief Sigproc is executed for each packet in the pcap file
 */
void sigproc(int sig) {

  static int called = 0;
  int thread_id;

  (void)sig;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}


#ifndef USE_DPDK

/**
 * @brief Get the next pcap file from a passed playlist
 */
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

/**
 * @brief Configure the pcap handle
 */
static void configurePcapHandle(pcap_t * pcap_handle) {
  if(!pcap_handle)
    return;
  
  if(bpfFilter != NULL) {
    if(!bpf_cfilter) {
      if(pcap_compile(pcap_handle, &bpf_code, bpfFilter, 1, 0xFFFFFF00) < 0) {
	printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
	return;
      }
      bpf_cfilter = &bpf_code;
    }
    
    if(pcap_setfilter(pcap_handle, bpf_cfilter) < 0) {
      printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
    } else {
      printf("Successfully set BPF filter to '%s'\n", bpfFilter);
    }
  }
}

#endif

/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) {
#ifndef USE_DPDK
  u_int snaplen = 1536;
  int promisc = 1;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif
  pcap_t * pcap_handle = NULL;

  /* trying to open a live interface */
#ifdef USE_DPDK
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
							  MBUF_CACHE_SIZE, 0,
							  RTE_MBUF_DEFAULT_BUF_SIZE,
							  rte_socket_id());

  if(mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: are hugepages ok?\n");

  if(dpdk_port_init(dpdk_port_id, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "DPDK: Cannot init port %u: please see README.dpdk\n", dpdk_port_id);
#else
  /* Trying to open the interface */
  if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
				   promisc, 500, pcap_error_buffer)) == NULL) {
    capture_for = capture_until = 0;

    live_capture = 0;
    num_threads = 1; /* Open pcap files in single threads mode */

    /* Trying to open a pcap file */
    if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
      char filename[256] = { 0 };

      if(strstr((char*)pcap_file, (char*)".pcap"))
	printf("ERROR: could not open pcap file: %s\n", pcap_error_buffer);

      /* Trying to open as a playlist as last attempt */
      else if((getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0)
	      || ((pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL)) {
	/* This probably was a bad interface name, printing a generic error */
	printf("ERROR: could not open %s: %s\n", filename, pcap_error_buffer);
	exit(-1);
      } else {
	if(!quiet_mode)
	  printf("Reading packets from playlist %s...\n", pcap_file);
      }
    } else {
      if(!quiet_mode)
	printf("Reading packets from pcap file %s...\n", pcap_file);
    }
  } else {
    live_capture = 1;

    if(!quiet_mode) {
#ifdef USE_DPDK
      printf("Capturing from DPDK (port 0)...\n");
#else
      printf("Capturing live traffic from device %s...\n", pcap_file);
#endif
    }
  }

  configurePcapHandle(pcap_handle);
#endif /* !DPDK */

  if(capture_for > 0) {
    if(!quiet_mode)
      printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_for);

#ifndef WIN32
    alarm(capture_for);
    signal(SIGALRM, sigproc);
#endif
  }

  return pcap_handle;
}

/**
 * @brief Check pcap packet
 */
static void ndpi_process_packet(u_char *args,
				const struct pcap_pkthdr *header,
				const u_char *packet) {
  struct ndpi_proto p;
  ndpi_risk flow_risk;
  struct ndpi_flow_info *flow;
  u_int16_t thread_id = *((u_int16_t*)args);

  /* allocate an exact size buffer to check overflows */
  uint8_t *packet_checked = ndpi_malloc(header->caplen);

  if(packet_checked == NULL) {
    return ;
  }

  memcpy(packet_checked, packet, header->caplen);
  p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked, &flow_risk, &flow);

  if(!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
  pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

  /* Idle flows cleanup */
  if(live_capture) {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time) {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		 node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while(ndpi_thread_info[thread_id].num_idle_flows > 0) {
	/* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
	ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
		     &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		     ndpi_workflow_node_cmp);

	/* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
	ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
	ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
      }

      if(++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots)
	ndpi_thread_info[thread_id].idle_scan_idx = 0;

      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].workflow->last_time;
    }
  }

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Found %u bytes packet %u.%u\n", header->caplen, p.proto.app_protocol, p.proto.master_protocol);
#endif

  if(extcap_dumper
     && ((extcap_packet_filter == (u_int16_t)-1)
	 || (p.proto.app_protocol == extcap_packet_filter)
	 || (p.proto.master_protocol == extcap_packet_filter)
	 )
     ) {
    struct pcap_pkthdr h;
    u_int32_t *crc, delta = sizeof(struct ndpi_packet_trailer);
    struct ndpi_packet_trailer *trailer;
    u_int16_t cli_score, srv_score;

    memcpy(&h, header, sizeof(h));

    if(extcap_add_crc)
      delta += 4; /* ethernet trailer */

    if(h.caplen > (sizeof(extcap_buf) - delta)) {
      printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
      h.caplen = sizeof(extcap_buf) - delta;
    }

    trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
    memcpy(extcap_buf, packet, h.caplen);
    memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
    trailer->magic = htonl(WIRESHARK_NTOP_MAGIC);
    if(flow) {
      trailer->flags = flow->current_pkt_from_client_to_server;
      trailer->flags |= (flow->detection_completed << 2);
    } else {
      trailer->flags = 0 | (2 << 2);
    }
    trailer->flow_risk = htonl64(flow_risk);
    trailer->flow_score = htons(ndpi_risk2score(flow_risk, &cli_score, &srv_score));
    trailer->flow_risk_info_len = ntohs(WIRESHARK_FLOW_RISK_INFO_SIZE);
    if(flow && flow->risk_str) {
      strncpy(trailer->flow_risk_info, flow->risk_str, sizeof(trailer->flow_risk_info));
    }
    trailer->flow_risk_info[sizeof(trailer->flow_risk_info) - 1] = '\0';
    trailer->proto.master_protocol = htons(p.proto.master_protocol), trailer->proto.app_protocol = htons(p.proto.app_protocol);
    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));

    /* Metadata */
    /* Metadata are (all) available in `flow` only after nDPI completed its work!
       We export them only once */
    /* TODO: boundary check. Right now there is always enough room, but we should check it if we are
       going to extend the list of the metadata exported */
    trailer->metadata_len = ntohs(WIRESHARK_METADATA_SIZE);
    struct ndpi_packet_tlv *tlv = (struct ndpi_packet_tlv *)trailer->metadata;
    int tot_len = 0;
    if(flow && flow->detection_completed == 1) {
      if(flow->host_server_name[0] != '\0') {
        tlv->type = ntohs(WIRESHARK_METADATA_SERVERNAME);
        tlv->length = ntohs(sizeof(flow->host_server_name));
        memcpy(tlv->data, flow->host_server_name, sizeof(flow->host_server_name));
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }
      if(flow->ssh_tls.ja4_client[0] != '\0') {
        tlv->type = ntohs(WIRESHARK_METADATA_JA4C);
        tlv->length = ntohs(sizeof(flow->ssh_tls.ja4_client));
        memcpy(tlv->data, flow->ssh_tls.ja4_client, sizeof(flow->ssh_tls.ja4_client));
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }
      if(flow->ssh_tls.obfuscated_heur_matching_set.pkts[0] != 0) {
        tlv->type = ntohs(WIRESHARK_METADATA_TLS_HEURISTICS_MATCHING_FINGERPRINT);
        tlv->length = ntohs(sizeof(struct ndpi_tls_obfuscated_heuristic_matching_set));
        struct ndpi_tls_obfuscated_heuristic_matching_set *s =  (struct ndpi_tls_obfuscated_heuristic_matching_set *)tlv->data;
        s->bytes[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[0]);
        s->bytes[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[1]);
        s->bytes[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[2]);
        s->bytes[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.bytes[3]);
        s->pkts[0] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[0]);
        s->pkts[1] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[1]);
        s->pkts[2] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[2]);
        s->pkts[3] = ntohl(flow->ssh_tls.obfuscated_heur_matching_set.pkts[3]);
        /* TODO: boundary check */
        tot_len += 4 + htons(tlv->length);
        tlv = (struct ndpi_packet_tlv *)&trailer->metadata[tot_len];
      }

      flow->detection_completed = 2; /* Avoid exporting metadata again.
                                        If we really want to have the metadata on Wireshark for *all*
                                        the future packets of this flow, simply remove that assignment */
    }
    /* Last: padding */
    tlv->type = 0;
    tlv->length = ntohs(WIRESHARK_METADATA_SIZE - tot_len - 4);
    /* The remaining bytes are already set to 0 */

    if(extcap_add_crc) {
      crc = (uint32_t*)&extcap_buf[h.caplen+sizeof(struct ndpi_packet_trailer)];
      *crc = ndpi_crc32((const void*)extcap_buf, h.caplen+sizeof(struct ndpi_packet_trailer), 0);
    }
    h.caplen += delta, h.len += delta;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Dumping %u bytes packet\n", h.caplen);
#endif

    pcap_dump((u_char*)extcap_dumper, &h, (const u_char *)extcap_buf);
    pcap_dump_flush(extcap_dumper);
  }

  /* check for buffer changes */
  if(memcmp(packet, packet_checked, header->caplen) != 0)
    printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu, caplen=%u]\n",
	   thread_id, (unsigned long)ndpi_thread_info[thread_id].workflow->stats.raw_packet_count, header->caplen);

  if((u_int32_t)(pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
    unsigned int i;
    u_int64_t processing_time_usec, setup_time_usec;

    gettimeofday(&end, NULL);
    processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

    printResults(processing_time_usec, setup_time_usec);

    for(i=0; i<ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
      ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
      ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

      memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
    }

    if(!quiet_mode)
      printf("\n-------------------------------------------\n\n");

    memcpy(&begin, &end, sizeof(begin));
    memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
  }

  /*
    Leave the free as last statement to avoid crashes when ndpi_detection_giveup()
    is called above by printResults()
  */
  if(packet_checked) {
    ndpi_free(packet_checked);
    packet_checked = NULL;
  }
}

#ifndef USE_DPDK
/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)) {
    int datalink_type = pcap_datalink(ndpi_thread_info[thread_id].workflow->pcap_handle);

    /* When using as extcap interface, the output/dumper pcap must have the same datalink
       type of the input traffic [to be able to use, for example, input pcaps with
       Linux "cooked" capture encapsulation (i.e. captured with "any" interface...) where
       there isn't an ethernet header] */
    if(do_extcap_capture) {
      extcap_capture(datalink_type);
      if(datalink_type == DLT_EN10MB)
        extcap_add_crc = 1;
    }

    if(!ndpi_is_datalink_supported(datalink_type)) {
      printf("Unsupported datalink %d. Skip pcap\n", datalink_type);
      return;
    }
    int ret = pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndpi_process_packet, (u_char*)&thread_id);
    if (ret == -1)
      printf("Error while reading pcap file: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id].workflow->pcap_handle));
  }
}
#endif

/**
 * @brief Process a running thread
 */
void * processing_thread(void *_thread_id) {
#ifdef WIN64
  long long int thread_id = (long long int)_thread_id;
#else
  long int thread_id = (long int)_thread_id;
#endif
#ifndef USE_DPDK
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
#endif

#if defined(__linux__) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
  if(core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else {
      if(!quiet_mode) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  } else
#endif
    if((!quiet_mode)) {
#ifdef WIN64
      printf("Running thread %lld...\n", thread_id);
#else
      printf("Running thread %ld...\n", thread_id);
#endif
    }

#ifdef USE_DPDK
  while(dpdk_run_capture) {
    struct rte_mbuf *bufs[BURST_SIZE];
    u_int16_t num = rte_eth_rx_burst(dpdk_port_id, 0, bufs, BURST_SIZE);
    u_int i;

    if(num == 0) {
      usleep(1);
      continue;
    }

    for(i = 0; i < PREFETCH_OFFSET && i < num; i++)
      rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

    for(i = 0; i < num; i++) {
      char *data = rte_pktmbuf_mtod(bufs[i], char *);
      int len = rte_pktmbuf_pkt_len(bufs[i]);
      struct pcap_pkthdr h;

      h.len = h.caplen = len;
      gettimeofday(&h.ts, NULL);

      ndpi_process_packet((u_char*)&thread_id, &h, (const u_char *)data);
      rte_pktmbuf_free(bufs[i]);
    }
  }
#else
 pcap_loop:
  runPcapLoop(thread_id);

  if(ndpi_thread_info[thread_id].workflow->pcap_handle)
    pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

  ndpi_thread_info[thread_id].workflow->pcap_handle = NULL;

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
      configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }
#endif
  if(bpf_cfilter) {
    pcap_freecode(bpf_cfilter);
    bpf_cfilter = NULL;
  }

  return NULL;
}

/* ***************************************************** */

/**
 * @brief Begin, process, end detection process
 */
void test_lib() {
  u_int64_t processing_time_usec, setup_time_usec;
#ifdef WIN64
  long long int thread_id;
#else
  long thread_id;
#endif
  struct ndpi_global_context *g_ctx;

  set_ndpi_malloc(ndpi_malloc_wrapper), set_ndpi_free(free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

#ifndef USE_GLOBAL_CONTEXT
  /* ndpiReader works even if libnDPI has been compiled without global context support,
     but you can't configure any cache with global scope */
  g_ctx = NULL;
#else
  g_ctx = ndpi_global_init();
  if(!g_ctx) {
    fprintf(stderr, "Error ndpi_global_init\n");
    exit(-1);
  }
#endif

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
#endif

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    pcap_t *cap;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

    cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
    setupDetection(thread_id, cap, g_ctx);
  }

  gettimeofday(&begin, NULL);

  int status;
  void * thd_res;

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    /* check pthreade_create return value */
    if(status != 0) {
#ifdef WIN64
      fprintf(stderr, "error on create %lld thread\n", thread_id);
#else
      fprintf(stderr, "error on create %ld thread\n", thread_id);
#endif
      exit(-1);
    }
  }
  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
    /* check pthreade_join return value */
    if(status != 0) {
#ifdef WIN64
      fprintf(stderr, "error on join %lld thread\n", thread_id);
#else
      fprintf(stderr, "error on join %ld thread\n", thread_id);
#endif
      exit(-1);
    }
    if(thd_res != NULL) {
#ifdef WIN64
      fprintf(stderr, "error on returned value of %lld joined thread\n", thread_id);
#else
      fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
#endif
      exit(-1);
    }
  }

#ifdef USE_DPDK
  dpdk_port_deinit(dpdk_port_id);
#endif

  gettimeofday(&end, NULL);
  processing_time_usec = (u_int64_t)end.tv_sec*1000000 + end.tv_usec - ((u_int64_t)begin.tv_sec*1000000 + begin.tv_usec);
  setup_time_usec = (u_int64_t)begin.tv_sec*1000000 + begin.tv_usec - ((u_int64_t)startup_time.tv_sec*1000000 + startup_time.tv_usec);

  /* Printing cumulative results */
  printResults(processing_time_usec, setup_time_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    terminateDetection(thread_id);
  }

  ndpi_global_deinit(g_ctx);
}

/* *********************************************** */

#if 0
static void binUnitTest() {
  struct ndpi_bin *bins, b0, b1;
  u_int8_t num_bins = 32;
  u_int8_t num_points = 24;
  u_int32_t i, j;
  u_int8_t num_clusters = 3;
  u_int16_t cluster_ids[256];
  char out_buf[128];

  srand(time(NULL));

  assert((bins = (struct ndpi_bin*)ndpi_malloc(sizeof(struct ndpi_bin)*num_bins)) != NULL);

  for(i=0; i<num_bins; i++) {
    ndpi_init_bin(&bins[i], ndpi_bin_family8, num_points);

    for(j=0; j<num_points; j++)
      ndpi_set_bin(&bins[i], j, rand() % 0xFF);

    ndpi_normalize_bin(&bins[i]);
  }

  ndpi_cluster_bins(bins, num_bins, num_clusters, cluster_ids, NULL);

  for(j=0; j<num_clusters; j++) {
    if(verbose) printf("\n");

    for(i=0; i<num_bins; i++) {
      if(cluster_ids[i] == j) {
	if(verbose)
	  printf("[%u] %s\n", cluster_ids[i],
		 ndpi_print_bin(&bins[i], 0, out_buf, sizeof(out_buf)));
      }
    }
  }
  // printf("Similarity: %f\n\n", ndpi_bin_similarity(&b1, &b2, 1));

  for(i=0; i<num_bins; i++)
    ndpi_free_bin(&bins[i]);

  ndpi_free(bins);

  /* ************************ */

  ndpi_init_bin(&b0, ndpi_bin_family8, 16);
  ndpi_init_bin(&b1, ndpi_bin_family8, 16);

  ndpi_set_bin(&b0, 1, 100);
  ndpi_set_bin(&b1, 1, 100);

  printf("Similarity: %f\n\n", ndpi_bin_similarity(&b0, &b1, 1));

  ndpi_free_bin(&b0), ndpi_free_bin(&b1);

  // exit(0);
}
#endif

/* *********************************************** */

#ifndef DEBUG_TRACE

static void dgaUnitTest() {
  const char *dga[] = {
    //"www.lbjamwptxz.com",
    "www.l54c2e21e80ba5471be7a8402cffb98768.so",
    "www.wdd7ee574106a84807a601beb62dd851f0.hk",
    "www.jaa12148a5831a5af92aa1d8fe6059e276.ws",
    "www.e6r5p57kbafwrxj3plz.com",
    // "grdawgrcwegpjaoo.eu",
    "www.mcfpeqbotiwxfxqu.eu",
    "www.adgxwxhqsegnrsih.eu",
    NULL
  };

  const char *non_dga[] = {
    "mail.100x100design.com",
    "cdcvps.cloudapps.cisco.com",
    "vcsa.vmware.com",
    "mz.gov.pl",
    "zoomam104zc.zoom.us",
    "5CI_DOMBIN",
    "ALICEGATE",
    "BOWIE",
    "D002465",
    "DESKTOP-RB5T12G",
    "ECI_DOM",
    "ECI_DOMA",
    "ECI_DOMAIN",
    "ENDIAN-PC",
    "GFILE",
    "GIOVANNI-PC",
    "GUNNAR",
    "ISATAP",
    "LAB111",
    "LP-RKERUR-OSX",
    "LUCAS-IMAC",
    "LUCASMACBOOKPRO",
    "MACBOOKAIR-E1D0",
    //"MDJR98",
    "NASFILE",
    "SANJI-LIFEBOOK-",
    "SC.ARRANCAR.ORG",
    "WORKG",
    "WORKGROUP",
    "XSTREAM_HY",
    "__MSBROWSE__",
    "mqtt.facebook.com",
    NULL
  };
  int debug = 0, i;
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);

  assert(ndpi_str != NULL);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  ndpi_finalize_initialization(ndpi_str);

  assert(ndpi_str != NULL);

  for(i=0; non_dga[i] != NULL; i++) {
    if(debug) printf("Checking non DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)non_dga[i], 1, 1) == 0);
  }

  for(i=0; dga[i] != NULL; i++) {
    if(debug) printf("Checking DGA %s\n", non_dga[i]);
    assert(ndpi_check_dga_name(ndpi_str, NULL, (char*)dga[i], 1, 1) == 1);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

static void hllUnitTest() {
  struct ndpi_hll h;
  u_int8_t bits = 8; /* >= 4, <= 16 */
  u_int32_t i;

  assert(ndpi_hll_init(&h, bits) == 0);

  for(i=0; i<21320; i++)
    ndpi_hll_add_number(&h, i);

  /* printf("Count estimate: %f\n", ndpi_hll_count(&h)); */

  ndpi_hll_destroy(&h);
}

/* *********************************************** */

static void bitmapUnitTest() {
  u_int32_t val, i, j;
  u_int64_t val64;

  /* With a 32 bit integer */
  for(i=0; i<32; i++) {
    NDPI_ZERO_BIT(val);
    NDPI_SET_BIT(val, i);

    assert(NDPI_ISSET_BIT(val, i));

    for(j=0; j<32; j++) {
      if(j != i) {
	assert(!NDPI_ISSET_BIT(val, j));
      }
    }
  }

  /* With a 64 bit integer */
  for(i=0; i<64; i++) {
    NDPI_ZERO_BIT(val64);
    NDPI_SET_BIT(val64, i);

    assert(NDPI_ISSET_BIT(val64, i));

    for(j=0; j<64; j++) {
      if(j != i) {
	assert(!NDPI_ISSET_BIT(val64, j));
      }
    }
  }
}

/* *********************************************** */

void automataUnitTest() {
  void *automa = ndpi_init_automa();

  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("hello")) == 0);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("world")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 1);
  ndpi_free_automa(automa);
}

/* *********************************************** */

void automataDomainsUnitTest() {
  void *automa = ndpi_init_automa_domain();

  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("wikipedia.it")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foo.wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foowikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foowikipedia") == 0);
  assert(ndpi_match_string(automa, "-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foo-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "wikipedia.it.com") == 0);
  ndpi_free_automa(automa);

  automa = ndpi_init_automa_domain();
  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("wikipedia.")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foo.wikipedia.it") == 1);
  assert(ndpi_match_string(automa, "foowikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foowikipedia") == 0);
  assert(ndpi_match_string(automa, "-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "foo-wikipedia.it") == 0);
  assert(ndpi_match_string(automa, "wikipediafoo") == 0);
  assert(ndpi_match_string(automa, "wikipedia.it.com") == 1);
  ndpi_free_automa(automa);

  automa = ndpi_init_automa_domain();
  assert(automa);
  assert(ndpi_add_string_to_automa(automa, ndpi_strdup("-buy.itunes.apple.com")) == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "buy.itunes.apple.com") == 0);
  assert(ndpi_match_string(automa, "p53-buy.itunes.apple.com") == 1);
  assert(ndpi_match_string(automa, "p53buy.itunes.apple.com") == 0);
  assert(ndpi_match_string(automa, "foo.p53-buy.itunes.apple.com") == 1);
  ndpi_free_automa(automa);
}

#endif

/* *********************************************** */

// #define RUN_DATA_ANALYSIS_THEN_QUIT 1

void analyzeUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++) {
    ndpi_data_add_value(s, rand() * (u_int64_t)i);
    // ndpi_data_add_value(s, i+1);
  }

  // ndpi_data_print_window_values(s);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
  printf("Average: [all: %f][window: %f]\n",
	 ndpi_data_average(s), ndpi_data_window_average(s));
  printf("Entropy: %f\n", ndpi_data_entropy(s));

  printf("Min/Max: %u/%u\n",
	 ndpi_data_min(s), ndpi_data_max(s));
#endif

  ndpi_free_data_analysis(s, 1);

#ifdef RUN_DATA_ANALYSIS_THEN_QUIT
  exit(0);
#endif
}

/* *********************************************** */

/**
 * @brief Initialize port array
 */

void bpf_filter_port_array_init(int array[], int size) {
  int i;
  for(i=0; i<size; i++)
    array[i] = INIT_VAL;
}

/* *********************************************** */
/**
 * @brief Initialize host array
 */

void bpf_filter_host_array_init(const char *array[48], int size) {
  int i;
  for(i=0; i<size; i++)
    array[i] = NULL;
}

/* *********************************************** */

/**
 * @brief Add host to host filter array
 */

void bpf_filter_host_array_add(const char *filter_array[48], int size, const char *host) {
  int i;
  int r;
  for(i=0; i<size; i++) {
    if((filter_array[i] != NULL) && (r = strcmp(filter_array[i], host)) == 0)
      return;
    if(filter_array[i] == NULL) {
      filter_array[i] = host;
      return;
    }
  }
  fprintf(stderr,"bpf_filter_host_array_add: max array size is reached!\n");
  exit(-1);
}


/* *********************************************** */

/**
 * @brief Add port to port filter array
 */

void bpf_filter_port_array_add(int filter_array[], int size, int port) {
  int i;
  for(i=0; i<size; i++) {
    if(filter_array[i] == port)
      return;
    if(filter_array[i] == INIT_VAL) {
      filter_array[i] = port;
      return;
    }
  }
  fprintf(stderr,"bpf_filter_port_array_add: max array size is reached!\n");
  exit(-1);
}

/* *********************************************** */

void analysisUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++)
    ndpi_data_add_value(s, i);

  if(0) {
    ndpi_data_print_window_values(s);
    printf("Average: [all: %f][window: %f]\n", ndpi_data_average(s), ndpi_data_window_average(s));
    printf("Entropy: %f\n", ndpi_data_entropy(s));
    printf("StdDev:  %f\n", ndpi_data_stddev(s));
    printf("Min/Max: %llu/%llu\n",
	   (unsigned long long int)ndpi_data_min(s),
	   (unsigned long long int)ndpi_data_max(s));
  }

  ndpi_free_data_analysis(s, 1);
}

/* *********************************************** */

void rsiUnitTest() {
  struct ndpi_rsi_struct s;
  unsigned int v[] = {
    31,
    87,
    173,
    213,
    223,
    230,
    238,
    245,
    251,
    151,
    259,
    261,
    264,
    264,
    270,
    273,
    288,
    288,
    304,
    304,
    350,
    384,
    423,
    439,
    445,
    445,
    445,
    445
  };

  u_int i, n = sizeof(v) / sizeof(unsigned int);
  u_int debug = 0;

  assert(ndpi_alloc_rsi(&s, 8) == 0);

  for(i=0; i<n; i++) {
    float rsi = ndpi_rsi_add_value(&s, v[i]);


    if(debug)
      printf("%2d) RSI = %f\n", i, rsi);
  }

  ndpi_free_rsi(&s);
}

/* *********************************************** */

void hashUnitTest() {
  ndpi_str_hash *h;
  char * const dict[] = { "hello", "world", NULL };
  u_int16_t i;

  assert(ndpi_hash_init(&h) == 0);
  assert(h == NULL);

  for(i=0; dict[i] != NULL; i++) {
    u_int8_t l = strlen(dict[i]);
    u_int16_t v;

    assert(ndpi_hash_add_entry(&h, dict[i], l, i) == 0);
    assert(ndpi_hash_find_entry(h, dict[i], l, &v) == 0);
    assert(v == i);
  }

  ndpi_hash_free(&h);
  assert(h == NULL);
}

/* *********************************************** */

void hwUnitTest() {
  struct ndpi_hw_struct hw;
  double v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, j, num = sizeof(v) / sizeof(double);
  u_int num_learning_points = 2;
  u_int8_t trace = 0;

  for(j=0; j<2; j++) {
    assert(ndpi_hw_init(&hw, num_learning_points, j /* 0=multiplicative, 1=additive */, 0.9, 0.9, 0.1, 0.05) == 0);

    if(trace)
      printf("\nHolt-Winters %s method\n", (j == 0) ? "multiplicative" : "additive");

    for(i=0; i<num; i++) {
      double prediction, confidence_band;
      double lower, upper;
      int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

      lower = prediction - confidence_band, upper = prediction + confidence_band;

      if(trace)
	printf("%2u)\t%.3f\t%.3f\t%.3f\t%.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	       ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	       confidence_band);
    }

    ndpi_hw_free(&hw);
  }
}

/* *********************************************** */

void hwUnitTest2() {
  struct ndpi_hw_struct hw;
  u_int8_t trace = 1;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int num_learning_points = 1;
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5, gamma = 1;
  FILE *fd = fopen("/tmp/result.csv", "w");

  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */,
		      alpha, beta, gamma, 0.05) == 0);

  if(trace) {
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_hw_free(&hw);

  //exit(0);
}

/* *********************************************** */

void sesUnitTest() {
  struct ndpi_ses_struct ses;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9;
  FILE *fd = fopen("/tmp/ses_result.csv", "w");

  assert(ndpi_ses_init(&ses, alpha, 0.05) == 0);
  ndpi_ses_reset(&ses);

  if(trace) {
    printf("\nSingle Exponential Smoothing [alpha: %.1f]\n", alpha);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_ses_add_value(&ses, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_ses_fitting(v, num, &alpha); /* Compute the best alpha */
}

/* *********************************************** */

void desUnitTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 0;
  double v[] = {
    31.908466339111,
    87.339714050293,
    173.47660827637,
    213.92568969727,
    223.32124328613,
    230.60134887695,
    238.09457397461,
    245.8137512207,
    251.09228515625,
    251.09228515625,
    259.21997070312,
    261.98754882812,
    264.78540039062,
    264.78540039062,
    270.47451782227,
    173.3671875,
    288.34222412109,
    288.34222412109,
    304.24795532227,
    304.24795532227,
    350.92227172852,
    384.54431152344,
    423.25942993164,
    439.43322753906,
    445.05981445312,
    445.05981445312,
    445.05981445312,
    445.05981445312
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.9, beta = 0.5;
  FILE *fd = fopen("/tmp/des_result.csv", "w");

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);

    if(fd)
      fprintf(fd, "index;value;prediction;lower;upper;anomaly\n");
  }

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_des_add_value(&des, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, v[i], prediction, lower, upper,
	     (rc == 0) ? "LEARNING" : (((v[i] >= lower) && (v[i] <= upper)) ? "OK" : "ANOMALY"),
	     confidence_band);

      if(fd)
	fprintf(fd, "%u;%.0f;%.0f;%.0f;%.0f;%s\n",
		i, v[i], prediction, lower, upper,
		((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY");
    }
  }

  if(fd) fclose(fd);

  ndpi_des_fitting(v, num, &alpha, &beta); /* Compute the best alpha/beta */
}

/* *********************************************** */

void desUnitStressTest() {
  struct ndpi_des_struct des;
  u_int8_t trace = 1;
  u_int i;
  float alpha = 0.9, beta = 0.5;
  double init_value = time(NULL) % 1000;

  assert(ndpi_des_init(&des, alpha, beta, 0.05) == 0);
  ndpi_des_reset(&des);

  if(trace) {
    printf("\nDouble Exponential Smoothing [alpha: %.1f][beta: %.1f]\n", alpha, beta);
  }

  for(i=0; i<512; i++) {
    double prediction, confidence_band;
    double lower, upper;
    double value = init_value + rand() % 25;
    int rc = ndpi_des_add_value(&des, value, &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace) {
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n", i, value, prediction, lower, upper,
	     ((rc == 0) || ((value >= lower) && (value <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);
    }
  }
}

/* *********************************************** */

void hwUnitTest3() {
  struct ndpi_hw_struct hw;
  u_int num_learning_points = 3;
  u_int8_t trace = 1;
  double v[] = {
    10,
    14,
    8,
    25,
    16,
    22,
    14,
    35,
    15,
    27,
    18,
    40,
    28,
    40,
    25,
    65,
  };
  u_int i, num = sizeof(v) / sizeof(double);
  float alpha = 0.5, beta = 0.5, gamma = 0.1;
  assert(ndpi_hw_init(&hw, num_learning_points, 0 /* 0=multiplicative, 1=additive */, alpha, beta, gamma, 0.05) == 0);
  ndpi_hw_reset(&hw);

  if(trace)
    printf("\nHolt-Winters [alpha: %.1f][beta: %.1f][gamma: %.1f]\n", alpha, beta, gamma);

  for(i=0; i<num; i++) {
    double prediction, confidence_band;
    double lower, upper;
    int rc = ndpi_hw_add_value(&hw, v[i], &prediction, &confidence_band);

    lower = prediction - confidence_band, upper = prediction + confidence_band;

    if(trace)
      printf("%2u)\t%12.3f\t%.3f\t%12.3f\t%12.3f\t %s [%.3f]\n",
	     i, v[i], prediction, lower, upper,
	     ((rc == 0) || ((v[i] >= lower) && (v[i] <= upper))) ? "OK" : "ANOMALY",
	     confidence_band);
  }

  ndpi_hw_free(&hw);
}

/* *********************************************** */

void jitterUnitTest() {
  struct ndpi_jitter_struct jitter;
  float v[] = { 10, 14, 8, 25, 16, 22, 14, 35, 15, 27, 218, 40, 28, 40, 25, 65 };
  u_int i, num = sizeof(v) / sizeof(float);
  u_int num_learning_points = 4;
  u_int8_t trace = 0;

  assert(ndpi_jitter_init(&jitter, num_learning_points) == 0);

  for(i=0; i<num; i++) {
    float rc = ndpi_jitter_add_value(&jitter, v[i]);

    if(trace)
      printf("%2u)\t%.3f\t%.3f\n", i, v[i], rc);
  }

  ndpi_jitter_free(&jitter);
}

/* *********************************************** */

void compressedBitmapUnitTest() {
  ndpi_bitmap *b = ndpi_bitmap_alloc(), *b1;
  u_int i, trace = 0;
  size_t ser;
  char *buf;
  ndpi_bitmap_iterator *it;
  u_int64_t value;

  for(i=0; i<1000; i++) {
    u_int32_t v = rand();

    if(trace) printf("%u ", v);
    ndpi_bitmap_set(b, v);
    assert(ndpi_bitmap_isset(b, v));
  }

  if(trace) printf("\n");

  ser = ndpi_bitmap_serialize(b, &buf);
  assert(ser > 0);

  if(trace) printf("len: %u\n", (unsigned int)ser);
  b1 = ndpi_bitmap_deserialize(buf, ser);
  assert(b1);

  assert((it = ndpi_bitmap_iterator_alloc(b)));
  while(ndpi_bitmap_iterator_next(it, &value)) {
    if(trace) printf("%lu ", (unsigned long)value);
  }

  if(trace) printf("\n");
  ndpi_bitmap_iterator_free(it);

  ndpi_free(buf);
  ndpi_bitmap_free(b);
  ndpi_bitmap_free(b1);
}

/* *********************************************** */

void strtonumUnitTest() {
  const char *errstrp;

  assert(ndpi_strtonum("0", -10, +10, &errstrp, 10) == 0);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("0", +10, -10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
  assert(ndpi_strtonum("  -11  ", -10, +10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
  assert(ndpi_strtonum("  -11  ", -100, +100, &errstrp, 10) == -11);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("123abc", LLONG_MIN, LLONG_MAX, &errstrp, 10) == 123);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("123abc", LLONG_MIN, LLONG_MAX, &errstrp, 16) == 0x123abc);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("  0x123abc", LLONG_MIN, LLONG_MAX, &errstrp, 16) == 0x123abc);
  assert(errstrp == NULL);
  assert(ndpi_strtonum("ghi", -10, +10, &errstrp, 10) == 0);
  assert(errstrp != NULL);
}

/* *********************************************** */

void strlcpyUnitTest() {
  // Test empty string
  char dst_empty[10] = "";
  assert(ndpi_strlcpy(dst_empty, "", sizeof(dst_empty), 0) == 0);
  assert(dst_empty[0] == '\0');

  // Basic copy test
  char dst1[10] = "";
  assert(ndpi_strlcpy(dst1, "abc", sizeof(dst1), 3) == 3);
  assert(strcmp(dst1, "abc") == 0);

  // Test with dst_len smaller than src_len
  char dst2[4] = "";
  assert(ndpi_strlcpy(dst2, "abcdef", sizeof(dst2), 6) == 6);
  assert(strcmp(dst2, "abc") == 0); // Should truncate "abcdef" to "abc"

  // Test with dst_len bigger than src_len
  char dst3[10] = "";
  assert(ndpi_strlcpy(dst3, "abc", sizeof(dst3), 3) == 3);
  assert(strcmp(dst3, "abc") == 0);

  // Test with dst_len equal to 1 (only null terminator should be copied)
  char dst4[1];
  assert(ndpi_strlcpy(dst4, "abc", sizeof(dst4), 3) == 3);
  assert(dst4[0] == '\0'); // Should only contain the null terminator

  // Test with NULL source, expecting return value to be 0
  char dst5[10];
  assert(ndpi_strlcpy(dst5, NULL, sizeof(dst5), 0) == 0);

  // Test with NULL destination, should also return 0 without crashing
  assert(ndpi_strlcpy(NULL, "abc", sizeof(dst5), 3) == 0);
}

/* *********************************************** */

void strnstrUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_strnstr(NULL, "find", 10) == NULL);
  assert(ndpi_strnstr("string", NULL, 10) == NULL);

  /* Test 2: empty substring */
  assert(strcmp(ndpi_strnstr("string", "", 6), "string") == 0);

  /* Test 3: single character substring */
  assert(strcmp(ndpi_strnstr("string", "r", 6), "ring") == 0);
  assert(ndpi_strnstr("string", "x", 6) == NULL);

  /* Test 4: multiple character substring */
  assert(strcmp(ndpi_strnstr("string", "ing", 6), "ing") == 0);
  assert(ndpi_strnstr("string", "xyz", 6) == NULL);

  /* Test 5: substring equal to the beginning of the string */
  assert(strcmp(ndpi_strnstr("string", "str", 3), "string") == 0);

  /* Test 6: substring at the end of the string */
  assert(strcmp(ndpi_strnstr("string", "ing", 6), "ing") == 0);

  /* Test 7: substring in the middle of the string */
  assert(strcmp(ndpi_strnstr("hello world", "lo wo", 11), "lo world") == 0);

  /* Test 8: repeated characters in the string */
  assert(strcmp(ndpi_strnstr("aaaaaa", "aaa", 6), "aaaaaa") == 0);

  /* Test 9: empty string and slen 0 */
  assert(ndpi_strnstr("", "find", 0) == NULL);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_strnstr("string", "string", 6), "string") == 0);

  /* Test 11a,b: max_length bigger that string length */
  assert(strcmp(ndpi_strnstr("string", "string", 66), "string") == 0);
  assert(ndpi_strnstr("string", "a", 66) == NULL);

  /* Test 12: substring longer than the string */
  assert(ndpi_strnstr("string", "stringA", 6) == NULL);

  /* Test 13 */
  assert(ndpi_strnstr("abcdef", "abc", 2) == NULL);

  /* Test 14: zero length */
  assert(strcmp(ndpi_strnstr("", "", 0), "") == 0);
  assert(strcmp(ndpi_strnstr("string", "", 0), "string") == 0);
  assert(ndpi_strnstr("", "str", 0) == NULL);
  assert(ndpi_strnstr("string", "str", 0) == NULL);
  assert(ndpi_strnstr("str", "string", 0) == NULL);
}

/* *********************************************** */

void strncasestrUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_strncasestr(NULL, "find", 10) == NULL);
  assert(ndpi_strncasestr("string", NULL, 10) == NULL);

  /* Test 2: empty substring */
  assert(strcmp(ndpi_strncasestr("string", "", 6), "string") == 0);

  /* Test 3: single character substring */
  assert(strcmp(ndpi_strncasestr("string", "r", 6), "ring") == 0);
  assert(strcmp(ndpi_strncasestr("string", "R", 6), "ring") == 0);
  assert(strcmp(ndpi_strncasestr("stRing", "r", 6), "Ring") == 0);
  assert(ndpi_strncasestr("string", "x", 6) == NULL);
  assert(ndpi_strncasestr("string", "X", 6) == NULL);

  /* Test 4: multiple character substring */
  assert(strcmp(ndpi_strncasestr("string", "ing", 6), "ing") == 0);
  assert(strcmp(ndpi_strncasestr("striNg", "InG", 6), "iNg") == 0);
  assert(ndpi_strncasestr("string", "xyz", 6) == NULL);
  assert(ndpi_strncasestr("striNg", "XyZ", 6) == NULL);

  /* Test 5: substring equal to the beginning of the string */
  assert(strcmp(ndpi_strncasestr("string", "str", 5), "string") == 0);
  assert(strcmp(ndpi_strncasestr("string", "sTR", 5), "string") == 0);
  assert(strcmp(ndpi_strncasestr("String", "STR", 5), "String") == 0);
  assert(strcmp(ndpi_strncasestr("Long Long String", "long long", 15), "Long Long String") == 0);

  /* Test 6: substring at the end of the string */
  assert(strcmp(ndpi_strncasestr("string", "ing", 6), "ing") == 0);
  assert(strcmp(ndpi_strncasestr("some longer STRing", "GEr sTrING", 18), "ger STRing") == 0);

  /* Test 7: substring in the middle of the string */
  assert(strcmp(ndpi_strncasestr("hello world", "lo wo", 11), "lo world") == 0);
  assert(strcmp(ndpi_strncasestr("hello BEAUTIFUL world", "beautiful", 20), "BEAUTIFUL world") == 0);

  /* Test 8: repeated characters in the string */
  assert(strcmp(ndpi_strncasestr("aaaaaa", "aaa", 6), "aaaaaa") == 0);
  assert(strcmp(ndpi_strncasestr("aaAaAa", "aaa", 6), "aaAaAa") == 0);
  assert(strcmp(ndpi_strncasestr("AAAaaa", "aaa", 6), "AAAaaa") == 0);

  /* Test 9: empty string and slen 0 */
  assert(ndpi_strncasestr("", "find", 0) == NULL);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_strncasestr("string", "string", 6), "string") == 0);
  assert(strcmp(ndpi_strncasestr("string", "STRING", 6), "string") == 0);
  assert(strcmp(ndpi_strncasestr("sTrInG", "StRiNg", 6), "sTrInG") == 0);

  /* Test 11a,b: max_length bigger that string length */
  assert(strcmp(ndpi_strncasestr("string", "string", 66), "string") == 0);
  assert(ndpi_strncasestr("string", "a", 66) == NULL);

  /* Test 12: substring longer than the string */
  assert(ndpi_strncasestr("string", "stringA", 6) == NULL);

  /* Test 13 */
  assert(ndpi_strncasestr("abcdef", "abc", 2) == NULL);

  /* Test 14: zero length */
  assert(strcmp(ndpi_strncasestr("", "", 0), "") == 0);
  assert(strcmp(ndpi_strncasestr("string", "", 0), "string") == 0);
  assert(ndpi_strncasestr("", "str", 0) == NULL);
  assert(ndpi_strncasestr("string", "str", 0) == NULL);
  assert(ndpi_strncasestr("str", "string", 0) == NULL);
}

/* *********************************************** */

void memmemUnitTest(void) {
  /* Test 1: null string */
  assert(ndpi_memmem(NULL, 0, NULL, 0) == NULL);
  assert(ndpi_memmem(NULL, 0, NULL, 10) == NULL);
  assert(ndpi_memmem(NULL, 0, "find", 10) == NULL);
  assert(ndpi_memmem(NULL, 10, "find", 10) == NULL);
  assert(ndpi_memmem("string", 10, NULL, 0) == NULL);
  assert(ndpi_memmem("string", 10, NULL, 10) == NULL);

  /* Test 2: zero length */
  assert(strcmp(ndpi_memmem("", 0, "", 0), "") == 0);
  assert(strcmp(ndpi_memmem("string", 6, "", 0), "string") == 0);
  assert(strcmp(ndpi_memmem("string", 0, "", 0), "string") == 0);
  assert(ndpi_memmem("", 0, "string", 6) == NULL);

  /* Test 3: empty substring */
  assert(strcmp(ndpi_memmem("string", 6, "", 0), "string") == 0);

  /* Test 4: single character substring */
  assert(strcmp(ndpi_memmem("string", 6, "r", 1), "ring") == 0);
  assert(ndpi_memmem("string", 6, "x", 1) == NULL);

  /* Test 5: multiple character substring */
  assert(strcmp(ndpi_memmem("string", 6, "ing", 3), "ing") == 0);
  assert(ndpi_memmem("string", 6, "xyz", 3) == NULL);

  /* Test 6: substring equal to the beginning of the string */
  assert(strcmp(ndpi_memmem("string", 6, "str", 3), "string") == 0);

  /* Test 7: substring at the end of the string */
  assert(strcmp(ndpi_memmem("string", 6, "ing", 3), "ing") == 0);

  /* Test 8: substring in the middle of the string */
  assert(strcmp(ndpi_memmem("hello world", strlen("hello world"), "lo wo", strlen("lo wo")), "lo world") == 0);

  /* Test 9: repeated characters in the string */
  assert(strcmp(ndpi_memmem("aaaaaa", 6, "aaa", 3), "aaaaaa") == 0);

  /* Test 10: substring equal to the string */
  assert(strcmp(ndpi_memmem("string", 6, "string", 6), "string") == 0);

  /* Test 11: substring longer than the string */
  assert(ndpi_memmem("string", 6, "stringA", 7) == NULL);
}

/* *********************************************** */

void mahalanobisUnitTest()
{
  /* Example based on: https://supplychenmanagement.com/2019/03/06/calculating-mahalanobis-distance/ */

  const float i_s[3 * 3] = {  0.0482486100061447, -0.00420645518018837, -0.0138921893248235,
			      -0.00420645518018836, 0.00177288408892603, -0.00649813703331057,
			      -0.0138921893248235, -0.00649813703331056,  0.066800436339011 }; /* Inverted covar matrix */
  const float u[3] = { 22.8, 180.0, 9.2 }; /* Means vector */
  u_int32_t x[3] = { 26, 167, 12 }; /* Point */
  float md;

  md = ndpi_mahalanobis_distance(x, 3, u, i_s);
  /* It is a bit tricky to test float equality on different archs -> loose check.
   * md sholud be 1.3753 */
  assert(md >= 1.37 && md <= 1.38);
}

/* *********************************************** */

void filterUnitTest() {
  ndpi_filter* f = ndpi_filter_alloc();
  u_int32_t v, i;

  assert(f);

  srand(time(NULL));

  for(i=0; i<1000; i++)
    assert(ndpi_filter_add(f, v = rand()));

  assert(ndpi_filter_contains(f, v));

  ndpi_filter_free(f);
}

/* *********************************************** */

void zscoreUnitTest() {
  u_int32_t values[] = { 1, 3, 3, 4, 5, 2, 6, 7, 30, 16 };
  u_int32_t i;
  u_int32_t num_outliers;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool outliers[NDPI_ARRAY_LENGTH(values)], do_trace = false;

  num_outliers = ndpi_find_outliers(values, outliers, num);

  if(do_trace) {
    printf("outliers: %u\n", num_outliers);

    for(i=0; i<num; i++)
      printf("%u %s\n", values[i], outliers[i] ? "OUTLIER" : "OK");
  }
}

/* *********************************************** */

void linearUnitTest() {
  u_int32_t values[] = {15, 27, 38, 49, 68, 72, 90, 150, 175, 203};
  u_int32_t prediction;
  u_int32_t const num = NDPI_ARRAY_LENGTH(values);
  bool do_trace = false;
  int rc = ndpi_predict_linear(values, num, 2*num, &prediction);

  if(do_trace) {
    printf("[rc: %d][predicted value: %u]\n", rc, prediction);
  }
}

/* *********************************************** */

void sketchUnitTest() {
  struct ndpi_cm_sketch *sketch;

#if 0
  ndpi_cm_sketch_init(8);
  ndpi_cm_sketch_init(16);
  ndpi_cm_sketch_init(32);
  ndpi_cm_sketch_init(64);
  ndpi_cm_sketch_init(256);
  ndpi_cm_sketch_init(512);
  ndpi_cm_sketch_init(1024);
  ndpi_cm_sketch_init(2048);
  ndpi_cm_sketch_init(4096);
  ndpi_cm_sketch_init(8192);
  exit(0);
#endif

  sketch = ndpi_cm_sketch_init(32);

  if(sketch) {
    u_int32_t i, num_one = 0;
    bool do_trace = false;

    srand(time(NULL));

    for(i=0; i<10000; i++) {
      u_int32_t v = rand() % 1000;

      if(v == 1) num_one++;
      ndpi_cm_sketch_add(sketch, v);
    }

    if(do_trace)
      printf("The estimated count of 1 is %u [expectedl: %u]\n",
	     ndpi_cm_sketch_count(sketch, 1), num_one);

    ndpi_cm_sketch_destroy(sketch);

    if(do_trace)
      exit(0);
  }
}

/* *********************************************** */

void binaryBitmapUnitTest() {
  ndpi_binary_bitmap *b = ndpi_binary_bitmap_alloc();
  u_int64_t hashval = 8149764909040470312;
  u_int8_t category = 33;

  ndpi_binary_bitmap_set(b, hashval, category);
  ndpi_binary_bitmap_set(b, hashval+1, category);
  category = 0;
  assert(ndpi_binary_bitmap_isset(b, hashval, &category));
  assert(category == 33);
  ndpi_binary_bitmap_free(b);
}

/* *********************************************** */

void pearsonUnitTest() {
  u_int32_t data_a[] = {1, 2, 3, 4, 5};
  u_int32_t data_b[] = {1000, 113, 104, 105, 106};
  u_int16_t num = sizeof(data_a) / sizeof(u_int32_t);
  float pearson = ndpi_pearson_correlation(data_a, data_b, num);

  assert(pearson != 0.0);
  // printf("%.8f\n", pearson);
}

/* *********************************************** */

void outlierUnitTest() {
  u_int32_t data[] = {1, 2, 3, 4, 5};
  u_int16_t num = sizeof(data) / sizeof(u_int32_t);
  u_int16_t value_to_check = 8;
  float threshold = 1.5, lower, upper;
  float is_outlier = ndpi_is_outlier(data, num, value_to_check,
				     threshold, &lower, &upper);

  /* printf("%.2f < %u < %.2f : %s\n", lower, value_to_check, upper, is_outlier ? "OUTLIER" : "OK"); */
  assert(is_outlier == true);
}

/* *********************************************** */

void loadStressTest() {
  struct ndpi_detection_module_struct *ndpi_struct_shadow = ndpi_init_detection_module(NULL);
  NDPI_PROTOCOL_BITMASK all;

  if(ndpi_struct_shadow) {
    int i;

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct_shadow, &all);

    for(i=1; i<100000; i++) {
      char name[32];
      ndpi_protocol_category_t id = CUSTOM_CATEGORY_MALWARE;
      u_int8_t value = (u_int8_t)i;

      snprintf(name, sizeof(name), "%d.com", i);
      ndpi_load_hostname_category(ndpi_struct_shadow, name, id);

      snprintf(name, sizeof(name), "%u.%u.%u.%u", value, value, value, value);
      ndpi_load_ip_category(ndpi_struct_shadow, name, id, (void *)"My list");
    }

    ndpi_enable_loaded_categories(ndpi_struct_shadow);
    ndpi_finalize_initialization(ndpi_struct_shadow);
    ndpi_exit_detection_module(ndpi_struct_shadow);
  }
}

/* *********************************************** */

void kdUnitTest() {
  ndpi_kd_tree *t = ndpi_kd_create(5);
  double v[][5] = {
    { 0, 4, 2, 3, 4 },
    { 0, 1, 2, 3, 6 },
    { 1, 2, 3, 4, 5 },
  };
  double v1[5] = { 0, 1, 2, 3, 8 };
  u_int i, sz = 5*sizeof(double), num = sizeof(v) / sz;
  ndpi_kd_tree_result *res;
  double *ret, *to_find = v[1];

  assert(t);

  for(i=0; i<num; i++)
    assert(ndpi_kd_insert(t, v[i], NULL) == true);

  assert((res = ndpi_kd_nearest(t, to_find)) != NULL);
  assert(ndpi_kd_num_results(res) == 1);
  assert((ret = ndpi_kd_result_get_item(res, NULL)) != NULL);
  assert(memcmp(ret, to_find, sz) == 0);
  ndpi_kd_result_free(res);

  assert((res = ndpi_kd_nearest(t, v1)) != NULL);
  assert(ndpi_kd_num_results(res) == 1);
  assert((ret = ndpi_kd_result_get_item(res, NULL)) != NULL);
  assert(memcmp(ret, v1, sz) != 0);
  assert(ndpi_kd_distance(ret, v1, 5) == 4.);
  ndpi_kd_result_free(res);

  ndpi_kd_free(t);
}

/* *********************************************** */

void ballTreeUnitTest() {
  ndpi_btree *ball_tree;
  double v[][5] = {
    { 0, 4, 2, 3, 4 },
    { 0, 1, 2, 3, 6 },
    { 1, 2, 3, 4, 5 },
  };
  double v1[] = { 0, 1, 2, 3, 8 };
  double *rows[] = { v[0], v[1], v[2] };
  double *q_rows[] = { v1 };
  u_int32_t num_columns = 5;
  u_int32_t num_rows = sizeof(v) / (sizeof(double)*num_columns);
  ndpi_knn result;
  u_int32_t nun_results = 2;
  int i, j;

  ball_tree = ndpi_btree_init(rows, num_rows, num_columns);
  assert(ball_tree != NULL);
  result = ndpi_btree_query(ball_tree, q_rows,
			    sizeof(q_rows) / sizeof(double*),
			    num_columns, nun_results);

  assert(result.n_samples == 2);

  for (i = 0; i < result.n_samples; i++) {
    printf("{\"knn_idx\": [");
    for (j = 0; j < result.n_neighbors; j++)
      {
	printf("%d", result.indices[i][j]);
	if (j != result.n_neighbors - 1)
	  printf(", ");
      }
    printf("],\n \"knn_dist\": [");
    for (j = 0; j < result.n_neighbors; j++)
      {
	printf("%.12lf", result.distances[i][j]);
	if (j != result.n_neighbors - 1)
	  printf(", ");
      }
    printf("]\n}\n");
    if (i != result.n_samples - 1)
      printf(", ");
  }

  ndpi_free_knn(result);
  ndpi_free_btree(ball_tree);
}

/* *********************************************** */

void cryptDecryptUnitTest() {
  u_char enc_dec_key[64] = "9dedb817e5a8805c1de62eb8982665b9a2b4715174c34d23b9a46ffafacfb2a7" /* SHA256("nDPI") */;
  const char *test_string = "The quick brown fox jumps over the lazy dog";
  char *enc, *dec;
  u_int16_t e_len, d_len, t_len = strlen(test_string);

  enc = ndpi_quick_encrypt(test_string, t_len, &e_len, enc_dec_key);
  assert(enc != NULL);
  dec = ndpi_quick_decrypt((const char*)enc, e_len, &d_len, enc_dec_key);
  assert(dec != NULL);
  assert(t_len == d_len);

  assert(strncmp(dec, test_string, e_len) == 0);

  ndpi_free(enc);
  ndpi_free(dec);
}

/* *********************************************** */

void encodeDomainsUnitTest() {
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  const char *lists_path = "../lists/public_suffix_list.dat";
  struct stat st;

  if(stat(lists_path, &st) == 0) {
    u_int16_t suffix_id;
    char out[256];
    char *str;
    ndpi_protocol_category_t id;

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

    assert(ndpi_load_domain_suffixes(ndpi_str, (char*)lists_path) == 0);

    ndpi_get_host_domain_suffix(ndpi_str, "lcb.it", &suffix_id);
    ndpi_get_host_domain_suffix(ndpi_str, "www.ntop.org", &suffix_id);
    ndpi_get_host_domain_suffix(ndpi_str, "www.bbc.co.uk", &suffix_id);

    str = (char*)"www.ntop.org"; assert(ndpi_encode_domain(ndpi_str, str, out, sizeof(out)) == 8);
    str = (char*)"www.bbc.co.uk"; assert(ndpi_encode_domain(ndpi_str, str, out, sizeof(out)) == 8);

    assert(ndpi_load_categories_dir(ndpi_str, "../lists"));
    assert(ndpi_load_categories_file(ndpi_str, "./categories.txt", "categories.txt"));

    str = (char*)"2001:db8:1::1"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 100);
    str = (char*)"www.internetbadguys.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 100);
    str = (char*)"0grand-casino.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 107);
    str = (char*)"222.0grand-casino.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 107);
    str = (char*)"10bet.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 107);
    str = (char*)"www.ntop.org"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == -1); assert(id == 0);
    str = (char*)"www.andrewpope.com"; assert(ndpi_get_custom_category_match(ndpi_str, str, strlen(str), &id) == 0); assert(id == 100);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

void domainsUnitTest() {
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  const char *lists_path = "../lists/public_suffix_list.dat";
  struct stat st;

  if(stat(lists_path, &st) == 0) {
    u_int16_t suffix_id;

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

    assert(ndpi_load_domain_suffixes(ndpi_str, (char*)lists_path) == 0);

    assert(strcmp(ndpi_get_host_domain(ndpi_str, "extension.femetrics.grammarly.io"), "grammarly.io") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.ovh.commander1.com"), "commander1.com") == 0);

    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.chosei.chiba.jp", &suffix_id), "chosei.chiba.jp") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.unipi.it", &suffix_id), "it") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "mail.apple.com", &suffix_id), "com") == 0);
    assert(strcmp(ndpi_get_host_domain_suffix(ndpi_str, "www.bbc.co.uk", &suffix_id), "co.uk") == 0);

    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.chosei.chiba.jp"), "www.chosei.chiba.jp") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.unipi.it"), "unipi.it") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "mail.apple.com"), "apple.com") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "www.bbc.co.uk"), "bbc.co.uk") == 0);
    assert(strcmp(ndpi_get_host_domain(ndpi_str, "zy1ssnfwwl.execute-api.eu-north-1.amazonaws.com"), "amazonaws.com") == 0);
  }

  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

void domainSearchUnitTest() {
  ndpi_domain_classify *sc = ndpi_domain_classify_alloc();
  char *domain = "ntop.org";
  u_int16_t class_id;
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  u_int8_t trace = 0;
  NDPI_PROTOCOL_BITMASK all;

  assert(ndpi_str);
  assert(sc);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_finalize_initialization(ndpi_str);

  ndpi_domain_classify_add(ndpi_str, sc, NDPI_PROTOCOL_NTOP, ".ntop.org");
  ndpi_domain_classify_add(ndpi_str, sc, NDPI_PROTOCOL_NTOP, domain);
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, domain));
  assert(class_id == NDPI_PROTOCOL_NTOP);

  ndpi_domain_classify_add(ndpi_str, sc, NDPI_PROTOCOL_CATEGORY_GAMBLING, "123vc.club");
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, "123vc.club"));
  assert(class_id == NDPI_PROTOCOL_CATEGORY_GAMBLING);

  /* Subdomain check */
  assert(ndpi_domain_classify_hostname(ndpi_str, sc, &class_id, "blog.ntop.org"));
  assert(class_id == NDPI_PROTOCOL_NTOP);

  u_int32_t s = ndpi_domain_classify_size(sc);
  if(trace) printf("ndpi_domain_classify size: %u \n",s);


  ndpi_domain_classify_free(sc);
  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

void domainSearchUnitTest2() {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_init_detection_module(NULL);
  ndpi_domain_classify *c = ndpi_domain_classify_alloc();
  u_int16_t class_id = 9;
  NDPI_PROTOCOL_BITMASK all;

  assert(ndpi_str);
  assert(c);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);
  ndpi_finalize_initialization(ndpi_str);

  ndpi_domain_classify_add(ndpi_str, c, class_id, "ntop.org");
  ndpi_domain_classify_add(ndpi_str, c, class_id, "apple.com");

  assert(!ndpi_domain_classify_hostname(ndpi_str, c, &class_id, "ntop.com"));

  ndpi_domain_classify_free(c);
  ndpi_exit_detection_module(ndpi_str);
}

/* *********************************************** */

void domainCacheTestUnit() {
  struct ndpi_address_cache *cache = ndpi_init_address_cache(32000);
  ndpi_ip_addr_t ip;
  u_int32_t epoch_now = (u_int32_t)time(NULL);
  struct ndpi_address_cache_item *ret;
  char fname[64] = {0};

  assert(cache);

  /* On GitHub Actions, ndpiReader might be called multiple times in parallel, so
     every instance must use its own file */
  snprintf(fname, sizeof(fname), "./cache.%u.dump", (unsigned int)getpid());

  memset(&ip, 0, sizeof(ip));
  ip.ipv4 = 12345678;
  assert(ndpi_address_cache_insert(cache, ip, "nodomain.local", epoch_now, 32) == true);

  ip.ipv4 = 87654321;
  assert(ndpi_address_cache_insert(cache, ip, "hello.local", epoch_now, 0) == true);

  assert((ret = ndpi_address_cache_find(cache, ip, epoch_now)) != NULL);
  assert(strcmp(ret->hostname, "hello.local") == 0);
  assert(ndpi_address_cache_find(cache, ip, epoch_now + 1) == NULL);

  assert(ndpi_address_cache_dump(cache, fname, epoch_now));
  ndpi_term_address_cache(cache);

  cache = ndpi_init_address_cache(32000);
  assert(cache);
  assert(ndpi_address_cache_restore(cache, fname, epoch_now) == 1);

  ip.ipv4 = 12345678;
  assert((ret = ndpi_address_cache_find(cache, ip, epoch_now)) != NULL);
  assert(strcmp(ret->hostname, "nodomain.local") == 0);

  ndpi_term_address_cache(cache);
  unlink(fname);
}

/* *********************************************** */

/**
   @brief MAIN FUNCTION
**/
int main(int argc, char **argv) {
  int i;
#ifdef NDPI_EXTENDED_SANITY_CHECKS
  int skip_unit_tests = 0;
#else
  int skip_unit_tests = 1;
#endif

#ifdef DEBUG_TRACE
  trace = fopen("/tmp/ndpiReader.log", "a");

  if(trace) {
    int i;

    fprintf(trace, " #### %s #### \n", __FUNCTION__);
    fprintf(trace, " #### [argc: %u] #### \n", argc);

    for(i=0; i<argc; i++)
      fprintf(trace, " #### [%d] [%s]\n", i, argv[i]);
  }
#endif

  if(ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return(-1);
  }

  if(!skip_unit_tests) {
#ifndef DEBUG_TRACE
    /* Skip tests when debugging */

#ifdef HW_TEST
    hwUnitTest2();
#endif

#ifdef STRESS_TEST
    desUnitStressTest();
    exit(0);
#endif

    domainCacheTestUnit();
    cryptDecryptUnitTest();
    kdUnitTest();
    encodeDomainsUnitTest();
    loadStressTest();
    domainsUnitTest();
    outlierUnitTest();
    pearsonUnitTest();
    binaryBitmapUnitTest();
    domainSearchUnitTest();
    domainSearchUnitTest2();
    sketchUnitTest();
    linearUnitTest();
    zscoreUnitTest();
    sesUnitTest();
    desUnitTest();

    /* Internal checks */
    // binUnitTest();
    //hwUnitTest();
    jitterUnitTest();
    rsiUnitTest();
    hashUnitTest();
    dgaUnitTest();
    hllUnitTest();
    bitmapUnitTest();
    filterUnitTest();
    automataUnitTest();
    automataDomainsUnitTest();
    analyzeUnitTest();
    ndpi_self_check_host_match(stderr);
    analysisUnitTest();
    compressedBitmapUnitTest();
    strtonumUnitTest();
    strlcpyUnitTest();
    strnstrUnitTest();
    strncasestrUnitTest();
    memmemUnitTest();
    mahalanobisUnitTest();
#endif
  }

  gettimeofday(&startup_time, NULL);
  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

  if(getenv("AHO_DEBUG"))
    ac_automata_enable_debug(1);

  parseOptions(argc, argv);

  if(domain_to_check) {
    ndpiCheckHostStringMatch(domain_to_check);
    exit(0);
  }
  
  if(ip_port_to_check) {
    ndpiCheckIPMatch(ip_port_to_check);
    exit(0);
  }

  if(enable_doh_dot_detection) {
    init_doh_bins();
    /* Clusters are not really used in DoH/DoT detection, but because of how
       the code has been written, we need to enable also clustering feature */
    if(num_bin_clusters == 0)
      num_bin_clusters = 1;
  }

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../nDPI-custom/ndpiReader_init.c"
#endif
  
  if(!quiet_mode) {
    printf("\n-----------------------------------------------------------\n"
	   "* NOTE: This is demo app to show *some* nDPI features.\n"
	   "* In this demo we have implemented only some basic features\n"
	   "* just to show you what you can do with the library. Feel \n"
	   "* free to extend it and send us the patches for inclusion\n"
	   "------------------------------------------------------------\n\n");

    printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);

    const char *gcrypt_ver = ndpi_get_gcrypt_version();
    if(gcrypt_ver)
      printf("Using libgcrypt version %s\n", gcrypt_ver);
  }

  signal(SIGINT, sigproc);

  for(i=0; i<num_loops; i++)
    test_lib();

  if(results_path)  ndpi_free(results_path);
  if(results_file)  fclose(results_file);
  if(extcap_dumper) pcap_dump_close(extcap_dumper);
  if(extcap_fifo_h) pcap_close(extcap_fifo_h);
  if(enable_malloc_bins) ndpi_free_bin(&malloc_bins);
  if(csv_fp)         fclose(csv_fp);
  if(fingerprint_fp) fclose(fingerprint_fp);

  ndpi_free(_disabled_protocols);

  for(i = 0; i < num_cfgs; i++) {
    ndpi_free(cfgs[i].proto);
    ndpi_free(cfgs[i].param);
    ndpi_free(cfgs[i].value);
  }

  for(i = 0; i < fargc; i++)
    ndpi_free(fargv[i]);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../nDPI-custom/ndpiReader_term.c"
#endif

#ifdef DEBUG_TRACE
  if(trace) fclose(trace);
#endif

  return 0;
}

#ifdef _MSC_BUILD
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
  }

  return main(__argc, __argv);
}
#endif

#if defined(WIN32) && !defined(_MSC_BUILD)
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

/**
   @brief Timezone
**/
#ifndef __GNUC__
struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};
#endif

/**
   @brief Set time
**/
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
