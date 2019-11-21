/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-19 - ntop.org
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

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
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
#include <assert.h>
#include <math.h>
#include "ndpi_api.h"
#include "uthash.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libgen.h>

#include "reader_util.h"


/** Client parameters **/

static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path  */
static char *_customCategoryFilePath= NULL; /**< Custom categories file path  */
static FILE *csv_fp                 = NULL; /**< for CSV export */
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
/** User preferences **/
u_int8_t enable_protocol_guess = 1, enable_payload_analyzer = 0;
u_int8_t verbose = 0, enable_joy_stats = 0;
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
u_int8_t human_readeable_string_len = 5;
u_int8_t max_num_udp_dissected_pkts = 16 /* 8 is enough for most protocols, Signal requires more */, max_num_tcp_dissected_pkts = 80 /* due to telnet */;
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval startup_time, begin, end;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
static struct timeval pcap_start = { 0, 0}, pcap_end = { 0, 0 };
/** Detection parameters **/
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int32_t num_flows;
static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

extern u_int32_t max_num_packets_per_flow, max_packet_payload_dissection, max_num_reported_top_payloads;
extern u_int16_t min_pattern_len, max_pattern_len;

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

typedef struct node_a{
  u_int32_t addr;
  u_int8_t version; /* IP version */
  char proto[16]; /*app level protocol*/
  int count;
  struct node_a *left, *right;
}addr_node;

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


struct ndpi_packet_trailer {
  u_int32_t magic; /* 0x19682017 */
  u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
  char name[16];
};

static pcap_dumper_t *extcap_dumper = NULL;
static char extcap_buf[16384];
static char *extcap_capture_fifo    = NULL;
static u_int16_t extcap_packet_filter = (u_int16_t)-1;

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
  u_int8_t ip[4];		   // Ip address
  struct ndpi_id_struct *ndpi_id;  // nDpi worker structure
} ndpi_id_t;

// used memory counters
u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
#ifdef USE_DPDK
static int dpdk_port_id = 0, dpdk_run_capture = 1;
#endif

void test_lib(); /* Forward */

extern void ndpi_report_payload_stats();

/* ********************************** */

#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

/********************** FUNCTIONS ********************* */

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle);

static void reduceBDbits(uint32_t *bd, unsigned int len) {
  int mask = 0;
  int shift = 0;
  unsigned int i = 0;

  for(i = 0; i < len; i++)
    mask = mask | bd[i];

  mask = mask >> 8;
  for(i = 0; i < 24 && mask; i++) {
    mask = mask >> 1;
    if (mask == 0) {
      shift = i+1;
      break;
    }
  }

  for(i = 0; i < len; i++)
    bd[i] = bd[i] >> shift;
}

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
  struct ndpi_entropy last_entropy = flow->last_entropy;

  fflush(out);

  /*
   * Sum up the byte_count array for outbound and inbound flows,
   * if this flow is bidirectional
   */
  if (!flow->bidirectional) {
    array = last_entropy.src2dst_byte_count;
    num_bytes = last_entropy.src2dst_l4_bytes;
    for (i=0; i<256; i++) {
      tmp[i] = last_entropy.src2dst_byte_count[i];
    }

    if (last_entropy.src2dst_num_bytes != 0) {
      mean = last_entropy.src2dst_bd_mean;
      variance = last_entropy.src2dst_bd_variance/(last_entropy.src2dst_num_bytes - 1);
      variance = sqrt(variance);

      if (last_entropy.src2dst_num_bytes == 1) {
        variance = 0.0;
      }
    }
  } else {
    for (i=0; i<256; i++) {
      tmp[i] = last_entropy.src2dst_byte_count[i] + last_entropy.dst2src_byte_count[i];
    }
    array = tmp;
    num_bytes = last_entropy.src2dst_l4_bytes + last_entropy.dst2src_l4_bytes;

    if (last_entropy.src2dst_num_bytes + last_entropy.dst2src_num_bytes != 0) {
      mean = ((double)last_entropy.src2dst_num_bytes)/((double)(last_entropy.src2dst_num_bytes+last_entropy.dst2src_num_bytes))*last_entropy.src2dst_bd_mean +
             ((double)last_entropy.dst2src_num_bytes)/((double)(last_entropy.dst2src_num_bytes+last_entropy.src2dst_num_bytes))*last_entropy.dst2src_bd_mean;

      variance = ((double)last_entropy.src2dst_num_bytes)/((double)(last_entropy.src2dst_num_bytes+last_entropy.dst2src_num_bytes))*last_entropy.src2dst_bd_variance +
                 ((double)last_entropy.dst2src_num_bytes)/((double)(last_entropy.dst2src_num_bytes+last_entropy.src2dst_num_bytes))*last_entropy.dst2src_bd_variance;

      variance = variance/((double)(last_entropy.src2dst_num_bytes + last_entropy.dst2src_num_bytes - 1));
      variance = sqrt(variance);
      if (last_entropy.src2dst_num_bytes + last_entropy.dst2src_num_bytes == 1) {
        variance = 0.0;
      }
    }
  }

  if(enable_joy_stats) {
    if(verbose > 1) {
      reduceBDbits(tmp, 256);
      array = tmp;

      fprintf(out, " [byte_dist: ");
      for(i = 0; i < 255; i++)
	fprintf(out, "%u,", (unsigned char)array[i]);

      fprintf(out, "%u]", (unsigned char)array[i]);
    }

    /* Output the mean */
    if(num_bytes != 0) {
      double entropy = ndpi_flow_get_byte_count_entropy(array, num_bytes);

      fprintf(out, "][byte_dist_mean: %f", mean);
      fprintf(out, "][byte_dist_std: %f]", variance);
      fprintf(out, "[entropy: %f]", entropy);
      fprintf(out, "[total_entropy: %f]", entropy * num_bytes);
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
	 "[-f <filter>][-s <duration>][-m <duration>]\n"
	 "          [-p <protos>][-l <loops> [-q][-d][-J][-h][-e <len>][-t][-v <level>]\n"
	 "          [-n <threads>][-w <file>][-c <file>][-C <file>][-j <file>][-x <file>]\n"
	 "          [-T <num>][-U <num>]\n\n"
	 "Usage:\n"
	 "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a\n"
	 "                            | device for live capture (comma-separated list)\n"
	 "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
	 "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
	 "  -m <duration>             | Split analysis duration in <duration> max seconds\n"
	 "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
	 "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -n <num threads>          | Number of threads. Default: number of interfaces in -i.\n"
	 "                            | Ignored with pcap files.\n"
#ifdef linux
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
	 "  -d                        | Disable protocol guess and use only DPI\n"
	 "  -e <len>                  | Min human readeable string match len. Default %u\n"
	 "  -q                        | Quiet mode\n"
	 "  -J                        | Display flow SPLT (sequence of packet length and time)\n"
	 "                            | and BD (byte distribution). See https://github.com/cisco/joy\n"
	 "  -t                        | Dissect GTP/TZSP tunnels\n"
	 "  -P <a>:<b>:<c>:<d>:<e>    | Enable payload analysis:\n"
	 "                            | <a> = min pattern len to search\n"
	 "                            | <b> = max pattern len to search\n"
	 "                            | <c> = max num packets per flow\n"
	 "                            | <d> = max packet payload dissection\n"
	 "                            | <d> = max num reported payloads\n"
	 "                            | Default: %u:%u:%u:%u:%u\n"
	 "  -r                        | Print nDPI version and git revision\n"
	 "  -c <path>                 | Load custom categories from the specified file\n"
	 "  -C <path>                 | Write output in CSV format on the specified file\n"
	 "  -w <path>                 | Write test output on the specified file. This is useful for\n"
	 "                            | testing purposes in order to compare results across runs\n"
	 "  -h                        | This help\n"
	 "  -v <1|2|3>                | Verbose 'unknown protocol' packet print.\n"
	 "                            | 1 = verbose\n"
	 "                            | 2 = very verbose\n"
	 "                            | 3 = port stats\n"
	 "  -V <1-4>                  | nDPI logging level\n"
	 "                            | 1 - trace, 2 - debug, 3 - full debug\n"
	 "                            | >3 - full debug + dbg_proto = all\n"
	 "  -T <num>                  | Max number of TCP processed packets before giving up [default: %u]\n"
	 "  -U <num>                  | Max number of UDP processed packets before giving up [default: %u]\n"
	 ,
	 human_readeable_string_len,
	 min_pattern_len, max_pattern_len, max_num_packets_per_flow, max_packet_payload_dissection,
	 max_num_reported_top_payloads, max_num_tcp_dissected_pkts, max_num_udp_dissected_pkts);

#ifndef WIN32
  printf("\nExcap (wireshark) options:\n"
	 "  --extcap-interfaces\n"
	 "  --extcap-version\n"
	 "  --extcap-dlts\n"
	 "  --extcap-interface <name>\n"
	 "  --extcap-config\n"
	 "  --capture\n"
	 "  --extcap-capture-filter\n"
	 "  --fifo <path to file or pipe>\n"
	 "  --debug\n"
	 "  --dbg-proto proto|num[,...]\n"
    );
#endif

  if(long_help) {
    NDPI_PROTOCOL_BITMASK all;

    printf("\n\nnDPI supported protocols:\n");
    printf("%3s %-22s %-8s %-12s %s\n", "Id", "Protocol", "Layer_4", "Breed", "Category");
    num_threads = 1;

    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_info_mod, &all);

    ndpi_dump_protocols(ndpi_info_mod);
  }
  exit(!long_help);
}


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
  { "debug", no_argument, NULL, '8'},
  { "dbg-proto", required_argument, NULL, 257},
  { "ndpi-proto-filter", required_argument, NULL, '9'},

  /* ndpiReader options */
  { "enable-protocol-guess", no_argument, NULL, 'd'},
  { "categories", required_argument, NULL, 'c'},
  { "csv-dump", required_argument, NULL, 'C'},
  { "interface", required_argument, NULL, 'i'},
  { "filter", required_argument, NULL, 'f'},
  { "cpu-bind", required_argument, NULL, 'g'},
  { "loops", required_argument, NULL, 'l'},
  { "num-threads", required_argument, NULL, 'n'},

  { "protos", required_argument, NULL, 'p'},
  { "capture-duration", required_argument, NULL, 's'},
  { "decode-tunnels", no_argument, NULL, 't'},
  { "revision", no_argument, NULL, 'r'},
  { "verbose", no_argument, NULL, 'v'},
  { "version", no_argument, NULL, 'V'},
  { "help", no_argument, NULL, 'h'},
  { "joy", required_argument, NULL, 'J'},
  { "payload-analysis", required_argument, NULL, 'P'},
  { "result-path", required_argument, NULL, 'w'},
  { "quiet", no_argument, NULL, 'q'},

  {0, 0, 0, 0}
};

/* ********************************** */

void extcap_interfaces() {
  printf("extcap {version=%s}\n", ndpi_revision());
  printf("interface {value=ndpi}{display=nDPI interface}\n");
  exit(0);
}

/* ********************************** */

void extcap_dlts() {
  u_int dlts_number = DLT_EN10MB;
  printf("dlt {number=%u}{name=%s}{display=%s}\n", dlts_number, "ndpi", "nDPI Interface");
  exit(0);
}

/* ********************************** */

struct ndpi_proto_sorter {
  int id;
  char name[16];
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
  return(0);
}

/* ********************************** */

void extcap_config() {
  int i, argidx = 0;
  struct ndpi_proto_sorter *protos;
  u_int ndpi_num_supported_protocols = ndpi_get_ndpi_num_supported_protocols(ndpi_info_mod);
  ndpi_proto_defaults_t *proto_defaults = ndpi_get_proto_defaults(ndpi_info_mod);

  /* -i <interface> */
  printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}"
	 "{tooltip=The interface name}\n", argidx++);
  printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}"
	 "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);

  protos = (struct ndpi_proto_sorter*)malloc(sizeof(struct ndpi_proto_sorter) * ndpi_num_supported_protocols);
  if(!protos) exit(0);

  for(i=0; i<(int) ndpi_num_supported_protocols; i++) {
    protos[i].id = i;
    snprintf(protos[i].name, sizeof(protos[i].name), "%s", proto_defaults[i].protoName);
  }

  qsort(protos, ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

  printf("arg {number=%d}{call=-9}{display=nDPI Protocol Filter}{type=selector}"
	 "{tooltip=nDPI Protocol to be filtered}\n", argidx);

  printf("value {arg=%d}{value=%d}{display=%s}\n", argidx, -1, "All Protocols (no nDPI filtering)");

  for(i=0; i<(int)ndpi_num_supported_protocols; i++)
    printf("value {arg=%d}{value=%d}{display=%s (%d)}\n", argidx, protos[i].id,
	   protos[i].name, protos[i].id);

  free(protos);

  exit(0);
}

/* ********************************** */

void extcap_capture() {
#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

  if((extcap_dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */),
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

  fprintf(csv_fp, "#flow_id,protocol,first_seen,last_seen,duration,src_ip,src_port,dst_ip,dst_port,ndpi_proto_num,ndpi_proto,");
  fprintf(csv_fp, "src2dst_packets,src2dst_bytes,src2dst_goodput_bytes,dst2src_packets,dst2src_bytes,dst2src_goodput_bytes,");
  fprintf(csv_fp, "data_ratio,str_data_ratio,src2dst_goodput_ratio,dst2src_goodput_ratio,");

  /* IAT (Inter Arrival Time) */
  fprintf(csv_fp, "iat_flow_min,iat_flow_avg,iat_flow_max,iat_flow_stddev,");
  fprintf(csv_fp, "iat_c_to_s_min,iat_c_to_s_avg,iat_c_to_s_max,iat_c_to_s_stddev,");
  fprintf(csv_fp, "iat_s_to_c_min,iat_s_to_c_avg,iat_s_to_c_max,iat_s_to_c_stddev,");

  /* Packet Length */
  fprintf(csv_fp, "pktlen_c_to_s_min,pktlen_c_to_s_avg,pktlen_c_to_s_max,pktlen_c_to_s_stddev,");
  fprintf(csv_fp, "pktlen_s_to_c_min,pktlen_s_to_c_avg,pktlen_s_to_c_max,pktlen_s_to_c_stddev,");

  /* Flow info */
  fprintf(csv_fp, "client_info,server_info,");
  fprintf(csv_fp, "tls_version,ja3c,tls_client_unsafe,");
  fprintf(csv_fp, "ja3s,tls_server_unsafe,");
  fprintf(csv_fp, "ssh_client_hassh,ssh_server_hassh");
  fprintf(csv_fp, "\n");
}

/* ********************************** */

/**
 * @brief Option parser
 */
static void parseOptions(int argc, char **argv) {
  int option_idx = 0, do_capture = 0;
  char *__pcap_file = NULL, *bind_mask = NULL;
  int thread_id, opt;
#ifdef linux
  u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif

#ifdef DEBUG_TRACE
  trace = fopen("/tmp/ndpiReader.log", "a");

  if(trace) fprintf(trace, " #### %s #### \n", __FUNCTION__);
#endif

#ifdef USE_DPDK
  {
    int ret = rte_eal_init(argc, argv);

    if(ret < 0)
      rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret, argv += ret;
  }
#endif

  while((opt = getopt_long(argc, argv, "e:c:C:df:g:i:hp:P:l:s:tv:V:n:Jrp:w:q0123:456:7:89:m:T:U:",
			   longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'e':
      human_readeable_string_len = atoi(optarg);
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'f':
    case '6':
      bpfFilter = optarg;
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

    case 'c':
      _customCategoryFilePath = optarg;
      break;

    case 'C':
      if((csv_fp = fopen(optarg, "w")) == NULL)
	printf("Unable to write on CSV file %s\n", optarg);
      else
	printCSVHeader();
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
      nDPI_LogLevel  = atoi(optarg);
      if(nDPI_LogLevel < 0) nDPI_LogLevel = 0;
      if(nDPI_LogLevel > 3) {
	nDPI_LogLevel = 3;
	_debug_protocols = strdup("all");
      }
      break;

    case 'h':
      help(1);
      break;

    case 'J':
      enable_joy_stats = 1;
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

    case 'w':
      results_path = strdup(optarg);
      if((results_file = fopen(results_path, "w")) == NULL) {
	printf("Unable to write in file %s: quitting\n", results_path);
	return;
      }
      break;

    case 'q':
      quiet_mode = 1;
      nDPI_LogLevel = 0;
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

    case '5':
      do_capture = 1;
      break;

    case '7':
      extcap_capture_fifo = strdup(optarg);
      break;

    case '8':
      nDPI_LogLevel = NDPI_LOG_DEBUG_EXTRA;
      _debug_protocols = strdup("all");
      break;

    case '9':
      extcap_packet_filter = ndpi_get_proto_by_name(ndpi_info_mod, optarg);
      if(extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);
      break;

    case 257:
      _debug_protocols = strdup(optarg);
      break;

    case 'T':
      max_num_tcp_dissected_pkts = atoi(optarg);
      if(max_num_tcp_dissected_pkts < 3) max_num_tcp_dissected_pkts = 3;
      break;

    case 'U':
      max_num_udp_dissected_pkts = atoi(optarg);
      if(max_num_udp_dissected_pkts < 3) max_num_udp_dissected_pkts = 3;
      break;

    default:
      help(0);
      break;
    }
  }

  if(_pcap_file[0] == NULL)
    help(0);

#ifndef USE_DPDK
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

#ifdef linux
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

#ifdef DEBUG_TRACE
  if(trace) fclose(trace);
#endif
}

/* ********************************** */

/**
 * @brief From IPPROTO to string NAME
 */
static char* ipProto2Name(u_int16_t proto_id) {
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

/* ********************************** */

#if 0
/**
 * @brief A faster replacement for inet_ntoa().
 */
char* intoaV4(u_int32_t addr, char* buf, u_int16_t bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  return(cp);
}
#endif

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

static char* is_unsafe_cipher(ndpi_cipher_weakness c) {
  switch(c) {
  case ndpi_cipher_insecure:
    return("INSECURE");
    break;

  case ndpi_cipher_weak:
    return("WEAK");
    break;

  default:
    return("OK");
  }
}

/* ********************************** */

char* printUrlRisk(ndpi_url_risk risk) {
  switch(risk) {
    case ndpi_url_no_problem:
      return("");
      break;
    case ndpi_url_possible_xss:
      return(" ** XSS **");
      break;
    case ndpi_url_possible_sql_injection:
      return(" ** SQL Injection **");
      break;
  }

  return("");
}
/* ********************************** */

/**
 * @brief Print the flow
 */
static void printFlow(u_int16_t id, struct ndpi_flow_info *flow, u_int16_t thread_id) {
  FILE *out = results_file ? results_file : stdout;
  u_int8_t known_tls;
  char buf[32], buf1[64];
  u_int i;

  if(csv_fp != NULL) {
    float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);
    double f = (double)flow->first_seen, l = (double)flow->last_seen;

    /* PLEASE KEEP IN SYNC WITH printCSVHeader() */

    fprintf(csv_fp, "%u,%u,%.3f,%.3f,%.3f,%s,%u,%s,%u,",
	    flow->flow_id,
	    flow->protocol,
	    f/1000.0, l/1000.0,
	    (l-f)/1000.0,
	    flow->src_name, ntohs(flow->src_port),
	    flow->dst_name, ntohs(flow->dst_port)
	    );

    fprintf(csv_fp, "%u.%u,%s,",
	    flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
	    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			       flow->detected_protocol, buf, sizeof(buf)));

    fprintf(csv_fp, "%u,%llu,%llu,", flow->src2dst_packets,
	    (long long unsigned int) flow->src2dst_bytes, (long long unsigned int) flow->src2dst_goodput_bytes);
    fprintf(csv_fp, "%u,%llu,%llu,", flow->dst2src_packets,
	    (long long unsigned int) flow->dst2src_bytes, (long long unsigned int) flow->dst2src_goodput_bytes);
    fprintf(csv_fp, "%.3f,%s,", data_ratio, ndpi_data_ratio2str(data_ratio));
    fprintf(csv_fp, "%.1f,%.1f", 100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
	    100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));
    
    /* IAT (Inter Arrival Time) */
    fprintf(csv_fp, "%u,%.1f,%u,%.1f,",
	    ndpi_data_min(flow->iat_flow), ndpi_data_average(flow->iat_flow), ndpi_data_max(flow->iat_flow), ndpi_data_stddev(flow->iat_flow));

    fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
	    ndpi_data_min(flow->iat_c_to_s), ndpi_data_average(flow->iat_c_to_s), ndpi_data_max(flow->iat_c_to_s), ndpi_data_stddev(flow->iat_c_to_s),
	    ndpi_data_min(flow->iat_s_to_c), ndpi_data_average(flow->iat_s_to_c), ndpi_data_max(flow->iat_s_to_c), ndpi_data_stddev(flow->iat_s_to_c));

    /* Packet Length */
    fprintf(csv_fp, "%u,%.1f,%u,%.1f,%u,%.1f,%u,%.1f,",
	    ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_stddev(flow->pktlen_c_to_s),
	    ndpi_data_min(flow->pktlen_s_to_c), ndpi_data_average(flow->pktlen_s_to_c), ndpi_data_max(flow->pktlen_s_to_c), ndpi_data_stddev(flow->pktlen_s_to_c));

    fprintf(csv_fp, "%s,%s,",
	    (flow->ssh_tls.client_info[0] != '\0')  ? flow->ssh_tls.client_info : "",
	    (flow->ssh_tls.server_info[0] != '\0')  ? flow->ssh_tls.server_info : "");

    fprintf(csv_fp, "%s,%s,%s,",
	    (flow->ssh_tls.ssl_version != 0)        ? ndpi_ssl_version2str(flow->ssh_tls.ssl_version, &known_tls) : "",
	    (flow->ssh_tls.ja3_client[0] != '\0')   ? flow->ssh_tls.ja3_client : "",
	    (flow->ssh_tls.ja3_client[0] != '\0')   ? is_unsafe_cipher(flow->ssh_tls.client_unsafe_cipher) : "");

    fprintf(csv_fp, "%s,%s,",
	    (flow->ssh_tls.ja3_server[0] != '\0')   ? flow->ssh_tls.ja3_server : "",
	    (flow->ssh_tls.ja3_server[0] != '\0')   ? is_unsafe_cipher(flow->ssh_tls.server_unsafe_cipher) : "");

    fprintf(csv_fp, "%s,%s",
	    (flow->ssh_tls.client_hassh[0] != '\0') ? flow->ssh_tls.client_hassh : "",
	    (flow->ssh_tls.server_hassh[0] != '\0') ? flow->ssh_tls.server_hassh : ""
	    );

    fprintf(csv_fp, "\n");
  }

  if((verbose != 1) && (verbose != 2))
    return;

#if 1
  fprintf(out, "\t%u", id);
#else
  fprintf(out, "\t%u(%u)", id, flow->flow_id);
#endif

  fprintf(out, "\t%s ", ipProto2Name(flow->protocol));

  fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
	  (flow->ip_version == 6) ? "[" : "",
	  flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
	  flow->bidirectional ? "<->" : "->",
	  (flow->ip_version == 6) ? "[" : "",
	  flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
	  );

  if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);
  if(enable_payload_analyzer) fprintf(out, "[flowId: %u]", flow->flow_id);

  if(enable_joy_stats) {
    /* Print entropy values for monitored flows. */
    flowGetBDMeanandVariance(flow);
    fflush(out);
    fprintf(out, "[score: %.4f]", flow->entropy.score);
  }

  fprintf(out, "[proto: ");
  if(flow->tunnel_type != ndpi_no_tunnel)
    fprintf(out, "%s:", ndpi_tunnel2str(flow->tunnel_type));

  fprintf(out, "%s/%s]",
	  ndpi_protocol2id(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			   flow->detected_protocol, buf, sizeof(buf)),
	  ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			     flow->detected_protocol, buf1, sizeof(buf1)));

  if(flow->detected_protocol.category != 0)
    fprintf(out, "[cat: %s/%u]",
	    ndpi_category_get_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				   flow->detected_protocol.category),
	    (unsigned int)flow->detected_protocol.category);

  fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
  fprintf(out, "%s %u pkts/%llu bytes]",
	  (flow->dst2src_packets > 0) ? "<->" : "->",
	  flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

  fprintf(out, "[Goodput ratio: %.1f/%.1f]",
	  100.0*((float)flow->src2dst_goodput_bytes / (float)(flow->src2dst_bytes+1)),
	  100.0*((float)flow->dst2src_goodput_bytes / (float)(flow->dst2src_bytes+1)));

  if(flow->last_seen > flow->first_seen)
    fprintf(out, "[%.2f sec]", ((float)(flow->last_seen - flow->first_seen))/(float)1000);
  else
    fprintf(out, "[< 1 sec]");

  if(flow->telnet.username[0] != '\0')  fprintf(out, "[Username: %s]", flow->telnet.username);
  if(flow->telnet.password[0] != '\0')  fprintf(out, "[Password: %s]", flow->telnet.password);
  if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);

  if(flow->info[0] != '\0') fprintf(out, "[%s]", flow->info);

  if((flow->src2dst_packets+flow->dst2src_packets) > 5) {
    if(flow->iat_c_to_s && flow->iat_s_to_c) {
      float data_ratio = ndpi_data_ratio(flow->src2dst_bytes, flow->dst2src_bytes);

      fprintf(out, "[bytes ratio: %.3f (%s)]", data_ratio, ndpi_data_ratio2str(data_ratio));

      /* IAT (Inter Arrival Time) */
      fprintf(out, "[IAT c2s/s2c min/avg/max/stddev: %u/%u %.1f/%.1f %u/%u %.1f/%.1f]",
	      ndpi_data_min(flow->iat_c_to_s),     ndpi_data_min(flow->iat_s_to_c),
	      (float)ndpi_data_average(flow->iat_c_to_s), (float)ndpi_data_average(flow->iat_s_to_c),
	      ndpi_data_max(flow->iat_c_to_s),     ndpi_data_max(flow->iat_s_to_c),
	      (float)ndpi_data_stddev(flow->iat_c_to_s),  (float)ndpi_data_stddev(flow->iat_s_to_c));

      /* Packet Length */
      fprintf(out, "[Pkt Len c2s/s2c min/avg/max/stddev: %u/%u %.1f/%.1f %u/%u %.1f/%.1f]",
	      ndpi_data_min(flow->pktlen_c_to_s), ndpi_data_min(flow->pktlen_s_to_c),
	      ndpi_data_average(flow->pktlen_c_to_s), ndpi_data_average(flow->pktlen_s_to_c),
	      ndpi_data_max(flow->pktlen_c_to_s), ndpi_data_max(flow->pktlen_s_to_c),
	      ndpi_data_stddev(flow->pktlen_c_to_s),  ndpi_data_stddev(flow->pktlen_s_to_c));
    }
  }

  if(flow->http.url[0] != '\0')
    fprintf(out, "[URL: %s%s][StatusCode: %u][ContentType: %s][UserAgent: %s]",
	    flow->http.url,
	    printUrlRisk(ndpi_validate_url(flow->http.url)),
	    flow->http.response_status_code,
	    flow->http.content_type, flow->http.user_agent);

  if(flow->ssh_tls.ssl_version != 0) fprintf(out, "[%s]", ndpi_ssl_version2str(flow->ssh_tls.ssl_version, &known_tls));
  if(flow->ssh_tls.client_info[0] != '\0') fprintf(out, "[Client: %s]", flow->ssh_tls.client_info);
  if(flow->ssh_tls.client_hassh[0] != '\0') fprintf(out, "[HASSH-C: %s]", flow->ssh_tls.client_hassh);

  if(flow->ssh_tls.ja3_client[0] != '\0') fprintf(out, "[JA3C: %s%s]", flow->ssh_tls.ja3_client,
						  print_cipher(flow->ssh_tls.client_unsafe_cipher));

  if(flow->ssh_tls.server_info[0] != '\0') fprintf(out, "[Server: %s]", flow->ssh_tls.server_info);
  if(flow->ssh_tls.server_hassh[0] != '\0') fprintf(out, "[HASSH-S: %s]", flow->ssh_tls.server_hassh);

  if(flow->ssh_tls.ja3_server[0] != '\0') fprintf(out, "[JA3S: %s%s]", flow->ssh_tls.ja3_server,
						  print_cipher(flow->ssh_tls.server_unsafe_cipher));
  if(flow->ssh_tls.server_organization[0] != '\0') fprintf(out, "[Organization: %s]", flow->ssh_tls.server_organization);

  if((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_TLS)
     || (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_TLS)) {
    if((flow->ssh_tls.sha1_cert_fingerprint[0] == 0)
       && (flow->ssh_tls.sha1_cert_fingerprint[1] == 0)
       && (flow->ssh_tls.sha1_cert_fingerprint[2] == 0))
      ; /* Looks empty */
    else {
      fprintf(out, "[Certificate SHA-1: ");
      for(i=0; i<20; i++)
	fprintf(out, "%s%02X", (i > 0) ? ":" : "",
		flow->ssh_tls.sha1_cert_fingerprint[i] & 0xFF);
      fprintf(out, "]");
    }
  }

  if(flow->ssh_tls.notBefore && flow->ssh_tls.notAfter) {
    char notBefore[32], notAfter[32];
    struct tm a, b;
    struct tm *before = gmtime_r(&flow->ssh_tls.notBefore, &a);
    struct tm *after  = gmtime_r(&flow->ssh_tls.notAfter, &b);

    strftime(notBefore, sizeof(notBefore), "%F %T", before);
    strftime(notAfter, sizeof(notAfter), "%F %T", after);

    fprintf(out, "[Validity: %s - %s]", notBefore, notAfter);
  }

  if(flow->ssh_tls.server_cipher != '\0') fprintf(out, "[Cipher: %s]", ndpi_cipher2str(flow->ssh_tls.server_cipher));
  if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);
  if(flow->dhcp_fingerprint[0] != '\0') fprintf(out, "[DHCP Fingerprint: %s]", flow->dhcp_fingerprint);

  if(flow->has_human_readeable_strings) fprintf(out, "[PLAIN TEXT (%s)]", flow->human_readeable_string_buffer);

  fprintf(out, "\n");
}

/* ********************************** */

/**
 * @brief Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node,
					    ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if((flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)
     || (flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN))
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

  if((flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN)
     && (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN))
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
  u_int16_t thread_id = *((u_int16_t *) user_data), proto;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow) {
      u_int8_t proto_guessed;

      flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct,
						      flow->ndpi_flow, enable_protocol_guess, &proto_guessed);
    }

    process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);

    proto = flow->detected_protocol.app_protocol ? flow->detected_protocol.app_protocol : flow->detected_protocol.master_protocol;

    ndpi_thread_info[thread_id].workflow->stats.protocol_counter[proto]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[proto] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.protocol_flows[proto]++;
  }
}

/* *********************************************** */

void updateScanners(struct single_flow_info **scanners, u_int32_t saddr,
                    u_int8_t version, u_int32_t dport) {
  struct single_flow_info *f;
  struct port_flow_info *p;

  HASH_FIND_INT(*scanners, (int *)&saddr, f);

  if(f == NULL) {
    f = (struct single_flow_info*)malloc(sizeof(struct single_flow_info));
    if(!f) return;
    f->saddr = saddr;
    f->version = version;
    f->tot_flows = 1;
    f->ports = NULL;

    p = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));

    if(!p) {
      free(f);
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
      pp = (struct port_flow_info*)malloc(sizeof(struct port_flow_info));
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
      &(*rootp)->left :		/* T3: follow left branch */
      &(*rootp)->right;		/* T4: follow right branch */
  }

  q = (addr_node *) malloc(sizeof(addr_node));	/* T5: key not found */
  if(q != (addr_node *)0) {	                /* make new node */
    *rootp = q;			                /* link new node to old */

    q->addr = key;
    q->version = version;
    strncpy(q->proto, proto, sizeof(q->proto));
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
  free(root);
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
  strncpy(pair.proto, proto, sizeof(pair.proto));

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
    s = (struct port_stats*)calloc(1, sizeof(struct port_stats));
    if(!s) return;

    s->port = port, s->num_pkts = num_pkts, s->num_bytes = num_bytes;
    s->num_addr = 1, s->cumulative_addr = 1; s->num_flows = 1;

    updateTopIpAddress(addr, version, proto, 1, s->top_ip_addrs, MAX_NUM_IP_ADDRESS);

    s->addr_tree = (addr_node *) malloc(sizeof(addr_node));
    if(!s->addr_tree) {
      free(s);
      return;
    }

    s->addr_tree->addr = addr;
    s->addr_tree->version = version;
    strncpy(s->addr_tree->proto, proto, sizeof(s->addr_tree->proto));
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
static int acceptable(u_int32_t num_pkts){
  return num_pkts > 5;
}

/* *********************************************** */

static int receivers_sort(void *_a, void *_b) {
  struct receiver *a = (struct receiver *)_a;
  struct receiver *b = (struct receiver *)_b;

  return(b->num_pkts - a->num_pkts);
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
static struct receiver *cutBackTo(struct receiver **receivers, u_int32_t size, u_int32_t max) {
  struct receiver *r, *tmp;
  int i=0;
  int count;

  if(size < max) //return the original table
    return *receivers;

  count = size - max;

  HASH_ITER(hh, *receivers, r, tmp) {
    if(i++ == count)
      return r;
    HASH_DEL(*receivers, r);
    free(r);
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
    if(s == NULL){
      s = (struct receiver *)malloc(sizeof(struct receiver));
      if(!s) return;

      s->addr = r->addr;
      s->version = r->version;
      s->num_pkts = r->num_pkts;

      HASH_ADD_INT(*secondary, addr, s);
    }
    else
      s->num_pkts += r->num_pkts;

    HASH_DEL(*primary, r);
    free(r);
  }
}
/* *********************************************** */

static void deleteReceivers(struct receiver *receivers) {
  struct receiver *current, *tmp;

  HASH_ITER(hh, receivers, current, tmp) {
    HASH_DEL(receivers, current);
    free(current);
  }
}

/* *********************************************** */
/* implementation of: https://jeroen.massar.ch/presentations/files/FloCon2010-TopK.pdf
 *
 * if(table1.size < max1 || acceptable){
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
static void updateReceivers(struct receiver **receivers, u_int32_t dst_addr,
                            u_int8_t version, u_int32_t num_pkts,
                            struct receiver **topReceivers) {
  struct receiver *r;
  u_int32_t size;
  int a;

  HASH_FIND_INT(*receivers, (int *)&dst_addr, r);
  if(r == NULL) {
    if(((size = HASH_COUNT(*receivers)) < MAX_TABLE_SIZE_1)
       || ((a = acceptable(num_pkts)) != 0)){
      r = (struct receiver *)malloc(sizeof(struct receiver));
      if(!r) return;

      r->addr = dst_addr;
      r->version = version;
      r->num_pkts = num_pkts;

      HASH_ADD_INT(*receivers, addr, r);

      if((size = HASH_COUNT(*receivers)) > MAX_TABLE_SIZE_2){

        HASH_SORT(*receivers, receivers_sort_asc);
        *receivers = cutBackTo(receivers, size, MAX_TABLE_SIZE_1);
        mergeTables(receivers, topReceivers);

        if((size = HASH_COUNT(*topReceivers)) > MAX_TABLE_SIZE_1){
          HASH_SORT(*topReceivers, receivers_sort_asc);
          *topReceivers = cutBackTo(topReceivers, size, MAX_TABLE_SIZE_1);
        }

        *receivers = NULL;
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
      free(p);
    }
    HASH_DEL(scanners, s);
    free(s);
  }
}

/* *********************************************** */

static void deletePortsStats(struct port_stats *stats) {
  struct port_stats *current_port, *tmp;

  HASH_ITER(hh, stats, current_port, tmp) {
    HASH_DEL(stats, current_port);
    freeIpTree(current_port->addr_tree);
    free(current_port);
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
    int r;

    sport = ntohs(flow->src_port), dport = ntohs(flow->dst_port);

    /* get app level protocol */
    if(flow->detected_protocol.master_protocol)
      ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
			 flow->detected_protocol, proto, sizeof(proto));
    else
      strncpy(proto, ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
					 flow->detected_protocol.app_protocol),sizeof(proto));

    if(((r = strcmp(ipProto2Name(flow->protocol), "TCP")) == 0)
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
    if(flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].workflow->last_time) {

      /* update stats */
      node_proto_guess_walker(node, which, depth, user_data);

      if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
        undetected_flows_deleted = 1;

      ndpi_free_flow_info_half(flow);
      ndpi_free_flow_data_analysis(flow);
      ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* *********************************************** */

/**
 * @brief On Protocol Discover - demo callback
 */
static void on_protocol_discovered(struct ndpi_workflow * workflow,
				   struct ndpi_flow_info * flow,
				   void * udata) {
  ;
}

/* *********************************************** */

#if 0
/**
 * @brief Print debug
 */
static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_LogLevel) {
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
#endif

/* *********************************************** */

/**
 * @brief Setup for detection begin
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle) {
  NDPI_PROTOCOL_BITMASK all;
  struct ndpi_workflow_prefs prefs;

  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = decode_tunnels;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = quiet_mode;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
  ndpi_thread_info[thread_id].workflow = ndpi_workflow_init(&prefs, pcap_handle);

  /* Preferences */
  ndpi_workflow_set_flow_detected_callback(ndpi_thread_info[thread_id].workflow,
					   on_protocol_discovered,
					   (void *)(uintptr_t)thread_id);

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

  // clear memory for results
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0,
	 sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);

  if(_customCategoryFilePath)
    ndpi_load_categories_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _customCategoryFilePath);

  ndpi_finalize_initalization(ndpi_thread_info[thread_id].workflow->ndpi_struct);
}

/* *********************************************** */

/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
  ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
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
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < (1024*1024)) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/(1024*1024);

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

/* *********************************************** */

/**
 * @brief Packets stats format
 */
char* formatPackets(float numPkts, char *buf) {

  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < (1000*1000)) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= (1000*1000);
    snprintf(buf, 32, "%.2f M", numPkts);
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
    snprintf(buf, buf_len, "%lu %c", (unsigned long)howMuch, unit);
  } else if(howMuch < (1024*1024)) {
    snprintf(buf, buf_len, "%.2f K%c", (float)(howMuch)/1024, unit);
  } else {
    float tmpGB = ((float)howMuch)/(1024*1024);

    if(tmpGB < 1024) {
      snprintf(buf, buf_len, "%.2f M%c", tmpGB, unit);
    } else {
      tmpGB /= 1024;

      snprintf(buf, buf_len, "%.2f G%c", tmpGB, unit);
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

static void printFlowsStats() {
  int thread_id;
  u_int32_t total_flows = 0;
  FILE *out = results_file ? results_file : stdout;

  if(enable_payload_analyzer)
    ndpi_report_payload_stats();

  for(thread_id = 0; thread_id < num_threads; thread_id++)
    total_flows += ndpi_thread_info[thread_id].workflow->num_allocated_flows;

  if((all_flows = (struct flow_info*)malloc(sizeof(struct flow_info)*total_flows)) == NULL) {
    fprintf(out, "Fatal error: not enough memory\n");
    exit(-1);
  }

  if(verbose) {
    ndpi_host_ja3_fingerprints *ja3ByHostsHashT = NULL; // outer hash table
    ndpi_ja3_fingerprints_host *hostByJA3C_ht = NULL;   // for client
    ndpi_ja3_fingerprints_host *hostByJA3S_ht = NULL;   // for server
    int i;
    ndpi_host_ja3_fingerprints *ja3ByHost_element = NULL;
    ndpi_ja3_info *info_of_element = NULL;
    ndpi_host_ja3_fingerprints *tmp = NULL;
    ndpi_ja3_info *tmp2 = NULL;
    unsigned int num_ja3_client;
    unsigned int num_ja3_server;

    fprintf(out, "\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
	ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		   node_print_known_proto_walker, &thread_id);
    }

    if((verbose == 2) || (verbose == 3)) {
      for(i = 0; i < num_flows; i++) {
	ndpi_host_ja3_fingerprints *ja3ByHostFound = NULL;
	ndpi_ja3_fingerprints_host *hostByJA3Found = NULL;

	//check if this is a ssh-ssl flow
	if(all_flows[i].flow->ssh_tls.ja3_client[0] != '\0'){
	  //looking if the host is already in the hash table
	  HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->src_ip), ja3ByHostFound);

	  //host ip -> ja3
	  if(ja3ByHostFound == NULL){
	    //adding the new host
	    ndpi_host_ja3_fingerprints *newHost = malloc(sizeof(ndpi_host_ja3_fingerprints));
	    newHost->host_client_info_hasht = NULL;
	    newHost->host_server_info_hasht = NULL;
	    newHost->ip_string = all_flows[i].flow->src_name;
	    newHost->ip = all_flows[i].flow->src_ip;
	    newHost->dns_name = all_flows[i].flow->ssh_tls.client_info;

	    ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
	    newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
	    newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
	    //adding the new ja3 fingerprint
	    HASH_ADD_KEYPTR(hh, newHost->host_client_info_hasht,
			    newJA3->ja3, strlen(newJA3->ja3), newJA3);
	    //adding the new host
	    HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
	  } else {
	    //host already in the hash table
	    ndpi_ja3_info *infoFound = NULL;

	    HASH_FIND_STR(ja3ByHostFound->host_client_info_hasht,
			  all_flows[i].flow->ssh_tls.ja3_client, infoFound);

	    if(infoFound == NULL){
	      ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
	      newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
	      newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
	      HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_client_info_hasht,
			      newJA3->ja3, strlen(newJA3->ja3), newJA3);
	    }
	  }

	  //ja3 -> host ip
	  HASH_FIND_STR(hostByJA3C_ht, all_flows[i].flow->ssh_tls.ja3_client, hostByJA3Found);
	  if(hostByJA3Found == NULL){
	    ndpi_ip_dns *newHost = malloc(sizeof(ndpi_ip_dns));

	    newHost->ip = all_flows[i].flow->src_ip;
	    newHost->ip_string = all_flows[i].flow->src_name;
	    newHost->dns_name = all_flows[i].flow->ssh_tls.client_info;;

	    ndpi_ja3_fingerprints_host *newElement = malloc(sizeof(ndpi_ja3_fingerprints_host));
	    newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_client;
	    newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.client_unsafe_cipher;
	    newElement->ipToDNS_ht = NULL;

	    HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
	    HASH_ADD_KEYPTR(hh, hostByJA3C_ht, newElement->ja3, strlen(newElement->ja3),
			    newElement);
	  } else {
	    ndpi_ip_dns *innerElement = NULL;
	    HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(all_flows[i].flow->src_ip), innerElement);
	    if(innerElement == NULL){
	      ndpi_ip_dns *newInnerElement = malloc(sizeof(ndpi_ip_dns));
	      newInnerElement->ip = all_flows[i].flow->src_ip;
	      newInnerElement->ip_string = all_flows[i].flow->src_name;
	      newInnerElement->dns_name = all_flows[i].flow->ssh_tls.client_info;
	      HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
	    }
	  }
	}

	if(all_flows[i].flow->ssh_tls.ja3_server[0] != '\0'){
	  //looking if the host is already in the hash table
	  HASH_FIND_INT(ja3ByHostsHashT, &(all_flows[i].flow->dst_ip), ja3ByHostFound);
	  if(ja3ByHostFound == NULL){
	    //adding the new host in the hash table
	    ndpi_host_ja3_fingerprints *newHost = malloc(sizeof(ndpi_host_ja3_fingerprints));
	    newHost->host_client_info_hasht = NULL;
	    newHost->host_server_info_hasht = NULL;
	    newHost->ip_string = all_flows[i].flow->dst_name;
	    newHost->ip = all_flows[i].flow->dst_ip;
	    newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;

	    ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
	    newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
	    newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
	    //adding the new ja3 fingerprint
	    HASH_ADD_KEYPTR(hh, newHost->host_server_info_hasht, newJA3->ja3,
			    strlen(newJA3->ja3), newJA3);
	    //adding the new host
	    HASH_ADD_INT(ja3ByHostsHashT, ip, newHost);
	  } else {
	    //host already in the hashtable
	    ndpi_ja3_info *infoFound = NULL;
	    HASH_FIND_STR(ja3ByHostFound->host_server_info_hasht,
			  all_flows[i].flow->ssh_tls.ja3_server, infoFound);
	    if(infoFound == NULL){
	      ndpi_ja3_info *newJA3 = malloc(sizeof(ndpi_ja3_info));
	      newJA3->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
	      newJA3->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
	      HASH_ADD_KEYPTR(hh, ja3ByHostFound->host_server_info_hasht,
			      newJA3->ja3, strlen(newJA3->ja3), newJA3);
	    }
	  }

	  HASH_FIND_STR(hostByJA3S_ht, all_flows[i].flow->ssh_tls.ja3_server, hostByJA3Found);
	  if(hostByJA3Found == NULL){
	    ndpi_ip_dns *newHost = malloc(sizeof(ndpi_ip_dns));

	    newHost->ip = all_flows[i].flow->dst_ip;
	    newHost->ip_string = all_flows[i].flow->dst_name;
	    newHost->dns_name = all_flows[i].flow->ssh_tls.server_info;;

	    ndpi_ja3_fingerprints_host *newElement = malloc(sizeof(ndpi_ja3_fingerprints_host));
	    newElement->ja3 = all_flows[i].flow->ssh_tls.ja3_server;
	    newElement->unsafe_cipher = all_flows[i].flow->ssh_tls.server_unsafe_cipher;
	    newElement->ipToDNS_ht = NULL;

	    HASH_ADD_INT(newElement->ipToDNS_ht, ip, newHost);
	    HASH_ADD_KEYPTR(hh, hostByJA3S_ht, newElement->ja3, strlen(newElement->ja3),
			    newElement);
	  } else {
	    ndpi_ip_dns *innerElement = NULL;

	    HASH_FIND_INT(hostByJA3Found->ipToDNS_ht, &(all_flows[i].flow->dst_ip), innerElement);
	    if(innerElement == NULL){
	      ndpi_ip_dns *newInnerElement = malloc(sizeof(ndpi_ip_dns));
	      newInnerElement->ip = all_flows[i].flow->dst_ip;
	      newInnerElement->ip_string = all_flows[i].flow->dst_name;
	      newInnerElement->dns_name = all_flows[i].flow->ssh_tls.server_info;
	      HASH_ADD_INT(hostByJA3Found->ipToDNS_ht, ip, newInnerElement);
	    }
	  }

	}
      }

      if(ja3ByHostsHashT) {
	ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
	ndpi_ja3_fingerprints_host *tmp3 = NULL;
	ndpi_ip_dns *innerHashEl = NULL;
	ndpi_ip_dns *tmp4 = NULL;

	if(verbose == 2) {
	  /* for each host the number of flow with a ja3 fingerprint is printed */
	  i = 1;

	  fprintf(out, "JA3 Host Stats: \n");
	  fprintf(out, "\t\t IP %-24s \t %-10s \n", "Address", "# JA3C");

	  for(ja3ByHost_element = ja3ByHostsHashT; ja3ByHost_element != NULL;
	      ja3ByHost_element = ja3ByHost_element->hh.next) {
	    num_ja3_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
	    num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);

	    if(num_ja3_client > 0) {
	      fprintf(out, "\t%d\t %-24s \t %-7d\n",
		      i,
		      ja3ByHost_element->ip_string,
		      num_ja3_client
		      );
	      i++;
	    }

	  }
	} else if(verbose == 3) {
	  int i = 1;
	  int againstRepeat;
	  ndpi_ja3_fingerprints_host *hostByJA3Element = NULL;
	  ndpi_ja3_fingerprints_host *tmp3 = NULL;
	  ndpi_ip_dns *innerHashEl = NULL;
	  ndpi_ip_dns *tmp4 = NULL;

	  //for each host it is printted the JA3C and JA3S, along the server name (if any)
	  //and the security status

	  fprintf(out, "JA3C/JA3S Host Stats: \n");
	  fprintf(out, "\t%-7s %-24s %-34s %s\n", "", "IP", "JA3C", "JA3S");

	  //reminder
	  //ja3ByHostsHashT: hash table <ip, (ja3, ht_client, ht_server)>
	  //ja3ByHost_element: element of ja3ByHostsHashT
	  //info_of_element: element of the inner hash table of ja3ByHost_element
	  HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
	    num_ja3_client = HASH_COUNT(ja3ByHost_element->host_client_info_hasht);
	    num_ja3_server = HASH_COUNT(ja3ByHost_element->host_server_info_hasht);
	    againstRepeat = 0;
	    if(num_ja3_client > 0) {
	      HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
		fprintf(out, "\t%-7d %-24s %s %s\n",
			i,
			ja3ByHost_element->ip_string,
			info_of_element->ja3,
			print_cipher(info_of_element->unsafe_cipher)
			);
		againstRepeat = 1;
		i++;
	      }
	    }

	    if(num_ja3_server > 0) {
	      HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
		fprintf(out, "\t%-7d %-24s %-34s %s %s %s%s%s\n",
			i,
			ja3ByHost_element->ip_string,
			"",
			info_of_element->ja3,
			print_cipher(info_of_element->unsafe_cipher),
			ja3ByHost_element->dns_name[0] ? "[" : "",
			ja3ByHost_element->dns_name,
			ja3ByHost_element->dns_name[0] ? "]" : ""
			);
		i++;
	      }
	    }
	  }

	  i = 1;

	  fprintf(out, "\nIP/JA3 Distribution:\n");
	  fprintf(out, "%-15s %-39s %-26s\n", "", "JA3", "IP");
	  HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
	    againstRepeat = 0;
	    HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
	      if(againstRepeat == 0) {
		fprintf(out, "\t%-7d JA3C %s",
			i,
			hostByJA3Element->ja3
			);
		fprintf(out, "   %-15s %s\n",
			innerHashEl->ip_string,
			print_cipher(hostByJA3Element->unsafe_cipher)
			);
		againstRepeat = 1;
		i++;
	      } else {
		fprintf(out, "\t%45s", "");
		fprintf(out, "   %-15s %s\n",
			innerHashEl->ip_string,
			print_cipher(hostByJA3Element->unsafe_cipher)
			);
	      }
	    }
	  }
	  HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
	    againstRepeat = 0;
	    HASH_ITER(hh, hostByJA3Element->ipToDNS_ht, innerHashEl, tmp4) {
	      if(againstRepeat == 0) {
		fprintf(out, "\t%-7d JA3S %s",
			i,
			hostByJA3Element->ja3
			);
		fprintf(out, "   %-15s %-10s %s%s%s\n",
			innerHashEl->ip_string,
			print_cipher(hostByJA3Element->unsafe_cipher),
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
			print_cipher(hostByJA3Element->unsafe_cipher),
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
	HASH_ITER(hh, ja3ByHostsHashT, ja3ByHost_element, tmp) {
	  HASH_ITER(hh, ja3ByHost_element->host_client_info_hasht, info_of_element, tmp2) {
	    if(ja3ByHost_element->host_client_info_hasht)
	      HASH_DEL(ja3ByHost_element->host_client_info_hasht, info_of_element);
	    free(info_of_element);
	  }
	  HASH_ITER(hh, ja3ByHost_element->host_server_info_hasht, info_of_element, tmp2) {
	    if(ja3ByHost_element->host_server_info_hasht)
	      HASH_DEL(ja3ByHost_element->host_server_info_hasht, info_of_element);
	    free(info_of_element);
	  }
	  HASH_DEL(ja3ByHostsHashT, ja3ByHost_element);
	  free(ja3ByHost_element);
	}

	HASH_ITER(hh, hostByJA3C_ht, hostByJA3Element, tmp3) {
	  HASH_ITER(hh, hostByJA3C_ht->ipToDNS_ht, innerHashEl, tmp4) {
	    if(hostByJA3Element->ipToDNS_ht)
	      HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
	    free(innerHashEl);
	  }
	  HASH_DEL(hostByJA3C_ht, hostByJA3Element);
	  free(hostByJA3Element);
	}

	hostByJA3Element = NULL;
	HASH_ITER(hh, hostByJA3S_ht, hostByJA3Element, tmp3) {
	  HASH_ITER(hh, hostByJA3S_ht->ipToDNS_ht, innerHashEl, tmp4) {
	    if(hostByJA3Element->ipToDNS_ht)
	      HASH_DEL(hostByJA3Element->ipToDNS_ht, innerHashEl);
	    free(innerHashEl);
	  }
	  HASH_DEL(hostByJA3S_ht, hostByJA3Element);
	  free(hostByJA3Element);
	}
      }
    }

    /* Print all flows stats */

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    if(verbose > 1) {
      for(i=0; i<num_flows; i++)
	printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
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
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0) {
	for(i=0; i<NUM_ROOTS; i++)
	  ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		     node_print_unknown_proto_walker, &thread_id);
      }
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);

  } else if(csv_fp != NULL) {
    int i;

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
	ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		   node_print_known_proto_walker, &thread_id);
    }

    for(i=0; i<num_flows; i++)
	printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);
  }

  free(all_flows);
}

/* *********************************************** */

/**
 * @brief Print result
 */
static void printResults(u_int64_t processing_time_usec, u_int64_t setup_time_usec) {
  u_int32_t i;
  u_int64_t total_flow_bytes = 0;
  u_int32_t avg_pkt_size = 0;
  struct ndpi_stats cumulative_stats;
  int thread_id;
  char buf[32];
  long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
       && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
      continue;

    for(i=0; i<NUM_ROOTS; i++) {
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
		 node_proto_guess_walker, &thread_id);
      if(verbose == 3)
	ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i],
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
    }

    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count;
    cumulative_stats.tcp_count   += ndpi_thread_info[thread_id].workflow->stats.tcp_count;
    cumulative_stats.udp_count   += ndpi_thread_info[thread_id].workflow->stats.udp_count;
    cumulative_stats.mpls_count  += ndpi_thread_info[thread_id].workflow->stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].workflow->stats.pppoe_count;
    cumulative_stats.vlan_count  += ndpi_thread_info[thread_id].workflow->stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].workflow->stats.fragmented_count;
    for(i = 0; i < sizeof(cumulative_stats.packet_len)/sizeof(cumulative_stats.packet_len[0]); i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].workflow->stats.packet_len[i];
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].workflow->stats.max_packet_len;
  }

  if(cumulative_stats.total_wire_bytes == 0)
    goto free_stats;

  if(!quiet_mode) {
    printf("\nnDPI Memory statistics:\n");
    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(ndpi_get_ndpi_detection_module_size(), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(sizeof(struct ndpi_flow_struct), buf, sizeof(buf)));
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

      if(processing_time_usec > 0) {
	char buf[32], buf1[32], when[64];
	float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)processing_time_usec;
	float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)processing_time_usec;
	float traffic_duration;

	if(live_capture) traffic_duration = processing_time_usec;
	else traffic_duration = (pcap_end.tv_sec*1000000 + pcap_end.tv_usec) - (pcap_start.tv_sec*1000000 + pcap_start.tv_usec);

	printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
	t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)traffic_duration;
	b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)traffic_duration;

	strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime(&pcap_start.tv_sec));
	printf("\tAnalysis begin:        %s\n", when);
	strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime(&pcap_end.tv_sec));
	printf("\tAnalysis end:          %s\n", when);
	printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
	printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
      }

      if(enable_protocol_guess)
	printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);
  }


  if(!quiet_mode) printf("\n\nDetected protocols:\n");
  for(i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].workflow->ndpi_struct); i++) {
    ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_thread_info[0].workflow->ndpi_struct, i);

    if(cumulative_stats.protocol_counter[i] > 0) {
      breed_stats[breed] += (long long unsigned int)cumulative_stats.protocol_counter_bytes[i];

      if(results_file)
	fprintf(results_file, "%s\t%llu\t%llu\t%u\n",
		ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
		(long long unsigned int)cumulative_stats.protocol_counter[i],
		(long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
		cumulative_stats.protocol_flows[i]);

      if((!quiet_mode)) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u\n",
	       ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
	       (long long unsigned int)cumulative_stats.protocol_counter[i],
	       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	       cumulative_stats.protocol_flows[i]);
      }

      total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
    }
  }

  if((!quiet_mode)) {
    printf("\n\nProtocol statistics:\n");

    for(i=0; i < NUM_BREEDS; i++) {
      if(breed_stats[i] > 0) {
	printf("\t%-20s %13llu bytes\n",
	       ndpi_get_proto_breed_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
	       breed_stats[i]);
      }
    }
  }

  // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

  printFlowsStats();

  if(verbose == 3) {
    HASH_SORT(srcStats, port_stats_sort);
    HASH_SORT(dstStats, port_stats_sort);

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

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}


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

  if(bpfFilter != NULL) {
    struct bpf_program fcode;

    if(pcap_compile(pcap_handle, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pcap_handle));
    } else {
      if(pcap_setfilter(pcap_handle, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pcap_handle));
      } else
	printf("Successfully set BPF filter to '%s'\n", bpfFilter);
    }
  }
}


/**
 * @brief Open a pcap file or a specified device - Always returns a valid pcap_t
 */
static pcap_t * openPcapFileOrDevice(u_int16_t thread_id, const u_char * pcap_file) {
  u_int snaplen = 1536;
  int promisc = 1;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
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
  if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen,
				   promisc, 500, pcap_error_buffer)) == NULL) {
    capture_for = capture_until = 0;

    live_capture = 0;
    num_threads = 1; /* Open pcap files in single threads mode */

    /* trying to open a pcap file */
    if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error_buffer)) == NULL) {
      char filename[256] = { 0 };

      if(strstr((char*)pcap_file, (char*)".pcap"))
	printf("ERROR: could not open pcap file %s: %s\n", pcap_file, pcap_error_buffer);
      else if((getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) != 0)
	      || ((pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) == NULL)) {
        printf("ERROR: could not open playlist %s: %s\n", filename, pcap_error_buffer);
        exit(-1);
      } else {
        if((!quiet_mode))
	  printf("Reading packets from playlist %s...\n", pcap_file);
      }
    } else {
      if((!quiet_mode))
	printf("Reading packets from pcap file %s...\n", pcap_file);
    }
  } else {
    live_capture = 1;

    if((!quiet_mode)) {
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
    if((!quiet_mode))
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
  u_int16_t thread_id = *((u_int16_t*)args);

  /* allocate an exact size buffer to check overflows */
  uint8_t *packet_checked = malloc(header->caplen);

  memcpy(packet_checked, packet, header->caplen);
  p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked);

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
  if(trace) fprintf(trace, "Found %u bytes packet %u.%u\n", header->caplen, p.app_protocol, p.master_protocol);
#endif

  if(extcap_dumper
     && ((extcap_packet_filter == (u_int16_t)-1)
	 || (p.app_protocol == extcap_packet_filter)
	 || (p.master_protocol == extcap_packet_filter)
       )
    ) {
    struct pcap_pkthdr h;
    uint32_t *crc, delta = sizeof(struct ndpi_packet_trailer) + 4 /* ethernet trailer */;
    struct ndpi_packet_trailer *trailer;

    memcpy(&h, header, sizeof(h));

    if(h.caplen > (sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4)) {
      printf("INTERNAL ERROR: caplen=%u\n", h.caplen);
      h.caplen = sizeof(extcap_buf)-sizeof(struct ndpi_packet_trailer) - 4;
    }

    trailer = (struct ndpi_packet_trailer*)&extcap_buf[h.caplen];
    memcpy(extcap_buf, packet, h.caplen);
    memset(trailer, 0, sizeof(struct ndpi_packet_trailer));
    trailer->magic = htonl(0x19680924);
    trailer->master_protocol = htons(p.master_protocol), trailer->app_protocol = htons(p.app_protocol);
    ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct, p, trailer->name, sizeof(trailer->name));
    crc = (uint32_t*)&extcap_buf[h.caplen+sizeof(struct ndpi_packet_trailer)];
    *crc = ethernet_crc32((const void*)extcap_buf, h.caplen+sizeof(struct ndpi_packet_trailer));
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

  if((pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
    int i;
    u_int64_t processing_time_usec, setup_time_usec;

    gettimeofday(&end, NULL);
    processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

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
  free(packet_checked);
}

/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
    pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &ndpi_process_packet, (u_char*)&thread_id);
}

/**
 * @brief Process a running thread
 */
void * processing_thread(void *_thread_id) {
  long thread_id = (long) _thread_id;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];

#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
  if(core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else {
      if((!quiet_mode)) printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
    }
  } else
#endif
    if((!quiet_mode)) printf("Running thread %ld...\n", thread_id);

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

  if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
    char filename[256];

    if(getNextPcapFileFromPlaylist(thread_id, filename, sizeof(filename)) == 0 &&
       (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
      configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }
#endif

  return NULL;
}


/**
 * @brief Begin, process, end detection process
 */
void test_lib() {
  struct timeval end;
  u_int64_t processing_time_usec, setup_time_usec;
  long thread_id;

#ifdef DEBUG_TRACE
  if(trace) fprintf(trace, "Num threads: %d\n", num_threads);
#endif

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    pcap_t *cap;

#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, "Opening %s\n", (const u_char*)_pcap_file[thread_id]);
#endif

    cap = openPcapFileOrDevice(thread_id, (const u_char*)_pcap_file[thread_id]);
    setupDetection(thread_id, cap);
  }

  gettimeofday(&begin, NULL);

  int status;
  void * thd_res;

  /* Running processing threads */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    /* check pthreade_create return value */
    if(status != 0) {
      fprintf(stderr, "error on create %ld thread\n", thread_id);
      exit(-1);
    }
  }
  /* Waiting for completion */
  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    status = pthread_join(ndpi_thread_info[thread_id].pthread, &thd_res);
    /* check pthreade_join return value */
    if(status != 0) {
      fprintf(stderr, "error on join %ld thread\n", thread_id);
      exit(-1);
    }
    if(thd_res != NULL) {
      fprintf(stderr, "error on returned value of %ld joined thread\n", thread_id);
      exit(-1);
    }
  }

  gettimeofday(&end, NULL);
  processing_time_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
  setup_time_usec = begin.tv_sec*1000000 + begin.tv_usec - (startup_time.tv_sec*1000000 + startup_time.tv_usec);

  /* Printing cumulative results */
  printResults(processing_time_usec, setup_time_usec);

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    terminateDetection(thread_id);
  }
}

/* *********************************************** */

void automataUnitTest() {
  void *automa;

  assert((automa = ndpi_init_automa()));
  assert(ndpi_add_string_to_automa(automa, "hello") == 0);
  assert(ndpi_add_string_to_automa(automa, "world") == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 1);
  ndpi_free_automa(automa);
}

/* *********************************************** */

void serializerUnitTest() {
  ndpi_serializer serializer, deserializer;
  int i;
  u_int8_t trace = 0;

  assert(ndpi_init_serializer(&serializer, ndpi_serialization_format_tlv) != -1);

  for(i=0; i<16; i++) {
    char kbuf[32], vbuf[32];
    assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);

    snprintf(kbuf, sizeof(kbuf), "Hello %u", i);
    snprintf(vbuf, sizeof(vbuf), "World %u", i);
    assert(ndpi_serialize_uint32_string(&serializer, i, "Hello") != -1);
    assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
    assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
    assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
  }

  if(trace)
    printf("Serialization size: %u\n", ndpi_serializer_get_buffer_len(&serializer));

  assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

  while(1) {
    ndpi_serialization_type kt, et;
    et = ndpi_deserialize_get_item_type(&deserializer, &kt);

    if(et == ndpi_serialization_unknown)
      break;
    else {
      u_int32_t k32, v32;
      ndpi_string ks, vs;
      float vf;

      switch(kt) {
        case ndpi_serialization_uint32:
          ndpi_deserialize_key_uint32(&deserializer, &k32);
	  if(trace) printf("%u=", k32);
          break;
        case ndpi_serialization_string:
          ndpi_deserialize_key_string(&deserializer, &ks);
          if (trace) {
	    u_int8_t bkp = ks.str[ks.str_len];
	    ks.str[ks.str_len] = '\0';
            printf("%s=", ks.str);
	    ks.str[ks.str_len] = bkp;
          }
          break;
        default:
          printf("Unsupported TLV key type %u\n", kt);
          return;
      }

      switch(et) {
      case ndpi_serialization_uint32:
	assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
	if(trace) printf("%u\n", v32);
	break;

      case ndpi_serialization_string:
	assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
	if(trace) {
	  u_int8_t bkp = vs.str[vs.str_len];
	  vs.str[vs.str_len] = '\0';
	  printf("%s\n", vs.str);
	  vs.str[vs.str_len] = bkp;
	}
	break;

      case ndpi_serialization_float:
	assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
	if(trace) printf("%f\n", vf);
	break;

      default:
	if (trace) printf("\n");
        printf("serializerUnitTest: unsupported type %u detected!\n", et);
        return;
	break;
      }
    }

    ndpi_deserialize_next(&deserializer);
  }

  ndpi_term_serializer(&serializer);
}

/* *********************************************** */

// #define RUN_DATA_ANALYSIS_THEN_QUIT 1

void analyzeUnitTest() {
  struct ndpi_analyze_struct *s = ndpi_alloc_data_analysis(32);
  u_int32_t i;

  for(i=0; i<256; i++) {
    ndpi_data_add_value(s, rand()*i);
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

  ndpi_free_data_analysis(s);

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


/**
   @brief MAIN FUNCTION
**/
#ifdef APP_HAS_OWN_MAIN
int orginal_main(int argc, char **argv) {
#else
  int main(int argc, char **argv) {
#endif
    int i;

    if(ndpi_get_api_version() != NDPI_API_VERSION) {
      printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
      return(-1);
    }

    /* Internal checks */
    automataUnitTest();
    serializerUnitTest();
    analyzeUnitTest();

    gettimeofday(&startup_time, NULL);
    ndpi_info_mod = ndpi_init_detection_module(ndpi_no_prefs);

    if(ndpi_info_mod == NULL) return -1;

    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

    parseOptions(argc, argv);

    if(!quiet_mode) {
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

    if(results_path)  free(results_path);
    if(results_file)  fclose(results_file);
    if(extcap_dumper) pcap_dump_close(extcap_dumper);
    if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);
    if(csv_fp)        fclose(csv_fp);

    return 0;
  }

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

/**
   @brief Timezone
**/
  struct timezone {
    int tz_minuteswest; /* minutes W of Greenwich */
    int tz_dsttime;     /* type of dst correction */
  };


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
