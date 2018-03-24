/*
 * ndpiReader.c
 *
 * Copyright (C) 2011-17 - ntop.org
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

#ifdef HAVE_JSON_C
#include <json.h>
#endif

#include "ndpi_util.h"

/** Client parameters **/
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interfaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file           = NULL;
static char *results_path           = NULL;
static char * bpfFilter             = NULL; /**< bpf filter  */
static char *_protoFilePath         = NULL; /**< Protocol file path  */
#ifdef HAVE_JSON_C
static char *_statsFilePath         = NULL; /**< Top stats file path */
static char *_diagnoseFilePath      = NULL; /**< Top stats file path */
static char *_jsonFilePath          = NULL; /**< JSON file path  */
static FILE *stats_fp               = NULL; /**< for Top Stats JSON file */
#endif
#ifdef HAVE_JSON_C
static json_object *jArray_known_flows, *jArray_unknown_flows;
static json_object *jArray_topStats;
#endif
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
/** User preferences **/
static u_int8_t enable_protocol_guess = 1, verbose = 0, json_flag = 0;
int nDPI_LogLevel = 0;
char *_debug_protocols = NULL;
static u_int8_t stats_flag = 0, bpf_filter_flag = 0;
#ifdef HAVE_JSON_C
static u_int8_t file_first_time = 1;
#endif
static u_int32_t pcap_analysis_duration = (u_int32_t)-1;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static struct timeval begin, end;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif
static struct timeval pcap_start, pcap_end;
/** Detection parameters **/
static time_t capture_for = 0;
static time_t capture_until = 0;
static u_int32_t num_flows;
static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;

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
  u_int8_t hasTopHost; /* as boolean flag*/
  u_int32_t top_host; /*host that is contributed to > 95% of traffic*/
  u_int8_t version; /* top host's ip version */
  char proto[16]; /*application level protocol of top host */
  UT_hash_handle hh; /* makes this structure hashable */
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


void test_lib(); /* Forward */

/* ********************************** */

#ifdef DEBUG_TRACE
FILE *trace = NULL;
#endif

/********************** FUNCTIONS ********************* */

/**
 * @brief Set main components necessary to the detection
 */
static void setupDetection(u_int16_t thread_id, pcap_t * pcap_handle);

/**
 * @brief Print help instructions
 */
static void help(u_int long_help) {
  printf("Welcome to nDPI %s\n\n", ndpi_revision());

  printf("ndpiReader -i <file|device> [-f <filter>][-s <duration>][-m <duration>]\n"
	 "          [-p <protos>][-l <loops> [-q][-d][-h][-t][-v <level>]\n"
	 "          [-n <threads>] [-w <file>] [-j <file>] [-x <file>] \n\n"
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
	 "  -v <1|2|3>                | Verbose 'unknown protocol' packet print.\n"
	 "                            | 1 = verbose\n"
	 "                            | 2 = very verbose\n"
	 "                            | 3 = port stats\n"
	 "  -V <1-4>                  | nDPI logging level\n"
	 "                            | 1 - trace, 2 - debug, 3 - full debug\n"
	 "                            | >3 - full debug + dbg_proto = all\n"
	 "  -b <file.json>            | Specify a file to write port based diagnose statistics\n"
	 "  -x <file.json>            | Produce bpf filters for specified diagnose file. Use\n"
	 "                            | this option only for .json files generated with -b flag.\n");


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
    printf("\n\nSupported protocols:\n");
    num_threads = 1;
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
  { "json", required_argument, NULL, 'j'},
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

int cmpProto(const void *_a, const void *_b) {
  struct ndpi_proto_sorter *a = (struct ndpi_proto_sorter*)_a;
  struct ndpi_proto_sorter *b = (struct ndpi_proto_sorter*)_b;

  return(strcmp(a->name, b->name));
}

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

void extcap_config() {
  int i, argidx = 0;
  struct ndpi_proto_sorter *protos;

  /* -i <interface> */
  printf("arg {number=%d}{call=-i}{display=Capture Interface}{type=string}"
	 "{tooltip=The interface name}\n", argidx++);
  printf("arg {number=%d}{call=-i}{display=Pcap File to Analyze}{type=fileselect}"
	 "{tooltip=The pcap file to analyze (if the interface is unspecified)}\n", argidx++);

  protos = (struct ndpi_proto_sorter*)malloc(sizeof(struct ndpi_proto_sorter) * ndpi_info_mod->ndpi_num_supported_protocols);
  if(!protos) exit(0);

  for(i=0; i<(int) ndpi_info_mod->ndpi_num_supported_protocols; i++) {
    protos[i].id = i;
    snprintf(protos[i].name, sizeof(protos[i].name), "%s", ndpi_info_mod->proto_defaults[i].protoName);
  }

  qsort(protos, ndpi_info_mod->ndpi_num_supported_protocols, sizeof(struct ndpi_proto_sorter), cmpProto);

  printf("arg {number=%d}{call=-9}{display=nDPI Protocol Filter}{type=selector}"
	 "{tooltip=nDPI Protocol to be filtered}\n", argidx);

  printf("value {arg=%d}{value=%d}{display=%s}\n", argidx, -1, "All Protocols (no nDPI filtering)");

  for(i=0; i<(int)ndpi_info_mod->ndpi_num_supported_protocols; i++)
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

  while ((opt = getopt_long(argc, argv, "df:g:i:hp:l:s:tv:V:n:j:rp:w:q0123:456:7:89:m:b:x:", longopts, &option_idx)) != EOF) {
#ifdef DEBUG_TRACE
    if(trace) fprintf(trace, " #### -%c [%s] #### \n", opt, optarg ? optarg : "");
#endif

    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'i':
    case '3':
      _pcap_file[0] = optarg;
      break;

    case 'b':
#ifndef HAVE_JSON_C
      printf("WARNING: this copy of ndpiReader has been compiled without JSON-C: json export disabled\n");
#else
      _statsFilePath = optarg;
      stats_flag = 1;
#endif
      break;

    case 'm':
      pcap_analysis_duration = atol(optarg);
      break;

    case 'x':
#ifndef HAVE_JSON_C
      printf("WARNING: this copy of ndpiReader has been compiled without JSON-C: json export disabled\n");
#else
      _diagnoseFilePath = optarg;
      bpf_filter_flag = 1;
#endif
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
      if (extcap_packet_filter == NDPI_PROTOCOL_UNKNOWN) extcap_packet_filter = atoi(optarg);
      break;
    
    case 257:
      _debug_protocols = strdup(optarg);
      break;

    default:
      help(0);
      break;
    }
  }

  if(!bpf_filter_flag) {
    if(do_capture) {
      quiet_mode = 1;
      extcap_capture();
    }

    // check parameters
    if(!bpf_filter_flag && (_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0)) {
      help(0);
    }

    if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
      num_threads = 0;               /* setting number of threads = number of interfaces */
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

#ifdef DEBUG_TRACE
  if(trace) fclose(trace);
#endif
}


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


/**
 * @brief A faster replacement for inet_ntoa().
 */
char* intoaV4(u_int32_t addr, char* buf, u_int16_t bufLen) {

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

/**
 * @brief Print the flow
 */
static void printFlow(u_int16_t id, struct ndpi_flow_info *flow, u_int16_t thread_id) {
#ifdef HAVE_JSON_C
  json_object *jObj;
#endif
  FILE *out = results_file ? results_file : stdout;

  if((verbose != 1) && (verbose != 2))
    return;

  if(!json_flag) {
    fprintf(out, "\t%u", id);

    fprintf(out, "\t%s ", ipProto2Name(flow->protocol));

    fprintf(out, "%s%s%s:%u %s %s%s%s:%u ",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->src_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->src_port),
	    flow->bidirectional ? "<->" : "->",
	    (flow->ip_version == 6) ? "[" : "",
	    flow->dst_name, (flow->ip_version == 6) ? "]" : "", ntohs(flow->dst_port)
	    );

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

    if(flow->detected_protocol.master_protocol) {
      char buf[64];

      fprintf(out, "[proto: %u.%u/%s]",
	      flow->detected_protocol.master_protocol, flow->detected_protocol.app_protocol,
	      ndpi_protocol2name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
				 flow->detected_protocol, buf, sizeof(buf)));
    } else
      fprintf(out, "[proto: %u/%s]",
	      flow->detected_protocol.app_protocol,
	      ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct, flow->detected_protocol.app_protocol));

    fprintf(out, "[%u pkts/%llu bytes ", flow->src2dst_packets, (long long unsigned int) flow->src2dst_bytes);
    fprintf(out, "%s %u pkts/%llu bytes]",
	    (flow->dst2src_packets > 0) ? "<->" : "->",
	    flow->dst2src_packets, (long long unsigned int) flow->dst2src_bytes);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
    if(flow->info[0] != '\0') fprintf(out, "[%s]", flow->info);

    if(flow->ssh_ssl.client_info[0] != '\0') fprintf(out, "[client: %s]", flow->ssh_ssl.client_info);
    if(flow->ssh_ssl.server_info[0] != '\0') fprintf(out, "[server: %s]", flow->ssh_ssl.server_info);
    if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

    fprintf(out, "\n");
  } else {
#ifdef HAVE_JSON_C
    jObj = json_object_new_object();

    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"host_a.name",json_object_new_string(flow->src_name));
    json_object_object_add(jObj,"host_a.port",json_object_new_int(ntohs(flow->src_port)));
    json_object_object_add(jObj,"host_b.name",json_object_new_string(flow->dst_name));
    json_object_object_add(jObj,"host_b.port",json_object_new_int(ntohs(flow->dst_port)));

    if(flow->detected_protocol.master_protocol)
      json_object_object_add(jObj,"detected.master_protocol",json_object_new_int(flow->detected_protocol.master_protocol));

    json_object_object_add(jObj,"detected.app_protocol",json_object_new_int(flow->detected_protocol.app_protocol));

    if(flow->detected_protocol.master_protocol) {
      char tmp[256];

      snprintf(tmp, sizeof(tmp), "%s.%s",
	       ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct, flow->detected_protocol.master_protocol),
	       ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct, flow->detected_protocol.app_protocol));

      json_object_object_add(jObj,"detected.protocol.name",
			     json_object_new_string(tmp));
    } else
      json_object_object_add(jObj,"detected.protocol.name",
			     json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[thread_id].workflow->ndpi_struct,
									flow->detected_protocol.app_protocol)));

    json_object_object_add(jObj,"packets",json_object_new_int(flow->src2dst_packets + flow->dst2src_packets));
    json_object_object_add(jObj,"bytes",json_object_new_int(flow->src2dst_bytes + flow->dst2src_bytes));

    if(flow->host_server_name[0] != '\0')
      json_object_object_add(jObj,"host.server.name",json_object_new_string(flow->host_server_name));

    if((flow->ssh_ssl.client_info[0] != '\0') || (flow->ssh_ssl.server_info[0] != '\0')) {
      json_object *sjObj = json_object_new_object();

      if(flow->ssh_ssl.client_info[0] != '\0')
	json_object_object_add(sjObj, "client", json_object_new_string(flow->ssh_ssl.client_info));

      if(flow->ssh_ssl.server_info[0] != '\0')
	json_object_object_add(sjObj, "server", json_object_new_string(flow->ssh_ssl.server_info));

      json_object_object_add(jObj, "ssh_ssl", sjObj);
    }

    if(json_flag == 1)
      json_object_array_add(jArray_known_flows,jObj);
    else if(json_flag == 2)
      json_object_array_add(jArray_unknown_flows,jObj);
#endif
  }
}


/**
 * @brief Unknown Proto Walker
 */
static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
     /* Avoid walking the same node multiple times */
     all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
     num_flows++;
  }
}

/**
 * @brief Known Proto Walker
 */
static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

  struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) {
     /* Avoid walking the same node multiple times */
     all_flows[num_flows].thread_id = thread_id, all_flows[num_flows].flow = flow;
     num_flows++;
  }
}


/**
 * @brief Guess Undetected Protocol
 */
static u_int16_t node_guess_undetected_protocol(u_int16_t thread_id, struct ndpi_flow_info *flow) {

  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].workflow->ndpi_struct,
							   flow->protocol,
							   ntohl(flow->src_ip),
							   ntohs(flow->src_port),
							   ntohl(flow->dst_ip),
							   ntohs(flow->dst_port));
  // printf("Guess state: %u\n", flow->detected_protocol);
  if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
    ndpi_thread_info[thread_id].workflow->stats.guessed_flow_protocols++;

  return(flow->detected_protocol.app_protocol);
}


/**
 * @brief Proto Guess Walker
 */
static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if((!flow->detection_completed) && flow->ndpi_flow)
      flow->detected_protocol = ndpi_detection_giveup(ndpi_thread_info[0].workflow->ndpi_struct, flow->ndpi_flow);

    if(enable_protocol_guess) {
      if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
	node_guess_undetected_protocol(thread_id, flow);
      }
    }

    process_ndpi_collected_info(ndpi_thread_info[thread_id].workflow, flow);
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter[flow->detected_protocol.app_protocol]       += flow->src2dst_packets + flow->dst2src_packets;
    ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes[flow->detected_protocol.app_protocol] += flow->src2dst_bytes + flow->dst2src_bytes;
    ndpi_thread_info[thread_id].workflow->stats.protocol_flows[flow->detected_protocol.app_protocol]++;
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

  while (*rootp != (addr_node *)0) {
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
  if (root == NULL)
    return;

  freeIpTree(root->left);
  freeIpTree(root->right);
  free(root);
  root = NULL;
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
 * if (table1.size < max1 || acceptable){
 *    create new element and add to the table1
 *    if (table1.size > max2) {
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

#ifdef HAVE_JSON_C
static void saveReceiverStats(json_object **jObj_group,
                              struct receiver **receivers,
                              u_int64_t total_pkt_count) {

  json_object *jArray_stats  = json_object_new_array();
  struct receiver *r, *tmp;
  int i = 0;

  HASH_ITER(hh, *receivers, r, tmp) {
    json_object *jObj_stat = json_object_new_object();
    char addr_name[48];

    if(r->version == IPVERSION)
      inet_ntop(AF_INET, &(r->addr), addr_name, sizeof(addr_name));
    else
      inet_ntop(AF_INET6, &(r->addr),  addr_name, sizeof(addr_name));


    json_object_object_add(jObj_stat,"ip.address",json_object_new_string(addr_name));
    json_object_object_add(jObj_stat,"packets.number", json_object_new_int(r->num_pkts));
    json_object_object_add(jObj_stat,"packets.percent",json_object_new_double(((double)r->num_pkts) / total_pkt_count));

    json_object_array_add(jArray_stats, jObj_stat);

    i++;
    if(i >= 10) break;
  }

  json_object_object_add(*jObj_group, "top.receiver.stats", jArray_stats);
}
#endif


/* *********************************************** */

static void deleteScanners(struct single_flow_info *scanners) {
  struct single_flow_info *s, *tmp;
  struct port_flow_info *p, *tmp2;

  HASH_ITER(hh, scanners, s, tmp) {
    HASH_ITER(hh, s->ports, p, tmp2) {
      HASH_DEL(s->ports, p);
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
      ndpi_thread_info[thread_id].workflow->stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}


/**
 * @brief On Protocol Discover - call node_guess_undetected_protocol() for protocol
 */
static void on_protocol_discovered(struct ndpi_workflow * workflow,
				   struct ndpi_flow_info * flow,
				   void * udata) {

  const u_int16_t thread_id = (uintptr_t) udata;

  if(verbose > 1) {
    if(enable_protocol_guess) {
      if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
        flow->detected_protocol.app_protocol = node_guess_undetected_protocol(thread_id, flow),
	  flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
      }
    }

    // printFlow(thread_id, flow);
  }
}

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
  ndpi_thread_info[thread_id].workflow->ndpi_struct->http_dont_dissect_response = 0;
  ndpi_thread_info[thread_id].workflow->ndpi_struct->dns_dissect_response = 0;

  ndpi_workflow_set_flow_detected_callback(ndpi_thread_info[thread_id].workflow,
					   on_protocol_discovered, (void *)(uintptr_t)thread_id);

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].workflow->ndpi_struct, &all);

  // clear memory for results
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].workflow->stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].workflow->stats.protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].workflow->ndpi_struct, _protoFilePath);
}


/**
 * @brief End of detection and free flow
 */
static void terminateDetection(u_int16_t thread_id) {
  ndpi_workflow_free(ndpi_thread_info[thread_id].workflow);
}


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


/**
 * @brief JSON function init
 */
#ifdef HAVE_JSON_C
static void json_init() {
  jArray_known_flows = json_object_new_array();
  jArray_unknown_flows = json_object_new_array();
  jArray_topStats = json_object_new_array();
}

static void json_open_stats_file() {
  if((file_first_time && ((stats_fp = fopen(_statsFilePath,"w")) == NULL))
     ||
     (!file_first_time && (stats_fp = fopen(_statsFilePath,"a")) == NULL)) {
    printf("Error creating/opening file %s\n", _statsFilePath);
    stats_flag = 0;
  }
  else file_first_time = 0;
}

static void json_close_stats_file() {
  json_object *jObjFinal = json_object_new_object();
  json_object_object_add(jObjFinal,"duration.in.seconds",json_object_new_int(pcap_analysis_duration));
  json_object_object_add(jObjFinal,"statistics", jArray_topStats);
  fprintf(stats_fp,"%s\n",json_object_to_json_string(jObjFinal));
  fclose(stats_fp);
  json_object_put(jObjFinal);
}
#endif

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

#ifdef HAVE_JSON_C
static int scanners_sort(void *_a, void *_b) {
  struct single_flow_info *a = (struct single_flow_info *)_a;
  struct single_flow_info *b = (struct single_flow_info *)_b;

  return(b->tot_flows - a->tot_flows);
}

/* *********************************************** */

static int scanners_port_sort(void *_a, void *_b) {
  struct port_flow_info *a = (struct port_flow_info *)_a;
  struct port_flow_info *b = (struct port_flow_info *)_b;

  return(b->num_flows - a->num_flows);
}

#endif
/* *********************************************** */

static int info_pair_cmp (const void *_a, const void *_b)
{
  struct info_pair *a = (struct info_pair *)_a;
  struct info_pair *b = (struct info_pair *)_b;

  return b->count - a->count;
}

/* *********************************************** */

#ifdef HAVE_JSON_C
static int top_stats_sort(void *_a, void *_b) {
  struct port_stats *a = (struct port_stats*)_a;
  struct port_stats *b = (struct port_stats*)_b;

  return(b->num_addr - a->num_addr);
}

/* *********************************************** */

/**
 * @brief Get port based top statistics
 */
static int getTopStats(struct port_stats *stats) {
  struct port_stats *sp, *tmp;
  struct info_pair inf;
  u_int64_t total_ip_addrs = 0;

  HASH_ITER(hh, stats, sp, tmp) {
    qsort(sp->top_ip_addrs, MAX_NUM_IP_ADDRESS, sizeof(struct info_pair), info_pair_cmp);
    inf = sp->top_ip_addrs[0];

    if(((inf.count * 100.0)/sp->cumulative_addr) > AGGRESSIVE_PERCENT) {
      sp->hasTopHost = 1;
      sp->top_host = inf.addr;
      sp->version = inf.version;
      strncpy(sp->proto, inf.proto, sizeof(sp->proto));
    } else
      sp->hasTopHost = 0;

    total_ip_addrs += sp->num_addr;
  }

  return total_ip_addrs;
}

/* *********************************************** */

static void saveScannerStats(json_object **jObj_group, struct single_flow_info **scanners) {
  struct single_flow_info *s, *tmp;
  struct port_flow_info *p, *tmp2;
  char addr_name[48];
  int i = 0, j = 0;

  json_object *jArray_stats  = json_object_new_array();

  HASH_SORT(*scanners, scanners_sort); // FIX

  HASH_ITER(hh, *scanners, s, tmp) {
    json_object *jObj_stat = json_object_new_object();
    json_object *jArray_ports = json_object_new_array();

    if(s->version == IPVERSION)
      inet_ntop(AF_INET, &(s->saddr), addr_name, sizeof(addr_name));
    else
      inet_ntop(AF_INET6, &(s->saddr),  addr_name, sizeof(addr_name));

    json_object_object_add(jObj_stat,"ip.address",json_object_new_string(addr_name));
    json_object_object_add(jObj_stat,"total.flows.number",json_object_new_int(s->tot_flows));

    HASH_SORT(s->ports, scanners_port_sort);

    HASH_ITER(hh, s->ports, p, tmp2) {
      json_object *jObj_port = json_object_new_object();

      json_object_object_add(jObj_port,"port",json_object_new_int(p->port));
      json_object_object_add(jObj_port,"flows.number",json_object_new_int(p->num_flows));

      json_object_array_add(jArray_ports, jObj_port);

      j++;
      if(j >= 10) break;
    }

    json_object_object_add(jObj_stat,"top.dst.ports",jArray_ports);
    json_object_array_add(jArray_stats, jObj_stat);

    j = 0;
    i++;
    if(i >= 10) break;
  }

  json_object_object_add(*jObj_group, "top.scanner.stats", jArray_stats);
}

#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
/*
 * @brief Save Top Stats in json format
 */
static void saveTopStats(json_object **jObj_group,
                         struct port_stats **stats,
                         u_int8_t direction,
                         u_int64_t total_flow_count,
                         u_int64_t total_ip_addr) {
  struct port_stats *s, *tmp;
  char addr_name[48];
  int i = 0;

  json_object *jArray_stats  = json_object_new_array();


  HASH_ITER(hh, *stats, s, tmp) {

    if((s->hasTopHost)) {
      json_object *jObj_stat = json_object_new_object();

      json_object_object_add(jObj_stat,"port",json_object_new_int(s->port));
      json_object_object_add(jObj_stat,"packets.number",json_object_new_int(s->num_pkts));
      json_object_object_add(jObj_stat,"flows.number",json_object_new_int(s->num_flows));
      json_object_object_add(jObj_stat,"flows.percent",json_object_new_double((s->num_flows*100.0)/total_flow_count));
      if(s->num_pkts) json_object_object_add(jObj_stat,"flows/packets",
					     json_object_new_double(((double)s->num_flows)/s->num_pkts));
      else json_object_object_add(jObj_stat,"flows.num_packets",json_object_new_double(0.0));

      if(s->version == IPVERSION) {
	inet_ntop(AF_INET, &(s->top_host), addr_name, sizeof(addr_name));
      } else {
	inet_ntop(AF_INET6, &(s->top_host),  addr_name, sizeof(addr_name));
      }

      json_object_object_add(jObj_stat,"aggressive.host",json_object_new_string(addr_name));
      json_object_object_add(jObj_stat,"host.app.protocol",json_object_new_string(s->proto));

      json_object_array_add(jArray_stats, jObj_stat);
      i++;

      if(i >= 10) break;
    }
  }

  json_object_object_add(*jObj_group, (direction == DIR_SRC) ?
			 "top.src.pkts.stats" : "top.dst.pkts.stats", jArray_stats);

  jArray_stats  = json_object_new_array();
  i=0;

  /*sort top stats by ip addr count*/
  HASH_SORT(*stats, top_stats_sort);


  HASH_ITER(hh, *stats, s, tmp) {
    json_object *jObj_stat = json_object_new_object();

    json_object_object_add(jObj_stat,"port",json_object_new_int(s->port));
    json_object_object_add(jObj_stat,"host.number",json_object_new_int64(s->num_addr));
    json_object_object_add(jObj_stat,"host.percent",json_object_new_double((s->num_addr*100.0)/total_ip_addr));
    json_object_object_add(jObj_stat,"flows.number",json_object_new_int(s->num_flows));

    json_object_array_add(jArray_stats,jObj_stat);
    i++;

    if(i >= 10) break;
  }

  json_object_object_add(*jObj_group, (direction == DIR_SRC) ?
			 "top.src.host.stats" : "top.dst.host.stats", jArray_stats);
}
#endif

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

/**
 * @brief Print result
 */
static void printResults(u_int64_t tot_usec) {
  u_int32_t i;
  u_int64_t total_flow_bytes = 0;
  u_int32_t avg_pkt_size = 0;
  struct ndpi_stats cumulative_stats;
  int thread_id;
  char buf[32];
#ifdef HAVE_JSON_C
  FILE *json_fp = NULL;
  json_object *jObj_main = NULL, *jObj_trafficStats, *jArray_detProto = NULL, *jObj;
#endif
  long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if((ndpi_thread_info[thread_id].workflow->stats.total_wire_bytes == 0)
       && (ndpi_thread_info[thread_id].workflow->stats.raw_packet_count == 0))
      continue;

    for(i=0; i<NUM_ROOTS; i++) {
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], node_proto_guess_walker, &thread_id);
      if(verbose == 3 || stats_flag) ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], port_stats_walker, &thread_id);
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
    printf("\tnDPI Memory (once):      %-13s\n", formatBytes(sizeof(struct ndpi_detection_module_struct), buf, sizeof(buf)));
    printf("\tFlow Memory (per flow):  %-13s\n", formatBytes(sizeof(struct ndpi_flow_struct), buf, sizeof(buf)));
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
	char buf[32], buf1[32], when[64];
	float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)tot_usec;
	float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)tot_usec;
	float traffic_duration;
	if(live_capture) traffic_duration = tot_usec;
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
  }

  if(json_flag) {
#ifdef HAVE_JSON_C
    if((json_fp = fopen(_jsonFilePath,"w")) == NULL) {
      printf("Error creating .json file %s\n", _jsonFilePath);
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

      if((!json_flag) && (!quiet_mode)) {
	printf("\t%-20s packets: %-13llu bytes: %-13llu "
	       "flows: %-13u\n",
	       ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
	       (long long unsigned int)cumulative_stats.protocol_counter[i],
	       (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	       cumulative_stats.protocol_flows[i]);
      } else {
#ifdef HAVE_JSON_C
	if(json_fp) {
	  jObj = json_object_new_object();

	  json_object_object_add(jObj,"name",json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[0].workflow->ndpi_struct, i)));
	  json_object_object_add(jObj,"breed",json_object_new_string(ndpi_get_proto_breed_name(ndpi_thread_info[0].workflow->ndpi_struct, breed)));
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
	       ndpi_get_proto_breed_name(ndpi_thread_info[0].workflow->ndpi_struct, i),
	       breed_stats[i]);
      }
    }
  }

  // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

  if((verbose == 1) || (verbose == 2)) {
    FILE *out = results_file ? results_file : stdout;
    u_int32_t total_flows = 0;

    for(thread_id = 0; thread_id < num_threads; thread_id++)
      total_flows += ndpi_thread_info[thread_id].workflow->num_allocated_flows;

    if((all_flows = (struct flow_info*)malloc(sizeof(struct flow_info)*total_flows)) == NULL) {
       printf("Fatal error: not enough memory\n");
       exit(-1);
    }

    if(!json_flag) fprintf(out, "\n");

    num_flows = 0;
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], node_print_known_proto_walker, &thread_id);
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);

    for(thread_id = 0; thread_id < num_threads; thread_id++) {
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0 /* 0 = Unknown */] > 0) {
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
      if(ndpi_thread_info[thread_id].workflow->stats.protocol_counter[0] > 0) {
        for(i=0; i<NUM_ROOTS; i++)
	  ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], node_print_unknown_proto_walker, &thread_id);
      }
    }

    qsort(all_flows, num_flows, sizeof(struct flow_info), cmpFlows);

    for(i=0; i<num_flows; i++)
      printFlow(i+1, all_flows[i].flow, all_flows[i].thread_id);

    free(all_flows);
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

  if(stats_flag) {
#ifdef HAVE_JSON_C
    json_object *jObj_stats = json_object_new_object();
    char timestamp[64];
    int count;

    strftime(timestamp, sizeof(timestamp), "%FT%TZ", localtime(&pcap_start.tv_sec));
    json_object_object_add(jObj_stats, "time", json_object_new_string(timestamp));

    saveScannerStats(&jObj_stats, &scannerHosts);

    if((count = HASH_COUNT(topReceivers)) == 0){
        HASH_SORT(receivers, receivers_sort);
        saveReceiverStats(&jObj_stats, &receivers, cumulative_stats.ip_packet_count);
    }
    else{
        HASH_SORT(topReceivers, receivers_sort);
        saveReceiverStats(&jObj_stats, &topReceivers, cumulative_stats.ip_packet_count);
    }

    u_int64_t total_src_addr = getTopStats(srcStats);
    u_int64_t total_dst_addr = getTopStats(dstStats);

    saveTopStats(&jObj_stats, &srcStats, DIR_SRC,
                 cumulative_stats.ndpi_flow_count, total_src_addr);

    saveTopStats(&jObj_stats, &dstStats, DIR_DST,
                 cumulative_stats.ndpi_flow_count, total_dst_addr);

    json_object_array_add(jArray_topStats, jObj_stats);
#endif
  }

 free_stats:
  if(scannerHosts) {
    deleteScanners(scannerHosts);
    scannerHosts = NULL;
  }

  if(receivers){
    deleteReceivers(receivers);
    receivers = NULL;
  }

  if(topReceivers){
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
  if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
  }
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
  if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen, promisc,
				   500, pcap_error_buffer)) == NULL) {
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
        if((!json_flag) && (!quiet_mode))
	  printf("Reading packets from playlist %s...\n", pcap_file);
      }
    } else {
      if((!json_flag) && (!quiet_mode))
	printf("Reading packets from pcap file %s...\n", pcap_file);
    }
  } else {
    live_capture = 1;

    if((!json_flag) && (!quiet_mode))
      printf("Capturing live traffic from device %s...\n", pcap_file);
  }

  configurePcapHandle(pcap_handle);

  if(capture_for > 0) {
    if((!json_flag) && (!quiet_mode))
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
static void pcap_process_packet(u_char *args,
				const struct pcap_pkthdr *header,
				const u_char *packet) {
  struct ndpi_proto p;
  u_int16_t thread_id = *((u_int16_t*)args);

  /* allocate an exact size buffer to check overflows */
  uint8_t *packet_checked = malloc(header->caplen);

  memcpy(packet_checked, packet, header->caplen);
  p = ndpi_workflow_process_packet(ndpi_thread_info[thread_id].workflow, header, packet_checked);

  if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_breakloop(ndpi_thread_info[thread_id].workflow->pcap_handle);
    return;
  }

  if(!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
  pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;

  /* Idle flows cleanup */
  if(live_capture) {
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].workflow->last_time) {
      /* scan for idle flows */
      ndpi_twalk(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

      /* remove idle flows (unfortunately we cannot do this inline) */
      while (ndpi_thread_info[thread_id].num_idle_flows > 0) {

	/* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
	ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
		     &ndpi_thread_info[thread_id].workflow->ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx],
		     ndpi_workflow_node_cmp);

	/* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
	ndpi_free_flow_info_half(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
	ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
      }

      if(++ndpi_thread_info[thread_id].idle_scan_idx == ndpi_thread_info[thread_id].workflow->prefs.num_roots) ndpi_thread_info[thread_id].idle_scan_idx = 0;
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
    h.caplen += delta;
    h.len += delta;

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
  free(packet_checked);

  if((pcap_end.tv_sec-pcap_start.tv_sec) > pcap_analysis_duration) {
    int i;
    u_int64_t tot_usec;

    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

    printResults(tot_usec);

    for(i=0; i<ndpi_thread_info[thread_id].workflow->prefs.num_roots; i++) {
      ndpi_tdestroy(ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i], ndpi_flow_info_freer);
      ndpi_thread_info[thread_id].workflow->ndpi_flows_root[i] = NULL;

      memset(&ndpi_thread_info[thread_id].workflow->stats, 0, sizeof(struct ndpi_stats));
    }

    printf("\n-------------------------------------------\n\n");

    memcpy(&begin, &end, sizeof(begin));
    memcpy(&pcap_start, &pcap_end, sizeof(pcap_start));
  }
}


/**
 * @brief Call pcap_loop() to process packets from a live capture or savefile
 */
static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id].workflow->pcap_handle != NULL))
    pcap_loop(ndpi_thread_info[thread_id].workflow->pcap_handle, -1, &pcap_process_packet, (u_char*)&thread_id);
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
       (ndpi_thread_info[thread_id].workflow->pcap_handle = pcap_open_offline(filename, pcap_error_buffer)) != NULL) {
      configurePcapHandle(ndpi_thread_info[thread_id].workflow->pcap_handle);
      goto pcap_loop;
    }
  }

  return NULL;
}


/**
 * @brief Begin, process, end detection process
 */
void test_lib() {
  struct timeval end;
  u_int64_t tot_usec;
  long thread_id;

#ifdef HAVE_JSON_C
  json_init();
  if(stats_flag)  json_open_stats_file();
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
  tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

  /* Printing cumulative results */
  printResults(tot_usec);

  if(stats_flag) {
#ifdef HAVE_JSON_C
    json_close_stats_file();
#endif
  }

  for(thread_id = 0; thread_id < num_threads; thread_id++) {
    if(ndpi_thread_info[thread_id].workflow->pcap_handle != NULL)
      pcap_close(ndpi_thread_info[thread_id].workflow->pcap_handle);

    terminateDetection(thread_id);
  }
}

void automataUnitTest() {
  void *automa;

  assert(automa = ndpi_init_automa());
  assert(ndpi_add_string_to_automa(automa, "hello") == 0);
  assert(ndpi_add_string_to_automa(automa, "world") == 0);
  ndpi_finalize_automa(automa);
  assert(ndpi_match_string(automa, "This is the wonderful world of nDPI") == 0);

  ndpi_free_automa(automa);
}

/* *********************************************** */
/**
 * @brief Produce bpf filter to filter ports and hosts
 * in order to remove a peak in terms of number of packets
 * sent by source hosts.
 */
#ifdef HAVE_JSON_C
void bpf_filter_pkt_peak_filter(json_object **jObj_bpfFilter,
                                int port_array[], int p_size,
                                const char *src_host_array[16],
                                int sh_size,
                                const char *dst_host_array[16],
                                int dh_size) {
  char filter[2048];
  int produced = 0;
  int i = 0;

  if(port_array[0] != INIT_VAL) {
    int l;

    strcpy(filter, "not (src port ");

    while(i < p_size && port_array[i] != INIT_VAL) {
      l = strlen(filter);

      if(i+1 == p_size || port_array[i+1] == INIT_VAL)
        snprintf(&filter[l], sizeof(filter)-l, "%d", port_array[i]);
      else
        snprintf(&filter[l], sizeof(filter)-l, "%d or ", port_array[i]);
      i++;
    }

    l = strlen(filter);
    snprintf(&filter[l], sizeof(filter)-l, "%s", ")");
    produced = 1;
  }


  if(src_host_array[0] != NULL) {
    int l;

    if(port_array[0] != INIT_VAL)
      strncat(filter, " and not (src ", sizeof(" and not (src "));
    else
      strcpy(filter, "not (src ");


    i=0;
    while(i < sh_size && src_host_array[i] != NULL) {
      l = strlen(filter);

      if(i+1 == sh_size || src_host_array[i+1] == NULL)
	snprintf(&filter[l], sizeof(filter)-l, "%s", src_host_array[i]);
      else
	snprintf(&filter[l], sizeof(filter)-l, "%s or ", src_host_array[i]);

      i++;
    }

    l = strlen(filter);
    snprintf(&filter[l], sizeof(filter)-l, "%s", ")");
    produced = 1;
  }


  if(dst_host_array[0] != NULL) {
    int l;

    if(port_array[0] != INIT_VAL || src_host_array[0] != NULL)
      strncat(filter, " and not (dst ", sizeof(" and not (dst "));
    else
      strcpy(filter, "not (dst ");

    i=0;

    while(i < dh_size && dst_host_array[i] != NULL) {
      l = strlen(filter);

      if(i+1 == dh_size || dst_host_array[i+1] == NULL)
	snprintf(&filter[l], sizeof(filter)-l, "%s", dst_host_array[i]);
      else
	snprintf(&filter[l], sizeof(filter)-l, "%s or ", dst_host_array[i]);

      i++;
    }

    l = strlen(filter);
    snprintf(&filter[l], sizeof(filter)-l, "%s", ")");
    produced = 1;
  }



  if(produced)
    json_object_object_add(*jObj_bpfFilter, "pkt.peak.filter", json_object_new_string(filter));
  else
    json_object_object_add(*jObj_bpfFilter, "pkt.peak.filter", json_object_new_string(""));
}
#endif

/* *********************************************** */
/**
 * @brief Produce bpf filter to filter ports and hosts
 * in order to remove a peak in terms of number of source
 * addresses.
 */
#ifdef HAVE_JSON_C
void bpf_filter_host_peak_filter(json_object **jObj_bpfFilter,
                                 const char *host_array[16],
                                 int h_size) {
  char filter[2048];
  int produced = 0;
  int i = 0;


  if(host_array[0] != NULL) {
    int l;

    strcpy(filter, "not (dst ");

    while(i < h_size && host_array[i] != NULL) {
      l = strlen(filter);

      if(i+1 == h_size || host_array[i+1] == NULL)
	snprintf(&filter[l], sizeof(filter)-l, "%s", host_array[i]);
      else
	snprintf(&filter[l], sizeof(filter)-l, "%s or ", host_array[i]);

      i++;
    }

    l = strlen(filter);
    snprintf(&filter[l], sizeof(filter)-l, "%s", ")");
    produced = 1;
  }

  if(produced)
    json_object_object_add(*jObj_bpfFilter, "host.peak.filter", json_object_new_string(filter));
  else
    json_object_object_add(*jObj_bpfFilter, "host.peak.filter", json_object_new_string(""));
}
#endif

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
#ifdef HAVE_JSON_C
/*
 * @brief returns average value for a given field
 */
float getAverage(struct json_object *jObj_stat, char *field){
  json_object *field_stat;
  json_bool res;
  float average;
  float sum = 0;
  int r;
  int j;

  if((r = strcmp(field, "top.scanner.stats")) == 0) {
    for(j=0; j<json_object_array_length(jObj_stat); j++) {
      field_stat = json_object_array_get_idx(jObj_stat, j);
      json_object *jObj_tot_flows_number;

      if((res = json_object_object_get_ex(field_stat, "total.flows.number", &jObj_tot_flows_number)) == 0) {
        fprintf(stderr, "ERROR: can't get \"total.flows.number\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
        exit(-1);
      }
      u_int32_t tot_flows_number = json_object_get_int(jObj_tot_flows_number);

      sum += tot_flows_number;
    }
  } else if((r = strcmp(field, "top.src.pkts.stats")) == 0) {
    for(j=0; j<json_object_array_length(jObj_stat); j++) {
      field_stat = json_object_array_get_idx(jObj_stat, j);
      json_object *jObj_packets_number;

      if((res = json_object_object_get_ex(field_stat, "packets.number", &jObj_packets_number)) == 0) {
        fprintf(stderr, "ERROR: can't get \"packets.number\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
        exit(-1);
      }
      u_int32_t packets_number = json_object_get_int(jObj_packets_number);

      sum += packets_number;
    }
  }

  if(j == 0) return 0.0;

  return sum/j;
}
#endif
/* *********************************************** */
#ifdef HAVE_JSON_C
/*
 * @brief returns standard deviation for a given
 * field and it's average value.
 */
float getStdDeviation(struct json_object *jObj_stat, float average, char *field){
  json_object *field_stat;
  json_bool res;
  float sum = 0;
  int j;
  int r;

  if((r = strcmp(field, "top.scanner.stats")) == 0){
    for(j=0; j<json_object_array_length(jObj_stat); j++) {
      field_stat = json_object_array_get_idx(jObj_stat, j);
      json_object *jObj_tot_flows_number;

      if((res = json_object_object_get_ex(field_stat, "total.flows.number", &jObj_tot_flows_number)) == 0) {
        fprintf(stderr, "ERROR: can't get \"total.flows.number\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
        exit(-1);
      }
      u_int32_t tot_flows_number = json_object_get_int(jObj_tot_flows_number);

      sum += pow((tot_flows_number - average), 2);
    }
  }

  return sqrt(sum/(float)j);
}

#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
void getSourcePorts(struct json_object *jObj_stat, int srcPortArray[], int size, float threshold) {
  int j;

  for(j=0; j<json_object_array_length(jObj_stat); j++) {
    json_object *src_pkts_stat = json_object_array_get_idx(jObj_stat, j);
    json_object *jObj_packets_number;
    json_object *jObj_flows_percent;
    json_object *jObj_flows_packets;
    json_object *jObj_port;
    json_bool res;

    if((res = json_object_object_get_ex(src_pkts_stat, "packets.number", &jObj_packets_number)) == 0) {
      fprintf(stderr, "ERROR: can't get \"packets.number\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    u_int32_t packets_number = json_object_get_int(jObj_packets_number);

    if((res = json_object_object_get_ex(src_pkts_stat, "flows.percent", &jObj_flows_percent)) == 0) {
      fprintf(stderr, "ERROR: can't get \"flows.percent\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    double flows_percent = json_object_get_double(jObj_flows_percent);


    if((res = json_object_object_get_ex(src_pkts_stat, "flows/packets", &jObj_flows_packets)) == 0) {
      fprintf(stderr, "ERROR: can't get \"flows/packets\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    double flows_packets = json_object_get_double(jObj_flows_packets);


    if((flows_packets > FLOWS_PACKETS_THRESHOLD)
        && (flows_percent >= FLOWS_PERCENT_THRESHOLD)
        && packets_number >= threshold) {
      if((res = json_object_object_get_ex(src_pkts_stat, "port", &jObj_port)) == 0) {
	fprintf(stderr, "ERROR: can't get \"port\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
	exit(-1);
      }
      int port = json_object_get_int(jObj_port);

      bpf_filter_port_array_add(srcPortArray, size, port);
    }
  }
}
#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
void getReceiverHosts(struct json_object *jObj_stat, const char *dstHostArray[16], int size) {
  int j;

  for(j=0; j<json_object_array_length(jObj_stat); j++) {
    json_object *scanner_stat = json_object_array_get_idx(jObj_stat, j);
    json_object *jObj_host_address;
    json_object *jObj_pkts_percent;
    json_bool res;

    if((res = json_object_object_get_ex(scanner_stat, "packets.percent", &jObj_pkts_percent)) == 0) {
      fprintf(stderr, "ERROR: can't get \"packets.percent\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    double pkts_percent = json_object_get_double(jObj_pkts_percent);


    if(pkts_percent > PKTS_PERCENT_THRESHOLD) {
      if((res = json_object_object_get_ex(scanner_stat, "ip.address", &jObj_host_address)) == 0) {
	fprintf(stderr, "ERROR: can't get \"ip.address, use -x flag only with .json files generated by ndpiReader -b flag.\n");
	exit(-1);
      }
      const char *host_address = json_object_get_string(jObj_host_address);

      bpf_filter_host_array_add(dstHostArray, size, host_address);
    }
  }
}
#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
void getScannerHosts(struct json_object *jObj_stat, int duration,
                     const char *srcHostArray[48], int size,
                     float threshold) {
  int j;

  for(j=0; j<json_object_array_length(jObj_stat); j++) {
    json_object *scanner_stat = json_object_array_get_idx(jObj_stat, j);
    json_object *jObj_host_address;
    json_object *jObj_tot_flows_number;
    json_bool res;


    if((res = json_object_object_get_ex(scanner_stat, "total.flows.number", &jObj_tot_flows_number)) == 0) {
      fprintf(stderr, "ERROR: can't get \"total.flows.number\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    u_int32_t tot_flows_number = json_object_get_int(jObj_tot_flows_number);


    if(((tot_flows_number/(float)duration) > FLOWS_THRESHOLD) && tot_flows_number > threshold) {
      if((res = json_object_object_get_ex(scanner_stat, "ip.address", &jObj_host_address)) == 0) {
	fprintf(stderr, "ERROR: can't get \"ip.address\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
	exit(-1);
      }
      const char *host_address = json_object_get_string(jObj_host_address);

      bpf_filter_host_array_add(srcHostArray, size, host_address);

    }
  }
}
#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
void getDestinationHosts(struct json_object *jObj_stat, int duration,
                 const char *dstHostArray[16], int size) {
  int j;

  for(j=0; j<json_object_array_length(jObj_stat); j++) {
    json_object *scanner_stat = json_object_array_get_idx(jObj_stat, j);
    json_object *jObj_host_address;
    json_object *jObj_flows_percent;
    json_bool res;


    if((res = json_object_object_get_ex(scanner_stat, "flows.percent", &jObj_flows_percent)) == 0) {
      fprintf(stderr, "ERROR: can't get \"flows.percent\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    double flows_percent = json_object_get_double(jObj_flows_percent);


    if(flows_percent > FLOWS_PERCENT_THRESHOLD_2) {
      if((res = json_object_object_get_ex(scanner_stat, "aggressive.host", &jObj_host_address)) == 0) {
	fprintf(stderr, "ERROR: can't get \"aggressive.host\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
	exit(-1);
      }
      const char *host_address = json_object_get_string(jObj_host_address);

      bpf_filter_host_array_add(dstHostArray, size, host_address);

    }
  }
}
#endif

/* *********************************************** */

#ifdef HAVE_JSON_C
static void produceBpfFilter(char *filePath) {
  json_object *jObj; /* entire json object from file */
  json_object *jObj_duration;
  json_object *jObj_statistics; /* json array */
  json_bool res;
  int filterSrcPorts[PORT_ARRAY_SIZE];
  const char *filterSrcHosts[48];
  const char *filterDstHosts[48];
  const char *filterPktDstHosts[48];
  struct stat statbuf;
  FILE *fp = NULL;
  char *fileName;
  char _filterFilePath[1024];
  json_object *jObj_bpfFilter;
  void *fmap;
  int fsock;
  float average;
  float deviation;
  int duration;
  int typeCheck;
  int array_len;
  int i;

  if((fsock = open(filePath, O_RDONLY)) == -1) {
    fprintf(stderr,"error opening file %s\n", filePath);
    exit(-1);
  }

  if(fstat(fsock, &statbuf) == -1) {
    fprintf(stderr,"error getting file stat\n");
    exit(-1);
  }

  if((fmap = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fsock, 0)) == MAP_FAILED) {
    fprintf(stderr,"error mmap is failed\n");
    exit(-1);
  }

  if((jObj = json_tokener_parse(fmap)) == NULL) {
    fprintf(stderr,"ERROR: invalid json file. Use -x flag only with .json files generated by ndpiReader -b flag.\n");
    exit(-1);
  }


  if((res = json_object_object_get_ex(jObj, "duration.in.seconds", &jObj_duration)) == 0) {
    fprintf(stderr,"ERROR: can't get \"duration.in.seconds\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
    exit(-1);
  }
  duration = json_object_get_int(jObj_duration);


  if((res = json_object_object_get_ex(jObj, "statistics", &jObj_statistics)) == 0) {
    fprintf(stderr,"ERROR: can't get \"statistics\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
    exit(-1);
  }

  if((typeCheck = json_object_is_type(jObj_statistics, json_type_array)) == 0) {
    fprintf(stderr,"ERROR: invalid json file. Use -x flag only with .json files generated by ndpiReader -b flag.\n");
    exit(-1);
  }
  array_len = json_object_array_length(jObj_statistics);


  bpf_filter_port_array_init(filterSrcPorts, PORT_ARRAY_SIZE);
  bpf_filter_host_array_init(filterSrcHosts, HOST_ARRAY_SIZE);
  bpf_filter_host_array_init(filterDstHosts, HOST_ARRAY_SIZE);
  bpf_filter_host_array_init(filterPktDstHosts, HOST_ARRAY_SIZE/2);

  for(i=0; i<array_len; i++) {
    json_object *stats = json_object_array_get_idx(jObj_statistics, i);
    json_object *val;

    if((res = json_object_object_get_ex(stats, "top.scanner.stats", &val)) == 0) {
      fprintf(stderr,"ERROR: can't get \"top.scanner.stats\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }

    if((average = getAverage(val, "top.scanner.stats")) != 0){
      deviation = getStdDeviation(val, average, "top.scanner.stats");
      getScannerHosts(val, duration, filterSrcHosts, HOST_ARRAY_SIZE, average+deviation);
    }


    if((res = json_object_object_get_ex(stats, "top.receiver.stats", &val)) == 0) {
      fprintf(stderr,"ERROR: can't get \"top.receiver.stats\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    getReceiverHosts(val, filterPktDstHosts, HOST_ARRAY_SIZE/2);


    if((res = json_object_object_get_ex(stats, "top.src.pkts.stats", &val)) == 0) {
      fprintf(stderr,"ERROR: can't get \"top.src.pkts.stats\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }

    if((average = getAverage(val, "top.src.pkts.stats")) != 0)
      getSourcePorts(val, filterSrcPorts, PORT_ARRAY_SIZE, average);


    if((res = json_object_object_get_ex(stats, "top.dst.pkts.stats", &val)) == 0) {
      fprintf(stderr,"ERROR: can't get \"top.dst.pkts.stats\", use -x flag only with .json files generated by ndpiReader -b flag.\n");
      exit(-1);
    }
    getDestinationHosts(val, duration, filterDstHosts, HOST_ARRAY_SIZE);
  }


  fileName = basename(filePath);
  snprintf(_filterFilePath, sizeof(_filterFilePath), "%s.bpf", filePath);

  if((fp = fopen(_filterFilePath,"w")) == NULL) {
    printf("Error creating .json file %s\n", _filterFilePath);
    exit(-1);
  }

  jObj_bpfFilter = json_object_new_object();

  bpf_filter_pkt_peak_filter(&jObj_bpfFilter, filterSrcPorts, PORT_ARRAY_SIZE,
                  filterSrcHosts, HOST_ARRAY_SIZE, filterPktDstHosts, HOST_ARRAY_SIZE/2);

  bpf_filter_host_peak_filter(&jObj_bpfFilter, filterDstHosts, HOST_ARRAY_SIZE);

  fprintf(fp,"%s\n",json_object_to_json_string(jObj_bpfFilter));
  fclose(fp);

  printf("created: %s\n", _filterFilePath);

  json_object_put(jObj); /* free memory */
}
#endif


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
  
  automataUnitTest();

  ndpi_info_mod = ndpi_init_detection_module();
  if (ndpi_info_mod == NULL) return -1;

  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

  parseOptions(argc, argv);

  if(bpf_filter_flag) {
#ifdef HAVE_JSON_C
    produceBpfFilter(_diagnoseFilePath);
    return 0;
#endif
  }

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

  if(results_path)  free(results_path);
  if(results_file)  fclose(results_file);
  if(extcap_dumper) pcap_dump_close(extcap_dumper);
  if(ndpi_info_mod) ndpi_exit_detection_module(ndpi_info_mod);

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
