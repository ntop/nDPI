/*
 * ndpi_util.h
 *
 * Copyright (C) 2011-22 - ntop.org
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

/**
 * This module contains routines to help setup a simple nDPI program.
 *
 * If you concern about performance or have to integrate nDPI in your
 * application, you could need to reimplement them yourself.
 *
 * WARNING: this API is just a demo od nDPI usage: Use it at your own risk!
 */
#ifndef __NDPI_UTIL_H__
#define __NDPI_UTIL_H__

#include "../src/lib/third_party/include/uthash.h"
#include <pcap.h>
#include "ndpi_includes.h"
#include "ndpi_classify.h"
#include "ndpi_typedefs.h"

#ifdef USE_DPDK
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE     128
#define TX_RING_SIZE     512
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE        32
#define PREFETCH_OFFSET    3

extern int dpdk_port_init(int port, struct rte_mempool *mbuf_pool);
extern int dpdk_port_deinit(int port);
#endif

#define PLEN_MAX         1504
#define PLEN_BIN_LEN     32
#define PLEN_NUM_BINS    48 /* 47*32 = 1504 */
#define MAX_NUM_BIN_PKTS 256

/* ETTA Spec defiintions for feature readiness */
#define ETTA_MIN_PACKETS 10
#define ETTA_MIN_OCTETS 4000
/** maximum line length */
#define LINEMAX 512
#define MAX_BYTE_COUNT_ARRAY_LENGTH 256
#define MAX_NUM_PKTS               10

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD           10 /* msec (use TICK_RESOLUTION = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024
#define NUM_ROOTS                 512
#define MAX_EXTRA_PACKETS_TO_CHECK  7
#define MAX_NDPI_FLOWS      200000000
#define TICK_RESOLUTION          1000
#define MAX_NUM_IP_ADDRESS          5  /* len of ip address array */
#define UPDATED_TREE                1
#define AGGRESSIVE_PERCENT      95.00
#define DIR_SRC                    10
#define DIR_DST                    20
#define PORT_ARRAY_SIZE            20
#define HOST_ARRAY_SIZE            20
#define FLOWS_PACKETS_THRESHOLD   0.9
#define FLOWS_PERCENT_THRESHOLD   1.0
#define FLOWS_PERCENT_THRESHOLD_2 0.2
#define FLOWS_THRESHOLD          1000
#define PKTS_PERCENT_THRESHOLD    0.1
#define MAX_TABLE_SIZE_1         4096
#define MAX_TABLE_SIZE_2         8192
#define INIT_VAL                   -1
#define SERIALIZATION_BUFSIZ     (8192 * 2)


#ifdef __cplusplus
extern "C" {
#endif

// inner hash table (ja -> security state)
typedef struct ndpi_ja_info {
  char * ja;
  ndpi_cipher_weakness unsafe_cipher;
  UT_hash_handle hh;
} ndpi_ja_info;

// external hash table (host ip -> <ip string, hash table ja4c, hash table ja3s>)
// used to aggregate ja3 fingerprints by hosts
typedef struct ndpi_host_ja_fingerprints {
  u_int32_t ip;
  char *ip_string;
  char *dns_name;
  ndpi_ja_info *host_client_info_hasht;
  ndpi_ja_info *host_server_info_hasht;

  UT_hash_handle hh;
} ndpi_host_ja_fingerprints;


//inner hash table
typedef struct ndpi_ip_dns{
  u_int32_t ip;
  char *ip_string;
  char *dns_name; //server name if any;
  UT_hash_handle hh;
} ndpi_ip_dns;

//hash table ja -> <host, ip, security>, used to aggregate host by ja fingerprints
typedef struct ndpi_ja_fingerprints_host{
  char *ja; //key
  ndpi_cipher_weakness unsafe_cipher;
  ndpi_ip_dns *ipToDNS_ht;
  UT_hash_handle hh;
} ndpi_ja_fingerprints_host;

struct flow_metrics {
  float entropy, average, stddev;
};

struct ndpi_entropy {
  // Entropy fields
  u_int16_t src2dst_pkt_len[MAX_NUM_PKTS];                     /*!< array of packet appdata lengths */
  pkt_timeval src2dst_pkt_time[MAX_NUM_PKTS];               /*!< array of arrival times          */
  u_int16_t dst2src_pkt_len[MAX_NUM_PKTS];                     /*!< array of packet appdata lengths */
  pkt_timeval dst2src_pkt_time[MAX_NUM_PKTS];               /*!< array of arrival times          */
  pkt_timeval src2dst_start;                                /*!< first packet arrival time       */
  pkt_timeval dst2src_start;                                /*!< first packet arrival time       */
  u_int32_t src2dst_opackets;                                  /*!< non-zero packet counts          */
  u_int32_t dst2src_opackets;                                  /*!< non-zero packet counts          */
  u_int16_t src2dst_pkt_count;                                 /*!< packet counts                   */
  u_int16_t dst2src_pkt_count;                                 /*!< packet counts                   */
  u_int32_t src2dst_l4_bytes;                                  /*!< packet counts                   */
  u_int32_t dst2src_l4_bytes;                                  /*!< packet counts                   */
  u_int32_t src2dst_byte_count[MAX_BYTE_COUNT_ARRAY_LENGTH];   /*!< number of occurences of each byte   */
  u_int32_t dst2src_byte_count[MAX_BYTE_COUNT_ARRAY_LENGTH];   /*!< number of occurences of each byte   */
  u_int32_t src2dst_num_bytes;
  u_int32_t dst2src_num_bytes;
  double src2dst_bd_mean;
  double src2dst_bd_variance;
  double dst2src_bd_mean;
  double dst2src_bd_variance;
  float score;
};

enum info_type {
    INFO_INVALID = 0,
    INFO_GENERIC,
    INFO_KERBEROS,
    INFO_SOFTETHER,
    INFO_TIVOCONNECT,
    INFO_FTP_IMAP_POP_SMTP,
    INFO_NATPMP,
    INFO_SIP,
};

typedef struct {
  ndpi_address_port *aps;
  unsigned int num_aps;
  unsigned int num_aps_allocated;
} ndpi_address_port_list;

// flow tracking
typedef struct ndpi_flow_info {
  u_int32_t flow_id;
  u_int32_t hashval;
  u_int32_t src_ip; /* network order */
  u_int32_t dst_ip; /* network order */
  struct ndpi_in6_addr src_ip6; /* network order */
  struct ndpi_in6_addr dst_ip6; /* network order */
  u_int16_t src_port; /* network order */
  u_int16_t dst_port; /* network order */
  u_int8_t detection_completed, protocol, bidirectional, check_extra_packets, current_pkt_from_client_to_server;
  u_int16_t vlan_id;
  ndpi_packet_tunnel tunnel_type;
  struct ndpi_flow_struct *ndpi_flow;
  char src_name[INET6_ADDRSTRLEN], dst_name[INET6_ADDRSTRLEN];
  u_int8_t ip_version;
  u_int32_t cwr_count, src2dst_cwr_count, dst2src_cwr_count;
  u_int32_t ece_count, src2dst_ece_count, dst2src_ece_count;
  u_int32_t urg_count, src2dst_urg_count, dst2src_urg_count;
  u_int32_t ack_count, src2dst_ack_count, dst2src_ack_count;
  u_int32_t psh_count, src2dst_psh_count, dst2src_psh_count;
  u_int32_t syn_count, src2dst_syn_count, dst2src_syn_count;
  u_int32_t fin_count, src2dst_fin_count, dst2src_fin_count;
  u_int32_t rst_count, src2dst_rst_count, dst2src_rst_count;
  u_int32_t c_to_s_init_win, s_to_c_init_win;
  u_int64_t first_seen_ms, last_seen_ms;
  u_int64_t src2dst_bytes, dst2src_bytes;
  u_int64_t src2dst_goodput_bytes, dst2src_goodput_bytes;
  u_int32_t src2dst_packets, dst2src_packets;
  u_int32_t has_human_readeable_strings;
  char human_readeable_string_buffer[32];
  char *risk_str;

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;
  ndpi_confidence_t confidence;
  struct ndpi_fpc_info fpc;
  u_int16_t num_dissector_calls;
  u_int16_t dpi_packets;
  u_int8_t monitoring_state;
  u_int16_t num_packets_before_monitoring;

  // Flow data analysis
  pkt_timeval src2dst_last_pkt_time, dst2src_last_pkt_time, flow_last_pkt_time;
  struct ndpi_analyze_struct *iat_c_to_s, *iat_s_to_c, *iat_flow,
    *pktlen_c_to_s, *pktlen_s_to_c;

  enum info_type info_type;

  union {
    char info[256];
    
    struct {
      unsigned char auth_failed;
      char username[127];
      char password[128];
    } ftp_imap_pop_smtp;
    
    struct {
      char domain[85];
      char hostname[85];
      char username[86];
    } kerberos;
    
    struct {
      char ip[16];
      char port[6];
      char hostname[48];
      char fqdn[48];
    } softether;
    
    struct {
      char identity_uuid[36];
      char machine[48];
      char platform[32];
      char services[48];
    } tivoconnect;
    
    struct  {
      uint16_t result_code;
      uint16_t internal_port;
      uint16_t external_port;
      char ip[16];
    } natpmp;

    struct {
      char from[256];
      char from_imsi[16];
      char to[256];
      char to_imsi[16];
    } sip;
  };

  ndpi_serializer ndpi_flow_serializer;

  char host_server_name[80]; /* Hostname/SNI */
  char *server_hostname;
  char *bittorent_hash;
  char *dhcp_fingerprint;
  char *dhcp_class_ident;
  uint32_t idle_timeout_sec;
  ndpi_risk risk;

  struct {
    char currency[16];
  } mining;
  
  struct {
    u_int16_t ssl_version;
    char server_info[64],
      client_hassh[33], server_hassh[33], *server_names,
      *advertised_alpns, *negotiated_alpn, *tls_supported_versions,
      *tls_issuerDN, *tls_subjectDN,
      ja3_server[33], ja4_client[37], *ja4_client_raw,
      sha1_cert_fingerprint[20];
    u_int8_t sha1_cert_fingerprint_set;
    struct tls_heuristics browser_heuristics;

    struct {
      u_int16_t version;
    } encrypted_ch;

    time_t notBefore, notAfter;
    u_int16_t server_cipher;
    ndpi_cipher_weakness client_unsafe_cipher, server_unsafe_cipher;

    u_int32_t quic_version;

    struct ndpi_tls_obfuscated_heuristic_matching_set obfuscated_heur_matching_set;
  } ssh_tls;

  struct {
    char url[256], request_content_type[64], content_type[64],
      user_agent[256], server[128], nat_ip[32], username[64], password[64], filename[256];
    u_int response_status_code;
  } http;

  struct {
    ndpi_address_port_list mapped_address, peer_address,
      relayed_address, response_origin, other_address;
    u_int16_t rtp_counters[2];
  } stun;
  
  struct {
    char *username, *password;
  } telnet;

  struct {
    char geolocation_iata_code[4];
  } dns;

  u_int8_t multimedia_flow_types;
  
  void *src_id, *dst_id;
  char *tcp_fingerprint;
  struct ndpi_entropy *entropy;
  struct ndpi_entropy *last_entropy;

  /* Payload lenght bins */
#ifdef DIRECTION_BINS
  struct ndpi_bin payload_len_bin_src2dst, payload_len_bin_dst2src;
#else
  struct ndpi_bin payload_len_bin;
#endif

  /* Flow payload */
  u_int16_t flow_payload_len;
  char *flow_payload;  
} ndpi_flow_info_t;


// flow statistics info
typedef struct ndpi_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t fpc_protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t fpc_protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t fpc_protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int32_t flow_count[3];
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
  u_int64_t dpi_packet_count[3];
  u_int64_t flow_confidence[NDPI_CONFIDENCE_MAX];
  u_int64_t fpc_flow_confidence[NDPI_FPC_CONFIDENCE_MAX];
  u_int64_t num_dissector_calls;

  struct ndpi_lru_cache_stats lru_stats[NDPI_LRUCACHE_MAX];
  struct ndpi_automa_stats automa_stats[NDPI_AUTOMA_MAX];
  struct ndpi_patricia_tree_stats patricia_stats[NDPI_PTREE_MAX];
} ndpi_stats_t;


// flow preferences
typedef struct ndpi_workflow_prefs {
  u_int8_t decode_tunnels;
  u_int8_t quiet_mode;
  u_int8_t ignore_vlanid;
  u_int32_t num_roots;
  u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;

/** workflow, flow, user data */
typedef void (*ndpi_workflow_callback_ptr) (struct ndpi_workflow *, struct ndpi_flow_info *, void *);


// workflow main structure
typedef struct ndpi_workflow {
  u_int64_t last_time;

  struct ndpi_workflow_prefs prefs;
  struct ndpi_stats stats;

  ndpi_workflow_callback_ptr flow_callback;
  void * flow_callback_userdata;

  /* outside referencies */
  pcap_t *pcap_handle;

  /* allocated by prefs */
  void **ndpi_flows_root;
  struct ndpi_detection_module_struct *ndpi_struct;
  struct ndpi_global_context *g_ctx;
  u_int32_t num_allocated_flows;

  /* CSV,TLV,JSON serialization interface */
  ndpi_serialization_format ndpi_serialization_format;
} ndpi_workflow_t;


/* TODO: remove wrappers parameters and use ndpi global, when their initialization will be fixed... */
struct ndpi_workflow * ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs, pcap_t * pcap_handle, int do_init_flows_root, ndpi_serialization_format serialization_format, struct ndpi_global_context *g_ctx);


/* workflow main free function */
void ndpi_workflow_free(struct ndpi_workflow * workflow);


/** Free flow_info ndpi support structures but not the flow_info itself
 *
 *  TODO remove! Half freeing things is bad!
 */
void ndpi_free_flow_info_half(struct ndpi_flow_info *flow);


/* Process a packet and update the workflow  */
struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow * workflow,
					       const struct pcap_pkthdr *header,
					       const u_char *packet,
					       ndpi_risk *flow_risk,
					       struct ndpi_flow_info **flow);


/* Flow callback for completed flows, before the flow memory will be freed. */
static inline void ndpi_workflow_set_flow_callback(struct ndpi_workflow * workflow, ndpi_workflow_callback_ptr callback, void * userdata) {
  workflow->flow_callback = callback;
  workflow->flow_callback_userdata = userdata;
}

int ndpi_is_datalink_supported(int datalink_type);

/* compare two nodes in workflow */
int ndpi_workflow_node_cmp(const void *a, const void *b);
void process_ndpi_collected_info(struct ndpi_workflow * workflow, struct ndpi_flow_info *flow);
void ndpi_flow_info_free_data(struct ndpi_flow_info *flow);
void ndpi_flow_info_freer(void *node);
const char* print_cipher_id(u_int32_t cipher);
int parse_proto_name_list(char *str, NDPI_PROTOCOL_BITMASK *bitmask, int inverted_logic);

extern int reader_log_level;

#if defined(NDPI_ENABLE_DEBUG_MESSAGES) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#define LOG(log_level, args...)			\
  {						\
    if(log_level <= reader_log_level)		\
      printf(args);				\
  }
#else
#define LOG(...) {}
#endif

#ifndef LINKTYPE_LINUX_SLL2
#define LINKTYPE_LINUX_SLL2 276
#endif

#ifdef __cplusplus
}
#endif

#endif
