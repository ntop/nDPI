/*
 *
 * Copyright (C) 2011-26 - ntop.org
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

#ifndef __NDPI_PRIVATE_H__
#define __NDPI_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Not sure if we still need it.. keep it for the time being */
#ifdef NDPI_LIB_COMPILATION

/* Needed to have access to HAVE_* defines */
#ifndef _NDPI_CONFIG_H_
#include "ndpi_config.h"
#define _NDPI_CONFIG_H_
#endif

#include "ndpi_usdt.h"

/* NDPI_NODE */
typedef struct node_t {
  char *key;
  struct node_t *left, *right;
} ndpi_node;

typedef struct {
  char *string_to_match;
  ndpi_protocol_category_t protocol_category;
  ndpi_protocol_breed_t protocol_breed;
} ndpi_category_match;

typedef struct {
  char *string_to_match;
  u_int16_t protocol_id;
} ndpi_tls_cert_name_match;

struct call_function_struct {
  char name[16];                /* Used only for logging/debugging */
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  u_int16_t dissector_idx;
  /* We don't need to keep track of the list of protocols handled by this dissector */
  u_int16_t first_protocol_id;  /* ID of the first protocol registered with this dissector.
                                   It is used ONLY for logging, because logging configuration
                                   is (still) for protocol, not for dissector */
};

typedef struct default_ports_tree_node {
  u_int16_t proto_idx;
  u_int8_t customUserProto;
  u_int16_t default_port;
} default_ports_tree_node_t;

#define LINE_STARTS(ndpi_int_one_line_struct, string_to_compare) \
  ((ndpi_int_one_line_struct).ptr != NULL && \
   (ndpi_int_one_line_struct).len >= strlen(string_to_compare) && \
   strncasecmp((const char *)((ndpi_int_one_line_struct).ptr), string_to_compare, strlen(string_to_compare)) == 0)

#define LINE_ENDS(ndpi_int_one_line_struct, string_to_compare) \
  ((ndpi_int_one_line_struct).len >= strlen(string_to_compare) && \
   strncasecmp((const char *)((ndpi_int_one_line_struct).ptr) + \
              ((ndpi_int_one_line_struct).len - strlen(string_to_compare)), \
              string_to_compare, strlen(string_to_compare)) == 0)

#define NDPI_MAX_PARSE_LINES_PER_PACKET                         64

struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
};

struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
  const struct ndpi_ipv6hdr *iphv6;
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *payload;

  u_int64_t current_time_ms;

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  /* HTTP headers */
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct content_disposition_line;
  struct ndpi_int_one_line_struct accept_line;
  struct ndpi_int_one_line_struct authorization_line;
  struct ndpi_int_one_line_struct user_agent_line;
  struct ndpi_int_one_line_struct http_url_name;
  struct ndpi_int_one_line_struct http_origin;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct upgrade_line;
  struct ndpi_int_one_line_struct http_response; /* the first "word" in this pointer is the
						    response code in the packet (200, etc) */
  struct ndpi_int_one_line_struct bootid;
  struct ndpi_int_one_line_struct usn;
  struct ndpi_int_one_line_struct cache_controle;
  struct ndpi_int_one_line_struct location;
  struct ndpi_int_one_line_struct household_smart_speaker_audio;
  struct ndpi_int_one_line_struct rincon_household;
  struct ndpi_int_one_line_struct rincon_bootseq;
  struct ndpi_int_one_line_struct rincon_wifimode;
  struct ndpi_int_one_line_struct rincon_variant;
  struct ndpi_int_one_line_struct sonos_securelocation;
  struct ndpi_int_one_line_struct securelocation_upnp;
  struct ndpi_int_one_line_struct location_smart_speaker_audio;
  struct ndpi_int_one_line_struct nt;
  struct ndpi_int_one_line_struct nts;
  struct ndpi_int_one_line_struct man;
  struct ndpi_int_one_line_struct mx;
  struct ndpi_int_one_line_struct st;

  u_int16_t l3_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t parsed_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;

  u_int8_t packet_lines_parsed_complete:1,
    packet_direction:1, empty_line_position_set:1, http_check_content:1, pad:4;
};

#ifdef HAVE_NBPF
typedef struct {
  void *tree; /* cast to nbpf_filter* */
  u_int16_t l7_protocol;
} nbpf_filter;
#endif

struct ndpi_global_context {

  /* LRU caches */

  /* NDPI_PROTOCOL_OOKLA */
  int ookla_cache_is_global;
  struct ndpi_lru_cache *ookla_global_cache;

  /* NDPI_PROTOCOL_BITTORRENT */
  struct ndpi_lru_cache *bittorrent_global_cache;

  /* NDPI_PROTOCOL_STUN and subprotocols */
  struct ndpi_lru_cache *stun_global_cache;

  /* NDPI_PROTOCOL_TLS and subprotocols */
  struct ndpi_lru_cache *tls_cert_global_cache;

  /* NDPI_PROTOCOL_MINING and subprotocols */
  struct ndpi_lru_cache *mining_global_cache;

  /* NDPI_PROTOCOL_MSTEAMS */
  struct ndpi_lru_cache *msteams_global_cache;

  /* FPC DNS cache */
  struct ndpi_lru_cache *fpc_dns_global_cache;

  /* Signal STUN cache */
  struct ndpi_lru_cache *signal_global_cache;
};

#define CFG_MAX_LEN	256


  /*
    NOTE: keep it in sync with "metadata.tcp_fingerprint_format"
    in ndpi_main.c
   */
  typedef enum  {
    NDPI_NATIVE_TCP_FINGERPRINT = 0,
    NDPI_MUONFP_TCP_FINGERPRINT /* https://github.com/sundruid/muonfp */
  } ndpi_tcp_fingerprint_format;

  /*
    NOTE: keep it in sync with "metadata.ndpi_fingerprint_format"
    in ndpi_main.c
   */
  typedef enum  {
    NDPI_CLIENT_ONLY_NDPI_FINGERPRINT = 0, /* Default */
    NDPI_CLIENT_SERVER_NDPI_FINGERPRINT
  } ndpi_fingerprint_format;

struct ndpi_detection_module_config_struct {
  int max_packets_to_process;
 /* In some networks, there are some anomalous TCP flows where
    the smallest ACK packets have some kind of zero padding.
    It looks like the IP and TCP headers in those frames wrongly consider the
    0x00 Ethernet padding bytes as part of the TCP payload.
    While this kind of packets is perfectly valid per-se, in some conditions
    they might be treated by the TCP reassembler logic as (partial) overlaps,
    deceiving the classification engine.
    Add an heuristic to detect these packets and to ignore them, allowing
    correct detection/classification.
    See #1946 for other details */
  int tcp_ack_paylod_heuristic;
  /* Heuristic to detect fully encrypted sessions, i.e. flows where every bytes of
     the payload is encrypted in an attempt to “look like nothing”.
     This heuristic only analyzes the first packet of the flow.
     See: https://www.usenix.org/system/files/sec23fall-prepub-234-wu-mingshi.pdf */
  int fully_encrypted_heuristic;
  int track_payload_enabled;
  int libgcrypt_init;
  int guess_on_giveup;
  int compute_entropy;
  int address_cache_size;
  int fpc_enabled;
  int hostname_dns_check_enabled;
  int guess_ip_before_port;
  int use_client_ip_in_guess;
  int use_client_port_in_guess;
  ndpi_tcp_fingerprint_format tcp_fingerprint_format;
  int tcp_fingerprint_enabled;
  int tcp_fingerprint_raw_enabled;
  int ndpi_fingerprint_enabled;
  int ndpi_server_fingerprint_enabled;
  ndpi_fingerprint_format ndpi_fingerprint_format;

  char filename_config[CFG_MAX_LEN];

  int log_level;

  /* LRU caches */

  int ookla_cache_num_entries;
  int ookla_cache_ttl;
  int ookla_cache_scope;
  int bittorrent_cache_num_entries;
  int bittorrent_cache_ttl;
  int bittorrent_cache_scope;
  int stun_cache_num_entries;
  int stun_cache_ttl;
  int stun_cache_scope;
  int tls_cert_cache_num_entries;
  int tls_cert_cache_ttl;
  int tls_cert_cache_scope;
  int mining_cache_num_entries;
  int mining_cache_ttl;
  int mining_cache_scope;
  int msteams_cache_num_entries;
  int msteams_cache_ttl;
  int msteams_cache_scope;
  int fpc_dns_cache_num_entries;
  int fpc_dns_cache_ttl;
  int fpc_dns_cache_scope;
  int signal_cache_num_entries;
  int signal_cache_ttl;
  int signal_cache_scope;

  /* Protocols */

  int http_request_content_type_enabled;
  int http_referer_enabled;
  int http_host_enabled;
  int http_username_enabled;
  int http_password_enabled;
  int http_resp_content_type_enabled;
  int http_resp_server_enabled;

  int tls_certificate_expire_in_x_days;
  int tls_app_blocks_tracking_enabled;
  int tls_heuristics;
  int tls_heuristics_max_packets;
  int tls_versions_supported_enabled;
  int tls_alpn_negotiated_enabled;
  int tls_cipher_enabled;
  int tls_sha1_fingerprint_enabled;
  int tls_cert_server_names_enabled;
  int tls_cert_validity_enabled;
  int tls_cert_issuer_enabled;
  int tls_cert_subject_enabled;
  int tls_browser_enabled;
  int tls_ja3s_fingerprint_enabled;
  int tls_ja4c_fingerprint_enabled;
  int tls_ja4r_fingerprint_enabled;
  int tls_ja_data_enabled;
  int tls_ja_ignore_ephemeral_extensions;
  int tls_ndpifp_ignore_sni_extension;
  int tls_ndpifp_ignore_tcp_fingerprint;
  int tls_subclassification_enabled;
  int tls_max_num_blocks_to_analyze;
  int tls_blocks_show_timing;
  int quic_subclassification_enabled;

  int smtp_opportunistic_tls_enabled;

  int imap_opportunistic_tls_enabled;

  int pop_opportunistic_tls_enabled;

  int ftp_opportunistic_tls_enabled;

  int sip_attribute_from_enabled;
  int sip_attribute_from_imsi_enabled;
  int sip_attribute_to_enabled;
  int sip_attribute_to_imsi_enabled;

  int ssh_hassh_fingerprint_enabled;
  int ssh_hassh_data_enabled;
  
  int stun_opportunistic_tls_enabled;
  int stun_max_packets_extra_dissection;
  int rtp_max_packets_extra_dissection;
  int stun_mapped_address_enabled;
  int stun_response_origin_enabled;
  int stun_other_address_enabled;
  int stun_relayed_address_enabled;
  int stun_peer_address_enabled;

  int bittorrent_hash_enabled;

  int ssdp_metadata_enabled;

  int ntp_metadata_enabled;

  int dns_subclassification_enabled;
  int dns_parse_response_enabled;

  int http_parse_response_enabled;
  int http_subclassification_enabled;

  int ookla_aggressiveness;

  int zoom_max_packets_extra_dissection;

  int rtp_search_for_stun;

  int openvpn_heuristics;
  int openvpn_heuristics_num_msgs;
  int openvpn_subclassification_by_ip;

  int wireguard_subclassification_by_ip;

  struct ndpi_bitmask detection_bitmask;

  struct ndpi_bitmask debug_bitmask;
  struct ndpi_bitmask ip_list_bitmask;
  struct ndpi_bitmask monitoring;

  struct ndpi_bitmask flowrisk_bitmask;
  struct ndpi_bitmask flowrisk_info_bitmask;

  int flow_risk_lists_enabled;
  int risk_anonymous_subscriber_list_icloudprivaterelay_enabled;
  int risk_anonymous_subscriber_list_tor_exit_nodes_enabled;
  int risk_crawler_bot_list_enabled;
};

struct ndpi_detection_module_struct {
  u_int64_t current_ts;
  u_int8_t finalized:1, _notused:7;
  u_int8_t tls_certificate_expire_in_x_days;

  void *user_data;
  char custom_category_labels[NUM_CUSTOM_CATEGORIES][CUSTOM_CATEGORY_LABEL_LEN];

  /* callback function buffer */
  struct call_function_struct *callback_buffer;
  struct call_function_struct *callback_buffer_tcp_no_payload;
  struct call_function_struct *callback_buffer_tcp_payload;
  struct call_function_struct *callback_buffer_udp;
  struct call_function_struct *callback_buffer_non_tcp_udp;
  u_int32_t callback_buffer_size;
  u_int32_t callback_buffer_size_tcp_no_payload;
  u_int32_t callback_buffer_size_tcp_payload;
  u_int32_t callback_buffer_size_udp;
  u_int32_t callback_buffer_size_non_tcp_udp;
  u_int32_t callback_buffer_num;
  u_int32_t current_dissector_idx;

  default_ports_tree_node_t *tcpRoot, *udpRoot;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
#endif

  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  u_int num_supported_protocols;
  u_int num_custom_protocols;
  u_int num_internal_protocols;

  /* HTTP/DNS/HTTPS/QUIC host matching */
  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
    risky_domain_automa, tls_cert_subject_automa,
    host_risk_mask_automa, common_alpns_automa;
  /* IMPORTANT: please, whenever you add a new automa:
   * update ndpi_finalize_initialization()
   * update automa_type above
   */

  ndpi_str_hash *malicious_ja4_hashmap, *malicious_sha1_hashmap, *tcp_fingerprint_hashmap, *http_url_hashmap;

  ndpi_list *trusted_issuer_dn;

  /* Patricia trees */
  ndpi_ptree_t *ip_risk_mask, *ip_risk, *protocols /* IP-based protocol detection */;

  /* *** If you add a new Patricia tree, please update ptree_type above! *** */

  struct {
    ndpi_domain_classify *sc_hostnames, *sc_hostnames_shadow;
    void *ipAddresses, *ipAddresses_shadow; /* Patricia */
    void *ipAddresses6, *ipAddresses6_shadow; /* Patricia IPv6*/
    u_int8_t categories_loaded;
  } custom_categories;

  u_int8_t ip_version_limit;

  struct ndpi_global_context *g_ctx;
  struct ndpi_detection_module_config_struct cfg;

  /* NDPI_PROTOCOL_TINC */
  struct cache *tinc_cache;

  /* NDPI_PROTOCOL_OOKLA */
  struct ndpi_lru_cache *ookla_cache;

  /* NDPI_PROTOCOL_SIGNAL */
  struct ndpi_lru_cache *signal_cache;

  /* NDPI_PROTOCOL_BITTORRENT */
  struct ndpi_lru_cache *bittorrent_cache;

  /* NDPI_PROTOCOL_STUN and subprotocols */
  struct ndpi_lru_cache *stun_cache;

  /* NDPI_PROTOCOL_TLS and subprotocols */
  struct ndpi_lru_cache *tls_cert_cache;

  /* NDPI_PROTOCOL_MINING and subprotocols */
  struct ndpi_lru_cache *mining_cache;

  /* NDPI_PROTOCOL_MSTEAMS */
  struct ndpi_lru_cache *msteams_cache;

  /* FPC DNS cache */
  struct ndpi_lru_cache *fpc_dns_cache;

  /* *** If you add a new LRU cache, please update lru_cache_type above! *** */

  u_int16_t *ndpi_to_user_proto_id; /* custom protocolId mapping */
  u_int16_t ndpi_to_user_proto_id_num_allocated;

  ndpi_proto_defaults_t *proto_defaults;
  u_int16_t proto_defaults_num_allocated;

#ifdef CUSTOM_NDPI_PROTOCOLS
  #include "../../../nDPI-custom/custom_ndpi_typedefs.h"
#endif

  /* GeoIP */
  void *mmdb_city, *mmdb_as;
  u_int8_t mmdb_city_loaded, mmdb_as_loaded;

  /* Current packet */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_input_info *input_info;

#ifdef HAVE_NBPF
  u_int8_t num_nbpf_custom_proto;
  nbpf_filter nbpf_custom_proto[MAX_NBPF_CUSTOM_PROTO];
#endif

  u_int16_t max_payload_track_len;

  ndpi_str_hash *public_domain_suffixes, *ja4_custom_protos, *ndpifp_custom_protos;
  struct ndpi_address_cache *address_cache;
  struct {
    ndpi_filter *cache, *cache_shadow;
  } dns_hostname;


  struct {
    u_int num_loaded_plugins /* 0 ... NDPI_MAX_NUM_PLUGINS-1 */;
    struct {
      NDPIProtocolPluginEntryPoint *pluginPtr;
      NDPIProtocolPluginEntryPoint *entryPoint;
    } plugin[NDPI_MAX_NUM_PLUGINS];
  } proto_plugins;
};

/* Used by ndpi_set_proto_subprotocols */
#define NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS (-1)
#define NDPI_PROTOCOL_MATCHED_BY_CONTENT (-2)

#define NDPI_HOSTNAME_NORM_LC 1
#define NDPI_HOSTNAME_NORM_REPLACE_IC 2
#define NDPI_HOSTNAME_NORM_STRIP_EOLSP 4
#define NDPI_HOSTNAME_NORM_STRIP_PORT 8 /* Used by SSDP/HTTP, for the time being */
#define NDPI_HOSTNAME_NORM_ALL (NDPI_HOSTNAME_NORM_LC | NDPI_HOSTNAME_NORM_REPLACE_IC | NDPI_HOSTNAME_NORM_STRIP_EOLSP)

#define NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE 0x10000

#define NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct,flow,packet)		\
                        if (packet->packet_lines_parsed_complete != 1) {        \
			  ndpi_parse_packet_line_info(ndpi_struct,flow);	\
                        }

#define MAX_PACKET_COUNTER                                   65000


/* Log macros */

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
 #define NDPI_LOG(proto, m, log_level, args...)		                                 \
  {								                         \
    struct ndpi_detection_module_struct *mod = (struct ndpi_detection_module_struct*) m; \
    if(mod && mod->cfg.log_level >= log_level) {	                                 \
      if(mod != NULL && mod->ndpi_debug_printf != NULL)		                         \
        (*(mod->ndpi_debug_printf))(proto, mod, log_level, __FILE__, __FUNCTION__, __LINE__, args); \
    } \
  }

 /* We must define NDPI_CURRENT_PROTO before include ndpi_main.h !!!
  *
  * #include "ndpi_protocol_ids.h"
  * #define NDPI_CURRENT_PROTO NDPI_PROTOCOL_XXXX
  * #include "ndpi_api.h"
  *
  */

 #ifndef NDPI_CURRENT_PROTO
 #define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN
 #endif

 #define NDPI_LOG_ERR(mod, args...)		                                 \
  if(mod && mod->cfg.log_level >= NDPI_LOG_ERROR) {	                         \
    if(mod != NULL && mod->ndpi_debug_printf != NULL)		                         \
      (*(mod->ndpi_debug_printf))(NDPI_CURRENT_PROTO, mod, NDPI_LOG_ERROR , __FILE__, __FUNCTION__, __LINE__, args); \
  }

 #define NDPI_LOG_INFO(mod, args...)		                                 \
  if(mod && mod->cfg.log_level >= NDPI_LOG_TRACE) {	                         \
    if(mod != NULL && mod->ndpi_debug_printf != NULL)		                         \
      (*(mod->ndpi_debug_printf))(NDPI_CURRENT_PROTO, mod, NDPI_LOG_TRACE , __FILE__, __FUNCTION__, __LINE__, args); \
  }

 #define NDPI_LOG_DBG(mod, args...)		                                 \
  if(mod && mod->cfg.log_level >= NDPI_LOG_DEBUG) {	                         \
    if(mod != NULL && mod->ndpi_debug_printf != NULL)		                         \
      (*(mod->ndpi_debug_printf))(NDPI_CURRENT_PROTO, mod, NDPI_LOG_DEBUG , __FILE__, __FUNCTION__, __LINE__, args); \
  }

 #define NDPI_LOG_DBG2(mod, args...)		                                 \
  if(mod && mod->cfg.log_level >= NDPI_LOG_DEBUG_EXTRA) {	                         \
    if(mod != NULL && mod->ndpi_debug_printf != NULL)		                         \
      (*(mod->ndpi_debug_printf))(NDPI_CURRENT_PROTO, mod, NDPI_LOG_DEBUG_EXTRA , __FILE__, __FUNCTION__, __LINE__, args); \
  }

#else /* not defined NDPI_ENABLE_DEBUG_MESSAGES */
# ifdef WIN32
/*
*  Already defined in ndpi_define.h
*/
#ifndef NDPI_LOG_DBG
# define NDPI_LOG(mod, ...) { (void)mod; }
# define NDPI_LOG_ERR(mod, ...) { (void)mod; }
# define NDPI_LOG_INFO(mod, ...) { (void)mod; }
# define NDPI_LOG_DBG(mod, ...) { (void)mod; }
# define NDPI_LOG_DBG2(mod, ...) { (void)mod; }
#endif
# else
# define NDPI_LOG(proto, mod, log_level, args...) { /* printf(args); */ }
# ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#  define NDPI_LOG_ERR(mod, args...)  { (void)mod; printf(args); }
# else
#  define NDPI_LOG_ERR(mod, args...)  { (void)mod; /* printf(args); */ }
# endif
# define NDPI_LOG_INFO(mod, args...) { (void)mod; /* printf(args); */ }
# define NDPI_LOG_DBG(mod,  args...) { (void)mod; /* printf(args); */ }
# define NDPI_LOG_DBG2(mod, args...) { (void)mod; /* printf(args); */ }
# endif
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */


/* Protocol bitmasks */

#define NDPI_SELECTION_BITMASK_PROTOCOL_IP			(1<<0)
#define NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP			(1<<1)
#define NDPI_SELECTION_BITMASK_PROTOCOL_L4_UDP			(1<<2)
#define NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP_OR_UDP		(1<<3)
#define NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD		(1<<4)
#define NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION	(1<<5)
#define NDPI_SELECTION_BITMASK_PROTOCOL_IPV6			(1<<6)
#define NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6		(1<<7)
#define NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC	(1<<8)
/* now combined detections */

/* v4 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_L4_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP_OR_UDP)

/* v6 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP_OR_UDP)

/* v4 or v6 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_L4_TCP_OR_UDP)

/* does it make sense to talk about udp with payload ??? have you ever seen empty udp packets ? */
#define NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

/* Generic */

int is_proto_enabled(struct ndpi_detection_module_struct *ndpi_str, int protoId);
int is_flowrisk_enabled(struct ndpi_detection_module_struct *ndpi_str, ndpi_risk_enum flowrisk_id);

void ndpi_register_dissector(char *dissector_name, struct ndpi_detection_module_struct *ndpi_str,
                        void (*func)(struct ndpi_detection_module_struct *,
                                     struct ndpi_flow_struct *flow),
                        const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
                        int num_protocol_ids, ...);
void exclude_dissector(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                       u_int16_t dissector_idx, const char *_file, const char *_func, int _line) ;

char *strptime(const char *s, const char *format, struct tm *tm);

u_int8_t iph_is_valid_and_not_fragmented(struct ndpi_detection_module_struct *ndpi_str,
                                         const struct ndpi_iphdr *iph, const u_int16_t ipsize);

int current_pkt_from_client_to_server(const struct ndpi_detection_module_struct *ndpi_str, const struct ndpi_flow_struct *flow);
int current_pkt_from_server_to_client(const struct ndpi_detection_module_struct *ndpi_str, const struct ndpi_flow_struct *flow);

int ndpi_seen_flow_beginning(const struct ndpi_flow_struct *flow);

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				u_int16_t upper_detected_protocol,
				u_int16_t lower_detected_protocol,
				ndpi_confidence_t confidence);

void reset_detected_protocol(struct ndpi_flow_struct *flow);

void ndpi_set_detected_protocol_keeping_master(struct ndpi_detection_module_struct *ndpi_str,
					       struct ndpi_flow_struct *flow,
					       u_int16_t detected_protocol,
					       ndpi_confidence_t confidence);

void change_category(struct ndpi_flow_struct *flow,
		     ndpi_protocol_category_t protocol_category);


char *ndpi_hostname_sni_set(struct ndpi_flow_struct *flow, const u_int8_t *value, size_t value_len, int normalize);
char *ndpi_user_agent_set(struct ndpi_flow_struct *flow, const u_int8_t *value, size_t value_len);

void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct,
					  struct ndpi_flow_struct *flow);

void load_common_alpns(struct ndpi_detection_module_struct *ndpi_str);
u_int8_t is_a_common_alpn(struct ndpi_detection_module_struct *ndpi_str,
			    const char *alpn_to_check, u_int alpn_to_check_len);

int64_t asn1_ber_decode_length(const unsigned char *payload, int payload_len, u_int16_t *value_len);

u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
		   u_int32_t net, u_int32_t num_bits);

u_int8_t ends_with(struct ndpi_detection_module_struct *ndpi_struct,
                   char *str, char *ends);

u_int ndpi_search_tcp_or_udp_raw(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int32_t saddr, u_int32_t daddr);

char* ndpi_intoav4(unsigned int addr, char* buf, u_int16_t bufLen);
char* ndpi_intoav6(struct ndpi_in6_addr *addr, char* buf, u_int16_t bufLen);

int is_flow_addr_informative(const struct ndpi_flow_struct *flow);

u_int16_t icmp4_checksum(u_int8_t const * const buf, size_t len);

ndpi_risk_enum ndpi_network_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					     struct in_addr *pin /* network byte order */);

int ndpi_set_default_config(struct ndpi_detection_module_config_struct *cfg,
			    u_int16_t max_internal_proto);

int load_protocols_file_fd(struct ndpi_detection_module_struct *ndpi_mod, FILE *fd);
int load_categories_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd, void *user_data);
int load_malicious_sha1_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd);
int load_malicious_ja4_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd);
int load_risk_domain_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd);
int load_config_file_fd(struct ndpi_detection_module_struct *ndpi_str, FILE *fd);
int load_category_file_fd(struct ndpi_detection_module_struct *ndpi_str,
			  FILE *fd, ndpi_protocol_category_t category_id);

u_int64_t fpc_dns_cache_key_from_flow(struct ndpi_flow_struct *flow);

bool ndpi_cache_address(struct ndpi_detection_module_struct *ndpi_struct,
			ndpi_ip_addr_t ip_addr, char *hostname,
			u_int32_t epoch_now, u_int32_t ttl);

int is_monitoring_enabled(struct ndpi_detection_module_struct *ndpi_str, int protoId);
int is_flowrisk_info_enabled(struct ndpi_detection_module_struct *ndpi_str, ndpi_risk_enum flowrisk_id);

void proto_stack_reset(struct ndpi_proto_stack *s);

u_int8_t ndpi_is_valid_protoId(const struct ndpi_detection_module_struct *ndpi_str, u_int16_t protoId);

void fill_protocol_category_and_breed(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow);
ndpi_protocol_breed_t get_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
                                      ndpi_master_app_protocol proto);
ndpi_protocol_category_t get_proto_category(struct ndpi_detection_module_struct *ndpi_str,
                                            ndpi_master_app_protocol proto);

  /* TLS */
int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow, uint32_t quic_version);
void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow,
                                u_int16_t p_offset, u_int16_t certificate_len);
void switch_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow, int first_dtls_pkt);
int is_dtls(const u_int8_t *buf, u_int32_t buf_len, u_int32_t *block_len);
void switch_extra_dissection_to_tls(struct ndpi_detection_module_struct *ndpi_struct,
				    struct ndpi_flow_struct *flow);
void switch_extra_dissection_to_tls_obfuscated_heur(struct ndpi_detection_module_struct* ndpi_struct,
                                                    struct ndpi_flow_struct* flow);

/* OOKLA */
int ookla_search_into_cache(struct ndpi_detection_module_struct* ndpi_struct,
                            struct ndpi_flow_struct* flow);
void ookla_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct *flow);

/* SIGNAL */
int signal_search_into_cache(struct ndpi_detection_module_struct* ndpi_struct,
                            struct ndpi_flow_struct* flow);
void signal_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct *flow);

/* DNS */
void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct,
                     struct ndpi_flow_struct *flow);

/* HTTP */
void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct,
                          struct ndpi_flow_struct *flow);

/* QUIC */
int quic_len(const uint8_t *buf, uint64_t *value);
int quic_len_buffer_still_required(uint8_t value);
int is_version_with_var_int_transport_params(uint32_t version);
int is_version_with_tls(uint32_t version);
int is_quic_ver_greater_than(uint32_t version, uint8_t min_version);
void process_chlo(struct ndpi_detection_module_struct *ndpi_struct,
                  struct ndpi_flow_struct *flow,
                  const u_int8_t *crypto_data, uint32_t crypto_data_len);
void process_tls(struct ndpi_detection_module_struct *ndpi_struct,
                 struct ndpi_flow_struct *flow,
                 const u_int8_t *crypto_data, uint32_t crypto_data_len);
const uint8_t *get_crypto_data(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow,
                               u_int8_t *clear_payload, uint32_t clear_payload_len,
                               uint64_t *crypto_data_len);

/* RTP */
int is_valid_rtp_payload_type(uint8_t type);
int is_rtp_or_rtcp(struct ndpi_detection_module_struct *ndpi_struct,
                   const u_int8_t *payload, u_int16_t payload_len, u_int16_t *seq);
u_int8_t rtp_get_stream_type(u_int8_t payloadType, u_int8_t *s_type, u_int16_t sub_proto);

/* Bittorrent */
u_int64_t make_bittorrent_host_key(struct ndpi_flow_struct *flow, int client, int offset);
u_int64_t make_bittorrent_peers_key(struct ndpi_flow_struct *flow);
int search_into_bittorrent_cache(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow);


/* Stun */
int is_stun(struct ndpi_detection_module_struct *ndpi_struct,
            struct ndpi_flow_struct *flow,
            u_int16_t *app_proto, ndpi_protocol_category_t *category);
void switch_extra_dissection_to_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, int std_callback);

/* TPKT */
int tpkt_verify_hdr(const struct ndpi_packet_struct * const packet);

/* Mining Protocols (Ethereum, Monero, ...) */
u_int64_t mining_make_lru_cache_key(struct ndpi_flow_struct *flow);

/* nDPI fingerprint */
char* ndpi_compute_ndpi_flow_fingerprint(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow);

/* Plugins */
void ndpi_unload_protocol_plugins(struct ndpi_detection_module_struct *ndpi_struct);
u_int ndpi_init_protocol_plugins(struct ndpi_detection_module_struct *ndpi_struct);
  
/* Protocols init */
void init_diameter_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_afp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_armagetron_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_amqp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bgp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bittorrent_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_lisp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_teredo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ciscovpn_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_citrix_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_corba_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_crossfire_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dcerpc_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dhcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dhcpv6_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dofus_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dropbox_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_eaq_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_edonkey_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ftp_control_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ftp_data_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_gnutella_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_gtp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hsrp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_guildwars2_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_h323_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hots_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_http_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_iax_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ipp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_irc_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_jabber_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_kakaotalk_voice_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_kerberos_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ldap_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hcl_notes_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mail_imap_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mail_pop_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mail_smtp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nexon_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_megaco_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mgcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mining_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mikrotik_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mms_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_monero_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nats_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mpegts_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mssql_tds_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mysql_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_netbios_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_netflow_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nfs_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_noe_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_non_tcp_udp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ntp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_openvpn_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_oracle_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_postgres_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_pptp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_qq_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_quake_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_quic_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_radius_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rdp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_resp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rsync_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rtcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rtmp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rtp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rtsp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_sflow_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_shoutcast_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_sip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_imo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_skinny_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_smb_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_socrates_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_socks_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_sonos_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_spotify_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ssh_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_blizzard_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_steam_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_syslog_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ssdp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_teamspeak_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_teamviewer_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_telegram_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_telnet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tftp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_usenet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_wsd_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_veohtv_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_viber_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_vmware_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_vnc_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_vxlan_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_whois_das_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_xbox_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_xdmcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_zmq_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_stracraft_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ubntac2_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_coap_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mqtt_dissector (struct ndpi_detection_module_struct *ndpi_struct);
void init_someip_dissector (struct ndpi_detection_module_struct *ndpi_struct);
void init_rx_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_git_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_drda_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bjnp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_smpp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tinc_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_fix_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nintendo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_csgo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_checkmk_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cpha_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_amazon_video_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_whatsapp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ajp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_memcached_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nest_log_sink_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ookla_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_modbus_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_capwap_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_zabbix_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_wireguard_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dnp3_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_104_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_s7comm_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_websocket_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_soap_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dnscrypt_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mongodb_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_among_us_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hpvirtgrp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_genshin_impact_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_z3950_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_avast_securedns_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cassandra_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ethernet_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_toca_boca_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_sd_rtn_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_raknet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_xiaomi_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mpegdash_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rsh_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ipsec_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_collectd_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_i3d_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_riotgames_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ultrasurf_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_threema_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_alicloud_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_avast_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_softether_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_activision_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_discord_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tivoconnect_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_kismet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_fastcgi_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_natpmp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_syncthing_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_crynet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_line_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_munin_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_elasticsearch_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tuya_lp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tplink_shp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_merakicloud_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tailscale_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_source_engine_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bacnet_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_oicq_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_epicgames_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bitcoin_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_apache_thrift_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_slp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_http2_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_haproxy_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rmcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_can_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_protobuf_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ethereum_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ptpv2_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hart_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_rtps_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_opc_ua_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_fins_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ethersio_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_beckhoff_ads_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_iso9506_1_mms_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ieee_c37118_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ethersbus_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_profinet_io_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hislip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_uftp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_openflow_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_json_rpc_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_kafka_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nomachine_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_iec62056_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hl7_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ceph_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_roughtime_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_kcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_valve_sdr_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mumble_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_zoom_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_yojimbo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_stomp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_radmin_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_raft_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_gearman_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tencent_games_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_gaijin_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_c1222_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dlep_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bfd_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_netease_games_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_pathofexile_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_pfcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_flute_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_lolwildrift_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_teso_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ldp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_knxnet_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_bfcp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_iqiyi_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_egd_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cod_mobile_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_zug_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_jrmi_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_ripe_atlas_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cloudflare_warp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_nano_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_openwire_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_cnp_ip_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_atg_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_trdp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_lustre_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dingtalk_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_paltalk_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_dicom_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_lagofast_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_gearup_booster_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_msdo_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_melsec_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_hamachi_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_glbp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_easyweather_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_mudfish_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_tristation_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_samsung_sdp_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_matter_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_json_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_msgpack_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_sbe_dissector(struct ndpi_detection_module_struct *ndpi_struct);
void init_iris_dissector(struct ndpi_detection_module_struct *ndpi_struct);

#ifdef CUSTOM_NDPI_PROTOCOLS
  #include "../../../nDPI-custom/custom_ndpi_private.h"
#endif


enum cfg_param_type {
  CFG_PARAM_ENABLE_DISABLE = 0,
  CFG_PARAM_INT,
  CFG_PARAM_PROTOCOL_ENABLE_DISABLE,
  CFG_PARAM_FILENAME_CONFIG, /* We call ndpi_set_config() immediately for each row in it */
  CFG_PARAM_FLOWRISK_ENABLE_DISABLE,
};

typedef int (*cfg_calback)(struct ndpi_detection_module_struct *ndpi_str, void *_variable, const char *proto, const char *param);

struct cfg_param {
  char *proto;
  char *param;
  char *default_value;
  char *min_value;
  char *max_value;
  enum cfg_param_type type;
  int offset;
  cfg_calback fn_callback;
};

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
extern const struct cfg_param cfg_params[];
#endif


#endif

#ifdef __cplusplus
}
#endif

#endif
