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

struct call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  u_int16_t ndpi_protocol_id;
  u_int8_t detection_feature;
};

struct subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
};

typedef struct default_ports_tree_node {
  ndpi_proto_defaults_t *proto;
  u_int8_t customUserProto;
  u_int16_t default_port;
} default_ports_tree_node_t;


#define LINE_EQUALS(ndpi_int_one_line_struct, string_to_compare) \
  ((ndpi_int_one_line_struct).len == strlen(string_to_compare) && \
   LINE_CMP(ndpi_int_one_line_struct, string_to_compare, strlen(string_to_compare)) == 1)

#define LINE_STARTS(ndpi_int_one_line_struct, string_to_compare) \
  ((ndpi_int_one_line_struct).len >= strlen(string_to_compare) && \
   LINE_CMP(ndpi_int_one_line_struct, string_to_compare, strlen(string_to_compare)) == 1)

#define LINE_ENDS(ndpi_int_one_line_struct, string_to_compare) \
  ((ndpi_int_one_line_struct).len >= strlen(string_to_compare) && \
   memcmp((ndpi_int_one_line_struct).ptr + \
          ((ndpi_int_one_line_struct).len - strlen(string_to_compare)), \
          string_to_compare, strlen(string_to_compare)) == 0)

#define LINE_CMP(ndpi_int_one_line_struct, string_to_compare, string_to_compare_length) \
  ((ndpi_int_one_line_struct).ptr != NULL && \
   memcmp((ndpi_int_one_line_struct).ptr, string_to_compare, string_to_compare_length) == 0)

struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
};

struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
  const struct ndpi_ipv6hdr *iphv6;
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
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
  struct ndpi_int_one_line_struct http_response; /* the first "word" in this pointer is the
						    response code in the packet (200, etc) */

  u_int16_t l3_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t parsed_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;

  u_int8_t packet_lines_parsed_complete:1,
    packet_direction:1, empty_line_position_set:1, http_check_content:1, pad:4;
};

typedef struct ndpi_list_struct {
  char *value;
  struct ndpi_list_struct *next;
} ndpi_list;

#ifdef HAVE_NBPF
typedef struct {
  void *tree; /* cast to nbpf_filter* */
  u_int16_t l7_protocol;
} nbpf_filter;
#endif

struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;

  u_int64_t current_ts;
  u_int16_t max_packets_to_process;
  u_int16_t num_tls_blocks_to_follow;
  u_int8_t skip_tls_blocks_until_change_cipher:1, enable_ja3_plus:1, _notused:6;
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

  default_ports_tree_node_t *tcpRoot, *udpRoot;

  ndpi_log_level_t ndpi_log_level; /* default error */

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
  u_int32_t ndpi_debug_print_line;
  NDPI_PROTOCOL_BITMASK debug_bitmask;
#endif

  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  /* subprotocol registration handler */
  struct subprotocol_conf_struct subprotocol_conf[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

  u_int ndpi_num_supported_protocols;
  u_int ndpi_num_custom_protocols;

  int ac_automa_finalized;
  /* HTTP/DNS/HTTPS/QUIC host matching */
  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
    risky_domain_automa, tls_cert_subject_automa,
    host_risk_mask_automa, common_alpns_automa;
  /* IMPORTANT: please, whenever you add a new automa:
   * update ndpi_finalize_initialization()
   * update automa_type above
   */

  ndpi_str_hash *malicious_ja3_hashmap, *malicious_sha1_hashmap;

  ndpi_list *trusted_issuer_dn;

  /* Patricia trees */
  ndpi_patricia_tree_t *ip_risk_mask_ptree;
  ndpi_patricia_tree_t *ip_risk_mask_ptree6;
  ndpi_patricia_tree_t *ip_risk_ptree; 
  ndpi_patricia_tree_t *ip_risk_ptree6;
  ndpi_patricia_tree_t *protocols_ptree;  /* IP-based protocol detection */
  ndpi_patricia_tree_t *protocols_ptree6;
  
  /* *** If you add a new Patricia tree, please update ptree_type above! *** */

  struct {
#ifdef USE_LEGACY_AHO_CORASICK
    ndpi_automa hostnames, hostnames_shadow;
#else
    ndpi_domain_classify *sc_hostnames, *sc_hostnames_shadow;
#endif
    void *ipAddresses, *ipAddresses_shadow; /* Patricia */
    void *ipAddresses6, *ipAddresses6_shadow; /* Patricia IPv6*/
    u_int8_t categories_loaded;
  } custom_categories;

  u_int8_t ip_version_limit;

  /* NDPI_PROTOCOL_TINC */
  struct cache *tinc_cache;

  /* NDPI_PROTOCOL_OOKLA */
  struct ndpi_lru_cache *ookla_cache;
  u_int32_t ookla_cache_num_entries;
  u_int32_t ookla_cache_ttl;

  /* NDPI_PROTOCOL_BITTORRENT */
  struct ndpi_lru_cache *bittorrent_cache;
  u_int32_t bittorrent_cache_num_entries;
  u_int32_t bittorrent_cache_ttl;

  /* NDPI_PROTOCOL_ZOOM */
  struct ndpi_lru_cache *zoom_cache;
  u_int32_t zoom_cache_num_entries;
  u_int32_t zoom_cache_ttl;

  /* NDPI_PROTOCOL_STUN and subprotocols */
  struct ndpi_lru_cache *stun_cache;
  u_int32_t stun_cache_num_entries;
  u_int32_t stun_cache_ttl;
  struct ndpi_lru_cache *stun_zoom_cache;
  u_int32_t stun_zoom_cache_num_entries;
  u_int32_t stun_zoom_cache_ttl;

  /* NDPI_PROTOCOL_TLS and subprotocols */
  struct ndpi_lru_cache *tls_cert_cache;
  u_int32_t tls_cert_cache_num_entries;
  int32_t tls_cert_cache_ttl;
  
  /* NDPI_PROTOCOL_MINING and subprotocols */
  struct ndpi_lru_cache *mining_cache;
  u_int32_t mining_cache_num_entries;
  u_int32_t mining_cache_ttl;

  /* NDPI_PROTOCOL_MSTEAMS */
  struct ndpi_lru_cache *msteams_cache;
  u_int32_t msteams_cache_num_entries;
  u_int32_t msteams_cache_ttl;

  /* *** If you add a new LRU cache, please update lru_cache_type above! *** */

  int opportunistic_tls_smtp_enabled;
  int opportunistic_tls_imap_enabled;
  int opportunistic_tls_pop_enabled;
  int opportunistic_tls_ftp_enabled;
  int opportunistic_tls_stun_enabled;

  u_int32_t monitoring_stun_pkts_to_process;
  u_int32_t monitoring_stun_flags;

  u_int32_t aggressiveness_ookla;

  int tcp_ack_paylod_heuristic;
  int fully_encrypted_based_on_first_pkt_heuristic;

  u_int16_t ndpi_to_user_proto_id[NDPI_MAX_NUM_CUSTOM_PROTOCOLS]; /* custom protocolId mapping */
  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

  u_int8_t direction_detect_disable:1, /* disable internal detection of packet direction */ _pad:7;

#ifdef CUSTOM_NDPI_PROTOCOLS
  #include "../../../nDPI-custom/custom_ndpi_typedefs.h"
#endif

  /* GeoIP */
  void *mmdb_city, *mmdb_as;
  u_int8_t mmdb_city_loaded, mmdb_as_loaded;

  /* Current packet */
  struct ndpi_packet_struct packet;
  const struct ndpi_flow_input_info *input_info;

#ifdef HAVE_NBPF
  u_int8_t num_nbpf_custom_proto;
  nbpf_filter nbpf_custom_proto[MAX_NBPF_CUSTOM_PROTO];
#endif

  u_int16_t max_payload_track_len;    
};






/* Generic */

char *strptime(const char *s, const char *format, struct tm *tm);

u_int8_t iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize);

int current_pkt_from_client_to_server(const struct ndpi_detection_module_struct *ndpi_str, const struct ndpi_flow_struct *flow);
int current_pkt_from_server_to_client(const struct ndpi_detection_module_struct *ndpi_str, const struct ndpi_flow_struct *flow);

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

/* HTTP */
void http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow,
                             const u_int8_t *ua_ptr, u_int16_t ua_ptr_len);

/* OOKLA */
int ookla_search_into_cache(struct ndpi_detection_module_struct* ndpi_struct,
                            struct ndpi_flow_struct* flow);
void ookla_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                        struct ndpi_flow_struct *flow);

/* QUIC */
int quic_len(const uint8_t *buf, uint64_t *value);
int quic_len_buffer_still_required(uint8_t value);
int is_version_with_var_int_transport_params(uint32_t version);
int is_version_with_tls(uint32_t version);
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
                          struct ndpi_flow_struct *flow);
u_int8_t rtp_get_stream_type(u_int8_t payloadType, ndpi_multimedia_flow_type *s_type);

/* Bittorrent */
u_int32_t make_bittorrent_host_key(struct ndpi_flow_struct *flow, int client, int offset);
u_int32_t make_bittorrent_peers_key(struct ndpi_flow_struct *flow);
int search_into_bittorrent_cache(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow);


/* Mining */
u_int32_t make_mining_key(struct ndpi_flow_struct *flow);

/* Stun */
int stun_search_into_zoom_cache(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);


#endif

#ifdef __cplusplus
}
#endif

#endif
