/*
 * ndpi_typedefs.h
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

#ifndef __NDPI_TYPEDEFS_H__
#define __NDPI_TYPEDEFS_H__

#include "ndpi_define.h"
#include "ndpi_protocol_ids.h"
#include "ndpi_utils.h"

/* Used by both nDPI core and patricia code under third-party */
#include "ndpi_patricia_typedefs.h"

/* NDPI_LOG_LEVEL */
typedef enum {
	      NDPI_LOG_ERROR,
	      NDPI_LOG_TRACE,
	      NDPI_LOG_DEBUG,
	      NDPI_LOG_DEBUG_EXTRA
} ndpi_log_level_t;

typedef enum {
	      ndpi_l4_proto_unknown = 0,
	      ndpi_l4_proto_tcp_only,
	      ndpi_l4_proto_udp_only,
	      ndpi_l4_proto_tcp_and_udp,
} ndpi_l4_proto_info;

typedef enum {
  ndpi_no_tunnel = 0,
  ndpi_gtp_tunnel,
  ndpi_capwap_tunnel,
  ndpi_tzsp_tunnel,
  ndpi_l2tp_tunnel,
  ndpi_vxlan_tunnel,
} ndpi_packet_tunnel;

/*
  NOTE
  When the typedef below is modified don't forget to update
  - nDPI/wireshark/ndpi.lua
  - ndpi_risk2str (in ndpi_utils.c)
  - doc/flow_risks.rst
  - ndpi_risk_enum (in python/ndpi.py)
  - ndpi_known_risks (ndpi_main.c)

  To make sure the risk is also seen by ntopng:
  1. Add a new flow alert key to the enum FlowAlertTypeEnum in include/ntop_typedefs.h
  2. Add the very same flow alert key to the table flow_alert_keys in scripts/lua/modules/alert_keys/flow_alert_keys.lua
  3. Add the risk to the array risk_enum_to_alert_type in src/FlowRiskAlerts.cpp
     - To initialize .alert_type use the flow alert key added in 1. and an AlertCategory
     - To initialize .alert_lua_name use a unique string

  Example: https://github.com/ntop/ntopng/commit/aecc1e3e6505a0522439dbb2b295a3703d3d0f9a
 */
typedef enum {
  NDPI_NO_RISK = 0,
  NDPI_URL_POSSIBLE_XSS,
  NDPI_URL_POSSIBLE_SQL_INJECTION,
  NDPI_URL_POSSIBLE_RCE_INJECTION,
  NDPI_BINARY_APPLICATION_TRANSFER,
  NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
  NDPI_TLS_SELFSIGNED_CERTIFICATE,
  NDPI_TLS_OBSOLETE_VERSION,
  NDPI_TLS_WEAK_CIPHER,
  NDPI_TLS_CERTIFICATE_EXPIRED,
  NDPI_TLS_CERTIFICATE_MISMATCH, /* 10 */
  NDPI_HTTP_SUSPICIOUS_USER_AGENT,
  NDPI_HTTP_NUMERIC_IP_HOST,
  NDPI_HTTP_SUSPICIOUS_URL,
  NDPI_HTTP_SUSPICIOUS_HEADER,
  NDPI_TLS_NOT_CARRYING_HTTPS,
  NDPI_SUSPICIOUS_DGA_DOMAIN,
  NDPI_MALFORMED_PACKET,
  NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
  NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
  NDPI_SMB_INSECURE_VERSION, /* 20 */
  NDPI_TLS_SUSPICIOUS_ESNI_USAGE,
  NDPI_UNSAFE_PROTOCOL,
  NDPI_DNS_SUSPICIOUS_TRAFFIC,
  NDPI_TLS_MISSING_SNI,
  NDPI_HTTP_SUSPICIOUS_CONTENT,
  NDPI_RISKY_ASN,
  NDPI_RISKY_DOMAIN,
  NDPI_MALICIOUS_JA3,
  NDPI_MALICIOUS_SHA1_CERTIFICATE,
  NDPI_DESKTOP_OR_FILE_SHARING_SESSION, /* 30 */
  NDPI_TLS_UNCOMMON_ALPN,
  NDPI_TLS_CERT_VALIDITY_TOO_LONG,
  NDPI_TLS_SUSPICIOUS_EXTENSION,
  NDPI_TLS_FATAL_ALERT,
  NDPI_SUSPICIOUS_ENTROPY,
  NDPI_CLEAR_TEXT_CREDENTIALS,
  NDPI_DNS_LARGE_PACKET,
  NDPI_DNS_FRAGMENTED,
  NDPI_INVALID_CHARACTERS,
  NDPI_POSSIBLE_EXPLOIT, /* Log4J and other exploits */
  NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,

  /* Leave this as last member */
  NDPI_MAX_RISK /* must be <= 63 due to (**) */
} ndpi_risk_enum;

typedef u_int64_t ndpi_risk; /* (**) */

typedef enum {
  NDPI_RISK_LOW,
  NDPI_RISK_MEDIUM,
  NDPI_RISK_HIGH,
  NDPI_RISK_SEVERE
} ndpi_risk_severity;

typedef enum {
  NDPI_SCORE_RISK_LOW    =  10,
  NDPI_SCORE_RISK_MEDIUM =  50,
  NDPI_SCORE_RISK_HIGH   = 100,
  NDPI_SCORE_RISK_SEVERE = 250,
} ndpi_risk_score;

typedef enum {
  CLIENT_NO_RISK_PERCENTAGE   =   0, /* 100% server risk */
  CLIENT_LOW_RISK_PERCENTAGE  =  10, /* 90%  server risk */
  CLIENT_FAIR_RISK_PERCENTAGE =  50, /* 50%  server risk */
  CLIENT_HIGH_RISK_PERCENTAGE =  90, /* 10%  server risk */
  CLIENT_FULL_RISK_PERCENTAGE = 100 /* 0%   server risk */
} risk_percentage;

typedef struct {
  ndpi_risk_enum risk;
  ndpi_risk_severity severity;
  risk_percentage default_client_risk_pctg; /* 0-100 */
} ndpi_risk_info;

/* NDPI_VISIT */
typedef enum {
   ndpi_preorder,
   ndpi_postorder,
   ndpi_endorder,
   ndpi_leaf
} ndpi_VISIT;

/* NDPI_NODE */
typedef struct node_t {
  char *key;
  struct node_t *left, *right;
} ndpi_node;

/* NDPI_MASK_SIZE */
typedef u_int32_t ndpi_ndpi_mask;

/* NDPI_PROTO_BITMASK_STRUCT */
typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask fds_bits[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;

/* NDPI_DEBUG_FUNCTION_PTR (cast) */
typedef void (*ndpi_debug_function_ptr) (u_int32_t protocol, void *module_struct,
					 ndpi_log_level_t log_level, const char *file,
					 const char *func, unsigned line,
					 const char *format, ...);

/* ************************************************************ */
/* ******************* NDPI NETWORKS HEADERS ****************** */
/* ************************************************************ */

/* ++++++++++++++++++++++++ Cisco headers +++++++++++++++++++++ */

/* Cisco HDLC */
#ifdef _MSC_VER
/* Windows */
#define PACK_ON   __pragma(pack(push, 1))
#define PACK_OFF  __pragma(pack(pop))
#elif defined(__GNUC__)
/* GNU C */
#define PACK_ON
#define PACK_OFF  __attribute__((packed))
#endif

PACK_ON
struct ndpi_chdlc
{
  u_int8_t addr;          /* 0x0F (Unicast) - 0x8F (Broadcast) */
  u_int8_t ctrl;          /* always 0x00                       */
  u_int16_t proto_code;   /* protocol type (e.g. 0x0800 IP)    */
} PACK_OFF;

/* SLARP - Serial Line ARP http://tinyurl.com/qa54e95 */
PACK_ON
struct ndpi_slarp
{
  /* address requests (0x00)
     address replies  (0x01)
     keep-alive       (0x02)
  */
  u_int32_t slarp_type;
  u_int32_t addr_1;
  u_int32_t addr_2;
} PACK_OFF;

/* Cisco Discovery Protocol http://tinyurl.com/qa6yw9l */
PACK_ON
struct ndpi_cdp
{
  u_int8_t version;
  u_int8_t ttl;
  u_int16_t checksum;
  u_int16_t type;
  u_int16_t length;
} PACK_OFF;

/* +++++++++++++++ Ethernet header (IEEE 802.3) +++++++++++++++ */

PACK_ON
struct ndpi_ethhdr
{
  u_char h_dest[6];       /* destination eth addr */
  u_char h_source[6];     /* source ether addr    */
  u_int16_t h_proto;      /* data length (<= 1500) or type ID proto (>=1536) */
} PACK_OFF;

/* +++++++++++++++ ARP header +++++++++++++++ */
PACK_ON
struct ndpi_arphdr {
  u_int16_t ar_hrd;/* Format of hardware address.  */
  u_int16_t ar_pro;/* Format of protocol address.  */
  u_int8_t  ar_hln;/* Length of hardware address.  */
  u_int8_t  ar_pln;/* Length of protocol address.  */
  u_int16_t ar_op;/* ARP opcode (command).  */
  u_char arp_sha[6];/* sender hardware address */
  u_int32_t arp_spa;/* sender protocol address */
  u_char arp_tha[6];/* target hardware address */
  u_int32_t arp_tpa;/* target protocol address */
} PACK_OFF;

/* +++++++++++++++ DHCP header +++++++++++++++ */
PACK_ON
struct ndpi_dhcphdr {
  u_int8_t      msgType;
  u_int8_t      htype;
  u_int8_t      hlen;
  u_int8_t      hops;
  u_int32_t     xid;/* 4 */
  u_int16_t     secs;/* 8 */
  u_int16_t     flags;
  u_int32_t     ciaddr;/* 12 */
  u_int32_t     yiaddr;/* 16 */
  u_int32_t     siaddr;/* 20 */
  u_int32_t     giaddr;/* 24 */
  u_int8_t      chaddr[16]; /* 28 */
  u_int8_t      sname[64]; /* 44 */
  u_int8_t      file[128]; /* 108 */
  u_int32_t     magic; /* 236 */
  u_int8_t      options[308];
} PACK_OFF;

/* +++++++++++++++ MDNS rsp header +++++++++++++++ */
PACK_ON
struct ndpi_mdns_rsp_entry {
  u_int16_t rsp_type, rsp_class;
  u_int32_t ttl;
  u_int16_t data_len;
} PACK_OFF;

/* +++++++++++++++++++ LLC header (IEEE 802.2) ++++++++++++++++ */

PACK_ON
struct ndpi_snap_extension
{
  u_int16_t   oui;
  u_int8_t    oui2;
  u_int16_t   proto_ID;
} PACK_OFF;

PACK_ON
struct ndpi_llc_header_snap
{
  u_int8_t    dsap;
  u_int8_t    ssap;
  u_int8_t    ctrl;
  struct ndpi_snap_extension snap;
} PACK_OFF;

/* ++++++++++ RADIO TAP header (for IEEE 802.11) +++++++++++++ */
PACK_ON
struct ndpi_radiotap_header
{
  u_int8_t  version;         /* set to 0 */
  u_int8_t  pad;
  u_int16_t len;
  u_int32_t present;
  u_int64_t MAC_timestamp;
  u_int8_t flags;
} PACK_OFF;

/* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
PACK_ON
struct ndpi_wifi_header
{
  u_int16_t fc;
  u_int16_t duration;
  u_char rcvr[6];
  u_char trsm[6];
  u_char dest[6];
  u_int16_t seq_ctrl;
  /* u_int64_t ccmp - for data encryption only - check fc.flag */
} PACK_OFF;

/* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_mpls_header
{
  /* Before using this strcut to parse an MPLS header, you will need to convert
   * the 4-byte data to the correct endianess with ntohl(). */
#if defined(__LITTLE_ENDIAN__)
  u_int32_t ttl:8, s:1, exp:3, label:20;
#elif defined(__BIG_ENDIAN__)
  u_int32_t label:20, exp:3, s:1, ttl:8;
#else
# error "Byte order must be defined"
#endif
} PACK_OFF;

/* ++++++++++++++++++++++++ IP header ++++++++++++++++++++++++ */

PACK_ON
struct ndpi_iphdr {
#if defined(__LITTLE_ENDIAN__)
  u_int8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
} PACK_OFF;

/* +++++++++++++++++++++++ IPv6 header +++++++++++++++++++++++ */
/* rfc3542 */

PACK_ON
struct ndpi_in6_addr {
  union {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
    u_int64_t  u6_addr64[2];
  } u6_addr;  /* 128-bit IP6 address */
} PACK_OFF;

PACK_ON
struct ndpi_ip6_hdrctl {
  u_int32_t ip6_un1_flow;
  u_int16_t ip6_un1_plen;
  u_int8_t ip6_un1_nxt;
  u_int8_t ip6_un1_hlim;
} PACK_OFF;

PACK_ON
struct ndpi_ipv6hdr {
  struct ndpi_ip6_hdrctl ip6_hdr;
  struct ndpi_in6_addr ip6_src;
  struct ndpi_in6_addr ip6_dst;
} PACK_OFF;

/* +++++++++++++++++++++++ TCP header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_tcphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
  u_int16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN__)
  u_int16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "Byte order must be defined"
#endif
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
} PACK_OFF;

/* +++++++++++++++++++++++ UDP header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
} PACK_OFF;

PACK_ON
struct ndpi_dns_packet_header {
  u_int16_t tr_id;
  u_int16_t flags;
  u_int16_t num_queries;
  u_int16_t num_answers;
  u_int16_t authority_rrs;
  u_int16_t additional_rrs;
} PACK_OFF;

typedef union
{
  u_int32_t ipv4;
  struct ndpi_in6_addr ipv6;
} ndpi_ip_addr_t;


/* +++++++++++++++++++++++ ICMP header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_icmphdr {
  u_int8_t type;/* message type */
  u_int8_t code;/* type sub-code */
  u_int16_t checksum;
  union {
    struct {
      u_int16_t id;
      u_int16_t sequence;
    } echo; /* echo datagram */

    u_int32_t gateway; /* gateway address */
    struct {
      u_int16_t _unused;
      u_int16_t mtu;
    } frag;/* path mtu discovery */
  } un;
} PACK_OFF;

/* +++++++++++++++++++++++ ICMP6 header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_icmp6hdr {
  uint8_t     icmp6_type;   /* type field */
  uint8_t     icmp6_code;   /* code field */
  uint16_t    icmp6_cksum;  /* checksum field */
  union {
    uint32_t  icmp6_un_data32[1]; /* type-specific field */
    uint16_t  icmp6_un_data16[2]; /* type-specific field */
    uint8_t   icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
} PACK_OFF;

/* +++++++++++++++++++++++ VXLAN header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_vxlanhdr {
  u_int16_t flags;
  u_int16_t groupPolicy;
  u_int32_t vni;
} PACK_OFF;

/* ************************************************************ */
/* ******************* ********************* ****************** */
/* ************************************************************ */

typedef struct message {
  u_int8_t *buffer;
  u_int buffer_len, buffer_used;
  u_int32_t next_seq[2]; /* Directions */
} message_t;

/* NDPI_PROTOCOL_TINC */
#define TINC_CACHE_MAX_SIZE 10

PACK_ON struct tinc_cache_entry {
  u_int32_t src_address;
  u_int32_t dst_address;
  u_int16_t dst_port;
} PACK_OFF;

/*
   In case the typedef below is modified, please update
   ndpi_http_method2str (ndpi_utils.c)
*/
typedef enum {
	      NDPI_HTTP_METHOD_UNKNOWN = 0,
	      NDPI_HTTP_METHOD_OPTIONS,
	      NDPI_HTTP_METHOD_GET,
	      NDPI_HTTP_METHOD_HEAD,
	      NDPI_HTTP_METHOD_PATCH,
	      NDPI_HTTP_METHOD_POST,
	      NDPI_HTTP_METHOD_PUT,
	      NDPI_HTTP_METHOD_DELETE,
	      NDPI_HTTP_METHOD_TRACE,
	      NDPI_HTTP_METHOD_CONNECT
} ndpi_http_method;

struct ndpi_lru_cache_entry {
  u_int32_t key; /* Store the whole key to avoid ambiguities */
  u_int32_t is_full:1, value:16, pad:15;
};

struct ndpi_lru_cache {
  u_int32_t num_entries;
  struct ndpi_lru_cache_entry *entries;
};

/* ************************************************** */

struct ndpi_flow_tcp_struct {

  /* NDPI_PROTOCOL_MAIL_SMTP */
  /* NDPI_PROTOCOL_MAIL_POP */
  /* NDPI_PROTOCOL_MAIL_IMAP */
  /* NDPI_PROTOCOL_MAIL_FTP */
  /* TODO: something clever to save memory */
  struct {
    u_int8_t auth_found:1, auth_failed:1, auth_tls:1, auth_done:1, _pad:4;
    char username[32], password[16];
  } ftp_imap_pop_smtp;

  /* NDPI_PROTOCOL_MAIL_SMTP */
  u_int16_t smtp_command_bitmask;

  /* NDPI_PROTOCOL_MAIL_POP */
  u_int16_t pop_command_bitmask;

  /* NDPI_PROTOCOL_WHATSAPP */
  u_int8_t wa_matched_so_far;

  /* NDPI_PROTOCOL_IRC */
  u_int8_t irc_stage;

  /* NDPI_PROTOCOL_H323 */
  u_int8_t h323_valid_packets;

  /* NDPI_PROTOCOL_GNUTELLA */
  u_int8_t gnutella_msg_id[3];

  /* NDPI_PROTOCOL_IRC */
  u_int32_t irc_3a_counter:3;
  u_int32_t irc_stage2:5;
  u_int32_t irc_direction:2;
  u_int32_t irc_0x1000_full:1;

  /* NDPI_PROTOCOL_USENET */
  u_int32_t usenet_stage:2;

  /* NDPI_PROTOCOL_HTTP */
  u_int32_t http_stage:2;
  u_int32_t http_empty_line_seen:1;

  /* NDPI_PROTOCOL_GNUTELLA */
  u_int32_t gnutella_stage:2;		       // 0 - 2

  /* NDPI_PROTOCOL_SSH */
  u_int32_t ssh_stage:3;

  /* NDPI_PROTOCOL_VNC */
  u_int32_t vnc_stage:2;			// 0 - 3

  /* NDPI_PROTOCOL_TELNET */
  u_int32_t telnet_stage:2;			// 0 - 2

  struct {
    message_t message;

    /* NDPI_PROTOCOL_TLS */
    u_int8_t certificate_processed:1, fingerprint_set:1, _pad:6;
    u_int8_t num_tls_blocks;
    int16_t tls_application_blocks_len[NDPI_MAX_NUM_TLS_APPL_BLOCKS]; /* + = src->dst, - = dst->src */
  } tls;

  /* NDPI_PROTOCOL_POSTGRES */
  u_int32_t postgres_stage:3;

  /* Part of the TCP header. */
  u_int32_t seen_syn:1;
  u_int32_t seen_syn_ack:1;
  u_int32_t seen_ack:1;

  /* NDPI_PROTOCOL_ICECAST */
  u_int32_t icecast_stage:1;

  /* NDPI_PROTOCOL_DOFUS */
  u_int32_t dofus_stage:1;

  /* NDPI_PROTOCOL_FIESTA */
  u_int32_t fiesta_stage:2;

  /* NDPI_PROTOCOL_WORLDOFWARCRAFT */
  u_int32_t wow_stage:2;

  /* NDPI_PROTOCOL_SHOUTCAST */
  u_int32_t shoutcast_stage:2;

  /* NDPI_PROTOCOL_RTP */
  u_int32_t rtp_special_packets_seen:1;

  /* NDPI_PROTOCOL_MAIL_POP */
  u_int32_t mail_pop_stage:2;

  /* NDPI_PROTOCOL_MAIL_IMAP */
  u_int32_t mail_imap_stage:3, mail_imap_starttls:2;

  /* NDPI_PROTOCOL_SOAP */
  u_int32_t soap_stage:1;

  /* NDPI_PROTOCOL_SKYPE */
  u_int8_t skype_packet_id;

  /* NDPI_PROTOCOL_CITRIX */
  u_int8_t citrix_packet_id;

  /* NDPI_PROTOCOL_LOTUS_NOTES */
  u_int8_t lotus_notes_packet_id;

  /* NDPI_PROTOCOL_TEAMVIEWER */
  u_int8_t teamviewer_stage;

  /* NDPI_PROTOCOL_ZMQ */
  u_int8_t prev_zmq_pkt_len;
  u_char prev_zmq_pkt[10];

  /* NDPI_PROTOCOL_PPSTREAM */
  u_int32_t ppstream_stage:3;

  /* NDPI_PROTOCOL_MEMCACHED */
  u_int8_t memcached_matches;

  /* NDPI_PROTOCOL_NEST_LOG_SINK */
  u_int8_t nest_log_sink_matches;
};

/* ************************************************** */

struct ndpi_flow_udp_struct {
  /* NDPI_PROTOCOL_PPSTREAM */
  u_int32_t ppstream_stage:3;		  // 0 - 7

  /* NDPI_PROTOCOL_HALFLIFE2 */
  u_int32_t halflife2_stage:2;		  // 0 - 2

  /* NDPI_PROTOCOL_TFTP */
  u_int32_t tftp_stage:2;

  /* NDPI_PROTOCOL_AIMINI */
  u_int32_t aimini_stage:5;

  /* NDPI_PROTOCOL_XBOX */
  u_int32_t xbox_stage:1;

  /* NDPI_PROTOCOL_SKYPE */
  u_int8_t skype_packet_id;
  u_int8_t skype_crc[4];

  /* NDPI_PROTOCOL_TEAMVIEWER */
  u_int8_t teamviewer_stage;

  /* NDPI_PROTOCOL_EAQ */
  u_int8_t eaq_pkt_id;
  u_int32_t eaq_sequence;

  /* NDPI_PROTOCOL_RX */
  u_int32_t rx_conn_epoch;
  u_int32_t rx_conn_id;

  /* NDPI_PROTOCOL_MEMCACHED */
  u_int8_t memcached_matches;

  /* NDPI_PROTOCOL_WIREGUARD */
  u_int8_t wireguard_stage;
  u_int32_t wireguard_peer_index[2];

  /* NDPI_PROTOCOL_QUIC */
  u_int8_t *quic_reasm_buf;
  u_int32_t quic_reasm_buf_len;

  /* NDPI_PROTOCOL_CSGO */
  u_int8_t csgo_strid[18],csgo_state,csgo_s2;
  u_int32_t csgo_id2;

  /* NDPI_PROTOCOL_RDP */
  u_int8_t rdp_to_srv[3], rdp_from_srv[3], rdp_to_srv_pkts, rdp_from_srv_pkts;   

  /* NDPI_PROTOCOL_IMO */
  u_int8_t imo_last_one_byte_pkt, imo_last_byte;
};

/* ************************************************** */

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
  struct ndpi_int_one_line_struct http_encoding;
  struct ndpi_int_one_line_struct http_transfer_encoding;
  struct ndpi_int_one_line_struct http_contentlen;
  struct ndpi_int_one_line_struct http_cookie;
  struct ndpi_int_one_line_struct http_origin;
  struct ndpi_int_one_line_struct http_x_session_type;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct http_response; /* the first "word" in this pointer is the
						    response code in the packet (200, etc) */
  u_int8_t http_num_headers; /* number of found (valid) header lines in HTTP request or response */

  u_int16_t l3_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t parsed_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;

  u_int8_t packet_lines_parsed_complete:1,
    packet_direction:1, empty_line_position_set:1, http_check_content:1, pad:4;
};

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

struct ndpi_call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  u_int16_t ndpi_protocol_id;
  u_int8_t detection_feature;
};

struct ndpi_subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
};

typedef struct {
  u_int16_t port_low, port_high;
} ndpi_port_range;

typedef enum {
  NDPI_CONFIDENCE_UNKNOWN = 0,		/* Unknown classification */
  NDPI_CONFIDENCE_MATCH_BY_PORT,	/* Classification obtained looking only at the L4 ports */
  NDPI_CONFIDENCE_MATCH_BY_IP,		/* Classification obtained looking only at the L3 addresses */
  NDPI_CONFIDENCE_DPI_CACHE,		/* Classification results based on same LRU cache (i.e. correlation among sessions) */
  NDPI_CONFIDENCE_DPI,			/* Deep packet inspection */

  /*
    IMPORTANT

    Please keep in sync with

    ndpi_confidence_get_name()

    in ndpi_main.c
  */

  /* Last one */
  NDPI_CONFIDENCE_MAX,
} ndpi_confidence_t;

typedef enum {
  NDPI_PROTOCOL_SAFE = 0,              /* Surely doesn't provide risks for the network. (e.g., a news site) */
  NDPI_PROTOCOL_ACCEPTABLE,            /* Probably doesn't provide risks, but could be malicious (e.g., Dropbox) */
  NDPI_PROTOCOL_FUN,                   /* Pure fun protocol, which may be prohibited by the user policy (e.g., Netflix) */
  NDPI_PROTOCOL_UNSAFE,                /* Probably provides risks, but could be a normal traffic. Unencrypted protocols with clear pass should be here (e.g., telnet) */
  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, /* Possibly dangerous (ex. Tor). */
  NDPI_PROTOCOL_DANGEROUS,             /* Surely is dangerous (ex. smbv1). Be prepared to troubles */
  NDPI_PROTOCOL_TRACKER_ADS,           /* Trackers, Advertisements... */
  NDPI_PROTOCOL_UNRATED                /* No idea, not implemented or impossible to classify */
} ndpi_protocol_breed_t;

#define NUM_BREEDS (NDPI_PROTOCOL_UNRATED+1)

/* Abstract categories to group the protocols. */
typedef enum {
  NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,   /* For general services and unknown protocols */
  NDPI_PROTOCOL_CATEGORY_MEDIA,             /* Multimedia and streaming */
  NDPI_PROTOCOL_CATEGORY_VPN,               /* Virtual Private Networks */
  NDPI_PROTOCOL_CATEGORY_MAIL,              /* Protocols to send/receive/sync emails */
  NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,     /* AFS/NFS and similar protocols */
  NDPI_PROTOCOL_CATEGORY_WEB,               /* Web/mobile protocols and services */
  NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,    /* Social networks */
  NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,       /* Download, FTP, file transfer/sharing */
  NDPI_PROTOCOL_CATEGORY_GAME,              /* Online games */
  NDPI_PROTOCOL_CATEGORY_CHAT,              /* Instant messaging */
  NDPI_PROTOCOL_CATEGORY_VOIP,              /* Real-time communications and conferencing */
  NDPI_PROTOCOL_CATEGORY_DATABASE,          /* Protocols for database communication */
  NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,     /* Remote access and control */
  NDPI_PROTOCOL_CATEGORY_CLOUD,             /* Online cloud services */
  NDPI_PROTOCOL_CATEGORY_NETWORK,           /* Network infrastructure protocols */
  NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,     /* Software for collaborative development, including Webmail */
  NDPI_PROTOCOL_CATEGORY_RPC,               /* High level network communication protocols */
  NDPI_PROTOCOL_CATEGORY_STREAMING,         /* Streaming protocols */
  NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,         /* System/Operating System level applications */
  NDPI_PROTOCOL_CATEGORY_SW_UPDATE,         /* Software update */
  
  /* See #define NUM_CUSTOM_CATEGORIES */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_1,          /* User custom category 1 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_2,          /* User custom category 2 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_3,          /* User custom category 3 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_4,          /* User custom category 4 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_5,          /* User custom category 5 */
  
  /* Further categories... */
  NDPI_PROTOCOL_CATEGORY_MUSIC,
  NDPI_PROTOCOL_CATEGORY_VIDEO,
  NDPI_PROTOCOL_CATEGORY_SHOPPING,
  NDPI_PROTOCOL_CATEGORY_PRODUCTIVITY,
  NDPI_PROTOCOL_CATEGORY_FILE_SHARING,
  /*
    The category below is used by sites who are used
    to test connectivity
  */
  NDPI_PROTOCOL_CATEGORY_CONNECTIVITY_CHECK,
  NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
  /*
    The category below is used for vocal assistance services.
  */
  NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT,
  
  /* Some custom categories */
  CUSTOM_CATEGORY_MINING           = 99,
  CUSTOM_CATEGORY_MALWARE          = 100,
  CUSTOM_CATEGORY_ADVERTISEMENT    = 101,
  CUSTOM_CATEGORY_BANNED_SITE      = 102,
  CUSTOM_CATEGORY_SITE_UNAVAILABLE = 103,
  CUSTOM_CATEGORY_ALLOWED_SITE     = 104,
  /*
    The category below is used to track communications made by
    security applications (e.g. sophosxl.net, spamhaus.org)
    to track malware, spam etc.
  */
  CUSTOM_CATEGORY_ANTIMALWARE      = 105,
  
  /*
    IMPORTANT

    Please keep in sync with

    static const char* categories[] = { ..}

    in ndpi_main.c
  */

  NDPI_PROTOCOL_NUM_CATEGORIES, /*
				  NOTE: Keep this as last member
				  Unused as value but useful to getting the number of elements
				  in this datastructure
				*/
  NDPI_PROTOCOL_ANY_CATEGORY /* Used to handle wildcards */
} ndpi_protocol_category_t;

typedef enum {
   ndpi_pref_direction_detect_disable = 0,
   ndpi_pref_enable_tls_block_dissection /* nDPI considers only those blocks past the certificate exchange */
} ndpi_detection_preference;

/* ntop extensions */
typedef struct ndpi_proto_defaults {
  char *protoName;
  ndpi_protocol_category_t protoCategory;
  u_int8_t isClearTextProto;
  u_int16_t *subprotocols;
  u_int32_t subprotocol_count;
  u_int16_t protoId, protoIdx;
  u_int16_t tcp_default_ports[MAX_DEFAULT_PORTS], udp_default_ports[MAX_DEFAULT_PORTS];
  ndpi_protocol_breed_t protoBreed;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
} ndpi_proto_defaults_t;

typedef struct ndpi_default_ports_tree_node {
  ndpi_proto_defaults_t *proto;
  u_int8_t customUserProto;
  u_int16_t default_port;
} ndpi_default_ports_tree_node_t;

typedef struct _ndpi_automa {
  void *ac_automa; /* Real type is AC_AUTOMATA_t */
} ndpi_automa;

typedef struct ndpi_proto {
  /*
    Note
    below we do not use ndpi_protocol_id_t as users can define their own
    custom protocols and thus the typedef could be too short in size.
  */
  u_int16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
  ndpi_protocol_category_t category;
} ndpi_protocol;

#define NDPI_PROTOCOL_NULL { NDPI_PROTOCOL_UNKNOWN , NDPI_PROTOCOL_UNKNOWN , NDPI_PROTOCOL_CATEGORY_UNSPECIFIED }

#define NUM_CUSTOM_CATEGORIES      5
#define CUSTOM_CATEGORY_LABEL_LEN 32

#ifdef NDPI_LIB_COMPILATION

/* Needed to have access to HAVE_* defines */
#ifndef _NDPI_CONFIG_H_
#include "ndpi_config.h"
#define _NDPI_CONFIG_H_
#endif

typedef enum {
  ndpi_stun_cache,
  ndpi_hangout_cache
} ndpi_lru_cache_type;

typedef struct ndpi_list_struct {
  char *value;
  struct ndpi_list_struct *next;
} ndpi_list;

struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;

  u_int32_t current_ts;
  u_int32_t ticks_per_second;
  u_int16_t num_tls_blocks_to_follow;
  u_int8_t skip_tls_blocks_until_change_cipher:1, enable_ja3_plus:1, _notused:6;
  u_int8_t tls_certificate_expire_in_x_days;
  
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void *user_data;
#endif
  char custom_category_labels[NUM_CUSTOM_CATEGORIES][CUSTOM_CATEGORY_LABEL_LEN];
  /* callback function buffer */
  struct ndpi_call_function_struct callback_buffer[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size;

  struct ndpi_call_function_struct callback_buffer_tcp_no_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_no_payload;

  struct ndpi_call_function_struct callback_buffer_tcp_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_payload;

  struct ndpi_call_function_struct callback_buffer_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_udp;

  struct ndpi_call_function_struct callback_buffer_non_tcp_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_non_tcp_udp;

  ndpi_default_ports_tree_node_t *tcpRoot, *udpRoot;

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

  u_int32_t directconnect_connection_ip_tick_timeout;

  /* subprotocol registration handler */
  struct ndpi_subprotocol_conf_struct subprotocol_conf[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

  u_int ndpi_num_supported_protocols;
  u_int ndpi_num_custom_protocols;

  int ac_automa_finalized;
  /* HTTP/DNS/HTTPS/QUIC host matching */
  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
    risky_domain_automa, tls_cert_subject_automa,
    malicious_ja3_automa, malicious_sha1_automa,
    host_risk_mask_automa, common_alpns_automa;  
  /* IMPORTANT: please update ndpi_finalize_initialization() whenever you add a new automa */

  ndpi_list *trusted_issuer_dn;
  
  void *ip_risk_mask_ptree;
  
  struct {
    ndpi_automa hostnames, hostnames_shadow;
    void *ipAddresses, *ipAddresses_shadow; /* Patricia */
    u_int8_t categories_loaded;
  } custom_categories;

  /* IP-based protocol detection */
  void *protocols_ptree;

  /* irc parameters */
  u_int32_t irc_timeout;
  /* gnutella parameters */
  u_int32_t gnutella_timeout;
  /* rstp */
  u_int32_t jabber_stun_timeout;
  u_int32_t jabber_file_transfer_timeout;
  u_int8_t ip_version_limit;

  /* NDPI_PROTOCOL_OOKLA */
  struct ndpi_lru_cache *ookla_cache;

  /* NDPI_PROTOCOL_TINC */
  struct cache *tinc_cache;

  /* NDPI_PROTOCOL_BITTORRENT */
  struct ndpi_lru_cache *bittorrent_cache;

  /* NDPI_PROTOCOL_ZOOM */
  struct ndpi_lru_cache *zoom_cache;

  /* NDPI_PROTOCOL_STUN and subprotocols */
  struct ndpi_lru_cache *stun_cache;

  /* NDPI_PROTOCOL_TLS and subprotocols */
  struct ndpi_lru_cache *tls_cert_cache;
  
  /* NDPI_PROTOCOL_MINING and subprotocols */
  struct ndpi_lru_cache *mining_cache;

  /* NDPI_PROTOCOL_MSTEAMS */
  struct ndpi_lru_cache *msteams_cache;

  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

  u_int8_t direction_detect_disable:1, /* disable internal detection of packet direction */ _pad:7;

  void (*ndpi_notify_lru_add_handler_ptr)(ndpi_lru_cache_type cache_type, u_int32_t proto, u_int32_t app_proto);

#ifdef CUSTOM_NDPI_PROTOCOLS
  #include "../../../nDPI-custom/custom_ndpi_typedefs.h"
#endif

  /* GeoIP */
  void *mmdb_city, *mmdb_as;
  u_int8_t mmdb_city_loaded, mmdb_as_loaded;

  /* Current packet */
  struct ndpi_packet_struct packet;
};

#endif /* NDPI_LIB_COMPILATION */

typedef enum {
   ndpi_cipher_safe = NDPI_CIPHER_SAFE,
   ndpi_cipher_weak = NDPI_CIPHER_WEAK,
   ndpi_cipher_insecure = NDPI_CIPHER_INSECURE
} ndpi_cipher_weakness;

#define MAX_NUM_TLS_SIGNATURE_ALGORITHMS 16

struct tls_heuristics {
  /*
    TLS heuristics for detecting browsers usage
    NOTE: expect false positives
  */
  u_int8_t is_safari_tls:1, is_firefox_tls:1, is_chrome_tls:1, notused:5;
};

/*
  NOTE
  When the struct below is modified don't forget to update
  - ndpi_flow_struct (in python/ndpi.py)
 */
struct ndpi_flow_struct {
  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_SIZE];

  /* init parameter, internal used to set up timestamp,... */
  u_int16_t guessed_protocol_id, guessed_host_protocol_id, guessed_category, guessed_header_category;
  u_int8_t l4_proto, protocol_id_already_guessed:1, host_already_guessed:1, fail_with_unknown:1,
    init_finished:1, setup_packet_direction:1, packet_direction:1, check_extra_packets:1, is_ipv6:1;
  ndpi_confidence_t confidence; /* ndpi_confidence_t */

  /*
    if ndpi_struct->direction_detect_disable == 1
    tcp sequence number connection tracking
  */
  u_int32_t next_tcp_seq_nr[2];

  /* Flow addresses (used mainly for LRU lookups in ndpi_detection_giveup())
     and ports. All in *network* byte order

     TODO
     - IPv6. Note that LRU is ipv4 only, for the time being 
   */
  u_int32_t saddr, daddr;
  u_int16_t sport, dport;
  
  // -----------------------------------------

  u_int8_t max_extra_packets_to_check;
  u_int8_t num_extra_packets_checked;
  u_int16_t num_processed_pkts; /* <= WARNING it can wrap but we do expect people to giveup earlier */

  int (*extra_packets_func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);

  u_int64_t last_packet_time_ms;

  /*
    the tcp / udp / other l4 value union
    used to reduce the number of bytes for tcp or udp protocol states
  */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;

  /* Some protocols calculate the entropy. */
  float entropy;

  /* Place textual flow info here */
  char flow_extra_info[16];

  /* General purpose field used to save mainly hostname/SNI information.
   * In details it used for: DNS and NETBIOS name, HTTP and DHCP hostname,
   * WHOIS request, TLS/QUIC server name and STUN realm.
   *
   * Please, think *very* hard before increasing its size!
   */
  char host_server_name[80];

  u_int8_t initial_binary_bytes[8], initial_binary_bytes_len;
  u_int8_t risk_checked:1, ip_risk_mask_evaluated:1, host_risk_mask_evaluated:1, _notused:5;
  ndpi_risk risk_mask; /* Stores the flow risk mask for flow peers */
  ndpi_risk risk; /* Issues found with this flow [bitmask of ndpi_risk] */

  /*
    This structure below will not not stay inside the protos
    structure below as HTTP is used by many subprotocols
    such as FaceBook, Google... so it is hard to know
    when to use it or not. Thus we leave it outside for the
    time being.
  */
  struct {
    ndpi_http_method method;
    u_int8_t request_version; /* 0=1.0 and 1=1.1. Create an enum for this? */
    u_int16_t response_status_code; /* 200, 404, etc. */
    char *url, *content_type /* response */, *request_content_type /* e.g. for POST */, *user_agent;
    char *detected_os; /* Via HTTP/QUIC User-Agent */
    char *nat_ip; /* Via HTTP X-Forwarded-For */
  } http;

  /*
     Put outside of the union to avoid issues in case the protocol
     is remapped to somethign pther than Kerberos due to a faulty
     dissector
  */
  struct {
    char *pktbuf;
    u_int16_t pktbuf_maxlen, pktbuf_currlen;
  } kerberos_buf;

  struct {
    u_int8_t num_udp_pkts, num_binding_requests;
    u_int16_t num_processed_pkts;
  } stun;

  union {
    /* the only fields useful for nDPI and ntopng */
    struct {
      u_int8_t num_queries, num_answers, reply_code, is_query;
      u_int16_t query_type, query_class, rsp_type;
      ndpi_ip_addr_t rsp_addr; /* The first address in a DNS response packet */
    } dns;

    struct {
      u_int8_t request_code;
      u_int8_t version;
    } ntp;

    struct {
      char hostname[48], domain[48], username[48];
    } kerberos;

    struct {
      char *server_names, *alpn, *tls_supported_versions, *issuerDN, *subjectDN;
      u_int32_t notBefore, notAfter;
      char ja3_client[33], ja3_server[33];
      u_int16_t server_cipher;
      u_int8_t sha1_certificate_fingerprint[20];
      u_int8_t hello_processed:1, subprotocol_detected:1, _pad:6;

#ifdef TLS_HANDLE_SIGNATURE_ALGORITMS
      /* Under #ifdef to save memory for those who do not need them */
      u_int8_t num_tls_signature_algorithms;
      u_int16_t client_signature_algorithms[MAX_NUM_TLS_SIGNATURE_ALGORITHMS];
#endif

      struct tls_heuristics browser_heuristics;

      u_int16_t ssl_version, server_names_len;

      struct {
        u_int16_t cipher_suite;
        char *esni;
      } encrypted_sni;
      ndpi_cipher_weakness server_unsafe_cipher;
    } tls_quic;

    struct {
      char client_signature[48], server_signature[48];
      char hassh_client[33], hassh_server[33];
    } ssh;

    struct {
      u_int8_t username_detected:1, username_found:1,
	password_detected:1, password_found:1,
	_pad:4;
      u_int8_t character_id;
      char username[32], password[32];
    } telnet;

    struct {
      char version[32];
    } ubntac2;

    /* In TLS.Bittorent flows there is no hash.
       Nonetheless, we must pay attention to NOT write to /read from this field
       with these flows */
    struct {
      /* Bittorrent hash */
      u_char hash[20];
    } bittorrent;

    struct {
      char fingerprint[48];
      char class_ident[48];
    } dhcp;
  } protos;

  /*** ALL protocol specific 64 bit variables here ***/

  /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u_int64_t */
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

  ndpi_protocol_category_t category;

  /* NDPI_PROTOCOL_REDIS */
  u_int8_t redis_s2d_first_char, redis_d2s_first_char;

  u_int16_t packet_counter;		      // can be 0 - 65000
  u_int16_t packet_direction_counter[2];
  u_int16_t byte_counter[2];
  /* NDPI_PROTOCOL_BITTORRENT */
  u_int8_t bittorrent_stage;		      // can be 0 - 255
  u_int8_t bt_check_performed : 1;

  /* NDPI_PROTOCOL_DIRECTCONNECT */
  u_int8_t directconnect_stage:2;	      // 0 - 1

  /* NDPI_PROTOCOL_HTTP */
  u_int8_t http_detected:1;

  /* NDPI_PROTOCOL_RTSP */
  u_int8_t rtsprdt_stage:2;

  /* NDPI_PROTOCOL_ZATTOO */
  u_int8_t zattoo_stage:3;

  /* NDPI_PROTOCOL_THUNDER */
  u_int8_t thunder_stage:2;		        // 0 - 3

  /* NDPI_PROTOCOL_FLORENSIA */
  u_int8_t florensia_stage:1;

  /* NDPI_PROTOCOL_SOCKS */
  u_int8_t socks5_stage:2, socks4_stage:2;      // 0 - 3

  /* NDPI_PROTOCOL_EDONKEY */
  u_int8_t edonkey_stage:2;	                // 0 - 3

  /* NDPI_PROTOCOL_FTP_CONTROL */
  u_int8_t ftp_control_stage:2;

  /* NDPI_PROTOCOL_RTMP */
  u_int8_t rtmp_stage:2;

  /* NDPI_PROTOCOL_STEAM */
  u_int16_t steam_stage:3, steam_stage1:3, steam_stage2:2, steam_stage3:2;

  /* NDPI_PROTOCOL_STARCRAFT */
  u_int8_t starcraft_udp_stage : 3;	// 0-7

  /* NDPI_PROTOCOL_Z3950 */
  u_int8_t z3950_stage : 2; // 0-3

  /* NDPI_PROTOCOL_OPENVPN */
  u_int8_t ovpn_session_id[8];
  u_int8_t ovpn_counter;

  /* NDPI_PROTOCOL_TINC */
  u_int8_t tinc_state;
  struct tinc_cache_entry tinc_cache_entry;
};

#define NDPI_PROTOCOL_DEFAULT_LEVEL	0

typedef struct {
  char *string_to_match, *proto_name;
  u_int16_t protocol_id;
  ndpi_protocol_category_t protocol_category;
  ndpi_protocol_breed_t protocol_breed;
  int level; /* NDPI_PROTOCOL_DEFAULT_LEVEL (0) by default */
} ndpi_protocol_match;

typedef struct {
  char *string_to_match;
  ndpi_protocol_category_t protocol_category;
} ndpi_category_match;

typedef struct {
  char *string_to_match;
  u_int16_t protocol_id;
} ndpi_tls_cert_name_match;

typedef struct {
  u_int32_t network;
  u_int8_t cidr;
  u_int16_t value;
} ndpi_network;

typedef u_int32_t ndpi_init_prefs;

typedef enum
  {
    ndpi_no_prefs            = 0,
    ndpi_dont_load_tor_hosts = 1,
    ndpi_dont_init_libgcrypt = 2,
    ndpi_enable_ja3_plus     = 4
  } ndpi_prefs;

typedef struct {
  u_int32_t protocol_id;
  ndpi_protocol_category_t protocol_category;
  ndpi_protocol_breed_t protocol_breed;
} ndpi_protocol_match_result;

typedef enum {
  ndpi_serialization_format_unknown = 0,
  ndpi_serialization_format_tlv,
  ndpi_serialization_format_json,
  ndpi_serialization_format_csv
} ndpi_serialization_format;

/* Note:
 * - up to 16 types (TLV encoding: "4 bit key type" << 4 | "4 bit value type")
 * - key supports string and uint32 (compressed to uint8/uint16) only, this is also enforced by the API */
typedef enum {
  ndpi_serialization_unknown = 0,
  ndpi_serialization_end_of_record,
  ndpi_serialization_uint8,
  ndpi_serialization_uint16,
  ndpi_serialization_uint32,
  ndpi_serialization_uint64,
  ndpi_serialization_int8,
  ndpi_serialization_int16,
  ndpi_serialization_int32,
  ndpi_serialization_int64,
  ndpi_serialization_float,
  ndpi_serialization_string,
  ndpi_serialization_start_of_block,
  ndpi_serialization_end_of_block,
  ndpi_serialization_start_of_list,
  ndpi_serialization_end_of_list
} ndpi_serialization_type;

#define NDPI_SERIALIZER_DEFAULT_HEADER_SIZE 1024
#define NDPI_SERIALIZER_DEFAULT_BUFFER_SIZE 8192
#define NDPI_SERIALIZER_DEFAULT_BUFFER_INCR 1024

#define NDPI_SERIALIZER_STATUS_COMMA     (1 << 0)
#define NDPI_SERIALIZER_STATUS_ARRAY     (1 << 1)
#define NDPI_SERIALIZER_STATUS_EOR       (1 << 2)
#define NDPI_SERIALIZER_STATUS_SOB       (1 << 3)
#define NDPI_SERIALIZER_STATUS_NOT_EMPTY (1 << 4)
#define NDPI_SERIALIZER_STATUS_LIST      (1 << 5)
#define NDPI_SERIALIZER_STATUS_SOL       (1 << 6)
#define NDPI_SERIALIZER_STATUS_HDR_DONE  (1 << 7)

typedef struct {
  u_int32_t size_used;
} ndpi_private_serializer_buffer_status;

typedef struct {
  u_int32_t flags;
  ndpi_private_serializer_buffer_status buffer;
  ndpi_private_serializer_buffer_status header;
} ndpi_private_serializer_status;

typedef struct {
  u_int32_t initial_size;
  u_int32_t size;
  u_int8_t *data;
} ndpi_private_serializer_buffer;

typedef struct {
  ndpi_private_serializer_status status;
  ndpi_private_serializer_buffer buffer;
  ndpi_private_serializer_buffer header;
  ndpi_serialization_format fmt;
  char csv_separator[2];
  u_int8_t has_snapshot;
  ndpi_private_serializer_status snapshot;
} ndpi_private_serializer;

#define ndpi_private_deserializer ndpi_private_serializer

typedef struct { char c[sizeof(ndpi_private_serializer)]; } ndpi_serializer;

#define ndpi_deserializer ndpi_serializer

typedef struct {
  char *str;
  u_int16_t str_len;
} ndpi_string;

/* **************************************** */

struct ndpi_analyze_struct {
  u_int32_t *values;
  u_int32_t min_val, max_val, sum_total, num_data_entries, next_value_insert_index;
  u_int16_t num_values_array_len /* length of the values array */;

  struct {
    u_int64_t sum_square_total;
  } stddev;
};

#define DEFAULT_SERIES_LEN  64
#define MAX_SERIES_LEN      512
#define MIN_SERIES_LEN      8

/* **************************************** */

struct ndpi_rsi_struct {
  u_int8_t empty:1, rsi_ready:1, _notused:6;
  u_int16_t num_values, next_index;
  u_int32_t *gains, *losses;
  u_int32_t last_value, total_gains, total_losses;
};

/* **************************************** */

struct ndpi_jitter_struct {
  u_int8_t empty:1, jitter_ready:1, _notused:6;
  u_int16_t num_values, next_index;
  float *observations, last_value, jitter_total;
};

/* **************************************** */

#ifndef AF_MAC
#define AF_MAC            99
#endif

typedef void (*ndpi_void_fn_t)(void *data);
typedef void (*ndpi_void_fn2_t)(ndpi_prefix_t *prefix, void *data);
typedef void (*ndpi_void_fn3_t)(ndpi_patricia_node_t *node, void *data, void *user_data);

/* **************************************** */

typedef struct ndpi_ptree ndpi_ptree_t;

/* **************************************** */

struct ndpi_hll {
  u_int8_t bits;
  size_t size;
  u_int8_t *registers;
};

/* **************************************** */

enum ndpi_bin_family {
   ndpi_bin_family8,
   ndpi_bin_family16,
   ndpi_bin_family32
};

struct ndpi_bin {
  u_int8_t is_empty;
  u_int16_t num_bins;
  enum ndpi_bin_family family;

  union {
    u_int8_t  *bins8; /* num_bins bins */
    u_int16_t *bins16; /* num_bins bins */
    u_int32_t *bins32; /* num_bins bins */
  } u;
};

/* **************************************** */

struct ndpi_str_hash_info {
  char *key;         /* Key   */
  u_int8_t key_len;
  u_int8_t value;    /* Value */
  struct ndpi_str_hash_info *next;
};

typedef struct {
  u_int32_t num_buckets, max_num_entries;
  struct ndpi_str_hash_info **buckets;
} ndpi_str_hash;


/* **************************************** */

#define HW_HISTORY_LEN               4
#define MAX_SQUARE_ERROR_ITERATIONS 64 /* MUST be < num_values_rollup (256 max) */

struct ndpi_hw_struct {
  struct {
    u_int8_t use_hw_additive_seasonal;
    double alpha, beta, gamma, ro;
    u_int16_t num_season_periods; /* num of values of a season */
  } params;

  struct {
    double sum_square_error;
    u_int8_t num_values_rollup;
  } prev_error;

  u_int32_t num_values;
  double    u, v, sum_square_error;

  /* These two values need to store the signal history */
  u_int64_t *y;
  double    *s;
};

struct ndpi_ses_struct {
  struct {
    double alpha, ro;
  } params;

  struct {
    double sum_square_error;
    u_int8_t num_values_rollup;
  } prev_error;

  u_int32_t num_values;
  double sum_square_error, last_forecast, last_value;
};

struct ndpi_des_struct {
  struct {
    double alpha, beta, ro;
  } params;

  struct {
    double sum_square_error;
    u_int8_t num_values_rollup;
  } prev_error;

  u_int32_t num_values;
  double sum_square_error, last_forecast, last_trend, last_value;
};

/* **************************************** */

/* Prototype used to define custom DGA detection function */
typedef int (*ndpi_custom_dga_predict_fctn)(const char* domain, int domain_length);

/* **************************************** */

typedef void ndpi_bitmap;
typedef void ndpi_bitmap_iterator;

/* **************************************** */

#endif /* __NDPI_TYPEDEFS_H__ */
