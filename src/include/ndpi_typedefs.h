/*
 * ndpi_typedefs.h
 *
 * Copyright (C) 2011-16 - ntop.org
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

#define BT_ANNOUNCE
#define SNAP_EXT


/* NDPI_LOG_LEVEL */
typedef enum
  {
    NDPI_LOG_ERROR,
    NDPI_LOG_TRACE,
    NDPI_LOG_DEBUG
  } ndpi_log_level_t;

/* NDPI_VISIT */
typedef enum
  {
    ndpi_preorder,
    ndpi_postorder,
    ndpi_endorder,
    ndpi_leaf
  } ndpi_VISIT;

/* NDPI_NODE */
typedef struct node_t
{
  char *key;
  struct node_t *left, *right;
} ndpi_node;

/* NDPI_MASK_SIZE */
typedef u_int32_t ndpi_ndpi_mask;

/* NDPI_PROTO_BITMASK_STRUCT */
typedef struct ndpi_protocol_bitmask_struct
{
  ndpi_ndpi_mask fds_bits[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;

/* NDPI_DEBUG_FUNCTION_PTR (cast) */
typedef void (*ndpi_debug_function_ptr) (u_int32_t protocol, void *module_struct,
					 ndpi_log_level_t log_level, const char *format, ...);


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

/* +++++++++++++++++++ LLC header (IEEE 802.2) ++++++++++++++++ */

PACK_ON
struct ndpi_snap_extension
{
  u_int16_t   oui;
  u_int8_t    oui2;
  u_int16_t   proto_ID;
} PACK_OFF;

PACK_ON
struct ndpi_llc_header
{
  u_int8_t    dsap;
  u_int8_t    ssap;
  u_int8_t    ctrl;
#ifdef SNAP_EXT
  struct ndpi_snap_extension snap;
#endif
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
  /* u_int64_t ccmp - for data encription only - check fc.flag */
} PACK_OFF;

/* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */

PACK_ON
struct ndpi_mpls_header
{
  u_int32_t label:20, exp:3, s:1, ttl:8;
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

struct ndpi_in6_addr
{
  union
  {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
  } u6_addr;  /* 128-bit IP6 address */
};

PACK_ON
struct ndpi_ipv6hdr
{
  union
  {
    struct ndpi_ip6_hdrctl
    {
      u_int32_t ip6_un1_flow;
      u_int16_t ip6_un1_plen;
      u_int8_t ip6_un1_nxt;
      u_int8_t ip6_un1_hlim;
    } ip6_un1;
    u_int8_t ip6_un2_vfc;
  } ip6_ctlun;

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
  u_int8_t ipv4_u_int8_t[4];
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  struct ndpi_in6_addr ipv6;
#endif
} ndpi_ip_addr_t;

/* ************************************************************ */
/* ******************* ********************* ****************** */
/* ************************************************************ */

#ifdef NDPI_PROTOCOL_BITTORRENT

typedef struct spinlock {
  volatile int    val;
} spinlock_t;

typedef struct atomic {
  volatile int counter;
} atomic_t;

struct hash_ip4p_node {
  struct hash_ip4p_node   *next,*prev;
  time_t                  lchg;
  u_int16_t               port,count:12,flag:4;
  u_int32_t               ip;
  // + 12 bytes for ipv6
};

struct hash_ip4p {
  struct hash_ip4p_node   *top;
  spinlock_t              lock;
  size_t                  len;
};

struct hash_ip4p_table {
  size_t                  size;
  int			  ipv6;
  spinlock_t              lock;
  atomic_t                count;
  struct hash_ip4p        tbl;
};

struct bt_announce {              // 192 bytes
  u_int32_t		hash[5];
  u_int32_t		ip[4];
  u_int32_t		time;
  u_int16_t		port;
  u_int8_t		name_len,
    name[192 - 4*10 - 2 - 1];     // 149 bytes
};
#endif

typedef enum {
  HTTP_METHOD_UNKNOWN = 0,
  HTTP_METHOD_OPTIONS,
  HTTP_METHOD_GET,
  HTTP_METHOD_HEAD,
  HTTP_METHOD_POST,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
  HTTP_METHOD_TRACE,
  HTTP_METHOD_CONNECT
} ndpi_http_method;

struct ndpi_id_struct {
  /**
     detected_protocol_bitmask:
     access this bitmask to find out whether an id has used skype or not
     if a flag is set here, it will not be resetted
     to compare this, use:
  **/
  NDPI_PROTOCOL_BITMASK detected_protocol_bitmask;
#ifdef NDPI_PROTOCOL_RTSP
  ndpi_ip_addr_t rtsp_ip_address;
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t yahoo_video_lan_timer;
#endif
#endif
  /* NDPI_PROTOCOL_IRC_MAXPORT % 2 must be 0 */
#ifdef NDPI_PROTOCOL_IRC
#define NDPI_PROTOCOL_IRC_MAXPORT 8
  u_int16_t irc_port[NDPI_PROTOCOL_IRC_MAXPORT];
  u_int32_t last_time_port_used[NDPI_PROTOCOL_IRC_MAXPORT];
  u_int32_t irc_ts;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  u_int32_t gnutella_ts;
#endif
#ifdef NDPI_PROTOCOL_BATTLEFIELD
  u_int32_t battlefield_ts;
#endif
#ifdef NDPI_PROTOCOL_THUNDER
  u_int32_t thunder_ts;
#endif
#ifdef NDPI_PROTOCOL_RTSP
  u_int32_t rtsp_timer;
#endif
#ifdef NDPI_PROTOCOL_OSCAR
  u_int32_t oscar_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_ZATTOO
  u_int32_t zattoo_ts;
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
  u_int32_t jabber_stun_or_ft_ts;
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
  u_int32_t directconnect_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
  u_int32_t soulseek_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
  u_int16_t detected_directconnect_port;
  u_int16_t detected_directconnect_udp_port;
  u_int16_t detected_directconnect_ssl_port;
#endif
#ifdef NDPI_PROTOCOL_BITTORRENT
#define NDPI_BT_PORTS 8
  u_int16_t bt_port_t[NDPI_BT_PORTS];
  u_int16_t bt_port_u[NDPI_BT_PORTS];
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
#define JABBER_MAX_STUN_PORTS 6
  u_int16_t jabber_voice_stun_port[JABBER_MAX_STUN_PORTS];
  u_int16_t jabber_file_transfer_port[2];
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  u_int16_t detected_gnutella_port;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  u_int16_t detected_gnutella_udp_port1;
  u_int16_t detected_gnutella_udp_port2;
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
  u_int16_t soulseek_listen_port;
#endif
#ifdef NDPI_PROTOCOL_IRC
  u_int8_t irc_number_of_port;
#endif
#ifdef NDPI_PROTOCOL_OSCAR
  u_int8_t oscar_ssl_session_id[33];
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
  u_int8_t jabber_voice_stun_used_ports;
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t yahoo_video_lan_dir:1;
#endif
#endif
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t yahoo_conf_logged_in:1;
  u_int32_t yahoo_voice_conf_logged_in:1;
#endif
#ifdef NDPI_PROTOCOL_RTSP
  u_int32_t rtsp_ts_set:1;
#endif
};

/* ************************************************** */

struct ndpi_flow_tcp_struct {
#ifdef NDPI_PROTOCOL_MAIL_SMTP
  u_int16_t smtp_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
  u_int16_t pop_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_QQ
  u_int16_t qq_nxt_len;
#endif
#ifdef NDPI_PROTOCOL_TDS
  u_int8_t tds_login_version;
#endif
#ifdef NDPI_PROTOCOL_IRC
  u_int8_t irc_stage;
  u_int8_t irc_port;
#endif
#ifdef NDPI_PROTOCOL_H323
  u_int8_t h323_valid_packets;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  u_int8_t gnutella_msg_id[3];
#endif
#ifdef NDPI_PROTOCOL_IRC
  u_int32_t irc_3a_counter:3;
  u_int32_t irc_stage2:5;
  u_int32_t irc_direction:2;
  u_int32_t irc_0x1000_full:1;
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
  u_int32_t soulseek_stage:2;
#endif
#ifdef NDPI_PROTOCOL_FILETOPIA
  u_int32_t filetopia_stage:2;
#endif
#ifdef NDPI_PROTOCOL_TDS
  u_int32_t tds_stage:3;
#endif
#ifdef NDPI_PROTOCOL_USENET
  u_int32_t usenet_stage:2;
#endif
#ifdef NDPI_PROTOCOL_IMESH
  u_int32_t imesh_stage:4;
#endif
#ifdef NDPI_PROTOCOL_HTTP
  u_int32_t http_setup_dir:2;
  u_int32_t http_stage:2;
  u_int32_t http_empty_line_seen:1;
  u_int32_t http_wait_for_retransmission:1;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
  u_int32_t gnutella_stage:2;		       // 0 - 2
#endif
#ifdef NDPI_CONTENT_MMS
  u_int32_t mms_stage:2;
#endif
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t yahoo_sip_comm:1;
  u_int32_t yahoo_http_proxy_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MSN
  u_int32_t msn_stage:3;
  u_int32_t msn_ssl_ft:2;
#endif
#ifdef NDPI_PROTOCOL_SSH
  u_int32_t ssh_stage:3;
#endif
#ifdef NDPI_PROTOCOL_VNC
  u_int32_t vnc_stage:2;			// 0 - 3
#endif
#ifdef NDPI_PROTOCOL_TELNET
  u_int32_t telnet_stage:2;			// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_SSL
  u_int8_t ssl_stage:2, ssl_seen_client_cert:1, ssl_seen_server_cert:1; // 0 - 5
#endif
#ifdef NDPI_PROTOCOL_POSTGRES
  u_int32_t postgres_stage:3;
#endif
#ifdef NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK
  u_int32_t ddlink_server_direction:1;
#endif
  u_int32_t seen_syn:1;
  u_int32_t seen_syn_ack:1;
  u_int32_t seen_ack:1;
#ifdef NDPI_PROTOCOL_ICECAST
  u_int32_t icecast_stage:1;
#endif
#ifdef NDPI_PROTOCOL_DOFUS
  u_int32_t dofus_stage:1;
#endif
#ifdef NDPI_PROTOCOL_FIESTA
  u_int32_t fiesta_stage:2;
#endif
#ifdef NDPI_PROTOCOL_WORLDOFWARCRAFT
  u_int32_t wow_stage:2;
#endif
#ifdef NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV
  u_int32_t veoh_tv_stage:2;
#endif
#ifdef NDPI_PROTOCOL_SHOUTCAST
  u_int32_t shoutcast_stage:2;
#endif
#ifdef NDPI_PROTOCOL_RTP
  u_int32_t rtp_special_packets_seen:1;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
  u_int32_t mail_pop_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MAIL_IMAP
  u_int32_t mail_imap_stage:3, mail_imap_starttls:2;
#endif
#ifdef NDPI_PROTOCOL_SKYPE
  u_int8_t skype_packet_id;
#endif
#ifdef NDPI_PROTOCOL_CITRIX
  u_int8_t citrix_packet_id;
#endif
#ifdef NDPI_PROTOCOL_LOTUS_NOTES
  u_int8_t lotus_notes_packet_id;
#endif
#ifdef NDPI_PROTOCOL_TEAMVIEWER
  u_int8_t teamviewer_stage;
#endif
#ifdef NDPI_PROTOCOL_ZMQ
  u_int8_t prev_zmq_pkt_len;
  u_char prev_zmq_pkt[10];
#endif
}
#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  ;

/* ************************************************** */

struct ndpi_flow_udp_struct {
#ifdef NDPI_PROTOCOL_BATTLEFIELD
  u_int32_t battlefield_msg_id;
#endif
#ifdef NDPI_PROTOCOL_SNMP
  u_int32_t snmp_msg_id;
#endif
#ifdef NDPI_PROTOCOL_BATTLEFIELD
  u_int32_t battlefield_stage:3;
#endif
#ifdef NDPI_PROTOCOL_SNMP
  u_int32_t snmp_stage:2;
#endif
#ifdef NDPI_PROTOCOL_PPSTREAM
  u_int32_t ppstream_stage:3;		  // 0 - 7
#endif
#ifdef NDPI_PROTOCOL_HALFLIFE2
  u_int32_t halflife2_stage:2;		  // 0 - 2
#endif
#ifdef NDPI_PROTOCOL_TFTP
  u_int32_t tftp_stage:1;
#endif
#ifdef NDPI_PROTOCOL_AIMINI
  u_int32_t aimini_stage:5;
#endif
#ifdef NDPI_PROTOCOL_XBOX
  u_int32_t xbox_stage:1;
#endif
#ifdef NDPI_PROTOCOL_WINDOWS_UPDATE
  u_int32_t wsus_stage:1;
#endif
#ifdef NDPI_PROTOCOL_SKYPE
  u_int8_t skype_packet_id;
#endif
#ifdef NDPI_PROTOCOL_TEAMVIEWER
  u_int8_t teamviewer_stage;
#endif
#ifdef NDPI_PROTOCOL_EAQ
  u_int8_t eaq_pkt_id;
  u_int32_t eaq_sequence;
#endif
#ifdef NDPI_PROTOCOL_RX
  u_int32_t rx_conn_epoch;
  u_int32_t rx_conn_id;
#endif
}
#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  ;

/* ************************************************** */

struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
};

struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6;
#endif
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const u_int8_t *payload;

  u_int32_t tick_timestamp;
  u_int64_t tick_timestamp_l;

  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
  u_int8_t detected_subprotocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];


#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  u_int16_t protocol_stack_info;

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct accept_line;
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
  struct ndpi_int_one_line_struct http_response;

  u_int16_t l3_packet_len;
  u_int16_t l4_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t actual_payload_len;
  u_int16_t num_retried_bytes;
  u_int16_t parsed_lines;
  u_int16_t parsed_unix_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;
  u_int8_t l4_protocol;

  u_int8_t ssl_certificate_detected:4, ssl_certificate_num_checks:4;
  u_int8_t packet_lines_parsed_complete:1,
    packet_direction:1,
    empty_line_position_set:1;
};

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

struct ndpi_call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  u_int8_t detection_feature;
};

struct ndpi_subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
};


typedef struct {
  u_int16_t port_low, port_high;
} ndpi_port_range;

typedef enum {
  NDPI_PROTOCOL_SAFE = 0,              /* Safe protocol with encryption */
  NDPI_PROTOCOL_ACCEPTABLE,            /* Ok but not encrypted */
  NDPI_PROTOCOL_FUN,                   /* Pure fun protocol */
  NDPI_PROTOCOL_UNSAFE,                /* Protocol with a safe version existing  what should be used instead */
  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, /* Be prepared to troubles */
  NDPI_PROTOCOL_UNRATED                /* No idea */
} ndpi_protocol_breed_t;

#define NUM_BREEDS (NDPI_PROTOCOL_UNRATED+1)

/* ntop extensions */
typedef struct ndpi_proto_defaults {
  char *protoName;
  u_int16_t protoId, protoIdx;
  u_int16_t master_tcp_protoId[2], master_udp_protoId[2]; /* The main protocols on which this sub-protocol sits on */
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
  u_int8_t ac_automa_finalized;
} ndpi_automa;

typedef struct ndpi_proto {
  u_int16_t master_protocol /* e.g. HTTP */, protocol /* e.g. FaceBook */;
} ndpi_protocol;

#define NDPI_PROTOCOL_NULL { NDPI_PROTOCOL_UNKNOWN , NDPI_PROTOCOL_UNKNOWN }

struct ndpi_detection_module_struct {

  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;

  u_int32_t current_ts;
  u_int32_t ticks_per_second;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void *user_data;
#endif

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

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
  u_int32_t ndpi_debug_print_line;
#endif

  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  u_int32_t directconnect_connection_ip_tick_timeout;

  /* subprotocol registration handler */
  struct ndpi_subprotocol_conf_struct subprotocol_conf[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

  u_int ndpi_num_supported_protocols;
  u_int ndpi_num_custom_protocols;

  /* HTTP/DNS/HTTPS host matching */
  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
    content_automa,                            /* Used for HTTP subprotocol_detection */
    subprotocol_automa,                        /* Used for HTTP subprotocol_detection */
    bigrams_automa, impossible_bigrams_automa; /* TOR */

  /* IP-based protocol detection */
  void *protocols_ptree;

  /* irc parameters */
  u_int32_t irc_timeout;
  /* gnutella parameters */
  u_int32_t gnutella_timeout;
  /* battlefield parameters */
  u_int32_t battlefield_timeout;
  /* thunder parameters */
  u_int32_t thunder_timeout;
  /* SoulSeek parameters */
  u_int32_t soulseek_connection_ip_tick_timeout;
  /* rtsp parameters */
  u_int32_t rtsp_connection_timeout;
  /* tvants parameters */
  u_int32_t tvants_connection_timeout;
  /* rstp */
  u_int32_t orb_rstp_ts_timeout;
  /* yahoo */
  u_int8_t yahoo_detect_http_connections;
  u_int32_t yahoo_lan_video_timeout;
  u_int32_t zattoo_connection_timeout;
  u_int32_t jabber_stun_timeout;
  u_int32_t jabber_file_transfer_timeout;
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
#define NDPI_IP_STRING_SIZE 40
  char ip_string[NDPI_IP_STRING_SIZE];
#endif
  u_int8_t ip_version_limit;
#ifdef NDPI_PROTOCOL_BITTORRENT
  struct hash_ip4p_table *bt_ht;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  struct hash_ip4p_table *bt6_ht;
#endif
#ifdef BT_ANNOUNCE
  struct bt_announce *bt_ann;
  int    bt_ann_len;
#endif
#endif

  ndpi_proto_defaults_t proto_defaults[NDPI_MAX_SUPPORTED_PROTOCOLS+NDPI_MAX_NUM_CUSTOM_PROTOCOLS];

  u_int8_t http_dont_dissect_response:1, dns_dissect_response:1,
    direction_detect_disable:1; /* disable internal detection of packet direction */
};

struct ndpi_flow_struct {
  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
#ifndef WIN32
  __attribute__ ((__packed__))
#endif
  u_int16_t protocol_stack_info;

  /* init parameter, internal used to set up timestamp,... */
  u_int16_t guessed_protocol_id, guessed_host_protocol_id;

  u_int8_t protocol_id_already_guessed:1, host_already_guessed:1, init_finished:1, setup_packet_direction:1, packet_direction:1;

  /*
     if ndpi_struct->direction_detect_disable == 1
     tcp sequence number connection tracking
  */
  u_int32_t next_tcp_seq_nr[2];

  /*
     the tcp / udp / other l4 value union
     used to reduce the number of bytes for tcp or udp protocol states
  */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;

  /*
     Pointer to src or dst
     that identifies the
     server of this connection
  */
  struct ndpi_id_struct *server_id;
  /* HTTP host or DNS query */
  u_char host_server_name[192];
  /* Via HTTP User-Agent */
  u_char detected_os[32];
  /* Via HTTP X-Forwarded-For */
  u_char nat_ip[24];
  /* Bittorrent hash */
  u_char bittorent_hash[20];

  /*
     This structure below will not not stay inside the protos
     structure below as HTTP is used by many subprotocols
     such as FaceBook, Google... so it is hard to know
     when to use it or not. Thus we leave it outside for the
     time being.
  */
  struct {
    ndpi_http_method method;
    char *url, *content_type;
  } http;

  union {

    /* the only fields useful for nDPI and ntopng */
    struct {
      u_int8_t num_queries, num_answers, reply_code;
      u_int16_t query_type, query_class, rsp_type;
    } dns;

    struct {
      u_int8_t request_code;
      u_int8_t version;
    } ntp;

    struct {
      char client_certificate[48], server_certificate[48];
    } ssl;
  } protos;

  /*** ALL protocol specific 64 bit variables here ***/

  /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u_int64_t */
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

  u_int8_t num_stun_udp_pkts;

#ifdef NDPI_PROTOCOL_REDIS
  u_int8_t redis_s2d_first_char, redis_d2s_first_char;
#endif
  u_int16_t packet_counter;		      // can be 0 - 65000
  u_int16_t packet_direction_counter[2];
  u_int16_t byte_counter[2];
#ifdef NDPI_PROTOCOL_BITTORRENT
  u_int8_t bittorrent_stage;		      // can be 0 - 255
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
  u_int32_t directconnect_stage:2;	      // 0 - 1
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t sip_yahoo_voice:1;
#endif
#endif
#ifdef NDPI_PROTOCOL_HTTP
  u_int32_t http_detected:1;
#endif
#ifdef NDPI_PROTOCOL_RTSP
  u_int32_t rtsprdt_stage:2;
  u_int32_t rtsp_control_flow:1;
#endif
#ifdef NDPI_PROTOCOL_YAHOO
  u_int32_t yahoo_detection_finished:2;
#endif
#ifdef NDPI_PROTOCOL_ZATTOO
  u_int32_t zattoo_stage:3;
#endif
#ifdef NDPI_PROTOCOL_QQ
  u_int32_t qq_stage:3;
#endif
#ifdef NDPI_PROTOCOL_THUNDER
  u_int32_t thunder_stage:2;		        // 0 - 3
#endif
#ifdef NDPI_PROTOCOL_OSCAR
  u_int32_t oscar_ssl_voice_stage:3;
  u_int32_t oscar_video_voice:1;
#endif
#ifdef NDPI_PROTOCOL_FLORENSIA
  u_int32_t florensia_stage:1;
#endif
#ifdef NDPI_PROTOCOL_SOCKS
  u_int32_t socks5_stage:2;	                // 0 - 3
  u_int32_t socks4_stage:2;	                // 0 - 3
#endif
#ifdef NDPI_PROTOCOL_EDONKEY
  u_int32_t edonkey_stage:2;	                // 0 - 3
#endif
#ifdef NDPI_PROTOCOL_FTP_CONTROL
  u_int32_t ftp_control_stage:2;
#endif
#ifdef NDPI_PROTOCOL_RTMP
  u_int32_t rtmp_stage:2;
#endif
#ifdef NDPI_PROTOCOL_PANDO
  u_int32_t pando_stage:3;
#endif
#ifdef NDPI_PROTOCOL_STEAM
  u_int32_t steam_stage:3;
  u_int32_t steam_stage1:3;			// 0 - 4
  u_int32_t steam_stage2:2;			// 0 - 2
  u_int32_t steam_stage3:2;			// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
  u_int32_t pplive_stage1:3;			// 0 - 6
  u_int32_t pplive_stage2:2;			// 0 - 2
  u_int32_t pplive_stage3:2;			// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_STARCRAFT
  u_int32_t starcraft_udp_stage : 3;	// 0-7
#endif
#ifdef NDPI_PROTOCOL_OPENVPN
  u_int8_t ovpn_session_id[8];
  u_int8_t ovpn_counter;
#endif

  /* internal structures to save functions calls */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_struct *flow;
  struct ndpi_id_struct *src;
  struct ndpi_id_struct *dst;
};

typedef struct {
  char *string_to_match, *proto_name;
  int protocol_id;
  ndpi_protocol_breed_t protocol_breed;
} ndpi_protocol_match;

typedef struct {
  u_int32_t network;
  u_int8_t cidr;
  u_int8_t value;
} ndpi_network;

#endif/* __NDPI_TYPEDEFS_H__ */
