/*
 * ndpi_main.c
 *
 * Copyright (C) 2011-23 - ntop.org
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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_UNKNOWN

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ahocorasick.h"
#include "libcache.h"

#ifdef USE_HOST_LIBGCRYPT
#include <gcrypt.h>
#else
#include <gcrypt_light.h>
#endif

#include <time.h>

#ifndef WIN32
#include <unistd.h>
#endif

#ifndef TH_FIN
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20
#endif

#if defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__
#include <sys/endian.h>
#endif

#include "ndpi_content_match.c.inc"
#include "ndpi_dga_match.c.inc"
#include "inc_generated/ndpi_azure_match.c.inc"
#include "inc_generated/ndpi_tor_match.c.inc"
#include "inc_generated/ndpi_whatsapp_match.c.inc"
#include "inc_generated/ndpi_amazon_aws_match.c.inc"
#include "inc_generated/ndpi_ethereum_match.c.inc"
#include "inc_generated/ndpi_zoom_match.c.inc"
#include "inc_generated/ndpi_cachefly_match.c.inc"
#include "inc_generated/ndpi_cloudflare_match.c.inc"
#include "inc_generated/ndpi_ms_office365_match.c.inc"
#include "inc_generated/ndpi_ms_onedrive_match.c.inc"
#include "inc_generated/ndpi_ms_outlook_match.c.inc"
#include "inc_generated/ndpi_ms_skype_teams_match.c.inc"
#include "inc_generated/ndpi_gambling_match.c.inc"
#include "inc_generated/ndpi_google_match.c.inc"
#include "inc_generated/ndpi_google_cloud_match.c.inc"
#include "inc_generated/ndpi_crawlers_match.c.inc"
#include "inc_generated/ndpi_icloud_private_relay_match.c.inc"
#include "inc_generated/ndpi_protonvpn_in_match.c.inc"
#include "inc_generated/ndpi_protonvpn_out_match.c.inc"
#include "inc_generated/ndpi_mullvad_match.c.inc"
#include "inc_generated/ndpi_asn_telegram.c.inc"
#include "inc_generated/ndpi_asn_apple.c.inc"
#include "inc_generated/ndpi_asn_twitter.c.inc"
#include "inc_generated/ndpi_asn_netflix.c.inc"
#include "inc_generated/ndpi_asn_webex.c.inc"
#include "inc_generated/ndpi_asn_teamviewer.c.inc"
#include "inc_generated/ndpi_asn_facebook.c.inc"
#include "inc_generated/ndpi_asn_tencent.c.inc"
#include "inc_generated/ndpi_asn_opendns.c.inc"
#include "inc_generated/ndpi_asn_dropbox.c.inc"
#include "inc_generated/ndpi_asn_starcraft.c.inc"
#include "inc_generated/ndpi_asn_ubuntuone.c.inc"
#include "inc_generated/ndpi_asn_twitch.c.inc"
#include "inc_generated/ndpi_asn_hotspotshield.c.inc"
#include "inc_generated/ndpi_asn_github.c.inc"
#include "inc_generated/ndpi_asn_steam.c.inc"
#include "inc_generated/ndpi_asn_bloomberg.c.inc"
#include "inc_generated/ndpi_asn_citrix.c.inc"
#include "inc_generated/ndpi_asn_edgecast.c.inc"
#include "inc_generated/ndpi_asn_goto.c.inc"
#include "inc_generated/ndpi_asn_riotgames.c.inc"
#include "inc_generated/ndpi_asn_threema.c.inc"
#include "inc_generated/ndpi_asn_alibaba.c.inc"
#include "inc_generated/ndpi_asn_avast.c.inc"
#include "inc_generated/ndpi_asn_discord.c.inc"
#include "inc_generated/ndpi_asn_line.c.inc"
#include "inc_generated/ndpi_asn_vk.c.inc"
#include "inc_generated/ndpi_asn_yandex.c.inc"
#include "inc_generated/ndpi_asn_yandex_cloud.c.inc"
#include "inc_generated/ndpi_asn_disney_plus.c.inc"
#include "inc_generated/ndpi_asn_hulu.c.inc"
#include "inc_generated/ndpi_asn_epicgames.c.inc"
#include "inc_generated/ndpi_asn_nvidia.c.inc"
#include "inc_generated/ndpi_asn_roblox.c.inc"

/* Third party libraries */
#include "third_party/include/ndpi_patricia.h"
#include "third_party/include/ndpi_md5.h"

#ifdef HAVE_NBPF
#include "nbpf.h"
#endif

static int _ndpi_debug_callbacks = 0;

/* #define DGA_DEBUG 1 */
/* #define MATCH_DEBUG 1 */

u_int ndpi_verbose_dga_detection = 0;

/* ****************************************** */

static void *(*_ndpi_flow_malloc)(size_t size);
static void (*_ndpi_flow_free)(void *ptr);

/* ****************************************** */

static ndpi_risk_info ndpi_known_risks[] = {
  { NDPI_NO_RISK,                               NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_NO_ACCOUNTABILITY  },
  { NDPI_URL_POSSIBLE_XSS,                      NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_URL_POSSIBLE_SQL_INJECTION,            NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_URL_POSSIBLE_RCE_INJECTION,            NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_BINARY_APPLICATION_TRANSFER,           NDPI_RISK_SEVERE, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,   NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_SELFSIGNED_CERTIFICATE,            NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_OBSOLETE_VERSION,                  NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_WEAK_CIPHER,                       NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_EXPIRED,               NDPI_RISK_HIGH,   CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_MISMATCH,              NDPI_RISK_HIGH,   CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_USER_AGENT,            NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_NUMERIC_IP_HOST,                       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_URL,                   NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_HEADER,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_NOT_CARRYING_HTTPS,                NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SUSPICIOUS_DGA_DOMAIN,                 NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MALFORMED_PACKET,                      NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER, NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER, NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_SMB_INSECURE_VERSION,                  NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_SUSPICIOUS_ESNI_USAGE,             NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_UNSAFE_PROTOCOL,                       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_DNS_SUSPICIOUS_TRAFFIC,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_MISSING_SNI,                       NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_SUSPICIOUS_CONTENT,               NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_RISKY_ASN,                             NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_RISKY_DOMAIN,                          NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_MALICIOUS_JA3,                         NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MALICIOUS_SHA1_CERTIFICATE,            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_DESKTOP_OR_FILE_SHARING_SESSION,       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TLS_UNCOMMON_ALPN,                     NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERT_VALIDITY_TOO_LONG,            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_SERVER_ACCOUNTABLE },
  { NDPI_TLS_SUSPICIOUS_EXTENSION,              NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TLS_FATAL_ALERT,                       NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_SUSPICIOUS_ENTROPY,                    NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_CLEAR_TEXT_CREDENTIALS,                NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_DNS_LARGE_PACKET,                      NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_DNS_FRAGMENTED,                        NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_INVALID_CHARACTERS,                    NDPI_RISK_HIGH,   CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_POSSIBLE_EXPLOIT,                      NDPI_RISK_SEVERE, CLIENT_HIGH_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,       NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_PUNYCODE_IDN,                          NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_ERROR_CODE_DETECTED,                   NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_HTTP_CRAWLER_BOT,                      NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_ANONYMOUS_SUBSCRIBER,                  NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_UNIDIRECTIONAL_TRAFFIC,                NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_HTTP_OBSOLETE_SERVER,                  NDPI_RISK_MEDIUM, CLIENT_LOW_RISK_PERCENTAGE,  NDPI_SERVER_ACCOUNTABLE },
  { NDPI_PERIODIC_FLOW,                         NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_MINOR_ISSUES,                          NDPI_RISK_LOW,    CLIENT_LOW_RISK_PERCENTAGE,  NDPI_BOTH_ACCOUNTABLE   },
  { NDPI_TCP_ISSUES,                            NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },
  { NDPI_FULLY_ENCRYPTED,                       NDPI_RISK_MEDIUM, CLIENT_FAIR_RISK_PERCENTAGE, NDPI_CLIENT_ACCOUNTABLE },

  /* Leave this as last member */
  { NDPI_MAX_RISK,                              NDPI_RISK_LOW,    CLIENT_FAIR_RISK_PERCENTAGE, NDPI_NO_ACCOUNTABILITY   }
};
#if !defined(NDPI_CFFI_PREPROCESSING) && defined(__linux__)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(ndpi_known_risks) / sizeof(ndpi_risk_info) == NDPI_MAX_RISK + 1,
               "Invalid risks length. Do you need to update 'ndpi_known_risks' array?");
#endif
#endif


/* ****************************************** */

extern void ndpi_unset_risk(struct ndpi_detection_module_struct *ndpi_str,
			    struct ndpi_flow_struct *flow, ndpi_risk_enum r);
extern u_int32_t make_mining_key(struct ndpi_flow_struct *flow);
extern u_int32_t make_bittorrent_host_key(struct ndpi_flow_struct *flow, int client, int offset);
extern u_int32_t make_bittorrent_peers_key(struct ndpi_flow_struct *flow);
extern int stun_search_into_zoom_cache(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern void ookla_add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
                               struct ndpi_flow_struct *flow);
extern int ookla_search_into_cache(struct ndpi_detection_module_struct *ndpi_struct,
                                   struct ndpi_flow_struct *flow);

/* Forward */
static int addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
			  ndpi_port_range *range, ndpi_proto_defaults_t *def,
			  u_int8_t customUserProto, ndpi_default_ports_tree_node_t **root,
			  const char *_func, int _line);
static int removeDefaultPort(ndpi_port_range *range, ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root);

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet);
static void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				     u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
				     ndpi_confidence_t confidence);

static int ndpi_callback_init(struct ndpi_detection_module_struct *ndpi_str);
static void ndpi_enabled_callbacks_init(struct ndpi_detection_module_struct *ndpi_str,
	  const NDPI_PROTOCOL_BITMASK *dbm, int count_only);

/* ****************************************** */

ndpi_custom_dga_predict_fctn ndpi_dga_function = NULL;

/* ****************************************** */

static inline u_int8_t flow_is_proto(struct ndpi_flow_struct *flow, u_int16_t p) {
  return((flow->detected_protocol_stack[0] == p) || (flow->detected_protocol_stack[1] == p));
}

/* ****************************************** */

void *ndpi_flow_malloc(size_t size) {
  return(_ndpi_flow_malloc ? _ndpi_flow_malloc(size) : ndpi_malloc(size));
}

/* ****************************************** */

void ndpi_flow_free(void *ptr) {
  if(_ndpi_flow_free)
    _ndpi_flow_free(ptr);
  else
    ndpi_free_flow((struct ndpi_flow_struct *) ptr);
}

/* ****************************************** */

/* Opaque structure defined here */
struct ndpi_ptree
{
  ndpi_patricia_tree_t *v4;
  ndpi_patricia_tree_t *v6;
};

/* *********************************************************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void) {
  return(sizeof(struct ndpi_flow_struct));
}

/* *********************************************************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_tcp_struct(void) {
  return(sizeof(struct ndpi_flow_tcp_struct));
}

/* *********************************************************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_udp_struct(void) {
  return(sizeof(struct ndpi_flow_udp_struct));
}

/* *********************************************************************************** */

char *ndpi_get_proto_by_id(struct ndpi_detection_module_struct *ndpi_str, u_int id) {
  if(!ndpi_str)
    return NULL;
  return((id >= ndpi_str->ndpi_num_supported_protocols) ? NULL : ndpi_str->proto_defaults[id].protoName);
}

/* *********************************************************************************** */

u_int16_t ndpi_get_proto_by_name(struct ndpi_detection_module_struct *ndpi_str, const char *name) {
  u_int16_t i, num = ndpi_get_num_supported_protocols(ndpi_str);
  char *p;

  if(!ndpi_str || !name)
    return(NDPI_PROTOCOL_UNKNOWN);

  for(i = 0; i < num; i++) {
    p = ndpi_get_proto_by_id(ndpi_str, i);
    if(p && strcasecmp(p, name) == 0)
      return(i);
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ************************************************************************************* */
/* ************************************************************************************* */

void ndpi_add_user_proto_id_mapping(struct ndpi_detection_module_struct *ndpi_str,
				      u_int16_t ndpi_proto_id, u_int16_t user_proto_id) {
  if(ndpi_proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS)
    return; /* Nothing to map */

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  NDPI_LOG_DBG2(ndpi_str, "[DEBUG] *** %u (>= %u)-> %u\n",
	 ndpi_proto_id, NDPI_MAX_SUPPORTED_PROTOCOLS,
	 user_proto_id);
#endif

  ndpi_str->ndpi_to_user_proto_id[ndpi_proto_id-NDPI_MAX_SUPPORTED_PROTOCOLS] = user_proto_id;
}

/* ************************************************************************************* */

/* Map a custom user protocol into an internal nDPI protocol id */
u_int16_t ndpi_map_user_proto_id_to_ndpi_id(struct ndpi_detection_module_struct *ndpi_str,
					    u_int16_t user_proto_id) {

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
#if 0 /* Too much verbose... */
  NDPI_LOG_DBG2(ndpi_str, "[DEBUG] ***** %s(%u)\n", __FUNCTION__, user_proto_id);
#endif
#endif

  if(!ndpi_str)
    return(0);

  if(user_proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS)
    return(user_proto_id);
  else {
    u_int idx, idx_max = ndpi_str->ndpi_num_supported_protocols - NDPI_MAX_SUPPORTED_PROTOCOLS;

    /* TODO: improve it and remove linear scan */
    for(idx = 0; idx < idx_max; idx++) {
      if(ndpi_str->ndpi_to_user_proto_id[idx] == 0)
	break;
      else if(ndpi_str->ndpi_to_user_proto_id[idx] == user_proto_id) {
	return(idx + NDPI_MAX_SUPPORTED_PROTOCOLS);
      }
    }
  }

  return(0);
}

/* ************************************************************************************* */

/* Map an internal nDPI protocol id to a custom user protocol */
u_int16_t ndpi_map_ndpi_id_to_user_proto_id(struct ndpi_detection_module_struct *ndpi_str,
						   u_int16_t ndpi_proto_id) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
#if 0 /* Too much verbose... */
  NDPI_LOG_DBG2(ndpi_str, "[DEBUG] ***** %s(%u)\n", __FUNCTION__, ndpi_proto_id);
#endif
#endif

  if(!ndpi_str)
    return(0);

  if(ndpi_proto_id < NDPI_MAX_SUPPORTED_PROTOCOLS)
    return(ndpi_proto_id);
  else if(ndpi_proto_id < ndpi_str->ndpi_num_supported_protocols) {
    u_int id = ndpi_proto_id - NDPI_MAX_SUPPORTED_PROTOCOLS;

    if(id < ndpi_str->ndpi_num_supported_protocols)
      return(ndpi_str->ndpi_to_user_proto_id[id]);
  }

  return(0);
}

/* ************************************************************************************* */
/* ************************************************************************************* */

#ifdef CODE_UNUSED
ndpi_port_range *ndpi_build_default_ports_range(ndpi_port_range *ports, u_int16_t portA_low, u_int16_t portA_high,
                                                u_int16_t portB_low, u_int16_t portB_high, u_int16_t portC_low,
                                                u_int16_t portC_high, u_int16_t portD_low, u_int16_t portD_high,
                                                u_int16_t portE_low, u_int16_t portE_high) {
  int i = 0;

  ports[i].port_low = portA_low, ports[i].port_high = portA_high;
  i++;
  ports[i].port_low = portB_low, ports[i].port_high = portB_high;
  i++;
  ports[i].port_low = portC_low, ports[i].port_high = portC_high;
  i++;
  ports[i].port_low = portD_low, ports[i].port_high = portD_high;
  i++;
  ports[i].port_low = portE_low, ports[i].port_high = portE_high;

  return(ports);
}
#endif

/* *********************************************************************************** */

ndpi_port_range *ndpi_build_default_ports(ndpi_port_range *ports, u_int16_t portA, u_int16_t portB, u_int16_t portC,
                                          u_int16_t portD, u_int16_t portE) {
  int i = 0;

  ports[i].port_low = portA, ports[i].port_high = portA;
  i++;
  ports[i].port_low = portB, ports[i].port_high = portB;
  i++;
  ports[i].port_low = portC, ports[i].port_high = portC;
  i++;
  ports[i].port_low = portD, ports[i].port_high = portD;
  i++;
  ports[i].port_low = portE, ports[i].port_high = portE;

  return(ports);
}

/* ********************************************************************************** */

void ndpi_set_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
			  u_int16_t protoId, ndpi_protocol_breed_t breed) {
  if(!ndpi_is_valid_protoId(protoId))
    return;
  else if(ndpi_str)
    ndpi_str->proto_defaults[protoId].protoBreed = breed;
}

/* ********************************************************************************** */

void ndpi_set_proto_category(struct ndpi_detection_module_struct *ndpi_str, u_int16_t protoId,
                             ndpi_protocol_category_t protoCategory) {
  if(!ndpi_is_valid_protoId(protoId))
    return;
  else if(ndpi_str)
    ndpi_str->proto_defaults[protoId].protoCategory = protoCategory;
}

/* ********************************************************************************** */

/*
  There are some (master) protocols that are informative, meaning that it shows
  what is the subprotocol about, but also that the subprotocol isn't a real protocol.

  Example:
  - DNS is informative as if we see a DNS request for www.facebook.com, the
  returned protocol is DNS.Facebook, but Facebook isn't a real subprotocol but
  rather it indicates a query for Facebook and not Facebook traffic.
  - HTTP/SSL are NOT informative as SSL.Facebook (likely) means that this is
  SSL (HTTPS) traffic containg Facebook traffic.
*/
u_int8_t ndpi_is_subprotocol_informative(struct ndpi_detection_module_struct *ndpi_str, u_int16_t protoId) {
  if(!ndpi_is_valid_protoId(protoId))
    return(0);

  switch(protoId) {
    /* All dissectors that have calls to ndpi_match_host_subprotocol() */
  case NDPI_PROTOCOL_DNS:
    return(1);
    break;

  default:
    return(0);
  }
}
/* ********************************************************************************** */

void ndpi_exclude_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                           u_int16_t protocol_id, const char *_file, const char *_func, int _line) {
  if(ndpi_is_valid_protoId(protocol_id)) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    if(ndpi_str && ndpi_str->ndpi_log_level >= NDPI_LOG_DEBUG && ndpi_str->ndpi_debug_printf != NULL) {
      (*(ndpi_str->ndpi_debug_printf))(protocol_id, ndpi_str, NDPI_LOG_DEBUG, _file, _func, _line, "exclude %s\n",
				       ndpi_get_proto_name(ndpi_str, protocol_id));
    }
#endif
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, protocol_id);
  }
}

/* ********************************************************************************** */

static int is_proto_enabled(struct ndpi_detection_module_struct *ndpi_str, int protoId)
{
  /* Custom protocols are always enabled */
  if(protoId >= NDPI_MAX_SUPPORTED_PROTOCOLS)
    return 1;
  if(NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi_str->detection_bitmask, protoId) == 0)
    return 0;
  return 1;
}

/* ********************************************************************************** */

void ndpi_set_proto_subprotocols(struct ndpi_detection_module_struct *ndpi_str, int protoId, ...)
{
  va_list ap;
  int current_arg = protoId;
  size_t i = 0;

  if(!is_proto_enabled(ndpi_str, protoId)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip subprotocols for %d (disabled)\n", protoId);
      return;
  }

  va_start(ap, protoId);
  while (current_arg != NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS) {
    if(!is_proto_enabled(ndpi_str, current_arg)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip subprotocol %d (disabled)\n", protoId);
    } else {
      ndpi_str->proto_defaults[protoId].subprotocol_count++;
    }
    current_arg = va_arg(ap, int);
  }
  va_end(ap);

  ndpi_str->proto_defaults[protoId].subprotocols = NULL;

  /* The last protocol is not a subprotocol. */
  ndpi_str->proto_defaults[protoId].subprotocol_count--;
  /* No subprotocol was set before NDPI_NO_MORE_SUBPROTOCOLS. */
  if(ndpi_str->proto_defaults[protoId].subprotocol_count == 0) {
      return;
    }

  ndpi_str->proto_defaults[protoId].subprotocols =
    ndpi_malloc(sizeof(protoId) * ndpi_str->proto_defaults[protoId].subprotocol_count);
  if(!ndpi_str->proto_defaults[protoId].subprotocols) {
    ndpi_str->proto_defaults[protoId].subprotocol_count = 0;
    return;
  }

  va_start(ap, protoId);
  current_arg = va_arg(ap, int);

  while (current_arg != NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS) {
    if(is_proto_enabled(ndpi_str, current_arg)) {
      ndpi_str->proto_defaults[protoId].subprotocols[i++] = current_arg;
    }
    current_arg = va_arg(ap, int);
  }

  va_end(ap);
}

/* ********************************************************************************** */

void ndpi_set_proto_defaults(struct ndpi_detection_module_struct *ndpi_str,
			     u_int8_t is_cleartext, u_int8_t is_app_protocol,
			     ndpi_protocol_breed_t breed,
			     u_int16_t protoId, char *protoName,
			     ndpi_protocol_category_t protoCategory,
			     ndpi_port_range *tcpDefPorts,
			     ndpi_port_range *udpDefPorts) {
  char *name;
  int j;

  if(!ndpi_is_valid_protoId(protoId)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: INTERNAL ERROR\n", protoName, protoId);
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "[NDPI] %s/protoId=%d: already initialized. Ignoring it\n", protoName, protoId);
    return;
  }

  name = ndpi_strdup(protoName);
  if(!name) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] %s/protoId=%d: mem allocation error\n", protoName, protoId);
    return;
  }

  if(ndpi_str->proto_defaults[protoId].protoName)
    ndpi_free(ndpi_str->proto_defaults[protoId].protoName);

  ndpi_str->proto_defaults[protoId].isClearTextProto = is_cleartext;
  /*
    is_appprotocol=1 means that this is only an application protocol layered
    on top of a network protocol. Example WhatsApp=1, TLS=0
  */
  ndpi_str->proto_defaults[protoId].isAppProtocol = is_app_protocol;
  ndpi_str->proto_defaults[protoId].protoName = name;
  ndpi_str->proto_defaults[protoId].protoCategory = protoCategory;
  ndpi_str->proto_defaults[protoId].protoId = protoId;
  ndpi_str->proto_defaults[protoId].protoBreed = breed;
  ndpi_str->proto_defaults[protoId].subprotocols = NULL;
  ndpi_str->proto_defaults[protoId].subprotocol_count = 0;

  if(!is_proto_enabled(ndpi_str, protoId)) {
    NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip default ports for %s/protoId=%d: disabled\n", protoName, protoId);
    return;
  }

  for(j = 0; j < MAX_DEFAULT_PORTS; j++) {
    if(udpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &udpDefPorts[j], &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->udpRoot,
		     __FUNCTION__, __LINE__);

    if(tcpDefPorts[j].port_low != 0)
      addDefaultPort(ndpi_str, &tcpDefPorts[j], &ndpi_str->proto_defaults[protoId], 0, &ndpi_str->tcpRoot,
		     __FUNCTION__, __LINE__);

    /* No port range, just the lower port */
    ndpi_str->proto_defaults[protoId].tcp_default_ports[j] = tcpDefPorts[j].port_low;
    ndpi_str->proto_defaults[protoId].udp_default_ports[j] = udpDefPorts[j].port_low;
  }
}

/* ******************************************************************** */

static int ndpi_default_ports_tree_node_t_cmp(const void *a, const void *b) {
  ndpi_default_ports_tree_node_t *fa = (ndpi_default_ports_tree_node_t *) a;
  ndpi_default_ports_tree_node_t *fb = (ndpi_default_ports_tree_node_t *) b;

  //printf("[NDPI] %s(%d, %d)\n", __FUNCTION__, fa->default_port, fb->default_port);

  return((fa->default_port == fb->default_port) ? 0 : ((fa->default_port < fb->default_port) ? -1 : 1));
}

/* ******************************************************************** */

static int addDefaultPort(struct ndpi_detection_module_struct *ndpi_str,
			  ndpi_port_range *range,
			  ndpi_proto_defaults_t *def,
			  u_int8_t customUserProto,
			  ndpi_default_ports_tree_node_t **root,
			  const char *_func,
			  int _line) {
  u_int32_t port;

  for(port = range->port_low; port <= range->port_high; port++) {
    ndpi_default_ports_tree_node_t *node =
      (ndpi_default_ports_tree_node_t *) ndpi_malloc(sizeof(ndpi_default_ports_tree_node_t));
    ndpi_default_ports_tree_node_t *ret;

    if(!node) {
      NDPI_LOG_ERR(ndpi_str, "%s:%d not enough memory\n", _func, _line);
      break;
    }

    node->proto = def, node->default_port = port, node->customUserProto = customUserProto;
    ret = (ndpi_default_ports_tree_node_t *) ndpi_tsearch(node,
							  (void *) root,
							  ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret == NULL) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d error searching for port %u\n", _func, _line, port);
      ndpi_free(node);
      break;
    }

    if(ret != node) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] %s:%d found duplicate for port %u: overwriting it with new value\n",
		   _func, _line, port);

      ret->proto = def;
      ndpi_free(node);
      return(-1); /* Duplicates found */
    }
  }

  return(0);
}

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastructures while using them
*/
static int removeDefaultPort(ndpi_port_range *range, ndpi_proto_defaults_t *def,
			     ndpi_default_ports_tree_node_t **root) {
  ndpi_default_ports_tree_node_t node;
  u_int16_t port;

  for(port = range->port_low; port <= range->port_high; port++) {
    ndpi_default_ports_tree_node_t *ret;

    node.proto = def, node.default_port = port;

    ret = (ndpi_default_ports_tree_node_t *)
      ndpi_tdelete(&node, (void *) root,
		   ndpi_default_ports_tree_node_t_cmp); /* Add it to the tree */

    if(ret != NULL) {
      ndpi_free((ndpi_default_ports_tree_node_t *) ret);
      return(0);
    }
  }

  return(-1);
}

/* ****************************************************** */

/*
  This is a function used to see if we need to
  add a trailer $ in case the string is complete
  or is a string that can be matched in the
  middle of a domain name

  Example:
  microsoft.com    ->     microsoft.com$
  apple.           ->     apple.
*/
static u_int8_t ndpi_is_middle_string_char(char c) {
  switch(c) {
  case '.':
  case '-':
    return(1);

  default:
    return(0);
  }
}

/*******************************************************/

static const u_int8_t ndpi_domain_level_automat[4][4]= {
  /* symbol,'.','-',inc */
  { 2,1,2,0 }, // start state
  { 2,0,0,0 }, // first char is '.'; disable .. or .-
  { 2,3,2,0 }, // part of domain name
  { 2,0,0,1 }  // next level domain name; disable .. or .-
};

/*
 * domain level
 *  a. = 1
 * .a. = 1
 * a.b = 2
 */

static u_int8_t ndpi_domain_level(const char *name) {
  u_int8_t level = 1, state = 0;
  char c;
  while((c = *name++) != '\0') {
    c = c == '-' ? 2 : (c == '.' ? 1:0);
    level += ndpi_domain_level_automat[state][3];
    state  = ndpi_domain_level_automat[state][(u_int8_t)c];
    if(!state) break;
  }
  return state >= 2 ? level:0;
}

/* ****************************************************** */

static int ndpi_string_to_automa(struct ndpi_detection_module_struct *ndpi_str,
				 AC_AUTOMATA_t *ac_automa, const char *value,
                                 u_int16_t protocol_id, ndpi_protocol_category_t category,
				 ndpi_protocol_breed_t breed, u_int8_t level,
                                 u_int8_t add_ends_with) {
  AC_PATTERN_t ac_pattern;
  AC_ERROR_t rc;
  u_int len;
  char *value_dup = NULL;

  if(!ndpi_is_valid_protoId(protocol_id)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] protoId=%d: INTERNAL ERROR\n", protocol_id);
    return(-1);
  }

  if((ac_automa == NULL) || (value == NULL) || !*value)
    return(-2);

  value_dup = ndpi_strdup(value);
  if(!value_dup)
    return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));

  len = strlen(value);

  ac_pattern.astring      = value_dup;
  ac_pattern.length       = len;
  ac_pattern.rep.number   = protocol_id;
  ac_pattern.rep.category = (u_int16_t) category;
  ac_pattern.rep.breed    = (u_int16_t) breed;
  ac_pattern.rep.level    = level ? level : ndpi_domain_level(value);
  ac_pattern.rep.at_end   = add_ends_with && !ndpi_is_middle_string_char(value[len-1]); /* len != 0 */
  ac_pattern.rep.dot      = memchr(value,'.',len) != NULL;

#ifdef MATCH_DEBUG
  printf("Adding to %s %lx [%s%s][protocol_id: %u][category: %u][breed: %u][level: %u]\n",
	 ac_automa->name,(unsigned long int)ac_automa,
	 ac_pattern.astring,ac_pattern.rep.at_end? "$":"", protocol_id, category, breed,ac_pattern.rep.level);
#endif

  rc = ac_automata_add(ac_automa, &ac_pattern);

  if(rc != ACERR_SUCCESS) {
    ndpi_free(value_dup);

    if(rc != ACERR_DUPLICATE_PATTERN)
      return (-2);
  }

  return(0);
}

/* ****************************************************** */

static int ndpi_add_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					 char *value, int protocol_id,
                                         ndpi_protocol_category_t category,
					 ndpi_protocol_breed_t breed, u_int8_t level) {
#ifndef NDPI_ENABLE_DEBUG_MESSAGES
  NDPI_LOG_DBG2(ndpi_str, "[NDPI] Adding [%s][%d]\n", value, protocol_id);
#endif

  return ndpi_string_to_automa(ndpi_str, (AC_AUTOMATA_t *)ndpi_str->host_automa.ac_automa,
			       value, protocol_id, category, breed, level, 1);

}

/* ****************************************************** */

/*
  NOTE

  This function must be called with a semaphore set, this in order to avoid
  changing the datastructures while using them
*/
static int ndpi_remove_host_url_subprotocol(struct ndpi_detection_module_struct *ndpi_str, char *value, int protocol_id) {
  NDPI_LOG_ERR(ndpi_str, "[NDPI] Missing implementation for proto %s/%d\n", value, protocol_id);
  return(-1);
}

/* ******************************************************************** */

int ndpi_init_empty_app_protocol(ndpi_protocol_match const * const hostname_list,
                                 ndpi_protocol_match * const empty_app_protocol) {
  if (hostname_list[0].proto_name == NULL)
    return 1;

  memset(empty_app_protocol, 0, sizeof(*empty_app_protocol));
  empty_app_protocol->proto_name = hostname_list[0].proto_name;
  empty_app_protocol->protocol_id = hostname_list[0].protocol_id;
  empty_app_protocol->protocol_category = hostname_list[0].protocol_category;
  empty_app_protocol->protocol_breed = hostname_list[0].protocol_breed;
  empty_app_protocol->level = hostname_list[0].level;

  return 0;
}

int ndpi_init_app_protocol(struct ndpi_detection_module_struct *ndpi_str,
                           ndpi_protocol_match const * const match) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  if(ndpi_str->proto_defaults[match->protocol_id].protoName == NULL) {
    ndpi_str->proto_defaults[match->protocol_id].protoName = ndpi_strdup(match->proto_name);
    if(!ndpi_str->proto_defaults[match->protocol_id].protoName)
      return 1;
    ndpi_str->proto_defaults[match->protocol_id].isAppProtocol = 1;
    ndpi_str->proto_defaults[match->protocol_id].protoId = match->protocol_id;
    ndpi_str->proto_defaults[match->protocol_id].protoCategory = match->protocol_category;
    ndpi_str->proto_defaults[match->protocol_id].protoBreed = match->protocol_breed;

    ndpi_set_proto_defaults(ndpi_str,
                ndpi_str->proto_defaults[match->protocol_id].isClearTextProto,
                ndpi_str->proto_defaults[match->protocol_id].isAppProtocol,
                ndpi_str->proto_defaults[match->protocol_id].protoBreed,
                ndpi_str->proto_defaults[match->protocol_id].protoId,
                ndpi_str->proto_defaults[match->protocol_id].protoName,
                ndpi_str->proto_defaults[match->protocol_id].protoCategory,
                ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  }

  if(!is_proto_enabled(ndpi_str, match->protocol_id)) {
    NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip protocol match for %s/protoId=%d: disabled\n",
         match->string_to_match, match->protocol_id);
    return 1;
  }

  return 0;
}

/* ******************************************************************** */

void ndpi_init_protocol_match(struct ndpi_detection_module_struct *ndpi_str,
                              ndpi_protocol_match const * const match) {
	if (ndpi_init_app_protocol(ndpi_str, match) == 0) {
		ndpi_add_host_url_subprotocol(ndpi_str, match->string_to_match,
				match->protocol_id, match->protocol_category,
				match->protocol_breed, match->level);
	}
}

/* ******************************************************************** */

/* Self check function to be called only for testing purposes */
void ndpi_self_check_host_match(FILE *error_out) {
  u_int32_t i, j;

  for(i = 0; host_match[i].string_to_match != NULL; i++) {
    for(j = 0; host_match[j].string_to_match != NULL; j++) {
      if((i != j) && (strcmp(host_match[i].string_to_match, host_match[j].string_to_match) == 0)) {
        if (error_out != NULL) {
          fprintf(error_out,
                  "[NDPI] INTERNAL ERROR duplicate string detected '%s' [id: %u, id %u]\n",
                  host_match[i].string_to_match, i, j);
          fprintf(error_out, "\nPlease fix host_match[] in ndpi_content_match.c.inc\n");
        }
        abort();
      }
    }
  }
}

/* ******************************************************************** */

#define XGRAMS_C 26
static int ndpi_xgrams_inited = 0;
static unsigned int bigrams_bitmap[(XGRAMS_C*XGRAMS_C+31)/32];
static unsigned int impossible_bigrams_bitmap[(XGRAMS_C*XGRAMS_C+31)/32];
static unsigned int trigrams_bitmap[(XGRAMS_C*XGRAMS_C*XGRAMS_C+31)/32];


static void ndpi_xgrams_init(struct ndpi_detection_module_struct *ndpi_str,
                             unsigned int *dst, size_t dn,
                             const char **src, size_t sn,
                             unsigned int l)
{
  unsigned int i,j,c;
  for(i=0;i < sn && src[i]; i++) {
    for(j=0,c=0; j < l; j++) {
      unsigned char a = (unsigned char)src[i][j];
      if(a < 'a' || a > 'z') {
        NDPI_LOG_ERR(ndpi_str,
                     "[NDPI] INTERNAL ERROR ndpi_xgrams_init %u: c%u %c\n",
                     i,j,a);
        abort();
      }
      c *= XGRAMS_C;
      c += a - 'a';
    }
    if(src[i][l]) {
      NDPI_LOG_ERR(ndpi_str,
                   "[NDPI] INTERNAL ERROR ndpi_xgrams_init %u: c[%d] != 0\n",
                   i,l);
      abort();
    }
    if((c >> 3) >= dn) abort();
    dst[c >> 5] |= 1u << (c & 0x1f);
  }
}

/* ******************************************************************** */

static void init_string_based_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  for(i = 0; host_match[i].string_to_match != NULL; i++)
    ndpi_init_protocol_match(ndpi_str, &host_match[i]);

  if(ndpi_str->enable_load_gambling_list)
    for(i = 0; ndpi_protocol_gambling_hostname_list[i].string_to_match != NULL; i++)
      ndpi_init_protocol_match(ndpi_str, &ndpi_protocol_gambling_hostname_list[i]);
  else {
    ndpi_protocol_match gambling_match;
    if (ndpi_init_empty_app_protocol(ndpi_protocol_gambling_hostname_list, &gambling_match) != 0 ||
        ndpi_init_app_protocol(ndpi_str, &gambling_match) != 0) {
      NDPI_LOG_ERR(ndpi_str,
        "[NDPI] INTERNAL ERROR could not initialize empty gambling app protocol\n");
    }
  }

  /* ************************ */

  for(i = 0; tls_certificate_match[i].string_to_match != NULL; i++) {

#if 0
    printf("%s() %s / %u\n", __FUNCTION__,
	   tls_certificate_match[i].string_to_match,
	   tls_certificate_match[i].protocol_id);
#endif

    if(!is_proto_enabled(ndpi_str, tls_certificate_match[i].protocol_id)) {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Skip tls cert match for %s/protoId=%d: disabled\n",
		   tls_certificate_match[i].string_to_match, tls_certificate_match[i].protocol_id);
      continue;
    }
    /* Note: string_to_match is not malloc'ed here as ac_automata_release is
     * called with free_pattern = 0 */
    ndpi_add_string_value_to_automa(ndpi_str->tls_cert_subject_automa.ac_automa,
				    tls_certificate_match[i].string_to_match,
                                    tls_certificate_match[i].protocol_id);
  }

  /* ************************ */

  ndpi_enable_loaded_categories(ndpi_str);

  if(!ndpi_xgrams_inited) {
    ndpi_xgrams_inited = 1;
    ndpi_xgrams_init(ndpi_str,bigrams_bitmap,sizeof(bigrams_bitmap),
		     ndpi_en_bigrams,sizeof(ndpi_en_bigrams)/sizeof(ndpi_en_bigrams[0]), 2);

    ndpi_xgrams_init(ndpi_str,impossible_bigrams_bitmap,sizeof(impossible_bigrams_bitmap),
		     ndpi_en_impossible_bigrams,sizeof(ndpi_en_impossible_bigrams)/sizeof(ndpi_en_impossible_bigrams[0]), 2);
    ndpi_xgrams_init(ndpi_str,trigrams_bitmap,sizeof(trigrams_bitmap),
		     ndpi_en_trigrams,sizeof(ndpi_en_trigrams)/sizeof(ndpi_en_trigrams[0]), 3);
  }
}

/* ******************************************************************** */

int ndpi_set_detection_preferences(struct ndpi_detection_module_struct *ndpi_str, ndpi_detection_preference pref,
                                   int value) {
  if(!ndpi_str)
    return -1;

  switch(pref) {
  case ndpi_pref_direction_detect_disable:
    ndpi_str->direction_detect_disable = (u_int8_t) value;
    break;

  case ndpi_pref_enable_tls_block_dissection:
    /*
      If this option is enabled only the TLS Application data blocks past the
      certificate negotiation are considered
    */
    ndpi_str->num_tls_blocks_to_follow = NDPI_MAX_NUM_TLS_APPL_BLOCKS;
    ndpi_str->skip_tls_blocks_until_change_cipher = 1;
    break;

  case ndpi_pref_max_packets_to_process:
    if(value > 0xFFFF) {
      return(-1);
    }
    ndpi_str->max_packets_to_process = value;
    break;

  default:
    return(-1);
  }

  return(0);
}

/* ******************************************************************** */

static void ndpi_validate_protocol_initialization(struct ndpi_detection_module_struct *ndpi_str) {
  u_int i;

  for(i = 0; i < ndpi_str->ndpi_num_supported_protocols; i++) {
    if(ndpi_str->proto_defaults[i].protoName == NULL) {
      NDPI_LOG_ERR(ndpi_str,
		   "[NDPI] INTERNAL ERROR missing protoName initialization for [protoId=%d]: recovering\n", i);
    } else {
      if((i != NDPI_PROTOCOL_UNKNOWN) &&
	 (ndpi_str->proto_defaults[i].protoCategory == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
	NDPI_LOG_ERR(ndpi_str,
		     "[NDPI] INTERNAL ERROR missing category [protoId=%d/%s] initialization: recovering\n", i,
		     ndpi_str->proto_defaults[i].protoName ? ndpi_str->proto_defaults[i].protoName : "???");
      }
    }
  }
}

/* ******************************************************************** */

/* This function is used to map protocol name and default ports and it MUST
   be updated whenever a new protocol is added to NDPI.

   Do NOT add web services (NDPI_SERVICE_xxx) here.
*/
static void ndpi_init_protocol_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];

  /* Reset all settings */
  memset(ndpi_str->proto_defaults, 0, sizeof(ndpi_str->proto_defaults));

  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNRATED, NDPI_PROTOCOL_UNKNOWN,
			  "Unknown", NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTP_CONTROL,
			  "FTP_CONTROL", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 21, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_FTP_DATA,
			  "FTP_DATA", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 20, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_POP,
			  "POP3", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 110, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_POPS,
			  "POPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 995, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MAIL_SMTP,
			  "SMTP", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 25, 587, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_SMTPS,
			  "SMTPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 465, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MAIL_IMAP,
			  "IMAP", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 143, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MAIL_IMAPS,
			  "IMAPS", NDPI_PROTOCOL_CATEGORY_MAIL,
			  ndpi_build_default_ports(ports_a, 993, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNS,
			  "DNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 53, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 53, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_DNS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_DNS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IPP,
			  "IPP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IMO,
			  "IMO", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP,
			  "HTTP", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 80, 0 /* ntop */, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP,
			      NDPI_PROTOCOL_CROSSFIRE, NDPI_PROTOCOL_SOAP,
			      NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_GNUTELLA,
			      NDPI_PROTOCOL_MAPLESTORY, NDPI_PROTOCOL_ZATTOO, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			      NDPI_PROTOCOL_IRC,
			      NDPI_PROTOCOL_IPP,
			      NDPI_PROTOCOL_MPEGDASH,
			      NDPI_PROTOCOL_RTSP,
			      NDPI_PROTOCOL_APACHE_THRIFT,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MDNS,
			  "MDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5353, 5354, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_MDNS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_MDNS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NTP,
			  "NTP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 123, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETBIOS,
			  "NetBIOS", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 139, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 137, 138, 139, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NFS,
			  "NFS", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 2049, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2049, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSDP,
			  "SSDP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BGP,
			  "BGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 179, 2605, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNMP,
			  "SNMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 161, 162, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XDMCP,
			  "XDMCP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 177, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 177, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_DANGEROUS, NDPI_PROTOCOL_SMBV1,
			  "SMBv1", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SYSLOG,
			  "Syslog", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 514, 601, 6514, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 514, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCP,
			  "DHCP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 67, 68, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_POSTGRES,
			  "PostgreSQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 5432, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MYSQL,
			  "MySQL", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 3306, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NATS,
			  "Nats", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AMONG_US,
			  "AmongUs", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 22023, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_NTOP,
			  "ntop", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VMWARE,
			  "VMware", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 903, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 902, 903, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_KONTIKI,
			  "Kontiki", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_GNUTELLA,
			  "Gnutella", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_EDONKEY,
			  "eDonkey", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BITTORRENT,
			  "BitTorrent", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 51413, 53646, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6771, 51413, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE_TEAMS,
			  "Skype_Teams", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GOOGLE,
                          "Google", NDPI_PROTOCOL_CATEGORY_WEB,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKYPE_TEAMS_CALL,
			  "Skype_TeamsCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TIKTOK,
			  "TikTok", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEREDO,
			  "Teredo", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WECHAT,
			  "WeChat", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEMCACHED,
			  "Memcached", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 11211, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 11211, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMBV23,
			  "SMBv23", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 445, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_MINING,
			  "Mining", CUSTOM_CATEGORY_MINING,
			  ndpi_build_default_ports(ports_a, 30303, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NEST_LOG_SINK,
			  "NestLogSink", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 11095, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MODBUS,
			  "Modbus", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 502, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_CALL,
			  "WhatsAppCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DATASAVER,
			  "DataSaver", NDPI_PROTOCOL_CATEGORY_WEB /* dummy */,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SIGNAL,
			  "Signal", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DOH_DOT,
			  "DoH_DoT", NDPI_PROTOCOL_CATEGORY_NETWORK /* dummy */,
			  ndpi_build_default_ports(ports_a, 853, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 784, 853, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_REDDIT,
			  "Reddit", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WIREGUARD,
			  "WireGuard", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 51820, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PPSTREAM,
			  "PPStream", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_XBOX,
			  "Xbox", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PLAYSTATION,
			  "Playstation", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_QQ,
			  "QQ", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RTSP,
			  "RTSP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 554, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 554, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ICECAST,
			  "IceCast", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CPHA,
			  "CPHA", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 8116, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ZATTOO,
			  "Zattoo", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DISCORD,
			  "Discord", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TVUPLAYER,
			  "TVUplayer", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PLURALSIGHT,
			  "Pluralsight", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OCSP,
			  "OCSP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VXLAN,
			  "VXLAN", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4789, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_IRC,
			  "IRC", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 194, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 194, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MERAKI_CLOUD,
			  "MerakiCloud", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_JABBER,
			  "Jabber", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DISNEYPLUS,
			  "DisneyPlus", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_VRRP,
			  "VRRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STEAM,
			  "Steam", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HALFLIFE2,
			  "HalfLife2", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLDOFWARCRAFT,
			  "WorldOfWarcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_HOTSPOT_SHIELD,
			  "HotspotShield", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_TELNET,
			  "Telnet", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 23, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_STUN,
			  "STUN", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3478, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_IPSEC,
			  "IPSec", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 500, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 500, 4500, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_GRE,
			  "GRE", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMP,
			  "ICMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IGMP,
			  "IGMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_EGP,
			  "EGP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_PGM,
			  "PGM", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_SCTP,
			  "SCTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_OSPF,
			  "OSPF", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 2604, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_IP_IN_IP,
			  "IP_in_IP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTP,
			  "RTP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RDP,
			  "RDP", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 3389, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3389, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_VNC,
			  "VNC", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 5900, 5901, 5800, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TUMBLR,
			  "Tumblr", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZOOM,
			  "Zoom", NDPI_PROTOCOL_CATEGORY_VIDEO,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP_FILES,
			  "WhatsAppFiles", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHATSAPP,
			  "WhatsApp", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_TLS,
			  "TLS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 443, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_TLS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_TLS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_DTLS,
			  "DTLS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_DTLS,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_DTLS can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SSH,
			  "SSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 22, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_USENET,
			  "Usenet", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MGCP,
			  "MGCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IAX,
			  "IAX", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 4569, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4569, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AFP,
			  "AFP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 548, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 548, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HULU,
			  "Hulu", NDPI_PROTOCOL_CATEGORY_STREAMING,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CHECKMK,
			  "CHECKMK", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 6556, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIP,
			  "SIP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 5060, 5061, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5060, 5061, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TRUPHONE,
			  "TruPhone", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_ICMPV6,
			  "ICMPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DHCPV6,
			  "DHCPV6", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ARMAGETRON,
			  "Armagetron", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CROSSFIRE,
			  "Crossfire", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_DOFUS,
			  "Dofus", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GUILDWARS,
			  "Guildwars", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMAZON_ALEXA,
			  "AmazonAlexa", NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KERBEROS,
			  "Kerberos", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 88, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 88, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LDAP,
			  "LDAP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 389, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 389, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MAPLESTORY,
			  "MapleStory", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MSSQL_TDS,
			  "MsSQL-TDS", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 1433, 1434, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PPTP,
			  "PPTP", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WARCRAFT3,
			  "Warcraft3", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_WORLD_OF_KUNG_FU,
			  "WorldOfKungFu", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RPC,
			  "RPC", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 135, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NETFLOW,
			  "NetFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2055, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SFLOW,
			  "sFlow", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6343, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_CONNECT,
			  "HTTP_Connect", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8080, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP_CONNECT,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP_CONNECT can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HTTP_PROXY,
			  "HTTP_Proxy", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8080, 3128, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_HTTP_PROXY,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_HTTP_PROXY can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CITRIX,
			  "Citrix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 1494, 2598, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBEX,
			  "Webex", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RADIUS,
			  "Radius", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 1812, 1813, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1812, 1813, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TEAMVIEWER,
			  "TeamViewer", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 5938, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5938, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LOTUS_NOTES,
			  "LotusNotes", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 1352, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SAP,
			  "SAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 3201, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP,
			  "GTP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 2152, 2123, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_C,
			  "GTP_C", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_U,
			  "GTP_U", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GTP_PRIME,
			  "GTP_PRIME", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HSRP,
			  "HSRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1985, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WSD,
			  "WSD", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 3702, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ETHERNET_IP,
			  "EthernetIP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 44818, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TELEGRAM,
			  "Telegram", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_QUIC,
			  "QUIC", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 443, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_subprotocols(ndpi_str, NDPI_PROTOCOL_QUIC,
			      NDPI_PROTOCOL_MATCHED_BY_CONTENT,
			      NDPI_PROTOCOL_NO_MORE_SUBPROTOCOLS); /* NDPI_PROTOCOL_QUIC can have (content-matched) subprotocols */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DIAMETER,
			  "Diameter", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 3868, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APPLE_PUSH,
			  "ApplePush", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DROPBOX,
			  "Dropbox", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 17500, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SPOTIFY,
			  "Spotify", NDPI_PROTOCOL_CATEGORY_MUSIC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MESSENGER,
			  "Messenger", NDPI_PROTOCOL_CATEGORY_CHAT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LISP,
			  "LISP", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 4342, 4341, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EAQ,
			  "EAQ", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 6000, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KAKAOTALK_VOICE,
			  "KakaoTalk_Voice", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGTS,
			  "MPEG_TS", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  /* http://en.wikipedia.org/wiki/Link-local_Multicast_Name_Resolution */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LLMNR,
			  "LLMNR", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 5355, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5355, 0, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TOCA_BOCA,
			  "TocaBoca", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5055, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_H323,
			  "H323", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 1719, 1720, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1719, 1720, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OPENVPN,
			  "OpenVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 1194, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 1194, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NOE,
			  "NOE", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CISCOVPN,
			  "CiscoVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 10000, 8008, 8009, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 10000, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TEAMSPEAK,
			  "TeamSpeak", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, NDPI_PROTOCOL_TOR,
			  "Tor", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SKINNY,
			  "CiscoSkinny", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 2000, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTCP,
			  "RTCP", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RSYNC,
			  "RSYNC", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 873, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ORACLE,
			  "Oracle", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 1521, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CORBA,
			  "Corba", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_UBUNTUONE,
			  "UbuntuONE", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WHOIS_DAS,
			  "Whois-DAS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 43, 4343, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));    /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SD_RTN,
			  "SD-RTN", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOCKS,
			  "SOCKS", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 1080, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 1080, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TFTP,
			  "TFTP", NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),   /* TCP */
			  ndpi_build_default_ports(ports_b, 69, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RTMP,
			  "RTMP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 1935, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_PINTEREST,
			  "Pinterest", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MEGACO,
			  "Megaco", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),     /* TCP */
			  ndpi_build_default_ports(ports_b, 2944, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_REDIS,
			  "Redis", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 6379, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZMQ,
			  "ZeroMQ", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VHUA,
			  "VHUA", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 58267, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_STARCRAFT,
			  "Starcraft", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 1119, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 1119, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_UBNTAC2,
			  "UBNTAC2", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 10001, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_VIBER,
			  "Viber", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 7985, 5242, 5243, 4244, 0),     /* TCP */
			  ndpi_build_default_ports(ports_b, 7985, 7987, 5242, 5243, 4244)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_COAP,
			  "COAP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),        /* TCP */
			  ndpi_build_default_ports(ports_b, 5683, 5684, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MQTT,
			  "MQTT", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 1883, 8883, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));      /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOMEIP,
			  "SOMEIP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 30491, 30501, 0, 0, 0),      /* TCP */
			  ndpi_build_default_ports(ports_b, 30491, 30501, 30490, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_RX,
			  "RX", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_GIT,
			  "Git", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 9418, 0, 0, 0, 0), /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0));   /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DRDA,
			  "DRDA", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HANGOUT_DUO,
			  "GoogleHangoutDuo", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BJNP,
			  "BJNP", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 8612, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SMPP,
			  "SMPP", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_OOKLA,
			  "Ookla", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AMQP,
			  "AMQP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNSCRYPT,
			  "DNScrypt", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TINC,
			  "TINC", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 655, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 655, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FIX,
			  "FIX", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_NINTENDO,
			  "Nintendo", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CSGO,
			  "CSGO", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_AJP,
			  "AJP", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 8009, 8010, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TARGUS_GETDATA,
			  "TargusDataspeed", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 5001, 5201, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5001, 5201, 0, 0, 0) /* UDP */); /* Missing dissector: port based only */
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_AMAZON_VIDEO,
			  "AmazonVideo", NDPI_PROTOCOL_CATEGORY_CLOUD,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_DNP3,
			  "DNP3", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 20000, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IEC60870,
			  "IEC60870", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
			  ndpi_build_default_ports(ports_a, 2404, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BLOOMBERG,
			  "Bloomberg", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CAPWAP,
			  "CAPWAP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 5246, 5247, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ZABBIX,
			  "Zabbix", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 10050, 10051, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_S7COMM,
			  "s7comm", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 102, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_MSTEAMS,
			  "Teams", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_WEBSOCKET,
			  "WebSocket", NDPI_PROTOCOL_CATEGORY_WEB,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ANYDESK,
			  "AnyDesk", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOAP,
			  "SOAP", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MONGODB,
			  "MongoDB", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 27017, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APPLE_SIRI,
			  "AppleSiri", NDPI_PROTOCOL_CATEGORY_VIRTUAL_ASSISTANT,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SNAPCHAT_CALL,
			  "SnapchatCall", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_HPVIRTGRP,
			  "HP_VIRTGRP", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GENSHIN_IMPACT,
			  "GenshinImpact", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 22102, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ACTIVISION,
			  "Activision", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FORTICLIENT,
			  "FortiClient", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 8013, 8014, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_Z3950,
			  "Z3950", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 210, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_LIKEE,
			  "Likee", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_GITLAB,
			  "GitLab", NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_AVAST_SECUREDNS,
			  "AVASTSecureDNS", NDPI_PROTOCOL_CATEGORY_NETWORK,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0),  /* TCP */
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0)); /* UDP */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CASSANDRA,
			  "Cassandra", NDPI_PROTOCOL_CATEGORY_DATABASE,
			  ndpi_build_default_ports(ports_a, 9042, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_FACEBOOK_VOIP,
			  "FacebookVoip", NDPI_PROTOCOL_CATEGORY_VOIP,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SIGNAL_VOIP,
			  "SignalVoip", NDPI_PROTOCOL_CATEGORY_VOIP,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MICROSOFT_AZURE,
			  "Azure", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_GOOGLE_CLOUD,
			  "GoogleCloud", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TENCENT,
                          "Tencent", NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RAKNET,
                          "RakNet", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0), /* TCP */
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_XIAOMI,
                          "Xiaomi", NDPI_PROTOCOL_CATEGORY_WEB,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_EDGECAST,
                          "Edgecast", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_CACHEFLY,
                          "Cachefly", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SOFTETHER,
                          "Softether", NDPI_PROTOCOL_CATEGORY_VPN,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_MPEGDASH,
                          "MpegDash", NDPI_PROTOCOL_CATEGORY_MEDIA,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  /*
     Note: removed RSH port 514 as TCP/514 is often used for syslog and RSH is as such on;y
     if both source and destination ports are 514. So we removed the default for RSH and used with syslog
  */
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_RSH,
                          "RSH", NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_IP_PIM,
                          "IP_PIM", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_COLLECTD,
                          "collectd", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 25826, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_I3D,
                          "i3D", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_RIOTGAMES,
                          "RiotGames", NDPI_PROTOCOL_CATEGORY_GAME,
                           ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                           ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ULTRASURF,
                          "UltraSurf", NDPI_PROTOCOL_CATEGORY_VPN,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_THREEMA,
                          "Threema", NDPI_PROTOCOL_CATEGORY_CHAT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ALICLOUD,
                          "AliCloud", NDPI_PROTOCOL_CATEGORY_CLOUD,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_AVAST,
                          "AVAST", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_TIVOCONNECT,
                          "TiVoConnect", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 2190, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 2190, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_KISMET,
                          "Kismet", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_FASTCGI,
                          "FastCGI", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_UNSAFE, NDPI_PROTOCOL_FTPS,
                          "FTPS", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_NATPMP,
                          "NAT-PMP", NDPI_PROTOCOL_CATEGORY_NETWORK,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 5351, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SYNCTHING,
                          "Syncthing", NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_CRYNET,
                          "CryNetwork", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LINE,
                         "Line", NDPI_PROTOCOL_CATEGORY_CHAT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_LINE_CALL,
                         "LineCall", NDPI_PROTOCOL_CATEGORY_VOIP,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MUNIN,
                          "Munin", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 4949, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_ELASTICSEARCH,
                          "Elasticsearch", NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TUYA_LP,
                          "TuyaLP", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 6667, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TPLINK_SHP,
                          "TPLINK_SHP", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
                          ndpi_build_default_ports(ports_a, 9999, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 9999, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_TAILSCALE,
			  "Tailscale", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 41641, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_SOURCE_ENGINE,
                          "Source_Engine", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 27015, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_SAFE, NDPI_PROTOCOL_BACNET,
                          "BACnet", NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 47808, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_OICQ,
                          "OICQ", NDPI_PROTOCOL_CATEGORY_CHAT,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 8000, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_HOTS,
                          "Heroes_of_the_Storm", NDPI_PROTOCOL_CATEGORY_GAME,
                          ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
                          ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SRTP,
			  "SRTP", NDPI_PROTOCOL_CATEGORY_MEDIA,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_BITCOIN,
			  "BITCOIN", NDPI_PROTOCOL_CATEGORY_CRYPTO_CURRENCY,
			  ndpi_build_default_ports(ports_a, 8333, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_PROTONVPN,
			  "ProtonVPN", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_APACHE_THRIFT,
			  "Thrift", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_FUN, NDPI_PROTOCOL_ROBLOX,
			  "Roblox", NDPI_PROTOCOL_CATEGORY_GAME,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 1 /* cleartext */, 0 /* nw proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_SERVICE_LOCATION,
			  "Service_Location_Protocol", NDPI_PROTOCOL_CATEGORY_RPC,
			  ndpi_build_default_ports(ports_a, 427, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 427, 0, 0, 0, 0) /* UDP */);
  ndpi_set_proto_defaults(ndpi_str, 0 /* encrypted */, 1 /* app proto */, NDPI_PROTOCOL_ACCEPTABLE, NDPI_PROTOCOL_MULLVAD,
			  "Mullvad", NDPI_PROTOCOL_CATEGORY_VPN,
			  ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			  ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);


#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main.c"
#endif

  /* calling function for host and content matched protocols */
  init_string_based_protocols(ndpi_str);

  ndpi_validate_protocol_initialization(ndpi_str);
}

/* ****************************************************** */

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_protocols.c"
#endif

/* ****************************************************** */

#define MATCH_DEBUG_INFO(fmt, ...) if(txt->option & AC_FEATURE_DEBUG) printf(fmt, ##__VA_ARGS__)

/* No static because it is used by fuzzer, too */
int ac_domain_match_handler(AC_MATCH_t *m, AC_TEXT_t *txt, AC_REP_t *match) {
  AC_PATTERN_t *pattern = m->patterns;
  int i,start,end = m->position;

  for(i=0; i < m->match_num && i < 32; i++,pattern++) {
    /*
     * See ac_automata_exact_match()
     * The bit is set if the pattern exactly matches AND
     * the length of the pattern is longer than that of the previous one.
     * Skip shorter (less precise) templates.
     */
    if(!(m->match_map & (1u << i)))
      continue;
    start = end - pattern->length;

    MATCH_DEBUG_INFO("[NDPI] Searching: [to search: %.*s/%u][pattern: %s%.*s%s/%u l:%u] %d-%d\n",
		     txt->length, txt->astring,(unsigned int) txt->length,
		     m->patterns[0].rep.from_start ? "^":"",
		     (unsigned int) pattern->length, pattern->astring,
		     m->patterns[0].rep.at_end ? "$":"", (unsigned int) pattern->length,m->patterns[0].rep.level,
		     start,end);

    if(start == 0 && end == txt->length) {
      *match = pattern->rep; txt->match.last = pattern;
      MATCH_DEBUG_INFO("[NDPI] Searching: Found exact match. Proto %d \n",pattern->rep.number);
      return 1;
    }
    /* pattern is DOMAIN.NAME and string x.DOMAIN.NAME ? */
    if(start > 1 && !ndpi_is_middle_string_char(pattern->astring[0]) && pattern->rep.dot) {
      /*
	The patch below allows in case of pattern ws.amazon.com
	to avoid matching aws.amazon.com whereas a.ws.amazon.com
	has to match
      */
      if(ndpi_is_middle_string_char(txt->astring[start-1])) {
	if(!txt->match.last || txt->match.last->rep.level < pattern->rep.level) {
	  txt->match.last = pattern; *match = pattern->rep;
	  MATCH_DEBUG_INFO("[NDPI] Searching: Found domain match. Proto %d \n",pattern->rep.number);
	}
      }
      continue;
    }

    if(!txt->match.last || txt->match.last->rep.level < pattern->rep.level) {
      txt->match.last = pattern; *match = pattern->rep;
      MATCH_DEBUG_INFO("[NDPI] Searching: matched. Proto %d \n",pattern->rep.number);
    }
  }
  return 0;
}

/* ******************************************************************** */

u_int16_t ndpi_patricia_get_maxbits(ndpi_patricia_tree_t *tree) {
  if(!tree)
    return 0;
  return(tree->maxbits);
}

/* ******************************************************************** */

void ndpi_patricia_get_stats(ndpi_patricia_tree_t *tree, struct ndpi_patricia_tree_stats *stats) {
  if(tree) {
    stats->n_search = tree->stats.n_search;
    stats->n_found = tree->stats.n_found;
  } else {
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

/* ******************************************************************** */

int ndpi_get_patricia_stats(struct ndpi_detection_module_struct *ndpi_struct,
			    ptree_type ptree_type,
			    struct ndpi_patricia_tree_stats *stats) {
  if(!ndpi_struct || !stats)
    return -1;

  switch(ptree_type) {
  case NDPI_PTREE_RISK_MASK:
    ndpi_patricia_get_stats(ndpi_struct->ip_risk_mask_ptree, stats);
    return 0;

  case NDPI_PTREE_RISK:
    ndpi_patricia_get_stats(ndpi_struct->ip_risk_ptree, stats);
    return 0;

  case NDPI_PTREE_PROTOCOLS:
    ndpi_patricia_get_stats(ndpi_struct->protocols_ptree, stats);
    return 0;

  default:
    return -1;
  }
}

/* ****************************************************** */

int ndpi_fill_prefix_v4(ndpi_prefix_t *p, const struct in_addr *a, int b, int mb) {
  memset(p, 0, sizeof(ndpi_prefix_t));

  if(b < 0 || b > mb)
    return(-1);

  p->add.sin.s_addr = a->s_addr, p->family = AF_INET, p->bitlen = b, p->ref_count = 0;

  return(0);
}

/* ******************************************* */

int ndpi_fill_prefix_v6(ndpi_prefix_t *prefix, const struct in6_addr *addr, int bits, int maxbits) {
  memset(prefix, 0, sizeof(ndpi_prefix_t));

  if(bits < 0 || bits > maxbits)
    return -1;

  memcpy(&prefix->add.sin6, addr, (maxbits + 7) / 8);
  prefix->family = AF_INET6, prefix->bitlen = bits, prefix->ref_count = 0;

  return 0;
}

/* ******************************************* */

int ndpi_fill_prefix_mac(ndpi_prefix_t *prefix, u_int8_t *mac, int bits, int maxbits) {
  if(bits < 0 || bits > maxbits)
    return -1;

  memcpy(prefix->add.mac, mac, 6);
  prefix->family = AF_MAC, prefix->bitlen = bits, prefix->ref_count = 0;

  return 0;
}

/* ******************************************* */

ndpi_prefix_t *ndpi_patricia_get_node_prefix(ndpi_patricia_node_t *node) {
  return(node->prefix);
}

/* ******************************************* */

u_int16_t ndpi_patricia_get_node_bits(ndpi_patricia_node_t *node) {
  return(node->bit);
}

/* ******************************************* */

void ndpi_patricia_set_node_data(ndpi_patricia_node_t *node, void *data) {
  node->data = data;
}

/* ******************************************* */

void *ndpi_patricia_get_node_data(ndpi_patricia_node_t *node) {
  return(node->data);
}

/* ******************************************* */

void ndpi_patricia_set_node_u64(ndpi_patricia_node_t *node, u_int64_t value) {
  node->value.u.uv64 = value;
}

/* ******************************************* */

u_int64_t ndpi_patricia_get_node_u64(ndpi_patricia_node_t *node) {
  return(node->value.u.uv64);
}

/* ******************************************* */

u_int8_t ndpi_is_public_ipv4(u_int32_t a /* host byte order */) {
  if(   ((a & 0xFF000000) == 0x0A000000 /* 10.0.0.0/8 */)
	|| ((a & 0xFFF00000) == 0xAC100000 /* 172.16.0.0/12 */)
	|| ((a & 0xFFFF0000) == 0xC0A80000 /* 192.168.0.0/16 */)
	|| ((a & 0xFF000000) == 0x7F000000 /* 127.0.0.0/8 */)
	|| ((a & 0xF0000000) == 0xE0000000 /* 224.0.0.0/4 */)
	)
    return(0);
  else
    return(1);
}

/* ******************************************* */

u_int16_t ndpi_network_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
                                   struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str || !ndpi_str->protocols_ptree)
    return(NDPI_PROTOCOL_UNKNOWN);

  if(ndpi_str->ndpi_num_custom_protocols == 0) {
    /*
      In case we don't have defined any custom protocol we check the ptree
      only in case of public IP addresses as in ndpi_content_match.c.inc
      we only have public IP addresses. Instead with custom protocols, users
      might have defined private protocols hence we should not skip
      the checks below
    */

    if(ndpi_is_public_ipv4(ntohl(pin->s_addr)) == 0)
      return(NDPI_PROTOCOL_UNKNOWN); /* Non public IP */
  }

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

  return(node ? node->value.u.uv16[0].user_value : NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************* */

u_int16_t ndpi_network_port_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					struct in_addr *pin /* network byte order */,
					u_int16_t port /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!ndpi_str || !ndpi_str->protocols_ptree)
    return(NDPI_PROTOCOL_UNKNOWN);

  if(ndpi_str->ndpi_num_custom_protocols == 0) {
    /*
      In case we don't have defined any custom protocol we check the ptree
      only in case of public IP addresses as in ndpi_content_match.c.inc
      we only have public IP addresses. Instead with custom protocols, users
      might have defined private protocols hence we should not skip
      the checks below
    */

    if(ndpi_is_public_ipv4(ntohl(pin->s_addr)) == 0)
      return(NDPI_PROTOCOL_UNKNOWN); /* Non public IP */
  }

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->protocols_ptree, &prefix);

  if(node) {
    int i;
    struct patricia_uv16_list *item;

    for(i=0; i<UV16_MAX_USER_VALUES; i++) {
      if((node->value.u.uv16[i].additional_user_value == 0)
	 || (node->value.u.uv16[i].additional_user_value == port))
	return(node->value.u.uv16[i].user_value);
    }

    /*
      If we're here it means that we don't have
      enough room for our custom value so we need
      to check the custom_user_data pointer.
    */
    item = (struct patricia_uv16_list*)node->data;

    while(item != NULL) {
      if(item->value.additional_user_value == port)
	return(item->value.user_value);
      else
	item = item->next;
    }
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************* */

ndpi_risk_enum ndpi_network_risk_ptree_match(struct ndpi_detection_module_struct *ndpi_str,
					     struct in_addr *pin /* network byte order */) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  /* Make sure all in network byte order otherwise compares wont work */
  ndpi_fill_prefix_v4(&prefix, pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->ip_risk_ptree)->maxbits);
  node = ndpi_patricia_search_best(ndpi_str->ip_risk_ptree, &prefix);

  if(node)
    return((ndpi_risk_enum)node->value.u.uv16[0].user_value);

  return(NDPI_NO_RISK);
}

/* ******************************************* */

static ndpi_patricia_node_t* add_to_ptree(ndpi_patricia_tree_t *tree, int family, void *addr, int bits) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  ndpi_fill_prefix_v4(&prefix, (struct in_addr *) addr, bits, tree->maxbits);

  node = ndpi_patricia_lookup(tree, &prefix);
  /* if(node) memset(&node->value, 0, sizeof(node->value)); */

  return(node);
}

/* ******************************************* */

/*
  Load a file containing IPv4 addresses in CIDR format as 'protocol_id'

  Return: the number of entries loaded or -1 in case of error
*/
int ndpi_load_ipv4_ptree(struct ndpi_detection_module_struct *ndpi_str,
			 const char *path, u_int16_t protocol_id) {
  char buffer[128], *line, *addr, *cidr, *saveptr;
  FILE *fd;
  int len;
  u_int num_loaded = 0;

  if(!ndpi_str || !path || !ndpi_str->protocols_ptree)
    return(-1);

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len - 1] = '\0';
    addr = strtok_r(line, "/", &saveptr);

    if(addr) {
      struct in_addr pin;
      ndpi_patricia_node_t *node;

      cidr = strtok_r(NULL, "\n", &saveptr);

      pin.s_addr = inet_addr(addr);
      if((node = add_to_ptree(ndpi_str->protocols_ptree, AF_INET, &pin, cidr ? atoi(cidr) : 32 /* bits */)) != NULL) {
	u_int i, found = 0;

	for(i=0; i<UV16_MAX_USER_VALUES; i++) {
	  if(node->value.u.uv16[i].user_value == 0) {
	    node->value.u.uv16[i].user_value = protocol_id, node->value.u.uv16[i].additional_user_value =  0 /* port */;
	    found = 1;
	    break;
	  }
	}

	if(found)
	  num_loaded++;
      }
    }
  }

  fclose(fd);
  return(num_loaded);
}

/* ******************************************* */

static void ndpi_init_ptree_ipv4(struct ndpi_detection_module_struct *ndpi_str,
				 void *ptree, ndpi_network host_list[]) {
  int i;

  for(i = 0; host_list[i].network != 0x0; i++) {
    struct in_addr pin;
    ndpi_patricia_node_t *node;

    pin.s_addr = htonl(host_list[i].network);
    if((node = add_to_ptree(ptree, AF_INET, &pin, host_list[i].cidr /* bits */)) != NULL) {
      /*
	Two main cases:
	1) ip -> protocol: uv16[0].user_value = protocol; uv16[0].additional_user_value = 0;
	2) ip -> risk: uv16[0].user_value = risk; uv16[0].additional_user_value = 0;
      */
      node->value.u.uv16[0].user_value = host_list[i].value, node->value.u.uv16[0].additional_user_value = 0;
    }
  }
}

/* ******************************************* */

static int ndpi_add_host_ip_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
					char *value, u_int16_t protocol_id) {
  ndpi_patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr = strrchr(value, '/');
  u_int16_t port = 0; /* Format ip:8.248.73.247:443 */
  char *double_column;

  if(!ndpi_str->protocols_ptree)
    return(-1);

  if(ptr) {
    ptr[0] = '\0';
    ptr++;

    if((double_column = strrchr(ptr, ':')) != NULL) {
      double_column[0] = '\0';
      port = atoi(&double_column[1]);
    }

    if(atoi(ptr) >= 0 && atoi(ptr) <= 32)
      bits = atoi(ptr);
  } else {
    /*
      Let's check if there is the port defined
      Example: ip:8.248.73.247:443@AmazonPrime
    */
    double_column = strrchr(value, ':');

    if(double_column) {
      double_column[0] = '\0';
      port = atoi(&double_column[1]);
    }
  }

  if(inet_pton(AF_INET, value, &pin) != 1)
    return(-1);

  if((node = add_to_ptree(ndpi_str->protocols_ptree, AF_INET, &pin, bits)) != NULL) {
    int i;
    struct patricia_uv16_list *item;

    for(i=0; i<UV16_MAX_USER_VALUES; i++) {
      if(node->value.u.uv16[i].user_value == 0) {
	node->value.u.uv16[i].user_value = protocol_id, node->value.u.uv16[i].additional_user_value = htons(port);

	return(0);
      }
    } /* for */

    /*
      If we're here it means that we don't have
      enough room for our custom value
    */
    item = (struct patricia_uv16_list*)ndpi_malloc(sizeof(struct patricia_uv16_list));

    if(item != NULL) {
      item->value.user_value = protocol_id,
	item->value.additional_user_value = htons(port),
	item->next = (struct patricia_uv16_list*)node->data;

      node->data = item;

      return(0);
    }

    return(-1); /* All slots are full */
  }

  return(0);
}

void set_ndpi_flow_malloc(void *(*__ndpi_flow_malloc)(size_t size)) {
  _ndpi_flow_malloc = __ndpi_flow_malloc;
}

void set_ndpi_flow_free(void (*__ndpi_flow_free)(void *ptr)) {
  _ndpi_flow_free = __ndpi_flow_free;
}

void ndpi_debug_printf(unsigned int proto, struct ndpi_detection_module_struct *ndpi_str, ndpi_log_level_t log_level,
                       const char *file_name, const char *func_name, unsigned int line_number, const char *format, ...) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  va_list args;
#define MAX_STR_LEN 250
  char str[MAX_STR_LEN];
  if(ndpi_str != NULL && log_level > NDPI_LOG_ERROR && proto > 0 && proto < NDPI_MAX_SUPPORTED_PROTOCOLS &&
     !NDPI_ISSET(&ndpi_str->debug_bitmask, proto))
    return;
  va_start(args, format);
  ndpi_vsnprintf(str, sizeof(str) - 1, format, args);
  va_end(args);

  if(ndpi_str != NULL) {
    printf("%s:%s:%-3d - [%u]: %s", file_name, func_name, line_number, proto, str);
  } else {
    printf("Proto: %u, %s", proto, str);
  }
#endif
}

/* ****************************************** */

void set_ndpi_debug_function(struct ndpi_detection_module_struct *ndpi_str, ndpi_debug_function_ptr ndpi_debug_printf) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_str->ndpi_debug_printf = ndpi_debug_printf;
#endif
}

/* ****************************************** */

/* Keep it in order and in sync with ndpi_protocol_category_t in ndpi_typedefs.h */
static const char *categories[] = {
  "Unspecified",
  "Media",
  "VPN",
  "Email",
  "DataTransfer",
  "Web",
  "SocialNetwork",
  "Download",
  "Game",
  "Chat",
  "VoIP",
  "Database",
  "RemoteAccess",
  "Cloud",
  "Network",
  "Collaborative",
  "RPC",
  "Streaming",
  "System",
  "SoftwareUpdate",
  "",
  "",
  "",
  "",
  "",
  "Music",
  "Video",
  "Shopping",
  "Productivity",
  "FileSharing",
  "ConnCheck",
  "IoT-Scada",
  "VirtAssistant",
  "Cybersecurity",
  "AdultContent",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "Mining", /* 99 */
  "Malware",
  "Advertisement",
  "Banned_Site",
  "Site_Unavailable",
  "Allowed_Site",
  "Antimalware",
  "Crypto_Currency",
};

#if !defined(NDPI_CFFI_PREPROCESSING) && defined(__linux__)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(categories) / sizeof(char *) == NDPI_PROTOCOL_NUM_CATEGORIES,
               "Invalid categories length. Do you need to update 'categories' array or 'ndpi_protocol_category_t'?");
#endif
#endif

/* ******************************************************************** */

struct ndpi_detection_module_struct *ndpi_init_detection_module(ndpi_init_prefs prefs) {
  struct ndpi_detection_module_struct *ndpi_str = ndpi_malloc(sizeof(struct ndpi_detection_module_struct));
  int i;

  if(ndpi_str == NULL) {
    /* Logging this error is a bit tricky. At this point, we can't use NDPI_LOG*
       functions yet, we don't have a custom log function and, as a library,
       we shouldn't use stdout/stderr. Since this error is quite unlikely,
       simply avoid any logs at all */
    return(NULL);
  }

  memset(ndpi_str, 0, sizeof(struct ndpi_detection_module_struct));

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  set_ndpi_debug_function(ndpi_str, (ndpi_debug_function_ptr) ndpi_debug_printf);
  NDPI_BITMASK_RESET(ndpi_str->debug_bitmask);
#endif /* NDPI_ENABLE_DEBUG_MESSAGES */

  if(prefs & ndpi_enable_ja3_plus)
    ndpi_str->enable_ja3_plus = 1;

  ndpi_str->enable_load_gambling_list = 1;
  if(prefs & ndpi_dont_load_gambling_list)
    ndpi_str->enable_load_gambling_list = 0;

  if(!(prefs & ndpi_dont_init_libgcrypt)) {
    if(!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
      const char *gcrypt_ver = gcry_check_version(NULL);
      if(!gcrypt_ver) {
        NDPI_LOG_ERR(ndpi_str, "Error initializing libgcrypt\n");
        ndpi_free(ndpi_str);
        return NULL;
      }
      NDPI_LOG_DBG(ndpi_str, "Libgcrypt %s\n", gcrypt_ver);
      /* Tell Libgcrypt that initialization has completed. */
      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
  } else {
    NDPI_LOG_DBG(ndpi_str, "Libgcrypt initialization skipped\n");
  }

  if((ndpi_str->protocols_ptree = ndpi_patricia_new(32 /* IPv4 */)) != NULL) {
    ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, host_protocol_list);

    if(!(prefs & ndpi_dont_load_cachefly_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_cachefly_protocol_list);

    if(!(prefs & ndpi_dont_load_tor_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_tor_protocol_list);

    if(!(prefs & ndpi_dont_load_azure_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_microsoft_azure_protocol_list);

    if(!(prefs & ndpi_dont_load_whatsapp_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_whatsapp_protocol_list);

    if(!(prefs & ndpi_dont_load_amazon_aws_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_amazon_aws_protocol_list);

    if(!(prefs & ndpi_dont_load_ethereum_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_mining_protocol_list);

    if(!(prefs & ndpi_dont_load_zoom_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_zoom_protocol_list);

    if(!(prefs & ndpi_dont_load_cloudflare_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_cloudflare_protocol_list);

    if(!(prefs & ndpi_dont_load_microsoft_list)) {
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_microsoft_365_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ms_one_drive_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ms_outlook_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_skype_teams_protocol_list);
    }

    if(!(prefs & ndpi_dont_load_google_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_google_protocol_list);

    if(!(prefs & ndpi_dont_load_google_cloud_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_google_cloud_protocol_list);

    if(!(prefs & ndpi_dont_load_protonvpn_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_protonvpn_protocol_list);

    if(!(prefs & ndpi_dont_load_mullvad_list))
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_mullvad_protocol_list);

    if(!(prefs & ndpi_dont_load_asn_lists)) {
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_telegram_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_apple_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_twitter_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_netflix_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_webex_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_teamviewer_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_facebook_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_tencent_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_opendns_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_dropbox_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_starcraft_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_ubuntuone_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_twitch_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_hotspot_shield_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_github_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_steam_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_bloomberg_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_citrix_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_edgecast_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_goto_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_riotgames_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_threema_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_alibaba_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_avast_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_discord_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_line_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_vk_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_yandex_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_yandex_cloud_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_disneyplus_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_hulu_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_epicgames_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_nvidia_protocol_list);
      ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->protocols_ptree, ndpi_protocol_roblox_protocol_list);
    }

    if(prefs & ndpi_track_flow_payload)
      ndpi_str->max_payload_track_len = 1024; /* track up to X payload bytes */
  }

  ndpi_str->ip_risk_mask_ptree = ndpi_patricia_new(32 /* IPv4 */);

  if(!(prefs & ndpi_dont_init_risk_ptree)) {
    if((ndpi_str->ip_risk_ptree = ndpi_patricia_new(32 /* IPv4 */)) != NULL) {
      if(!(prefs & ndpi_dont_load_icloud_private_relay_list))
        ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->ip_risk_ptree, ndpi_anonymous_subscriber_icloud_private_relay_protocol_list);
      if(!(prefs & ndpi_dont_load_protonvpn_exit_nodes_list))
        ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->ip_risk_ptree, ndpi_anonymous_subscriber_protonvpn_protocol_list);
      if(!(prefs & ndpi_dont_load_crawlers_list))
        ndpi_init_ptree_ipv4(ndpi_str, ndpi_str->ip_risk_ptree, ndpi_http_crawler_bot_protocol_list);
    }
  }

  ndpi_str->max_packets_to_process = NDPI_DEFAULT_MAX_NUM_PKTS_PER_FLOW_TO_DISSECT;

  NDPI_BITMASK_SET_ALL(ndpi_str->detection_bitmask);
  ndpi_str->user_data = NULL;

  ndpi_str->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
  ndpi_str->tls_certificate_expire_in_x_days = 30; /* NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE flow risk */

  ndpi_str->ndpi_num_supported_protocols = NDPI_MAX_SUPPORTED_PROTOCOLS;
  ndpi_str->ndpi_num_custom_protocols = 0;

  ndpi_str->host_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->host_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->host_risk_mask_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->host_risk_mask_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->common_alpns_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->common_alpns_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  load_common_alpns(ndpi_str);

  ndpi_str->tls_cert_subject_automa.ac_automa = ac_automata_init(NULL);
  if(!ndpi_str->tls_cert_subject_automa.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->malicious_ja3_hashmap = NULL; /* Initialized on demand */
  ndpi_str->malicious_sha1_hashmap = NULL; /* Initialized on demand */
  ndpi_str->risky_domain_automa.ac_automa = NULL; /* Initialized on demand */
  ndpi_str->trusted_issuer_dn = NULL;

  ndpi_str->custom_categories.hostnames.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->custom_categories.hostnames.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(!ndpi_str->custom_categories.hostnames_shadow.ac_automa) {
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->custom_categories.ipAddresses = ndpi_patricia_new(32 /* IPv4 */);
  ndpi_str->custom_categories.ipAddresses_shadow = ndpi_patricia_new(32 /* IPv4 */);

  if(ndpi_str->host_automa.ac_automa)
    ac_automata_feature(ndpi_str->host_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->custom_categories.hostnames.ac_automa)
    ac_automata_feature(ndpi_str->custom_categories.hostnames.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_feature(ndpi_str->custom_categories.hostnames_shadow.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->tls_cert_subject_automa.ac_automa)
    ac_automata_feature(ndpi_str->tls_cert_subject_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->host_risk_mask_automa.ac_automa)
    ac_automata_feature(ndpi_str->host_risk_mask_automa.ac_automa,AC_FEATURE_LC);

  if(ndpi_str->common_alpns_automa.ac_automa)
    ac_automata_feature(ndpi_str->common_alpns_automa.ac_automa,AC_FEATURE_LC);

  /* ahocorasick debug */
  /* Needed ac_automata_enable_debug(1) for show debug */
  if(ndpi_str->host_automa.ac_automa)
    ac_automata_name(ndpi_str->host_automa.ac_automa,"host",AC_FEATURE_DEBUG);

  if(ndpi_str->custom_categories.hostnames.ac_automa)
    ac_automata_name(ndpi_str->custom_categories.hostnames.ac_automa,"ccat",0);

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_name(ndpi_str->custom_categories.hostnames_shadow.ac_automa,"ccat_sh",0);

  if(ndpi_str->tls_cert_subject_automa.ac_automa)
    ac_automata_name(ndpi_str->tls_cert_subject_automa.ac_automa,"tls_cert",AC_FEATURE_DEBUG);

  if(ndpi_str->host_risk_mask_automa.ac_automa)
    ac_automata_name(ndpi_str->host_risk_mask_automa.ac_automa,"content",AC_FEATURE_DEBUG);

  if(ndpi_str->common_alpns_automa.ac_automa)
    ac_automata_name(ndpi_str->common_alpns_automa.ac_automa,"content",AC_FEATURE_DEBUG);

  if((ndpi_str->custom_categories.ipAddresses == NULL) || (ndpi_str->custom_categories.ipAddresses_shadow == NULL)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] Error allocating Patricia trees\n");
    ndpi_exit_detection_module(ndpi_str);
    return(NULL);
  }

  ndpi_str->ookla_cache_num_entries = 1024;
  ndpi_str->bittorrent_cache_num_entries = 32768;
  ndpi_str->zoom_cache_num_entries = 512;
  ndpi_str->stun_cache_num_entries = 1024;
  ndpi_str->tls_cert_cache_num_entries = 1024;
  ndpi_str->mining_cache_num_entries = 1024;
  ndpi_str->msteams_cache_num_entries = 1024;
  ndpi_str->stun_zoom_cache_num_entries = 1024;

  ndpi_str->ookla_cache_ttl = 120; /* sec */
  ndpi_str->bittorrent_cache_ttl = 0;
  ndpi_str->zoom_cache_ttl = 0;
  ndpi_str->stun_cache_ttl = 0;
  ndpi_str->tls_cert_cache_ttl = 0;
  ndpi_str->mining_cache_ttl = 0;
  ndpi_str->msteams_cache_ttl = 60; /* sec */
  ndpi_str->stun_zoom_cache_ttl = 60; /* sec */

  ndpi_str->opportunistic_tls_smtp_enabled = 1;
  ndpi_str->opportunistic_tls_imap_enabled = 1;
  ndpi_str->opportunistic_tls_pop_enabled = 1;
  ndpi_str->opportunistic_tls_ftp_enabled = 1;
  ndpi_str->opportunistic_tls_stun_enabled = 1;

  ndpi_str->monitoring_stun_pkts_to_process = 4;
  ndpi_str->monitoring_stun_flags = 0;

  ndpi_str->aggressiveness_ookla = NDPI_AGGRESSIVENESS_OOKLA_TLS;

  if(prefs & ndpi_enable_tcp_ack_payload_heuristic)
    ndpi_str->tcp_ack_paylod_heuristic = 1;

  if(!(prefs & ndpi_disable_fully_encrypted_heuristic))
    ndpi_str->fully_encrypted_based_on_first_pkt_heuristic = 1;

  for(i = 0; i < NUM_CUSTOM_CATEGORIES; i++)
    ndpi_snprintf(ndpi_str->custom_category_labels[i], CUSTOM_CATEGORY_LABEL_LEN, "User custom category %u",
	     (unsigned int) (i + 1));

  return(ndpi_str);
}

/* *********************************************** */

/*
  This function adds some exceptions for popular domain names
  in order to avoid "false" positives and avoid polluting
  results
*/
static void ndpi_add_domain_risk_exceptions(struct ndpi_detection_module_struct *ndpi_str) {
  const char *domains[] = {
    ".local",
    ".work",
    /* DGA's are used for caching */
    "akamaihd.net",
    NULL /* End */
  };
  const ndpi_risk risks_to_mask[] = {
    NDPI_SUSPICIOUS_DGA_DOMAIN,
    NDPI_BINARY_APPLICATION_TRANSFER,
    NDPI_NUMERIC_IP_HOST,
    NDPI_MALICIOUS_JA3,
    NDPI_NO_RISK /* End */
  };
  u_int i;
  ndpi_risk mask = ((ndpi_risk)-1);

  if(!ndpi_str) return;

  for(i=0; risks_to_mask[i] != NDPI_NO_RISK; i++)
    mask &= ~(1ULL << risks_to_mask[i]);

  for(i=0; domains[i] != NULL; i++)
    ndpi_add_host_risk_mask(ndpi_str, (char*)domains[i], mask);

  for(i=0; host_match[i].string_to_match != NULL; i++) {
    switch(host_match[i].protocol_category) {
    case NDPI_PROTOCOL_CATEGORY_CONNECTIVITY_CHECK:
    case NDPI_PROTOCOL_CATEGORY_CYBERSECURITY:
      ndpi_add_host_risk_mask(ndpi_str, (char*)host_match[i].string_to_match, mask);
      break;

    default:
      /* Nothing to do */
      break;
    }
  }
}

/* *********************************************** */

void ndpi_finalize_initialization(struct ndpi_detection_module_struct *ndpi_str) {
  u_int i;

  if(!ndpi_str)
    return;

  ndpi_add_domain_risk_exceptions(ndpi_str);

  if(ndpi_str->ookla_cache_num_entries > 0) {
    ndpi_str->ookla_cache = ndpi_lru_cache_init(ndpi_str->ookla_cache_num_entries,
                                                ndpi_str->ookla_cache_ttl);
    if(!ndpi_str->ookla_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->ookla_cache_num_entries);
    }
  }
  if(ndpi_str->bittorrent_cache_num_entries > 0) {
    ndpi_str->bittorrent_cache = ndpi_lru_cache_init(ndpi_str->bittorrent_cache_num_entries,
                                                     ndpi_str->bittorrent_cache_ttl);
    if(!ndpi_str->bittorrent_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->bittorrent_cache_num_entries);
    }
  }
  if(ndpi_str->zoom_cache_num_entries > 0) {
    ndpi_str->zoom_cache = ndpi_lru_cache_init(ndpi_str->zoom_cache_num_entries,
                                               ndpi_str->zoom_cache_ttl);
    if(!ndpi_str->zoom_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->zoom_cache_num_entries);
    }
  }
  if(ndpi_str->stun_cache_num_entries > 0) {
    ndpi_str->stun_cache = ndpi_lru_cache_init(ndpi_str->stun_cache_num_entries,
                                               ndpi_str->stun_cache_ttl);
    if(!ndpi_str->stun_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->stun_cache_num_entries);
    }
  }
  if(ndpi_str->tls_cert_cache_num_entries > 0) {
    ndpi_str->tls_cert_cache = ndpi_lru_cache_init(ndpi_str->tls_cert_cache_num_entries,
                                                   ndpi_str->tls_cert_cache_ttl);
    if(!ndpi_str->tls_cert_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->tls_cert_cache_num_entries);
    }
  }
  if(ndpi_str->mining_cache_num_entries > 0) {
    ndpi_str->mining_cache = ndpi_lru_cache_init(ndpi_str->mining_cache_num_entries,
                                                 ndpi_str->mining_cache_ttl);
    if(!ndpi_str->mining_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->mining_cache_num_entries);
    }
  }
  if(ndpi_str->msteams_cache_num_entries > 0) {
    ndpi_str->msteams_cache = ndpi_lru_cache_init(ndpi_str->msteams_cache_num_entries,
                                                  ndpi_str->msteams_cache_ttl);
    if(!ndpi_str->msteams_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->msteams_cache_num_entries);
    }
  }
  if(ndpi_str->stun_zoom_cache_num_entries > 0) {
    ndpi_str->stun_zoom_cache = ndpi_lru_cache_init(ndpi_str->stun_zoom_cache_num_entries,
                                                    ndpi_str->stun_zoom_cache_ttl);
    if(!ndpi_str->stun_zoom_cache) {
      NDPI_LOG_ERR(ndpi_str, "Error allocating lru cache (num_entries %u)\n",
                   ndpi_str->stun_zoom_cache_num_entries);
    }
  }

  if(ndpi_str->ac_automa_finalized) return;

  ndpi_automa * const automa[] = { &ndpi_str->host_automa,
                                   &ndpi_str->tls_cert_subject_automa,
                                   &ndpi_str->host_risk_mask_automa,
                                   &ndpi_str->common_alpns_automa };

  for(i = 0; i < NDPI_ARRAY_LENGTH(automa); ++i) {
    ndpi_automa *a = automa[i];

    if(a && a->ac_automa)
      ac_automata_finalize((AC_AUTOMATA_t *) a->ac_automa);
  }

  ndpi_str->ac_automa_finalized = 1;
}

/* *********************************************** */

/* Wrappers */
void *ndpi_init_automa(void) {
  return(ac_automata_init(ac_domain_match_handler));
}

/* ****************************************************** */

int ndpi_add_string_value_to_automa(void *_automa, char *str, u_int32_t num) {
  AC_PATTERN_t ac_pattern;
  AC_AUTOMATA_t *automa = (AC_AUTOMATA_t *) _automa;
  AC_ERROR_t rc;

  if(automa == NULL)
    return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));
  ac_pattern.astring    = str;
  ac_pattern.rep.number = num;
  ac_pattern.length     = strlen(ac_pattern.astring);

  rc = ac_automata_add(automa, &ac_pattern);
  return(rc == ACERR_SUCCESS ? 0 : (rc == ACERR_DUPLICATE_PATTERN ? -2 : -1));
}

/* ****************************************************** */

int ndpi_add_string_to_automa(void *_automa, char *str) {
  return(ndpi_add_string_value_to_automa(_automa, str, 1));
}

/* ****************************************************** */

void ndpi_free_automa(void *_automa) {
  ac_automata_release((AC_AUTOMATA_t *) _automa, 1);
}

/* ****************************************************** */

void ndpi_finalize_automa(void *_automa) {
  ac_automata_finalize((AC_AUTOMATA_t *) _automa);
}

/* ****************************************************** */

void ndpi_automa_get_stats(void *_automa, struct ndpi_automa_stats *stats) {
  struct ac_stats ac_stats;

  ac_automata_get_stats((AC_AUTOMATA_t *) _automa, &ac_stats);
  stats->n_search = ac_stats.n_search;
  stats->n_found = ac_stats.n_found;
}

/* ****************************************************** */

int ndpi_get_automa_stats(struct ndpi_detection_module_struct *ndpi_struct,
			  automa_type automa_type,
			  struct ndpi_automa_stats *stats)
{
  if(!ndpi_struct || !stats)
    return -1;

  switch(automa_type) {
  case NDPI_AUTOMA_HOST:
    ndpi_automa_get_stats(ndpi_struct->host_automa.ac_automa, stats);
    return 0;

  case NDPI_AUTOMA_DOMAIN:
    ndpi_automa_get_stats(ndpi_struct->risky_domain_automa.ac_automa, stats);
    return 0;

  case NDPI_AUTOMA_TLS_CERT:
    ndpi_automa_get_stats(ndpi_struct->tls_cert_subject_automa.ac_automa, stats);
    return 0;

  case NDPI_AUTOMA_RISK_MASK:
    ndpi_automa_get_stats(ndpi_struct->host_risk_mask_automa.ac_automa, stats);
    return 0;

  case NDPI_AUTOMA_COMMON_ALPNS:
    ndpi_automa_get_stats(ndpi_struct->common_alpns_automa.ac_automa, stats);
    return 0;

  default:
    return -1;
  }
}

/* ****************************************************** */

static int ndpi_match_string_common(AC_AUTOMATA_t *automa, char *string_to_match,size_t string_len,
				    u_int32_t *protocol_id, ndpi_protocol_category_t *category,
				    ndpi_protocol_breed_t *breed) {
  AC_REP_t match = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NDPI_PROTOCOL_UNRATED, 0, 0, 0, 0, 0 };
  AC_TEXT_t ac_input_text;
  int rc;

  if(protocol_id) *protocol_id = NDPI_PROTOCOL_UNKNOWN;

  if((automa == NULL) || (string_to_match == NULL) || (string_to_match[0] == '\0')) {
    return(-2);
  }

  if(automa->automata_open) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    printf("[%s:%d] [NDPI] Internal error: please call ndpi_finalize_initialization()\n", __FILE__, __LINE__);
#endif
    return(-1);
  }

  ac_input_text.astring = string_to_match, ac_input_text.length = string_len;
  ac_input_text.option = 0;
  rc = ac_automata_search(automa, &ac_input_text, &match);

  if(protocol_id)
    *protocol_id = rc ? match.number : NDPI_PROTOCOL_UNKNOWN;

  if(category)
    *category = rc ? match.category : 0;

  if(breed)
    *breed = rc ? match.breed : 0;

  return rc;
}

/* ****************************************************** */

int ndpi_match_string(void *_automa, char *string_to_match) {
  uint32_t proto_id;
  int rc;

  if(!string_to_match)
    return(-2);

  rc = ndpi_match_string_common(_automa, string_to_match,
				strlen(string_to_match),
				&proto_id, NULL, NULL);
  if(rc < 0) return rc;

  return rc ? proto_id : NDPI_PROTOCOL_UNKNOWN;
}

/* ****************************************************** */

int ndpi_match_string_protocol_id(void *automa, char *string_to_match,
				  u_int match_len, u_int16_t *protocol_id,
				  ndpi_protocol_category_t *category,
				  ndpi_protocol_breed_t *breed) {
  u_int32_t proto_id;
  int rc = ndpi_match_string_common((AC_AUTOMATA_t*)automa, string_to_match,
				    match_len, &proto_id, category, breed);
  if(rc < 0) return rc;
  *protocol_id = (u_int16_t)proto_id;
  return(proto_id != NDPI_PROTOCOL_UNKNOWN ? 0 : -1);
}

/* ****************************************************** */

int ndpi_match_string_value(void *automa, char *string_to_match,
			    u_int match_len, u_int32_t *num) {
  int rc = ndpi_match_string_common((AC_AUTOMATA_t *)automa, string_to_match,
				    match_len, num, NULL, NULL);
  if(rc < 0) return rc;
  return rc ? 0 : -1;
}


/* *********************************************** */

int ndpi_match_custom_category(struct ndpi_detection_module_struct *ndpi_str,
			       char *name, u_int name_len,
                               ndpi_protocol_category_t *category) {
  u_int32_t id;
  int rc = ndpi_match_string_common(ndpi_str->custom_categories.hostnames.ac_automa,
				    name, name_len, &id, category, NULL);
  if(rc < 0) return rc;
  return(id != NDPI_PROTOCOL_UNKNOWN ? 0 : -1);
}

/* *********************************************** */

int ndpi_get_custom_category_match(struct ndpi_detection_module_struct *ndpi_str,
				   char *name_or_ip, u_int name_len,
				   ndpi_protocol_category_t *id) {
  char ipbuf[64], *ptr;
  struct in_addr pin;
  u_int cp_len = ndpi_min(sizeof(ipbuf) - 1, name_len);

  if(!ndpi_str->custom_categories.categories_loaded)
    return(-1);

  if(cp_len > 0) {
    memcpy(ipbuf, name_or_ip, cp_len);
    ipbuf[cp_len] = '\0';
  } else
    ipbuf[0] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr)
    ptr[0] = '\0';

  if(inet_pton(AF_INET, ipbuf, &pin) == 1) {
    /* Search IP */
    ndpi_prefix_t prefix;
    ndpi_patricia_node_t *node;

    /* Make sure all in network byte order otherwise compares wont work */
    ndpi_fill_prefix_v4(&prefix, &pin, 32, ((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses)->maxbits);
    node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);

    if(node) {
      *id = node->value.u.uv32.user_value;

      return(0);
    }

    return(-1);
  } else {
    /* Search Host */
    return(ndpi_match_custom_category(ndpi_str, name_or_ip, name_len, id));
  }
}

/* *********************************************** */

static void free_ptree_data(void *data) {
  struct patricia_uv16_list *item = (struct patricia_uv16_list *)data;

  while(item != NULL) {
    struct patricia_uv16_list *next = item->next;

    ndpi_free(item);
    item = next;
  }
}

/* ****************************************************** */

void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_str) {
  if(ndpi_str != NULL) {
    int i;

    for (i = 0; i < (NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS); i++) {
      if(ndpi_str->proto_defaults[i].protoName)
        ndpi_free(ndpi_str->proto_defaults[i].protoName);
      if(ndpi_str->proto_defaults[i].subprotocols != NULL)
        ndpi_free(ndpi_str->proto_defaults[i].subprotocols);
    }

#ifdef HAVE_NBPF
    for(i = 0; (i < MAX_NBPF_CUSTOM_PROTO) && (ndpi_str->nbpf_custom_proto[i].tree != NULL); i++)
      nbpf_free(ndpi_str->nbpf_custom_proto[i].tree);
#endif

    /* NDPI_PROTOCOL_TINC */
    if(ndpi_str->tinc_cache)
      cache_free((cache_t)(ndpi_str->tinc_cache));

    if(ndpi_str->ookla_cache)
      ndpi_lru_free_cache(ndpi_str->ookla_cache);

    if(ndpi_str->bittorrent_cache)
      ndpi_lru_free_cache(ndpi_str->bittorrent_cache);

    if(ndpi_str->zoom_cache)
      ndpi_lru_free_cache(ndpi_str->zoom_cache);

    if(ndpi_str->stun_cache)
      ndpi_lru_free_cache(ndpi_str->stun_cache);

    if(ndpi_str->stun_zoom_cache)
      ndpi_lru_free_cache(ndpi_str->stun_zoom_cache);

    if(ndpi_str->tls_cert_cache)
      ndpi_lru_free_cache(ndpi_str->tls_cert_cache);

    if(ndpi_str->mining_cache)
      ndpi_lru_free_cache(ndpi_str->mining_cache);

    if(ndpi_str->msteams_cache)
      ndpi_lru_free_cache(ndpi_str->msteams_cache);

    if(ndpi_str->protocols_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->protocols_ptree, free_ptree_data);

    if(ndpi_str->ip_risk_mask_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->ip_risk_mask_ptree, NULL);

    if(ndpi_str->ip_risk_ptree)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->ip_risk_ptree, NULL);

    if(ndpi_str->udpRoot != NULL) ndpi_tdestroy(ndpi_str->udpRoot, ndpi_free);
    if(ndpi_str->tcpRoot != NULL) ndpi_tdestroy(ndpi_str->tcpRoot, ndpi_free);

    if(ndpi_str->host_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->host_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->risky_domain_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->risky_domain_automa.ac_automa,
                          1 /* free patterns strings memory */);

    if(ndpi_str->tls_cert_subject_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->tls_cert_subject_automa.ac_automa, 0);

    if(ndpi_str->malicious_ja3_hashmap != NULL)
      ndpi_hash_free(&ndpi_str->malicious_ja3_hashmap, NULL);

    if(ndpi_str->malicious_sha1_hashmap != NULL)
      ndpi_hash_free(&ndpi_str->malicious_sha1_hashmap, NULL);

    if(ndpi_str->custom_categories.hostnames.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.hostnames_shadow.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames_shadow.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->custom_categories.ipAddresses != NULL)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses, free_ptree_data);

    if(ndpi_str->custom_categories.ipAddresses_shadow != NULL)
      ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses_shadow, free_ptree_data);

    if(ndpi_str->host_risk_mask_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->host_risk_mask_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->common_alpns_automa.ac_automa != NULL)
      ac_automata_release((AC_AUTOMATA_t *) ndpi_str->common_alpns_automa.ac_automa,
			  1 /* free patterns strings memory */);

    if(ndpi_str->trusted_issuer_dn) {
      ndpi_list *head = ndpi_str->trusted_issuer_dn;

      while(head != NULL) {
	ndpi_list *next;

	if(head->value) ndpi_free(head->value);
	next = head->next;
	ndpi_free(head);
	head = next;
      }
    }

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/ndpi_exit_detection_module.c"
#endif

    ndpi_free_geoip(ndpi_str);

    if(ndpi_str->callback_buffer)
	    ndpi_free(ndpi_str->callback_buffer);
    if(ndpi_str->callback_buffer_tcp_payload)
	    ndpi_free(ndpi_str->callback_buffer_tcp_payload);
    ndpi_free(ndpi_str);
  }
}

/* ****************************************************** */

static ndpi_default_ports_tree_node_t *ndpi_get_guessed_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
                                                                    u_int8_t proto, u_int16_t sport, u_int16_t dport) {
  ndpi_default_ports_tree_node_t node;

  if(sport && dport) {
    const void *ret;

    node.default_port = dport; /* Check server port first */
    ret = ndpi_tfind(&node, (proto == IPPROTO_TCP) ? (void *) &ndpi_str->tcpRoot : (void *) &ndpi_str->udpRoot,
		     ndpi_default_ports_tree_node_t_cmp);

    if(ret == NULL) {
      node.default_port = sport;
      ret = ndpi_tfind(&node, (proto == IPPROTO_TCP) ? (void *) &ndpi_str->tcpRoot : (void *) &ndpi_str->udpRoot,
		       ndpi_default_ports_tree_node_t_cmp);
    }

    if(ret)
      return(*(ndpi_default_ports_tree_node_t **) ret);
  }

  return(NULL);
}

/* ****************************************************** */

/*
  These are UDP protocols that must fit a single packet
  and thus that if have NOT been detected they cannot be guessed
  as they have been excluded
*/
u_int8_t is_udp_not_guessable_protocol(u_int16_t l7_guessed_proto) {
  switch(l7_guessed_proto) {
  case NDPI_PROTOCOL_SNMP:
  case NDPI_PROTOCOL_NETFLOW:
    /* TODO: add more protocols (if any missing) */
    return(1);
  }

  return(0);
}

/* ****************************************************** */

u_int16_t ndpi_guess_protocol_id(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
                                 u_int8_t proto, u_int16_t sport, u_int16_t dport, u_int8_t *user_defined_proto) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  *user_defined_proto = 0; /* Default */

  if(sport && dport) {
    ndpi_default_ports_tree_node_t *found = ndpi_get_guessed_protocol_id(ndpi_str, proto, sport, dport);

    if(found != NULL) {
      u_int16_t guessed_proto = found->proto->protoId;

      /* We need to check if the guessed protocol isn't excluded by nDPI */
      if(flow && (proto == IPPROTO_UDP) &&
	 NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, guessed_proto) &&
	 is_udp_not_guessable_protocol(guessed_proto))
	return(NDPI_PROTOCOL_UNKNOWN);
      else {
	*user_defined_proto = found->customUserProto;
	return(guessed_proto);
      }
    }
  } else {
    /* No TCP/UDP */

    switch(proto) {
    case NDPI_IPSEC_PROTOCOL_ESP:
    case NDPI_IPSEC_PROTOCOL_AH:
      return(NDPI_PROTOCOL_IPSEC);
    case NDPI_GRE_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_GRE);
    case NDPI_PGM_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_PGM);
    case NDPI_PIM_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_PIM);
    case NDPI_ICMP_PROTOCOL_TYPE:
      if(flow) {
        flow->entropy = 0.0f;
	/* Run some basic consistency tests */

	if(packet->payload_packet_len < sizeof(struct ndpi_icmphdr)) {
	  ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	} else {
	  u_int8_t icmp_type = (u_int8_t)packet->payload[0];
	  u_int8_t icmp_code = (u_int8_t)packet->payload[1];

	  /* https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml */
	  if(((icmp_type >= 44) && (icmp_type <= 252))
	     || (icmp_code > 15))
	    ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);

	  if(packet->payload_packet_len > sizeof(struct ndpi_icmphdr)) {
	    flow->entropy = ndpi_entropy(packet->payload + sizeof(struct ndpi_icmphdr),
	                                 packet->payload_packet_len - sizeof(struct ndpi_icmphdr));

	    if(NDPI_ENTROPY_ENCRYPTED_OR_RANDOM(flow->entropy) != 0) {
	      char str[32];

		snprintf(str, sizeof(str), "Entropy %.2f", flow->entropy);
		ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_ENTROPY, str);
	    }

	    u_int16_t chksm = ndpi_calculate_icmp4_checksum(packet->payload, packet->payload_packet_len);
	    if(chksm) {
	      ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	    }
	  }
	}
      }
      return(NDPI_PROTOCOL_IP_ICMP);
    case NDPI_IGMP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IGMP);
    case NDPI_EGP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_EGP);
    case NDPI_SCTP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_SCTP);
    case NDPI_OSPF_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_OSPF);
    case NDPI_IPIP_PROTOCOL_TYPE:
      return(NDPI_PROTOCOL_IP_IP_IN_IP);
    case NDPI_ICMPV6_PROTOCOL_TYPE:
      if(flow) {
	/* Run some basic consistency tests */

	if(packet->payload_packet_len < sizeof(struct ndpi_icmphdr))
	  ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	else {
	  u_int8_t icmp6_type = (u_int8_t)packet->payload[0];
	  u_int8_t icmp6_code = (u_int8_t)packet->payload[1];

	  /* https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6 */
	  if(((icmp6_type >= 5) && (icmp6_type <= 127))
	     || ((icmp6_code >= 156) && (icmp6_type != 255)))
	    ndpi_set_risk(ndpi_str, flow, NDPI_MALFORMED_PACKET, NULL);
	}
      }
      return(NDPI_PROTOCOL_IP_ICMPV6);
    case 112:
      return(NDPI_PROTOCOL_IP_VRRP);
    }
  }

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ******************************************************************** */

u_int ndpi_get_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str ? ndpi_str->ndpi_num_supported_protocols : 0);
}

/* ******************************************************************** */

#ifdef WIN32
char *strsep(char **sp, char *sep) {
  char *p, *s;
  if(sp == NULL || *sp == NULL || **sp == '\0')
    return(NULL);
  s = *sp;
  p = s + strcspn(s, sep);
  if(*p != '\0')
    *p++ = '\0';
  *sp = p;
  return(s);
}
#endif

/* ******************************************************************** */

int ndpi_add_ip_risk_mask(struct ndpi_detection_module_struct *ndpi_str,
			  char *ip, ndpi_risk mask) {
  char *saveptr, *addr = strtok_r(ip, "/", &saveptr);

  if(!ndpi_str->ip_risk_mask_ptree)
    return(-3);

  if(addr) {
    char *cidr = strtok_r(NULL, "\n", &saveptr);
    struct in_addr pin;
    ndpi_patricia_node_t *node;

    pin.s_addr = inet_addr(addr);
    /* FIX: Add IPv6 support */
    if((node = add_to_ptree(ndpi_str->ip_risk_mask_ptree, AF_INET,
			    &pin, cidr ? atoi(cidr) : 32 /* bits */)) != NULL) {
      node->value.u.uv64 = (u_int64_t)mask;
      return(0);
    } else
      return(-1);
  } else
    return(-2);
}

/* ******************************************************************** */

int ndpi_add_host_risk_mask(struct ndpi_detection_module_struct *ndpi_str,
			    char *host, ndpi_risk mask) {
  AC_PATTERN_t ac_pattern;
  AC_ERROR_t rc;
  u_int len;
  char *host_dup = NULL;

  if((ndpi_str == NULL) || (ndpi_str->host_risk_mask_automa.ac_automa == NULL) || (host == NULL))
    return(-2);

  /* Zap heading/trailing quotes */
  switch(host[0]) {
  case '"':
  case '\'':
    {
      int len;

      host = &host[1];
      len = strlen(host);
      if(len > 0)
	host[len-1] = '\0';
    }

    break;
  }

  host_dup = ndpi_strdup(host);
  if(!host_dup)
    return(-1);

  memset(&ac_pattern, 0, sizeof(ac_pattern));

  len = strlen(host);

  ac_pattern.astring      = host_dup;
  ac_pattern.length       = len;
  ac_pattern.rep.number64 = (ndpi_risk)mask;
  ac_pattern.rep.level    = ndpi_domain_level(host);
  ac_pattern.rep.at_end   = 0;
  ac_pattern.rep.dot      = memchr(host,'.',len) != NULL;

  rc = ac_automata_add(ndpi_str->host_risk_mask_automa.ac_automa, &ac_pattern);

  if(rc != ACERR_SUCCESS) {
    ndpi_free(host_dup);

    if(rc != ACERR_DUPLICATE_PATTERN)
      return (-2);
  }

  return(0);
}

/* ******************************************************************** */

int ndpi_add_trusted_issuer_dn(struct ndpi_detection_module_struct *ndpi_str, char *dn) {
  ndpi_list *head;

  if(dn == NULL)
    return(-1);
  else
    head = (ndpi_list*)ndpi_malloc(sizeof(ndpi_list));

  if(head == NULL) return(-2);

  if(dn[0] == '"') {
    char buf[128], *quote;

    ndpi_snprintf(buf, sizeof(buf), "%s", &dn[1]);

    if((quote = strchr(buf, '"')) != NULL)
      quote[0] = '\0';

    head->value = ndpi_strdup(buf);
  } else
    head->value = ndpi_strdup(dn);

  if(head->value == NULL) {
    ndpi_free(head);
    return(-3);
  }

  head->next = ndpi_str->trusted_issuer_dn;
  ndpi_str->trusted_issuer_dn = head;

  return(0);
}
/* ******************************************************************** */

int ndpi_handle_rule(struct ndpi_detection_module_struct *ndpi_str,
		     char *rule, u_int8_t do_add) {
  char *at, *proto, *elem;
  ndpi_proto_defaults_t *def;
  u_int subprotocol_id, i;
  int id, ret = 0;

  at = strrchr(rule, '@');
  if(at == NULL) {
    /* This looks like a mask rule or an invalid rule */
    char _rule[256], *rule_type, *key;

    ndpi_snprintf(_rule, sizeof(_rule), "%s", rule);
    rule_type = strtok(rule, ":");

    if(!rule_type) {
      NDPI_LOG_ERR(ndpi_str, "Invalid rule '%s'\n", rule);
      return(-1);
    }

    if(!strcmp(rule_type, "trusted_issuer_dn"))
      return(ndpi_add_trusted_issuer_dn(ndpi_str, strtok(NULL, ":")));

    key = strtok(NULL, "=");
    if(key) {
      char *value = strtok(NULL, "=");

      if(value) {
	ndpi_risk risk_mask = (ndpi_risk)atoll(value);

	if(!strcmp(rule_type, "ip_risk_mask")) {
	  return(ndpi_add_ip_risk_mask(ndpi_str, key, risk_mask));
	} else if(!strcmp(rule_type, "host_risk_mask")) {
	  return(ndpi_add_host_risk_mask(ndpi_str, key, risk_mask));
	}
      }
    }

    NDPI_LOG_ERR(ndpi_str, "Unknown rule '%s'\n", rule);
    return(-1);
  } else
    at[0] = 0, proto = &at[1];

  for(i = 0; proto[i] != '\0'; i++) {
    switch(proto[i]) {
    case '/':
    case '&':
    case '^':
    case ':':
    case ';':
    case '\'':
    case '"':
    case ' ':
      proto[i] = '_';
      break;
    }
  }

  if((id = ndpi_get_protocol_id(ndpi_str, proto)) != -1) {
    subprotocol_id = (u_int)id;
    def = &ndpi_str->proto_defaults[subprotocol_id];
  } else
    def = NULL;

  if(def == NULL) {
    if(!do_add) {
      /* We need to remove a rule */
      NDPI_LOG_ERR(ndpi_str, "Unable to find protocol '%s': skipping rule '%s'\n", proto, rule);
      return(-3);
    } else {
      ndpi_port_range ports_a[MAX_DEFAULT_PORTS], ports_b[MAX_DEFAULT_PORTS];
      char *equal = strchr(proto, '=');
      u_int16_t user_proto_id = ndpi_str->ndpi_num_supported_protocols;

      if(equal != NULL) {
	/* PROTO=VALUE */

	equal[0] = '\0';
	user_proto_id = atoi(&equal[1]);

	/* NOTE: ndpi_str->ndpi_num_supported_protocols >= NDPI_MAX_SUPPORTED_PROTOCOLS */
	ndpi_add_user_proto_id_mapping(ndpi_str, ndpi_str->ndpi_num_supported_protocols, user_proto_id);

	/* printf("***** ADDING MAPPING %s: %u -> %u\n", proto, ndpi_str->ndpi_num_supported_protocols, user_proto_id); */
      } else
	ndpi_add_user_proto_id_mapping(ndpi_str, ndpi_str->ndpi_num_supported_protocols,
				       ndpi_str->ndpi_num_supported_protocols);

      if(ndpi_str->ndpi_num_custom_protocols >= (NDPI_MAX_NUM_CUSTOM_PROTOCOLS - 1)) {
	NDPI_LOG_ERR(ndpi_str, "Too many protocols defined (%u): skipping protocol %s\n",
		     ndpi_str->ndpi_num_custom_protocols, proto);
	return(-2);
      }

      ndpi_set_proto_defaults(ndpi_str, 1 /* is_cleartext */,
			      1 /* is_app_protocol */,
			      NDPI_PROTOCOL_ACCEPTABLE, /* breed*/
			      ndpi_str->ndpi_num_supported_protocols /* protoId */,
			      proto, /* protoName */
			      NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, /* TODO add protocol category support in rules */
			      ndpi_build_default_ports(ports_a, 0, 0, 0, 0, 0) /* TCP */,
			      ndpi_build_default_ports(ports_b, 0, 0, 0, 0, 0) /* UDP */);

      def = &ndpi_str->proto_defaults[ndpi_str->ndpi_num_supported_protocols];
      subprotocol_id = ndpi_str->ndpi_num_supported_protocols;
      ndpi_str->ndpi_num_supported_protocols++, ndpi_str->ndpi_num_custom_protocols++;
    }
  }

  while((elem = strsep(&rule, ",")) != NULL) {
    char *attr = elem, *value = NULL;
    ndpi_port_range range;
    int is_tcp = 0, is_udp = 0, is_ip = 0;

    if(strncmp(attr, "tcp:", 4) == 0)
      is_tcp = 1, value = &attr[4];
    else if(strncmp(attr, "udp:", 4) == 0)
      is_udp = 1, value = &attr[4];
    else if(strncmp(attr, "ip:", 3) == 0)
      is_ip = 1, value = &attr[3];
    else if(strncmp(attr, "host:", 5) == 0) {
      /* host:"<value>",host:"<value>",.....@<subproto> */
      u_int i, max_len;

      value = &attr[5];
      if(value[0] == '"')
	value++; /* remove leading " */

      max_len = strlen(value) - 1;
      if(value[max_len] == '"')
	value[max_len] = '\0'; /* remove trailing " */

      for(i=0; i<max_len; i++) value[i] = tolower(value[i]);
    } else if(strncmp(attr, "nbpf:", 5) == 0) {
#ifdef HAVE_NBPF
      char *filter = &attr[5];

      if(ndpi_str->num_nbpf_custom_proto >= MAX_NBPF_CUSTOM_PROTO) {
	NDPI_LOG_ERR(ndpi_str, "nBPF: too many protocols\n");
	return(-4); /* Too many protocols */
      }

      if(filter[0] == '"') {
	u_int len;

	filter = &filter[1];
	len = strlen(filter);

	if(len > 0)
	  filter[len-1] = '\0';
      }

      if((ndpi_str->nbpf_custom_proto[ndpi_str->num_nbpf_custom_proto].tree =
	  nbpf_parse(filter, NULL)) == NULL) {
	NDPI_LOG_ERR(ndpi_str, "nBPF invalid filter: %s\n", filter)
	return(-5); /* Invalid filter */
      } else
	ndpi_str->nbpf_custom_proto[ndpi_str->num_nbpf_custom_proto].l7_protocol = subprotocol_id;

    ndpi_str->num_nbpf_custom_proto++;
#else
      NDPI_LOG_INFO(ndpi_str, "nDPI compiled without nBPF support: skipping rule\n");
      return(-6);
#endif
    }

    if(is_tcp || is_udp) {
      u_int p_low, p_high;
      int rc;

      if(sscanf(value, "%u-%u", &p_low, &p_high) == 2)
	range.port_low = p_low, range.port_high = p_high;
      else
	range.port_low = range.port_high = atoi(&elem[4]);

      if(do_add)
	rc = addDefaultPort(ndpi_str, &range, def, 1 /* Custom user proto */,
		       is_tcp ? &ndpi_str->tcpRoot : &ndpi_str->udpRoot, __FUNCTION__, __LINE__);
      else
	rc = removeDefaultPort(&range, def, is_tcp ? &ndpi_str->tcpRoot : &ndpi_str->udpRoot);

      if(rc != 0) ret = rc;
    } else if(is_ip) {
      int rc = ndpi_add_host_ip_subprotocol(ndpi_str, value, subprotocol_id);

      if(rc != 0)
	return(rc);
    } else {
      if(do_add)
	ndpi_add_host_url_subprotocol(ndpi_str, value, subprotocol_id, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
				      NDPI_PROTOCOL_ACCEPTABLE, 0);
      else
	ndpi_remove_host_url_subprotocol(ndpi_str, value, subprotocol_id);
    }
  }

  return(ret);
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <host|ip>	<category_id>
 *
 * Notes:
 *  - host and category are separated by a single TAB
 *  - empty lines or lines starting with # are ignored
 */
int ndpi_load_categories_file(struct ndpi_detection_module_struct *ndpi_str,
			      const char *path, void *user_data) {
  char buffer[512], *line, *name, *category, *saveptr;
  FILE *fd;
  int len, num = 0;

  if(!ndpi_str || !path)
    return(-1);

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len - 1] = '\0';
    name = strtok_r(line, "\t", &saveptr);

    if(name) {
      category = strtok_r(NULL, "\t", &saveptr);

      if(category) {
	int rc = ndpi_load_category(ndpi_str, name,
				    (ndpi_protocol_category_t) atoi(category),
				    user_data);

	if(rc >= 0)
	  num++;
      }
    }
  }

  fclose(fd);
  ndpi_enable_loaded_categories(ndpi_str);

  return(num);
}

/* ******************************************************************** */

static int ndpi_load_risky_domain(struct ndpi_detection_module_struct *ndpi_str,
				  char* domain_name) {
  if(ndpi_str->risky_domain_automa.ac_automa == NULL) {
    ndpi_str->risky_domain_automa.ac_automa = ac_automata_init(ac_domain_match_handler);
    if(!ndpi_str->risky_domain_automa.ac_automa) return -1;
    ac_automata_feature(ndpi_str->risky_domain_automa.ac_automa,AC_FEATURE_LC);
    ac_automata_name(ndpi_str->risky_domain_automa.ac_automa, "risky", 0);
  }

  if(!ndpi_str->risky_domain_automa.ac_automa)
    return -1;

  return ndpi_string_to_automa(ndpi_str, (AC_AUTOMATA_t *)ndpi_str->risky_domain_automa.ac_automa,
			       domain_name, 1, 0, 0, 0, 1); /* domain, protocol, category, breed, level , at_end */
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <domain name>
 *
 * Notes:
 *  - you can add a .<domain name> to avoid mismatches
 */
int ndpi_load_risk_domain_file(struct ndpi_detection_module_struct *ndpi_str, const char *path) {
  char buffer[128], *line;
  FILE *fd;
  int len, num = 0;

  if(!ndpi_str || !path)
    return(-1);

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len - 1] = '\0';

    if(ndpi_load_risky_domain(ndpi_str, line) >= 0)
      num++;
  }

  fclose(fd);

  if(ndpi_str->risky_domain_automa.ac_automa)
    ac_automata_finalize((AC_AUTOMATA_t *)ndpi_str->risky_domain_automa.ac_automa);

  return(num);
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <ja3 hash>[,<other info>]
 *
 */
int ndpi_load_malicious_ja3_file(struct ndpi_detection_module_struct *ndpi_str, const char *path) {
  char buffer[128], *line;
  FILE *fd;
  int len, num = 0;

  if(!ndpi_str || !path)
    return(-1);
  if(ndpi_str->malicious_ja3_hashmap == NULL && ndpi_hash_init(&ndpi_str->malicious_ja3_hashmap) != 0)
    return(-1);

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return(-1);
  }

  while(1) {
    char *comma;

    line = fgets(buffer, sizeof(buffer), fd);

    if(line == NULL)
      break;

    len = strlen(line);

    if((len <= 1) || (line[0] == '#'))
      continue;

    line[len - 1] = '\0';

    if((comma = strchr(line, ',')) != NULL)
      comma[0] = '\0';

    len = strlen(line);

    if(len != 32 /* size of MD5 hash */) {
      NDPI_LOG_ERR(ndpi_str, "Not a JA3 md5 hash: [%s]\n", line);
      continue;
    }

    if(ndpi_hash_add_entry(&ndpi_str->malicious_ja3_hashmap, line, len, NULL) == 0)
      num++;
  }

  fclose(fd);

  return(num);
}

/* ******************************************************************** */

/*
 * Format:
 *
 * <sha1 hash>
 * <other info>,<sha1 hash>
 * <other info>,<sha1 hash>[,<other info>[...]]
 *
 */
int ndpi_load_malicious_sha1_file(struct ndpi_detection_module_struct *ndpi_str, const char *path)
{
  char buffer[128];
  char *first_comma, *second_comma;
  FILE *fd;
  size_t i, len;
  int num = 0;

  if(!ndpi_str || !path)
    return(-1);
  if(ndpi_str->malicious_sha1_hashmap == NULL && ndpi_hash_init(&ndpi_str->malicious_sha1_hashmap) != 0)
    return(-1);

  fd = fopen(path, "r");

  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return -1;
  }

  while (fgets(buffer, sizeof(buffer), fd) != NULL) {
    len = strlen(buffer);

    if(len <= 1 || buffer[0] == '#')
      continue;

    first_comma = strchr(buffer, ',');
    if(first_comma != NULL) {
      first_comma++;
      second_comma = strchr(first_comma, ',');
      if(second_comma == NULL)
        second_comma = &buffer[len - 1];
    } else {
      first_comma = &buffer[0];
      second_comma = &buffer[len - 1];
    }

    second_comma[0] = '\0';
    if((second_comma - first_comma) != 40) {
      NDPI_LOG_ERR(ndpi_str, "Not a SSL certificate sha1 hash: [%s]\n", first_comma);
      continue;
    }

    for (i = 0; i < 40; ++i)
      first_comma[i] = toupper(first_comma[i]);

    if(ndpi_hash_add_entry(&ndpi_str->malicious_sha1_hashmap, first_comma, second_comma - first_comma, NULL) == 0)
      num++;
  }

  fclose(fd);

  return num;
}

/* ******************************************************************** */

/*
  Format:
  <tcp|udp>:<port>,<tcp|udp>:<port>,.....@<proto>

  Subprotocols Format:
  host:"<value>",host:"<value>",.....@<subproto>

  IP based Subprotocols Format (<value> is IP or CIDR):
  ip:<value>,ip:<value>,.....@<subproto>

  nBPF-based Filters
  nbpf:"<nBPF filter>@<proto>

  Example:
  tcp:80,tcp:3128@HTTP
  udp:139@NETBIOS

*/
int ndpi_load_protocols_file(struct ndpi_detection_module_struct *ndpi_str, const char *path) {
  int rc;
  FILE *fd;

  if(!ndpi_str || !path)
    return(-1);

  fd = fopen(path, "r");
  if(fd == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Unable to open file %s [%s]\n", path, strerror(errno));
    return -1;
  }

  rc = ndpi_load_protocols_file2(ndpi_str, fd);

  fclose(fd);

  return rc;
}

int ndpi_load_protocols_file2(struct ndpi_detection_module_struct *ndpi_str, FILE *fd) {
  char *buffer, *old_buffer;
  int chunk_len = 1024, buffer_len = chunk_len, old_buffer_len;
  int i;

  if(!ndpi_str || !fd)
    return -1;

  buffer = ndpi_malloc(buffer_len);
  if(buffer == NULL) {
    NDPI_LOG_ERR(ndpi_str, "Memory allocation failure\n");
    return -2;
  }

  while(1) {
    char *line = buffer;
    int line_len = buffer_len;

    while(((line = fgets(line, line_len, fd)) != NULL)
	  && strlen(line) > 0
	  && (line[strlen(line) - 1] != '\n')) {
      i = strlen(line);
      old_buffer = buffer;
      old_buffer_len = buffer_len;
      buffer_len += chunk_len;

      buffer = ndpi_realloc(old_buffer, old_buffer_len, buffer_len);
      if(buffer == NULL) {
	NDPI_LOG_ERR(ndpi_str, "Memory allocation failure\n");
	ndpi_free(old_buffer);
	return -2;
      }

      line = &buffer[i];
      line_len = chunk_len;
    } /* while */

    if(!line) /* safety check */
      break;

    i = strlen(buffer);
    if((i <= 1) || (buffer[0] == '#'))
      continue;
    else {
      buffer[i - 1] = '\0';
      i--;

      if((i > 0) && (buffer[i-1] == '\r'))
	buffer[i - 1] = '\0';

      if(buffer[0] == '\0')
	continue;
    }

    /* printf("Processing: \"%s\"\n", buffer); */

    if(ndpi_handle_rule(ndpi_str, buffer, 1) != 0)
      NDPI_LOG_INFO(ndpi_str, "Discraded rule '%s'\n", buffer);
  }

  ndpi_free(buffer);

  return 0;
}

/* ******************************************************************** */

/* ntop */
void ndpi_set_bitmask_protocol_detection(char *label, struct ndpi_detection_module_struct *ndpi_str,
                                         const u_int32_t idx,
                                         u_int16_t ndpi_protocol_id,
                                         void (*func)(struct ndpi_detection_module_struct *,
                                                      struct ndpi_flow_struct *flow),
                                         const NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask,
                                         u_int8_t b_save_bitmask_unknow, u_int8_t b_add_detection_bitmask) {
  /*
    Compare specify protocol bitmask with main detection bitmask
  */
  if(is_proto_enabled(ndpi_str, ndpi_protocol_id)) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    NDPI_LOG_DBG2(ndpi_str,
		  "[NDPI] ndpi_set_bitmask_protocol_detection: %s : [callback_buffer] idx= %u, [proto_defaults] "
		  "protocol_id=%u\n",
		  label, idx, ndpi_protocol_id);
#endif

    if(ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx != 0) {
      NDPI_LOG_DBG2(ndpi_str, "[NDPI] Internal error: protocol %s/%u has been already registered\n", label,
		    ndpi_protocol_id);
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    } else {
      NDPI_LOG_DBG2(ndpi_str, "[NDPI] Adding %s with protocol id %d\n", label, ndpi_protocol_id);
#endif
    }

    /*
      Set function and index protocol within proto_default structure for port protocol detection
      and callback_buffer function for DPI protocol detection
    */
    ndpi_str->proto_defaults[ndpi_protocol_id].protoIdx = idx;
    ndpi_str->proto_defaults[ndpi_protocol_id].func = ndpi_str->callback_buffer[idx].func = func;
    ndpi_str->callback_buffer[idx].ndpi_protocol_id = ndpi_protocol_id;

    /*
      Set ndpi_selection_bitmask for protocol
    */
    ndpi_str->callback_buffer[idx].ndpi_selection_bitmask = ndpi_selection_bitmask;

    /*
      Reset protocol detection bitmask via NDPI_PROTOCOL_UNKNOWN and than add specify protocol bitmast to callback
      buffer.
    */
    if(b_save_bitmask_unknow)
      NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, NDPI_PROTOCOL_UNKNOWN);
    if(b_add_detection_bitmask)
      NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_str->callback_buffer[idx].detection_bitmask, ndpi_protocol_id);

    NDPI_SAVE_AS_BITMASK(ndpi_str->callback_buffer[idx].excluded_protocol_bitmask, ndpi_protocol_id);
  } else {
      NDPI_LOG_DBG(ndpi_str, "[NDPI] Protocol %s/%u disabled\n", label, ndpi_protocol_id);
  }
}

/* ******************************************************************** */

static int ndpi_callback_init(struct ndpi_detection_module_struct *ndpi_str) {

  NDPI_PROTOCOL_BITMASK *detection_bitmask = &ndpi_str->detection_bitmask;
  struct ndpi_call_function_struct *all_cb = NULL;
  u_int32_t a = 0;

  if(ndpi_str->callback_buffer) return 0;

  ndpi_str->callback_buffer = ndpi_calloc(NDPI_MAX_SUPPORTED_PROTOCOLS+1,sizeof(struct ndpi_call_function_struct));
  if(!ndpi_str->callback_buffer) return 1;

  /* set this here to zero to be interrupt safe */
  ndpi_str->callback_buffer_size = 0;

  /* HTTP */
  init_http_dissector(ndpi_str, &a);

  /* STARCRAFT */
  init_starcraft_dissector(ndpi_str, &a);

  /* TLS+DTLS */
  init_tls_dissector(ndpi_str, &a);

  /* RTP */
  init_rtp_dissector(ndpi_str, &a);

  /* RTSP */
  init_rtsp_dissector(ndpi_str, &a);

  /* RDP */
  init_rdp_dissector(ndpi_str, &a);

  /* STUN */
  init_stun_dissector(ndpi_str, &a);

  /* SIP */
  init_sip_dissector(ndpi_str, &a);

  /* IMO */
  init_imo_dissector(ndpi_str, &a);

  /* Teredo */
  init_teredo_dissector(ndpi_str, &a);

  /* EDONKEY */
  init_edonkey_dissector(ndpi_str, &a);

  /* GNUTELLA */
  init_gnutella_dissector(ndpi_str, &a);

  /* NATS */
  init_nats_dissector(ndpi_str, &a);

  /* SOCKS */
  init_socks_dissector(ndpi_str, &a);

  /* IRC */
  init_irc_dissector(ndpi_str, &a);

  /* JABBER */
  init_jabber_dissector(ndpi_str, &a);

  /* MAIL_POP */
  init_mail_pop_dissector(ndpi_str, &a);

  /* MAIL_IMAP */
  init_mail_imap_dissector(ndpi_str, &a);

  /* MAIL_SMTP */
  init_mail_smtp_dissector(ndpi_str, &a);

  /* USENET */
  init_usenet_dissector(ndpi_str, &a);

  /* DNS */
  init_dns_dissector(ndpi_str, &a);

  /* VMWARE */
  init_vmware_dissector(ndpi_str, &a);

  /* NON_TCP_UDP */
  init_non_tcp_udp_dissector(ndpi_str, &a);

  /* TVUPLAYER */
  init_tvuplayer_dissector(ndpi_str, &a);

  /* PPSTREAM */
  init_ppstream_dissector(ndpi_str, &a);

  /* IAX */
  init_iax_dissector(ndpi_str, &a);

  /* Media Gateway Control Protocol */
  init_mgcp_dissector(ndpi_str, &a);

  /* ZATTOO */
  init_zattoo_dissector(ndpi_str, &a);

  /* QQ */
  init_qq_dissector(ndpi_str, &a);

  /* SSH */
  init_ssh_dissector(ndpi_str, &a);

  /* VNC */
  init_vnc_dissector(ndpi_str, &a);

  /* VXLAN */
  init_vxlan_dissector(ndpi_str, &a);

  /* TEAMVIEWER */
  init_teamviewer_dissector(ndpi_str, &a);

  /* DHCP */
  init_dhcp_dissector(ndpi_str, &a);

  /* STEAM */
  init_steam_dissector(ndpi_str, &a);

  /* HALFLIFE2 */
  init_halflife2_dissector(ndpi_str, &a);

  /* XBOX */
  init_xbox_dissector(ndpi_str, &a);

  /* SMB */
  init_smb_dissector(ndpi_str, &a);

  /* MINING */
  init_mining_dissector(ndpi_str, &a);

  /* TELNET */
  init_telnet_dissector(ndpi_str, &a);

  /* NTP */
  init_ntp_dissector(ndpi_str, &a);

  /* NFS */
  init_nfs_dissector(ndpi_str, &a);

  /* SSDP */
  init_ssdp_dissector(ndpi_str, &a);

  /* WORLD_OF_WARCRAFT */
  init_world_of_warcraft_dissector(ndpi_str, &a);

  /* POSTGRES */
  init_postgres_dissector(ndpi_str, &a);

  /* MYSQL */
  init_mysql_dissector(ndpi_str, &a);

  /* BGP */
  init_bgp_dissector(ndpi_str, &a);

  /* SNMP */
  init_snmp_dissector(ndpi_str, &a);

  /* KONTIKI */
  init_kontiki_dissector(ndpi_str, &a);

  /* ICECAST */
  init_icecast_dissector(ndpi_str, &a);

  /* KERBEROS */
  init_kerberos_dissector(ndpi_str, &a);

  /* SYSLOG */
  init_syslog_dissector(ndpi_str, &a);

  /* NETBIOS */
  init_netbios_dissector(ndpi_str, &a);

  /* IPP */
  init_ipp_dissector(ndpi_str, &a);

  /* LDAP */
  init_ldap_dissector(ndpi_str, &a);

  /* WARCRAFT3 */
  init_warcraft3_dissector(ndpi_str, &a);

  /* XDMCP */
  init_xdmcp_dissector(ndpi_str, &a);

  /* TFTP */
  init_tftp_dissector(ndpi_str, &a);

  /* MSSQL_TDS */
  init_mssql_tds_dissector(ndpi_str, &a);

  /* PPTP */
  init_pptp_dissector(ndpi_str, &a);

  /* DHCPV6 */
  init_dhcpv6_dissector(ndpi_str, &a);

  /* AFP */
  init_afp_dissector(ndpi_str, &a);

  /* check_mk */
  init_checkmk_dissector(ndpi_str, &a);

  /* cpha */
  init_cpha_dissector(ndpi_str, &a);

  /* MAPLESTORY */
  init_maplestory_dissector(ndpi_str, &a);

  /* DOFUS */
  init_dofus_dissector(ndpi_str, &a);

  /* WORLD_OF_KUNG_FU */
  init_world_of_kung_fu_dissector(ndpi_str, &a);

  /* CROSSIFIRE */
  init_crossfire_dissector(ndpi_str, &a);

  /* GUILDWARS */
  init_guildwars_dissector(ndpi_str, &a);

  /* ARMAGETRON */
  init_armagetron_dissector(ndpi_str, &a);

  /* DROPBOX */
  init_dropbox_dissector(ndpi_str, &a);

  /* SPOTIFY */
  init_spotify_dissector(ndpi_str, &a);

  /* RADIUS */
  init_radius_dissector(ndpi_str, &a);

  /* CITRIX */
  init_citrix_dissector(ndpi_str, &a);

  /* LOTUS_NOTES */
  init_lotus_notes_dissector(ndpi_str, &a);

  /* GTP */
  init_gtp_dissector(ndpi_str, &a);

  /* HSRP */
  init_hsrp_dissector(ndpi_str, &a);

  /* DCERPC */
  init_dcerpc_dissector(ndpi_str, &a);

  /* NETFLOW */
  init_netflow_dissector(ndpi_str, &a);

  /* SFLOW */
  init_sflow_dissector(ndpi_str, &a);

  /* H323 */
  init_h323_dissector(ndpi_str, &a);

  /* OPENVPN */
  init_openvpn_dissector(ndpi_str, &a);

  /* NOE */
  init_noe_dissector(ndpi_str, &a);

  /* CISCOVPN */
  init_ciscovpn_dissector(ndpi_str, &a);

  /* TEAMSPEAK */
  init_teamspeak_dissector(ndpi_str, &a);

  /* SKINNY */
  init_skinny_dissector(ndpi_str, &a);

  /* RTCP */
  init_rtcp_dissector(ndpi_str, &a);

  /* RSYNC */
  init_rsync_dissector(ndpi_str, &a);

  /* WHOIS_DAS */
  init_whois_das_dissector(ndpi_str, &a);

  /* ORACLE */
  init_oracle_dissector(ndpi_str, &a);

  /* CORBA */
  init_corba_dissector(ndpi_str, &a);

  /* RTMP */
  init_rtmp_dissector(ndpi_str, &a);

  /* FTP_CONTROL */
  init_ftp_control_dissector(ndpi_str, &a);

  /* FTP_DATA */
  init_ftp_data_dissector(ndpi_str, &a);

  /* MEGACO */
  init_megaco_dissector(ndpi_str, &a);

  /* REDIS */
  init_redis_dissector(ndpi_str, &a);

  /* VHUA */
  init_vhua_dissector(ndpi_str, &a);

  /* ZMQ */
  init_zmq_dissector(ndpi_str, &a);

  /* TELEGRAM */
  init_telegram_dissector(ndpi_str, &a);

  /* QUIC */
  init_quic_dissector(ndpi_str, &a);

  /* DIAMETER */
  init_diameter_dissector(ndpi_str, &a);

  /* APPLE_PUSH */
  init_apple_push_dissector(ndpi_str, &a);

  /* EAQ */
  init_eaq_dissector(ndpi_str, &a);

  /* KAKAOTALK_VOICE */
  init_kakaotalk_voice_dissector(ndpi_str, &a);

  /* MPEGTS */
  init_mpegts_dissector(ndpi_str, &a);

  /* UBNTAC2 */
  init_ubntac2_dissector(ndpi_str, &a);

  /* COAP */
  init_coap_dissector(ndpi_str, &a);

  /* MQTT */
  init_mqtt_dissector(ndpi_str, &a);

  /* SOME/IP */
  init_someip_dissector(ndpi_str, &a);

  /* RX */
  init_rx_dissector(ndpi_str, &a);

  /* GIT */
  init_git_dissector(ndpi_str, &a);

  /* DRDA */
  init_drda_dissector(ndpi_str, &a);

  /* BJNP */
  init_bjnp_dissector(ndpi_str, &a);

  /* SMPP */
  init_smpp_dissector(ndpi_str, &a);

  /* TINC */
  init_tinc_dissector(ndpi_str, &a);

  /* FIX */
  init_fix_dissector(ndpi_str, &a);

  /* NINTENDO */
  init_nintendo_dissector(ndpi_str, &a);

  /* MODBUS */
  init_modbus_dissector(ndpi_str, &a);

  /* CAPWAP */
  init_capwap_dissector(ndpi_str, &a);

  /* ZABBIX */
  init_zabbix_dissector(ndpi_str, &a);

  /*** Put false-positive sensitive protocols at the end ***/

  /* VIBER */
  init_viber_dissector(ndpi_str, &a);

  /* SKYPE */
  init_skype_dissector(ndpi_str, &a);

  /* BITTORRENT */
  init_bittorrent_dissector(ndpi_str, &a);

  /* WHATSAPP */
  init_whatsapp_dissector(ndpi_str, &a);

  /* OOKLA */
  init_ookla_dissector(ndpi_str, &a);

  /* AMQP */
  init_amqp_dissector(ndpi_str, &a);

  /* CSGO */
  init_csgo_dissector(ndpi_str, &a);

  /* LISP */
  init_lisp_dissector(ndpi_str, &a);

  /* AJP */
  init_ajp_dissector(ndpi_str, &a);

  /* Memcached */
  init_memcached_dissector(ndpi_str, &a);

  /* Nest Log Sink */
  init_nest_log_sink_dissector(ndpi_str, &a);

  /* WireGuard VPN */
  init_wireguard_dissector(ndpi_str, &a);

  /* Amazon_Video */
  init_amazon_video_dissector(ndpi_str, &a);

  /* S7 comm */
  init_s7comm_dissector(ndpi_str, &a);

  /* IEC 60870-5-104 */
  init_104_dissector(ndpi_str, &a);

  /* DNP3 */
  init_dnp3_dissector(ndpi_str, &a);

  /* WEBSOCKET */
  init_websocket_dissector(ndpi_str, &a);

  /* SOAP */
  init_soap_dissector(ndpi_str, &a);

  /* DNScrypt */
  init_dnscrypt_dissector(ndpi_str, &a);

  /* MongoDB */
  init_mongodb_dissector(ndpi_str, &a);

  /* AmongUS */
  init_among_us_dissector(ndpi_str, &a);

  /* HP Virtual Machine Group Management */
  init_hpvirtgrp_dissector(ndpi_str, &a);

  /* Genshin Impact */
  init_genshin_impact_dissector(ndpi_str, &a);

  /* Z39.50 international standard client–server, application layer communications protocol */
  init_z3950_dissector(ndpi_str, &a);

  /* AVAST SecureDNS */
  init_avast_securedns_dissector(ndpi_str, &a);

  /* Cassandra */
  init_cassandra_dissector(ndpi_str, &a);

  /* EthernetIP */
  init_ethernet_ip_dissector(ndpi_str, &a);

  /* WSD */
  init_wsd_dissector(ndpi_str, &a);

  /* TocaBoca */
  init_toca_boca_dissector(ndpi_str, &a);

  /* SD-RTN Software Defined Real-time Network */
  init_sd_rtn_dissector(ndpi_str, &a);

  /* RakNet */
  init_raknet_dissector(ndpi_str, &a);

  /* Xiaomi */
  init_xiaomi_dissector(ndpi_str, &a);

  /* MpegDash */
  init_mpegdash_dissector(ndpi_str, &a);

  /* RSH */
  init_rsh_dissector(ndpi_str, &a);

  /* IPsec */
  init_ipsec_dissector(ndpi_str, &a);

  /* collectd */
  init_collectd_dissector(ndpi_str, &a);

  /* i3D */
  init_i3d_dissector(ndpi_str, &a);

  /* RiotGames */
  init_riotgames_dissector(ndpi_str, &a);

  /* UltraSurf */
  init_ultrasurf_dissector(ndpi_str, &a);

  /* Threema */
  init_threema_dissector(ndpi_str, &a);

  /* AliCloud */
  init_alicloud_dissector(ndpi_str, &a);

  /* AVAST */
  init_avast_dissector(ndpi_str, &a);

  /* Softether */
  init_softether_dissector(ndpi_str, &a);

  /* Activision */
  init_activision_dissector(ndpi_str, &a);

  /* Discord */
  init_discord_dissector(ndpi_str, &a);

  /* TiVoConnect */
  init_tivoconnect_dissector(ndpi_str, &a);

  /* Kismet */
  init_kismet_dissector(ndpi_str, &a);

  /* FastCGI */
  init_fastcgi_dissector(ndpi_str, &a);

  /* NATPMP */
  init_natpmp_dissector(ndpi_str, &a);

  /* Syncthing */
  init_syncthing_dissector(ndpi_str, &a);

  /* CryNetwork */
  init_crynet_dissector(ndpi_str, &a);

  /* Line voip */
  init_line_dissector(ndpi_str, &a);

  /* Munin */
  init_munin_dissector(ndpi_str, &a);

  /* Elasticsearch */
  init_elasticsearch_dissector(ndpi_str, &a);

  /* TUYA LP */
  init_tuya_lp_dissector(ndpi_str, &a);

  /* TPLINK_SHP */
  init_tplink_shp_dissector(ndpi_str, &a);

  /* Meraki Cloud */
  init_merakicloud_dissector(ndpi_str, &a);

  /* Tailscale */
  init_tailscale_dissector(ndpi_str, &a);

  /* Source Engine */
  init_source_engine_dissector(ndpi_str, &a);

  /* BACnet */
  init_bacnet_dissector(ndpi_str, &a);

  /* OICQ */
  init_oicq_dissector(ndpi_str, &a);

  /* Heroes of the Storm */
  init_hots_dissector(ndpi_str, &a);

  /* EpicGames */
  init_epicgames_dissector(ndpi_str, &a);

  /*BITCOIN*/
  init_bitcoin_dissector(ndpi_str, &a);

  /* Apache Thrift */
  init_apache_thrift_dissector(ndpi_str, &a);

  /* Service Location Protocol */
  init_slp_dissector(ndpi_str, &a);

#ifdef CUSTOM_NDPI_PROTOCOLS
#include "../../../nDPI-custom/custom_ndpi_main_init.c"
#endif

  /* ----------------------------------------------------------------- */

  ndpi_str->callback_buffer_size = a;

  /* Resize callback_buffer */
  all_cb = ndpi_calloc(a+1,sizeof(struct ndpi_call_function_struct));
  if(all_cb) {
    memcpy((char *)all_cb,(char *)ndpi_str->callback_buffer, (a+1) * sizeof(struct ndpi_call_function_struct));
    ndpi_free(ndpi_str->callback_buffer);
    ndpi_str->callback_buffer = all_cb;
  }

  NDPI_LOG_DBG2(ndpi_str, "callback_buffer_size is %u\n", ndpi_str->callback_buffer_size);
  /* Calculating the size of an array for callback functions */
  ndpi_enabled_callbacks_init(ndpi_str,detection_bitmask,1);
  all_cb = ndpi_calloc(ndpi_str->callback_buffer_size_tcp_payload +
		       ndpi_str->callback_buffer_size_tcp_no_payload +
		       ndpi_str->callback_buffer_size_udp +
		       ndpi_str->callback_buffer_size_non_tcp_udp,
		       sizeof(struct ndpi_call_function_struct));
  if(!all_cb) return 1;

  ndpi_str->callback_buffer_tcp_payload = all_cb;
  all_cb += ndpi_str->callback_buffer_size_tcp_payload;
  ndpi_str->callback_buffer_tcp_no_payload = all_cb;
  all_cb += ndpi_str->callback_buffer_size_tcp_no_payload;
  ndpi_str->callback_buffer_udp = all_cb;
  all_cb += ndpi_str->callback_buffer_size_udp;
  ndpi_str->callback_buffer_non_tcp_udp = all_cb;

  ndpi_enabled_callbacks_init(ndpi_str,detection_bitmask,0);

  /*   When the module ends, it is necessary to free the memory ndpi_str->callback_buffer and
       ndpi_str->callback_buffer_tcp_payload  */

  return 0;
}

/* ******************************************************************** */

static inline int ndpi_proto_cb_tcp_payload(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
              NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0;
}

/* ******************************************************************** */

static inline int ndpi_proto_cb_tcp_nopayload(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
              NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0
	   && (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	       NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0;
}

/* ******************************************************************** */

static inline int ndpi_proto_cb_udp(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC)) != 0;
}

/* ******************************************************************** */

static inline int ndpi_proto_cb_other(const struct ndpi_detection_module_struct *ndpi_str, uint32_t idx) {
    return (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	     (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP |
	      NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)) == 0
	   ||
             (ndpi_str->callback_buffer[idx].ndpi_selection_bitmask &
	       NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC) != 0;
}

/* ******************************************************************** */

static void ndpi_enabled_callbacks_init(struct ndpi_detection_module_struct *ndpi_str,
					const NDPI_PROTOCOL_BITMASK *dbm, int count_only) {
  uint32_t a;

  /* now build the specific buffer for tcp, udp and non_tcp_udp */
  ndpi_str->callback_buffer_size_tcp_payload = 0;
  ndpi_str->callback_buffer_size_tcp_no_payload = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_tcp_payload(ndpi_str,a)) continue;
    if(!count_only) {
      if(_ndpi_debug_callbacks)
	  NDPI_LOG_DBG2(ndpi_str, "callback_buffer_tcp_payload, adding buffer %u as entry %u\n", a,
		        ndpi_str->callback_buffer_size_tcp_payload);
          memcpy(&ndpi_str->callback_buffer_tcp_payload[ndpi_str->callback_buffer_size_tcp_payload],
	         &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_tcp_payload++;
  }
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_tcp_nopayload(ndpi_str,a)) continue;
    if(!count_only) {
      if(_ndpi_debug_callbacks)
	  NDPI_LOG_DBG2( ndpi_str,
                        "\tcallback_buffer_tcp_no_payload, additional adding buffer %u to no_payload process\n", a);
	  memcpy(&ndpi_str->callback_buffer_tcp_no_payload[ndpi_str->callback_buffer_size_tcp_no_payload],
	         &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_tcp_no_payload++;
  }

  ndpi_str->callback_buffer_size_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_udp(ndpi_str,a)) continue;
    if(!count_only) {
      if(_ndpi_debug_callbacks)
	 NDPI_LOG_DBG2(ndpi_str, "callback_buffer_size_udp: adding buffer : %u\n", a);

      memcpy(&ndpi_str->callback_buffer_udp[ndpi_str->callback_buffer_size_udp], &ndpi_str->callback_buffer[a],
	     sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_udp++;
  }

  ndpi_str->callback_buffer_size_non_tcp_udp = 0;
  for(a = 0; a < ndpi_str->callback_buffer_size; a++) {
    if(!NDPI_ISSET(dbm,ndpi_str->callback_buffer[a].ndpi_protocol_id)) continue;
    if(!ndpi_proto_cb_other(ndpi_str,a)) continue;
    if(!count_only) {
      if(_ndpi_debug_callbacks)
	NDPI_LOG_DBG2(ndpi_str, "callback_buffer_non_tcp_udp: adding buffer : %u\n", a);

      memcpy(&ndpi_str->callback_buffer_non_tcp_udp[ndpi_str->callback_buffer_size_non_tcp_udp],
	     &ndpi_str->callback_buffer[a], sizeof(struct ndpi_call_function_struct));
    }
    ndpi_str->callback_buffer_size_non_tcp_udp++;
  }
}

/* ******************************************************************** */

/* handle extension headers in IPv6 packets
 * arguments:
 *  l3len: the packet length excluding the IPv6 header
 * 	l4ptr: pointer to the byte following the initial IPv6 header
 * 	l4len: the length of the IPv6 packet parsed from the IPv6 header
 * 	nxt_hdr: next header value from the IPv6 header
 * result:
 * 	l4ptr: pointer to the start of the actual layer 4 header
 * 	l4len: length of the actual layer 4 header
 * 	nxt_hdr: first byte of the layer 4 packet
 * returns 0 upon success and 1 upon failure
 */
int ndpi_handle_ipv6_extension_headers(u_int16_t l3len, const u_int8_t **l4ptr,
                                       u_int16_t *l4len, u_int8_t *nxt_hdr) {
  while(l3len > 1 && (*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len, frag_offset;

    // no next header
    if(*nxt_hdr == 59) {
      return(1);
    }

    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return(1);
      }

      if(l3len < 5) {
        return 1;
      }
      l3len -= 5;

      *nxt_hdr = (*l4ptr)[0];
      frag_offset = ntohs(*(u_int16_t *)((*l4ptr) + 2)) >> 3;
      // Handle ipv6 fragments as the ipv4 ones: keep the first fragment, drop the others
      if(frag_offset != 0)
          return(1);
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }

    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    if(*l4len < 2) {
      return(1);
    }

    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(ehdr_len > l3len) {
      return 1;
    }
    l3len -= ehdr_len;

    if(*l4len < ehdr_len) {
      return(1);
    }

    *nxt_hdr = (*l4ptr)[0];

    if(*l4len < ehdr_len)
      return(1);

    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }

  return(0);
}

/* ******************************************************************** */

/* Used by dns.c */
u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize) {
  /*
    returned value:
    0: fragmented
    1: not fragmented
  */
  //#ifdef REQUIRE_FULL_PACKETS

  if(iph->protocol == IPPROTO_UDP) {
    if((ipsize < iph->ihl * 4)
       || (ipsize < ntohs(iph->tot_len))
       || (ntohs(iph->tot_len) < iph->ihl * 4)
       || (iph->frag_off & htons(0x1FFF)) != 0) {
      return(0);
    }
  }
  //#endif

  return(1);
}

/* ******************************************************************** */

/*
  extract the l4 payload, if available
  returned value:
  0: ok, extracted
  1: packet too small
  2,3: fragmented, ....
  else
  0: ok, extracted
  1: error or not available
*/
static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_str, const u_int8_t *l3,
                                               u_int16_t l3_len, const u_int8_t **l4_return, u_int16_t *l4_len_return,
                                               u_int8_t *l4_protocol_return, u_int32_t flags) {
  const struct ndpi_iphdr *iph = NULL;
  const struct ndpi_ipv6hdr *iph_v6 = NULL;
  u_int16_t l4len = 0;
  const u_int8_t *l4ptr = NULL;
  u_int8_t l4protocol = 0;

  if(l3 == NULL || l3_len < sizeof(struct ndpi_iphdr))
    return(1);

  if((iph = (const struct ndpi_iphdr *) l3) == NULL)
    return(1);

  if(iph->version == IPVERSION && iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  }
  else if(iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr)) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    iph_v6 = (const struct ndpi_ipv6hdr *) l3;
    iph = NULL;
  } else {
    return(1);
  }

  if((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header found but excluded by flag\n");
    return(1);
  } else if((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header found but excluded by flag\n");
    return(1);
  }

  /* 0: fragmented; 1: not fragmented */
  if(iph != NULL && ndpi_iph_is_valid_and_not_fragmented(iph, l3_len)) {
    u_int16_t len = ndpi_min(ntohs(iph->tot_len), l3_len);
    u_int16_t hlen = (iph->ihl * 4);

    l4ptr = (((const u_int8_t *) iph) + iph->ihl * 4);

    if(len == 0)
      len = l3_len;

    l4len = (len > hlen) ? (len - hlen) : 0;
    l4protocol = iph->protocol;
  }

  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->ip6_hdr.ip6_un1_plen)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->ip6_hdr.ip6_un1_plen);
    l4protocol = iph_v6->ip6_hdr.ip6_un1_nxt;

    // we need to handle IPv6 extension headers if present
    if(ndpi_handle_ipv6_extension_headers(l3_len - sizeof(struct ndpi_ipv6hdr), &l4ptr, &l4len, &l4protocol) != 0) {
      return(1);
    }

  } else {
    return(1);
  }

  if(l4_return != NULL) {
    *l4_return = l4ptr;
  }

  if(l4_len_return != NULL) {
    *l4_len_return = l4len;
  }

  if(l4_protocol_return != NULL) {
    *l4_protocol_return = l4protocol;
  }

  return(0);
}

/* ****************************************************** */

void ndpi_free_flow_data(struct ndpi_flow_struct* flow) {
  if(flow) {
    if(flow->num_risk_infos) {
      u_int i;

      for(i=0; i<flow->num_risk_infos; i++)
	ndpi_free(flow->risk_infos[i].info);
    }

    if(flow->http.url)
      ndpi_free(flow->http.url);

    if(flow->http.content_type)
      ndpi_free(flow->http.content_type);

    if(flow->http.request_content_type)
      ndpi_free(flow->http.request_content_type);

    if(flow->http.user_agent)
      ndpi_free(flow->http.user_agent);

    if(flow->http.nat_ip)
      ndpi_free(flow->http.nat_ip);

    if(flow->http.detected_os)
      ndpi_free(flow->http.detected_os);

    if(flow->http.server)
      ndpi_free(flow->http.server);

    if(flow->http.filename)
      ndpi_free(flow->http.filename);

    if(flow->kerberos_buf.pktbuf)
      ndpi_free(flow->kerberos_buf.pktbuf);

   if(flow_is_proto(flow, NDPI_PROTOCOL_QUIC) ||
       flow_is_proto(flow, NDPI_PROTOCOL_TLS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_DTLS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_SMTPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_POPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_MAIL_IMAPS) ||
       flow_is_proto(flow, NDPI_PROTOCOL_FTPS)) {
      if(flow->protos.tls_quic.server_names)
	ndpi_free(flow->protos.tls_quic.server_names);

      if(flow->protos.tls_quic.advertised_alpns)
	ndpi_free(flow->protos.tls_quic.advertised_alpns);

      if(flow->protos.tls_quic.negotiated_alpn)
	ndpi_free(flow->protos.tls_quic.negotiated_alpn);

      if(flow->protos.tls_quic.tls_supported_versions)
	ndpi_free(flow->protos.tls_quic.tls_supported_versions);

      if(flow->protos.tls_quic.issuerDN)
	ndpi_free(flow->protos.tls_quic.issuerDN);

      if(flow->protos.tls_quic.subjectDN)
	ndpi_free(flow->protos.tls_quic.subjectDN);

      if(flow->protos.tls_quic.encrypted_sni.esni)
	ndpi_free(flow->protos.tls_quic.encrypted_sni.esni);
    }

    if(flow->tls_quic.message[0].buffer)
      ndpi_free(flow->tls_quic.message[0].buffer);
    if(flow->tls_quic.message[1].buffer)
      ndpi_free(flow->tls_quic.message[1].buffer);

    if(flow->l4_proto == IPPROTO_UDP) {
      if(flow->l4.udp.quic_reasm_buf)
        ndpi_free(flow->l4.udp.quic_reasm_buf);
      if(flow->l4.udp.quic_reasm_buf_bitmap)
        ndpi_free(flow->l4.udp.quic_reasm_buf_bitmap);
    }

    if(flow->flow_payload != NULL)
      ndpi_free(flow->flow_payload);
  }
}

/* ************************************************ */

int ndpi_set_protocol_detection_bitmask2(struct ndpi_detection_module_struct *ndpi_str,
                                          const NDPI_PROTOCOL_BITMASK *dbm) {
  if(!ndpi_str)
    return -1;

  NDPI_BITMASK_SET(ndpi_str->detection_bitmask, *dbm);

  ndpi_init_protocol_defaults(ndpi_str);

  ndpi_enabled_callbacks_init(ndpi_str,dbm,0);

  if(ndpi_callback_init(ndpi_str)) {
    NDPI_LOG_ERR(ndpi_str, "[NDPI] Error allocating callbacks\n");
    return -1;
  }
  return 0;
}

/* ************************************************ */

static int ndpi_init_packet(struct ndpi_detection_module_struct *ndpi_str,
			    struct ndpi_flow_struct *flow,
			    const u_int64_t current_time_ms,
			    const unsigned char *packet_data,
			    unsigned short packetlen,
			    const struct ndpi_flow_input_info *input_info) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  const struct ndpi_iphdr *decaps_iph = NULL;
  u_int16_t l3len;
  u_int16_t l4len, l4_packet_len;
  const u_int8_t *l4ptr;
  u_int8_t l4protocol;
  u_int8_t l4_result;

  if(!flow)
    return(1);

  /* need at least 20 bytes for ip header */
  if(packetlen < 20)
    return 1;

  packet->current_time_ms = current_time_ms;

  ndpi_str->input_info = input_info;

  packet->iph = (const struct ndpi_iphdr *)packet_data;

  /* reset payload_packet_len, will be set if ipv4 tcp or udp */
  packet->payload = NULL;
  packet->payload_packet_len = 0;
  packet->l3_packet_len = packetlen;

  packet->tcp = NULL, packet->udp = NULL;
  packet->generic_l4_ptr = NULL;
  packet->iphv6 = NULL;

  l3len = packet->l3_packet_len;

  ndpi_reset_packet_line_info(packet);
  packet->packet_lines_parsed_complete = 0;
  packet->http_check_content = 0;

  if(packet->iph != NULL)
    decaps_iph = packet->iph;

  if(decaps_iph && decaps_iph->version == IPVERSION && decaps_iph->ihl >= 5) {
    NDPI_LOG_DBG2(ndpi_str, "ipv4 header\n");
  } else if(decaps_iph && decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
	    (ndpi_str->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0) {
    NDPI_LOG_DBG2(ndpi_str, "ipv6 header\n");
    packet->iphv6 = (struct ndpi_ipv6hdr *)packet->iph;
    packet->iph = NULL;
  } else {
    packet->iph = NULL;
    return(1);
  }

  /* needed:
   *  - unfragmented packets
   *  - ip header <= packet len
   *  - ip total length >= packet len
   */

  l4ptr = NULL;
  l4len = 0;
  l4protocol = 0;

  l4_result =
    ndpi_detection_get_l4_internal(ndpi_str, (const u_int8_t *) decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

  if(l4_result != 0) {
    return(1);
  }

  l4_packet_len = l4len;
  flow->l4_proto = l4protocol;

  /* TCP / UDP detection */
  if(l4protocol == IPPROTO_TCP) {
    if(l4_packet_len < 20 /* min size of tcp */)
      return(1);

    /* tcp */
    packet->tcp = (struct ndpi_tcphdr *) l4ptr;
    if(l4_packet_len >= packet->tcp->doff * 4) {
      packet->payload_packet_len = l4_packet_len - packet->tcp->doff * 4;
      packet->payload = ((u_int8_t *) packet->tcp) + (packet->tcp->doff * 4);

      /* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
      if(packet->tcp->syn != 0 && packet->tcp->ack == 0 && flow->init_finished != 0 &&
	 flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	u_int16_t guessed_protocol_id, guessed_protocol_id_by_ip;
	u_int16_t packet_direction_counter[2];
        u_int8_t num_processed_pkts;

#define flow_save(a) a = flow->a
#define flow_restore(a) flow->a = a

	flow_save(packet_direction_counter[0]);
	flow_save(packet_direction_counter[1]);
	flow_save(num_processed_pkts);
	flow_save(guessed_protocol_id);
	flow_save(guessed_protocol_id_by_ip);

        ndpi_free_flow_data(flow);
        memset(flow, 0, sizeof(*(flow)));

        /* Restore pointers */
        flow->l4_proto = IPPROTO_TCP;

	flow_restore(packet_direction_counter[0]);
	flow_restore(packet_direction_counter[1]);
	flow_restore(num_processed_pkts);
	flow_restore(guessed_protocol_id);
	flow_restore(guessed_protocol_id_by_ip);

#undef flow_save
#undef flow_restore

        NDPI_LOG_DBG(ndpi_str, "tcp syn packet for unknown protocol, reset detection state\n");
      }
    } else {
      /* tcp header not complete */
      return(1);
    }
  } else if(l4protocol == IPPROTO_UDP) {
    if(l4_packet_len < 8 /* size of udp */)
      return(1);
    packet->udp = (struct ndpi_udphdr *) l4ptr;
    packet->payload_packet_len = l4_packet_len - 8;
    packet->payload = ((u_int8_t *) packet->udp) + 8;
  } else if((l4protocol == IPPROTO_ICMP) || (l4protocol == IPPROTO_ICMPV6)) {
    if((l4protocol == IPPROTO_ICMP && l4_packet_len < sizeof(struct ndpi_icmphdr)) ||
       (l4protocol == IPPROTO_ICMPV6 && l4_packet_len < sizeof(struct ndpi_icmp6hdr)))
      return(1);
    packet->payload = ((u_int8_t *) l4ptr);
    packet->payload_packet_len = l4_packet_len;
  } else {
    packet->generic_l4_ptr = l4ptr;
  }

  return(0);
}

/* ************************************************ */

static u_int8_t ndpi_is_multi_or_broadcast(struct ndpi_packet_struct *packet) {

  if(packet->iph) {
    /* IPv4 */
    u_int32_t daddr = ntohl(packet->iph->daddr);

    if(((daddr & 0xE0000000) == 0xE0000000 /* multicast */)
       || ((daddr & 0x000000FF) == 0x000000FF /* last byte is 0xFF, not super correct, but a good approximation */)
       || ((daddr & 0x000000FF) == 0x00000000 /* last byte is 0x00, not super correct, but a good approximation */)
       || (daddr == 0xFFFFFFFF))
      return(1);
  } else if(packet->iphv6) {
    /* IPv6 */

    if((ntohl(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0]) & 0xFF000000) == 0xFF000000)
      return(1);
  }

  return(0);
}

/* ************************************************ */

static int fully_enc_heuristic(struct ndpi_detection_module_struct *ndpi_str,
                               struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  struct ndpi_popcount popcount;
  float ratio;
  unsigned int i, len, cnt, cnt_consecutives = 0;

  if(flow->l4_proto == IPPROTO_TCP &&
     ndpi_seen_flow_beginning(flow)) {
    /* See original paper, Algorithm 1, for the reference numbers */

    /* Ex1 */
    ndpi_popcount_init(&popcount);
    ndpi_popcount_count(&popcount, packet->payload, packet->payload_packet_len);
    ratio = (float)popcount.pop_count / (float)popcount.tot_bytes_count;
    if(ratio <= 3.4 || ratio >= 4.6) {
      return 0;
    }

    /* Ex2 */
    len = ndpi_min(6, packet->payload_packet_len);
    cnt = 0;
    for(i = 0; i < len; i++) {
      if(ndpi_isprint(packet->payload[i]))
        cnt += 1;
    }
    if(cnt == len) {
      return 0;
    }

    /* Ex3 */
    cnt = 0;
    for(i = 0; i < packet->payload_packet_len; i++) {
      if(ndpi_isprint(packet->payload[i])) {
        cnt += 1;
        cnt_consecutives += 1;
        if(cnt_consecutives >= 20) { /* Ex4 */
          return 0;;
        }
      } else {
        cnt_consecutives = 0;
      }
    }
    if((float)cnt / packet->payload_packet_len > 0.5) {
      return 0;
    }

    return 1;
  }
  return 0;
}

/* ************************************************ */

static int tcp_ack_padding(struct ndpi_packet_struct *packet) {
  const struct ndpi_tcphdr *tcph = packet->tcp;
  if(tcph && tcph->ack && !tcph->psh &&
     packet->payload_packet_len < 8 &&
     packet->payload_packet_len > 1 /* To avoid TCP keep-alives */) {
    int i;
    for(i = 0; i < packet->payload_packet_len; i++)
      if(packet->payload[i] != 0)
        return 0;
    return 1;
  }
  return 0;
}

void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_str,
			      struct ndpi_flow_struct *flow) {
  if(!flow) {
    return;
  } else {
    /* const for gcc code optimization and cleaner code */
    struct ndpi_packet_struct *packet = &ndpi_str->packet;
    const struct ndpi_iphdr *iph = packet->iph;
    const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
    const struct ndpi_tcphdr *tcph = packet->tcp;
    const struct ndpi_udphdr *udph = packet->udp;

    if(ndpi_str->max_payload_track_len > 0 && packet->payload_packet_len > 0) {
      /* printf("LEN: %u [%s]\n", packet->payload_packet_len, packet->payload); */

      if(flow->flow_payload == NULL)
	flow->flow_payload = (char*)ndpi_malloc(ndpi_str->max_payload_track_len + 1);

      if(flow->flow_payload != NULL)  {
	u_int i;

	for(i=0; (i<packet->payload_packet_len)
	      && (flow->flow_payload_len < ndpi_str->max_payload_track_len); i++) {
	  flow->flow_payload[flow->flow_payload_len++] =
	    (isprint(packet->payload[i]) || isspace(packet->payload[i])) ? packet->payload[i] : '.';
	}
      }
    }

    packet->tcp_retransmission = 0, packet->packet_direction = 0;

    if(ndpi_str->direction_detect_disable) {
      packet->packet_direction = flow->packet_direction;
    } else {
      if(iph != NULL && ntohl(iph->saddr) < ntohl(iph->daddr))
	packet->packet_direction = 1;

      if((iphv6 != NULL)
	 && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->ip6_src, &iphv6->ip6_dst) != 0)
	packet->packet_direction = 1;
    }

    flow->is_ipv6 = (packet->iphv6 != NULL);

    flow->last_packet_time_ms = packet->current_time_ms;

    packet->packet_lines_parsed_complete = 0;

    if(tcph != NULL) {
      u_int8_t flags = ((u_int8_t*)tcph)[13];

      if(flags == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP NULL scan");
      else if(flags == (TH_FIN | TH_PUSH | TH_URG))
	ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP XMAS scan");

      if(!ndpi_str->direction_detect_disable &&
         (tcph->source != tcph->dest))
	packet->packet_direction = (ntohs(tcph->source) < ntohs(tcph->dest)) ? 1 : 0;

      if(packet->packet_direction == 0 /* cli -> srv */) {
	if(flags == TH_FIN)
	  ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP FIN scan");

	flow->l4.tcp.cli2srv_tcp_flags |= flags;
      } else
	flow->l4.tcp.srv2cli_tcp_flags |= flags;

      if((ndpi_str->input_info == NULL)
	 || ndpi_str->input_info->seen_flow_beginning == NDPI_FLOW_BEGINNING_UNKNOWN) {
	if(tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0
	   && flow->l4.tcp.seen_syn_ack == 0 &&
	   flow->l4.tcp.seen_ack == 0) {
	  flow->l4.tcp.seen_syn = 1;
	} else {
	  if(tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1
	     && flow->l4.tcp.seen_syn_ack == 0 &&
	     flow->l4.tcp.seen_ack == 0) {
	    flow->l4.tcp.seen_syn_ack = 1;
	  } else {
	    if(tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1 &&
	       flow->l4.tcp.seen_ack == 0) {
	      flow->l4.tcp.seen_ack = 1;
	    }
	  }
	}
      }

      if(ndpi_str->tcp_ack_paylod_heuristic && tcp_ack_padding(packet)) {
        NDPI_LOG_DBG2(ndpi_str, "TCP ACK with zero padding. Ignoring\n");
        packet->tcp_retransmission = 1;
      } else if(flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0 ||
	 (tcph->syn && flow->packet_counter == 0)) {
	/* initialize tcp sequence counters */
	/* the ack flag needs to be set to get valid sequence numbers from the other
	 * direction. Usually it will catch the second packet syn+ack but it works
	 * also for asymmetric traffic where it will use the first data packet
	 *
	 * if the syn flag is set add one to the sequence number,
	 * otherwise use the payload length.
	 *
	 * If we receive multiple syn-ack (before any real data), keep the last one
	 */
	if(tcph->ack != 0) {
	  flow->next_tcp_seq_nr[packet->packet_direction] =
	    ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);

	  /*
	    Check to avoid discrepancies in case we analyze a flow that does not start with SYN...
	    but that is already started when nDPI being to process it. See also (***) below
	  */
	  if(flow->num_processed_pkts > 1)
	    flow->next_tcp_seq_nr[1 - packet->packet_direction] = ntohl(tcph->ack_seq);
	}
      } else if(packet->payload_packet_len > 0) {
	/* check tcp sequence counters */
	if(((u_int32_t)(ntohl(tcph->seq) - flow->next_tcp_seq_nr[packet->packet_direction])) >
	   ndpi_str->tcp_max_retransmission_window_size) {
	  packet->tcp_retransmission = 1;

	  /* CHECK IF PARTIAL RETRY IS HAPPENING */
	  if((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) <
	      packet->payload_packet_len)) {
	    if(flow->num_processed_pkts > 1) /* See also (***) above */
	      flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	  }
	}
	else {
	  flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	}
      }

      if(tcph->rst) {
	flow->next_tcp_seq_nr[0] = 0;
	flow->next_tcp_seq_nr[1] = 0;
      }
    } else if(udph != NULL) {
      if(!ndpi_str->direction_detect_disable &&
         (udph->source != udph->dest))
	packet->packet_direction = (htons(udph->source) < htons(udph->dest)) ? 1 : 0;
    }

    if(flow->init_finished == 0) {
      u_int16_t s_port, d_port; /* Source/Dest ports */

      flow->init_finished = 1;

      if(tcph != NULL &&
	 ndpi_str->input_info &&
	 ndpi_str->input_info->seen_flow_beginning == NDPI_FLOW_BEGINNING_SEEN) {
	flow->l4.tcp.seen_syn = 1;
	flow->l4.tcp.seen_syn_ack = 1;
	flow->l4.tcp.seen_ack = 1;
      }

      /* Client/Server direction */

      s_port = 0;
      d_port = 0;
      if(tcph != NULL) {
	s_port = tcph->source;
	d_port = tcph->dest;
      } else if(udph != NULL) {
	s_port = udph->source;
	d_port = udph->dest;
      }

      if(ndpi_str->input_info &&
	 ndpi_str->input_info->in_pkt_dir != NDPI_IN_PKT_DIR_UNKNOWN) {
	if(ndpi_str->input_info->in_pkt_dir == NDPI_IN_PKT_DIR_C_TO_S)
	  flow->client_packet_direction = packet->packet_direction;
	else
	  flow->client_packet_direction = !packet->packet_direction;
      } else {
	if(tcph && tcph->syn) {
	  if(tcph->ack == 0) {
	    flow->client_packet_direction = packet->packet_direction;
	  } else {
	    flow->client_packet_direction = !packet->packet_direction;
	  }
	} else if(ntohs(s_port) > 1024 && ntohs(d_port) < 1024) {
	  flow->client_packet_direction = packet->packet_direction;
	} else if(ntohs(s_port) < 1024 && ntohs(d_port) > 1024) {
	  flow->client_packet_direction = !packet->packet_direction;
	} else {
	  flow->client_packet_direction = packet->packet_direction;
	}
      }

      if(ndpi_current_pkt_from_client_to_server(packet, flow)) {
	if(flow->is_ipv6 == 0) {
	  flow->c_address.v4 = packet->iph->saddr;
	  flow->s_address.v4 = packet->iph->daddr;
	} else {
	  memcpy(flow->c_address.v6, &packet->iphv6->ip6_src, 16);
	  memcpy(flow->s_address.v6, &packet->iphv6->ip6_dst, 16);
	}
	flow->c_port = s_port;
	flow->s_port = d_port;
      } else {
	if(flow->is_ipv6 == 0) {
	  flow->c_address.v4 = packet->iph->daddr;
	  flow->s_address.v4 = packet->iph->saddr;
	} else {
	  memcpy(flow->c_address.v6, &packet->iphv6->ip6_dst, 16);
	  memcpy(flow->s_address.v6, &packet->iphv6->ip6_src, 16);
	}
	flow->c_port = d_port;
	flow->s_port = s_port;
      }
    }

    if(flow->packet_counter < MAX_PACKET_COUNTER && packet->payload_packet_len) {
      flow->packet_counter++;
    }

    if(flow->all_packets_counter < MAX_PACKET_COUNTER)
      flow->all_packets_counter++;

    if((flow->packet_direction_counter[packet->packet_direction] < MAX_PACKET_COUNTER)
       && packet->payload_packet_len) {
      flow->packet_direction_counter[packet->packet_direction]++;
    }

    if(flow->packet_direction_complete_counter[packet->packet_direction] < MAX_PACKET_COUNTER) {
      flow->packet_direction_complete_counter[packet->packet_direction]++;
    }

    if(ndpi_is_multi_or_broadcast(packet))
      ; /* multicast or broadcast */
    else {
      if(flow->packet_direction_complete_counter[flow->client_packet_direction] == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC, "No client to server traffic"); /* Should never happen */
      else if(flow->packet_direction_complete_counter[!flow->client_packet_direction] == 0)
	ndpi_set_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC, "No server to client traffic");
      else {
	ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC); /* Clear bit */
      }
    }
  }
}

/* ************************************************ */

static u_int32_t check_ndpi_subprotocols(struct ndpi_detection_module_struct * const ndpi_str,
                                         struct ndpi_flow_struct * const flow,
                                         NDPI_SELECTION_BITMASK_PROTOCOL_SIZE const ndpi_selection_packet,
                                         NDPI_PROTOCOL_BITMASK detection_bitmask,
                                         u_int16_t detected_protocol)
{
  u_int32_t num_calls = 0, a;

  if(detected_protocol == NDPI_PROTOCOL_UNKNOWN)
  {
    return num_calls;
  }

  for (a = 0; a < ndpi_str->proto_defaults[detected_protocol].subprotocol_count; a++)
  {
    u_int16_t subproto_id = ndpi_str->proto_defaults[detected_protocol].subprotocols[a];
    if(subproto_id == (uint16_t)NDPI_PROTOCOL_MATCHED_BY_CONTENT ||
        subproto_id == flow->detected_protocol_stack[0] ||
        subproto_id == flow->detected_protocol_stack[1])
    {
      continue;
    }

    u_int16_t subproto_index = ndpi_str->proto_defaults[subproto_id].protoIdx;
    if((ndpi_str->callback_buffer[subproto_index].ndpi_selection_bitmask & ndpi_selection_packet) ==
         ndpi_str->callback_buffer[subproto_index].ndpi_selection_bitmask &&
        NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
                             ndpi_str->callback_buffer[subproto_index].excluded_protocol_bitmask) == 0 &&
        NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[subproto_index].detection_bitmask,
                             detection_bitmask) != 0)
    {
      ndpi_str->callback_buffer[subproto_index].func(ndpi_str, flow);
      num_calls++;
    }
  }

  return num_calls;
}

/* ************************************************ */

static u_int32_t check_ndpi_detection_func(struct ndpi_detection_module_struct * const ndpi_str,
					   struct ndpi_flow_struct * const flow,
					   NDPI_SELECTION_BITMASK_PROTOCOL_SIZE const ndpi_selection_packet,
					   struct ndpi_call_function_struct const * const callback_buffer,
					   uint32_t callback_buffer_size,
					   int is_tcp_without_payload)
{
  void *func = NULL;
  u_int32_t num_calls = 0;
  u_int16_t proto_index = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoIdx;
  u_int16_t proto_id = ndpi_str->proto_defaults[flow->guessed_protocol_id].protoId;
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  u_int32_t a;

  NDPI_SAVE_AS_BITMASK(detection_bitmask, flow->detected_protocol_stack[0]);

  if((proto_id != NDPI_PROTOCOL_UNKNOWN) &&
      NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
			   ndpi_str->callback_buffer[proto_index].excluded_protocol_bitmask) == 0 &&
      NDPI_BITMASK_COMPARE(ndpi_str->callback_buffer[proto_index].detection_bitmask, detection_bitmask) != 0 &&
      (ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask & ndpi_selection_packet) ==
      ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask)
    {
      if((flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) &&
          (ndpi_str->proto_defaults[flow->guessed_protocol_id].func != NULL) &&
          (is_tcp_without_payload == 0 ||
           ((ndpi_str->callback_buffer[proto_index].ndpi_selection_bitmask &
	     NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD) == 0)))
	{
	  ndpi_str->proto_defaults[flow->guessed_protocol_id].func(ndpi_str, flow);
	  func = ndpi_str->proto_defaults[flow->guessed_protocol_id].func;
	  num_calls++;
	}
    }

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN)
    {
      for (a = 0; a < callback_buffer_size; a++) {
        if((func != callback_buffer[a].func) &&
            (callback_buffer[a].ndpi_selection_bitmask & ndpi_selection_packet) ==
	    callback_buffer[a].ndpi_selection_bitmask &&
            NDPI_BITMASK_COMPARE(flow->excluded_protocol_bitmask,
                                 callback_buffer[a].excluded_protocol_bitmask) == 0 &&
            NDPI_BITMASK_COMPARE(callback_buffer[a].detection_bitmask,
                                 detection_bitmask) != 0)
	  {
	    callback_buffer[a].func(ndpi_str, flow);
	    num_calls++;

	    if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
	      {
		break; /* Stop after the first detected protocol. */
	      }
	  }
      }
    }

  num_calls += check_ndpi_subprotocols(ndpi_str, flow, ndpi_selection_packet, detection_bitmask,
                                       flow->detected_protocol_stack[0]);
  num_calls += check_ndpi_subprotocols(ndpi_str, flow, ndpi_selection_packet, detection_bitmask,
                                       flow->detected_protocol_stack[1]);

  return num_calls;
}

/* ************************************************ */

u_int32_t check_ndpi_other_flow_func(struct ndpi_detection_module_struct *ndpi_str,
				     struct ndpi_flow_struct *flow,
				     NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				   ndpi_str->callback_buffer_non_tcp_udp,
				   ndpi_str->callback_buffer_size_non_tcp_udp, 0);
}

/* ************************************************ */

static u_int32_t check_ndpi_udp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				   ndpi_str->callback_buffer_udp,
				   ndpi_str->callback_buffer_size_udp, 0);
}

/* ************************************************ */

static u_int32_t check_ndpi_tcp_flow_func(struct ndpi_detection_module_struct *ndpi_str,
					  struct ndpi_flow_struct *flow,
					  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet)
{
  if(ndpi_str->packet.payload_packet_len != 0) {
    return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				     ndpi_str->callback_buffer_tcp_payload,
				     ndpi_str->callback_buffer_size_tcp_payload, 0);
  } else {
    /* no payload */
    return check_ndpi_detection_func(ndpi_str, flow, *ndpi_selection_packet,
				     ndpi_str->callback_buffer_tcp_no_payload,
				     ndpi_str->callback_buffer_size_tcp_no_payload, 1);
  }
}

/* ********************************************************************************* */

u_int32_t ndpi_check_flow_func(struct ndpi_detection_module_struct *ndpi_str,
			       struct ndpi_flow_struct *flow,
			       NDPI_SELECTION_BITMASK_PROTOCOL_SIZE *ndpi_selection_packet) {
  if(!flow)
    return(0);
  else if(ndpi_str->packet.tcp != NULL)
    return(check_ndpi_tcp_flow_func(ndpi_str, flow, ndpi_selection_packet));
  else if(ndpi_str->packet.udp != NULL)
    return(check_ndpi_udp_flow_func(ndpi_str, flow, ndpi_selection_packet));
  else
    return(check_ndpi_other_flow_func(ndpi_str, flow, ndpi_selection_packet));
}

/* ********************************************************************************* */

u_int16_t ndpi_guess_host_protocol_id(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  u_int16_t ret = NDPI_PROTOCOL_UNKNOWN;

  if(packet->iph) {
    struct in_addr addr;

    /* guess host protocol; server first */
    addr.s_addr = flow->s_address.v4;
    ret = ndpi_network_port_ptree_match(ndpi_str, &addr, flow->s_port);

    if(ret == NDPI_PROTOCOL_UNKNOWN) {
      addr.s_addr = flow->c_address.v4;
      ret = ndpi_network_port_ptree_match(ndpi_str, &addr, flow->c_port);
    }
  }

  return(ret);
}

/* ********************************************************************************* */

static u_int32_t make_msteams_key(struct ndpi_flow_struct *flow, u_int8_t use_client) {
  u_int32_t key;

  if(use_client) {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->c_address.v6, 16);
    else
      key = ntohl(flow->c_address.v4);
  } else {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->s_address.v6, 16);
    else
      key = ntohl(flow->s_address.v4);
  }

  return key;
}

/* ********************************************************************************* */

static void ndpi_reconcile_msteams_udp(struct ndpi_detection_module_struct *ndpi_str,
				       struct ndpi_flow_struct *flow,
				       u_int16_t master) {
  /* This function can NOT access &ndpi_str->packet since it is called also from ndpi_detection_giveup(), via ndpi_reconcile_protocols() */

  if(flow->l4_proto == IPPROTO_UDP) {
    u_int16_t sport = ntohs(flow->c_port);
    u_int16_t dport = ntohs(flow->s_port);
    u_int8_t  s_match = ((sport >= 3478) && (sport <= 3481)) ? 1 : 0;
    u_int8_t  d_match = ((dport >= 3478) && (dport <= 3481)) ? 1 : 0;

    if(s_match || d_match) {
      ndpi_int_change_protocol(ndpi_str, flow,
			       NDPI_PROTOCOL_SKYPE_TEAMS, master,
			       /* Keep the same confidence */
			       flow->confidence);


      if(ndpi_str->msteams_cache)
	ndpi_lru_add_to_cache(ndpi_str->msteams_cache,
			      make_msteams_key(flow, s_match ? 0 /* server */ : 1 /* client */),
			      0 /* dummy */,
			      ndpi_get_current_time(flow));

    }
  }
}

/* ********************************************************************************* */

static int ndpi_reconcile_msteams_call_udp_port(struct ndpi_detection_module_struct *ndpi_str,
						struct ndpi_flow_struct *flow,
						u_int16_t sport, u_int16_t dport) {

  /*
    https://extremeportal.force.com/ExtrArticleDetail?an=000101782

    Audio:   UDP 50000-50019; 3478; 3479
    Video:   UDP 50020-50039; 3480
	Sharing: UDP 50040-50059; 3481
  */

  if((dport == 3478) || (dport == 3479) || ((sport >= 50000) && (sport <= 50019)))
    flow->flow_multimedia_type = ndpi_multimedia_audio_flow;
  else if((dport == 3480) || ((sport >= 50020) && (sport <= 50039)))
    flow->flow_multimedia_type = ndpi_multimedia_video_flow;
  else if((dport == 3481) || ((sport >= 50040) && (sport <= 50059)))
    flow->flow_multimedia_type = ndpi_multimedia_screen_sharing_flow;
  else {
    flow->flow_multimedia_type = ndpi_multimedia_unknown_flow;
    return(0);
  }

  return(1);
}

/* ********************************************************************************* */

static void ndpi_reconcile_msteams_call_udp(struct ndpi_detection_module_struct *ndpi_str,
					    struct ndpi_flow_struct *flow) {
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_SKYPE_TEAMS_CALL) {
    if(flow->l4_proto == IPPROTO_UDP) {
      u_int16_t sport = ntohs(flow->c_port);
      u_int16_t dport = ntohs(flow->s_port);

      if(ndpi_reconcile_msteams_call_udp_port(ndpi_str, flow, sport, dport) == 0)
	ndpi_reconcile_msteams_call_udp_port(ndpi_str, flow, dport, sport);
    }
  }
}

/* ********************************************************************************* */

static void ndpi_reconcile_protocols(struct ndpi_detection_module_struct *ndpi_str,
				     struct ndpi_flow_struct *flow,
				     ndpi_protocol *ret) {
  u_int i;

  /* This function can NOT access &ndpi_str->packet since it is called also from ndpi_detection_giveup() */

  // printf("====>> %u.%u [%u]\n", ret->master_protocol, ret->app_protocol, flow->detected_protocol_stack[0]);

  if((flow->risk != 0) && (flow->risk != flow->risk_shadow)) {
    /* Trick to avoid evaluating exceptions when nothing changed */
    ndpi_handle_risk_exceptions(ndpi_str, flow);
    flow->risk_shadow = flow->risk;
  }
  
  switch(ret->app_protocol) {
  case NDPI_PROTOCOL_MICROSOFT_AZURE:
    ndpi_reconcile_msteams_udp(ndpi_str, flow, flow->detected_protocol_stack[1]);
    break;

    /*
      Skype for a host doing MS Teams means MS Teams
      (MS Teams uses Skype as transport protocol for voice/video)
    */
  case NDPI_PROTOCOL_MSTEAMS:
    if(flow && (flow->l4_proto == IPPROTO_TCP)) {
      // printf("====>> NDPI_PROTOCOL_MSTEAMS\n");

      if(ndpi_str->msteams_cache)
	ndpi_lru_add_to_cache(ndpi_str->msteams_cache,
			      make_msteams_key(flow, 1 /* client */),
			      0 /* dummy */,
			      ndpi_get_current_time(flow));
    }
    break;

  case NDPI_PROTOCOL_STUN:
    if(flow && (flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_MICROSOFT_AZURE))
      ndpi_reconcile_msteams_udp(ndpi_str, flow, NDPI_PROTOCOL_STUN);
    break;

  case NDPI_PROTOCOL_NETFLOW:
  case NDPI_PROTOCOL_SFLOW:
  case NDPI_PROTOCOL_RTP:
  case NDPI_PROTOCOL_COLLECTD:
    /* Remove NDPI_UNIDIRECTIONAL_TRAFFIC from unidirectional protocols */
    ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC);
    break;

  case NDPI_PROTOCOL_SYSLOG:
    if(flow->l4_proto == IPPROTO_UDP)
      ndpi_unset_risk(ndpi_str, flow, NDPI_UNIDIRECTIONAL_TRAFFIC);
    break;

  case NDPI_PROTOCOL_TLS:
    /*
      When Teams is unable to communicate via UDP
      it switches to TLS.TCP. Let's try to catch it
    */
    if(flow
       && (flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_MICROSOFT_AZURE)
       && (ret->master_protocol == NDPI_PROTOCOL_UNKNOWN)
       && ndpi_str->msteams_cache
      ) {
      u_int16_t dummy;

      if(ndpi_lru_find_cache(ndpi_str->msteams_cache,
			     make_msteams_key(flow, 1 /* client */),
			     &dummy, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
	ndpi_int_change_protocol(ndpi_str, flow,
				 NDPI_PROTOCOL_SKYPE_TEAMS, NDPI_PROTOCOL_TLS,
				 NDPI_CONFIDENCE_DPI_PARTIAL);
      }
    }
    break;

  case NDPI_PROTOCOL_SKYPE_TEAMS:
  case NDPI_PROTOCOL_SKYPE_TEAMS_CALL:
    if(flow->l4_proto == IPPROTO_UDP && ndpi_str->msteams_cache) {
      u_int16_t dummy;

      if(ndpi_lru_find_cache(ndpi_str->msteams_cache, make_msteams_key(flow, 1 /* client */),
			     &dummy, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
	  ret->app_protocol = NDPI_PROTOCOL_MSTEAMS;

	  /* Refresh cache */
	  ndpi_lru_add_to_cache(ndpi_str->msteams_cache,
				make_msteams_key(flow, 1 /* client */),
				0 /* dummy */,
				ndpi_get_current_time(flow));
      }
    }

    ndpi_reconcile_msteams_call_udp(ndpi_str, flow);
    break;

  case NDPI_PROTOCOL_RDP:
    ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found RDP"); /* Remote assistance */
    break;

  case NDPI_PROTOCOL_ANYDESK:
    if(flow->l4_proto == IPPROTO_TCP) /* TCP only */
      ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found AnyDesk"); /* Remote assistance */
    break;

    /* Generic container for microsoft subprotocols */
  case NDPI_PROTOCOL_MICROSOFT:
    switch(flow->guessed_protocol_id_by_ip) {
    case NDPI_PROTOCOL_MICROSOFT_365:
    case NDPI_PROTOCOL_MS_ONE_DRIVE:
    case NDPI_PROTOCOL_MS_OUTLOOK:
    case NDPI_PROTOCOL_SKYPE_TEAMS:
      ndpi_int_change_protocol(ndpi_str, flow,
			       flow->guessed_protocol_id_by_ip, flow->detected_protocol_stack[1],
			       NDPI_CONFIDENCE_DPI_PARTIAL);
      break;
    }
    break;

    /* Generic container for google subprotocols */
  case NDPI_PROTOCOL_GOOGLE:
    switch(flow->guessed_protocol_id_by_ip) {
    case NDPI_PROTOCOL_GOOGLE_CLOUD:
      ndpi_int_change_protocol(ndpi_str, flow,
			       flow->guessed_protocol_id_by_ip, flow->detected_protocol_stack[1],
			       NDPI_CONFIDENCE_DPI_PARTIAL);

      break;
    }
    break;

  case NDPI_PROTOCOL_UNKNOWN:
    break;
  } /* switch */

  ret->master_protocol = flow->detected_protocol_stack[1], ret->app_protocol = flow->detected_protocol_stack[0];

  for(i=0; i<2; i++) {
    switch(ndpi_get_proto_breed(ndpi_str, flow->detected_protocol_stack[i])) {
    case NDPI_PROTOCOL_UNSAFE:
    case NDPI_PROTOCOL_POTENTIALLY_DANGEROUS:
    case NDPI_PROTOCOL_DANGEROUS:
      ndpi_set_risk(ndpi_str, flow, NDPI_UNSAFE_PROTOCOL, NULL);
      break;
    default:
      /* Nothing to do */
      break;
    }
  }
}

/* ********************************************************************************* */

u_int32_t ndpi_ip_port_hash_funct(u_int32_t ip, u_int16_t port) {
  return(ip + 3 * port);
}

/* ********************************************************************************* */

/* #define BITTORRENT_CACHE_DEBUG */

int ndpi_search_into_bittorrent_cache(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow) {

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] ndpi_search_into_bittorrent_cache(%u, %u) [bt_check_performed=%d]\n",
	 __FILE__, __LINE__, ntohs(flow->c_port), ntohs(flow->s_port),
	 flow->bt_check_performed);
#endif

  if(flow->bt_check_performed /* Do the check once */)
    return(0);

  if(ndpi_struct->bittorrent_cache) {
    u_int16_t cached_proto;
    u_int8_t found = 0;
    u_int32_t key, key1, key2;

    flow->bt_check_performed = 1;

    /* Check cached communications */
    key = make_bittorrent_peers_key(flow);
    key1 = make_bittorrent_host_key(flow, 1, 0), key2 = make_bittorrent_host_key(flow, 0, 0);

    found =
      ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, key, &cached_proto, 0 /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow))
      || ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, key1, &cached_proto, 0     /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow))
      || ndpi_lru_find_cache(ndpi_struct->bittorrent_cache, key2, &cached_proto, 0     /* Don't remove it as it can be used for other connections */, ndpi_get_current_time(flow));

#ifdef BITTORRENT_CACHE_DEBUG
    printf("[BitTorrent] *** [%s] SEARCHING ports %u / %u [%u][%u][%u][found: %u]\n",
           flow->l4_proto == IPPROTO_UDP ? "UDP": "TCP",
           ntohs(flow->c_port), ntohs(flow->s_port), key, key1, key2, found);
#endif

    return(found);
  }

  return(0);
}

/* ********************************************************************************* */

/* #define ZOOM_CACHE_DEBUG */


static u_int32_t make_zoom_key(struct ndpi_flow_struct *flow, int server) {
  u_int32_t key;

  if(server) {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->s_address.v6, 16);
    else
      key = flow->s_address.v4;
  } else {
    if(flow->is_ipv6)
      key = ndpi_quick_hash(flow->c_address.v6, 16);
    else
      key = flow->c_address.v4;
  }

  return key;
}

/* ********************************************************************************* */

static u_int8_t ndpi_search_into_zoom_cache(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow, int server) {

  if(ndpi_struct->zoom_cache) {
    u_int16_t cached_proto;
    u_int32_t key;

    key = make_zoom_key(flow, server);
    u_int8_t found = ndpi_lru_find_cache(ndpi_struct->zoom_cache, key, &cached_proto,
					 0 /* Don't remove it as it can be used for other connections */,
					 ndpi_get_current_time(flow));

#ifdef ZOOM_CACHE_DEBUG
    printf("[Zoom] *** [TCP] SEARCHING key %u [found: %u]\n", key, found);
#endif

    return(found);
  }

  return(0);
}

/* ********************************************************************************* */

static void ndpi_add_connection_as_zoom(struct ndpi_detection_module_struct *ndpi_struct,
					struct ndpi_flow_struct *flow) {
  if(ndpi_struct->zoom_cache)
    ndpi_lru_add_to_cache(ndpi_struct->zoom_cache, make_zoom_key(flow, 1), NDPI_PROTOCOL_ZOOM, ndpi_get_current_time(flow));
}

/* ********************************************************************************* */

/*
  NOTE:

  This function is called only by ndpi_detection_giveup() as it checks
  flows that have anomalous conditions such as SYN+RST ACK+RST....
  As these conditions won't happen with nDPI protocol-detected protocols
  it is not necessary to call this function elsewhere
 */
static void ndpi_check_tcp_flags(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow) {
  // printf("[TOTAL] %u / %u [tot: %u]\n", flow->packet_direction_complete_counter[0], flow->packet_direction_complete_counter[1], flow->all_packets_counter);

  if((flow->l4.tcp.cli2srv_tcp_flags & TH_SYN)
     && (flow->l4.tcp.srv2cli_tcp_flags & TH_RST)
     && (flow->all_packets_counter < 5 /* Ignore connections terminated by RST but that exchanged data (3WH + RST) */)
     )
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "Connection refused (server)");
  else if((flow->l4.tcp.cli2srv_tcp_flags & TH_SYN)
	  && (flow->l4.tcp.cli2srv_tcp_flags & TH_RST)
	  && (flow->all_packets_counter < 5 /* Ignore connections terminated by RST but that exchanged data (3WH + RST) */)
     )
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "Connection refused (client)");
  else if((flow->l4.tcp.srv2cli_tcp_flags & TH_RST) && (flow->packet_direction_complete_counter[1 /* server -> client */] == 1))
    ndpi_set_risk(ndpi_str, flow, NDPI_TCP_ISSUES, "TCP probing attempt");
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_giveup(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				    u_int8_t enable_guess, u_int8_t *protocol_was_guessed) {
  ndpi_protocol ret = NDPI_PROTOCOL_NULL;
  u_int16_t cached_proto;

  /* *** We can't access ndpi_str->packet from this function!! *** */

  *protocol_was_guessed = 0;

  if(!ndpi_str || !flow)
    return(ret);

  if(flow->l4_proto == IPPROTO_TCP)
    ndpi_check_tcp_flags(ndpi_str, flow);

  /* Init defaults */
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
  ret.protocol_by_ip = flow->guessed_protocol_id_by_ip;
  ret.category = flow->category;

  /* Ensure that we don't change our mind if detection is already complete */
  if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN)
    return(ret);

  if((flow->guessed_protocol_id == NDPI_PROTOCOL_STUN) ||
     (enable_guess &&
      flow->stun.num_binding_requests > 0 &&
      flow->stun.num_processed_pkts > 0)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Check some caches */

  /* Does it looks like BitTorrent? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     ndpi_search_into_bittorrent_cache(ndpi_str, flow)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_BITTORRENT, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }
  /* Does it looks like some Mining protocols? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     ndpi_str->mining_cache &&
     ndpi_lru_find_cache(ndpi_str->mining_cache, make_mining_key(flow),
			 &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			 ndpi_get_current_time(flow))) {
    ndpi_set_detected_protocol(ndpi_str, flow, cached_proto, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Does it looks like Zoom? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     flow->l4_proto == IPPROTO_UDP && /* Zoom/UDP used for video */
     ((ntohs(flow->s_port) == 8801 && ndpi_search_into_zoom_cache(ndpi_str, flow, 1)) ||
      (ntohs(flow->c_port) == 8801 && ndpi_search_into_zoom_cache(ndpi_str, flow, 0)))) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Does it looks like Zoom (via STUN)? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     stun_search_into_zoom_cache(ndpi_str, flow)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_ZOOM, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* Does it looks like Ookla? */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     ntohs(flow->s_port) == 8080 && ookla_search_into_cache(ndpi_str, flow)) {
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_OOKLA, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI_PARTIAL_CACHE);
    ret.app_protocol = flow->detected_protocol_stack[0];
  }

  /* TODO: not sure about the best "order" among fully encrypted logic, classification by-port and classification by-ip...*/
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     flow->first_pkt_fully_encrypted == 1) {
    ndpi_set_risk(ndpi_str, flow, NDPI_FULLY_ENCRYPTED, NULL);
  }

  /* Classification by-port */
  if(enable_guess && ret.app_protocol == NDPI_PROTOCOL_UNKNOWN) {

    /* Ignore guessed protocol if they have been discarded */
    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN &&
       flow->l4_proto == IPPROTO_UDP &&
       NDPI_ISSET(&flow->excluded_protocol_bitmask, flow->guessed_protocol_id) &&
       is_udp_not_guessable_protocol(flow->guessed_protocol_id))
      flow->guessed_protocol_id = NDPI_PROTOCOL_UNKNOWN;

    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      ndpi_set_detected_protocol(ndpi_str, flow, flow->guessed_protocol_id, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_MATCH_BY_PORT);
      ret.app_protocol = flow->detected_protocol_stack[0];
    }
  }

  /* Classification by-ip, as last effort */
  if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
     flow->guessed_protocol_id_by_ip != NDPI_PROTOCOL_UNKNOWN) {

      ndpi_set_detected_protocol(ndpi_str, flow,
			         flow->guessed_protocol_id_by_ip, ret.master_protocol,
			         NDPI_CONFIDENCE_MATCH_BY_IP);
      ret.app_protocol = flow->detected_protocol_stack[0];
  }

  if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
    *protocol_was_guessed = 1;
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
  }

  return(ret);
}

/* ********************************************************************************* */

void ndpi_process_extra_packet(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
			       const unsigned char *packet_data, const unsigned short packetlen,
			       const u_int64_t current_time_ms,
			       const struct ndpi_flow_input_info *input_info) {
  if(flow == NULL)
    return;

  /* set up the packet headers for the extra packet function to use if it wants */
  if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
    return;

  ndpi_connection_tracking(ndpi_str, flow);

  /* call the extra packet function (which may add more data/info to flow) */
  if(flow->extra_packets_func) {
    if((flow->extra_packets_func(ndpi_str, flow)) == 0)
      flow->extra_packets_func = NULL; /* Enough packets detected */

    if(++flow->num_extra_packets_checked == flow->max_extra_packets_to_check)
      flow->extra_packets_func = NULL; /* Enough packets detected */
  }
}

/* ********************************************************************************* */

int ndpi_load_ip_category(struct ndpi_detection_module_struct *ndpi_str,
			  const char *ip_address_and_mask,
			  ndpi_protocol_category_t category,
			  void *user_data) {
  ndpi_patricia_node_t *node;
  struct in_addr pin;
  int bits = 32;
  char *ptr;
  char ipbuf[64];

  if(!ndpi_str->custom_categories.ipAddresses_shadow)
    return(-1);

  strncpy(ipbuf, ip_address_and_mask, sizeof(ipbuf) - 1);
  ipbuf[sizeof(ipbuf) - 1] = '\0';

  ptr = strrchr(ipbuf, '/');

  if(ptr) {
    *(ptr++) = '\0';
    if(atoi(ptr) >= 0 && atoi(ptr) <= 32)
      bits = atoi(ptr);
  }

  if(inet_pton(AF_INET, ipbuf, &pin) != 1) {
    NDPI_LOG_DBG2(ndpi_str, "Invalid ip/ip+netmask: %s\n", ip_address_and_mask);
    return(-1);
  }

  if((node = add_to_ptree(ndpi_str->custom_categories.ipAddresses_shadow, AF_INET, &pin, bits)) != NULL) {
    node->value.u.uv32.user_value = (u_int16_t)category, node->value.u.uv32.additional_user_value = 0;
    node->custom_user_data = user_data;
  }


  return(0);
}

/* ********************************************************************************* */

int ndpi_load_hostname_category(struct ndpi_detection_module_struct *ndpi_str,
				const char *name_to_add,
				ndpi_protocol_category_t category) {

  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa == NULL)
    return(-1);

  if(name_to_add == NULL)
    return(-1);

  return ndpi_string_to_automa(ndpi_str,
			       (AC_AUTOMATA_t *)ndpi_str->custom_categories.hostnames_shadow.ac_automa,
			       name_to_add,category,category, 0, 0, 1); /* at_end */
}

/* ********************************************************************************* */

/* Loads an IP or name category */
int ndpi_load_category(struct ndpi_detection_module_struct *ndpi_struct, const char *ip_or_name,
		       ndpi_protocol_category_t category, void *user_data) {
  int rv;

  /* Try to load as IP address first */
  rv = ndpi_load_ip_category(ndpi_struct, ip_or_name, category, user_data);

  if(rv < 0) {
    /*
       IP load failed, load as hostname

       NOTE:
       we cannot add user_data here as with Aho-Corasick this
       information would not be used
    */
    rv = ndpi_load_hostname_category(ndpi_struct, ip_or_name, category);
  }

  return(rv);
}

/* ********************************************************************************* */

int ndpi_enable_loaded_categories(struct ndpi_detection_module_struct *ndpi_str) {
  int i;
  static char *built_in = "built-in";

  /* First add the nDPI known categories matches */
  for(i = 0; category_match[i].string_to_match != NULL; i++)
    ndpi_load_category(ndpi_str, category_match[i].string_to_match,
		       category_match[i].protocol_category, built_in);

  /* Free */
  ac_automata_release((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames.ac_automa,
		      1 /* free patterns strings memory */);

  /* Finalize */
  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa)
    ac_automata_finalize((AC_AUTOMATA_t *) ndpi_str->custom_categories.hostnames_shadow.ac_automa);

  /* Swap */
  ndpi_str->custom_categories.hostnames.ac_automa = ndpi_str->custom_categories.hostnames_shadow.ac_automa;

  /* Realloc */
  ndpi_str->custom_categories.hostnames_shadow.ac_automa = ac_automata_init(ac_domain_match_handler);
  if(ndpi_str->custom_categories.hostnames_shadow.ac_automa) {
    ac_automata_feature(ndpi_str->custom_categories.hostnames_shadow.ac_automa,AC_FEATURE_LC);
    ac_automata_name(ndpi_str->custom_categories.hostnames_shadow.ac_automa,"ccat_sh",0);
  }

  if(ndpi_str->custom_categories.ipAddresses != NULL)
    ndpi_patricia_destroy((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses, free_ptree_data);

  ndpi_str->custom_categories.ipAddresses = ndpi_str->custom_categories.ipAddresses_shadow;
  ndpi_str->custom_categories.ipAddresses_shadow = ndpi_patricia_new(32 /* IPv4 */);

  ndpi_str->custom_categories.categories_loaded = 1;

  return(0);
}

/* ********************************************************************************* */

/* NOTE u_int32_t is represented in network byte order */
void* ndpi_find_ipv4_category_userdata(struct ndpi_detection_module_struct *ndpi_str,
				       u_int32_t saddr) {
  ndpi_patricia_node_t *node;

  if(saddr == 0 || !ndpi_str || !ndpi_str->custom_categories.ipAddresses)
    node = NULL;
  else {
    ndpi_prefix_t prefix;

    ndpi_fill_prefix_v4(&prefix, (struct in_addr *) &saddr, 32,
			((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses)->maxbits);
    node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
  }

  return(node ? node->custom_user_data : NULL);
}

/* ********************************************************************************* */

/* NOTE u_int32_t is represented in network byte order */
int ndpi_fill_ip_protocol_category(struct ndpi_detection_module_struct *ndpi_str,
				   u_int32_t saddr, u_int32_t daddr,
				   ndpi_protocol *ret) {

  ret->custom_category_userdata = NULL;

  if(ndpi_str->custom_categories.categories_loaded &&
     ndpi_str->custom_categories.ipAddresses) {

    ndpi_prefix_t prefix;
    ndpi_patricia_node_t *node;

    if(saddr == 0)
      node = NULL;
    else {
      /* Make sure all in network byte order otherwise compares wont work */
      ndpi_fill_prefix_v4(&prefix, (struct in_addr *) &saddr, 32,
			  ((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses)->maxbits);
      node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
    }

    if(!node) {
      if(daddr != 0) {
	ndpi_fill_prefix_v4(&prefix, (struct in_addr *) &daddr, 32,
			    ((ndpi_patricia_tree_t *) ndpi_str->custom_categories.ipAddresses)->maxbits);
	node = ndpi_patricia_search_best(ndpi_str->custom_categories.ipAddresses, &prefix);
      }
    }

    if(node) {
      ret->category = (ndpi_protocol_category_t) node->value.u.uv32.user_value;
      ret->custom_category_userdata = node->custom_user_data;
      return(1);
    }
  }

  ret->category = ndpi_get_proto_category(ndpi_str, *ret);

  return(0);
}

/* ********************************************************************************* */

void ndpi_fill_protocol_category(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				 ndpi_protocol *ret) {
  if((ret->master_protocol == NDPI_PROTOCOL_UNKNOWN) && (ret->app_protocol == NDPI_PROTOCOL_UNKNOWN))
    return;

  if(ndpi_str->custom_categories.categories_loaded) {
    if(flow->guessed_header_category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) {
      flow->category = ret->category = flow->guessed_header_category;
      return;
    }

    if(flow->host_server_name[0] != '\0') {
      u_int32_t id;
      int rc = ndpi_match_custom_category(ndpi_str, flow->host_server_name,
					  strlen(flow->host_server_name), &id);
      if(rc == 0) {
	flow->category = ret->category = (ndpi_protocol_category_t) id;
	return;
      }
    }
  }

  flow->category = ret->category = ndpi_get_proto_category(ndpi_str, *ret);
}

/* ********************************************************************************* */

static void ndpi_reset_packet_line_info(struct ndpi_packet_struct *packet) {
  packet->parsed_lines = 0, packet->empty_line_position_set = 0, packet->host_line.ptr = NULL,
    packet->host_line.len = 0, packet->referer_line.ptr = NULL, packet->referer_line.len = 0,
    packet->authorization_line.len = 0, packet->authorization_line.ptr = NULL,
    packet->content_line.ptr = NULL, packet->content_line.len = 0, packet->accept_line.ptr = NULL,
    packet->accept_line.len = 0, packet->user_agent_line.ptr = NULL, packet->user_agent_line.len = 0,
    packet->http_url_name.ptr = NULL, packet->http_url_name.len = 0, packet->http_encoding.ptr = NULL,
    packet->http_encoding.len = 0, packet->http_transfer_encoding.ptr = NULL, packet->http_transfer_encoding.len = 0,
    packet->http_contentlen.ptr = NULL, packet->http_contentlen.len = 0, packet->content_disposition_line.ptr = NULL,
    packet->content_disposition_line.len = 0, packet->http_cookie.ptr = NULL,
    packet->http_cookie.len = 0, packet->http_origin.len = 0, packet->http_origin.ptr = NULL,
    packet->http_x_session_type.ptr = NULL, packet->http_x_session_type.len = 0, packet->server_line.ptr = NULL,
    packet->server_line.len = 0, packet->http_method.ptr = NULL, packet->http_method.len = 0,
    packet->http_response.ptr = NULL, packet->http_response.len = 0, packet->http_num_headers = 0,
    packet->forwarded_line.ptr = NULL, packet->forwarded_line.len = 0;
}

/* ********************************************************************************* */

static int ndpi_is_ntop_protocol(ndpi_protocol *ret) {
  if((ret->master_protocol == NDPI_PROTOCOL_HTTP) && (ret->app_protocol == NDPI_PROTOCOL_NTOP))
    return(1);
  else
    return(0);
}

/* ********************************************************************************* */

static int ndpi_check_protocol_port_mismatch_exceptions(struct ndpi_detection_module_struct *ndpi_str,
							struct ndpi_flow_struct *flow,
							ndpi_default_ports_tree_node_t *expected_proto,
							ndpi_protocol *returned_proto) {
  /*
    For TLS (and other protocols) it is not simple to guess the exact protocol so before
    triggering an alert we need to make sure what we have exhausted all the possible
    options available
  */

  if(ndpi_is_ntop_protocol(returned_proto)) return(1);

  if(returned_proto->master_protocol == NDPI_PROTOCOL_TLS) {
    switch(expected_proto->proto->protoId) {
    case NDPI_PROTOCOL_MAIL_IMAPS:
    case NDPI_PROTOCOL_MAIL_POPS:
    case NDPI_PROTOCOL_MAIL_SMTPS:
      return(1); /* This is a reasonable exception */
      break;
    }
  }

  return(0);
}

/* ****************************************************** */

static int ndpi_do_guess(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow, ndpi_protocol *ret) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  ret->master_protocol = ret->app_protocol = NDPI_PROTOCOL_UNKNOWN, ret->category = 0;

  if(packet->iphv6 || packet->iph) {
    u_int8_t user_defined_proto;

    /* guess protocol */
    flow->guessed_protocol_id = (int16_t) ndpi_guess_protocol_id(ndpi_str, flow, flow->l4_proto,
								 ntohs(flow->c_port), ntohs(flow->s_port),
								 &user_defined_proto);
    flow->guessed_protocol_id_by_ip = ndpi_guess_host_protocol_id(ndpi_str, flow);

    ret->protocol_by_ip = flow->guessed_protocol_id_by_ip;

    if(ndpi_str->custom_categories.categories_loaded && packet->iph) {
      if(ndpi_str->ndpi_num_custom_protocols != 0)
	ndpi_fill_ip_protocol_category(ndpi_str, flow->c_address.v4, flow->s_address.v4, ret);
      flow->guessed_header_category = ret->category;
    } else
      flow->guessed_header_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

    if(flow->guessed_protocol_id >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
      /* This is a custom protocol and it has priority over everything else */
      ret->master_protocol = NDPI_PROTOCOL_UNKNOWN,
      ret->app_protocol = flow->guessed_protocol_id;
      flow->confidence = NDPI_CONFIDENCE_MATCH_BY_PORT; /* TODO */
      ndpi_fill_protocol_category(ndpi_str, flow, ret);
      return(-1);
    }

    if(user_defined_proto && flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      if(flow->guessed_protocol_id_by_ip != NDPI_PROTOCOL_UNKNOWN) {
        u_int8_t protocol_was_guessed;

        *ret = ndpi_detection_giveup(ndpi_str, flow, 0, &protocol_was_guessed);
      }

      ndpi_fill_protocol_category(ndpi_str, flow, ret);
      return(-1);
    }
  }

  if(flow->guessed_protocol_id_by_ip >= NDPI_MAX_SUPPORTED_PROTOCOLS) {
    NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet = {0};

    /* This is a custom protocol and it has priority over everything else */
    ret->master_protocol = flow->guessed_protocol_id, ret->app_protocol = flow->guessed_protocol_id_by_ip;

    flow->num_dissector_calls += ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

    ndpi_fill_protocol_category(ndpi_str, flow, ret);
    return(-1);
  }

  return(0);
}

/* ********************************************************************************* */

static ndpi_protocol ndpi_internal_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
							    struct ndpi_flow_struct *flow, const unsigned char *packet_data,
							    const unsigned short packetlen, const u_int64_t current_time_ms,
							    const struct ndpi_flow_input_info *input_info) {
  struct ndpi_packet_struct *packet;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  u_int32_t num_calls = 0;
  ndpi_protocol ret;

  memset(&ret, 0, sizeof(ret));

  if((!flow) || (!ndpi_str))
    return(ret);

  packet = &ndpi_str->packet;

  NDPI_LOG_DBG(ndpi_str, "[%d/%d] START packet processing\n",
               flow->detected_protocol_stack[0],
	       flow->detected_protocol_stack[1]);

  ret.master_protocol = flow->detected_protocol_stack[1],
    ret.app_protocol = flow->detected_protocol_stack[0];
  ret.protocol_by_ip = flow->guessed_protocol_id_by_ip;
  ret.category = flow->category;

  if(flow->fail_with_unknown) {
    // printf("%s(): FAIL_WITH_UNKNOWN\n", __FUNCTION__);
    return(ret);
  }

  if(ndpi_str->max_packets_to_process > 0 && flow->num_processed_pkts >= ndpi_str->max_packets_to_process) {
    flow->extra_packets_func = NULL; /* To allow ndpi_extra_dissection_possible() to fail */
    flow->fail_with_unknown = 1;
    return(ret); /* Avoid spending too much time with this flow */
  }

  flow->num_processed_pkts++;
  ndpi_str->current_ts = current_time_ms;

  /* Init default */

  if(flow->extra_packets_func) {
    ndpi_process_extra_packet(ndpi_str, flow, packet_data, packetlen, current_time_ms, input_info);
    /* Update in case of new match */
    ret.master_protocol = flow->detected_protocol_stack[1],
      ret.app_protocol = flow->detected_protocol_stack[0],
      ret.category = flow->category;

    return(ret);
  } else if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN) {
    if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
      return(ret);

    goto ret_protocols;
  }

  if(ndpi_init_packet(ndpi_str, flow, current_time_ms, packet_data, packetlen, input_info) != 0)
    return(ret);

#ifdef HAVE_NBPF
  if((flow->num_processed_pkts == 1) /* first packet of this flow to be analyzed */
     && (ndpi_str->nbpf_custom_proto[0].tree != NULL)) {
    u_int8_t i;
    nbpf_pkt_info_t t;

    memset(&t, 0, sizeof(t));

    if(packet->iphv6 != NULL) {
      t.tuple.eth_type = 0x86DD;
      t.tuple.ip_version = 6;
      memcpy(&t.tuple.ip_src.v6, &packet->iphv6->ip6_src, 16);
      memcpy(&t.tuple.ip_dst.v6, &packet->iphv6->ip6_dst, 16);
    } else {
      t.tuple.eth_type = 0x0800;
      t.tuple.ip_version = 4;
      t.tuple.ip_src.v4 = packet->iph->saddr;
      t.tuple.ip_dst.v4 = packet->iph->daddr;
    }

    t.tuple.l3_proto = flow->l4_proto;

    if(packet->tcp)
      t.tuple.l4_src_port = packet->tcp->source, t.tuple.l4_dst_port = packet->tcp->dest;
    else if(packet->udp)
      t.tuple.l4_src_port = packet->udp->source, t.tuple.l4_dst_port = packet->udp->dest;

    for(i=0; (i<MAX_NBPF_CUSTOM_PROTO) && (ndpi_str->nbpf_custom_proto[i].tree != NULL); i++) {
      if(nbpf_match(ndpi_str->nbpf_custom_proto[i].tree, &t)) {
	/* match found */
	ret.master_protocol = ret.app_protocol = ndpi_str->nbpf_custom_proto[i].l7_protocol;
	ndpi_fill_protocol_category(ndpi_str, flow, &ret);
	ndpi_reconcile_protocols(ndpi_str, flow, &ret);
	flow->confidence = NDPI_CONFIDENCE_NBPF;

	return(ret);
      }
    }
  }
#endif

  ndpi_connection_tracking(ndpi_str, flow);

  /* build ndpi_selection packet bitmask */
  ndpi_selection_packet = NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC;
  if(packet->iph != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

  if(packet->tcp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(packet->udp != NULL)
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);

  if(packet->payload_packet_len != 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;

  if(packet->tcp_retransmission == 0)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;

  if(packet->iphv6 != NULL)
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;

  if(!flow->protocol_id_already_guessed) {
    flow->protocol_id_already_guessed = 1;

    if(ndpi_do_guess(ndpi_str, flow, &ret) == -1)
      return(ret);
  }

  num_calls = ndpi_check_flow_func(ndpi_str, flow, &ndpi_selection_packet);

 ret_protocols:
  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
    ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];

    if(ret.app_protocol == ret.master_protocol)
      ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  } else
    ret.app_protocol = flow->detected_protocol_stack[0];

  /* Don't overwrite the category if already set */
  if((flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED) && (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
    ndpi_fill_protocol_category(ndpi_str, flow, &ret);
  else
    ret.category = flow->category;

  if((!flow->risk_checked)
     && ((ret.master_protocol != NDPI_PROTOCOL_UNKNOWN) || (ret.app_protocol != NDPI_PROTOCOL_UNKNOWN))
     ) {
    ndpi_default_ports_tree_node_t *found;
    u_int16_t *default_ports;

    if(packet->udp)
      found = ndpi_get_guessed_protocol_id(ndpi_str, IPPROTO_UDP,
					   ntohs(flow->c_port),
					   ntohs(flow->s_port)),
	default_ports = ndpi_str->proto_defaults[ret.master_protocol ? ret.master_protocol : ret.app_protocol].udp_default_ports;
    else if(packet->tcp)
      found = ndpi_get_guessed_protocol_id(ndpi_str, IPPROTO_TCP,
					   ntohs(flow->c_port),
					   ntohs(flow->s_port)),
	default_ports = ndpi_str->proto_defaults[ret.master_protocol ? ret.master_protocol : ret.app_protocol].tcp_default_ports;
    else
      found = NULL, default_ports = NULL;

    if(found
       && (found->proto->protoId != NDPI_PROTOCOL_UNKNOWN)
       && (found->proto->protoId != ret.master_protocol)
       && (found->proto->protoId != ret.app_protocol)
       ) {
      // printf("******** %u / %u\n", found->proto->protoId, ret.master_protocol);

      if(!ndpi_check_protocol_port_mismatch_exceptions(ndpi_str, flow, found, &ret)) {
	/*
	  Before triggering the alert we need to make some extra checks
	  - the protocol found is not running on the port we have found
	  (i.e. two or more protools share the same default port)
	*/
	u_int8_t found = 0, i;

	for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
	  if(default_ports[i] == ntohs(flow->s_port)) {
	    found = 1;
	    break;
	  }
	} /* for */

	if(!found) {
	  ndpi_default_ports_tree_node_t *r = ndpi_get_guessed_protocol_id(ndpi_str, packet->udp ? IPPROTO_UDP : IPPROTO_TCP,
									   ntohs(flow->c_port), ntohs(flow->s_port));

	  if((r == NULL)
	     || ((r->proto->protoId != ret.app_protocol) && (r->proto->protoId != ret.master_protocol))) {
	    if(default_ports[0] != 0) {
		char str[64];
		u_int8_t i, offset;

		offset = snprintf(str, sizeof(str), "Expected on port ");

		for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
		  int rc = snprintf(&str[offset], sizeof(str)-offset, "%s%u",
				    (i > 0) ? "," : "", default_ports[i]);

		  if(rc > 0)
		    offset += rc;
		  else
		    break;
		}

		str[offset] = '\0';
		ndpi_set_risk(ndpi_str, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT, str);
	    }
	  }
	}
      }
    } else if((!ndpi_is_ntop_protocol(&ret)) && default_ports && (default_ports[0] != 0)) {
      u_int8_t found = 0, i, num_loops = 0;

    check_default_ports:
      for(i=0; (i<MAX_DEFAULT_PORTS) && (default_ports[i] != 0); i++) {
	if((default_ports[i] == ntohs(flow->c_port)) || (default_ports[i] == ntohs(flow->s_port))) {
	  found = 1;
	  break;
	}
      } /* for */

      if((num_loops == 0) && (!found)) {
	if(packet->udp)
	  default_ports = ndpi_str->proto_defaults[ret.app_protocol].udp_default_ports;
	else
	  default_ports = ndpi_str->proto_defaults[ret.app_protocol].tcp_default_ports;

	num_loops = 1;
	goto check_default_ports;
      }

      if(!found) {
	ndpi_default_ports_tree_node_t *r = ndpi_get_guessed_protocol_id(ndpi_str, packet->udp ? IPPROTO_UDP : IPPROTO_TCP,
									   ntohs(flow->c_port), ntohs(flow->s_port));

	if((r == NULL)
	   || ((r->proto->protoId != ret.app_protocol) && (r->proto->protoId != ret.master_protocol)))
	  ndpi_set_risk(ndpi_str, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,NULL);
      }
    }

    flow->risk_checked = 1;
  }
  if(!flow->tree_risk_checked) {
    if(ndpi_str->ip_risk_ptree) {
      /* TODO: ipv6 */
      if(packet->iph &&
         ndpi_is_public_ipv4(ntohl(packet->iph->saddr)) &&
         ndpi_is_public_ipv4(ntohl(packet->iph->daddr))) {
        struct in_addr addr;
        ndpi_risk_enum net_risk;

        addr.s_addr = packet->iph->saddr;
        net_risk = ndpi_network_risk_ptree_match(ndpi_str, &addr);
        if(net_risk == NDPI_NO_RISK) {
          addr.s_addr = packet->iph->daddr;
          net_risk = ndpi_network_risk_ptree_match(ndpi_str, &addr);
        }

        if(net_risk != NDPI_NO_RISK)
          ndpi_set_risk(ndpi_str, flow, net_risk, NULL);
      }
    }
    flow->tree_risk_checked = 1;
  }

  /* It is common to don't trigger any dissectors for pure TCP ACKs
     and for for retransmissions */
  if(num_calls == 0 &&
     (packet->tcp_retransmission == 0 && packet->payload_packet_len != 0))
    flow->fail_with_unknown = 1;
  flow->num_dissector_calls += num_calls;

  /* ndpi_reconcile_protocols(ndpi_str, flow, &ret); */

  /* Zoom cache */
  if((ret.app_protocol == NDPI_PROTOCOL_ZOOM)
     && (flow->l4_proto == IPPROTO_TCP))
    ndpi_add_connection_as_zoom(ndpi_str, flow);

  if(ndpi_str->fully_encrypted_based_on_first_pkt_heuristic &&
     ret.app_protocol == NDPI_PROTOCOL_UNKNOWN && /* Only for unknown traffic */
     flow->packet_counter == 1 && packet->payload_packet_len > 0) {
   flow->first_pkt_fully_encrypted = fully_enc_heuristic(ndpi_str, flow);
  }

  return(ret);
}

/* ********************************************************************************* */

ndpi_protocol ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_str,
					    struct ndpi_flow_struct *flow, const unsigned char *packet_data,
					    const unsigned short packetlen, const u_int64_t current_time_ms,
					    const struct ndpi_flow_input_info *input_info) {


  ndpi_protocol p  = ndpi_internal_detection_process_packet(ndpi_str, flow, packet_data,
							    packetlen, current_time_ms,
							    input_info);

  p.master_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, p.master_protocol),
    p.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, p.app_protocol);

  return(p);
}

/* ********************************************************************************* */

u_int32_t ndpi_bytestream_to_number(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  val = 0;

  // cancel if eof, ' ' or line end chars are reached
  while(max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }

  return(val);
}

/* ********************************************************************************* */

#ifdef CODE_UNUSED
u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return(ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read));
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;

    while(max_chars_to_read > 0) {
      if(*str >= '0' && *str <= '9') {
	val *= 16;
	val += *str - '0';
      } else if(*str >= 'a' && *str <= 'f') {
	val *= 16;
	val += *str + 10 - 'a';
      } else if(*str >= 'A' && *str <= 'F') {
	val *= 16;
	val += *str + 10 - 'A';
      } else {
	break;
      }
      str++;
      max_chars_to_read = max_chars_to_read - 1;
      *bytes_read = *bytes_read + 1;
    }
  }

  return(val);
}

#endif

/* ********************************************************************************* */

u_int64_t ndpi_bytestream_to_number64(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int64_t val;
  val = 0;
  // cancel if eof, ' ' or line end chars are reached
  while(max_chars_to_read > 0 && *str >= '0' && *str <= '9') {
    val *= 10;
    val += *str - '0';
    str++;
    max_chars_to_read = max_chars_to_read - 1;
    *bytes_read = *bytes_read + 1;
  }
  return(val);
}

/* ********************************************************************************* */

u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t *str, u_int16_t max_chars_to_read,
						 u_int16_t *bytes_read) {
  u_int64_t val;
  val = 0;
  if(max_chars_to_read <= 2 || str[0] != '0' || str[1] != 'x') {
    return(ndpi_bytestream_to_number64(str, max_chars_to_read, bytes_read));
  } else {
    /*use base 16 system */
    str += 2;
    max_chars_to_read -= 2;
    *bytes_read = *bytes_read + 2;
    while(max_chars_to_read > 0) {
      if(*str >= '0' && *str <= '9') {
	val *= 16;
	val += *str - '0';
      } else if(*str >= 'a' && *str <= 'f') {
	val *= 16;
	val += *str + 10 - 'a';
      } else if(*str >= 'A' && *str <= 'F') {
	val *= 16;
	val += *str + 10 - 'A';
      } else {
	break;
      }
      str++;
      max_chars_to_read = max_chars_to_read - 1;
      *bytes_read = *bytes_read + 1;
    }
  }
  return(val);
}

/* ********************************************************************************* */

u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t *str, u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int32_t val;
  u_int16_t read = 0;
  u_int16_t oldread;
  u_int32_t c;

  /* ip address must be X.X.X.X with each X between 0 and 255 */
  oldread = read;
  c = ndpi_bytestream_to_number(str, max_chars_to_read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = c << 24;
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = val + (c << 16);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);

  read++;
  val = val + (c << 8);
  oldread = read;
  c = ndpi_bytestream_to_number(&str[read], max_chars_to_read - read, &read);
  if(c > 255 || oldread == read || max_chars_to_read == read)
    return(0);

  val = val + c;

  *bytes_read = *bytes_read + read;

  return(htonl(val));
}

/* ********************************************************************************* */

void ndpi_parse_single_packet_line(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  /* First line of a HTTP response parsing. Expected a "HTTP/1.? ???" */
  if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.X 200 ") &&
     strncasecmp((const char *) packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] > '0' && /* response code between 000 and 699 */
     packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.X ")] < '6') {
    packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
    packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
    packet->http_num_headers++;
  }

  if((packet->parsed_lines == 0) && (packet->line[0].len > 0)) {
    /*
       Check if the file contains a : otherwise ignore the line as this
       line i slike "GET /....
    */

    if(memchr((char*)packet->line[0].ptr, ':', packet->line[0].len) == NULL)
      return;
  }

  /* "Server:" header line in HTTP response */
  if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1 &&
     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr,
		 "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
    // some stupid clients omit a space and place the servername directly after the colon
    if(packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")] == ' ') {
      packet->server_line.ptr =
	&packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:") + 1];
      packet->server_line.len =
	packet->line[packet->parsed_lines].len - (NDPI_STATICSTRING_LEN("Server:") + 1);
    } else {
      packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")];
      packet->server_line.len = packet->line[packet->parsed_lines].len - NDPI_STATICSTRING_LEN("Server:");
    }
    packet->http_num_headers++;
  } else
    /* "Host:" header line in HTTP request */
    if(packet->line[packet->parsed_lines].len > 6 &&
       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Host:", 5) == 0) {
      // some stupid clients omit a space and place the hostname directly after the colon
      if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
	packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
	packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
      } else {
	packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
	packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
      }
      packet->http_num_headers++;
    } else
      /* "X-Forwarded-For:" header line in HTTP request. Commonly used for HTTP proxies. */
      if(packet->line[packet->parsed_lines].len > 17 &&
	 strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
	} else {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
	}
	packet->http_num_headers++;
      } else

	/* "Authorization:" header line in HTTP. */
	if(packet->line[packet->parsed_lines].len > 15 &&
	   (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Authorization: ", 15) == 0)) {
	  packet->authorization_line.ptr = &packet->line[packet->parsed_lines].ptr[15];
	  packet->authorization_line.len = packet->line[packet->parsed_lines].len - 15;

	  while((packet->authorization_line.len > 0) && (packet->authorization_line.ptr[0] == ' '))
	    packet->authorization_line.len--, packet->authorization_line.ptr++;
	  if(packet->authorization_line.len == 0)
	    packet->authorization_line.ptr = NULL;

	  packet->http_num_headers++;
	} else
	  /* "Accept:" header line in HTTP request. */
	  if(packet->line[packet->parsed_lines].len > 8 &&
	     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
	    packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
	    packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
	    packet->http_num_headers++;
	  } else
	    /* "Referer:" header line in HTTP request. */
	    if(packet->line[packet->parsed_lines].len > 9 &&
	       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
	      packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
	      packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
	      packet->http_num_headers++;
	    } else
	      /* "User-Agent:" header line in HTTP request. */
	      if(packet->line[packet->parsed_lines].len > 12 &&
		 strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0) {
		packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
		packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
		packet->http_num_headers++;
	      } else
		/* "Content-Encoding:" header line in HTTP response (and request?). */
		if(packet->line[packet->parsed_lines].len > 18 &&
		   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
		  packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
		  packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
		  packet->http_num_headers++;
		} else
		  /* "Transfer-Encoding:" header line in HTTP. */
		  if(packet->line[packet->parsed_lines].len > 19 &&
		     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
		    packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
		    packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
		    packet->http_num_headers++;
		  } else
		    /* "Content-Length:" header line in HTTP. */
		    if(packet->line[packet->parsed_lines].len > 16 &&
		       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0) {
		      packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
		      packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
		      packet->http_num_headers++;
		    } else
		      /* "Content-Disposition"*/
		      if(packet->line[packet->parsed_lines].len > 21 &&
			 ((strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Disposition: ", 21) == 0))) {
			packet->content_disposition_line.ptr = &packet->line[packet->parsed_lines].ptr[21];
			packet->content_disposition_line.len = packet->line[packet->parsed_lines].len - 21;
			packet->http_num_headers++;
		      } else
			/* "Cookie:" header line in HTTP. */
			if(packet->line[packet->parsed_lines].len > 8 &&
			   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
			  packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
			  packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
			  packet->http_num_headers++;
			} else
			  /* "Origin:" header line in HTTP. */
			  if(packet->line[packet->parsed_lines].len > 8 &&
			     strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Origin: ", 8) == 0) {
			    packet->http_origin.ptr = &packet->line[packet->parsed_lines].ptr[8];
			    packet->http_origin.len = packet->line[packet->parsed_lines].len - 8;
			    packet->http_num_headers++;
			  } else
			    /* "X-Session-Type:" header line in HTTP. */
			    if(packet->line[packet->parsed_lines].len > 16 &&
			       strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
			      packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
			      packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
			      packet->http_num_headers++;
			    } else
			      /* Identification and counting of other HTTP headers.
			       * We consider the most common headers, but there are many others,
			       * which can be seen at references below:
			       * - https://tools.ietf.org/html/rfc7230
			       * - https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
			       */
			      if((packet->line[packet->parsed_lines].len > 6 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Date: ", 6) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Vary: ", 6) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "ETag: ", 6) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 8 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Pragma: ", 8) == 0) ||
				 (packet->line[packet->parsed_lines].len > 9 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Expires: ", 9) == 0) ||
				 (packet->line[packet->parsed_lines].len > 12 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Set-Cookie: ", 12) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Keep-Alive: ", 12) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Connection: ", 12) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 15 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Last-Modified: ", 15) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Ranges: ", 15) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 17 &&
				  (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Language: ", 17) == 0 ||
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Accept-Encoding: ", 17) == 0)) ||
				 (packet->line[packet->parsed_lines].len > 27 &&
				  strncasecmp((const char *) packet->line[packet->parsed_lines].ptr,
					      "Upgrade-Insecure-Requests: ", 27) == 0)) {
				/* Just count. In the future, if needed, this if can be splited to parse these headers */
				packet->http_num_headers++;
			      } else
				/* "Content-Type:" header line in HTTP. */
				if(packet->line[packet->parsed_lines].len > 14 &&
				   strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-Type: ", 14) == 0 ) {
				  packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
				  packet->content_line.len = packet->line[packet->parsed_lines].len - 14;

				  while((packet->content_line.len > 0) && (packet->content_line.ptr[0] == ' '))
				    packet->content_line.len--, packet->content_line.ptr++;
				  if(packet->content_line.len == 0)
				    packet->content_line.ptr = NULL;;

				  packet->http_num_headers++;
				} else

				  /* "Content-Type:" header line in HTTP AGAIN. Probably a bogus response without space after ":" */
				  if((packet->content_line.len == 0) && (packet->line[packet->parsed_lines].len > 13) &&
				     (strncasecmp((const char *) packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0)) {
				    packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
				    packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
				    packet->http_num_headers++;
				  }

  if(packet->content_line.len > 0) {
    /* application/json; charset=utf-8 */
    char separator[] = {';', '\r', '\0'};
    int i;

    for(i = 0; separator[i] != '\0'; i++) {
      char *c = memchr((char *) packet->content_line.ptr, separator[i], packet->content_line.len);

      if(c != NULL)
	packet->content_line.len = c - (char *) packet->content_line.ptr;
    }
  }
}

/* ********************************************************************************* */

/* internal function for every detection to parse one packet and to increase the info buffer */
void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  u_int32_t a;
  struct ndpi_packet_struct *packet = &ndpi_str->packet;

  if((packet->payload_packet_len < 3) || (packet->payload == NULL))
    return;

  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  ndpi_reset_packet_line_info(packet);

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; ((a+1) < packet->payload_packet_len) && (packet->parsed_lines < NDPI_MAX_PARSE_LINES_PER_PACKET); a++) {
    if((packet->payload[a] == 0x0d) && (packet->payload[a+1] == 0x0a)) {
      /* If end of line char sequence CR+NL "\r\n", process line */

      if(((a + 3) < packet->payload_packet_len)
	 && (packet->payload[a+2] == 0x0d)
	 && (packet->payload[a+3] == 0x0a)) {
	/* \r\n\r\n */
	int diff; /* No unsigned ! */
	u_int32_t a1 = a + 4;

	diff = packet->payload_packet_len - a1;

	if(diff > 0) {
	  diff = ndpi_min((unsigned int)diff, sizeof(flow->initial_binary_bytes));
	  memcpy(&flow->initial_binary_bytes, &packet->payload[a1], diff);
	  flow->initial_binary_bytes_len = diff;
	}
      }

      packet->line[packet->parsed_lines].len =
	(u_int16_t)(((size_t) &packet->payload[a]) - ((size_t) packet->line[packet->parsed_lines].ptr));

      ndpi_parse_single_packet_line(ndpi_str, flow);

      if(packet->line[packet->parsed_lines].len == 0) {
	packet->empty_line_position = a;
	packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
	return;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      a++; /* next char in the payload */
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len =
      (u_int16_t)(((size_t) &packet->payload[packet->payload_packet_len]) -
		  ((size_t) packet->line[packet->parsed_lines].ptr));

    ndpi_parse_single_packet_line(ndpi_str, flow);
    packet->parsed_lines++;
  }
}

/* ********************************************************************************* */

void ndpi_parse_packet_line_info_any(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_str->packet;
  u_int32_t a;
  u_int16_t end = packet->payload_packet_len;

  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  packet->parsed_lines = 0;

  if(packet->payload_packet_len == 0)
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for(a = 0; a < end; a++) {
    if(packet->payload[a] == 0x0a) {
      packet->line[packet->parsed_lines].len = (u_int16_t)(
							   ((size_t) &packet->payload[a]) - ((size_t) packet->line[packet->parsed_lines].ptr));

      if(a > 0 && packet->payload[a - 1] == 0x0d)
	packet->line[packet->parsed_lines].len--;

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1))
	break;

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 1];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 1) >= packet->payload_packet_len)
	break;

      //a++;
    }
  }
}

/* ********************************************************************************* */

u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_str,
				       u_int16_t counter) {
  struct ndpi_packet_struct *packet;

  if(!ndpi_str)
    return(0);

  packet = &ndpi_str->packet;
  NDPI_LOG_DBG2(ndpi_str, "called ndpi_check_for_email_address\n");

  if(packet->payload_packet_len > counter && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z') ||
					      (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z') ||
					      (packet->payload[counter] >= '0' && packet->payload[counter] <= '9') ||
					      packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
    NDPI_LOG_DBG2(ndpi_str, "first letter\n");
    counter++;
    while(packet->payload_packet_len > counter &&
	  ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z') ||
	   (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z') ||
	   (packet->payload[counter] >= '0' && packet->payload[counter] <= '9') ||
	   packet->payload[counter] == '-' || packet->payload[counter] == '_' ||
	   packet->payload[counter] == '.')) {
      NDPI_LOG_DBG2(ndpi_str, "further letter\n");
      counter++;
      if(packet->payload_packet_len > counter && packet->payload[counter] == '@') {
	NDPI_LOG_DBG2(ndpi_str, "@\n");
	counter++;
	while(packet->payload_packet_len > counter &&
	      ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z') ||
	       (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z') ||
	       (packet->payload[counter] >= '0' && packet->payload[counter] <= '9') ||
	       packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
	  NDPI_LOG_DBG2(ndpi_str, "letter\n");
	  counter++;
	  if(packet->payload_packet_len > counter && packet->payload[counter] == '.') {
	    NDPI_LOG_DBG2(ndpi_str, ".\n");
	    counter++;
	    if(packet->payload_packet_len > counter + 1 &&
	       ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z') &&
		(packet->payload[counter + 1] >= 'a' && packet->payload[counter + 1] <= 'z'))) {
	      NDPI_LOG_DBG2(ndpi_str, "two letters\n");
	      counter += 2;
	      if(packet->payload_packet_len > counter &&
		 (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		NDPI_LOG_DBG2(ndpi_str, "whitespace1\n");
		return(counter);
	      } else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a' &&
			packet->payload[counter] <= 'z') {
		NDPI_LOG_DBG2(ndpi_str, "one letter\n");
		counter++;
		if(packet->payload_packet_len > counter &&
		   (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		  NDPI_LOG_DBG2(ndpi_str, "whitespace2\n");
		  return(counter);
		} else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a' &&
			  packet->payload[counter] <= 'z') {
		  counter++;
		  if(packet->payload_packet_len > counter &&
		     (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		    NDPI_LOG_DBG2(ndpi_str, "whitespace3\n");
		    return(counter);
		  } else {
		    return(0);
		  }
		} else {
		  return(0);
		}
	      } else {
		return(0);
	      }
	    } else {
	      return(0);
	    }
	  }
	}
	return(0);
      }
    }
  }
  return(0);
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
/* ********************************************************************************* */

void ndpi_debug_get_last_log_function_line(struct ndpi_detection_module_struct *ndpi_str, const char **file,
					   const char **func, u_int32_t *line) {
  *file = "";
  *func = "";

  if(ndpi_str->ndpi_debug_print_file != NULL)
    *file = ndpi_str->ndpi_debug_print_file;

  if(ndpi_str->ndpi_debug_print_function != NULL)
    *func = ndpi_str->ndpi_debug_print_function;

  *line = ndpi_str->ndpi_debug_print_line;
}
#endif

/* ********************************************************************************* */

u_int8_t ndpi_detection_get_l4(const u_int8_t *l3, u_int16_t l3_len, const u_int8_t **l4_return,
			       u_int16_t *l4_len_return, u_int8_t *l4_protocol_return, u_int32_t flags) {
  return(ndpi_detection_get_l4_internal(NULL, l3, l3_len, l4_return, l4_len_return, l4_protocol_return, flags));
}

/* ********************************************************************************* */

void ndpi_set_detected_protocol_keeping_master(struct ndpi_detection_module_struct *ndpi_str,
					       struct ndpi_flow_struct *flow,
					       u_int16_t detected_protocol,
					       ndpi_confidence_t confidence) {
  u_int16_t master;

  master = flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

  if (master != NDPI_PROTOCOL_UNKNOWN)
    ndpi_set_detected_protocol(ndpi_str, flow, detected_protocol, master, confidence);
  else
    ndpi_set_detected_protocol(ndpi_str, flow, NDPI_PROTOCOL_UNKNOWN, detected_protocol, confidence);
}

/* ********************************************************************************* */

void ndpi_set_detected_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
				ndpi_confidence_t confidence) {
  ndpi_protocol ret;

  ndpi_int_change_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol, confidence);
  ret.master_protocol = flow->detected_protocol_stack[1], ret.app_protocol = flow->detected_protocol_stack[0];
  ndpi_reconcile_protocols(ndpi_str, flow, &ret);
}

/* ********************************************************************************* */

u_int16_t ndpi_get_flow_masterprotocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  return(flow->detected_protocol_stack[1]);
}

/* ********************************************************************************* */

u_int16_t ndpi_get_flow_appprotocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow) {
  return(flow->detected_protocol_stack[0]);
}

/* ********************************************************************************* */

ndpi_protocol_category_t ndpi_get_flow_category(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow)
{
  return(flow->category);
}

/* ********************************************************************************* */

void ndpi_get_flow_ndpi_proto(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
			      struct ndpi_proto * ndpi_proto)
{
  ndpi_proto->master_protocol = ndpi_get_flow_masterprotocol(ndpi_str, flow);
  ndpi_proto->app_protocol = ndpi_get_flow_appprotocol(ndpi_str, flow);
  ndpi_proto->category = ndpi_get_flow_category(ndpi_str, flow);
}

/* ********************************************************************************* */

static void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
					  u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
					  ndpi_confidence_t confidence) {
  if(!flow)
    return;

  flow->detected_protocol_stack[0] = upper_detected_protocol,
  flow->detected_protocol_stack[1] = lower_detected_protocol;
  flow->confidence = confidence;
}

/* ********************************************************************************* */

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 */
static void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
				     u_int16_t upper_detected_protocol, u_int16_t lower_detected_protocol,
				     ndpi_confidence_t confidence) {
  if((upper_detected_protocol == NDPI_PROTOCOL_UNKNOWN) && (lower_detected_protocol != NDPI_PROTOCOL_UNKNOWN))
    upper_detected_protocol = lower_detected_protocol;

  if(upper_detected_protocol == lower_detected_protocol)
    lower_detected_protocol = NDPI_PROTOCOL_UNKNOWN;

  ndpi_int_change_flow_protocol(ndpi_str, flow, upper_detected_protocol, lower_detected_protocol, confidence);
}

/* ********************************************************************************* */

void ndpi_int_change_category(struct ndpi_detection_module_struct *ndpi_str, struct ndpi_flow_struct *flow,
			      ndpi_protocol_category_t protocol_category) {
  flow->category = protocol_category;
}

/* ********************************************************************************* */

void NDPI_PROTOCOL_IP_clear(ndpi_ip_addr_t *ip) {
  memset(ip, 0, sizeof(ndpi_ip_addr_t));
}

/* ********************************************************************************* */

#ifdef CODE_UNUSED
/* NTOP */
int NDPI_PROTOCOL_IP_is_set(const ndpi_ip_addr_t *ip) {
  return(memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(ndpi_ip_addr_t)) != 0);
}
#endif

/* ********************************************************************************* */

/* check if the source ip address in packet and ip are equal */
/* NTOP */
int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t *ip) {
  /* IPv6 */
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->ip6_src.u6_addr.u6_addr32[0] == ip->ipv6.u6_addr.u6_addr32[0] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[1] == ip->ipv6.u6_addr.u6_addr32[1] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[2] == ip->ipv6.u6_addr.u6_addr32[2] &&
       packet->iphv6->ip6_src.u6_addr.u6_addr32[3] == ip->ipv6.u6_addr.u6_addr32[3])
      return(1);
    //else
    return(0);
  }

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return(1);
  return(0);
}

/* ********************************************************************************* */

/* check if the destination ip address in packet and ip are equal */
int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t *ip) {
  /* IPv6 */
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->ip6_dst.u6_addr.u6_addr32[0] == ip->ipv6.u6_addr.u6_addr32[0] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[1] == ip->ipv6.u6_addr.u6_addr32[1] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[2] == ip->ipv6.u6_addr.u6_addr32[2] &&
       packet->iphv6->ip6_dst.u6_addr.u6_addr32[3] == ip->ipv6.u6_addr.u6_addr32[3])
      return(1);
    //else
    return(0);
  }

  /* IPv4 */
  if(packet->iph->saddr == ip->ipv4)
    return(1);

  return(0);
}

/* ********************************************************************************* */

/* get the source ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t *ip) {
  NDPI_PROTOCOL_IP_clear(ip);

  /* IPv6 */
  if(packet->iphv6 != NULL) {
    ip->ipv6.u6_addr.u6_addr32[0] = packet->iphv6->ip6_src.u6_addr.u6_addr32[0];
    ip->ipv6.u6_addr.u6_addr32[1] = packet->iphv6->ip6_src.u6_addr.u6_addr32[1];
    ip->ipv6.u6_addr.u6_addr32[2] = packet->iphv6->ip6_src.u6_addr.u6_addr32[2];
    ip->ipv6.u6_addr.u6_addr32[3] = packet->iphv6->ip6_src.u6_addr.u6_addr32[3];
  } else {
    /* IPv4 */
    ip->ipv4 = packet->iph->saddr;
  }
}

/* ********************************************************************************* */

/* get the destination ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t *ip) {
  NDPI_PROTOCOL_IP_clear(ip);

  if(packet->iphv6 != NULL) {
    ip->ipv6.u6_addr.u6_addr32[0] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[0];
    ip->ipv6.u6_addr.u6_addr32[1] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[1];
    ip->ipv6.u6_addr.u6_addr32[2] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[2];
    ip->ipv6.u6_addr.u6_addr32[3] = packet->iphv6->ip6_dst.u6_addr.u6_addr32[3];

  } else
    ip->ipv4 = packet->iph->daddr;
}

/* ********************************************************************************* */

u_int8_t ndpi_is_ipv6(const ndpi_ip_addr_t *ip) {
  return(ip->ipv6.u6_addr.u6_addr32[1] != 0 || ip->ipv6.u6_addr.u6_addr32[2] != 0 ||
	 ip->ipv6.u6_addr.u6_addr32[3] != 0);
}

/* ********************************************************************************* */

char *ndpi_get_ip_string(const ndpi_ip_addr_t *ip, char *buf, u_int buf_len) {
  const u_int8_t *a = (const u_int8_t *) &ip->ipv4;

  if(ndpi_is_ipv6(ip)) {
    struct in6_addr addr = *(struct in6_addr *)&ip->ipv6.u6_addr;

    if(inet_ntop(AF_INET6, &addr, buf, buf_len) == NULL)
      buf[0] = '\0';

    return(buf);
  }

  ndpi_snprintf(buf, buf_len, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);

  return(buf);
}

/* ****************************************************** */

/* Returns -1 on failutre, otherwise fills parsed_ip and returns the IP version */
int ndpi_parse_ip_string(const char *ip_str, ndpi_ip_addr_t *parsed_ip) {
  int rv = -1;
  memset(parsed_ip, 0, sizeof(*parsed_ip));

  if(strchr(ip_str, '.')) {
    if(inet_pton(AF_INET, ip_str, &parsed_ip->ipv4) > 0)
      rv = 4;
  } else {
    if(inet_pton(AF_INET6, ip_str, &parsed_ip->ipv6) > 0)
      rv = 6;
  }

  return(rv);
}

/* ****************************************************** */

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t *str,
					  u_int16_t max_chars_to_read, u_int16_t *bytes_read) {
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return(ntohs(val));
}

/* ****************************************************** */

u_int8_t ndpi_is_proto(ndpi_protocol proto, u_int16_t p) {
  return(((proto.app_protocol == p) || (proto.master_protocol == p)) ? 1 : 0);
}

/* ****************************************************** */

u_int16_t ndpi_get_lower_proto(ndpi_protocol proto) {
  return((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) ? proto.master_protocol : proto.app_protocol);
}

/* ****************************************************** */

u_int16_t ndpi_get_upper_proto(ndpi_protocol proto) {
  return((proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) ? proto.app_protocol : proto.master_protocol);
}

/* ****************************************************** */

static ndpi_protocol ndpi_internal_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_str,
							     struct ndpi_flow_struct *flow, u_int8_t proto) {
  ndpi_protocol ret = NDPI_PROTOCOL_NULL;
  u_int8_t user_defined_proto;

  if(!ndpi_str)
    return(ret);

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] [flow: %p] proto %u\n", __FILE__, __LINE__, flow, proto);
#endif

  if(flow && ((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP))) {
    if(flow->guessed_protocol_id != NDPI_PROTOCOL_UNKNOWN) {
      if(flow->guessed_protocol_id_by_ip != NDPI_PROTOCOL_UNKNOWN) {
        ret.master_protocol = flow->guessed_protocol_id;
        ret.app_protocol = flow->guessed_protocol_id_by_ip;
      } else {
        ret.app_protocol = flow->guessed_protocol_id;
      }
    } else {
      ret.app_protocol = flow->guessed_protocol_id_by_ip;
    }

    if(ret.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
       ndpi_search_into_bittorrent_cache(ndpi_str, flow)) {
      /* This looks like BitTorrent */
      ret.app_protocol = NDPI_PROTOCOL_BITTORRENT;
    }
  } else {
    ret.app_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, 0, 0, &user_defined_proto);
  }

  ret.category = ndpi_get_proto_category(ndpi_str, ret);

#ifdef BITTORRENT_CACHE_DEBUG
  printf("[%s:%u] Guessed %u.%u\n", __FILE__, __LINE__, ret.master_protocol, ret.app_protocol);
#endif

  return(ret);
}

/* ****************************************************** */

/* Extension of ndpi_guess_undetected_protocol() with IPv4 matching for host and protocol */

ndpi_protocol ndpi_guess_undetected_protocol_v4(struct ndpi_detection_module_struct *ndpi_str,
						struct ndpi_flow_struct *flow, u_int8_t proto,
						u_int32_t shost /* host byte order */, u_int16_t sport,
						u_int32_t dhost /* host byte order */, u_int16_t dport) {
  u_int32_t rc;
  ndpi_protocol ret = NDPI_PROTOCOL_NULL;
  u_int8_t user_defined_proto;

  if(!ndpi_str)
    return ret;

  if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) {
    if(shost && dhost)
      rc = ndpi_search_tcp_or_udp_raw(ndpi_str, flow, proto, shost, dhost);
    else
      rc = NDPI_PROTOCOL_UNKNOWN;

    if(rc != NDPI_PROTOCOL_UNKNOWN) {
      ret.app_protocol = rc,
	ret.master_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto);

      if(ret.app_protocol == ret.master_protocol)
	ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    } else {
      ret.app_protocol = ndpi_guess_protocol_id(ndpi_str, flow, proto, sport, dport, &user_defined_proto),
	ret.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    }

    if(ret.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
      ret.category = ndpi_get_proto_category(ndpi_str, ret);
      return(ret);
    }
  }

  return(ndpi_guess_undetected_protocol(ndpi_str, flow, proto));
}

/* ****************************************************** */

ndpi_protocol ndpi_guess_undetected_protocol(struct ndpi_detection_module_struct *ndpi_str,
					     struct ndpi_flow_struct *flow, u_int8_t proto) {
  ndpi_protocol p = ndpi_internal_guess_undetected_protocol(ndpi_str, flow, proto);

  p.master_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, p.master_protocol),
    p.app_protocol = ndpi_map_ndpi_id_to_user_proto_id(ndpi_str, p.app_protocol);

  return(p);
}

/* ****************************************************** */

char *ndpi_protocol2id(struct ndpi_detection_module_struct *ndpi_str,
		       ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      ndpi_snprintf(buf, buf_len, "%u.%u", proto.master_protocol, proto.app_protocol);
    else
      ndpi_snprintf(buf, buf_len, "%u", proto.master_protocol);
  } else
    ndpi_snprintf(buf, buf_len, "%u", proto.app_protocol);

  return(buf);
}

/* ****************************************************** */

char *ndpi_protocol2name(struct ndpi_detection_module_struct *ndpi_str,
			 ndpi_protocol proto, char *buf, u_int buf_len) {
  if((proto.master_protocol != NDPI_PROTOCOL_UNKNOWN) && (proto.master_protocol != proto.app_protocol)) {
    if(proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
      ndpi_snprintf(buf, buf_len, "%s.%s", ndpi_get_proto_name(ndpi_str, proto.master_protocol),
	       ndpi_get_proto_name(ndpi_str, proto.app_protocol));
    else
      ndpi_snprintf(buf, buf_len, "%s", ndpi_get_proto_name(ndpi_str, proto.master_protocol));
  } else
    ndpi_snprintf(buf, buf_len, "%s", ndpi_get_proto_name(ndpi_str, proto.app_protocol));

  return(buf);
}

/* ****************************************************** */

int ndpi_is_custom_category(ndpi_protocol_category_t category) {
  switch(category) {
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
    return(1);

  default:
    return(0);
  }
}

/* ****************************************************** */

void ndpi_category_set_name(struct ndpi_detection_module_struct *ndpi_str,
			    ndpi_protocol_category_t category,
			    char *name) {
  if(!ndpi_str || !name)
    return;

  switch(category) {
  case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
    ndpi_snprintf(ndpi_str->custom_category_labels[0], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
    ndpi_snprintf(ndpi_str->custom_category_labels[1], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
    ndpi_snprintf(ndpi_str->custom_category_labels[2], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
    ndpi_snprintf(ndpi_str->custom_category_labels[3], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
    ndpi_snprintf(ndpi_str->custom_category_labels[4], CUSTOM_CATEGORY_LABEL_LEN, "%s", name);
    break;

  default:
    break;
  }
}

/* ****************************************************** */

const char *ndpi_confidence_get_name(ndpi_confidence_t confidence)
{
  switch(confidence) {
  case NDPI_CONFIDENCE_UNKNOWN:
    return "Unknown";

  case NDPI_CONFIDENCE_MATCH_BY_PORT:
    return "Match by port";

  case NDPI_CONFIDENCE_DPI_PARTIAL:
    return "DPI (partial)";

  case NDPI_CONFIDENCE_DPI_PARTIAL_CACHE:
    return "DPI (partial cache)";

  case NDPI_CONFIDENCE_DPI_CACHE:
    return "DPI (cache)";

  case NDPI_CONFIDENCE_DPI:
    return "DPI";

  case NDPI_CONFIDENCE_NBPF:
    return "nBPF";

  case NDPI_CONFIDENCE_MATCH_BY_IP:
    return "Match by IP";

  case NDPI_CONFIDENCE_DPI_AGGRESSIVE:
    return "DPI (aggressive)";

  default:
    return NULL;
  }
}

/* ****************************************************** */

const char *ndpi_category_get_name(struct ndpi_detection_module_struct *ndpi_str,
				   ndpi_protocol_category_t category) {
  if((!ndpi_str) || (category >= NDPI_PROTOCOL_NUM_CATEGORIES)) {
    static char b[24];

    if(!ndpi_str)
      ndpi_snprintf(b, sizeof(b), "NULL nDPI");
    else
      ndpi_snprintf(b, sizeof(b), "Invalid category %d", (int) category);
    return(b);
  }

  if((category >= NDPI_PROTOCOL_CATEGORY_CUSTOM_1) && (category <= NDPI_PROTOCOL_CATEGORY_CUSTOM_5)) {
    switch(category) {
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_1:
      return(ndpi_str->custom_category_labels[0]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_2:
      return(ndpi_str->custom_category_labels[1]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_3:
      return(ndpi_str->custom_category_labels[2]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_4:
      return(ndpi_str->custom_category_labels[3]);
    case NDPI_PROTOCOL_CATEGORY_CUSTOM_5:
      return(ndpi_str->custom_category_labels[4]);
    case NDPI_PROTOCOL_NUM_CATEGORIES:
      return("Code should not use this internal constant");
    default:
      return("Unspecified");
    }
  } else
    return(categories[category]);
}

/* ****************************************************** */

static int category_depends_on_master(int proto)
{
  switch(proto) {
  case NDPI_PROTOCOL_MAIL_POP:
  case NDPI_PROTOCOL_MAIL_SMTP:
  case NDPI_PROTOCOL_MAIL_IMAP:
  case NDPI_PROTOCOL_MAIL_POPS:
  case NDPI_PROTOCOL_MAIL_SMTPS:
  case NDPI_PROTOCOL_MAIL_IMAPS:
  case NDPI_PROTOCOL_DNS:
	  return 1;
  }
  return 0;
}

/* ****************************************************** */

ndpi_protocol_category_t ndpi_get_proto_category(struct ndpi_detection_module_struct *ndpi_str,
						 ndpi_protocol proto) {

  if(proto.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    return(proto.category);

#if 0
  proto.master_protocol = ndpi_map_user_proto_id_to_ndpi_id(ndpi_str, proto.master_protocol),
    proto.app_protocol = ndpi_map_user_proto_id_to_ndpi_id(ndpi_str, proto.app_protocol);
#endif

  /* Simple rule: sub protocol first, master after, with some exceptions (i.e. mail) */

  if(category_depends_on_master(proto.master_protocol)) {
    if(ndpi_is_valid_protoId(proto.master_protocol))
      return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);
  } else if((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) ||
	  (ndpi_str->proto_defaults[proto.app_protocol].protoCategory != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)) {
    if(ndpi_is_valid_protoId(proto.app_protocol))
      return(ndpi_str->proto_defaults[proto.app_protocol].protoCategory);
  } else if(ndpi_is_valid_protoId(proto.master_protocol))
    return(ndpi_str->proto_defaults[proto.master_protocol].protoCategory);

  return(NDPI_PROTOCOL_CATEGORY_UNSPECIFIED);
}

/* ****************************************************** */

char *ndpi_get_proto_name(struct ndpi_detection_module_struct *ndpi_str,
			  u_int16_t proto_id) {
  if(!ndpi_str) return("Unknown");

  proto_id = ndpi_map_user_proto_id_to_ndpi_id(ndpi_str, proto_id);

  if((proto_id >= ndpi_str->ndpi_num_supported_protocols)
     || (!ndpi_is_valid_protoId(proto_id))
     || (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoName);
}

/* ****************************************************** */

ndpi_protocol_breed_t ndpi_get_proto_breed(struct ndpi_detection_module_struct *ndpi_str,
					   u_int16_t proto_id) {

  if(!ndpi_str) return(NDPI_PROTOCOL_UNRATED);

  proto_id = ndpi_map_user_proto_id_to_ndpi_id(ndpi_str, proto_id);

  if((proto_id >= ndpi_str->ndpi_num_supported_protocols) ||
     (!ndpi_is_valid_protoId(proto_id)) ||
     (ndpi_str->proto_defaults[proto_id].protoName == NULL))
    proto_id = NDPI_PROTOCOL_UNKNOWN;

  return(ndpi_str->proto_defaults[proto_id].protoBreed);
}

/* ****************************************************** */

char *ndpi_get_proto_breed_name(struct ndpi_detection_module_struct *ndpi_str,
				ndpi_protocol_breed_t breed_id) {
  switch(breed_id) {
  case NDPI_PROTOCOL_SAFE:
    return("Safe");
  case NDPI_PROTOCOL_ACCEPTABLE:
    return("Acceptable");
  case NDPI_PROTOCOL_FUN:
    return("Fun");
  case NDPI_PROTOCOL_UNSAFE:
    return("Unsafe");
  case NDPI_PROTOCOL_POTENTIALLY_DANGEROUS:
    return("Potentially Dangerous");
  case NDPI_PROTOCOL_TRACKER_ADS:
    return("Tracker/Ads");
  case NDPI_PROTOCOL_DANGEROUS:
    return("Dangerous");
  case NDPI_PROTOCOL_UNRATED:
    return("Unrated");
  default:
    return("???");
  }
}

/* ****************************************************** */

int ndpi_get_protocol_id(struct ndpi_detection_module_struct *ndpi_str, char *proto) {
  int i;

  if(!ndpi_str) return(-1);

  for(i = 0; i < (int) ndpi_str->ndpi_num_supported_protocols; i++)
    if(ndpi_str->proto_defaults[i].protoName &&
       strcasecmp(proto, ndpi_str->proto_defaults[i].protoName) == 0)
      return(i);

  return(-1);
}

/* ****************************************************** */

int ndpi_get_category_id(struct ndpi_detection_module_struct *ndpi_str, char *cat) {
  int i;

  if(!ndpi_str) return(-1);

  for(i = 0; i < NDPI_PROTOCOL_NUM_CATEGORIES; i++) {
    const char *name = ndpi_category_get_name(ndpi_str, i);

    if(strcasecmp(cat, name) == 0)
      return(i);
  }

  return(-1);
}

/* ****************************************************** */

void ndpi_dump_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  int i;

  if(!ndpi_str) return;

  for(i = 0; i < (int) ndpi_str->ndpi_num_supported_protocols; i++)
    printf("%3d %-22s %-10s %-8s %-12s %s\n",
	   i, ndpi_str->proto_defaults[i].protoName,
	   ndpi_get_l4_proto_name(ndpi_get_l4_proto_info(ndpi_str, i)),
	   ndpi_str->proto_defaults[i].isAppProtocol ? "" : "X",
	   ndpi_get_proto_breed_name(ndpi_str, ndpi_str->proto_defaults[i].protoBreed),
	   ndpi_category_get_name(ndpi_str, ndpi_str->proto_defaults[i].protoCategory));
}

/* ********************************** */

/* Helper function used to generate Options fields in OPNsense */

void ndpi_generate_options(u_int opt) {
  struct ndpi_detection_module_struct *ndpi_str;
  NDPI_PROTOCOL_BITMASK all;
  u_int i;

  ndpi_str = ndpi_init_detection_module(ndpi_no_prefs);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_str, &all);

  switch(opt) {
  case 0: /* List known protocols */
    {
      for(i = 1 /* Skip unknown */; i < ndpi_str->ndpi_num_supported_protocols; i++) {
	printf("            <Option%d value=\"%u\">%s</Option%d>\n",
	       i, i, ndpi_str->proto_defaults[i].protoName, i);
      }
    }
    break;

  case 1: /* List known categories */
    {
      for(i = 1 /* Skip Unknown */; i < NDPI_PROTOCOL_NUM_CATEGORIES; i++) {
	const char *name = ndpi_category_get_name(ndpi_str, i);

	if((name != NULL) && (name[0] != '\0')) {
	  printf("            <Option%d value=\"%u\">%s</Option%d>\n",
		 i, i, name, i);
	}
      }
    }
    break;

  case 2: /* List known risks */
    {
      for(i = 1 /* Skip no risk */; i < NDPI_MAX_RISK; i++) {
	ndpi_risk_enum r = (ndpi_risk_enum)i;

	printf("            <Option%d value=\"%u\">%s</Option%d>\n",
	       i, i, ndpi_risk2str(r), i);
      }
    }
    break;

  default:
    printf("WARNING: option -a out of range\n");
    break;
  }
}

/* ****************************************************** */

void ndpi_dump_risks_score() {
  u_int i;

  printf("%3s %-48s %-8s %s %-8s %-8s\n",
	 "Id", "Risk", "Severity", "Score", "CliScore", "SrvScore");

  for(i = 1; i < NDPI_MAX_RISK; i++) {
    ndpi_risk_enum r = (ndpi_risk_enum)i;
    ndpi_risk risk   = (uint64_t)2 << (r-1);
    ndpi_risk_info* info = ndpi_risk2severity(r);
    ndpi_risk_severity s =info->severity;
    u_int16_t client_score, server_score;
    u_int16_t score = ndpi_risk2score(risk, &client_score, &server_score);

    printf("%3d %-48s %-8s %-8u %-8u %-8u\n",
	   i, ndpi_risk2str(r),
	   ndpi_severity2str(s),
	   score,
	   client_score, server_score);
  }
}

/* ****************************************************** */

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char *ndpi_strnstr(const char *s, const char *find, size_t slen) {
  char c;
  size_t len;

  if((c = *find++) != '\0') {
    len = strnlen(find, slen);
    do {
      char sc;

      do {
	if(slen-- < 1 || (sc = *s++) == '\0')
	  return(NULL);
      } while(sc != c);
      if(len > slen)
	return(NULL);
    } while(strncmp(s, find, len) != 0);
    s--;
  }

  return((char *) s);
}

/* ****************************************************** */

/*
 * Same as ndpi_strnstr but case-insensitive.
 * Please note that this function is *NOT* equivalent to strncasecmp().
 */
const char * ndpi_strncasestr(const char *str1, const char *str2, size_t len) {
  size_t str1_len = strnlen(str1, len);
  size_t str2_len = strlen(str2);
  int i; /* signed! */

  for(i = 0; i < (int)(str1_len - str2_len + 1); i++){
    if(str1[0] == '\0')
      return NULL;
    else if(strncasecmp(str1, str2, str2_len) == 0)
      return(str1);

    str1++;
  }

  return NULL;
}

/* ****************************************************** */

int ndpi_match_prefix(const u_int8_t *payload,
		      size_t payload_len, const char *str, size_t str_len) {
  int rc = str_len <= payload_len ? memcmp(payload, str, str_len) == 0 : 0;

  return(rc);
}

/* ****************************************************** */

int ndpi_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str, char *string_to_match,
				  u_int string_to_match_len, ndpi_protocol_match_result *ret_match) {
  ndpi_automa *automa = &ndpi_str->host_automa;
  int rc;

  if(!ndpi_str) return(NDPI_PROTOCOL_UNKNOWN);

  if((automa->ac_automa == NULL) || (string_to_match_len == 0))
    return(NDPI_PROTOCOL_UNKNOWN);

  rc = ndpi_match_string_common(((AC_AUTOMATA_t *) automa->ac_automa),
				string_to_match,string_to_match_len, &ret_match->protocol_id,
				&ret_match->protocol_category, &ret_match->protocol_breed);
  return rc < 0 ? rc : (int)ret_match->protocol_id;
}

/* **************************************** */

static u_int8_t ndpi_is_more_generic_protocol(u_int16_t previous_proto, u_int16_t new_proto) {
  /* Sometimes certificates are more generic than previously identified protocols */

  if((previous_proto == NDPI_PROTOCOL_UNKNOWN) || (previous_proto == new_proto))
    return(0);

  switch(previous_proto) {
  case NDPI_PROTOCOL_WHATSAPP_CALL:
  case NDPI_PROTOCOL_WHATSAPP_FILES:
    if(new_proto == NDPI_PROTOCOL_WHATSAPP)
      return(1);
    break;
  case NDPI_PROTOCOL_FACEBOOK_VOIP:
    if(new_proto == NDPI_PROTOCOL_FACEBOOK)
      return(1);
    break;
  }

  return(0);
}

/* ****************************************************** */

static u_int16_t ndpi_automa_match_string_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
						      struct ndpi_flow_struct *flow, char *string_to_match,
						      u_int string_to_match_len, u_int16_t master_protocol_id,
						      ndpi_protocol_match_result *ret_match) {
  int matching_protocol_id;

  if(!ndpi_str) return(NDPI_PROTOCOL_UNKNOWN);

  matching_protocol_id =
    ndpi_match_string_subprotocol(ndpi_str, string_to_match, string_to_match_len, ret_match);

  if(matching_protocol_id < 0)
    return NDPI_PROTOCOL_UNKNOWN;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  {
    char m[256];
    u_int len = ndpi_min(sizeof(m) - 1, string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    NDPI_LOG_DBG2(ndpi_str, "[NDPI] ndpi_match_host_subprotocol(%s): %s\n", m,
		  ndpi_str->proto_defaults[matching_protocol_id].protoName);
  }
#endif

  if((matching_protocol_id != NDPI_PROTOCOL_UNKNOWN) &&
     (!ndpi_is_more_generic_protocol(flow->detected_protocol_stack[0], matching_protocol_id))) {
    /* Move the protocol on slot 0 down one position */
    flow->detected_protocol_stack[1] = master_protocol_id,
    flow->detected_protocol_stack[0] = matching_protocol_id;
    flow->confidence = NDPI_CONFIDENCE_DPI;
    if(!category_depends_on_master(master_protocol_id) &&
       flow->category == NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
      flow->category = ret_match->protocol_category;

    return(flow->detected_protocol_stack[0]);
  }

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  {
    char m[256];
    u_int len = ndpi_min(sizeof(m) - 1, string_to_match_len);

    strncpy(m, string_to_match, len);
    m[len] = '\0';

    NDPI_LOG_DBG2(ndpi_str, "[NTOP] Unable to find a match for '%s'\n", m);
  }
#endif

  ret_match->protocol_id = NDPI_PROTOCOL_UNKNOWN, ret_match->protocol_category = NDPI_PROTOCOL_CATEGORY_UNSPECIFIED,
    ret_match->protocol_breed = NDPI_PROTOCOL_UNRATED;

  return(NDPI_PROTOCOL_UNKNOWN);
}

/* ****************************************************** */

void ndpi_check_subprotocol_risk(struct ndpi_detection_module_struct *ndpi_str,
				 struct ndpi_flow_struct *flow, u_int16_t subprotocol_id) {

  if(!ndpi_str) return;

  switch(subprotocol_id) {
  case NDPI_PROTOCOL_ANYDESK:
    ndpi_set_risk(ndpi_str, flow, NDPI_DESKTOP_OR_FILE_SHARING_SESSION, "Found AnyDesk"); /* Remote assistance */
    break;
  }
}

/* ****************************************************** */

u_int16_t ndpi_match_host_subprotocol(struct ndpi_detection_module_struct *ndpi_str,
				      struct ndpi_flow_struct *flow,
				      char *string_to_match, u_int string_to_match_len,
				      ndpi_protocol_match_result *ret_match,
				      u_int16_t master_protocol_id) {
  u_int16_t rc;
  ndpi_protocol_category_t id;

  if(!ndpi_str) return(-1);

  memset(ret_match, 0, sizeof(*ret_match));

  rc = ndpi_automa_match_string_subprotocol(ndpi_str, flow,
					    string_to_match, string_to_match_len,
					    master_protocol_id, ret_match);
  id = ret_match->protocol_category;

  if(ndpi_get_custom_category_match(ndpi_str, string_to_match,
				    string_to_match_len, &id) != -1) {
    /* if(id != -1) */ {
      flow->category = ret_match->protocol_category = id;
      rc = master_protocol_id;
    }
  }

  if(ndpi_str->risky_domain_automa.ac_automa != NULL) {
    u_int32_t proto_id;
    u_int16_t rc1 = ndpi_match_string_common(ndpi_str->risky_domain_automa.ac_automa,
					     string_to_match, string_to_match_len,
					     &proto_id, NULL, NULL);
    if(rc1 > 0) {
      char str[64] = { '\0' };

      strncpy(str, string_to_match, ndpi_min(string_to_match_len, sizeof(str)-1));
      ndpi_set_risk(ndpi_str, flow, NDPI_RISKY_DOMAIN, str);
    }
  }

  /* Add punycode check */
  if(ndpi_check_punycode_string(string_to_match, string_to_match_len)) {
    char str[64] = { '\0' };

    strncpy(str, string_to_match, ndpi_min(string_to_match_len, sizeof(str)-1));
    ndpi_set_risk(ndpi_str, flow, NDPI_PUNYCODE_IDN, str);
  }

  return(rc);
}

/* **************************************** */

int ndpi_match_hostname_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow,
				 u_int16_t master_protocol, char *name, u_int name_len) {
  ndpi_protocol_match_result ret_match;
  u_int16_t subproto, what_len;
  char *what;

  if(!ndpi_struct) return(0);

  if((name_len > 2) && (name[0] == '*') && (name[1] == '.'))
    what = &name[1], what_len = name_len - 1;
  else
    what = name, what_len = name_len;

  subproto = ndpi_match_host_subprotocol(ndpi_struct, flow, what, what_len,
					 &ret_match, master_protocol);

  if(subproto != NDPI_PROTOCOL_UNKNOWN) {
    ndpi_set_detected_protocol(ndpi_struct, flow, subproto, master_protocol, NDPI_CONFIDENCE_DPI);
    if(!category_depends_on_master(master_protocol))
      ndpi_int_change_category(ndpi_struct, flow, ret_match.protocol_category);

    if(subproto == NDPI_PROTOCOL_OOKLA) {
	ookla_add_to_cache(ndpi_struct, flow);
    }

    return(1);
  } else
    return(0);
}

/* ****************************************************** */

static inline int ndpi_match_xgram(unsigned int *map,unsigned int l,const char *str) {
  unsigned int i,c;

  for(i=0,c=0; *str && i < l; i++) {
    unsigned char a = (unsigned char)(*str++);
    if(a < 'a' || a > 'z') return 0;
    c *= XGRAMS_C;
    c += a-'a';
  }

  return (map[c >> 5] & (1u << (c & 0x1f))) != 0;
}

int ndpi_match_bigram(const char *str) {
  return ndpi_match_xgram(bigrams_bitmap, 2, str);
}

int ndpi_match_impossible_bigram(const char *str) {
  return ndpi_match_xgram(impossible_bigrams_bitmap, 2, str);
}

/* ****************************************************** */

int ndpi_match_trigram(const char *str) {
  return ndpi_match_xgram(trigrams_bitmap, 3, str);
}

/* ****************************************************** */

void ndpi_free_flow(struct ndpi_flow_struct *flow) {
  if(flow) {
    ndpi_free_flow_data(flow);
    ndpi_free(flow);
  }
}

/* ****************************************************** */

char *ndpi_revision() {
  return(NDPI_GIT_RELEASE);
}

/* ****************************************************** */

int NDPI_BITMASK_COMPARE(NDPI_PROTOCOL_BITMASK a, NDPI_PROTOCOL_BITMASK b) {
  unsigned int i;

  for(i = 0; i < NDPI_NUM_FDS_BITS; i++) {
    if(a.fds_bits[i] & b.fds_bits[i])
      return(1);
  }

  return(0);
}

#ifdef CODE_UNUSED
int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a) {
  unsigned int i;

  for(i = 0; i < NDPI_NUM_FDS_BITS; i++)
    if(a.fds_bits[i] != 0)
      return(0);

  return(1);
}

void NDPI_DUMP_BITMASK(NDPI_PROTOCOL_BITMASK a) {
  unsigned int i;

  for(i = 0; i < NDPI_NUM_FDS_BITS; i++)
    printf("[%d=%u]", i, a.fds_bits[i]);

  printf("\n");
}
#endif

u_int16_t ndpi_get_api_version() {
  return(NDPI_API_VERSION);
}

const char *ndpi_get_gcrypt_version(void) {
  return gcry_check_version(NULL);
}

ndpi_proto_defaults_t *ndpi_get_proto_defaults(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str ? ndpi_str->proto_defaults : NULL);
}

u_int ndpi_get_ndpi_num_supported_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str ? ndpi_str->ndpi_num_supported_protocols : 0);
}

u_int ndpi_get_ndpi_num_custom_protocols(struct ndpi_detection_module_struct *ndpi_str) {
  return(ndpi_str ? ndpi_str->ndpi_num_custom_protocols : 0);
}

u_int ndpi_get_ndpi_detection_module_size() {
  return(sizeof(struct ndpi_detection_module_struct));
}

void ndpi_set_debug_bitmask(struct ndpi_detection_module_struct *ndpi_str, NDPI_PROTOCOL_BITMASK debug_bitmask) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  if(ndpi_str)
    ndpi_str->debug_bitmask = debug_bitmask;
#endif
}

void ndpi_set_log_level(struct ndpi_detection_module_struct *ndpi_str, u_int l){
  if(ndpi_str)
    ndpi_str->ndpi_log_level = l;
}

/* ******************************************************************** */

u_int32_t ndpi_get_current_time(struct ndpi_flow_struct *flow)
{
  if(flow)
    return flow->last_packet_time_ms / 1000;
  return 0;
}

/* ******************************************************************** */

/* LRU cache */
struct ndpi_lru_cache *ndpi_lru_cache_init(u_int32_t num_entries, u_int32_t ttl) {
  struct ndpi_lru_cache *c = (struct ndpi_lru_cache *) ndpi_calloc(1, sizeof(struct ndpi_lru_cache));

  if(!c)
    return(NULL);

  c->ttl = ttl;
  c->entries = (struct ndpi_lru_cache_entry *) ndpi_calloc(num_entries, sizeof(struct ndpi_lru_cache_entry));

  if(!c->entries) {
    ndpi_free(c);
    return(NULL);
  } else
    c->num_entries = num_entries;

  return(c);
}

void ndpi_lru_free_cache(struct ndpi_lru_cache *c) {
  ndpi_free(c->entries);
  ndpi_free(c);
}

u_int8_t ndpi_lru_find_cache(struct ndpi_lru_cache *c, u_int32_t key,
			     u_int16_t *value, u_int8_t clean_key_when_found, u_int32_t now_sec) {
  u_int32_t slot = key % c->num_entries;

  c->stats.n_search++;
  if(c->entries[slot].is_full && c->entries[slot].key == key &&
     now_sec >= c->entries[slot].timestamp &&
     (c->ttl == 0 || now_sec - c->entries[slot].timestamp <= c->ttl)) {
    *value = c->entries[slot].value;
    if(clean_key_when_found)
      c->entries[slot].is_full = 0;
    c->stats.n_found++;
    return(1);
  } else
    return(0);
}

void ndpi_lru_add_to_cache(struct ndpi_lru_cache *c, u_int32_t key, u_int16_t value, u_int32_t now_sec) {
  u_int32_t slot = key % c->num_entries;

  c->stats.n_insert++;
  c->entries[slot].is_full = 1, c->entries[slot].key = key, c->entries[slot].value = value, c->entries[slot].timestamp = now_sec;
}

void ndpi_lru_get_stats(struct ndpi_lru_cache *c, struct ndpi_lru_cache_stats *stats) {
  if(c) {
    stats->n_insert = c->stats.n_insert;
    stats->n_search = c->stats.n_search;
    stats->n_found = c->stats.n_found;
  } else {
    stats->n_insert = 0;
    stats->n_search = 0;
    stats->n_found = 0;
  }
}

int ndpi_get_lru_cache_stats(struct ndpi_detection_module_struct *ndpi_struct,
			     lru_cache_type cache_type,
			     struct ndpi_lru_cache_stats *stats)
{
  if(!ndpi_struct || !stats)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_lru_get_stats(ndpi_struct->ookla_cache, stats);
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_lru_get_stats(ndpi_struct->bittorrent_cache, stats);
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_lru_get_stats(ndpi_struct->zoom_cache, stats);
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_lru_get_stats(ndpi_struct->stun_cache, stats);
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_lru_get_stats(ndpi_struct->tls_cert_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_lru_get_stats(ndpi_struct->mining_cache, stats);
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_lru_get_stats(ndpi_struct->msteams_cache, stats);
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_lru_get_stats(ndpi_struct->stun_zoom_cache, stats);
    return 0;
  default:
    return -1;
  }
}

int ndpi_set_lru_cache_size(struct ndpi_detection_module_struct *ndpi_struct,
			    lru_cache_type cache_type,
			    u_int32_t num_entries)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_struct->ookla_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_struct->bittorrent_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_struct->zoom_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_struct->stun_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_struct->tls_cert_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_struct->mining_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_struct->msteams_cache_num_entries = num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_struct->stun_zoom_cache_num_entries = num_entries;
    return 0;
  default:
    return -1;
  }
}

int ndpi_get_lru_cache_size(struct ndpi_detection_module_struct *ndpi_struct,
			    lru_cache_type cache_type,
			    u_int32_t *num_entries)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    *num_entries = ndpi_struct->ookla_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    *num_entries = ndpi_struct->bittorrent_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    *num_entries = ndpi_struct->zoom_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN:
    *num_entries = ndpi_struct->stun_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    *num_entries = ndpi_struct->tls_cert_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_MINING:
    *num_entries = ndpi_struct->mining_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    *num_entries = ndpi_struct->msteams_cache_num_entries;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    *num_entries = ndpi_struct->stun_zoom_cache_num_entries;
    return 0;
  default:
    return -1;
  }
}

int ndpi_set_lru_cache_ttl(struct ndpi_detection_module_struct *ndpi_struct,
			   lru_cache_type cache_type,
			   u_int32_t ttl)
{
  if(!ndpi_struct)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    ndpi_struct->ookla_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    ndpi_struct->bittorrent_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    ndpi_struct->zoom_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_STUN:
    ndpi_struct->stun_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    ndpi_struct->tls_cert_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_MINING:
    ndpi_struct->mining_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    ndpi_struct->msteams_cache_ttl = ttl;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    ndpi_struct->stun_zoom_cache_ttl = ttl;
    return 0;
  default:
    return -1;
  }
}

int ndpi_get_lru_cache_ttl(struct ndpi_detection_module_struct *ndpi_struct,
			   lru_cache_type cache_type,
			   u_int32_t *ttl)
{
  if(!ndpi_struct || !ttl)
    return -1;

  switch(cache_type) {
  case NDPI_LRUCACHE_OOKLA:
    *ttl = ndpi_struct->ookla_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_BITTORRENT:
    *ttl = ndpi_struct->bittorrent_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_ZOOM:
    *ttl = ndpi_struct->zoom_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_STUN:
    *ttl = ndpi_struct->stun_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_TLS_CERT:
    *ttl = ndpi_struct->tls_cert_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_MINING:
    *ttl = ndpi_struct->mining_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_MSTEAMS:
    *ttl = ndpi_struct->msteams_cache_ttl;
    return 0;
  case NDPI_LRUCACHE_STUN_ZOOM:
    *ttl = ndpi_struct->stun_zoom_cache_ttl;
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */

/*
  This function tells if it's possible to further dissect a given flow
  0 - All possible dissection has been completed
  1 - Additional dissection is possible
*/
u_int8_t ndpi_extra_dissection_possible(struct ndpi_detection_module_struct *ndpi_str,
					struct ndpi_flow_struct *flow) {
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  u_int16_t proto =
    flow->detected_protocol_stack[1] ? flow->detected_protocol_stack[1] : flow->detected_protocol_stack[0];

  NDPI_LOG_DBG2(ndpi_str, "[DEBUG] %s(%u.%u): %u\n", __FUNCTION__,
	 flow->detected_protocol_stack[0],
	 flow->detected_protocol_stack[1],
	 proto);
#endif

  if(!flow->extra_packets_func)
    return(0);
  return(1);
}

/* ******************************************************************** */

const char *ndpi_get_l4_proto_name(ndpi_l4_proto_info proto) {
  switch(proto) {
  case ndpi_l4_proto_unknown:
    return("");

  case ndpi_l4_proto_tcp_only:
    return("TCP");

  case ndpi_l4_proto_udp_only:
    return("UDP");

  case ndpi_l4_proto_tcp_and_udp:
    return("TCP/UDP");
  }

  return("");
}

/* ******************************************************************** */

ndpi_l4_proto_info ndpi_get_l4_proto_info(struct ndpi_detection_module_struct *ndpi_struct,
					  u_int16_t ndpi_proto_id) {
  if(ndpi_struct && ndpi_proto_id < ndpi_struct->ndpi_num_supported_protocols) {
    u_int16_t idx = ndpi_struct->proto_defaults[ndpi_proto_id].protoIdx;
    NDPI_SELECTION_BITMASK_PROTOCOL_SIZE bm = ndpi_struct->callback_buffer[idx].ndpi_selection_bitmask;

    if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP)
      return(ndpi_l4_proto_tcp_only);
    else if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP)
      return(ndpi_l4_proto_udp_only);
    else if(bm & NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)
      return(ndpi_l4_proto_tcp_and_udp);
  }

  return(ndpi_l4_proto_unknown); /* default */
}

/* ******************************************************************** */

ndpi_ptree_t *ndpi_ptree_create(void) {
  ndpi_ptree_t *tree = (ndpi_ptree_t *) ndpi_malloc(sizeof(ndpi_ptree_t));

  if(tree) {
    tree->v4 = ndpi_patricia_new(32);
    tree->v6 = ndpi_patricia_new(128);

    if((!tree->v4) || (!tree->v6)) {
      ndpi_ptree_destroy(tree);
      return(NULL);
    }
  }

  return(tree);
}

/* ******************************************************************** */

void ndpi_ptree_destroy(ndpi_ptree_t *tree) {
  if(tree) {
    if(tree->v4)
      ndpi_patricia_destroy(tree->v4, free_ptree_data);
    if(tree->v6)
      ndpi_patricia_destroy(tree->v6, free_ptree_data);

    ndpi_free(tree);
  }
}

/* ******************************************************************** */

int ndpi_ptree_insert(ndpi_ptree_t *tree, const ndpi_ip_addr_t *addr,
		      u_int8_t bits, u_int64_t user_data) {
  u_int8_t is_v6 = ndpi_is_ipv6(addr);
  ndpi_patricia_tree_t *ptree;
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;

  if(!tree)
    return(-4);

  ptree = is_v6 ? tree->v6 : tree->v4;

  if(bits > ptree->maxbits)
    return(-1);

  if(is_v6)
    ndpi_fill_prefix_v6(&prefix, (const struct in6_addr *) &addr->ipv6, bits, ptree->maxbits);
  else
    ndpi_fill_prefix_v4(&prefix, (const struct in_addr *) &addr->ipv4, bits, ptree->maxbits);

  /* Verify that the node does not already exist */
  node = ndpi_patricia_search_best(ptree, &prefix);

  if(node && (node->prefix->bitlen == bits))
    return(-2);

  node = ndpi_patricia_lookup(ptree, &prefix);

  if(node != NULL) {
    node->value.u.uv64 = user_data;

    return(0);
  }

  return(-3);
}

/* ******************************************************************** */

int ndpi_ptree_match_addr(ndpi_ptree_t *tree,
			  const ndpi_ip_addr_t *addr, u_int64_t *user_data) {
  u_int8_t is_v6 = ndpi_is_ipv6(addr);
  ndpi_patricia_tree_t *ptree;
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;
  int bits;

  if(!tree)
    return(-2);

  ptree = is_v6 ? tree->v6 : tree->v4;
  bits = ptree->maxbits;

  if(is_v6)
    ndpi_fill_prefix_v6(&prefix, (const struct in6_addr *) &addr->ipv6, bits, ptree->maxbits);
  else
    ndpi_fill_prefix_v4(&prefix, (const struct in_addr *) &addr->ipv4, bits, ptree->maxbits);

  node = ndpi_patricia_search_best(ptree, &prefix);

  if(node) {
    *user_data = node->value.u.uv64;

    return(0);
  }

  return(-1);
}

/* ******************************************************************** */

/* Based on djb2 hash - http://www.cse.yorku.ca/~oz/hash.html */
u_int32_t ndpi_quick_hash(unsigned char *str, u_int str_len) {
  u_int32_t hash = 5381, i;

  for(i=0; i<str_len; i++)
    hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + str[i] */

  return hash;
}

/* ******************************************************************** */

void ndpi_md5(const u_char *data, size_t data_len, u_char hash[16]) {
  ndpi_MD5_CTX ctx;

  ndpi_MD5Init(&ctx);
  ndpi_MD5Update(&ctx, data, data_len);
  ndpi_MD5Final(hash, &ctx);
}

/* ******************************************************************** */

static int enough(int a, int b) {
  u_int8_t percentage = 20;

  if(b <= 1) return(0);
  if(a == 0) return(1);

  if(b > (((a+1)*percentage)/100)) return(1);

  return(0);
}

/* ******************************************************************** */

u_int8_t ndpi_ends_with(char *str, char *ends) {
  u_int str_len = str ? strlen(str) : 0;
  u_int8_t ends_len = strlen(ends);
  u_int8_t rc;


  if(str_len < ends_len) return(0);

  rc = (strncmp(&str[str_len-ends_len], ends, ends_len) != 0) ? 0 : 1;

#ifdef DGA_DEBUG
  printf("[DGA] %s / %s [rc: %u]\n", str, ends, rc);
#endif

  return(rc);
}

/* ******************************************************************** */

static int ndpi_is_trigram_char(char c) {
  if(isdigit(c) || (c == '.') || (c == '-'))
    return(0);
  else
    return(1);
}

/* ******************************************************************** */

static int ndpi_is_vowel(char c) {
  switch(c) {
  case 'a':
  case 'e':
  case 'i':
  case 'o':
  case 'u':
  case 'y': // Not a real vowel...
  case 'x': // Not a real vowel...
    return(1);
    break;

  default:
    return(0);
  }
}

/* ******************************************************************** */

int ndpi_check_dga_name(struct ndpi_detection_module_struct *ndpi_str,
			struct ndpi_flow_struct *flow,
			char *name, u_int8_t is_hostname, u_int8_t check_subproto) {
  if(ndpi_dga_function != NULL) {
    /* A custom DGA function is defined */
    int rc = ndpi_dga_function(name, is_hostname);

    if(rc) {
      if(flow)
	ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);
    }

    return(rc);
  } else {
    int len, rc = 0, trigram_char_skip = 0;
    u_int8_t max_num_char_repetitions = 0, last_char = 0, num_char_repetitions = 0, num_dots = 0, num_trigram_dots = 0;
    u_int8_t max_domain_element_len = 0, curr_domain_element_len = 0, first_element_is_numeric = 1;
    ndpi_protocol_match_result ret_match;

    if((!name)
       || (strchr(name, '_') != NULL)
       || (strchr(name, '-') != NULL)
       || (ndpi_ends_with(name, "in-addr.arpa"))
       || (ndpi_ends_with(name, "ip6.arpa"))
       /* Ignore TLD .local .lan and .home */
       || (ndpi_ends_with(name, ".local"))
       || (ndpi_ends_with(name, ".lan"))
       || (ndpi_ends_with(name, ".home"))
       )
      return(0);

    if(flow && (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN))
      return(0); /* Ignore DGA check for protocols already fully detected */

    if(check_subproto &&
       ndpi_match_string_subprotocol(ndpi_str, name, strlen(name), &ret_match) > 0)
      return(0); /* Ignore DGA for known domain names */

    if(isdigit((int)name[0])) {
      struct in_addr ip_addr;

      ip_addr.s_addr = inet_addr(name);
      if(strcmp(inet_ntoa(ip_addr), name) == 0)
	return(0); /* Ignore numeric IPs */
    }

    if(strncmp(name, "www.", 4) == 0)
      name = &name[4];

    if(ndpi_verbose_dga_detection)
      printf("[DGA check] %s\n", name);

    len = strlen(name);

    if(len >= 5) {
      int num_found = 0, num_impossible = 0, num_bigram_checks = 0,
	num_trigram_found = 0, num_trigram_checked = 0, num_dash = 0,
	num_digits = 0, num_vowels = 0, num_trigram_vowels = 0, num_words = 0, skip_next_bigram = 0;
      char tmp[128], *word, *tok_tmp;
      u_int i, j, max_tmp_len = sizeof(tmp)-1;

      len = ndpi_snprintf(tmp, max_tmp_len, "%s", name);
      if(len < 0) {

	if(ndpi_verbose_dga_detection)
	  printf("[DGA] Too short");

	return(0);
      } else
	tmp[(u_int)len < max_tmp_len ? (u_int)len : max_tmp_len] = '\0';

      for(i=0, j=0; (i<(u_int)len) && (j<max_tmp_len); i++) {
	tmp[j] = tolower(name[i]);

	if(tmp[j] == '.') {
	  num_dots++;
	} else if(num_dots == 0) {
	  if(!isdigit((int)tmp[j]))
	    first_element_is_numeric = 0;
	}

	if(ndpi_is_vowel(tmp[j]))
	  num_vowels++;

	if(last_char == tmp[j]) {
	  if(++num_char_repetitions > max_num_char_repetitions)
	    max_num_char_repetitions = num_char_repetitions;
	} else
	  num_char_repetitions = 1, last_char = tmp[j];

	if(isdigit((int)tmp[j])) {
	  num_digits++;

	  if(((j+2)<(u_int)len) && isdigit((int)tmp[j+1]) && (tmp[j+2] == '.')) {
	    /* Check if there are too many digits */
	    if(num_digits < 4)
	      return(0); /* Double digits */
	  }
	}

	switch(tmp[j]) {
	case '.':
	case '-':
	case '_':
	case '/':
	case ')':
	case '(':
	case ';':
	case ':':
	case '[':
	case ']':
	case ' ':
	  /*
	    Domain/word separator chars

	    NOTE:
	    this function is used also to detect other type of issues
	    such as invalid/suspiciuous user agent
	  */
	  if(curr_domain_element_len > max_domain_element_len)
	    max_domain_element_len = curr_domain_element_len;

	  curr_domain_element_len = 0;
	  break;

	default:
	  curr_domain_element_len++;
	  break;
	}

	j++;
      }

      if(num_dots == 0) /* Doesn't look like a domain name */
	return(0);

      if(curr_domain_element_len > max_domain_element_len)
	max_domain_element_len = curr_domain_element_len;

      if(ndpi_verbose_dga_detection)
	printf("[DGA] [max_num_char_repetitions: %u][max_domain_element_len: %u]\n",
	       max_num_char_repetitions, max_domain_element_len);

      if(
	 (is_hostname
	  && (num_dots > 5)
	  && (!first_element_is_numeric)
	  )
	 || (max_num_char_repetitions > 5 /* num or consecutive repeated chars */)
	 /*
	   In case of a name with too many consecutive chars an alert is triggered
	   This is the case for instance of the wildcard DNS query used by NetBIOS
	   (ckaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) and that can be exploited
	   for reflection attacks
	   - https://www.akamai.com/uk/en/multimedia/documents/state-of-the-internet/ddos-reflection-netbios-name-server-rpc-portmap-sentinel-udp-threat-advisory.pdf
	   - http://ubiqx.org/cifs/NetBIOS.html
	 */
	 || ((max_domain_element_len >= 19 /* word too long. Example bbcbedxhgjmdobdprmen.com */) && ((num_char_repetitions > 1) || (num_digits > 1)))
	 ) {
	if(flow) {
	  ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);
	}

	if(ndpi_verbose_dga_detection)
	  printf("[DGA] Found!");

	return(1);
      }

      tmp[j] = '\0';
      len = j;

      u_int max_num_consecutive_digits_first_word = 0, num_word = 0;

      for(word = strtok_r(tmp, ".", &tok_tmp); ; word = strtok_r(NULL, ".", &tok_tmp)) {
	u_int num_consecutive_digits = 0;

	if(!word) break; else num_word++;

	num_words++;

	if(num_words > 2)
	  break; /* Stop after the 2nd word of the domain name */

	if(strlen(word) < 5) continue;

	if(ndpi_verbose_dga_detection)
	  printf("-> word(%s) [%s][len: %u]\n", word, name, (unsigned int)strlen(word));

	trigram_char_skip = 0;

	for(i = 0; word[i+1] != '\0'; i++) {
	  if(isdigit((int)word[i]))
	    num_consecutive_digits++;
	  else {
	    if((num_word == 1) && (num_consecutive_digits > max_num_consecutive_digits_first_word))
	      max_num_consecutive_digits_first_word = num_consecutive_digits;

	    num_consecutive_digits = 0;
	  }

	  switch(word[i]) {
	  case '-':
	    num_dash++;
	    /*
	      Let's check for double+consecutive --
	      that are usually ok
	      r2---sn-uxaxpu5ap5-2n5e.gvt1.com
	    */
	    if(word[i+1] == '-')
	      return(0); /* Double dash */
	    continue;

	  case '_':
	  case ':':
	    continue;
	    break;

	  case '.':
	    continue;
	    break;
	  }

	  num_bigram_checks++;

	  if(ndpi_verbose_dga_detection)
	    printf("-> Checking %c%c\n", word[i], word[i+1]);

	  if(ndpi_match_impossible_bigram(&word[i])) {
	    if(ndpi_verbose_dga_detection)
	      printf("IMPOSSIBLE %s\n", &word[i]);

	    num_impossible++;
	  } else {
	    if(!skip_next_bigram) {
	      if(ndpi_match_bigram(&word[i])) {
		num_found++, skip_next_bigram = 1;
	      }
	    } else
	      skip_next_bigram = 0;
	  }

	  if((num_trigram_dots < 2) && (word[i+2] != '\0')) {
	    if(ndpi_verbose_dga_detection)
	      printf("***> %s [trigram_char_skip: %u]\n", &word[i], trigram_char_skip);

	    if(ndpi_is_trigram_char(word[i]) && ndpi_is_trigram_char(word[i+1]) && ndpi_is_trigram_char(word[i+2])) {
	      if(trigram_char_skip) {
		trigram_char_skip--;
	      } else {
		num_trigram_checked++;

		if(ndpi_match_trigram(&word[i]))
		  num_trigram_found++, trigram_char_skip = 2 /* 1 char overlap */;
		else if(ndpi_verbose_dga_detection)
		  printf("[NDPI] NO Trigram %c%c%c\n", word[i], word[i+1], word[i+2]);

		/* Count vowels */
		num_trigram_vowels += ndpi_is_vowel(word[i]) + ndpi_is_vowel(word[i+1]) + ndpi_is_vowel(word[i+2]);
	      }
	    } else {
	      if(word[i] == '.')
		num_trigram_dots++;

	      trigram_char_skip = 0;
	    }
	  }
	} /* for */

	if((num_word == 1) && (num_consecutive_digits > max_num_consecutive_digits_first_word))
	  max_num_consecutive_digits_first_word = num_consecutive_digits;
      } /* for */

      if(ndpi_verbose_dga_detection)
	printf("[NDPI] max_num_consecutive_digits_first_word=%u\n", max_num_consecutive_digits_first_word);

      if(ndpi_verbose_dga_detection)
	printf("[%s][num_found: %u][num_impossible: %u][num_digits: %u][num_bigram_checks: %u][num_vowels: %u/%u][num_trigram_vowels: %u][num_trigram_found: %u/%u][vowels: %u][rc: %u]\n",
	       name, num_found, num_impossible, num_digits, num_bigram_checks, num_vowels, len, num_trigram_vowels,
	       num_trigram_checked, num_trigram_found, num_vowels, rc);

      if((len > 16) && (num_dots < 3) && ((num_vowels*4) < (len-num_dots))) {
	if((num_trigram_checked > 2) && (num_trigram_vowels >= (num_trigram_found-1)))
	  ; /* skip me */
	else
	  rc = 1;
      }

      if(num_bigram_checks
	 /* We already checked num_dots > 0 */
	 && ((num_found == 0) || ((num_digits > 5) && (num_words <= 3) && (num_impossible > 0))
	     || enough(num_found, num_impossible)
	     || ((num_trigram_checked > 2)
		 && ((num_trigram_found < (num_trigram_checked/2))
		     || ((num_trigram_vowels < (num_trigram_found-1)) && (num_dash == 0) && (num_dots > 1) && (num_impossible > 0)))
		 )
	     )
	 )
	rc = 1;

      if((num_trigram_checked > 2) && (num_vowels == 0))
	rc = 1;

      if(num_dash > 2)
	rc = 0;

      /* Skip names whose first word item has at least 3 consecutive digits */
      if(max_num_consecutive_digits_first_word > 2)
	rc = 0;

      if(ndpi_verbose_dga_detection) {
	if(rc)
	  printf("DGA %s [num_found: %u][num_impossible: %u]\n",
		 name, num_found, num_impossible);
      }
    }

    if(ndpi_verbose_dga_detection)
      printf("[DGA] Result: %u\n", rc);

    if(rc && flow)
      ndpi_set_risk(ndpi_str, flow, NDPI_SUSPICIOUS_DGA_DOMAIN, name);

    return(rc);
  }
}

/* ******************************************************************** */

ndpi_risk_info* ndpi_risk2severity(ndpi_risk_enum risk) {
  return(&ndpi_known_risks[risk]);
}

/* ******************************************************************** */

char *ndpi_hostname_sni_set(struct ndpi_flow_struct *flow,
			    const u_int8_t *value, size_t value_len) {
  char *dst;
  size_t len, i;

  len = ndpi_min(value_len, sizeof(flow->host_server_name) - 1);
  dst = flow->host_server_name;

  for(i = 0; i < len; i++)
    dst[i] = tolower(value[value_len - len + i]);
  dst[i] = '\0';

  return dst;
}

/* ******************************************************************** */

char *ndpi_user_agent_set(struct ndpi_flow_struct *flow,
			  const u_int8_t *value, size_t value_len) {
  if(flow->http.user_agent != NULL) {
    /* Already set: ignore double set */
    return NULL;
  }
  if(value_len == 0) {
    return NULL;
  }

  flow->http.user_agent = ndpi_malloc(value_len + 1);
  if(flow->http.user_agent != NULL) {
    memcpy(flow->http.user_agent, value, value_len);
    flow->http.user_agent[value_len] = '\0';
  }

  return flow->http.user_agent;
}

/* ******************************************************************** */

int ndpi_current_pkt_from_client_to_server(const struct ndpi_packet_struct *packet,
					   const struct ndpi_flow_struct *flow)
{
  return packet->packet_direction == flow->client_packet_direction;
}

/* ******************************************************************** */

int ndpi_current_pkt_from_server_to_client(const struct ndpi_packet_struct *packet,
					   const struct ndpi_flow_struct *flow)
{
  return packet->packet_direction != flow->client_packet_direction;
}

/* ******************************************************************** */

int ndpi_seen_flow_beginning(const struct ndpi_flow_struct *flow)
{
  if(flow->l4_proto == IPPROTO_TCP &&
     (flow->l4.tcp.seen_syn == 0 || flow->l4.tcp.seen_syn_ack == 0 ||
      flow->l4.tcp.seen_ack == 0))
    return 0;
  return 1;
}

/* ******************************************************************** */

int ndpi_set_monitoring_state(struct ndpi_detection_module_struct *ndpi_struct,
			      u_int16_t proto, u_int32_t num_pkts, u_int32_t flags)
{
  if(!ndpi_struct || num_pkts > 0xFFFF)
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_STUN:
    ndpi_struct->monitoring_stun_pkts_to_process = num_pkts;
    ndpi_struct->monitoring_stun_flags = flags;
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */

int ndpi_get_monitoring_state(struct ndpi_detection_module_struct *ndpi_struct,
			      u_int16_t proto, u_int32_t *num_pkts, u_int32_t *flags)
{
  if(!ndpi_struct || !num_pkts || !flags)
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_STUN:
    *num_pkts = ndpi_struct->monitoring_stun_pkts_to_process;
    *flags = ndpi_struct->monitoring_stun_flags;
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */

int ndpi_set_opportunistic_tls(struct ndpi_detection_module_struct *ndpi_struct,
			       u_int16_t proto, int value)
{
  if(!ndpi_struct || (value != 0 && value != 1))
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_MAIL_SMTP:
    ndpi_struct->opportunistic_tls_smtp_enabled = value;
    return 0;
  case NDPI_PROTOCOL_MAIL_IMAP:
    ndpi_struct->opportunistic_tls_imap_enabled = value;
    return 0;
  case NDPI_PROTOCOL_MAIL_POP:
    ndpi_struct->opportunistic_tls_pop_enabled = value;
    return 0;
  case NDPI_PROTOCOL_FTP_CONTROL:
    ndpi_struct->opportunistic_tls_ftp_enabled = value;
    return 0;
  case NDPI_PROTOCOL_STUN:
    ndpi_struct->opportunistic_tls_stun_enabled = value;
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */

int ndpi_get_opportunistic_tls(struct ndpi_detection_module_struct *ndpi_struct,
			       u_int16_t proto)
{
  if(!ndpi_struct)
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_MAIL_SMTP:
    return ndpi_struct->opportunistic_tls_smtp_enabled;
  case NDPI_PROTOCOL_MAIL_IMAP:
    return ndpi_struct->opportunistic_tls_imap_enabled;
  case NDPI_PROTOCOL_MAIL_POP:
    return ndpi_struct->opportunistic_tls_pop_enabled;
  case NDPI_PROTOCOL_FTP_CONTROL:
    return ndpi_struct->opportunistic_tls_ftp_enabled;
  case NDPI_PROTOCOL_STUN:
    return ndpi_struct->opportunistic_tls_stun_enabled;
  default:
    return -1;
  }
}

/* ******************************************************************** */

int ndpi_set_protocol_aggressiveness(struct ndpi_detection_module_struct *ndpi_struct,
                                     u_int16_t proto, u_int32_t value)
{
  if(!ndpi_struct)
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_OOKLA:
    ndpi_struct->aggressiveness_ookla = value;
    return 0;
  default:
    return -1;
  }
}

/* ******************************************************************** */

u_int32_t ndpi_get_protocol_aggressiveness(struct ndpi_detection_module_struct *ndpi_struct,
                                           u_int16_t proto)
{
  if(!ndpi_struct)
    return -1;

  switch(proto) {
  case NDPI_PROTOCOL_OOKLA:
    return ndpi_struct->aggressiveness_ookla;
  default:
    return -1;
  }
}

/* ******************************************************************** */

void ndpi_set_user_data(struct ndpi_detection_module_struct *ndpi_str, void *user_data)
{
  if (ndpi_str == NULL)
  {
    return;
  }

  if (ndpi_str->user_data != NULL)
  {
    NDPI_LOG_ERR(ndpi_str, "%s", "User data is already set. Overwriting.")
  }

  ndpi_str->user_data = user_data;
}

void *ndpi_get_user_data(struct ndpi_detection_module_struct *ndpi_str)
{
  if(ndpi_str)
    return ndpi_str->user_data;
  return NULL;
}
