/*
 * stun.c
 *
 * Copyright (C) 2011-24 - ntop.org
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
 * along with nDPI. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_STUN

#include "ndpi_api.h"
#include "ndpi_private.h"

// #define DEBUG_LRU  1

#define STUN_HDR_LEN   20 /* STUN message header length, Classic-STUN (RFC 3489) and STUN (RFC 8489) both */


/* Methods */
#define METHOD_BINDING                 0x0001 /* RFC8489 */
#define METHOD_SHARED_SECRET           0x0002 /* RFC3489 */
#define METHOD_ALLOCATE                0x0003 /* RFC8489 */
#define METHOD_REFRESH                 0x0004 /* RFC8489 */
#define METHOD_DATA_IND_OLD            0x0005
#define METHOD_SEND                    0x0006 /* RFC8656 */
#define METHOD_DATA_IND                0x0007 /* RFC8656 */
#define METHOD_CREATE_PERMISSION       0x0008 /* RFC8656 */
#define METHOD_CHANNELBIND             0x0009 /* RFC8656 */
/* TCP specific */
#define METHOD_CONNECT                 0x000a /* RFC6062 */
#define METHOD_CONNECTION_BIND         0x000b /* RFC6062 */
#define METHOD_CONNECTION_ATTEMPT      0x000c /* RFC6062 */


static u_int64_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev);
static u_int64_t get_stun_lru_key_raw4(u_int32_t ip, u_int16_t port);
static u_int64_t get_stun_lru_key_raw6(u_int8_t *ip, u_int16_t port);
static void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int16_t app_proto,
					 u_int16_t master_proto);
static int stun_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow);


/* Valid classifications:
    * STUN, DTLS, STUN/RTP, DTLS/SRTP, RTP or RTCP (only from RTP dissector)
      and TELEGRAM (only from Telegram dissector, note that TELEGRAM != TELEGRAM_VOIP!!)
    * STUN/APP, DTLS/APP, SRTP/APP ["real" sub-classification]
   The idea is:
    * the specific "real" application (WA/FB/Signal/...), if present, should
      be always set as "app" protocol, with STUN or DTLS or SRTP as "master" protocol
    * every "real" application that we handle, if it uses RTP, it is
      encrypted --> SRTP
    * keep STUN/RTP for the generic case without sub-classification [because
      nDPI uses SRTP only when it is sure that there is encryption]
*/

static int is_subclassification_real_by_proto(u_int16_t proto)
{
  if(proto == NDPI_PROTOCOL_UNKNOWN ||
     proto == NDPI_PROTOCOL_STUN ||
     proto == NDPI_PROTOCOL_RTP ||
     proto == NDPI_PROTOCOL_RTCP ||
     proto == NDPI_PROTOCOL_SRTP ||
     proto == NDPI_PROTOCOL_DTLS ||
     proto == NDPI_PROTOCOL_TELEGRAM)
    return 0;
  return 1;
}

/* ***************************************************** */

static int is_subclassification_real(struct ndpi_flow_struct *flow)
{
  /* No previous subclassification */
  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN)
    return 0;
  return is_subclassification_real_by_proto(flow->detected_protocol_stack[0]);
}

/* ***************************************************** */

static int is_new_subclassification_better(struct ndpi_detection_module_struct *ndpi_struct,
                                           struct ndpi_flow_struct *flow,
                                           u_int16_t new_app_proto)
{
  NDPI_LOG_DBG(ndpi_struct, "%d/%d -> %d\n",
               flow->detected_protocol_stack[1], flow->detected_protocol_stack[0],
               new_app_proto);

  /* If we don't have a real subclassification, we might want to lookup into the cache again
     (even if new_app_proto == NDPI_PROTOCOL_UNKNOWN) */

  if(is_subclassification_real(flow) &&
     new_app_proto == NDPI_PROTOCOL_UNKNOWN)
    return 0;

  /* Debug */
  if(new_app_proto != NDPI_PROTOCOL_UNKNOWN &&
     is_subclassification_real(flow) &&
     new_app_proto != flow->detected_protocol_stack[0]) {
    NDPI_LOG_DBG(ndpi_struct, "Incoherent sub-classification change %d/%d->%d \n",
                 flow->detected_protocol_stack[1],
                 flow->detected_protocol_stack[0], new_app_proto);
  }

  if(new_app_proto != flow->detected_protocol_stack[0])
    return 1;
  return 0;
}

/* ***************************************************** */

static u_int16_t search_into_cache(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow)
{
  u_int16_t proto;
  u_int64_t key;
  int rc;

  if(ndpi_struct->stun_cache) {
    key = get_stun_lru_key(flow, 0);
    rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto,
			     0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
    printf("[LRU] Searching 0x%llx\n", (long long unsigned int)key);
#endif

    if(!rc) {
      key = get_stun_lru_key(flow, 1);
      rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto,
			       0 /* Don't remove it as it can be used for other connections */,
			       ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
      printf("[LRU] Searching 0x%llx\n", (long long unsigned int)key);
#endif
    }

    if(rc) {
#ifdef DEBUG_LRU
      printf("[LRU] Cache FOUND 0x%llx / %u\n", (long long unsigned int)key, proto);
#endif

      return proto;
    } else {
#ifdef DEBUG_LRU
      printf("[LRU] NOT FOUND 0x%llx\n", (long long unsigned int)key);
#endif
    }
  } else {
#ifdef DEBUG_LRU
    printf("[LRU] NO/EMPTY CACHE\n");
#endif
  }
  return NDPI_PROTOCOL_UNKNOWN;
}

/* ***************************************************** */

static void add_to_cache(struct ndpi_detection_module_struct *ndpi_struct,
			 struct ndpi_flow_struct *flow,
			 u_int16_t app_proto)
{
  u_int64_t key, key_rev;

  if(ndpi_struct->stun_cache) {
    key = get_stun_lru_key(flow, 0);
    ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key, app_proto, ndpi_get_current_time(flow));
    key_rev = get_stun_lru_key(flow, 1);
    ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key_rev, app_proto, ndpi_get_current_time(flow));

#ifdef DEBUG_LRU
    printf("[LRU] ADDING 0x%llx 0x%llx app %u [%u -> %u]\n",
	   (long long unsigned int)key, (long long unsigned int)key_rev, app_proto,
	   ntohs(flow->c_port), ntohs(flow->s_port));
#endif
  }
}

/* ***************************************************** */

static void parse_ip_port_attribute(const u_int8_t *payload, u_int16_t payload_length,
                                    int off, u_int16_t real_len, ndpi_address_port *ap,
                                    ndpi_address_port *ap_monit)
{
  if(off + 4 + real_len <= payload_length &&
     (real_len == 8 || real_len == 20)) {
    u_int8_t protocol_family = payload[off+5];

    if(protocol_family == 0x01 /* IPv4 */ &&
       real_len == 8) {
      u_int16_t port = ntohs(*((u_int16_t*)&payload[off+6]));
      u_int32_t ip   = ntohl(*((u_int32_t*)&payload[off+8]));

      /* Only the first attribute ever in the flow */
      if(ap->port == 0) {
        ap->port = port;
        ap->address.v4 = htonl(ip);
        ap->is_ipv6 = 0;
      }

      if(ap_monit) {
        ap_monit->port = port;
        ap_monit->address.v4 = htonl(ip);
        ap_monit->is_ipv6 = 0;
      }
    } else if(protocol_family == 0x02 /* IPv6 */ &&
              real_len == 20) {
      u_int16_t port = ntohs(*((u_int16_t*)&payload[off+6]));
      u_int32_t ip[4];

      ip[0] = *((u_int32_t *)&payload[off + 8]);
      ip[1] = *((u_int32_t *)&payload[off + 12]);
      ip[2] = *((u_int32_t *)&payload[off + 16]);
      ip[3] = *((u_int32_t *)&payload[off + 20]);

      /* Only the first attribute ever in the flow */
      if(ap->port == 0) {
        ap->port = port;
        memcpy(&ap->address, &ip, 16);
        ap->is_ipv6 = 1;
      }

      if(ap_monit) {
        ap_monit->port = port;
        memcpy(&ap_monit->address, &ip, 16);
        ap_monit->is_ipv6 = 1;
      }
    }
  }
}

/* ***************************************************** */

static void parse_xor_ip_port_attribute(struct ndpi_detection_module_struct *ndpi_struct,
                                        struct ndpi_flow_struct *flow,
                                        const u_int8_t *payload, u_int16_t payload_length,
                                        int off, u_int16_t real_len,
                                        ndpi_address_port *ap, ndpi_address_port *ap_monit,
                                        u_int32_t transaction_id[3], u_int32_t magic_cookie,
                                        int add_to_cache)
{
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  char buf[128];
#endif

  if(off + 4 + real_len <= payload_length &&
     (real_len == 8 || real_len == 20)) {
    u_int8_t protocol_family = payload[off+5];

    if(protocol_family == 0x01 /* IPv4 */ &&
       real_len == 8) {
      u_int32_t ip;
      u_int16_t port;

      port = ntohs(*((u_int16_t *)&payload[off + 6])) ^ (magic_cookie >> 16);
      ip = *((u_int32_t *)&payload[off + 8]) ^ htonl(magic_cookie);

      /* Only the first attribute ever in the flow */
      if(ap->port == 0) {
        ap->port = port;
        ap->address.v4 = ip;
        ap->is_ipv6 = 0;
      }

      if(ap_monit) {
          ap_monit->port = port;
          ap_monit->address.v4 = ip;
          ap_monit->is_ipv6 = 0;
      }

      if(add_to_cache) {
        NDPI_LOG_DBG(ndpi_struct, "Peer %s:%d [proto %d]\n",
                     inet_ntop(AF_INET, &ip, buf, sizeof(buf)), port,
                     flow->detected_protocol_stack[0]);

        if(ndpi_struct->stun_cache &&
           is_subclassification_real(flow)) {
          u_int64_t key = get_stun_lru_key_raw4(ip, port);

          ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key,
				flow->detected_protocol_stack[0],
				ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
          printf("[LRU] Add peer 0x%llx %d\n", (long long unsigned int)key, flow->detected_protocol_stack[0]);
#endif
	}
      }
    } else if(protocol_family == 0x02 /* IPv6 */ &&
              real_len == 20) {
      u_int32_t ip[4];
      u_int16_t port;

      port = ntohs(*((u_int16_t *)&payload[off + 6])) ^ (magic_cookie >> 16);
      ip[0] = *((u_int32_t *)&payload[off + 8]) ^ htonl(magic_cookie);
      ip[1] = *((u_int32_t *)&payload[off + 12]) ^ htonl(transaction_id[0]);
      ip[2] = *((u_int32_t *)&payload[off + 16]) ^ htonl(transaction_id[1]);
      ip[3] = *((u_int32_t *)&payload[off + 20]) ^ htonl(transaction_id[2]);

      /* Only the first attribute ever in the flow */
      if(ap->port == 0) {
        ap->port = port;
        memcpy(&ap->address, &ip, 16);
        ap->is_ipv6 = 1;
      }

      if(ap_monit) {
        ap_monit->port = port;
        memcpy(&ap_monit->address, &ip, 16);
        ap_monit->is_ipv6 = 1;
      }

      if(add_to_cache) {
        NDPI_LOG_DBG(ndpi_struct, "Peer %s:%d [proto %d]\n",
                     inet_ntop(AF_INET6, &ip, buf, sizeof(buf)), port,
                     flow->detected_protocol_stack[0]);

        if(ndpi_struct->stun_cache &&
           is_subclassification_real(flow)) {
          u_int64_t key = get_stun_lru_key_raw6((u_int8_t *)ip, port);

          ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key,
                                flow->detected_protocol_stack[0],
                                ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
          printf("[LRU] Add peer 0x%llx %d\n", (long long unsigned int)key, flow->detected_protocol_stack[0]);
#endif
	}
      }
    }
  }
}

/* ***************************************************** */

int is_stun(struct ndpi_detection_module_struct *ndpi_struct,
            struct ndpi_flow_struct *flow,
            u_int16_t *app_proto)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t msg_type, msg_len, method;
  int off;
  const u_int8_t *payload = packet->payload;
  u_int16_t payload_length = packet->payload_packet_len;
  const u_int8_t *orig_payload;
  u_int16_t orig_payload_length;
  u_int32_t magic_cookie;
  u_int32_t transaction_id[3];

  if(payload_length < STUN_HDR_LEN)
    return(-1);

  /* Some really old/legacy stuff */
  if(strncmp((const char *)payload, "RSP/", 4) == 0 &&
     strncmp((const char *)&payload[7], " STUN_", 6) == 0) {
    NDPI_LOG_DBG(ndpi_struct, "found old/legacy stun in rsp\n");
    return 1; /* No real metadata */
  }

  /* STUN may be encapsulated in TCP packets with a special TCP framing described in RFC 4571 */
  if(packet->tcp &&
     payload_length >= STUN_HDR_LEN + 2 &&
     /* TODO: multiple STUN messagges */
     ((ntohs(get_u_int16_t(payload, 0)) + 2) == payload_length)) {
    payload += 2;
    payload_length -=2;
  }

  /* Microsoft Multiplexed TURN messages */
  if(payload_length >= STUN_HDR_LEN + 12 &&
     ntohs(get_u_int16_t(payload, 0)) == 0xFF10 &&
     ntohs(get_u_int16_t(payload, 2)) + 4 == payload_length) {
    payload += 12;
    payload_length -= 12;
  }

  msg_type = ntohs(*((u_int16_t *)&payload[0]));
  msg_len = ntohs(*((u_int16_t *)&payload[2]));
  magic_cookie = ntohl(*((u_int32_t *)&payload[4]));
  transaction_id[0] = ntohl(*((u_int32_t *)&payload[8]));
  transaction_id[1] = ntohl(*((u_int32_t *)&payload[12]));
  transaction_id[2] = ntohl(*((u_int32_t *)&payload[16]));

  /* No magic_cookie on classic-stun */
  /* Let's hope that we don't have anymore classic-stun over TCP */
  if(packet->tcp && magic_cookie != 0x2112A442) {
    return 0;
  }

  NDPI_LOG_DBG2(ndpi_struct, "msg_type = %04X msg_len = %d\n", msg_type, msg_len);

  /* With tcp, we might have multiple msg in the same TCP pkt.
     Parse only the first one. TODO */
  if(packet->tcp) {
    if(msg_len + STUN_HDR_LEN > payload_length)
      return 0;

    payload_length = msg_len + STUN_HDR_LEN;
  }

  if(msg_type == 0 || (msg_len + STUN_HDR_LEN != payload_length)) {
    NDPI_LOG_DBG(ndpi_struct, "Invalid msg_type = %04X or len %d %d\n",
                 msg_type, msg_len, payload_length);
    return -1;
  }

  /* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml */
  if(((msg_type & 0x3EEF) > 0x000B) &&
     msg_type != 0x0800 && msg_type != 0x0801 && msg_type != 0x0802 &&
     msg_type != 0x0804 && msg_type != 0x0805) {
    NDPI_LOG_DBG(ndpi_struct, "Invalid msg_type = %04X\n", msg_type);
    return -1;
  }

  if(magic_cookie != 0x2112A442) {
    /* Some heuristic to detect classic-stun:
       * msg type check (list from Wireshark)
       * let's see if attributes list seems ok */
    if(msg_type != 0x0001 && msg_type != 0x0101 && msg_type != 0x0111 && /* Binding */
       msg_type != 0x0002 && msg_type != 0x0102 && msg_type != 0x0112 && /* Shared secret */
       msg_type != 0x0003 && msg_type != 0x0103 && msg_type != 0x0113 && /* Allocate */
       msg_type != 0x0004 && msg_type != 0x0104 && msg_type != 0x0114 && /* Send */
       msg_type != 0x0115 && /* Data Indication */
       msg_type != 0x0006 && msg_type != 0x0106 && msg_type != 0x0116 /* Set Active Destination */) {
      NDPI_LOG_DBG(ndpi_struct, "No classic-stun 0x%x\n", msg_type);
      return 0;
    }

    off = STUN_HDR_LEN;
    while(off + 4 < payload_length) {
      u_int16_t len = ntohs(*((u_int16_t *)&payload[off + 2]));
      u_int16_t real_len = (len + 3) & 0xFFFFFFFC;

      off += 4 + real_len;
    }
    if(off != payload_length) {
      NDPI_LOG_DBG(ndpi_struct, "No classic-stun %d/%d\n", off, payload_length);
      return 0;
    }
  }

  /* STUN */

  if(flow->monit == NULL &&
     is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN))
    flow->monit = ndpi_calloc(1, sizeof(struct ndpi_metadata_monitoring));

  if(msg_type == 0x0800 || msg_type == 0x0801 || msg_type == 0x0802 ||
     msg_type == 0x0804 || msg_type == 0x0805) {
    *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
    return 1;
  }

  method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2);
  switch(method) {
  case METHOD_ALLOCATE:
  case METHOD_REFRESH:
  case METHOD_SEND:
  case METHOD_DATA_IND:
  case METHOD_DATA_IND_OLD:
  case METHOD_CREATE_PERMISSION:
  case METHOD_CHANNELBIND:
  case METHOD_CONNECT:
  case METHOD_CONNECTION_BIND:
  case METHOD_CONNECTION_ATTEMPT:
    NDPI_LOG_DBG(ndpi_struct, "TURN flow (method %d)\n", method);
    flow->stun.is_turn = 1;
    break;
  }

  /* See https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings.
     Since the check is quite weak, give time to other applications to kick in */
  if(flow->packet_counter > 4 && !flow->stun.is_turn &&
     !is_subclassification_real(flow) &&
     (ntohs(flow->c_port) == 10000 || ntohs(flow->s_port) == 10000)) {
     *app_proto = NDPI_PROTOCOL_SIGNAL_VOIP;
  }

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TELEGRAM)
    *app_proto = NDPI_PROTOCOL_TELEGRAM_VOIP;

  off = STUN_HDR_LEN;
  while(off + 4 < payload_length) {
    u_int16_t attribute = ntohs(*((u_int16_t *)&payload[off]));
    u_int16_t len = ntohs(*((u_int16_t *)&payload[off + 2]));
    u_int16_t real_len = (len + 3) & 0xFFFFFFFC;

    NDPI_LOG_DBG(ndpi_struct, "Attribute 0x%x (%d/%d)\n", attribute, len, real_len);

    switch(attribute) {
    case 0x0001: /* MAPPED-ADDRESS */
      if(ndpi_struct->cfg.stun_mapped_address_enabled) {
        parse_ip_port_attribute(payload, payload_length, off, real_len, &flow->stun.mapped_address,
                                flow->monit ? &flow->monit->protos.dtls_stun_rtp.mapped_address : NULL);
      }
      break;

    case 0x802b: /* RESPONSE-ORIGIN */
      if(ndpi_struct->cfg.stun_response_origin_enabled) {
        parse_ip_port_attribute(payload, payload_length, off, real_len, &flow->stun.response_origin,
                                flow->monit ? &flow->monit->protos.dtls_stun_rtp.response_origin : NULL);
      }
      break;

    case 0x802c: /* OTHER-ADDRESS */
      if(ndpi_struct->cfg.stun_other_address_enabled) {
        parse_ip_port_attribute(payload, payload_length, off, real_len, &flow->stun.other_address,
                                flow->monit ? &flow->monit->protos.dtls_stun_rtp.other_address : NULL);
      }
      break;

    case 0x0012: /* XOR-PEER-ADDRESS */
      if(ndpi_struct->cfg.stun_peer_address_enabled) {
        parse_xor_ip_port_attribute(ndpi_struct, flow,
                                    payload, payload_length, off, real_len,
                                    &flow->stun.peer_address,
                                    flow->monit ? &flow->monit->protos.dtls_stun_rtp.peer_address : NULL,
                                    transaction_id, magic_cookie, 1);
      }
      break;

    case 0x0101:
    case 0x0103:
      *app_proto = NDPI_PROTOCOL_ZOOM;
      return 1;

    case 0x4000:
    case 0x4001:
    case 0x4002:
    case 0x4003:
    case 0x4004:
    case 0x4007:
      /* These are the only messages apparently whatsapp voice can use */
      *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
      break;

    case 0x0014: /* Realm */
      if(flow->host_server_name[0] == '\0') {
	int i;
	bool valid = true;

        ndpi_hostname_sni_set(flow, payload + off + 4, ndpi_min(len, payload_length - off - 4), NDPI_HOSTNAME_NORM_ALL);
        NDPI_LOG_DBG(ndpi_struct, "Realm [%s]\n", flow->host_server_name);

	/* Some Realm contain junk, so let's validate it */
	for(i=0; flow->host_server_name[i] != '\0'; i++) {
	  if(flow->host_server_name[i] == '?') {
	    valid = false;
	    break;
	  }
	}

	if(valid) {
	  if(strstr(flow->host_server_name, "google.com") != NULL) {
	    *app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
	  } else if(strstr(flow->host_server_name, "whispersystems.org") != NULL ||
		    strstr(flow->host_server_name, "signal.org") != NULL) {
	    *app_proto = NDPI_PROTOCOL_SIGNAL_VOIP;
	  } else if(strstr(flow->host_server_name, "facebook") != NULL) {
	    *app_proto = NDPI_PROTOCOL_FACEBOOK_VOIP;
	  } else if(strstr(flow->host_server_name, "stripcdn.com") != NULL) {
	    *app_proto = NDPI_PROTOCOL_ADULT_CONTENT;
	  } else if(strstr(flow->host_server_name, "telegram") != NULL) {
	    *app_proto = NDPI_PROTOCOL_TELEGRAM_VOIP;
	  } else if(strstr(flow->host_server_name, "viber") != NULL) {
	    *app_proto = NDPI_PROTOCOL_VIBER_VOIP;
	  }
	} else
	  flow->host_server_name[0] = '\0';
      }
      break;

    /* Proprietary fields found on Microsoft Teams/Skype calls */
    case 0x8054: /* Candidate Identifier: Either skype for business or "normal" skype with multiparty call */
    case 0x24DF:
    case 0x3802:
    case 0x8036:
    case 0x8095: /* MS-Multiplexed-TURN-Session-ID */
    case 0x0800:
    case 0x8006:
    case 0x8070: /* MS Implementation Version */
    case 0x8055: /* MS Service Quality */
      *app_proto = NDPI_PROTOCOL_MSTEAMS_CALL;
      break;

    case 0x8029: /* ICE-CONTROLLED */
      if(current_pkt_from_client_to_server(ndpi_struct, flow))
        flow->stun.is_client_controlling = 0;
      else
        flow->stun.is_client_controlling = 1;
      break;

    case 0x802A: /* ICE-CONTROLLING */
      if(current_pkt_from_client_to_server(ndpi_struct, flow))
        flow->stun.is_client_controlling = 1;
      else
        flow->stun.is_client_controlling = 0;
      break;

    case 0xFF03:
      *app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
      break;

    case 0x0013:
      NDPI_LOG_DBG(ndpi_struct, "DATA attribute (%d/%d)\n",
                  real_len, payload_length - off - 4);
      if(real_len <= payload_length - off - 4) {
        orig_payload = packet->payload;
        orig_payload_length = packet->payload_packet_len;
        packet->payload = payload + off + 4;
        packet->payload_packet_len = real_len;

        stun_search_again(ndpi_struct, flow);
        NDPI_LOG_DBG(ndpi_struct, "End recursion\n");

        packet->payload = orig_payload;
        packet->payload_packet_len = orig_payload_length;
      }
      break;

    case 0x0020: /* XOR-MAPPED-ADDRESS */
      if(ndpi_struct->cfg.stun_mapped_address_enabled) {
        parse_xor_ip_port_attribute(ndpi_struct, flow,
                                    payload, payload_length, off, real_len,
                                    &flow->stun.mapped_address,
                                    flow->monit ? &flow->monit->protos.dtls_stun_rtp.mapped_address : NULL,
                                    transaction_id, magic_cookie, 0);
	flow->stun.num_xor_mapped_addresses++;
      }
      break;

    case 0x0016: /* XOR-RELAYED-ADDRESS */
      if(ndpi_struct->cfg.stun_relayed_address_enabled) {
        parse_xor_ip_port_attribute(ndpi_struct, flow,
                                    payload, payload_length, off, real_len,
                                    &flow->stun.relayed_address,
                                    flow->monit ? &flow->monit->protos.dtls_stun_rtp.relayed_address : NULL,
                                    transaction_id, magic_cookie, 0);
	flow->stun.num_xor_relayed_addresses++;
      }
      break;

    default:
      NDPI_LOG_DBG2(ndpi_struct, "Unknown attribute %04X\n", attribute);
      break;
    }

    off += 4 + real_len;
  }

  return 1;
}

/* ***************************************************** */

static int keep_extra_dissection(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  /* We want extra dissection for:
   * sub-classification
   * metadata extraction (*-ADDRESS) or looking for RTP
   * At the moment:
   * it seems ZOOM doens't have any meaningful attributes
   * we want (all) XOR-PEER-ADDRESS only for Telegram.
   * for the other protocols, we stop after we have all metadata (if enabled)
   * for some specific protocol, we might know that some attributes are never used
   * if monitoring is enabled, keep looking for (S)RTP anyway

   **After** extra dissection is ended, we might move to monitoring. Note that:
   * classification doesn't change while in monitoring!
   */

  if(packet->udp
     && (ntohs(packet->udp->source) == 3478)
     && (packet->payload_packet_len > 0)
     && (packet->payload[0] != 0x0) && (packet->payload[0] != 0x1)) {
    if(flow->stun.num_non_stun_pkt < 2) {
      flow->stun.non_stun_pkt_len[flow->stun.num_non_stun_pkt++] = packet->payload_packet_len;

#ifdef STUN_DEBUG
      if(flow->stun.num_non_stun_pkt == 2)
	printf("%d %d\n", flow->stun.non_stun_pkt_len[0], flow->stun.non_stun_pkt_len[1]);
#endif
    }
  }

  if(packet->payload_packet_len > 699) {
    if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TELEGRAM_VOIP) {
      if((packet->payload[0] == 0x16) && (packet->payload[1] == 0xfe)
	 && ((packet->payload[2] == 0xff) /* DTLS 1.0 */
	     || (packet->payload[2] == 0xfd) /* DTLS 1.2 */ ))
	; /* Skip DTLS */
      else {
	/* STUN or RTP */
	/* This packet is too big to be audio: add video */
	flow->flow_multimedia_types |= ndpi_multimedia_video_flow;
      }
    }
  }

  if(flow->monitoring)
    return 1;

  if(flow->num_extra_packets_checked + 1 == flow->max_extra_packets_to_check) {
    if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling monitoring (end extra dissection)\n");
      flow->monitoring = 1;
      return 1;
    }
  }

  if(!is_subclassification_real(flow))
    return 1;

  if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN) &&
     (flow->detected_protocol_stack[1] != NDPI_PROTOCOL_SRTP &&
      flow->detected_protocol_stack[1] != NDPI_PROTOCOL_DTLS))
    return 1;

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TELEGRAM_VOIP &&
     ndpi_struct->cfg.stun_peer_address_enabled)
    return 1;

  /* General rule */
  if((flow->stun.mapped_address.port || !ndpi_struct->cfg.stun_mapped_address_enabled) &&
     (flow->stun.peer_address.port || !ndpi_struct->cfg.stun_peer_address_enabled) &&
     (flow->stun.relayed_address.port || !ndpi_struct->cfg.stun_relayed_address_enabled) &&
     (flow->stun.response_origin.port || !ndpi_struct->cfg.stun_response_origin_enabled) &&
     (flow->stun.other_address.port || !ndpi_struct->cfg.stun_other_address_enabled)) {
    if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling monitoring (found all metadata)\n");
      flow->monitoring = 1;
      return 1;
    }
    return 0;
  }

  /* Exception WA: only relayed and mapped address attributes but we keep looking for RTP packets */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_WHATSAPP_CALL &&
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_SRTP &&
     (flow->stun.mapped_address.port || !ndpi_struct->cfg.stun_mapped_address_enabled) &&
     (flow->stun.relayed_address.port || !ndpi_struct->cfg.stun_relayed_address_enabled)) {
    if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling monitor (found all metadata; wa case)\n");
      flow->monitoring = 1;
      return 1;
    }
    return 0;
  }

  /* Exception Zoom: no metadata */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_ZOOM) {
    if(is_monitoring_enabled(ndpi_struct, NDPI_PROTOCOL_STUN)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling monitor (zoom case)\n");
      flow->monitoring = 1;
      return 1;
    }
    return 0;
  }

  return 1;
}

/* ***************************************************** */

static u_int32_t __get_master(struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[1];
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN &&
     flow->detected_protocol_stack[0] != NDPI_PROTOCOL_TELEGRAM)
    return flow->detected_protocol_stack[0];
  return NDPI_PROTOCOL_STUN;
}

/* ***************************************************** */

static int stun_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int rtp_rtcp;
  u_int8_t first_byte;
  u_int16_t msg_type, app_proto = NDPI_PROTOCOL_UNKNOWN;
  u_int32_t unused;
  int first_dtls_pkt = 0;
  u_int16_t old_proto_stack[2] = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};

  NDPI_LOG_DBG2(ndpi_struct, "Packet counter %d protos %d/%d Monitoring? %d\n",
                flow->packet_counter,
                flow->detected_protocol_stack[0], flow->detected_protocol_stack[1],
                flow->monitoring);

  /* TODO: check TCP support. We need to pay some attention because:
     * multiple msg in the same TCP segment
     * same msg split across multiple segments */

  if(packet->payload_packet_len <= 1)
    return keep_extra_dissection(ndpi_struct, flow);

  first_byte = packet->payload[0];
  msg_type = ntohs(*((u_int16_t *)&packet->payload[0]));

  /* RFC9443 */
  if(first_byte <= 3 ||
     /* Whatsapp special case */
     (flow->detected_protocol_stack[0] == NDPI_PROTOCOL_WHATSAPP_CALL &&
      (msg_type == 0x0800 || msg_type == 0x0801 || msg_type == 0x0802 ||
       msg_type == 0x0804 || msg_type == 0x0805))) {
    NDPI_LOG_DBG(ndpi_struct, "Still STUN\n");
    if(is_stun(ndpi_struct, flow, &app_proto) == 1) { /* To extract other metadata */
      if(is_new_subclassification_better(ndpi_struct, flow, app_proto)) {
        ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto, __get_master(flow));
      }
    }
  } else if(first_byte <= 15) {
    NDPI_LOG_DBG(ndpi_struct, "DROP range. Unexpected\n");
  } else if(first_byte <= 19) {
    NDPI_LOG_DBG(ndpi_struct, "ZRTP range. Unexpected\n");
  } else if(first_byte <= 63) {
    NDPI_LOG_DBG(ndpi_struct, "DTLS\n");

    if(ndpi_struct->cfg.stun_opportunistic_tls_enabled &&
       is_dtls(packet->payload, packet->payload_packet_len, &unused)) {

      /* Process this DTLS packet via TLS/DTLS code but keep using STUN dissection.
         This way we can keep demultiplexing DTLS/STUN/RTP */

      /* Switching to TLS dissector is tricky, because we are calling one dissector
         from another one, and that is not a common operation...
         Additionally:
         * at that point protocol stack is already set to STUN or STUN/XXX
         * we have room for only two protocols in flow->detected_protocol_stack[] so
           we can't have something like STUN/DTLS/SNAPCHAT_CALL
         * the easiest (!?) solution is to remove everything, and let the TLS dissector
	   to set both master (i.e. DTLS) and subprotocol (if any) */

      /* If we already have a real sub-classification, and the DTLS code doesn't set any
         subclassification iself (it is quite unlikely that we have a subprotocol only via
         Client Hello, for example), keep the original one */

      /* In same rare cases, with malformed/fuzzed traffic, `is_dtls()` might return false
         positives. In that case, the TLS dissector doesn't set the master protocol, so we
         need to rollback to the current state */

      if(flow->tls_quic.certificate_processed == 1) {
        NDPI_LOG_DBG(ndpi_struct, "Interesting DTLS stuff already processed. Ignoring\n");
      } else if(!flow->monitoring) {
        NDPI_LOG_DBG(ndpi_struct, "Switch to DTLS (%d/%d)\n",
                     flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);

        if(flow->stun.maybe_dtls == 0) {
          /* First DTLS packet of the flow */
          first_dtls_pkt = 1;

          /* We might need to rollback this change... */
          old_proto_stack[0] = flow->detected_protocol_stack[0];
          old_proto_stack[1] = flow->detected_protocol_stack[1];

          /* TODO: right way? It is a bit scary... do we need to reset something else too? */
          reset_detected_protocol(flow);
          /* We keep the category related to STUN traffic */
          /* STUN often triggers this risk; clear it. TODO: clear other risks? */
          ndpi_unset_risk(flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);

          /* Give room for DTLS handshake, where we might have
             retransmissions and fragments */
          flow->max_extra_packets_to_check = ndpi_min(255, (int)flow->max_extra_packets_to_check + 10);
          flow->stun.maybe_dtls = 1;
        }

        switch_to_tls(ndpi_struct, flow, first_dtls_pkt);

        if(first_dtls_pkt &&
           flow->detected_protocol_stack[0] == NDPI_PROTOCOL_DTLS &&
           flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN &&
           old_proto_stack[0] != NDPI_PROTOCOL_UNKNOWN &&
           old_proto_stack[0] != NDPI_PROTOCOL_STUN) {
          NDPI_LOG_DBG(ndpi_struct, "Keeping old subclassification %d\n", old_proto_stack[0]);
          ndpi_int_stun_add_connection(ndpi_struct, flow,
                                       old_proto_stack[0] == NDPI_PROTOCOL_RTP ? NDPI_PROTOCOL_SRTP : old_proto_stack[0],
                                       __get_master(flow));
        }

        /* If this is not a real DTLS packet, we need to restore the old state */
        if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
           first_dtls_pkt) {
          NDPI_LOG_DBG(ndpi_struct, "Switch to TLS failed. Rollback to old classification\n");

          ndpi_set_detected_protocol(ndpi_struct, flow,
                                     old_proto_stack[0], old_proto_stack[1],
                                     NDPI_CONFIDENCE_DPI);

          flow->stun.maybe_dtls = 0;
          flow->max_extra_packets_to_check -= 10;
        }

        NDPI_LOG_DBG(ndpi_struct, "(%d/%d)\n",
                     flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
      } else {
        NDPI_LOG_DBG(ndpi_struct, "Skip DTLS packet because in monitoring\n");
      }
    }
  } else if(first_byte <= 79) {
    if(flow->stun.is_turn) {
      NDPI_LOG_DBG(ndpi_struct, "TURN range\n");

      if(packet->payload_packet_len >= 4) {
        u_int16_t ch_len;

        ch_len = ntohs(*(u_int16_t *)&packet->payload[2]);

        if(ch_len <= packet->payload_packet_len - 4) {
          const u_int8_t *orig_payload;
          u_int16_t orig_payload_length;

          orig_payload = packet->payload;
          orig_payload_length = packet->payload_packet_len;
          packet->payload = packet->payload + 4;
          packet->payload_packet_len = ch_len;

          stun_search_again(ndpi_struct, flow);
          NDPI_LOG_DBG(ndpi_struct, "End recursion on turn channel\n");

          packet->payload = orig_payload;
          packet->payload_packet_len = orig_payload_length;

        } else {
          if(flow->l4_proto == IPPROTO_UDP) /* The error is quite common on TCP since we don't reassemble msgs */
            NDPI_LOG_DBG(ndpi_struct, "Invalid channel length %d %d\n",
                         ch_len, packet->payload_packet_len - 4);
        }
      }
    } else {
      NDPI_LOG_DBG(ndpi_struct, "QUIC range (not turn). Unexpected\n");
    }
  } else if(first_byte <= 127) {
    NDPI_LOG_DBG(ndpi_struct, "QUIC range. Unexpected\n");
  } else if(first_byte <= 191) {

    rtp_rtcp = is_rtp_or_rtcp(ndpi_struct, packet->payload, packet->payload_packet_len, NULL);
    if(rtp_rtcp == IS_RTP) {

      NDPI_LOG_DBG(ndpi_struct, "RTP (dir %d) [%d/%d]\n", packet->packet_direction,
                                 flow->stun.rtp_counters[0], flow->stun.rtp_counters[1]);

      flow->stun.rtp_counters[packet->packet_direction]++;

      NDPI_LOG_INFO(ndpi_struct, "Found RTP over STUN\n");

      rtp_get_stream_type(packet->payload[1] & 0x7F, &flow->flow_multimedia_types, flow->detected_protocol_stack[0]);

      if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_RTP &&
         flow->detected_protocol_stack[0] != NDPI_PROTOCOL_RTCP &&
         flow->detected_protocol_stack[1] != NDPI_PROTOCOL_SRTP) {

        if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
          if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_DTLS) {
            /* Keep DTLS/SUBPROTO since we already wrote to flow->protos.tls_quic */
          } else {
            /* STUN/SUBPROTO -> SRTP/SUBPROTO */
            ndpi_int_stun_add_connection(ndpi_struct, flow,
                                         flow->detected_protocol_stack[0], NDPI_PROTOCOL_SRTP);
          }
        } else {
          /* STUN -> STUN/RTP, or
             DTLS -> DTLS/SRTP */
          ndpi_int_stun_add_connection(ndpi_struct, flow,
                                       __get_master(flow) == NDPI_PROTOCOL_STUN ? NDPI_PROTOCOL_RTP: NDPI_PROTOCOL_SRTP,
                                       __get_master(flow));
        }
      } else if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_RTCP &&
                flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
        /* From RTP dissector; if we have RTP and RTCP multiplexed together (but not STUN, yet) we always
	   use RTP, as we do in RTP dissector */
        if(!flow->monitoring)
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_RTP, NDPI_CONFIDENCE_DPI);
        else
          NDPI_LOG_DBG(ndpi_struct, "Skip RTP packet because in monitoring\n");
      }
    } else if(rtp_rtcp == IS_RTCP) {
      NDPI_LOG_DBG(ndpi_struct, "RTCP\n");
      flow->stun.rtcp_seen = 1;
    } else {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected\n");
    }
  } else {
    /* Microsoft Multiplexed TURN messages.
       See: https://msopenspecs.azureedge.net/files/MS-TURN/%5bMS-TURN%5d.pdf 2.2.3 */
    if(packet->payload_packet_len >= 12 &&
       ntohs(get_u_int16_t(packet->payload, 0)) == 0xFF10 &&
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_MSTEAMS_CALL) {
      u_int16_t ch_len;

      ch_len = ntohs(get_u_int16_t(packet->payload, 2));

      if(ch_len == packet->payload_packet_len - 4 &&
         ch_len >= 8) {
        const u_int8_t *orig_payload;
        u_int16_t orig_payload_length;

        orig_payload = packet->payload;
        orig_payload_length = packet->payload_packet_len;
        packet->payload = packet->payload + 12;
        packet->payload_packet_len = ch_len - 8;

        stun_search_again(ndpi_struct, flow);

        NDPI_LOG_DBG(ndpi_struct, "End recursion on MS channel\n");

        packet->payload = orig_payload;
        packet->payload_packet_len = orig_payload_length;

      } else {
        NDPI_LOG_DBG(ndpi_struct, "Invalid MS channel length %d %d\n",
                     ch_len, packet->payload_packet_len - 4);
      }
    } else {
      NDPI_LOG_DBG(ndpi_struct, "QUIC other range. Unexpected\n");
    }
  }
  return keep_extra_dissection(ndpi_struct, flow);
}

/* ************************************************************ */

static int stun_telegram_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                                      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const u_int8_t *orig_payload;
  u_int16_t orig_payload_length;
  char pattern[12] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  u_int16_t length;

  NDPI_LOG_DBG2(ndpi_struct, "[T] Packet counter %d protos %d/%d Monitoring? %d\n",
                flow->packet_counter,
                flow->detected_protocol_stack[0], flow->detected_protocol_stack[1],
                flow->monitoring);

  /* For SOME of its STUN flows, Telegram uses a custom encapsulation
     There is no documentation. It seems:
     * some unknown packets (especially at the beginning/end of the flow) have a bunch of 0xFF
     * the other packets encapsulate standard STUN/DTLS/RTP payload at offset 24
       (with a previous field containing the payload length)
   */

  if(packet->payload_packet_len <= 28) {
    NDPI_LOG_DBG(ndpi_struct, "Malformed custom Telegram packet (too short)\n");
    return keep_extra_dissection(ndpi_struct, flow);
  }

  if(memcmp(&packet->payload[16], pattern, sizeof(pattern)) == 0) {
    NDPI_LOG_DBG(ndpi_struct, "Custom/Unknown Telegram packet\n");
    return keep_extra_dissection(ndpi_struct, flow);
  }

  /* It should be STUN/DTLS/RTP */

  length = ntohs(*(u_int16_t *)&packet->payload[22]);
  if(24 + length > packet->payload_packet_len) {
    NDPI_LOG_DBG(ndpi_struct, "Malformed custom Telegram packet (too long: %d %d)\n",
                 length, packet->payload_packet_len);
    return keep_extra_dissection(ndpi_struct, flow);
  }

  orig_payload = packet->payload;
  orig_payload_length = packet->payload_packet_len ;
  packet->payload = packet->payload + 24;
  packet->payload_packet_len = length;

  stun_search_again(ndpi_struct, flow);

  packet->payload = orig_payload;
  packet->payload_packet_len = orig_payload_length;

  return keep_extra_dissection(ndpi_struct, flow);
}

/* ************************************************************ */

static u_int64_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev) {
  if(rev) {
    if(flow->is_ipv6)
      return (ndpi_quick_hash64((const char *)flow->s_address.v6, 16) << 16) | ntohs(flow->s_port);
    else
      return ((u_int64_t)flow->s_address.v4 << 32) | flow->s_port;
  } else {
    if(flow->is_ipv6)
      return (ndpi_quick_hash64((const char *)flow->c_address.v6, 16) << 16) | ntohs(flow->c_port);
    else
      return ((u_int64_t)flow->c_address.v4 << 32) | flow->c_port;
  }
}

/* ************************************************************ */

static u_int64_t get_stun_lru_key_raw4(u_int32_t ip, u_int16_t port_host_order) {
  return ((u_int64_t)ip << 32) | htons(port_host_order);
}

/* ************************************************************ */

static u_int64_t get_stun_lru_key_raw6(u_int8_t *ip, u_int16_t port_host_order) {
  return ((u_int64_t)ndpi_quick_hash(ip, 16) << 32) | htons(port_host_order);
}

/* ************************************************************ */

static void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int16_t app_proto,
					 u_int16_t master_proto) {
  ndpi_confidence_t confidence = NDPI_CONFIDENCE_DPI;
  u_int16_t new_app_proto;

  /* In monitoring the classification can't change again */
  if(flow->monitoring)
    return;

  NDPI_LOG_DBG(ndpi_struct, "Wanting %d/%d\n", master_proto, app_proto);

  if(app_proto == NDPI_PROTOCOL_UNKNOWN) {
    /* https://support.google.com/a/answer/1279090?hl=en */
    if((ntohs(flow->c_port) >= 19302 && ntohs(flow->c_port) <= 19309) ||
       ntohs(flow->c_port) == 3478 ||
       (ntohs(flow->s_port) >= 19302 && ntohs(flow->s_port) <= 19309) ||
       ntohs(flow->s_port) == 3478) {
      if(flow->is_ipv6) {
	u_int64_t pref1 = ndpi_htonll(0x2001486048640005); /* 2001:4860:4864:5::/64 */
	u_int64_t pref2 = ndpi_htonll(0x2001486048640006); /* 2001:4860:4864:6::/64 */

        if(memcmp(flow->c_address.v6, &pref1, sizeof(pref1)) == 0 ||
           memcmp(flow->c_address.v6, &pref2, sizeof(pref2)) == 0 ||
           memcmp(flow->s_address.v6, &pref1, sizeof(pref1)) == 0 ||
           memcmp(flow->s_address.v6, &pref2, sizeof(pref2)) == 0) {
          app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
	}
      } else {
        u_int32_t c_address, s_address;

	c_address = ntohl(flow->c_address.v4);
	s_address = ntohl(flow->s_address.v4);
	if((c_address & 0xFFFFFF00) == 0x4a7dfa00 || /* 74.125.250.0/24 */
           (c_address & 0xFFFFFF00) == 0x8efa5200 || /* 142.250.82.0/24 */
           (s_address & 0xFFFFFF00) == 0x4a7dfa00 ||
           (s_address & 0xFFFFFF00) == 0x8efa5200) {
          app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
	}
      }
    }
  }

  if(!is_subclassification_real_by_proto(app_proto)) {
    new_app_proto = search_into_cache(ndpi_struct, flow);
    if(new_app_proto != NDPI_PROTOCOL_UNKNOWN) {
      confidence = NDPI_CONFIDENCE_DPI_CACHE;
      if(app_proto == NDPI_PROTOCOL_RTP)
        master_proto = NDPI_PROTOCOL_SRTP; /* STUN/RTP --> SRTP/APP */
      if(master_proto == NDPI_PROTOCOL_RTP || master_proto == NDPI_PROTOCOL_RTCP)
        master_proto = NDPI_PROTOCOL_SRTP; /* RTP|RTCP --> SRTP/APP */
      app_proto = new_app_proto;
    }
  }

  /* From RTP dissector */
  if(master_proto == NDPI_PROTOCOL_RTP || master_proto == NDPI_PROTOCOL_RTCP) {
    if(app_proto == NDPI_PROTOCOL_UNKNOWN) {
      app_proto = NDPI_PROTOCOL_RTP;
      master_proto = NDPI_PROTOCOL_STUN; /* RTP|RTCP ->STUN/RTP */
    } else {
      master_proto = NDPI_PROTOCOL_SRTP;
    }
  }

  /* Adding only real subclassifications */
  if(is_subclassification_real_by_proto(app_proto))
    add_to_cache(ndpi_struct, flow, app_proto);

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN ||
     app_proto != NDPI_PROTOCOL_UNKNOWN) {
    NDPI_LOG_DBG(ndpi_struct, "Setting %d/%d\n", master_proto, app_proto);
    ndpi_set_detected_protocol(ndpi_struct, flow, app_proto, master_proto, confidence);

    /* In "normal" data-path the generic code in `ndpi_internal_detection_process_packet()`
       takes care of setting the category */
    if(flow->extra_packets_func) {
      ndpi_protocol ret = { { master_proto, app_proto }, NDPI_PROTOCOL_UNKNOWN /* unused */, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NULL};
      flow->category = ndpi_get_proto_category(ndpi_struct, ret);
    }
  }

  switch_extra_dissection_to_stun(ndpi_struct, flow, 1);
}

/* ************************************************************ */

void switch_extra_dissection_to_stun(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     int std_callback)
{
  if(!flow->extra_packets_func) {
    if(keep_extra_dissection(ndpi_struct, flow)) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
      flow->max_extra_packets_to_check = ndpi_struct->cfg.stun_max_packets_extra_dissection;
      if(std_callback)
        flow->extra_packets_func = stun_search_again;
      else
        flow->extra_packets_func = stun_telegram_search_again;
    }
  }
}

/* ************************************************************ */

static void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t app_proto;
  int rc;

  NDPI_LOG_DBG(ndpi_struct, "search stun\n");

  app_proto = NDPI_PROTOCOL_UNKNOWN;

  if(packet->iph &&
     ((packet->iph->daddr == 0xFFFFFFFF /* 255.255.255.255 */) ||
      ((ntohl(packet->iph->daddr) & 0xF0000000) == 0xE0000000 /* A multicast address */))) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  rc = is_stun(ndpi_struct, flow, &app_proto);

  if(rc == 1) {
    ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto, __get_master(flow));
    return;
  }

  /* TODO: can we stop earlier? */
  if(flow->packet_counter > 5)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}

/* ************************************************************ */

void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("STUN", ndpi_struct, *id,
				      NDPI_PROTOCOL_STUN,
				      ndpi_search_stun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
