/*
 * stun.c
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
 * along with nDPI. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_STUN

#include "ndpi_api.h"
#include "ndpi_private.h"

// #define DEBUG_LRU  1
// #define DEBUG_ZOOM_LRU  1

#define STUN_HDR_LEN   20 /* STUN message header length, Classic-STUN (RFC 3489) and STUN (RFC 8489) both */

static u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev);
static u_int32_t get_stun_lru_key_raw4(u_int32_t ip, u_int16_t port);
static void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int app_proto);
static int stun_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow);


static u_int16_t search_into_cache(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow)
{
  u_int16_t proto;
  u_int32_t key;
  int rc;

  if(ndpi_struct->stun_cache) {
    key = get_stun_lru_key(flow, 0);
    rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto,
			     0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
    printf("[LRU] Searching %u\n", key);
#endif

    if(!rc) {
      key = get_stun_lru_key(flow, 1);
      rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto,
			       0 /* Don't remove it as it can be used for other connections */,
			       ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
      printf("[LRU] Searching %u\n", key);
#endif
    }

    if(rc) {
#ifdef DEBUG_LRU
      printf("[LRU] Cache FOUND %u / %u\n", key, proto);
#endif

      return proto;
    } else {
#ifdef DEBUG_LRU
      printf("[LRU] NOT FOUND %u\n", key);
#endif
    }
  } else {
#ifdef DEBUG_LRU
    printf("[LRU] NO/EMPTY CACHE\n");
#endif
  }
  return NDPI_PROTOCOL_UNKNOWN;
}

static void add_to_caches(struct ndpi_detection_module_struct *ndpi_struct,
			  struct ndpi_flow_struct *flow,
			  u_int16_t app_proto)
{
  u_int32_t key, key_rev;

  if(ndpi_struct->stun_cache &&
     app_proto != NDPI_PROTOCOL_STUN &&
     app_proto != NDPI_PROTOCOL_UNKNOWN) {
    /* No sense to add STUN, but only subprotocols */

    key = get_stun_lru_key(flow, 0);
    ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key, app_proto, ndpi_get_current_time(flow));
    key_rev = get_stun_lru_key(flow, 1);
    ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key_rev, app_proto, ndpi_get_current_time(flow));

#ifdef DEBUG_LRU
    printf("[LRU] ADDING %u 0x%x app %u [%u -> %u]\n", key, key_rev, app_proto,
	   ntohs(flow->c_port), ntohs(flow->s_port));
#endif
  }

  /* TODO: extend to other protocols? */
  if(ndpi_struct->stun_zoom_cache &&
     app_proto == NDPI_PROTOCOL_ZOOM &&
     flow->l4_proto == IPPROTO_UDP) {
    key = get_stun_lru_key(flow, 0); /* Src */
    ndpi_lru_add_to_cache(ndpi_struct->stun_zoom_cache, key,
                          0 /* dummy */, ndpi_get_current_time(flow));

#ifdef DEBUG_ZOOM_LRU
    printf("[LRU ZOOM] ADDING %u [src_port %u]\n", key, ntohs(flow->c_port));
#endif
  }
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static
#endif
int is_stun(struct ndpi_detection_module_struct *ndpi_struct,
            struct ndpi_flow_struct *flow,
            u_int16_t *app_proto)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t msg_type, msg_len;
  int off;
  const u_int8_t *payload = packet->payload;
  u_int16_t payload_length = packet->payload_packet_len;
  const u_int8_t *orig_payload;
  u_int16_t orig_payload_length;
  u_int32_t magic_cookie;

  if(payload_length < STUN_HDR_LEN) {
    return 0;
  }

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

  msg_type = ntohs(*((u_int16_t *)&payload[0]));
  msg_len = ntohs(*((u_int16_t *)&payload[2]));
  magic_cookie = ntohl(*((u_int32_t *)&payload[4]));

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
    return 0;
  }

  /* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml */
  if(((msg_type & 0x3EEF) > 0x000B) &&
     msg_type != 0x0800 && msg_type != 0x0801 && msg_type != 0x0802) {
    NDPI_LOG_DBG(ndpi_struct, "Invalid msg_type = %04X\n", msg_type);
    return 0;
  }

  if(magic_cookie != 0x2112A442) {
    /* Some heuristic to detect classic-stun: let's see if attributes list seems ok */
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

  if(msg_type == 0x0800 || msg_type == 0x0801 || msg_type == 0x0802) {
    *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
    return 1;
  }

  off = STUN_HDR_LEN;
  while(off + 4 < payload_length) {
    u_int16_t attribute = ntohs(*((u_int16_t *)&payload[off]));
    u_int16_t len = ntohs(*((u_int16_t *)&payload[off + 2]));
    u_int16_t real_len = (len + 3) & 0xFFFFFFFC;

    NDPI_LOG_DBG(ndpi_struct, "Attribute 0x%x (%d/%d)\n", attribute, len, real_len);

    switch(attribute) {
    case 0x0012: /* XOR-PEER-ADDRESS */
      if(off + 12 < payload_length &&
         len == 8 && payload[off + 5] == 0x01) { /* TODO: ipv6 */
        u_int16_t port;
        u_int32_t ip;
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
	char buf[128];
#endif

        port = ntohs(*((u_int16_t *)&payload[off + 6])) ^ (magic_cookie >> 16);
        ip = *((u_int32_t *)&payload[off + 8]) ^ htonl(magic_cookie);

        NDPI_LOG_DBG(ndpi_struct, "Peer %s:%d [proto %d]\n",
                     inet_ntop(AF_INET, &ip, buf, sizeof(buf)), port,
                     flow->detected_protocol_stack[0]);

        if(1 /* TODO: enable/disable */ &&
           ndpi_struct->stun_cache) {
          u_int32_t key = get_stun_lru_key_raw4(ip, port);

          ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key,
				flow->detected_protocol_stack[0],
				ndpi_get_current_time(flow));
#ifdef DEBUG_LRU
          printf("[LRU] Add peer %u %d\n", key, flow->detected_protocol_stack[0]);
#endif
        }
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
      return 1;

    case 0x0014: /* Realm */
      if(flow->host_server_name[0] == '\0') {
        ndpi_hostname_sni_set(flow, payload + off + 4, ndpi_min(len, payload_length - off - 4), NDPI_HOSTNAME_NORM_ALL);
        NDPI_LOG_DBG(ndpi_struct, "Realm [%s]\n", flow->host_server_name);

        if(strstr(flow->host_server_name, "google.com") != NULL) {
          *app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
          return 1;
        } else if(strstr(flow->host_server_name, "whispersystems.org") != NULL ||
                  strstr(flow->host_server_name, "signal.org") != NULL) {
          *app_proto = NDPI_PROTOCOL_SIGNAL_VOIP;
          return 1;
        } else if(strstr(flow->host_server_name, "facebook") != NULL) {
          *app_proto = NDPI_PROTOCOL_FACEBOOK_VOIP;
          return 1;
        } else if(strstr(flow->host_server_name, "stripcdn.com") != NULL) {
          *app_proto = NDPI_PROTOCOL_ADULT_CONTENT;
          return 1;
        } else if(strstr(flow->host_server_name, "telegram") != NULL) {
          *app_proto = NDPI_PROTOCOL_TELEGRAM_VOIP;
          return 1;
        }
      }
      break;

    /* Proprietary fields found on skype calls */
    case 0x8054: /* Candidate Identifier: Either skype for business or "normal" skype with multiparty call */
    case 0x24DF:
    case 0x3802:
    case 0x8036:
    case 0x8095: /* MS-Multiplexed-TURN-Session-ID */
    case 0x0800:
    case 0x8006:
    case 0x8070: /* MS Implementation Version */
    case 0x8055: /* MS Service Quality */
      *app_proto = NDPI_PROTOCOL_SKYPE_TEAMS_CALL;
      return 1;

    case 0xFF03:
      *app_proto = NDPI_PROTOCOL_GOOGLE_CALL;
      return 1;

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

    default:
      NDPI_LOG_DBG2(ndpi_struct, "Unknown attribute %04X\n", attribute);
      break;
    }

    off += 4 + real_len;
  }

  return 1;
}

static int keep_extra_dissection(struct ndpi_detection_module_struct *ndpi_struct,
                                 struct ndpi_flow_struct *flow)
{
  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN /* No subclassification */)
    return 1;

  /* We have a sub-classification */

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_RTP)
    return 0;

  /* Looking for XOR-PEER-ADDRESS metadata; TODO: other protocols? */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TELEGRAM_VOIP)
    return 1;
  return 0;
}

static u_int32_t __get_master(struct ndpi_flow_struct *flow) {

  if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[1];
  if(flow->detected_protocol_stack[0] != NDPI_PROTOCOL_UNKNOWN)
    return flow->detected_protocol_stack[0];
  return NDPI_PROTOCOL_STUN;
}

static int stun_search_again(struct ndpi_detection_module_struct *ndpi_struct,
                             struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  int rtp_rtcp;
  u_int8_t first_byte;
  u_int16_t app_proto = NDPI_PROTOCOL_UNKNOWN;
  u_int32_t unused;
  int first_dtls_pkt = 0;
  u_int16_t old_proto_stack[2] = {NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN};

  NDPI_LOG_DBG2(ndpi_struct, "Packet counter %d protos %d/%d\n", flow->packet_counter,
                flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);

  /* TODO: check TCP support. We need to pay some attention because:
     * multiple msg in the same TCP segment
     * same msg split across multiple segments */

  if(packet->payload_packet_len == 0)
    return 1;

  first_byte = packet->payload[0];

  /* draft-ietf-avtcore-rfc7983bis */
  if(first_byte <= 3) {
    NDPI_LOG_DBG(ndpi_struct, "Still STUN\n");
    if(is_stun(ndpi_struct, flow, &app_proto) /* To extract other metadata */ &&
       flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN /* No previous subclassification */) {
      ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto);
    }
  } else if(first_byte <= 19) {
    NDPI_LOG_DBG(ndpi_struct, "DROP or ZRTP range. Unexpected\n");
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

      /* In same rare cases, with malformed/fuzzed traffic, `is_dtls()` might return false
         positives. In that case, the TLS dissector doesn't set the master protocol, so we
         need to rollback to the current state */

      if(packet->tcp) {
        /* TODO: TLS code assumes that DTLS is only over UDP */
        NDPI_LOG_DBG(ndpi_struct, "Ignoring DTLS over TCP\n");
      } else {
        if(flow->tls_quic.certificate_processed == 1) {
          NDPI_LOG_DBG(ndpi_struct, "Interesting DTLS stuff already processed. Ignoring\n");
        } else {
          NDPI_LOG_DBG(ndpi_struct, "Switch to DTLS (%d/%d)\n",
                       flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);

          if(flow->stun.maybe_dtls == 0) {
            /* First DTLS packet of the flow */
            first_dtls_pkt = 1;

	    /* We might need to rollback this change... */
	    old_proto_stack[0] = flow->detected_protocol_stack[0];
	    old_proto_stack[1] = flow->detected_protocol_stack[1];

            /* TODO: right way? It is a bit scary... do we need to reset something else too? */
            reset_detected_protocol(ndpi_struct, flow);
            /* We keep the category related to STUN traffic */
	    /* STUN often triggers this risk; clear it. TODO: clear other risks? */
	    ndpi_unset_risk(ndpi_struct, flow, NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT);

            /* Give room for DTLS handshake, where we might have
               retransmissions and fragments */
            flow->max_extra_packets_to_check = ndpi_min(255, (int)flow->max_extra_packets_to_check + 10);
            flow->stun.maybe_dtls = 1;
	  }

	  switch_to_tls(ndpi_struct, flow, first_dtls_pkt);

	  NDPI_LOG_DBG(ndpi_struct, "(%d/%d)\n",
                       flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);

	  /* If this is not a real DTLS packet, we need to restore the old state */
          if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
             first_dtls_pkt) {
            NDPI_LOG_DBG(ndpi_struct, "Switch to TLS failed. Rollback to old classification\n");

            ndpi_set_detected_protocol(ndpi_struct, flow,
                                       old_proto_stack[1], old_proto_stack[0],
                                       NDPI_CONFIDENCE_DPI);

            flow->stun.maybe_dtls = 0;
            flow->max_extra_packets_to_check -= 10;

            NDPI_LOG_DBG(ndpi_struct, "(%d/%d)\n",
                         flow->detected_protocol_stack[0], flow->detected_protocol_stack[1]);
          }
        }
      }
    }
  } else if(first_byte <= 127) {
    NDPI_LOG_DBG(ndpi_struct, "QUIC or TURN range. Unexpected\n");
  } else if(first_byte <= 191) {

    rtp_rtcp = is_rtp_or_rtcp(ndpi_struct, flow);
    if(rtp_rtcp == IS_RTP) {
      NDPI_LOG_DBG(ndpi_struct, "RTP (dir %d)\n", packet->packet_direction);
      NDPI_LOG_INFO(ndpi_struct, "Found RTP over STUN\n");

      rtp_get_stream_type(packet->payload[1] & 0x7F, &flow->flow_multimedia_type);

      if(flow->detected_protocol_stack[1] != NDPI_PROTOCOL_UNKNOWN) {
        if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_DTLS) {
          /* Keep DTLS/SUBPROTO since we already wrote to flow->protos.tls_quic */
        } else {
          /* STUN/SUBPROTO -> SUBPROTO/RTP */
          ndpi_set_detected_protocol(ndpi_struct, flow,
                                     NDPI_PROTOCOL_RTP, flow->detected_protocol_stack[0],
                                     NDPI_CONFIDENCE_DPI);
        }
      } else {
        /* STUN -> STUN/RTP, or
           DTLS -> DTLS/RTP */
        ndpi_set_detected_protocol(ndpi_struct, flow,
                                   NDPI_PROTOCOL_RTP, __get_master(flow),
                                   NDPI_CONFIDENCE_DPI);
      }
      return 0; /* Stop */
    } else if(rtp_rtcp == IS_RTCP) {
      NDPI_LOG_DBG(ndpi_struct, "RTCP\n");
    } else {
      NDPI_LOG_DBG(ndpi_struct, "Unexpected\n");
    }
  } else {
    NDPI_LOG_DBG(ndpi_struct, "QUIC range. Unexpected\n");
  }
  return keep_extra_dissection(ndpi_struct, flow);
}

/* ************************************************************ */

static u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev) {
  if(rev) {
    if(flow->is_ipv6)
      return ndpi_quick_hash(flow->s_address.v6, 16) + ntohs(flow->s_port);
    else
      return ntohl(flow->s_address.v4) + ntohs(flow->s_port);
  } else {
    if(flow->is_ipv6)
      return ndpi_quick_hash(flow->c_address.v6, 16) + ntohs(flow->c_port);
    else
      return ntohl(flow->c_address.v4) + ntohs(flow->c_port);
  }
}

/* ************************************************************ */

static u_int32_t get_stun_lru_key_raw4(u_int32_t ip, u_int16_t port_host_order) {
  return ntohl(ip) + port_host_order;
}

/* ************************************************************ */

int stun_search_into_zoom_cache(struct ndpi_detection_module_struct *ndpi_struct,
                                struct ndpi_flow_struct *flow)
{
  u_int16_t dummy;
  u_int32_t key;

  if(ndpi_struct->stun_zoom_cache &&
     flow->l4_proto == IPPROTO_UDP) {
    key = get_stun_lru_key(flow, 0); /* Src */
#ifdef DEBUG_ZOOM_LRU
    printf("[LRU ZOOM] Search %u [src_port %u]\n", key, ntohs(flow->c_port));
#endif

    if(ndpi_lru_find_cache(ndpi_struct->stun_zoom_cache, key,
                           &dummy, 0 /* Don't remove it as it can be used for other connections */,
			   ndpi_get_current_time(flow))) {
#ifdef DEBUG_ZOOM_LRU
      printf("[LRU ZOOM] Found");
#endif
      return 1;
    }
  }
  return 0;
}

/* ************************************************************ */

static void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 struct ndpi_flow_struct *flow,
					 u_int app_proto) {
  ndpi_confidence_t confidence = NDPI_CONFIDENCE_DPI;

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

  if(app_proto == NDPI_PROTOCOL_UNKNOWN) {
    app_proto = search_into_cache(ndpi_struct, flow);
    if(app_proto != NDPI_PROTOCOL_UNKNOWN)
      confidence = NDPI_CONFIDENCE_DPI_CACHE;
  }
  if(app_proto != NDPI_PROTOCOL_UNKNOWN)
    add_to_caches(ndpi_struct, flow, app_proto);

  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN ||
     app_proto != NDPI_PROTOCOL_UNKNOWN) {
    NDPI_LOG_DBG(ndpi_struct, "Setting %d\n", app_proto);
    ndpi_set_detected_protocol(ndpi_struct, flow, app_proto, __get_master(flow), confidence);

    /* In "normal" data-path the generic code in `ndpi_internal_detection_process_packet()`
       takes care of setting the category */
    if(flow->extra_packets_func) {
      ndpi_protocol ret = { __get_master(flow), app_proto, NDPI_PROTOCOL_UNKNOWN /* unused */, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED, NULL};
      flow->category = ndpi_get_proto_category(ndpi_struct, ret);
    }
  }

  /* We want extra dissection for:
     * sub-classification
     * metadata extraction or looking for RTP
     The latter is enabled only without sub-classification or for Telegram
     (to find all XOR-PEER-ADDRESS attributes)
  */
  if(!flow->extra_packets_func) {
    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN /* No-subclassification */ ||
       flow->detected_protocol_stack[0] == NDPI_PROTOCOL_TELEGRAM_VOIP /* Metadata. TODO: other protocols? */) {
      NDPI_LOG_DBG(ndpi_struct, "Enabling extra dissection\n");
      flow->max_extra_packets_to_check = ndpi_struct->cfg.stun_max_packets_extra_dissection;
      flow->extra_packets_func = stun_search_again;
    }
  }
}

/* ************************************************************ */


static void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t app_proto;

  NDPI_LOG_DBG(ndpi_struct, "search stun\n");

  app_proto = NDPI_PROTOCOL_UNKNOWN;

  if(packet->iph &&
     ((packet->iph->daddr == 0xFFFFFFFF /* 255.255.255.255 */) ||
      ((ntohl(packet->iph->daddr) & 0xF0000000) == 0xE0000000 /* A multicast address */))) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(is_stun(ndpi_struct, flow, &app_proto)) {
    ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto);
    return;
  }

  /* TODO: can we stop earlier? */
  if(flow->packet_counter > 10)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  if(flow->packet_counter > 0) {
    /* This might be a RTP stream: let's make sure we check it */
    /* At this point the flow has not been fully classified as STUN yet */
    NDPI_LOG_DBG(ndpi_struct, "re-enable RTP\n");
    NDPI_CLR(&flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTP);
  }
}

void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id) {
  ndpi_set_bitmask_protocol_detection("STUN", ndpi_struct, *id,
				      NDPI_PROTOCOL_STUN,
				      ndpi_search_stun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
