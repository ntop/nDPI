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

#define MAX_NUM_STUN_PKTS     3

// #define DEBUG_STUN 1
// #define DEBUG_LRU  1
// #define DEBUG_ZOOM_LRU  1

#define STUN_HDR_LEN   20 /* STUN message header length, Classic-STUN (RFC 3489) and STUN (RFC 8489) both */

/* ************************************************************ */

u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev) {
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
    if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_GOOGLE)
      app_proto = NDPI_PROTOCOL_HANGOUT_DUO;
    else if(flow->guessed_protocol_id_by_ip == NDPI_PROTOCOL_FACEBOOK)
      app_proto = NDPI_PROTOCOL_FACEBOOK_VOIP;
  }

  if(ndpi_struct->stun_cache
     && (app_proto != NDPI_PROTOCOL_UNKNOWN)
     ) /* Cache flow sender info */ {
    u_int32_t key = get_stun_lru_key(flow, 0);
    u_int16_t cached_proto;

    if(ndpi_lru_find_cache(ndpi_struct->stun_cache, key,
			   &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			   ndpi_get_current_time(flow))) {
#ifdef DEBUG_LRU
      printf("[LRU] FOUND %u / %u: no need to cache %u.%u\n", key, cached_proto, proto, app_proto);
#endif
      if(app_proto != cached_proto) {
        app_proto = cached_proto;
        confidence = NDPI_CONFIDENCE_DPI_CACHE;
      }
    } else {
      u_int32_t key_rev = get_stun_lru_key(flow, 1);

      if(ndpi_lru_find_cache(ndpi_struct->stun_cache, key_rev,
			     &cached_proto, 0 /* Don't remove it as it can be used for other connections */,
			     ndpi_get_current_time(flow))) {
#ifdef DEBUG_LRU
	printf("[LRU] FOUND %u / %u: no need to cache %u.%u\n", key_rev, cached_proto, proto, app_proto);
#endif
	if(app_proto != cached_proto) {
	  app_proto = cached_proto;
	  confidence = NDPI_CONFIDENCE_DPI_CACHE;
	}
      } else {
	if(app_proto != NDPI_PROTOCOL_STUN) {
	  /* No sense to add STUN, but only subprotocols */

#ifdef DEBUG_LRU
	  printf("[LRU] ADDING %u / %u.%u [%u -> %u]\n", key, proto, app_proto,
		 ntohs(packet->udp->source), ntohs(packet->udp->dest));
#endif

	  ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key, app_proto, ndpi_get_current_time(flow));
	  ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key_rev, app_proto, ndpi_get_current_time(flow));
	}
      }
    }
  }

  /* TODO: extend to other protocols? */
  if(ndpi_struct->stun_zoom_cache &&
     app_proto == NDPI_PROTOCOL_ZOOM &&
     flow->l4_proto == IPPROTO_UDP) {
    u_int32_t key = get_stun_lru_key(flow, 0); /* Src */
#ifdef DEBUG_ZOOM_LRU
    printf("[LRU ZOOM] ADDING %u [src_port %u]\n", key, ntohs(flow->c_port));
#endif
    ndpi_lru_add_to_cache(ndpi_struct->stun_zoom_cache, key,
                          0 /* dummy */, ndpi_get_current_time(flow));
  }

  ndpi_set_detected_protocol(ndpi_struct, flow, app_proto, NDPI_PROTOCOL_STUN, confidence);
}

typedef enum {
  NDPI_IS_STUN,
  NDPI_IS_NOT_STUN
} ndpi_int_stun_t;

/* ************************************************************ */

static ndpi_int_stun_t ndpi_int_check_stun(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   const u_int8_t * payload,
					   const u_int16_t payload_length,
					   u_int16_t *app_proto) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t msg_type, msg_len;
  int rc;
  
  if(packet->iph &&
     ((packet->iph->daddr == 0xFFFFFFFF /* 255.255.255.255 */) ||
     ((ntohl(packet->iph->daddr) & 0xF0000000) == 0xE0000000 /* A multicast address */))) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return(NDPI_IS_NOT_STUN);
  }

  if(payload_length >= 512) {
    return(NDPI_IS_NOT_STUN);
  } else if(payload_length < STUN_HDR_LEN) {
    /* This looks like an invalid packet */

    if(flow->stun.num_pkts > 0) {
      return(NDPI_IS_STUN);
    } else
      return(NDPI_IS_NOT_STUN);
  }

  if((strncmp((const char*)payload, (const char*)"RSP/", 4) == 0)
     && (strncmp((const char*)&payload[7], (const char*)" STUN_", 6) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "found stun\n");
    goto stun_found;
  }

  msg_type = ntohs(*((u_int16_t*)payload));
  msg_len  = ntohs(*((u_int16_t*)&payload[2]));

  if((msg_type == 0) || ((msg_len+20) != payload_length))
    return(NDPI_IS_NOT_STUN);  
  
  /* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml */
  if(((msg_type & 0x3EEF) > 0x000B) && (msg_type != 0x0800)) {
#ifdef DEBUG_STUN
    printf("[STUN] msg_type = %04X\n", msg_type);
#endif

    /*
      If we're here it's because this does not look like STUN anymore
      as this was a flow that started as STUN and turned into something
      else. Let's investigate what is that about
    */
    if(payload[0] == 0x16) {
      /* Let's check if this is DTLS used by some socials */
      struct ndpi_packet_struct *packet = &ndpi_struct->packet;
      u_int16_t total_len, version = htons(*((u_int16_t*) &packet->payload[1]));

      switch (version) {
      case 0xFEFF: /* DTLS 1.0 */
      case 0xFEFD: /* DTLS 1.2 */
	total_len = ntohs(*((u_int16_t*) &packet->payload[11])) + 13;

	if(payload_length == total_len) {
	  flow->guessed_protocol_id = NDPI_PROTOCOL_DTLS;
	  return(NDPI_IS_NOT_STUN);
	}
      }
    }

    return(NDPI_IS_NOT_STUN);
  }

  if(ndpi_struct->stun_cache) {
    u_int16_t proto;
    u_int32_t key = get_stun_lru_key(flow, 0);
    int rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto,
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

      *app_proto = proto;
      return(NDPI_IS_STUN);
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

  if(msg_type == 0x01 /* Binding Request */) {
    flow->stun.num_binding_requests++;

    flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

    if(!msg_len) {
      /* flow->stun.num_pkts++; */
      return(NDPI_IS_NOT_STUN); /* This to keep analyzing STUN instead of giving up */
    }
  }

  flow->stun.num_pkts++;

  if((payload[0] == 0x80 && payload_length < 512 && ((msg_len+20) <= payload_length))) {
    *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
    return(NDPI_IS_STUN); /* This is WhatsApp Call */
  } else if((payload[0] == 0x90) && (((msg_len+11) == payload_length) ||
				     (flow->stun.num_binding_requests >= 4))) {
    *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
    return(NDPI_IS_STUN); /* This is WhatsApp Call */
  }

  if(payload[0] != 0x80 && (msg_len + 20) > payload_length)
    return(NDPI_IS_NOT_STUN);

  flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

  if(payload_length == (msg_len+20)) {
    if((msg_type & 0x3EEF) <= 0x000B) /* http://www.3cx.com/blog/voip-howto/stun-details/ */ {
      u_int offset = 20;

      /*
	This can either be the standard RTCP or Ms Lync RTCP that
	later will become Ms Lync RTP. In this case we need to
	be careful before deciding about the protocol before dissecting the packet

	MS Lync = Skype
	https://en.wikipedia.org/wiki/Skype_for_Business
      */

      while((offset+4) < payload_length) {
        u_int16_t attribute = ntohs(*((u_int16_t*)&payload[offset]));
        u_int16_t len = ntohs(*((u_int16_t*)&payload[offset+2]));
        u_int16_t x = (len + 4) % 4;

        if(x)
          len += 4-x;

#ifdef DEBUG_STUN
        printf("==> Attribute: %04X\n", attribute);
#endif

        switch(attribute) {
	case 0x0101:
	case 0x0103:
          *app_proto = NDPI_PROTOCOL_ZOOM;
          return(NDPI_IS_STUN);
	  break;
	  
        case 0x4000:
        case 0x4001:
        case 0x4002:
          /* These are the only messages apparently whatsapp voice can use */
          *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
          return(NDPI_IS_STUN);
          break;

        case 0x0014: /* Realm */
	  {
	    u_int16_t realm_len = ntohs(*((u_int16_t*)&payload[offset+2]));

	    if(flow->host_server_name[0] == '\0') {
	      u_int k = offset+4;

	      ndpi_hostname_sni_set(flow, payload + k, ndpi_min(realm_len, payload_length - k));

#ifdef DEBUG_STUN
	      printf("==> [%s]\n", flow->host_server_name);
#endif

	      if(strstr(flow->host_server_name, "google.com") != NULL) {
                *app_proto = NDPI_PROTOCOL_HANGOUT_DUO;
                return(NDPI_IS_STUN);
	      } else if(strstr(flow->host_server_name, "whispersystems.org") != NULL ||
	                (strstr(flow->host_server_name, "signal.org") != NULL)) {
		*app_proto = NDPI_PROTOCOL_SIGNAL_VOIP;
		return(NDPI_IS_STUN);
	      } else if(strstr(flow->host_server_name, "facebook") != NULL) {
		*app_proto = NDPI_PROTOCOL_FACEBOOK_VOIP;
		return(NDPI_IS_STUN);
	      }
	    }
	  }
	  break;

        case 0xC057: /* Messeger */
          if(msg_type == 0x0001) {
            if((msg_len == 100) || (msg_len == 104)) {
              *app_proto = NDPI_PROTOCOL_FACEBOOK_VOIP;
              return(NDPI_IS_STUN);
            }
          }
          break;

        case 0x8054: /* Candidate Identifier */
          if((len == 4)
             && ((offset+7) < payload_length)
             && (payload[offset+5] == 0x00)
             && (payload[offset+6] == 0x00)
             && (payload[offset+7] == 0x00)) {
            /* Either skype for business or "normal" skype with multiparty call */
#ifdef DEBUG_STUN
            printf("==> Skype found\n");
#endif
            *app_proto = NDPI_PROTOCOL_SKYPE_TEAMS_CALL;
            return(NDPI_IS_STUN);
          }

          break;

        case 0x8055: /* MS Service Quality (skype?) */
          break;

          /* Proprietary fields found on skype calls */
        case 0x24DF:
        case 0x3802:
        case 0x8036:
        case 0x8095:
        case 0x0800:
        case 0x8006: /* This is found on skype calls) */
          /* printf("====>>>> %04X\n", attribute); */
#ifdef DEBUG_STUN
          printf("==> Skype (2) found\n");
#endif

          *app_proto = NDPI_PROTOCOL_SKYPE_TEAMS_CALL;
          return(NDPI_IS_STUN);
          break;

        case 0x8070: /* Implementation Version */
          if(len == 4 && ((offset+7) < payload_length)
             && (payload[offset+4] == 0x00) && (payload[offset+5] == 0x00) && (payload[offset+6] == 0x00) &&
             ((payload[offset+7] == 0x02) || (payload[offset+7] == 0x03))) {
#ifdef DEBUG_STUN
            printf("==> Skype (3) found\n");
#endif

            *app_proto = NDPI_PROTOCOL_SKYPE_TEAMS_CALL;
            return(NDPI_IS_STUN);
          }
          break;

        case 0xFF03:
          *app_proto = NDPI_PROTOCOL_HANGOUT_DUO;
          return(NDPI_IS_STUN);
          break;

        default:
#ifdef DEBUG_STUN
          printf("==> %04X\n", attribute);
#endif
          break;
        }

        offset += len + 4;
      }

      goto stun_found;
    } else if(msg_type == 0x0800) {
      *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
      return(NDPI_IS_STUN);
    }
  }

  if((flow->stun.num_pkts > 0) && (msg_type <= 0x00FF)) {
    *app_proto = NDPI_PROTOCOL_WHATSAPP_CALL;
    return(NDPI_IS_STUN);
  } else
    return(NDPI_IS_NOT_STUN);

stun_found:
  flow->stun.num_processed_pkts++;

#ifdef DEBUG_STUN
  printf("==>> NDPI_PROTOCOL_WHATSAPP_CALL\n");
#endif
  
  rc = (flow->stun.num_pkts < MAX_NUM_STUN_PKTS) ? NDPI_IS_NOT_STUN : NDPI_IS_STUN;

  return rc;
}

static void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t app_proto;

  NDPI_LOG_DBG(ndpi_struct, "search stun\n");

  app_proto = NDPI_PROTOCOL_UNKNOWN;

  if(packet->tcp) {
    /* STUN may be encapsulated in TCP packets */
    if((packet->payload_packet_len >= 22)
       && ((ntohs(get_u_int16_t(packet->payload, 0)) + 2) == packet->payload_packet_len)) {
      /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
       * improved by checking only the STUN packet of given length */

      if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload + 2,
			     packet->payload_packet_len - 2, &app_proto) == NDPI_IS_STUN) {
        ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto);
        return;
      }
    }
  }

  /* UDP */
  if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload,
			 packet->payload_packet_len, &app_proto) == NDPI_IS_STUN) {
    ndpi_int_stun_add_connection(ndpi_struct, flow, app_proto);
    return;
  }

  if(flow->stun.num_pkts >= MAX_NUM_STUN_PKTS)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  if(flow->packet_counter > 0) {
    /* This might be a RTP stream: let's make sure we check it */
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
