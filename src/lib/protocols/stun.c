/*
 * stun.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-18 - ntop.org
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

#define MAX_NUM_STUN_PKTS     8

// #define DEBUG_STUN 1
// #define DEBUG_LRU  1

struct stun_packet_header {
  u_int16_t msg_type, msg_len;
  u_int32_t cookie;
  u_int8_t  transaction_id[8];
};

/* ************************************************************ */

static u_int8_t is_stun_based_proto(u_int16_t proto) {

  switch(proto) {
  case NDPI_PROTOCOL_WHATSAPP:
  case NDPI_PROTOCOL_WHATSAPP_CALL:
  case NDPI_PROTOCOL_MESSENGER:
  case NDPI_PROTOCOL_HANGOUT_DUO:
  case NDPI_PROTOCOL_SKYPE_CALL:
  case NDPI_PROTOCOL_SIGNAL:
  case NDPI_PROTOCOL_STUN:
    return(1);
  }
 
  return(0);
}

/* ************************************************************ */

u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev) {
  if(rev)
    return(flow->packet.iph->daddr + flow->packet.udp->dest);
  else
    return(flow->packet.iph->saddr + flow->packet.udp->source);
}

/* ************************************************************ */

void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
				  struct ndpi_flow_struct *flow,
				  u_int app_proto, u_int proto) {
  if(ndpi_struct->stun_cache == NULL)
    ndpi_struct->stun_cache = ndpi_lru_cache_init(1024);

  if(ndpi_struct->stun_cache
     && flow->packet.iph
     && flow->packet.udp
     && (app_proto != NDPI_PROTOCOL_UNKNOWN)
     ) /* Cache flow sender info */ {
    u_int32_t key = get_stun_lru_key(flow, 0);
    u_int16_t cached_proto;

    if(ndpi_lru_find_cache(ndpi_struct->stun_cache, key,
			   &cached_proto, 0 /* Don't remove it as it can be used for other connections */)) {
#ifdef DEBUG_LRU
      printf("[LRU] FOUND %u / %u: no need to cache %u.%u\n", key, cached_proto, proto, app_proto);
#endif
      app_proto = cached_proto, proto = NDPI_PROTOCOL_STUN;
    } else {
      u_int32_t key_rev = get_stun_lru_key(flow, 1);

      if(ndpi_lru_find_cache(ndpi_struct->stun_cache, key_rev,
			     &cached_proto, 0 /* Don't remove it as it can be used for other connections */)) {
#ifdef DEBUG_LRU
	printf("[LRU] FOUND %u / %u: no need to cache %u.%u\n", key_rev, cached_proto, proto, app_proto);
#endif
	app_proto = cached_proto, proto = NDPI_PROTOCOL_STUN;
      } else {
	if(app_proto != NDPI_PROTOCOL_STUN) {
	  /* No sense to ass STUN, but only subprotocols */
	  
#ifdef DEBUG_LRU
	  printf("[LRU] ADDING %u / %u.%u [%u -> %u]\n", key, proto, app_proto,
		 ntohs(flow->packet.udp->source), ntohs(flow->packet.udp->dest));
#endif
	  
	  ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key, app_proto);
	  ndpi_lru_add_to_cache(ndpi_struct->stun_cache, key_rev, app_proto);
	}
      }
    }
  }

  ndpi_set_detected_protocol(ndpi_struct, flow, app_proto, proto);
}

typedef enum {
  NDPI_IS_STUN,
  NDPI_IS_NOT_STUN
} ndpi_int_stun_t;

/* ************************************************************ */

static int is_google_ip_address(u_int32_t host) {
  if(
     ((host & 0xFFFF0000 /* 255.255.0.0 */) == 0x4A7D0000 /* 74.125.0.0/16 */)
     || ((host & 0xFFFF0000 /* 255.255.0.0 */) == 0x42660000 /* 66.102.0.0/16 */)
     )
    return(1);
  else
    return(0);
}

/* ************************************************************ */

/*
 WhatsApp
 31.13.86.48
 31.13.92.50
 157.240.20.51
 157.240.21.51
 185.60.216.51

 Messenger
 31.13.86.5
*/

static int is_messenger_ip_address(u_int32_t host) {
  if(host == 0x1F0D5605 /* 31.13.86.5 */)
    return(1);
  else
    return(0);
}

/* ************************************************************ */

static ndpi_int_stun_t ndpi_int_check_stun(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   const u_int8_t * payload,
					   const u_int16_t payload_length,
					   u_int8_t *is_whatsapp,
					   u_int8_t *is_messenger,
					   u_int8_t *is_duo
					   ) {
  u_int16_t msg_type, msg_len;
  struct stun_packet_header *h = (struct stun_packet_header*)payload;
  u_int8_t can_this_be_whatsapp_voice = 1;

  /* STUN over TCP does not look good */
  if(flow->packet.tcp) return(NDPI_IS_NOT_STUN);

  *is_whatsapp = 0, *is_messenger = 0, *is_duo = 0;

  if(payload_length >= 512) {
    return(NDPI_IS_NOT_STUN);
  } else if(payload_length < sizeof(struct stun_packet_header)) {
    /* This looks like an invalid packet */

    if(flow->protos.stun_ssl.stun.num_udp_pkts > 0) {
      *is_whatsapp = 1;
      return(NDPI_IS_STUN); /* This is WhatsApp Voice */
    } else
      return(NDPI_IS_NOT_STUN);
  }

  if((strncmp((const char*)payload, (const char*)"RSP/", 4) == 0)
     && (strncmp((const char*)&payload[7], (const char*)" STUN_", 6) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "found stun\n");
    goto udp_stun_found;
  }

  msg_type = ntohs(h->msg_type) /* & 0x3EEF */, msg_len = ntohs(h->msg_len);

  /* https://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml */
  if(msg_type > 0x000C) {
#ifdef DEBUG_STUN
    printf("[STUN] msg_type = %04X\n", msg_type);
#endif
    
    if(is_stun_based_proto(flow->guessed_host_protocol_id)) {
      /*
	In this case we have the detected the typical STUN pattern
	of modern protocols where the flow starts as STUN and becomes
	something else that has nothing to do with STUN anymore
      */
      ndpi_int_stun_add_connection(ndpi_struct, flow,
				   flow->guessed_host_protocol_id,
				   NDPI_PROTOCOL_STUN);
      return(NDPI_IS_STUN);
    }
    
    return(NDPI_IS_NOT_STUN);
  }

#if 0
  if((flow->packet.udp->dest == htons(3480)) ||
     (flow->packet.udp->source == htons(3480))
    )
    printf("[STUN] Here we go\n");;
#endif

  if(ndpi_struct->stun_cache) {
    u_int16_t proto;
    u_int32_t key = get_stun_lru_key(flow, 0);
    int rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto, 0 /* Don't remove it as it can be used for other connections */);

#ifdef DEBUG_LRU
    printf("[LRU] Searching %u\n", key);
#endif

    if(!rc) {
      key = get_stun_lru_key(flow, 1);
      rc = ndpi_lru_find_cache(ndpi_struct->stun_cache, key, &proto, 0 /* Don't remove it as it can be used for other connections */);

#ifdef DEBUG_LRU
    printf("[LRU] Searching %u\n", key);
#endif
    }

    if(rc) {
#ifdef DEBUG_LRU
      printf("[LRU] Cache FOUND %u / %u\n", key, proto);
#endif

      flow->guessed_host_protocol_id = proto, flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

      switch(proto) {
      case NDPI_PROTOCOL_WHATSAPP:
	*is_whatsapp = 1;
	break;
      case NDPI_PROTOCOL_MESSENGER:
	*is_messenger = 1;
	break;
      case NDPI_PROTOCOL_HANGOUT_DUO:
	*is_duo = 1;
	break;
      case NDPI_PROTOCOL_SKYPE_CALL:
	flow->protos.stun_ssl.stun.is_skype = 1;
	break;
      }

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
    flow->protos.stun_ssl.stun.num_binding_requests++;

    if((msg_len == 0) && (flow->guessed_host_protocol_id == NDPI_PROTOCOL_GOOGLE))
      flow->guessed_host_protocol_id = NDPI_PROTOCOL_HANGOUT_DUO;
    else
      flow->guessed_host_protocol_id = NDPI_PROTOCOL_STUN;

    if(msg_len == 0) {
      /* flow->protos.stun_ssl.stun.num_udp_pkts++; */
      return(NDPI_IS_NOT_STUN); /* This to keep analyzing STUN instead of giving up */
    }
  }

  if((msg_len == 0) && (flow->guessed_host_protocol_id == NDPI_PROTOCOL_UNKNOWN)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return(NDPI_IS_NOT_STUN);
  }

  flow->protos.stun_ssl.stun.num_udp_pkts++;

  /*
    printf("[msg_type: %04X][payload_length: %u][num_binding_request: %u]\n",
           msg_type, payload_length, flow->protos.stun_ssl.stun.num_binding_requests);
  */

  if(((payload[0] == 0x80)
      && (payload_length < 512)
      && ((msg_len+20) <= payload_length)) /* WhatsApp Voice */) {
    *is_whatsapp = 1;
    return(NDPI_IS_STUN); /* This is WhatsApp Voice */
  } else if((payload[0] == 0x90)
	    && (((msg_len+11) == payload_length) /* WhatsApp Video */
		|| (flow->protos.stun_ssl.stun.num_binding_requests >= 4))) {
    *is_whatsapp = 2;
    return(NDPI_IS_STUN); /* This is WhatsApp Video */
  }

  if((payload[0] != 0x80) && ((msg_len+20) > payload_length))
    return(NDPI_IS_NOT_STUN);
  else {
    switch(flow->guessed_protocol_id) {
    case NDPI_PROTOCOL_HANGOUT_DUO:
    case NDPI_PROTOCOL_MESSENGER:
    case NDPI_PROTOCOL_WHATSAPP_CALL:
      /* Don't overwrite the protocol with sub-STUN protocols */
      break;

    default:
      flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
      break;
    }
  }

  if(payload_length == (msg_len+20)) {
    if(msg_type <= 0x000b) /* http://www.3cx.com/blog/voip-howto/stun-details/ */ {
      u_int offset = 20;

      // printf("[%02X][%02X][%02X][%02X][payload_length: %u]\n", payload[offset], payload[offset+1], payload[offset+2], payload[offset+3],payload_length);

      /*
	This can either be the standard RTCP or Ms Lync RTCP that
	later will become Ms Lync RTP. In this case we need to
	be careful before deciding about the protocol before dissecting the packet

	MS Lync = Skype
	https://en.wikipedia.org/wiki/Skype_for_Business
      */

      while((offset+2) < payload_length) {
	u_int16_t attribute = ntohs(*((u_int16_t*)&payload[offset]));
	u_int16_t len = ntohs(*((u_int16_t*)&payload[offset+2]));
	u_int16_t x = (len + 4) % 4;

	if(x != 0)
	  len += 4-x;

#ifdef DEBUG_STUN
	printf("==> Attribute: %04X\n", attribute);
#endif

	switch(attribute) {
	case 0x0008: /* Message Integrity */
	case 0x0020: /* XOR-MAPPED-ADDRESSES */
	case 0x4000:
	case 0x4001:
	case 0x4002:
	  /* These are the only messages apparently whatsapp voice can use */
	  break;

	case 0x0014: /* Realm */
	{
	  u_int16_t realm_len = ntohs(*((u_int16_t*)&payload[offset+2]));

	  if(flow->host_server_name[0] == '\0') {
	    u_int j, i = (realm_len > sizeof(flow->host_server_name)) ? sizeof(flow->host_server_name) : realm_len;
	    u_int k = offset+4;

	    memset(flow->host_server_name, 0, sizeof(flow->host_server_name));

	    for(j=0; j<i; j++)
	      flow->host_server_name[j] = payload[k++];

#ifdef DEBUG_STUN
	    printf("==> [%s]\n", flow->host_server_name);
#endif

	    if(strstr((char*)flow->host_server_name, "google.com") != NULL) {
	      *is_duo = 1;
	      flow->guessed_host_protocol_id = NDPI_PROTOCOL_HANGOUT_DUO, flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
	      return(NDPI_IS_STUN);
	    } else if(strstr((char*)flow->host_server_name, "whispersystems.org") != NULL) {
	      flow->guessed_host_protocol_id = NDPI_PROTOCOL_SIGNAL, flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
	      return(NDPI_IS_STUN);
	    }
	  }
	}
	break;

	case 0xC057: /* Messeger */
	  if(msg_type == 0x0001) {
	    if((msg_len == 100) || (msg_len == 104)) {
	      *is_messenger = 1;
	      return(NDPI_IS_STUN);
	    } else if(msg_len == 76) {
#if 0
	      *is_duo = 1;

	      if(1) {
		flow->guessed_host_protocol_id = NDPI_PROTOCOL_HANGOUT_DUO, flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
		return(NDPI_IS_NOT_STUN); /* This case is found also with signal traffic */
	      } else
		return(NDPI_IS_STUN);
#endif
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
	    flow->guessed_protocol_id = NDPI_PROTOCOL_SKYPE_CALL;
	    flow->protos.stun_ssl.stun.is_skype = 1;
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

	  flow->guessed_protocol_id = NDPI_PROTOCOL_SKYPE_CALL;
	  flow->protos.stun_ssl.stun.is_skype = 1;
	  return(NDPI_IS_STUN);
	  break;

	case 0x8070: /* Implementation Version */
	  if((len == 4)
	     && ((offset+7) < payload_length)
	     && (payload[offset+4] == 0x00)
	     && (payload[offset+5] == 0x00)
	     && (payload[offset+6] == 0x00)
	     && ((payload[offset+7] == 0x02) || (payload[offset+7] == 0x03))
	     ) {
	    flow->guessed_protocol_id = NDPI_PROTOCOL_SKYPE_CALL;
	    flow->protos.stun_ssl.stun.is_skype = 1;
#ifdef DEBUG_STUN
	    printf("==> Skype (3) found\n");
#endif

	    return(NDPI_IS_STUN);
	  }
	  break;

	case 0xFF03:
	  can_this_be_whatsapp_voice = 0;
	  flow->guessed_host_protocol_id = NDPI_PROTOCOL_HANGOUT_DUO;
	  break;

	default:
	  /* This means this STUN packet cannot be confused with whatsapp voice */
#ifdef DEBUG_STUN
	  printf("==> %04X\n", attribute);
#endif
	  can_this_be_whatsapp_voice = 0;
	  break;
	}

	offset += len + 4;
      }
      goto udp_stun_found;
    } else if(msg_type == 0x0800) {
      *is_whatsapp = 1;
      return(NDPI_IS_STUN); /* This is WhatsApp */
    }
  }

  if((flow->protos.stun_ssl.stun.num_udp_pkts > 0) && (msg_type <= 0x00FF)) {
    *is_whatsapp = 1;
    return(NDPI_IS_STUN); /* This is WhatsApp Voice */
  } else
    return(NDPI_IS_NOT_STUN);

 udp_stun_found:
  if(can_this_be_whatsapp_voice) {
    struct ndpi_packet_struct *packet = &flow->packet;
    int rc;
    
    flow->protos.stun_ssl.stun.num_processed_pkts++;
#ifdef DEBUG_STUN
    printf("==>> NDPI_PROTOCOL_WHATSAPP_CALL\n");
#endif

    if((ntohs(packet->udp->source) == 3478) || (ntohs(packet->udp->dest) == 3478)) {
      flow->guessed_host_protocol_id = (is_messenger_ip_address(ntohl(packet->iph->saddr)) || is_messenger_ip_address(ntohl(packet->iph->daddr))) ?
	NDPI_PROTOCOL_MESSENGER : NDPI_PROTOCOL_WHATSAPP_CALL;
    } else
      flow->guessed_host_protocol_id = (is_google_ip_address(ntohl(packet->iph->saddr)) || is_google_ip_address(ntohl(packet->iph->daddr)))
					? NDPI_PROTOCOL_HANGOUT_DUO : NDPI_PROTOCOL_WHATSAPP_CALL;

    rc = (flow->protos.stun_ssl.stun.num_udp_pkts < MAX_NUM_STUN_PKTS) ? NDPI_IS_NOT_STUN : NDPI_IS_STUN;

    if(rc == NDPI_IS_STUN)
      ndpi_int_stun_add_connection(ndpi_struct, flow, flow->guessed_host_protocol_id, NDPI_IS_STUN);

    return(rc);
  } else {
    /*
      We cannot immediately say that this is STUN as there are other protocols
      like GoogleHangout that might be candidates, thus we set the
      guessed protocol to STUN
    */
    return(NDPI_IS_NOT_STUN);
  }
}

void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t is_whatsapp = 0, is_messenger = 0, is_duo = 0;

  NDPI_LOG_DBG(ndpi_struct, "search stun\n");

  if(packet->payload == NULL)
    return;
  else if(packet->iphv6 != NULL) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  if(packet->tcp) {
    /* STUN may be encapsulated in TCP packets */
    if((packet->payload_packet_len >= 22)
       && ((ntohs(get_u_int16_t(packet->payload, 0)) + 2) == packet->payload_packet_len)) {
      /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
       * improved by checking only the STUN packet of given length */

      if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload + 2,
			     packet->payload_packet_len - 2,
			     &is_whatsapp, &is_messenger, &is_duo) == NDPI_IS_STUN) {
	if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN) flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

	if(is_messenger) {
	  ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MESSENGER, NDPI_PROTOCOL_STUN);
	  return;
	} else if(is_duo) {
	  ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HANGOUT_DUO, NDPI_PROTOCOL_STUN);
	  return;
	} else if(flow->guessed_host_protocol_id == NDPI_PROTOCOL_SIGNAL) {
	  ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SIGNAL, NDPI_PROTOCOL_STUN);
	  return;
	} else if(flow->protos.stun_ssl.stun.is_skype || (flow->guessed_host_protocol_id = NDPI_PROTOCOL_SKYPE_CALL)) {
	  NDPI_LOG_INFO(ndpi_struct, "found Skype\n");

	  // if((flow->protos.stun_ssl.stun.num_processed_pkts >= 8) || (flow->protos.stun_ssl.stun.num_binding_requests >= 4))
	  ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
	} else {
	  NDPI_LOG_INFO(ndpi_struct, "found UDP stun\n"); /* Ummmmm we're in the TCP branch. This code looks bad */
	  ndpi_int_stun_add_connection(ndpi_struct, flow,
				       is_whatsapp ? NDPI_PROTOCOL_WHATSAPP_CALL : NDPI_PROTOCOL_STUN,
				       NDPI_PROTOCOL_UNKNOWN);
	}

	return;
      }
    }
  }

  /* UDP */
  if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload,
			 packet->payload_packet_len,
			 &is_whatsapp, &is_messenger, &is_duo) == NDPI_IS_STUN) {
    if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN) flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

    if(is_messenger) {
      ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_MESSENGER, NDPI_PROTOCOL_STUN);
      return;
    } else if(is_duo) {
      ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_HANGOUT_DUO, NDPI_PROTOCOL_STUN);
      return;
    } else if(flow->guessed_host_protocol_id == NDPI_PROTOCOL_SIGNAL) {
      ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SIGNAL, NDPI_PROTOCOL_STUN);
      return;
    } else if(flow->protos.stun_ssl.stun.is_skype) {
      NDPI_LOG_INFO(ndpi_struct, "Found Skype\n");

      /* flow->protos.stun_ssl.stun.num_binding_requests < 4) ? NDPI_PROTOCOL_SKYPE_CALL_IN : NDPI_PROTOCOL_SKYPE_CALL_OUT */
      // if((flow->protos.stun_ssl.stun.num_udp_pkts >= 6) || (flow->protos.stun_ssl.stun.num_binding_requests >= 3))
	ndpi_int_stun_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
    } else {
      NDPI_LOG_INFO(ndpi_struct, "found UDP stun\n");
      ndpi_int_stun_add_connection(ndpi_struct, flow,
				   is_whatsapp ? NDPI_PROTOCOL_WHATSAPP_CALL : NDPI_PROTOCOL_STUN,
				   NDPI_PROTOCOL_UNKNOWN);
    }

    return;
  }

  if(flow->protos.stun_ssl.stun.num_udp_pkts >= MAX_NUM_STUN_PKTS)
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);

  if(flow->packet_counter > 0) {
    /* This might be a RTP stream: let's make sure we check it */
    NDPI_CLR(&flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTP);
  }
}


void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id,
			 NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("STUN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_STUN,
				      ndpi_search_stun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
