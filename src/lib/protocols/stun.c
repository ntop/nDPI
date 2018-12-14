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

#define MAX_NUM_STUN_PKTS     10

struct stun_packet_header {
  u_int16_t msg_type, msg_len;
  u_int32_t cookie;
  u_int8_t  transaction_id[8];
};

static void ndpi_int_stun_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
					 u_int proto, struct ndpi_flow_struct *flow) {
  ndpi_set_detected_protocol(ndpi_struct, flow, proto, NDPI_PROTOCOL_UNKNOWN);
}

typedef enum {
  NDPI_IS_STUN,
  NDPI_IS_NOT_STUN
} ndpi_int_stun_t;

static ndpi_int_stun_t ndpi_int_check_stun(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   const u_int8_t * payload,
					   const u_int16_t payload_length,
					   u_int8_t *is_whatsapp) {
  u_int16_t msg_type, msg_len;
  struct stun_packet_header *h = (struct stun_packet_header*)payload;
  u_int8_t can_this_be_whatsapp_voice = 1;

  flow->protos.stun_ssl.stun.num_processed_pkts++;
  
  if(payload_length < sizeof(struct stun_packet_header)) {
    if(flow->protos.stun_ssl.stun.num_udp_pkts > 0) {
      *is_whatsapp = 1;
      return NDPI_IS_STUN; /* This is WhatsApp Voice */
    } else
      return(NDPI_IS_NOT_STUN);
  }

  if((strncmp((const char*)payload, (const char*)"RSP/", 4) == 0)
     && (strncmp((const char*)&payload[7], (const char*)" STUN_", 6) == 0)) {
    NDPI_LOG_INFO(ndpi_struct, "found stun\n");
    goto udp_stun_found;
  }

  msg_type = ntohs(h->msg_type) & 0x3EEF, msg_len = ntohs(h->msg_len);

  if(ntohs(h->msg_type) == 0x01 /* Binding Request */)
    flow->protos.stun_ssl.stun.num_binding_requests++;
  
  if((payload[0] != 0x80) && ((msg_len+20) > payload_length))
    return(NDPI_IS_NOT_STUN);

  if((payload_length == (msg_len+20))
     && ((msg_type <= 0x000b) /* http://www.3cx.com/blog/voip-howto/stun-details/ */)) {
    u_int offset = 20;

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
      
      switch(attribute) {
      case 0x0008: /* Message Integrity */
      case 0x0020: /* XOR-MAPPED-ADDRESSES */
      case 0x4002:
	/* These are the only messages apparently whatsapp voice can use */
	break;
	
      case 0x8054: /* Candidate Identifier */
	if((len == 4)
	   && ((offset+7) < payload_length)
	   && (payload[offset+5] == 0x00)
	   && (payload[offset+6] == 0x00)
	   && (payload[offset+7] == 0x00)) {
	  /* Either skype for business or "normal" skype with multiparty call */
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
	/* printf("====>>>> %04X\n", attribute); */
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
	  flow->protos.stun_ssl.stun.is_skype = 1;
	  return(NDPI_IS_STUN);
	}
	break;

      default:
	/* This means this STUN packet cannot be confused with whatsapp voice */
	can_this_be_whatsapp_voice = 0;
	break;
      }
     
      offset += len + 4;
    }
    goto udp_stun_found;
  }

  if((flow->protos.stun_ssl.stun.num_udp_pkts > 0) && (msg_type <= 0x00FF)) {
    *is_whatsapp = 1;
    return NDPI_IS_STUN; /* This is WhatsApp Voice */
  } else
    return NDPI_IS_NOT_STUN;

 udp_stun_found:      
  if(can_this_be_whatsapp_voice) {
    flow->protos.stun_ssl.stun.num_udp_pkts++;

    return((flow->protos.stun_ssl.stun.num_udp_pkts < MAX_NUM_STUN_PKTS) ? NDPI_IS_NOT_STUN : NDPI_IS_STUN);
  } else {
    /*
      We cannot immediately say that this is STUN as there are other protocols
      like GoogleHangout that might be candidates, thus we set the
      guessed protocol to STUN      
    */
    flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
    return(NDPI_IS_NOT_STUN);
  }  
}

void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t is_whatsapp = 0;

  NDPI_LOG_DBG(ndpi_struct, "search stun\n");

  if(packet->payload == NULL) return;
    
  if(packet->tcp) {
    /* STUN may be encapsulated in TCP packets */
    if((packet->payload_packet_len >= 22)
       && ((ntohs(get_u_int16_t(packet->payload, 0)) + 2) == packet->payload_packet_len)) {      
      /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
       * improved by checking only the STUN packet of given length */

      if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload + 2,
			     packet->payload_packet_len - 2, &is_whatsapp) == NDPI_IS_STUN) {
	if(flow->guessed_protocol_id == 0) flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;

	if(flow->protos.stun_ssl.stun.is_skype) {
	  NDPI_LOG_INFO(ndpi_struct, "found Skype\n");

	  if((flow->protos.stun_ssl.stun.num_processed_pkts >= 8) || (flow->protos.stun_ssl.stun.num_binding_requests >= 4))
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
	} else {
	  NDPI_LOG_INFO(ndpi_struct, "found UDP stun\n"); /* Ummmmm we're in the TCP branch. This code looks bad */
	  ndpi_int_stun_add_connection(ndpi_struct,
				       is_whatsapp ? NDPI_PROTOCOL_WHATSAPP_VOICE : NDPI_PROTOCOL_STUN, flow);
	}
	
	return;
      }
    }
  }

  if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload,
			 packet->payload_packet_len, &is_whatsapp) == NDPI_IS_STUN) {
    if(flow->guessed_protocol_id == 0) flow->guessed_protocol_id = NDPI_PROTOCOL_STUN;
    
    if(flow->protos.stun_ssl.stun.is_skype) {
      NDPI_LOG_INFO(ndpi_struct, "Found Skype\n");

      /* flow->protos.stun_ssl.stun.num_binding_requests < 4) ? NDPI_PROTOCOL_SKYPE_CALL_IN : NDPI_PROTOCOL_SKYPE_CALL_OUT */ 
      if((flow->protos.stun_ssl.stun.num_processed_pkts >= 8) || (flow->protos.stun_ssl.stun.num_binding_requests >= 4))
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE_CALL, NDPI_PROTOCOL_SKYPE);
    } else {
      NDPI_LOG_INFO(ndpi_struct, "found UDP stun\n");
      ndpi_int_stun_add_connection(ndpi_struct,
				   is_whatsapp ? NDPI_PROTOCOL_WHATSAPP_VOICE : NDPI_PROTOCOL_STUN, flow);
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
