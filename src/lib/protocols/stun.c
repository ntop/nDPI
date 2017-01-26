/*
 * stun.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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
#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_STUN


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
					   u_int8_t *is_whatsapp,
					   u_int8_t *is_lync) {
  u_int16_t msg_type, msg_len;
  struct stun_packet_header *h = (struct stun_packet_header*)payload;
  u_int8_t can_this_be_whatsapp_voice = 1;
	  
  if(payload_length < sizeof(struct stun_packet_header)) {
    if(flow->num_stun_udp_pkts > 0) {
      *is_whatsapp = 1;
      return NDPI_IS_STUN; /* This is WhatsApp Voice */
    } else
      return(NDPI_IS_NOT_STUN);
  }

  if((strncmp((const char*)payload, (const char*)"RSP/", 4) == 0)
     && (strncmp((const char*)&payload[7], (const char*)" STUN_", 6) == 0)) {
    NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "Found stun.\n");
    goto udp_stun_found;
  }

  msg_type = ntohs(h->msg_type) & 0x3EEF, msg_len = ntohs(h->msg_len);

  if((payload[0] != 0x80) && ((msg_len+20) > payload_length))
    return(NDPI_IS_NOT_STUN);

  /* printf("msg_type=%04X, msg_len=%u\n", msg_type, msg_len); */

  if((payload_length == (msg_len+20))
     && ((msg_type <= 0x000b) /* http://www.3cx.com/blog/voip-howto/stun-details/ */)) {
    u_int offset = 20;

    /*
      This can either be the standard RTCP or Ms Lync RTCP that
      later will becomg Ms Lync RTP. In this case we need to
      be careful before deciding about the protocol before dissecting the packet
    */

    while(offset < payload_length) {

      u_int16_t attribute = ntohs(*((u_int16_t*)&payload[offset]));
      u_int16_t len = ntohs(*((u_int16_t*)&payload[offset+2]));

      switch(attribute) {
      case 0x0008: /* Message Integrity */
      case 0x0020: /* XOR-MAPPED-ADDRESSES */
      case 0x4002:
	/* These are the only messages apparently whatsapp voice can use */
	break;
	      
      case 0x8054: /* Candidate Identifier */
	if((len == 4)
	   && (payload[offset+4] == 0x31)
	   && (payload[offset+5] == 0x00)
	   && (payload[offset+6] == 0x00)
	   && (payload[offset+7] == 0x00)) {
	  *is_lync = 1;
	  return(NDPI_IS_STUN);
	}
	break;

      case 0x8070: /* Implementation Version */
	if((len == 4)
	   && (payload[offset+4] == 0x00)
	   && (payload[offset+5] == 0x00)
	   && (payload[offset+6] == 0x00)
	   && (payload[offset+7] == 0x02)) {
	  *is_lync = 1;
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

#ifdef ORIGINAL_CODE
  /*
   * token list of message types and attribute types from
   * http://wwwbs1.informatik.htw-dresden.de/svortrag/i02/Schoene/stun/stun.html
   * the same list you can find in
   * https://summersoft.fay.ar.us/repos/ethereal/branches/redhat-9/ethereal-0.10.3-1/ethereal-0.10.3/packet-stun.c
   * token further message types and attributes from
   * http://www.freeswitch.org/docs/group__stun1.html
   * added further attributes observed
   * message types: 0x0001, 0x0101, 0x0111, 0x0002, 0x0102, 0x0112, 0x0003, 0x0103, 0x0004, 0x0104, 0x0114, 0x0115
   * attribute types: 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
   * 0x000a, 0x000b, 0c000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0020,
   * 0x0022, 0x0024, 0x8001, 0x8006, 0x8008, 0x8015, 0x8020, 0x8028, 0x802a, 0x8029, 0x8050, 0x8054, 0x8055
   *
   * 0x8003, 0x8004 used by facetime
   */

  if(payload_length >= 20 && ntohs(get_u_int16_t(payload, 2)) + 20 == payload_length &&
     ((payload[0] == 0x00 && (payload[1] >= 0x01 && payload[1] <= 0x04)) ||
      (payload[0] == 0x01 &&
       ((payload[1] >= 0x01 && payload[1] <= 0x04) || (payload[1] >= 0x11 && payload[1] <= 0x15))))) {
    u_int8_t mod;
    u_int8_t old = 1;
    u_int8_t padding = 0;
    NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "len and type match.\n");

    if(payload_length == 20) {
      NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "found stun.\n");
      goto udp_stun_found;
    }

    a = 20;

    while (a < payload_length) {

      if(old && payload_length >= a + 4
	 &&
	 ((payload[a] == 0x00
	   && ((payload[a + 1] >= 0x01 && payload[a + 1] <= 0x16) || payload[a + 1] == 0x19
	       || payload[a + 1] == 0x20 || payload[a + 1] == 0x22 || payload[a + 1] == 0x24
	       || payload[a + 1] == 0x25))
	  || (payload[a] == 0x80
	      && (payload[a + 1] == 0x01 || payload[a + 1] == 0x03 || payload[a + 1] == 0x04
		  || payload[a + 1] == 0x06 || payload[a + 1] == 0x08 || payload[a + 1] == 0x15
		  || payload[a + 1] == 0x20 || payload[a + 1] == 0x22 || payload[a + 1] == 0x28
		  || payload[a + 1] == 0x2a || payload[a + 1] == 0x29 || payload[a + 1] == 0x50
		  || payload[a + 1] == 0x54 || payload[a + 1] == 0x55)))) {

	NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "attribute match.\n");

	a += ((payload[a + 2] << 8) + payload[a + 3] + 4);
	mod = a % 4;
	if(mod) {
	  padding = 4 - mod;
	}
	if(a == payload_length || (padding && (a + padding) == payload_length)) {
	  NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "found stun.\n");
	  goto udp_stun_found;
	}

      } else if(payload_length >= a + padding + 4
		&&
		((payload[a + padding] == 0x00
		  && ((payload[a + 1 + padding] >= 0x01 && payload[a + 1 + padding] <= 0x16)
		      || payload[a + 1 + padding] == 0x19 || payload[a + 1 + padding] == 0x20
		      || payload[a + 1 + padding] == 0x22 || payload[a + 1 + padding] == 0x24
		      || payload[a + 1 + padding] == 0x25))
		 || (payload[a + padding] == 0x80
		     && (payload[a + 1 + padding] == 0x01 || payload[a + 1 + padding] == 0x03
			 || payload[a + 1 + padding] == 0x04 || payload[a + 1 + padding] == 0x06
			 || payload[a + 1 + padding] == 0x08 || payload[a + 1 + padding] == 0x15
			 || payload[a + 1 + padding] == 0x20 || payload[a + 1 + padding] == 0x22
			 || payload[a + 1 + padding] == 0x28 || payload[a + 1 + padding] == 0x2a
			 || payload[a + 1 + padding] == 0x29 || payload[a + 1 + padding] == 0x50
			 || payload[a + 1 + padding] == 0x54 || payload[a + 1 + padding] == 0x55))
		 || ((payload[a + padding] == 0x40) && (payload[a + padding + 1] == 0x00))
		 )) {
	if((payload[a + padding] == 0x40) && (payload[a + padding + 1] == 0x00))
	  goto udp_stun_found;

	NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "New STUN - attribute match.\n");

	old = 0;
	a += ((payload[a + 2 + padding] << 8) + payload[a + 3 + padding] + 4);
	padding = 0;
	mod = a % 4;
	if(mod) {
	  a += 4 - mod;
	}
	if(a == payload_length) {
	  NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "found stun.\n");
	  goto udp_stun_found;
	}
      } else {
	break;
      }
    }
  }
#endif


  if((flow->num_stun_udp_pkts > 0) && (msg_type <= 0x00FF)) {
    *is_whatsapp = 1;
    return NDPI_IS_STUN; /* This is WhatsApp Voice */
  } else
    return NDPI_IS_NOT_STUN;

 udp_stun_found:
  if(can_this_be_whatsapp_voice)
    flow->num_stun_udp_pkts++;

  return((flow->num_stun_udp_pkts < MAX_NUM_STUN_PKTS) ? NDPI_IS_NOT_STUN : NDPI_IS_STUN);
}

void ndpi_search_stun(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t is_whatsapp = 0, is_lync = 0;

  NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "search stun.\n");

  if(packet->tcp) {
    /* STUN may be encapsulated in TCP packets */

    if(packet->payload_packet_len >= 2 + 20 &&
       ntohs(get_u_int16_t(packet->payload, 0)) + 2 == packet->payload_packet_len) {

      /* TODO there could be several STUN packets in a single TCP packet so maybe the detection could be
       * improved by checking only the STUN packet of given length */

      if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload + 2,
			     packet->payload_packet_len - 2, &is_whatsapp, &is_lync) == NDPI_IS_STUN) {
	NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "found TCP stun.\n");
	ndpi_int_stun_add_connection(ndpi_struct, NDPI_PROTOCOL_STUN, flow);
	return;
      }
    }
  }

  if(ndpi_int_check_stun(ndpi_struct, flow, packet->payload,
			 packet->payload_packet_len, &is_whatsapp, &is_lync) == NDPI_IS_STUN) {
    if(is_lync) {
      NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "Found MS Lync\n");
      ndpi_int_stun_add_connection(ndpi_struct, NDPI_PROTOCOL_MS_LYNC, flow);
    } else {
      NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "found UDP stun.\n");
      ndpi_int_stun_add_connection(ndpi_struct,
				   is_whatsapp ? NDPI_PROTOCOL_WHATSAPP_VOICE : NDPI_PROTOCOL_STUN, flow);
    }
    return;
  }

  if(flow->num_stun_udp_pkts >= MAX_NUM_STUN_PKTS) {
    NDPI_LOG(NDPI_PROTOCOL_STUN, ndpi_struct, NDPI_LOG_DEBUG, "exclude stun.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_STUN);
  }
}


void init_stun_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("STUN", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_STUN,
				      ndpi_search_stun,
				      NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

#endif
