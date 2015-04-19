/*
 * h323.c
 *
 * Copyright (C) 2015 ntop.org
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_H323

struct tpkt {
  u_int8_t version, reserved;
  u_int16_t len;
};

void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "search H323.\n");

  if(packet->tcp != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over tcp.\n");

    /* H323  */
    if((packet->payload[0] == 0x03)
       && (packet->payload[1] == 0x00)
       && (packet->payload[2] == 0x00)) {
	struct tpkt *t = (struct tpkt*)packet->payload;
	u_int16_t len = ntohs(t->len);

	if(packet->payload_packet_len == len) {
	  /*
	    We need to check if this packet is in reality
	    a RDP (Remote Desktop) packet encapsulated on TPTK
	   */

	  if(packet->payload[4] == (packet->payload_packet_len - sizeof(struct tpkt) - 1)) {
	    /* ISO 8073/X.224 */
	    if((packet->payload[5] == 0xE0 /* CC Connect Request */)
	       || (packet->payload[5] == 0xD0 /* CC Connect Confirm */)) {
	      ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RDP, NDPI_REAL_PROTOCOL);
	      return;
	    }
	  }

	  flow->l4.tcp.h323_valid_packets++;

	  if(flow->l4.tcp.h323_valid_packets >= 2) {
	    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	  }
	} else {
	  /* This is not H.323 */
	  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_H323);
	}
      }    
  } else if(packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over udp.\n");

    if(packet->payload[0] == 0x80 && packet->payload[1] == 0x08 && (packet->payload[2] == 0xe7 || packet->payload[2] == 0x26) &&
       packet->payload[4] == 0x00 && packet->payload[5] == 0x00)
      {
	NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	return;
      }
    /* H323  */
    if(sport == 1719 || dport == 1719)
      {
        if(packet->payload[0] == 0x16 && packet->payload[1] == 0x80 && packet->payload[4] == 0x06 && packet->payload[5] == 0x00)
	  {
	    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	    return;
	  }
        else if(packet->payload_packet_len >= 20 || packet->payload_packet_len <= 117)
	  {
	    NDPI_LOG(NDPI_PROTOCOL_H323, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_REAL_PROTOCOL);
	    return;
	  }
        else
	  {
	    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_H323);
	    return;
	  }
      }
  }

}
#endif
