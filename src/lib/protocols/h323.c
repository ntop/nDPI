/*
 * h323.c
 *
 * Copyright (C) 2015-18 ntop.org
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_H323

#include "ndpi_api.h"


struct tpkt {
  u_int8_t version, reserved;
  u_int16_t len;
};

void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search H323\n");

  if(packet->tcp != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "calculated dport over tcp\n");

    /* H323  */
    if(packet->payload_packet_len >= 3
       && (packet->payload[0] == 0x03)
       && (packet->payload[1] == 0x00)) {
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
	      NDPI_LOG_INFO(ndpi_struct, "found RDP\n");
	      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RDP, NDPI_PROTOCOL_UNKNOWN);
	      return;
	    }
	  }

	  flow->l4.tcp.h323_valid_packets++;

	  if(flow->l4.tcp.h323_valid_packets >= 2) {
	    NDPI_LOG_INFO(ndpi_struct, "found H323 broadcast\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_PROTOCOL_UNKNOWN);
	  }
	} else {
	  /* This is not H.323 */
	  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	  return;
	}
      }    
  } else if(packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculated dport over udp\n");

    if(packet->payload_packet_len >= 6 && packet->payload[0] == 0x80 && packet->payload[1] == 0x08 &&
       (packet->payload[2] == 0xe7 || packet->payload[2] == 0x26) &&
       packet->payload[4] == 0x00 && packet->payload[5] == 0x00)
      {
	NDPI_LOG_INFO(ndpi_struct, "found H323 broadcast\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    /* H323  */
    if(sport == 1719 || dport == 1719)
      {
        if(packet->payload[0] == 0x16 && packet->payload[1] == 0x80 && packet->payload[4] == 0x06 && packet->payload[5] == 0x00)
	  {
	    NDPI_LOG_INFO(ndpi_struct, "found H323 broadcast\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
        else if(packet->payload_packet_len >= 20 && packet->payload_packet_len <= 117)
	  {
	    NDPI_LOG_INFO(ndpi_struct, "found H323 broadcast\n");
	    ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_H323, NDPI_PROTOCOL_UNKNOWN);
	    return;
	  }
        else
	  {
	    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	    return;
	  }
      }
  }

}

void init_h323_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("H323", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_H323,
				      ndpi_search_h323,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
