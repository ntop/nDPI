/*
 * rtcp.c (RTP Control Protocol)
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_RTCP

#include "ndpi_api.h"

static void ndpi_int_rtcp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_RTCP,
			     NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_rtcp(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG_DBG(ndpi_struct, "search RTCP\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG_DBG2(ndpi_struct, "calculating dport over tcp\n");

    if(packet->payload_packet_len > 13 && (sport == 554 || dport == 554) &&
       packet->payload[0] == 0x00 && packet->payload[1] == 0x00 &&
       packet->payload[2] == 0x01 && packet->payload[3] == 0x01 &&
       packet->payload[4] == 0x08 && packet->payload[5] == 0x0a &&
       packet->payload[6] == 0x00 && packet->payload[7] == 0x01) {
      NDPI_LOG_INFO(ndpi_struct, "found rtcp\n");
      ndpi_int_rtcp_add_connection(ndpi_struct, flow);
    }
  } else if(packet->udp != NULL) {
    /* Let's check first the RTCP packet length */
    u_int16_t len, offset = 0, rtcp_section_len;
    
    while(offset + 3 < packet->payload_packet_len) {
      len = packet->payload[2+offset] * 256 + packet->payload[2+offset+1];
      rtcp_section_len = (len + 1) * 4;
      
      if(((offset+rtcp_section_len) > packet->payload_packet_len) || (rtcp_section_len == 0))
	goto exclude_rtcp;
      else
	offset += rtcp_section_len;
    }
    
    NDPI_LOG_DBG2(ndpi_struct, "calculating dport over udp\n");
    /* TODO changed a pair of length condition to the && from ||. Is it correct? */
    if(((packet->payload_packet_len >= 28 && packet->payload_packet_len <= 1200) &&
	((packet->payload[0] == 0x80) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9)) && (packet->payload[2] == 0x00)))
       || (packet->payload_packet_len >= 3 && ((packet->payload[0] == 0x81) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9))
	    && (packet->payload[2] == 0x00)))) {
      NDPI_LOG_INFO(ndpi_struct, "found rtcp\n");
      ndpi_int_rtcp_add_connection(ndpi_struct, flow);
    }
  } else {
  exclude_rtcp:
    
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  }
}


void init_rtcp_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("RTCP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_RTCP,
				      ndpi_search_rtcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
