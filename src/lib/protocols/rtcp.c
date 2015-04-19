/*
 * rtcp.c (RTP Control Protocol)
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_RTCP
static void ndpi_int_rtcp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_RTCP, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_rtcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "search for RTCP.\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over tcp.\n");

    if(packet->payload_packet_len > 13 && (sport == 554 || dport == 554) &&
       packet->payload[0] == 0x00 && packet->payload[1] == 0x00 &&
       packet->payload[2] == 0x01 && packet->payload[3] == 0x01 &&
       packet->payload[4] == 0x08 && packet->payload[5] == 0x0a &&
       packet->payload[6] == 0x00 && packet->payload[7] == 0x01) {
      NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "found rtcp.\n");
      ndpi_int_rtcp_add_connection(ndpi_struct, flow);
    }
  } else if(packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over udp.\n");
    if(((packet->payload_packet_len >= 28 || packet->payload_packet_len <= 1200) &&
	((packet->payload[0] == 0x80) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9)) && (packet->payload[2] == 0x00)))
       || (((packet->payload[0] == 0x81) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9))
	    && (packet->payload[2] == 0x00)))) {
      NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "found rtcp.\n");
      ndpi_int_rtcp_add_connection(ndpi_struct, flow);
    }
  } else {
    NDPI_LOG(NDPI_PROTOCOL_RTCP, ndpi_struct, NDPI_LOG_DEBUG, "exclude RTCP.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_RTCP);
  }
}
#endif
