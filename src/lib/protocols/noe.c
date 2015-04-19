/*
 * noe.c (Alcatel new office environment)
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_api.h"


#ifdef NDPI_PROTOCOL_NOE
static void ndpi_int_noe_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_NOE, NDPI_CORRELATED_PROTOCOL);
}

void ndpi_search_noe(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "search for NOE.\n");
  
  if(packet->udp != NULL) {
    NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over udp.\n");

    if (packet->payload_packet_len == 1 && ( packet->payload[0] == 0x05 || packet->payload[0] == 0x04 )) {
      NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      ndpi_int_noe_add_connection(ndpi_struct, flow);
      return;
    } else if((packet->payload_packet_len == 5 || packet->payload_packet_len == 12) &&
	      (packet->payload[0] == 0x07 ) && 
	      (packet->payload[1] == 0x00 ) &&
	      (packet->payload[2] != 0x00 ) &&
	      (packet->payload[3] == 0x00 )) {
      NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      ndpi_int_noe_add_connection(ndpi_struct, flow);
    } else if((packet->payload_packet_len >= 25) &&
	      (packet->payload[0] == 0x00 &&
	       packet->payload[1] == 0x06 &&
	       packet->payload[2] == 0x62 &&
	       packet->payload[3] == 0x6c)) {
      NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      ndpi_int_noe_add_connection(ndpi_struct, flow);
    }
  } else {
      NDPI_LOG(NDPI_PROTOCOL_NOE, ndpi_struct, NDPI_LOG_DEBUG, "exclude NOE.\n");
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_NOE);
    }
}
#endif
