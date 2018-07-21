/*
 * noe.c (Alcatel new office environment)
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_NOE

#include "ndpi_api.h"


static void ndpi_int_noe_add_connection(struct ndpi_detection_module_struct
					*ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_NOE, NDPI_PROTOCOL_UNKNOWN);
  NDPI_LOG_INFO(ndpi_struct, "found noe\n");
}

void ndpi_search_noe(struct ndpi_detection_module_struct *ndpi_struct,
		     struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG_DBG(ndpi_struct, "search NOE\n");
  
  if(packet->udp != NULL) {
    NDPI_LOG_DBG2(ndpi_struct, "calculating dport over udp\n");

    if (packet->payload_packet_len == 1 && ( packet->payload[0] == 0x05 || packet->payload[0] == 0x04 )) {
      ndpi_int_noe_add_connection(ndpi_struct, flow);
      return;
    } else if((packet->payload_packet_len == 5 || packet->payload_packet_len == 12) &&
	      (packet->payload[0] == 0x07 ) && 
	      (packet->payload[1] == 0x00 ) &&
	      (packet->payload[2] != 0x00 ) &&
	      (packet->payload[3] == 0x00 )) {
      ndpi_int_noe_add_connection(ndpi_struct, flow);
      return;
    } else if((packet->payload_packet_len >= 25) &&
	      (packet->payload[0] == 0x00 &&
	       packet->payload[1] == 0x06 &&
	       packet->payload[2] == 0x62 &&
	       packet->payload[3] == 0x6c)) {
      ndpi_int_noe_add_connection(ndpi_struct, flow);
      return;
    }
  } else {
      NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    }
}


void init_noe_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("NOE", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_NOE,
				      ndpi_search_noe,
				      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

