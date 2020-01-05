/*
 * vnc.c
 *
 * Copyright (C) 2016-20 - ntop.org
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
#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VNC

#include "ndpi_api.h"

void ndpi_search_vnc_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG_DBG(ndpi_struct, "search vnc\n");
  /* search over TCP */
  if(packet->tcp) {
    
    if(flow->l4.tcp.vnc_stage == 0) {
      
      if((packet->payload_packet_len == 12) &&
	 ((memcmp(packet->payload, "RFB 003.003", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 003.007", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 003.008", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 004.001", 11) == 0 && packet->payload[11] == 0x0a))) {	   
	NDPI_LOG_DBG2(ndpi_struct, "reached vnc stage one\n");
	flow->l4.tcp.vnc_stage = 1 + packet->packet_direction;
	return;
      }
    } else if(flow->l4.tcp.vnc_stage == 2 - packet->packet_direction) {
      
      if((packet->payload_packet_len == 12) &&
	 ((memcmp(packet->payload, "RFB 003.003", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 003.007", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 003.008", 11) == 0 && packet->payload[11] == 0x0a) ||
	  (memcmp(packet->payload, "RFB 004.001", 11) == 0 && packet->payload[11] == 0x0a))) {
	
	NDPI_LOG_INFO(ndpi_struct, "found vnc\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VNC, NDPI_PROTOCOL_UNKNOWN);
	return;
      }
    }
  }
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


void init_vnc_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("VNC", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_VNC,
				      ndpi_search_vnc_tcp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  
  *id += 1;
}
