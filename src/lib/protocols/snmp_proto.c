/*
 * snmp.c
 *
 * Copyright (C) 2011-22 - ntop.org
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

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_SNMP

#include "ndpi_api.h"

static void ndpi_int_snmp_add_connection(struct ndpi_detection_module_struct
					 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_SNMP, NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
}

void ndpi_search_snmp(struct ndpi_detection_module_struct *ndpi_struct,
		      struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  u_int16_t snmp_port = htons(161), trap_port = htons(162);
  
  if((packet->payload_packet_len <= 32)
     ||(packet->payload[0] != 0x30)
     || ((packet->payload[4] != 0 /* SNMPv1 */)
	 && (packet->payload[4] != 1 /* SNMPv2c */)
	 && (packet->payload[4] != 3 /* SNMPv3 */))
     || ((packet->udp->source != snmp_port)
	 && (packet->udp->dest != snmp_port)
	 && (packet->udp->dest != trap_port))
     /* version */
     || ((packet->payload[1] + 2) != packet->payload_packet_len)) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
  } else {
    ndpi_int_snmp_add_connection(ndpi_struct, flow);
    return;    
  }
}


void init_snmp_dissector(struct ndpi_detection_module_struct *ndpi_struct,
			 u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("SNMP", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_SNMP,
				      ndpi_search_snmp,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}

